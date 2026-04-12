import { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import {
    db,
    getScan,
    getScanEndpointInventory,
    getScanLogs,
    getVulnerabilitiesByScan,
    getBrowserActions,
    saveChatMessage,
    saveScanLogs,
    updateScanStatus,
} from '../../db/init';
import { browserService } from '../BrowserService';
import { redactAuthStartupConfig } from '../web-auth-startup-config';
import { logger } from '../../utils/logger';
import { scanRuntimeCheckpointService } from './ScanRuntimeCheckpointService';
import { ScanRuntimeRegistry, scanRuntimeRegistry } from './ScanRuntimeRegistry';
import {
    PreparedAgentRuntime,
    PreparedPoolRuntime,
    PreparedScanRuntime,
    ScanRecord,
    ScanRuntimeFactory,
    WebScanRuntimeConfig,
    scanRuntimeFactory,
} from './ScanRuntimeFactory';
import { projectCoverageGraph } from '../graph/ScanCoverageGraphProjector';
import type { CoverageGraphSnapshot } from '../graph/ScanCoverageGraph.types';

export class ScanRuntimeService {
    constructor(
        private readonly registry: ScanRuntimeRegistry = scanRuntimeRegistry,
        private readonly runtimeFactory: ScanRuntimeFactory = scanRuntimeFactory,
    ) {}

    public launchWebScan(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): void {
        void this.startWebScan(scanId, targetUrl, config).catch(() => {
            /* startWebScan already records terminal failure state */
        });
    }

    public getActiveAgent(scanId: string): OrchestratorAgent | undefined {
        return this.registry.getAgent(scanId);
    }

    public hasActiveRuntime(scanId: string): boolean {
        return this.registry.hasActiveRuntime(scanId);
    }

    public getEndpointInventory(scanId: string): any {
        const agent = this.registry.getAgent(scanId);
        return agent?.getState?.().endpointInventory || getScanEndpointInventory(scanId);
    }

    public getRuntimeCheckpoint(scanId: string): any {
        return scanRuntimeCheckpointService.getCheckpoint(scanId);
    }

    /**
     * Build a coverage graph snapshot from existing scan data.
     * Pure derived read — no mutations, no side effects.
     */
    public getCoverageGraph(scanId: string): CoverageGraphSnapshot | null {
        try {
            const endpointInventory = this.getEndpointInventory(scanId);
            if (!endpointInventory?.records?.length) return null;

            const vulnerabilities = getVulnerabilitiesByScan(scanId);

            // Get browser session info for this scan
            let browserActions: any[] = [];
            let currentUrl: string | null = null;

            const runtime = this.registry.getRuntime(scanId);
            if (runtime?.kind === 'agent') {
                const sessionId = runtime.agent.getBrowserSessionId?.();
                if (sessionId) {
                    browserActions = getBrowserActions(sessionId);
                    const visibility = browserService.getSessionVisibility(sessionId);
                    currentUrl = (visibility as any)?.currentUrl || null;
                }
            }

            // Fallback: try DB for browser session
            if (browserActions.length === 0) {
                try {
                    const session = db.prepare(
                        'SELECT id, current_url FROM browser_sessions WHERE scan_id = ? ORDER BY launched_at DESC LIMIT 1'
                    ).get(scanId) as any;
                    if (session?.id) {
                        browserActions = getBrowserActions(session.id);
                        if (!currentUrl) currentUrl = session.current_url || null;
                    }
                } catch { /* DB not ready or no session */ }
            }

            // Get coverage summary
            let coverageSummary: { coveragePercentage: number } | null = null;
            if (runtime?.kind === 'agent') {
                const state = runtime.agent.getState();
                coverageSummary = state.coverageSummary || null;
            } else {
                const checkpoint = scanRuntimeCheckpointService.getCheckpoint(scanId);
                if (checkpoint?.coverage?.coveragePercentage != null) {
                    coverageSummary = { coveragePercentage: checkpoint.coverage.coveragePercentage };
                }
            }

            // Get target origin for third-party filtering
            const scan = getScan(scanId) as any;
            const targetOrigin = scan?.target || null;

            return projectCoverageGraph({
                scanId,
                targetOrigin,
                endpointInventory,
                vulnerabilities,
                browserActions,
                currentUrl,
                coverageSummary,
            });
        } catch (error: any) {
            logger.warn('Coverage graph projection failed', { scanId, error: error.message });
            return null;
        }
    }

    public async startWebScan(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): Promise<void> {
        logger.info('Starting web scan', {
            scanId,
            targetUrl,
            config: {
                ...config,
                idorUsers: Array.isArray(config.idorUsers)
                    ? config.idorUsers.map((entry: any) => ({ ...entry, password: entry?.password ? '[REDACTED]' : undefined }))
                    : [],
                authStartup: config.authStartup ? redactAuthStartupConfig(config.authStartup) : undefined,
            },
        });

        updateScanStatus(scanId, 'initializing');

        try {
            const runtime = await this.runtimeFactory.createWebRuntime(scanId, targetUrl, config);
            logger.info('Using Burp MCP for scanning', { scanId, executionMode: runtime.executionMode });

            const finalPhase = await this.runPreparedRuntime(runtime);
            logger.info('Web scan completed', { scanId, executionMode: runtime.executionMode, finalPhase });
        } catch (error: any) {
            logger.error('Web scan error', { scanId, error: error.message });
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        }
    }

    public async pauseScan(scanId: string, userId: number): Promise<{ message: string }> {
        const runtime = this.registry.getRuntime(scanId);
        if (!runtime) {
            throw new Error('No active scan to pause');
        }

        if (runtime.kind === 'pool') {
            runtime.pool.pause();
            logger.info('Pool scan paused by user', { scanId, userId });
        } else {
            runtime.agent.pause();
            logger.info('Scan paused by user', { scanId, userId });
        }

        updateScanStatus(scanId, 'paused');
        return { message: 'Scan paused. Activity monitor is watching your manual testing.' };
    }

    public async resumeScan(scanId: string, userId: number): Promise<{ message: string }> {
        const runtime = this.registry.getRuntime(scanId);
        if (!runtime) {
            throw new Error('No active scan to resume');
        }

        if (runtime.kind === 'pool') {
            runtime.pool.resume();
            logger.info('Pool scan resumed by user', { scanId, userId });
        } else {
            runtime.agent.resume();
            logger.info('Scan resumed by user', { scanId, userId });
        }

        updateScanStatus(scanId, 'testing');
        return { message: 'Scan resumed. Automated testing continues.' };
    }

    public async stopScan(scanId: string, userId: number, scanStatus: string): Promise<{ message: string }> {
        const runtime = this.registry.getRuntime(scanId);

        if (!runtime) {
            if (!['completed', 'failed', 'stopped', 'interrupted'].includes(scanStatus)) {
                updateScanStatus(scanId, 'stopped', 'Scan stopped by user');
            }
            return { message: 'Scan was not actively running, status updated' };
        }

        if (runtime.kind === 'pool') {
            runtime.pool.stop();
            this.finalizePoolRuntime(scanId, runtime.pool, 'stopped');
            updateScanStatus(scanId, 'stopped', 'Scan stopped by user');
            logger.info('Pool scan stopped by user', { scanId, userId });
            return { message: 'Pool scan stopped successfully' };
        }

        runtime.agent.stop();
        await runtime.agent.waitForCompletion();
        this.finalizeAgentRuntime(scanId, runtime.agent);
        logger.info('Scan stopped by user', { scanId, userId });
        return { message: 'Scan stopped successfully' };
    }

    public async continueCompletedScan(scan: ScanRecord, options: {
        instruction: string;
        iterations: number;
        planningEnabled: boolean;
    }): Promise<{ message: string }> {
        const { id } = scan;

        if (this.registry.hasActiveRuntime(id)) {
            throw new Error('Scan is already running. Use the command input instead.');
        }

        const { runtime, continuation } = await this.runtimeFactory.createContinuationRuntime(scan, options);

        saveChatMessage(id, 'human', `[CONTINUE SCAN] ${continuation.instruction} (${continuation.iterations} rounds, planning: ${continuation.planningEnabled ? 'ON' : 'OFF'})`);

        void (async () => {
            try {
                const finalPhase = await this.runAgentRuntime(runtime, (agent) => agent.continueScan(continuation));
                if (finalPhase === 'completed') {
                    updateScanStatus(id, 'completed');
                }
                logger.info('Scan continuation completed', { scanId: id, finalPhase });
            } catch (error: any) {
                logger.error('Scan continuation error', { scanId: id, error: error.message });
                updateScanStatus(id, 'failed', error.message);
            }
        })();

        return { message: `Scan continuing with ${continuation.iterations} rounds. Instruction: "${continuation.instruction.slice(0, 100)}..."` };
    }

    public getLiveStatus(scanId: string, scan: ScanRecord, since: number): any {
        const runtime = this.registry.getRuntime(scanId);

        if (runtime?.kind === 'pool') {
            const state = runtime.pool.getState();
            const logs = runtime.pool.getLogs(since);

            return {
                isActive: true,
                isPool: true,
                executionMode: 'dormant-multi-agent',
                phase: 'testing',
                coverageGraph: null,
                isRunning: state.isRunning,
                isPaused: false,
                logs,
                logsCount: state.logsCount,
                burpConnected: true,
                activeAgents: state.workerCount,
                workers: state.workers,
                stats: state.stats,
                endpointInventory: null,
            };
        }

        if (runtime?.kind === 'agent') {
            const state = runtime.agent.getState();
            const logs = runtime.agent.getLogs(since);
            const browserSessionId = runtime.agent.getBrowserSessionId?.() || null;
            const browserVisibility = browserSessionId ? browserService.getSessionVisibility(browserSessionId) : null;

            return {
                isActive: true,
                isPool: false,
                executionMode: 'single-agent',
                phase: state.phase,
                isRunning: state.isRunning,
                isPaused: state.isPaused,
                logs,
                logsCount: state.logsCount,
                burpConnected: true,
                activeAgents: this.registry.getActiveAgentCount(),
                browserSessionId,
                browserIsHeadless: browserVisibility?.isHeadless ?? null,
                browserTransitioning: browserVisibility?.transitioning ?? false,
                browserLifecycleState: browserVisibility?.lifecycleState ?? null,
                browserIsLive: browserVisibility?.isLive ?? false,
                browserStatusDetail: browserVisibility?.detail ?? null,
                harvestedRequestCount: state.harvestedRequestCount || 0,
                promotedRequestCount: state.promotedRequestCount || 0,
                hypothesisCount: state.hypothesisCount || { new: 0, testing: 0, escalated: 0, confirmed: 0, discarded: 0 },
                coverageSummary: state.coverageSummary || null,
                endpointInventory: state.endpointInventory || null,
                coverageGraph: this.getCoverageGraph(scanId),
            };
        }

        let cached = this.registry.getCachedLogs(scanId);

        if (!cached) {
            const dbLogs = getScanLogs(scanId);
            if (dbLogs.length > 0) {
                cached = this.registry.cacheLogs(scanId, { logs: dbLogs, phase: scan.status });
            }
        }

        const cachedLogs = cached ? cached.logs.slice(since) : [];
        const cachedLogsCount = cached ? cached.logs.length : 0;
        const isCompleted = scan.status === 'completed' || scan.status === 'stopped' || scan.status === 'failed';
        const checkpoint = scanRuntimeCheckpointService.getCheckpoint(scanId);

        return {
            isActive: false,
            isPool: false,
            executionMode: checkpoint?.executionMode || 'single-agent',
            phase: cached?.phase || scan.status,
            isRunning: false,
            isPaused: false,
            logs: cachedLogs,
            logsCount: cachedLogsCount,
            burpConnected: isCompleted ? null : false,
            activeAgents: this.registry.getTotalActiveRuntimeCount(),
            scanCompleted: isCompleted,
            endpointInventory: getScanEndpointInventory(scanId),
            harvestedRequestCount: checkpoint?.harvested?.total || 0,
            promotedRequestCount: checkpoint?.harvested?.promoted || 0,
            hypothesisCount: checkpoint?.hypotheses?.counts || { new: 0, testing: 0, escalated: 0, confirmed: 0, discarded: 0 },
            coverageSummary: checkpoint?.coverage ? {
                routesSeen: checkpoint.coverage.routesSeen,
                exercised: checkpoint.coverage.routesExercisedInBrowser,
                promoted: checkpoint.coverage.requestsPromoted,
                untested: Array.isArray(checkpoint.coverage.untestedRoutes) ? checkpoint.coverage.untestedRoutes.length : 0,
                coveragePercentage: checkpoint.coverage.coveragePercentage,
            } : null,
            runtimeCheckpoint: checkpoint,
            coverageGraph: this.getCoverageGraph(scanId),
        };
    }

    public async showScanBrowser(scanId: string): Promise<any> {
        const agent = this.registry.getAgent(scanId);
        if (!agent) {
            throw new Error('No active scan agent');
        }

        const browserSessionId = agent.getBrowserSessionId?.();
        if (!browserSessionId) {
            throw new Error('No browser session for this scan');
        }

        const visibility = await browserService.showBrowser(browserSessionId);
        return { ...visibility, browserSessionId };
    }

    public async hideScanBrowser(scanId: string): Promise<any> {
        const agent = this.registry.getAgent(scanId);
        if (!agent) {
            throw new Error('No active scan agent');
        }

        const browserSessionId = agent.getBrowserSessionId?.();
        if (!browserSessionId) {
            throw new Error('No browser session for this scan');
        }

        const visibility = await browserService.hideBrowser(browserSessionId);
        return { ...visibility, browserSessionId };
    }

    public async startAssistedScan(scanId: string, suggestion: any): Promise<void> {
        updateScanStatus(scanId, 'scanning');
        const runtime = await this.runtimeFactory.createAssistedScanRuntime(scanId, suggestion);
        const finalPhase = await this.runPreparedRuntime(runtime);
        logger.info('Assisted scan completed', { scanId, executionMode: runtime.executionMode, finalPhase });
    }

    private async runPreparedRuntime(runtime: PreparedScanRuntime): Promise<string> {
        if (runtime.kind === 'pool') {
            return this.runPoolRuntime(runtime);
        }

        return this.runAgentRuntime(runtime, (agent) => agent.start());
    }

    private async runAgentRuntime(
        runtime: PreparedAgentRuntime,
        runner: (agent: OrchestratorAgent) => Promise<void>,
    ): Promise<string> {
        this.registry.registerAgent(runtime.scanId, runtime.agent);

        let finalPhase: string = runtime.agent.getState().phase;
        try {
            await runner(runtime.agent);
        } finally {
            finalPhase = this.finalizeAgentRuntime(runtime.scanId, runtime.agent);
            runtime.burp.disconnect();
        }

        return finalPhase;
    }

    private async runPoolRuntime(runtime: PreparedPoolRuntime): Promise<string> {
        this.registry.registerPool(runtime.scanId, runtime.pool);

        let finalPhase = this.resolveFinalPhase(runtime.scanId, 'completed');
        try {
            await runtime.pool.start();
            finalPhase = this.resolveFinalPhase(runtime.scanId, 'completed');
        } finally {
            finalPhase = this.finalizePoolRuntime(runtime.scanId, runtime.pool, finalPhase);
            runtime.burp.disconnect();
        }

        return finalPhase;
    }

    private finalizeAgentRuntime(scanId: string, agent: OrchestratorAgent): string {
        const finalPhase = this.resolveAgentFinalPhase(scanId, agent, agent.getState().phase);
        this.registry.captureAgentLogs(scanId, agent, finalPhase);
        agent.flushLogsToDB();
        this.registry.unregister(scanId);
        return finalPhase;
    }

    private finalizePoolRuntime(scanId: string, pool: AgentPool, finalPhase: string): string {
        const snapshot = this.registry.capturePoolLogs(scanId, pool, finalPhase);
        saveScanLogs(scanId, snapshot.logs);
        this.registry.unregister(scanId);
        return finalPhase;
    }

    private resolveAgentFinalPhase(scanId: string, agent: OrchestratorAgent, fallbackPhase: string): string {
        return this.resolveFinalPhase(scanId, agent.getState().phase || fallbackPhase);
    }

    private resolveFinalPhase(scanId: string, fallbackPhase: string): string {
        const scan = getScan(scanId);
        return (scan?.status as string | undefined) || fallbackPhase;
    }
}

export const scanRuntimeService = new ScanRuntimeService();
