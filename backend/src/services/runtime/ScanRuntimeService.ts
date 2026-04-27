import { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import {
    getScan,
    getScanEndpointInventory,
    getScanLogs,
    saveChatMessage,
    saveScanLogs,
    updateScanStatus,
} from '../../db/init';
import { browserService } from '../BrowserService';
import { redactAuthStartupConfig } from '../web-auth-startup-config';
import { logger } from '../../utils/logger';
import { scanRuntimeCheckpointService } from './ScanRuntimeCheckpointService';
import { ScanRuntimeRegistry, scanRuntimeRegistry } from './ScanRuntimeRegistry';
import { normalizeScanMode } from './ScopedScanTypes';
import { ScopedMissionRuntime } from './ScopedMissionRuntime';
import type { ActiveScanRuntime } from './ScanRuntimeContract';
import {
    PreparedAgentRuntime,
    PreparedPoolRuntime,
    PreparedScanRuntime,
    ScanRecord,
    ScanRuntimeFactory,
    WebScanRuntimeConfig,
    scanRuntimeFactory,
} from './ScanRuntimeFactory';

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

    public launchScopedWebScan(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): void {
        void this.startScopedWebScan(scanId, targetUrl, config).catch(() => {
            /* startScopedWebScan already records terminal failure state */
        });
    }

    public launchScopedMission(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): void {
        void this.startScopedMission(scanId, targetUrl, config).catch(() => {
            /* startScopedMission already records terminal failure state */
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

    public getRuntimeSummary(scanId: string): any {
        const runtime = this.registry.getRuntime(scanId);
        if (runtime?.kind === 'runtime') {
            return runtime.runtime.getRuntimeSummary?.() || null;
        }
        if (runtime?.kind === 'agent') {
            return runtime.agent.getRuntimeSummary?.() || null;
        }
        return null;
    }

    public async startWebScan(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): Promise<void> {
        logger.info('Starting web scan', {
            scanId,
            targetUrl,
            scanMode: normalizeScanMode(config.scanMode),
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
            logger.info('Using Burp MCP for scanning', { scanId, scanMode: runtime.scanMode, executionMode: runtime.executionMode });

            const finalPhase = await this.runPreparedRuntime(runtime);
            logger.info('Web scan completed', { scanId, scanMode: runtime.scanMode, executionMode: runtime.executionMode, finalPhase });
        } catch (error: any) {
            logger.error('Web scan error', { scanId, error: error.message });
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        }
    }

    public async startScopedWebScan(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): Promise<void> {
        logger.info('Starting scoped web scan', {
            scanId,
            targetUrl,
            scanMode: 'scoped',
            scopeType: config.focusedTestObjective?.scopeType,
            allowedHosts: config.scopeEnvelope?.allowedHosts?.length || 0,
            allowedRoutes: config.scopeEnvelope?.allowedRoutes?.length || 0,
        });

        updateScanStatus(scanId, 'initializing');

        try {
            const runtime = await this.runtimeFactory.createScopedWebRuntime(scanId, targetUrl, {
                ...config,
                scanMode: 'scoped',
            });
            logger.info('Using Burp MCP for scoped scanning', { scanId, scanMode: runtime.scanMode, executionMode: runtime.executionMode });

            const finalPhase = await this.runPreparedRuntime(runtime);
            logger.info('Scoped web scan completed', { scanId, scanMode: runtime.scanMode, executionMode: runtime.executionMode, finalPhase });
        } catch (error: any) {
            logger.error('Scoped web scan error', { scanId, error: error.message });
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        }
    }

    public async startScopedMission(scanId: string, targetUrl: string, config: WebScanRuntimeConfig = {}): Promise<void> {
        logger.info('Starting scoped mission runtime', {
            scanId,
            targetUrl,
            scanMode: 'scoped',
        });

        const runtime = new ScopedMissionRuntime(scanId, targetUrl, config, this.runtimeFactory);
        this.registry.registerRuntime(scanId, runtime);

        try {
            await runtime.start();
            logger.info('Scoped mission runtime completed', {
                scanId,
                phase: runtime.getPhase(),
            });
        } catch (error: any) {
            if (runtime.getPhase() === 'stopped' || /stopped by user/i.test(error.message || '')) {
                updateScanStatus(scanId, 'stopped', 'Scan stopped by user');
                return;
            }
            logger.error('Scoped mission runtime error', { scanId, error: error.message });
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        } finally {
            this.finalizeGenericRuntime(scanId, runtime);
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
        } else if (runtime.kind === 'runtime') {
            if (!runtime.runtime.pause) {
                throw new Error('This live runtime does not support pausing.');
            }
            await runtime.runtime.pause();
            logger.info('Live runtime paused by user', { scanId, userId, runtimeKind: runtime.runtime.runtimeKind });
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
        } else if (runtime.kind === 'runtime') {
            if (!runtime.runtime.resume) {
                throw new Error('This live runtime does not support resuming.');
            }
            await runtime.runtime.resume();
            logger.info('Live runtime resumed by user', { scanId, userId, runtimeKind: runtime.runtime.runtimeKind });
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

        if (runtime.kind === 'runtime') {
            if (runtime.runtime.stop) {
                await runtime.runtime.stop();
            }
            if (runtime.runtime.waitForCompletion) {
                await runtime.runtime.waitForCompletion();
            }
            this.finalizeGenericRuntime(scanId, runtime.runtime, 'stopped');
            updateScanStatus(scanId, 'stopped', 'Scan stopped by user');
            logger.info('Live runtime stopped by user', { scanId, userId, runtimeKind: runtime.runtime.runtimeKind });
            return { message: 'Scan stopped successfully' };
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
                scanMode: normalizeScanMode(scan.scan_mode),
                executionMode: 'dormant-multi-agent',
                phase: 'testing',
                isRunning: state.isRunning,
                isPaused: false,
                logs,
                logsCount: state.logsCount,
                burpConnected: true,
                activeAgents: state.workerCount,
                workers: state.workers,
                stats: state.stats,
                endpointInventory: null,
                liveRuntimeSummary: null,
                scopedRuntime: null,
                supportsPause: true,
                supportsBrowserVisibility: false,
            };
        }

        if (runtime?.kind === 'agent') {
            const state = runtime.agent.getState();
            const logs = runtime.agent.getLogs(since);
            const browserSessionId = runtime.agent.getBrowserSessionId?.() || null;
            const browserVisibility = browserSessionId ? browserService.getSessionVisibility(browserSessionId) : null;
            const liveRuntimeSummary = runtime.agent.getRuntimeSummary?.() || null;

            return {
                isActive: true,
                isPool: false,
                scanMode: normalizeScanMode(scan.scan_mode),
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
                liveRuntimeSummary,
                scopedRuntime: liveRuntimeSummary,
                supportsPause: true,
                supportsBrowserVisibility: true,
            };
        }

        if (runtime?.kind === 'runtime') {
            const liveStatus = runtime.runtime.getLiveStatus(scan, since, this.registry.getTotalActiveRuntimeCount());
            const liveRuntimeSummary = liveStatus.liveRuntimeSummary ?? liveStatus.scopedRuntime ?? null;

            return {
                ...liveStatus,
                liveRuntimeSummary,
                scopedRuntime: liveStatus.scopedRuntime ?? liveRuntimeSummary,
                supportsPause: typeof runtime.runtime.pause === 'function',
                supportsBrowserVisibility: typeof runtime.runtime.showBrowser === 'function' && typeof runtime.runtime.hideBrowser === 'function',
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
            scanMode: normalizeScanMode(scan.scan_mode),
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
            liveRuntimeSummary: null,
            scopedRuntime: null,
            supportsPause: false,
            supportsBrowserVisibility: false,
        };
    }

    public async showScanBrowser(scanId: string): Promise<any> {
        const runtime = this.registry.getRuntime(scanId);
        if (!runtime) {
            throw new Error('No active scan runtime');
        }

        if (runtime.kind === 'runtime') {
            if (!runtime.runtime.showBrowser) {
                throw new Error('This live runtime does not expose a browser.');
            }
            return runtime.runtime.showBrowser();
        }

        const agent = runtime.kind === 'agent' ? runtime.agent : undefined;
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
        const runtime = this.registry.getRuntime(scanId);
        if (!runtime) {
            throw new Error('No active scan runtime');
        }

        if (runtime.kind === 'runtime') {
            if (!runtime.runtime.hideBrowser) {
                throw new Error('This live runtime does not expose a browser.');
            }
            return runtime.runtime.hideBrowser();
        }

        const agent = runtime.kind === 'agent' ? runtime.agent : undefined;
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

    private finalizeGenericRuntime(scanId: string, runtime: ActiveScanRuntime, phaseOverride?: string): string {
        const finalPhase = phaseOverride ?? this.resolveFinalPhase(scanId, runtime.getPhase());
        this.registry.captureRuntimeLogs(scanId, runtime, finalPhase);
        runtime.flushLogsToDB?.();
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
