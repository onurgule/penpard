import { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import {
    getScan,
    getScanEndpointInventory,
    getScanLogs,
    getVulnerabilitiesByScan,
    saveChatMessage,
    saveScanLogs,
    updateScanStatus,
} from '../../db/init';
import { browserService } from '../BrowserService';
import { BurpMCPClient } from '../burp-mcp';
import { defaultAuthStartupConfig, redactAuthStartupConfig } from '../web-auth-startup-config';
import { logger } from '../../utils/logger';
import { ScanRuntimeRegistry, scanRuntimeRegistry } from './ScanRuntimeRegistry';

interface ScanRecord {
    id: string;
    target: string;
    status: string;
    user_id: number;
    initial_request?: string | null;
    [key: string]: any;
}

interface WebScanRuntimeConfig {
    userId?: number;
    rateLimit?: number;
    maxIterations?: number;
    maxPlanRounds?: number;
    useNuclei?: boolean;
    useFfuf?: boolean;
    idorUsers?: any[];
    parallelAgents?: number;
    customSystemPrompt?: string;
    sessionCookies?: string;
    initialRequest?: string;
    sourcePackagePath?: string;
    sourceAnalysisMode?: string;
    authStartup?: any;
}

export class ScanRuntimeService {
    constructor(private readonly registry: ScanRuntimeRegistry = scanRuntimeRegistry) {}

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
            const burpMCP = new BurpMCPClient();
            let mcpAvailable = false;

            try {
                mcpAvailable = await burpMCP.isAvailable();
            } catch {
                logger.warn('Burp MCP connection check failed');
            }

            if (!mcpAvailable) {
                const errorMsg = 'Burp Suite is not connected. Cannot start scan without Burp MCP. Please ensure Burp Suite is running with the PenPard extension loaded (port 9876).';
                logger.error(errorMsg, { scanId });
                updateScanStatus(scanId, 'failed', errorMsg);
                return;
            }

            logger.info('Using Burp MCP for scanning', { scanId });

            const requestedParallelAgents = config.parallelAgents || 1;
            const authFirstStartupRequired = true;
            const parallelAgents = authFirstStartupRequired ? 1 : requestedParallelAgents;
            logger.info(`parallelAgents config value: ${requestedParallelAgents} (effective: ${parallelAgents})`, { scanId, config });

            if (requestedParallelAgents > 1) {
                logger.warn('Web Scan startup now requires a single orchestrator so browser-driven auth inventory, Burp traffic correlation, and session state stay consistent across the scan lifecycle.', {
                    scanId,
                    requestedParallelAgents,
                });
            }

            if (parallelAgents > 1) {
                await this.runPoolScan(scanId, targetUrl, burpMCP, config, parallelAgents);
            } else {
                await this.runSingleAgentScan(scanId, targetUrl, burpMCP, config);
            }

            logger.info('Web scan completed', { scanId });
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
            if (scanStatus !== 'completed' && scanStatus !== 'failed') {
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
        this.finalizeAgentRuntime(scanId, runtime.agent);
        updateScanStatus(scanId, 'stopped', 'Scan stopped by user');
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

        const existingFindings = getVulnerabilitiesByScan(id);
        const existingEndpoints: string[] = [];

        for (const finding of existingFindings) {
            if (finding.request) {
                const urlMatch = finding.request.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(https?:\/\/[^\s]+)/i);
                if (urlMatch) existingEndpoints.push(urlMatch[1]);
            }
        }

        const burpMCP = new BurpMCPClient();
        let mcpAvailable = false;
        try {
            mcpAvailable = await burpMCP.isAvailable();
        } catch {
            logger.warn('Burp MCP not available for continuation');
        }

        if (!mcpAvailable) {
            throw new Error('Burp Suite is not connected. Please ensure Burp is running with the PenPard extension.');
        }

        const initialRequest = (scan.initial_request && String(scan.initial_request).trim()) ? String(scan.initial_request).trim() : undefined;
        const agent = new OrchestratorAgent(id, scan.target, {
            userId: scan.user_id,
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            customSystemPrompt: options.instruction,
            initialRequest,
        }, burpMCP);

        this.registry.registerAgent(id, agent);

        saveChatMessage(id, 'human', `[CONTINUE SCAN] ${options.instruction} (${options.iterations} rounds, planning: ${options.planningEnabled ? 'ON' : 'OFF'})`);

        void (async () => {
            try {
                await agent.continueScan({
                    instruction: options.instruction,
                    iterations: Math.min(Math.max(Number(options.iterations), 1), 20),
                    planningEnabled: !!options.planningEnabled,
                    existingFindings,
                    existingEndpoints: [...new Set(existingEndpoints)],
                });

                const finalPhase = this.resolveAgentFinalPhase(id, agent, 'completed');
                if (finalPhase === 'completed') {
                    updateScanStatus(id, 'completed');
                }
                logger.info('Scan continuation completed', { scanId: id, finalPhase });
            } catch (error: any) {
                logger.error('Scan continuation error', { scanId: id, error: error.message });
                updateScanStatus(id, 'failed', error.message);
            } finally {
                this.finalizeAgentRuntime(id, agent);
                burpMCP.disconnect();
            }
        })();

        return { message: `Scan continuing with ${options.iterations} rounds. Instruction: "${options.instruction.slice(0, 100)}..."` };
    }

    public getLiveStatus(scanId: string, scan: ScanRecord, since: number): any {
        const runtime = this.registry.getRuntime(scanId);

        if (runtime?.kind === 'pool') {
            const state = runtime.pool.getState();
            const logs = runtime.pool.getLogs(since);

            return {
                isActive: true,
                isPool: true,
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

        return {
            isActive: false,
            isPool: false,
            phase: cached?.phase || scan.status,
            isRunning: false,
            isPaused: false,
            logs: cachedLogs,
            logsCount: cachedLogsCount,
            burpConnected: isCompleted ? null : false,
            activeAgents: this.registry.getTotalActiveRuntimeCount(),
            scanCompleted: isCompleted,
            endpointInventory: getScanEndpointInventory(scanId),
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
        const burp = new BurpMCPClient();
        const available = await burp.isAvailable();
        if (!available) {
            throw new Error('Burp MCP not available');
        }

        updateScanStatus(scanId, 'scanning');

        const focusPrompts: Record<string, string> = {
            sqli: `FOCUSED SQL INJECTION SCAN: The user was manually testing SQL injection on the following endpoints.
Your job is to quickly and efficiently test these endpoints with comprehensive SQLi payloads:
- Time-based blind: ' AND SLEEP(5)--, ' WAITFOR DELAY '0:0:5'--
- Boolean-based: ' AND '1'='1 vs ' AND '1'='2
- Error-based: ' AND 1=CONVERT(int,@@version)--
- UNION-based: ' UNION SELECT NULL,NULL--
- Stacked queries: '; EXEC xp_cmdshell('whoami')--

Endpoints to test:
${suggestion.endpoints.join('\n')}

Be fast, focused and thorough. Test each parameter systematically.`,

            xss: `FOCUSED XSS SCAN: The user was manually testing Cross-Site Scripting.
Test these endpoints with comprehensive XSS payloads:
- Reflected: <script>alert(1)</script>, <img src=x onerror=alert(1)>
- DOM-based: javascript:alert(1), " onmouseover="alert(1)
- Stored: Check if payloads persist across requests
- Filter bypass: <ScRiPt>alert(1)</ScRiPt>, <svg/onload=alert(1)>
- Encoding bypass: &#60;script&#62;, %3Cscript%3E

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

            lfi: `FOCUSED LFI/PATH TRAVERSAL SCAN: The user was testing file inclusion.
Test these endpoints:
- Basic traversal: ../../etc/passwd, ....//....//etc/passwd
- Null byte: ../../../etc/passwd%00
- Double encoding: ..%252f..%252f..%252fetc/passwd
- PHP wrappers: php://filter/convert.base64-encode/resource=index.php
- Windows: ..\\..\\windows\\system32\\drivers\\etc\\hosts

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

            cmdi: `FOCUSED COMMAND INJECTION SCAN: The user was testing command injection.
Test these endpoints:
- Basic: ; ls, | cat /etc/passwd, \`id\`
- Blind: ; sleep 5, | ping -c 5 127.0.0.1
- Alternative: $( whoami ), \${IFS}cat\${IFS}/etc/passwd
- Windows: & dir, | type C:\\windows\\win.ini

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

            ssrf: `FOCUSED SSRF SCAN: The user was testing Server-Side Request Forgery.
Test these endpoints:
- Internal: http://127.0.0.1, http://localhost, http://[::1]
- Cloud metadata: http://169.254.169.254/latest/meta-data/
- DNS rebinding: Use alternative IP representations
- Protocol: file:///etc/passwd, gopher://, dict://

Endpoints to test:
${suggestion.endpoints.join('\n')}`,
        };

        const focusPrompt = focusPrompts[suggestion.type] || `Test the following endpoints for ${suggestion.type} vulnerabilities:\n${suggestion.endpoints.join('\n')}`;

        const agent = new OrchestratorAgent(
            scanId,
            suggestion.targetHosts[0] || suggestion.endpoints[0]?.split(' ').pop() || 'target',
            {
                rateLimit: 5,
                useNuclei: false,
                useFfuf: false,
                idorUsers: [],
                parallelAgents: 1,
                customSystemPrompt: focusPrompt,
                maxIterations: 15,
            },
            burp,
        );

        this.registry.registerAgent(scanId, agent);

        try {
            await agent.start();
        } finally {
            const finalPhase = this.resolveAgentFinalPhase(scanId, agent, 'completed');
            this.finalizeAgentRuntime(scanId, agent);
            burp.disconnect();
            if (finalPhase === 'completed') {
                updateScanStatus(scanId, 'completed');
            }
        }
    }

    private async runPoolScan(
        scanId: string,
        targetUrl: string,
        burpMCP: BurpMCPClient,
        config: WebScanRuntimeConfig,
        parallelAgents: number,
    ): Promise<void> {
        logger.info(`Using AgentPool with ${parallelAgents} parallel workers`, { scanId });

        const poolConfig = {
            crawlerCount: Math.max(1, Math.floor(parallelAgents * 0.2)),
            scannerCount: Math.max(1, Math.floor(parallelAgents * 0.4)),
            fuzzerCount: Math.max(1, Math.floor(parallelAgents * 0.25)),
            analyzerCount: Math.max(1, Math.floor(parallelAgents * 0.15)),
            maxIterationsPerWorker: 25,
            rateLimit: config.rateLimit || 5,
        };

        const pool = new AgentPool(scanId, targetUrl, burpMCP, poolConfig);
        this.registry.registerPool(scanId, pool);

        try {
            await pool.start();
        } finally {
            const finalPhase = this.resolveFinalPhase(scanId, 'completed');
            this.finalizePoolRuntime(scanId, pool, finalPhase);
            burpMCP.disconnect();
        }
    }

    private async runSingleAgentScan(
        scanId: string,
        targetUrl: string,
        burpMCP: BurpMCPClient,
        config: WebScanRuntimeConfig,
    ): Promise<void> {
        const agent = new OrchestratorAgent(scanId, targetUrl, {
            userId: config.userId,
            rateLimit: config.rateLimit || 5,
            maxIterations: config.maxIterations,
            maxPlanRounds: config.maxPlanRounds,
            useNuclei: config.useNuclei || false,
            useFfuf: config.useFfuf || false,
            idorUsers: config.idorUsers || [],
            sessionCookies: config.sessionCookies,
            initialRequest: config.initialRequest,
            sourcePackagePath: config.sourcePackagePath,
            sourceAnalysisMode: config.sourceAnalysisMode,
            authStartup: config.authStartup || defaultAuthStartupConfig(),
            customSystemPrompt: config.customSystemPrompt,
        }, burpMCP);

        this.registry.registerAgent(scanId, agent);

        try {
            await agent.start();
        } finally {
            this.finalizeAgentRuntime(scanId, agent);
            burpMCP.disconnect();
        }
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
