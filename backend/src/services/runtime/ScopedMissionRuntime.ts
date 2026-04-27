import {
    getFocusedTestObjective,
    getScan,
    getScanConfig,
    getScopedTestRequest,
    getScopeEnvelope,
    updateScanStatus,
} from '../../db/init';
import { browserService } from '../BrowserService';
import { defaultAuthStartupConfig } from '../web-auth-startup-config';
import { logger } from '../../utils/logger';
import { FeatureAnchoringService } from './FeatureAnchoringService';
import type {
    ActiveScanRuntime,
    LiveRuntimeSummary,
    ScanRuntimeLogSnapshot,
} from './ScanRuntimeContract';
import {
    type PreparedAgentRuntime,
    type ScanRecord,
    type ScanRuntimeFactory,
    type WebScanRuntimeConfig,
    scanRuntimeFactory,
} from './ScanRuntimeFactory';
import { RuntimeLogLedger } from './RuntimeLogLedger';
import { ScopedMissionPolicy } from './ScopedMissionPolicy';
import type {
    FocusedTestObjective,
    ScopeEnvelope,
    StructuredSecurityTestRequest,
} from './ScopedScanTypes';

type ScopedMissionPhase =
    | 'scoped_discovering'
    | 'scoped_executing'
    | 'scoped_executed'
    | 'failed'
    | 'stopped';

export class ScopedMissionRuntime implements ActiveScanRuntime {
    public readonly runtimeKind = 'scoped_mission';

    private readonly logLedger: RuntimeLogLedger;
    private readonly anchoringService: FeatureAnchoringService;
    private runPromise: Promise<void> | null = null;
    private running = false;
    private phase: ScopedMissionPhase = 'scoped_discovering';
    private scopePolicy: ScopedMissionPolicy | null = null;
    private preparedRuntime: PreparedAgentRuntime | null = null;
    private stopRequested = false;

    constructor(
        private readonly scanId: string,
        private readonly targetUrl: string,
        private readonly launchConfig: WebScanRuntimeConfig = {},
        private readonly runtimeFactory: ScanRuntimeFactory = scanRuntimeFactory,
    ) {
        this.logLedger = new RuntimeLogLedger({ scanId });
        this.anchoringService = new FeatureAnchoringService({
            planningLauncher: {
                launchPlanning: () => undefined,
            },
        });
    }

    public start(): Promise<void> {
        if (!this.runPromise) {
            this.runPromise = this.run();
        }
        return this.runPromise;
    }

    public async stop(): Promise<void> {
        this.stopRequested = true;
        if (this.preparedRuntime?.agent) {
            this.preparedRuntime.agent.stop();
        }
        this.phase = 'stopped';
        this.running = false;
        this.log('system', 'Stop requested. The scoped live mission is halting.');
    }

    public async pause(): Promise<void> {
        this.preparedRuntime?.agent.pause();
    }

    public async resume(): Promise<void> {
        this.preparedRuntime?.agent.resume();
    }

    public waitForCompletion(): Promise<void> {
        return this.runPromise || Promise.resolve();
    }

    public getLogs(since: number = 0): string[] {
        return this.getMergedLogs().slice(since);
    }

    public getLogCount(): number {
        return this.getMergedLogs().length;
    }

    public getPhase(): string {
        return this.phase;
    }

    public isRunning(): boolean {
        return this.running;
    }

    public isPaused(): boolean {
        return this.preparedRuntime?.agent.getState().isPaused || false;
    }

    public captureLogs(phaseOverride?: string): ScanRuntimeLogSnapshot {
        return {
            logs: this.getMergedLogs(),
            phase: phaseOverride ?? this.phase,
        };
    }

    public flushLogsToDB(): void {
        this.logLedger.flushToDB();
        this.preparedRuntime?.agent.flushLogsToDB();
    }

    public getRuntimeSummary(): LiveRuntimeSummary | null {
        return this.scopePolicy?.buildRuntimeSummary({
            missionState: this.phase,
            targetUrl: this.targetUrl,
        }) || buildPendingScopedSummary({
            phase: this.phase,
            targetUrl: this.targetUrl,
            objective: getFocusedTestObjective(this.scanId),
            request: getScopedTestRequest(this.scanId),
            envelope: getScopeEnvelope(this.scanId),
        });
    }

    public getLiveStatus(scan: ScanRecord, since: number, activeRuntimeCount: number): any {
        const agentState = this.preparedRuntime?.agent.getState();
        const browserSessionId = this.preparedRuntime?.agent.getBrowserSessionId?.() || null;
        const browserVisibility = browserSessionId ? browserService.getSessionVisibility(browserSessionId) : null;
        const liveRuntimeSummary = this.getRuntimeSummary();

        return {
            isActive: this.running,
            isPool: false,
            scanMode: 'scoped',
            executionMode: 'exploratory-core-scoped-runtime',
            phase: this.phase,
            isRunning: this.running && !this.isPaused(),
            isPaused: this.isPaused(),
            logs: this.getLogs(since),
            logsCount: this.getLogCount(),
            burpConnected: this.running ? true : null,
            activeAgents: activeRuntimeCount,
            browserSessionId,
            browserIsHeadless: browserVisibility?.isHeadless ?? null,
            browserTransitioning: browserVisibility?.transitioning ?? false,
            browserLifecycleState: browserVisibility?.lifecycleState ?? null,
            browserIsLive: browserVisibility?.isLive ?? false,
            browserStatusDetail: browserVisibility?.detail ?? null,
            harvestedRequestCount: agentState?.harvestedRequestCount || 0,
            promotedRequestCount: agentState?.promotedRequestCount || 0,
            hypothesisCount: agentState?.hypothesisCount || { new: 0, testing: 0, escalated: 0, confirmed: 0, discarded: 0 },
            coverageSummary: agentState?.coverageSummary || null,
            endpointInventory: agentState?.endpointInventory || null,
            scanCompleted: !this.running && ['scoped_executed', 'failed', 'stopped'].includes(scan.status),
            liveRuntimeSummary,
            scopedRuntime: liveRuntimeSummary,
        };
    }

    public getAgent(): any {
        return this.preparedRuntime?.agent;
    }

    public async showBrowser(): Promise<any> {
        const sessionId = this.preparedRuntime?.agent.getBrowserSessionId?.();
        if (!sessionId) {
            throw new Error('No browser session for this scoped mission.');
        }
        return {
            ...(await browserService.showBrowser(sessionId)),
            browserSessionId: sessionId,
        };
    }

    public async hideBrowser(): Promise<any> {
        const sessionId = this.preparedRuntime?.agent.getBrowserSessionId?.();
        if (!sessionId) {
            throw new Error('No browser session for this scoped mission.');
        }
        return {
            ...(await browserService.hideBrowser(sessionId)),
            browserSessionId: sessionId,
        };
    }

    private async run(): Promise<void> {
        this.running = true;
        this.phase = 'scoped_discovering';
        this.log('mission', `Scoped mission booted for ${this.targetUrl}.`);
        this.log('analysis', 'Feature anchoring is running as preflight before the exploratory-core live mission starts.');

        try {
            this.throwIfStopped();
            const discovery = await this.anchoringService.discoverNow(this.scanId);
            this.log(
                discovery.discovery.phase === 'ready_to_plan' ? 'discovery' : 'warn',
                discovery.discovery.summary || 'Scoped feature discovery completed.',
            );

            if (discovery.discovery.phase !== 'ready_to_plan') {
                this.log('warn', 'Scoped discovery did not retain enough in-scope anchors to enter the live mission loop.');
                return;
            }
            this.throwIfStopped();

            const request = getScopedTestRequest(this.scanId);
            if (!request) {
                throw new Error(`Scoped mission request context is missing for scan ${this.scanId}.`);
            }

            this.scopePolicy = new ScopedMissionPolicy({
                objective: discovery.objective,
                envelope: discovery.envelope,
                request,
                targetUrl: this.targetUrl,
            });
            this.scopePolicy.recordManualDecision('Anchors ready. Entering exploratory-style scoped execution.', 'system');

            this.phase = 'scoped_executing';
            updateScanStatus(this.scanId, 'scoped_executing');
            this.log('system', 'Anchors are ready. Launching the live exploratory runtime inside the bounded mission envelope.');
            this.log('analysis', this.scopePolicy.describeBoundary());

            const preparedRuntime = await this.runtimeFactory.createScopedWebRuntime(
                this.scanId,
                this.targetUrl,
                this.buildRuntimeConfig(discovery.objective, discovery.envelope, request, this.scopePolicy),
            );
            if (preparedRuntime.kind !== 'agent') {
                throw new Error('Scoped missions require the single-agent exploratory runtime.');
            }
            this.preparedRuntime = preparedRuntime;
            this.throwIfStopped();

            await this.preparedRuntime.agent.start();

            const persistedPhase = getScan(this.scanId)?.status as ScopedMissionPhase | undefined;
            this.phase = persistedPhase === 'scoped_executed' || persistedPhase === 'stopped' || persistedPhase === 'failed'
                ? persistedPhase
                : 'scoped_executed';
            this.scopePolicy.recordManualDecision('Scoped live mission completed. Findings and evidence are ready for review.', 'system');
        } catch (error: any) {
            const message = error?.message || 'Scoped mission failed.';
            if (this.phase !== 'stopped') {
                this.phase = 'failed';
            }
            this.log('error', message);
            throw error;
        } finally {
            this.running = false;
            this.flushLogsToDB();
            this.preparedRuntime?.burp.disconnect();
            logger.info('Scoped mission runtime finalized', {
                scanId: this.scanId,
                phase: this.phase,
            });
        }
    }

    private buildRuntimeConfig(
        objective: FocusedTestObjective,
        envelope: ScopeEnvelope,
        request: StructuredSecurityTestRequest,
        scopePolicy: ScopedMissionPolicy,
    ): WebScanRuntimeConfig {
        const scan = getScan(this.scanId);
        const persistedConfig = getScanConfig(this.scanId) || {};

        return {
            ...this.launchConfig,
            scanMode: 'scoped',
            userId: scan?.user_id,
            rateLimit: Number(this.launchConfig.rateLimit ?? persistedConfig.rateLimit) || 5,
            maxIterations: Number(this.launchConfig.maxIterations ?? persistedConfig.maxIterations) || 50,
            maxPlanRounds: Number(this.launchConfig.maxPlanRounds ?? persistedConfig.maxPlanRounds) || 0,
            useNuclei: false,
            useFfuf: false,
            idorUsers: Array.isArray(this.launchConfig.idorUsers)
                ? this.launchConfig.idorUsers
                : Array.isArray(persistedConfig.idorUsers)
                    ? persistedConfig.idorUsers
                    : [],
            sessionCookies: this.launchConfig.sessionCookies ?? persistedConfig.sessionCookies,
            initialRequest: scan?.initial_request || this.launchConfig.initialRequest,
            sourcePackagePath: this.launchConfig.sourcePackagePath || scan?.source_package_path || persistedConfig.sourcePackagePath,
            sourceAnalysisMode: this.launchConfig.sourceAnalysisMode || scan?.source_analysis_mode || persistedConfig.sourceAnalysisMode,
            authStartup: this.launchConfig.authStartup || defaultAuthStartupConfig(),
            focusedTestObjective: objective,
            scopeEnvelope: envelope,
            structuredSecurityTestRequest: request,
            scopedMissionPolicy: scopePolicy,
            statusOverrides: {
                planning: 'scoped_executing',
                testing: 'scoped_executing',
                reporting: 'scoped_executing',
                completed: 'scoped_executed',
                ...(this.launchConfig.statusOverrides || {}),
            },
        };
    }

    private getMergedLogs(): string[] {
        const base = this.logLedger.getLogs(0);
        const runtimeLogs = this.preparedRuntime?.agent.getLogs(0) || [];
        return runtimeLogs.length > 0 ? [...base, ...runtimeLogs] : base;
    }

    private log(type: string, message: string): void {
        this.logLedger.append(type, message);
    }

    private throwIfStopped(): void {
        if (this.stopRequested) {
            this.phase = 'stopped';
            throw new Error('Scoped mission stopped by user.');
        }
    }
}

function buildPendingScopedSummary(input: {
    phase: ScopedMissionPhase;
    targetUrl: string;
    objective: FocusedTestObjective | null;
    request: StructuredSecurityTestRequest | null;
    envelope: ScopeEnvelope | null;
}): LiveRuntimeSummary | null {
    if (!input.objective && !input.request && !input.envelope) {
        return null;
    }

    return {
        missionState: input.phase,
        targetUrl: input.targetUrl,
        objectiveTitle: input.objective?.title || null,
        objectiveGoal: input.objective?.goal || null,
        requestDescription: input.request?.description || null,
        currentRail: 'system',
        activeCaseId: null,
        activeCaseTitle: null,
        activeFindingThreadId: null,
        activeFindingTitle: null,
        observationSummary: input.phase === 'scoped_discovering'
            ? 'Feature anchoring is deriving the bounded battlefield before live execution starts.'
            : null,
        nextStepRationale: input.phase === 'scoped_discovering'
            ? 'Wait for in-scope anchors, then hand control to the exploratory-core runtime.'
            : null,
        lastResponseDeltaSummary: null,
        boundaryReason: null,
        lastRequestSummary: null,
        latestSuspiciousSignal: null,
        currentDecisionSummary: input.phase === 'scoped_discovering'
            ? 'Preparing scoped discovery and live mission launch.'
            : null,
        liveFindingCount: 0,
        boundarySummary: input.envelope ? {
            allowedHosts: [...input.envelope.allowedHosts],
            allowedRoutes: [...input.envelope.allowedRoutes],
            selectedEndpointCount: input.envelope.selectedEndpoints.length,
            browserAnchorCount: input.envelope.browserAnchors.length,
            requestAnchorCount: input.envelope.discoveredRequestRefs.length + input.envelope.baselineRequestRefs.length,
            boundaryHints: [...input.envelope.boundaryHints],
            outOfScopeNotes: [...input.envelope.outOfScopeNotes],
            explorationBudget: input.envelope.explorationBudget || null,
            blockedActionReason: null,
            activeAnchorSummary: null,
            budgetState: {
                maxRequests: input.envelope.explorationBudget?.maxRequests ?? null,
                requestActionsUsed: 0,
                remainingRequests: input.envelope.explorationBudget?.maxRequests ?? null,
                maxBrowserActions: input.envelope.explorationBudget?.maxBrowserActions ?? null,
                browserActionsUsed: 0,
                remainingBrowserActions: input.envelope.explorationBudget?.maxBrowserActions ?? null,
                maxRouteVariants: input.envelope.explorationBudget?.maxRouteVariants ?? null,
                routeVariantsUsed: 0,
            },
        } : null,
    };
}
