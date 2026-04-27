import type { ScanRecord } from './ScanRuntimeFactory';

export interface ScanRuntimeLogSnapshot {
    logs: string[];
    phase: string;
}

export interface LiveRuntimeRequestSummary {
    method?: string | null;
    path?: string | null;
    url?: string | null;
    statusCode?: number | null;
    summary: string;
}

export interface LiveRuntimeBudgetState {
    maxRequests: number | null;
    requestActionsUsed: number;
    remainingRequests: number | null;
    maxBrowserActions: number | null;
    browserActionsUsed: number;
    remainingBrowserActions: number | null;
    maxRouteVariants: number | null;
    routeVariantsUsed: number;
}

export interface LiveRuntimeBoundarySummary {
    allowedHosts: string[];
    allowedRoutes: string[];
    selectedEndpointCount: number;
    browserAnchorCount: number;
    requestAnchorCount: number;
    boundaryHints: string[];
    outOfScopeNotes: string[];
    explorationBudget: Record<string, any> | null;
    blockedActionReason: string | null;
    activeAnchorSummary: string | null;
    budgetState: LiveRuntimeBudgetState;
}

export interface LiveRuntimeSummary {
    missionState: string;
    targetUrl: string | null;
    objectiveTitle: string | null;
    objectiveGoal: string | null;
    requestDescription: string | null;
    currentRail: string | null;
    activeCaseId: string | null;
    activeCaseTitle: string | null;
    activeFindingThreadId: string | null;
    activeFindingTitle: string | null;
    observationSummary: string | null;
    nextStepRationale: string | null;
    lastResponseDeltaSummary: string | null;
    boundaryReason: string | null;
    lastRequestSummary: LiveRuntimeRequestSummary | null;
    latestSuspiciousSignal: string | null;
    currentDecisionSummary: string | null;
    liveFindingCount: number;
    boundarySummary: LiveRuntimeBoundarySummary | null;
}

export interface ActiveScanRuntime {
    readonly runtimeKind: string;
    getLogs(since?: number): string[];
    getLogCount(): number;
    getPhase(): string;
    isRunning(): boolean;
    isPaused(): boolean;
    getLiveStatus(scan: ScanRecord, since: number, activeRuntimeCount: number): any;
    getRuntimeSummary?(): LiveRuntimeSummary | null;
    captureLogs?(phaseOverride?: string): ScanRuntimeLogSnapshot;
    flushLogsToDB?(): void;
    pause?(): void | Promise<void>;
    resume?(): void | Promise<void>;
    stop?(): void | Promise<void>;
    waitForCompletion?(): Promise<void>;
    showBrowser?(): Promise<any>;
    hideBrowser?(): Promise<any>;
    getAgent?(): any;
}
