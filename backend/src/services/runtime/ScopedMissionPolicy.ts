import type { HarvestedRequest } from '../RequestHarvester';
import type { RequestExecutionAftermath } from '../../agents/orchestrator/OrchestratorRequestExecutor';
import type {
    FocusedExecutionRail,
    FocusedTestObjective,
    ScopeEnvelope,
    StructuredSecurityTestRequest,
} from './ScopedScanTypes';
import type {
    LiveRuntimeSummary,
} from './ScanRuntimeContract';

type ScopedToolName =
    | 'send_http_request'
    | 'send_to_scanner'
    | 'browser_navigate'
    | 'browser_fill_and_submit'
    | 'browser_get_page_state'
    | 'browser_get_frontend_analysis'
    | 'browser_evaluate_js'
    | 'browser_screenshot'
    | 'browser_correlate_burp'
    | 'repeater_test'
    | 'harvest_traffic';

export interface ScopedMissionBudgetState {
    maxRequests: number | null;
    requestActionsUsed: number;
    remainingRequests: number | null;
    maxBrowserActions: number | null;
    browserActionsUsed: number;
    remainingBrowserActions: number | null;
    maxRouteVariants: number | null;
    routeVariantsUsed: number;
}

export interface ScopedMissionBoundarySummary {
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
    budgetState: ScopedMissionBudgetState;
}

export interface ScopedMissionGuardInput {
    toolName: ScopedToolName;
    method?: string;
    url?: string;
    useInitialRequestBaseline?: boolean;
}

export interface ScopedMissionGuardDecision {
    allowed: boolean;
    normalizedHost?: string;
    normalizedPath?: string;
    reason?: string;
}

interface ScopedMissionPolicyOptions {
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
    request: StructuredSecurityTestRequest;
    targetUrl: string;
}

function normalizeHost(value?: string | null): string | undefined {
    if (!value) {
        return undefined;
    }

    try {
        return new URL(value).host.toLowerCase();
    } catch {
        return value
            .trim()
            .toLowerCase()
            .replace(/^https?:\/\//i, '')
            .replace(/\/.*$/, '');
    }
}

function normalizeRoutePath(value?: string | null): string | undefined {
    if (!value) {
        return undefined;
    }

    try {
        const parsed = new URL(value);
        return parsed.pathname || '/';
    } catch {
        const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
        if (!withoutQuery) {
            return undefined;
        }
        return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
    }
}

function routeMatches(pattern: string, candidate: string): boolean {
    const normalizedPattern = normalizeRoutePath(pattern);
    const normalizedCandidate = normalizeRoutePath(candidate);
    if (!normalizedPattern || !normalizedCandidate) {
        return false;
    }

    if (normalizedPattern === normalizedCandidate) {
        return true;
    }

    const escaped = normalizedPattern
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\/:([A-Za-z0-9_]+)/g, '/[^/]+');
    return new RegExp(`^${escaped}$`).test(normalizedCandidate);
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
    const seen = new Set<string>();
    const output: string[] = [];

    for (const value of values) {
        const normalized = String(value || '').trim();
        if (!normalized || seen.has(normalized)) {
            continue;
        }
        seen.add(normalized);
        output.push(normalized);
    }

    return output;
}

export class ScopedMissionPolicy {
    private readonly allowedHosts: string[];
    private readonly allowedRoutes: string[];
    private readonly baselinePaths: string[];
    private readonly seededAnchorPaths: string[];
    private readonly variantPaths = new Set<string>();
    private requestActionsUsed = 0;
    private browserActionsUsed = 0;
    private navigationDepth = 0;
    private verificationRetries = 0;
    private currentRail: FocusedExecutionRail | null = null;
    private activeAnchorSummary: string | null = null;
    private blockedActionReason: string | null = null;
    private currentDecisionSummary: string | null = null;
    private latestSuspiciousSignal: string | null = null;
    private activeFindingTitle: string | null = null;
    private lastFindingFingerprint: string | null = null;
    private liveFindingCount = 0;
    private lastRequestSummary: {
        method?: string | null;
        path?: string | null;
        url?: string | null;
        statusCode?: number | null;
        summary: string;
    } | null = null;
    private lastResponseSummary: string | null = null;

    constructor(private readonly options: ScopedMissionPolicyOptions) {
        this.allowedHosts = uniqueStrings([
            ...options.envelope.allowedHosts,
            normalizeHost(options.targetUrl),
            normalizeHost(options.request.targetUrl),
        ]);
        this.allowedRoutes = uniqueStrings([
            ...options.envelope.allowedRoutes.map((entry) => normalizeRoutePath(entry)),
        ]);
        this.baselinePaths = uniqueStrings(
            options.envelope.baselineRequestRefs.map((entry) => normalizeRoutePath(entry.path || entry.url)),
        );
        this.seededAnchorPaths = uniqueStrings([
            ...options.envelope.selectedEndpoints.map((entry) => normalizeRoutePath(entry.path || entry.url)),
            ...options.envelope.discoveredRequestRefs.map((entry) => normalizeRoutePath(entry.path || entry.url)),
            ...options.envelope.browserAnchors.map((entry) => normalizeRoutePath(entry.startPath || entry.startUrl)),
            ...this.baselinePaths,
        ]);
        this.activeAnchorSummary = this.seededAnchorPaths[0] || normalizeRoutePath(options.targetUrl) || options.targetUrl;
    }

    public evaluateTool(input: ScopedMissionGuardInput): ScopedMissionGuardDecision {
        if (input.toolName === 'send_http_request' || input.toolName === 'send_to_scanner' || input.toolName === 'repeater_test') {
            return this.evaluateRequestLikeTool(input);
        }

        if (input.toolName === 'browser_navigate') {
            return this.evaluateBrowserNavigation(input);
        }

        if (isBrowserActionTool(input.toolName)) {
            return this.evaluateBrowserAction(input.toolName);
        }

        return { allowed: true };
    }

    public evaluateHarvestedRequest(request: HarvestedRequest): ScopedMissionGuardDecision {
        return this.evaluateRouteAndHost({
            attemptedAction: 'harvest_traffic',
            method: request.method,
            url: request.url,
            reserveRouteVariant: false,
        });
    }

    public recordExecutedRequest(aftermath: RequestExecutionAftermath): void {
        const normalizedPath = normalizeRoutePath(aftermath.url);
        this.currentRail = 'request';
        this.activeAnchorSummary = normalizedPath || aftermath.url;
        this.currentDecisionSummary = [
            aftermath.method?.toUpperCase(),
            normalizedPath || aftermath.url,
        ].filter(Boolean).join(' ');
        this.lastRequestSummary = {
            method: aftermath.method?.toUpperCase() || null,
            path: normalizedPath || null,
            url: aftermath.url || null,
            statusCode: typeof aftermath.statusCode === 'number' ? aftermath.statusCode : null,
            summary: [
                aftermath.method?.toUpperCase(),
                normalizedPath || aftermath.url,
            ].filter(Boolean).join(' '),
        };
        this.lastResponseSummary = typeof aftermath.statusCode === 'number'
            ? `Observed HTTP ${aftermath.statusCode} from ${this.lastRequestSummary.summary}.`
            : `Observed response from ${this.lastRequestSummary.summary}.`;
        this.blockedActionReason = null;
    }

    public recordFinding(finding: any): void {
        const title = typeof finding?.name === 'string' ? finding.name.trim() : '';
        const severity = typeof finding?.severity === 'string' ? finding.severity.trim().toUpperCase() : 'MEDIUM';
        const signal = title
            ? `[${severity}] ${title}`
            : null;
        if (!signal || signal === this.lastFindingFingerprint) {
            return;
        }

        this.lastFindingFingerprint = signal;
        this.activeFindingTitle = title || this.activeFindingTitle;
        this.latestSuspiciousSignal = signal;
        this.liveFindingCount += 1;
    }

    public recordBoundaryBlock(reason: string): void {
        this.blockedActionReason = reason;
        this.currentDecisionSummary = reason;
    }

    public recordManualDecision(summary: string, rail: FocusedExecutionRail): void {
        this.currentDecisionSummary = summary;
        this.currentRail = rail;
    }

    public buildBoundarySummary(): ScopedMissionBoundarySummary {
        const maxRequests = this.options.envelope.explorationBudget?.maxRequests ?? null;
        const maxBrowserActions = this.options.envelope.explorationBudget?.maxBrowserActions ?? null;
        const maxRouteVariants = this.options.envelope.explorationBudget?.maxRouteVariants ?? null;

        return {
            allowedHosts: [...this.allowedHosts],
            allowedRoutes: [...this.allowedRoutes],
            selectedEndpointCount: this.options.envelope.selectedEndpoints.length,
            browserAnchorCount: this.options.envelope.browserAnchors.length,
            requestAnchorCount: this.options.envelope.discoveredRequestRefs.length + this.options.envelope.baselineRequestRefs.length,
            boundaryHints: [...this.options.envelope.boundaryHints],
            outOfScopeNotes: [...this.options.envelope.outOfScopeNotes],
            explorationBudget: this.options.envelope.explorationBudget ? { ...this.options.envelope.explorationBudget } : null,
            blockedActionReason: this.blockedActionReason,
            activeAnchorSummary: this.activeAnchorSummary,
            budgetState: {
                maxRequests,
                requestActionsUsed: this.requestActionsUsed,
                remainingRequests: maxRequests === null ? null : Math.max(0, maxRequests - this.requestActionsUsed),
                maxBrowserActions,
                browserActionsUsed: this.browserActionsUsed,
                remainingBrowserActions: maxBrowserActions === null ? null : Math.max(0, maxBrowserActions - this.browserActionsUsed),
                maxRouteVariants,
                routeVariantsUsed: this.variantPaths.size,
            },
        };
    }

    public buildRuntimeSummary(input: {
        missionState: string;
        targetUrl?: string | null;
    }): LiveRuntimeSummary {
        const boundarySummary = this.buildBoundarySummary();
        return {
            missionState: input.missionState,
            targetUrl: input.targetUrl || this.options.targetUrl || this.options.request.targetUrl,
            objectiveTitle: this.options.objective.title || null,
            objectiveGoal: this.options.objective.goal || null,
            requestDescription: this.options.request.description || null,
            currentRail: this.currentRail,
            activeCaseId: null,
            activeCaseTitle: this.activeAnchorSummary,
            activeFindingThreadId: null,
            activeFindingTitle: this.activeFindingTitle,
            observationSummary: this.lastResponseSummary,
            nextStepRationale: this.currentDecisionSummary,
            lastResponseDeltaSummary: this.lastResponseSummary,
            boundaryReason: this.blockedActionReason,
            lastRequestSummary: this.getLastRequestSummary(),
            latestSuspiciousSignal: this.latestSuspiciousSignal,
            currentDecisionSummary: this.getCurrentDecisionSummary(),
            liveFindingCount: this.liveFindingCount,
            boundarySummary,
        };
    }

    public getCurrentRail(): FocusedExecutionRail | null {
        return this.currentRail;
    }

    public getCurrentDecisionSummary(): string | null {
        return this.currentDecisionSummary || this.lastResponseSummary;
    }

    public getLastRequestSummary() {
        return this.lastRequestSummary ? { ...this.lastRequestSummary } : null;
    }

    public getLatestSuspiciousSignal(): string | null {
        return this.latestSuspiciousSignal;
    }

    public getActiveFindingTitle(): string | null {
        return this.activeFindingTitle;
    }

    public getObjective(): FocusedTestObjective {
        return this.options.objective;
    }

    public getRequest(): StructuredSecurityTestRequest {
        return this.options.request;
    }

    public describeBoundary(): string {
        const hostSummary = this.allowedHosts.length > 0
            ? `Allowed host${this.allowedHosts.length === 1 ? '' : 's'}: ${this.allowedHosts.join(', ')}.`
            : 'Host remains pinned to the original target origin.';
        const routeSummary = this.allowedRoutes.length > 0
            ? `Allowed route anchors: ${this.allowedRoutes.slice(0, 8).join(', ')}${this.allowedRoutes.length > 8 ? ` (+${this.allowedRoutes.length - 8} more)` : ''}.`
            : 'Route scope stays pinned to the discovered feature anchors.';
        const noteSummary = this.options.envelope.outOfScopeNotes.length > 0
            ? `Out of scope: ${this.options.envelope.outOfScopeNotes.join(' ')}`
            : 'Do not broaden to unrelated routes or endpoints.';

        return `${hostSummary} ${routeSummary} ${noteSummary}`.trim();
    }

    private evaluateRequestLikeTool(input: ScopedMissionGuardInput): ScopedMissionGuardDecision {
        const requestBudget = this.options.envelope.explorationBudget?.maxRequests ?? null;
        if (requestBudget !== null && this.requestActionsUsed >= requestBudget) {
            const reason = `Scoped request budget of ${requestBudget} has been exhausted.`;
            this.recordBoundaryBlock(reason);
            return { allowed: false, reason };
        }

        const decision = this.evaluateRouteAndHost({
            attemptedAction: input.toolName,
            method: input.method,
            url: input.url,
            useInitialRequestBaseline: input.useInitialRequestBaseline,
            reserveRouteVariant: true,
        });
        if (!decision.allowed) {
            return decision;
        }

        this.requestActionsUsed += 1;
        this.currentRail = 'request';
        this.currentDecisionSummary = [
            input.method?.toUpperCase(),
            decision.normalizedPath || input.url,
        ].filter(Boolean).join(' ');
        this.activeAnchorSummary = decision.normalizedPath || input.url || this.activeAnchorSummary;
        this.blockedActionReason = null;
        return decision;
    }

    private evaluateBrowserNavigation(input: ScopedMissionGuardInput): ScopedMissionGuardDecision {
        const browserDecision = this.evaluateBrowserAction('browser_navigate');
        if (!browserDecision.allowed) {
            return browserDecision;
        }

        const decision = this.evaluateRouteAndHost({
            attemptedAction: 'browser_navigate',
            url: input.url,
            reserveRouteVariant: true,
        });
        if (!decision.allowed) {
            return decision;
        }

        this.navigationDepth += 1;
        this.currentRail = 'browser';
        this.currentDecisionSummary = `Navigate to ${decision.normalizedPath || input.url}`;
        this.activeAnchorSummary = decision.normalizedPath || input.url || this.activeAnchorSummary;
        this.blockedActionReason = null;
        return decision;
    }

    private evaluateBrowserAction(toolName: ScopedToolName): ScopedMissionGuardDecision {
        const browserBudget = this.options.envelope.explorationBudget?.maxBrowserActions ?? null;
        if (browserBudget !== null && this.browserActionsUsed >= browserBudget) {
            const reason = `Scoped browser action budget of ${browserBudget} has been exhausted.`;
            this.recordBoundaryBlock(reason);
            return { allowed: false, reason };
        }

        const maxNavigationDepth = this.options.envelope.explorationBudget?.maxNavigationDepth ?? null;
        if (toolName === 'browser_navigate' && maxNavigationDepth !== null && this.navigationDepth >= maxNavigationDepth) {
            const reason = `Browser navigation depth exceeded the scoped limit of ${maxNavigationDepth}.`;
            this.recordBoundaryBlock(reason);
            return { allowed: false, reason };
        }

        const maxVerificationRetries = this.options.envelope.explorationBudget?.maxVerificationRetries ?? null;
        if (
            (toolName === 'browser_get_page_state' || toolName === 'browser_get_frontend_analysis')
            && maxVerificationRetries !== null
            && this.verificationRetries >= maxVerificationRetries
        ) {
            const reason = `Browser verification retry budget of ${maxVerificationRetries} has been exhausted.`;
            this.recordBoundaryBlock(reason);
            return { allowed: false, reason };
        }

        this.browserActionsUsed += 1;
        if (toolName === 'browser_get_page_state' || toolName === 'browser_get_frontend_analysis') {
            this.verificationRetries += 1;
        }
        this.currentRail = 'browser';
        this.currentDecisionSummary = formatBrowserActionSummary(toolName);
        this.blockedActionReason = null;
        return { allowed: true };
    }

    private evaluateRouteAndHost(input: {
        attemptedAction: ScopedToolName;
        method?: string;
        url?: string;
        useInitialRequestBaseline?: boolean;
        reserveRouteVariant: boolean;
    }): ScopedMissionGuardDecision {
        const normalizedHost = normalizeHost(input.url || this.options.targetUrl);
        const normalizedPath = normalizeRoutePath(input.url || this.options.targetUrl);

        if (normalizedHost && this.allowedHosts.length > 0 && !this.allowedHosts.includes(normalizedHost)) {
            const reason = `Attempted host ${normalizedHost} is outside the scoped mission boundary.`;
            this.recordBoundaryBlock(reason);
            return {
                allowed: false,
                normalizedHost,
                normalizedPath,
                reason,
            };
        }

        const matchedRoute = normalizedPath
            ? this.allowedRoutes.find((route) => routeMatches(route, normalizedPath))
            : undefined;
        if (normalizedPath && this.allowedRoutes.length > 0 && !matchedRoute) {
            const reason = `Attempted path ${normalizedPath} is outside the allowed scoped routes.`;
            this.recordBoundaryBlock(reason);
            return {
                allowed: false,
                normalizedHost,
                normalizedPath,
                reason,
            };
        }

        if (
            this.options.objective.scopeType === 'request_scoped'
            && this.baselinePaths.length > 0
            && input.useInitialRequestBaseline === false
            && normalizedPath
            && !this.baselinePaths.some((baselinePath) => routeMatches(baselinePath, normalizedPath))
        ) {
            const reason = 'Request-scoped missions must stay anchored to the Burp baseline request path.';
            this.recordBoundaryBlock(reason);
            return {
                allowed: false,
                normalizedHost,
                normalizedPath,
                reason,
            };
        }

        if (input.reserveRouteVariant && normalizedPath && matchedRoute && matchedRoute !== normalizedPath) {
            const variantBudget = this.options.envelope.explorationBudget?.maxRouteVariants ?? null;
            if (!this.seededAnchorPaths.includes(normalizedPath) && !this.variantPaths.has(normalizedPath)) {
                if (variantBudget !== null && this.variantPaths.size >= variantBudget) {
                    const reason = `Scoped route-variant budget of ${variantBudget} has been exhausted.`;
                    this.recordBoundaryBlock(reason);
                    return {
                        allowed: false,
                        normalizedHost,
                        normalizedPath,
                        reason,
                    };
                }
                this.variantPaths.add(normalizedPath);
            }
        }

        return {
            allowed: true,
            normalizedHost,
            normalizedPath,
        };
    }
}

function isBrowserActionTool(toolName: ScopedToolName): boolean {
    return [
        'browser_fill_and_submit',
        'browser_get_page_state',
        'browser_get_frontend_analysis',
        'browser_evaluate_js',
        'browser_screenshot',
        'browser_correlate_burp',
    ].includes(toolName);
}

function formatBrowserActionSummary(toolName: ScopedToolName): string {
    switch (toolName) {
        case 'browser_fill_and_submit':
            return 'Advance the current scoped browser workflow.';
        case 'browser_get_page_state':
            return 'Inspect the current scoped browser state.';
        case 'browser_get_frontend_analysis':
            return 'Inspect the current scoped frontend surface.';
        case 'browser_evaluate_js':
            return 'Evaluate scoped in-page JavaScript.';
        case 'browser_screenshot':
            return 'Capture scoped browser evidence.';
        case 'browser_correlate_burp':
            return 'Correlate current browser observations with in-scope Burp traffic.';
        default:
            return 'Continue the scoped browser rail.';
    }
}
