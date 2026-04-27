import { v4 as uuidv4 } from 'uuid';
import { browserService, type PageState } from '../BrowserService';
import {
    getFocusedTestObjective,
    getScan,
    getScanEndpointInventory,
    getScopeEnvelope,
    getScopedFeatureDiscoveryState,
    getScopedTestRequest,
    getSourceAnalysisResult,
    updateFocusedTestObjective,
    updateScopeEnvelope,
    updateScanStatus,
    updateScopedFeatureDiscoveryState,
} from '../../db/init';
import { logger } from '../../utils/logger';
import type { EndpointInventorySnapshot } from '../EndpointIntelligenceService';
import type { FullSourceAnalysisResult, SourceAnalysisResult } from '../source-analysis/SourceAnalysisMode';
import { isFullSourceResult } from '../source-analysis/SourceAnalysisMode';
import type {
    DiscoveredRequestRef,
    FocusedTestObjective,
    ScopeEnvelope,
    ScopedBrowserAnchorRef,
    ScopedFeatureDiscoveryOutcome,
    ScopedFeatureDiscoveryState,
    SelectedScopedEndpoint,
    StructuredSecurityTestRequest,
} from './ScopedScanTypes';
import { focusedAnchoringProfileResolver, type FocusedAnchoringProfileResolver } from './FocusedAnchoringProfiles';
import { buildFocusedContextInfluence, focusedReasoningTraceService } from './FocusedReasoningTraceService';

interface FeatureAnchoringDependencies {
    getScanById: typeof getScan;
    getObjectiveByScanId: typeof getFocusedTestObjective;
    getEnvelopeByScanId: typeof getScopeEnvelope;
    getStructuredRequestByScanId: typeof getScopedTestRequest;
    getDiscoveryStateByScanId: typeof getScopedFeatureDiscoveryState;
    getEndpointInventoryByScanId: typeof getScanEndpointInventory;
    getSourceAnalysisResultByScanId: typeof getSourceAnalysisResult;
    updateObjectiveByScanId: typeof updateFocusedTestObjective;
    updateEnvelopeByScanId: typeof updateScopeEnvelope;
    updateDiscoveryStateByScanId: typeof updateScopedFeatureDiscoveryState;
    updateScanStatusById: typeof updateScanStatus;
    launchBrowserSession: typeof browserService.launchSession;
    getFullPageState: typeof browserService.getFullPageState;
    closeBrowserSession: typeof browserService.closeSession;
    profileResolver: FocusedAnchoringProfileResolver;
    planningLauncher: {
        launchPlanning(scanId: string): void;
    };
    createId: () => string;
    now: () => string;
}

interface AnchorCandidate<T> {
    score: number;
    value: T;
}

export interface FeatureAnchoringResult {
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
    discovery: ScopedFeatureDiscoveryState;
}

const MAX_DISCOVERED_REQUEST_REFS = 6;
const MAX_DISCOVERED_ENDPOINTS = 6;
const MAX_DISCOVERED_BROWSER_ANCHORS = 4;
const MAX_ALLOWED_ROUTES = 12;

export class FeatureAnchoringService {
    private readonly activeDiscoveries = new Map<string, Promise<FeatureAnchoringResult>>();
    private readonly deps: FeatureAnchoringDependencies;

    constructor(
        deps: Partial<FeatureAnchoringDependencies> = {},
    ) {
        this.deps = {
            getScanById: getScan,
            getObjectiveByScanId: getFocusedTestObjective,
            getEnvelopeByScanId: getScopeEnvelope,
            getStructuredRequestByScanId: getScopedTestRequest,
            getDiscoveryStateByScanId: getScopedFeatureDiscoveryState,
            getEndpointInventoryByScanId: getScanEndpointInventory,
            getSourceAnalysisResultByScanId: getSourceAnalysisResult,
            updateObjectiveByScanId: updateFocusedTestObjective,
            updateEnvelopeByScanId: updateScopeEnvelope,
            updateDiscoveryStateByScanId: updateScopedFeatureDiscoveryState,
            updateScanStatusById: updateScanStatus,
            launchBrowserSession: browserService.launchSession.bind(browserService),
            getFullPageState: browserService.getFullPageState.bind(browserService),
            closeBrowserSession: browserService.closeSession.bind(browserService),
            profileResolver: focusedAnchoringProfileResolver,
            planningLauncher: {
                launchPlanning: () => {
                    throw new Error('Focused planning launcher not configured');
                },
            },
            createId: () => uuidv4(),
            now: () => new Date().toISOString(),
            ...deps,
        };
    }

    public launchDiscovery(scanId: string): void {
        void this.discoverNow(scanId).catch((error: any) => {
            logger.error('Scoped feature discovery job failed', {
                scanId,
                error: error.message,
            });
        });
    }

    public discoverNow(scanId: string): Promise<FeatureAnchoringResult> {
        const existing = this.activeDiscoveries.get(scanId);
        if (existing) {
            return existing;
        }

        const pending = this.executeDiscovery(scanId)
            .finally(() => {
                this.activeDiscoveries.delete(scanId);
            });
        this.activeDiscoveries.set(scanId, pending);
        return pending;
    }

    private async executeDiscovery(scanId: string): Promise<FeatureAnchoringResult> {
        const scan = this.deps.getScanById(scanId);
        const objective = this.deps.getObjectiveByScanId(scanId);
        const envelope = this.deps.getEnvelopeByScanId(scanId);
        const securityTestRequest = this.deps.getStructuredRequestByScanId(scanId);

        if (!scan || !objective || !envelope || !securityTestRequest) {
            throw new Error(`Feature anchoring could not load persisted scoped request data for scan ${scanId}.`);
        }

        const startedAt = this.deps.now();
        this.deps.updateScanStatusById(scanId, 'scoped_discovering');
        this.deps.updateDiscoveryStateByScanId(scanId, {
            phase: 'discovering',
            outcome: null,
            summary: 'Bounded feature discovery is inspecting the request URL and nearby feature signals.',
            errorMessage: null,
            startedAt,
            completedAt: null,
        });
        const anchoringContextInfluence = buildAnchoringContextInfluence(securityTestRequest);
        focusedReasoningTraceService.record({
            scanId,
            objectiveId: objective.id,
            stage: 'feature_discovery',
            entryType: 'observation',
            rail: 'system_only',
            summary: 'Bounded feature discovery started from the scoped request target and nearby same-origin anchors.',
            observationSummary: `Starting from ${securityTestRequest.targetUrl} with persisted scope boundaries and optional request context.`,
            actionSelectionRationale: 'Discovery remains constrained to the structured request target, same-origin candidates, and persisted scope envelope.',
            linkedRequestContextKeys: anchoringContextInfluence.map((entry) => entry.field),
            contextInfluence: anchoringContextInfluence,
        });

        try {
            const profile = this.deps.profileResolver.resolve(scan.user_id);
            const signals = profile.buildSignals({
                targetUrl: securityTestRequest.targetUrl,
                request: securityTestRequest,
                objectiveTitle: objective.title,
            });
            const targetHost = safeHost(securityTestRequest.targetUrl);
            const targetPath = normalizeRoutePath(securityTestRequest.targetUrl) || '/';
            const requestMethod = parseInitialRequestMethod(scan.initial_request) || 'GET';

            const requestCandidates: AnchorCandidate<DiscoveredRequestRef>[] = [];
            const endpointCandidates: AnchorCandidate<SelectedScopedEndpoint>[] = [];
            const browserCandidates: AnchorCandidate<ScopedBrowserAnchorRef>[] = [];

            const seedRequestRef: DiscoveredRequestRef = {
                id: this.deps.createId(),
                source: 'request_url',
                method: requestMethod,
                url: securityTestRequest.targetUrl,
                host: targetHost || undefined,
                path: targetPath,
                label: `${requestMethod} ${targetPath}`,
                matchReason: 'Target URL from structured security test request.',
            };
            requestCandidates.push({
                score: 1.6,
                value: seedRequestRef,
            });
            endpointCandidates.push({
                score: 1.4,
                value: {
                    method: requestMethod,
                    path: targetPath,
                    url: securityTestRequest.targetUrl,
                    host: targetHost || undefined,
                    source: 'request_intake',
                    notes: ['Derived directly from the structured request target URL.'],
                },
            });
            browserCandidates.push({
                score: 1.2,
                value: {
                    id: this.deps.createId(),
                    startUrl: securityTestRequest.targetUrl,
                    startPath: targetPath,
                    source: 'request_url',
                    label: objective.featureDescription || objective.title,
                    matchReason: 'Start browser anchoring from the request URL.',
                },
            });

            const endpointInventory = this.deps.getEndpointInventoryByScanId(scanId) as EndpointInventorySnapshot | null;
            if (endpointInventory?.records?.length) {
                for (const record of endpointInventory.records) {
                    if (!isSameHost(record.endpoint, targetHost)) {
                        continue;
                    }

                    const score = scoreCandidate({
                        candidatePath: record.path || record.endpoint,
                        candidateText: `${record.endpoint} ${record.path} ${(record.notes || []).join(' ')} ${(record.evidence || []).join(' ')}`,
                        targetPath,
                        signals,
                        sourceWeight: 0.78,
                    });
                    if (score < 0.8) {
                        continue;
                    }

                    const normalizedPath = normalizeRoutePath(record.path || record.endpoint);
                    const normalizedUrl = normalizeUrl(record.endpoint);
                    if (normalizedPath) {
                        endpointCandidates.push({
                            score,
                            value: {
                                method: String(record.methods?.[0] || 'GET').toUpperCase(),
                                path: normalizedPath,
                                url: normalizedUrl,
                                host: safeHost(record.endpoint) || undefined,
                                source: 'endpoint_inventory',
                                notes: dedupeStrings([
                                    record.classification ? `Endpoint intelligence: ${record.classification}` : undefined,
                                    ...(record.notes || []),
                                ]),
                            },
                        });
                    }

                    requestCandidates.push({
                        score,
                        value: {
                            id: this.deps.createId(),
                            source: 'endpoint_inventory',
                            method: String(record.methods?.[0] || 'GET').toUpperCase(),
                            url: normalizedUrl,
                            host: safeHost(record.endpoint) || undefined,
                            path: normalizedPath,
                            statusCode: Array.isArray(record.observedStatusCodes) && record.observedStatusCodes.length > 0
                                ? Number(record.observedStatusCodes[0])
                                : undefined,
                            label: normalizedPath ? `${String(record.methods?.[0] || 'GET').toUpperCase()} ${normalizedPath}` : normalizedUrl || undefined,
                            matchReason: dedupeStrings([
                                record.classification ? `endpoint inventory ${record.classification}` : undefined,
                                record.observedInBurp ? 'observed in Burp' : undefined,
                                record.exercisedInBrowser ? 'exercised in browser' : undefined,
                            ]).join(', ') || 'Matched endpoint inventory signal.',
                        },
                    });
                }
            }

            const sourceAnalysis = this.deps.getSourceAnalysisResultByScanId(scanId) as SourceAnalysisResult | null;
            if (sourceAnalysis && isFullSourceResult(sourceAnalysis)) {
                this.addSourceAnalysisAnchors(sourceAnalysis, {
                    targetPath,
                    targetHost,
                    signals,
                    requestCandidates,
                    endpointCandidates,
                    browserCandidates,
                });
            }

            const browserPageState = await this.tryInspectBrowserSurface(scan.user_id, securityTestRequest.targetUrl);
            if (browserPageState) {
                this.addBrowserAnchors(browserPageState, {
                    targetPath,
                    targetHost,
                    signals,
                    browserCandidates,
                    endpointCandidates,
                });
            }

            const discoveredRequestRefs = dedupeRequestRefs(requestCandidates)
                .slice(0, MAX_DISCOVERED_REQUEST_REFS);
            const selectedEndpoints = dedupeEndpoints([
                ...envelope.selectedEndpoints,
                ...dedupeCandidates(endpointCandidates).slice(0, MAX_DISCOVERED_ENDPOINTS),
            ]);
            const browserAnchors = dedupeBrowserAnchors(browserCandidates)
                .slice(0, MAX_DISCOVERED_BROWSER_ANCHORS);
            const allowedRoutes = dedupeStrings([
                ...envelope.allowedRoutes,
                ...selectedEndpoints.map((entry) => normalizeRoutePath(entry.path)),
                ...discoveredRequestRefs.map((entry) => normalizeRoutePath(entry.path || entry.url)),
                ...browserAnchors.map((entry) => normalizeRoutePath(entry.startPath || entry.startUrl)),
            ]).slice(0, MAX_ALLOWED_ROUTES);

            const updatedEnvelope = this.deps.updateEnvelopeByScanId(scanId, {
                allowedRoutes,
                selectedEndpoints,
                discoveredRequestRefs,
                browserAnchors,
            }) || {
                ...envelope,
                allowedRoutes,
                selectedEndpoints,
                discoveredRequestRefs,
                browserAnchors,
            };

            const upgradedScopeType = resolveDiscoveredScopeType(updatedEnvelope);
            const updatedObjective = this.deps.updateObjectiveByScanId(scanId, {
                scopeType: upgradedScopeType,
                featureDescription: objective.featureDescription || securityTestRequest.description,
                goal: objective.goal || `Anchor and test the requested feature area starting from ${securityTestRequest.targetUrl}.`,
            }) || {
                ...objective,
                scopeType: upgradedScopeType,
            };

            const requestAnchorCount = discoveredRequestRefs.length + updatedEnvelope.baselineRequestRefs.length;
            const browserAnchorCount = browserAnchors.length;
            const selectedEndpointCount = selectedEndpoints.length;
            const allowedRouteCount = allowedRoutes.length;

            const hasStrongAnchors = selectedEndpointCount > 1 || requestAnchorCount > 1;
            const hasAnyAnchors = requestAnchorCount > 0 || browserAnchorCount > 0 || selectedEndpointCount > 0;
            const outcome: ScopedFeatureDiscoveryOutcome | null = !hasAnyAnchors
                ? 'no_useful_anchors'
                : hasStrongAnchors
                    ? 'candidate_anchors_found'
                    : 'partial_anchors_found';
            const phase = hasAnyAnchors ? 'ready_to_plan' : 'blocked';
            const summary = hasAnyAnchors
                ? `Anchored ${selectedEndpointCount} endpoint(s), ${requestAnchorCount} request reference(s), and ${browserAnchorCount} browser start point(s) from the structured request.`
                : 'Bounded discovery did not find enough same-origin anchors beyond the submitted URL.';

            const discovery = this.deps.updateDiscoveryStateByScanId(scanId, {
                phase,
                outcome,
                summary,
                errorMessage: null,
                requestAnchorCount,
                browserAnchorCount,
                selectedEndpointCount,
                allowedRouteCount,
                completedAt: this.deps.now(),
            });

            if (phase === 'ready_to_plan') {
                this.deps.planningLauncher.launchPlanning(scanId);
            } else {
                this.deps.updateScanStatusById(scanId, 'scoped_discovering', summary);
            }

            logger.info('Scoped feature discovery completed', {
                scanId,
                phase,
                outcome,
                selectedEndpointCount,
                requestAnchorCount,
                browserAnchorCount,
            });
            focusedReasoningTraceService.record({
                scanId,
                objectiveId: objective.id,
                stage: 'feature_discovery',
                entryType: hasAnyAnchors ? 'result' : 'constraint',
                rail: 'system_only',
                summary,
                observationSummary: [
                    selectedEndpointCount > 0 ? `${selectedEndpointCount} endpoint anchor(s)` : null,
                    requestAnchorCount > 0 ? `${requestAnchorCount} request reference(s)` : null,
                    browserAnchorCount > 0 ? `${browserAnchorCount} browser start point(s)` : null,
                ].filter((entry): entry is string => !!entry).join(' | ') || 'No same-origin anchors were retained beyond the submitted request URL.',
                actionSelectionRationale: hasAnyAnchors
                    ? 'Planning can proceed because bounded discovery retained concrete in-scope anchors.'
                    : 'Planning stayed blocked because discovery could not retain enough in-scope anchors without widening scope.',
                stopRetryBlockRationale: hasAnyAnchors ? null : 'Bounded discovery stopped before planning because anchor quality was too weak to justify broader follow-up behavior.',
                linkedRequestContextKeys: anchoringContextInfluence.map((entry) => entry.field),
                contextInfluence: anchoringContextInfluence,
            });

            return {
                objective: updatedObjective as FocusedTestObjective,
                envelope: updatedEnvelope as ScopeEnvelope,
                discovery: discovery as ScopedFeatureDiscoveryState,
            };
        } catch (error: any) {
            const summary = error.message || 'Feature discovery failed.';
            const discovery = this.deps.updateDiscoveryStateByScanId(scanId, {
                phase: 'blocked',
                outcome: 'no_useful_anchors',
                summary,
                errorMessage: summary,
                completedAt: this.deps.now(),
            });
            this.deps.updateScanStatusById(scanId, 'scoped_discovering', summary);
            focusedReasoningTraceService.record({
                scanId,
                objectiveId: objective.id,
                stage: 'feature_discovery',
                entryType: 'constraint',
                rail: 'system_only',
                summary: 'Feature discovery stopped before planning.',
                observationSummary: summary,
                stopRetryBlockRationale: summary,
                linkedRequestContextKeys: anchoringContextInfluence.map((entry) => entry.field),
                contextInfluence: anchoringContextInfluence,
            });
            throw Object.assign(error, {
                discovery,
            });
        }
    }

    private addSourceAnalysisAnchors(
        sourceAnalysis: FullSourceAnalysisResult,
        input: {
            targetPath: string;
            targetHost: string | null;
            signals: Array<{ phrase: string; weight: number }>;
            requestCandidates: AnchorCandidate<DiscoveredRequestRef>[];
            endpointCandidates: AnchorCandidate<SelectedScopedEndpoint>[];
            browserCandidates: AnchorCandidate<ScopedBrowserAnchorRef>[];
        },
    ): void {
        for (const endpoint of sourceAnalysis.endpoints || []) {
            const score = scoreCandidate({
                candidatePath: endpoint.path,
                candidateText: `${endpoint.method} ${endpoint.path} ${endpoint.description} ${(endpoint.userInputs || []).join(' ')}`,
                targetPath: input.targetPath,
                signals: input.signals,
                sourceWeight: 0.7,
            });
            if (score < 0.85) {
                continue;
            }

            const normalizedPath = normalizeRoutePath(endpoint.path);
            if (!normalizedPath) {
                continue;
            }

            input.endpointCandidates.push({
                score,
                value: {
                    method: endpoint.method.toUpperCase(),
                    path: normalizedPath,
                    url: undefined,
                    host: input.targetHost || undefined,
                    source: 'source_analysis',
                    notes: dedupeStrings([
                        endpoint.description,
                        endpoint.authRequired ? 'Source analysis marked the route as authenticated.' : undefined,
                    ]),
                },
            });
            input.requestCandidates.push({
                score,
                value: {
                    id: uuidv4(),
                    source: 'source_analysis',
                    method: endpoint.method.toUpperCase(),
                    path: normalizedPath,
                    host: input.targetHost || undefined,
                    label: `${endpoint.method.toUpperCase()} ${normalizedPath}`,
                    matchReason: endpoint.description || 'Matched source analysis endpoint.',
                },
            });
        }

        for (const flow of sourceAnalysis.securityFlows || []) {
            const score = scoreCandidate({
                candidatePath: flow.description,
                candidateText: `${flow.category} ${flow.description} ${flow.components.join(' ')}`,
                targetPath: input.targetPath,
                signals: input.signals,
                sourceWeight: 0.55,
            });
            if (score < 0.85) {
                continue;
            }

            input.browserCandidates.push({
                score,
                value: {
                    id: uuidv4(),
                    startUrl: buildAbsoluteUrl(input.targetHost, input.targetPath),
                    startPath: input.targetPath,
                    source: 'source_analysis',
                    label: flow.description,
                    matchReason: `Source analysis flow: ${flow.category}`,
                },
            });
        }
    }

    private addBrowserAnchors(
        pageState: PageState,
        input: {
            targetPath: string;
            targetHost: string | null;
            signals: Array<{ phrase: string; weight: number }>;
            browserCandidates: AnchorCandidate<ScopedBrowserAnchorRef>[];
            endpointCandidates: AnchorCandidate<SelectedScopedEndpoint>[];
        },
    ): void {
        for (const link of pageState.links.slice(0, 8)) {
            const normalizedUrl = normalizeUrl(link.href);
            if (!normalizedUrl || !isSameHost(normalizedUrl, input.targetHost)) {
                continue;
            }

            const normalizedPath = normalizeRoutePath(normalizedUrl);
            const score = scoreCandidate({
                candidatePath: normalizedPath,
                candidateText: `${normalizedUrl} ${link.text}`,
                targetPath: input.targetPath,
                signals: input.signals,
                sourceWeight: 0.58,
            });
            if (score < 0.75 || !normalizedPath) {
                continue;
            }

            input.browserCandidates.push({
                score,
                value: {
                    id: uuidv4(),
                    startUrl: normalizedUrl,
                    startPath: normalizedPath,
                    source: 'page_link',
                    label: link.text || normalizedPath,
                    matchReason: 'Bounded browser page link near the requested feature area.',
                },
            });
        }

        for (const form of pageState.forms.slice(0, 6)) {
            const normalizedUrl = normalizeUrl(form.action);
            if (!normalizedUrl || !isSameHost(normalizedUrl, input.targetHost)) {
                continue;
            }

            const normalizedPath = normalizeRoutePath(normalizedUrl);
            const score = scoreCandidate({
                candidatePath: normalizedPath,
                candidateText: `${normalizedUrl} ${form.method} ${(form.fields || []).map((field) => field.name || field.id).join(' ')}`,
                targetPath: input.targetPath,
                signals: input.signals,
                sourceWeight: 0.62,
            });
            if (score < 0.8 || !normalizedPath) {
                continue;
            }

            input.browserCandidates.push({
                score,
                value: {
                    id: uuidv4(),
                    startUrl: normalizedUrl,
                    startPath: normalizedPath,
                    source: 'page_form',
                    label: `Form ${form.method.toUpperCase()} ${normalizedPath}`,
                    matchReason: 'Bounded browser form action near the requested feature area.',
                },
            });
            input.endpointCandidates.push({
                score,
                value: {
                    method: String(form.method || 'GET').toUpperCase(),
                    path: normalizedPath,
                    url: normalizedUrl,
                    host: safeHost(normalizedUrl) || undefined,
                    source: 'browser_discovery',
                    notes: ['Derived from bounded browser form inspection.'],
                },
            });
        }
    }

    private async tryInspectBrowserSurface(userId: number, targetUrl: string): Promise<PageState | null> {
        let sessionId: string | null = null;
        try {
            sessionId = await this.deps.launchBrowserSession(userId, {
                targetUrl,
                headless: true,
            });
            return await this.deps.getFullPageState(sessionId);
        } catch (error: any) {
            logger.warn('Bounded browser feature discovery fell back to deterministic anchors', {
                targetUrl,
                error: error.message,
            });
            return null;
        } finally {
            if (sessionId) {
                try {
                    await this.deps.closeBrowserSession(sessionId);
                } catch {
                    // ignore cleanup failures
                }
            }
        }
    }
}

function scoreCandidate(input: {
    candidatePath?: string | null;
    candidateText?: string | null;
    targetPath: string;
    signals: Array<{ phrase: string; weight: number }>;
    sourceWeight: number;
}): number {
    const normalizedPath = normalizeRoutePath(input.candidatePath);
    let score = input.sourceWeight;

    if (normalizedPath) {
        if (normalizedPath === input.targetPath) {
            score += 0.8;
        } else if (normalizedPath.startsWith(input.targetPath) || input.targetPath.startsWith(normalizedPath)) {
            score += 0.45;
        } else if (firstPathSegment(normalizedPath) && firstPathSegment(normalizedPath) === firstPathSegment(input.targetPath)) {
            score += 0.25;
        }
    }

    const haystack = `${normalizedPath || ''} ${String(input.candidateText || '').toLowerCase()}`;
    let signalScore = 0;
    for (const signal of input.signals) {
        if (haystack.includes(signal.phrase)) {
            signalScore += Math.min(signal.weight, 0.2);
        }
    }

    return Number((score + Math.min(signalScore, 0.6)).toFixed(2));
}

function resolveDiscoveredScopeType(envelope: ScopeEnvelope): FocusedTestObjective['scopeType'] {
    if (envelope.baselineRequestRefs.length > 0) {
        return 'request_scoped';
    }
    if (envelope.selectedEndpoints.length > 0 || envelope.discoveredRequestRefs.length > 0) {
        return 'endpoint_scoped';
    }
    if (envelope.browserAnchors.length > 0) {
        return 'flow_scoped';
    }
    return 'feature_scoped';
}

function dedupeRequestRefs(candidates: AnchorCandidate<DiscoveredRequestRef>[]): DiscoveredRequestRef[] {
    const deduped = new Map<string, AnchorCandidate<DiscoveredRequestRef>>();
    for (const candidate of candidates) {
        const key = [
            String(candidate.value.method || 'GET').toUpperCase(),
            normalizeRoutePath(candidate.value.path || candidate.value.url) || normalizeUrl(candidate.value.url) || candidate.value.id,
        ].join(':');
        const existing = deduped.get(key);
        if (!existing || candidate.score > existing.score) {
            deduped.set(key, candidate);
        }
    }

    return [...deduped.values()]
        .sort((left, right) => right.score - left.score)
        .map((candidate) => candidate.value);
}

function dedupeEndpoints(entries: SelectedScopedEndpoint[]): SelectedScopedEndpoint[] {
    const deduped = new Map<string, SelectedScopedEndpoint>();
    for (const entry of entries) {
        const path = normalizeRoutePath(entry.path || entry.url);
        if (!path) {
            continue;
        }
        const method = String(entry.method || 'GET').toUpperCase();
        const key = `${method}:${path}`;
        deduped.set(key, {
            ...entry,
            method,
            path,
            url: normalizeUrl(entry.url),
            host: safeHost(entry.host || entry.url) || entry.host,
            notes: dedupeStrings(entry.notes || []),
        });
    }
    return [...deduped.values()];
}

function dedupeCandidates(candidates: AnchorCandidate<SelectedScopedEndpoint>[]): SelectedScopedEndpoint[] {
    const deduped = new Map<string, AnchorCandidate<SelectedScopedEndpoint>>();
    for (const candidate of candidates) {
        const path = normalizeRoutePath(candidate.value.path || candidate.value.url);
        if (!path) {
            continue;
        }
        const method = String(candidate.value.method || 'GET').toUpperCase();
        const key = `${method}:${path}`;
        const existing = deduped.get(key);
        if (!existing || candidate.score > existing.score) {
            deduped.set(key, {
                score: candidate.score,
                value: {
                    ...candidate.value,
                    method,
                    path,
                    url: normalizeUrl(candidate.value.url),
                    host: safeHost(candidate.value.host || candidate.value.url) || candidate.value.host,
                    notes: dedupeStrings(candidate.value.notes || []),
                },
            });
        }
    }

    return [...deduped.values()]
        .sort((left, right) => right.score - left.score)
        .map((candidate) => candidate.value);
}

function dedupeBrowserAnchors(candidates: AnchorCandidate<ScopedBrowserAnchorRef>[]): ScopedBrowserAnchorRef[] {
    const deduped = new Map<string, AnchorCandidate<ScopedBrowserAnchorRef>>();
    for (const candidate of candidates) {
        const key = normalizeUrl(candidate.value.startUrl)
            || normalizeRoutePath(candidate.value.startPath || candidate.value.startUrl)
            || candidate.value.id;
        const existing = deduped.get(key);
        if (!existing || candidate.score > existing.score) {
            deduped.set(key, {
                score: candidate.score,
                value: {
                    ...candidate.value,
                    startUrl: normalizeUrl(candidate.value.startUrl) || candidate.value.startUrl,
                    startPath: normalizeRoutePath(candidate.value.startPath || candidate.value.startUrl),
                },
            });
        }
    }

    return [...deduped.values()]
        .sort((left, right) => right.score - left.score)
        .map((candidate) => candidate.value);
}

function normalizeUrl(value: string | null | undefined): string | undefined {
    if (!value) {
        return undefined;
    }
    try {
        return new URL(value).toString();
    } catch {
        return undefined;
    }
}

function normalizeRoutePath(value: string | null | undefined): string | undefined {
    if (!value) {
        return undefined;
    }

    try {
        if (/^https?:\/\//i.test(value)) {
            return new URL(value).pathname || '/';
        }
    } catch {
        return undefined;
    }

    const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
    if (!withoutQuery) {
        return undefined;
    }
    return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
}

function safeHost(value: string | null | undefined): string | null {
    if (!value) {
        return null;
    }
    try {
        if (/^https?:\/\//i.test(value)) {
            return new URL(value).host.toLowerCase();
        }
    } catch {
        return null;
    }
    return String(value).trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '') || null;
}

function isSameHost(candidateUrl: string | null | undefined, targetHost: string | null): boolean {
    if (!candidateUrl || !targetHost) {
        return false;
    }
    return safeHost(candidateUrl) === targetHost;
}

function buildAbsoluteUrl(host: string | null, path: string | null | undefined): string {
    if (!host) {
        return normalizeRoutePath(path) || '/';
    }
    return `https://${host}${normalizeRoutePath(path) || '/'}`;
}

function firstPathSegment(path: string): string | null {
    const segment = path.split('/').map((entry) => entry.trim()).filter(Boolean)[0];
    return segment || null;
}

function parseInitialRequestMethod(initialRequest?: string | null): string | null {
    if (!initialRequest?.trim()) {
        return null;
    }
    const firstLine = initialRequest.trim().split(/\r?\n/)[0] || '';
    const method = firstLine.split(/\s+/)[0] || '';
    return /^[A-Z]+$/.test(method) ? method.toUpperCase() : null;
}

function dedupeStrings(values: Array<string | undefined>): string[] {
    return [...new Set(values.filter((entry): entry is string => !!entry))];
}

function buildAnchoringContextInfluence(request: StructuredSecurityTestRequest) {
    const influences = [
        ...(request.authMechanismHints.length > 0 ? [buildFocusedContextInfluence(
            'authMechanismHints',
            'used',
            'Authentication hints were included when ranking same-origin anchor candidates.',
        )] : []),
        ...(request.testData.length > 0 ? [buildFocusedContextInfluence(
            'testData',
            'used',
            'Named test data was used as an anchoring hint while matching nearby routes and forms.',
        )] : []),
        ...(request.testUsers.length > 0 ? [buildFocusedContextInfluence(
            'testUsers',
            'used',
            'Provided user references were included in bounded anchor-selection signals.',
        )] : []),
        ...(request.attachmentSummary ? [buildFocusedContextInfluence(
            'attachmentSummary',
            'used',
            'Attachment notes were included in bounded anchor-matching signals.',
        )] : []),
        ...(request.attachmentMetadata.length > 0 ? [buildFocusedContextInfluence(
            'attachmentMetadata',
            'used',
            'Attachment metadata labels and notes were retained as discovery hints when present.',
        )] : []),
        ...(request.operatorNotes ? [buildFocusedContextInfluence(
            'operatorNotes',
            'used',
            'Operator notes were used to bias discovery toward the requested feature area.',
        )] : []),
        ...(typeof request.newScreenCount === 'number' && request.newScreenCount > 0 ? [buildFocusedContextInfluence(
            'newScreenCount',
            'insufficient',
            'Screen counts were persisted for context, but they did not identify a concrete browser anchor by themselves.',
        )] : []),
        ...(typeof request.newInputCount === 'number' && request.newInputCount > 0 ? [buildFocusedContextInfluence(
            'newInputCount',
            'insufficient',
            'Input counts were persisted for context, but they were not enough to justify a broader bounded anchor set.',
        )] : []),
    ];

    return influences;
}

export const featureAnchoringService = new FeatureAnchoringService();
