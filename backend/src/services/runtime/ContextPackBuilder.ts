import {
    getFocusedTestObjective,
    getScan,
    getScanAuthInventory,
    getScanConfig,
    getScanEndpointInventory,
    getScopedFeatureDiscoveryState,
    getScopedTestRequest,
    getScopeEnvelope,
    getSourceAnalysisResult,
} from '../../db/init';
import type { EndpointInventorySnapshot } from '../EndpointIntelligenceService';
import type { AuthStartupInventory } from '../auth';
import { analyzeSource } from '../source-analysis/SourceAnalysisService';
import {
    isFullSourceResult,
    SourceAnalysisMode,
    SourceAnalysisResult,
} from '../source-analysis/SourceAnalysisMode';
import { logger } from '../../utils/logger';
import type {
    BaselineRequestRef,
    ContextPack,
    ContextPackAuthSummary,
    ContextPackEndpointIntelligenceRecordSummary,
    ContextPackEndpointIntelligenceSummary,
    ContextPackSelectedTarget,
    ContextPackSourceAnalysisSummary,
    FocusedTestObjective,
    ScopeEnvelope,
    ScopedTargetType,
    SelectedScopedEndpoint,
} from './ScopedScanTypes';
import {
    CONTEXT_PACK_SCHEMA_VERSION,
} from './ScopedScanTypes';

interface ScanLikeRecord {
    id: string;
    target: string;
    user_id: number;
    source_package_path?: string | null;
    source_analysis_mode?: string | null;
}

interface ContextPackBuilderDependencies {
    getScanById: typeof getScan;
    getObjectiveByScanId: typeof getFocusedTestObjective;
    getEnvelopeByScanId: typeof getScopeEnvelope;
    getStructuredRequestByScanId: typeof getScopedTestRequest;
    getFeatureDiscoveryStateByScanId: typeof getScopedFeatureDiscoveryState;
    getScanConfigById: typeof getScanConfig;
    getScanAuthInventoryById: typeof getScanAuthInventory;
    getScanEndpointInventoryById: typeof getScanEndpointInventory;
    getSourceAnalysisResultById: typeof getSourceAnalysisResult;
    analyzeSourceCode: typeof analyzeSource;
}

const MAX_ENDPOINT_INTELLIGENCE_RECORDS = 6;
const MAX_SOURCE_ENDPOINTS = 6;
const MAX_SOURCE_HINTS = 6;
const MAX_SOURCE_FLOWS = 4;

const MAX_CASES_BY_SCOPE: Record<ScopedTargetType, number> = {
    request_scoped: 5,
    endpoint_scoped: 8,
    flow_scoped: 8,
    feature_scoped: 8,
};

export class ContextPackBuilder {
    constructor(
        deps: Partial<ContextPackBuilderDependencies> = {},
    ) {
        this.deps = {
            getScanById: getScan,
            getObjectiveByScanId: getFocusedTestObjective,
            getEnvelopeByScanId: getScopeEnvelope,
            getStructuredRequestByScanId: getScopedTestRequest,
            getFeatureDiscoveryStateByScanId: getScopedFeatureDiscoveryState,
            getScanConfigById: getScanConfig,
            getScanAuthInventoryById: getScanAuthInventory,
            getScanEndpointInventoryById: getScanEndpointInventory,
            getSourceAnalysisResultById: getSourceAnalysisResult,
            analyzeSourceCode: analyzeSource,
            ...deps,
        };
    }

    private readonly deps: ContextPackBuilderDependencies;

    public async build(scanId: string): Promise<ContextPack> {
        const scan = this.deps.getScanById(scanId) as ScanLikeRecord | undefined;
        const objective = this.deps.getObjectiveByScanId(scanId);
        const envelope = this.deps.getEnvelopeByScanId(scanId);

        if (!scan || !objective || !envelope) {
            throw new Error(`Scoped planning context could not be built for scan ${scanId}. Persisted scoped entities are missing.`);
        }

        const scanConfig = this.deps.getScanConfigById(scanId) || {};
        const authInventory = this.deps.getScanAuthInventoryById(scanId) as AuthStartupInventory | null;
        const endpointInventory = this.deps.getScanEndpointInventoryById(scanId) as EndpointInventorySnapshot | null;
        const structuredRequest = this.tryLoadOptional(() => this.deps.getStructuredRequestByScanId(scanId));
        const featureDiscovery = this.tryLoadOptional(() => this.deps.getFeatureDiscoveryStateByScanId(scanId));
        const sourceAnalysis = await this.resolveSourceAnalysis(scan);
        const selectedTargets = this.buildSelectedTargets(objective, envelope);
        const keywordHints = buildKeywordHints(objective, envelope, structuredRequest);
        const maxCases = this.resolveMaxCases(objective.scopeType, envelope);

        return {
            scanId,
            objective: {
                id: objective.id,
                title: objective.title,
                scopeType: objective.scopeType,
                featureDescription: trimOptional(objective.featureDescription, 240),
                goal: trimOptional(objective.goal, 240),
                operatorNotes: trimOptional(objective.operatorNotes, 320),
                riskTags: (objective.riskTags || []).slice(0, 8),
            },
            scope: {
                allowedHosts: envelope.allowedHosts.slice(0, 8),
                allowedRoutes: envelope.allowedRoutes.slice(0, 12),
                selectedEndpoints: envelope.selectedEndpoints.slice(0, 8),
                baselineRequestRefs: envelope.baselineRequestRefs.slice(0, 4),
                discoveredRequestRefs: (envelope.discoveredRequestRefs || []).slice(0, 6),
                browserAnchors: (envelope.browserAnchors || []).slice(0, 4),
                requestBundleRefs: envelope.requestBundleRefs.slice(0, 8),
                boundaryHints: envelope.boundaryHints.slice(0, 8),
                outOfScopeNotes: envelope.outOfScopeNotes.slice(0, 8),
                explorationBudget: envelope.explorationBudget,
            },
            authSummary: this.buildAuthSummary(envelope, authInventory),
            selectedTargets,
            supportingContext: {
                operatorInstructions: trimOptional(readOperatorInstructions(scanConfig), 320),
                requestBundles: envelope.requestBundleRefs.slice(0, 8),
                securityTestRequest: structuredRequest || undefined,
                featureDiscovery: featureDiscovery ? {
                    phase: featureDiscovery.phase,
                    outcome: featureDiscovery.outcome ?? null,
                    summary: trimOptional(featureDiscovery.summary, 240),
                    requestAnchorCount: featureDiscovery.requestAnchorCount,
                    browserAnchorCount: featureDiscovery.browserAnchorCount,
                    selectedEndpointCount: featureDiscovery.selectedEndpointCount,
                    allowedRouteCount: featureDiscovery.allowedRouteCount,
                } : undefined,
                endpointIntelligence: this.buildEndpointIntelligenceSummary(endpointInventory, envelope, keywordHints),
                sourceAnalysis: this.buildSourceAnalysisSummary(sourceAnalysis, envelope, keywordHints),
                observedInputHints: buildObservedInputHints({
                    selectedTargets,
                    requestTargetUrl: structuredRequest?.targetUrl,
                    requestDescription: structuredRequest?.description,
                    endpointInventory,
                }),
            },
            plannerConstraints: {
                schemaVersion: CONTEXT_PACK_SCHEMA_VERSION,
                noScopeExpansion: true,
                maxCases,
            },
        };
    }

    private async resolveSourceAnalysis(scan: ScanLikeRecord): Promise<SourceAnalysisResult | null> {
        const cached = this.deps.getSourceAnalysisResultById(scan.id) as SourceAnalysisResult | null;
        if (cached) {
            return cached;
        }

        const sourcePath = trimOptional(scan.source_package_path, 500);
        const sourceMode = this.normalizeSourceAnalysisMode(scan.source_analysis_mode);
        if (!sourcePath || !sourceMode) {
            return null;
        }

        try {
            return await this.deps.analyzeSourceCode(scan.id, sourcePath, sourceMode, scan.user_id);
        } catch (error: any) {
            logger.warn('Scoped planner could not hydrate source analysis, continuing without it', {
                scanId: scan.id,
                error: error.message,
            });
            return null;
        }
    }

    private normalizeSourceAnalysisMode(value: string | null | undefined): SourceAnalysisMode | null {
        if (value === SourceAnalysisMode.VERSION_AWARE || value === SourceAnalysisMode.FULL_SOURCE_AWARE) {
            return value;
        }
        return null;
    }

    private buildSelectedTargets(
        objective: FocusedTestObjective,
        envelope: ScopeEnvelope,
    ): ContextPackSelectedTarget[] {
        const targets: ContextPackSelectedTarget[] = [];

        for (const endpoint of envelope.selectedEndpoints) {
            targets.push({
                kind: 'endpoint',
                method: endpoint.method,
                path: normalizeRoutePath(endpoint.path),
                url: trimOptional(endpoint.url, 500),
                label: buildEndpointLabel(endpoint),
            });
        }

        for (const baseline of envelope.baselineRequestRefs) {
            targets.push({
                kind: 'baseline_request',
                method: baseline.method,
                path: normalizeRoutePath(baseline.path),
                url: trimOptional(baseline.url, 500),
                referenceKind: baseline.kind,
                referenceId: baseline.requestSlot,
                label: buildBaselineLabel(baseline),
            });
        }

        for (const discovered of envelope.discoveredRequestRefs || []) {
            const path = normalizeRoutePath(discovered.path || discovered.url);
            const url = trimOptional(discovered.url, 500);
            if (!path && !url) {
                continue;
            }

            targets.push({
                kind: 'endpoint',
                method: trimOptional(discovered.method, 16)?.toUpperCase() || 'GET',
                path,
                url,
                referenceKind: 'discovered_request',
                referenceId: discovered.id,
                label: trimOptional(discovered.label, 180) || buildDiscoveredRequestLabel(discovered),
            });
        }

        if (targets.length === 0) {
            for (const browserAnchor of envelope.browserAnchors || []) {
                targets.push({
                    kind: 'flow',
                    path: normalizeRoutePath(browserAnchor.startPath || browserAnchor.startUrl),
                    url: trimOptional(browserAnchor.startUrl, 500),
                    label: trimOptional(browserAnchor.label, 180) || normalizeRoutePath(browserAnchor.startPath || browserAnchor.startUrl) || 'Discovered browser flow',
                });
            }
        }

        if (targets.length === 0 && objective.scopeType === 'flow_scoped') {
            targets.push({
                kind: 'flow',
                label: trimOptional(objective.featureDescription || objective.title, 160) || objective.title,
            });
        }

        if (targets.length === 0 && objective.scopeType === 'feature_scoped') {
            targets.push({
                kind: 'feature',
                label: trimOptional(objective.featureDescription || objective.title, 160) || objective.title,
            });
        }

        return dedupeTargets(targets).slice(0, 8);
    }

    private buildAuthSummary(
        envelope: ScopeEnvelope,
        authInventory: AuthStartupInventory | null,
    ): ContextPackAuthSummary {
        const authRoutes = dedupeStrings(authInventory?.authRoutes || []).slice(0, 8);

        return {
            continuityStrategy: envelope.authContext?.continuityStrategy || 'unknown',
            summary: trimOptional(authInventory?.summary || envelope.authContext?.summary, 320) || 'No explicit auth context was captured for the scoped planner.',
            authContext: envelope.authContext,
            inventorySummary: authInventory ? {
                status: authInventory.status,
                summary: trimOptional(authInventory.summary, 240),
                authRoutes,
                formsCount: authInventory.forms.length,
                trafficCount: authInventory.traffic.length,
                ssoProviders: dedupeStrings(authInventory.ssoProviders || []).slice(0, 6),
                registrationAvailable: authInventory.registrationAvailable,
                passwordResetAvailable: authInventory.passwordResetAvailable,
            } : undefined,
        };
    }

    private buildEndpointIntelligenceSummary(
        inventory: EndpointInventorySnapshot | null,
        envelope: ScopeEnvelope,
        keywordHints: Set<string>,
    ): ContextPackEndpointIntelligenceSummary | undefined {
        if (!inventory?.records?.length) {
            return undefined;
        }

        const filteredRecords = inventory.records
            .filter((record) => recordWithinScope(record.endpoint, record.path, envelope, keywordHints))
            .slice(0, MAX_ENDPOINT_INTELLIGENCE_RECORDS)
            .map<ContextPackEndpointIntelligenceRecordSummary>((record) => ({
                endpoint: trimOptional(record.endpoint, 240) || record.endpoint,
                path: normalizeRoutePath(record.path) || record.path,
                methods: (record.methods || []).slice(0, 4),
                classification: record.classification,
                likelyAuthRelevant: !!record.likelyAuthRelevant,
                observedInBurp: !!record.observedInBurp,
                exercisedInBrowser: !!record.exercisedInBrowser,
                confidence: Number(record.confidence || 0),
                notes: (record.notes || []).slice(0, 4).map((entry) => trimOptional(entry, 120) || '').filter(Boolean),
                evidence: (record.evidence || []).slice(0, 3).map((entry) => trimOptional(entry, 160) || '').filter(Boolean),
            }));

        if (filteredRecords.length === 0) {
            return undefined;
        }

        return {
            summary: trimOptional(inventory.summary, 240) || `${filteredRecords.length} scoped endpoint intelligence record(s) retained.`,
            authRelevantCount: filteredRecords.filter((record) => record.likelyAuthRelevant).length,
            observedInBurpCount: filteredRecords.filter((record) => record.observedInBurp).length,
            exercisedInBrowserCount: filteredRecords.filter((record) => record.exercisedInBrowser).length,
            records: filteredRecords,
        };
    }

    private buildSourceAnalysisSummary(
        sourceAnalysis: SourceAnalysisResult | null,
        envelope: ScopeEnvelope,
        keywordHints: Set<string>,
    ): ContextPackSourceAnalysisSummary | undefined {
        if (!sourceAnalysis) {
            return undefined;
        }

        const testingHints = sourceAnalysis.testingHints
            .filter((hint) => matchesKeywordHints(`${hint.category} ${hint.hint}`, keywordHints) || keywordHints.size === 0)
            .slice(0, MAX_SOURCE_HINTS)
            .map((hint) => ({
                category: trimOptional(hint.category, 80) || hint.category,
                hint: trimOptional(hint.hint, 180) || hint.hint,
            }));

        const summary: ContextPackSourceAnalysisSummary = {
            mode: sourceAnalysis.mode,
            framework: trimOptional(sourceAnalysis.framework, 120) || sourceAnalysis.framework,
            technologyStack: (sourceAnalysis.technologyStack || []).slice(0, 8),
            testingHints,
        };

        if (!isFullSourceResult(sourceAnalysis)) {
            return summary;
        }

        const endpoints = (sourceAnalysis.endpoints || [])
            .filter((endpoint) => endpointWithinScope(endpoint.method, endpoint.path, envelope, keywordHints))
            .slice(0, MAX_SOURCE_ENDPOINTS)
            .map((endpoint) => ({
                method: endpoint.method,
                path: normalizeRoutePath(endpoint.path) || endpoint.path,
                authRequired: !!endpoint.authRequired,
                description: trimOptional(endpoint.description || endpoint.handler, 160) || endpoint.handler,
            }));

        const securityFlows = (sourceAnalysis.securityFlows || [])
            .filter((flow) => matchesKeywordHints(`${flow.category} ${flow.description} ${flow.components.join(' ')}`, keywordHints) || keywordHints.size === 0)
            .slice(0, MAX_SOURCE_FLOWS)
            .map((flow) => ({
                category: trimOptional(flow.category, 80) || flow.category,
                description: trimOptional(flow.description, 180) || flow.description,
                riskLevel: trimOptional(flow.riskLevel, 40) || flow.riskLevel,
            }));

        if (endpoints.length > 0) {
            summary.endpoints = endpoints;
        }
        if (securityFlows.length > 0) {
            summary.securityFlows = securityFlows;
        }

        return summary;
    }

    private resolveMaxCases(scopeType: ScopedTargetType, envelope: ScopeEnvelope): number {
        if (scopeType === 'endpoint_scoped') {
            return Math.min(Math.max((envelope.selectedEndpoints.length + (envelope.discoveredRequestRefs || []).length) * 2, 2), MAX_CASES_BY_SCOPE.endpoint_scoped);
        }
        if (scopeType === 'request_scoped') {
            return Math.max(3, Math.min(MAX_CASES_BY_SCOPE.request_scoped, envelope.baselineRequestRefs.length + 3));
        }
        return Math.max(4, Math.min(MAX_CASES_BY_SCOPE[scopeType], envelope.selectedEndpoints.length + envelope.baselineRequestRefs.length + (envelope.discoveredRequestRefs || []).length + 3));
    }

    private tryLoadOptional<T>(loader: () => T): T | null {
        try {
            return loader();
        } catch {
            return null;
        }
    }
}

function readOperatorInstructions(scanConfig: Record<string, any>): string | undefined {
    return typeof scanConfig?.customSystemPrompt === 'string'
        ? scanConfig.customSystemPrompt.trim()
        : undefined;
}

function buildKeywordHints(
    objective: FocusedTestObjective,
    envelope: ScopeEnvelope,
    structuredRequest?: {
        description?: string;
        serviceName?: string;
        environment?: string;
        authMechanismHints?: string[];
        operatorNotes?: string;
        testData?: string[];
        testUsers?: string[];
        attachmentSummary?: string;
        attachmentMetadata?: Array<{ label?: string; kind?: string; note?: string }>;
        newScreenCount?: number | null;
        newInputCount?: number | null;
    } | null,
): Set<string> {
    const raw = [
        objective.title,
        objective.featureDescription,
        objective.goal,
        objective.operatorNotes,
        structuredRequest?.description,
        structuredRequest?.serviceName,
        structuredRequest?.environment,
        structuredRequest?.operatorNotes,
        ...((structuredRequest?.authMechanismHints || [])),
        ...((structuredRequest?.testData || [])),
        ...((structuredRequest?.testUsers || [])),
        structuredRequest?.attachmentSummary,
        ...((structuredRequest?.attachmentMetadata || []).flatMap((entry) => [entry?.label, entry?.kind, entry?.note])),
        typeof structuredRequest?.newScreenCount === 'number' && structuredRequest.newScreenCount > 0
            ? `${structuredRequest.newScreenCount} new screens`
            : '',
        typeof structuredRequest?.newInputCount === 'number' && structuredRequest.newInputCount > 0
            ? `${structuredRequest.newInputCount} new inputs`
            : '',
        ...(objective.riskTags || []),
        ...(envelope.boundaryHints || []),
    ].join(' ');

    return new Set(
        raw
            .toLowerCase()
            .split(/[^a-z0-9_/-]+/i)
            .map((part) => part.trim())
            .filter((part) => part.length >= 4),
    );
}

function buildEndpointLabel(endpoint: SelectedScopedEndpoint): string {
    return `${endpoint.method.toUpperCase()} ${normalizeRoutePath(endpoint.path) || endpoint.path}`;
}

function buildBaselineLabel(baseline: BaselineRequestRef): string {
    const method = baseline.method || 'REQUEST';
    const path = normalizeRoutePath(baseline.path) || baseline.path || baseline.requestSlot;
    return `${method.toUpperCase()} ${path}`;
}

function buildDiscoveredRequestLabel(discovered: { method?: string; path?: string; url?: string; label?: string }): string {
    if (discovered.label) {
        return discovered.label;
    }
    const method = discovered.method?.toUpperCase() || 'GET';
    const path = normalizeRoutePath(discovered.path || discovered.url) || discovered.url || 'request';
    return `${method} ${path}`;
}

function dedupeTargets(targets: ContextPackSelectedTarget[]): ContextPackSelectedTarget[] {
    const seen = new Set<string>();
    return targets.filter((target) => {
        const key = [
            target.kind,
            target.method || '',
            target.path || '',
            target.referenceKind || '',
            target.referenceId || '',
            target.label || '',
        ].join(':');
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}

function dedupeStrings(values: string[]): string[] {
    return [...new Set(values.filter(Boolean))];
}

function buildObservedInputHints(input: {
    selectedTargets: ContextPackSelectedTarget[];
    requestTargetUrl?: string | null;
    requestDescription?: string | null;
    endpointInventory?: EndpointInventorySnapshot | null;
}): string[] {
    const hints = new Set<string>();
    const add = (value: string | null | undefined) => {
        const normalized = String(value || '').trim();
        if (normalized) {
            hints.add(normalized);
        }
    };
    const harvest = (value: string | null | undefined) => {
        const text = String(value || '');
        for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_]{1,40}(?:Id|ID|Token|token|Email|email|Name|name|Status|status|State|state|Comment|comment|Content|content|Query|query|Search|search))\b/g)) {
            add(match[1]);
        }
        try {
            const candidate = text.includes('://')
                ? new URL(text)
                : new URL(`https://placeholder.local${text.startsWith('/') ? text : `/${text}`}`);
            for (const [name] of candidate.searchParams.entries()) {
                add(name);
            }
        } catch {
            // Ignore non-URL text.
        }
    };

    for (const target of input.selectedTargets) {
        harvest(target.path);
        harvest(target.url);
        harvest(target.label);
    }
    harvest(input.requestTargetUrl);
    harvest(input.requestDescription);
    for (const record of input.endpointInventory?.records || []) {
        harvest(record.path);
        for (const note of record.notes || []) {
            harvest(note);
        }
    }

    return [...hints].slice(0, 8);
}

function normalizeRoutePath(value: string | null | undefined): string | undefined {
    if (!value) {
        return undefined;
    }

    const trimmed = value.trim();
    if (!trimmed) {
        return undefined;
    }

    try {
        if (/^https?:\/\//i.test(trimmed)) {
            const parsed = new URL(trimmed);
            return parsed.pathname || '/';
        }
    } catch {
        return undefined;
    }

    const withoutQuery = trimmed.split('?')[0]?.split('#')[0] || trimmed;
    return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
}

function normalizeHost(value: string | null | undefined): string | undefined {
    if (!value) {
        return undefined;
    }

    const trimmed = value.trim().toLowerCase();
    if (!trimmed) {
        return undefined;
    }

    try {
        if (/^https?:\/\//i.test(trimmed)) {
            return new URL(trimmed).host.toLowerCase();
        }
    } catch {
        return undefined;
    }

    return trimmed.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
}

function trimOptional(value: string | null | undefined, maxLength: number): string | undefined {
    if (typeof value !== 'string') {
        return undefined;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return undefined;
    }
    return trimmed.slice(0, maxLength);
}

function recordWithinScope(
    endpoint: string,
    path: string,
    envelope: ScopeEnvelope,
    keywordHints: Set<string>,
): boolean {
    const host = normalizeHost(endpoint);
    if (envelope.allowedHosts.length > 0 && host && !envelope.allowedHosts.includes(host)) {
        return false;
    }

    const normalizedPath = normalizeRoutePath(path || endpoint);
    if (normalizedPath && envelope.allowedRoutes.length > 0) {
        return envelope.allowedRoutes.includes(normalizedPath);
    }

    return keywordHints.size === 0 || matchesKeywordHints(`${endpoint} ${path}`, keywordHints);
}

function endpointWithinScope(
    method: string,
    path: string,
    envelope: ScopeEnvelope,
    keywordHints: Set<string>,
): boolean {
    const normalizedPath = normalizeRoutePath(path);
    if (normalizedPath && envelope.allowedRoutes.length > 0) {
        return envelope.allowedRoutes.includes(normalizedPath);
    }
    return keywordHints.size === 0 || matchesKeywordHints(`${method} ${path}`, keywordHints);
}

function matchesKeywordHints(text: string, keywordHints: Set<string>): boolean {
    if (keywordHints.size === 0) {
        return true;
    }

    const haystack = text.toLowerCase();
    for (const keyword of keywordHints) {
        if (haystack.includes(keyword)) {
            return true;
        }
    }

    return false;
}

export const contextPackBuilder = new ContextPackBuilder();
