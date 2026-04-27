import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import { parseRawBurpRequest } from '../burp-request';
import {
    AuthContextSummary,
    BaselineRequestRef,
    DEFAULT_SCOPE_ENVELOPE_VERSION,
    FocusedTestObjective,
    RequestBundleRef,
    ScopeEnvelope,
    SCOPED_TARGET_TYPE_VALUES,
    ScopedTargetType,
    SelectedScopedEndpoint,
} from './ScopedScanTypes';

const focusedObjectiveSchema = z.object({
    title: z.string().trim().optional(),
    scopeType: z.enum(SCOPED_TARGET_TYPE_VALUES).optional(),
    featureDescription: z.string().trim().optional(),
    goal: z.string().trim().optional(),
    operatorNotes: z.string().trim().optional(),
    riskTags: z.array(z.string()).optional(),
}).passthrough();

const selectedEndpointSchema = z.object({
    method: z.string().trim().optional(),
    path: z.string().trim().optional(),
    url: z.string().trim().optional(),
    host: z.string().trim().optional(),
    source: z.string().trim().optional(),
    notes: z.array(z.string()).optional(),
    handler: z.string().trim().optional(),
}).passthrough();

const requestBundleRefSchema = z.object({
    kind: z.string().trim().min(1),
    id: z.string().trim().min(1),
    label: z.string().trim().optional(),
});

const explorationBudgetSchema = z.object({
    maxRequests: z.number().int().positive().nullable().optional(),
    maxRouteVariants: z.number().int().positive().nullable().optional(),
    maxBrowserActions: z.number().int().positive().nullable().optional(),
    maxNavigationDepth: z.number().int().positive().nullable().optional(),
    maxVerificationRetries: z.number().int().positive().nullable().optional(),
    notes: z.string().trim().nullable().optional(),
}).passthrough();

const scopeEnvelopeSchema = z.object({
    allowedHosts: z.array(z.string()).optional(),
    allowedRoutes: z.array(z.string()).optional(),
    selectedEndpoints: z.array(selectedEndpointSchema).optional(),
    requestBundleRefs: z.array(requestBundleRefSchema).optional(),
    outOfScopeNotes: z.array(z.string()).optional(),
    boundaryHints: z.array(z.string()).optional(),
    explorationBudget: explorationBudgetSchema.nullable().optional(),
}).passthrough();

export interface BuildScopedArtifactsInput {
    scanId: string;
    targetUrl: string;
    focusedObjective?: unknown;
    scopeEnvelope?: unknown;
    targetEndpoints?: unknown;
    authStartupMode?: unknown;
    authCredentials?: unknown;
    sessionCookies?: unknown;
    initialRequest?: string;
}

export interface PreparedScopedArtifacts {
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
}

export interface BuildScopedArtifactsOptions {
    requireConcreteAnchors?: boolean;
}

export class ScopedScanValidationError extends Error {}

export class ScopeEnvelopeService {
    public buildScopedArtifacts(input: BuildScopedArtifactsInput, options: BuildScopedArtifactsOptions = {}): PreparedScopedArtifacts {
        let parsedFocusedObjective: z.infer<typeof focusedObjectiveSchema>;
        let parsedScopeEnvelope: z.infer<typeof scopeEnvelopeSchema>;
        let fallbackTargetEndpoints: Array<z.infer<typeof selectedEndpointSchema>>;

        try {
            parsedFocusedObjective = focusedObjectiveSchema.parse(this.parseStructuredField(input.focusedObjective, {}));
            parsedScopeEnvelope = scopeEnvelopeSchema.parse(this.parseStructuredField(input.scopeEnvelope, {}));
            fallbackTargetEndpoints = z.array(selectedEndpointSchema).parse(this.parseStructuredField(input.targetEndpoints, []));
        } catch (error: any) {
            throw new ScopedScanValidationError(`Invalid scoped payload: ${error.message}`);
        }

        const selectedEndpoints = this.normalizeSelectedEndpoints(
            parsedScopeEnvelope.selectedEndpoints && parsedScopeEnvelope.selectedEndpoints.length > 0
                ? parsedScopeEnvelope.selectedEndpoints
                : fallbackTargetEndpoints,
        );
        const baselineRequestRefs = this.buildBaselineRequestRefs(input.initialRequest);
        const requestBundleRefs = this.normalizeRequestBundleRefs(parsedScopeEnvelope.requestBundleRefs || []);
        const outOfScopeNotes = this.normalizeStringList(parsedScopeEnvelope.outOfScopeNotes || []);
        const boundaryHints = this.normalizeStringList(parsedScopeEnvelope.boundaryHints || []);
        const scopeType = this.resolveScopeType(parsedFocusedObjective.scopeType, selectedEndpoints, baselineRequestRefs);

        if (options.requireConcreteAnchors !== false) {
            this.validateScopeAnchors(scopeType, selectedEndpoints, baselineRequestRefs, boundaryHints, outOfScopeNotes);
        }

        const allowedHosts = this.deduplicateStrings([
            this.normalizeHost(new URL(input.targetUrl).host),
            ...this.normalizeStringList(parsedScopeEnvelope.allowedHosts || []).map((entry) => this.normalizeHost(entry)).filter(Boolean),
            ...selectedEndpoints.map((entry) => this.normalizeHost(entry.host)).filter(Boolean),
            ...baselineRequestRefs.map((entry) => this.normalizeHost(entry.host)).filter(Boolean),
        ]);

        const allowedRoutes = this.deduplicateStrings([
            ...this.normalizeStringList(parsedScopeEnvelope.allowedRoutes || []).map((entry) => this.normalizeRoutePath(entry)).filter(Boolean),
            ...selectedEndpoints.map((entry) => this.normalizeRoutePath(entry.path)).filter(Boolean),
            ...baselineRequestRefs.map((entry) => this.normalizeRoutePath(entry.path)).filter(Boolean),
        ]);

        const objective: FocusedTestObjective = {
            id: uuidv4(),
            scanId: input.scanId,
            title: this.normalizeOptionalString(parsedFocusedObjective.title)
                || this.buildDefaultTitle(scopeType, input.targetUrl, selectedEndpoints, baselineRequestRefs),
            scopeType,
            featureDescription: this.normalizeOptionalString(parsedFocusedObjective.featureDescription),
            goal: this.normalizeOptionalString(parsedFocusedObjective.goal)
                || 'Execute a bounded security test within the persisted scope envelope.',
            operatorNotes: this.normalizeOptionalString(parsedFocusedObjective.operatorNotes),
            riskTags: this.normalizeStringList(parsedFocusedObjective.riskTags || []),
        };

        return {
            objective,
            envelope: {
                id: uuidv4(),
                scanId: input.scanId,
                version: DEFAULT_SCOPE_ENVELOPE_VERSION,
                allowedHosts,
                allowedRoutes,
                selectedEndpoints,
                baselineRequestRefs,
                discoveredRequestRefs: [],
                browserAnchors: [],
                requestBundleRefs,
                authContext: this.buildAuthContextSummary(input),
                outOfScopeNotes,
                boundaryHints,
                explorationBudget: parsedScopeEnvelope.explorationBudget
                    ? {
                        maxRequests: parsedScopeEnvelope.explorationBudget.maxRequests ?? null,
                        maxRouteVariants: parsedScopeEnvelope.explorationBudget.maxRouteVariants ?? null,
                        maxBrowserActions: parsedScopeEnvelope.explorationBudget.maxBrowserActions ?? null,
                        maxNavigationDepth: parsedScopeEnvelope.explorationBudget.maxNavigationDepth ?? null,
                        maxVerificationRetries: parsedScopeEnvelope.explorationBudget.maxVerificationRetries ?? null,
                        notes: this.normalizeOptionalString(parsedScopeEnvelope.explorationBudget.notes ?? undefined) ?? null,
                    }
                    : null,
            },
        };
    }

    private parseStructuredField(value: unknown, fallback: any): any {
        if (value === undefined || value === null || value === '') {
            return fallback;
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) {
                return fallback;
            }
            return JSON.parse(trimmed);
        }
        return value;
    }

    private normalizeSelectedEndpoints(entries: Array<Record<string, any>>): SelectedScopedEndpoint[] {
        const deduped = new Map<string, SelectedScopedEndpoint>();

        for (const entry of entries) {
            const method = this.normalizeMethod(entry.method);
            const path = this.normalizeRoutePath(entry.path || entry.url);
            if (!method || !path) {
                continue;
            }

            const normalized: SelectedScopedEndpoint = {
                method,
                path,
                url: this.normalizeUrl(entry.url),
                host: this.normalizeHost(entry.host || entry.url),
                source: this.normalizeOptionalString(entry.source) || 'unknown',
                notes: this.normalizeStringList([
                    ...(Array.isArray(entry.notes) ? entry.notes : []),
                    entry.handler,
                ]),
            };

            const key = `${normalized.method}:${normalized.path}`;
            deduped.set(key, normalized);
        }

        return [...deduped.values()];
    }

    private normalizeRequestBundleRefs(entries: RequestBundleRef[]): RequestBundleRef[] {
        const deduped = new Map<string, RequestBundleRef>();
        for (const entry of entries) {
            const kind = this.normalizeOptionalString(entry.kind);
            const id = this.normalizeOptionalString(entry.id);
            if (!kind || !id) {
                continue;
            }
            const key = `${kind}:${id}`;
            deduped.set(key, {
                kind,
                id,
                label: this.normalizeOptionalString(entry.label),
            });
        }
        return [...deduped.values()];
    }

    private buildBaselineRequestRefs(initialRequest?: string): BaselineRequestRef[] {
        if (!initialRequest?.trim()) {
            return [];
        }

        const parsed = parseRawBurpRequest(initialRequest.trim());
        return [{
            kind: 'scan_initial_request',
            source: 'burp_send_to_penpard',
            requestSlot: 'initial_request',
            method: parsed?.method,
            url: parsed?.url,
            host: this.normalizeHost(parsed?.host),
            path: this.normalizeRoutePath(parsed?.pathWithQuery),
        }];
    }

    private buildAuthContextSummary(input: BuildScopedArtifactsInput): AuthContextSummary {
        const authStartupMode = input.authStartupMode === 'provided_credentials'
            ? 'provided_credentials'
            : input.authStartupMode === 'no_credentials'
                ? 'no_credentials'
                : 'unknown';
        const parsedCredentials = this.parseStructuredField(input.authCredentials, []);
        const providedCredentialCount = Array.isArray(parsedCredentials)
            ? parsedCredentials.filter((entry) => {
                const username = this.normalizeOptionalString(entry?.username);
                const email = this.normalizeOptionalString(entry?.email);
                const password = this.normalizeOptionalString(entry?.password);
                return !!password && (!!username || !!email);
            }).length
            : 0;
        const hasSessionCookies = !!this.normalizeOptionalString(typeof input.sessionCookies === 'string' ? input.sessionCookies : undefined);
        const hasInitialRequestBaseline = !!input.initialRequest?.trim();
        const continuityStrategy = hasInitialRequestBaseline
            ? 'burp_baseline'
            : providedCredentialCount > 0
                ? 'provided_credentials'
                : hasSessionCookies
                    ? 'session_cookies'
                    : 'browser_discovery';

        const summaryParts = [
            hasInitialRequestBaseline ? 'Burp baseline request available' : null,
            providedCredentialCount > 0 ? `${providedCredentialCount} provided credential set(s)` : null,
            hasSessionCookies ? 'session cookies supplied' : null,
            authStartupMode === 'no_credentials' ? 'browser-first auth discovery' : null,
        ].filter((entry): entry is string => !!entry);

        return {
            authStartupMode,
            providedCredentialCount,
            hasSessionCookies,
            hasInitialRequestBaseline,
            continuityStrategy,
            summary: summaryParts.join(', ') || 'No explicit auth context supplied.',
        };
    }

    private resolveScopeType(
        requestedType: ScopedTargetType | undefined,
        selectedEndpoints: SelectedScopedEndpoint[],
        baselineRequestRefs: BaselineRequestRef[],
    ): ScopedTargetType {
        if (requestedType) {
            return requestedType;
        }
        if (baselineRequestRefs.length > 0) {
            return 'request_scoped';
        }
        if (selectedEndpoints.length > 0) {
            return 'endpoint_scoped';
        }
        return 'feature_scoped';
    }

    private validateScopeAnchors(
        scopeType: ScopedTargetType,
        selectedEndpoints: SelectedScopedEndpoint[],
        baselineRequestRefs: BaselineRequestRef[],
        boundaryHints: string[],
        outOfScopeNotes: string[],
    ): void {
        const hasEndpointAnchor = selectedEndpoints.length > 0;
        const hasBaselineAnchor = baselineRequestRefs.length > 0;
        const hasBoundaryAnchor = boundaryHints.length > 0 || outOfScopeNotes.length > 0;
        const allowsNarrativeAnchor = scopeType === 'flow_scoped' || scopeType === 'feature_scoped';

        if (!hasEndpointAnchor && !hasBaselineAnchor && !(allowsNarrativeAnchor && hasBoundaryAnchor)) {
            throw new ScopedScanValidationError(
                'Scoped scans require selected endpoints, a Burp baseline request, or boundary notes for flow/feature scope.',
            );
        }
    }

    private buildDefaultTitle(
        scopeType: ScopedTargetType,
        targetUrl: string,
        selectedEndpoints: SelectedScopedEndpoint[],
        baselineRequestRefs: BaselineRequestRef[],
    ): string {
        const targetHost = new URL(targetUrl).host;
        if (scopeType === 'request_scoped' && baselineRequestRefs[0]?.path) {
            return `Request-scoped test for ${baselineRequestRefs[0].path}`;
        }
        if (scopeType === 'endpoint_scoped' && selectedEndpoints.length > 0) {
            if (selectedEndpoints.length === 1) {
                return `Endpoint-scoped test for ${selectedEndpoints[0].path}`;
            }
            return `Endpoint-scoped test for ${selectedEndpoints.length} endpoints on ${targetHost}`;
        }
        if (scopeType === 'flow_scoped') {
            return `Flow-scoped test for ${targetHost}`;
        }
        return `Feature-scoped test for ${targetHost}`;
    }

    private normalizeMethod(value: unknown): string {
        const normalized = this.normalizeOptionalString(typeof value === 'string' ? value : undefined);
        return normalized ? normalized.toUpperCase() : 'GET';
    }

    private normalizeRoutePath(value: unknown): string | undefined {
        const raw = this.normalizeOptionalString(typeof value === 'string' ? value : undefined);
        if (!raw) {
            return undefined;
        }

        if (/^https?:\/\//i.test(raw)) {
            try {
                return new URL(raw).pathname || '/';
            } catch {
                return undefined;
            }
        }

        const withoutQuery = raw.split('?')[0]?.split('#')[0] || raw;
        const trimmed = withoutQuery.trim();
        if (!trimmed) {
            return undefined;
        }
        return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
    }

    private normalizeHost(value: unknown): string | undefined {
        const raw = this.normalizeOptionalString(typeof value === 'string' ? value : undefined);
        if (!raw) {
            return undefined;
        }

        if (/^https?:\/\//i.test(raw)) {
            try {
                return new URL(raw).host.toLowerCase();
            } catch {
                return undefined;
            }
        }

        return raw
            .toLowerCase()
            .replace(/^https?:\/\//i, '')
            .replace(/\/.*$/, '');
    }

    private normalizeUrl(value: unknown): string | undefined {
        const raw = this.normalizeOptionalString(typeof value === 'string' ? value : undefined);
        if (!raw || !/^https?:\/\//i.test(raw)) {
            return undefined;
        }
        try {
            return new URL(raw).toString();
        } catch {
            return undefined;
        }
    }

    private normalizeOptionalString(value: string | undefined | null): string | undefined {
        if (typeof value !== 'string') {
            return undefined;
        }
        const trimmed = value.trim();
        return trimmed ? trimmed : undefined;
    }

    private normalizeStringList(values: unknown[]): string[] {
        return this.deduplicateStrings(values
            .map((entry) => typeof entry === 'string' ? entry.trim() : '')
            .filter((entry) => !!entry));
    }

    private deduplicateStrings(values: Array<string | undefined>): string[] {
        return [...new Set(values.filter((entry): entry is string => !!entry))];
    }
}

export const scopeEnvelopeService = new ScopeEnvelopeService();
