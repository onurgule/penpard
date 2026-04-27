import type { FocusedTestObjective, ScopeEnvelope, StructuredAttachmentMetadata, StructuredSecurityTestRequest } from './ScopedScanTypes';
import { ScopeEnvelopeService, scopeEnvelopeService } from './ScopeEnvelopeService';

export interface PrepareScopedRequestIntakeInput {
    scanId: string;
    targetUrl: string;
    requestBody: Record<string, any>;
    initialRequest?: string;
}

export interface PreparedScopedRequestIntake {
    securityTestRequest: StructuredSecurityTestRequest;
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
}

type LooseRecord = Record<string, any>;

const DEFAULT_DISCOVERY_BUDGET = {
    maxRequests: 6,
    maxRouteVariants: 2,
    maxBrowserActions: 4,
    maxNavigationDepth: 1,
    maxVerificationRetries: 1,
    notes: 'Bounded feature discovery from structured security test request intake.',
} as const;

export class ScopedRequestIntakeService {
    constructor(
        private readonly scopeService: ScopeEnvelopeService = scopeEnvelopeService,
    ) {}

    public prepare(input: PrepareScopedRequestIntakeInput): PreparedScopedRequestIntake {
        const structuredRequest = this.normalizeStructuredRequest(input);
        const parsedFocusedObjective = this.parseStructuredField(input.requestBody.focusedObjective, {});
        const parsedScopeEnvelope = this.parseStructuredField(input.requestBody.scopeEnvelope, {});
        const targetEndpoints = this.parseStructuredField(input.requestBody.targetEndpoints, []);
        const explicitAnchorCount = countExplicitAnchors(parsedScopeEnvelope, targetEndpoints, input.initialRequest);
        const scopedTitle = normalizeOptionalString(parsedFocusedObjective?.title)
            || this.buildObjectiveTitle(structuredRequest, input.targetUrl);
        const description = normalizeOptionalString(parsedFocusedObjective?.featureDescription)
            || structuredRequest.description;
        const goal = normalizeOptionalString(parsedFocusedObjective?.goal)
            || this.buildGoal(structuredRequest, input.targetUrl);
        const operatorNotes = joinNotes(
            normalizeOptionalString(parsedFocusedObjective?.operatorNotes),
            structuredRequest.operatorNotes,
        );
        const synthesizedScopeEnvelope = this.buildSyntheticScopeEnvelope({
            targetUrl: input.targetUrl,
            structuredRequest,
            parsedScopeEnvelope,
            hasBaselineAnchor: !!input.initialRequest?.trim(),
        });

        const desiredScopeType = normalizeOptionalString(parsedFocusedObjective?.scopeType)
            || (explicitAnchorCount > 0
                ? undefined
                : 'feature_scoped');

        const { objective, envelope } = this.scopeService.buildScopedArtifacts({
            scanId: input.scanId,
            targetUrl: input.targetUrl,
            focusedObjective: {
                ...parsedFocusedObjective,
                title: scopedTitle,
                scopeType: desiredScopeType,
                featureDescription: description,
                goal,
                operatorNotes,
                riskTags: normalizeStringList(parsedFocusedObjective?.riskTags || []),
            },
            scopeEnvelope: synthesizedScopeEnvelope,
            targetEndpoints,
            authStartupMode: input.requestBody.authStartupMode,
            authCredentials: input.requestBody.authCredentials,
            sessionCookies: input.requestBody.sessionCookies,
            initialRequest: input.initialRequest,
        }, {
            requireConcreteAnchors: false,
        });

        return {
            securityTestRequest: {
                ...structuredRequest,
                scanId: input.scanId,
            },
            objective,
            envelope,
        };
    }

    private normalizeStructuredRequest(input: PrepareScopedRequestIntakeInput): StructuredSecurityTestRequest {
        const raw = this.parseStructuredField(input.requestBody.securityTestRequest, {}) as LooseRecord;
        const parsedFocusedObjective = this.parseStructuredField(input.requestBody.focusedObjective, {});
        const parsedScopeEnvelope = this.parseStructuredField(input.requestBody.scopeEnvelope, {});
        const targetPath = normalizeRoutePath(input.targetUrl);
        const fallbackDescription = [
            normalizeOptionalString(raw.description),
            normalizeOptionalString(parsedFocusedObjective?.featureDescription),
            normalizeOptionalString(parsedFocusedObjective?.goal),
            normalizeOptionalString(input.requestBody.scanInstructions),
            normalizeStringList(parsedScopeEnvelope?.boundaryHints || [])[0],
            targetPath ? `Security test request for ${targetPath}` : null,
        ].find(Boolean) || 'Security test request for the provided target URL.';

        return {
            targetUrl: input.targetUrl,
            description: fallbackDescription,
            environment: normalizeOptionalString(raw.environment),
            serviceName: normalizeOptionalString(raw.serviceName),
            testData: normalizeStringList(raw.testData || []),
            testUsers: normalizeStringList(raw.testUsers || []),
            loginPresent: normalizeNullableBoolean(raw.loginPresent),
            authMechanismHints: normalizeStringList(raw.authMechanismHints || []),
            hasScreenshotOrAttachment: normalizeNullableBoolean(raw.hasScreenshotOrAttachment),
            attachmentMetadata: normalizeAttachmentMetadata(raw.attachmentMetadata || []),
            attachmentSummary: normalizeOptionalString(raw.attachmentSummary),
            newScreenCount: normalizeOptionalNumber(raw.newScreenCount),
            newInputCount: normalizeOptionalNumber(raw.newInputCount),
            operatorNotes: joinNotes(
                normalizeOptionalString(raw.operatorNotes),
                normalizeOptionalString(parsedFocusedObjective?.operatorNotes),
            ),
        };
    }

    private buildObjectiveTitle(request: StructuredSecurityTestRequest, targetUrl: string): string {
        const serviceName = normalizeOptionalString(request.serviceName);
        if (serviceName) {
            return `Scoped request intake for ${serviceName}`;
        }

        try {
            const parsed = new URL(targetUrl);
            const firstSegment = parsed.pathname.split('/').map((entry) => entry.trim()).filter(Boolean)[0];
            if (firstSegment) {
                return `Scoped request intake for ${firstSegment}`;
            }
            return `Scoped request intake for ${parsed.host}`;
        } catch {
            return 'Scoped request intake';
        }
    }

    private buildGoal(request: StructuredSecurityTestRequest, targetUrl: string): string {
        const parts = [
            `Start from ${targetUrl}.`,
            'Anchor the requested feature area with bounded discovery.',
            normalizeOptionalString(request.description),
        ].filter(Boolean);

        return parts.join(' ').slice(0, 280);
    }

    private buildSyntheticScopeEnvelope(input: {
        targetUrl: string;
        structuredRequest: StructuredSecurityTestRequest;
        parsedScopeEnvelope: LooseRecord;
        hasBaselineAnchor: boolean;
    }): LooseRecord {
        const explicitAllowedRoutes = normalizeStringList(input.parsedScopeEnvelope?.allowedRoutes || [])
            .map((entry) => normalizeRoutePath(entry))
            .filter(Boolean);
        const explicitSelectedEndpoints = Array.isArray(input.parsedScopeEnvelope?.selectedEndpoints)
            ? input.parsedScopeEnvelope.selectedEndpoints.length
            : 0;
        const targetRoute = normalizeRoutePath(input.targetUrl);
        const boundaryHints = [
            ...normalizeStringList(input.parsedScopeEnvelope?.boundaryHints || []),
            input.structuredRequest.description,
            input.structuredRequest.environment ? `Environment: ${input.structuredRequest.environment}` : '',
            input.structuredRequest.serviceName ? `Service: ${input.structuredRequest.serviceName}` : '',
        ];

        const outOfScopeNotes = [
            ...normalizeStringList(input.parsedScopeEnvelope?.outOfScopeNotes || []),
            'Do not broaden beyond the request URL, nearby same-origin routes, and request-described feature area.',
        ];

        return {
            ...input.parsedScopeEnvelope,
            allowedRoutes: dedupeStrings([
                (targetRoute && targetRoute !== '/')
                    || (!input.hasBaselineAnchor && explicitSelectedEndpoints === 0)
                    ? targetRoute
                    : undefined,
                ...explicitAllowedRoutes,
            ]),
            boundaryHints: dedupeStrings(boundaryHints),
            outOfScopeNotes: dedupeStrings(outOfScopeNotes),
            explorationBudget: {
                ...DEFAULT_DISCOVERY_BUDGET,
                ...(input.parsedScopeEnvelope?.explorationBudget || {}),
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
            try {
                return JSON.parse(trimmed);
            } catch {
                return fallback;
            }
        }
        return value;
    }
}

function countExplicitAnchors(scopeEnvelope: LooseRecord, targetEndpoints: unknown[], initialRequest?: string): number {
    const selectedEndpoints = Array.isArray(scopeEnvelope?.selectedEndpoints) ? scopeEnvelope.selectedEndpoints.length : 0;
    const fallbackEndpoints = Array.isArray(targetEndpoints) ? targetEndpoints.length : 0;
    const baseline = initialRequest?.trim() ? 1 : 0;
    return selectedEndpoints + fallbackEndpoints + baseline;
}

function normalizeAttachmentMetadata(value: unknown[]): StructuredAttachmentMetadata[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .map((entry) => {
            const attachment = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
            return {
                label: normalizeOptionalString(attachment.label),
                kind: normalizeOptionalString(attachment.kind),
                mimeType: normalizeOptionalString(attachment.mimeType),
                note: normalizeOptionalString(attachment.note),
            };
        })
        .filter((entry) => entry.label || entry.kind || entry.mimeType || entry.note)
        .slice(0, 8);
}

function normalizeOptionalString(value: unknown): string | undefined {
    if (typeof value !== 'string') {
        return undefined;
    }
    const trimmed = value.trim();
    return trimmed ? trimmed.slice(0, 500) : undefined;
}

function normalizeStringList(value: unknown): string[] {
    if (Array.isArray(value)) {
        return dedupeStrings(value.map((entry) => normalizeOptionalString(entry)));
    }
    if (typeof value === 'string') {
        return dedupeStrings(value.split(/\r?\n|,/).map((entry) => normalizeOptionalString(entry)));
    }
    return [];
}

function normalizeNullableBoolean(value: unknown): boolean | null {
    if (value === null || value === undefined || value === '') {
        return null;
    }
    if (typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        return value > 0;
    }
    const normalized = String(value).trim().toLowerCase();
    if (['true', 'yes', '1'].includes(normalized)) {
        return true;
    }
    if (['false', 'no', '0'].includes(normalized)) {
        return false;
    }
    return null;
}

function normalizeOptionalNumber(value: unknown): number | null {
    if (value === null || value === undefined || value === '') {
        return null;
    }
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric < 0) {
        return null;
    }
    return Math.round(numeric);
}

function normalizeRoutePath(value: unknown): string | undefined {
    const raw = normalizeOptionalString(value);
    if (!raw) {
        return undefined;
    }

    try {
        if (/^https?:\/\//i.test(raw)) {
            const parsed = new URL(raw);
            return parsed.pathname || '/';
        }
    } catch {
        return undefined;
    }

    const withoutQuery = raw.split('?')[0]?.split('#')[0] || raw;
    return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
}

function joinNotes(...values: Array<string | undefined>): string | undefined {
    const parts = values.map((entry) => normalizeOptionalString(entry)).filter(Boolean) as string[];
    if (parts.length === 0) {
        return undefined;
    }
    return dedupeStrings(parts).join('\n\n').slice(0, 1000);
}

function dedupeStrings(values: Array<string | undefined>): string[] {
    return [...new Set(values.filter((entry): entry is string => !!entry))];
}

export const scopedRequestIntakeService = new ScopedRequestIntakeService();
