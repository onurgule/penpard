import type {
    ContextPack,
    ContextPackEndpointIntelligenceRecordSummary,
    FocusedCaseFamily,
    FocusedCaseInputLocation,
    FocusedCaseIntelligence,
    FocusedCaseIntelligenceCandidateInput,
    FocusedCaseIntelligenceConcern,
    FocusedCaseMutationStrategy,
    FocusedConfirmationKind,
    FocusedExecutionRail,
    FocusedSignalMarker,
    FocusedTestCaseDraft,
} from './ScopedScanTypes';
import { resolveFocusedCaseFamily } from './FocusedSignalInterpreter';

const IDENTIFIER_HINT = /(id|uuid|tenant|account|user|order|invoice|document|project|record|item)$/i;
const RENDER_HINT = /(content|comment|message|body|html|markdown|bio|description|name|title|search|query|preview)$/i;
const STATE_HINT = /(state|status|step|phase|approved|publish|active|enabled|role)$/i;

interface CaseIntelligenceDefaults {
    preferredRail: FocusedExecutionRail;
    maxAdaptiveFollowUps: number;
    allowedConfirmationKinds: FocusedConfirmationKind[];
}

export class FocusedCaseIntelligenceBuilder {
    public build(contextPack: ContextPack, draftCase: FocusedTestCaseDraft): FocusedCaseIntelligence {
        const family = draftCase.caseFamily || resolveFocusedCaseFamily(contextPack.objective, draftCase);
        const targetLabel = formatTargetLabel(draftCase);
        const matchedEndpointRecord = this.findMatchedEndpointRecord(contextPack, draftCase);
        const requestSummary = contextPack.supportingContext.securityTestRequest;
        const candidateInputs = this.buildCandidateInputs({
            contextPack,
            draftCase,
            family,
            matchedEndpointRecord,
        });

        const selectionSummary = [
            `${targetLabel} was selected because it stays inside the persisted scoped anchors.`,
            requestSummary?.description
                ? `Request context points at ${trimSentence(requestSummary.description, 150)}`
                : null,
            matchedEndpointRecord?.classification
                ? `Endpoint intelligence classified it as ${matchedEndpointRecord.classification}.`
                : null,
            matchedEndpointRecord?.likelyAuthRelevant
                ? 'Observed endpoint intelligence also marks it as auth-sensitive.'
                : null,
            contextPack.supportingContext.sourceAnalysis?.testingHints?.[0]
                ? `Source-aware testing hint: ${trimSentence(contextPack.supportingContext.sourceAnalysis.testingHints[0]?.hint, 140)}`
                : null,
        ].filter((entry): entry is string => !!entry).join(' ').slice(0, 280);

        const anchorSummary = [
            draftCase.targetArtifact.kind === 'baseline_request'
                ? 'Execution will stay anchored to the persisted baseline request when available.'
                : draftCase.targetArtifact.kind === 'endpoint'
                    ? 'Execution will stay anchored to the approved endpoint and allowed route set.'
                    : 'Execution will stay anchored to the approved feature/flow start point and existing browser anchors.',
            contextPack.scope.allowedRoutes.length > 0
                ? `Allowed routes retained: ${contextPack.scope.allowedRoutes.slice(0, 3).join(', ')}.`
                : null,
            contextPack.scope.boundaryHints.length > 0
                ? `Boundary hints: ${contextPack.scope.boundaryHints.slice(0, 2).join(' ')}`
                : null,
        ].filter((entry): entry is string => !!entry).join(' ').slice(0, 280);

        const securityConcerns = this.buildSecurityConcerns({
            contextPack,
            draftCase,
            family,
            candidateInputs,
            matchedEndpointRecord,
        });
        const defaults = buildDefaultsForFamily(family, draftCase.targetArtifact.kind);

        return {
            selectionSummary,
            anchorSummary,
            candidateInputs,
            securityConcerns,
            followUpPolicy: {
                maxAdaptiveFollowUps: defaults.maxAdaptiveFollowUps,
                allowedConfirmationKinds: defaults.allowedConfirmationKinds,
                queueThresholdScore: 40,
                strongSignalMarkers: strongSignalMarkersForFamily(family),
                boundedBy: [
                    'Persisted anchors only',
                    'Allowed routes and hosts only',
                    'Existing observed inputs only',
                ],
                stopConditions: [
                    'Adaptive follow-up budget exhausted',
                    'Scope guard blocks the next step',
                    'Control-held evidence weakens the active hypothesis',
                    'No same-scope input variation remains',
                ],
            },
        };
    }

    public deriveDefaults(intelligence: FocusedCaseIntelligence, fallbackFamily: FocusedCaseFamily, targetKind: FocusedTestCaseDraft['targetArtifact']['kind']): CaseIntelligenceDefaults {
        const defaults = buildDefaultsForFamily(fallbackFamily, targetKind);
        return {
            preferredRail: defaults.preferredRail,
            maxAdaptiveFollowUps: Math.max(0, Math.min(2, intelligence.followUpPolicy.maxAdaptiveFollowUps || defaults.maxAdaptiveFollowUps)),
            allowedConfirmationKinds: intelligence.followUpPolicy.allowedConfirmationKinds.length > 0
                ? intelligence.followUpPolicy.allowedConfirmationKinds.slice(0, 4)
                : defaults.allowedConfirmationKinds,
        };
    }

    private buildCandidateInputs(input: {
        contextPack: ContextPack;
        draftCase: FocusedTestCaseDraft;
        family: FocusedCaseFamily;
        matchedEndpointRecord?: ContextPackEndpointIntelligenceRecordSummary;
    }): FocusedCaseIntelligenceCandidateInput[] {
        const target = input.draftCase.targetArtifact;
        const seeds = new Map<string, FocusedCaseIntelligenceCandidateInput>();
        const targetUrl = target.url || input.contextPack.supportingContext.securityTestRequest?.targetUrl || null;
        const addCandidate = (candidate: FocusedCaseIntelligenceCandidateInput) => {
            const key = `${candidate.location}:${candidate.name}:${candidate.mutationStrategy}`;
            if (!seeds.has(key)) {
                seeds.set(key, candidate);
            }
        };

        for (const candidate of deriveCandidatesFromUrl(target.path || targetUrl, input.family)) {
            addCandidate(candidate);
        }
        if (targetUrl) {
            for (const candidate of deriveCandidatesFromQuery(targetUrl, input.family)) {
                addCandidate(candidate);
            }
        }

        const freeTextSeeds = [
            input.contextPack.objective.title,
            input.contextPack.objective.featureDescription,
            input.contextPack.objective.goal,
            input.contextPack.supportingContext.securityTestRequest?.description,
            input.contextPack.supportingContext.securityTestRequest?.attachmentSummary,
            ...(input.contextPack.supportingContext.observedInputHints || []),
            ...input.draftCase.steps.map((entry) => entry.action),
            ...input.draftCase.assertions.map((entry) => entry.description),
        ];
        for (const name of extractInputHints(freeTextSeeds)) {
            addCandidate(this.buildTextCandidate(name, input.family));
        }

        if (input.matchedEndpointRecord) {
            for (const name of extractInputHints([
                ...input.matchedEndpointRecord.notes,
                ...input.matchedEndpointRecord.evidence,
                input.matchedEndpointRecord.path,
            ])) {
                addCandidate(this.buildTextCandidate(name, input.family));
            }
        }

        const familyFallback = this.buildFallbackCandidate(input.family);
        if (![...seeds.values()].some((entry) => entry.mutationStrategy === familyFallback.mutationStrategy)) {
            addCandidate(familyFallback);
        }

        if (seeds.size === 0) {
            addCandidate(familyFallback);
        }

        return [...seeds.values()].slice(0, 6);
    }

    private buildTextCandidate(name: string, family: FocusedCaseFamily): FocusedCaseIntelligenceCandidateInput {
        const location = inferLocationFromName(name, family);
        return {
            name,
            location,
            reason: candidateReason(name, family, location),
            mutationStrategy: inferMutationStrategy(name, family, location),
            observedValuePreview: null,
        };
    }

    private buildFallbackCandidate(family: FocusedCaseFamily): FocusedCaseIntelligenceCandidateInput {
        switch (family) {
            case 'access_control':
                return {
                    name: 'objectId',
                    location: 'path',
                    reason: 'The scoped target appears object-oriented, so the existing object reference is the safest bounded authz probe.',
                    mutationStrategy: 'adjacent_identifier',
                    observedValuePreview: null,
                };
            case 'xss':
                return {
                    name: 'content',
                    location: 'body',
                    reason: 'Rendered-content cases still need a bounded benign marker through an existing content field.',
                    mutationStrategy: 'benign_render_marker',
                    observedValuePreview: null,
                };
            case 'workflow_logic':
                return {
                    name: 'workflow',
                    location: 'workflow_state',
                    reason: 'Workflow cases can safely use a duplicate or out-of-order replay against the same anchored step.',
                    mutationStrategy: 'duplicate_replay',
                    observedValuePreview: null,
                };
            default:
                return {
                    name: 'input',
                    location: 'body',
                    reason: 'The scoped case still needs one existing input surface for bounded contrast.',
                    mutationStrategy: family === 'error_handling' ? 'malformed_value' : 'type_contract_variation',
                    observedValuePreview: null,
                };
        }
    }

    private buildSecurityConcerns(input: {
        contextPack: ContextPack;
        draftCase: FocusedTestCaseDraft;
        family: FocusedCaseFamily;
        candidateInputs: FocusedCaseIntelligenceCandidateInput[];
        matchedEndpointRecord?: ContextPackEndpointIntelligenceRecordSummary;
    }): FocusedCaseIntelligenceConcern[] {
        const primary = buildConcernForFamily(input.family, input.draftCase, input.candidateInputs, input.contextPack, input.matchedEndpointRecord);
        const secondaryFamilies = [
            input.family !== 'access_control' && input.contextPack.authSummary.authContext ? 'access_control' : null,
            input.family !== 'input_validation' && input.candidateInputs.some((entry) => entry.location === 'body' || entry.location === 'query') ? 'input_validation' : null,
            input.family !== 'error_handling' && input.contextPack.objective.riskTags.some((entry) => /error|exception|leak/i.test(entry)) ? 'error_handling' : null,
        ].filter((entry): entry is FocusedCaseFamily => !!entry);

        const concerns = [primary];
        for (const family of secondaryFamilies) {
            if (concerns.some((entry) => entry.family === family)) {
                continue;
            }
            concerns.push(buildConcernForFamily(family, input.draftCase, input.candidateInputs, input.contextPack, input.matchedEndpointRecord));
        }
        return concerns.slice(0, 3);
    }

    private findMatchedEndpointRecord(contextPack: ContextPack, draftCase: FocusedTestCaseDraft) {
        const targetPath = normalizeRoutePath(draftCase.targetArtifact.path || draftCase.targetArtifact.url);
        return contextPack.supportingContext.endpointIntelligence?.records.find((record) => {
            const recordPath = normalizeRoutePath(record.path || record.endpoint);
            return targetPath ? routeMatches(targetPath, recordPath) : false;
        });
    }
}

export const focusedCaseIntelligenceBuilder = new FocusedCaseIntelligenceBuilder();

function buildDefaultsForFamily(family: FocusedCaseFamily, targetKind: FocusedTestCaseDraft['targetArtifact']['kind']): CaseIntelligenceDefaults {
    switch (family) {
        case 'access_control':
            return {
                preferredRail: 'request',
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['alternate_id_compare', 'control_contrast'],
            };
        case 'xss':
            return {
                preferredRail: targetKind === 'flow' || targetKind === 'feature' ? 'hybrid' : 'request',
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['render_check', 'control_contrast'],
            };
        case 'workflow_logic':
            return {
                preferredRail: 'hybrid',
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['state_replay', 'control_contrast'],
            };
        case 'sqli':
            return {
                preferredRail: 'request',
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['repeat_mutation', 'error_surface_compare'],
            };
        case 'error_handling':
            return {
                preferredRail: 'request',
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['error_surface_compare', 'control_contrast'],
            };
        case 'input_validation':
            return {
                preferredRail: 'request',
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['control_contrast', 'error_surface_compare'],
            };
        default:
            return {
                preferredRail: 'request',
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['control_contrast', 'repeat_mutation'],
            };
    }
}

function strongSignalMarkersForFamily(family: FocusedCaseFamily): FocusedSignalMarker[] {
    switch (family) {
        case 'access_control':
            return ['authz_bypass', 'strong_fail_keyword'];
        case 'xss':
            return ['script_reflection_marker', 'browser_expectation_missed'];
        case 'workflow_logic':
            return ['workflow_state_shift', 'state_mismatch_marker'];
        case 'sqli':
            return ['sql_error_marker', 'server_error_transition'];
        case 'error_handling':
            return ['server_error_transition', 'strong_fail_keyword'];
        default:
            return ['strong_fail_keyword', 'strong_structural_delta'];
    }
}

function buildConcernForFamily(
    family: FocusedCaseFamily,
    draftCase: FocusedTestCaseDraft,
    candidateInputs: FocusedCaseIntelligenceCandidateInput[],
    contextPack: ContextPack,
    matchedEndpointRecord?: ContextPackEndpointIntelligenceRecordSummary,
): FocusedCaseIntelligenceConcern {
    const keyInput = candidateInputs[0];
    const targetLabel = formatTargetLabel(draftCase);
    const authContextPresent = !!contextPack.authSummary.authContext;
    const sharedChecks = [
        'Stay on the same persisted route or anchored browser path.',
        'Mutate only one observed input or replay characteristic at a time.',
    ];

    switch (family) {
        case 'access_control':
            return {
                family,
                title: `Adjacent object access on ${targetLabel}`,
                whyRelevant: authContextPresent
                    ? 'The request is identity-sensitive and already has a persisted auth context, so adjacent object checks are high-value and still bounded.'
                    : 'The selected target looks object-oriented, so an adjacent identifier check is a plausible bounded access-control concern.',
                strengtheningSignals: [
                    'A foreign object reference succeeds or returns materially different data.',
                    'Control-held contrast does not block the alternate object access.',
                ],
                weakeningSignals: [
                    'The alternate object reference is denied or returns only scoped data.',
                    'The same contrast replay shows stable object isolation.',
                ],
                boundedChecks: [
                    `Use only the observed object-style input ${keyInput?.name || 'identifier'} for contrast.`,
                    ...sharedChecks,
                ],
            };
        case 'xss':
            return {
                family,
                title: `Rendered content handling on ${targetLabel}`,
                whyRelevant: 'The target appears to accept or display user-controlled content, so a benign render marker can test reflection or storage without broadening scope.',
                strengtheningSignals: [
                    'The benign marker reappears unsafely in the same display path.',
                    'Browser proof shows script-like content was not neutralized.',
                ],
                weakeningSignals: [
                    'The marker is encoded, sanitized, or absent on the same display path.',
                    'Browser proof holds the same control behavior after the marker replay.',
                ],
                boundedChecks: [
                    `Use the existing content-style input ${keyInput?.name || 'content'} with a benign marker only.`,
                    'Confirm on the same anchored display or response path.',
                ],
            };
        case 'workflow_logic':
            return {
                family,
                title: `State transition integrity on ${targetLabel}`,
                whyRelevant: matchedEndpointRecord?.exercisedInBrowser
                    ? 'The target was already exercised in browser context, making a duplicate or out-of-order replay a realistic bounded workflow check.'
                    : 'The target looks stateful enough that duplicate or order-sensitive behavior is plausible inside the same anchored flow.',
                strengtheningSignals: [
                    'A duplicate replay changes persisted state unexpectedly.',
                    'Out-of-order or toggled state behaves inconsistently on the same path.',
                ],
                weakeningSignals: [
                    'A duplicate replay is idempotent or safely rejected.',
                    'State remains stable across same-scope control replays.',
                ],
                boundedChecks: [
                    'Replay only the same anchored workflow step or immediate state toggle.',
                    ...sharedChecks,
                ],
            };
        case 'error_handling':
            return {
                family,
                title: `Safe failure behavior on ${targetLabel}`,
                whyRelevant: 'Malformed or boundary values on an existing input can reveal whether the feature fails safely without exposing internals.',
                strengtheningSignals: [
                    'The response shifts from normal handling to an internal error or stack-style leak.',
                    'Control contrast shows the malformed input changes server behavior sharply.',
                ],
                weakeningSignals: [
                    'The malformed value is rejected with a controlled 4xx-style response.',
                    'The failure surface is stable and non-leaky across same-scope contrasts.',
                ],
                boundedChecks: [
                    `Keep malformed or boundary testing on ${keyInput?.name || 'one existing field'} only.`,
                    ...sharedChecks,
                ],
            };
        case 'input_validation':
            return {
                family,
                title: `Contract enforcement on ${targetLabel}`,
                whyRelevant: 'The target accepts existing inputs that can be safely stressed with one-field boundary or type variations inside the same scope.',
                strengtheningSignals: [
                    'A one-field variation bypasses validation or changes behavior unexpectedly.',
                    'The invalid value is accepted instead of being rejected cleanly.',
                ],
                weakeningSignals: [
                    'Invalid values are rejected consistently with a stable control response.',
                    'Comparison shows no unsafe error disclosure while validation holds.',
                ],
                boundedChecks: [
                    `Use one observed input like ${keyInput?.name || 'the current field'} for boundary/type variation.`,
                    ...sharedChecks,
                ],
            };
        case 'sqli':
            return {
                family,
                title: `Backend query handling on ${targetLabel}`,
                whyRelevant: 'Query-shaped features can expose backend parser or SQL-style anomalies from one bounded same-scope replay.',
                strengtheningSignals: [
                    'A bounded replay triggers SQL-style error markers or a strong server-error transition.',
                    'A second same-scope replay strengthens the same parser-style anomaly.',
                ],
                weakeningSignals: [
                    'The contrast replay returns a stable control response with no backend error markers.',
                    'The suspicious delta collapses on a same-scope confirmation replay.',
                ],
                boundedChecks: [
                    `Keep query manipulation on ${keyInput?.name || 'the existing query field'} only.`,
                    ...sharedChecks,
                ],
            };
        default:
            return {
                family,
                title: `Feature misuse contrast on ${targetLabel}`,
                whyRelevant: 'The target has enough existing input or workflow surface to justify one bounded contract-contrast replay.',
                strengtheningSignals: [
                    'A same-scope contrast replay changes behavior materially without a clear control explanation.',
                    'A confirmation replay preserves the suspicious delta.',
                ],
                weakeningSignals: [
                    'Control replays hold the same behavior with no meaningful suspicious delta.',
                    'The suspicious signal disappears when the same anchored contrast is repeated.',
                ],
                boundedChecks: [
                    `Keep the misuse check on ${keyInput?.name || 'one observed input'} only.`,
                    ...sharedChecks,
                ],
            };
    }
}

function deriveCandidatesFromUrl(pathOrUrl: string | null | undefined, family: FocusedCaseFamily): FocusedCaseIntelligenceCandidateInput[] {
    const normalized = normalizeRoutePath(pathOrUrl);
    if (!normalized) {
        return [];
    }

    return normalized
        .split('/')
        .filter(Boolean)
        .map((segment, index, segments) => ({ segment, index, previous: segments[index - 1] || 'id' }))
        .filter(({ segment }) => isDynamicSegment(segment))
        .map(({ segment, previous }) => ({
            name: normalizeCandidateName(previous),
            location: 'path' as FocusedCaseInputLocation,
            reason: `The route already carries a concrete path object reference (${segment}), so the safest bounded probe is to vary that same identifier.`,
            mutationStrategy: family === 'workflow_logic' ? 'state_toggle' : 'adjacent_identifier' as FocusedCaseMutationStrategy,
            observedValuePreview: segment.slice(0, 60),
        }));
}

function deriveCandidatesFromQuery(urlOrPath: string, family: FocusedCaseFamily): FocusedCaseIntelligenceCandidateInput[] {
    try {
        const candidateUrl = urlOrPath.includes('://') ? new URL(urlOrPath) : new URL(`https://placeholder.local${urlOrPath.startsWith('/') ? urlOrPath : `/${urlOrPath}`}`);
        return [...candidateUrl.searchParams.entries()]
            .map(([name, value]) => ({
                name: normalizeCandidateName(name),
                location: 'query' as FocusedCaseInputLocation,
                reason: candidateReason(name, family, 'query'),
                mutationStrategy: inferMutationStrategy(name, family, 'query'),
                observedValuePreview: value.slice(0, 60),
            }))
            .filter((entry) => entry.name);
    } catch {
        return [];
    }
}

function extractInputHints(values: Array<string | null | undefined>): string[] {
    const candidates = new Set<string>();
    for (const value of values) {
        const text = String(value || '');
        const explicitMatches = text.matchAll(/\b([A-Za-z][A-Za-z0-9_]{1,40}(?:Id|ID|Token|token|Email|email|Name|name|Status|status|State|state|Comment|comment|Content|content|Query|query|Search|search))\b/g);
        for (const match of explicitMatches) {
            const token = normalizeCandidateName(match[1]);
            if (token) {
                candidates.add(token);
            }
        }

        const quotedMatches = text.matchAll(/["'`]([A-Za-z][A-Za-z0-9_.-]{1,40})["'`]/g);
        for (const match of quotedMatches) {
            const token = normalizeCandidateName(match[1]);
            if (token && (IDENTIFIER_HINT.test(token) || RENDER_HINT.test(token) || STATE_HINT.test(token))) {
                candidates.add(token);
            }
        }
    }
    return [...candidates].slice(0, 6);
}

function inferLocationFromName(name: string, family: FocusedCaseFamily): FocusedCaseInputLocation {
    if (family === 'workflow_logic') {
        return 'workflow_state';
    }
    if (family === 'xss' || RENDER_HINT.test(name)) {
        return 'body';
    }
    if (IDENTIFIER_HINT.test(name)) {
        return 'path';
    }
    return 'body';
}

function inferMutationStrategy(name: string, family: FocusedCaseFamily, location: FocusedCaseInputLocation): FocusedCaseMutationStrategy {
    if (family === 'access_control' || IDENTIFIER_HINT.test(name)) {
        return location === 'identity' ? 'identity_contrast' : 'adjacent_identifier';
    }
    if (family === 'xss' || RENDER_HINT.test(name)) {
        return 'benign_render_marker';
    }
    if (family === 'workflow_logic') {
        return STATE_HINT.test(name) ? 'state_toggle' : 'duplicate_replay';
    }
    if (family === 'error_handling') {
        return 'malformed_value';
    }
    if (family === 'input_validation') {
        return 'boundary_value';
    }
    return 'type_contract_variation';
}

function candidateReason(name: string, family: FocusedCaseFamily, location: FocusedCaseInputLocation): string {
    if (family === 'access_control') {
        return `Existing ${location} input ${name} looks like an object reference, so it is the best bounded authorization contrast candidate.`;
    }
    if (family === 'xss') {
        return `Existing ${location} input ${name} is content-shaped, which makes it suitable for a benign render marker replay.`;
    }
    if (family === 'workflow_logic') {
        return `Existing ${location} signal ${name} suggests a stateful flow, so it supports a duplicate or state-toggle replay.`;
    }
    if (family === 'error_handling') {
        return `Existing ${location} input ${name} can be safely malformed to compare the feature's failure surface.`;
    }
    if (family === 'input_validation') {
        return `Existing ${location} input ${name} is a plausible contract boundary for one-field validation contrast.`;
    }
    return `Existing ${location} input ${name} gives the bounded case a concrete same-scope contrast point.`;
}

function formatTargetLabel(testCase: Pick<FocusedTestCaseDraft, 'title' | 'targetArtifact'>): string {
    return [
        testCase.targetArtifact.method?.toUpperCase(),
        testCase.targetArtifact.path || testCase.targetArtifact.label || testCase.targetArtifact.url || testCase.title,
    ].filter(Boolean).join(' ');
}

function routeMatches(left: string | null | undefined, right: string | null | undefined): boolean {
    const normalizedLeft = normalizeRoutePath(left);
    const normalizedRight = normalizeRoutePath(right);
    if (!normalizedLeft || !normalizedRight) {
        return false;
    }
    const leftSegments = normalizedLeft.split('/').filter(Boolean);
    const rightSegments = normalizedRight.split('/').filter(Boolean);
    if (leftSegments.length !== rightSegments.length) {
        return false;
    }
    return leftSegments.every((segment, index) => {
        const other = rightSegments[index];
        return segment === other || isDynamicSegment(segment) || isDynamicSegment(other);
    });
}

function normalizeRoutePath(value: string | null | undefined): string | null {
    const trimmed = String(value || '').trim();
    if (!trimmed) {
        return null;
    }
    try {
        if (trimmed.includes('://')) {
            const parsed = new URL(trimmed);
            return `${parsed.pathname}${parsed.search || ''}` || '/';
        }
    } catch {
        return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
    }
    return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function isDynamicSegment(segment: string): boolean {
    return /^[:{]/.test(segment)
        || /^[0-9]+$/.test(segment)
        || /^[0-9a-f]{8,}$/i.test(segment)
        || /^[A-Za-z0-9_-]{6,}$/.test(segment);
}

function normalizeCandidateName(value: string | null | undefined): string {
    return String(value || '')
        .trim()
        .replace(/^[{:]?/, '')
        .replace(/[}\]]$/, '')
        .replace(/[^A-Za-z0-9_]/g, '')
        .slice(0, 40) || 'input';
}

function trimSentence(value: string | null | undefined, maxLength: number): string {
    return String(value || '').trim().slice(0, maxLength);
}
