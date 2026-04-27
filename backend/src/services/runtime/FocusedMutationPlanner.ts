import type {
    FocusedCaseIntelligenceCandidateInput,
    FocusedConfirmationKind,
    FocusedExecutionAction,
    FocusedTestCase,
} from './ScopedScanTypes';

export interface FocusedObservedRequestField {
    name: string;
    location: 'path' | 'query' | 'body' | 'header';
    valuePreview?: string | null;
}

export interface FocusedObservedRequestShape {
    pathParams: FocusedObservedRequestField[];
    queryParams: FocusedObservedRequestField[];
    bodyFields: FocusedObservedRequestField[];
    headerFields: FocusedObservedRequestField[];
}

export interface FocusedMutationPlanningAnchor {
    defaultMethod: string;
    defaultUrl: string;
    useInitialRequestBaseline: boolean;
    requestShape?: FocusedObservedRequestShape | null;
}

export class FocusedMutationPlanner {
    public buildPrimaryMutationAction(input: {
        testCase: FocusedTestCase;
        anchor: FocusedMutationPlanningAnchor;
    }): FocusedExecutionAction | null {
        return this.buildMutationAction({
            testCase: input.testCase,
            anchor: input.anchor,
            mode: 'primary',
            confirmationOrdinal: 0,
            confirmationKind: null,
        });
    }

    public buildConfirmationMutationAction(input: {
        testCase: FocusedTestCase;
        anchor: FocusedMutationPlanningAnchor;
        confirmationKind: FocusedConfirmationKind;
        confirmationOrdinal: number;
        browserAnchorAvailable: boolean;
    }): FocusedExecutionAction | null {
        if (input.confirmationKind === 'render_check') {
            const requestMutation = this.buildMutationAction({
                testCase: input.testCase,
                anchor: input.anchor,
                mode: 'confirmation',
                confirmationOrdinal: input.confirmationOrdinal,
                confirmationKind: input.confirmationKind,
            });
            if (requestMutation?.type === 'mutated_replay') {
                return requestMutation;
            }
            return {
                type: input.browserAnchorAvailable ? 'browser_state_check' : 'capture_note',
                summary: input.browserAnchorAvailable
                    ? `Adaptive confirmation ${input.confirmationOrdinal}: verify the suspicious rendered state on the same approved display path because no bounded request mutation was available.`
                    : `Adaptive confirmation ${input.confirmationOrdinal}: render-sensitive confirmation could not run because neither a bounded request mutation nor an approved browser anchor was available.`,
                selectionReason: input.browserAnchorAvailable
                    ? 'The active hypothesis is render-sensitive and no bounded request mutation remained, so the strongest fallback is a browser check on the same anchored path.'
                    : 'Render confirmation needs either a persisted request mutation target or browser anchor, and neither was available in scope.',
                expectedSignals: input.browserAnchorAvailable
                    ? ['Visible render marker outcome on the same approved path']
                    : ['Record why render confirmation could not proceed'],
                targetInputs: this.readableTargetInputs(input.testCase.caseIntelligence?.candidateInputs || []),
                note: input.browserAnchorAvailable ? undefined : 'Render confirmation remained blocked because the scoped case has no approved browser anchor.',
                reason: input.browserAnchorAvailable
                    ? 'Confirm or weaken the active render/reflection hypothesis without widening the target path.'
                    : 'Preserve the bounded blocker instead of widening into exploratory browsing.',
            };
        }

        return this.buildMutationAction({
            testCase: input.testCase,
            anchor: input.anchor,
            mode: 'confirmation',
            confirmationOrdinal: input.confirmationOrdinal,
            confirmationKind: input.confirmationKind,
        });
    }

    private buildMutationAction(input: {
        testCase: FocusedTestCase;
        anchor: FocusedMutationPlanningAnchor;
        mode: 'primary' | 'confirmation';
        confirmationOrdinal: number;
        confirmationKind: FocusedConfirmationKind | null;
    }): FocusedExecutionAction | null {
        const candidateInputs = this.selectObservedCandidates(input.testCase, input.anchor);
        const preferred = this.pickCandidate(candidateInputs, input.confirmationKind, input.testCase.caseFamily || 'generic');
        if (!preferred) {
            if ((input.testCase.caseFamily || 'generic') === 'workflow_logic') {
                return {
                    type: 'mutated_replay',
                    summary: input.mode === 'primary'
                        ? 'Replay the same scoped workflow step one additional time to detect duplicate or out-of-order effects.'
                        : `Adaptive confirmation ${input.confirmationOrdinal}: replay the same scoped workflow step again to confirm whether the state anomaly persists.`,
                    method: input.anchor.defaultMethod,
                    url: input.anchor.defaultUrl,
                    preserveExplicitAuth: true,
                    useInitialRequestBaseline: input.anchor.useInitialRequestBaseline,
                    selectionReason: 'No concrete mutable parameter was observed, so the safest bounded workflow check is a duplicate replay on the same anchor.',
                    expectedSignals: [
                        'Unexpected state transition',
                        'Idempotent control holds the same result',
                    ],
                    targetInputs: [],
                    reason: 'Keep the workflow check bounded to the exact same anchored interaction.',
                };
            }
            return null;
        }

        const mutation = this.buildMutation(preferred, input.confirmationOrdinal, input.mode, input.confirmationKind);
        const action: FocusedExecutionAction = {
            type: 'mutated_replay',
            summary: mutation.summary,
            method: input.anchor.defaultMethod,
            url: mutation.pathReplacement
                ? replaceInUrlPath(input.anchor.defaultUrl, mutation.pathReplacement.from, mutation.pathReplacement.to)
                : input.anchor.defaultUrl,
            preserveExplicitAuth: true,
            useInitialRequestBaseline: input.anchor.useInitialRequestBaseline,
            queryMutations: mutation.queryMutations,
            bodyMutations: mutation.bodyMutations,
            selectionReason: mutation.selectionReason,
            expectedSignals: mutation.expectedSignals,
            targetInputs: [preferred],
            reason: mutation.reason,
        };
        return action;
    }

    private buildMutation(
        candidate: FocusedCaseIntelligenceCandidateInput,
        confirmationOrdinal: number,
        mode: 'primary' | 'confirmation',
        confirmationKind: FocusedConfirmationKind | null,
    ): {
        summary: string;
        pathReplacement?: {
            from: string;
            to: string;
        };
        queryMutations?: FocusedExecutionAction['queryMutations'];
        bodyMutations?: FocusedExecutionAction['bodyMutations'];
        selectionReason: string;
        expectedSignals: string[];
        reason: string;
    } {
        const ordinal = confirmationOrdinal > 0 ? confirmationOrdinal : 1;
        switch (candidate.mutationStrategy) {
            case 'adjacent_identifier':
            case 'identity_contrast': {
                const mutated = mutateIdentifier(candidate.observedValuePreview || '');
                const summary = mode === 'primary'
                    ? `Replay the same scoped target with one adjacent identifier contrast on ${candidate.name}.`
                    : `Adaptive confirmation ${confirmationOrdinal}: replay the same scoped target with a second identifier contrast on ${candidate.name}.`;
                if (candidate.location === 'path' && candidate.observedValuePreview) {
                    return {
                        summary,
                        pathReplacement: {
                            from: candidate.observedValuePreview,
                            to: mutated,
                        },
                        queryMutations: undefined,
                        bodyMutations: undefined,
                        selectionReason: `The observed ${candidate.location} field ${candidate.name} is the cleanest same-scope authorization contrast target.`,
                        expectedSignals: [
                            'Unauthorized object access is denied or reduced',
                            'Foreign object access still succeeds',
                        ],
                        reason: 'Confirm whether the suspicious access-control signal persists under a bounded adjacent-object replay.',
                    };
                }
                return {
                    summary,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value: mutated }] : undefined,
                    bodyMutations: candidate.location === 'body' ? [{ name: candidate.name, value: mutated }] : undefined,
                    selectionReason: `The observed ${candidate.location} field ${candidate.name} behaves like an object reference and can be varied without leaving scope.`,
                    expectedSignals: [
                        'Authorization contrast holds or fails on the same route',
                        'Response shape exposes foreign-object data',
                    ],
                    reason: 'Keep the authz confirmation tied to the same route family and one observed identifier.',
                };
            }
            case 'benign_render_marker': {
                const marker = `<span data-penpard=\"render-${ordinal}\">penpard-render-${ordinal}</span>`;
                return {
                    summary: mode === 'primary'
                        ? `Replay the same scoped content field ${candidate.name} with one benign render marker.`
                        : `Adaptive confirmation ${confirmationOrdinal}: replay ${candidate.name} with a second benign render marker on the same path.`,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value: marker }] : undefined,
                    bodyMutations: candidate.location === 'body' || candidate.location === 'rendered_content'
                        ? [{ name: candidate.name, value: marker }]
                        : undefined,
                    selectionReason: `${candidate.name} is already content-shaped, so a benign HTML marker is the tightest bounded render check.`,
                    expectedSignals: [
                        'Marker is encoded or sanitized',
                        'Marker renders unsafely on the same path',
                    ],
                    reason: 'Preserve the render check inside the existing content entry/display path only.',
                };
            }
            case 'boundary_value': {
                const value = candidate.observedValuePreview && /^\d+$/.test(candidate.observedValuePreview)
                    ? Number(candidate.observedValuePreview) + 1
                    : 'A'.repeat(257);
                return {
                    summary: mode === 'primary'
                        ? `Replay the same scoped input ${candidate.name} with one boundary value.`
                        : `Adaptive confirmation ${confirmationOrdinal}: replay ${candidate.name} with a second bounded boundary variation.`,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value }] : undefined,
                    bodyMutations: candidate.location === 'body' ? [{ name: candidate.name, value }] : undefined,
                    selectionReason: `${candidate.name} is an observed input and a boundary variation is appropriate for validation-focused confirmation.`,
                    expectedSignals: [
                        'Controlled validation failure',
                        'Unexpected acceptance or unsafe behavior',
                    ],
                    reason: 'Keep the validation contrast on one observed field so the signal remains bounded and explainable.',
                };
            }
            case 'malformed_value': {
                const value = candidate.observedValuePreview && /^\d+$/.test(candidate.observedValuePreview)
                    ? 'NaN'
                    : `bad::${candidate.name}::${ordinal}`;
                return {
                    summary: mode === 'primary'
                        ? `Replay the same scoped input ${candidate.name} with one malformed value.`
                        : `Adaptive confirmation ${confirmationOrdinal}: replay ${candidate.name} with a second malformed same-scope variation.`,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value }] : undefined,
                    bodyMutations: candidate.location === 'body' ? [{ name: candidate.name, value }] : undefined,
                    selectionReason: `${candidate.name} can be malformed without broadening scope, which makes it useful for safe-failure comparison.`,
                    expectedSignals: [
                        'Controlled error surface',
                        'Internal error or parser leak',
                    ],
                    reason: 'Compare the error surface without inventing new routes or new fields.',
                };
            }
            case 'state_toggle': {
                const value = toggleStateValue(candidate.observedValuePreview);
                return {
                    summary: mode === 'primary'
                        ? `Replay the same scoped state input ${candidate.name} with one bounded toggle.`
                        : `Adaptive confirmation ${confirmationOrdinal}: replay ${candidate.name} with the opposite same-scope state toggle.`,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value }] : undefined,
                    bodyMutations: candidate.location === 'body' || candidate.location === 'workflow_state'
                        ? [{ name: candidate.name, value }]
                        : undefined,
                    selectionReason: `${candidate.name} looks stateful, so a bounded toggle is the best workflow confirmation step on the same artifact.`,
                    expectedSignals: [
                        'State transition is safely rejected or stable',
                        'Unexpected state change persists',
                    ],
                    reason: 'Keep the workflow confirmation on the same artifact and a single state-like input.',
                };
            }
            case 'duplicate_replay': {
                return {
                    summary: mode === 'primary'
                        ? 'Replay the same scoped interaction once more to detect duplicate side effects.'
                        : `Adaptive confirmation ${confirmationOrdinal}: repeat the same scoped interaction again to confirm the duplicate side effect.`,
                    selectionReason: 'A duplicate replay is the safest bounded workflow misuse probe when no separate field mutation is required.',
                    expectedSignals: [
                        'No duplicate side effect occurs',
                        'Unexpected duplicate side effect or persistence shift',
                    ],
                    reason: 'Use the same anchored request only, without widening into exploratory chaining.',
                };
            }
            case 'type_contract_variation':
            default: {
                const value = candidate.observedValuePreview && /^\d+$/.test(candidate.observedValuePreview)
                    ? String(candidate.observedValuePreview)
                    : confirmationKind === 'control_contrast'
                        ? 'control'
                        : null;
                return {
                    summary: mode === 'primary'
                        ? `Replay the same scoped input ${candidate.name} with one contract-shape variation.`
                        : `Adaptive confirmation ${confirmationOrdinal}: replay ${candidate.name} with one additional contract-shape contrast.`,
                    queryMutations: candidate.location === 'query' ? [{ name: candidate.name, value }] : undefined,
                    bodyMutations: candidate.location === 'body' ? [{ name: candidate.name, value }] : undefined,
                    selectionReason: `${candidate.name} is an observed input and can support a bounded contract contrast without broadening scope.`,
                    expectedSignals: [
                        'Control contrast holds with stable behavior',
                        'Material delta persists on the same route',
                    ],
                    reason: 'Keep the generic misuse probe tied to the same input and route family.',
                };
            }
        }
    }

    private selectObservedCandidates(testCase: FocusedTestCase, anchor: FocusedMutationPlanningAnchor): FocusedCaseIntelligenceCandidateInput[] {
        const observedPathNames = new Set((anchor.requestShape?.pathParams || []).map((entry) => entry.name));
        const observedQueryNames = new Set((anchor.requestShape?.queryParams || []).map((entry) => entry.name));
        const observedBodyNames = new Set((anchor.requestShape?.bodyFields || []).map((entry) => entry.name));
        const candidates = (testCase.caseIntelligence?.candidateInputs || []).filter((entry) => {
            if (entry.location === 'path') {
                return observedPathNames.size === 0 || observedPathNames.has(entry.name) || !!entry.observedValuePreview;
            }
            if (entry.location === 'query') {
                return observedQueryNames.has(entry.name) || observedQueryNames.size === 0;
            }
            if (entry.location === 'body' || entry.location === 'rendered_content' || entry.location === 'workflow_state') {
                return observedBodyNames.has(entry.name) || observedBodyNames.size === 0;
            }
            return false;
        });
        if (candidates.length > 0) {
            return candidates;
        }

        return [
            ...(anchor.requestShape?.pathParams || []).map((entry) => ({
                name: entry.name,
                location: 'path' as const,
                reason: 'Observed path parameter from the anchored request.',
                mutationStrategy: 'adjacent_identifier' as const,
                observedValuePreview: entry.valuePreview || null,
            })),
            ...(anchor.requestShape?.queryParams || []).map((entry) => ({
                name: entry.name,
                location: 'query' as const,
                reason: 'Observed query parameter from the anchored request.',
                mutationStrategy: 'type_contract_variation' as const,
                observedValuePreview: entry.valuePreview || null,
            })),
            ...(anchor.requestShape?.bodyFields || []).map((entry) => ({
                name: entry.name,
                location: 'body' as const,
                reason: 'Observed body field from the anchored request.',
                mutationStrategy: 'type_contract_variation' as const,
                observedValuePreview: entry.valuePreview || null,
            })),
        ];
    }

    private pickCandidate(
        candidates: FocusedCaseIntelligenceCandidateInput[],
        confirmationKind: FocusedConfirmationKind | null,
        family: string,
    ): FocusedCaseIntelligenceCandidateInput | null {
        const rank = (candidate: FocusedCaseIntelligenceCandidateInput): number => {
            let score = 0;
            if (confirmationKind === 'alternate_id_compare' && candidate.mutationStrategy === 'adjacent_identifier') {
                score += 20;
            }
            if (confirmationKind === 'error_surface_compare' && candidate.mutationStrategy === 'malformed_value') {
                score += 20;
            }
            if (confirmationKind === 'control_contrast' && candidate.mutationStrategy === 'type_contract_variation') {
                score += 15;
            }
            if (confirmationKind === 'state_replay' && (candidate.mutationStrategy === 'state_toggle' || candidate.mutationStrategy === 'duplicate_replay')) {
                score += 20;
            }
            if (confirmationKind === 'repeat_mutation') {
                score += 5;
            }
            if (family === 'access_control' && candidate.mutationStrategy === 'adjacent_identifier') {
                score += 8;
            }
            if (family === 'xss' && candidate.mutationStrategy === 'benign_render_marker') {
                score += 8;
            }
            if (family === 'workflow_logic' && (candidate.mutationStrategy === 'state_toggle' || candidate.mutationStrategy === 'duplicate_replay')) {
                score += 8;
            }
            if (candidate.location === 'path' || candidate.location === 'query' || candidate.location === 'body') {
                score += 2;
            }
            return score;
        };

        return [...candidates].sort((left, right) => rank(right) - rank(left))[0] || null;
    }

    private readableTargetInputs(inputs: FocusedCaseIntelligenceCandidateInput[]): FocusedCaseIntelligenceCandidateInput[] {
        return inputs.slice(0, 2);
    }
}

export const focusedMutationPlanner = new FocusedMutationPlanner();

function mutateIdentifier(value: string): string {
    const trimmed = String(value || '').trim();
    if (/^\d+$/.test(trimmed)) {
        return String(Number(trimmed) + 1);
    }
    if (/^[0-9a-f]{8,}$/i.test(trimmed)) {
        return `${trimmed.slice(0, -1)}${trimmed.slice(-1).toLowerCase() === 'a' ? 'b' : 'a'}`;
    }
    return trimmed ? `${trimmed}-alt` : '2';
}

function toggleStateValue(value: string | null | undefined): string | boolean {
    const trimmed = String(value || '').trim().toLowerCase();
    switch (trimmed) {
        case 'true':
        case 'enabled':
        case 'active':
        case 'approved':
        case 'published':
            return 'false';
        case 'false':
        case 'disabled':
        case 'inactive':
        case 'draft':
            return 'true';
        default:
            return 'toggle';
    }
}

function replaceInUrlPath(url: string, from: string, to: string): string {
    try {
        const parsed = new URL(url);
        parsed.pathname = parsed.pathname.replace(from, to);
        return parsed.toString();
    } catch {
        return url.replace(from, to);
    }
}
