import { z } from 'zod';
import { llmProvider } from '../LLMProviderService';
import { llmRuntime } from '../llm/LlmRuntime';
import {
    buildJsonSchemaResponseFormat,
    parseStructuredJsonResponse,
} from '../llm/LlmStructuredOutput';
import { logger } from '../../utils/logger';
import type {
    ContextPack,
    ContextPackSelectedTarget,
    FocusedPlannerResponse,
    FocusedTestAssertion,
    FocusedTestCaseDraft,
    FocusedTestCaseTargetArtifact,
    FocusedTestEvidenceRequirement,
    FocusedTestStep,
} from './ScopedScanTypes';
import {
    FOCUSED_TEST_CASE_PRIORITY_VALUES,
    FOCUSED_TEST_CASE_REVIEW_STATE_VALUES,
    FOCUSED_TEST_CASE_STATUS_VALUES,
    FOCUSED_TEST_CASE_TARGET_KIND_VALUES,
    normalizeFocusedTestCasePriority,
    normalizeFocusedTestCaseReviewState,
    normalizeFocusedTestCaseStatus,
} from './ScopedScanTypes';
import { focusedCaseIntelligenceBuilder } from './FocusedCaseIntelligenceBuilder';

interface PlannerDependencies {
    generate: typeof llmRuntime.generate;
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

const MAX_PROMPT_CHARS = 18_000;

const plannerResponseSchema = z.object({
    cases: z.array(z.object({
        title: z.string().trim().min(1).max(180),
        hypothesis: z.string().trim().min(1).max(320),
        targetArtifact: z.object({
            kind: z.enum(FOCUSED_TEST_CASE_TARGET_KIND_VALUES),
            method: z.string().trim().max(16).optional(),
            path: z.string().trim().max(240).optional(),
            url: z.string().trim().max(500).optional(),
            referenceKind: z.string().trim().max(80).optional(),
            referenceId: z.string().trim().max(120).optional(),
            label: z.string().trim().max(180).optional(),
        }),
        preconditions: z.array(z.string().trim().min(1).max(200)).max(6),
        steps: z.array(z.object({
            order: z.number().int().positive(),
            action: z.string().trim().min(1).max(240),
        })).min(1).max(6),
        assertions: z.array(z.object({
            kind: z.string().trim().min(1).max(60),
            description: z.string().trim().min(1).max(220),
        })).min(1).max(5),
        requiredEvidence: z.array(z.object({
            kind: z.string().trim().min(1).max(60),
            description: z.string().trim().min(1).max(220),
        })).min(1).max(5),
        priority: z.enum(FOCUSED_TEST_CASE_PRIORITY_VALUES),
        plannerRationaleSummary: z.string().trim().min(1).max(220),
        status: z.enum(FOCUSED_TEST_CASE_STATUS_VALUES).optional(),
        reviewState: z.enum(FOCUSED_TEST_CASE_REVIEW_STATE_VALUES).optional(),
    })).max(12),
});

const plannerJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['cases'],
    properties: {
        cases: {
            type: 'array',
            maxItems: 12,
            items: {
                type: 'object',
                additionalProperties: false,
                required: [
                    'title',
                    'hypothesis',
                    'targetArtifact',
                    'preconditions',
                    'steps',
                    'assertions',
                    'requiredEvidence',
                    'priority',
                    'plannerRationaleSummary',
                ],
                properties: {
                    title: { type: 'string' },
                    hypothesis: { type: 'string' },
                    targetArtifact: {
                        type: 'object',
                        additionalProperties: false,
                        required: ['kind'],
                        properties: {
                            kind: { type: 'string', enum: [...FOCUSED_TEST_CASE_TARGET_KIND_VALUES] },
                            method: { type: 'string' },
                            path: { type: 'string' },
                            url: { type: 'string' },
                            referenceKind: { type: 'string' },
                            referenceId: { type: 'string' },
                            label: { type: 'string' },
                        },
                    },
                    preconditions: {
                        type: 'array',
                        items: { type: 'string' },
                    },
                    steps: {
                        type: 'array',
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['order', 'action'],
                            properties: {
                                order: { type: 'integer' },
                                action: { type: 'string' },
                            },
                        },
                    },
                    assertions: {
                        type: 'array',
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['kind', 'description'],
                            properties: {
                                kind: { type: 'string' },
                                description: { type: 'string' },
                            },
                        },
                    },
                    requiredEvidence: {
                        type: 'array',
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['kind', 'description'],
                            properties: {
                                kind: { type: 'string' },
                                description: { type: 'string' },
                            },
                        },
                    },
                    priority: { type: 'string', enum: [...FOCUSED_TEST_CASE_PRIORITY_VALUES] },
                    plannerRationaleSummary: { type: 'string' },
                    status: { type: 'string', enum: [...FOCUSED_TEST_CASE_STATUS_VALUES] },
                    reviewState: { type: 'string', enum: [...FOCUSED_TEST_CASE_REVIEW_STATE_VALUES] },
                },
            },
        },
    },
} as const;

export class FocusedTestPlanner {
    constructor(
        private readonly deps: PlannerDependencies = {
            generate: llmRuntime.generate.bind(llmRuntime),
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public async plan(contextPack: ContextPack, userId?: number): Promise<FocusedPlannerResponse> {
        const seedCases = this.buildSeedCases(contextPack);
        const refinedCases = await this.refineWithLlm(contextPack, seedCases, userId);
        const normalizedRefined = refinedCases
            ? this.normalizeCases(refinedCases.cases, contextPack)
            : [];

        if (normalizedRefined.length > 0) {
            return { cases: normalizedRefined };
        }

        return { cases: this.normalizeCases(seedCases, contextPack) };
    }

    private buildSeedCases(contextPack: ContextPack): FocusedTestCaseDraft[] {
        const maxCases = contextPack.plannerConstraints.maxCases;
        const targets = contextPack.selectedTargets.length > 0
            ? contextPack.selectedTargets
            : [{
                kind: contextPack.objective.scopeType === 'flow_scoped' ? 'flow' : 'feature',
                label: contextPack.objective.featureDescription || contextPack.objective.title,
            } satisfies ContextPackSelectedTarget];

        const seeds: FocusedTestCaseDraft[] = [];
        for (const target of targets) {
            const signal = analyzeTargetSignal(target, contextPack);

            if (signal.shouldTestAuthorization) {
                seeds.push(buildAuthorizationCase(target, contextPack, signal));
            }

            if (signal.shouldTestValidation) {
                seeds.push(buildValidationCase(target, contextPack, signal));
            }

            if (signal.shouldTestCsrf) {
                seeds.push(buildCsrfCase(target, contextPack, signal));
            }

            if (signal.shouldTestRendering) {
                seeds.push(buildRenderingCase(target, contextPack, signal));
            }

            if (signal.shouldTestApiMisuse) {
                seeds.push(buildApiMisuseCase(target, contextPack, signal));
            }
        }

        if (seeds.length === 0) {
            seeds.push(buildGenericScopedCase(contextPack));
        }

        return this.normalizeCases(seeds, contextPack).slice(0, maxCases);
    }

    private async refineWithLlm(
        contextPack: ContextPack,
        seedCases: FocusedTestCaseDraft[],
        userId?: number,
    ): Promise<FocusedPlannerResponse | null> {
        if (!this.shouldUseStructuredLocalPlanner(userId)) {
            return null;
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: [
                    'You are PenPard focused planner.',
                    'You produce compact, execution-oriented scoped security test cases.',
                    'Never widen backend-owned scope.',
                    'Reuse only the selectedTargets from the provided context pack.',
                    'Return only JSON that matches the schema.',
                ].join(' '),
                userPrompt: this.buildPlannerPrompt(contextPack, seedCases),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_case_plan', plannerJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 2400,
            }, {
                scanId: contextPack.scanId,
                userId,
                callSite: 'focused_test_planning',
                context: 'focused-test-planner',
                maxAttempts: 2,
            });

            return parseStructuredJsonResponse<FocusedPlannerResponse>(response, {
                label: 'Focused test planning response',
                schema: plannerResponseSchema,
            });
        } catch (error: any) {
            logger.warn('Focused test planner fell back to deterministic seed cases', {
                scanId: contextPack.scanId,
                error: error.message,
            });
            return null;
        }
    }

    private shouldUseStructuredLocalPlanner(userId?: number): boolean {
        try {
            const activeConfig = this.deps.getActiveConfig(userId);
            return activeConfig.provider === 'local_llm';
        } catch {
            return false;
        }
    }

    private buildPlannerPrompt(contextPack: ContextPack, seedCases: FocusedTestCaseDraft[]): string {
        const payload = JSON.stringify({
            contextPack,
            seedCases,
            instructions: {
                role: 'refine_seed_cases_without_expanding_scope',
                maxCases: contextPack.plannerConstraints.maxCases,
                requirements: [
                    'Keep only in-scope target artifacts.',
                    'Prefer compact, reviewable cases.',
                    'Make steps, assertions, and evidence execution-ready.',
                    'Do not add markdown or prose outside JSON.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS
            ? payload.slice(0, MAX_PROMPT_CHARS)
            : payload;
    }

    private normalizeCases(cases: FocusedTestCaseDraft[], contextPack: ContextPack): FocusedTestCaseDraft[] {
        const allowedTargets = new Set(contextPack.selectedTargets.map(toTargetKey));
        const deduped = new Map<string, FocusedTestCaseDraft>();

        for (const candidate of cases) {
            const normalized = normalizeDraftCase(candidate, contextPack, allowedTargets);
            if (!normalized) {
                continue;
            }

            const enriched = this.applyCaseIntelligence(normalized, contextPack);
            const key = `${toTargetKey(enriched.targetArtifact)}::${enriched.title.toLowerCase()}`;
            if (!deduped.has(key)) {
                deduped.set(key, enriched);
            }
        }

        return Array.from(deduped.values()).slice(0, contextPack.plannerConstraints.maxCases);
    }

    private applyCaseIntelligence(candidate: FocusedTestCaseDraft, contextPack: ContextPack): FocusedTestCaseDraft {
        const intelligence = focusedCaseIntelligenceBuilder.build(contextPack, candidate);
        const resolvedFamily = intelligence.securityConcerns[0]?.family || candidate.caseFamily || 'generic';
        const defaults = focusedCaseIntelligenceBuilder.deriveDefaults(
            intelligence,
            resolvedFamily,
            candidate.targetArtifact.kind,
        );

        return {
            ...candidate,
            caseFamily: resolvedFamily,
            caseIntelligence: intelligence,
            maxAdaptiveFollowUps: candidate.maxAdaptiveFollowUps ?? defaults.maxAdaptiveFollowUps,
            preferredRail: candidate.preferredRail ?? defaults.preferredRail,
            allowedConfirmationKinds: candidate.allowedConfirmationKinds?.length
                ? candidate.allowedConfirmationKinds
                : defaults.allowedConfirmationKinds,
        };
    }
}

function normalizeDraftCase(
    candidate: FocusedTestCaseDraft,
    contextPack: ContextPack,
    allowedTargets: Set<string>,
): FocusedTestCaseDraft | null {
    const title = trimTo(candidate.title, 180);
    const hypothesis = trimTo(candidate.hypothesis, 320);
    const plannerRationaleSummary = trimTo(candidate.plannerRationaleSummary, 220);
    if (!title || !hypothesis || !plannerRationaleSummary) {
        return null;
    }

    const targetArtifact = normalizeTargetArtifact(candidate.targetArtifact, contextPack, allowedTargets);
    if (!targetArtifact) {
        return null;
    }

    const preconditions = dedupeStrings((candidate.preconditions || []).map((entry) => trimTo(entry, 200)).filter(Boolean) as string[]).slice(0, 6);
    const steps = normalizeSteps(candidate.steps || []);
    const assertions = normalizeAssertions(candidate.assertions || []);
    const requiredEvidence = normalizeEvidence(candidate.requiredEvidence || []);

    if (steps.length === 0 || assertions.length === 0 || requiredEvidence.length === 0) {
        return null;
    }

    return {
        title,
        hypothesis,
        targetArtifact,
        preconditions: preconditions.length > 0
            ? preconditions
            : ['Stay within the persisted scoped target and reuse the captured auth context when needed.'],
        steps,
        assertions,
        requiredEvidence,
        priority: normalizeFocusedTestCasePriority(candidate.priority),
        plannerRationaleSummary,
        caseFamily: candidate.caseFamily,
        caseIntelligence: candidate.caseIntelligence || null,
        maxAdaptiveFollowUps: candidate.maxAdaptiveFollowUps ?? null,
        preferredRail: candidate.preferredRail ?? null,
        allowedConfirmationKinds: Array.isArray(candidate.allowedConfirmationKinds)
            ? candidate.allowedConfirmationKinds
            : undefined,
        status: normalizeFocusedTestCaseStatus(candidate.status),
        reviewState: normalizeFocusedTestCaseReviewState(candidate.reviewState),
    };
}

function normalizeTargetArtifact(
    artifact: FocusedTestCaseTargetArtifact,
    contextPack: ContextPack,
    allowedTargets: Set<string>,
): FocusedTestCaseTargetArtifact | null {
    const normalized: FocusedTestCaseTargetArtifact = {
        kind: artifact.kind,
        method: trimTo(artifact.method, 16)?.toUpperCase(),
        path: normalizeRoutePath(artifact.path),
        url: trimTo(artifact.url, 500),
        referenceKind: trimTo(artifact.referenceKind, 80),
        referenceId: trimTo(artifact.referenceId, 120),
        label: trimTo(artifact.label, 180),
    };

    if (normalized.kind === 'endpoint' && (!normalized.path || !normalized.method)) {
        return null;
    }
    if (normalized.kind === 'baseline_request' && !normalized.referenceKind && !normalized.path) {
        return null;
    }
    if ((normalized.kind === 'flow' || normalized.kind === 'feature') && !normalized.label) {
        normalized.label = trimTo(contextPack.objective.featureDescription || contextPack.objective.title, 180);
    }

    if (!allowedTargets.has(toTargetKey(normalized))) {
        return null;
    }

    return normalized;
}

function normalizeSteps(steps: FocusedTestStep[]): FocusedTestStep[] {
    return steps
        .map((step, index) => ({
            order: index + 1,
            action: trimTo(step.action, 240),
        }))
        .filter((step): step is FocusedTestStep => !!step.action)
        .slice(0, 6);
}

function normalizeAssertions(assertions: FocusedTestAssertion[]): FocusedTestAssertion[] {
    return assertions
        .map((assertion) => ({
            kind: trimTo(assertion.kind, 60),
            description: trimTo(assertion.description, 220),
        }))
        .filter((assertion): assertion is FocusedTestAssertion => !!assertion.kind && !!assertion.description)
        .slice(0, 5);
}

function normalizeEvidence(evidence: FocusedTestEvidenceRequirement[]): FocusedTestEvidenceRequirement[] {
    return evidence
        .map((entry) => ({
            kind: trimTo(entry.kind, 60),
            description: trimTo(entry.description, 220),
        }))
        .filter((entry): entry is FocusedTestEvidenceRequirement => !!entry.kind && !!entry.description)
        .slice(0, 5);
}

function toTargetKey(target: Pick<FocusedTestCaseTargetArtifact, 'kind' | 'method' | 'path' | 'referenceKind' | 'referenceId' | 'label'>): string {
    return [
        target.kind,
        target.method || '',
        target.path || '',
        target.referenceKind || '',
        target.referenceId || '',
        target.label || '',
    ].join(':');
}

function analyzeTargetSignal(target: ContextPackSelectedTarget, contextPack: ContextPack) {
    const text = `${target.label || ''} ${target.path || ''} ${contextPack.objective.title} ${contextPack.objective.goal || ''} ${(contextPack.objective.riskTags || []).join(' ')}`.toLowerCase();
    const method = (target.method || '').toUpperCase();
    const riskTags = new Set((contextPack.objective.riskTags || []).map((entry) => entry.toLowerCase()));
    const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
    const authSignals = riskTags.has('idor') || riskTags.has('authz') || riskTags.has('privilege') || !!contextPack.authSummary.authContext;

    return {
        method,
        mutating,
        shouldTestAuthorization: authSignals || /account|profile|admin|user|order|tenant|invoice|document|me\b|session/.test(text),
        shouldTestValidation: mutating || /search|filter|query|input|comment|message|name|email|id\b|token/.test(text),
        shouldTestCsrf: mutating,
        shouldTestRendering: /comment|post|message|bio|profile|render|html|markdown|preview|search|content/.test(text),
        shouldTestApiMisuse: target.kind === 'baseline_request' || mutating || /api|graphql|rest|json/.test(text),
        targetLabel: target.label || `${target.method || target.kind} ${target.path || ''}`.trim(),
    };
}

function buildAuthorizationCase(
    target: ContextPackSelectedTarget,
    contextPack: ContextPack,
    signal: ReturnType<typeof analyzeTargetSignal>,
): FocusedTestCaseDraft {
    return {
        title: `Authorization boundary on ${signal.targetLabel}`,
        hypothesis: 'The scoped target may return data or perform an action for an identity that should not be authorized.',
        targetArtifact: toTargetArtifact(target),
        preconditions: [
            'Use the persisted auth context or baseline request associated with this scoped scan.',
            'Keep requests inside the selected scoped target only.',
        ],
        steps: [
            { order: 1, action: 'Replay the in-scope baseline interaction to establish the authorized response shape.' },
            { order: 2, action: 'Repeat the same in-scope interaction with a lower-privilege or alternate identity when available.' },
            { order: 3, action: 'Compare ownership markers, returned fields, and authorization outcomes without widening the route scope.' },
        ],
        assertions: [
            { kind: 'authz_enforced', description: 'Unauthorized identities are denied or receive only properly scoped data.' },
            { kind: 'object_isolation', description: 'No foreign object identifiers or privilege-only fields leak in the response.' },
        ],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the authorized vs alternate-identity response difference for the same scoped target.' },
            { kind: 'status_code', description: 'Record the final status code and any authorization error markers.' },
        ],
        priority: 'high',
        plannerRationaleSummary: 'Identity-sensitive target plus scoped auth context makes an authorization boundary check high value.',
        caseFamily: 'access_control',
    };
}

function buildValidationCase(
    target: ContextPackSelectedTarget,
    contextPack: ContextPack,
    signal: ReturnType<typeof analyzeTargetSignal>,
): FocusedTestCaseDraft {
    return {
        title: `Input handling on ${signal.targetLabel}`,
        hypothesis: 'The scoped target may mishandle malformed, boundary, or unexpected input values.',
        targetArtifact: toTargetArtifact(target),
        preconditions: [
            'Limit mutations to parameters or body fields already present in the scoped interaction.',
        ],
        steps: [
            { order: 1, action: 'Identify the smallest set of in-scope parameters or body fields accepted by this target.' },
            { order: 2, action: 'Replay the same scoped request with boundary or malformed values in one field at a time.' },
            { order: 3, action: 'Observe validation errors, error handling consistency, and sensitive detail exposure.' },
        ],
        assertions: [
            { kind: 'validation_enforced', description: 'Invalid values are rejected with controlled, non-leaky responses.' },
            { kind: 'error_safety', description: 'No stack traces, raw SQL, template fragments, or parser errors are disclosed.' },
        ],
        requiredEvidence: [
            { kind: 'response_excerpt', description: 'Capture the error body or validation message for the invalid in-scope mutation.' },
            { kind: 'status_code', description: 'Record the status code change between baseline and invalid input attempts.' },
        ],
        priority: signal.mutating ? 'high' : 'medium',
        plannerRationaleSummary: 'Scoped input mutation is a bounded way to exercise validation without widening routes or flows.',
        caseFamily: 'input_validation',
    };
}

function buildCsrfCase(
    target: ContextPackSelectedTarget,
    _contextPack: ContextPack,
    signal: ReturnType<typeof analyzeTargetSignal>,
): FocusedTestCaseDraft {
    return {
        title: `Cross-site request protection on ${signal.targetLabel}`,
        hypothesis: 'The state-changing scoped target may accept unsafe cross-site style replays or missing CSRF protections.',
        targetArtifact: toTargetArtifact(target),
        preconditions: [
            'Target must remain limited to the exact scoped state-changing interaction.',
        ],
        steps: [
            { order: 1, action: 'Replay the state-changing request with the normal scoped auth context to confirm the baseline behavior.' },
            { order: 2, action: 'Repeat the same in-scope request while removing or altering CSRF-related material only.' },
            { order: 3, action: 'Compare whether the target still processes the action or exposes a missing anti-CSRF control.' },
        ],
        assertions: [
            { kind: 'csrf_enforced', description: 'Missing or invalid anti-CSRF protections block the state-changing request.' },
            { kind: 'state_change_blocked', description: 'No unintended state transition occurs when CSRF protections are absent.' },
        ],
        requiredEvidence: [
            { kind: 'state_change', description: 'Capture whether the target state changed after the CSRF-stripped replay.' },
            { kind: 'response_diff', description: 'Preserve the response difference between baseline and protection-bypassed attempts.' },
        ],
        priority: 'medium',
        plannerRationaleSummary: 'Mutating scoped routes are natural CSRF candidates and can be tested without leaving the selected target.',
        caseFamily: 'workflow_logic',
    };
}

function buildRenderingCase(
    target: ContextPackSelectedTarget,
    _contextPack: ContextPack,
    signal: ReturnType<typeof analyzeTargetSignal>,
): FocusedTestCaseDraft {
    return {
        title: `Rendered content safety on ${signal.targetLabel}`,
        hypothesis: 'User-controlled content in the scoped target may be rendered unsafely or reflected without neutralization.',
        targetArtifact: toTargetArtifact(target),
        preconditions: [
            'Use only in-scope content entry or display points tied to the selected target.',
        ],
        steps: [
            { order: 1, action: 'Submit a benign marker payload through the scoped input or query surface.' },
            { order: 2, action: 'Load the corresponding in-scope display or response path that reflects or stores the value.' },
            { order: 3, action: 'Check whether the marker is safely encoded, sanitized, or otherwise neutralized.' },
        ],
        assertions: [
            { kind: 'output_encoding', description: 'User-controlled content is encoded or sanitized before rendering.' },
            { kind: 'stored_content_safety', description: 'Stored or reflected content cannot trigger unsafe rendering behavior.' },
        ],
        requiredEvidence: [
            { kind: 'rendered_output', description: 'Capture the rendered response or DOM fragment showing safe or unsafe handling.' },
            { kind: 'payload_trace', description: 'Record the exact benign marker payload used for the in-scope test.' },
        ],
        priority: signal.mutating ? 'medium' : 'high',
        plannerRationaleSummary: 'The scoped target looks content-bearing or reflective, so rendered output safety is worth a bounded check.',
        caseFamily: 'xss',
    };
}

function buildApiMisuseCase(
    target: ContextPackSelectedTarget,
    _contextPack: ContextPack,
    signal: ReturnType<typeof analyzeTargetSignal>,
): FocusedTestCaseDraft {
    return {
        title: `API contract misuse on ${signal.targetLabel}`,
        hypothesis: 'The scoped API target may accept unsafe method, content-type, or field-shape variations that should be rejected.',
        targetArtifact: toTargetArtifact(target),
        preconditions: [
            'Constrain protocol variations to the same scoped endpoint or baseline request family.',
        ],
        steps: [
            { order: 1, action: 'Record the successful baseline request method, headers, and minimal body requirements.' },
            { order: 2, action: 'Replay the same in-scope interaction with one protocol variation, such as an unexpected method or missing required field.' },
            { order: 3, action: 'Confirm whether the target enforces the contract or processes the misuse unexpectedly.' },
        ],
        assertions: [
            { kind: 'contract_enforced', description: 'Unexpected methods, content types, or missing required fields are rejected.' },
            { kind: 'safe_failure', description: 'Contract failures are explicit and do not trigger hidden state changes.' },
        ],
        requiredEvidence: [
            { kind: 'status_code', description: 'Record the status code returned for the protocol misuse attempt.' },
            { kind: 'response_excerpt', description: 'Capture the body fragment or error marker proving contract enforcement or failure.' },
        ],
        priority: signal.mutating ? 'medium' : 'low',
        plannerRationaleSummary: 'Contract misuse checks stay bounded to the exact scoped API surface while revealing weak method or schema enforcement.',
        caseFamily: 'generic',
    };
}

function buildGenericScopedCase(contextPack: ContextPack): FocusedTestCaseDraft {
    const label = contextPack.objective.featureDescription || contextPack.objective.title;
    return {
        title: `Bounded abuse test for ${label}`,
        hypothesis: 'The scoped feature may expose at least one abuse path under the persisted boundaries.',
        targetArtifact: {
            kind: contextPack.objective.scopeType === 'flow_scoped' ? 'flow' : 'feature',
            label,
        },
        preconditions: [
            'Stay entirely inside the persisted hosts, routes, and boundary hints.',
        ],
        steps: [
            { order: 1, action: 'Reconstruct the smallest valid in-scope interaction for the selected feature or flow.' },
            { order: 2, action: 'Exercise one controlled security mutation based on the declared risk tags.' },
            { order: 3, action: 'Capture whether the feature rejects or mishandles the bounded mutation.' },
        ],
        assertions: [
            { kind: 'scope_respected', description: 'The plan remains inside the persisted scope anchors.' },
            { kind: 'security_control', description: 'The feature enforces the expected control under a bounded abuse attempt.' },
        ],
        requiredEvidence: [
            { kind: 'request_trace', description: 'Record the exact in-scope request or interaction used for the feature-level test.' },
            { kind: 'response_excerpt', description: 'Capture the response or rendered output demonstrating the control outcome.' },
        ],
        priority: 'medium',
        plannerRationaleSummary: 'A generic bounded abuse case provides coverage when the scoped target is narrative rather than endpoint-only.',
        caseFamily: 'generic',
    };
}

function toTargetArtifact(target: ContextPackSelectedTarget): FocusedTestCaseTargetArtifact {
    return {
        kind: target.kind,
        method: target.method?.toUpperCase(),
        path: normalizeRoutePath(target.path),
        url: trimTo(target.url, 500),
        label: trimTo(target.label, 180),
        referenceKind: trimTo(target.referenceKind, 80),
        referenceId: trimTo(target.referenceId, 120),
    };
}

function normalizeRoutePath(value: string | undefined): string | undefined {
    if (!value) {
        return undefined;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return undefined;
    }

    try {
        if (/^https?:\/\//i.test(trimmed)) {
            return new URL(trimmed).pathname || '/';
        }
    } catch {
        return undefined;
    }

    const withoutQuery = trimmed.split('?')[0]?.split('#')[0] || trimmed;
    return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
}

function trimTo(value: string | undefined, maxLength: number): string | undefined {
    if (typeof value !== 'string') {
        return undefined;
    }
    const trimmed = value.trim();
    return trimmed ? trimmed.slice(0, maxLength) : undefined;
}

function dedupeStrings(values: string[]): string[] {
    return [...new Set(values)];
}

export const focusedTestPlanner = new FocusedTestPlanner();
