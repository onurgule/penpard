import { z } from 'zod';
import type { LLMConfig } from '../LLMProviderService';
import { llmProvider } from '../LLMProviderService';
import { llmRuntime } from '../llm/LlmRuntime';
import {
    buildJsonSchemaResponseFormat,
    parseStructuredJsonResponse,
} from '../llm/LlmStructuredOutput';
import { logger } from '../../utils/logger';
import type {
    EvidenceBundle,
    FocusedBrowserExpectation,
    FocusedBrowserPlan,
    FocusedBrowserStep,
    FocusedConfirmationKind,
    FocusedExecutionAction,
    FocusedFindingThread,
    FocusedTestCase,
    FocusedTestObjective,
    ScopeEnvelope,
} from './ScopedScanTypes';
import {
    FOCUSED_CASE_INPUT_LOCATION_VALUES,
    FOCUSED_CASE_MUTATION_STRATEGY_VALUES,
    FOCUSED_BROWSER_STEP_ACTION_VALUES,
    FOCUSED_EXECUTION_ACTION_VALUES,
} from './ScopedScanTypes';
import {
    focusedMutationPlanner,
    type FocusedObservedRequestShape,
} from './FocusedMutationPlanner';

const MAX_PROMPT_CHARS = 14_000;

export interface FocusedExecutionAnchor {
    defaultMethod: string;
    defaultUrl: string;
    defaultPath?: string;
    useInitialRequestBaseline: boolean;
    baselineAvailable: boolean;
    requestShape?: FocusedObservedRequestShape | null;
}

export interface FocusedBrowserAnchor {
    startUrl: string;
    startPath?: string;
    source: 'target_artifact' | 'selected_endpoint' | 'baseline_request' | 'allowed_route' | 'discovered_request' | 'discovered_browser' | 'request_url';
}

export interface FocusedExecutionPlanningInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope;
    testCase: FocusedTestCase;
    anchor: FocusedExecutionAnchor;
    remainingRequestBudget: number;
    maxRouteVariants: number;
    recentEvidence: EvidenceBundle[];
}

export interface FocusedBrowserPlanningInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope;
    testCase: FocusedTestCase;
    browserAnchor: FocusedBrowserAnchor;
    relatedEvidence: EvidenceBundle[];
}

export interface FocusedConfirmationPlanningInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope;
    testCase: FocusedTestCase;
    anchor: FocusedExecutionAnchor;
    browserAnchor?: FocusedBrowserAnchor | null;
    findingThread: FocusedFindingThread;
    confirmationKind: FocusedConfirmationKind;
    remainingRequestBudget: number;
    recentEvidence: EvidenceBundle[];
    confirmationOrdinal: number;
}

export interface FocusedStatefulExecutionSummaryInput {
    testCase: FocusedTestCase;
    browserPlan: FocusedBrowserPlan;
    browserEvidence?: EvidenceBundle | null;
    relatedEvidence: EvidenceBundle[];
}

export interface FocusedExecutionProfile {
    key: string;
    provider: string | null;
    model: string | null;
    planActions(input: FocusedExecutionPlanningInput): Promise<FocusedExecutionAction[]>;
    planConfirmationActions(input: FocusedConfirmationPlanningInput): Promise<FocusedExecutionAction[]>;
    planBrowserSequence?(input: FocusedBrowserPlanningInput): Promise<FocusedBrowserPlan | null>;
    summarizeStatefulExecution?(input: FocusedStatefulExecutionSummaryInput): Promise<string | null>;
}

interface ExecutionDependencies {
    generate: typeof llmRuntime.generate;
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

const actionSchema = z.object({
    type: z.enum(FOCUSED_EXECUTION_ACTION_VALUES),
    summary: z.string().trim().min(1).max(220),
    method: z.string().trim().max(16).optional(),
    url: z.string().trim().max(500).optional(),
    preserveExplicitAuth: z.boolean().optional(),
    useInitialRequestBaseline: z.boolean().optional(),
    queryMutations: z.array(z.object({
        name: z.string().trim().min(1).max(80),
        value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
    })).max(4).optional(),
    bodyMutations: z.array(z.object({
        name: z.string().trim().min(1).max(80),
        value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
    })).max(4).optional(),
    targetInputs: z.array(z.object({
        name: z.string().trim().min(1).max(80),
        location: z.enum(FOCUSED_CASE_INPUT_LOCATION_VALUES),
        reason: z.string().trim().min(1).max(220),
        mutationStrategy: z.enum(FOCUSED_CASE_MUTATION_STRATEGY_VALUES),
        observedValuePreview: z.string().trim().max(120).nullable().optional(),
    })).max(3).optional(),
    expectedSignals: z.array(z.string().trim().min(1).max(160)).max(4).optional(),
    selectionReason: z.string().trim().max(220).optional(),
    note: z.string().trim().max(300).optional(),
    reason: z.string().trim().max(220).optional(),
});

const responseSchema = z.object({
    actions: z.array(actionSchema).max(5),
});

const responseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['actions'],
    properties: {
        actions: {
            type: 'array',
            maxItems: 5,
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['type', 'summary'],
                properties: {
                    type: { type: 'string', enum: [...FOCUSED_EXECUTION_ACTION_VALUES] },
                    summary: { type: 'string' },
                    method: { type: 'string' },
                    url: { type: 'string' },
                    preserveExplicitAuth: { type: 'boolean' },
                    useInitialRequestBaseline: { type: 'boolean' },
                    queryMutations: {
                        type: 'array',
                        maxItems: 4,
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['name', 'value'],
                            properties: {
                                name: { type: 'string' },
                                value: { anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] },
                            },
                        },
                    },
                    bodyMutations: {
                        type: 'array',
                        maxItems: 4,
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['name', 'value'],
                            properties: {
                                name: { type: 'string' },
                                value: { anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] },
                            },
                        },
                    },
                    targetInputs: {
                        type: 'array',
                        maxItems: 3,
                        items: {
                            type: 'object',
                            additionalProperties: false,
                            required: ['name', 'location', 'reason', 'mutationStrategy'],
                            properties: {
                                name: { type: 'string' },
                                location: { type: 'string' },
                                reason: { type: 'string' },
                                mutationStrategy: { type: 'string' },
                                observedValuePreview: { type: ['string', 'null'] },
                            },
                        },
                    },
                    expectedSignals: {
                        type: 'array',
                        maxItems: 4,
                        items: { type: 'string' },
                    },
                    selectionReason: { type: 'string' },
                    note: { type: 'string' },
                    reason: { type: 'string' },
                },
            },
        },
    },
} as const;

const browserStepSchema = z.object({
    action: z.enum(FOCUSED_BROWSER_STEP_ACTION_VALUES),
    summary: z.string().trim().min(1).max(220),
    url: z.string().trim().max(500).optional(),
    selector: z.string().trim().max(220).optional(),
    value: z.string().trim().max(240).optional(),
    timeoutMs: z.number().int().positive().max(30000).optional(),
});

const browserExpectationSchema = z.object({
    kind: z.string().trim().min(1).max(80),
    description: z.string().trim().min(1).max(240),
    matcher: z.enum(['page_loaded', 'path_matches', 'text_contains', 'text_absent', 'title_contains', 'state_changed', 'state_unchanged']),
    value: z.string().trim().max(240).nullable().optional(),
});

const browserPlanSchema = z.object({
    summary: z.string().trim().min(1).max(280),
    steps: z.array(browserStepSchema).max(8),
    expectations: z.array(browserExpectationSchema).max(6),
});

const browserPlanJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'steps', 'expectations'],
    properties: {
        summary: { type: 'string' },
        steps: {
            type: 'array',
            maxItems: 8,
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['action', 'summary'],
                properties: {
                    action: { type: 'string', enum: [...FOCUSED_BROWSER_STEP_ACTION_VALUES] },
                    summary: { type: 'string' },
                    url: { type: 'string' },
                    selector: { type: 'string' },
                    value: { type: 'string' },
                    timeoutMs: { type: 'number' },
                },
            },
        },
        expectations: {
            type: 'array',
            maxItems: 6,
            items: {
                type: 'object',
                additionalProperties: false,
                required: ['kind', 'description', 'matcher'],
                properties: {
                    kind: { type: 'string' },
                    description: { type: 'string' },
                    matcher: { type: 'string', enum: ['page_loaded', 'path_matches', 'text_contains', 'text_absent', 'title_contains', 'state_changed', 'state_unchanged'] },
                    value: { type: ['string', 'null'] },
                },
            },
        },
    },
} as const;

abstract class BaseFocusedExecutionProfile implements FocusedExecutionProfile {
    public readonly provider: string | null;
    public readonly model: string | null;

    protected constructor(
        protected readonly activeConfig: LLMConfig | null,
        protected readonly deps: ExecutionDependencies,
    ) {
        this.provider = activeConfig?.provider || null;
        this.model = activeConfig?.model || null;
    }

    public abstract get key(): string;

    public async planActions(input: FocusedExecutionPlanningInput): Promise<FocusedExecutionAction[]> {
        if (!this.activeConfig) {
            return this.buildFallbackActions(input);
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildSystemPrompt(),
                userPrompt: this.buildUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_execution_actions', responseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 1400,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_execution',
                context: `focused-execution-profile:${this.key}`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<{ actions: FocusedExecutionAction[] }>(response, {
                label: 'Focused execution action plan',
                schema: responseSchema,
            });
            const normalized = this.normalizeActions(parsed.actions, input);
            return normalized.length > 0 ? normalized : this.buildFallbackActions(input);
        } catch (error: any) {
            logger.warn('Focused execution profile fell back to deterministic actions', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                profileKey: this.key,
                error: error.message,
            });
            return this.buildFallbackActions(input);
        }
    }

    public async planBrowserSequence(input: FocusedBrowserPlanningInput): Promise<FocusedBrowserPlan | null> {
        if (!this.activeConfig) {
            return this.buildFallbackBrowserPlan(input);
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildBrowserSystemPrompt(),
                userPrompt: this.buildBrowserUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_browser_plan', browserPlanJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 1400,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_execution',
                context: `focused-browser-profile:${this.key}`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<FocusedBrowserPlan>(response, {
                label: 'Focused browser plan',
                schema: browserPlanSchema,
            });
            return this.normalizeBrowserPlan(parsed, input);
        } catch (error: any) {
            logger.warn('Focused execution profile fell back to deterministic browser steps', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                profileKey: this.key,
                error: error.message,
            });
            return this.buildFallbackBrowserPlan(input);
        }
    }

    public async summarizeStatefulExecution(input: FocusedStatefulExecutionSummaryInput): Promise<string | null> {
        const passed = input.browserPlan.expectations.length > 0
            ? input.browserPlan.expectations.length
            : null;
        const relatedEvidenceCount = input.relatedEvidence.length;
        return [
            `Stateful proof stayed anchored to ${input.testCase.title}.`,
            passed !== null ? `${passed} bounded browser expectation(s) were planned.` : null,
            relatedEvidenceCount > 0 ? `${relatedEvidenceCount} related request evidence bundle(s) were linked.` : null,
        ].filter((entry): entry is string => !!entry).join(' ').slice(0, 320) || null;
    }

    public async planConfirmationActions(input: FocusedConfirmationPlanningInput): Promise<FocusedExecutionAction[]> {
        return this.buildFallbackConfirmationActions(input);
    }

    protected buildSystemPrompt(): string {
        return [
            'You are PenPard focused execution planner.',
            'Return only compact JSON actions for a reviewed scoped test case.',
            'Never widen backend-owned scope.',
            'Use only the provided anchor and allowed routes.',
            'Prefer request-grounded execution first and add browser_sequence/browser_state_check only when UI or state proof is necessary.',
            'Do not invent crawling, recon, or verdicts.',
        ].join(' ');
    }

    protected buildBrowserSystemPrompt(): string {
        return [
            'You are PenPard focused browser planner.',
            'Return only compact JSON for a bounded browser verification sequence.',
            'Stay inside the approved focused case, approved start URL, allowed hosts, and allowed routes.',
            'Use only goto, click, fill, select, submit, waitForNavigation, waitForSelector, and reload.',
            'Do not invent new routes, crawling, or recon.',
        ].join(' ');
    }

    protected buildUserPrompt(input: FocusedExecutionPlanningInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
                riskTags: input.objective.riskTags,
            },
            scope: {
                allowedHosts: input.scopeEnvelope.allowedHosts,
                allowedRoutes: input.scopeEnvelope.allowedRoutes,
                selectedEndpoints: input.scopeEnvelope.selectedEndpoints,
                baselineRequestRefs: input.scopeEnvelope.baselineRequestRefs,
                explorationBudget: input.scopeEnvelope.explorationBudget,
            },
            testCase: {
                id: input.testCase.id,
                title: input.testCase.title,
                hypothesis: input.testCase.hypothesis,
                targetArtifact: input.testCase.targetArtifact,
                caseIntelligence: input.testCase.caseIntelligence,
                steps: input.testCase.steps,
                assertions: input.testCase.assertions,
                requiredEvidence: input.testCase.requiredEvidence,
            },
            anchor: input.anchor,
            executionBudget: {
                remainingRequestBudget: input.remainingRequestBudget,
                maxRouteVariants: input.maxRouteVariants,
            },
            recentEvidence: input.recentEvidence.slice(-3).map((bundle) => ({
                source: bundle.source,
                summary: bundle.summary,
                notes: bundle.executionNotes || null,
            })),
            instructions: {
                allowedActions: [...FOCUSED_EXECUTION_ACTION_VALUES],
                requirements: [
                    'Stay inside the approved case and persisted scope.',
                    'Use useInitialRequestBaseline=true whenever the case is baseline-request scoped.',
                    'Use compare_responses after any mutated replay when request evidence exists.',
                    'Prefer browser_state_check for rendered_output or state_change proof.',
                    'Finish with complete_case or block_case.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }

    protected buildBrowserUserPrompt(input: FocusedBrowserPlanningInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
            },
            scope: {
                allowedHosts: input.scopeEnvelope.allowedHosts,
                allowedRoutes: input.scopeEnvelope.allowedRoutes,
                explorationBudget: input.scopeEnvelope.explorationBudget,
            },
            testCase: {
                id: input.testCase.id,
                title: input.testCase.title,
                hypothesis: input.testCase.hypothesis,
                targetArtifact: input.testCase.targetArtifact,
                caseIntelligence: input.testCase.caseIntelligence,
                steps: input.testCase.steps,
                assertions: input.testCase.assertions,
                requiredEvidence: input.testCase.requiredEvidence,
            },
            browserAnchor: input.browserAnchor,
            relatedEvidence: input.relatedEvidence.slice(-3).map((bundle) => ({
                source: bundle.source,
                summary: bundle.summary,
                relatedEvidenceIds: bundle.relatedEvidenceIds || [],
            })),
            instructions: {
                allowedActions: [...FOCUSED_BROWSER_STEP_ACTION_VALUES],
                requirements: [
                    'Open only the approved start URL and routes that remain inside the allowed scope.',
                    'Select a short bounded browser sequence that verifies the approved state change or rendered output.',
                    'Include only expectation checks that can be evaluated from page title, path, or visible text.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }

    protected normalizeActions(actions: FocusedExecutionAction[], input: FocusedExecutionPlanningInput): FocusedExecutionAction[] {
        const normalized = actions
            .map((action) => this.normalizeAction(action, input))
            .filter((action): action is FocusedExecutionAction => !!action)
            .slice(0, 5);

        if (normalized.length === 0) {
            return [];
        }

        const hasTerminalAction = normalized.some((action) => action.type === 'complete_case' || action.type === 'block_case');
        if (!hasTerminalAction) {
            normalized.push({
                type: 'complete_case',
                summary: 'Complete the bounded focused test case after the planned steps.',
            });
        }

        return normalized;
    }

    protected normalizeAction(action: FocusedExecutionAction, input: FocusedExecutionPlanningInput): FocusedExecutionAction | null {
        const summary = String(action.summary || '').trim().slice(0, 220);
        if (!summary) {
            return null;
        }

        const normalizedType = FOCUSED_EXECUTION_ACTION_VALUES.includes(action.type) ? action.type : null;
        if (!normalizedType) {
            return null;
        }

        if ((normalizedType === 'baseline_replay' || normalizedType === 'mutated_replay') && input.remainingRequestBudget <= 0) {
            return null;
        }

        return {
            type: normalizedType,
            summary,
            method: typeof action.method === 'string' ? action.method.trim().toUpperCase() : undefined,
            url: typeof action.url === 'string' ? action.url.trim() : undefined,
            preserveExplicitAuth: action.preserveExplicitAuth,
            useInitialRequestBaseline: action.useInitialRequestBaseline,
            queryMutations: Array.isArray(action.queryMutations)
                ? action.queryMutations.slice(0, 4).map((entry) => ({ name: entry.name.trim(), value: entry.value }))
                : undefined,
            bodyMutations: Array.isArray(action.bodyMutations)
                ? action.bodyMutations.slice(0, 4).map((entry) => ({ name: entry.name.trim(), value: entry.value }))
                : undefined,
            targetInputs: Array.isArray(action.targetInputs)
                ? action.targetInputs.slice(0, 3).map((entry) => ({
                    name: entry.name.trim(),
                    location: entry.location,
                    reason: entry.reason.trim(),
                    mutationStrategy: entry.mutationStrategy,
                    observedValuePreview: entry.observedValuePreview ?? null,
                }))
                : undefined,
            expectedSignals: Array.isArray(action.expectedSignals)
                ? action.expectedSignals.slice(0, 4).map((entry) => entry.trim()).filter(Boolean)
                : undefined,
            selectionReason: typeof action.selectionReason === 'string' ? action.selectionReason.trim().slice(0, 220) : undefined,
            note: typeof action.note === 'string' ? action.note.trim().slice(0, 300) : undefined,
            reason: typeof action.reason === 'string' ? action.reason.trim().slice(0, 220) : undefined,
        };
    }

    protected normalizeBrowserPlan(plan: FocusedBrowserPlan, input: FocusedBrowserPlanningInput): FocusedBrowserPlan {
        const steps = (plan.steps || [])
            .map((step) => this.normalizeBrowserStep(step, input.browserAnchor))
            .filter((step): step is FocusedBrowserStep => !!step)
            .slice(0, 8);
        const expectations = (plan.expectations || [])
            .map((expectation) => this.normalizeBrowserExpectation(expectation))
            .filter((expectation): expectation is FocusedBrowserExpectation => !!expectation)
            .slice(0, 6);

        return {
            summary: String(plan.summary || '').trim().slice(0, 280) || `Verify ${input.testCase.title} through a bounded browser path.`,
            steps,
            expectations,
        };
    }

    protected normalizeBrowserStep(step: FocusedBrowserStep, anchor: FocusedBrowserAnchor): FocusedBrowserStep | null {
        const action = FOCUSED_BROWSER_STEP_ACTION_VALUES.includes(step.action) ? step.action : null;
        const summary = String(step.summary || '').trim().slice(0, 220);
        if (!action || !summary) {
            return null;
        }
        return {
            action,
            summary,
            url: typeof step.url === 'string' ? step.url.trim() : (action === 'goto' ? anchor.startUrl : undefined),
            selector: typeof step.selector === 'string' ? step.selector.trim() : undefined,
            value: typeof step.value === 'string' ? step.value.trim() : undefined,
            timeoutMs: typeof step.timeoutMs === 'number' ? step.timeoutMs : undefined,
        };
    }

    protected normalizeBrowserExpectation(expectation: FocusedBrowserExpectation): FocusedBrowserExpectation | null {
        const kind = String(expectation.kind || '').trim().slice(0, 80);
        const description = String(expectation.description || '').trim().slice(0, 240);
        if (!kind || !description) {
            return null;
        }
        return {
            kind,
            description,
            matcher: expectation.matcher,
            value: expectation.value ? String(expectation.value).trim().slice(0, 240) : null,
        };
    }

    protected buildFallbackActions(input: FocusedExecutionPlanningInput): FocusedExecutionAction[] {
        const actions: FocusedExecutionAction[] = [];
        const requestActionBase = {
            method: input.anchor.defaultMethod,
            url: input.anchor.defaultUrl,
            preserveExplicitAuth: true,
            useInitialRequestBaseline: input.anchor.useInitialRequestBaseline,
        };

        const needsBrowserProof = this.caseNeedsBrowserProof(input.testCase);
        const requestEligible = input.testCase.targetArtifact.kind === 'endpoint' || input.testCase.targetArtifact.kind === 'baseline_request';
        const primaryMutation = requestEligible && input.remainingRequestBudget > 1
            ? focusedMutationPlanner.buildPrimaryMutationAction({
                testCase: input.testCase,
                anchor: input.anchor,
            })
            : null;

        if (requestEligible) {
            actions.push({
                type: 'baseline_replay',
                summary: 'Replay the approved in-scope request anchor to capture the baseline response.',
                ...requestActionBase,
                selectionReason: input.testCase.caseIntelligence?.selectionSummary
                    || 'Baseline evidence keeps the focused case anchored before any same-scope contrast is attempted.',
                expectedSignals: ['Authorized baseline response shape'],
                targetInputs: input.testCase.caseIntelligence?.candidateInputs?.slice(0, 2),
            });

            if (primaryMutation) {
                actions.push(primaryMutation);
                actions.push({
                    type: 'compare_responses',
                    summary: 'Compare the mutated response against the captured baseline response.',
                    selectionReason: 'The bounded contrast only matters if it can be explained against the baseline response shape.',
                    expectedSignals: [
                        'Control-held response stays stable',
                        'Suspicious delta strengthens the active hypothesis',
                    ],
                });
            }
        }

        if (needsBrowserProof) {
            actions.push({
                type: requestEligible ? 'browser_state_check' : 'browser_sequence',
                summary: requestEligible
                    ? 'Use a bounded browser check to confirm the post-request UI or state outcome.'
                    : 'Execute the approved bounded browser flow for this flow/feature-scoped case.',
                selectionReason: input.testCase.caseIntelligence?.securityConcerns?.[0]?.boundedChecks?.[0]
                    || 'The case still needs same-path browser proof to explain the observed state or render outcome.',
                expectedSignals: ['Same-path UI or state proof'],
                targetInputs: input.testCase.caseIntelligence?.candidateInputs?.filter((entry) => entry.location === 'rendered_content' || entry.location === 'workflow_state').slice(0, 2),
            });
        }

        if (actions.length < 4) {
            actions.push({
                type: 'capture_note',
                summary: 'Capture a concise execution note for the bounded case.',
                note: [
                    `Executed scoped case "${input.testCase.title}".`,
                    input.testCase.caseIntelligence?.anchorSummary || null,
                ].filter((entry): entry is string => !!entry).join(' '),
                selectionReason: 'Preserve the operator-readable story even when the bounded case stops early.',
                expectedSignals: ['Operator-readable bounded execution note'],
            });
        }
        actions.push({
            type: 'complete_case',
            summary: 'Complete the focused case after evidence capture.',
        });

        return actions.slice(0, 5);
    }

    protected buildFallbackBrowserPlan(input: FocusedBrowserPlanningInput): FocusedBrowserPlan {
        const expectations = this.buildFallbackExpectations(input);
        const formFillHints = this.extractFillHints(input.testCase.steps);
        const steps: FocusedBrowserStep[] = [];

        for (const hint of formFillHints) {
            steps.push({
                action: 'fill',
                summary: `Populate ${hint.selector}.`,
                selector: hint.selector,
                value: hint.value,
            });
        }

        if (input.testCase.steps.some((step) => /submit|save|update|create|confirm/i.test(step.action))) {
            steps.push({
                action: 'submit',
                summary: 'Submit the approved form or action trigger.',
                selector: 'button[type="submit"], input[type="submit"], button',
            });
            steps.push({
                action: 'waitForNavigation',
                summary: 'Wait for the approved post-submit page state to settle.',
                timeoutMs: 15000,
            });
        } else if (expectations.some((expectation) => expectation.matcher === 'text_contains' || expectation.matcher === 'text_absent')) {
            steps.push({
                action: 'waitForSelector',
                summary: 'Wait briefly for the approved page state to render.',
                selector: 'body',
                timeoutMs: 8000,
            });
        }

        return {
            summary: `Verify ${input.testCase.title} through the approved browser anchor ${input.browserAnchor.startPath || input.browserAnchor.startUrl}.`,
            steps,
            expectations,
        };
    }

    protected buildFallbackExpectations(input: FocusedBrowserPlanningInput): FocusedBrowserExpectation[] {
        const expectations: FocusedBrowserExpectation[] = [{
            kind: 'page_loaded',
            description: 'The approved scoped page should load inside the browser rail.',
            matcher: 'page_loaded',
        }];

        if (input.browserAnchor.startPath) {
            expectations.push({
                kind: 'path_matches',
                description: 'The browser should remain on an approved in-scope path.',
                matcher: 'path_matches',
                value: input.browserAnchor.startPath,
            });
        }

        for (const requirement of input.testCase.requiredEvidence) {
            const normalizedKind = String(requirement.kind || '').trim().toLowerCase();
            const expectedText = this.extractQuotedSnippet(requirement.description)
                || this.extractQuotedSnippet(input.testCase.hypothesis)
                || this.extractQuotedSnippet(input.testCase.assertions.map((entry) => entry.description).join(' '));
            if (normalizedKind === 'rendered_output' && expectedText) {
                expectations.push({
                    kind: requirement.kind,
                    description: requirement.description,
                    matcher: 'text_contains',
                    value: expectedText,
                });
            }
            if (normalizedKind === 'state_change') {
                expectations.push({
                    kind: requirement.kind,
                    description: requirement.description,
                    matcher: 'state_changed',
                    value: expectedText || null,
                });
            }
            if ((normalizedKind === 'scope_respected' || normalizedKind === 'response_trace') && input.browserAnchor.startPath) {
                expectations.push({
                    kind: requirement.kind,
                    description: requirement.description,
                    matcher: 'path_matches',
                    value: input.browserAnchor.startPath,
                });
            }
        }

        return expectations.slice(0, 6);
    }

    protected caseNeedsBrowserProof(testCase: FocusedTestCase): boolean {
        const scopeDriven = testCase.targetArtifact.kind === 'flow' || testCase.targetArtifact.kind === 'feature';
        const evidenceDriven = testCase.requiredEvidence.some((entry) => {
            const kind = String(entry.kind || '').trim().toLowerCase();
            return kind === 'rendered_output' || kind === 'state_change';
        });
        return scopeDriven || evidenceDriven;
    }

    protected extractFillHints(steps: Array<{ action: string }>): Array<{ selector: string; value: string }> {
        const hints: Array<{ selector: string; value: string }> = [];
        for (const step of steps) {
            const action = String(step.action || '');
            const selectorMatch = action.match(/(#[-_A-Za-z0-9]+|\[[^\]]+\]|[A-Za-z]+(?:\[[^\]]+\])?)/);
            const valueMatch = action.match(/["']([^"']+)["']/);
            if (selectorMatch && valueMatch && /fill|enter|type/i.test(action)) {
                hints.push({
                    selector: selectorMatch[1],
                    value: valueMatch[1],
                });
            }
        }
        return hints.slice(0, 3);
    }

    protected extractQuotedSnippet(value: string): string | null {
        const match = String(value || '').match(/["']([^"']{2,120})["']/);
        return match ? match[1] : null;
    }

    protected buildFallbackConfirmationActions(input: FocusedConfirmationPlanningInput): FocusedExecutionAction[] {
        const actions: FocusedExecutionAction[] = [];
        const push = (action: FocusedExecutionAction) => {
            actions.push({
                ...action,
                phase: 'adaptive_confirmation',
                confirmationKind: input.confirmationKind,
                generatedFromFindingThreadId: input.findingThread.id,
                confirmationOrdinal: input.confirmationOrdinal,
            });
        };

        const mutationAction = input.remainingRequestBudget > 0
            ? focusedMutationPlanner.buildConfirmationMutationAction({
                testCase: input.testCase,
                anchor: input.anchor,
                confirmationKind: input.confirmationKind,
                confirmationOrdinal: input.confirmationOrdinal,
                browserAnchorAvailable: !!input.browserAnchor,
            })
            : null;

        if (mutationAction) {
            push(mutationAction);
        }
        if (mutationAction?.type === 'mutated_replay') {
            push({
                type: 'compare_responses',
                summary: `Adaptive confirmation ${input.confirmationOrdinal}: compare the new same-scope replay against the strongest suspicious baseline.`,
                selectionReason: 'The follow-up is only useful if the operator can see whether it strengthened or weakened the same hypothesis.',
                expectedSignals: [
                    'Signal strengthens on the same scope',
                    'Control-held contrast weakens the hypothesis',
                ],
            });
            if (input.confirmationKind === 'render_check' && input.browserAnchor) {
                push({
                    type: 'browser_state_check',
                    summary: `Adaptive confirmation ${input.confirmationOrdinal}: verify whether the same suspicious render outcome appears on the approved display path.`,
                    selectionReason: 'Keep the request-backed mutation authoritative, then gather browser-backed proof on the same path as supporting evidence only.',
                    expectedSignals: [
                        'Visible render marker outcome on the same approved path',
                        'Render proof stays absent even though request-backed suspicion remains',
                    ],
                });
            }
        }
        if (!mutationAction) {
            push({
                type: 'capture_note',
                summary: `Adaptive confirmation ${input.confirmationOrdinal}: no same-scope follow-up could be planned.`,
                note: 'No bounded adaptive confirmation step could be planned from the persisted inputs and anchors.',
                selectionReason: 'The runtime preserves the blocker instead of widening scope.',
                expectedSignals: ['Explicit bounded stop reason'],
                reason: 'Keep the operator informed about why confirmation stopped.',
            });
        }

        return actions.slice(0, 3);
    }
}

export class GenericFocusedExecutionProfile extends BaseFocusedExecutionProfile {
    constructor(activeConfig: LLMConfig | null, deps: ExecutionDependencies) {
        super(activeConfig, deps);
    }

    public get key(): string {
        return this.activeConfig?.provider ? `generic:${this.activeConfig.provider}` : 'generic:fallback';
    }
}

export class QwenFocusedExecutionProfile extends BaseFocusedExecutionProfile {
    constructor(activeConfig: LLMConfig | null, deps: ExecutionDependencies) {
        super(activeConfig, deps);
    }

    public get key(): string {
        return 'local_qwen';
    }

    protected buildSystemPrompt(): string {
        return [
            'You are PenPard focused execution planner for a local Qwen profile.',
            'Return only compact JSON actions.',
            'Stay strictly inside persisted scope and the approved focused case.',
            'Prefer one baseline replay, one bounded mutated replay, then compare_responses.',
            'When the case needs rendered/state proof, add browser_state_check without widening scope.',
            'Do not widen scope, do not crawl, and do not issue verdicts.',
        ].join(' ');
    }

    protected buildBrowserSystemPrompt(): string {
        return [
            'You are PenPard focused browser planner for a local Qwen profile.',
            'Return only compact JSON for a bounded browser verification sequence.',
            'Stay inside the approved start URL, allowed hosts, allowed routes, and the case objective.',
            'Choose the smallest sequence that can confirm the intended rendered output or state change.',
            'Never invent broad browsing, route discovery, or recon.',
        ].join(' ');
    }
}

function isQwenModel(model: string | null | undefined): boolean {
    const normalized = String(model || '').trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

export class FocusedExecutionProfileResolver {
    constructor(
        private readonly deps: ExecutionDependencies = {
            generate: llmRuntime.generate.bind(llmRuntime),
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public resolve(userId?: number): FocusedExecutionProfile {
        let activeConfig: LLMConfig | null = null;
        try {
            activeConfig = this.deps.getActiveConfig(userId);
        } catch {
            activeConfig = null;
        }

        if (activeConfig?.provider === 'local_llm' && isQwenModel(activeConfig.model)) {
            return new QwenFocusedExecutionProfile(activeConfig, this.deps);
        }

        return new GenericFocusedExecutionProfile(activeConfig, this.deps);
    }
}

export const focusedExecutionProfileResolver = new FocusedExecutionProfileResolver();
