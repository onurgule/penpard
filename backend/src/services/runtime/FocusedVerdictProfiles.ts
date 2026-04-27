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
    FocusedEvidenceSufficiencyReport,
    FocusedSignalInterpretationSummary,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedTestObjective,
    FocusedVerdictEvidenceRef,
    FocusedVerdictScopeViolationImpact,
    FocusedVerdictState,
    ScopeEnvelope,
} from './ScopedScanTypes';

const MAX_PROMPT_CHARS = 16_000;

export interface FocusedVerdictAssistanceInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope;
    testCase: FocusedTestCase;
    execution: FocusedTestCaseExecution | null;
    evidenceBundles: EvidenceBundle[];
    verdictState: FocusedVerdictState;
    verdictReason: string;
    evidenceSufficiency: FocusedEvidenceSufficiencyReport;
    interpretationSummary: FocusedSignalInterpretationSummary;
    supportingEvidenceRefs: FocusedVerdictEvidenceRef[];
    scopeViolationImpact: FocusedVerdictScopeViolationImpact;
}

export interface FocusedVerdictAssistanceProfile {
    key: string;
    provider: string | null;
    model: string | null;
    explainVerdict(input: FocusedVerdictAssistanceInput): Promise<string | null>;
}

interface VerdictProfileDependencies {
    generate: typeof llmRuntime.generate;
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

const responseSchema = z.object({
    narrative: z.string().trim().min(1).max(500),
});

const responseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['narrative'],
    properties: {
        narrative: { type: 'string' },
    },
} as const;

abstract class BaseFocusedVerdictAssistanceProfile implements FocusedVerdictAssistanceProfile {
    public readonly provider: string | null;
    public readonly model: string | null;

    public constructor(
        protected readonly activeConfig: LLMConfig | null,
        protected readonly deps: VerdictProfileDependencies,
    ) {
        this.provider = activeConfig?.provider || null;
        this.model = activeConfig?.model || null;
    }

    public abstract get key(): string;

    public async explainVerdict(input: FocusedVerdictAssistanceInput): Promise<string | null> {
        if (!this.activeConfig) {
            return null;
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildSystemPrompt(),
                userPrompt: this.buildUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_verdict_assistance', responseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 900,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_verdict',
                context: `focused-verdict-profile:${this.key}`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<{ narrative: string }>(response, {
                label: 'Focused verdict assistance',
                schema: responseSchema,
            });
            return parsed.narrative.trim().slice(0, 500);
        } catch (error: any) {
            logger.warn('Focused verdict assistance skipped after provider failure', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                profileKey: this.key,
                error: error.message,
            });
            return null;
        }
    }

    protected buildSystemPrompt(): string {
        return [
            'You are PenPard focused verdict assistance.',
            'The system already decided the verdict state using product-owned rules.',
            'Your role is only to draft a concise operator-facing narrative.',
            'Do not change the verdict, do not invent evidence, and do not widen scope.',
            'Reference only the supplied evidence, sufficiency, and blocker information.',
        ].join(' ');
    }

    protected buildUserPrompt(input: FocusedVerdictAssistanceInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
                riskTags: input.objective.riskTags,
            },
            testCase: {
                id: input.testCase.id,
                title: input.testCase.title,
                hypothesis: input.testCase.hypothesis,
                targetArtifact: input.testCase.targetArtifact,
                assertions: input.testCase.assertions,
                requiredEvidence: input.testCase.requiredEvidence,
            },
            execution: input.execution ? {
                executionState: input.execution.executionState,
                executionProfileKey: input.execution.executionProfileKey,
                notesSummary: input.execution.notesSummary,
                errorMessage: input.execution.errorMessage,
                requestActionsUsed: input.execution.requestActionsUsed,
            } : null,
            systemVerdict: {
                state: input.verdictState,
                reason: input.verdictReason,
                evidenceSufficiency: input.evidenceSufficiency,
                interpretationSummary: input.interpretationSummary,
                scopeViolationImpact: input.scopeViolationImpact,
                supportingEvidenceRefs: input.supportingEvidenceRefs,
            },
            evidenceBundles: input.evidenceBundles.slice(0, 6).map((bundle) => ({
                id: bundle.id,
                source: bundle.source,
                summary: bundle.summary,
                executionNotes: bundle.executionNotes || null,
                responseDiffSummary: bundle.responseDiffSummary || null,
                scopeViolation: bundle.scopeViolation || null,
            })),
            instructions: {
                requirements: [
                    'Write 2-4 sentences in plain operator-facing language.',
                    'Explain why the current verdict was system-selected.',
                    'Call out missing evidence or blockers when the verdict is not pass.',
                    'Never suggest that the model overrode the verdict.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS
            ? payload.slice(0, MAX_PROMPT_CHARS)
            : payload;
    }
}

export class GenericFocusedVerdictProfile extends BaseFocusedVerdictAssistanceProfile {
    public get key(): string {
        return this.activeConfig?.provider
            ? `generic:${this.activeConfig.provider}`
            : 'generic:fallback';
    }
}

export class QwenFocusedVerdictProfile extends BaseFocusedVerdictAssistanceProfile {
    public get key(): string {
        return 'local_qwen';
    }

    protected buildSystemPrompt(): string {
        return [
            'You are PenPard focused verdict assistance for a local Qwen profile.',
            'The verdict state is already decided by backend rules and cannot be changed by you.',
            'Return only compact JSON with a concise narrative grounded in the supplied evidence.',
            'Do not invent extra testing steps, verdict states, or scope changes.',
        ].join(' ');
    }
}

function isQwenModel(model: string | null | undefined): boolean {
    const normalized = String(model || '').trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

export class FocusedVerdictAssistanceProfileResolver {
    constructor(
        private readonly deps: VerdictProfileDependencies = {
            generate: llmRuntime.generate.bind(llmRuntime),
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public resolve(userId?: number): FocusedVerdictAssistanceProfile {
        let activeConfig: LLMConfig | null = null;
        try {
            activeConfig = this.deps.getActiveConfig(userId);
        } catch {
            activeConfig = null;
        }

        if (activeConfig?.provider === 'local_llm' && isQwenModel(activeConfig.model)) {
            return new QwenFocusedVerdictProfile(activeConfig, this.deps);
        }

        return new GenericFocusedVerdictProfile(activeConfig, this.deps);
    }
}

export const focusedVerdictAssistanceProfileResolver = new FocusedVerdictAssistanceProfileResolver();
