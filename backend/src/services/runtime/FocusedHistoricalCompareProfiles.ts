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
    FocusedCaseHistoricalCompare,
    FocusedHistoricalCompareState,
    FocusedHistoricalCompareSummary,
    FocusedTestCase,
    FocusedTestObjective,
} from './ScopedScanTypes';

const MAX_PROMPT_CHARS = 16_000;

export interface FocusedHistoricalCompareCaseNarrativeInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    testCase: FocusedTestCase;
    previousCase: FocusedTestCase | null;
    compare: FocusedCaseHistoricalCompare;
}

export interface FocusedHistoricalCompareRunNarrativeInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    compareState: FocusedHistoricalCompareState;
    compareSummary: FocusedHistoricalCompareSummary;
}

export interface FocusedHistoricalCompareAssistanceProfile {
    key: string;
    provider: string | null;
    model: string | null;
    describeCaseCompare(input: FocusedHistoricalCompareCaseNarrativeInput): Promise<string | null>;
    describeRunCompare(input: FocusedHistoricalCompareRunNarrativeInput): Promise<string | null>;
}

interface HistoricalCompareProfileDependencies {
    generate: typeof llmRuntime.generate;
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

const caseResponseSchema = z.object({
    narrative: z.string().trim().min(1).max(320).nullable(),
});

const caseResponseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['narrative'],
    properties: {
        narrative: { type: ['string', 'null'] },
    },
} as const;

const runResponseSchema = z.object({
    headline: z.string().trim().min(1).max(320).nullable(),
});

const runResponseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['headline'],
    properties: {
        headline: { type: ['string', 'null'] },
    },
} as const;

abstract class BaseFocusedHistoricalCompareProfile implements FocusedHistoricalCompareAssistanceProfile {
    public readonly provider: string | null;
    public readonly model: string | null;

    public constructor(
        protected readonly activeConfig: LLMConfig | null,
        protected readonly deps: HistoricalCompareProfileDependencies,
    ) {
        this.provider = activeConfig?.provider || null;
        this.model = activeConfig?.model || null;
    }

    public abstract get key(): string;

    public async describeCaseCompare(input: FocusedHistoricalCompareCaseNarrativeInput): Promise<string | null> {
        if (!this.activeConfig) {
            return null;
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildCaseSystemPrompt(),
                userPrompt: this.buildCaseUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_historical_case_compare', caseResponseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 800,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_verdict',
                context: `focused-historical-compare-profile:${this.key}:case`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<{ narrative: string | null }>(response, {
                label: 'Focused historical case compare assistance',
                schema: caseResponseSchema,
            });
            return parsed.narrative?.trim().slice(0, 320) || null;
        } catch (error: any) {
            logger.warn('Focused historical case compare assistance skipped after provider failure', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                profileKey: this.key,
                error: error.message,
            });
            return null;
        }
    }

    public async describeRunCompare(input: FocusedHistoricalCompareRunNarrativeInput): Promise<string | null> {
        if (!this.activeConfig) {
            return null;
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildRunSystemPrompt(),
                userPrompt: this.buildRunUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_historical_run_compare', runResponseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 700,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_verdict',
                context: `focused-historical-compare-profile:${this.key}:run`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<{ headline: string | null }>(response, {
                label: 'Focused historical compare summary assistance',
                schema: runResponseSchema,
            });
            return parsed.headline?.trim().slice(0, 320) || null;
        } catch (error: any) {
            logger.warn('Focused historical run compare assistance skipped after provider failure', {
                scanId: input.scanId,
                profileKey: this.key,
                error: error.message,
            });
            return null;
        }
    }

    protected buildCaseSystemPrompt(): string {
        return [
            'You are PenPard focused historical compare assistance.',
            'The backend has already selected the baseline, matched the case, and classified verdict, evidence, and blocker drift.',
            'Write only a short grounded operator-facing narrative.',
            'Do not change compare status or invent historical facts.',
        ].join(' ');
    }

    protected buildRunSystemPrompt(): string {
        return [
            'You are PenPard focused historical compare assistance.',
            'The backend has already computed the compare status and summary.',
            'Return one short grounded headline describing the most important change since the previous comparable run.',
            'Do not invent regressions, fixes, or trend data that are not present in the supplied facts.',
        ].join(' ');
    }

    protected buildCaseUserPrompt(input: FocusedHistoricalCompareCaseNarrativeInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
                riskTags: input.objective.riskTags,
            },
            currentCase: {
                id: input.testCase.id,
                title: input.testCase.title,
                hypothesis: input.testCase.hypothesis,
                targetArtifact: input.testCase.targetArtifact,
                executionRailSummary: input.testCase.executionRailSummary || null,
                latestExecutionTracePreview: (input.testCase.latestExecutionTracePreview || []).slice(0, 3),
                latestVerdict: input.testCase.latestVerdict
                    ? {
                        verdictState: input.testCase.latestVerdict.verdictState,
                        verdictReason: input.testCase.latestVerdict.verdictReason,
                        evidenceSufficiency: input.testCase.latestVerdict.evidenceSufficiency,
                        interpretationSummary: input.testCase.latestVerdict.interpretationSummary,
                    }
                    : null,
                investigationSummary: input.testCase.investigationSummary || null,
            },
            previousCase: input.previousCase
                ? {
                    id: input.previousCase.id,
                    title: input.previousCase.title,
                    hypothesis: input.previousCase.hypothesis,
                    executionRailSummary: input.previousCase.executionRailSummary || null,
                    latestExecutionTracePreview: (input.previousCase.latestExecutionTracePreview || []).slice(0, 3),
                    latestVerdict: input.previousCase.latestVerdict
                        ? {
                            verdictState: input.previousCase.latestVerdict.verdictState,
                            verdictReason: input.previousCase.latestVerdict.verdictReason,
                            evidenceSufficiency: input.previousCase.latestVerdict.evidenceSufficiency,
                            interpretationSummary: input.previousCase.latestVerdict.interpretationSummary,
                        }
                        : null,
                    investigationSummary: input.previousCase.investigationSummary || null,
                }
                : null,
            compare: input.compare,
            instructions: {
                requirements: [
                    'Write 1-3 short sentences.',
                    'Focus on the most material factual change for this case.',
                    'Mention weakened evidence or recurring blockers when they matter.',
                    'Do not imply the model decided the compare result.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }

    protected buildRunUserPrompt(input: FocusedHistoricalCompareRunNarrativeInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
                riskTags: input.objective.riskTags,
            },
            compareState: input.compareState,
            compareSummary: input.compareSummary,
            instructions: {
                requirements: [
                    'Write one sentence.',
                    'Summarize the most important current historical comparison signal.',
                    'Call out instability or regression when the deterministic summary says manual review is recommended.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }
}

export class GenericFocusedHistoricalCompareProfile extends BaseFocusedHistoricalCompareProfile {
    public get key(): string {
        return this.activeConfig?.provider
            ? `generic:${this.activeConfig.provider}`
            : 'generic:fallback';
    }
}

export class QwenFocusedHistoricalCompareProfile extends BaseFocusedHistoricalCompareProfile {
    public get key(): string {
        return 'local_qwen';
    }

    protected buildCaseSystemPrompt(): string {
        return [
            'You are PenPard focused historical compare assistance for a local Qwen profile.',
            'The compare status, matching, and drift classifications are already fixed by backend rules.',
            'Return only compact JSON grounded in the supplied current and prior facts.',
        ].join(' ');
    }

    protected buildRunSystemPrompt(): string {
        return [
            'You are PenPard focused historical compare summary assistance for a local Qwen profile.',
            'The summary is already determined by backend rules.',
            'Return only compact JSON with one short grounded headline.',
        ].join(' ');
    }
}

function isQwenModel(model: string | null | undefined): boolean {
    const normalized = String(model || '').trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

export class FocusedHistoricalCompareAssistanceProfileResolver {
    constructor(
        private readonly deps: HistoricalCompareProfileDependencies = {
            generate: llmRuntime.generate.bind(llmRuntime),
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public resolve(userId?: number): FocusedHistoricalCompareAssistanceProfile {
        let activeConfig: LLMConfig | null = null;
        try {
            activeConfig = this.deps.getActiveConfig(userId);
        } catch {
            activeConfig = null;
        }

        if (activeConfig?.provider === 'local_llm' && isQwenModel(activeConfig.model)) {
            return new QwenFocusedHistoricalCompareProfile(activeConfig, this.deps);
        }

        return new GenericFocusedHistoricalCompareProfile(activeConfig, this.deps);
    }
}

export const focusedHistoricalCompareAssistanceProfileResolver = new FocusedHistoricalCompareAssistanceProfileResolver();
