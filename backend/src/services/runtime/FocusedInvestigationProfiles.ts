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
    FocusedCaseVerdict,
    FocusedInvestigationIssue,
    FocusedScanBlockerSummary,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedTestObjective,
    ScopeEnvelope,
} from './ScopedScanTypes';

const MAX_PROMPT_CHARS = 16_000;

export interface FocusedInvestigationAssistanceIssueInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope | null;
    testCase: FocusedTestCase;
    execution: FocusedTestCaseExecution | null;
    evidenceBundles: EvidenceBundle[];
    verdict: FocusedCaseVerdict | null;
    issue: FocusedInvestigationIssue;
}

export interface FocusedInvestigationAssistanceBlockerInput {
    scanId: string;
    userId?: number;
    objective: FocusedTestObjective;
    blockerSummary: FocusedScanBlockerSummary;
    unresolvedIssues: FocusedInvestigationIssue[];
}

export interface FocusedInvestigationAssistanceResult {
    assistanceSummary: string | null;
    expertFollowupHint: string | null;
}

export interface FocusedInvestigationAssistanceProfile {
    key: string;
    provider: string | null;
    model: string | null;
    enhanceIssue(input: FocusedInvestigationAssistanceIssueInput): Promise<FocusedInvestigationAssistanceResult>;
    summarizeBlockers(input: FocusedInvestigationAssistanceBlockerInput): Promise<string | null>;
}

interface InvestigationProfileDependencies {
    generate: typeof llmRuntime.generate;
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

const issueResponseSchema = z.object({
    assistanceSummary: z.string().trim().min(1).max(360).nullable(),
    expertFollowupHint: z.string().trim().min(1).max(220).nullable(),
});

const issueResponseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['assistanceSummary', 'expertFollowupHint'],
    properties: {
        assistanceSummary: { type: ['string', 'null'] },
        expertFollowupHint: { type: ['string', 'null'] },
    },
} as const;

const blockerResponseSchema = z.object({
    headline: z.string().trim().min(1).max(240).nullable(),
});

const blockerResponseJsonSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['headline'],
    properties: {
        headline: { type: ['string', 'null'] },
    },
} as const;

abstract class BaseFocusedInvestigationAssistanceProfile implements FocusedInvestigationAssistanceProfile {
    public readonly provider: string | null;
    public readonly model: string | null;

    public constructor(
        protected readonly activeConfig: LLMConfig | null,
        protected readonly deps: InvestigationProfileDependencies,
    ) {
        this.provider = activeConfig?.provider || null;
        this.model = activeConfig?.model || null;
    }

    public abstract get key(): string;

    public async enhanceIssue(input: FocusedInvestigationAssistanceIssueInput): Promise<FocusedInvestigationAssistanceResult> {
        if (!this.activeConfig) {
            return {
                assistanceSummary: null,
                expertFollowupHint: null,
            };
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildIssueSystemPrompt(),
                userPrompt: this.buildIssueUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_investigation_issue', issueResponseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 900,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_investigation',
                context: `focused-investigation-profile:${this.key}:issue`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<FocusedInvestigationAssistanceResult>(response, {
                label: 'Focused investigation assistance',
                schema: issueResponseSchema,
            });
            return {
                assistanceSummary: parsed.assistanceSummary?.trim().slice(0, 360) || null,
                expertFollowupHint: parsed.expertFollowupHint?.trim().slice(0, 220) || null,
            };
        } catch (error: any) {
            logger.warn('Focused investigation assistance skipped after provider failure', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                executionId: input.execution?.id,
                profileKey: this.key,
                error: error.message,
            });
            return {
                assistanceSummary: null,
                expertFollowupHint: null,
            };
        }
    }

    public async summarizeBlockers(input: FocusedInvestigationAssistanceBlockerInput): Promise<string | null> {
        if (!this.activeConfig || input.unresolvedIssues.length === 0) {
            return null;
        }

        try {
            const response = await this.deps.generate({
                systemPrompt: this.buildBlockerSystemPrompt(),
                userPrompt: this.buildBlockerUserPrompt(input),
                responseFormat: buildJsonSchemaResponseFormat('focused_test_investigation_blockers', blockerResponseJsonSchema),
                reasoningMode: 'disabled',
                temperature: 0.1,
                maxTokens: 600,
            }, {
                scanId: input.scanId,
                userId: input.userId,
                callSite: 'focused_test_investigation',
                context: `focused-investigation-profile:${this.key}:blockers`,
                maxAttempts: 2,
            });

            const parsed = parseStructuredJsonResponse<{ headline: string | null }>(response, {
                label: 'Focused blocker summary assistance',
                schema: blockerResponseSchema,
            });
            return parsed.headline?.trim().slice(0, 240) || null;
        } catch (error: any) {
            logger.warn('Focused investigation blocker summary skipped after provider failure', {
                scanId: input.scanId,
                profileKey: this.key,
                error: error.message,
            });
            return null;
        }
    }

    protected buildIssueSystemPrompt(): string {
        return [
            'You are PenPard focused investigation assistance.',
            'The product has already determined the issue type, status, impact, and linkage using system-owned runtime and verdict facts.',
            'Return only compact JSON with a grounded issue summary and one concise expert follow-up hint.',
            'Do not invent evidence, do not change status or impact, and do not widen the scope.',
        ].join(' ');
    }

    protected buildBlockerSystemPrompt(): string {
        return [
            'You are PenPard focused investigation blocker summary assistance.',
            'The blocker summary is already system-owned.',
            'Return only compact JSON with one short grounded headline describing the most important current blocker pattern.',
            'Do not invent missing issue categories or suggest autonomous troubleshooting.',
        ].join(' ');
    }

    protected buildIssueUserPrompt(input: FocusedInvestigationAssistanceIssueInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
                riskTags: input.objective.riskTags,
            },
            scopeEnvelope: input.scopeEnvelope ? {
                allowedHosts: input.scopeEnvelope.allowedHosts,
                allowedRoutes: input.scopeEnvelope.allowedRoutes,
                boundaryHints: input.scopeEnvelope.boundaryHints,
                outOfScopeNotes: input.scopeEnvelope.outOfScopeNotes,
            } : null,
            testCase: {
                id: input.testCase.id,
                title: input.testCase.title,
                hypothesis: input.testCase.hypothesis,
                targetArtifact: input.testCase.targetArtifact,
                assertions: input.testCase.assertions,
                requiredEvidence: input.testCase.requiredEvidence,
            },
            execution: input.execution ? {
                id: input.execution.id,
                executionState: input.execution.executionState,
                executionProfileKey: input.execution.executionProfileKey,
                runReason: input.execution.runReason,
                notesSummary: input.execution.notesSummary,
                errorMessage: input.execution.errorMessage,
                requestActionsUsed: input.execution.requestActionsUsed,
                browserActionsUsed: input.execution.browserActionsUsed,
            } : null,
            verdict: input.verdict ? {
                verdictState: input.verdict.verdictState,
                verdictReason: input.verdict.verdictReason,
                evidenceSufficiency: input.verdict.evidenceSufficiency,
                interpretationSummary: input.verdict.interpretationSummary,
            } : null,
            issue: {
                issueType: input.issue.issueType,
                issueTitle: input.issue.issueTitle,
                issueDetails: input.issue.issueDetails,
                issueStatus: input.issue.issueStatus,
                impact: input.issue.impact,
                correlation: input.issue.correlation,
                linkedEvidenceIds: input.issue.linkedEvidenceIds,
                linkedVerdictIds: input.issue.linkedVerdictIds,
                workaroundAttempts: input.issue.workaroundAttempts,
            },
            evidenceBundles: input.evidenceBundles.slice(0, 6).map((bundle) => ({
                id: bundle.id,
                source: bundle.source,
                summary: bundle.summary,
                executionNotes: bundle.executionNotes || null,
                requestRef: bundle.requestRef || null,
                responseRef: bundle.responseRef || null,
                responseDiffSummary: bundle.responseDiffSummary || null,
                browserState: bundle.browserState ? {
                    finalPath: bundle.browserState.finalPath,
                    pageTitle: bundle.browserState.pageTitle,
                    expectations: bundle.browserState.expectations,
                    stateNotes: bundle.browserState.stateNotes,
                } : null,
                scopeViolation: bundle.scopeViolation || null,
            })),
            instructions: {
                requirements: [
                    'Summarize what went wrong and why it still matters in 1-2 short sentences.',
                    'Provide one expert follow-up hint focused on what to inspect next.',
                    'Keep both fields concise and practical.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }

    protected buildBlockerUserPrompt(input: FocusedInvestigationAssistanceBlockerInput): string {
        const payload = JSON.stringify({
            objective: {
                title: input.objective.title,
                scopeType: input.objective.scopeType,
                goal: input.objective.goal,
            },
            blockerSummary: input.blockerSummary,
            unresolvedIssues: input.unresolvedIssues.slice(0, 6).map((issue) => ({
                issueType: issue.issueType,
                issueTitle: issue.issueTitle,
                issueStatus: issue.issueStatus,
                impact: issue.impact,
                caseId: issue.caseId,
                expertFollowupHint: issue.expertFollowupHint || null,
            })),
            instructions: {
                requirements: [
                    'Write one sentence.',
                    'Focus on the most important current blocker pattern.',
                    'Do not speculate beyond the supplied issue facts.',
                ],
            },
        }, null, 2);

        return payload.length > MAX_PROMPT_CHARS ? payload.slice(0, MAX_PROMPT_CHARS) : payload;
    }
}

export class GenericFocusedInvestigationProfile extends BaseFocusedInvestigationAssistanceProfile {
    public get key(): string {
        return this.activeConfig?.provider
            ? `generic:${this.activeConfig.provider}`
            : 'generic:fallback';
    }
}

export class QwenFocusedInvestigationProfile extends BaseFocusedInvestigationAssistanceProfile {
    public get key(): string {
        return 'local_qwen';
    }

    protected buildIssueSystemPrompt(): string {
        return [
            'You are PenPard focused investigation assistance for a local Qwen profile.',
            'The issue type, status, impact, and linkage are already fixed by backend rules.',
            'Return only compact JSON grounded in the supplied facts.',
            'Do not invent root causes, extra evidence, or scope changes.',
        ].join(' ');
    }

    protected buildBlockerSystemPrompt(): string {
        return [
            'You are PenPard blocker summary assistance for a local Qwen profile.',
            'The blocker summary is already system-owned.',
            'Return only compact JSON with a short grounded headline.',
            'Do not invent extra blockers or remediation workflows.',
        ].join(' ');
    }
}

function isQwenModel(model: string | null | undefined): boolean {
    const normalized = String(model || '').trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

export class FocusedInvestigationAssistanceProfileResolver {
    constructor(
        private readonly deps: InvestigationProfileDependencies = {
            generate: llmRuntime.generate.bind(llmRuntime),
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public resolve(userId?: number): FocusedInvestigationAssistanceProfile {
        let activeConfig: LLMConfig | null = null;
        try {
            activeConfig = this.deps.getActiveConfig(userId);
        } catch {
            activeConfig = null;
        }

        if (activeConfig?.provider === 'local_llm' && isQwenModel(activeConfig.model)) {
            return new QwenFocusedInvestigationProfile(activeConfig, this.deps);
        }

        return new GenericFocusedInvestigationProfile(activeConfig, this.deps);
    }
}

export const focusedInvestigationAssistanceProfileResolver = new FocusedInvestigationAssistanceProfileResolver();
