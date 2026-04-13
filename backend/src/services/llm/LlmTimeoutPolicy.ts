import type { GenerationRequest } from '../LLMProviderService';
import type {
    LlmCallOptions,
    LlmCallSite,
    LlmCriticality,
    LlmPromptMetrics,
    ResolvedLlmCallOptions,
} from './LlmRuntimeTypes';

const CRITICAL_CALL_SITES = new Set<LlmCallSite>([
    'plan_creation',
    'replan_check',
    'step_execution_reasoning',
    'instruction_analysis',
]);

const TWO_ATTEMPT_NON_CRITICAL_SITES = new Set<LlmCallSite>([
    'report_parser_extraction',
    'red_team_ttp_derivation',
]);

const CRITICAL_ATTEMPT_TIMEOUTS = [45_000, 60_000, 75_000, 90_000];
const NON_CRITICAL_ATTEMPT_TIMEOUTS = [30_000, 45_000, 60_000, 75_000];

function resolvePromptTier(totalPromptChars: number): number {
    if (totalPromptChars <= 8_000) return 0;
    if (totalPromptChars <= 20_000) return 1;
    if (totalPromptChars <= 40_000) return 2;
    return 3;
}

function resolveCriticality(callSite: LlmCallSite): LlmCriticality {
    return CRITICAL_CALL_SITES.has(callSite) ? 'critical' : 'non_critical';
}

function resolveMaxAttempts(callSite: LlmCallSite, criticality: LlmCriticality): number {
    if (criticality === 'critical') {
        return callSite === 'plan_json_repair' ? 1 : 2;
    }

    return TWO_ATTEMPT_NON_CRITICAL_SITES.has(callSite) ? 2 : 1;
}

export function computePromptMetrics(request: GenerationRequest): LlmPromptMetrics {
    const systemPromptChars = request.systemPrompt.length;
    const userPromptChars = request.userPrompt.length;

    return {
        systemPromptChars,
        userPromptChars,
        totalPromptChars: systemPromptChars + userPromptChars,
        imageCount: request.images?.length || 0,
    };
}

export function resolveLlmCallOptions(
    request: GenerationRequest,
    options: LlmCallOptions,
): ResolvedLlmCallOptions {
    const promptMetrics = options.promptMetrics || computePromptMetrics(request);
    const criticality = options.criticality || resolveCriticality(options.callSite);
    const tier = resolvePromptTier(promptMetrics.totalPromptChars);
    const attemptTimeoutMs = options.attemptTimeoutMs !== undefined
        ? options.attemptTimeoutMs
        : (criticality === 'critical' ? CRITICAL_ATTEMPT_TIMEOUTS[tier] : NON_CRITICAL_ATTEMPT_TIMEOUTS[tier]);
    const retryBudgetMs = options.retryBudgetMs !== undefined
        ? options.retryBudgetMs
        : (criticality === 'critical' ? 150_000 : 75_000);
    const firstEventTimeoutMs = options.firstEventTimeoutMs !== undefined
        ? options.firstEventTimeoutMs
        : (criticality === 'critical' ? 20_000 : 15_000);

    return {
        ...options,
        criticality,
        queueMode: options.queueMode || 'queued',
        promptMetrics,
        maxAttempts: options.maxAttempts ?? resolveMaxAttempts(options.callSite, criticality),
        retryBudgetMs,
        firstEventTimeoutMs,
        attemptTimeoutMs,
        providerIdleTimeoutMs: options.providerIdleTimeoutMs !== undefined
            ? options.providerIdleTimeoutMs
            : attemptTimeoutMs,
        queueWaitTimeoutMs: options.queueWaitTimeoutMs !== undefined
            ? options.queueWaitTimeoutMs
            : (criticality === 'critical' ? null : 30_000),
        queueExecutionTimeoutMs: options.queueExecutionTimeoutMs !== undefined
            ? options.queueExecutionTimeoutMs
            : (retryBudgetMs === null ? null : retryBudgetMs + 5_000),
    };
}
