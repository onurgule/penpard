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

const CRITICAL_SLOW_FIRST_PROGRESS_WARNING_MS = 20_000;
const NON_CRITICAL_SLOW_FIRST_PROGRESS_WARNING_MS = 15_000;
const DEFAULT_FINALIZATION_GRACE_MS = 15_000;
const DEFAULT_EXECUTION_WATCHDOG_SLACK_MS = 20_000;

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
    const retryBudgetMs = options.retryBudgetMs !== undefined
        ? options.retryBudgetMs
        : (criticality === 'critical' ? 150_000 : 75_000);
    const slowFirstProgressWarningMs = options.slowFirstProgressWarningMs !== undefined
        ? options.slowFirstProgressWarningMs
        : (criticality === 'critical' ? CRITICAL_SLOW_FIRST_PROGRESS_WARNING_MS : NON_CRITICAL_SLOW_FIRST_PROGRESS_WARNING_MS);
    const finalizationGraceMs = options.finalizationGraceMs !== undefined
        ? options.finalizationGraceMs
        : DEFAULT_FINALIZATION_GRACE_MS;
    const executionWatchdogMs = options.executionWatchdogMs !== undefined
        ? options.executionWatchdogMs
        : (retryBudgetMs === null ? null : retryBudgetMs + DEFAULT_EXECUTION_WATCHDOG_SLACK_MS);

    return {
        ...options,
        criticality,
        queueMode: options.queueMode || 'queued',
        promptMetrics,
        maxAttempts: options.maxAttempts ?? resolveMaxAttempts(options.callSite, criticality),
        retryBudgetMs,
        slowFirstProgressWarningMs,
        finalizationGraceMs,
        queueWaitTimeoutMs: options.queueWaitTimeoutMs !== undefined
            ? options.queueWaitTimeoutMs
            : (criticality === 'critical' ? null : 30_000),
        executionWatchdogMs,
    };
}
