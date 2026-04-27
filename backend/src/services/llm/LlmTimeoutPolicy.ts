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
    'focused_test_planning',
    'focused_test_execution',
    'focused_test_verdict',
    'focused_test_investigation',
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
    if (request.messages?.length) {
        let totalPromptChars = 0;
        let systemPromptChars = 0;
        let userPromptChars = 0;
        let imageCount = 0;

        for (const message of request.messages) {
            const content = Array.isArray(message.content) ? message.content : [message.content];
            let messageChars = 0;

            for (const block of content) {
                if (typeof block === 'string') {
                    messageChars += block.length;
                    continue;
                }
                if (!block || typeof block !== 'object') {
                    continue;
                }
                if (typeof block.text === 'string') {
                    messageChars += block.text.length;
                }
                if ((block as any).image_url?.url) {
                    imageCount += 1;
                }
            }

            totalPromptChars += messageChars;
            if (message.role === 'system') {
                systemPromptChars += messageChars;
            }
            if (message.role === 'user') {
                userPromptChars += messageChars;
            }

            if (message.role === 'assistant' && Array.isArray(message.tool_calls)) {
                for (const toolCall of message.tool_calls) {
                    totalPromptChars += toolCall.function?.name?.length || 0;
                    totalPromptChars += toolCall.function?.arguments?.length || 0;
                }
            }

            if (message.role === 'tool') {
                totalPromptChars += message.tool_call_id?.length || 0;
                totalPromptChars += message.name?.length || 0;
            }
        }

        return {
            systemPromptChars,
            userPromptChars,
            totalPromptChars,
            imageCount,
        };
    }

    const systemPromptChars = request.systemPrompt?.length || 0;
    const userPromptChars = request.userPrompt?.length || 0;

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
