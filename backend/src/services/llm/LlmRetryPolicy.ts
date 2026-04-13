import type { LlmExecutionError, LlmFailureCategory, LlmRetryDecision, ResolvedLlmCallOptions } from './LlmRuntimeTypes';

const RETRYABLE_FAILURES = new Set<LlmFailureCategory>([
    'provider_call_timeout',
    'provider_first_event_timeout',
    'sdk_session_timeout',
    'transient_provider_error',
]);

export interface RetryDecisionResult {
    decision: LlmRetryDecision;
    reason: string;
}

export function shouldRetryLlmAttempt(
    error: LlmExecutionError,
    attempt: number,
    options: ResolvedLlmCallOptions,
    startedAtMs: number,
    nowMs: number = Date.now(),
): RetryDecisionResult {
    if (!RETRYABLE_FAILURES.has(error.failureCategory)) {
        return {
            decision: 'stop',
            reason: `failure category ${error.failureCategory} is not retryable`,
        };
    }

    if (attempt >= options.maxAttempts) {
        return {
            decision: 'stop',
            reason: `max attempts reached (${options.maxAttempts})`,
        };
    }

    const elapsedMs = nowMs - startedAtMs;
    const remainingBudgetMs = options.retryBudgetMs === null
        ? null
        : options.retryBudgetMs - elapsedMs;
    if (remainingBudgetMs !== null && remainingBudgetMs <= 0) {
        return {
            decision: 'stop',
            reason: 'retry budget exhausted',
        };
    }

    return {
        decision: 'retry',
        reason: remainingBudgetMs === null
            ? `retryable ${error.failureCategory} with no retry budget limit`
            : `retryable ${error.failureCategory} with ${remainingBudgetMs}ms remaining`,
    };
}
