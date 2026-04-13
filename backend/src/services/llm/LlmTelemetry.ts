import type {
    LlmAttemptTrace,
    LlmCallTrace,
    LlmCallOptions,
    LlmExecutionError,
    ResolvedLlmCallOptions,
    ProviderAttemptResult,
} from './LlmRuntimeTypes';
import { logger } from '../../utils/logger';

function buildBasePayload(options: LlmCallOptions | ResolvedLlmCallOptions) {
    return {
        scanId: options.scanId,
        reportExportId: options.reportExportId,
        analysisId: options.analysisId,
        context: options.context,
        callSite: options.callSite,
        criticality: options.criticality,
        queueMode: options.queueMode,
    };
}

export function logLlmCallStarted(options: ResolvedLlmCallOptions) {
    logger.info('llm.call.started', {
        ...buildBasePayload(options),
        promptChars: options.promptMetrics.totalPromptChars,
        imageCount: options.promptMetrics.imageCount,
        firstEventTimeoutMs: options.firstEventTimeoutMs,
        attemptTimeoutMs: options.attemptTimeoutMs,
        providerIdleTimeoutMs: options.providerIdleTimeoutMs,
        retryBudgetMs: options.retryBudgetMs,
        maxAttempts: options.maxAttempts,
        queueWaitTimeoutMs: options.queueWaitTimeoutMs,
        queueExecutionTimeoutMs: options.queueExecutionTimeoutMs,
    });
}

export function logLlmAttemptFinished(
    options: ResolvedLlmCallOptions,
    attempt: number,
    queueWaitMs: number,
    queueDepthAtEnqueue: number,
    result: ProviderAttemptResult,
    trace: LlmAttemptTrace,
) {
    logger.info('llm.attempt.finished', {
        ...buildBasePayload(options),
        provider: result.provider,
        model: result.model,
        attempt,
        queueWaitMs,
        queueDepth: queueDepthAtEnqueue,
        executionMs: result.executionMs,
        promptChars: result.promptMetrics.totalPromptChars,
        imageCount: result.promptMetrics.imageCount,
        streamingStarted: trace.streamingStarted,
        anyEventReceived: trace.anyEventReceived,
        assistantMessageReceived: trace.assistantMessageReceived,
        idleReceived: trace.idleReceived,
        firstEventAtMs: trace.firstEventAtMs,
        idleAtMs: trace.idleAtMs,
        warningCategory: trace.warningCategory,
        retryDecision: trace.retryDecision,
        retryReason: trace.retryReason,
    });
}

export function logLlmCallFinished(
    options: ResolvedLlmCallOptions,
    trace: LlmCallTrace,
) {
    logger.info('llm.call.finished', {
        ...buildBasePayload(options),
        provider: trace.provider,
        model: trace.model,
        totalMs: trace.totalMs,
        attemptCount: trace.attemptCount,
        queueWaitMs: trace.queueWaitMs,
        queueDepth: trace.queueDepthAtEnqueue,
        promptChars: trace.promptMetrics.totalPromptChars,
        imageCount: trace.promptMetrics.imageCount,
        warnings: trace.attempts
            .map((attempt) => attempt.warningCategory)
            .filter((warning): warning is NonNullable<LlmAttemptTrace['warningCategory']> => typeof warning === 'string'),
    });
}

export function logLlmCallFailed(
    options: ResolvedLlmCallOptions,
    trace: LlmCallTrace,
    error: LlmExecutionError,
) {
    logger.error('llm.call.failed', {
        ...buildBasePayload(options),
        provider: trace.provider,
        model: trace.model,
        totalMs: trace.totalMs,
        attemptCount: trace.attemptCount,
        queueWaitMs: trace.queueWaitMs,
        queueDepth: trace.queueDepthAtEnqueue,
        promptChars: trace.promptMetrics.totalPromptChars,
        imageCount: trace.promptMetrics.imageCount,
        failureCategory: error.failureCategory,
        budgetMs: error.budgetMs,
        rawError: error.rawError,
        attempts: trace.attempts.map((attempt) => ({
            attempt: attempt.attempt,
            executionMs: attempt.executionMs,
            queueWaitMs: attempt.queueWaitMs,
            queueDepth: attempt.queueDepthAtEnqueue,
            provider: attempt.provider,
            model: attempt.model,
            streamingStarted: attempt.streamingStarted,
            anyEventReceived: attempt.anyEventReceived,
            assistantMessageReceived: attempt.assistantMessageReceived,
            idleReceived: attempt.idleReceived,
            firstEventAtMs: attempt.firstEventAtMs,
            idleAtMs: attempt.idleAtMs,
            warningCategory: attempt.warningCategory,
            failureCategory: attempt.failureCategory,
            rawError: attempt.rawError,
            retryDecision: attempt.retryDecision,
            retryReason: attempt.retryReason,
        })),
    });
}
