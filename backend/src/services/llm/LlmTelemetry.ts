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
        slowFirstProgressWarningMs: options.slowFirstProgressWarningMs,
        finalizationGraceMs: options.finalizationGraceMs,
        retryBudgetMs: options.retryBudgetMs,
        maxAttempts: options.maxAttempts,
        queueWaitTimeoutMs: options.queueWaitTimeoutMs,
        executionWatchdogMs: options.executionWatchdogMs,
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
        partialOutputReceived: trace.partialOutputReceived,
        assistantMessageReceived: trace.assistantMessageReceived,
        idleReceived: trace.idleReceived,
        finalizationReceived: trace.finalizationReceived,
        firstEventAtMs: trace.firstEventAtMs,
        firstProgressAtMs: trace.firstProgressAtMs,
        partialOutputAtMs: trace.partialOutputAtMs,
        lastEventAtMs: trace.lastEventAtMs,
        lastProgressAtMs: trace.lastProgressAtMs,
        idleAtMs: trace.idleAtMs,
        finalizationAtMs: trace.finalizationAtMs,
        finalContentLength: trace.finalContentLength,
        progressEventCount: trace.progressEventCount,
        attemptPhase: trace.attemptPhase,
        completionSignal: trace.completionSignal,
        livenessCategory: trace.livenessCategory,
        warningCategory: trace.warningCategory,
        finishReason: trace.finishReason,
        toolCallCount: trace.toolCallCount,
        reasoningContentLength: trace.reasoningContentLength,
        visibleContentLength: trace.visibleContentLength,
        retryDecision: trace.retryDecision,
        retryReason: trace.retryReason,
    });
}

export function logLlmAttemptFailed(
    options: ResolvedLlmCallOptions,
    trace: LlmAttemptTrace,
) {
    logger.warn('llm.attempt.failed', {
        ...buildBasePayload(options),
        provider: trace.provider,
        model: trace.model,
        attempt: trace.attempt,
        queueWaitMs: trace.queueWaitMs,
        queueDepth: trace.queueDepthAtEnqueue,
        executionMs: trace.executionMs,
        promptChars: trace.promptMetrics.totalPromptChars,
        imageCount: trace.promptMetrics.imageCount,
        streamingStarted: trace.streamingStarted,
        anyEventReceived: trace.anyEventReceived,
        partialOutputReceived: trace.partialOutputReceived,
        assistantMessageReceived: trace.assistantMessageReceived,
        idleReceived: trace.idleReceived,
        finalizationReceived: trace.finalizationReceived,
        firstEventAtMs: trace.firstEventAtMs,
        firstProgressAtMs: trace.firstProgressAtMs,
        partialOutputAtMs: trace.partialOutputAtMs,
        lastEventAtMs: trace.lastEventAtMs,
        lastProgressAtMs: trace.lastProgressAtMs,
        idleAtMs: trace.idleAtMs,
        finalizationAtMs: trace.finalizationAtMs,
        finalContentLength: trace.finalContentLength,
        progressEventCount: trace.progressEventCount,
        attemptPhase: trace.attemptPhase,
        completionSignal: trace.completionSignal,
        livenessCategory: trace.livenessCategory,
        warningCategory: trace.warningCategory,
        finishReason: trace.finishReason,
        toolCallCount: trace.toolCallCount,
        reasoningContentLength: trace.reasoningContentLength,
        visibleContentLength: trace.visibleContentLength,
        failureCategory: trace.failureCategory,
        rawError: trace.rawError,
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
        livenessCategory: error.livenessCategory,
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
            partialOutputReceived: attempt.partialOutputReceived,
            assistantMessageReceived: attempt.assistantMessageReceived,
            idleReceived: attempt.idleReceived,
            finalizationReceived: attempt.finalizationReceived,
            firstEventAtMs: attempt.firstEventAtMs,
            firstProgressAtMs: attempt.firstProgressAtMs,
            partialOutputAtMs: attempt.partialOutputAtMs,
            lastEventAtMs: attempt.lastEventAtMs,
            lastProgressAtMs: attempt.lastProgressAtMs,
            idleAtMs: attempt.idleAtMs,
            finalizationAtMs: attempt.finalizationAtMs,
            finalContentLength: attempt.finalContentLength,
            progressEventCount: attempt.progressEventCount,
            attemptPhase: attempt.attemptPhase,
            completionSignal: attempt.completionSignal,
            livenessCategory: attempt.livenessCategory,
            warningCategory: attempt.warningCategory,
            finishReason: attempt.finishReason,
            toolCallCount: attempt.toolCallCount,
            reasoningContentLength: attempt.reasoningContentLength,
            visibleContentLength: attempt.visibleContentLength,
            failureCategory: attempt.failureCategory,
            rawError: attempt.rawError,
            retryDecision: attempt.retryDecision,
            retryReason: attempt.retryReason,
        })),
    });
}
