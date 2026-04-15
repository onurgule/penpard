import type { GenerationRequest, GenerationResponse } from '../LLMProviderService';
import { llmProvider } from '../LLMProviderService';
import { llmQueue } from '../LLMQueue';
import {
    logLlmAttemptFailed,
    logLlmAttemptFinished,
    logLlmCallFailed,
    logLlmCallFinished,
    logLlmCallStarted,
} from './LlmTelemetry';
import { shouldRetryLlmAttempt } from './LlmRetryPolicy';
import { resolveLlmCallOptions } from './LlmTimeoutPolicy';
import {
    isLlmExecutionError,
    LlmCallOptions,
    LlmAttemptTrace,
    LlmAttemptPhase,
    LlmCallTrace,
    LlmExecutionError,
    LlmFailureCategory,
    LlmLivenessCategory,
    LlmPromptMetrics,
    ProviderAttemptDiagnostics,
    ProviderAttemptResult,
    ResolvedLlmCallOptions,
} from './LlmRuntimeTypes';

interface AbortSignalBundle {
    signal: AbortSignal;
    cleanup: () => void;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorMessage(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error || 'Unknown LLM error');
}

function normalizeFailureCategory(message: string): LlmFailureCategory {
    const lower = message.toLowerCase();
    if (
        lower.includes('429')
        || lower.includes('rate limit')
        || lower.includes('resource exhausted')
        || lower.includes('temporarily unavailable')
        || lower.includes('connection reset')
        || lower.includes('econnreset')
        || lower.includes('socket hang up')
        || lower.includes('timeout')
    ) {
        return 'transient_provider_error';
    }
    if (
        lower.includes('empty response')
        || lower.includes('invalid structured output')
        || lower.includes('failed to parse')
        || lower.includes('invalid json')
        || lower.includes('malformed')
    ) {
        return 'malformed_provider_result';
    }
    return 'transient_provider_error';
}

function combineAbortSignals(signals: Array<AbortSignal | undefined>): AbortSignalBundle {
    const controller = new AbortController();
    const cleanups: Array<() => void> = [];

    for (const signal of signals) {
        if (!signal) continue;
        if (signal.aborted) {
            controller.abort(signal.reason);
            break;
        }

        const handler = () => controller.abort(signal.reason);
        signal.addEventListener('abort', handler, { once: true });
        cleanups.push(() => signal.removeEventListener('abort', handler));
    }

    return {
        signal: controller.signal,
        cleanup: () => {
            for (const cleanup of cleanups) {
                cleanup();
            }
        },
    };
}

function createAttemptTrace(
    attempt: number,
    queueWaitMs: number,
    queueDepthAtEnqueue: number,
    promptMetrics: LlmPromptMetrics,
    result?: ProviderAttemptResult,
    normalizedError?: LlmExecutionError,
    failureCategory?: LlmFailureCategory,
    rawError?: string | null,
): LlmAttemptTrace {
    const diagnostics = normalizedError?.diagnostics ?? result?.diagnostics ?? null;

    return {
        attempt,
        executionMs: result?.executionMs ?? 0,
        queueWaitMs,
        queueDepthAtEnqueue,
        provider: result?.provider ?? 'unknown',
        model: result?.model ?? 'unknown',
        promptMetrics: result?.promptMetrics ?? promptMetrics,
        streamingStarted: diagnostics?.streamingStarted ?? false,
        anyEventReceived: diagnostics?.anyEventReceived ?? false,
        partialOutputReceived: diagnostics?.partialOutputReceived ?? false,
        assistantMessageReceived: diagnostics?.assistantMessageReceived ?? false,
        idleReceived: diagnostics?.idleReceived ?? false,
        finalizationReceived: diagnostics?.finalizationReceived ?? false,
        firstEventAtMs: diagnostics?.firstEventAtMs ?? null,
        firstProgressAtMs: diagnostics?.firstProgressAtMs ?? null,
        partialOutputAtMs: diagnostics?.partialOutputAtMs ?? null,
        lastEventAtMs: diagnostics?.lastEventAtMs ?? null,
        lastProgressAtMs: diagnostics?.lastProgressAtMs ?? null,
        idleAtMs: diagnostics?.idleAtMs ?? null,
        finalizationAtMs: diagnostics?.finalizationAtMs ?? null,
        finalContentLength: diagnostics?.finalContentLength ?? result?.text.length ?? 0,
        progressEventCount: diagnostics?.progressEventCount ?? 0,
        attemptPhase: diagnostics?.attemptPhase ?? normalizedError?.attemptPhase ?? 'awaiting_first_event',
        completionSignal: diagnostics?.completionSignal ?? null,
        livenessCategory: diagnostics?.livenessCategory ?? normalizedError?.livenessCategory ?? null,
        warningCategory: diagnostics?.warningCategory ?? null,
        finishReason: diagnostics?.finishReason ?? result?.finishReason ?? null,
        toolCallCount: diagnostics?.toolCallCount ?? result?.toolCalls?.length ?? 0,
        reasoningContentLength: diagnostics?.reasoningContentLength ?? result?.reasoning?.length ?? 0,
        visibleContentLength: diagnostics?.visibleContentLength ?? result?.text.length ?? 0,
        failureCategory,
        rawError: rawError ?? diagnostics?.rawProviderError ?? null,
        retryDecision: undefined,
        retryReason: null,
    };
}

function makeAttemptResultStub(
    provider: string,
    model: string,
    promptMetrics: LlmPromptMetrics,
): ProviderAttemptResult {
    return {
        text: '',
        provider,
        model,
        executionMs: 0,
        promptMetrics,
        diagnostics: {
            streamingStarted: false,
            anyEventReceived: false,
            partialOutputReceived: false,
            assistantMessageReceived: false,
            idleReceived: false,
            finalizationReceived: false,
            firstEventAtMs: null,
            firstProgressAtMs: null,
            partialOutputAtMs: null,
            lastEventAtMs: null,
            lastProgressAtMs: null,
            idleAtMs: null,
            finalizationAtMs: null,
            finalContentLength: 0,
            progressEventCount: 0,
            attemptPhase: 'awaiting_first_event',
            completionSignal: null,
            livenessCategory: null,
            warningCategory: null,
            rawProviderError: null,
        },
    };
}

function deriveRetryBudgetLiveness(
    normalized?: Pick<LlmExecutionError, 'failureCategory' | 'livenessCategory' | 'diagnostics'>,
): LlmLivenessCategory {
    return 'retry_budget_exhausted';
}

function deriveFailureLiveness(
    failureCategory: LlmFailureCategory,
    diagnostics?: Partial<ProviderAttemptDiagnostics> | null,
): LlmLivenessCategory | null {
    if (failureCategory === 'transient_provider_error' || failureCategory === 'malformed_provider_result') {
        return null;
    }

    if (failureCategory === 'retry_budget_exhausted') {
        return deriveRetryBudgetLiveness({
            failureCategory,
            diagnostics: diagnostics ?? null,
            livenessCategory: null,
        });
    }

    return failureCategory;
}

class LlmRuntime {
    private buildRetryBudgetError(
        budgetMs: number | null,
        normalized?: Pick<LlmExecutionError, 'rawError' | 'message' | 'diagnostics' | 'attemptPhase' | 'failureCategory' | 'livenessCategory'>,
    ): LlmExecutionError {
        return new LlmExecutionError({
            failureCategory: 'retry_budget_exhausted',
            message: budgetMs === null
                ? 'LLM attempts exhausted before a successful completion.'
                : `LLM retry budget exhausted after ${budgetMs}ms.`,
            budgetMs,
            rawError: normalized?.rawError || normalized?.message || null,
            attemptPhase: normalized?.attemptPhase ?? null,
            livenessCategory: deriveRetryBudgetLiveness(normalized),
            diagnostics: normalized?.diagnostics ?? null,
        });
    }

    private getConfiguredProviderSnapshot(userId?: number): { provider: string; model: string } {
        try {
            const config = llmProvider.getActiveConfig(userId);
            return {
                provider: config.provider,
                model: config.model,
            };
        } catch {
            return {
                provider: 'unknown',
                model: 'unknown',
            };
        }
    }

    public async generate(request: GenerationRequest, options: LlmCallOptions): Promise<GenerationResponse> {
        const resolved = resolveLlmCallOptions(request, options);
        const startedAtMs = Date.now();
        const trace: LlmCallTrace = {
            totalMs: 0,
            attemptCount: 0,
            promptMetrics: resolved.promptMetrics,
            queueWaitMs: 0,
            queueDepthAtEnqueue: 0,
            attempts: [],
        };

        logLlmCallStarted(resolved);

        try {
            const response = resolved.queueMode === 'queued'
                ? await llmQueue.execute(
                    async (context) => {
                        trace.queueWaitMs = context.queueWaitMs;
                        trace.queueDepthAtEnqueue = context.queueDepthAtEnqueue;
                        return this.runAttempts(request, resolved, trace, startedAtMs, context.signal);
                    },
                    {
                        waitTimeoutMs: resolved.queueWaitTimeoutMs,
                        executionWatchdogMs: resolved.executionWatchdogMs,
                        callSite: resolved.callSite,
                        scanId: resolved.scanId,
                    },
                )
                : await this.runAttempts(request, resolved, trace, startedAtMs, resolved.signal);

            trace.totalMs = Date.now() - startedAtMs;
            trace.attemptCount = trace.attempts.length;
            logLlmCallFinished(resolved, trace);
            return response;
        } catch (error) {
            const normalized = this.normalizeError(error, resolved.signal);
            trace.totalMs = Date.now() - startedAtMs;
            trace.attemptCount = trace.attempts.length;
            logLlmCallFailed(resolved, trace, normalized);
            throw normalized;
        }
    }

    private async runAttempts(
        request: GenerationRequest,
        resolved: ResolvedLlmCallOptions,
        trace: LlmCallTrace,
        startedAtMs: number,
        queueSignal?: AbortSignal,
    ): Promise<GenerationResponse> {
        let lastRetryableFailure: LlmExecutionError | undefined;
        for (let attempt = 1; attempt <= resolved.maxAttempts; attempt += 1) {
            if (resolved.signal?.aborted || queueSignal?.aborted) {
                throw new LlmExecutionError({
                    failureCategory: 'canceled',
                    message: 'LLM call canceled before attempt execution completed.',
                    rawError: 'AbortSignal triggered',
                    attemptPhase: 'queued',
                    livenessCategory: 'canceled',
                });
            }

            const elapsedMs = Date.now() - startedAtMs;
            const remainingBudgetMs = resolved.retryBudgetMs === null
                ? null
                : resolved.retryBudgetMs - elapsedMs;
            if (remainingBudgetMs !== null && remainingBudgetMs <= 0) {
                throw this.buildRetryBudgetError(resolved.retryBudgetMs, lastRetryableFailure);
            }

            const signalBundle = combineAbortSignals([resolved.signal, queueSignal]);

            try {
                const result = await llmProvider.executeAttempt(
                    request,
                    {
                        ...resolved,
                        promptMetrics: resolved.promptMetrics,
                    },
                    {
                        signal: signalBundle.signal,
                        slowFirstProgressWarningMs: resolved.slowFirstProgressWarningMs,
                        finalizationGraceMs: resolved.finalizationGraceMs,
                    },
                );

                const attemptTrace = createAttemptTrace(
                    attempt,
                    trace.queueWaitMs,
                    trace.queueDepthAtEnqueue,
                    resolved.promptMetrics,
                    result,
                );

                trace.provider = result.provider;
                trace.model = result.model;
                trace.attempts.push(attemptTrace);
                logLlmAttemptFinished(
                    resolved,
                    attempt,
                    trace.queueWaitMs,
                    trace.queueDepthAtEnqueue,
                    result,
                    attemptTrace,
                );

                return {
                    text: result.text,
                    reasoning: result.reasoning,
                    toolCalls: result.toolCalls,
                    finishReason: result.finishReason,
                    usage: result.usage,
                };
            } catch (error) {
                const normalized = this.normalizeError(error, resolved.signal);
                const providerSnapshot = this.getConfiguredProviderSnapshot(resolved.userId);
                const attemptTrace = createAttemptTrace(
                    attempt,
                    trace.queueWaitMs,
                    trace.queueDepthAtEnqueue,
                    resolved.promptMetrics,
                    {
                        ...makeAttemptResultStub(providerSnapshot.provider, providerSnapshot.model, resolved.promptMetrics),
                    },
                    normalized,
                    normalized.failureCategory,
                    normalized.rawError || errorMessage(error),
                );
                const retryDecision = shouldRetryLlmAttempt(normalized, attempt, resolved, startedAtMs);
                attemptTrace.retryDecision = retryDecision.decision;
                attemptTrace.retryReason = retryDecision.reason;
                trace.attempts.push(attemptTrace);
                trace.provider = trace.provider || providerSnapshot.provider;
                trace.model = trace.model || providerSnapshot.model;
                logLlmAttemptFailed(resolved, attemptTrace);

                if (retryDecision.decision === 'retry') {
                    lastRetryableFailure = normalized;
                    await sleep(Math.min(1500 * attempt, 3000));
                    continue;
                }

                if (
                    retryDecision.reason === 'retry budget exhausted'
                    && resolved.retryBudgetMs !== null
                    && normalized.failureCategory !== 'retry_budget_exhausted'
                ) {
                    throw this.buildRetryBudgetError(resolved.retryBudgetMs, normalized);
                }

                throw normalized;
            } finally {
                signalBundle.cleanup();
            }
        }

        throw this.buildRetryBudgetError(resolved.retryBudgetMs, lastRetryableFailure);
    }

    private normalizeError(
        error: unknown,
        signal?: AbortSignal,
    ): LlmExecutionError {
        if (isLlmExecutionError(error)) {
            if (error.livenessCategory) {
                return error;
            }

            return new LlmExecutionError({
                failureCategory: error.failureCategory,
                message: error.message,
                budgetMs: error.budgetMs,
                rawError: error.rawError,
                retryable: error.retryable,
                attemptPhase: error.attemptPhase,
                livenessCategory: deriveFailureLiveness(error.failureCategory, error.diagnostics),
                diagnostics: error.diagnostics,
                cause: (error as Error & { cause?: unknown }).cause,
            });
        }

        if (signal?.aborted) {
            return new LlmExecutionError({
                failureCategory: 'canceled',
                message: 'LLM call canceled due to scan state change.',
                rawError: errorMessage(error),
                attemptPhase: 'queued',
                livenessCategory: 'canceled',
                cause: error,
            });
        }

        const message = errorMessage(error);
        const failureCategory = normalizeFailureCategory(message);
        const retryable = failureCategory === 'transient_provider_error';
        const attemptPhase: LlmAttemptPhase | null = null;

        return new LlmExecutionError({
            failureCategory,
            message,
            budgetMs: null,
            rawError: message,
            retryable,
            attemptPhase,
            livenessCategory: deriveFailureLiveness(failureCategory),
            cause: error,
        });
    }
}

export const llmRuntime = new LlmRuntime();
