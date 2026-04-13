import type { GenerationRequest, GenerationResponse } from '../LLMProviderService';
import { llmProvider } from '../LLMProviderService';
import { llmQueue } from '../LLMQueue';
import { logLlmAttemptFinished, logLlmCallFailed, logLlmCallFinished, logLlmCallStarted } from './LlmTelemetry';
import { shouldRetryLlmAttempt } from './LlmRetryPolicy';
import { resolveLlmCallOptions } from './LlmTimeoutPolicy';
import {
    isLlmExecutionError,
    LlmCallOptions,
    LlmAttemptTrace,
    LlmCallTrace,
    LlmExecutionError,
    LlmFailureCategory,
    LlmPromptMetrics,
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

function minNullable(left: number | null, right: number | null): number | null {
    if (left === null) return right;
    if (right === null) return left;
    return Math.min(left, right);
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
    if (lower.includes('timeout')) {
        return 'provider_call_timeout';
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
    failureCategory?: LlmFailureCategory,
    rawError?: string | null,
): LlmAttemptTrace {
    return {
        attempt,
        executionMs: result?.executionMs ?? 0,
        queueWaitMs,
        queueDepthAtEnqueue,
        provider: result?.provider ?? 'unknown',
        model: result?.model ?? 'unknown',
        promptMetrics: result?.promptMetrics ?? promptMetrics,
        streamingStarted: result?.diagnostics.streamingStarted ?? false,
        anyEventReceived: result?.diagnostics.anyEventReceived ?? false,
        assistantMessageReceived: result?.diagnostics.assistantMessageReceived ?? false,
        idleReceived: result?.diagnostics.idleReceived ?? false,
        firstEventAtMs: result?.diagnostics.firstEventAtMs ?? null,
        idleAtMs: result?.diagnostics.idleAtMs ?? null,
        warningCategory: result?.diagnostics.warningCategory ?? null,
        failureCategory,
        rawError: rawError ?? result?.diagnostics.rawProviderError ?? null,
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
            assistantMessageReceived: false,
            idleReceived: false,
            firstEventAtMs: null,
            idleAtMs: null,
            finalContentLength: 0,
            warningCategory: null,
            rawProviderError: null,
        },
    };
}

class LlmRuntime {
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
                        executionTimeoutMs: resolved.queueExecutionTimeoutMs,
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
            const normalized = this.normalizeError(error, resolved.attemptTimeoutMs, resolved.signal);
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
        for (let attempt = 1; attempt <= resolved.maxAttempts; attempt += 1) {
            if (resolved.signal?.aborted || queueSignal?.aborted) {
                throw new LlmExecutionError({
                    failureCategory: 'canceled_due_to_scan_state',
                    message: 'LLM call canceled before attempt execution completed.',
                    rawError: 'AbortSignal triggered',
                });
            }

            const elapsedMs = Date.now() - startedAtMs;
            const remainingBudgetMs = resolved.retryBudgetMs === null
                ? null
                : resolved.retryBudgetMs - elapsedMs;
            if (remainingBudgetMs !== null && remainingBudgetMs <= 0) {
                throw new LlmExecutionError({
                    failureCategory: 'retry_budget_exhausted',
                    message: `LLM retry budget exhausted after ${resolved.retryBudgetMs}ms.`,
                    budgetMs: resolved.retryBudgetMs,
                });
            }

            const attemptTimeoutMs = minNullable(resolved.attemptTimeoutMs, remainingBudgetMs);
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
                        firstEventTimeoutMs: minNullable(resolved.firstEventTimeoutMs, attemptTimeoutMs),
                        attemptTimeoutMs,
                        providerIdleTimeoutMs: minNullable(resolved.providerIdleTimeoutMs, attemptTimeoutMs),
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
                    usage: result.usage,
                };
            } catch (error) {
                const normalized = this.normalizeError(error, attemptTimeoutMs, resolved.signal);
                const providerSnapshot = this.getConfiguredProviderSnapshot(resolved.userId);
                const attemptTrace = createAttemptTrace(
                    attempt,
                    trace.queueWaitMs,
                    trace.queueDepthAtEnqueue,
                    resolved.promptMetrics,
                    {
                        ...makeAttemptResultStub(providerSnapshot.provider, providerSnapshot.model, resolved.promptMetrics),
                    },
                    normalized.failureCategory,
                    normalized.rawError || errorMessage(error),
                );
                const retryDecision = shouldRetryLlmAttempt(normalized, attempt, resolved, startedAtMs);
                attemptTrace.retryDecision = retryDecision.decision;
                attemptTrace.retryReason = retryDecision.reason;
                trace.attempts.push(attemptTrace);
                trace.provider = trace.provider || providerSnapshot.provider;
                trace.model = trace.model || providerSnapshot.model;

                if (retryDecision.decision === 'retry') {
                    await sleep(Math.min(1500 * attempt, 3000));
                    continue;
                }

                if (
                    retryDecision.reason === 'retry budget exhausted'
                    && resolved.retryBudgetMs !== null
                    && normalized.failureCategory !== 'retry_budget_exhausted'
                ) {
                    throw new LlmExecutionError({
                        failureCategory: 'retry_budget_exhausted',
                        message: `LLM retry budget exhausted after ${resolved.retryBudgetMs}ms.`,
                        budgetMs: resolved.retryBudgetMs,
                        rawError: normalized.rawError || normalized.message,
                    });
                }

                throw normalized;
            } finally {
                signalBundle.cleanup();
            }
        }

        throw new LlmExecutionError({
            failureCategory: 'retry_budget_exhausted',
            message: resolved.retryBudgetMs === null
                ? `LLM attempts exhausted after ${resolved.maxAttempts} attempt(s).`
                : `LLM retry budget exhausted after ${resolved.retryBudgetMs}ms.`,
            budgetMs: resolved.retryBudgetMs,
        });
    }

    private normalizeError(
        error: unknown,
        attemptTimeoutMs: number | null,
        signal?: AbortSignal,
    ): LlmExecutionError {
        if (isLlmExecutionError(error)) {
            return error;
        }

        if (signal?.aborted) {
            return new LlmExecutionError({
                failureCategory: 'canceled_due_to_scan_state',
                message: 'LLM call canceled due to scan state change.',
                rawError: errorMessage(error),
                cause: error,
            });
        }

        const message = errorMessage(error);
        const failureCategory = normalizeFailureCategory(message);

        return new LlmExecutionError({
            failureCategory,
            message,
            budgetMs: failureCategory === 'provider_call_timeout' ? attemptTimeoutMs : null,
            rawError: message,
            retryable: failureCategory === 'provider_call_timeout' || failureCategory === 'transient_provider_error',
            cause: error,
        });
    }
}

export const llmRuntime = new LlmRuntime();
