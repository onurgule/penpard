import test from 'node:test';
import assert from 'node:assert/strict';

import { llmRuntime } from '../src/services/llm/LlmRuntime';
import { llmProvider } from '../src/services/LLMProviderService';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';
import { logger } from '../src/utils/logger';

function makeAttemptResult(text: string, overrides: Record<string, unknown> = {}) {
    return {
        text,
        provider: 'github_copilot',
        model: 'claude-opus-4.6',
        executionMs: 1,
        promptMetrics: {
            systemPromptChars: 6,
            userPromptChars: 4,
            totalPromptChars: 10,
            imageCount: 0,
        },
        diagnostics: {
            streamingStarted: true,
            anyEventReceived: true,
            partialOutputReceived: text.length > 0,
            assistantMessageReceived: true,
            idleReceived: true,
            finalizationReceived: true,
            firstEventAtMs: 1,
            firstProgressAtMs: 1,
            partialOutputAtMs: 1,
            lastEventAtMs: 2,
            lastProgressAtMs: 2,
            idleAtMs: 3,
            finalizationAtMs: 3,
            finalContentLength: text.length,
            progressEventCount: 2,
            attemptPhase: 'completed',
            completionSignal: 'session_idle',
            livenessCategory: null,
            warningCategory: null,
            rawProviderError: null,
            ...overrides,
        },
    };
}

test('LLM runtime retries transient failures and succeeds on a later attempt', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    let attempts = 0;

    (llmProvider as any).executeAttempt = async () => {
        attempts += 1;
        if (attempts === 1) {
            throw new LlmExecutionError({
                failureCategory: 'transient_provider_error',
                message: '429 rate limit',
                rawError: '429 rate limit',
                retryable: true,
            });
        }

        return makeAttemptResult('recovered');
    };

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-retry',
            callSite: 'plan_creation',
            retryBudgetMs: 4_000,
            maxAttempts: 2,
            queueWaitTimeoutMs: null,
            executionWatchdogMs: 5_000,
        });

        assert.equal(response.text, 'recovered');
        assert.equal(attempts, 2);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime upgrades exhausted retry windows to retry_budget_exhausted', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    let attempts = 0;

    (llmProvider as any).executeAttempt = async () => {
        attempts += 1;
        throw new LlmExecutionError({
            failureCategory: 'transient_provider_error',
            message: 'upstream timeout',
            rawError: 'upstream timeout',
            retryable: true,
            attemptPhase: 'awaiting_first_progress',
            diagnostics: makeAttemptResult('', {
                anyEventReceived: true,
                partialOutputReceived: false,
                assistantMessageReceived: false,
                idleReceived: false,
                finalizationReceived: false,
                firstEventAtMs: 5,
                firstProgressAtMs: null,
                partialOutputAtMs: null,
                lastEventAtMs: 5,
                lastProgressAtMs: null,
                idleAtMs: null,
                finalizationAtMs: null,
                finalContentLength: 0,
                progressEventCount: 0,
                attemptPhase: 'awaiting_first_progress',
                completionSignal: null,
                rawProviderError: 'upstream timeout',
            }).diagnostics,
        });
    };

    try {
        await assert.rejects(
            () => llmRuntime.generate({
                systemPrompt: 'system',
                userPrompt: 'user',
            }, {
                scanId: 'scan-runtime-budget',
                callSite: 'plan_creation',
                retryBudgetMs: 10,
                maxAttempts: 2,
                queueWaitTimeoutMs: null,
                executionWatchdogMs: 5_000,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'retry_budget_exhausted');
                assert.equal(error.livenessCategory, 'retry_budget_exhausted');
                return true;
            },
        );

        assert.equal(attempts, 1);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime emits started telemetry without the old provider output deadline fields', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    const originalInfo = logger.info.bind(logger);
    const infoCalls: Array<{ message: string; meta: any }> = [];

    (llmProvider as any).executeAttempt = async () => makeAttemptResult('ok');
    (logger as any).info = (message: string, meta: any) => {
        infoCalls.push({ message, meta });
    };

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-started-log',
            callSite: 'plan_creation',
            retryBudgetMs: 4_000,
            slowFirstProgressWarningMs: 250,
            finalizationGraceMs: 500,
            executionWatchdogMs: 8_000,
            queueWaitTimeoutMs: null,
            maxAttempts: 1,
        });

        assert.equal(response.text, 'ok');
        const started = infoCalls.find((entry) => entry.message === 'llm.call.started');
        assert.ok(started);
        assert.equal(started?.meta.slowFirstProgressWarningMs, 250);
        assert.equal(started?.meta.finalizationGraceMs, 500);
        assert.equal(started?.meta.executionWatchdogMs, 8_000);
        assert.ok(!Object.hasOwn(started?.meta || {}, 'firstEventTimeoutMs'));
        assert.ok(!Object.hasOwn(started?.meta || {}, 'attemptTimeoutMs'));
        assert.ok(!Object.hasOwn(started?.meta || {}, 'providerIdleTimeoutMs'));
        assert.ok(!Object.hasOwn(started?.meta || {}, 'queueExecutionTimeoutMs'));
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
        (logger as any).info = originalInfo;
    }
});

test('LLM runtime emits structured failure telemetry without fixed-window no-output wording', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    const originalWarn = logger.warn.bind(logger);
    const originalError = logger.error.bind(logger);
    const warnCalls: Array<{ message: string; meta: any }> = [];
    const errorCalls: Array<{ message: string; meta: any }> = [];

    (llmProvider as any).executeAttempt = async () => {
        throw new LlmExecutionError({
            failureCategory: 'watchdog_timeout',
            message: 'LLM execution watchdog expired after 50ms.',
            rawError: 'LLM execution watchdog expired after 50ms.',
            retryable: false,
            attemptPhase: 'streaming',
            livenessCategory: 'watchdog_timeout',
            diagnostics: makeAttemptResult('partial', {
                idleReceived: false,
                finalizationReceived: false,
                idleAtMs: null,
                finalizationAtMs: null,
                completionSignal: null,
                attemptPhase: 'streaming',
                warningCategory: 'slow_first_event',
                rawProviderError: 'LLM execution watchdog expired after 50ms.',
            }).diagnostics,
        });
    };
    (logger as any).warn = (message: string, meta: any) => {
        warnCalls.push({ message, meta });
    };
    (logger as any).error = (message: string, meta: any) => {
        errorCalls.push({ message, meta });
    };

    try {
        await assert.rejects(
            () => llmRuntime.generate({
                systemPrompt: 'system',
                userPrompt: 'user',
            }, {
                scanId: 'scan-runtime-failure-log',
                callSite: 'js_digging_classification',
                retryBudgetMs: 50,
                maxAttempts: 1,
                executionWatchdogMs: 5_000,
            }),
        );

        const failedAttempt = warnCalls.find((entry) => entry.message === 'llm.attempt.failed');
        assert.ok(failedAttempt);
        assert.equal(failedAttempt?.meta.failureCategory, 'watchdog_timeout');
        assert.equal(failedAttempt?.meta.partialOutputReceived, true);
        assert.equal(failedAttempt?.meta.progressEventCount, 2);
        assert.equal(failedAttempt?.meta.attemptPhase, 'streaming');
        assert.equal(failedAttempt?.meta.livenessCategory, 'watchdog_timeout');
        assert.ok(!(failedAttempt?.meta.rawError || '').includes('no assistant output within'));

        const failedCall = errorCalls.find((entry) => entry.message === 'llm.call.failed');
        assert.ok(failedCall);
        assert.equal(failedCall?.meta.callSite, 'js_digging_classification');
        assert.equal(failedCall?.meta.failureCategory, 'watchdog_timeout');
        assert.equal(failedCall?.meta.livenessCategory, 'watchdog_timeout');
        assert.equal(failedCall?.meta.attemptCount, 1);
        assert.equal(failedCall?.meta.attempts[0].partialOutputReceived, true);
        assert.equal(failedCall?.meta.attempts[0].warningCategory, 'slow_first_event');
        assert.equal(failedCall?.meta.attempts[0].attemptPhase, 'streaming');
        assert.equal(failedCall?.meta.attempts[0].progressEventCount, 2);
        assert.ok(!(failedCall?.meta.rawError || '').includes('no assistant output within'));
        assert.ok(JSON.stringify(failedCall?.meta).includes('watchdog_timeout'));
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
        (logger as any).warn = originalWarn;
        (logger as any).error = originalError;
    }
});

test('LLM runtime preserves provider diagnostics when retry budget is exhausted after meaningful progress', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);

    (llmProvider as any).executeAttempt = async () => {
        throw new LlmExecutionError({
            failureCategory: 'transient_provider_error',
            message: 'provider stream disconnected before finalization',
            rawError: 'provider stream disconnected before finalization',
            retryable: true,
            attemptPhase: 'streaming',
            diagnostics: makeAttemptResult('partial-response', {
                idleReceived: false,
                finalizationReceived: false,
                idleAtMs: null,
                finalizationAtMs: null,
                completionSignal: null,
                attemptPhase: 'streaming',
                warningCategory: 'slow_first_event',
                rawProviderError: 'provider stream disconnected before finalization',
            }).diagnostics,
        });
    };

    try {
        await assert.rejects(
            () => llmRuntime.generate({
                systemPrompt: 'system',
                userPrompt: 'user',
            }, {
                scanId: 'scan-runtime-progress-budget',
                callSite: 'plan_creation',
                retryBudgetMs: 50,
                maxAttempts: 2,
                queueWaitTimeoutMs: null,
                executionWatchdogMs: 5_000,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'retry_budget_exhausted');
                assert.equal(error.attemptPhase, 'streaming');
                assert.equal(error.livenessCategory, 'retry_budget_exhausted');
                assert.equal(error.diagnostics?.partialOutputReceived, true);
                assert.equal(error.diagnostics?.warningCategory, 'slow_first_event');
                return true;
            },
        );
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime allows later calls to succeed after an earlier watchdog timeout', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    let callCount = 0;

    (llmProvider as any).executeAttempt = async () => {
        callCount += 1;
        if (callCount === 1) {
            throw new LlmExecutionError({
                failureCategory: 'watchdog_timeout',
                message: 'LLM execution watchdog expired after 20ms.',
                rawError: 'LLM execution watchdog expired after 20ms.',
                retryable: false,
                attemptPhase: 'awaiting_first_progress',
                livenessCategory: 'watchdog_timeout',
            });
        }

        return makeAttemptResult('later-success');
    };

    try {
        await assert.rejects(
            () => llmRuntime.generate({
                systemPrompt: 'system',
                userPrompt: 'user',
            }, {
                scanId: 'scan-runtime-sequence',
                callSite: 'step_execution_reasoning',
                retryBudgetMs: 20,
                maxAttempts: 1,
                executionWatchdogMs: 5_000,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'watchdog_timeout');
                return true;
            },
        );

        const later = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-sequence',
            callSite: 'executive_summary',
            retryBudgetMs: 20,
            maxAttempts: 1,
            executionWatchdogMs: 5_000,
        });

        assert.equal(later.text, 'later-success');
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime can disable warning, finalization, and watchdog rails when explicitly requested', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    const capturedExecutionOptions: any[] = [];

    (llmProvider as any).executeAttempt = async (_request: any, _metadata: any, executionOptions: any) => {
        capturedExecutionOptions.push(executionOptions);
        return makeAttemptResult('long-running-ok');
    };

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-unbounded',
            callSite: 'report_enrichment',
            maxAttempts: 1,
            retryBudgetMs: null,
            slowFirstProgressWarningMs: null,
            finalizationGraceMs: null,
            queueWaitTimeoutMs: null,
            executionWatchdogMs: null,
        });

        assert.equal(response.text, 'long-running-ok');
        assert.equal(capturedExecutionOptions.length, 1);
        assert.equal(capturedExecutionOptions[0].slowFirstProgressWarningMs, null);
        assert.equal(capturedExecutionOptions[0].finalizationGraceMs, null);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime forwards caller userId into provider execution metadata', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    const capturedMetadata: any[] = [];

    (llmProvider as any).executeAttempt = async (_request: any, metadata: any, executionOptions: any) => {
        capturedMetadata.push({ metadata, executionOptions });
        return makeAttemptResult('user-scoped-ok');
    };

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-user',
            userId: 77,
            callSite: 'plan_creation',
            maxAttempts: 1,
            retryBudgetMs: 100,
            executionWatchdogMs: 5_000,
        });

        assert.equal(response.text, 'user-scoped-ok');
        assert.equal(capturedMetadata.length, 1);
        assert.equal(capturedMetadata[0].metadata.userId, 77);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});
