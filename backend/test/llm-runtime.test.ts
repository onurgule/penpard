import test from 'node:test';
import assert from 'node:assert/strict';

import { llmRuntime } from '../src/services/llm/LlmRuntime';
import { llmProvider } from '../src/services/LLMProviderService';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';
import { logger } from '../src/utils/logger';

function makeAttemptResult(text: string) {
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
            assistantMessageReceived: true,
            idleReceived: true,
            firstEventAtMs: 1,
            idleAtMs: 2,
            finalContentLength: text.length,
            warningCategory: null,
            rawProviderError: null,
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
            attemptTimeoutMs: 50,
            retryBudgetMs: 4_000,
            maxAttempts: 2,
            queueWaitTimeoutMs: null,
            queueExecutionTimeoutMs: 5_000,
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
                attemptTimeoutMs: 10,
                retryBudgetMs: 10,
                maxAttempts: 2,
                queueWaitTimeoutMs: null,
                queueExecutionTimeoutMs: 5_000,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'retry_budget_exhausted');
                return true;
            },
        );

        assert.equal(attempts, 1);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime emits structured failure telemetry with categorized attempts', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    const originalError = logger.error.bind(logger);
    const errorCalls: Array<{ message: string; meta: any }> = [];

    (llmProvider as any).executeAttempt = async () => {
        throw new LlmExecutionError({
            failureCategory: 'provider_first_event_timeout',
            message: 'No first event arrived in time.',
            rawError: 'No first event arrived in time.',
            retryable: true,
        });
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
                attemptTimeoutMs: 50,
                retryBudgetMs: 50,
                maxAttempts: 1,
                queueExecutionTimeoutMs: 5_000,
            }),
        );

        const failedCall = errorCalls.find((entry) => entry.message === 'llm.call.failed');
        assert.ok(failedCall);
        assert.equal(failedCall?.meta.callSite, 'js_digging_classification');
        assert.equal(failedCall?.meta.failureCategory, 'provider_first_event_timeout');
        assert.equal(failedCall?.meta.attemptCount, 1);
        assert.equal(failedCall?.meta.attempts[0].failureCategory, 'provider_first_event_timeout');
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
        (logger as any).error = originalError;
    }
});

test('LLM runtime allows later calls to succeed after an earlier categorized failure', async () => {
    const originalExecuteAttempt = llmProvider.executeAttempt.bind(llmProvider);
    let callCount = 0;

    (llmProvider as any).executeAttempt = async () => {
        callCount += 1;
        if (callCount === 1) {
            throw new LlmExecutionError({
                failureCategory: 'provider_call_timeout',
                message: 'Attempt timed out.',
                rawError: 'Attempt timed out.',
                retryable: true,
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
                attemptTimeoutMs: 20,
                retryBudgetMs: 20,
                maxAttempts: 1,
                queueExecutionTimeoutMs: 5_000,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'provider_call_timeout');
                return true;
            },
        );

        const later = await llmRuntime.generate({
            systemPrompt: 'system',
            userPrompt: 'user',
        }, {
            scanId: 'scan-runtime-sequence',
            callSite: 'executive_summary',
            attemptTimeoutMs: 20,
            retryBudgetMs: 20,
            maxAttempts: 1,
            queueExecutionTimeoutMs: 5_000,
        });

        assert.equal(later.text, 'later-success');
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});

test('LLM runtime can disable provider and retry timeouts for long-running calls', async () => {
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
            firstEventTimeoutMs: null,
            attemptTimeoutMs: null,
            providerIdleTimeoutMs: null,
            queueWaitTimeoutMs: null,
            queueExecutionTimeoutMs: null,
        });

        assert.equal(response.text, 'long-running-ok');
        assert.equal(capturedExecutionOptions.length, 1);
        assert.equal(capturedExecutionOptions[0].firstEventTimeoutMs, null);
        assert.equal(capturedExecutionOptions[0].attemptTimeoutMs, null);
        assert.equal(capturedExecutionOptions[0].providerIdleTimeoutMs, null);
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
            queueExecutionTimeoutMs: 5_000,
        });

        assert.equal(response.text, 'user-scoped-ok');
        assert.equal(capturedMetadata.length, 1);
        assert.equal(capturedMetadata[0].metadata.userId, 77);
    } finally {
        (llmProvider as any).executeAttempt = originalExecuteAttempt;
    }
});
