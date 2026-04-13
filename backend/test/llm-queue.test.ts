import test from 'node:test';
import assert from 'node:assert/strict';

import { llmQueue } from '../src/services/LLMQueue';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';
import { logger } from '../src/utils/logger';

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeDiagnostics(overrides: Record<string, unknown> = {}) {
    return {
        streamingStarted: true,
        anyEventReceived: true,
        partialOutputReceived: false,
        assistantMessageReceived: false,
        idleReceived: false,
        finalizationReceived: false,
        firstEventAtMs: 1,
        firstProgressAtMs: null,
        partialOutputAtMs: null,
        lastEventAtMs: 1,
        lastProgressAtMs: null,
        idleAtMs: null,
        finalizationAtMs: null,
        finalContentLength: 0,
        progressEventCount: 0,
        attemptPhase: 'awaiting_first_progress',
        completionSignal: null,
        livenessCategory: null,
        warningCategory: null,
        rawProviderError: null,
        ...overrides,
    };
}

test('LLM queue reports queue_timeout before execution begins', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    let release!: () => void;
    const blocker = llmQueue.execute(async () => new Promise<void>((resolve) => {
        release = resolve;
    }), {
        executionWatchdogMs: 1_000,
    });

    try {
        await sleep(5);
        await assert.rejects(
            () => llmQueue.execute(async () => 'never', {
                waitTimeoutMs: 10,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'queue_timeout');
                assert.equal(error.livenessCategory, 'queue_timeout');
                return true;
            },
        );
    } finally {
        release();
        await blocker;
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue reports watchdog_timeout after a task exceeds its execution watchdog', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    try {
        await assert.rejects(
            () => llmQueue.execute(async () => {
                await sleep(20);
                return 'late';
            }, {
                executionWatchdogMs: 5,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'watchdog_timeout');
                assert.equal(error.livenessCategory, 'watchdog_timeout');
                return true;
            },
        );
    } finally {
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue preserves single-flight execution until watchdog-expired work fully settles', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    let firstFinishedAt = 0;
    let secondStartedAt = 0;

    try {
        const first = llmQueue.execute(async () => {
            await sleep(25);
            firstFinishedAt = Date.now();
            return 'first';
        }, {
            executionWatchdogMs: 5,
        });

        await sleep(2);

        const second = llmQueue.execute(async () => {
            secondStartedAt = Date.now();
            return 'second';
        });

        await assert.rejects(
            () => first,
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'watchdog_timeout');
                assert.equal(error.livenessCategory, 'watchdog_timeout');
                return true;
            },
        );

        assert.equal(await second, 'second');
        assert.ok(secondStartedAt >= firstFinishedAt);
    } finally {
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue preserves diagnostics when the outer execution watchdog fires', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    try {
        await assert.rejects(
            () => llmQueue.execute(async ({ signal }) => {
                await new Promise<void>((_, reject) => {
                    signal.addEventListener('abort', () => {
                        reject(new LlmExecutionError({
                            failureCategory: 'canceled',
                            message: 'provider aborted after queue execution timeout',
                            rawError: 'provider aborted after queue execution timeout',
                            attemptPhase: 'streaming',
                            diagnostics: makeDiagnostics({
                                partialOutputReceived: true,
                                assistantMessageReceived: true,
                                firstProgressAtMs: 2,
                                partialOutputAtMs: 2,
                                lastProgressAtMs: 4,
                                finalContentLength: 12,
                                progressEventCount: 3,
                                attemptPhase: 'streaming',
                            }),
                        }));
                    }, { once: true });
                });
                return 'never';
            }, {
                executionWatchdogMs: 5,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'watchdog_timeout');
                assert.equal(error.livenessCategory, 'watchdog_timeout');
                assert.equal(error.diagnostics?.partialOutputReceived, true);
                return true;
            },
        );
    } finally {
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue emits structured queue timing telemetry', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    const originalDebug = (logger as any).debug?.bind(logger);
    (llmQueue as any).requestDelay = 0;
    const debugCalls: Array<{ message: string; meta: any }> = [];
    (logger as any).debug = (message: string, meta: any) => {
        debugCalls.push({ message, meta });
    };

    try {
        await llmQueue.execute(async () => 'ok', {
            callSite: 'source_analysis',
            scanId: 'scan-queue-test',
        });

        assert.ok(debugCalls.some((entry) =>
            entry.message === 'llm.queue.execution.finished'
            && entry.meta.callSite === 'source_analysis'
            && entry.meta.scanId === 'scan-queue-test'
            && typeof entry.meta.queueWaitMs === 'number',
        ));
    } finally {
        (llmQueue as any).requestDelay = originalDelay;
        (logger as any).debug = originalDebug;
    }
});

