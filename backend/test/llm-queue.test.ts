import test from 'node:test';
import assert from 'node:assert/strict';

import { llmQueue } from '../src/services/LLMQueue';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';
import { logger } from '../src/utils/logger';

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

test('LLM queue reports queue_wait_timeout before execution begins', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    let release!: () => void;
    const blocker = llmQueue.execute(async () => new Promise<void>((resolve) => {
        release = resolve;
    }), {
        executionTimeoutMs: 1_000,
    });

    try {
        await sleep(5);
        await assert.rejects(
            () => llmQueue.execute(async () => 'never', {
                waitTimeoutMs: 10,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'queue_wait_timeout');
                return true;
            },
        );
    } finally {
        release();
        await blocker;
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue reports queue_execution_timeout after a task exceeds its reservation budget', async () => {
    const originalDelay = (llmQueue as any).requestDelay;
    (llmQueue as any).requestDelay = 0;

    try {
        await assert.rejects(
            () => llmQueue.execute(async () => {
                await sleep(20);
                return 'late';
            }, {
                executionTimeoutMs: 5,
            }),
            (error: any) => {
                assert.ok(error instanceof LlmExecutionError);
                assert.equal(error.failureCategory, 'queue_execution_timeout');
                return true;
            },
        );
    } finally {
        (llmQueue as any).requestDelay = originalDelay;
    }
});

test('LLM queue preserves single-flight execution until timed-out work fully settles', async () => {
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
            executionTimeoutMs: 5,
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
                assert.equal(error.failureCategory, 'queue_execution_timeout');
                return true;
            },
        );

        assert.equal(await second, 'second');
        assert.ok(secondStartedAt >= firstFinishedAt);
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

