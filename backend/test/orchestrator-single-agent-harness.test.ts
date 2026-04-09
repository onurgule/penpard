import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorSingleAgentHarness } = require('../src/agents/orchestrator/OrchestratorSingleAgentHarness') as typeof import('../src/agents/orchestrator/OrchestratorSingleAgentHarness');

function deferred(): { promise: Promise<void>; resolve: () => void } {
    let resolve!: () => void;
    const promise = new Promise<void>((innerResolve) => {
        resolve = innerResolve;
    });
    return { promise, resolve };
}

test('single-agent harness rejects overlapping lifecycle requests instead of silently dropping them', async () => {
    const gate = deferred();
    const callOrder: string[] = [];

    const harness = new OrchestratorSingleAgentHarness<{ instruction: string }>({
        beforeRun: (kind: 'initial' | 'continuation') => {
            callOrder.push(`before:${kind}`);
        },
        runInitial: async () => {
            callOrder.push('run:initial');
            await gate.promise;
        },
        runContinuation: async () => {
            callOrder.push('run:continuation');
        },
        handleFailure: () => {
            callOrder.push('failure');
        },
        finalizeRun: async () => {
            callOrder.push('finalize');
        },
    });

    const initialRun = harness.start();
    await new Promise((resolve) => setTimeout(resolve, 0));

    await assert.rejects(
        harness.continueScan({ instruction: 'continue' }),
        /already running/i,
    );

    gate.resolve();
    await initialRun;

    assert.deepEqual(callOrder, ['before:initial', 'run:initial', 'finalize']);
});
