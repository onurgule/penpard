import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorAgent } = require('../src/agents/OrchestratorAgent') as typeof import('../src/agents/OrchestratorAgent');

function createAgent() {
    return new OrchestratorAgent(
        'scan-lifecycle-test',
        'https://app.example.com',
        {
            rateLimit: 0,
            maxIterations: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
        },
        {
            isAvailable: async () => true,
            callTool: async () => ({}),
        } as any,
    );
}

test('start skips reporting when the orchestrator is stopped mid-run', async () => {
    const agent = createAgent();
    let reportingCalls = 0;

    (agent as any).phaseInit = async () => {};
    // The iterative testing loop is now in the harness, but phaseInit succeeds
    // and scanStatus.testing() is called. The harness then drives the loop.
    // To simulate a stop mid-run, we override via the createPlanForHarness:
    (agent as any).createPlanForHarness = async () => {
        agent.stop();
        return { kind: 'complete' };
    };
    (agent as any).phaseReporting = async () => {
        reportingCalls += 1;
    };
    (agent as any).saveLogs = () => {};

    await agent.start();

    assert.equal(reportingCalls, 0);
    assert.equal(agent.getState().phase, 'stopped');
    assert.equal(agent.getState().isRunning, false);
});

test('stop clears paused state so terminal status is truthful', () => {
    const agent = createAgent();

    agent.state.setRunning(true);
    agent.pause();
    agent.stop();

    assert.equal(agent.getState().phase, 'stopped');
    assert.equal(agent.getState().isPaused, false);
    assert.equal(agent.getState().isRunning, false);
});

test('start always cleans up the browser session when the run fails', async () => {
    const agent = createAgent();
    let cleanupCalls = 0;

    (agent as any).phaseInit = async () => {
        throw new Error('boom');
    };
    (agent as any).browserSession = {
        cleanup: () => {
            cleanupCalls += 1;
        },
    };
    (agent as any).saveLogs = () => {};

    await agent.start();

    assert.equal(agent.getState().phase, 'failed');
    assert.equal(cleanupCalls, 1);
});

test('start awaits browser cleanup before persisting final logs', async () => {
    const agent = createAgent();
    const callOrder: string[] = [];

    (agent as any).phaseInit = async () => {
        throw new Error('boom');
    };
    (agent as any).browserSession = {
        cleanup: async () => {
            callOrder.push('cleanup');
        },
    };
    (agent as any).saveLogs = () => {
        callOrder.push('save');
    };

    await agent.start();

    assert.deepEqual(callOrder, ['cleanup', 'save']);
});
