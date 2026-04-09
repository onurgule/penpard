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
    (agent as any).phaseIterativeTesting = async () => {
        agent.stop();
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

    (agent as any).isRunning = true;
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
