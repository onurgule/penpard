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
