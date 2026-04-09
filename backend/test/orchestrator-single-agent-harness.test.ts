import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorSingleAgentHarness } = require('../src/agents/orchestrator/OrchestratorSingleAgentHarness') as typeof import('../src/agents/orchestrator/OrchestratorSingleAgentHarness');
const { OrchestratorScanState } = require('../src/agents/orchestrator/OrchestratorScanState') as typeof import('../src/agents/orchestrator/OrchestratorScanState');

function deferred(): { promise: Promise<void>; resolve: () => void } {
    let resolve!: () => void;
    const promise = new Promise<void>((innerResolve) => {
        resolve = innerResolve;
    });
    return { promise, resolve };
}

function createState() {
    return new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });
}

function createTestHarness(overrides: Partial<import('../src/agents/orchestrator/OrchestratorSingleAgentHarness').HarnessAgentContract<any>> = {}, state?: InstanceType<typeof OrchestratorScanState>) {
    const callOrder: string[] = [];
    const s = state ?? createState();

    const defaults: import('../src/agents/orchestrator/OrchestratorSingleAgentHarness').HarnessAgentContract<any> = {
        beforeRun: (kind: 'initial' | 'continuation') => { callOrder.push(`before:${kind}`); s.setRunning(true); },
        finalizeRun: async () => { callOrder.push('finalize'); },
        handleFailure: () => { callOrder.push('failure'); },
        runInit: async () => { callOrder.push('runInit'); },
        prepareContinuation: async () => { callOrder.push('prepareContinuation'); },
        createPlan: async () => { callOrder.push('createPlan'); return { kind: 'complete' }; },
        executeStep: async () => { callOrder.push('executeStep'); return { stepFindings: [], toolResultSummary: null, stepComplete: true }; },
        shouldContinueTesting: async () => { callOrder.push('shouldContinue'); return false; },
        processHumanCommand: async () => { callOrder.push('processCommand'); },
        runPostRoundWork: async () => { callOrder.push('postRound'); },
        runReporting: async () => { callOrder.push('reporting'); },
        runDirectExecution: async () => { callOrder.push('directExec'); },
        log: () => {},
        persistCheckpoint: async () => {},
        delay: async () => {},
    };

    const agent = { ...defaults, ...overrides };
    const harness = new OrchestratorSingleAgentHarness({ state: s, agent });
    return { harness, callOrder, state: s };
}

test('single-agent harness rejects overlapping lifecycle requests instead of silently dropping them', async () => {
    const gate = deferred();
    const { harness, callOrder, state } = createTestHarness({
        runInit: async () => {
            callOrder.push('run:initial');
            await gate.promise;
        },
    });

    state.setRunning(true);
    const initialRun = harness.start();
    await new Promise((resolve) => setTimeout(resolve, 0));

    await assert.rejects(
        harness.continueScan({ instruction: 'continue', iterations: 1, planningEnabled: true }),
        /already running/i,
    );

    gate.resolve();
    await initialRun;

    assert.ok(callOrder.includes('before:initial'));
    assert.ok(callOrder.includes('run:initial'));
    assert.ok(callOrder.includes('finalize'));
});

test('harness drives the plan→execute→replan loop through the agent contract', async () => {
    let planRounds = 0;

    const { harness, callOrder, state } = createTestHarness({
        runInit: async () => { callOrder.push('runInit'); },
        createPlan: async () => {
            planRounds++;
            if (planRounds > 2) return { kind: 'complete' };
            return {
                kind: 'plan',
                plan: {
                    round: planRounds,
                    analysis: 'test plan',
                    steps: [{ step: 1, objective: 'test', approach: 'test', tools: ['send_http_request'], status: 'pending' as const }],
                },
            };
        },
        executeStep: async () => ({
            stepFindings: [],
            toolResultSummary: '[send_http_request] ok',
            stepComplete: true,
        }),
        shouldContinueTesting: async () => planRounds < 2,
        runReporting: async () => { callOrder.push('reporting'); },
    });

    await harness.start();

    // The harness should have driven 2 plan rounds (round 1 continues, round 2 stops)
    assert.ok(callOrder.includes('runInit'));
    assert.ok(callOrder.includes('reporting'));
    assert.equal(planRounds, 2); // 2 rounds, shouldContinue=false after round 2
});

test('harness stops the loop when state.isRunning becomes false', async () => {
    let planCalls = 0;

    const { harness, state } = createTestHarness({
        runInit: async () => {},
        createPlan: async () => {
            planCalls++;
            if (planCalls >= 2) {
                state.setRunning(false); // simulate stop mid-loop
            }
            return {
                kind: 'plan' as const,
                plan: { round: planCalls, analysis: 'test', steps: [] },
            };
        },
        shouldContinueTesting: async () => true, // always want to continue — stop comes from isRunning
        runReporting: async () => {},
    });

    await harness.start();

    // planCalls=1: plan created, 0 steps executed, shouldContinue=true, loop continues
    // planCalls=2: plan created, sets isRunning=false, steps loop sees !isRunning and breaks
    // Loop condition sees !isRunning and breaks
    assert.ok(planCalls >= 2);
});

test('harness enforces iteration budget from state', async () => {
    const s = new OrchestratorScanState({ maxIterations: 3, maxPlanRounds: 0 });
    let stepCalls = 0;

    const { harness } = createTestHarness({
        runInit: async () => {},
        createPlan: async () => ({
            kind: 'plan' as const,
            plan: {
                round: 1,
                analysis: 'test',
                steps: [
                    { step: 1, objective: 'a', approach: 'a', tools: ['t'], status: 'pending' as const },
                    { step: 2, objective: 'b', approach: 'b', tools: ['t'], status: 'pending' as const },
                    { step: 3, objective: 'c', approach: 'c', tools: ['t'], status: 'pending' as const },
                    { step: 4, objective: 'd', approach: 'd', tools: ['t'], status: 'pending' as const },
                    { step: 5, objective: 'e', approach: 'e', tools: ['t'], status: 'pending' as const },
                ],
            },
        }),
        executeStep: async () => {
            stepCalls++;
            return { stepFindings: [], toolResultSummary: 'ok', stepComplete: false };
        },
        shouldContinueTesting: async () => true,
        runReporting: async () => {},
        delay: async () => {},
    }, s);

    await harness.start();

    // Should stop when maxIterations (3) is exhausted
    assert.equal(stepCalls, 3);
});

test('OrchestratorScanState tracks lifecycle transitions correctly', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });

    assert.equal(state.phase, 'planning');
    assert.equal(state.isRunning, false);
    assert.equal(state.isPaused, false);

    state.setRunning(true);
    state.setPhase('executing');
    assert.equal(state.phase, 'executing');
    assert.equal(state.isRunning, true);

    state.transitionToStopped();
    assert.equal(state.phase, 'stopped');
    assert.equal(state.isRunning, false);
    assert.equal(state.isPaused, false);
    assert.equal(state.isStoppedPhase(), true);
    assert.equal(state.isTerminalPhase(), true);
});

test('OrchestratorScanState swapContinuationBudget saves and restores correctly', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 10 });
    state.setPlanRound(3);

    const restore = state.swapContinuationBudget(5);

    assert.equal(state.planRound, 0);
    assert.equal(state.maxPlanRounds, 5);
    assert.equal(state.maxIterations, 50); // 5 * 10

    // Simulate completing 2 rounds in continuation
    state.incrementPlanRound();
    state.incrementPlanRound();

    restore();

    assert.equal(state.planRound, 5); // 3 + 2
    assert.equal(state.maxPlanRounds, 10);
    assert.equal(state.maxIterations, 50);
});

test('OrchestratorScanState manages findings and conversation correctly', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });

    state.pushFinding({ name: 'XSS', severity: 'high' });
    state.pushFinding({ name: 'SQLi', severity: 'critical' });
    assert.equal(state.findingsCount, 2);

    state.pushMessage({ role: 'user', content: 'test' });
    assert.equal(state.conversationHistory.length, 1);

    state.pushMessages([{ role: 'system', content: 'a' }, { role: 'user', content: 'b' }]);
    assert.equal(state.conversationHistory.length, 3);

    state.setFindings([]);
    assert.equal(state.findingsCount, 0);
});

test('OrchestratorScanState human command queue works correctly', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });

    assert.equal(state.hasHumanCommands(), false);

    state.pushHumanCommand('focus on XSS');
    state.pushHumanCommand('skip /admin');
    assert.equal(state.hasHumanCommands(), true);

    const cmd1 = state.shiftHumanCommand();
    assert.equal(cmd1, 'focus on XSS');
    assert.equal(state.hasHumanCommands(), true);

    const cmd2 = state.shiftHumanCommand();
    assert.equal(cmd2, 'skip /admin');
    assert.equal(state.hasHumanCommands(), false);
});

test('OrchestratorScanState checkpoint snapshot is truthful', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });
    state.setPhase('executing');
    state.setRunning(true);
    state.setPlanRound(3);
    state.pushFinding({ name: 'test' });
    state.setCurrentPlan({
        round: 3,
        analysis: 'testing',
        steps: [{ step: 1, objective: 'test', approach: 'x', tools: ['t'], status: 'completed' as const }],
    });

    const snapshot = state.getCheckpointSnapshot();
    assert.equal(snapshot.phase, 'executing');
    assert.equal(snapshot.isRunning, true);
    assert.equal(snapshot.planRound, 3);
    assert.equal(snapshot.maxPlanRounds, 5);
    assert.equal(snapshot.maxIterations, 50);
    assert.equal(snapshot.findingsCount, 1);
    assert.ok(snapshot.currentPlan);
    assert.equal(snapshot.currentPlan?.round, 3);
});

test('OrchestratorScanState rate limit tracking works', () => {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });

    assert.equal(state.isRateLimited(), false);
    assert.equal(state.getRateLimitWaitMs(), 0);

    state.applyRateLimitPause();
    assert.equal(state.isRateLimited(), true);
    assert.ok(state.getRateLimitWaitMs() > 0);

    state.clearRateLimitPause();
    assert.equal(state.isRateLimited(), false);
});
