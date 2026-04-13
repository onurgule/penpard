import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorContinuationCoordinator } = require('../src/agents/orchestrator/OrchestratorContinuationCoordinator') as typeof import('../src/agents/orchestrator/OrchestratorContinuationCoordinator');
const { OrchestratorScanState } = require('../src/agents/orchestrator/OrchestratorScanState') as typeof import('../src/agents/orchestrator/OrchestratorScanState');

// ── Helpers ──

function createState(overrides: Partial<{ maxIterations: number; maxPlanRounds: number }> = {}) {
    return new OrchestratorScanState({
        maxIterations: overrides.maxIterations ?? 50,
        maxPlanRounds: overrides.maxPlanRounds ?? 5,
    });
}

function createStubDeps(overrides: Partial<import('../src/agents/orchestrator/OrchestratorContinuationCoordinator').ContinuationCoordinatorDeps> = {}): import('../src/agents/orchestrator/OrchestratorContinuationCoordinator').ContinuationCoordinatorDeps {
    const logs: string[] = [];
    const state = createState();

    const discoveredEndpoints = new Set<string>();

    return {
        targetUrl: 'https://target.example.com',
        burp: {
            isAvailable: async () => true,
        },
        llm: {
            hasActiveConfig: () => true,
        },
        state,
        scanSurface: {
            restoreDiscoveredEndpoints: (endpoints: Iterable<string>) => {
                for (const ep of endpoints) discoveredEndpoints.add(ep);
                return discoveredEndpoints.size;
            },
            getDiscoveredEndpoints: () => Array.from(discoveredEndpoints),
        },
        scanStatus: {
            testing: () => {},
        },
        lifecycle: {
            persistRuntimeCheckpoint: async () => {},
        },
        initialRequestContext: null,
        systemPromptBuilder: {
            build: async () => 'system prompt for continuation',
        },
        buildAccountPromptContext: () => [],
        buildContinuationScopeMessage: (analysis) => ({
            role: 'system' as const,
            content: `Focused scope: ${analysis.focused_areas?.join(', ')}`,
        }),
        analyzeOperatorInstructions: async () => ({
            analysis: null,
            isFocusedScope: false,
        }),
        log: (_channel: string, message: string) => { logs.push(message); },
        ...overrides,
    };
}

function createBaseInput(): import('../src/agents/orchestrator/OrchestratorContinuationCoordinator').ContinuationInput {
    return {
        instruction: 'Test IDOR on /api/users',
        iterations: 3,
        planningEnabled: true,
    };
}

// ── Tests ──

test('continuation coordinator restores findings from persisted state', async () => {
    const state = createState();
    const deps = createStubDeps({ state });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const input = {
        ...createBaseInput(),
        existingFindings: [
            { name: 'XSS on /search', severity: 'high' },
            { name: 'SQLi on /login', severity: 'critical' },
        ],
    };

    const result = await coordinator.prepare(input);

    assert.equal(result.restoredState.restoredFindingsCount, 2);
    assert.equal(state.findingsCount, 2);
});

test('continuation coordinator restores endpoints from persisted state', async () => {
    const state = createState();
    const restored: string[] = [];
    const deps = createStubDeps({
        state,
        scanSurface: {
            restoreDiscoveredEndpoints: (endpoints: Iterable<string>) => {
                for (const ep of endpoints) restored.push(ep);
                return restored.length;
            },
            getDiscoveredEndpoints: () => restored,
        },
    });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const input = {
        ...createBaseInput(),
        existingEndpoints: ['/api/users', '/api/admin', '/api/session'],
    };

    const result = await coordinator.prepare(input);

    assert.equal(result.restoredState.restoredEndpointsCount, 3);
    assert.deepEqual(restored, ['/api/users', '/api/admin', '/api/session']);
});

test('continuation coordinator throws on missing LLM — hard requirement', async () => {
    const deps = createStubDeps({
        llm: { hasActiveConfig: () => false },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);

    await assert.rejects(
        coordinator.prepare(createBaseInput()),
        /No active LLM configured/,
    );
});

test('continuation coordinator logs Burp unavailability but continues', async () => {
    const logs: string[] = [];
    const deps = createStubDeps({
        burp: { isAvailable: async () => false },
        log: (_channel: string, message: string) => { logs.push(message); },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    const result = await coordinator.prepare(createBaseInput());

    assert.ok(result);
    assert.ok(logs.some(l => l.includes('Burp MCP not available')));
});

test('continuation coordinator enforces iteration bounds (1-20)', async () => {
    const deps = createStubDeps();
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    // Test lower bound
    const input1 = { ...createBaseInput(), iterations: 0 };
    const result1 = await coordinator.prepare(input1);
    assert.equal(result1.maxRounds, 1);

    // Reset state for second test
    const deps2 = createStubDeps();
    const coordinator2 = new OrchestratorContinuationCoordinator(deps2);

    // Test upper bound
    const input2 = { ...createBaseInput(), iterations: 100 };
    const result2 = await coordinator2.prepare(input2);
    assert.equal(result2.maxRounds, 20);
});

test('continuation coordinator injects system prompt when conversation is empty', async () => {
    const state = createState();
    const deps = createStubDeps({
        state,
        systemPromptBuilder: {
            build: async () => 'CONTINUATION SYSTEM PROMPT',
        },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    await coordinator.prepare(createBaseInput());

    // System prompt should be the first message
    assert.ok(state.conversationHistory.length > 0);
    assert.equal(state.conversationHistory[0].role, 'system');
    assert.equal(state.conversationHistory[0].content, 'CONTINUATION SYSTEM PROMPT');
});

test('continuation coordinator injects initial request context messages when present', async () => {
    const state = createState();
    const deps = createStubDeps({
        state,
        initialRequestContext: {
            continuationMessages: [
                { role: 'user', content: 'REMINDER - Burp request context' },
                { role: 'assistant', content: 'Understood, preserving headers.' },
            ],
            logSummary: 'Burp request parsed - GET /api/test',
        },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    const result = await coordinator.prepare(createBaseInput());

    assert.equal(result.restoredState.initialRequestRestored, true);
    // Should contain the initial request context messages
    assert.ok(state.conversationHistory.some(m => m.content.includes('Burp request context')));
});

test('continuation coordinator does not inject initial request context when null', async () => {
    const state = createState();
    const deps = createStubDeps({
        state,
        initialRequestContext: null,
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    const result = await coordinator.prepare(createBaseInput());

    assert.equal(result.restoredState.initialRequestRestored, false);
});

test('continuation coordinator injects operator command message with findings summary', async () => {
    const state = createState();
    const deps = createStubDeps({ state });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const input = {
        ...createBaseInput(),
        instruction: 'Focus on authentication bypass',
        existingFindings: [
            { name: 'XSS on /search', severity: 'high' },
        ],
    };

    await coordinator.prepare(input);

    const operatorMessage = state.conversationHistory.find(m =>
        m.role === 'user' && m.content.includes('OPERATOR COMMAND'));

    assert.ok(operatorMessage);
    assert.ok(operatorMessage!.content.includes('Focus on authentication bypass'));
    assert.ok(operatorMessage!.content.includes('XSS on /search'));
    assert.ok(operatorMessage!.content.includes('This is a NEW runtime'));
});

test('continuation coordinator swaps budget correctly', async () => {
    const state = createState({ maxIterations: 50, maxPlanRounds: 10 });
    state.setPlanRound(5);

    const deps = createStubDeps({ state });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const input = { ...createBaseInput(), iterations: 3 };
    const result = await coordinator.prepare(input);

    assert.equal(result.maxRounds, 3);
    // After budget swap, planRound should be 0 for continuation scope
    assert.equal(state.planRound, 0);
    // maxPlanRounds should be set to extraRounds
    assert.equal(state.maxPlanRounds, 3);
});

test('continuation coordinator persists checkpoint after preparation', async () => {
    const checkpoints: string[] = [];
    const deps = createStubDeps({
        lifecycle: {
            persistRuntimeCheckpoint: async (reason: string) => {
                checkpoints.push(reason);
            },
        },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    await coordinator.prepare(createBaseInput());

    assert.ok(checkpoints.includes('continuation-prepared'));
});

test('continuation coordinator calls scanStatus.testing() during preparation', async () => {
    let testingCalled = false;
    const deps = createStubDeps({
        scanStatus: {
            testing: () => { testingCalled = true; },
        },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    await coordinator.prepare(createBaseInput());

    assert.ok(testingCalled);
});

test('continuation coordinator analyzes operator instructions and injects focused scope', async () => {
    const state = createState();
    const deps = createStubDeps({
        state,
        analyzeOperatorInstructions: async () => ({
            analysis: {
                is_focused: true,
                focused_areas: ['IDOR', 'authentication'],
                testing_approach: 'parametric',
                priority_endpoints: ['/api/users'],
            } as any,
            isFocusedScope: true,
        }),
        buildContinuationScopeMessage: (analysis) => ({
            role: 'system' as const,
            content: `SCOPE: ${analysis.focused_areas?.join(', ')}`,
        }),
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    await coordinator.prepare(createBaseInput());

    const scopeMessage = state.conversationHistory.find(m =>
        m.content.includes('SCOPE: IDOR'));

    assert.ok(scopeMessage);
});

test('continuation coordinator full pipeline ordering: burp → llm → restore → prompt → inject → analyze → swap', async () => {
    const callOrder: string[] = [];
    const state = createState();

    const deps = createStubDeps({
        state,
        burp: {
            isAvailable: async () => { callOrder.push('burp-check'); return true; },
        },
        llm: {
            hasActiveConfig: () => { callOrder.push('llm-check'); return true; },
        },
        scanSurface: {
            restoreDiscoveredEndpoints: () => { callOrder.push('restore-endpoints'); return 0; },
            getDiscoveredEndpoints: () => [],
        },
        scanStatus: {
            testing: () => { callOrder.push('status-testing'); },
        },
        systemPromptBuilder: {
            build: async () => { callOrder.push('build-prompt'); return 'prompt'; },
        },
        analyzeOperatorInstructions: async () => {
            callOrder.push('analyze-instructions');
            return { analysis: null, isFocusedScope: false };
        },
        lifecycle: {
            persistRuntimeCheckpoint: async () => { callOrder.push('checkpoint'); },
        },
    });

    const coordinator = new OrchestratorContinuationCoordinator(deps);
    await coordinator.prepare({
        ...createBaseInput(),
        existingEndpoints: ['/api/test'],
    });

    // Verify ordering
    assert.equal(callOrder[0], 'burp-check');
    assert.equal(callOrder[1], 'llm-check');
    assert.equal(callOrder[2], 'restore-endpoints');
    assert.equal(callOrder[3], 'status-testing');
    assert.equal(callOrder[4], 'build-prompt');
    assert.equal(callOrder[5], 'analyze-instructions');
    assert.equal(callOrder[6], 'checkpoint');
});

test('continuation coordinator returns correct planningEnabled from input', async () => {
    const deps = createStubDeps();
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const result1 = await coordinator.prepare({ ...createBaseInput(), planningEnabled: true });
    assert.equal(result1.planningEnabled, true);

    const deps2 = createStubDeps();
    const coordinator2 = new OrchestratorContinuationCoordinator(deps2);

    const result2 = await coordinator2.prepare({ ...createBaseInput(), planningEnabled: false });
    assert.equal(result2.planningEnabled, false);
});

test('continuation coordinator handles missing findings and endpoints gracefully', async () => {
    const state = createState();
    const deps = createStubDeps({ state });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    const input = createBaseInput();
    // No existingFindings or existingEndpoints
    const result = await coordinator.prepare(input);

    assert.equal(result.restoredState.restoredFindingsCount, 0);
    assert.equal(result.restoredState.restoredEndpointsCount, 0);
});

test('continuation coordinator operator message mentions "NEW runtime" — truthful about semantic', async () => {
    const state = createState();
    const deps = createStubDeps({ state });
    const coordinator = new OrchestratorContinuationCoordinator(deps);

    await coordinator.prepare(createBaseInput());

    const operatorMessage = state.conversationHistory.find(m =>
        m.role === 'user' && m.content.includes('OPERATOR COMMAND'));

    assert.ok(operatorMessage);
    // The message should explicitly state this is a new runtime (truthful semantics)
    assert.ok(operatorMessage!.content.includes('NEW runtime'));
    assert.ok(operatorMessage!.content.includes('not available'));
});
