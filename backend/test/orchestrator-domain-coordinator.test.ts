import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorDomainCoordinator } = require('../src/agents/orchestrator/OrchestratorDomainCoordinator') as typeof import('../src/agents/orchestrator/OrchestratorDomainCoordinator');

function createCoordinator(overrides: Record<string, any> = {}) {
    const logs: string[] = [];
    const checkpoints: string[] = [];
    const confirmedFindings: any[] = [];

    const coordinator = new OrchestratorDomainCoordinator({
        targetUrl: 'https://app.example.com',
        burp: {
            callTool: async (_tool: string, _args: Record<string, any>) => ({
                items: [],
            }),
        },
        authManager: {
            prepareRequest: (_headers: any, body: string, _url: string, _method: string, _identityId: string, _preserveExplicitAuth: boolean) => ({
                headers: {},
                body,
            }),
        } as any,
        log: (_channel, message) => logs.push(message),
        onCheckpoint: async (reason) => { checkpoints.push(reason); },
        onHypothesisConfirmed: (finding) => { confirmedFindings.push(finding); },
        ...overrides,
    });

    return { coordinator, logs, checkpoints, confirmedFindings };
}

test('domain coordinator owns harvester, hypothesis engine, and coverage tracker', () => {
    const { coordinator } = createCoordinator();

    assert.ok(coordinator.harvester, 'harvester should be initialized');
    assert.ok(coordinator.hypothesisEngine, 'hypothesis engine should be initialized');
    assert.ok(coordinator.coverageTracker, 'coverage tracker should be initialized');
});

test('executeGetCoverage returns coverage summary from the tracker', async () => {
    const { coordinator, logs } = createCoordinator();

    // Add some routes to coverage
    coordinator.coverageTracker.addRoute('/api/users', 'GET', 'burp');
    coordinator.coverageTracker.addRoute('/api/login', 'POST', 'burp');

    const result = await coordinator.executeGetCoverage();

    assert.ok(result.routesSeen >= 2, 'should see at least 2 routes');
    assert.ok(logs.some((l) => l.includes('get_coverage')));
});

test('executeGetHypotheses returns hypotheses filtered by status', async () => {
    const { coordinator, logs } = createCoordinator();

    const result = await coordinator.executeGetHypotheses({ tool: 'get_hypotheses', args: { status: 'all' } });

    assert.equal(typeof result.count, 'number');
    assert.ok(result.statusCounts !== undefined);
    assert.ok(Array.isArray(result.hypotheses));
    assert.ok(logs.some((l) => l.includes('get_hypotheses')));
});

test('executeHarvestTraffic invokes checkpoint callback', async () => {
    const { coordinator, checkpoints } = createCoordinator();

    await coordinator.executeHarvestTraffic();

    assert.ok(checkpoints.includes('harvest-traffic-tool'));
});

test('getCheckpointSummary returns structured domain state', () => {
    const { coordinator } = createCoordinator();

    coordinator.coverageTracker.addRoute('/api/test', 'GET', 'burp');
    const summary = coordinator.getCheckpointSummary();

    assert.ok(summary.harvested !== undefined);
    assert.ok(summary.hypotheses !== undefined);
    assert.ok(summary.coverage !== undefined);
    assert.ok(summary.hypotheses.total !== undefined);
    assert.ok(summary.hypotheses.counts !== undefined);
});

test('getPentesterLoopState returns aggregate loop state', () => {
    const { coordinator } = createCoordinator();

    const state = coordinator.getPentesterLoopState();

    assert.equal(typeof state.harvestedRequestCount, 'number');
    assert.equal(typeof state.promotedRequestCount, 'number');
    assert.ok(state.hypothesisCount !== undefined);
    assert.ok(state.coverageSummary !== undefined);
    assert.equal(typeof state.coverageSummary.routesSeen, 'number');
    assert.equal(typeof state.coverageSummary.coveragePercentage, 'number');
});

test('runHarvestCycle logs and completes without errors', async () => {
    const { coordinator, logs } = createCoordinator();

    await coordinator.runHarvestCycle();

    assert.ok(logs.some((l) => l.includes('HARVEST CYCLE')));
});

test('repeater_test sends scoped mutations through the Burp-visible request rail with attribution', async () => {
    const sent: Array<{ tool: string; args: Record<string, any> }> = [];
    const { coordinator } = createCoordinator({
        scanId: 'scan-domain-scoped',
        burp: {
            callTool: async (tool: string, args: Record<string, any>) => {
                sent.push({ tool, args });
                return {
                    statusCode: 200,
                    headers: ['content-type: application/json'],
                    body: '{"orderId":2}',
                };
            },
        },
    });
    (coordinator.harvester as any).getById = () => ({
        id: 'req-order',
        method: 'GET',
        url: 'https://app.example.com/api/orders?orderId=1',
        path: '/api/orders?orderId=1',
        host: 'app.example.com',
        statusCode: 200,
        mimeType: 'application/json',
        requestHeaders: {},
        requestBody: '',
        responseBody: '{"orderId":1}',
        responseHeaders: { 'content-type': 'application/json' },
        params: [],
        classification: 'object-reference',
        interestScore: 90,
        harvestedAt: new Date(),
        source: 'user',
        promoted: true,
        testedHypotheses: [],
    });

    const result = await coordinator.executeRepeaterTest({
        tool: 'repeater_test',
        args: {
            requestId: 'req-order',
            mutations: [{
                parameter: 'orderId',
                originalValue: '1',
                newValue: '2',
                description: 'Adjacent order identifier contrast',
            }],
        },
    });

    assert.equal(sent[0].tool, 'send_http_request');
    assert.equal(sent[0].args.use_proxy, true);
    assert.match(sent[0].args.penpard_source, /scan-domain-scoped\/repeater_test/);
    assert.equal(result.results[0].burpVisible, true);
    assert.match(result.results[0].requestSummary, /orderId=2/);
});

test('getHarvestConversationSummary returns system-injection-ready string', () => {
    const { coordinator } = createCoordinator();
    const summary = coordinator.getHarvestConversationSummary();

    assert.ok(summary.startsWith('[SYSTEM]'));
    assert.ok(summary.includes('Harvest cycle complete'));
});
