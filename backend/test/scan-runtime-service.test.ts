import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanRuntimeService } = require('../src/services/runtime/ScanRuntimeService') as typeof import('../src/services/runtime/ScanRuntimeService');
const { BurpMCPClient } = require('../src/services/burp-mcp') as typeof import('../src/services/burp-mcp');
const { createScan, getScan, initDatabase } = require('../src/db/init') as typeof import('../src/db/init');
const { scanRuntimeCheckpointService } = require('../src/services/runtime/ScanRuntimeCheckpointService') as typeof import('../src/services/runtime/ScanRuntimeCheckpointService');

test('finalizeAgentRuntime captures the resolved terminal phase before unregistering the runtime', () => {
    const callOrder: string[] = [];
    let capturedPhase: string | undefined;

    const registry = {
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push('capture');
            capturedPhase = phase;
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };

    const service = new ScanRuntimeService(registry as any);
    (service as any).resolveAgentFinalPhase = () => 'failed';

    const agent = {
        getState: () => ({ phase: 'planning' }),
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
    };

    const finalPhase = (service as any).finalizeAgentRuntime('scan-runtime-test', agent);

    assert.equal(finalPhase, 'failed');
    assert.equal(capturedPhase, 'failed');
    assert.deepEqual(callOrder, ['capture', 'flush', 'unregister']);
});

test('stopScan stops the agent before caching logs so terminal stop messages are retained', async () => {
    await initDatabase();

    const callOrder: string[] = [];
    const registry = {
        getRuntime: () => ({ kind: 'agent', agent }),
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push(`capture:${phase}`);
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };

    const agent = {
        stop: () => {
            callOrder.push('stop');
        },
        waitForCompletion: async () => {
            callOrder.push('wait');
        },
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
        getState: () => ({ phase: 'testing' }),
    };

    const service = new ScanRuntimeService(registry as any);
    (service as any).resolveAgentFinalPhase = () => 'stopped';

    const result = await service.stopScan('scan-runtime-stop-test', 1, 'testing');

    assert.match(result.message, /stopped/i);
    assert.deepEqual(callOrder, ['stop', 'wait', 'capture:stopped', 'flush', 'unregister']);
});

test('stopScan records stopped scans as terminal rows even when runtime state was already lost', async () => {
    await initDatabase();

    const scanId = `scan-runtime-terminal-${Date.now()}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
    });

    const service = new ScanRuntimeService({
        getRuntime: () => undefined,
    } as any);

    const result = await service.stopScan(scanId, 1, 'testing');
    const scan = getScan(scanId);

    assert.match(result.message, /status updated/i);
    assert.equal(scan.status, 'stopped');
    assert.equal(scan.error_message, 'Scan stopped by user');
    assert.ok(scan.completed_at);
});

test('startWebScan keeps the active production path on the single orchestrator even when parallelAgents is requested', async () => {
    const originalIsAvailable = BurpMCPClient.prototype.isAvailable;
    const originalDisconnect = BurpMCPClient.prototype.disconnect;
    let singleAgentCalls = 0;

    BurpMCPClient.prototype.isAvailable = async () => true;
    BurpMCPClient.prototype.disconnect = () => {};

    const service = new ScanRuntimeService();
    (service as any).runSingleAgentScan = async () => {
        singleAgentCalls += 1;
    };
    (service as any).runPoolScan = async () => {
        throw new Error('runPoolScan should stay dormant for web scans');
    };

    try {
        await service.startWebScan('scan-runtime-single-path', 'https://app.example.com', {
            parallelAgents: 4,
        });
    } finally {
        BurpMCPClient.prototype.isAvailable = originalIsAvailable;
        BurpMCPClient.prototype.disconnect = originalDisconnect;
    }

    assert.equal(singleAgentCalls, 1);
});

test('getLiveStatus surfaces the persisted runtime checkpoint when no active runtime survives', async () => {
    await initDatabase();

    const scanId = `scan-runtime-checkpoint-${Date.now()}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
    });

    scanRuntimeCheckpointService.saveCheckpoint(scanId, {
        version: 1,
        executionMode: 'single-agent',
        reason: 'planning-round-2',
        updatedAt: new Date().toISOString(),
        phase: 'planning',
        isRunning: false,
        isPaused: false,
        planRound: 2,
        maxPlanRounds: 5,
        maxIterations: 50,
        findingsCount: 1,
        discoveredEndpointsCount: 3,
        discoveredEndpointsPreview: ['GET /api/me'],
        currentPlan: null,
        harvested: {
            total: 4,
            promoted: 2,
            byClassification: { authentication: 1, object_reference: 1 },
            promotedRequests: [],
            topScoring: [],
        },
        hypotheses: {
            total: 3,
            counts: { new: 1, testing: 1, escalated: 0, confirmed: 1, discarded: 0 },
            activeHypotheses: [],
        },
        coverage: {
            routesSeen: 6,
            routesFromFrontend: 2,
            routesExercisedInBrowser: 3,
            requestsObservedInBurp: 4,
            requestsPromoted: 2,
            hypothesesActive: 2,
            untestedRoutes: ['GET /admin'],
            weaklyTestedRoutes: [],
            workflowStatus: { login: { explored: true, completeness: 'complete' } },
            coveragePercentage: 50,
        },
        endpointInventory: {
            summary: 'checkpoint summary',
            authSurfaceCount: 1,
            endpointCount: 6,
            highValueCount: 2,
        },
    });

    const service = new ScanRuntimeService({
        getRuntime: () => undefined,
        getCachedLogs: () => undefined,
        getTotalActiveRuntimeCount: () => 0,
    } as any);

    const live = service.getLiveStatus(scanId, getScan(scanId) as any, 0);

    assert.equal(live.executionMode, 'single-agent');
    assert.equal(live.harvestedRequestCount, 4);
    assert.equal(live.promotedRequestCount, 2);
    assert.equal(live.coverageSummary?.coveragePercentage, 50);
    assert.equal(live.runtimeCheckpoint?.reason, 'planning-round-2');
});
