import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanRuntimeService } = require('../src/services/runtime/ScanRuntimeService') as typeof import('../src/services/runtime/ScanRuntimeService');
const { createScan, getScan, initDatabase, updateScanStatus } = require('../src/db/init') as typeof import('../src/db/init');
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

test('continueCompletedScan launches the composed continuation runtime and finalizes it on completion', async () => {
    await initDatabase();

    const scanId = `scan-runtime-continue-${Date.now()}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
    });

    const callOrder: string[] = [];
    const agent = {
        continueScan: async (options: any) => {
            callOrder.push(`continue:${options.iterations}:${options.planningEnabled}`);
        },
        getState: () => ({ phase: 'completed' }),
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
    };
    const registry = {
        hasActiveRuntime: () => false,
        registerAgent: () => {
            callOrder.push('register');
        },
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push(`capture:${phase}`);
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };
    const runtimeFactory = {
        createContinuationRuntime: async () => ({
            runtime: {
                kind: 'agent',
                scanId,
                scanMode: 'exploratory',
                executionMode: 'single-agent',
                agent,
                burp: {
                    disconnect: () => {
                        callOrder.push('disconnect');
                    },
                },
            },
            continuation: {
                instruction: 'Continue the authenticated API testing',
                iterations: 3,
                planningEnabled: true,
                existingFindings: [],
                existingEndpoints: [],
            },
        }),
    };

    const service = new ScanRuntimeService(registry as any, runtimeFactory as any);
    (service as any).resolveAgentFinalPhase = () => 'completed';
    const result = await service.continueCompletedScan({
        id: scanId,
        target: 'https://app.example.com',
        status: 'completed',
        user_id: 1,
    } as any, {
        instruction: 'Continue the authenticated API testing',
        iterations: 3,
        planningEnabled: true,
    });

    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.match(result.message, /continuing/i);
    assert.deepEqual(callOrder, [
        'register',
        'continue:3:true',
        'capture:completed',
        'flush',
        'unregister',
        'disconnect',
    ]);
});

test('startWebScan launches the runtime composed by the factory before lifecycle finalization runs', async () => {
    const callOrder: string[] = [];
    const agent = {
        start: async () => {
            callOrder.push('start');
        },
        getState: () => ({ phase: 'completed' }),
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
    };
    const registry = {
        registerAgent: () => {
            callOrder.push('register');
        },
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push(`capture:${phase}`);
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };
    const runtimeFactory = {
        createWebRuntime: async () => ({
            kind: 'agent',
            scanId: 'scan-runtime-single-path',
            scanMode: 'exploratory',
            executionMode: 'single-agent',
            agent,
            burp: {
                disconnect: () => {
                    callOrder.push('disconnect');
                },
            },
        }),
    };

    const service = new ScanRuntimeService(registry as any, runtimeFactory as any);
    await service.startWebScan('scan-runtime-single-path', 'https://app.example.com', {
        parallelAgents: 4,
    });

    assert.deepEqual(callOrder, ['register', 'start', 'capture:completed', 'flush', 'unregister', 'disconnect']);
});

test('startScopedWebScan uses the dedicated scoped runtime factory path before lifecycle finalization runs', async () => {
    const callOrder: string[] = [];
    const agent = {
        start: async () => {
            callOrder.push('start');
        },
        getState: () => ({ phase: 'completed' }),
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
    };
    const registry = {
        registerAgent: () => {
            callOrder.push('register');
        },
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push(`capture:${phase}`);
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };
    const runtimeFactory = {
        createScopedWebRuntime: async () => ({
            kind: 'agent',
            scanId: 'scan-runtime-scoped-path',
            scanMode: 'scoped',
            executionMode: 'single-agent',
            agent,
            burp: {
                disconnect: () => {
                    callOrder.push('disconnect');
                },
            },
        }),
    };

    const service = new ScanRuntimeService(registry as any, runtimeFactory as any);
    await service.startScopedWebScan('scan-runtime-scoped-path', 'https://app.example.com', {
        scanMode: 'scoped',
        focusedTestObjective: {
            id: 'objective-1',
            scanId: 'scan-runtime-scoped-path',
            title: 'Scoped API test',
            scopeType: 'endpoint_scoped',
            riskTags: [],
        },
        scopeEnvelope: {
            id: 'envelope-1',
            scanId: 'scan-runtime-scoped-path',
            version: 1,
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders'],
            selectedEndpoints: [{ method: 'GET', path: '/api/orders' }],
            baselineRequestRefs: [],
            requestBundleRefs: [],
            authContext: null,
            outOfScopeNotes: [],
            boundaryHints: [],
            explorationBudget: null,
        },
    });

    assert.deepEqual(callOrder, ['register', 'start', 'capture:completed', 'flush', 'unregister', 'disconnect']);
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
    assert.equal(Object.prototype.hasOwnProperty.call(live, 'liveRuntimeSummary'), true);
    assert.equal(Object.prototype.hasOwnProperty.call(live, 'scopedRuntime'), true);
    assert.equal(live.liveRuntimeSummary, null);
    assert.equal(live.scopedRuntime, null);
});

test('getLiveStatus treats scoped_executed as a completed terminal state', async () => {
    await initDatabase();

    const scanId = `scan-runtime-scoped-complete-${Date.now()}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com/orders/1',
        scanMode: 'scoped',
    });
    updateScanStatus(scanId, 'scoped_executed');

    const service = new ScanRuntimeService({
        getRuntime: () => undefined,
        getCachedLogs: () => undefined,
        getTotalActiveRuntimeCount: () => 0,
    } as any);

    const live = service.getLiveStatus(scanId, getScan(scanId) as any, 0);

    assert.equal(live.scanCompleted, true);
    assert.equal(live.burpConnected, null);
});

test('getLiveStatus mirrors active agent runtime summaries onto the generic Mission Control field', () => {
    const service = new ScanRuntimeService({
        getRuntime: () => ({
            kind: 'agent',
            agent: {
                getState: () => ({
                    phase: 'scoped_executing',
                    isRunning: true,
                    isPaused: false,
                    logsCount: 2,
                    harvestedRequestCount: 1,
                    promotedRequestCount: 1,
                    hypothesisCount: { new: 0, testing: 1, escalated: 0, confirmed: 0, discarded: 0 },
                    coverageSummary: null,
                    endpointInventory: null,
                }),
                getLogs: () => ['[2026-04-21T12:00:00] [SYSTEM] running'],
                getRuntimeSummary: () => ({
                    missionState: 'scoped_executing',
                    targetUrl: 'https://app.example.com/orders/1',
                    objectiveTitle: 'Scoped order detail',
                    objectiveGoal: 'Stay inside the seeded request boundary.',
                    requestDescription: 'Validate access control on the seeded order detail route.',
                    currentRail: 'request',
                    activeCaseId: 'case-1',
                    activeCaseTitle: 'GET /orders/:id',
                    activeFindingThreadId: 'thread-1',
                    activeFindingTitle: 'Potential IDOR',
                    observationSummary: '403 on contrast request',
                    nextStepRationale: 'Capture one more bounded contrast request.',
                    lastResponseDeltaSummary: 'Status 200 -> 403',
                    boundaryReason: null,
                    lastRequestSummary: { method: 'GET', path: '/orders/2', url: 'https://app.example.com/orders/2', statusCode: 403, summary: 'GET /orders/2' },
                    latestSuspiciousSignal: 'Authorization boundary shifted',
                    currentDecisionSummary: 'Replay one more adjacent identifier request.',
                    liveFindingCount: 1,
                    boundarySummary: null,
                }),
                getBrowserSessionId: () => null,
            },
        }),
        getActiveAgentCount: () => 1,
    } as any);

    const live = service.getLiveStatus('scan-runtime-agent-summary', {
        id: 'scan-runtime-agent-summary',
        scan_mode: 'scoped',
    } as any, 0);

    assert.equal(live.liveRuntimeSummary?.missionState, 'scoped_executing');
    assert.equal(live.scopedRuntime?.activeCaseTitle, 'GET /orders/:id');
});
