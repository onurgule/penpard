import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorLifecycleCoordinator } = require('../src/agents/orchestrator/OrchestratorLifecycleCoordinator') as typeof import('../src/agents/orchestrator/OrchestratorLifecycleCoordinator');
const { OrchestratorScanState } = require('../src/agents/orchestrator/OrchestratorScanState') as typeof import('../src/agents/orchestrator/OrchestratorScanState');

function createCoordinator(overrides: Partial<ConstructorParameters<typeof OrchestratorLifecycleCoordinator>[0]> = {}) {
    const state = new OrchestratorScanState({ maxIterations: 50, maxPlanRounds: 5 });
    const statusEvents: string[] = [];
    const logs: string[] = [];
    const cleanupEvents: string[] = [];
    const checkpointEvents: string[] = [];

    const options: ConstructorParameters<typeof OrchestratorLifecycleCoordinator>[0] = {
        scanId: 'scan-lifecycle-coordinator-test',
        targetUrl: 'https://app.example.com',
        state,
        scanStatus: {
            reporting: () => statusEvents.push('reporting'),
            completed: () => statusEvents.push('completed'),
            failed: (message?: string) => statusEvents.push(`failed:${message || ''}`),
            stopped: (message?: string) => statusEvents.push(`stopped:${message || ''}`),
        } as any,
        browserSession: () => ({
            cleanup: async () => {
                cleanupEvents.push('cleanup');
            },
        }),
        scanSurface: () => ({
            getDiscoveredEndpointCount: () => 3,
            getDiscoveredEndpointPreview: () => ['GET /api/me', 'POST /api/session'],
            getEndpointInventory: () => ({
                scanId: 'scan-lifecycle-coordinator-test',
                targetUrl: 'https://app.example.com',
                targetOrigin: 'https://app.example.com',
                generatedAt: new Date().toISOString(),
                summary: 'inventory summary',
                authRelevantCount: 1,
                observedInBurpCount: 2,
                exercisedInBrowserCount: 1,
                jsArtifacts: { count: 0, analyzedCount: 0, totalBytes: 0 },
                classifications: {},
                records: [
                    {
                        id: 'endpoint-1',
                        endpoint: '/api/me',
                        path: '/api/me',
                        methods: ['GET'],
                        primarySource: 'burp',
                        sources: ['burp'],
                        confidence: 0.9,
                        classification: 'profile_account',
                        likelyAuthRelevant: true,
                        observedInBurp: true,
                        exercisedInBrowser: true,
                        inferredOnly: false,
                        notes: [],
                        evidence: [],
                        scriptSources: [],
                        domSources: [],
                        authSignals: [],
                        storageKeys: [],
                        observedStatusCodes: [200],
                    },
                ],
            }),
        }),
        domainCoordinator: () => ({
            getCheckpointSummary: () => ({
                harvested: {
                    total: 4,
                    promoted: 2,
                    byClassification: { authentication: 1 },
                    promotedRequests: [],
                    topScoring: [],
                },
                hypotheses: {
                    total: 1,
                    counts: { new: 1, confirmed: 0 },
                    activeHypotheses: [],
                },
                coverage: {
                    routesSeen: 6,
                    routesFromFrontend: 1,
                    routesExercisedInBrowser: 2,
                    requestsObservedInBurp: 3,
                    requestsPromoted: 2,
                    hypothesesActive: 1,
                    untestedRoutes: [],
                    weaklyTestedRoutes: [],
                    workflowStatus: {},
                    coveragePercentage: 50,
                },
            }),
        }),
        contextSignals: {
            resetBudgetSignals: () => {
                logs.push('budget-reset');
            },
        } as any,
        persistence: {
            loadVulnerabilitiesForReporting: () => [
                { name: 'SQL Injection - /api/login (username)', severity: 'critical' },
                { name: 'IDOR - /api/account/2', severity: 'high' },
            ],
        },
        log: (_channel, message) => logs.push(message),
        delay: async () => {},
        saveLogs: () => {
            cleanupEvents.push('save');
        },
        checkpoint: async (checkpoint) => {
            checkpointEvents.push(checkpoint.reason);
        },
        summarizeReport: async () => 'summary text',
    };

    const coordinator = new OrchestratorLifecycleCoordinator({ ...options, ...overrides });
    return { coordinator, state, statusEvents, logs, cleanupEvents, checkpointEvents };
}

test('lifecycle coordinator owns reporting/finalization without changing terminal behavior', async () => {
    const { coordinator, state, statusEvents, logs, cleanupEvents } = createCoordinator();
    state.setRunning(true);
    state.setPlanRound(3);

    await coordinator.runReporting();

    assert.equal(state.phase, 'completed');
    assert.deepEqual(statusEvents, ['reporting', 'completed']);
    assert.deepEqual(cleanupEvents, ['cleanup']);
    assert.ok(logs.some((entry) => entry.includes('Total findings: 2')));
    assert.ok(logs.some((entry) => entry.includes('Executive Summary')));
    assert.ok(logs.some((entry) => entry.includes('Rounds: 3 | Endpoints: 3 | Findings: 2')));
});

test('lifecycle coordinator builds truthful runtime checkpoints from state and domain surfaces', async () => {
    const captured: any[] = [];
    const { coordinator, state } = createCoordinator({
        checkpoint: async (checkpoint) => {
            captured.push(checkpoint);
        },
    });

    state.setRunning(true);
    state.setPhase('executing');
    state.setPlanRound(2);
    state.pushFinding({ name: 'XSS' });
    state.setCurrentPlan({
        round: 2,
        analysis: 'test plan',
        steps: [{ step: 1, objective: 'probe', approach: 'probe', tools: ['send_http_request'], status: 'completed' as const }],
    });

    await coordinator.persistRuntimeCheckpoint('planning-round-2');

    assert.equal(captured.length, 1);
    assert.equal(captured[0].reason, 'planning-round-2');
    assert.equal(captured[0].phase, 'executing');
    assert.equal(captured[0].findingsCount, 1);
    assert.equal(captured[0].discoveredEndpointsCount, 3);
    assert.equal(captured[0].endpointInventory?.summary, 'inventory summary');
    assert.equal(captured[0].coverage.coveragePercentage, 50);
});

test('lifecycle coordinator finalizes by checkpointing around cleanup and log persistence', async () => {
    const order: string[] = [];
    const { coordinator, state } = createCoordinator({
        browserSession: () => ({
            cleanup: async () => {
                order.push('cleanup');
            },
        }),
        saveLogs: () => {
            order.push('save');
        },
        checkpoint: async (checkpoint) => {
            order.push(`checkpoint:${checkpoint.reason}`);
        },
    });

    state.setRunning(true);

    await coordinator.finalizeRun();

    assert.equal(state.isRunning, false);
    assert.deepEqual(order, [
        'checkpoint:run-finalizing',
        'cleanup',
        'save',
        'checkpoint:run-finalized',
    ]);
});
