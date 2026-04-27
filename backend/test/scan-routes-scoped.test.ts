import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-scan-routes-scoped-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'scan-routes-scoped-test-secret';

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { createApp } = require('../src/app') as typeof import('../src/app');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const { scanRuntimeService } = require('../src/services/runtime/ScanRuntimeService') as typeof import('../src/services/runtime/ScanRuntimeService');
const { focusedPlanningService } = require('../src/services/runtime/FocusedPlanningService') as typeof import('../src/services/runtime/FocusedPlanningService');
const { focusedExecutionRunner } = require('../src/services/runtime/FocusedExecutionRunner') as typeof import('../src/services/runtime/FocusedExecutionRunner');
const { buildFocusedPlanSummary } = require('../src/services/runtime/ScopedScanTypes') as typeof import('../src/services/runtime/ScopedScanTypes');

async function resetDb() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM focused_scan_historical_compare_summaries;
        DELETE FROM focused_test_case_historical_compares;
        DELETE FROM focused_scan_historical_compare_states;
        DELETE FROM focused_scan_blocker_summaries;
        DELETE FROM focused_test_case_investigation_issues;
        DELETE FROM focused_scan_verdict_summaries;
        DELETE FROM focused_test_case_verdicts;
        DELETE FROM focused_test_case_finding_threads;
        DELETE FROM focused_test_case_findings;
        DELETE FROM focused_test_case_evidence_bundles;
        DELETE FROM focused_reasoning_trace_entries;
        DELETE FROM focused_test_case_execution_trace_entries;
        DELETE FROM focused_test_case_executions;
        DELETE FROM focused_test_cases;
        DELETE FROM focused_test_objectives;
        DELETE FROM scope_envelopes;
        DELETE FROM scan_chat_messages;
        DELETE FROM scan_logs;
        DELETE FROM vulnerabilities;
        DELETE FROM scans;
    `);
}

test('scoped /api/scans/web persists objective and envelope and launches the scoped mission path', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);
    const missionLaunches: any[] = [];
    const exploratoryLaunches: any[] = [];
    const originalMissionLaunch = scanRuntimeService.launchScopedMission;
    const originalExploratoryLaunch = scanRuntimeService.launchWebScan;

    scanRuntimeService.launchScopedMission = ((scanId: string, targetUrl: string) => {
        missionLaunches.push({ scanId, targetUrl });
    }) as any;
    scanRuntimeService.launchWebScan = ((scanId: string, targetUrl: string, config: any) => {
        exploratoryLaunches.push({ scanId, targetUrl, config });
    }) as any;

    try {
        const response = await request(app)
            .post('/api/scans/web')
            .set('Authorization', `Bearer ${token}`)
            .field('url', 'https://app.example.com')
            .field('scanMode', 'scoped')
            .field('focusedObjective', JSON.stringify({
                title: 'Account profile scoped test',
                scopeType: 'endpoint_scoped',
                goal: 'Validate access control around profile reads.',
                riskTags: ['idor', 'authz'],
            }))
            .field('scopeEnvelope', JSON.stringify({
                selectedEndpoints: [{ method: 'GET', path: '/api/profile' }],
                boundaryHints: ['Stay inside account profile routes'],
                outOfScopeNotes: ['Do not enumerate admin APIs'],
            }));

        assert.equal(response.status, 200);
        const scanId = (response.body as any).scanId;
        const scan = dbModule.getScan(scanId);
        const objective = dbModule.getFocusedTestObjective(scanId);
        const envelope = dbModule.getScopeEnvelope(scanId);
        const structuredRequest = dbModule.getScopedTestRequest(scanId);
        const discoveryState = dbModule.getScopedFeatureDiscoveryState(scanId);
        const reasoningTrace = dbModule.listFocusedReasoningTraceEntriesByScan(scanId);

        assert.equal(scan.scan_mode, 'scoped');
        assert.equal(scan.status, 'scoped_discovering');
        assert.ok(objective);
        assert.equal(objective?.title, 'Account profile scoped test');
        assert.ok(envelope);
        assert.deepEqual(envelope?.allowedRoutes, ['/api/profile']);
        assert.equal(structuredRequest?.description, 'Validate access control around profile reads.');
        assert.equal(discoveryState?.phase, 'not_started');
        assert.equal(reasoningTrace.some((entry: any) => entry.stage === 'request_intake'), true);
        assert.equal(missionLaunches.length, 1);
        assert.equal(exploratoryLaunches.length, 0);
        assert.equal(missionLaunches[0].scanId, scanId);
        assert.equal(missionLaunches[0].targetUrl, 'https://app.example.com/');
    } finally {
        scanRuntimeService.launchScopedMission = originalMissionLaunch;
        scanRuntimeService.launchWebScan = originalExploratoryLaunch;
    }
});

test('exploratory /api/scans/web still uses the existing exploratory runtime path', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);
    const exploratoryLaunches: any[] = [];
    const originalExploratoryLaunch = scanRuntimeService.launchWebScan;

    scanRuntimeService.launchWebScan = ((scanId: string, targetUrl: string, config: any) => {
        exploratoryLaunches.push({ scanId, targetUrl, config });
    }) as any;

    try {
        const response = await request(app)
            .post('/api/scans/web')
            .set('Authorization', `Bearer ${token}`)
            .field('url', 'https://exploratory.example.com');

        assert.equal(response.status, 200);
        const scanId = (response.body as any).scanId;
        const scan = dbModule.getScan(scanId);
        const detailResponse = await request(app)
            .get(`/api/scans/${scanId}`)
            .set('Authorization', `Bearer ${token}`);
        const liveResponse = await request(app)
            .get(`/api/scans/${scanId}/live`)
            .set('Authorization', `Bearer ${token}`);

        assert.equal(scan.scan_mode, 'exploratory');
        assert.equal(exploratoryLaunches.length, 1);
        assert.equal(exploratoryLaunches[0].config.scanMode, 'exploratory');
        assert.equal(detailResponse.status, 200);
        assert.equal((detailResponse.body as any).liveRuntimeSummary, null);
        assert.equal((liveResponse.body as any).liveRuntimeSummary, null);
        assert.equal((liveResponse.body as any).scopedRuntime, null);
    } finally {
        scanRuntimeService.launchWebScan = originalExploratoryLaunch;
    }
});

test('scoped /api/scans/from-burp persists the Burp baseline request and scoped envelope before launching the scoped mission', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);
    const missionLaunches: any[] = [];
    const originalMissionLaunch = scanRuntimeService.launchScopedMission;

    scanRuntimeService.launchScopedMission = ((scanId: string, targetUrl: string) => {
        missionLaunches.push({ scanId, targetUrl });
    }) as any;

    try {
        const queueResponse = await request(app)
            .post('/api/penpard/send-request')
            .send({ rawRequest: 'GET /api/orders/1 HTTP/1.1\nHost: app.example.com\n\n' });
        assert.equal(queueResponse.status, 201);
        const pendingId = (queueResponse.body as any).pendingId;

        const response = await request(app)
            .post('/api/scans/from-burp')
            .set('Authorization', `Bearer ${token}`)
            .field('pendingId', pendingId)
            .field('scanMode', 'scoped')
            .field('focusedObjective', JSON.stringify({
                title: 'Order request scoped test',
                scopeType: 'request_scoped',
                goal: 'Validate access control around a Burp-seeded order lookup.',
                riskTags: ['idor'],
            }))
            .field('scopeEnvelope', JSON.stringify({
                boundaryHints: ['Stay inside order detail replay'],
                outOfScopeNotes: ['Do not fuzz unrelated report exports'],
            }));

        assert.equal(response.status, 200);
        const scanId = (response.body as any).scanId;
        const scan = dbModule.getScan(scanId);
        const envelope = dbModule.getScopeEnvelope(scanId);
        const structuredRequest = dbModule.getScopedTestRequest(scanId);
        const discoveryState = dbModule.getScopedFeatureDiscoveryState(scanId);
        const reasoningTrace = dbModule.listFocusedReasoningTraceEntriesByScan(scanId);

        assert.equal(scan.scan_mode, 'scoped');
        assert.equal(scan.status, 'scoped_discovering');
        assert.equal(scan.initial_request, 'GET /api/orders/1 HTTP/1.1\nHost: app.example.com');
        assert.ok(envelope);
        assert.equal(envelope?.baselineRequestRefs.length, 1);
        assert.deepEqual(envelope?.allowedRoutes, ['/api/orders/1']);
        assert.equal(structuredRequest?.description, 'Validate access control around a Burp-seeded order lookup.');
        assert.equal(discoveryState?.phase, 'not_started');
        assert.equal(reasoningTrace.some((entry: any) => entry.stage === 'request_intake'), true);
        assert.equal(missionLaunches.length, 1);
        assert.equal(missionLaunches[0].scanId, scanId);
        assert.equal(missionLaunches[0].targetUrl, 'https://app.example.com/api/orders/1');
    } finally {
        scanRuntimeService.launchScopedMission = originalMissionLaunch;
    }
});

test('focused planning routes list, update, and regenerate persisted scoped cases', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);

    dbModule.createScan({
        id: 'scoped-route-scan',
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });

    dbModule.createFocusedTestObjective({
        id: 'objective-1',
        scanId: 'scoped-route-scan',
        title: 'Orders scoped review',
        scopeType: 'endpoint_scoped',
        goal: 'Review bounded order access cases.',
        riskTags: ['idor', 'authz'],
    });

    dbModule.createScopeEnvelope({
        id: 'scope-1',
        scanId: 'scoped-route-scan',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/orders'],
        selectedEndpoints: [{ method: 'GET', path: '/api/orders', source: 'manual' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: ['Do not widen to admin routes'],
        boundaryHints: ['Stay inside order APIs'],
        explorationBudget: null,
    });

    const seededCase: import('../src/services/runtime/ScopedScanTypes').FocusedTestCase = {
        id: 'case-seeded',
        scanId: 'scoped-route-scan',
        objectiveId: 'objective-1',
        title: 'Authorization boundary on GET /api/orders',
        hypothesis: 'Order listings may over-expose records.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders' },
        preconditions: ['Reuse the persisted auth context when available.'],
        steps: [{ order: 1, action: 'Replay the in-scope order listing request.' }],
        assertions: [{ kind: 'authz_enforced', description: 'Only authorized order records are returned.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture any cross-tenant order leak.' }],
        priority: 'high',
        plannerRationaleSummary: 'Order listings are commonly authz-sensitive.',
        caseFamily: 'access_control',
        caseIntelligence: {
            selectionSummary: 'Order listings remain plausible authz targets inside the approved scoped anchors.',
            anchorSummary: 'Stay on the approved /api/orders route only.',
            candidateInputs: [{
                name: 'orderId',
                location: 'query',
                reason: 'Observed order identifiers in the request description.',
                mutationStrategy: 'adjacent_identifier',
                observedValuePreview: '41',
            }],
            securityConcerns: [{
                family: 'access_control',
                title: 'Adjacent order access',
                whyRelevant: 'Order listings can over-expose cross-tenant records if authorization checks drift.',
                strengtheningSignals: ['Foreign order data appears on the same listing route.'],
                weakeningSignals: ['Order listing remains tenant-bound under the same contrast.'],
                boundedChecks: ['Change only one observed order-style identifier at a time.'],
            }],
            followUpPolicy: {
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['alternate_id_compare'],
                queueThresholdScore: 40,
                strongSignalMarkers: ['authz_bypass'],
                boundedBy: ['Persisted anchors only'],
                stopConditions: ['No adjacent identifier remains'],
            },
        },
        maxAdaptiveFollowUps: 2,
        preferredRail: 'request',
        allowedConfirmationKinds: ['alternate_id_compare'],
        status: 'planned',
        reviewState: 'pending_review',
    };

    dbModule.createFocusedTestCase(seededCase);
    dbModule.updateScanStatus('scoped-route-scan', 'awaiting_review');

    const detailResponse = await request(app)
        .get('/api/scans/scoped-route-scan')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(detailResponse.status, 200);
    assert.equal((detailResponse.body as any).focusedTestCases.length, 1);
    assert.equal((detailResponse.body as any).focusedPlanSummary.totalCases, 1);
    assert.ok((detailResponse.body as any).focusedStorySummary);
    assert.equal((detailResponse.body as any).focusedTestCases[0].caseIntelligence.selectionSummary.includes('scoped anchors'), true);
    assert.equal((detailResponse.body as any).liveRuntimeSummary.objectiveTitle, 'Orders scoped review');
    assert.equal((detailResponse.body as any).scopedLiveRuntime.objectiveTitle, 'Orders scoped review');

    const getResponse = await request(app)
        .get('/api/scans/scoped-route-scan/focused-test-cases')
        .set('Authorization', `Bearer ${token}`);
    const liveResponse = await request(app)
        .get('/api/scans/scoped-route-scan/live')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(getResponse.status, 200);
    assert.equal((getResponse.body as any).focusedTestCases.length, 1);
    assert.equal((getResponse.body as any).focusedTestCases[0].title, seededCase.title);
    assert.equal((getResponse.body as any).focusedTestCases[0].caseIntelligence.candidateInputs[0].name, 'orderId');
    assert.equal((getResponse.body as any).liveRuntimeSummary.objectiveTitle, 'Orders scoped review');
    assert.equal((getResponse.body as any).scopedLiveRuntime.objectiveTitle, 'Orders scoped review');
    assert.equal(Object.prototype.hasOwnProperty.call(liveResponse.body as any, 'liveRuntimeSummary'), true);
    assert.equal(Object.prototype.hasOwnProperty.call(liveResponse.body as any, 'scopedRuntime'), true);
    assert.equal((liveResponse.body as any).liveRuntimeSummary, null);
    assert.equal((liveResponse.body as any).scopedRuntime, null);

    const patchResponse = await request(app)
        .patch('/api/scans/scoped-route-scan/focused-test-cases/case-seeded')
        .set('Authorization', `Bearer ${token}`)
        .send({ reviewState: 'approved', priority: 'medium', status: 'disabled' });

    assert.equal(patchResponse.status, 200);
    assert.equal((patchResponse.body as any).focusedTestCase.reviewState, 'approved');
    assert.equal((patchResponse.body as any).focusedTestCase.priority, 'medium');
    assert.equal((patchResponse.body as any).focusedTestCase.status, 'disabled');

    const originalPlanNow = focusedPlanningService.planNow;
    const regeneratedCase: import('../src/services/runtime/ScopedScanTypes').FocusedTestCase = {
        ...seededCase,
        id: 'case-regenerated',
        title: 'Input handling on GET /api/orders',
        priority: 'medium',
        plannerRationaleSummary: 'Regenerated case for plan refresh.',
    };

    focusedPlanningService.planNow = (async (scanId: string) => {
        dbModule.replaceFocusedTestCasesByScan(scanId, [regeneratedCase]);
        dbModule.updateScanStatus(scanId, 'awaiting_review');
        return {
            scanId,
            focusedTestCases: [regeneratedCase],
            focusedPlanSummary: buildFocusedPlanSummary([regeneratedCase]),
        };
    }) as any;

    try {
        const postResponse = await request(app)
            .post('/api/scans/scoped-route-scan/plan-focused-tests')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(postResponse.status, 200);
        assert.equal((postResponse.body as any).status, 'awaiting_review');
        assert.equal((postResponse.body as any).focusedTestCases.length, 1);
        assert.equal((postResponse.body as any).focusedTestCases[0].id, 'case-regenerated');
        assert.ok((postResponse.body as any).focusedStorySummary);
    } finally {
        focusedPlanningService.planNow = originalPlanNow;
    }
});

test('focused execution routes launch approved runs and expose persisted evidence bundles', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);

    dbModule.createScan({
        id: 'scoped-execution-route-scan',
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });

    dbModule.createFocusedTestObjective({
        id: 'objective-execution-route',
        scanId: 'scoped-execution-route-scan',
        title: 'Execution route objective',
        scopeType: 'endpoint_scoped',
        goal: 'Execute approved scoped cases.',
        riskTags: ['idor'],
    });

    dbModule.createScopeEnvelope({
        id: 'scope-execution-route',
        scanId: 'scoped-execution-route-scan',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/orders/:id'],
        selectedEndpoints: [{ method: 'GET', path: '/api/orders/:id', host: 'app.example.com' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: [],
        explorationBudget: { maxRequests: 3, maxRouteVariants: 1 },
    });
    dbModule.createScopedTestRequest({
        id: 'request-execution-route',
        scanId: 'scoped-execution-route-scan',
        targetUrl: 'https://app.example.com/api/orders/1',
        description: 'Validate access control around the seeded order detail request.',
        environment: 'staging',
        serviceName: 'orders',
        testData: ['order id 1'],
        testUsers: ['primary-user'],
        loginPresent: true,
        authMechanismHints: ['session cookie'],
        hasScreenshotOrAttachment: true,
        attachmentMetadata: [{ label: 'orders-flow.png', kind: 'screenshot' }],
        attachmentSummary: 'Operator supplied annotated order screenshot.',
        newScreenCount: 1,
        newInputCount: 2,
        operatorNotes: 'Use the seeded account context only.',
    });

    dbModule.createFocusedTestCase({
        id: 'case-execution-route',
        scanId: 'scoped-execution-route-scan',
        objectiveId: 'objective-execution-route',
        title: 'Approved case',
        hypothesis: 'Stay inside the endpoint.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' },
        preconditions: ['Reuse scoped auth context.'],
        steps: [{ order: 1, action: 'Replay the request.' }],
        assertions: [{ kind: 'authz', description: 'Unauthorized access is denied.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture response diff.' }],
        priority: 'high',
        plannerRationaleSummary: 'Execution should be inspectable.',
        status: 'planned',
        reviewState: 'approved',
    });

    dbModule.createFocusedTestCaseExecution({
        id: 'exec-execution-route',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        objectiveId: 'objective-execution-route',
        executionState: 'completed',
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: 'Completed with persisted evidence.',
        requestActionsUsed: 2,
        startedAt: '2026-04-18T10:00:00.000Z',
        completedAt: '2026-04-18T10:01:00.000Z',
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-execution-request',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        summary: 'Captured the bounded baseline request.',
        source: 'baseline_replay',
        capturedAt: '2026-04-18T10:00:10.000Z',
        requestRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            path: '/api/orders/1',
            host: 'app.example.com',
            raw: 'GET /api/orders/1 HTTP/1.1',
        },
        responseRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            path: '/api/orders/1',
            host: 'app.example.com',
            statusCode: 200,
            raw: 'HTTP/1.1 200 OK',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'baseline_replay',
            source: 'system',
        },
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-execution-route',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        summary: 'Captured a response diff.',
        source: 'comparison',
        capturedAt: '2026-04-18T10:00:30.000Z',
        responseDiffSummary: {
            summary: 'Status: 200 → 403',
            significant: true,
            originalStatus: 200,
            mutatedStatus: 403,
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'compare_responses',
            source: 'system',
        },
    });
    dbModule.createFocusedExecutionTraceEntry({
        id: 'trace-execution-start',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        timestamp: '2026-04-18T10:00:00.000Z',
        actionType: 'execution_started',
        actionSummary: 'Focused execution started.',
        targetSummary: 'GET /api/orders/:id',
        reasoningNote: 'Execution remains bounded to the approved request anchor.',
        nextStepRationale: 'Replay the baseline request before mutating.',
        rail: 'system',
        toolSummary: 'Execution profile generic:test',
        linkedEvidenceIds: [],
    });
    dbModule.createFocusedExecutionTraceEntry({
        id: 'trace-execution-request',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        timestamp: '2026-04-18T10:00:10.000Z',
        actionType: 'request_dispatch',
        actionSummary: 'Sent the bounded request replay.',
        targetSummary: 'https://app.example.com/api/orders/1',
        requestSummary: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            path: '/api/orders/1',
            host: 'app.example.com',
        },
        reasoningNote: 'Verify the baseline response before comparing mutations.',
        rail: 'request',
        toolSummary: 'Burp/MCP request rail',
        linkedEvidenceIds: ['evidence-execution-request'],
    });
    dbModule.createFocusedExecutionTraceEntry({
        id: 'trace-execution-compare',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        timestamp: '2026-04-18T10:00:30.000Z',
        actionType: 'response_compared',
        actionSummary: 'Compared the bounded baseline and mutated responses.',
        responseSummary: {
            statusCode: 403,
            structureChanged: false,
            bodyLengthDelta: 42,
        },
        reasoningNote: 'The bounded mutation was rejected while the baseline request succeeded.',
        nextStepRationale: 'Use the comparison evidence for verdicting.',
        rail: 'request',
        toolSummary: 'Burp/MCP request rail',
        linkedEvidenceIds: ['evidence-execution-route'],
    });
    dbModule.createFocusedReasoningTraceEntry({
        id: 'reasoning-execution-intake',
        scanId: 'scoped-execution-route-scan',
        objectiveId: 'objective-execution-route',
        timestamp: '2026-04-18T09:59:50.000Z',
        stage: 'request_intake',
        entryType: 'context',
        rail: 'system_only',
        summary: 'Structured request metadata was persisted for bounded scoped execution.',
        observationSummary: 'Operator supplied seeded request context, notes, and screenshot metadata.',
        linkedEvidenceIds: [],
        linkedRequestContextKeys: ['testData', 'operatorNotes', 'attachmentSummary'],
        contextInfluence: [{
            field: 'testData',
            effect: 'used',
            summary: 'Seeded order identifiers anchored bounded request selection.',
        }, {
            field: 'operatorNotes',
            effect: 'used',
            summary: 'Operator notes constrained the run to the seeded account context.',
        }],
    });
    dbModule.createFocusedReasoningTraceEntry({
        id: 'reasoning-execution-plan',
        scanId: 'scoped-execution-route-scan',
        objectiveId: 'objective-execution-route',
        caseId: 'case-execution-route',
        timestamp: '2026-04-18T09:59:55.000Z',
        stage: 'planning',
        entryType: 'hypothesis',
        rail: 'request',
        caseFamily: 'access_control',
        summary: 'The case remains plausible because the selected order detail endpoint is authz-sensitive.',
        observationSummary: 'The bounded request targets /api/orders/:id inside the approved scope envelope.',
        hypothesisRationaleSummary: 'A seeded order lookup can expose cross-tenant reads if authorization checks drift.',
        linkedEvidenceIds: [],
        linkedRequestContextKeys: ['testData'],
        contextInfluence: [{
            field: 'testData',
            effect: 'used',
            summary: 'The provided order id focused the case on a single approved object lookup.',
        }],
    });
    dbModule.createFocusedReasoningTraceEntry({
        id: 'reasoning-execution-run',
        scanId: 'scoped-execution-route-scan',
        objectiveId: 'objective-execution-route',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        timestamp: '2026-04-18T10:00:30.000Z',
        stage: 'execution',
        entryType: 'observation',
        rail: 'request',
        caseFamily: 'access_control',
        summary: 'The bounded mutation changed the status from 200 to 403.',
        observationSummary: 'The baseline request succeeded, but the mutated comparison response was rejected.',
        actionSelectionRationale: 'Use the bounded comparison to decide whether the access-control hypothesis strengthened.',
        requestResponseImpactSummary: 'GET /api/orders/1 => HTTP 403 | body delta 42',
        confidenceShiftSummary: 'This strengthened confidence that the control held for the seeded order lookup.',
        linkedEvidenceIds: ['evidence-execution-route'],
        linkedRequestContextKeys: ['testData'],
        contextInfluence: [],
    });
    dbModule.createFocusedReasoningTraceEntry({
        id: 'reasoning-execution-verdict',
        scanId: 'scoped-execution-route-scan',
        objectiveId: 'objective-execution-route',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        timestamp: '2026-04-18T10:01:00.000Z',
        stage: 'verdict',
        entryType: 'result',
        rail: 'system_only',
        caseFamily: 'access_control',
        summary: 'The bounded case passed because the mutated request stayed denied.',
        observationSummary: 'Required response-diff evidence was sufficient and stayed anchored to the intended request.',
        confidenceShiftSummary: 'Confidence increased because the deny signal held under the bounded mutation.',
        linkedEvidenceIds: ['evidence-execution-route'],
        linkedRequestContextKeys: [],
        contextInfluence: [],
    });
    dbModule.upsertFocusedFindingThread({
        id: 'thread-execution-route',
        scanId: 'scoped-execution-route-scan',
        caseId: 'case-execution-route',
        executionId: 'exec-execution-route',
        objectiveId: 'objective-execution-route',
        findingKey: 'family:access_control:runtime',
        title: 'Potential Access Control Bypass on order detail',
        family: 'access_control',
        status: 'strengthening',
        suspicionScore: 39,
        confirmationProgress: 58,
        confidenceBand: 'medium',
        isPrimary: true,
        strongestSupportSummary: 'The baseline request succeeded while the mutation stayed rejected.',
        strongestSuspiciousSignal: 'The request remained bounded and inspectable.',
        strongestBlockerSummary: 'One more bounded contrast would be needed for stronger confirmation.',
        nextStepSummary: 'Retry one bounded confirmation variation against the same target.',
        stopReason: null,
        supportingSignals: ['The baseline request succeeded while the mutation stayed rejected.'],
        blockingConstraints: ['One more bounded contrast would be needed for stronger confirmation.'],
        supportingEvidenceRefs: [{
            evidenceId: 'evidence-execution-route',
            source: 'comparison',
            role: 'comparison',
            summary: 'Captured a response diff.',
            capturedAt: '2026-04-18T10:00:30.000Z',
        }],
        blockingEvidenceRefs: [],
        supportProvenance: {
            rail: 'request',
            requestHeavy: true,
            requestBackedEvidence: true,
            browserBackedEvidence: false,
            requestEvidenceIds: ['evidence-execution-request', 'evidence-execution-route'],
            browserEvidenceIds: [],
            systemEvidenceIds: [],
            summary: 'Request-backed support: Burp-visible request evidence is anchoring the current conclusion.',
            lowConfidenceReason: null,
        },
        requestEvidenceStory: {
            requestHeavy: true,
            hasRequestBackedEvidence: true,
            baselineRequestRef: {
                evidenceId: 'evidence-execution-request',
                source: 'baseline_replay',
                summary: 'Captured the bounded baseline request.',
                capturedAt: '2026-04-18T10:00:10.000Z',
                method: 'GET',
                url: 'https://app.example.com/api/orders/1',
                path: '/api/orders/1',
                host: 'app.example.com',
                statusCode: 200,
            },
            strongestSuspiciousRequestRef: {
                evidenceId: 'evidence-execution-request',
                source: 'baseline_replay',
                summary: 'Captured the bounded baseline request.',
                capturedAt: '2026-04-18T10:00:10.000Z',
                method: 'GET',
                url: 'https://app.example.com/api/orders/1',
                path: '/api/orders/1',
                host: 'app.example.com',
                statusCode: 200,
            },
            supportingRequestRefs: [{
                evidenceId: 'evidence-execution-request',
                source: 'baseline_replay',
                summary: 'Captured the bounded baseline request.',
                capturedAt: '2026-04-18T10:00:10.000Z',
                method: 'GET',
                url: 'https://app.example.com/api/orders/1',
                path: '/api/orders/1',
                host: 'app.example.com',
                statusCode: 200,
            }],
            contradictingRequestRefs: [],
            confirmationRequestRefs: [],
            summary: 'Request-backed suspicious signal observed.',
            lowConfidenceReason: null,
        },
        linkedTraceIds: ['trace-execution-start', 'trace-execution-request', 'trace-execution-compare'],
        linkedVerdictIds: [],
        linkedInvestigationIds: [],
        confirmationState: {
            maxAdaptiveFollowUps: 1,
            usedAdaptiveFollowUps: 0,
            preferredRail: 'request',
            allowedConfirmationKinds: ['alternate_id_compare'],
            recommendedConfirmationKinds: ['alternate_id_compare'],
            nextKind: 'alternate_id_compare',
            nextStepSummary: 'Retry one bounded confirmation variation against the same target.',
            readyForAdaptiveConfirmation: true,
            exhausted: false,
            stopReason: null,
            steps: [],
        },
        publishedFindingId: null,
        createdAt: '2026-04-18T10:00:35.000Z',
        updatedAt: '2026-04-18T10:00:35.000Z',
    });

    const originalLaunchExecution = focusedExecutionRunner.launchExecution;
    const launches: any[] = [];
    focusedExecutionRunner.launchExecution = ((scanId: string, caseIds?: string[]) => {
        launches.push({ scanId, caseIds: caseIds || null });
    }) as any;

    try {
        const executeResponse = await request(app)
            .post('/api/scans/scoped-execution-route-scan/execute-focused-tests')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(executeResponse.status, 202);
        assert.equal(launches.length, 1);
        assert.equal(launches[0].scanId, 'scoped-execution-route-scan');

        const listResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan/focused-test-cases')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(listResponse.status, 200);
        assert.equal((listResponse.body as any).focusedTestCases[0].executionState, 'completed');
        assert.equal((listResponse.body as any).focusedTestCases[0].executionPresentationState, 'completed_with_evidence');
        assert.equal((listResponse.body as any).focusedTestCases[0].evidenceCount, 2);
        assert.equal((listResponse.body as any).focusedTestCases[0].executionRailSummary.rail, 'request');
        assert.equal((listResponse.body as any).focusedTestCases[0].latestExecutionTracePreview[0].actionType, 'execution_started');
        assert.equal((listResponse.body as any).focusedTestCases[0].hypothesisVisibility.currentStatus, 'strengthened');
        assert.equal((listResponse.body as any).focusedTestCases[0].suspicionExplanation.proofStatus, 'weak');
        assert.equal((listResponse.body as any).focusedFindingThreads.length, 1);
        assert.equal((listResponse.body as any).focusedTestCases[0].activeFindingThread.id, 'thread-execution-route');
        assert.equal((listResponse.body as any).focusedTestCases[0].activeFindingThread.supportProvenance.rail, 'request');
        assert.equal((listResponse.body as any).focusedTestCases[0].activeFindingThread.requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((listResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'comparison_unavailable');

        const generateVerdictsResponse = await request(app)
            .post('/api/scans/scoped-execution-route-scan/generate-focused-verdicts')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(generateVerdictsResponse.status, 200);
        assert.equal((generateVerdictsResponse.body as any).caseVerdicts.length, 1);
        assert.equal((generateVerdictsResponse.body as any).caseVerdicts[0].verdictState, 'pass');
        assert.equal((generateVerdictsResponse.body as any).caseVerdicts[0].supportProvenance.rail, 'request');
        assert.equal((generateVerdictsResponse.body as any).caseVerdicts[0].requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((generateVerdictsResponse.body as any).focusedFindings.length, 1);
        assert.equal((generateVerdictsResponse.body as any).focusedFindings[0].supportProvenance.rail, 'request');
        assert.equal((generateVerdictsResponse.body as any).focusedFindings[0].requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((generateVerdictsResponse.body as any).focusedFindingThreads.length, 1);
        assert.equal((generateVerdictsResponse.body as any).focusedFindingThreads[0].supportProvenance.rail, 'request');
        assert.equal((generateVerdictsResponse.body as any).focusedFindingSummary.primaryFindings, 1);
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].primaryFinding.status, 'inconclusive');
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].activeFindingThread.status, 'published');
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].latestVerdict.supportProvenance.rail, 'request');
        assert.equal((generateVerdictsResponse.body as any).focusedVerdictSummary.overallVerdict, 'pass');
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].latestVerdict.verdictState, 'pass');
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].suspicionExplanation.proofStatus, 'supported');
        assert.equal((generateVerdictsResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'baseline_created');
        assert.equal((generateVerdictsResponse.body as any).focusedHistoricalCompareSummary.overallChangeClassification, 'baseline_only');
        assert.equal((generateVerdictsResponse.body as any).focusedTestCases[0].historicalCompare.compareStatus, 'baseline_only');

        const focusedVerdictsResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan/focused-verdicts')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(focusedVerdictsResponse.status, 200);
        assert.equal((focusedVerdictsResponse.body as any).caseVerdicts.length, 1);
        assert.equal((focusedVerdictsResponse.body as any).caseVerdicts[0].verdictState, 'pass');
        assert.equal((focusedVerdictsResponse.body as any).caseVerdicts[0].requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((focusedVerdictsResponse.body as any).focusedVerdictSummary.countsByVerdict.pass, 1);
        assert.equal((focusedVerdictsResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'baseline_created');

        const focusedCompareResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan/focused-compare')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(focusedCompareResponse.status, 200);
        assert.equal((focusedCompareResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'baseline_created');
        assert.equal((focusedCompareResponse.body as any).focusedHistoricalCompareSummary.overallChangeClassification, 'baseline_only');

        const caseCompareResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan/focused-test-cases/case-execution-route/compare')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(caseCompareResponse.status, 200);
        assert.equal((caseCompareResponse.body as any).historicalCompare.compareStatus, 'baseline_only');

        const detailResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(detailResponse.status, 200);
        assert.equal((detailResponse.body as any).focusedFindings.length, 1);
        assert.equal((detailResponse.body as any).focusedFindingThreads.length, 1);
        assert.equal((detailResponse.body as any).focusedFindingSummary.primaryFindings, 1);
        assert.equal((detailResponse.body as any).focusedVerdictSummary.overallVerdict, 'pass');
        assert.equal((detailResponse.body as any).focusedTestCases[0].latestVerdict.verdictState, 'pass');
        assert.equal((detailResponse.body as any).focusedTestCases[0].latestVerdict.supportProvenance.rail, 'request');
        assert.equal((detailResponse.body as any).focusedTestCases[0].primaryFinding.requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((detailResponse.body as any).focusedTestCases[0].primaryFinding.title.includes('Potential'), true);
        assert.equal((detailResponse.body as any).focusedTestCases[0].executionRailSummary.rail, 'request');
        assert.equal((detailResponse.body as any).focusedAgentTrace.length >= 4, true);
        assert.equal((detailResponse.body as any).focusedRequestContextUsage.usedFields.length >= 2, true);
        assert.equal((detailResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'baseline_created');
        assert.equal((detailResponse.body as any).focusedHistoricalCompareSummary.overallChangeClassification, 'baseline_only');

        const evidenceResponse = await request(app)
            .get('/api/scans/scoped-execution-route-scan/focused-test-cases/case-execution-route/evidence')
            .set('Authorization', `Bearer ${token}`);

        assert.equal(evidenceResponse.status, 200);
        assert.equal((evidenceResponse.body as any).execution.id, 'exec-execution-route');
        assert.equal((evidenceResponse.body as any).caseVerdict.verdictState, 'pass');
        assert.equal((evidenceResponse.body as any).caseVerdict.supportProvenance.rail, 'request');
        assert.equal((evidenceResponse.body as any).findings.length >= 1, true);
        assert.equal((evidenceResponse.body as any).findingThreads.length, 1);
        assert.equal(
            (evidenceResponse.body as any).findings.filter((finding: any) => finding.isPrimary).length,
            1,
        );
        assert.equal((evidenceResponse.body as any).primaryFinding.isPrimary, true);
        assert.equal((evidenceResponse.body as any).primaryFinding.requestEvidenceStory.hasRequestBackedEvidence, true);
        assert.equal((evidenceResponse.body as any).primaryFindingThread.status, 'published');
        assert.equal((evidenceResponse.body as any).primaryFindingThread.supportProvenance.rail, 'request');
        assert.equal((evidenceResponse.body as any).focusedTestCase.latestVerdict.verdictState, 'pass');
        assert.equal((evidenceResponse.body as any).focusedTestCase.primaryFinding.title.includes('Potential'), true);
        assert.equal((evidenceResponse.body as any).focusedTestCase.activeFindingThread.status, 'published');
        assert.equal((evidenceResponse.body as any).focusedTestCase.historicalCompare.compareStatus, 'baseline_only');
        assert.equal((evidenceResponse.body as any).focusedVerdictSummary.overallVerdict, 'pass');
        assert.equal((evidenceResponse.body as any).focusedHistoricalCompareState.comparisonStatus, 'baseline_created');
        assert.equal((evidenceResponse.body as any).evidenceBundles.length, 2);
        assert.equal((evidenceResponse.body as any).evidenceBundles[1].source, 'comparison');
        assert.equal((evidenceResponse.body as any).executionTrace.length, 3);
        assert.equal((evidenceResponse.body as any).reasoningTrace.length >= 3, true);
        assert.equal((evidenceResponse.body as any).hypothesisVisibility.currentStatus, 'strengthened');
        assert.equal((evidenceResponse.body as any).suspicionExplanation.proofStatus, 'supported');
        assert.equal((evidenceResponse.body as any).contextInfluenceSummary.usedFields.length >= 1, true);
        assert.equal((evidenceResponse.body as any).evidenceReasoningLinks.length >= 1, true);
        assert.equal((evidenceResponse.body as any).executionTrace[1].actionType, 'request_dispatch');
        assert.equal((evidenceResponse.body as any).railSummary.rail, 'request');
        assert.equal((evidenceResponse.body as any).focusedTestCase.executionPresentationState, 'completed_with_evidence');
        assert.equal((evidenceResponse.body as any).focusedTestCase.historicalCompare.compareStatus, 'baseline_only');
    } finally {
        focusedExecutionRunner.launchExecution = originalLaunchExecution;
    }
});

test('focused investigation routes expose persisted issue history and blocker summaries in scan and evidence responses', async () => {
    await resetDb();

    const app = createApp();
    const token = generateToken(1);

    dbModule.createScan({
        id: 'scoped-investigation-route-scan',
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });

    dbModule.createFocusedTestObjective({
        id: 'objective-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        title: 'Investigation route objective',
        scopeType: 'flow_scoped',
        goal: 'Expose scoped troubleshooting data to operators.',
        riskTags: ['authz'],
    });

    dbModule.createScopeEnvelope({
        id: 'scope-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/checkout'],
        selectedEndpoints: [],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: ['Do not widen outside the checkout flow.'],
        boundaryHints: ['Stay inside the checkout route.'],
        explorationBudget: { maxBrowserActions: 3, maxNavigationDepth: 1, maxVerificationRetries: 1 },
    });

    dbModule.createFocusedTestCase({
        id: 'case-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        objectiveId: 'objective-investigation-route',
        title: 'Checkout flow anchor case',
        hypothesis: 'The checkout flow should remain inspectable in bounded mode.',
        targetArtifact: { kind: 'flow', label: 'Checkout flow', url: 'https://app.example.com/checkout' },
        preconditions: ['Remain inside the persisted checkout boundary.'],
        steps: [{ order: 1, action: 'Attempt the bounded checkout verification flow.' }],
        assertions: [{ kind: 'flow', description: 'The flow should stay bounded and evidence-backed.' }],
        requiredEvidence: [{ kind: 'rendered_output', description: 'Capture a rendered checkout confirmation.' }],
        priority: 'medium',
        plannerRationaleSummary: 'Operators should be able to inspect troubleshooting data from Mission Control.',
        status: 'planned',
        reviewState: 'approved',
    });

    dbModule.createFocusedTestCaseExecution({
        id: 'exec-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        caseId: 'case-investigation-route',
        objectiveId: 'objective-investigation-route',
        executionState: 'blocked',
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: 'Blocked because no concrete browser anchor could be resolved.',
        startedAt: '2026-04-18T10:00:00.000Z',
        completedAt: '2026-04-18T10:00:20.000Z',
    });

    dbModule.createEvidenceBundle({
        id: 'evidence-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        caseId: 'case-investigation-route',
        executionId: 'exec-investigation-route',
        summary: 'Execution was blocked before proof could be collected.',
        source: 'execution_note',
        capturedAt: '2026-04-18T10:00:05.000Z',
        executionNotes: 'No concrete anchor existed for the checkout flow.',
        provenance: {
            profileKey: 'generic:test',
            actionType: 'browser_sequence',
            source: 'system',
        },
    });
    dbModule.createFocusedExecutionTraceEntry({
        id: 'trace-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        caseId: 'case-investigation-route',
        executionId: 'exec-investigation-route',
        timestamp: '2026-04-18T10:00:02.000Z',
        actionType: 'blocked',
        actionSummary: 'Execution blocked because no approved browser anchor was available.',
        targetSummary: 'Checkout flow',
        reasoningNote: 'No safe bounded next step was available.',
        stopReason: 'Missing approved anchor.',
        rail: 'system',
        toolSummary: 'System-owned preflight gate',
        linkedEvidenceIds: ['evidence-investigation-route'],
    });

    dbModule.createFocusedInvestigationIssue({
        id: 'issue-investigation-route',
        scanId: 'scoped-investigation-route-scan',
        caseId: 'case-investigation-route',
        executionId: 'exec-investigation-route',
        objectiveId: 'objective-investigation-route',
        issueType: 'blocked_flow',
        issueTitle: 'Focused checkout verification could not start without a concrete anchor.',
        issueDetails: 'The scoped case targeted a flow artifact, but no approved request or browser anchor was available for bounded execution.',
        issueStatus: 'unresolved',
        impact: 'blocking',
        source: 'system',
        correlation: {
            executionState: 'blocked',
            evidenceSources: ['note'],
        },
        linkedEvidenceIds: ['evidence-investigation-route'],
        linkedVerdictIds: [],
        workaroundAttempts: [{
            attemptedAt: '2026-04-18T10:00:10.000Z',
            summary: 'Attempted bounded browser fallback after request anchoring was unavailable.',
            outcome: 'no_change',
            details: 'The flow still lacked a concrete approved anchor.',
        }],
        expertFollowupHint: 'Confirm that the selected checkout flow is paired with an approved browser or request anchor before rerunning.',
        assistanceSummary: 'Execution stayed blocked because the scoped flow could not be grounded to a concrete approved anchor.',
        assistanceProfileKey: 'generic:test',
        assistanceProvider: null,
        assistanceModel: null,
        detectedAt: '2026-04-18T10:00:05.000Z',
        resolvedAt: null,
        createdAt: '2026-04-18T10:00:05.000Z',
        updatedAt: '2026-04-18T10:00:10.000Z',
    });

    dbModule.upsertFocusedScanBlockerSummary({
        scanId: 'scoped-investigation-route-scan',
        objectiveId: 'objective-investigation-route',
        countsByStatus: {
            open: 0,
            resolved: 0,
            partially_resolved: 0,
            unresolved: 1,
            not_applicable: 0,
        },
        countsByImpact: {
            informational: 0,
            degrading: 0,
            blocking: 1,
        },
        unresolvedByType: {
            scope_violation: 0,
            auth_session_drift: 0,
            missing_anchor: 0,
            browser_state_mismatch: 0,
            evidence_insufficient: 0,
            execution_budget_exhausted: 0,
            request_replay_mismatch: 0,
            unexpected_navigation: 0,
            unsupported_verification_primitive: 0,
            environment_instability: 0,
            contradictory_signals: 0,
            retry_failure: 0,
            blocked_flow: 1,
        },
        repeatedBlockers: [],
        casesNeedingReview: ['case-investigation-route'],
        latestMajorBlockerSummary: 'Checkout flow verification is blocked until the scoped case is grounded to a concrete approved anchor.',
        createdAt: '2026-04-18T10:00:05.000Z',
        updatedAt: '2026-04-18T10:00:10.000Z',
    });

    const detailResponse = await request(app)
        .get('/api/scans/scoped-investigation-route-scan')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(detailResponse.status, 200);
    assert.equal((detailResponse.body as any).focusedBlockerSummary.unresolvedByType.blocked_flow, 1);
    assert.equal((detailResponse.body as any).focusedTestCases[0].investigationSummary.unresolvedCount, 1);

    const evidenceResponse = await request(app)
        .get('/api/scans/scoped-investigation-route-scan/focused-test-cases/case-investigation-route/evidence')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(evidenceResponse.status, 200);
    assert.equal((evidenceResponse.body as any).investigationIssues.length, 1);
    assert.equal((evidenceResponse.body as any).investigationIssues[0].workaroundAttempts[0].outcome, 'no_change');
    assert.equal((evidenceResponse.body as any).executionTrace[0].actionType, 'blocked');
    assert.equal((evidenceResponse.body as any).railSummary.rail, 'system');
    assert.equal((evidenceResponse.body as any).focusedBlockerSummary.casesNeedingReview[0], 'case-investigation-route');

    const scanIssuesResponse = await request(app)
        .get('/api/scans/scoped-investigation-route-scan/focused-investigations')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(scanIssuesResponse.status, 200);
    assert.equal((scanIssuesResponse.body as any).investigationIssues[0].issueType, 'blocked_flow');

    const caseIssuesResponse = await request(app)
        .get('/api/scans/scoped-investigation-route-scan/focused-test-cases/case-investigation-route/investigations')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(caseIssuesResponse.status, 200);
    assert.equal((caseIssuesResponse.body as any).investigationSummary.latestIssueTitle, 'Focused checkout verification could not start without a concrete anchor.');
    assert.equal((caseIssuesResponse.body as any).investigationSummary.blockingCount, 1);

    const blockersResponse = await request(app)
        .get('/api/scans/scoped-investigation-route-scan/focused-blockers')
        .set('Authorization', `Bearer ${token}`);

    assert.equal(blockersResponse.status, 200);
    assert.equal((blockersResponse.body as any).focusedBlockerSummary.latestMajorBlockerSummary, 'Checkout flow verification is blocked until the scoped case is grounded to a concrete approved anchor.');
});
