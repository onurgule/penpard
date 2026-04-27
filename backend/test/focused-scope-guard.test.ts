import test from 'node:test';
import assert from 'node:assert/strict';

import { FocusedScopeGuard } from '../src/services/runtime/FocusedScopeGuard';
import type { FocusedTestCase, ScopeEnvelope } from '../src/services/runtime/ScopedScanTypes';

const guard = new FocusedScopeGuard();

const scopedCase: FocusedTestCase = {
    id: 'case-1',
    scanId: 'scan-1',
    objectiveId: 'objective-1',
    title: 'GET /api/orders/:id',
    hypothesis: 'Authorization should remain bounded.',
    targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' },
    preconditions: [],
    steps: [{ order: 1, action: 'Replay the bounded request.' }],
    assertions: [{ kind: 'authz', description: 'Unauthorized access is denied.' }],
    requiredEvidence: [{ kind: 'response_diff', description: 'Capture response diff.' }],
    priority: 'high',
    plannerRationaleSummary: 'Keep the test anchored to the selected endpoint.',
    status: 'planned',
    reviewState: 'approved',
};

const envelope: ScopeEnvelope = {
    id: 'scope-1',
    scanId: 'scan-1',
    version: 1,
    allowedHosts: ['app.example.com'],
    allowedRoutes: ['/api/orders/:id'],
    selectedEndpoints: [{ method: 'GET', path: '/api/orders/:id', host: 'app.example.com' }],
    baselineRequestRefs: [{
        kind: 'scan_initial_request',
        source: 'burp_send_to_penpard',
        requestSlot: 'initial_request',
        method: 'GET',
        url: 'https://app.example.com/api/orders/1',
        host: 'app.example.com',
        path: '/api/orders/1',
    }],
    requestBundleRefs: [],
    authContext: null,
    outOfScopeNotes: [],
    boundaryHints: [],
    explorationBudget: { maxRequests: 3, maxRouteVariants: 1 },
};

test('focused scope guard blocks off-scope hosts before execution', () => {
    const decision = guard.evaluate({
        action: {
            type: 'mutated_replay',
            method: 'GET',
            url: 'https://admin.example.com/api/orders/1',
            useInitialRequestBaseline: false,
        },
        testCase: scopedCase,
        envelope,
    });

    assert.equal(decision.allowed, false);
    assert.equal(decision.violation?.violationKind, 'host');
});

test('focused scope guard blocks off-scope paths before execution', () => {
    const decision = guard.evaluate({
        action: {
            type: 'mutated_replay',
            method: 'GET',
            url: 'https://app.example.com/api/admin/export',
            useInitialRequestBaseline: false,
        },
        testCase: scopedCase,
        envelope,
    });

    assert.equal(decision.allowed, false);
    assert.equal(decision.violation?.violationKind, 'route');
});

test('focused scope guard blocks baseline-request cases that skip the persisted baseline anchor', () => {
    const baselineCase: FocusedTestCase = {
        ...scopedCase,
        id: 'case-2',
        targetArtifact: { kind: 'baseline_request', method: 'GET', path: '/api/orders/1' },
    };

    const decision = guard.evaluate({
        action: {
            type: 'baseline_replay',
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            useInitialRequestBaseline: false,
        },
        testCase: baselineCase,
        envelope,
    });

    assert.equal(decision.allowed, false);
    assert.equal(decision.violation?.violationKind, 'baseline_anchor');
});
