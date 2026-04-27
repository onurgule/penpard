import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-test-planner-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const { FocusedTestPlanner } = require('../src/services/runtime/FocusedTestPlanner') as typeof import('../src/services/runtime/FocusedTestPlanner');

function buildContextPack(): import('../src/services/runtime/ScopedScanTypes').ContextPack {
    return {
        scanId: 'scan-planner-1',
        objective: {
            id: 'objective-planner-1',
            title: 'Order update review',
            scopeType: 'request_scoped',
            goal: 'Keep the planner bounded to the order update request family.',
            operatorNotes: 'Compact plan only.',
            riskTags: ['idor', 'authz', 'validation'],
        },
        scope: {
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders/1'],
            selectedEndpoints: [],
            baselineRequestRefs: [{
                kind: 'scan_initial_request',
                source: 'burp_send_to_penpard',
                requestSlot: 'initial_request',
                method: 'POST',
                host: 'app.example.com',
                path: '/api/orders/1',
            }],
            requestBundleRefs: [],
            boundaryHints: ['Only the captured order update request'],
            outOfScopeNotes: ['Do not widen to exports'],
            explorationBudget: null,
        },
        authSummary: {
            continuityStrategy: 'burp_baseline',
            summary: 'Baseline request and auth cookies are available.',
            authContext: {
                authStartupMode: 'no_credentials',
                providedCredentialCount: 0,
                hasSessionCookies: true,
                hasInitialRequestBaseline: true,
                continuityStrategy: 'burp_baseline',
                summary: 'Baseline request available',
            },
        },
        selectedTargets: [{
            kind: 'baseline_request',
            method: 'POST',
            path: '/api/orders/1',
            referenceKind: 'scan_initial_request',
            referenceId: 'initial_request',
            label: 'POST /api/orders/1',
        }],
        supportingContext: {
            operatorInstructions: 'Stay compact and execution ready.',
            requestBundles: [],
        },
        plannerConstraints: {
            schemaVersion: 1,
            noScopeExpansion: true,
            maxCases: 5,
        },
    };
}

test('FocusedTestPlanner produces bounded deterministic seed cases when local structured planning is unavailable', async () => {
    const planner = new FocusedTestPlanner({
        generate: async () => {
            throw new Error('generate should not be called for non-local providers');
        },
        getActiveConfig: () => ({
            provider: 'openai',
            api_key: '',
            model: 'gpt-4o',
            is_active: 1,
            is_online: 1,
            settings_json: '{}',
        }),
    });

    const result = await planner.plan(buildContextPack(), 1);

    assert.ok(result.cases.length >= 4 && result.cases.length <= 5);
    assert.ok(result.cases.every((testCase) => testCase.targetArtifact.path === '/api/orders/1'));
    assert.ok(result.cases.some((testCase) => testCase.title.includes('Authorization boundary')));
    assert.ok(result.cases.some((testCase) => testCase.title.includes('Input handling')));
    assert.equal(result.cases.every((testCase) => !!testCase.caseIntelligence?.selectionSummary), true);
    assert.equal(result.cases.every((testCase) => (testCase.caseIntelligence?.candidateInputs.length || 0) > 0), true);
    assert.equal(result.cases.every((testCase) => (testCase.allowedConfirmationKinds?.length || 0) > 0), true);
});

test('FocusedTestPlanner accepts structured Qwen-style JSON while rejecting out-of-scope cases', async () => {
    const planner = new FocusedTestPlanner({
        generate: async () => ({
            text: JSON.stringify({
                cases: [
                    {
                        title: 'Authorization boundary on POST /api/orders/1',
                        hypothesis: 'In-scope request may leak cross-tenant updates.',
                        targetArtifact: {
                            kind: 'baseline_request',
                            method: 'POST',
                            path: '/api/orders/1',
                            referenceKind: 'scan_initial_request',
                            referenceId: 'initial_request',
                            label: 'POST /api/orders/1',
                        },
                        preconditions: ['Reuse the persisted baseline request.'],
                        steps: [{ order: 1, action: 'Replay the request with an alternate tenant identifier.' }],
                        assertions: [{ kind: 'authz_enforced', description: 'Alternate tenant updates are denied.' }],
                        requiredEvidence: [{ kind: 'response_diff', description: 'Capture the authorization failure.' }],
                        priority: 'high',
                        plannerRationaleSummary: 'In-scope authz check.',
                    },
                    {
                        title: 'Out of scope admin export',
                        hypothesis: 'Admin export may be weakly protected.',
                        targetArtifact: {
                            kind: 'endpoint',
                            method: 'GET',
                            path: '/api/admin/export',
                        },
                        preconditions: ['This should be filtered.'],
                        steps: [{ order: 1, action: 'Try admin export.' }],
                        assertions: [{ kind: 'authz_enforced', description: 'Export should be denied.' }],
                        requiredEvidence: [{ kind: 'status_code', description: 'Capture denial.' }],
                        priority: 'high',
                        plannerRationaleSummary: 'Should be removed for scope expansion.',
                    },
                ],
            }),
            finishReason: 'stop',
        }),
        getActiveConfig: () => ({
            provider: 'local_llm',
            api_key: '',
            model: 'qwen-3.5',
            is_active: 1,
            is_online: 1,
            settings_json: '{}',
        }),
    });

    const result = await planner.plan(buildContextPack(), 1);

    assert.equal(result.cases.length, 1);
    assert.equal(result.cases[0]?.targetArtifact.path, '/api/orders/1');
    assert.equal(result.cases[0]?.reviewState, 'pending_review');
    assert.equal(result.cases[0]?.caseFamily, 'access_control');
    assert.equal((result.cases[0]?.caseIntelligence?.securityConcerns.length || 0) > 0, true);
});

test('FocusedTestPlanner falls back to deterministic seeds when structured local output is invalid', async () => {
    const planner = new FocusedTestPlanner({
        generate: async () => ({
            text: 'not valid json',
            finishReason: 'stop',
        }),
        getActiveConfig: () => ({
            provider: 'local_llm',
            api_key: '',
            model: 'qwen-3.5',
            is_active: 1,
            is_online: 1,
            settings_json: '{}',
        }),
    });

    const result = await planner.plan(buildContextPack(), 1);

    assert.ok(result.cases.length >= 3);
    assert.ok(result.cases.every((testCase) => testCase.targetArtifact.path === '/api/orders/1'));
    assert.equal(result.cases.every((testCase) => !!testCase.caseIntelligence?.anchorSummary), true);
});
