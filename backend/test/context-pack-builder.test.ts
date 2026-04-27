import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-context-pack-builder-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const { ContextPackBuilder } = require('../src/services/runtime/ContextPackBuilder') as typeof import('../src/services/runtime/ContextPackBuilder');
const { SourceAnalysisMode } = require('../src/services/source-analysis/SourceAnalysisMode') as typeof import('../src/services/source-analysis/SourceAnalysisMode');

test('ContextPackBuilder builds compact scoped planning context from persisted scoped data', async () => {
    const builder = new ContextPackBuilder({
        getScanById: () => ({
            id: 'scan-context-1',
            target: 'https://app.example.com',
            user_id: 1,
            source_package_path: '/tmp/source',
            source_analysis_mode: SourceAnalysisMode.FULL_SOURCE_AWARE,
        }),
        getObjectiveByScanId: () => ({
            id: 'objective-context-1',
            scanId: 'scan-context-1',
            title: 'Orders feature review',
            scopeType: 'endpoint_scoped',
            goal: 'Stay inside order detail and update flows.',
            operatorNotes: 'Prioritize authz and validation.',
            riskTags: ['idor', 'validation'],
        }),
        getEnvelopeByScanId: () => ({
            id: 'scope-context-1',
            scanId: 'scan-context-1',
            version: 1,
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders', '/api/orders/:id'],
            selectedEndpoints: [
                { method: 'GET', path: '/api/orders', source: 'manual' },
                { method: 'PATCH', path: '/api/orders/:id', source: 'manual' },
            ],
            baselineRequestRefs: [{
                kind: 'scan_initial_request',
                source: 'burp_send_to_penpard',
                requestSlot: 'initial_request',
                method: 'GET',
                host: 'app.example.com',
                path: '/api/orders/1',
            }],
            requestBundleRefs: [{ kind: 'captured_request_bundle', id: 'bundle-1', label: 'Order detail bundle' }],
            authContext: {
                authStartupMode: 'no_credentials',
                providedCredentialCount: 0,
                hasSessionCookies: true,
                hasInitialRequestBaseline: true,
                continuityStrategy: 'burp_baseline',
                summary: 'Burp baseline request available, session cookies supplied',
            },
            outOfScopeNotes: ['Do not touch admin exports'],
            boundaryHints: ['Stay within order detail and update flows'],
            explorationBudget: { maxRequests: 6, maxRouteVariants: 2, notes: 'Compact planner only' },
        }),
        getScanConfigById: () => ({
            customSystemPrompt: 'Operator wants compact review-ready cases only.',
        }),
        getScanAuthInventoryById: () => ({
            status: 'completed',
            summary: 'Login already observed through the browser bootstrap.',
            authRoutes: ['/login', '/logout', '/api/orders'],
            forms: [{}, {}],
            traffic: [{}, {}],
            ssoProviders: ['google'],
            registrationAvailable: false,
            passwordResetAvailable: true,
        } as any),
        getScanEndpointInventoryById: () => ({
            summary: 'Endpoint inventory summary',
            authRelevantCount: 2,
            observedInBurpCount: 1,
            exercisedInBrowserCount: 1,
            records: [
                {
                    endpoint: 'https://app.example.com/api/orders',
                    path: '/api/orders',
                    methods: ['GET'],
                    classification: 'profile_account',
                    likelyAuthRelevant: true,
                    observedInBurp: true,
                    exercisedInBrowser: false,
                    confidence: 0.92,
                    notes: ['In scope'],
                    evidence: ['Captured in Burp'],
                },
                {
                    endpoint: 'https://app.example.com/api/orders/1',
                    path: '/api/orders/:id',
                    methods: ['PATCH'],
                    classification: 'unknown',
                    likelyAuthRelevant: false,
                    observedInBurp: false,
                    exercisedInBrowser: true,
                    confidence: 0.77,
                    notes: ['Update route'],
                    evidence: ['Seen in browser'],
                },
                {
                    endpoint: 'https://app.example.com/api/admin/export',
                    path: '/api/admin/export',
                    methods: ['GET'],
                    classification: 'admin_only',
                    likelyAuthRelevant: true,
                    observedInBurp: true,
                    exercisedInBrowser: false,
                    confidence: 0.99,
                    notes: ['Out of scope'],
                    evidence: ['Should be filtered'],
                },
            ],
        } as any),
        getSourceAnalysisResultById: () => ({
            mode: SourceAnalysisMode.FULL_SOURCE_AWARE,
            framework: 'Next.js',
            technologyStack: ['Next.js', 'React', 'Node.js'],
            dependencies: [],
            cves: [],
            testingHints: [
                { category: 'authz', hint: 'Order IDs appear tenant-scoped in handlers.' },
                { category: 'noise', hint: 'Ignore payment exports for this bounded run.' },
            ],
            analyzedAt: new Date().toISOString(),
            applicationSummary: 'Orders portal',
            architectureSummary: 'BFF API',
            modules: [],
            functions: [],
            endpoints: [
                { method: 'GET', path: '/api/orders', handler: 'listOrders', authRequired: true, description: 'List orders', userInputs: [] },
                { method: 'PATCH', path: '/api/orders/:id', handler: 'updateOrder', authRequired: true, description: 'Update order', userInputs: ['status'] },
                { method: 'GET', path: '/api/admin/export', handler: 'exportOrders', authRequired: true, description: 'Admin export', userInputs: [] },
            ],
            securityFlows: [
                { category: 'authz', description: 'Order detail flow enforces tenant ownership.', components: ['orders', 'tenant'], riskLevel: 'high' },
                { category: 'exports', description: 'Admin export flow is out of scope.', components: ['admin', 'export'], riskLevel: 'medium' },
            ],
        }),
        analyzeSourceCode: async () => {
            throw new Error('analyzeSourceCode should not be called when cached source analysis exists');
        },
    });

    const contextPack = await builder.build('scan-context-1');

    assert.equal(contextPack.objective.title, 'Orders feature review');
    assert.equal(contextPack.selectedTargets.length, 3);
    assert.deepEqual(contextPack.scope.allowedRoutes, ['/api/orders', '/api/orders/:id']);
    assert.equal(contextPack.authSummary.inventorySummary?.authRoutes.length, 3);
    assert.equal(contextPack.supportingContext.requestBundles[0]?.id, 'bundle-1');
    assert.equal(contextPack.supportingContext.endpointIntelligence?.records.length, 2);
    assert.equal(contextPack.supportingContext.sourceAnalysis?.endpoints?.length, 2);
    assert.equal(contextPack.supportingContext.sourceAnalysis?.securityFlows?.length, 1);
    assert.equal(contextPack.plannerConstraints.maxCases, 4);
});

test('ContextPackBuilder can hydrate source analysis from persisted source path when cache is missing', async () => {
    let analyzeCalls = 0;
    const builder = new ContextPackBuilder({
        getScanById: () => ({
            id: 'scan-context-2',
            target: 'https://app.example.com',
            user_id: 7,
            source_package_path: '/tmp/source-two',
            source_analysis_mode: SourceAnalysisMode.VERSION_AWARE,
        }),
        getObjectiveByScanId: () => ({
            id: 'objective-context-2',
            scanId: 'scan-context-2',
            title: 'Request scoped review',
            scopeType: 'request_scoped',
            goal: 'Keep the planner compact.',
            riskTags: ['idor'],
        }),
        getEnvelopeByScanId: () => ({
            id: 'scope-context-2',
            scanId: 'scan-context-2',
            version: 1,
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders/1'],
            selectedEndpoints: [],
            baselineRequestRefs: [{
                kind: 'scan_initial_request',
                source: 'burp_send_to_penpard',
                requestSlot: 'initial_request',
                method: 'GET',
                host: 'app.example.com',
                path: '/api/orders/1',
            }],
            requestBundleRefs: [],
            authContext: null,
            outOfScopeNotes: [],
            boundaryHints: ['Only the captured order detail request'],
            explorationBudget: null,
        }),
        getScanConfigById: () => ({}),
        getScanAuthInventoryById: () => null,
        getScanEndpointInventoryById: () => null,
        getSourceAnalysisResultById: () => null,
        analyzeSourceCode: async (scanId: string, sourcePath: string, mode: string, userId?: number) => {
            analyzeCalls += 1;
            assert.equal(scanId, 'scan-context-2');
            assert.equal(sourcePath, '/tmp/source-two');
            assert.equal(mode, SourceAnalysisMode.VERSION_AWARE);
            assert.equal(userId, 7);
            return {
                mode: SourceAnalysisMode.VERSION_AWARE,
                framework: 'Express',
                technologyStack: ['Express'],
                dependencies: [],
                cves: [],
                testingHints: [{ category: 'authz', hint: 'Order detail handler uses ownership checks.' }],
                analyzedAt: new Date().toISOString(),
            };
        },
    });

    const contextPack = await builder.build('scan-context-2');

    assert.equal(analyzeCalls, 1);
    assert.equal(contextPack.selectedTargets.length, 1);
    assert.equal(contextPack.supportingContext.sourceAnalysis?.testingHints.length, 1);
    assert.equal(contextPack.plannerConstraints.maxCases, 4);
});
