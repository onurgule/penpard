import test from 'node:test';
import assert from 'node:assert/strict';

import { AuthStartupInventory } from '../src/services/auth';
import { EndpointInventorySnapshot } from '../src/services/EndpointIntelligenceService';

const { CoverageTracker } = require('../src/services/CoverageTracker') as typeof import('../src/services/CoverageTracker');
const { OrchestratorBrowserTools } = require('../src/agents/orchestrator/OrchestratorBrowserTools') as typeof import('../src/agents/orchestrator/OrchestratorBrowserTools');
const { OrchestratorScanSurface } = require('../src/agents/orchestrator/OrchestratorScanSurface') as typeof import('../src/agents/orchestrator/OrchestratorScanSurface');

function createStartupInventory(): AuthStartupInventory {
    return {
        mode: 'no_credentials',
        status: 'completed',
        authRoutes: ['/login'],
        forms: [],
        domElements: [],
        traffic: [
            {
                source: 'browser',
                method: 'POST',
                url: 'https://app.example.com/api/session',
                storageKeys: [],
            },
        ],
        actions: [],
        discoveredCredentials: [],
        ssoProviders: [],
        blockers: [],
        registrationAvailable: false,
        passwordResetAvailable: false,
        activationRequired: false,
        transport: {
            carriesAuthorizationHeader: false,
            authorizationSchemes: [],
            cookieNames: ['sid'],
            localStorageKeys: [],
            sessionStorageKeys: [],
            indexedDbNames: [],
            csrfHeaders: [],
            csrfFormFields: [],
            csrfMetaNames: [],
            csrfCookieNames: [],
            mixedTransport: false,
            evidence: [],
        },
        browserSessionId: 'browser-1',
        startedAt: '2026-04-10T00:00:00.000Z',
        completedAt: '2026-04-10T00:01:00.000Z',
        summary: 'captured startup inventory',
    };
}

function createEndpointInventory(summary: string = '2 endpoint(s) captured'): EndpointInventorySnapshot {
    return {
        scanId: 'scan-1',
        targetUrl: 'https://app.example.com',
        targetOrigin: 'https://app.example.com',
        generatedAt: '2026-04-10T00:02:00.000Z',
        summary,
        authRelevantCount: 1,
        observedInBurpCount: 1,
        exercisedInBrowserCount: 1,
        jsArtifacts: {
            count: 0,
            analyzedCount: 0,
            totalBytes: 0,
        },
        classifications: {
            login: 1,
            session_bootstrap: 1,
        },
        records: [
            {
                id: 'endpoint-login',
                endpoint: 'https://app.example.com/login',
                path: '/login',
                methods: ['GET'],
                primarySource: 'dom',
                sources: ['dom'],
                confidence: 0.8,
                classification: 'login',
                likelyAuthRelevant: true,
                observedInBurp: false,
                exercisedInBrowser: true,
                inferredOnly: false,
                notes: [],
                evidence: [],
                scriptSources: [],
                domSources: [],
                authSignals: [],
                storageKeys: [],
                observedStatusCodes: [],
            },
            {
                id: 'endpoint-session',
                endpoint: 'https://app.example.com/api/session',
                path: '/api/session',
                methods: ['POST'],
                primarySource: 'burp',
                sources: ['burp'],
                confidence: 0.9,
                classification: 'session_bootstrap',
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
    };
}

test('scan surface owns auth startup capture and endpoint inventory refresh', async () => {
    const coverageTracker = new CoverageTracker();
    let browserSessionId: string | null = null;
    let refreshedArgs: any = null;
    let persistedAuth: any = null;
    let persistedEndpoint: any = null;

    const surface = new OrchestratorScanSurface({
        scanId: 'scan-1',
        targetUrl: 'https://app.example.com',
        burp: {} as any,
        authManager: {} as any,
        browserSession: {
            getSessionId: () => browserSessionId,
            setSessionId: (nextId: string | null) => {
                browserSessionId = nextId;
            },
        } as any,
        coverageTracker,
        runAuthStartup: async () => ({
            browserSessionId: 'browser-1',
            inventory: createStartupInventory(),
        }),
        buildEndpointInventory: async (args: any) => {
            refreshedArgs = args;
            return createEndpointInventory();
        },
        persistAuthInventory: (scanId: string, inventoryJson: string) => {
            persistedAuth = { scanId, inventory: JSON.parse(inventoryJson) };
        },
        persistEndpointInventory: (scanId: string, inventoryJson: string) => {
            persistedEndpoint = { scanId, inventory: JSON.parse(inventoryJson) };
        },
    });

    await surface.runAuthStartup({
        mode: 'no_credentials',
        credentials: [],
        allowAccountCreation: false,
        preferSharedPassword: true,
    });

    assert.equal(browserSessionId, 'browser-1');
    assert.deepEqual(surface.getDiscoveredEndpoints().sort(), [
        'https://app.example.com/api/session',
        'https://app.example.com/login',
    ]);
    assert.equal(refreshedArgs.browserSessionId, 'browser-1');
    assert.equal(refreshedArgs.allowAiClassification, true);
    assert.equal(persistedAuth.scanId, 'scan-1');
    assert.equal(persistedAuth.inventory.summary, 'captured startup inventory');
    assert.equal(persistedEndpoint.scanId, 'scan-1');
    assert.equal(surface.getEndpointInventory()?.summary, '2 endpoint(s) captured');
    assert.match(surface.buildStartupAuthPromptBlock(), /WEB AUTH STARTUP INVENTORY/);

    const coverageSummary = coverageTracker.getSummary();
    assert.ok(coverageSummary.routesSeen >= 2);
});

test('request execution aftermath is routed through scan surface instead of the executor mutating scan state directly', () => {
    const coverageTracker = new CoverageTracker();

    const surface = new OrchestratorScanSurface({
        scanId: 'scan-1',
        targetUrl: 'https://app.example.com',
        burp: {} as any,
        authManager: {} as any,
        browserSession: {
            getSessionId: () => null,
        } as any,
        coverageTracker,
    });

    surface.recordRequestExecution({
        url: 'https://app.example.com/api/orders/42?view=full',
        method: 'POST',
        statusCode: 200,
    });

    assert.deepEqual(surface.getDiscoveredEndpoints(), ['/api/orders/42']);

    const coverageSummary = coverageTracker.getSummary();
    assert.ok(coverageSummary.routesSeen >= 1);
});

test('browser tools route browser aftermath through scan surface instead of agent state', async () => {
    const calls: Record<string, any> = {
        navigated: [],
        syncedFromBrowser: 0,
        syncedPageState: null,
        recordedFrontendAnalysis: [],
        correlated: [],
        frontendDelta: null,
    };

    const tools = new OrchestratorBrowserTools({
        browserSession: {
            ensureSession: async () => 'browser-1',
            syncAuthFromBrowser: async () => {
                calls.syncedFromBrowser += 1;
            },
            syncAuthFromPageState: (state: any) => {
                calls.syncedPageState = state;
            },
        } as any,
        scanSurface: {
            noteBrowserNavigation: (url: string) => {
                calls.navigated.push(url);
            },
            recordFrontendAnalysis: async (_analysis: any, trigger: string) => {
                calls.recordedFrontendAnalysis.push(trigger);
                return [];
            },
            applyBurpCorrelation: (correlation: any) => {
                calls.correlated.push(correlation.frontendOnlyEndpoints);
                return correlation.frontendOnlyEndpoints;
            },
            runDeltaFrontendAnalysis: async (trigger: string) => {
                calls.frontendDelta = trigger;
                return ['/api/hidden'];
            },
        } as any,
        browser: {
            executeAction: async (_sessionId: string, action: any) => ({ kind: action.type }),
            getFullPageState: async () => ({
                contextCookies: [{ name: 'sid', value: '123' }],
                localStorageData: { token: 'abc' },
                sessionStorageData: { trace: 'xyz' },
            }),
            getPageState: async () => ({
                url: 'https://app.example.com/post-submit',
                title: 'Submitted',
                forms: [],
            }),
            getFrontendAnalysis: async () => ({
                apiEndpoints: ['/api/me'],
            }),
            correlateBrowserWithBurp: async () => ({
                frontendOnlyEndpoints: ['/api/hidden'],
            }),
        } as any,
        onFrontendDelta: (trigger: string, newEndpoints: string[]) => {
            calls.frontendDelta = { trigger, newEndpoints };
        },
    });

    const navigateResult = await tools.navigate({
        tool: 'browser_navigate',
        args: { url: 'https://app.example.com/account' },
    });
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepEqual(navigateResult, { kind: 'goto' });
    assert.deepEqual(calls.navigated, ['https://app.example.com/account']);
    assert.equal(calls.syncedFromBrowser, 1);
    assert.deepEqual(calls.frontendDelta, {
        trigger: 'navigation',
        newEndpoints: ['/api/hidden'],
    });

    const pageState = await tools.getPageState();
    assert.deepEqual(pageState.cookies, [{ name: 'sid', value: '123' }]);
    assert.deepEqual(pageState.localStorage, { token: 'abc' });
    assert.deepEqual(pageState.sessionStorage, { trace: 'xyz' });
    assert.ok(calls.syncedPageState);

    const analysis = await tools.getFrontendAnalysis();
    assert.deepEqual(analysis.apiEndpoints, ['/api/me']);
    assert.deepEqual(calls.recordedFrontendAnalysis, ['browser-tool']);

    const correlation = await tools.correlateBurp();
    assert.deepEqual(correlation.frontendOnlyEndpoints, ['/api/hidden']);
    assert.deepEqual(calls.correlated, [['/api/hidden']]);
});
