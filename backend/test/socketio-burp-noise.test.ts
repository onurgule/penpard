import test from 'node:test';
import assert from 'node:assert/strict';

import { WebAuthStartupService } from '../src/services/WebAuthStartupService';
import { AuthStateManager } from '../src/services/auth';
import { defaultAuthStartupConfig } from '../src/services/web-auth-startup-config';
import { browserService } from '../src/services/BrowserService';

type BrowserServiceMethodName =
    | 'launchSession'
    | 'syncCookiesToSession'
    | 'getFullPageState'
    | 'captureJavaScriptArtifacts'
    | 'getTrafficSnapshot'
    | 'executeAction'
    | 'getFrontendAnalysis'
    | 'closeSession';

type PatchMap = Partial<Record<BrowserServiceMethodName, any>>;

function buildPageState(url: string, overrides: Record<string, any> = {}) {
    return {
        url,
        title: `Page ${url}`,
        forms: [],
        links: [],
        buttons: [],
        metaTags: [],
        antiAutomationMarkers: [],
        indexedDbNames: [],
        localStorageData: {},
        sessionStorageData: {},
        contextCookies: [],
        textSummary: '',
        ...overrides,
    };
}

async function withPatchedBrowserService<T>(patches: PatchMap, fn: () => Promise<T>): Promise<T> {
    const originals = new Map<BrowserServiceMethodName, any>();

    for (const [name, replacement] of Object.entries(patches) as Array<[BrowserServiceMethodName, any]>) {
        originals.set(name, (browserService as any)[name]);
        (browserService as any)[name] = replacement;
    }

    try {
        return await fn();
    } finally {
        for (const [name, original] of originals.entries()) {
            (browserService as any)[name] = original;
        }
    }
}

function createFakeBurp() {
    return {
        async callTool() {
            return { content: [{ text: JSON.stringify({ items: [] }) }] };
        },
    };
}

test('auth startup does not blindly visit guessed auth routes when the target exposed none', async () => {
    const targetUrl = 'http://target.local/';
    const sessionId = 'session-passive-only';
    const navigatedUrls: string[] = [];
    let currentUrl = targetUrl;

    await withPatchedBrowserService({
        launchSession: async () => sessionId,
        syncCookiesToSession: async () => {},
        captureJavaScriptArtifacts: async () => [],
        getTrafficSnapshot: () => [],
        getFrontendAnalysis: async () => ({
            apiEndpoints: [],
            graphqlIndicators: [],
            websocketUrls: [],
            tokenPatterns: [],
            csrfTokens: [],
            frontendRoutes: [],
            hiddenParams: [],
            inlineScriptInsights: [],
        }),
        getFullPageState: async () => buildPageState(currentUrl),
        executeAction: async (_sessionId: string, action: { type: string; url?: string }) => {
            if (action.type === 'goto' && action.url) {
                currentUrl = action.url;
                navigatedUrls.push(action.url);
            }
            return { url: currentUrl, title: `Page ${currentUrl}` };
        },
        closeSession: async () => {},
    }, async () => {
        const authManager = new AuthStateManager('scan-passive-only', targetUrl);
        const service = new WebAuthStartupService(
            'scan-passive-only',
            1,
            targetUrl,
            createFakeBurp() as any,
            authManager,
            () => {},
        );

        await service.run(defaultAuthStartupConfig());
    });

    assert.deepEqual(
        navigatedUrls,
        [],
        'startup should not browser-visit hard-coded auth routes that were never surfaced by the target',
    );
});

test('auth startup still follows auth routes that were passively discovered from the target', async () => {
    const targetUrl = 'http://target.local/';
    const sessionId = 'session-discovered-routes';
    const navigatedUrls: string[] = [];
    let currentUrl = targetUrl;

    await withPatchedBrowserService({
        launchSession: async () => sessionId,
        syncCookiesToSession: async () => {},
        captureJavaScriptArtifacts: async () => [],
        getTrafficSnapshot: () => [],
        getFrontendAnalysis: async () => currentUrl === targetUrl
            ? {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: ['/login'],
                hiddenParams: [],
                inlineScriptInsights: [],
            }
            : {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: [],
                hiddenParams: [],
                inlineScriptInsights: [],
            },
        getFullPageState: async () => buildPageState(currentUrl),
        executeAction: async (_sessionId: string, action: { type: string; url?: string }) => {
            if (action.type === 'goto' && action.url) {
                currentUrl = action.url;
                navigatedUrls.push(action.url);
            }
            return { url: currentUrl, title: `Page ${currentUrl}` };
        },
        closeSession: async () => {},
    }, async () => {
        const authManager = new AuthStateManager('scan-discovered-routes', targetUrl);
        const service = new WebAuthStartupService(
            'scan-discovered-routes',
            1,
            targetUrl,
            createFakeBurp() as any,
            authManager,
            () => {},
        );

        await service.run(defaultAuthStartupConfig());
    });

    assert.deepEqual(navigatedUrls, ['http://target.local/login']);
});

test('auth startup ignores auth API endpoints when selecting browser-navigation candidates', async () => {
    const targetUrl = 'http://target.local/';
    const sessionId = 'session-auth-api-filter';
    const navigatedUrls: string[] = [];
    let currentUrl = targetUrl;

    await withPatchedBrowserService({
        launchSession: async () => sessionId,
        syncCookiesToSession: async () => {},
        captureJavaScriptArtifacts: async () => [],
        getTrafficSnapshot: () => [],
        getFrontendAnalysis: async () => currentUrl === targetUrl
            ? {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: ['/api/auth/login', '/login'],
                hiddenParams: [],
                inlineScriptInsights: [],
            }
            : {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: [],
                hiddenParams: [],
                inlineScriptInsights: [],
            },
        getFullPageState: async () => buildPageState(currentUrl),
        executeAction: async (_sessionId: string, action: { type: string; url?: string }) => {
            if (action.type === 'goto' && action.url) {
                currentUrl = action.url;
                navigatedUrls.push(action.url);
            }
            return { url: currentUrl, title: `Page ${currentUrl}` };
        },
        closeSession: async () => {},
    }, async () => {
        const authManager = new AuthStateManager('scan-auth-api-filter', targetUrl);
        const service = new WebAuthStartupService(
            'scan-auth-api-filter',
            1,
            targetUrl,
            createFakeBurp() as any,
            authManager,
            () => {},
        );

        await service.run(defaultAuthStartupConfig());
    });

    assert.deepEqual(navigatedUrls, ['http://target.local/login']);
});

test('credential-driven auth startup does not brute-force login routes that were never discovered', async () => {
    const targetUrl = 'http://target.local/';
    const sessionId = 'session-provided-credentials';
    const navigatedUrls: string[] = [];
    let currentUrl = targetUrl;

    await withPatchedBrowserService({
        launchSession: async () => sessionId,
        syncCookiesToSession: async () => {},
        captureJavaScriptArtifacts: async () => [],
        getTrafficSnapshot: () => [],
        getFrontendAnalysis: async () => ({
            apiEndpoints: [],
            graphqlIndicators: [],
            websocketUrls: [],
            tokenPatterns: [],
            csrfTokens: [],
            frontendRoutes: [],
            hiddenParams: [],
            inlineScriptInsights: [],
        }),
        getFullPageState: async () => buildPageState(currentUrl),
        executeAction: async (_sessionId: string, action: { type: string; url?: string }) => {
            if (action.type === 'goto' && action.url) {
                currentUrl = action.url;
                navigatedUrls.push(action.url);
            }
            return { url: currentUrl, title: `Page ${currentUrl}` };
        },
        closeSession: async () => {},
    }, async () => {
        const authManager = new AuthStateManager('scan-provided-credentials', targetUrl);
        const service = new WebAuthStartupService(
            'scan-provided-credentials',
            1,
            targetUrl,
            createFakeBurp() as any,
            authManager,
            () => {},
        );

        await service.run({
            mode: 'provided_credentials',
            credentials: [
                {
                    username: 'alice',
                    password: 'secret',
                    source: 'scan_config',
                },
            ],
            allowAccountCreation: false,
            preferSharedPassword: true,
        });
    });

    assert.deepEqual(
        navigatedUrls,
        [],
        'credential mode should not browser-probe guessed login routes when the target exposed none',
    );
});
