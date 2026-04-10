import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorBrowserSession } = require('../src/agents/orchestrator/OrchestratorBrowserSession') as typeof import('../src/agents/orchestrator/OrchestratorBrowserSession');

test('orchestrator browser session uses the injected browser runtime when relaunching after browser loss', async () => {
    const calls: string[] = [];
    const browser = {
        isSessionAlive: (sessionId: string) => sessionId === 'replacement-session',
        getSessionVisibility: (sessionId: string) => sessionId === 'lost-session'
            ? {
                sessionId,
                lifecycleState: 'manually_closed',
                isHeadless: null,
                transitioning: false,
                isLive: false,
                lastKnownUrl: 'https://app.example.com/account',
                lastError: null,
                detail: 'Visible browser window was closed manually',
            }
            : null,
        launchSession: async () => {
            calls.push('launch');
            return 'replacement-session';
        },
        syncCookiesToSession: async (_sessionId: string, cookies: any[]) => {
            calls.push(`seed:${cookies.length}`);
            return cookies.length;
        },
        getFullPageState: async () => {
            calls.push('page-state');
            return {
                contextCookies: [{ name: 'sid', value: '123' }],
                localStorageData: { token: 'abc' },
                sessionStorageData: { csrf: 'def' },
            };
        },
        closeSession: async () => {},
        executeAction: async () => ({}),
        getPageState: async () => ({}),
        getFrontendAnalysis: async () => ({}),
        correlateBrowserWithBurp: async () => ({}),
    };
    const authManager = {
        exportForBrowser: () => [{
            name: 'sid',
            value: '123',
            domain: 'app.example.com',
            path: '/',
            expires: -1,
            httpOnly: true,
            secure: true,
            sameSite: 'Lax' as const,
        }],
        syncFromBrowser: () => {
            calls.push('sync-cookies');
        },
        syncFromBrowserStorage: () => {
            calls.push('sync-storage');
        },
        detectCSRFFromPage: () => {
            calls.push('sync-csrf');
        },
    };

    const browserSession = new OrchestratorBrowserSession({
        targetUrl: 'https://app.example.com',
        scanId: 'scan-browser-session-test',
        authManager: authManager as any,
        browser: browser as any,
    });

    browserSession.setSessionId('lost-session');
    const relaunchedSessionId = await browserSession.ensureSession();

    assert.equal(relaunchedSessionId, 'replacement-session');
    assert.equal(browserSession.getSessionId(), 'replacement-session');
    assert.deepEqual(calls, [
        'launch',
        'seed:1',
        'page-state',
        'sync-cookies',
        'sync-storage',
        'sync-csrf',
    ]);
});
