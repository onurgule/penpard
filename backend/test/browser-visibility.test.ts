import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import { chromium } from 'playwright-core';

import { browserService } from '../src/services/BrowserService';

test('showBrowser swaps to a visible context without invalidating the session id', async () => {
    const sessions = (browserService as any).sessions as Map<string, any>;
    const sessionId = 'visibility-session';
    sessions.clear();

    let oldContextClosed = false;
    const oldPage = {
        url: () => 'http://target.local/account',
    };
    const oldContext = {
        removeAllListeners: () => {},
        close: async () => { oldContextClosed = true; },
        pages: () => [oldPage],
    };

    sessions.set(sessionId, {
        browser: { close: async () => {} },
        context: oldContext,
        page: oldPage,
        sessionId,
        userId: 1,
        userDataDir: path.join(os.tmpdir(), 'penpard-browser-old'),
        scanId: 'scan-1',
        targetUrl: 'http://target.local',
        targetOrigin: 'http://target.local',
        isHeadless: true,
        proxyServer: 'http://127.0.0.1:8080',
        executablePath: '',
        brandingExtPath: null,
        transitioning: false,
        networkEvents: [],
        nextTrafficEventId: 1,
        jsArtifacts: new Map(),
        jsArtifactsDir: null,
    });

    const originalLaunch = (chromium as any).launchPersistentContext;
    const originalCapture = (browserService as any).captureContinuitySnapshot;
    const originalApply = (browserService as any).applyContinuitySnapshot;
    const originalAttach = (browserService as any).attachSessionListeners;

    let navigatedTo = '';
    const newPage = {
        goto: async (url: string) => { navigatedTo = url; },
        url: () => navigatedTo || 'http://target.local/account',
        title: async () => 'Account',
    };
    const newContext = {
        pages: () => [newPage],
        newPage: async () => newPage,
        addCookies: async () => {},
        addInitScript: async () => {},
        browser: () => null,
        removeAllListeners: () => {},
        close: async () => {},
        on: () => {},
        route: async () => {},
    };

    (chromium as any).launchPersistentContext = async () => newContext;
    (browserService as any).captureContinuitySnapshot = async () => ({
        url: 'http://target.local/account',
        cookies: [],
        storage: [],
    });
    (browserService as any).applyContinuitySnapshot = async () => {};
    (browserService as any).attachSessionListeners = () => {};

    try {
        await browserService.showBrowser(sessionId);

        const updated = sessions.get(sessionId);
        assert.ok(updated);
        assert.equal(updated.isHeadless, false);
        assert.equal(updated.page, newPage);
        assert.equal(updated.transitioning, false);
        assert.equal(navigatedTo, 'http://target.local/account');
        assert.equal(oldContextClosed, true);
    } finally {
        (chromium as any).launchPersistentContext = originalLaunch;
        (browserService as any).captureContinuitySnapshot = originalCapture;
        (browserService as any).applyContinuitySnapshot = originalApply;
        (browserService as any).attachSessionListeners = originalAttach;
        sessions.clear();
    }
});

test('browser executeAction blocks navigation to PenPard internal origins', async () => {
    const originalWait = (browserService as any).waitForSessionReady;
    let navigated = false;

    (browserService as any).waitForSessionReady = async () => ({
        sessionId: 'guard-session',
        page: {
            url: () => 'http://target.local/',
            title: async () => 'Target',
            goto: async () => { navigated = true; },
        },
        targetOrigin: 'http://target.local',
    });

    try {
        await assert.rejects(
            browserService.executeAction('guard-session', {
                type: 'goto',
                url: 'http://localhost:3000/create-account',
            }),
            /Blocked navigation to internal PenPard origin/,
        );
        assert.equal(navigated, false);
    } finally {
        (browserService as any).waitForSessionReady = originalWait;
    }
});
