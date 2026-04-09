import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import fs from 'fs';
import { EventEmitter } from 'events';
import { chromium } from 'playwright-core';

const { browserService } = require('../src/services/BrowserService') as typeof import('../src/services/BrowserService');
const { createBrowserSession, initDatabase } = require('../src/db/init') as typeof import('../src/db/init');
const { OrchestratorAgent } = require('../src/agents/OrchestratorAgent') as typeof import('../src/agents/OrchestratorAgent');

class FakePage extends EventEmitter {
    public closed = false;
    private currentUrl: string;
    private currentTitle: string;

    constructor(url: string = 'http://target.local/dashboard', title: string = 'Dashboard') {
        super();
        this.currentUrl = url;
        this.currentTitle = title;
    }

    url(): string {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
        return this.currentUrl;
    }

    async title(): Promise<string> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
        return this.currentTitle;
    }

    async goto(url: string): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
        this.currentUrl = url;
    }

    async screenshot(): Promise<Buffer> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
        return Buffer.from('png');
    }

    async evaluate(script: unknown): Promise<any> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }

        if (typeof script === 'string') {
            if (script.includes('document.querySelectorAll(\'script\')')) {
                return { scripts: [], preloads: [], totalScripts: 0 };
            }
            if (script.includes('localStorageData') && script.includes('sessionStorageData')) {
                return { cookies: '', localStorageData: {}, sessionStorageData: {} };
            }
            return {
                forms: [],
                links: [],
                textSummary: '',
                tagCounts: {},
                totalElements: 0,
                hiddenInputs: [],
                buttons: [],
                metaTags: [],
                scripts: [],
                cookies: '',
                localStorageData: {},
                sessionStorageData: {},
                indexedDbNames: [],
                antiAutomationMarkers: [],
            };
        }

        return null;
    }

    async click(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async fill(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async selectOption(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async waitForLoadState(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async waitForSelector(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async goBack(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async goForward(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    async reload(): Promise<void> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
    }

    mainFrame(): string {
        return 'main-frame';
    }

    isClosed(): boolean {
        return this.closed;
    }

    closeManually(): void {
        if (!this.closed) {
            this.closed = true;
            this.emit('close');
        }
    }
}

class FakeBrowser extends EventEmitter {
    public connected = true;
    public closeCalls = 0;

    isConnected(): boolean {
        return this.connected;
    }

    async close(): Promise<void> {
        if (!this.connected) {
            return;
        }
        this.closeCalls += 1;
        this.connected = false;
        this.emit('disconnected');
    }

    disconnect(): void {
        if (!this.connected) {
            return;
        }
        this.connected = false;
        this.emit('disconnected');
    }
}

class FakeContext extends EventEmitter {
    public closed = false;
    public closeCalls = 0;
    private readonly browserRef: FakeBrowser;
    private pagesList: FakePage[];

    constructor(browserRef: FakeBrowser, pagesList: FakePage[]) {
        super();
        this.browserRef = browserRef;
        this.pagesList = pagesList;
    }

    pages(): FakePage[] {
        if (this.closed || !this.browserRef.connected) {
            throw new Error('Target page, context or browser has been closed');
        }
        return this.pagesList.filter((page) => !page.closed);
    }

    async newPage(): Promise<FakePage> {
        const page = new FakePage('about:blank', 'New Page');
        this.pagesList = [page];
        return page;
    }

    async addCookies(): Promise<void> {}

    async addInitScript(): Promise<void> {}

    async route(): Promise<void> {}

    async cookies(): Promise<any[]> {
        if (this.closed) {
            throw new Error('Target page, context or browser has been closed');
        }
        return [];
    }

    browser(): FakeBrowser {
        return this.browserRef;
    }

    async close(): Promise<void> {
        if (this.closed) {
            return;
        }
        this.closeCalls += 1;
        this.closed = true;
        this.emit('close');
    }
}

function uniqueSessionId(prefix: string): string {
    return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function resetBrowserServiceState(): void {
    const sessions = (browserService as any).sessions as Map<string, any>;
    sessions.clear();
}

function registerDbSession(sessionId: string): void {
    createBrowserSession({
        id: sessionId,
        userId: 1,
        targetUrl: 'http://target.local',
        proxyHost: '127.0.0.1',
        proxyPort: 8080,
    });
}

function createRuntimeSession(options: {
    sessionId?: string;
    isHeadless?: boolean;
    browser?: FakeBrowser;
    context?: FakeContext;
    page?: FakePage;
}) {
    const sessionId = options.sessionId || uniqueSessionId('browser-session');
    registerDbSession(sessionId);

    const browser = options.browser || new FakeBrowser();
    const page = options.page || new FakePage();
    const context = options.context || new FakeContext(browser, [page]);
    const isHeadless = options.isHeadless ?? false;
    const lifecycleState = isHeadless ? 'headless_active' : 'visible_active';
    const userDataDir = path.join(os.tmpdir(), 'penpard-browser-tests', sessionId);
    fs.mkdirSync(userDataDir, { recursive: true });

    const session = {
        browser: browser as any,
        context: context as any,
        page: page as any,
        sessionId,
        userId: 1,
        userDataDir,
        scanId: 'scan-1',
        targetUrl: 'http://target.local',
        targetOrigin: 'http://target.local',
        isHeadless,
        proxyServer: 'http://127.0.0.1:8080',
        executablePath: 'fake-chromium',
        brandingExtPath: null,
        transitioning: false,
        lifecycleState,
        lifecycleDetail: null,
        lastError: null,
        lastKnownUrl: page.url(),
        lastKnownTitle: 'Dashboard',
        hasBeenVisible: !isHeadless,
        generation: 1,
        networkEvents: [],
        nextTrafficEventId: 1,
        jsArtifacts: new Map(),
        jsArtifactsDir: null,
    };

    ((browserService as any).sessions as Map<string, any>).set(sessionId, session);
    (browserService as any).attachSessionListeners(sessionId, page as any, context as any, session.generation);

    return { sessionId, session, browser, context, page };
}

function createAgent(): InstanceType<typeof OrchestratorAgent> {
    return new OrchestratorAgent(
        uniqueSessionId('scan'),
        'http://target.local',
        {
            rateLimit: 1,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            userId: 1,
        },
        { callTool: async () => ({ items: [] }) } as any,
    );
}

test.beforeEach(async () => {
    await initDatabase();
    resetBrowserServiceState();
});

test.afterEach(() => {
    resetBrowserServiceState();
});

test('manual browser close invalidates the visible session without crashing', async () => {
    const { sessionId, page } = createRuntimeSession({ isHeadless: false });

    page.closeManually();

    assert.equal(browserService.isSessionAlive(sessionId), false);
    const visibility = browserService.getSessionVisibility(sessionId);
    assert.ok(visibility);
    assert.equal(visibility.lifecycleState, 'manually_closed');
    assert.equal(visibility.isLive, false);
    assert.equal(visibility.transitioning, false);
});

test('hideBrowser after a manual close is a safe controlled no-op', async () => {
    const { sessionId, page } = createRuntimeSession({ isHeadless: false });
    page.closeManually();

    const result = await browserService.hideBrowser(sessionId);

    assert.equal(result.lifecycleState, 'manually_closed');
    assert.equal(result.isLive, false);
    assert.match(result.message, /safe no-op/i);
});

test('showBrowser reopens a manually closed session cleanly', async () => {
    const { sessionId, page } = createRuntimeSession({ isHeadless: false });
    page.closeManually();

    const relaunchedPage = new FakePage('http://target.local/account', 'Account');
    const relaunchedBrowser = new FakeBrowser();
    const relaunchedContext = new FakeContext(relaunchedBrowser, [relaunchedPage]);
    const originalLaunch = (chromium as any).launchPersistentContext;

    (chromium as any).launchPersistentContext = async () => relaunchedContext;

    try {
        const result = await browserService.showBrowser(sessionId);
        const visibility = browserService.getSessionVisibility(sessionId);

        assert.equal(result.reopened, true);
        assert.equal(result.lifecycleState, 'visible_active');
        assert.equal(result.isLive, true);
        assert.equal(browserService.isSessionAlive(sessionId), true);
        assert.equal(visibility?.lifecycleState, 'visible_active');
    } finally {
        (chromium as any).launchPersistentContext = originalLaunch;
    }
});

test('browser actions on dead sessions fail in a controlled way', async () => {
    const { sessionId, page } = createRuntimeSession({ isHeadless: false });
    page.closeManually();

    await assert.rejects(
        browserService.executeAction(sessionId, {
            type: 'goto',
            url: 'http://target.local/profile',
        }),
        /browser session .* manually_closed/i,
    );
});

test('closeSession is idempotent across repeated cleanup calls', async () => {
    const { sessionId, browser } = createRuntimeSession({ isHeadless: true });

    await browserService.closeSession(sessionId);
    await browserService.closeSession(sessionId);

    const visibility = browserService.getSessionVisibility(sessionId);
    assert.equal(browser.closeCalls, 1);
    assert.ok(visibility);
    assert.equal(visibility.lifecycleState, 'closed');
    assert.equal(visibility.isLive, false);
});

test('stale session registry entries are invalidated instead of poisoning future checks', async () => {
    const { sessionId, page } = createRuntimeSession({ isHeadless: true });
    page.closed = true;

    assert.equal(browserService.isSessionAlive(sessionId), false);
    const visibility = browserService.getSessionVisibility(sessionId);
    assert.ok(visibility);
    assert.equal(visibility.lifecycleState, 'stale_reference');
    assert.equal(visibility.isLive, false);
});

test('browser disconnect marks the session unavailable and does not poison a later reopen', async () => {
    const { sessionId, browser } = createRuntimeSession({ isHeadless: false });
    browser.disconnect();

    let visibility = browserService.getSessionVisibility(sessionId);
    assert.ok(visibility);
    assert.equal(visibility.lifecycleState, 'crashed_or_disconnected');
    assert.equal(visibility.isLive, false);

    const relaunchedPage = new FakePage('http://target.local/dashboard', 'Dashboard');
    const relaunchedBrowser = new FakeBrowser();
    const relaunchedContext = new FakeContext(relaunchedBrowser, [relaunchedPage]);
    const originalLaunch = (chromium as any).launchPersistentContext;
    (chromium as any).launchPersistentContext = async () => relaunchedContext;

    try {
        const result = await browserService.showBrowser(sessionId);
        visibility = browserService.getSessionVisibility(sessionId);

        assert.equal(result.reopened, true);
        assert.equal(result.lifecycleState, 'visible_active');
        assert.equal(visibility?.isLive, true);
    } finally {
        (chromium as any).launchPersistentContext = originalLaunch;
    }
});

test('orchestrator lazily relaunches after browser loss so scans degrade gracefully', async () => {
    const agent = createAgent();
    (agent as any).browserSessionId = 'lost-session';

    const originalIsAlive = browserService.isSessionAlive;
    const originalVisibility = browserService.getSessionVisibility;
    const originalLaunch = browserService.launchSession;
    const originalSyncCookies = browserService.syncCookiesToSession;
    const originalPageState = browserService.getFullPageState;

    browserService.isSessionAlive = ((sessionId: string) => sessionId === 'replacement-session') as any;
    browserService.getSessionVisibility = ((sessionId: string) => sessionId === 'lost-session'
        ? {
            sessionId,
            lifecycleState: 'manually_closed',
            isHeadless: null,
            transitioning: false,
            isLive: false,
            lastKnownUrl: 'http://target.local/account',
            lastError: null,
            detail: 'Visible browser window was closed manually',
        }
        : null) as any;
    browserService.launchSession = (async () => 'replacement-session') as any;
    browserService.syncCookiesToSession = (async () => 0) as any;
    browserService.getFullPageState = (async () => ({
        contextCookies: [],
        localStorageData: {},
        sessionStorageData: {},
    })) as any;

    try {
        const sessionId = await (agent as any).browserSession.ensureSession();
        assert.equal(sessionId, 'replacement-session');
        assert.equal(agent.getBrowserSessionId(), 'replacement-session');
    } finally {
        browserService.isSessionAlive = originalIsAlive;
        browserService.getSessionVisibility = originalVisibility;
        browserService.launchSession = originalLaunch;
        browserService.syncCookiesToSession = originalSyncCookies;
        browserService.getFullPageState = originalPageState;
    }
});
