/**
 * PenPard Browser Service
 *
 * Manages Playwright-controlled Chromium instances that route traffic through
 * Burp Suite. Supports dual-control: human pentester interaction via the real
 * browser window AND AI-driven programmatic control via the Playwright Page API.
 *
 * Architecture:
 *  - Each session launches a visible Chromium with --proxy-server and
 *    --ignore-certificate-errors (eliminates Burp CA trust requirement).
 *  - Sessions are held in-memory; metadata persisted to SQLite.
 *  - Action log captures both human-observed and AI-driven events.
 */

import { chromium, Browser, BrowserContext, Page } from 'playwright-core';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import {
    createBrowserSession,
    updateBrowserSession,
    addBrowserAction,
    getBrowserSession,
    getBrowserActions,
    closeBrowserSession as dbCloseSession,
} from '../db/init';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { createHash } from 'crypto';
import { execSync, exec } from 'child_process';
import { normalizeProxyHistoryItems } from './burp-tool-result';
import {
    deriveActiveBrowserLifecycleState,
    isLiveBrowserLifecycleState,
    type BrowserLifecycleState,
} from '../types/browserLifecycle';

// ── Types ──

export interface BrowserSessionOptions {
    targetUrl?: string;
    scanId?: string;
    findingId?: number;
    proxyHost?: string;
    proxyPort?: number;
    label?: string;
    /** Launch in headless mode. Default false (visible) for manual sessions, true for agent sessions. */
    headless?: boolean;
}

export interface BrowserAction {
    type: 'goto' | 'click' | 'fill' | 'select' | 'submit' | 'evaluate' | 'waitForNavigation' | 'waitForSelector' | 'screenshot' | 'back' | 'forward' | 'reload';
    url?: string;
    selector?: string;
    value?: string;
    script?: string;
    timeout?: number;
}

export interface PageState {
    url: string;
    title: string;
    forms: Array<{ action: string; method: string; fields: Array<{ name: string; type: string; id: string }> }>;
    links: Array<{ href: string; text: string }>;
    textSummary: string;
}

export interface BrowserTrafficEvent {
    id: number;
    kind: 'request' | 'response';
    method: string;
    url: string;
    timestamp: string;
    originCategory?: 'target' | 'internal' | 'external';
    resourceType?: string;
    requestHeaders?: Record<string, string>;
    responseHeaders?: Record<string, string>;
    requestBody?: string;
    statusCode?: number;
}

export interface CapturedJsArtifact {
    id: string;
    sessionId: string;
    scanId?: string;
    pageUrl: string;
    scriptUrl?: string;
    origin: string;
    type: 'external' | 'inline';
    contentType: string;
    contentHash: string;
    bytes: number;
    storedAt: string;
    filePath: string;
    evidence: string[];
}

interface BrowserContinuitySnapshot {
    url: string;
    cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>;
    storage: Array<{
        origin: string;
        localStorageData: Record<string, string>;
        sessionStorageData: Record<string, string>;
    }>;
}

export interface BrowserSessionVisibility {
    sessionId: string;
    lifecycleState: BrowserLifecycleState;
    isHeadless: boolean | null;
    transitioning: boolean;
    isLive: boolean;
    lastKnownUrl: string | null;
    lastError: string | null;
    detail: string | null;
}

export interface BrowserVisibilityResult extends BrowserSessionVisibility {
    message: string;
    reopened: boolean;
}

interface LiveSession {
    browser: Browser | null;
    context: BrowserContext | null;
    page: Page | null;
    sessionId: string;
    userId: number;
    userDataDir: string;
    scanId?: string;
    targetUrl?: string;
    targetOrigin: string | null;
    /** Whether this session is currently running in headless mode. */
    isHeadless: boolean;
    /** Proxy server string for relaunches (e.g. "http://127.0.0.1:8080"). */
    proxyServer: string;
    /** Chromium executable path resolved at first launch. */
    executablePath: string;
    /** Branding extension path, if available. */
    brandingExtPath: string | null;
    /** Lock to prevent concurrent show/hide transitions. */
    transitioning: boolean;
    /** Runtime lifecycle contract for the current session record. */
    lifecycleState: BrowserLifecycleState;
    /** Last lifecycle detail or reason for invalidation. */
    lifecycleDetail: string | null;
    /** Last lifecycle-related error without secrets. */
    lastError: string | null;
    /** Last URL observed before the session became unavailable. */
    lastKnownUrl: string | null;
    /** Last title observed before the session became unavailable. */
    lastKnownTitle: string | null;
    /** Tracks whether the session has ever been shown as a real browser window. */
    hasBeenVisible: boolean;
    /** Generation token so late events from prior contexts do not poison replacements. */
    generation: number;
    /** Rolling capture of browser-generated traffic for auth/session correlation. */
    networkEvents: BrowserTrafficEvent[];
    nextTrafficEventId: number;
    jsArtifacts: Map<string, CapturedJsArtifact>;
    jsArtifactsDir: string | null;
}

type ReadyLiveSession = LiveSession & {
    browser: Browser;
    context: BrowserContext;
    page: Page;
};

// ── Service ──

class BrowserService {
    private sessions: Map<string, LiveSession> = new Map();

    private now(): string {
        return new Date().toISOString();
    }

    private delay(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    private safePageUrl(session: Pick<LiveSession, 'page' | 'lastKnownUrl' | 'targetUrl'>): string | null {
        if (session.page) {
            try {
                const url = session.page.url();
                if (url) {
                    return url;
                }
            } catch {
                /* ignore */
            }
        }
        return session.lastKnownUrl || session.targetUrl || null;
    }

    private async safePageTitle(session: Pick<LiveSession, 'page' | 'lastKnownTitle'>): Promise<string | null> {
        if (session.page) {
            try {
                const title = await session.page.title();
                if (title) {
                    return title;
                }
            } catch {
                /* ignore */
            }
        }
        return session.lastKnownTitle || null;
    }

    private updateLastKnownPageState(session: LiveSession, page: Page | null = session.page): void {
        if (!page) return;
        try {
            const currentUrl = page.url();
            if (currentUrl) {
                session.lastKnownUrl = currentUrl;
            }
        } catch {
            /* ignore */
        }

        void page.title().then((title) => {
            session.lastKnownTitle = title || session.lastKnownTitle;
        }).catch(() => {});
    }

    private buildVisibilityState(session: LiveSession): BrowserSessionVisibility {
        return {
            sessionId: session.sessionId,
            lifecycleState: session.lifecycleState,
            isHeadless: session.page && session.context && session.browser ? session.isHeadless : null,
            transitioning: session.transitioning,
            isLive: isLiveBrowserLifecycleState(session.lifecycleState) && !!session.browser && !!session.context && !!session.page,
            lastKnownUrl: session.lastKnownUrl || null,
            lastError: session.lastError || null,
            detail: session.lifecycleDetail || null,
        };
    }

    private updateLifecycleState(
        sessionId: string,
        session: LiveSession,
        lifecycleState: BrowserLifecycleState,
        options: {
            detail?: string | null;
            error?: string | null;
            status?: 'launching' | 'active' | 'paused' | 'closed';
            currentUrl?: string | null;
            closedAt?: string | null;
            clearHandles?: boolean;
            preserveTransitioning?: boolean;
        } = {},
    ): void {
        session.lifecycleState = lifecycleState;
        session.lifecycleDetail = options.detail ?? null;
        session.lastError = options.error ?? null;
        if (!options.preserveTransitioning) {
            session.transitioning = lifecycleState === 'closing';
        }
        if (lifecycleState === 'visible_active') {
            session.hasBeenVisible = true;
        }
        if (options.currentUrl !== undefined) {
            session.lastKnownUrl = options.currentUrl;
        }
        if (options.clearHandles) {
            session.browser = null;
            session.context = null;
            session.page = null;
        }

        const dbUpdate: Record<string, any> = {
            lifecycle_state: lifecycleState,
            lifecycle_detail: options.detail ?? null,
            last_error: options.error ?? null,
            last_activity_at: this.now(),
        };

        if (options.status) {
            dbUpdate.status = options.status;
        }
        if (options.currentUrl !== undefined) {
            dbUpdate.current_url = options.currentUrl;
        }
        if (options.closedAt !== undefined) {
            dbUpdate.closed_at = options.closedAt;
        }

        updateBrowserSession(sessionId, dbUpdate);
    }

    private invalidateSession(
        sessionId: string,
        lifecycleState: BrowserLifecycleState,
        detail: string,
        error?: string | null,
    ): BrowserSessionVisibility | null {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        if (
            !isLiveBrowserLifecycleState(session.lifecycleState)
            && session.lifecycleState === lifecycleState
            && !session.browser
            && !session.context
            && !session.page
        ) {
            return this.buildVisibilityState(session);
        }

        const currentUrl = this.safePageUrl(session);
        this.updateLifecycleState(sessionId, session, lifecycleState, {
            detail,
            error: error || null,
            status: 'closed',
            currentUrl,
            closedAt: this.now(),
            clearHandles: true,
        });

        logger.warn('Browser session invalidated', {
            sessionId,
            lifecycleState,
            detail,
            error: error || undefined,
        });

        return this.buildVisibilityState(session);
    }

    private lifecycleError(sessionId: string, operation: string, session?: LiveSession): Error {
        const lifecycleState = session?.lifecycleState || 'closed';
        const detail = session?.lifecycleDetail ? ` (${session.lifecycleDetail})` : '';
        return new Error(`Cannot ${operation}: browser session ${sessionId} is ${lifecycleState}${detail}`);
    }

    private assertReadySession(sessionId: string, operation: string): ReadyLiveSession {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }

        if (!session.browser || !session.context || !session.page) {
            throw this.lifecycleError(sessionId, operation, session);
        }

        try {
            const browserAny = session.browser as any;
            if (typeof browserAny.isConnected === 'function' && !browserAny.isConnected()) {
                this.invalidateSession(sessionId, 'crashed_or_disconnected', 'Browser disconnected');
                throw this.lifecycleError(sessionId, operation, this.sessions.get(sessionId));
            }
        } catch (error) {
            if (error instanceof Error && /Cannot .*browser session/.test(error.message)) {
                throw error;
            }
        }

        const pageAny = session.page as any;
        if (typeof pageAny.isClosed === 'function' && pageAny.isClosed()) {
            this.invalidateSession(
                sessionId,
                session.isHeadless ? 'stale_reference' : 'manually_closed',
                session.isHeadless ? 'Closed page handle detected during session validation' : 'Visible browser window was closed manually',
            );
            throw this.lifecycleError(sessionId, operation, this.sessions.get(sessionId));
        }

        try {
            session.context.pages();
        } catch (error: any) {
            this.invalidateSession(
                sessionId,
                session.isHeadless ? 'stale_reference' : 'crashed_or_disconnected',
                'Browser context became unavailable',
                error?.message || null,
            );
            throw this.lifecycleError(sessionId, operation, this.sessions.get(sessionId));
        }

        try {
            const currentUrl = session.page.url();
            if (currentUrl) {
                session.lastKnownUrl = currentUrl;
            }
        } catch (error: any) {
            this.invalidateSession(
                sessionId,
                session.isHeadless ? 'stale_reference' : 'manually_closed',
                session.isHeadless ? 'Stale page reference detected' : 'Visible browser window was closed manually',
                error?.message || null,
            );
            throw this.lifecycleError(sessionId, operation, this.sessions.get(sessionId));
        }

        return session as ReadyLiveSession;
    }

    private recordTrafficEvent(sessionId: string, event: Omit<BrowserTrafficEvent, 'id'>): void {
        const session = this.sessions.get(sessionId);
        if (!session) return;

        session.networkEvents.push({
            id: session.nextTrafficEventId++,
            ...event,
        });

        if (session.networkEvents.length > 500) {
            session.networkEvents.splice(0, session.networkEvents.length - 500);
        }
    }

    private getTargetOrigin(targetUrl?: string): string | null {
        if (!targetUrl) return null;
        try {
            return new URL(targetUrl).origin;
        } catch {
            return null;
        }
    }

    private ensureJsArtifactsDir(scanId: string, sessionId: string): string {
        const dir = path.join(os.homedir(), '.penpard', 'scan_runtime', scanId, 'js-artifacts', sessionId);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        return dir;
    }

    private ensureVisibilityTransitionDir(session: LiveSession, targetHeadless: boolean): string {
        const parentDir = path.dirname(session.userDataDir);
        const dirName = `${session.sessionId}-${targetHeadless ? 'headless' : 'visible'}-${Date.now()}`;
        const nextDir = path.join(parentDir, dirName);
        if (!fs.existsSync(nextDir)) {
            fs.mkdirSync(nextDir, { recursive: true });
        }
        return nextDir;
    }

    private buildLaunchArgs(proxyServer: string, brandingExtPath: string | null, headless: boolean): string[] {
        const launchArgs: string[] = [
            `--proxy-server=${proxyServer}`,
            '--ignore-certificate-errors',
            '--ignore-certificate-errors-spki-list',
            '--disable-web-security',
            '--allow-running-insecure-content',
            '--disable-features=IsolateOrigins,site-per-process',
            '--disable-blink-features=AutomationControlled',
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        ];

        if (brandingExtPath && !headless) {
            launchArgs.push(
                `--disable-extensions-except=${brandingExtPath}`,
                `--load-extension=${brandingExtPath}`,
            );
        }

        return launchArgs;
    }

    private categorizeUrl(url: string, targetOrigin: string | null): 'target' | 'internal' | 'external' {
        if (!url) return 'external';
        try {
            const parsed = new URL(url);
            if (targetOrigin && parsed.origin === targetOrigin) {
                return 'target';
            }
            if (this.isPenPardInternalUrl(url, targetOrigin)) {
                return 'internal';
            }
        } catch {
            return 'external';
        }
        return 'external';
    }

    private isPenPardInternalUrl(url: string, targetOrigin: string | null): boolean {
        if (!url) return false;
        try {
            const parsed = new URL(url);
            if (targetOrigin && parsed.origin === targetOrigin) {
                return false;
            }
            if (parsed.protocol === 'file:' || parsed.protocol === 'app:' || parsed.protocol === 'electron:') {
                return true;
            }
            const host = parsed.hostname.toLowerCase();
            const port = parsed.port;
            const isLocalHost = host === 'localhost' || host === '127.0.0.1' || host === '::1';
            const isPenPardPort = port === '3000' || port === '4000';
            const looksLikeApi = parsed.pathname.startsWith('/api/');
            return (isLocalHost && isPenPardPort) || (isLocalHost && looksLikeApi);
        } catch {
            return false;
        }
    }

    private async persistJsArtifact(session: LiveSession, artifact: {
        type: 'external' | 'inline';
        pageUrl: string;
        scriptUrl?: string;
        contentType?: string;
        content: string;
        evidence?: string[];
    }): Promise<CapturedJsArtifact | null> {
        if (!session.jsArtifactsDir || !artifact.content || !artifact.content.trim()) {
            return null;
        }

        const contentHash = createHash('sha256').update(artifact.content).digest('hex');
        const existing = session.jsArtifacts.get(contentHash);
        if (existing) {
            return existing;
        }

        const ext = artifact.type === 'inline' ? 'inline.js' : 'bundle.js';
        const filePath = path.join(session.jsArtifactsDir, `${contentHash}.${ext}`);
        if (!fs.existsSync(filePath)) {
            fs.writeFileSync(filePath, artifact.content, 'utf8');
        }

        const record: CapturedJsArtifact = {
            id: `js-${contentHash.slice(0, 16)}`,
            sessionId: session.sessionId,
            scanId: session.scanId,
            pageUrl: artifact.pageUrl,
            scriptUrl: artifact.scriptUrl,
            origin: (() => {
                try {
                    return new URL(artifact.scriptUrl || artifact.pageUrl).origin;
                } catch {
                    return '';
                }
            })(),
            type: artifact.type,
            contentType: artifact.contentType || 'application/javascript',
            contentHash,
            bytes: Buffer.byteLength(artifact.content, 'utf8'),
            storedAt: new Date().toISOString(),
            filePath,
            evidence: artifact.evidence || [],
        };

        session.jsArtifacts.set(contentHash, record);
        return record;
    }

    private async captureScriptResponse(session: LiveSession, response: any): Promise<void> {
        if (!session.jsArtifactsDir) return;

        const request = response.request();
        if (request.resourceType() !== 'script') return;

        const scriptUrl = response.url();
        if (this.isPenPardInternalUrl(scriptUrl, session.targetOrigin)) {
            return;
        }

        let body: Buffer;
        try {
            body = await response.body();
        } catch {
            return;
        }

        if (!body || body.length === 0 || body.length > 1_500_000) {
            return;
        }

        const content = body.toString('utf8');
        await this.persistJsArtifact(session, {
            type: 'external',
            pageUrl: this.safePageUrl(session) || 'about:blank',
            scriptUrl,
            contentType: response.headers()['content-type'] || 'application/javascript',
            content,
            evidence: [`resourceType=script`, `status=${response.status()}`],
        });
    }

    private async captureContinuitySnapshot(session: ReadyLiveSession): Promise<BrowserContinuitySnapshot> {
        const currentUrl = (() => {
            try {
                return session.page.url() || session.targetUrl || 'about:blank';
            } catch {
                return session.targetUrl || 'about:blank';
            }
        })();

        let cookies: BrowserContinuitySnapshot['cookies'] = [];
        try {
            cookies = await session.context.cookies();
        } catch {
            cookies = [];
        }

        const storage = await session.page.evaluate(`(() => {
            const localStorageData = {};
            const sessionStorageData = {};
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = localStorage.getItem(key) || '';
                }
            } catch {}
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = sessionStorage.getItem(key) || '';
                }
            } catch {}
            return [{
                origin: window.location.origin,
                localStorageData,
                sessionStorageData,
            }];
        })()`).catch(() => []);

        return {
            url: currentUrl,
            cookies: cookies as BrowserContinuitySnapshot['cookies'],
            storage: Array.isArray(storage) ? storage : [],
        };
    }

    private async applyContinuitySnapshot(context: BrowserContext, snapshot: BrowserContinuitySnapshot): Promise<void> {
        if (snapshot.cookies.length > 0) {
            await context.addCookies(snapshot.cookies as any).catch(() => {});
        }

        if (snapshot.storage.length > 0) {
            await context.addInitScript((origins: BrowserContinuitySnapshot['storage']) => {
                const browserGlobal = globalThis as any;
                for (const originState of origins) {
                    if (browserGlobal.location?.origin !== originState.origin) continue;
                    for (const [key, value] of Object.entries(originState.localStorageData || {})) {
                        try { browserGlobal.localStorage?.setItem(key, value); } catch {}
                    }
                    for (const [key, value] of Object.entries(originState.sessionStorageData || {})) {
                        try { browserGlobal.sessionStorage?.setItem(key, value); } catch {}
                    }
                }
            }, snapshot.storage as any).catch(() => {});
        }
    }

    private async waitForSessionReady(sessionId: string, timeoutMs: number = 15000, operation: string = 'use the browser session'): Promise<ReadyLiveSession> {
        const started = Date.now();
        while (Date.now() - started < timeoutMs) {
            const session = this.sessions.get(sessionId);
            if (session && !session.transitioning) {
                return this.assertReadySession(sessionId, operation);
            }
            await this.delay(100);
        }

        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }
        return this.assertReadySession(sessionId, operation);
    }

    private attachSessionListeners(sessionId: string, page: Page, context: BrowserContext, generation: number): void {
        const session = this.sessions.get(sessionId);
        const targetOrigin = session?.targetOrigin || null;
        const browser = context.browser();

        const isCurrentGeneration = (): boolean => {
            const current = this.sessions.get(sessionId);
            return !!current && current.generation === generation;
        };

        const invalidateIfCurrent = (lifecycleState: BrowserLifecycleState, detail: string, error?: string | null) => {
            if (!isCurrentGeneration()) {
                return;
            }
            this.invalidateSession(sessionId, lifecycleState, detail, error);
        };

        context.route('**/*', async (route: any) => {
            const request = route.request();
            const requestUrl = request.url();
            if (this.isPenPardInternalUrl(requestUrl, targetOrigin)) {
                logger.warn('Blocked internal-origin browser request from scan session', {
                    sessionId,
                    requestUrl,
                    resourceType: request.resourceType(),
                });
                await route.abort();
                return;
            }
            await route.continue();
        }).catch(() => {});

        page.on('framenavigated', (frame: any) => {
            if (frame === page.mainFrame()) {
                const url = page.url();
                const liveSession = this.sessions.get(sessionId);
                if (liveSession) {
                    liveSession.lastKnownUrl = url;
                }
                updateBrowserSession(sessionId, {
                    current_url: url,
                    last_activity_at: new Date().toISOString(),
                });
                addBrowserAction({
                    sessionId,
                    actionType: 'page_load',
                    actionData: JSON.stringify({ url }),
                    pageUrl: url,
                    pageTitle: '',
                    source: 'system',
                });
            }
        });

        page.on('request', (request: any) => {
            const liveSession = this.sessions.get(sessionId);
            if (liveSession) {
                this.updateLastKnownPageState(liveSession, page);
            }
            this.recordTrafficEvent(sessionId, {
                kind: 'request',
                method: request.method(),
                url: request.url(),
                timestamp: new Date().toISOString(),
                originCategory: this.categorizeUrl(request.url(), targetOrigin),
                resourceType: request.resourceType(),
                requestHeaders: request.headers(),
                requestBody: request.postData() || undefined,
            });
        });

        page.on('response', async (response: any) => {
            let responseHeaders: Record<string, string> = {};
            try {
                responseHeaders = await response.allHeaders();
            } catch {
                try {
                    responseHeaders = response.headers();
                } catch {
                    responseHeaders = {};
                }
            }

            this.recordTrafficEvent(sessionId, {
                kind: 'response',
                method: response.request().method(),
                url: response.url(),
                timestamp: new Date().toISOString(),
                originCategory: this.categorizeUrl(response.url(), targetOrigin),
                resourceType: response.request().resourceType(),
                requestHeaders: response.request().headers(),
                statusCode: response.status(),
                responseHeaders,
            });

            const liveSession = this.sessions.get(sessionId);
            if (liveSession) {
                this.updateLastKnownPageState(liveSession, page);
                void this.captureScriptResponse(liveSession, response).catch((error: any) => {
                    logger.debug('Script artifact capture failed', { sessionId, error: error.message });
                });
            }
        });

        page.on('close', () => {
            const liveSession = this.sessions.get(sessionId);
            if (!liveSession || !isCurrentGeneration()) {
                return;
            }
            invalidateIfCurrent(
                liveSession.isHeadless ? 'stale_reference' : 'manually_closed',
                liveSession.isHeadless ? 'Headless browser page closed unexpectedly' : 'Visible browser window was closed manually',
            );
        });

        page.on('crash', () => {
            invalidateIfCurrent('crashed_or_disconnected', 'Playwright page crashed');
        });

        context.on('close', () => {
            invalidateIfCurrent('crashed_or_disconnected', 'Browser context closed unexpectedly');
        });

        if (browser && typeof (browser as any).on === 'function') {
            (browser as any).on('disconnected', () => {
                invalidateIfCurrent('crashed_or_disconnected', 'Browser disconnected');
            });
        }
    }

    /**
     * Resolve the path to the PenPard Browser branding extension.
     * This extension overrides tab favicons and sets the browser action icon
     * so the Chromium window shows PenPard identity in taskbar/tab/titlebar.
     *
     * Layout:
     *   dev:  <project>/electron/assets/browser-extension/
     *   prod: <resources>/browser-extension/  (extraResources copy)
     */
    private resolveBrandingExtensionPath(): string | null {
        const candidates: string[] = [];

        // Development: relative to backend/src/services → project root
        candidates.push(
            path.resolve(__dirname, '..', '..', '..', 'electron', 'assets', 'browser-extension'),
        );

        // Production (Electron packaged): extraResources
        if (process.env.RESOURCES_PATH) {
            candidates.push(path.join(process.env.RESOURCES_PATH, 'browser-extension'));
        }

        for (const c of candidates) {
            const manifest = path.join(c, 'manifest.json');
            if (fs.existsSync(manifest)) {
                logger.info('Found PenPard Browser branding extension', { path: c });
                return c;
            }
        }

        logger.warn('PenPard Browser branding extension not found; browser will use default Chromium icon');
        return null;
    }

    /**
     * Resolve the path to the PenPard Browser .ico file.
     * This is the icon used for Windows taskbar/titlebar override.
     */
    private resolveBrowserIconPath(): string | null {
        const candidates: string[] = [
            // Development: relative to backend/src/services → project root
            path.resolve(__dirname, '..', '..', '..', 'electron', 'assets', 'browser-icon.ico'),
        ];

        // Production (Electron packaged): extraResources or buildResources
        if (process.env.RESOURCES_PATH) {
            candidates.push(path.join(process.env.RESOURCES_PATH, 'browser-icon.ico'));
        }

        for (const c of candidates) {
            if (fs.existsSync(c)) {
                logger.info('Found PenPard Browser icon', { path: c });
                return c;
            }
        }

        logger.warn('PenPard Browser .ico not found; window icon cannot be overridden');
        return null;
    }

    /**
     * Override the window icon for a running PenPard Browser process on Windows.
     *
     * Chromium ignores the .exe icon at runtime and uses its own internal icon
     * from chrome.dll. The only way to force a custom icon is via the Windows
     * SendMessage(WM_SETICON) API after the window has been created.
     *
     * This method finds all windows belonging to the penpard_isolated.exe process
     * and overrides both the small (titlebar) and big (taskbar/alt-tab) icons.
     */
    private applyWindowsIconOverride(icoPath: string): void {
        if (process.platform !== 'win32') return;

        // Write PowerShell script to a temp file and execute it.
        // We use a file because the C# here-string syntax doesn't work inline.
        const tmpDir = path.join(os.tmpdir(), 'penpard');
        if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
        const psFile = path.join(tmpDir, 'set-browser-icon.ps1');

        const psScript = `
param([string]$IcoPath)

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class PenPardIconChanger {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadImage(IntPtr hinst, string lpszName, uint uType, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public static List<IntPtr> GetWindowsByProcessName(string processName) {
        var result = new List<IntPtr>();
        var procs = System.Diagnostics.Process.GetProcessesByName(processName);
        var pids = new HashSet<uint>();
        foreach (var p in procs) pids.Add((uint)p.Id);

        EnumWindows((hWnd, param) => {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            if (pids.Contains(pid) && IsWindowVisible(hWnd)) {
                result.Add(hWnd);
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }

    public static int SetIcon(string icoPath) {
        // Standard sizes: ICON_SMALL=16x16 for titlebar, ICON_BIG=32x32 for Alt+Tab/taskbar
        IntPtr hIconSmall = LoadImage(IntPtr.Zero, icoPath, 1, 16, 16, 0x00000010);
        IntPtr hIconBig = LoadImage(IntPtr.Zero, icoPath, 1, 32, 32, 0x00000010);
        if (hIconBig == IntPtr.Zero && hIconSmall == IntPtr.Zero) return -1;

        var windows = GetWindowsByProcessName("penpard_isolated");
        foreach (var hwnd in windows) {
            // Send ICON_SMALL first, then ICON_BIG (order matters on some Windows versions)
            if (hIconSmall != IntPtr.Zero)
                SendMessage(hwnd, 0x0080, (IntPtr)0, hIconSmall);
            if (hIconBig != IntPtr.Zero)
                SendMessage(hwnd, 0x0080, (IntPtr)1, hIconBig);
        }
        return windows.Count;
    }
}
'@

[PenPardIconChanger]::SetIcon($IcoPath)
`;

        fs.writeFileSync(psFile, psScript, 'utf8');

        // Run asynchronously with retries to handle window creation timing
        const attemptIconOverride = (attempt: number) => {
            if (attempt > 5) {
                logger.warn('PenPard Browser icon override: gave up after 5 attempts');
                return;
            }

            const delay = attempt === 1 ? 1500 : 2000;
            setTimeout(() => {
                try {
                    const result = execSync(
                        `powershell -ExecutionPolicy Bypass -NoProfile -File "${psFile}" -IcoPath "${icoPath}"`,
                        { timeout: 15000, encoding: 'utf8', windowsHide: true },
                    ).trim();

                    const windowCount = parseInt(result, 10);
                    if (windowCount > 0) {
                        logger.info(`PenPard Browser icon override applied to ${windowCount} window(s) on attempt ${attempt}`);
                    } else if (windowCount === 0) {
                        logger.debug(`PenPard Browser icon override: no visible windows on attempt ${attempt}, retrying...`);
                        attemptIconOverride(attempt + 1);
                    } else {
                        logger.warn('PenPard Browser icon override: failed to load .ico file');
                    }
                } catch (err: any) {
                    logger.warn('PenPard Browser icon override error', { error: err.message, attempt });
                    if (attempt < 5) attemptIconOverride(attempt + 1);
                }
            }, delay);
        };

        attemptIconOverride(1);
    }

    /**
     * Resolve the path to a Chromium executable.
     * Priority: PLAYWRIGHT_CHROMIUM_PATH env var → system Chrome/Chromium → bundled playwright.
     */
    private async resolveChromiumPath(): Promise<string | undefined> {
        // 1. Explicit env override
        if (process.env.PLAYWRIGHT_CHROMIUM_PATH) {
            const p = process.env.PLAYWRIGHT_CHROMIUM_PATH;
            if (fs.existsSync(p)) return p;
            logger.warn('PLAYWRIGHT_CHROMIUM_PATH set but not found', { path: p });
        }

        // 2. Check for PenPard custom patched Playwright browser (priority)
        try {
            const pwChromium = require('playwright-core').chromium;
            const defaultPwPath = pwChromium.executablePath();
            if (defaultPwPath) {
                const pathedExePath = defaultPwPath.replace(/chrome\.exe$/, 'penpard_isolated.exe');
                if (fs.existsSync(pathedExePath)) {
                    logger.info('Found PenPard-branded Chromium', { path: pathedExePath });
                    return pathedExePath;
                }
            }
        } catch (err) {
            /* ignore */
        }

        // 3. Check common system Chrome/Chromium locations
        const candidates: string[] = [];
        if (process.platform === 'win32') {
            candidates.push(
                path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
                path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
                path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'Application', 'chrome.exe'),
                path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Chromium', 'Application', 'chrome.exe'),
            );
        } else if (process.platform === 'darwin') {
            candidates.push(
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                '/Applications/Chromium.app/Contents/MacOS/Chromium',
            );
        } else {
            candidates.push(
                '/usr/bin/google-chrome',
                '/usr/bin/google-chrome-stable',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser',
                '/snap/bin/chromium',
            );
        }

        for (const c of candidates) {
            if (fs.existsSync(c)) {
                logger.info('Found system Chromium', { path: c });
                return c;
            }
        }

        // 3. Return undefined — Playwright will attempt to use its own bundled browser
        logger.info('No system Chromium found, will attempt Playwright bundled browser');
        return undefined;
    }

    /**
     * Get the Burp proxy configuration from DB settings.
     */
    private getBurpProxyConfig(): { host: string; port: number } {
        try {
            const { db } = require('../db/init');
            // First check dedicated browser proxy config
            const browserProxyRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('browser_proxy_config') as any;
            if (browserProxyRow?.value) {
                const cfg = JSON.parse(browserProxyRow.value);
                return { host: cfg.host || '127.0.0.1', port: cfg.port || 8080 };
            }

            // Fall back to burp_config host + default proxy port
            const burpRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
            if (burpRow?.value) {
                const cfg = JSON.parse(burpRow.value);
                return { host: cfg.host || '127.0.0.1', port: 8080 };
            }
        } catch { /* DB not ready */ }

        return { host: '127.0.0.1', port: 8080 };
    }

    /**
     * Launch a new browser session.
     */
    async launchSession(userId: number, options: BrowserSessionOptions = {}): Promise<string> {
        const sessionId = uuidv4();
        const proxyConfig = this.getBurpProxyConfig();
        const proxyHost = options.proxyHost || proxyConfig.host;
        const proxyPort = options.proxyPort || proxyConfig.port;
        const proxyServer = `http://${proxyHost}:${proxyPort}`;

        logger.info('Launching PenPard Browser session', {
            sessionId, proxyServer, targetUrl: options.targetUrl,
        });

        // Create DB record immediately
        createBrowserSession({
            id: sessionId,
            userId,
            scanId: options.scanId,
            findingId: options.findingId,
            targetUrl: options.targetUrl || '',
            proxyHost,
            proxyPort,
        });

        let context: BrowserContext | null = null;
        let liveSession: LiveSession | null = null;
        try {
            const executablePath = await this.resolveChromiumPath();
            const isHeadless = options.headless ?? false;

            // Resolve PenPard Browser branding extension
            const brandingExtPath = this.resolveBrandingExtensionPath();

            const launchArgs = this.buildLaunchArgs(proxyServer, brandingExtPath, isHeadless);

            // Per-session user data dir — fixes multi-browser bug.
            // Previously all sessions shared browser_profile_live, causing Chromium's
            // SingletonLock to block second launches ("chromium browser not found").
            const userDataDir = path.join(os.homedir(), '.penpard', 'browser_sessions', sessionId);
            if (!fs.existsSync(userDataDir)) fs.mkdirSync(userDataDir, { recursive: true });

            const targetOrigin = this.getTargetOrigin(options.targetUrl);
            const jsArtifactsDir = options.scanId ? this.ensureJsArtifactsDir(options.scanId, sessionId) : null;
            context = await chromium.launchPersistentContext(userDataDir, {
                headless: isHeadless,
                executablePath,
                args: launchArgs,
                ignoreHTTPSErrors: true,
                proxy: { server: proxyServer },
                viewport: isHeadless ? { width: 1280, height: 720 } : null,
            });

            // ── Windows Icon Override ──
            // Chromium's chrome.dll overrides the .exe icon at runtime.
            // We counter this by sending WM_SETICON messages to force PenPard branding.
            const browserIcoPath = this.resolveBrowserIconPath();
            if (browserIcoPath) {
                this.applyWindowsIconOverride(browserIcoPath);
            }

            // launchPersistentContext natively creates one empty page by default
            const pages = context.pages();
            const page = pages.length > 0 ? pages[0] : await context.newPage();

            // Store live session (Playwright's persistent context exposes its underlying browser instance natively)
            liveSession = {
                browser: context.browser() || (context as any), // Fallback map
                context,
                page,
                sessionId,
                userId,
                userDataDir,
                scanId: options.scanId,
                targetUrl: options.targetUrl,
                targetOrigin,
                isHeadless,
                proxyServer,
                executablePath: executablePath || '',
                brandingExtPath,
                transitioning: false,
                lifecycleState: deriveActiveBrowserLifecycleState(isHeadless, !isHeadless),
                lifecycleDetail: null,
                lastError: null,
                lastKnownUrl: null,
                lastKnownTitle: null,
                hasBeenVisible: !isHeadless,
                generation: 1,
                networkEvents: [],
                nextTrafficEventId: 1,
                jsArtifacts: new Map(),
                jsArtifactsDir,
            };
            this.updateLastKnownPageState(liveSession, page);
            this.sessions.set(sessionId, liveSession);

            // ── Event Listeners ──

            this.attachSessionListeners(sessionId, page, context, liveSession.generation);

            // Navigate to target URL if provided
            if (options.targetUrl) {
                await page.goto(options.targetUrl, {
                    waitUntil: 'domcontentloaded',
                    timeout: 30000,
                }).catch((err: any) => {
                    logger.warn('Initial navigation warning (may be proxy-related)', {
                        sessionId, error: err.message,
                    });
                });
            }

            // Update status to active
            const currentUrl = this.safePageUrl(liveSession) || 'about:blank';
            updateBrowserSession(sessionId, {
                status: 'active',
                lifecycle_state: liveSession.lifecycleState,
                lifecycle_detail: null,
                last_error: null,
                closed_at: null,
                current_url: currentUrl,
                mode: 'human',
            });

            addBrowserAction({
                sessionId,
                actionType: 'navigate',
                actionData: JSON.stringify({ url: options.targetUrl || 'about:blank' }),
                pageUrl: currentUrl,
                pageTitle: '',
                source: 'system',
            });

            logger.info('PenPard Browser session launched', {
                sessionId, proxyServer, currentUrl,
            });

            return sessionId;

        } catch (error: any) {
            logger.error('Failed to launch browser session', {
                sessionId, error: error.message,
            });
            if (context) {
                try {
                    await context.close();
                } catch {
                    /* ignore */
                }
            }
            if (liveSession) {
                this.sessions.delete(sessionId);
                liveSession.browser = null;
                liveSession.context = null;
                liveSession.page = null;
            }
            dbCloseSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: 'Browser launch failed',
                last_error: error.message,
                current_url: options.targetUrl || null,
            });
            throw error;
        }
    }

    /**
     * Execute an AI-driven action on a browser session.
     */
    async executeAction(sessionId: string, action: BrowserAction): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, `execute browser action "${action.type}"`);
        const { page } = session;
        let result: any = null;

        // Update mode to reflect AI control
        updateBrowserSession(sessionId, {
            mode: 'ai',
            last_activity_at: new Date().toISOString(),
        });

        try {
            switch (action.type) {
                case 'goto': {
                    if (!action.url) throw new Error('URL required for goto action');
                    if (this.isPenPardInternalUrl(action.url, session.targetOrigin)) {
                        throw new Error(`Blocked navigation to internal PenPard origin: ${action.url}`);
                    }
                    await page.goto(action.url, {
                        waitUntil: 'domcontentloaded',
                        timeout: action.timeout || 30000,
                    });
                    result = { url: page.url(), title: await page.title() };
                    break;
                }

                case 'click': {
                    if (!action.selector) throw new Error('Selector required for click action');
                    await page.click(action.selector, { timeout: action.timeout || 10000 });
                    result = { clicked: action.selector };
                    break;
                }

                case 'fill': {
                    if (!action.selector || action.value === undefined) {
                        throw new Error('Selector and value required for fill action');
                    }
                    await page.fill(action.selector, action.value, { timeout: action.timeout || 10000 });
                    result = { filled: action.selector, value: action.value };
                    break;
                }

                case 'select': {
                    if (!action.selector || !action.value) {
                        throw new Error('Selector and value required for select action');
                    }
                    await page.selectOption(action.selector, action.value, { timeout: action.timeout || 10000 });
                    result = { selected: action.selector, value: action.value };
                    break;
                }

                case 'submit': {
                    if (!action.selector) throw new Error('Selector required for submit action');
                    await page.click(action.selector, { timeout: action.timeout || 10000 });
                    await page.waitForLoadState('domcontentloaded').catch(() => { });
                    result = { submitted: action.selector, url: page.url() };
                    break;
                }

                case 'evaluate': {
                    if (!action.script) throw new Error('Script required for evaluate action');
                    result = await page.evaluate(action.script);
                    break;
                }

                case 'waitForNavigation': {
                    await page.waitForLoadState('networkidle', { timeout: action.timeout || 30000 });
                    result = { url: page.url(), title: await page.title() };
                    break;
                }

                case 'waitForSelector': {
                    if (!action.selector) throw new Error('Selector required for waitForSelector');
                    await page.waitForSelector(action.selector, { timeout: action.timeout || 10000 });
                    result = { found: action.selector };
                    break;
                }

                case 'screenshot': {
                    const buffer = await page.screenshot({ type: 'png', fullPage: false });
                    result = { screenshot: buffer.toString('base64'), mimeType: 'image/png' };
                    break;
                }

                case 'back': {
                    await page.goBack({ timeout: action.timeout || 10000 });
                    result = { url: page.url() };
                    break;
                }

                case 'forward': {
                    await page.goForward({ timeout: action.timeout || 10000 });
                    result = { url: page.url() };
                    break;
                }

                case 'reload': {
                    await page.reload({ timeout: action.timeout || 30000 });
                    result = { url: page.url() };
                    break;
                }

                default:
                    throw new Error(`Unknown action type: ${(action as any).type}`);
            }

            this.updateLastKnownPageState(session, page);

            // Log the action
            addBrowserAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify(action),
                pageUrl: this.safePageUrl(session) || undefined,
                pageTitle: await page.title().catch(() => ''),
                source: 'ai',
            });

            // Update session state
            updateBrowserSession(sessionId, {
                current_url: this.safePageUrl(session),
                last_activity_at: this.now(),
            });

            return result;

        } catch (error: any) {
            const maybeLifecycleError = /Target page, context or browser has been closed|Target closed|Browser has been closed|closed|crash/i.test(error.message || '');
            if (maybeLifecycleError) {
                this.invalidateSession(
                    sessionId,
                    session.isHeadless ? 'stale_reference' : 'manually_closed',
                    session.isHeadless ? 'Browser action hit a dead browser handle' : 'Visible browser window disappeared during browser action',
                    error.message,
                );
            }
            // Log failed action
            addBrowserAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify({ ...action, error: error.message }),
                pageUrl: this.safePageUrl(session) || undefined,
                pageTitle: '',
                source: 'ai',
            });
            throw error;
        }
    }

    /**
     * Get current page state for AI inspection.
     */
    async getPageState(sessionId: string): Promise<PageState> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'inspect the current page');
        const { page } = session;

        // Use string evaluate to avoid TS dom lib requirement (runs in browser context)
        const state = await page.evaluate(`(() => {
            const forms = Array.from(document.querySelectorAll('form')).slice(0, 20).map(form => ({
                action: form.action || '',
                method: (form.method || 'get').toUpperCase(),
                fields: Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 30).map(field => ({
                    name: field.name || '',
                    type: field.type || field.tagName.toLowerCase(),
                    id: field.id || '',
                })),
            }));
            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 50).map(a => ({
                href: a.href || '',
                text: (a.textContent || '').trim().substring(0, 100),
            }));
            const bodyText = document.body ? document.body.innerText : '';
            const textSummary = bodyText.substring(0, 2000);
            return { forms, links, textSummary };
        })()`) as { forms: any[]; links: any[]; textSummary: string };

        return {
            url: this.safePageUrl(session) || 'about:blank',
            title: await page.title(),
            ...state,
        };
    }

    /**
     * Capture a screenshot of the current page.
     */
    async captureScreenshot(sessionId: string): Promise<{ base64: string; mimeType: string }> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'capture a screenshot');

        const buffer = await session.page.screenshot({ type: 'png', fullPage: false });
        this.updateLastKnownPageState(session);

        addBrowserAction({
            sessionId,
            actionType: 'screenshot',
            actionData: JSON.stringify({ timestamp: new Date().toISOString() }),
            pageUrl: this.safePageUrl(session) || undefined,
            pageTitle: await session.page.title().catch(() => ''),
            source: 'ai',
        });

        return { base64: buffer.toString('base64'), mimeType: 'image/png' };
    }

    /**
     * Get live session info (combines DB + in-memory state).
     */
    async getSessionInfo(sessionId: string): Promise<any> {
        const dbSession = getBrowserSession(sessionId);
        if (!dbSession) return null;

        const liveSession = this.sessions.get(sessionId);
        if (liveSession) {
            const visibility = this.buildVisibilityState(liveSession);
            dbSession.current_url = visibility.lastKnownUrl || dbSession.current_url;
            dbSession.title = await this.safePageTitle(liveSession);
            dbSession.isLive = visibility.isLive;
            dbSession.lifecycle_state = liveSession.lifecycleState;
            dbSession.lifecycle_detail = liveSession.lifecycleDetail;
            dbSession.last_error = liveSession.lastError;
            dbSession.runtime = visibility;
        } else {
            dbSession.isLive = false;
        }

        return dbSession;
    }

    /**
     * Close a browser session.
     */
    async closeSession(sessionId: string): Promise<void> {
        const session = this.sessions.get(sessionId);

        if (!session) {
            dbCloseSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: 'Close requested after runtime already ended',
                last_error: null,
            });
            logger.info('Browser session closed', { sessionId, alreadyInactive: true });
            return;
        }

        if (session.lifecycleState === 'closed' && !session.browser && !session.context && !session.page) {
            dbCloseSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: session.lifecycleDetail || 'Session was already closed',
                last_error: session.lastError,
                current_url: this.safePageUrl(session),
            });
            return;
        }

        session.transitioning = true;
        session.generation += 1;
        this.updateLifecycleState(sessionId, session, 'closing', {
            detail: 'Session cleanup requested',
            status: 'closed',
            currentUrl: this.safePageUrl(session),
            preserveTransitioning: true,
        });

        const browser = session.browser;
        const context = session.context;
        session.browser = null;
        session.context = null;
        session.page = null;

        if (browser) {
            try {
                await browser.close();
            } catch (e: any) {
                logger.warn('Error closing browser', { sessionId, error: e.message });
            }
        } else if (context) {
            try {
                await context.close();
            } catch (e: any) {
                logger.warn('Error closing browser context', { sessionId, error: e.message });
            }
        }

        this.updateLifecycleState(sessionId, session, 'closed', {
            detail: 'Session cleanup completed',
            status: 'closed',
            currentUrl: this.safePageUrl(session),
            closedAt: this.now(),
        });
        dbCloseSession(sessionId, {
            lifecycle_state: 'closed',
            lifecycle_detail: 'Session cleanup completed',
            last_error: session.lastError,
            current_url: this.safePageUrl(session),
        });
        logger.info('Browser session closed', { sessionId });
    }

    /**
     * Check if a session is alive in-memory (simple check).
     * A more robust version with context validation is available below.
     */
    isSessionAliveSimple(sessionId: string): boolean {
        return this.sessions.has(sessionId);
    }

    /**
     * Get count of active sessions.
     */
    getActiveSessionCount(): number {
        let count = 0;
        for (const session of this.sessions.values()) {
            if (this.buildVisibilityState(session).isLive) {
                count += 1;
            }
        }
        return count;
    }

    /**
     * Clean up all sessions (on server shutdown).
     */
    async cleanup(): Promise<void> {
        logger.info('Cleaning up all browser sessions', { count: this.sessions.size });
        for (const [sessionId] of this.sessions) {
            await this.closeSession(sessionId);
        }
    }

    // ══════════════════════════════════════════════════════════
    //  FRONTEND ANALYSIS — AI-usable browser intelligence
    // ══════════════════════════════════════════════════════════

    /**
     * Deep page state: DOM summary, scripts, meta, cookies, storage.
     */
    async getFullPageState(sessionId: string): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'inspect loaded scripts');
        const { page, context } = session;

        const state = await page.evaluate(`(async () => {
            const allElements = document.querySelectorAll('*');
            const tagCounts = {};
            allElements.forEach(el => { tagCounts[el.tagName] = (tagCounts[el.tagName] || 0) + 1; });

            const sanitize = (value, limit = 500) => String(value || '').trim().substring(0, limit);
            const escapeCss = (value) => {
                if (!value) return '';
                if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(value);
                return String(value).replace(/([ #;?%&,.+*~\\':"!^$\\[\\]()=>|/@])/g, '\\\\$1');
            };
            const getSelector = (el) => {
                if (!el || !el.tagName) return '';
                if (el.id) return '#' + escapeCss(el.id);
                if (el.name) return el.tagName.toLowerCase() + '[name="' + escapeCss(el.name) + '"]';
                if (el.getAttribute && el.getAttribute('data-testid')) {
                    return el.tagName.toLowerCase() + '[data-testid="' + escapeCss(el.getAttribute('data-testid')) + '"]';
                }
                const parts = [];
                let current = el;
                let depth = 0;
                while (current && current.nodeType === Node.ELEMENT_NODE && depth < 4) {
                    const tag = current.tagName.toLowerCase();
                    let part = tag;
                    if (current.classList && current.classList.length > 0) {
                        part += '.' + Array.from(current.classList).slice(0, 2).map(escapeCss).join('.');
                    }
                    const siblings = current.parentElement ? Array.from(current.parentElement.children).filter(child => child.tagName === current.tagName) : [];
                    if (siblings.length > 1) {
                        part += ':nth-of-type(' + (siblings.indexOf(current) + 1) + ')';
                    }
                    parts.unshift(part);
                    current = current.parentElement;
                    depth++;
                }
                return parts.join(' > ');
            };
            const getFieldLabel = (field) => {
                if (!field) return '';
                const aria = field.getAttribute('aria-label');
                if (aria) return sanitize(aria, 120);
                if (field.id) {
                    const explicit = document.querySelector('label[for="' + field.id.replace(/"/g, '\\\\"') + '"]');
                    if (explicit) return sanitize(explicit.textContent, 120);
                }
                const wrapped = field.closest('label');
                if (wrapped) return sanitize(wrapped.textContent, 120);
                return '';
            };

            const forms = Array.from(document.querySelectorAll('form')).slice(0, 30).map((form, formIndex) => {
                const fields = Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 50).map(field => ({
                    name: field.name || '',
                    type: field.type || field.tagName.toLowerCase(),
                    id: field.id || '',
                    value: field.type === 'hidden' ? sanitize(field.value, 300) : '',
                    placeholder: field.placeholder || '',
                    autocomplete: field.autocomplete || '',
                    required: !!field.required,
                    label: getFieldLabel(field),
                    selector: getSelector(field),
                }));
                const hiddenInputs = fields.filter(field => field.type === 'hidden');
                const submitElements = Array.from(form.querySelectorAll('button, input[type="submit"], input[type="button"]')).slice(0, 10).map(button => ({
                    selector: getSelector(button),
                    tagName: button.tagName.toLowerCase(),
                    text: sanitize(button.innerText || button.value || button.textContent, 120),
                    type: button.type || button.tagName.toLowerCase(),
                }));
                const inlineValidation = Array.from(form.querySelectorAll('[aria-live], .error, .invalid-feedback, .form-error, [data-error], [role="alert"]'))
                    .slice(0, 20)
                    .map(node => sanitize(node.textContent, 160))
                    .filter(Boolean);

                return {
                    action: form.action || '',
                    method: (form.method || 'get').toUpperCase(),
                    id: form.id || ('form-' + (formIndex + 1)),
                    name: form.name || '',
                    selector: getSelector(form),
                    fields,
                    hiddenInputs,
                    submitElements,
                    inlineValidation,
                };
            });

            const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]')).slice(0, 100).map(el => ({
                name: el.name || '',
                id: el.id || '',
                value: sanitize(el.value, 300),
                form: el.form ? (el.form.id || el.form.action || 'unnamed-form') : 'no-form',
                selector: getSelector(el),
            }));

            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 120).map(a => ({
                href: a.href || '',
                text: sanitize(a.textContent, 120),
                selector: getSelector(a),
            }));

            const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="button"], input[type="submit"]'))
                .slice(0, 120)
                .map(button => ({
                    selector: getSelector(button),
                    tagName: button.tagName.toLowerCase(),
                    text: sanitize(button.innerText || button.value || button.textContent, 120),
                    type: button.type || button.tagName.toLowerCase(),
                    formId: button.form ? (button.form.id || button.form.action || '') : '',
                }));

            const metaTags = Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.name || m.httpEquiv || m.getAttribute('property') || '',
                content: sanitize(m.content, 500),
            }));

            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || '',
                type: s.type || '',
                isInline: !s.src,
                contentPreview: !s.src ? sanitize(s.textContent, 500) : '',
                contentLength: !s.src ? (s.textContent || '').length : 0,
            }));

            let localStorageData = {};
            try {
                for (let i = 0; i < localStorage.length && i < 50; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = sanitize(localStorage.getItem(key), 500);
                }
            } catch {}

            let sessionStorageData = {};
            try {
                for (let i = 0; i < sessionStorage.length && i < 50; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = sanitize(sessionStorage.getItem(key), 500);
                }
            } catch {}

            let indexedDbNames = [];
            try {
                if (window.indexedDB && typeof window.indexedDB.databases === 'function') {
                    const dbs = await window.indexedDB.databases();
                    indexedDbNames = dbs.map(db => sanitize(db && db.name, 120)).filter(Boolean);
                }
            } catch {}

            const antiAutomationMarkers = [
                ...Array.from(document.querySelectorAll('[data-sitekey], iframe[src*="captcha"], script[src*="turnstile"], [class*="captcha"], [id*="captcha"], [name*="captcha"]'))
                    .slice(0, 20)
                    .map(node => sanitize(node.getAttribute('class') || node.getAttribute('id') || node.tagName, 160)),
            ].filter(Boolean);

            const bodyText = document.body ? document.body.innerText : '';
            return {
                tagCounts,
                totalElements: allElements.length,
                forms,
                hiddenInputs,
                links,
                buttons,
                metaTags,
                scripts,
                cookies: document.cookie,
                localStorageData,
                sessionStorageData,
                indexedDbNames,
                antiAutomationMarkers,
                textSummary: bodyText.substring(0, 3000),
            };
        })()`);

        // Also get Playwright-level cookies for the context
        let contextCookies: any[] = [];
        try { contextCookies = await context.cookies(); } catch { /* ignore */ }

        return {
            url: this.safePageUrl(session) || 'about:blank',
            title: await page.title(),
            ...(state as any),
            contextCookies,
        };
    }

    /**
     * Loaded scripts analysis — all script tags with URLs and inline content.
     */
    async getLoadedScripts(sessionId: string): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'capture JavaScript artifacts');

        return await session.page.evaluate(`(() => {
            const MAX_INLINE_LENGTH = 25000;
            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || null,
                type: s.type || 'text/javascript',
                async: s.async,
                defer: s.defer,
                isModule: s.type === 'module',
                isInline: !s.src,
                content: !s.src ? (s.textContent || '').substring(0, MAX_INLINE_LENGTH) : null,
                contentPreview: !s.src ? (s.textContent || '').substring(0, 2000) : null,
                contentLength: !s.src ? (s.textContent || '').length : null,
            }));
            // Also check link preloads for JS
            const preloads = Array.from(document.querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')).map(l => ({
                href: l.href || '',
                rel: l.rel || '',
                as: l.getAttribute('as') || '',
            }));
            return { scripts, preloads, totalScripts: scripts.length };
        })()`);
    }

    async captureJavaScriptArtifacts(sessionId: string): Promise<CapturedJsArtifact[]> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'capture JavaScript artifacts');

        const loadedScripts = await this.getLoadedScripts(sessionId);
        const pageUrl = this.safePageUrl(session) || 'about:blank';

        for (const script of Array.isArray(loadedScripts?.scripts) ? loadedScripts.scripts : []) {
            if (script?.isInline && typeof script.content === 'string' && script.content.trim()) {
                await this.persistJsArtifact(session, {
                    type: 'inline',
                    pageUrl,
                    contentType: script.type || 'application/javascript',
                    content: script.content,
                    evidence: ['inline-script', `bytes=${script.contentLength || script.content.length}`],
                });
            }
        }

        return Array.from(session.jsArtifacts.values());
    }

    getCapturedJavaScriptArtifacts(sessionId: string): CapturedJsArtifact[] {
        const session = this.sessions.get(sessionId);
        if (!session) return [];
        return Array.from(session.jsArtifacts.values());
    }

    /**
     * Comprehensive frontend intelligence extraction.
     * Finds API endpoints, GraphQL, WebSockets, tokens, CSRF, routing patterns.
     */
    async getFrontendAnalysis(sessionId: string): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'analyze the frontend');
        await this.captureJavaScriptArtifacts(sessionId).catch(() => {});

        return await session.page.evaluate(`(() => {
            const results = {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: [],
                hiddenParams: [],
                inlineScriptInsights: [],
            };

            // Gather all inline script content
            const allScriptContent = Array.from(document.querySelectorAll('script:not([src])'))
                .map(s => s.textContent || '').join('\\n');

            // Also gather script src URLs
            const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src);

            // 1. API endpoints — regex patterns in inline JS
            const apiPatterns = [
                /["'\`](\\/api\\/[^"'\`\\s]{2,80})["'\`]/g,
                /["'\`](https?:\\/\\/[^"'\`\\s]*\\/api\\/[^"'\`\\s]{2,120})["'\`]/g,
                /fetch\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /axios\\.[a-z]+\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /\\.(?:get|post|put|delete|patch)\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /XMLHttpRequest[^]*?\\.open\\s*\\(\\s*["'][A-Z]+["']\\s*,\\s*["'\`]([^"'\`]+)["'\`]/g,
                /url\\s*[:=]\\s*["'\`](\\/[^"'\`\\s]{2,80})["'\`]/g,
                /endpoint\\s*[:=]\\s*["'\`]([^"'\`\\s]{2,80})["'\`]/g,
            ];
            const foundEndpoints = new Set();
            for (const pat of apiPatterns) {
                let m;
                while ((m = pat.exec(allScriptContent)) !== null) {
                    const ep = m[1];
                    if (ep && !ep.includes('{{') && ep.length < 200) foundEndpoints.add(ep);
                }
            }
            results.apiEndpoints = [...foundEndpoints].slice(0, 100);

            // 2. GraphQL indicators
            if (allScriptContent.includes('graphql') || allScriptContent.includes('GraphQL') ||
                allScriptContent.includes('__schema') || allScriptContent.includes('mutation ') ||
                allScriptContent.includes('query {')) {
                results.graphqlIndicators.push('GraphQL usage detected in inline scripts');
                const gqlUrlMatch = allScriptContent.match(/["'\`]([^"'\`]*graphql[^"'\`]*)["'\`]/gi);
                if (gqlUrlMatch) results.graphqlIndicators.push(...gqlUrlMatch.slice(0, 10).map(s => s.replace(/["'\`]/g, '')));
            }
            // Check script srcs
            scriptSrcs.forEach(src => {
                if (src.toLowerCase().includes('graphql')) results.graphqlIndicators.push('GraphQL script: ' + src);
            });

            // 3. WebSocket URLs
            const wsPatterns = /["'\`](wss?:\\/\\/[^"'\`\\s]+)["'\`]/g;
            let wsMatch;
            while ((wsMatch = wsPatterns.exec(allScriptContent)) !== null) {
                results.websocketUrls.push(wsMatch[1]);
            }
            if (allScriptContent.includes('new WebSocket')) results.websocketUrls.push('WebSocket constructor usage detected');

            // 4. Token patterns (JWT, Bearer, etc.)
            if (allScriptContent.match(/bearer/i)) results.tokenPatterns.push('Bearer token pattern detected');
            if (allScriptContent.match(/localStorage\\.getItem\\s*\\(\\s*["'\`](token|access_token|auth_token|jwt)/i))
                results.tokenPatterns.push('Token stored in localStorage');
            if (allScriptContent.match(/sessionStorage\\.getItem\\s*\\(\\s*["'\`](token|access_token|auth_token|jwt)/i))
                results.tokenPatterns.push('Token stored in sessionStorage');
            const jwtInStorage = [];
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    const v = k ? localStorage.getItem(k) : '';
                    if (v && v.match(/^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+/)) {
                        jwtInStorage.push({ key: k, location: 'localStorage', preview: v.substring(0, 80) + '...' });
                    }
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    const v = k ? sessionStorage.getItem(k) : '';
                    if (v && v.match(/^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+/)) {
                        jwtInStorage.push({ key: k, location: 'sessionStorage', preview: v.substring(0, 80) + '...' });
                    }
                }
            } catch(e) {}
            if (jwtInStorage.length > 0) results.tokenPatterns.push(...jwtInStorage.map(j => j.location + ':' + j.key + ' = ' + j.preview));

            // 5. CSRF tokens
            const csrfInputs = document.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name*="_token"], meta[name*="csrf"]');
            csrfInputs.forEach(el => {
                results.csrfTokens.push({
                    name: el.getAttribute('name') || el.getAttribute('property') || '',
                    value: (el.getAttribute('value') || el.getAttribute('content') || '').substring(0, 100),
                    tag: el.tagName,
                });
            });

            // 6. Frontend routes (React Router, Vue Router, Next.js patterns)
            const routePatterns = /(?:path|route)\\s*[:=]\\s*["'\`](\\/[^"'\`]{1,80})["'\`]/g;
            let routeMatch;
            const foundRoutes = new Set();
            while ((routeMatch = routePatterns.exec(allScriptContent)) !== null) {
                foundRoutes.add(routeMatch[1]);
            }
            results.frontendRoutes = [...foundRoutes].slice(0, 50);

            // 7. Hidden params (data attributes, hidden inputs outside forms)
            const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
            hiddenInputs.forEach(inp => {
                results.hiddenParams.push({
                    name: inp.name || '',
                    value: (inp.value || '').substring(0, 200),
                    id: inp.id || '',
                });
            });

            return results;
        })()`);
    }

    /**
     * Dump session storage: cookies, localStorage, sessionStorage.
     */
    async getSessionStorageData(sessionId: string): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'read browser storage');

        const browserStorage = await session.page.evaluate(`(() => {
            let localStorageData = {};
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = localStorage.getItem(key);
                }
            } catch(e) {}
            let sessionStorageData = {};
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = sessionStorage.getItem(key);
                }
            } catch(e) {}
            return { cookies: document.cookie, localStorageData, sessionStorageData };
        })()`);

        let contextCookies: any[] = [];
        try { contextCookies = await session.context.cookies(); } catch { /* ignore */ }

        return { url: this.safePageUrl(session) || 'about:blank', ...(browserStorage as any), contextCookies };
    }

    /**
     * Push cookies into a live browser context.
     * Used to keep the browser aligned with backend-side session refreshes.
     */
    async syncCookiesToSession(sessionId: string, cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>): Promise<number> {
        const session = this.assertReadySession(sessionId, 'sync cookies into the browser session');
        if (!cookies.length) return 0;

        await session.context.addCookies(cookies as any);
        updateBrowserSession(sessionId, {
            last_activity_at: new Date().toISOString(),
        });

        addBrowserAction({
            sessionId,
            actionType: 'sync_cookies',
            actionData: JSON.stringify({ count: cookies.length }),
            pageUrl: this.safePageUrl(session) || undefined,
            pageTitle: await session.page.title().catch(() => ''),
            source: 'system',
        });

        return cookies.length;
    }

    getTrafficSnapshot(sessionId: string): BrowserTrafficEvent[] {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);
        return [...session.networkEvents];
    }

    /**
     * Correlate browser-visible state with Burp MCP proxy history.
     * Merges what the browser sees with what Burp intercepted.
     */
    async correlateBrowserWithBurp(sessionId: string): Promise<any> {
        const session = await this.waitForSessionReady(sessionId, 15000, 'correlate browser traffic with Burp');

        // Get browser state
        const currentUrl = this.safePageUrl(session) || 'about:blank';
        let host = '';
        try { host = new URL(currentUrl).hostname; } catch { /* ignore */ }

        // Get Burp proxy history via MCP
        let burpHistory: any[] = [];
        let burpAvailable = false;
        try {
            const { burpMCP } = require('./burp-mcp');
            burpAvailable = await burpMCP.isAvailable();
            if (burpAvailable) {
                const result = await burpMCP.callTool('get_proxy_history', { count: 50, excludePenPard: true });
                burpHistory = normalizeProxyHistoryItems(result);
            }
        } catch (e: any) {
            logger.warn('Burp MCP correlation failed', { error: e.message });
        }

        // Get browser action log
        const actions = getBrowserActions(sessionId);
        const browserTraffic = this.getTrafficSnapshot(sessionId);

        // Match browser URLs with Burp history
        const matchedRequests = burpHistory.filter((entry: any) => {
            const entryUrl = entry.url || '';
            try {
                const entryHost = new URL(entryUrl).hostname;
                return entryHost === host &&
                    !this.isPenPardInternalUrl(entryUrl, session.targetOrigin) &&
                    !/\/socket\.io\/|\/sockjs\/|\/__webpack_hmr|transport=polling/i.test(entryUrl);
            } catch { return false; }
        });

        // Extract unique endpoints from Burp for this host
        const burpEndpoints = [...new Set(matchedRequests.map((r: any) => {
            try { return new URL(r.url).pathname; } catch { return r.url; }
        }))];

        // Get frontend-discovered API endpoints
        let frontendEndpoints: string[] = [];
        try {
            const analysis = await this.getFrontendAnalysis(sessionId);
            frontendEndpoints = analysis.apiEndpoints || [];
        } catch { /* ignore */ }

        // Find endpoints visible in frontend JS but NOT seen in Burp traffic
        const burpPathSet = new Set(burpEndpoints);
        const frontendOnly = frontendEndpoints.filter(ep => !burpPathSet.has(ep));

        return {
            burpAvailable,
            currentUrl,
            host,
            browserActionsCount: actions.length,
            browserTrafficCount: browserTraffic.length,
            burpRequestsForHost: matchedRequests.length,
            totalBurpHistory: burpHistory.length,
            matchedRequests: matchedRequests.slice(0, 30).map((r: any) => ({
                method: r.method,
                url: r.url,
                status: r.status,
                mimeType: r.mimeType,
            })),
            browserTraffic: browserTraffic.slice(-30),
            burpEndpoints,
            frontendEndpoints,
            frontendOnlyEndpoints: frontendOnly,
            insight: frontendOnly.length > 0
                ? `Found ${frontendOnly.length} API endpoint(s) in frontend JavaScript that have NOT been seen in Burp traffic. These may be untested attack surface.`
                : 'All frontend-discovered endpoints match Burp traffic.',
        };
    }

    /**
     * Compare two browser sessions — for IDOR, BAC, multi-user testing.
     */
    async compareSessionStates(sessionIdA: string, sessionIdB: string): Promise<any> {
        await this.waitForSessionReady(sessionIdA, 15000, 'compare browser sessions');
        await this.waitForSessionReady(sessionIdB, 15000, 'compare browser sessions');

        const [stateA, stateB] = await Promise.all([
            this.getSessionStorageData(sessionIdA),
            this.getSessionStorageData(sessionIdB),
        ]);

        // Compare cookies
        const cookiesA = new Set((stateA.contextCookies || []).map((c: any) => `${c.name}=${c.value}`));
        const cookiesB = new Set((stateB.contextCookies || []).map((c: any) => `${c.name}=${c.value}`));
        const sharedCookies = [...cookiesA].filter(c => cookiesB.has(c));
        const onlyA = [...cookiesA].filter(c => !cookiesB.has(c));
        const onlyB = [...cookiesB].filter(c => !cookiesA.has(c));

        // Compare localStorage keys
        const lsKeysA = Object.keys(stateA.localStorageData || {});
        const lsKeysB = Object.keys(stateB.localStorageData || {});
        const lsDiffs: any[] = [];
        const allLsKeys = new Set([...lsKeysA, ...lsKeysB]);
        allLsKeys.forEach(key => {
            const vA = stateA.localStorageData?.[key];
            const vB = stateB.localStorageData?.[key];
            if (vA !== vB) lsDiffs.push({ key, sessionA: vA || '(missing)', sessionB: vB || '(missing)' });
        });

        return {
            sessionA: { id: sessionIdA, url: stateA.url },
            sessionB: { id: sessionIdB, url: stateB.url },
            urlMatch: stateA.url === stateB.url,
            cookies: {
                sharedCount: sharedCookies.length,
                onlyInA: onlyA.length,
                onlyInB: onlyB.length,
                onlyInAList: onlyA.slice(0, 20),
                onlyInBList: onlyB.slice(0, 20),
                isolated: onlyA.length > 0 || onlyB.length > 0,
            },
            localStorage: {
                differencesCount: lsDiffs.length,
                differences: lsDiffs.slice(0, 20),
            },
            insight: (onlyA.length > 0 || onlyB.length > 0)
                ? 'Sessions have different cookies — session isolation is working. Suitable for IDOR/BAC testing.'
                : 'Sessions share identical cookies — may need different login states for access control testing.',
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  Session Health & Visibility Toggle
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if a session exists and its underlying Playwright context is still connected.
     */
    isSessionAlive(sessionId: string): boolean {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        try {
            this.assertReadySession(sessionId, 'check whether the browser session is alive');
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Get the current headless state of a session.
     */
    getSessionVisibility(sessionId: string): BrowserSessionVisibility | null {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        this.isSessionAlive(sessionId);
        return this.buildVisibilityState(session);
    }

    /**
     * Show a headless browser session — relaunch visible using the same userDataDir.
     * Cookies, localStorage, and sessionStorage are preserved via the persistent profile.
     */
    async showBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return await this.toggleVisibility(sessionId, false);
    }

    /**
     * Hide a visible browser session — relaunch headless using the same userDataDir.
     */
    async hideBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return await this.toggleVisibility(sessionId, true);
    }

    private async relaunchUnavailableSession(session: LiveSession, targetHeadless: boolean): Promise<BrowserVisibilityResult> {
        const label = targetHeadless ? 'headless' : 'visible';
        const priorState = session.lifecycleState;
        const priorDetail = session.lifecycleDetail;
        let newContext: BrowserContext | null = null;

        session.transitioning = true;
        updateBrowserSession(session.sessionId, {
            last_activity_at: this.now(),
            last_error: null,
        });

        try {
            const launchArgs = this.buildLaunchArgs(session.proxyServer, session.brandingExtPath, targetHeadless);
            if (!fs.existsSync(session.userDataDir)) {
                fs.mkdirSync(session.userDataDir, { recursive: true });
            }

            newContext = await chromium.launchPersistentContext(session.userDataDir, {
                headless: targetHeadless,
                executablePath: session.executablePath || undefined,
                args: launchArgs,
                ignoreHTTPSErrors: true,
                proxy: { server: session.proxyServer },
                viewport: targetHeadless ? { width: 1280, height: 720 } : null,
            });

            const pages = newContext.pages();
            const newPage = pages.length > 0 ? pages[0] : await newContext.newPage();
            const restoreUrl = (() => {
                const preferred = session.lastKnownUrl || session.targetUrl || 'about:blank';
                if (preferred === 'about:blank') return preferred;
                return this.isPenPardInternalUrl(preferred, session.targetOrigin)
                    ? (session.targetUrl || 'about:blank')
                    : preferred;
            })();

            if (restoreUrl && restoreUrl !== 'about:blank') {
                try {
                    await newPage.goto(restoreUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
                } catch (navErr: any) {
                    logger.warn('Could not restore URL while relaunching unavailable browser session (non-fatal)', {
                        sessionId: session.sessionId,
                        restoreUrl,
                        error: navErr.message,
                    });
                }
            }

            session.browser = newContext.browser() || (newContext as any);
            session.context = newContext;
            session.page = newPage;
            session.isHeadless = targetHeadless;
            session.transitioning = false;
            session.generation += 1;
            session.lastError = null;
            this.updateLastKnownPageState(session, newPage);
            this.attachSessionListeners(session.sessionId, newPage, newContext, session.generation);
            this.updateLifecycleState(
                session.sessionId,
                session,
                deriveActiveBrowserLifecycleState(targetHeadless, session.hasBeenVisible || !targetHeadless),
                {
                    status: 'active',
                    currentUrl: this.safePageUrl(session),
                    closedAt: null,
                },
            );

            if (!targetHeadless) {
                const browserIcoPath = this.resolveBrowserIconPath();
                if (browserIcoPath) {
                    this.applyWindowsIconOverride(browserIcoPath);
                }
            }

            return {
                ...this.buildVisibilityState(session),
                message: targetHeadless ? 'Browser relaunched in headless mode' : 'Browser window reopened',
                reopened: true,
            };
        } catch (error: any) {
            if (newContext) {
                try {
                    await newContext.close();
                } catch {
                    /* ignore */
                }
            }
            session.transitioning = false;
            session.lifecycleState = priorState;
            session.lifecycleDetail = priorDetail;
            session.lastError = error.message;
            updateBrowserSession(session.sessionId, {
                lifecycle_state: priorState,
                lifecycle_detail: priorDetail,
                last_error: error.message,
                last_activity_at: this.now(),
            });
            logger.error(`Failed to relaunch ${label} browser session`, { sessionId: session.sessionId, error: error.message });
            throw new Error(`Visibility toggle failed: ${error.message}`);
        }
    }

    /**
     * Core relaunch logic for visibility transitions.
     * Closes the current context and relaunches with the desired headless state.
     */
    private async toggleVisibility(sessionId: string, targetHeadless: boolean): Promise<BrowserVisibilityResult> {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);
        if (session.transitioning) throw new Error(`Session ${sessionId} is already transitioning`);
        if (!this.isSessionAlive(sessionId)) {
            if (targetHeadless) {
                return {
                    ...this.buildVisibilityState(session),
                    message: 'Browser is already unavailable; hide is a safe no-op',
                    reopened: false,
                };
            }
            return await this.relaunchUnavailableSession(session, targetHeadless);
        }
        if (session.isHeadless === targetHeadless) {
            logger.info('Session already in desired visibility state', { sessionId, headless: targetHeadless });
            return {
                ...this.buildVisibilityState(session),
                message: targetHeadless ? 'Browser is already hidden' : 'Browser is already visible',
                reopened: false,
            };
        }

        session.transitioning = true;
        const label = targetHeadless ? 'headless' : 'visible';
        logger.info(`Switching browser session to ${label}`, { sessionId });
        const previousLifecycleState = session.lifecycleState;
        const previousLifecycleDetail = session.lifecycleDetail;
        let newContext: BrowserContext | null = null;

        try {
            const readySession = this.assertReadySession(sessionId, `switch browser visibility to ${label}`);
            const previousContext = readySession.context;
            const previousBrowser = readySession.browser;
            const continuitySnapshot = await this.captureContinuitySnapshot(readySession);
            const replacementUserDataDir = this.ensureVisibilityTransitionDir(session, targetHeadless);
            const launchArgs = this.buildLaunchArgs(session.proxyServer, session.brandingExtPath, targetHeadless);
            this.updateLifecycleState(sessionId, session, 'closing', {
                detail: `Switching browser to ${label}`,
                status: 'active',
                currentUrl: this.safePageUrl(session),
                preserveTransitioning: true,
            });
            newContext = await chromium.launchPersistentContext(replacementUserDataDir, {
                headless: targetHeadless,
                executablePath: session.executablePath,
                args: launchArgs,
                ignoreHTTPSErrors: true,
                proxy: { server: session.proxyServer },
                viewport: targetHeadless ? { width: 1280, height: 720 } : null,
            });
            await this.applyContinuitySnapshot(newContext, continuitySnapshot);

            const pages = newContext.pages();
            const newPage = pages.length > 0 ? pages[0] : await newContext.newPage();
            const restoreUrl = (() => {
                const preferred = continuitySnapshot.url || session.targetUrl || 'about:blank';
                if (preferred === 'about:blank') return preferred;
                return this.isPenPardInternalUrl(preferred, session.targetOrigin)
                    ? (session.targetUrl || 'about:blank')
                    : preferred;
            })();

            if (restoreUrl && restoreUrl !== 'about:blank') {
                try {
                    await newPage.goto(restoreUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
                } catch (navErr: any) {
                    logger.warn('Could not restore URL after visibility toggle (non-fatal)', {
                        sessionId, restoreUrl, error: navErr.message,
                    });
                }
            }

            session.browser = newContext.browser() || (newContext as any);
            session.context = newContext;
            session.page = newPage;
            session.isHeadless = targetHeadless;
            session.userDataDir = replacementUserDataDir;
            session.generation += 1;
            session.transitioning = false;
            session.lastError = null;
            this.updateLastKnownPageState(session, newPage);
            this.attachSessionListeners(sessionId, newPage, newContext, session.generation);
            this.updateLifecycleState(
                sessionId,
                session,
                deriveActiveBrowserLifecycleState(targetHeadless, session.hasBeenVisible || !targetHeadless),
                {
                    status: 'active',
                    currentUrl: this.safePageUrl(session) || restoreUrl,
                    closedAt: null,
                },
            );

            if (!targetHeadless) {
                const browserIcoPath = this.resolveBrowserIconPath();
                if (browserIcoPath) {
                    this.applyWindowsIconOverride(browserIcoPath);
                }
            }

            try {
                previousContext.removeAllListeners('close');
            } catch {
                /* ignore */
            }
            try {
                await previousContext.close();
            } catch (closeError: any) {
                logger.warn('Error closing previous context after visibility swap (non-fatal)', {
                    sessionId,
                    error: closeError.message,
                });
                try {
                    await previousBrowser?.close();
                } catch {
                    /* ignore */
                }
            }

            logger.info(`Browser session switched to ${label}`, { sessionId, restoredUrl: restoreUrl });
            return {
                ...this.buildVisibilityState(session),
                message: targetHeadless ? 'Browser hidden and continued headless' : 'Browser window opened',
                reopened: false,
            };
        } catch (error: any) {
            if (newContext) {
                try {
                    await newContext.close();
                } catch {
                    /* ignore */
                }
            }
            session.transitioning = false;
            session.lifecycleState = previousLifecycleState;
            session.lifecycleDetail = previousLifecycleDetail;
            session.lastError = error.message;
            updateBrowserSession(sessionId, {
                lifecycle_state: previousLifecycleState,
                lifecycle_detail: previousLifecycleDetail,
                last_error: error.message,
                last_activity_at: this.now(),
            });
            logger.error(`Failed to switch browser visibility to ${label}`, { sessionId, error: error.message });
            throw new Error(`Visibility toggle failed: ${error.message}`);
        }
    }
}

// Singleton export
export const browserService = new BrowserService();
