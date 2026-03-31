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
import { execSync, exec } from 'child_process';

// ── Types ──

export interface BrowserSessionOptions {
    targetUrl?: string;
    scanId?: string;
    findingId?: number;
    proxyHost?: string;
    proxyPort?: number;
    label?: string;
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

interface LiveSession {
    browser: Browser;
    context: BrowserContext;
    page: Page;
    sessionId: string;
    userId: number;
    userDataDir: string;
}

// ── Service ──

class BrowserService {
    private sessions: Map<string, LiveSession> = new Map();

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

        try {
            const executablePath = await this.resolveChromiumPath();

            // Resolve PenPard Browser branding extension
            const brandingExtPath = this.resolveBrandingExtensionPath();

            const launchArgs: string[] = [
                `--proxy-server=${proxyServer}`,
                '--ignore-certificate-errors',
                '--ignore-certificate-errors-spki-list',
                '--disable-web-security',
                '--allow-running-insecure-content',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-blink-features=AutomationControlled',
                // User-agent that looks normal (not automated)
                '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            ];

            // Load the PenPard Browser branding extension
            // This sets the favicon, browser-action icon, and window title
            if (brandingExtPath) {
                launchArgs.push(
                    `--disable-extensions-except=${brandingExtPath}`,
                    `--load-extension=${brandingExtPath}`,
                );
            }

            // Per-session user data dir — fixes multi-browser bug.
            // Previously all sessions shared browser_profile_live, causing Chromium's
            // SingletonLock to block second launches ("chromium browser not found").
            const userDataDir = path.join(os.homedir(), '.penpard', 'browser_sessions', sessionId);
            if (!fs.existsSync(userDataDir)) fs.mkdirSync(userDataDir, { recursive: true });

            const context = await chromium.launchPersistentContext(userDataDir, {
                headless: false, // Visible for human interaction
                executablePath,
                args: launchArgs,
                ignoreHTTPSErrors: true,
                proxy: { server: proxyServer },
                viewport: null, // Use full window size
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
            const liveSession: LiveSession = {
                browser: context.browser() || (context as any), // Fallback map
                context,
                page,
                sessionId,
                userId,
                userDataDir,
            };
            this.sessions.set(sessionId, liveSession);

            // ── Event Listeners ──

            // Track page URL changes
            page.on('framenavigated', (frame: any) => {
                if (frame === page.mainFrame()) {
                    const url = page.url();
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

            // Track browser close (human closes the window)
            context.on('close', () => {
                logger.info('Browser context closed', { sessionId });
                this.sessions.delete(sessionId);
                dbCloseSession(sessionId);
            });

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
            const currentUrl = page.url();
            updateBrowserSession(sessionId, {
                status: 'active',
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
            updateBrowserSession(sessionId, {
                status: 'closed',
                closed_at: new Date().toISOString(),
            });
            throw error;
        }
    }

    /**
     * Execute an AI-driven action on a browser session.
     */
    async executeAction(sessionId: string, action: BrowserAction): Promise<any> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }

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

            // Log the action
            addBrowserAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify(action),
                pageUrl: page.url(),
                pageTitle: await page.title().catch(() => ''),
                source: 'ai',
            });

            // Update session state
            updateBrowserSession(sessionId, {
                current_url: page.url(),
                last_activity_at: new Date().toISOString(),
            });

            return result;

        } catch (error: any) {
            // Log failed action
            addBrowserAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify({ ...action, error: error.message }),
                pageUrl: page.url(),
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
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }

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
            url: page.url(),
            title: await page.title(),
            ...state,
        };
    }

    /**
     * Capture a screenshot of the current page.
     */
    async captureScreenshot(sessionId: string): Promise<{ base64: string; mimeType: string }> {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }

        const buffer = await session.page.screenshot({ type: 'png', fullPage: false });

        addBrowserAction({
            sessionId,
            actionType: 'screenshot',
            actionData: JSON.stringify({ timestamp: new Date().toISOString() }),
            pageUrl: session.page.url(),
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
            try {
                dbSession.current_url = liveSession.page.url();
                dbSession.title = await liveSession.page.title().catch(() => '');
                dbSession.isLive = true;
            } catch {
                dbSession.isLive = false;
            }
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

        if (session) {
            try {
                await session.browser.close();
            } catch (e: any) {
                logger.warn('Error closing browser', { sessionId, error: e.message });
            }
            this.sessions.delete(sessionId);
        }

        dbCloseSession(sessionId);
        logger.info('Browser session closed', { sessionId });
    }

    /**
     * Check if a session is alive in-memory.
     */
    isSessionAlive(sessionId: string): boolean {
        return this.sessions.has(sessionId);
    }

    /**
     * Get count of active sessions.
     */
    getActiveSessionCount(): number {
        return this.sessions.size;
    }

    /**
     * Clean up all sessions (on server shutdown).
     */
    async cleanup(): Promise<void> {
        logger.info('Cleaning up all browser sessions', { count: this.sessions.size });
        for (const [sessionId, session] of this.sessions) {
            try {
                await session.browser.close();
            } catch { /* ignore */ }
            dbCloseSession(sessionId);
        }
        this.sessions.clear();
    }

    // ══════════════════════════════════════════════════════════
    //  FRONTEND ANALYSIS — AI-usable browser intelligence
    // ══════════════════════════════════════════════════════════

    /**
     * Deep page state: DOM summary, scripts, meta, cookies, storage.
     */
    async getFullPageState(sessionId: string): Promise<any> {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);
        const { page, context } = session;

        const state = await page.evaluate(`(() => {
            // DOM summary
            const allElements = document.querySelectorAll('*');
            const tagCounts = {};
            allElements.forEach(el => { tagCounts[el.tagName] = (tagCounts[el.tagName] || 0) + 1; });

            // Forms
            const forms = Array.from(document.querySelectorAll('form')).slice(0, 30).map(form => ({
                action: form.action || '',
                method: (form.method || 'get').toUpperCase(),
                id: form.id || '',
                name: form.name || '',
                fields: Array.from(form.querySelectorAll('input, textarea, select, button')).slice(0, 50).map(field => ({
                    name: field.name || '',
                    type: field.type || field.tagName.toLowerCase(),
                    id: field.id || '',
                    value: field.type === 'hidden' ? field.value : '',
                    placeholder: field.placeholder || '',
                })),
            }));

            // Hidden inputs (outside forms too)
            const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]')).map(el => ({
                name: el.name || '',
                id: el.id || '',
                value: el.value || '',
                form: el.form ? (el.form.id || el.form.action || 'unnamed-form') : 'no-form',
            }));

            // Links
            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 100).map(a => ({
                href: a.href || '',
                text: (a.textContent || '').trim().substring(0, 100),
            }));

            // Meta tags
            const metaTags = Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.name || m.httpEquiv || m.getAttribute('property') || '',
                content: (m.content || '').substring(0, 500),
            }));

            // Scripts (src + inline)
            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || '',
                type: s.type || '',
                isInline: !s.src,
                contentPreview: !s.src ? (s.textContent || '').substring(0, 500) : '',
                contentLength: !s.src ? (s.textContent || '').length : 0,
            }));

            // Cookies
            const cookies = document.cookie;

            // localStorage
            let localStorageData = {};
            try {
                for (let i = 0; i < localStorage.length && i < 50; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = (localStorage.getItem(key) || '').substring(0, 500);
                }
            } catch(e) {}

            // sessionStorage
            let sessionStorageData = {};
            try {
                for (let i = 0; i < sessionStorage.length && i < 50; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = (sessionStorage.getItem(key) || '').substring(0, 500);
                }
            } catch(e) {}

            const bodyText = document.body ? document.body.innerText : '';
            return {
                tagCounts,
                totalElements: allElements.length,
                forms,
                hiddenInputs,
                links,
                metaTags,
                scripts,
                cookies,
                localStorageData,
                sessionStorageData,
                textSummary: bodyText.substring(0, 3000),
            };
        })()`);

        // Also get Playwright-level cookies for the context
        let contextCookies: any[] = [];
        try { contextCookies = await context.cookies(); } catch { /* ignore */ }

        return {
            url: page.url(),
            title: await page.title(),
            ...(state as any),
            contextCookies,
        };
    }

    /**
     * Loaded scripts analysis — all script tags with URLs and inline content.
     */
    async getLoadedScripts(sessionId: string): Promise<any> {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);

        return await session.page.evaluate(`(() => {
            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || null,
                type: s.type || 'text/javascript',
                async: s.async,
                defer: s.defer,
                isModule: s.type === 'module',
                isInline: !s.src,
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

    /**
     * Comprehensive frontend intelligence extraction.
     * Finds API endpoints, GraphQL, WebSockets, tokens, CSRF, routing patterns.
     */
    async getFrontendAnalysis(sessionId: string): Promise<any> {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);

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
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);

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

        return { url: session.page.url(), ...(browserStorage as any), contextCookies };
    }

    /**
     * Correlate browser-visible state with Burp MCP proxy history.
     * Merges what the browser sees with what Burp intercepted.
     */
    async correlateBrowserWithBurp(sessionId: string): Promise<any> {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);

        // Get browser state
        const currentUrl = session.page.url();
        let host = '';
        try { host = new URL(currentUrl).hostname; } catch { /* ignore */ }

        // Get Burp proxy history via MCP
        let burpHistory: any[] = [];
        let burpAvailable = false;
        try {
            const { burpMCP } = require('./burp-mcp');
            burpAvailable = await burpMCP.isAvailable();
            if (burpAvailable) {
                const result = await burpMCP.callTool('get_proxy_history', { count: 50 });
                burpHistory = result?.content?.[0]?.text
                    ? JSON.parse(result.content[0].text).history || []
                    : [];
            }
        } catch (e: any) {
            logger.warn('Burp MCP correlation failed', { error: e.message });
        }

        // Get browser action log
        const actions = getBrowserActions(sessionId);

        // Match browser URLs with Burp history
        const matchedRequests = burpHistory.filter((entry: any) => {
            const entryUrl = entry.url || '';
            try {
                const entryHost = new URL(entryUrl).hostname;
                return entryHost === host;
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
            burpRequestsForHost: matchedRequests.length,
            totalBurpHistory: burpHistory.length,
            matchedRequests: matchedRequests.slice(0, 30).map((r: any) => ({
                method: r.method,
                url: r.url,
                status: r.status,
                mimeType: r.mimeType,
            })),
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
        const sessionA = this.sessions.get(sessionIdA);
        const sessionB = this.sessions.get(sessionIdB);
        if (!sessionA) throw new Error(`Session A (${sessionIdA}) not found or not active`);
        if (!sessionB) throw new Error(`Session B (${sessionIdB}) not found or not active`);

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
}

// Singleton export
export const browserService = new BrowserService();
