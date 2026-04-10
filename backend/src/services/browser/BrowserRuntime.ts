import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { chromium, type BrowserContext, type Page } from 'playwright-core';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../utils/logger';
import { deriveActiveBrowserLifecycleState, type BrowserLifecycleState } from '../../types/browserLifecycle';
import type { BrowserContinuitySnapshot, BrowserSessionOptions, BrowserVisibilityResult, LiveSession, ReadyLiveSession } from './browserTypes';
import { BrowserSessionPersistence } from './BrowserSessionPersistence';
import { BrowserSessionStore } from './BrowserSessionStore';
import { BrowserTelemetry } from './BrowserTelemetry';
import { getTargetOrigin, resolveBrowserRestoreUrl } from './BrowserUrlPolicy';

export class BrowserRuntime {
    constructor(
        private readonly store: BrowserSessionStore,
        private readonly persistence: BrowserSessionPersistence,
        private readonly telemetry: BrowserTelemetry,
    ) {}

    public async launchSession(userId: number, options: BrowserSessionOptions = {}): Promise<string> {
        const sessionId = uuidv4();
        const proxyConfig = this.persistence.getProxyConfig();
        const proxyHost = options.proxyHost || proxyConfig.host;
        const proxyPort = options.proxyPort || proxyConfig.port;
        const proxyServer = `http://${proxyHost}:${proxyPort}`;

        logger.info('Launching PenPard Browser session', {
            sessionId,
            proxyServer,
            targetUrl: options.targetUrl,
        });

        this.persistence.createSession({
            id: sessionId,
            userId,
            scanId: options.scanId,
            findingId: options.findingId,
            targetUrl: options.targetUrl || '',
            proxyHost,
            proxyPort,
            label: options.label,
        });

        let context: BrowserContext | null = null;
        let liveSession: LiveSession | null = null;
        try {
            const executablePath = await this.resolveChromiumPath();
            const isHeadless = options.headless ?? false;
            const brandingExtPath = this.resolveBrandingExtensionPath();
            const launchArgs = this.buildLaunchArgs(proxyServer, brandingExtPath, isHeadless);
            const userDataDir = path.join(os.homedir(), '.penpard', 'browser_sessions', sessionId);
            if (!fs.existsSync(userDataDir)) fs.mkdirSync(userDataDir, { recursive: true });

            const targetOrigin = getTargetOrigin(options.targetUrl);
            const jsArtifactsDir = options.scanId ? this.telemetry.ensureJsArtifactsDir(options.scanId, sessionId) : null;
            context = await chromium.launchPersistentContext(userDataDir, {
                headless: isHeadless,
                executablePath,
                args: launchArgs,
                ignoreHTTPSErrors: true,
                proxy: { server: proxyServer },
                viewport: isHeadless ? { width: 1280, height: 720 } : null,
            });

            const browserIcoPath = this.resolveBrowserIconPath();
            if (browserIcoPath) {
                this.applyWindowsIconOverride(browserIcoPath);
            }

            const pages = context.pages();
            const page = pages.length > 0 ? pages[0] : await context.newPage();

            liveSession = {
                browser: context.browser() || (context as any),
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
            this.store.updateLastKnownPageState(liveSession, page);
            this.store.set(sessionId, liveSession);
            this.telemetry.attachSessionListeners(sessionId, page, context, liveSession.generation);

            if (options.targetUrl) {
                await page.goto(options.targetUrl, {
                    waitUntil: 'domcontentloaded',
                    timeout: 30000,
                }).catch((err: any) => {
                    logger.warn('Initial navigation warning (may be proxy-related)', {
                        sessionId,
                        error: err.message,
                    });
                });
            }

            const currentUrl = this.store.safePageUrl(liveSession) || 'about:blank';
            this.persistence.updateSession(sessionId, {
                status: 'active',
                lifecycle_state: liveSession.lifecycleState,
                lifecycle_detail: null,
                last_error: null,
                closed_at: null,
                current_url: currentUrl,
                mode: 'human',
            });

            this.persistence.addAction({
                sessionId,
                actionType: 'navigate',
                actionData: JSON.stringify({ url: options.targetUrl || 'about:blank' }),
                pageUrl: currentUrl,
                pageTitle: '',
                source: 'system',
            });

            logger.info('PenPard Browser session launched', {
                sessionId,
                proxyServer,
                currentUrl,
            });

            return sessionId;
        } catch (error: any) {
            logger.error('Failed to launch browser session', {
                sessionId,
                error: error.message,
            });
            if (context) {
                try {
                    await context.close();
                } catch {
                    /* ignore */
                }
            }
            if (liveSession) {
                this.store.delete(sessionId);
                liveSession.browser = null;
                liveSession.context = null;
                liveSession.page = null;
            }
            this.persistence.closeSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: 'Browser launch failed',
                last_error: error.message,
                current_url: options.targetUrl || null,
            });
            throw error;
        }
    }

    public async closeSession(sessionId: string): Promise<void> {
        const session = this.store.get(sessionId);

        if (!session) {
            this.persistence.closeSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: 'Close requested after runtime already ended',
                last_error: null,
            });
            logger.info('Browser session closed', { sessionId, alreadyInactive: true });
            return;
        }

        if (session.lifecycleState === 'closed' && !session.browser && !session.context && !session.page) {
            this.persistence.closeSession(sessionId, {
                lifecycle_state: 'closed',
                lifecycle_detail: session.lifecycleDetail || 'Session was already closed',
                last_error: session.lastError,
                current_url: this.store.safePageUrl(session),
            });
            return;
        }

        session.transitioning = true;
        session.generation += 1;
        this.store.updateLifecycleState(sessionId, session, 'closing', {
            detail: 'Session cleanup requested',
            status: 'closed',
            currentUrl: this.store.safePageUrl(session),
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
            } catch (error: any) {
                logger.warn('Error closing browser', { sessionId, error: error.message });
            }
        } else if (context) {
            try {
                await context.close();
            } catch (error: any) {
                logger.warn('Error closing browser context', { sessionId, error: error.message });
            }
        }

        this.store.updateLifecycleState(sessionId, session, 'closed', {
            detail: 'Session cleanup completed',
            status: 'closed',
            currentUrl: this.store.safePageUrl(session),
            closedAt: this.store.now(),
        });
        this.persistence.closeSession(sessionId, {
            lifecycle_state: 'closed',
            lifecycle_detail: 'Session cleanup completed',
            last_error: session.lastError,
            current_url: this.store.safePageUrl(session),
        });
        logger.info('Browser session closed', { sessionId });
    }

    public async cleanup(): Promise<void> {
        logger.info('Cleaning up all browser sessions', { count: this.store.sessions.size });
        for (const [sessionId] of this.store.entries()) {
            await this.closeSession(sessionId);
        }
    }

    public async showBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return this.toggleVisibility(sessionId, false);
    }

    public async hideBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return this.toggleVisibility(sessionId, true);
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

    private ensureVisibilityTransitionDir(session: LiveSession, targetHeadless: boolean): string {
        const parentDir = path.dirname(session.userDataDir);
        const dirName = `${session.sessionId}-${targetHeadless ? 'headless' : 'visible'}-${Date.now()}`;
        const nextDir = path.join(parentDir, dirName);
        if (!fs.existsSync(nextDir)) {
            fs.mkdirSync(nextDir, { recursive: true });
        }
        return nextDir;
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

    private async launchReplacementContext(
        session: LiveSession,
        targetHeadless: boolean,
        options: {
            userDataDir?: string;
            preferredUrl?: string | null;
            continuitySnapshot?: BrowserContinuitySnapshot | null;
            navigationFailureLog: string;
        },
    ): Promise<{ context: BrowserContext; page: Page; restoreUrl: string; userDataDir: string }> {
        const userDataDir = options.userDataDir || session.userDataDir;
        if (!fs.existsSync(userDataDir)) {
            fs.mkdirSync(userDataDir, { recursive: true });
        }

        const context = await chromium.launchPersistentContext(userDataDir, {
            headless: targetHeadless,
            executablePath: session.executablePath || undefined,
            args: this.buildLaunchArgs(session.proxyServer, session.brandingExtPath, targetHeadless),
            ignoreHTTPSErrors: true,
            proxy: { server: session.proxyServer },
            viewport: targetHeadless ? { width: 1280, height: 720 } : null,
        });

        if (options.continuitySnapshot) {
            await this.applyContinuitySnapshot(context, options.continuitySnapshot);
        }

        const pages = context.pages();
        const page = pages.length > 0 ? pages[0] : await context.newPage();
        const restoreUrl = resolveBrowserRestoreUrl(session, options.preferredUrl);

        if (restoreUrl && restoreUrl !== 'about:blank') {
            try {
                await page.goto(restoreUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
            } catch (navErr: any) {
                logger.warn(options.navigationFailureLog, {
                    sessionId: session.sessionId,
                    restoreUrl,
                    error: navErr.message,
                });
            }
        }

        return { context, page, restoreUrl, userDataDir };
    }

    private activateReplacementSession(
        session: LiveSession,
        targetHeadless: boolean,
        replacement: { context: BrowserContext; page: Page; restoreUrl: string; userDataDir: string },
    ): void {
        session.browser = replacement.context.browser() || (replacement.context as any);
        session.context = replacement.context;
        session.page = replacement.page;
        session.isHeadless = targetHeadless;
        session.userDataDir = replacement.userDataDir;
        session.generation += 1;
        session.transitioning = false;
        session.lastError = null;
        this.store.updateLastKnownPageState(session, replacement.page);
        this.telemetry.attachSessionListeners(session.sessionId, replacement.page, replacement.context, session.generation);
        this.store.updateLifecycleState(
            session.sessionId,
            session,
            deriveActiveBrowserLifecycleState(targetHeadless, session.hasBeenVisible || !targetHeadless),
            {
                status: 'active',
                currentUrl: this.store.safePageUrl(session) || replacement.restoreUrl,
                closedAt: null,
            },
        );

        if (!targetHeadless) {
            const browserIcoPath = this.resolveBrowserIconPath();
            if (browserIcoPath) {
                this.applyWindowsIconOverride(browserIcoPath);
            }
        }
    }

    private restoreTransitionFailure(
        session: LiveSession,
        previousLifecycleState: BrowserLifecycleState,
        previousLifecycleDetail: string | null,
        error: any,
    ): never {
        const message = error?.message || String(error);
        session.transitioning = false;
        session.lifecycleState = previousLifecycleState;
        session.lifecycleDetail = previousLifecycleDetail;
        session.lastError = message;
        this.persistence.updateSession(session.sessionId, {
            lifecycle_state: previousLifecycleState,
            lifecycle_detail: previousLifecycleDetail,
            last_error: message,
            last_activity_at: this.store.now(),
        });
        throw new Error(`Visibility toggle failed: ${message}`);
    }

    private async relaunchUnavailableSession(session: LiveSession, targetHeadless: boolean): Promise<BrowserVisibilityResult> {
        const label = targetHeadless ? 'headless' : 'visible';
        const priorState = session.lifecycleState;
        const priorDetail = session.lifecycleDetail;
        let replacementContext: BrowserContext | null = null;

        session.transitioning = true;
        this.persistence.updateSession(session.sessionId, {
            last_activity_at: this.store.now(),
            last_error: null,
        });

        try {
            const replacement = await this.launchReplacementContext(session, targetHeadless, {
                userDataDir: session.userDataDir,
                preferredUrl: session.lastKnownUrl || session.targetUrl || 'about:blank',
                navigationFailureLog: 'Could not restore URL while relaunching unavailable browser session (non-fatal)',
            });
            replacementContext = replacement.context;
            this.activateReplacementSession(session, targetHeadless, replacement);

            return {
                ...this.store.buildVisibilityState(session),
                message: targetHeadless ? 'Browser relaunched in headless mode' : 'Browser window reopened',
                reopened: true,
            };
        } catch (error: any) {
            if (replacementContext) {
                try {
                    await replacementContext.close();
                } catch {
                    /* ignore */
                }
            }
            logger.error(`Failed to relaunch ${label} browser session`, { sessionId: session.sessionId, error: error.message });
            this.restoreTransitionFailure(session, priorState, priorDetail, error);
        }
    }

    private async toggleVisibility(sessionId: string, targetHeadless: boolean): Promise<BrowserVisibilityResult> {
        const session = this.store.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);
        if (session.transitioning) throw new Error(`Session ${sessionId} is already transitioning`);
        if (!this.store.isSessionAlive(sessionId)) {
            if (targetHeadless) {
                return {
                    ...this.store.buildVisibilityState(session),
                    message: 'Browser is already unavailable; hide is a safe no-op',
                    reopened: false,
                };
            }
            return this.relaunchUnavailableSession(session, targetHeadless);
        }
        if (session.isHeadless === targetHeadless) {
            logger.info('Session already in desired visibility state', { sessionId, headless: targetHeadless });
            return {
                ...this.store.buildVisibilityState(session),
                message: targetHeadless ? 'Browser is already hidden' : 'Browser is already visible',
                reopened: false,
            };
        }

        session.transitioning = true;
        const label = targetHeadless ? 'headless' : 'visible';
        logger.info(`Switching browser session to ${label}`, { sessionId });
        const previousLifecycleState = session.lifecycleState;
        const previousLifecycleDetail = session.lifecycleDetail;
        let replacementContext: BrowserContext | null = null;

        try {
            const readySession = this.store.assertReadySession(sessionId, `switch browser visibility to ${label}`);
            const previousContext = readySession.context;
            const previousBrowser = readySession.browser;
            const continuitySnapshot = await this.captureContinuitySnapshot(readySession);
            const replacementUserDataDir = this.ensureVisibilityTransitionDir(session, targetHeadless);
            this.store.updateLifecycleState(sessionId, session, 'closing', {
                detail: `Switching browser to ${label}`,
                status: 'active',
                currentUrl: this.store.safePageUrl(session),
                preserveTransitioning: true,
            });
            const replacement = await this.launchReplacementContext(session, targetHeadless, {
                userDataDir: replacementUserDataDir,
                preferredUrl: continuitySnapshot.url || session.targetUrl || 'about:blank',
                continuitySnapshot,
                navigationFailureLog: 'Could not restore URL after visibility toggle (non-fatal)',
            });
            replacementContext = replacement.context;
            this.activateReplacementSession(session, targetHeadless, replacement);

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

            logger.info(`Browser session switched to ${label}`, { sessionId, restoredUrl: replacement.restoreUrl });
            return {
                ...this.store.buildVisibilityState(session),
                message: targetHeadless ? 'Browser hidden and continued headless' : 'Browser window opened',
                reopened: false,
            };
        } catch (error: any) {
            if (replacementContext) {
                try {
                    await replacementContext.close();
                } catch {
                    /* ignore */
                }
            }
            logger.error(`Failed to switch browser visibility to ${label}`, { sessionId, error: error.message });
            this.restoreTransitionFailure(session, previousLifecycleState, previousLifecycleDetail, error);
        }
    }

    private resolveBrandingExtensionPath(): string | null {
        const candidates: string[] = [];
        candidates.push(
            path.resolve(__dirname, '..', '..', '..', '..', 'electron', 'assets', 'browser-extension'),
        );

        if (process.env.RESOURCES_PATH) {
            candidates.push(path.join(process.env.RESOURCES_PATH, 'browser-extension'));
        }

        for (const candidate of candidates) {
            const manifest = path.join(candidate, 'manifest.json');
            if (fs.existsSync(manifest)) {
                logger.info('Found PenPard Browser branding extension', { path: candidate });
                return candidate;
            }
        }

        logger.warn('PenPard Browser branding extension not found; browser will use default Chromium icon');
        return null;
    }

    private resolveBrowserIconPath(): string | null {
        const candidates: string[] = [
            path.resolve(__dirname, '..', '..', '..', '..', 'electron', 'assets', 'browser-icon.ico'),
        ];

        if (process.env.RESOURCES_PATH) {
            candidates.push(path.join(process.env.RESOURCES_PATH, 'browser-icon.ico'));
        }

        for (const candidate of candidates) {
            if (fs.existsSync(candidate)) {
                logger.info('Found PenPard Browser icon', { path: candidate });
                return candidate;
            }
        }

        logger.warn('PenPard Browser .ico not found; window icon cannot be overridden');
        return null;
    }

    private applyWindowsIconOverride(icoPath: string): void {
        if (process.platform !== 'win32') return;

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
        IntPtr hIconSmall = LoadImage(IntPtr.Zero, icoPath, 1, 16, 16, 0x00000010);
        IntPtr hIconBig = LoadImage(IntPtr.Zero, icoPath, 1, 32, 32, 0x00000010);
        if (hIconBig == IntPtr.Zero && hIconSmall == IntPtr.Zero) return -1;

        var windows = GetWindowsByProcessName("penpard_isolated");
        foreach (var hwnd in windows) {
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
                } catch (error: any) {
                    logger.warn('PenPard Browser icon override error', { error: error.message, attempt });
                    if (attempt < 5) attemptIconOverride(attempt + 1);
                }
            }, delay);
        };

        attemptIconOverride(1);
    }

    private async resolveChromiumPath(): Promise<string | undefined> {
        if (process.env.PLAYWRIGHT_CHROMIUM_PATH) {
            const overridePath = process.env.PLAYWRIGHT_CHROMIUM_PATH;
            if (fs.existsSync(overridePath)) return overridePath;
            logger.warn('PLAYWRIGHT_CHROMIUM_PATH set but not found', { path: overridePath });
        }

        try {
            const pwChromium = require('playwright-core').chromium;
            const defaultPwPath = pwChromium.executablePath();
            if (defaultPwPath) {
                const brandedPath = defaultPwPath.replace(/chrome\.exe$/, 'penpard_isolated.exe');
                if (fs.existsSync(brandedPath)) {
                    logger.info('Found PenPard-branded Chromium', { path: brandedPath });
                    return brandedPath;
                }
            }
        } catch {
            /* ignore */
        }

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

        for (const candidate of candidates) {
            if (fs.existsSync(candidate)) {
                logger.info('Found system Chromium', { path: candidate });
                return candidate;
            }
        }

        logger.info('No system Chromium found, will attempt Playwright bundled browser');
        return undefined;
    }
}
