/**
 * PenPard Browser Service
 *
 * Public browser facade for routes, auth startup, endpoint intelligence, and
 * orchestrator tooling. The underlying ownership is now split between:
 *   - BrowserSessionStore: in-memory live session state and lifecycle truth
 *   - BrowserSessionPersistence: DB/session action persistence
 *   - BrowserTelemetry: network events, JS artifacts, listener attachment
 *   - BrowserRuntime: Chromium lifecycle and visibility transitions
 *   - BrowserActionRunner: tool-facing browser actions and browser inspection
 */

import type { BrowserContext, Page } from 'playwright-core';
import { BrowserActionRunner } from './browser/BrowserActionRunner';
import { BrowserRuntime } from './browser/BrowserRuntime';
import { BrowserSessionPersistence } from './browser/BrowserSessionPersistence';
import { BrowserSessionStore } from './browser/BrowserSessionStore';
import { BrowserTelemetry } from './browser/BrowserTelemetry';
import type {
    BrowserAction,
    BrowserSessionOptions,
    BrowserSessionVisibility,
    BrowserTrafficEvent,
    BrowserVisibilityResult,
    CapturedJsArtifact,
    LiveSession,
    PageState,
} from './browser/browserTypes';

export type {
    BrowserAction,
    BrowserSessionOptions,
    BrowserSessionVisibility,
    BrowserTrafficEvent,
    BrowserVisibilityResult,
    CapturedJsArtifact,
    LiveSession,
    PageState,
};

class BrowserService {
    private readonly persistence = new BrowserSessionPersistence();
    private readonly sessionStore = new BrowserSessionStore(this.persistence);
    private readonly telemetry = new BrowserTelemetry(this.sessionStore, this.persistence);
    private readonly runtime = new BrowserRuntime(this.sessionStore, this.persistence, this.telemetry);
    private readonly actionRunner = new BrowserActionRunner(
        this.sessionStore,
        this.persistence,
        this.telemetry,
        (ms) => this.delay(ms),
    );

    // Compatibility surface for focused tests that seed live sessions directly.
    public readonly sessions = this.sessionStore.sessions;

    private delay(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    public attachSessionListeners(sessionId: string, page: Page, context: BrowserContext, generation: number): void {
        this.telemetry.attachSessionListeners(sessionId, page, context, generation);
    }

    public async launchSession(userId: number, options: BrowserSessionOptions = {}): Promise<string> {
        return this.runtime.launchSession(userId, options);
    }

    public async executeAction(sessionId: string, action: BrowserAction): Promise<any> {
        return this.actionRunner.executeAction(sessionId, action);
    }

    public async getPageState(sessionId: string): Promise<PageState> {
        return this.actionRunner.getPageState(sessionId);
    }

    public async captureScreenshot(sessionId: string): Promise<{ base64: string; mimeType: string }> {
        return this.actionRunner.captureScreenshot(sessionId);
    }

    public async getSessionInfo(sessionId: string): Promise<any> {
        return this.actionRunner.getSessionInfo(sessionId);
    }

    public async closeSession(sessionId: string): Promise<void> {
        return this.runtime.closeSession(sessionId);
    }

    public isSessionAliveSimple(sessionId: string): boolean {
        return this.sessionStore.isSessionAliveSimple(sessionId);
    }

    public getActiveSessionCount(): number {
        return this.sessionStore.getActiveSessionCount();
    }

    public async cleanup(): Promise<void> {
        return this.runtime.cleanup();
    }

    public async getFullPageState(sessionId: string): Promise<any> {
        return this.actionRunner.getFullPageState(sessionId);
    }

    public async getLoadedScripts(sessionId: string): Promise<any> {
        return this.actionRunner.getLoadedScripts(sessionId);
    }

    public async captureJavaScriptArtifacts(sessionId: string): Promise<CapturedJsArtifact[]> {
        return this.actionRunner.captureJavaScriptArtifacts(sessionId);
    }

    public getCapturedJavaScriptArtifacts(sessionId: string): CapturedJsArtifact[] {
        return this.actionRunner.getCapturedJavaScriptArtifacts(sessionId);
    }

    public async getFrontendAnalysis(sessionId: string): Promise<any> {
        return this.actionRunner.getFrontendAnalysis(sessionId);
    }

    public async getSessionStorageData(sessionId: string): Promise<any> {
        return this.actionRunner.getSessionStorageData(sessionId);
    }

    public async syncCookiesToSession(sessionId: string, cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>): Promise<number> {
        return this.actionRunner.syncCookiesToSession(sessionId, cookies);
    }

    public getTrafficSnapshot(sessionId: string): BrowserTrafficEvent[] {
        return this.actionRunner.getTrafficSnapshot(sessionId);
    }

    public async correlateBrowserWithBurp(sessionId: string): Promise<any> {
        return this.actionRunner.correlateBrowserWithBurp(sessionId);
    }

    public async compareSessionStates(sessionIdA: string, sessionIdB: string): Promise<any> {
        return this.actionRunner.compareSessionStates(sessionIdA, sessionIdB);
    }

    public isSessionAlive(sessionId: string): boolean {
        return this.sessionStore.isSessionAlive(sessionId);
    }

    public getSessionVisibility(sessionId: string): BrowserSessionVisibility | null {
        return this.sessionStore.getSessionVisibility(sessionId);
    }

    public async showBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return this.runtime.showBrowser(sessionId);
    }

    public async hideBrowser(sessionId: string): Promise<BrowserVisibilityResult> {
        return this.runtime.hideBrowser(sessionId);
    }
}

export const browserService = new BrowserService();
