import { browserService } from '../../services/BrowserService';
import { AuthStateManager } from '../../services/auth';

type LogFn = (channel: 'system' | 'error' | 'debug', message: string) => void;

interface OrchestratorBrowserSessionOptions {
    userId?: number;
    targetUrl: string;
    scanId: string;
    authManager: AuthStateManager;
    log?: LogFn;
}

export class OrchestratorBrowserSession {
    private browserSessionId: string | null = null;
    private cleanupPromise: Promise<void> | null = null;

    constructor(private readonly options: OrchestratorBrowserSessionOptions) {}

    public getSessionId(): string | null {
        return this.browserSessionId;
    }

    public setSessionId(sessionId: string | null): void {
        this.browserSessionId = sessionId;
    }

    public async syncAuthFromBrowser(identityId: string = 'primary-user'): Promise<void> {
        if (!this.browserSessionId || !browserService.isSessionAlive(this.browserSessionId)) {
            return;
        }

        try {
            const pageState = await browserService.getFullPageState(this.browserSessionId);
            this.syncAuthFromPageState(pageState, identityId);
        } catch (error: any) {
            this.options.log?.('debug', `Browser auth sync failed (non-fatal): ${error.message}`);
        }
    }

    public syncAuthFromPageState(pageState: any, identityId: string = 'primary-user'): void {
        this.options.authManager.syncFromBrowser(pageState.contextCookies || [], identityId);
        this.options.authManager.syncFromBrowserStorage({
            localStorageData: pageState.localStorageData || {},
            sessionStorageData: pageState.sessionStorageData || {},
        }, identityId);
        this.options.authManager.detectCSRFFromPage(pageState, identityId);
    }

    public async seedBrowserFromAuthManager(identityId: string = 'primary-user'): Promise<void> {
        if (!this.browserSessionId || !browserService.isSessionAlive(this.browserSessionId)) {
            return;
        }

        try {
            const cookies = this.options.authManager.exportForBrowser(identityId);
            if (cookies.length > 0) {
                await browserService.syncCookiesToSession(this.browserSessionId, cookies);
            }
        } catch (error: any) {
            this.options.log?.('debug', `Browser auth seed failed (non-fatal): ${error.message}`);
        }
    }

    public async ensureSession(): Promise<string> {
        if (this.browserSessionId && browserService.isSessionAlive(this.browserSessionId)) {
            return this.browserSessionId;
        }

        if (this.browserSessionId) {
            const visibility = browserService.getSessionVisibility(this.browserSessionId);
            if (visibility && !visibility.isLive) {
                this.options.log?.(
                    'system',
                    `Browser session became unavailable (${visibility.lifecycleState}). Continuing in HTTP-only mode until browser features are needed again.`,
                );
            }
        }

        this.options.log?.('system', 'Browser session not found. Re-launching headless browser...');
        try {
            this.browserSessionId = await browserService.launchSession(this.options.userId || 1, {
                targetUrl: this.options.targetUrl,
                scanId: this.options.scanId,
                headless: true,
            });
            await this.seedBrowserFromAuthManager();
            await this.syncAuthFromBrowser();
            this.options.log?.('system', 'Browser re-launched successfully');
            return this.browserSessionId;
        } catch (error: any) {
            this.options.log?.('error', `Browser re-launch failed: ${error.message}`);
            throw new Error(`Browser session unavailable: ${error.message}`);
        }
    }

    public async cleanup(): Promise<void> {
        if (this.cleanupPromise) {
            await this.cleanupPromise;
            return;
        }

        if (!this.browserSessionId) {
            return;
        }

        const sessionId = this.browserSessionId;
        this.browserSessionId = null;
        this.cleanupPromise = (async () => {
            try {
                await browserService.closeSession(sessionId);
                this.options.log?.('system', 'Browser session closed');
            } catch (error: any) {
                this.options.log?.('error', `Browser session cleanup failed (non-fatal): ${error.message}`);
            } finally {
                this.cleanupPromise = null;
            }
        })();

        await this.cleanupPromise;
    }
}
