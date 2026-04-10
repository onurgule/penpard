import { addBrowserAction, closeBrowserSession as dbCloseSession, createBrowserSession, db, getBrowserActions, getBrowserSession, updateBrowserSession } from '../../db/init';
import type { BrowserLifecycleState } from '../../types/browserLifecycle';

interface BrowserSessionRecordInput {
    id: string;
    userId: number;
    scanId?: string;
    findingId?: number;
    targetUrl?: string;
    proxyHost?: string;
    proxyPort?: number;
    label?: string;
}

interface BrowserActionRecordInput {
    sessionId: string;
    actionType: string;
    actionData?: string;
    pageUrl?: string;
    pageTitle?: string;
    source?: string;
}

export class BrowserSessionPersistence {
    public createSession(input: BrowserSessionRecordInput): void {
        createBrowserSession({
            id: input.id,
            userId: input.userId,
            scanId: input.scanId,
            findingId: input.findingId,
            targetUrl: input.targetUrl || '',
            proxyHost: input.proxyHost,
            proxyPort: input.proxyPort,
        });

        if (input.label) {
            this.updateSession(input.id, { label: input.label });
        }
    }

    public updateSession(sessionId: string, updates: Record<string, any>): void {
        updateBrowserSession(sessionId, updates);
    }

    public addAction(input: BrowserActionRecordInput): void {
        addBrowserAction(input);
    }

    public getSession(sessionId: string): any {
        return getBrowserSession(sessionId);
    }

    public getActions(sessionId: string): any[] {
        return getBrowserActions(sessionId);
    }

    public closeSession(
        sessionId: string,
        updates: {
            lifecycle_state?: BrowserLifecycleState;
            lifecycle_detail?: string | null;
            last_error?: string | null;
            current_url?: string | null;
        } = {},
    ): void {
        dbCloseSession(sessionId, updates);
    }

    public getProxyConfig(): { host: string; port: number } {
        try {
            const browserProxyRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('browser_proxy_config') as any;
            if (browserProxyRow?.value) {
                const cfg = JSON.parse(browserProxyRow.value);
                return { host: cfg.host || '127.0.0.1', port: cfg.port || 8080 };
            }

            const burpRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
            if (burpRow?.value) {
                const cfg = JSON.parse(burpRow.value);
                return { host: cfg.host || '127.0.0.1', port: 8080 };
            }
        } catch {
            /* DB not ready */
        }

        return { host: '127.0.0.1', port: 8080 };
    }
}
