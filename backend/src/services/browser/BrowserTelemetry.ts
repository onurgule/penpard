import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import type { BrowserContext, Page } from 'playwright-core';
import type { BrowserLifecycleState } from '../../types/browserLifecycle';
import { logger } from '../../utils/logger';
import type { BrowserTrafficEvent, CapturedJsArtifact, LiveSession, ReadyLiveSession } from './browserTypes';
import { BrowserSessionPersistence } from './BrowserSessionPersistence';
import { BrowserSessionStore } from './BrowserSessionStore';
import { categorizeBrowserUrl, isPenPardInternalUrl } from './BrowserUrlPolicy';

export class BrowserTelemetry {
    constructor(
        private readonly store: BrowserSessionStore,
        private readonly persistence: BrowserSessionPersistence,
    ) {}

    public ensureJsArtifactsDir(scanId: string, sessionId: string): string {
        const dir = path.join(os.homedir(), '.penpard', 'scan_runtime', scanId, 'js-artifacts', sessionId);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        return dir;
    }

    public recordTrafficEvent(sessionId: string, event: Omit<BrowserTrafficEvent, 'id'>): void {
        const session = this.store.get(sessionId);
        if (!session) return;

        session.networkEvents.push({
            id: session.nextTrafficEventId++,
            ...event,
        });

        if (session.networkEvents.length > 500) {
            session.networkEvents.splice(0, session.networkEvents.length - 500);
        }
    }

    public getTrafficSnapshot(sessionId: string): BrowserTrafficEvent[] {
        const session = this.store.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found or not active`);
        return [...session.networkEvents];
    }

    public getCapturedJavaScriptArtifacts(sessionId: string): CapturedJsArtifact[] {
        const session = this.store.get(sessionId);
        if (!session) return [];
        return Array.from(session.jsArtifacts.values());
    }

    public async captureInlineScriptArtifacts(session: ReadyLiveSession, loadedScripts: any): Promise<CapturedJsArtifact[]> {
        const pageUrl = this.store.safePageUrl(session) || 'about:blank';
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

    public attachSessionListeners(sessionId: string, page: Page, context: BrowserContext, generation: number): void {
        const session = this.store.get(sessionId);
        const targetOrigin = session?.targetOrigin || null;
        const browser = context.browser();

        const isCurrentGeneration = (): boolean => {
            const current = this.store.get(sessionId);
            return !!current && current.generation === generation;
        };

        const invalidateIfCurrent = (lifecycleState: BrowserLifecycleState, detail: string, error?: string | null) => {
            if (!isCurrentGeneration()) {
                return;
            }
            this.store.invalidateSession(sessionId, lifecycleState, detail, error);
        };

        context.route('**/*', async (route: any) => {
            const request = route.request();
            const requestUrl = request.url();
            if (isPenPardInternalUrl(requestUrl, targetOrigin)) {
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
                const liveSession = this.store.get(sessionId);
                if (liveSession) {
                    liveSession.lastKnownUrl = url;
                }
                this.persistence.updateSession(sessionId, {
                    current_url: url,
                    last_activity_at: new Date().toISOString(),
                });
                this.persistence.addAction({
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
            const liveSession = this.store.get(sessionId);
            if (liveSession) {
                this.store.updateLastKnownPageState(liveSession, page);
            }
            this.recordTrafficEvent(sessionId, {
                kind: 'request',
                method: request.method(),
                url: request.url(),
                timestamp: new Date().toISOString(),
                originCategory: categorizeBrowserUrl(request.url(), targetOrigin),
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
                originCategory: categorizeBrowserUrl(response.url(), targetOrigin),
                resourceType: response.request().resourceType(),
                requestHeaders: response.request().headers(),
                statusCode: response.status(),
                responseHeaders,
            });

            const liveSession = this.store.get(sessionId);
            if (liveSession) {
                this.store.updateLastKnownPageState(liveSession, page);
                void this.captureScriptResponse(liveSession, response).catch((error: any) => {
                    logger.debug('Script artifact capture failed', { sessionId, error: error.message });
                });
            }
        });

        page.on('close', () => {
            const liveSession = this.store.get(sessionId);
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
        if (isPenPardInternalUrl(scriptUrl, session.targetOrigin)) {
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
            pageUrl: this.store.safePageUrl(session) || 'about:blank',
            scriptUrl,
            contentType: response.headers()['content-type'] || 'application/javascript',
            content,
            evidence: ['resourceType=script', `status=${response.status()}`],
        });
    }
}
