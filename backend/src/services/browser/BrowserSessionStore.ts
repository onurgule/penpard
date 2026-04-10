import type { Page } from 'playwright-core';
import { logger } from '../../utils/logger';
import { isLiveBrowserLifecycleState, type BrowserLifecycleState } from '../../types/browserLifecycle';
import type { BrowserSessionVisibility, LiveSession, ReadyLiveSession } from './browserTypes';
import { BrowserSessionPersistence } from './BrowserSessionPersistence';

interface LifecycleUpdateOptions {
    detail?: string | null;
    error?: string | null;
    status?: 'launching' | 'active' | 'paused' | 'closed';
    currentUrl?: string | null;
    closedAt?: string | null;
    clearHandles?: boolean;
    preserveTransitioning?: boolean;
}

export class BrowserSessionStore {
    public readonly sessions = new Map<string, LiveSession>();

    constructor(private readonly persistence: BrowserSessionPersistence) {}

    public get(sessionId: string): LiveSession | undefined {
        return this.sessions.get(sessionId);
    }

    public set(sessionId: string, session: LiveSession): void {
        this.sessions.set(sessionId, session);
    }

    public delete(sessionId: string): void {
        this.sessions.delete(sessionId);
    }

    public entries(): IterableIterator<[string, LiveSession]> {
        return this.sessions.entries();
    }

    public now(): string {
        return new Date().toISOString();
    }

    public safePageUrl(session: Pick<LiveSession, 'page' | 'lastKnownUrl' | 'targetUrl'>): string | null {
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

    public async safePageTitle(session: Pick<LiveSession, 'page' | 'lastKnownTitle'>): Promise<string | null> {
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

    public updateLastKnownPageState(session: LiveSession, page: Page | null = session.page): void {
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

    public buildVisibilityState(session: LiveSession): BrowserSessionVisibility {
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

    public updateLifecycleState(
        sessionId: string,
        session: LiveSession,
        lifecycleState: BrowserLifecycleState,
        options: LifecycleUpdateOptions = {},
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

        this.persistence.updateSession(sessionId, dbUpdate);
    }

    public invalidateSession(
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

    public assertReadySession(sessionId: string, operation: string): ReadyLiveSession {
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

    public async waitForSessionReady(
        sessionId: string,
        delay: (ms: number) => Promise<void>,
        timeoutMs: number = 15000,
        operation: string = 'use the browser session',
    ): Promise<ReadyLiveSession> {
        const started = Date.now();
        while (Date.now() - started < timeoutMs) {
            const session = this.sessions.get(sessionId);
            if (session && !session.transitioning) {
                return this.assertReadySession(sessionId, operation);
            }
            await delay(100);
        }

        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session ${sessionId} not found or not active`);
        }
        return this.assertReadySession(sessionId, operation);
    }

    public isSessionAlive(sessionId: string): boolean {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        try {
            this.assertReadySession(sessionId, 'check whether the browser session is alive');
            return true;
        } catch {
            return false;
        }
    }

    public isSessionAliveSimple(sessionId: string): boolean {
        return this.sessions.has(sessionId);
    }

    public getSessionVisibility(sessionId: string): BrowserSessionVisibility | null {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        this.isSessionAlive(sessionId);
        return this.buildVisibilityState(session);
    }

    public getActiveSessionCount(): number {
        let count = 0;
        for (const session of this.sessions.values()) {
            if (this.buildVisibilityState(session).isLive) {
                count += 1;
            }
        }
        return count;
    }

    private lifecycleError(sessionId: string, operation: string, session?: LiveSession): Error {
        const lifecycleState = session?.lifecycleState || 'closed';
        const detail = session?.lifecycleDetail ? ` (${session.lifecycleDetail})` : '';
        return new Error(`Cannot ${operation}: browser session ${sessionId} is ${lifecycleState}${detail}`);
    }
}
