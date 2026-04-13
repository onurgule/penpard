import crypto from 'crypto';
import { db } from '../../db/init';
import { GitHubAuthSessionStatus, GitHubAuthSessionSummary } from './types';

interface GitHubAuthSessionRow {
    id: string;
    user_id: number;
    provider: string;
    status: GitHubAuthSessionStatus;
    state: string;
    code_verifier: string;
    redirect_uri: string;
    app_redirect_url: string | null;
    authorization_url: string | null;
    created_at: string;
    expires_at: string;
    completed_at: string | null;
    error_message: string | null;
    result_json: string | null;
}

function parseResult(raw: string | null): GitHubAuthSessionSummary['result'] {
    if (!raw) return undefined;
    try {
        return JSON.parse(raw);
    } catch {
        return undefined;
    }
}

function toSummary(row: GitHubAuthSessionRow): GitHubAuthSessionSummary {
    return {
        id: row.id,
        provider: 'github',
        status: row.status,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        completedAt: row.completed_at,
        appRedirectUrl: row.app_redirect_url,
        authorizationUrl: row.authorization_url,
        errorMessage: row.error_message,
        result: parseResult(row.result_json),
    };
}

export class GitHubAuthSessionStore {
    expireStaleSessions(): number {
        const result = db.prepare(`
            UPDATE integration_auth_sessions
            SET status = 'expired',
                completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
                error_message = COALESCE(error_message, 'GitHub authorization session expired.')
            WHERE provider = 'github'
              AND status = 'pending'
              AND datetime(expires_at) <= datetime('now')
        `).run();

        return result.changes;
    }

    createPendingSession(input: {
        userId: number;
        state: string;
        codeVerifier: string;
        redirectUri: string;
        appRedirectUrl: string;
        authorizationUrl: string;
        expiresAt: string;
    }): GitHubAuthSessionSummary {
        this.expireStaleSessions();

        const id = crypto.randomUUID();
        db.prepare(`
            INSERT INTO integration_auth_sessions (
                id,
                user_id,
                provider,
                status,
                state,
                code_verifier,
                redirect_uri,
                app_redirect_url,
                authorization_url,
                expires_at
            )
            VALUES (?, ?, 'github', 'pending', ?, ?, ?, ?, ?, ?)
        `).run(
            id,
            input.userId,
            input.state,
            input.codeVerifier,
            input.redirectUri,
            input.appRedirectUrl,
            input.authorizationUrl,
            input.expiresAt
        );

        return this.getById(id, input.userId)!;
    }

    getById(id: string, userId?: number): GitHubAuthSessionSummary | null {
        this.expireStaleSessions();

        const row = userId
            ? db.prepare(`
                SELECT *
                FROM integration_auth_sessions
                WHERE id = ? AND user_id = ? AND provider = 'github'
            `).get(id, userId) as GitHubAuthSessionRow | undefined
            : db.prepare(`
                SELECT *
                FROM integration_auth_sessions
                WHERE id = ? AND provider = 'github'
            `).get(id) as GitHubAuthSessionRow | undefined;

        return row ? toSummary(row) : null;
    }

    getPendingSessionByState(state: string): (GitHubAuthSessionSummary & {
        userId: number;
        codeVerifier: string;
        redirectUri: string;
    }) | null {
        this.expireStaleSessions();

        const row = db.prepare(`
            SELECT *
            FROM integration_auth_sessions
            WHERE state = ? AND provider = 'github'
        `).get(state) as GitHubAuthSessionRow | undefined;

        if (!row) {
            return null;
        }

        return {
            ...toSummary(row),
            userId: row.user_id,
            codeVerifier: row.code_verifier,
            redirectUri: row.redirect_uri,
        };
    }

    markCompleted(sessionId: string, result: NonNullable<GitHubAuthSessionSummary['result']>): GitHubAuthSessionSummary {
        db.prepare(`
            UPDATE integration_auth_sessions
            SET status = 'completed',
                completed_at = CURRENT_TIMESTAMP,
                error_message = NULL,
                result_json = ?
            WHERE id = ? AND provider = 'github'
        `).run(JSON.stringify(result), sessionId);

        return this.getById(sessionId)!;
    }

    updateAppRedirectUrl(sessionId: string, appRedirectUrl: string): void {
        db.prepare(`
            UPDATE integration_auth_sessions
            SET app_redirect_url = ?
            WHERE id = ? AND provider = 'github'
        `).run(appRedirectUrl, sessionId);
    }

    markFailed(sessionId: string, errorMessage: string): GitHubAuthSessionSummary {
        db.prepare(`
            UPDATE integration_auth_sessions
            SET status = 'failed',
                completed_at = CURRENT_TIMESTAMP,
                error_message = ?,
                result_json = NULL
            WHERE id = ? AND provider = 'github'
        `).run(errorMessage, sessionId);

        return this.getById(sessionId)!;
    }

    buildElectronReturnUrl(sessionId: string, status: 'success' | 'error'): string {
        return `penpard://app/settings?githubAuthSession=${encodeURIComponent(sessionId)}&githubAuthResult=${status}`;
    }

    buildWebReturnUrl(origin: string, sessionId: string, status: 'success' | 'error'): string {
        const safeOrigin = origin.replace(/\/$/, '');
        return `${safeOrigin}/settings?githubAuthSession=${encodeURIComponent(sessionId)}&githubAuthResult=${status}`;
    }

    getDefaultWebOrigin(): string {
        return process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, '') || 'http://localhost:3000';
    }
}
