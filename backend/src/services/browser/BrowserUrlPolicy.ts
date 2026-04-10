import type { LiveSession } from './browserTypes';

export function getTargetOrigin(targetUrl?: string): string | null {
    if (!targetUrl) return null;
    try {
        return new URL(targetUrl).origin;
    } catch {
        return null;
    }
}

export function isPenPardInternalUrl(url: string, targetOrigin: string | null): boolean {
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

export function categorizeBrowserUrl(url: string, targetOrigin: string | null): 'target' | 'internal' | 'external' {
    if (!url) return 'external';
    try {
        const parsed = new URL(url);
        if (targetOrigin && parsed.origin === targetOrigin) {
            return 'target';
        }
        if (isPenPardInternalUrl(url, targetOrigin)) {
            return 'internal';
        }
    } catch {
        return 'external';
    }
    return 'external';
}

export function resolveBrowserRestoreUrl(
    session: Pick<LiveSession, 'lastKnownUrl' | 'targetUrl' | 'targetOrigin'>,
    preferredUrl?: string | null,
): string {
    const preferred = preferredUrl || session.lastKnownUrl || session.targetUrl || 'about:blank';
    if (preferred === 'about:blank') {
        return preferred;
    }
    return isPenPardInternalUrl(preferred, session.targetOrigin)
        ? (session.targetUrl || 'about:blank')
        : preferred;
}
