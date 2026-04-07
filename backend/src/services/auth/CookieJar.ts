/**
 * PenPard Auth State Management — CookieJar
 * 
 * RFC 6265-compliant per-identity cookie storage with domain/path scoping,
 * expiration tracking, and Set-Cookie parsing.
 */

import { CookieEntry, AuthCaptureSource, SESSION_COOKIE_PATTERNS, CSRF_COOKIE_PATTERNS, redactSecret } from './types';
import { logger } from '../../utils/logger';

export class CookieJar {
    /** Cookies keyed by domain → path → name to preserve RFC 6265 path variants. */
    private cookies: Map<string, Map<string, Map<string, CookieEntry>>> = new Map();
    private readonly identityId: string;

    constructor(identityId: string) {
        this.identityId = identityId;
    }

    // ═══════════════════════════════════════════════════════════
    //  SET-COOKIE PARSING
    // ═══════════════════════════════════════════════════════════

    /**
     * Parse a Set-Cookie header string and store the cookie.
     * Handles: name=value; Domain=...; Path=...; Expires=...; Max-Age=...; HttpOnly; Secure; SameSite=...
     */
    parseAndStore(setCookieHeader: string, requestDomain: string, source: AuthCaptureSource): CookieEntry | null {
        if (!setCookieHeader || !setCookieHeader.includes('=')) return null;

        try {
            const parts = setCookieHeader.split(';').map(p => p.trim());
            const [nameValue, ...attrs] = parts;
            const eqIdx = nameValue.indexOf('=');
            if (eqIdx <= 0) return null;

            const name = nameValue.substring(0, eqIdx).trim();
            const value = nameValue.substring(eqIdx + 1).trim();

            // Parse attributes
            let domain = requestDomain;
            let hostOnly = true;
            let path = '/';
            let expires: Date | null = null;
            let maxAge: number | null = null;
            let httpOnly = false;
            let secure = false;
            let sameSite: 'strict' | 'lax' | 'none' | null = null;

            for (const attr of attrs) {
                const lower = attr.toLowerCase();
                if (lower.startsWith('domain=')) {
                    domain = attr.substring(7).trim().replace(/^\./, ''); // strip leading dot
                    hostOnly = false;
                } else if (lower.startsWith('path=')) {
                    path = attr.substring(5).trim() || '/';
                } else if (lower.startsWith('expires=')) {
                    const dateStr = attr.substring(8).trim();
                    const parsed = new Date(dateStr);
                    if (!isNaN(parsed.getTime())) expires = parsed;
                } else if (lower.startsWith('max-age=')) {
                    const seconds = parseInt(attr.substring(8).trim(), 10);
                    if (!isNaN(seconds)) {
                        maxAge = seconds;
                        expires = new Date(Date.now() + seconds * 1000);
                    }
                } else if (lower === 'httponly') {
                    httpOnly = true;
                } else if (lower === 'secure') {
                    secure = true;
                } else if (lower.startsWith('samesite=')) {
                    const val = attr.substring(9).trim().toLowerCase();
                    if (val === 'strict' || val === 'lax' || val === 'none') sameSite = val;
                }
            }

            const entry: CookieEntry = {
                identityId: this.identityId,
                name,
                value,
                domain: domain.toLowerCase(),
                hostOnly,
                path,
                expires,
                maxAge,
                httpOnly,
                secure,
                sameSite,
                source,
                capturedAt: new Date(),
                lastUpdatedAt: new Date(),
                isSessionCookie: SESSION_COOKIE_PATTERNS.some(p => p.test(name)),
                isCSRFCookie: CSRF_COOKIE_PATTERNS.some(p => p.test(name)),
            };

            this.set(entry);
            return entry;
        } catch (e: any) {
            logger.warn(`CookieJar: Failed to parse Set-Cookie: ${e.message}`);
            return null;
        }
    }

    /**
     * Parse multiple Set-Cookie headers from a response.
     */
    parseMultiple(setCookieHeaders: string[], requestDomain: string, source: AuthCaptureSource): CookieEntry[] {
        const results: CookieEntry[] = [];
        for (const header of setCookieHeaders) {
            const entry = this.parseAndStore(header, requestDomain, source);
            if (entry) results.push(entry);
        }
        return results;
    }

    /**
     * Parse a Cookie header string (name1=val1; name2=val2) into entries.
     * Used for importing operator-provided cookies.
     */
    parseCookieHeader(cookieHeader: string, domain: string, source: AuthCaptureSource): CookieEntry[] {
        const results: CookieEntry[] = [];
        if (!cookieHeader) return results;

        const cleaned = cookieHeader.replace(/^Cookie:\s*/i, '').trim();
        const pairs = cleaned.split(';').map(p => p.trim()).filter(p => p);

        for (const pair of pairs) {
            const eqIdx = pair.indexOf('=');
            if (eqIdx <= 0) continue;

            const name = pair.substring(0, eqIdx).trim();
            const value = pair.substring(eqIdx + 1).trim();

            const entry: CookieEntry = {
                identityId: this.identityId,
                name,
                value,
                domain: domain.toLowerCase(),
                hostOnly: true,
                path: '/',
                expires: null,          // unknown from Cookie header
                maxAge: null,
                httpOnly: false,        // unknown
                secure: false,          // unknown
                sameSite: null,
                source,
                capturedAt: new Date(),
                lastUpdatedAt: new Date(),
                isSessionCookie: SESSION_COOKIE_PATTERNS.some(p => p.test(name)),
                isCSRFCookie: CSRF_COOKIE_PATTERNS.some(p => p.test(name)),
            };

            this.set(entry);
            results.push(entry);
        }

        return results;
    }

    // ═══════════════════════════════════════════════════════════
    //  STORAGE
    // ═══════════════════════════════════════════════════════════

    /** Set or update a cookie. */
    set(entry: CookieEntry): void {
        const domain = entry.domain.toLowerCase();
        const path = entry.path || '/';
        if (!this.cookies.has(domain)) {
            this.cookies.set(domain, new Map());
        }
        const domainMap = this.cookies.get(domain)!;
        if (!domainMap.has(path)) {
            domainMap.set(path, new Map());
        }
        const pathMap = domainMap.get(path)!;
        const existing = pathMap.get(entry.name);
        if (existing) {
            entry.capturedAt = existing.capturedAt; // preserve original capture time
        }
        entry.lastUpdatedAt = new Date();
        pathMap.set(entry.name, entry);
    }

    /** Remove a cookie by domain + name. */
    remove(domain: string, name: string, path?: string): void {
        const domainMap = this.cookies.get(domain.toLowerCase());
        if (!domainMap) return;

        if (path) {
            const pathMap = domainMap.get(path);
            pathMap?.delete(name);
            if (pathMap && pathMap.size === 0) {
                domainMap.delete(path);
            }
        } else {
            for (const [cookiePath, pathMap] of domainMap.entries()) {
                pathMap.delete(name);
                if (pathMap.size === 0) {
                    domainMap.delete(cookiePath);
                }
            }
        }

        if (domainMap.size === 0) {
            this.cookies.delete(domain.toLowerCase());
        }
    }

    /** Get a specific cookie. */
    get(domain: string, name: string, path?: string): CookieEntry | undefined {
        const domainMap = this.cookies.get(domain.toLowerCase());
        if (!domainMap) return undefined;

        if (path) {
            return domainMap.get(path)?.get(name);
        }

        const matches: CookieEntry[] = [];
        for (const pathMap of domainMap.values()) {
            const match = pathMap.get(name);
            if (match) matches.push(match);
        }

        matches.sort((a, b) => {
            const pathDiff = b.path.length - a.path.length;
            if (pathDiff !== 0) return pathDiff;
            return a.capturedAt.getTime() - b.capturedAt.getTime();
        });

        return matches[0];
    }

    /** Clear all cookies. */
    clear(): void {
        this.cookies.clear();
    }

    /** Get all cookies (across all domains). */
    getAll(): CookieEntry[] {
        const all: CookieEntry[] = [];
        for (const domainMap of this.cookies.values()) {
            for (const pathMap of domainMap.values()) {
                for (const entry of pathMap.values()) {
                    all.push(entry);
                }
            }
        }
        return all;
    }

    /** Get all session cookies. */
    getSessionCookies(): CookieEntry[] {
        return this.getAll().filter(c => c.isSessionCookie);
    }

    /** Get all CSRF cookies. */
    getCSRFCookies(): CookieEntry[] {
        return this.getAll().filter(c => c.isCSRFCookie);
    }

    /** Total cookie count. */
    get size(): number {
        let total = 0;
        for (const domainMap of this.cookies.values()) {
            for (const pathMap of domainMap.values()) {
                total += pathMap.size;
            }
        }
        return total;
    }

    // ═══════════════════════════════════════════════════════════
    //  RESOLUTION — Which cookies go to which request?
    // ═══════════════════════════════════════════════════════════

    /**
     * Resolve cookies for a given URL.
     * Applies RFC 6265 domain/path matching, expiration, and Secure checks.
     * Returns a formatted Cookie header string.
     */
    resolve(url: string, enablePathScoping: boolean = true): string {
        let parsedUrl: URL;
        try {
            parsedUrl = new URL(url);
        } catch {
            return '';
        }

        const hostname = parsedUrl.hostname.toLowerCase();
        const urlPath = parsedUrl.pathname || '/';
        const isSecure = parsedUrl.protocol === 'https:';
        const now = new Date();

        const matching: CookieEntry[] = [];

        for (const [, domainMap] of this.cookies.entries()) {
            for (const pathMap of domainMap.values()) {
                for (const cookie of pathMap.values()) {
                    // Domain matching: exact match or subdomain match, with host-only support
                    if (!this.domainMatches(hostname, cookie)) continue;

                    // Expiration check
                    if (cookie.expires && cookie.expires < now) continue;

                    // Secure flag check
                    if (cookie.secure && !isSecure) continue;

                    // Path matching (RFC 6265 §5.1.4)
                    if (enablePathScoping && !this.pathMatches(urlPath, cookie.path)) continue;

                    matching.push(cookie);
                }
            }
        }

        if (matching.length === 0) return '';

        // Sort: longest path first (more specific first), then by creation time
        matching.sort((a, b) => {
            const pathDiff = b.path.length - a.path.length;
            if (pathDiff !== 0) return pathDiff;
            return a.capturedAt.getTime() - b.capturedAt.getTime();
        });

        return matching.map(c => `${c.name}=${c.value}`).join('; ');
    }

    /**
     * Remove expired cookies.
     */
    purgeExpired(): number {
        const now = new Date();
        let purged = 0;
        for (const [domain, domainMap] of this.cookies.entries()) {
            for (const [path, pathMap] of domainMap.entries()) {
                for (const [name, cookie] of pathMap.entries()) {
                    if (cookie.expires && cookie.expires < now) {
                        pathMap.delete(name);
                        purged++;
                    }
                }
                if (pathMap.size === 0) {
                    domainMap.delete(path);
                }
            }
            if (domainMap.size === 0) {
                this.cookies.delete(domain);
            }
        }
        return purged;
    }

    // ═══════════════════════════════════════════════════════════
    //  IMPORT / EXPORT
    // ═══════════════════════════════════════════════════════════

    /**
     * Import cookies from Playwright's context.cookies() format.
     */
    importFromPlaywright(playwrightCookies: Array<{
        name: string; value: string; domain: string; path: string;
        expires: number; httpOnly: boolean; secure: boolean; sameSite: string;
    }>, source: AuthCaptureSource = 'browser_context_cookies'): void {
        for (const pc of playwrightCookies) {
            const entry: CookieEntry = {
                identityId: this.identityId,
                name: pc.name,
                value: pc.value,
                domain: pc.domain.replace(/^\./, '').toLowerCase(),
                hostOnly: !pc.domain.startsWith('.'),
                path: pc.path || '/',
                expires: pc.expires > 0 ? new Date(pc.expires * 1000) : null,
                maxAge: null,
                httpOnly: pc.httpOnly,
                secure: pc.secure,
                sameSite: (pc.sameSite?.toLowerCase() as any) || null,
                source,
                capturedAt: new Date(),
                lastUpdatedAt: new Date(),
                isSessionCookie: SESSION_COOKIE_PATTERNS.some(p => p.test(pc.name)),
                isCSRFCookie: CSRF_COOKIE_PATTERNS.some(p => p.test(pc.name)),
            };
            this.set(entry);
        }
    }

    /**
     * Export cookies in Playwright's addCookies() format.
     */
    exportForPlaywright(domain?: string): Array<{
        name: string; value: string; domain: string; path: string;
        expires: number; httpOnly: boolean; secure: boolean; sameSite: 'Strict' | 'Lax' | 'None';
    }> {
        const all = domain
            ? this.getAll().filter(c => c.domain === domain.toLowerCase())
            : this.getAll();

        return all.map(c => ({
            name: c.name,
            value: c.value,
            domain: c.hostOnly ? c.domain : `.${c.domain}`,
            path: c.path,
            expires: c.expires ? Math.floor(c.expires.getTime() / 1000) : -1,
            httpOnly: c.httpOnly,
            secure: c.secure,
            sameSite: (c.sameSite === 'strict' ? 'Strict' : c.sameSite === 'lax' ? 'Lax' : 'None') as 'Strict' | 'Lax' | 'None',
        }));
    }

    /**
     * Export as a summary string for logging (redacted values).
     */
    toRedactedSummary(): string {
        const entries = this.getAll();
        if (entries.length === 0) return 'CookieJar: empty';

        const lines = entries.map(c => {
            const flags = [
                c.hostOnly ? 'HostOnly' : 'Domain',
                c.httpOnly ? 'HttpOnly' : '',
                c.secure ? 'Secure' : '',
                c.isSessionCookie ? '🔑Session' : '',
                c.isCSRFCookie ? '🛡CSRF' : '',
            ].filter(Boolean).join(', ');
            return `  ${c.domain}${c.path}: ${c.name}=${redactSecret(c.value, 'cookie')}${flags ? ` [${flags}]` : ''}`;
        });

        return `CookieJar (${entries.length} cookies):\n${lines.join('\n')}`;
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════

    /**
     * Domain matching per RFC 6265 §5.1.3.
     * hostname "sub.example.com" matches cookie domain "example.com".
     */
    private domainMatches(hostname: string, cookie: CookieEntry): boolean {
        const cookieDomain = cookie.domain.toLowerCase();
        if (cookie.hostOnly) {
            return hostname === cookieDomain;
        }
        if (hostname === cookieDomain) return true;
        if (hostname.endsWith('.' + cookieDomain)) return true;
        return false;
    }

    /**
     * Path matching per RFC 6265 §5.1.4.
     */
    private pathMatches(requestPath: string, cookiePath: string): boolean {
        if (requestPath === cookiePath) return true;
        if (requestPath.startsWith(cookiePath)) {
            // cookie path "/foo" matches request "/foobar" only if cookie path ends with "/"
            // or the next char in request is "/"
            if (cookiePath.endsWith('/')) return true;
            if (requestPath[cookiePath.length] === '/') return true;
        }
        return false;
    }
}
