/**
 * PenPard Auth State Management — AuthCapture
 * 
 * Multi-source auth material capture: Burp proxy, browser context,
 * response headers, DOM, operator input, login responses.
 * Normalizes and routes captured material to the correct identity's stores.
 */

import { AuthCaptureSource, CookieEntry, TokenState, CSRFState, AuthEvidence, redactSecret } from './types';
import { CookieJar } from './CookieJar';
import { TokenStore } from './TokenStore';
import { CSRFManager } from './CSRFManager';
import { IdentityRegistry } from './IdentityRegistry';
import { logger } from '../../utils/logger';

/** Minimal Burp MCP client interface for decoupling. */
interface BurpClient {
    callTool(tool: string, args: any): Promise<any>;
}

export class AuthCapture {
    private readonly identityRegistry: IdentityRegistry;
    private readonly cookieJars: Map<string, CookieJar>;
    private readonly tokenStores: Map<string, TokenStore>;
    private readonly csrfManagers: Map<string, CSRFManager>;
    private evidence: AuthEvidence[] = [];

    /** Custom auth header names detected in traffic. */
    private detectedCustomAuthHeaders: Set<string> = new Set();

    /** Well-known custom auth header patterns. */
    private static readonly CUSTOM_AUTH_PATTERNS = [
        /^x-api-key$/i,
        /^x-auth-token$/i,
        /^x-access-token$/i,
        /^x-session-token$/i,
        /^api-key$/i,
        /^apikey$/i,
        /^x-token$/i,
    ];

    constructor(
        identityRegistry: IdentityRegistry,
        cookieJars: Map<string, CookieJar>,
        tokenStores: Map<string, TokenStore>,
        csrfManagers: Map<string, CSRFManager>,
    ) {
        this.identityRegistry = identityRegistry;
        this.cookieJars = cookieJars;
        this.tokenStores = tokenStores;
        this.csrfManagers = csrfManagers;
    }

    // ═══════════════════════════════════════════════════════════
    //  SOURCE 1: OPERATOR INPUT
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth from operator-provided session cookies string.
     * Input: "Cookie: name1=val1; name2=val2" or "name1=val1; name2=val2"
     */
    fromOperatorCookies(cookieHeader: string, targetDomain: string, identityId: string): CookieEntry[] {
        const jar = this.getOrCreateJar(identityId);
        const entries = jar.parseCookieHeader(cookieHeader, targetDomain, 'operator_input');
        this.recordEvidence('operator_input', `${entries.length} cookies`, identityId);
        logger.info(`AuthCapture: ${entries.length} cookies from operator input for ${identityId}`);
        return entries;
    }

    /**
     * Capture auth from operator-provided Authorization header.
     */
    fromOperatorAuthHeader(authHeader: string, identityId: string): TokenState | null {
        const store = this.getOrCreateTokenStore(identityId);
        const token = store.storeFromAuthHeader(authHeader, 'operator_input');
        if (token) {
            this.recordEvidence('operator_input', `${token.tokenType} token`, identityId);
            this.enrichIdentityFromToken(identityId, token);
            logger.info(`AuthCapture: ${token.tokenType} token from operator for ${identityId}`);
        }
        return token;
    }

    // ═══════════════════════════════════════════════════════════
    //  SOURCE 2: BURP PROXY HISTORY
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth material from Burp proxy history.
     * Scans recent requests for cookies and auth headers.
     */
    async fromBurpHistory(burpClient: BurpClient, targetHost: string, identityId: string, maxItems: number = 50): Promise<{
        cookies: CookieEntry[];
        tokens: TokenState[];
    }> {
        const cookies: CookieEntry[] = [];
        const tokens: TokenState[] = [];

        try {
            // Method 1: get_cookies_and_auth_for_host (newest to oldest)
            const historyResult = await burpClient.callTool('get_cookies_and_auth_for_host', {
                host: targetHost,
                maxItems,
            });

            const entries = Array.isArray(historyResult?.entries) ? historyResult.entries : [];

            for (const entry of entries) {
                // Capture cookies
                if (entry?.cookie && String(entry.cookie).trim()) {
                    const jar = this.getOrCreateJar(identityId);
                    const parsed = jar.parseCookieHeader(String(entry.cookie), targetHost, 'burp_proxy_history');
                    cookies.push(...parsed);
                }

                // Capture Authorization header
                if (entry?.authorization && String(entry.authorization).trim()) {
                    const store = this.getOrCreateTokenStore(identityId);
                    const token = store.storeFromAuthHeader(String(entry.authorization), 'burp_proxy_history');
                    if (token) {
                        tokens.push(token);
                        this.enrichIdentityFromToken(identityId, token);
                    }
                }
            }

            // Method 2: Fallback — get_session_cookies for single most recent
            if (cookies.length === 0 && tokens.length === 0) {
                try {
                    const result = await burpClient.callTool('get_session_cookies', { host: targetHost });
                    const cookie = result?.cookieHeader;
                    if (cookie && typeof cookie === 'string' && cookie.trim()) {
                        const jar = this.getOrCreateJar(identityId);
                        const parsed = jar.parseCookieHeader(cookie, targetHost, 'burp_proxy_history');
                        cookies.push(...parsed);
                    }
                } catch { /* fallback failed */ }
            }

            if (cookies.length > 0 || tokens.length > 0) {
                this.recordEvidence('burp_proxy_history', `${cookies.length} cookies, ${tokens.length} tokens`, identityId);
                logger.info(`AuthCapture: From Burp history — ${cookies.length} cookies, ${tokens.length} tokens for ${identityId}`);
            }
        } catch (e: any) {
            logger.warn(`AuthCapture: Burp history capture failed: ${e.message}`);
        }

        return { cookies, tokens };
    }

    // ═══════════════════════════════════════════════════════════
    //  SOURCE 3: HTTP RESPONSE (Set-Cookie + token rotation)
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth material from an HTTP response.
     * Called after every send_http_request to pick up Set-Cookie, token rotation, CSRF headers.
     */
    fromResponse(response: {
        statusCode?: number;
        headers?: Record<string, string> | Array<string>;
        body?: string;
    }, requestUrl: string, identityId: string): {
        newCookies: CookieEntry[];
        newTokens: TokenState[];
        csrfDetected: boolean;
    } {
        const newCookies: CookieEntry[] = [];
        const newTokens: TokenState[] = [];
        let csrfDetected = false;

        let requestDomain: string;
        try {
            requestDomain = new URL(requestUrl).hostname;
        } catch {
            return { newCookies, newTokens, csrfDetected };
        }

        // Normalize headers to Record<string, string>
        const headers = this.normalizeHeaders(response.headers);

        // Capture Set-Cookie headers
        const setCookieValues = this.extractSetCookieHeaders(headers, response.headers);
        if (setCookieValues.length > 0) {
            const jar = this.getOrCreateJar(identityId);
            const parsed = jar.parseMultiple(setCookieValues, requestDomain, 'login_response_header');
            newCookies.push(...parsed);

            // Check for CSRF cookies
            const csrfManager = this.getOrCreateCSRFManager(identityId);
            for (const cookie of parsed) {
                if (cookie.isCSRFCookie) {
                    csrfManager.detectFromCSRFCookie(cookie.name, cookie.value);
                    csrfDetected = true;
                }
            }
        }

        // Capture CSRF response headers
        const csrfManager = this.getOrCreateCSRFManager(identityId);
        const csrfFromHeaders = csrfManager.detectFromResponseHeaders(headers);
        if (csrfFromHeaders) csrfDetected = true;

        // Detect custom auth headers in response (rare, but some APIs return new tokens)
        for (const [name, value] of Object.entries(headers)) {
            if (AuthCapture.CUSTOM_AUTH_PATTERNS.some(p => p.test(name)) && value) {
                const store = this.getOrCreateTokenStore(identityId);
                const token = store.storeCustomHeader(name, value, 'login_response_header');
                newTokens.push(token);
                this.detectedCustomAuthHeaders.add(name.toLowerCase());
            }
        }

        return { newCookies, newTokens, csrfDetected };
    }

    // ═══════════════════════════════════════════════════════════
    //  SOURCE 4: BROWSER CONTEXT
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth from Playwright browser context cookies.
     */
    fromBrowserCookies(playwrightCookies: Array<{
        name: string; value: string; domain: string; path: string;
        expires: number; httpOnly: boolean; secure: boolean; sameSite: string;
    }>, identityId: string): void {
        const jar = this.getOrCreateJar(identityId);
        jar.importFromPlaywright(playwrightCookies, 'browser_context_cookies');
        this.recordEvidence('browser_context_cookies', `${playwrightCookies.length} cookies`, identityId);

        // Check for CSRF cookies
        const csrfManager = this.getOrCreateCSRFManager(identityId);
        for (const pc of playwrightCookies) {
            const lower = pc.name.toLowerCase();
            if (lower.includes('csrf') || lower.includes('xsrf') || lower.includes('_token')) {
                csrfManager.detectFromCSRFCookie(pc.name, pc.value);
            }
        }
    }

    /**
     * Capture auth from browser localStorage/sessionStorage.
     * Scans for JWT-shaped values and known token key names.
     */
    fromBrowserStorage(storageData: {
        localStorageData?: Record<string, string>;
        sessionStorageData?: Record<string, string>;
    }, identityId: string): TokenState[] {
        const tokens: TokenState[] = [];
        const store = this.getOrCreateTokenStore(identityId);

        const tokenKeyPatterns = [
            /^token$/i, /^access_token$/i, /^auth_token$/i, /^jwt$/i,
            /^id_token$/i, /^bearer$/i, /^session_token$/i, /^api_token$/i,
            /^user_token$/i, /^auth$/i,
        ];

        const scan = (data: Record<string, string> | undefined, source: AuthCaptureSource) => {
            if (!data) return;
            for (const [key, value] of Object.entries(data)) {
                if (!value || typeof value !== 'string') continue;

                // Check if key matches a known token pattern
                const isTokenKey = tokenKeyPatterns.some(p => p.test(key));

                // Check if value looks like a JWT
                const isJWT = value.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

                if (isTokenKey || isJWT) {
                    const token = store.store({
                        tokenType: isJWT ? 'jwt' : 'opaque',
                        headerName: 'Authorization',
                        headerValuePrefix: 'Bearer ',
                        value,
                        expiresAt: null,
                        isRefreshToken: key.toLowerCase().includes('refresh'),
                        source,
                        capturedAt: new Date(),
                    });
                    tokens.push(token);
                    this.enrichIdentityFromToken(identityId, token);
                }
            }
        };

        scan(storageData.localStorageData, 'browser_local_storage');
        scan(storageData.sessionStorageData, 'browser_session_storage');

        if (tokens.length > 0) {
            this.recordEvidence('browser_local_storage', `${tokens.length} tokens from storage`, identityId);
            logger.info(`AuthCapture: ${tokens.length} tokens from browser storage for ${identityId}`);
        }

        return tokens;
    }

    /**
     * Capture CSRF from browser page state (hidden inputs + meta tags).
     */
    fromBrowserPageState(pageState: {
        forms?: Array<{ fields?: Array<{ name: string; type: string; value: string }> }>;
        metaTags?: Array<{ name: string; content: string }>;
    }, identityId: string): CSRFState | null {
        const csrfManager = this.getOrCreateCSRFManager(identityId);
        return csrfManager.detectFromPageState(pageState);
    }

    // ═══════════════════════════════════════════════════════════
    //  SOURCE 5: HARVESTED REQUESTS
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth material from a harvested request (RequestHarvester output).
     * Extracts cookies, auth headers, and CSRF params.
     */
    fromHarvestedRequest(request: {
        requestHeaders: Record<string, string>;
        params?: Array<{ name: string; value: string; location: string }>;
        url: string;
    }, identityId: string): void {
        let domain: string;
        try {
            domain = new URL(request.url).hostname;
        } catch {
            return;
        }

        // Capture Cookie header
        const cookie = request.requestHeaders['cookie'] || request.requestHeaders['Cookie'];
        if (cookie) {
            const jar = this.getOrCreateJar(identityId);
            jar.parseCookieHeader(cookie, domain, 'burp_proxy_history');
        }

        // Capture Authorization header
        const auth = request.requestHeaders['authorization'] || request.requestHeaders['Authorization'];
        if (auth) {
            const store = this.getOrCreateTokenStore(identityId);
            store.storeFromAuthHeader(auth, 'burp_proxy_history');
        }

        // Capture custom auth headers
        for (const [name, value] of Object.entries(request.requestHeaders)) {
            if (AuthCapture.CUSTOM_AUTH_PATTERNS.some(p => p.test(name)) && value) {
                const store = this.getOrCreateTokenStore(identityId);
                store.storeCustomHeader(name, value, 'burp_proxy_history');
                this.detectedCustomAuthHeaders.add(name.toLowerCase());
            }
        }

        // Capture CSRF params
        if (request.params) {
            const csrfManager = this.getOrCreateCSRFManager(identityId);
            csrfManager.detectFromRequestParams(request.params);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  EVIDENCE & HELPERS
    // ═══════════════════════════════════════════════════════════

    /** Get all captured evidence records. */
    getEvidence(): AuthEvidence[] {
        return [...this.evidence];
    }

    /** Get detected custom auth header names. */
    getDetectedCustomAuthHeaders(): string[] {
        return [...this.detectedCustomAuthHeaders];
    }

    private recordEvidence(source: AuthCaptureSource, detail: string, identityId: string): void {
        this.evidence.push({
            captureSource: source,
            rawDataRedacted: detail,
            capturedAt: new Date(),
            linkedIdentityId: identityId,
            validated: false,
            validatedAt: null,
        });
    }

    /**
     * If a JWT token contains user claims, enrich the identity profile.
     */
    private enrichIdentityFromToken(identityId: string, token: TokenState): void {
        if (token.jwtPayload) {
            this.identityRegistry.updateFromClaims(identityId, token.jwtPayload);
        }
    }

    private getOrCreateJar(identityId: string): CookieJar {
        if (!this.cookieJars.has(identityId)) {
            this.cookieJars.set(identityId, new CookieJar(identityId));
        }
        return this.cookieJars.get(identityId)!;
    }

    private getOrCreateTokenStore(identityId: string): TokenStore {
        if (!this.tokenStores.has(identityId)) {
            this.tokenStores.set(identityId, new TokenStore(identityId));
        }
        return this.tokenStores.get(identityId)!;
    }

    private getOrCreateCSRFManager(identityId: string): CSRFManager {
        if (!this.csrfManagers.has(identityId)) {
            this.csrfManagers.set(identityId, new CSRFManager(identityId));
        }
        return this.csrfManagers.get(identityId)!;
    }

    /**
     * Normalize response headers to a flat Record<string, string>.
     */
    private normalizeHeaders(headers: Record<string, string> | Array<string> | undefined): Record<string, string> {
        if (!headers) return {};
        if (Array.isArray(headers)) {
            const result: Record<string, string> = {};
            for (const line of headers) {
                const idx = line.indexOf(':');
                if (idx > 0) {
                    result[line.substring(0, idx).trim().toLowerCase()] = line.substring(idx + 1).trim();
                }
            }
            return result;
        }
        // Lowercase all keys for consistent lookup
        const result: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers)) {
            result[k.toLowerCase()] = v;
        }
        return result;
    }

    /**
     * Extract all Set-Cookie values from response headers.
     * Handles both Array<string> and Record<string, string> formats,
     * including the common case where multiple Set-Cookie headers exist.
     */
    private extractSetCookieHeaders(normalized: Record<string, string>, original: Record<string, string> | Array<string> | undefined): string[] {
        const results: string[] = [];

        // From normalized (may lose multiple Set-Cookie headers)
        if (normalized['set-cookie']) {
            results.push(normalized['set-cookie']);
        }

        // From original array format (preserves multiple Set-Cookie)
        if (Array.isArray(original)) {
            for (const line of original) {
                if (line.toLowerCase().startsWith('set-cookie:')) {
                    const value = line.substring(11).trim();
                    if (value && !results.includes(value)) {
                        results.push(value);
                    }
                }
            }
        }

        return results;
    }
}
