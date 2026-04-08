/**
 * PenPard Auth State Management — AuthInjector
 * 
 * Deterministic request header assembly. For every outgoing HTTP request,
 * resolves the correct identity's auth material and assembles the
 * Cookie, Authorization, CSRF, and custom auth headers.
 * 
 * This replaces the LLM-driven header-copying approach.
 */

import {
    AuthContext,
    AuthContextHeaders,
    RequestAuthBindingRules,
    LOGIN_PATH_PATTERNS,
    CSRF_HEADER_NAMES,
    AUTH_BOOTSTRAP_PATH_PATTERNS,
    RequestAuthIntent,
} from './types';
import { CookieJar } from './CookieJar';
import { TokenStore } from './TokenStore';
import { CSRFManager } from './CSRFManager';
import { IdentityRegistry } from './IdentityRegistry';
import { logger } from '../../utils/logger';

export class AuthInjector {
    private static readonly KNOWN_CUSTOM_AUTH_HEADERS = [
        'x-api-key',
        'x-auth-token',
        'x-access-token',
        'x-session-token',
        'api-key',
        'apikey',
        'x-token',
    ];

    private readonly identityRegistry: IdentityRegistry;
    private readonly cookieJars: Map<string, CookieJar>;
    private readonly tokenStores: Map<string, TokenStore>;
    private readonly csrfManagers: Map<string, CSRFManager>;
    private readonly rules: RequestAuthBindingRules;

    constructor(
        identityRegistry: IdentityRegistry,
        cookieJars: Map<string, CookieJar>,
        tokenStores: Map<string, TokenStore>,
        csrfManagers: Map<string, CSRFManager>,
        rules: RequestAuthBindingRules,
    ) {
        this.identityRegistry = identityRegistry;
        this.cookieJars = cookieJars;
        this.tokenStores = tokenStores;
        this.csrfManagers = csrfManagers;
        this.rules = rules;
    }

    // ═══════════════════════════════════════════════════════════
    //  MAIN INJECTION METHOD
    // ═══════════════════════════════════════════════════════════

    /**
     * Prepare the AuthContext for an outgoing request.
     * This is the single deterministic function that all request paths call.
     * 
     * @param url - The target URL
     * @param method - HTTP method (GET, POST, etc.)
     * @param identityId - Which identity to use (default: primary). Use '__none__' for anonymous.
     * @returns AuthContext with all headers to inject
     */
    prepare(url: string, method: string = 'GET', identityId?: string, intent: RequestAuthIntent = 'authenticated'): AuthContext {
        const resolvedIdentityId = identityId || this.rules.defaultIdentityId;

        // Anonymous / unauthenticated request — return empty context
        if (resolvedIdentityId === IdentityRegistry.ANONYMOUS_ID) {
            return this.emptyContext(resolvedIdentityId);
        }

        // Check if identity exists and is active
        const identity = this.identityRegistry.get(resolvedIdentityId);
        if (!identity) {
            logger.warn(`AuthInjector: Identity "${resolvedIdentityId}" not found — falling back to anonymous`);
            return this.emptyContext(resolvedIdentityId);
        }
        if (!identity.isActive) {
            logger.warn(`AuthInjector: Identity "${resolvedIdentityId}" is deactivated (${identity.deactivationReason}) — returning empty auth`);
            return this.emptyContext(resolvedIdentityId, `Identity deactivated: ${identity.deactivationReason}`);
        }

        let parsedUrl: URL;
        try {
            parsedUrl = new URL(url);
        } catch {
            logger.warn(`AuthInjector: Invalid URL "${url}" — returning empty auth`);
            return this.emptyContext(resolvedIdentityId, 'Invalid URL');
        }

        // ── HOST SCOPE CHECK ──
        if (!this.isHostInScope(parsedUrl.hostname)) {
            return this.emptyContext(resolvedIdentityId, `Host ${parsedUrl.hostname} not in auth scope`);
        }

        // ── NO-AUTH PATH CHECK ──
        if (this.isNoAuthPath(parsedUrl.pathname)) {
            return this.emptyContext(resolvedIdentityId, `Path ${parsedUrl.pathname} excluded from auth`);
        }

        // ── COOKIE ASSEMBLY ──
        if (this.shouldSuppressManagedAuth(parsedUrl.pathname, intent)) {
            return this.emptyContext(
                resolvedIdentityId,
                `Managed auth suppressed for ${intent} on ${parsedUrl.pathname}`,
            );
        }

        const jar = this.cookieJars.get(resolvedIdentityId);
        const cookies = jar ? jar.resolve(url, this.rules.cookiePathScopingEnabled) : '';

        // ── AUTHORIZATION HEADER ──
        const tokenStore = this.tokenStores.get(resolvedIdentityId);
        const authorizationHeader = tokenStore ? tokenStore.formatAuthHeader() : null;

        // ── CSRF INJECTION ──
        let csrfHeaderName: string | null = null;
        let csrfHeaderValue: string | null = null;
        let csrfBodyField: string | null = null;
        let csrfBodyValue: string | null = null;

        const upperMethod = method.toUpperCase();
        if (this.rules.csrfRequiredMethods.has(upperMethod)) {
            const csrfManager = this.csrfManagers.get(resolvedIdentityId);
            if (csrfManager?.hasCSRF) {
                // Refresh from cookie jar first (cookie-to-header pattern)
                if (jar) csrfManager.refreshFromCookieJar(jar);

                const csrfHeaders = csrfManager.getHeadersForRequest();
                const headerEntries = Object.entries(csrfHeaders);
                if (headerEntries.length > 0) {
                    csrfHeaderName = headerEntries[0][0];
                    csrfHeaderValue = headerEntries[0][1];
                }

                const bodyFields = csrfManager.getBodyFieldsForRequest();
                const fieldEntries = Object.entries(bodyFields);
                if (fieldEntries.length > 0) {
                    csrfBodyField = fieldEntries[0][0];
                    csrfBodyValue = fieldEntries[0][1];
                }
            }
        }

        // ── CUSTOM HEADERS ──
        const customHeaders: Record<string, string> = tokenStore ? tokenStore.getCustomHeaders() : {};

        // ── WARNING CHECK ──
        let warning: string | undefined;
        if (tokenStore) {
            const secondsLeft = tokenStore.getSecondsUntilExpiry();
            if (secondsLeft !== null && secondsLeft <= 120) {
                warning = `Token expires in ${secondsLeft}s — refresh recommended`;
            }
            if (tokenStore.isExpired()) {
                warning = 'Token is EXPIRED — refresh required';
            }
        }

        const context: AuthContext = {
            identityId: resolvedIdentityId,
            cookies,
            authorizationHeader,
            csrfHeaderName,
            csrfHeaderValue,
            csrfBodyField,
            csrfBodyValue,
            customHeaders,
            warning,
        };

        // ── CONTAMINATION CHECK ──
        // Verify the resolved auth context actually belongs to the requested identity
        if (identityId && identityId !== resolvedIdentityId) {
            logger.error(`AuthInjector: CONTAMINATION — requested ${identityId} but resolved ${resolvedIdentityId}`);
        }

        return context;
    }

    /**
     * Prepare final request components for an outgoing request.
     * When preserveExplicit is enabled, explicit headers/body are trusted as-is
     * and no automatic auth material is injected.
     */
    prepareRequest(
        existingHeaders: Record<string, string> | undefined,
        body: string | undefined,
        url: string,
        method: string = 'GET',
        identityId?: string,
        preserveExplicit: boolean = false,
        intent: RequestAuthIntent = 'authenticated',
    ): { context: AuthContext; headers: Record<string, string>; body: string } {
        const context = this.prepare(url, method, identityId, intent);
        const normalizedBody = body || '';

        if (preserveExplicit) {
            return {
                context,
                headers: { ...(existingHeaders || {}) },
                body: normalizedBody,
            };
        }

        const strippedHeaders = this.stripManagedHeaders(existingHeaders);
        return {
            context,
            headers: AuthInjector.mergeHeaders(strippedHeaders, context),
            body: AuthInjector.injectCSRFIntoBody(normalizedBody, context),
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  HEADER MERGING
    // ═══════════════════════════════════════════════════════════

    /**
     * Convert an AuthContext into a flat header map.
     * Ready to merge into request headers.
     */
    static toHeaders(context: AuthContext): AuthContextHeaders {
        const headers: AuthContextHeaders = {};

        if (context.cookies) {
            headers['Cookie'] = context.cookies;
        }
        if (context.authorizationHeader) {
            headers['Authorization'] = context.authorizationHeader;
        }
        if (context.csrfHeaderName && context.csrfHeaderValue) {
            headers[context.csrfHeaderName] = context.csrfHeaderValue;
        }
        for (const [name, value] of Object.entries(context.customHeaders)) {
            headers[name] = value;
        }

        return headers;
    }

    /**
     * Merge auth headers into existing request headers.
     * Auth headers OVERRIDE any existing values (deterministic injection).
     * 
     * Exception: if `preserveExplicit` is true, explicitly-set auth headers
     * in the original are preserved (for auth bypass testing).
     */
    static mergeHeaders(
        existingHeaders: Record<string, string> | undefined,
        context: AuthContext,
        preserveExplicit: boolean = false,
    ): Record<string, string> {
        const merged = { ...(existingHeaders || {}) };
        const authHeaders = AuthInjector.toHeaders(context);

        for (const [name, value] of Object.entries(authHeaders)) {
            const lowerName = name.toLowerCase();
            const existingKey = Object.keys(merged).find(k => k.toLowerCase() === lowerName);

            if (preserveExplicit && existingKey) {
                // Preserve explicitly-set auth header (auth bypass test)
                continue;
            }

            // Remove existing key with different casing
            if (existingKey && existingKey !== name) {
                delete merged[existingKey];
            }

            merged[name] = value;
        }

        return merged;
    }

    /**
     * Inject CSRF body fields into a request body.
     * Supports JSON and form-urlencoded bodies.
     */
    static injectCSRFIntoBody(body: string | undefined, context: AuthContext): string {
        if (!context.csrfBodyField || !context.csrfBodyValue) return body || '';
        if (!body) body = '';

        // Try JSON injection
        try {
            const parsed = JSON.parse(body);
            if (typeof parsed === 'object' && parsed !== null) {
                parsed[context.csrfBodyField] = context.csrfBodyValue;
                return JSON.stringify(parsed);
            }
        } catch { /* not JSON */ }

        // Form-urlencoded injection
        if (body.includes('=') || body === '') {
            const separator = body ? '&' : '';
            return `${body}${separator}${encodeURIComponent(context.csrfBodyField)}=${encodeURIComponent(context.csrfBodyValue)}`;
        }

        return body;
    }

    // ═══════════════════════════════════════════════════════════
    //  SCOPE CHECKS
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if a hostname is in the auth scope.
     */
    private isHostInScope(hostname: string): boolean {
        const lower = hostname.toLowerCase();
        for (const pattern of this.rules.authRequiredHosts) {
            // Exact match
            if (pattern === lower) return true;
            // Wildcard *.example.com
            if (pattern.startsWith('*.') && lower.endsWith(pattern.substring(1))) return true;
            // Subdomain match
            if (lower.endsWith('.' + pattern)) return true;
        }
        return false;
    }

    /**
     * Check if a path should NOT receive auth headers.
     */
    private isNoAuthPath(pathname: string): boolean {
        const lower = pathname.toLowerCase();
        for (const np of this.rules.noAuthPaths) {
            if (lower === np || lower.startsWith(np + '/') || lower.startsWith(np + '?')) return true;
        }
        return false;
    }

    isAuthBootstrapPath(pathname: string): boolean {
        const lower = pathname.toLowerCase();
        return AUTH_BOOTSTRAP_PATH_PATTERNS.some((pattern) => pattern.test(lower));
    }

    private shouldSuppressManagedAuth(pathname: string, intent: RequestAuthIntent): boolean {
        if (!['anonymous_auth_probe', 'account_creation'].includes(intent)) {
            return false;
        }
        return this.isAuthBootstrapPath(pathname);
    }

    private stripManagedHeaders(existingHeaders: Record<string, string> | undefined): Record<string, string> {
        const stripped = { ...(existingHeaders || {}) };
        const managedHeaderNames = this.getManagedHeaderNames();

        for (const key of Object.keys(stripped)) {
            if (managedHeaderNames.has(key.toLowerCase())) {
                delete stripped[key];
            }
        }

        return stripped;
    }

    private getManagedHeaderNames(): Set<string> {
        const names = new Set<string>([
            'cookie',
            'authorization',
            ...CSRF_HEADER_NAMES.map(name => name.toLowerCase()),
            ...AuthInjector.KNOWN_CUSTOM_AUTH_HEADERS,
        ]);

        for (const store of this.tokenStores.values()) {
            for (const token of store.getAllActive()) {
                if (token.headerName && token.headerName !== '__refresh__') {
                    names.add(token.headerName.toLowerCase());
                }
            }
        }

        for (const csrfManager of this.csrfManagers.values()) {
            for (const csrfState of csrfManager.getAll()) {
                if (csrfState.headerName) {
                    names.add(csrfState.headerName.toLowerCase());
                }
            }
        }

        return names;
    }

    /**
     * Return an empty AuthContext.
     */
    private emptyContext(identityId: string, warning?: string): AuthContext {
        return {
            identityId,
            cookies: '',
            authorizationHeader: null,
            csrfHeaderName: null,
            csrfHeaderValue: null,
            csrfBodyField: null,
            csrfBodyValue: null,
            customHeaders: {},
            warning,
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  UTILITIES
    // ═══════════════════════════════════════════════════════════

    /**
     * Check whether an AuthContext has any auth material at all.
     */
    static hasAuth(context: AuthContext): boolean {
        return !!(context.cookies || context.authorizationHeader || Object.keys(context.customHeaders).length > 0);
    }

    /**
     * Detect if a response indicates the session has died (redirect to login).
     */
    static isLoginRedirect(statusCode: number, headers: Record<string, string>): boolean {
        if (statusCode !== 301 && statusCode !== 302 && statusCode !== 303 && statusCode !== 307) return false;
        const location = headers['location'] || headers['Location'] || '';
        return LOGIN_PATH_PATTERNS.some(p => p.test(location));
    }

    /**
     * Detect if a response indicates CSRF validation failure.
     */
    static isCSRFFailure(statusCode: number, body: string): boolean {
        if (statusCode !== 403 && statusCode !== 419 && statusCode !== 422) return false;
        const lower = (body || '').toLowerCase();
        return lower.includes('csrf') || lower.includes('token') || lower.includes('verification') || lower.includes('forgery');
    }

    /**
     * Summary for logging.
     */
    toSummary(): string {
        const identities = this.identityRegistry.getAll();
        const lines: string[] = [];
        for (const identity of identities) {
            const jar = this.cookieJars.get(identity.id);
            const store = this.tokenStores.get(identity.id);
            const csrf = this.csrfManagers.get(identity.id);
            lines.push(`  ${identity.id}: ${jar?.size || 0} cookies, ${store?.activeCount || 0} tokens, ${csrf?.hasCSRF ? 'CSRF' : 'no CSRF'}`);
        }
        return `AuthInjector:\n  Scope: ${this.rules.authRequiredHosts.join(', ')}\n${lines.join('\n')}`;
    }
}
