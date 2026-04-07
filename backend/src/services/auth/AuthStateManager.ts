/**
 * PenPard Auth State Management — AuthStateManager
 * 
 * Top-level singleton per scan. Source of truth for all authentication state.
 * Owns IdentityRegistry, CookieJars, TokenStores, CSRFManagers,
 * AuthCapture, AuthInjector, and SessionHealthMonitor.
 * 
 * Usage:
 *   const auth = new AuthStateManager(scanId, targetUrl);
 *   await auth.initialize(config, burpClient);
 *   // For every outgoing request:
 *   const ctx = auth.inject(url, method, identityId);
 *   const headers = AuthInjector.mergeHeaders(originalHeaders, ctx);
 *   // After every response:
 *   auth.handleResponse(statusCode, responseHeaders, body, requestUrl, identityId);
 */

import { 
    AuthCaptureSource, AuthContext, AuthExport, AuthExportIdentity, RequestAuthBindingRules,
    DEFAULT_NO_AUTH_PATHS, AuthEvent, AuthEventType, RequestAuthDiagnostics, redactSecret,
} from './types';
import { CookieJar } from './CookieJar';
import { TokenStore } from './TokenStore';
import { CSRFManager } from './CSRFManager';
import { IdentityRegistry } from './IdentityRegistry';
import { AuthCapture } from './AuthCapture';
import { AuthInjector } from './AuthInjector';
import { SessionHealthMonitor } from './SessionHealthMonitor';
import { logger } from '../../utils/logger';
import { getHeaderValue, hasHeaderKey, parseRawBurpRequest } from '../burp-request';

/** Minimal Burp MCP client interface. */
interface BurpClient {
    callTool(tool: string, args: any): Promise<any>;
}

/** Minimal scan config interface. */
interface ScanAuthConfig {
    sessionCookies?: string;
    initialRequest?: string;
    idorUsers?: Array<{
        username?: string;
        password?: string;
        userId?: string;
        email?: string;
        role?: string;
        label?: string;
    }>;
}

export class AuthStateManager {
    // ── Core Sub-Systems ──
    public readonly identityRegistry: IdentityRegistry;
    public readonly capture: AuthCapture;
    public readonly injector: AuthInjector;
    public readonly healthMonitor: SessionHealthMonitor;

    // ── Per-Identity Stores ──
    private readonly cookieJars: Map<string, CookieJar> = new Map();
    private readonly tokenStores: Map<string, TokenStore> = new Map();
    private readonly csrfManagers: Map<string, CSRFManager> = new Map();

    // ── Config ──
    private readonly scanId: string;
    private readonly targetUrl: string;
    private readonly rules: RequestAuthBindingRules;
    private initialized: boolean = false;
    private readonly burpRequestBaselines: Map<string, {
        url: string;
        hasAuthorization: boolean;
        hasCookie: boolean;
        hasCustomAuth: boolean;
    }> = new Map();

    // ── Events ──
    private events: AuthEvent[] = [];

    constructor(scanId: string, targetUrl: string) {
        this.scanId = scanId;
        this.targetUrl = targetUrl;

        // Extract target host for scope rules
        let targetHost = 'localhost';
        try {
            targetHost = new URL(targetUrl).hostname;
        } catch { /* invalid URL */ }

        // Default binding rules
        this.rules = {
            authRequiredHosts: [targetHost],
            noAuthPaths: [...DEFAULT_NO_AUTH_PATHS],
            csrfRequiredMethods: new Set(['POST', 'PUT', 'PATCH', 'DELETE']),
            defaultIdentityId: 'primary-user',
            cookiePathScopingEnabled: true,
            stripAuthOnRedirect: true,
        };

        // Initialize sub-systems
        this.identityRegistry = new IdentityRegistry(scanId);
        this.capture = new AuthCapture(this.identityRegistry, this.cookieJars, this.tokenStores, this.csrfManagers);
        this.injector = new AuthInjector(this.identityRegistry, this.cookieJars, this.tokenStores, this.csrfManagers, this.rules);
        this.healthMonitor = new SessionHealthMonitor(this.identityRegistry, this.tokenStores, this.cookieJars, targetUrl);
    }

    // ═══════════════════════════════════════════════════════════
    //  INITIALIZATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Initialize auth state from scan config and Burp proxy.
     * Called during phaseInit().
     */
    async initialize(config: ScanAuthConfig, burpClient: BurpClient, browserSessionId?: string | null): Promise<void> {
        logger.info(`AuthStateManager: Initializing for scan ${this.scanId}`);

        let targetHost: string;
        try {
            targetHost = new URL(this.targetUrl).hostname;
        } catch {
            logger.warn('AuthStateManager: Invalid target URL');
            return;
        }

        // ── 1. Create primary identity ──
        this.identityRegistry.createPrimary('Primary User');

        // ── 2. Create IDOR/secondary identities from config ──
        if (config.idorUsers && config.idorUsers.length > 0) {
            this.identityRegistry.initializeFromIdorUsers(config.idorUsers);
        }

        // ── 3. Capture from operator-provided cookies ──
        if (config.sessionCookies?.trim()) {
            this.capture.fromOperatorCookies(config.sessionCookies, targetHost, 'primary-user');
            this.emitEvent('cookie_captured', 'primary-user', 'Operator-provided cookies captured');
        }

        // ── 4. Capture from Burp proxy history ──
        try {
            const { cookies, tokens } = await this.capture.fromBurpHistory(burpClient, targetHost, 'primary-user');
            if (cookies.length > 0) this.emitEvent('cookie_captured', 'primary-user', `${cookies.length} cookies from Burp history`);
            if (tokens.length > 0) this.emitEvent('token_captured', 'primary-user', `${tokens.length} tokens from Burp history`);
        } catch (e: any) {
            logger.warn(`AuthStateManager: Burp history capture failed: ${e.message}`);
        }

        // ── 5. Capture from the exact Burp request that started the scan ──
        if (config.initialRequest?.trim()) {
            const seeded = this.captureFromRawRequest(config.initialRequest.trim(), 'primary-user');
            if (seeded.cookiesCaptured > 0) {
                this.emitEvent('cookie_captured', 'primary-user', `${seeded.cookiesCaptured} cookies from Burp initial request`);
            }
            if (seeded.tokensCaptured > 0) {
                this.emitEvent('token_captured', 'primary-user', `${seeded.tokensCaptured} tokens from Burp initial request`);
            }
        }

        // ── 6. Initialize health monitors ──
        for (const identity of this.identityRegistry.getAll()) {
            this.healthMonitor.initializeHealth(identity.id);
            this.ensureStores(identity.id);

            // Auto-detect refresh strategy
            const strategy = this.healthMonitor.autoDetectRefreshStrategy(identity.id);
            this.healthMonitor.setRefreshPlan(identity.id, strategy);
        }

        this.initialized = true;
        logger.info(`AuthStateManager: Initialized — ${this.identityRegistry.size} identities, ${this.getTotalCookies()} cookies, ${this.getTotalTokens()} tokens`);
    }

    // ═══════════════════════════════════════════════════════════
    //  MAIN API — INJECT
    // ═══════════════════════════════════════════════════════════

    /**
     * Prepare auth context for an outgoing request.
     * This is the primary method called by OrchestratorAgent.executeToolCall().
     */
    inject(url: string, method: string = 'GET', identityId?: string): AuthContext {
        return this.injector.prepare(url, method, identityId);
    }

    /**
     * Merge auth headers into existing request headers.
     * Convenience wrapper around AuthInjector.mergeHeaders().
     */
    mergeHeaders(existingHeaders: Record<string, string> | undefined, url: string, method: string = 'GET', identityId?: string): Record<string, string> {
        return this.prepareRequest(existingHeaders, undefined, url, method, identityId).headers;
    }

    /**
     * Prepare final outgoing request components with deterministic auth handling.
     * Set preserveExplicitAuth=true for exact Burp request replay or auth bypass tests.
     */
    prepareRequest(
        existingHeaders: Record<string, string> | undefined,
        body: string | undefined,
        url: string,
        method: string = 'GET',
        identityId?: string,
        preserveExplicitAuth: boolean = false,
    ): { context: AuthContext; headers: Record<string, string>; body: string } {
        return this.injector.prepareRequest(existingHeaders, body, url, method, identityId, preserveExplicitAuth);
    }

    // ═══════════════════════════════════════════════════════════
    //  MAIN API — RESPONSE HANDLING
    // ═══════════════════════════════════════════════════════════

    /**
     * Handle HTTP response — capture new cookies/tokens, update health.
     * Called after every send_http_request.
     */
    handleResponse(
        statusCode: number,
        headers: Record<string, string> | Array<string>,
        body: string,
        requestUrl: string,
        identityId: string = 'primary-user',
    ): { needsRefresh: boolean; needsRelogin: boolean; isCSRFFailure: boolean } {
        // 1. Capture any new auth material from response
        const normalizedHeaders = this.normalizeHeaders(headers);
        this.capture.fromResponse({ statusCode, headers: normalizedHeaders, body }, requestUrl, identityId);

        // 2. Analyze session health
        const healthResult = this.healthMonitor.analyzeResponse(identityId, statusCode, normalizedHeaders, body);

        // 3. Emit events
        if (healthResult.needsRefresh) {
            this.emitEvent('session_expired', identityId, 'Session needs refresh');
        }
        if (healthResult.needsRelogin) {
            this.emitEvent('session_dead', identityId, 'Session is dead — re-login required');
        }

        return healthResult;
    }

    /**
     * Attempt to refresh a session (proactive or reactive).
     */
    async refreshSession(identityId: string, burpClient: BurpClient): Promise<boolean> {
        const success = await this.healthMonitor.executeRefresh(identityId, burpClient);
        if (success) {
            this.emitEvent('session_refreshed', identityId, 'Session refreshed successfully');
        }
        return success;
    }

    // ═══════════════════════════════════════════════════════════
    //  BROWSER SYNC
    // ═══════════════════════════════════════════════════════════

    /**
     * Sync cookies from browser context into AuthStateManager.
     * Called after browser_navigate, browser_fill_and_submit.
     */
    syncFromBrowser(playwrightCookies: Array<{
        name: string; value: string; domain: string; path: string;
        expires: number; httpOnly: boolean; secure: boolean; sameSite: string;
    }>, identityId: string = 'primary-user'): void {
        this.capture.fromBrowserCookies(playwrightCookies, identityId);
    }

    /**
     * Sync cookies from browser storage (localStorage/sessionStorage).
     */
    syncFromBrowserStorage(storageData: {
        localStorageData?: Record<string, string>;
        sessionStorageData?: Record<string, string>;
    }, identityId: string = 'primary-user'): void {
        this.capture.fromBrowserStorage(storageData, identityId);
    }

    /**
     * Export cookies for pushing into a Playwright BrowserContext.
     */
    exportForBrowser(identityId: string = 'primary-user', domain?: string): Array<{
        name: string; value: string; domain: string; path: string;
        expires: number; httpOnly: boolean; secure: boolean; sameSite: 'Strict' | 'Lax' | 'None';
    }> {
        const jar = this.cookieJars.get(identityId);
        return jar ? jar.exportForPlaywright(domain) : [];
    }

    /**
     * Detect CSRF from browser page state.
     */
    detectCSRFFromPage(pageState: any, identityId: string = 'primary-user'): void {
        this.capture.fromBrowserPageState(pageState, identityId);
    }

    // ═══════════════════════════════════════════════════════════
    //  HARVEST INTEGRATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Capture auth from a harvested request.
     */
    captureFromHarvestedRequest(request: {
        requestHeaders: Record<string, string>;
        params?: Array<{ name: string; value: string; location: string }>;
        url: string;
    }, identityId: string = 'primary-user'): void {
        this.capture.fromHarvestedRequest(request, identityId);
    }

    /**
     * Capture auth state from a structured request before execution.
     * Useful when an explicit Burp-derived Authorization header is present but
     * the managed auth store has not learned it yet.
     */
    captureFromStructuredRequest(request: {
        requestHeaders: Record<string, string>;
        url: string;
        body?: string;
        params?: Array<{ name: string; value: string; location: string }>;
    }, identityId: string = 'primary-user', source: AuthCaptureSource = 'agent_explicit_request'): {
        cookies: number;
        tokens: number;
        csrfDetected: boolean;
    } {
        this.ensureStores(identityId);

        const params = request.params || this.extractRequestParams(request.url, request.body || '', request.requestHeaders);
        const captured = this.capture.fromStructuredRequest({
            requestHeaders: request.requestHeaders,
            params,
            url: request.url,
        }, identityId, source);

        return {
            cookies: captured.cookies.length,
            tokens: captured.tokens.length,
            csrfDetected: captured.csrfDetected,
        };
    }

    /**
     * Capture auth state from a raw Burp request string.
     */
    captureFromRawRequest(rawRequest: string, identityId: string = 'primary-user'): {
        parsed: ReturnType<typeof parseRawBurpRequest>;
        cookiesCaptured: number;
        tokensCaptured: number;
    } {
        const parsed = parseRawBurpRequest(rawRequest);
        if (!parsed) {
            return { parsed: null, cookiesCaptured: 0, tokensCaptured: 0 };
        }

        const captureResult = this.captureFromStructuredRequest({
            requestHeaders: parsed.headers,
            url: parsed.url,
            body: parsed.body,
        }, identityId, 'burp_initial_request');

        this.burpRequestBaselines.set(identityId, {
            url: parsed.url,
            hasAuthorization: !!getHeaderValue(parsed.headers, 'authorization'),
            hasCookie: !!getHeaderValue(parsed.headers, 'cookie'),
            hasCustomAuth: this.hasCustomAuthHeaders(parsed.headers),
        });

        return {
            parsed,
            cookiesCaptured: captureResult.cookies,
            tokensCaptured: captureResult.tokens,
        };
    }

    /**
     * Inspect how auth material will be used for a request.
     * Used for warnings and 401 recovery decisions.
     */
    assessPreparedRequest(opts: {
        originalHeaders?: Record<string, string>;
        preparedHeaders: Record<string, string>;
        url: string;
        method?: string;
        identityId?: string;
        preserveExplicitAuth?: boolean;
    }): RequestAuthDiagnostics {
        const method = opts.method || 'GET';
        const identityId = opts.identityId || this.rules.defaultIdentityId;
        const context = this.inject(opts.url, method, identityId);
        const explicitAuthorizationValue = getHeaderValue(opts.originalHeaders, 'authorization');
        const explicitCookieValue = getHeaderValue(opts.originalHeaders, 'cookie');
        const explicitCustomAuthPresent = this.hasCustomAuthHeaders(opts.originalHeaders);
        const outgoingAuthorizationValue = getHeaderValue(opts.preparedHeaders, 'authorization');
        const outgoingCookieValue = getHeaderValue(opts.preparedHeaders, 'cookie');
        const outgoingCustomAuthPresent = this.hasCustomAuthHeaders(opts.preparedHeaders);
        const storedCustomAuthAvailable = Object.keys(context.customHeaders).length > 0;
        const storedAuthAvailable = AuthInjector.hasAuth(context);
        const baseline = this.burpRequestBaselines.get(identityId);

        let likelyRequiresAuth = false;
        try {
            const parsedUrl = new URL(opts.url);
            likelyRequiresAuth =
                this.isHostInScope(parsedUrl.hostname) &&
                !this.isNoAuthPath(parsedUrl.pathname) &&
                (
                    !!baseline?.hasAuthorization ||
                    !!baseline?.hasCookie ||
                    !!baseline?.hasCustomAuth ||
                    !!explicitAuthorizationValue ||
                    !!explicitCookieValue ||
                    explicitCustomAuthPresent ||
                    storedAuthAvailable ||
                    this.matchesProtectedPath(parsedUrl.pathname)
                );
        } catch {
            likelyRequiresAuth = !!baseline?.hasAuthorization || !!baseline?.hasCookie || storedAuthAvailable;
        }

        let warning: string | undefined;
        if (likelyRequiresAuth && context.authorizationHeader && !outgoingAuthorizationValue) {
            warning = `Request is leaving without Authorization for ${identityId} even though managed token material is available.`;
        } else if (likelyRequiresAuth && storedAuthAvailable && !outgoingAuthorizationValue && !outgoingCookieValue && !outgoingCustomAuthPresent) {
            warning = `Request is leaving without any auth material for ${identityId} even though PenPard has stored auth state for this target.`;
        }

        return {
            identityId,
            method: method.toUpperCase(),
            url: opts.url,
            likelyRequiresAuth,
            storedAuthAvailable,
            storedAuthorizationAvailable: !!context.authorizationHeader,
            storedCookieAvailable: !!context.cookies,
            storedCustomAuthAvailable,
            explicitAuthorizationPresent: !!explicitAuthorizationValue,
            explicitAuthorizationKeyPresent: hasHeaderKey(opts.originalHeaders, 'authorization'),
            explicitCookiePresent: !!explicitCookieValue,
            explicitCookieKeyPresent: hasHeaderKey(opts.originalHeaders, 'cookie'),
            explicitCustomAuthPresent,
            explicitCustomAuthKeyPresent: this.hasCustomAuthHeaderKeys(opts.originalHeaders),
            outgoingAuthorizationPresent: !!outgoingAuthorizationValue,
            outgoingCookiePresent: !!outgoingCookieValue,
            outgoingCustomAuthPresent,
            preserveExplicitAuth: opts.preserveExplicitAuth === true,
            warning,
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  STATE QUERIES
    // ═══════════════════════════════════════════════════════════

    /** Get the CookieJar for an identity. */
    getCookieJar(identityId: string): CookieJar | undefined {
        return this.cookieJars.get(identityId);
    }

    /** Get the TokenStore for an identity. */
    getTokenStore(identityId: string): TokenStore | undefined {
        return this.tokenStores.get(identityId);
    }

    /** Get the CSRFManager for an identity. */
    getCSRFManager(identityId: string): CSRFManager | undefined {
        return this.csrfManagers.get(identityId);
    }

    /** Get total cookies across all identities. */
    getTotalCookies(): number {
        let total = 0;
        for (const jar of this.cookieJars.values()) total += jar.size;
        return total;
    }

    /** Get total active tokens across all identities. */
    getTotalTokens(): number {
        let total = 0;
        for (const store of this.tokenStores.values()) total += store.activeCount;
        return total;
    }

    /** Whether the manager has been initialized. */
    get isInitialized(): boolean {
        return this.initialized;
    }

    /** Get pentester loop state for frontend display. */
    getPentesterLoopState(): Record<string, any> {
        return {
            authIdentities: this.identityRegistry.getAll().map(i => ({
                id: i.id,
                label: i.label,
                role: i.role,
                isActive: i.isActive,
                username: i.username,
            })),
            authCookies: this.getTotalCookies(),
            authTokens: this.getTotalTokens(),
            authHealth: this.healthMonitor.getHealthReport(),
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  SYSTEM PROMPT GENERATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Generate the auth block for the system prompt.
     * Replaces the old static cookie/auth header injection.
     * Tells the LLM that auth is handled automatically.
     */
    getSystemPromptBlock(): string {
        const identities = this.identityRegistry.getAll();
        const jar = this.cookieJars.get('primary-user');
        const store = this.tokenStores.get('primary-user');

        let block = '\n\n═══════════════════════════════════════════════════════════════\n';
        block += '  AUTHENTICATION (managed automatically by PenPard)\n';
        block += '═══════════════════════════════════════════════════════════════\n\n';

        if (this.getTotalCookies() > 0 || this.getTotalTokens() > 0) {
            block += 'AUTH IS HANDLED AUTOMATICALLY. PenPard injects the correct Cookie, Authorization, and CSRF headers into every request.\n';
            block += 'You do NOT need to set Cookie or Authorization headers manually in send_http_request calls.\n';
            block += 'If you need exact Burp replay or auth bypass testing, set preserveExplicitAuth=true.\n';
            block += 'If you need to test without auth, use identityId="__none__".\n';
            block += 'If you need to test as a different user, use identityId="idor-user-1".\n\n';

            block += `Active identities: ${identities.map(i => `${i.id} (${i.label})`).join(', ')}\n`;
            block += `Cookies: ${this.getTotalCookies()} | Tokens: ${this.getTotalTokens()}\n`;

            if (jar && jar.size > 0) {
                block += `Session cookies: ${jar.getSessionCookies().map(c => c.name).join(', ') || 'none detected'}\n`;
            }
            if (store && store.activeCount > 0) {
                block += `Auth scheme: ${store.getActive()?.tokenType || 'cookie-only'}\n`;
            }
        } else {
            block += 'No authentication material captured yet.\n';
            block += 'For authenticated testing: have the user browse the target through Burp and log in first.\n';
            block += 'PenPard will automatically capture session cookies and tokens from Burp proxy history.\n';
        }

        return block;
    }

    // ═══════════════════════════════════════════════════════════
    //  EXPORT FOR HUMAN REUSE
    // ═══════════════════════════════════════════════════════════

    /**
     * Export live auth state for human pentester reuse.
     * Generates JSON with cookies, tokens, CSRF, and curl examples.
     */
    exportForHumanReuse(): AuthExport {
        const identities: AuthExportIdentity[] = [];

        for (const identity of this.identityRegistry.getAll()) {
            const jar = this.cookieJars.get(identity.id);
            const store = this.tokenStores.get(identity.id);
            const csrf = this.csrfManagers.get(identity.id);
            const health = this.healthMonitor.getHealth(identity.id);

            const cookies = jar ? jar.resolve(this.targetUrl) : '';
            const authHeader = store ? store.formatAuthHeader() : null;
            const csrfToken = csrf?.getPrimary() ? { name: csrf.getPrimary()!.tokenName, value: csrf.getPrimary()!.tokenValue } : null;
            const customHeaders = store ? store.getCustomHeaders() : {};

            // Build curl example
            let curlCmd = `curl`;
            if (cookies) curlCmd += ` -H 'Cookie: ${cookies}'`;
            if (authHeader) curlCmd += ` -H 'Authorization: ${authHeader}'`;
            if (csrfToken) curlCmd += ` -H 'X-CSRF-Token: ${csrfToken.value}'`;
            for (const [k, v] of Object.entries(customHeaders)) {
                curlCmd += ` -H '${k}: ${v}'`;
            }
            curlCmd += ` '${this.targetUrl}'`;

            identities.push({
                id: identity.id,
                label: identity.label,
                role: identity.role,
                username: identity.username,
                cookies,
                authorizationHeader: authHeader,
                csrfToken,
                customHeaders,
                curlExample: curlCmd,
                sessionHealth: {
                    isAlive: health?.isAlive ?? false,
                    confidence: health?.confidence ?? 0,
                    lastValidated: health?.lastProbeAt?.toISOString() ?? null,
                },
            });
        }

        return {
            exportedAt: new Date().toISOString(),
            scanId: this.scanId,
            targetUrl: this.targetUrl,
            identities,
        };
    }

    // ═══════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════

    /** Get all auth events. */
    getEvents(): AuthEvent[] {
        return [...this.events];
    }

    /** Get recent events (last N). */
    getRecentEvents(count: number = 10): AuthEvent[] {
        return this.events.slice(-count);
    }

    private emitEvent(type: AuthEventType, identityId: string, detail: string, data?: any): void {
        this.events.push({ type, identityId, timestamp: new Date(), detail, data });
        logger.info(`AuthEvent: [${type}] ${identityId} — ${detail}`);
    }

    // ═══════════════════════════════════════════════════════════
    //  SUMMARY
    // ═══════════════════════════════════════════════════════════

    /** Full summary for logging. */
    toSummary(): string {
        const lines: string[] = [
            `AuthStateManager (scan: ${this.scanId})`,
            this.identityRegistry.toSummary(),
        ];

        for (const [id, jar] of this.cookieJars.entries()) {
            lines.push(`  ${id}: ${jar.toRedactedSummary()}`);
        }
        for (const [id, store] of this.tokenStores.entries()) {
            lines.push(`  ${id}: ${store.toRedactedSummary()}`);
        }
        for (const [id, csrf] of this.csrfManagers.entries()) {
            lines.push(`  ${id}: ${csrf.toRedactedSummary()}`);
        }

        lines.push(this.healthMonitor.toSummary());
        return lines.join('\n');
    }

    // ═══════════════════════════════════════════════════════════
    //  INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════

    /** Ensure CookieJar, TokenStore, and CSRFManager exist for an identity. */
    private ensureStores(identityId: string): void {
        if (!this.cookieJars.has(identityId)) {
            this.cookieJars.set(identityId, new CookieJar(identityId));
        }
        if (!this.tokenStores.has(identityId)) {
            this.tokenStores.set(identityId, new TokenStore(identityId));
        }
        if (!this.csrfManagers.has(identityId)) {
            this.csrfManagers.set(identityId, new CSRFManager(identityId));
        }
    }

    /** Normalize response headers. */
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
        const result: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers)) {
            result[k.toLowerCase()] = v;
        }
        return result;
    }

    private extractRequestParams(url: string, body: string, headers: Record<string, string>): Array<{ name: string; value: string; location: string }> {
        const params: Array<{ name: string; value: string; location: string }> = [];

        try {
            const parsedUrl = new URL(url);
            parsedUrl.searchParams.forEach((value, name) => {
                params.push({ name, value, location: 'query' });
            });
        } catch { /* ignore */ }

        if (!body) return params;

        try {
            const parsedBody = JSON.parse(body);
            if (typeof parsedBody === 'object' && parsedBody !== null) {
                for (const [name, value] of Object.entries(parsedBody)) {
                    params.push({ name, value: String(value), location: 'body' });
                }
                return params;
            }
        } catch { /* ignore */ }

        try {
            const encoded = new URLSearchParams(body);
            encoded.forEach((value, name) => {
                params.push({ name, value, location: 'body' });
            });
        } catch { /* ignore */ }

        return params;
    }

    private isHostInScope(hostname: string): boolean {
        const lower = hostname.toLowerCase();
        for (const pattern of this.rules.authRequiredHosts) {
            if (pattern === lower) return true;
            if (pattern.startsWith('*.') && lower.endsWith(pattern.substring(1))) return true;
            if (lower.endsWith('.' + pattern)) return true;
        }
        return false;
    }

    private isNoAuthPath(pathname: string): boolean {
        const lower = pathname.toLowerCase();
        for (const path of this.rules.noAuthPaths) {
            if (lower === path || lower.startsWith(path + '/') || lower.startsWith(path + '?')) return true;
        }
        return false;
    }

    private matchesProtectedPath(pathname: string): boolean {
        return /\/(api|graphql|account|profile|admin|billing|orders|users|me|session|settings|checkout|cart|wallet|tenant)/i.test(pathname);
    }

    private hasCustomAuthHeaders(headers: Record<string, string> | undefined): boolean {
        if (!headers) return false;
        return Object.entries(headers).some(([name, value]) =>
            this.isCustomAuthHeaderName(name) && typeof value === 'string' && value.trim().length > 0
        );
    }

    private hasCustomAuthHeaderKeys(headers: Record<string, string> | undefined): boolean {
        if (!headers) return false;
        return Object.keys(headers).some(name => this.isCustomAuthHeaderName(name));
    }

    private isCustomAuthHeaderName(name: string): boolean {
        return [
            'x-api-key',
            'x-auth-token',
            'x-access-token',
            'x-session-token',
            'api-key',
            'apikey',
            'x-token',
        ].includes(name.toLowerCase());
    }
}
