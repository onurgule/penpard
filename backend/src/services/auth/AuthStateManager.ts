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
    AuthContext, AuthExport, AuthExportIdentity, RequestAuthBindingRules,
    DEFAULT_NO_AUTH_PATHS, AuthEvent, AuthEventType, redactSecret,
} from './types';
import { CookieJar } from './CookieJar';
import { TokenStore } from './TokenStore';
import { CSRFManager } from './CSRFManager';
import { IdentityRegistry } from './IdentityRegistry';
import { AuthCapture } from './AuthCapture';
import { AuthInjector } from './AuthInjector';
import { SessionHealthMonitor } from './SessionHealthMonitor';
import { logger } from '../../utils/logger';

/** Minimal Burp MCP client interface. */
interface BurpClient {
    callTool(tool: string, args: any): Promise<any>;
}

/** Minimal scan config interface. */
interface ScanAuthConfig {
    sessionCookies?: string;
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

        // ── 5. Initialize health monitors ──
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
        const ctx = this.inject(url, method, identityId);
        return AuthInjector.mergeHeaders(existingHeaders, ctx);
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
            block += 'If you need to test without auth (auth bypass), use: repeater_test with identityId="__none__"\n';
            block += 'If you need to test as a different user: repeater_test with identityId="idor-user-1"\n\n';

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
}
