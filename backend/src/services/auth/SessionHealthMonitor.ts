/**
 * PenPard Auth State Management — SessionHealthMonitor
 * 
 * Monitors session validity for each identity: JWT expiry,
 * 401/403 detection, login-redirect detection, proactive refresh,
 * re-login triggers, and lockout avoidance.
 */

import { SessionHealth, SessionProbeResult, RefreshPlan, SessionState, SessionStatus, RefreshStrategy, LOGIN_PATH_PATTERNS, redactSecret } from './types';
import { TokenStore } from './TokenStore';
import { CookieJar } from './CookieJar';
import { IdentityRegistry } from './IdentityRegistry';
import { AuthInjector } from './AuthInjector';
import { logger } from '../../utils/logger';

/** Minimal Burp MCP client interface. */
interface BurpClient {
    callTool(tool: string, args: any): Promise<any>;
}

export class SessionHealthMonitor {
    private healthStates: Map<string, SessionHealth> = new Map();
    private sessionStates: Map<string, SessionState> = new Map();
    private refreshPlans: Map<string, RefreshPlan> = new Map();

    private readonly identityRegistry: IdentityRegistry;
    private readonly tokenStores: Map<string, TokenStore>;
    private readonly cookieJars: Map<string, CookieJar>;
    private readonly targetUrl: string;

    /** How many requests between automatic health probes. */
    private requestCounters: Map<string, number> = new Map();
    private static readonly PROBE_EVERY_N_REQUESTS = 20;
    private static readonly PROBE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
    private static readonly MAX_CONSECUTIVE_FAILURES = 3;
    private static readonly REFRESH_COOLDOWN_MS = 30_000;
    private static readonly TOKEN_REFRESH_BUFFER_S = 60; // refresh 60s before expiry

    constructor(
        identityRegistry: IdentityRegistry,
        tokenStores: Map<string, TokenStore>,
        cookieJars: Map<string, CookieJar>,
        targetUrl: string,
    ) {
        this.identityRegistry = identityRegistry;
        this.tokenStores = tokenStores;
        this.cookieJars = cookieJars;
        this.targetUrl = targetUrl;
    }

    // ═══════════════════════════════════════════════════════════
    //  HEALTH TRACKING
    // ═══════════════════════════════════════════════════════════

    /**
     * Initialize health tracking for an identity.
     */
    initializeHealth(identityId: string): void {
        this.healthStates.set(identityId, {
            identityId,
            isAlive: true,
            confidence: 50,         // start neutral
            lastProbeAt: null,
            lastProbeResult: null,
            consecutiveFailures: 0,
            authErrorCount: 0,
            redirectToLoginCount: 0,
            tokenExpiryCountdown: null,
        });

        this.sessionStates.set(identityId, {
            identityId,
            status: 'unknown',
            establishedAt: new Date(),
            lastUsedAt: new Date(),
            expiresAt: null,
            validationCount: 0,
            lastValidationResult: null,
            refreshCount: 0,
        });

        this.requestCounters.set(identityId, 0);
    }

    /**
     * Get the health state for an identity.
     */
    getHealth(identityId: string): SessionHealth | undefined {
        return this.healthStates.get(identityId);
    }

    /**
     * Get health report for all identities (for injection into LLM replan prompt).
     */
    getHealthReport(): string {
        const lines: string[] = [];
        for (const [id, health] of this.healthStates.entries()) {
            const tokenStore = this.tokenStores.get(id);
            const expiryInfo = tokenStore?.getSecondsUntilExpiry();
            const expStr = expiryInfo !== null ? ` (token expires in ${expiryInfo}s)` : '';
            const status = health.isAlive ? '✓ alive' : '✗ dead';
            lines.push(`  ${id}: ${status} confidence=${health.confidence}%${expStr} failures=${health.consecutiveFailures}`);
        }
        return lines.length > 0 ? `Session Health:\n${lines.join('\n')}` : 'Session Health: not tracked';
    }

    // ═══════════════════════════════════════════════════════════
    //  RESPONSE ANALYSIS — Called after every HTTP response
    // ═══════════════════════════════════════════════════════════

    /**
     * Analyze an HTTP response for auth state signals.
     * Called after every `send_http_request`.
     */
    analyzeResponse(identityId: string, statusCode: number, headers: Record<string, string>, body: string): {
        needsRefresh: boolean;
        needsRelogin: boolean;
        isCSRFFailure: boolean;
    } {
        const health = this.healthStates.get(identityId);
        const session = this.sessionStates.get(identityId);
        if (!health || !session) return { needsRefresh: false, needsRelogin: false, isCSRFFailure: false };

        // Update last used
        session.lastUsedAt = new Date();
        this.incrementRequestCounter(identityId);

        let needsRefresh = false;
        let needsRelogin = false;
        let isCSRFFailure = false;

        // ── 401 Unauthorized ──
        if (statusCode === 401) {
            health.authErrorCount++;
            health.consecutiveFailures++;
            health.confidence = Math.max(0, health.confidence - 20);
            logger.warn(`SessionHealth: ${identityId} received 401 (${health.consecutiveFailures} consecutive)`);

            if (health.consecutiveFailures >= SessionHealthMonitor.MAX_CONSECUTIVE_FAILURES) {
                needsRelogin = true;
                health.isAlive = false;
                session.status = 'expired';
            } else {
                needsRefresh = true;
            }
        }

        // ── 403 Forbidden (unexpected) ──
        else if (statusCode === 403) {
            // Don't auto-refresh on 403 — could be legit access control
            // But track it for analysis
            health.authErrorCount++;
            health.confidence = Math.max(0, health.confidence - 5);
        }

        // ── 302/301 to login page ──
        else if (AuthInjector.isLoginRedirect(statusCode, headers)) {
            health.redirectToLoginCount++;
            health.consecutiveFailures++;
            health.confidence = Math.max(0, health.confidence - 30);
            logger.warn(`SessionHealth: ${identityId} redirected to login`);

            const location = headers['location'] || headers['Location'] || '';
            this.identityRegistry.setLoginUrl(identityId, location);

            if (health.consecutiveFailures >= 2) {
                needsRelogin = true;
                health.isAlive = false;
                session.status = 'expired';
            } else {
                needsRefresh = true;
            }
        }

        // ── CSRF failure (419/422 with CSRF message) ──
        else if (AuthInjector.isCSRFFailure(statusCode, body)) {
            isCSRFFailure = true;
            // Don't count as auth failure — just needs CSRF refresh
        }

        // ── Success (2xx / 3xx non-login) ──
        else if (statusCode >= 200 && statusCode < 400) {
            health.consecutiveFailures = 0;
            health.confidence = Math.min(100, health.confidence + 5);
            health.isAlive = true;
            session.status = 'active';
        }

        // ── 429 Rate Limited ──
        else if (statusCode === 429) {
            // NOT an auth failure — don't refresh
            // But note it for health reporting
        }

        // Update token expiry countdown
        this.updateTokenExpiry(identityId);

        return { needsRefresh, needsRelogin, isCSRFFailure };
    }

    // ═══════════════════════════════════════════════════════════
    //  PROACTIVE CHECKS
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if a proactive health probe is needed for this identity.
     */
    shouldProbe(identityId: string): boolean {
        const health = this.healthStates.get(identityId);
        if (!health) return false;

        // Probe if we've sent N requests since last probe
        const counter = this.requestCounters.get(identityId) || 0;
        if (counter >= SessionHealthMonitor.PROBE_EVERY_N_REQUESTS) return true;

        // Probe if interval elapsed
        if (health.lastProbeAt) {
            const elapsed = Date.now() - health.lastProbeAt.getTime();
            if (elapsed >= SessionHealthMonitor.PROBE_INTERVAL_MS) return true;
        } else {
            return true; // never probed
        }

        return false;
    }

    /**
     * Execute a lightweight health probe for an identity.
     * Sends a HEAD request to the target root and checks the response.
     */
    async probe(identityId: string, burpClient: BurpClient, injector: AuthInjector): Promise<SessionProbeResult> {
        const health = this.healthStates.get(identityId);
        if (!health) return 'error';

        try {
            const ctx = injector.prepare(this.targetUrl, 'HEAD', identityId);
            const headers = AuthInjector.toHeaders(ctx);

            const response = await burpClient.callTool('send_http_request', {
                method: 'HEAD',
                url: this.targetUrl,
                headers,
            });

            health.lastProbeAt = new Date();
            this.requestCounters.set(identityId, 0); // reset counter

            const statusCode = response?.statusCode || response?.status || 0;

            if (statusCode >= 200 && statusCode < 400) {
                health.lastProbeResult = 'authenticated';
                health.isAlive = true;
                health.confidence = Math.min(100, health.confidence + 10);
                health.consecutiveFailures = 0;

                const session = this.sessionStates.get(identityId);
                if (session) {
                    session.status = 'active';
                    session.validationCount++;
                    session.lastValidationResult = true;
                }

                this.identityRegistry.markValidated(identityId);
                return 'authenticated';
            }

            if (statusCode === 401 || statusCode === 403) {
                health.lastProbeResult = 'unauthenticated';
                health.confidence = Math.max(0, health.confidence - 25);
                return 'unauthenticated';
            }

            if (statusCode === 429) {
                health.lastProbeResult = 'rate_limited';
                return 'rate_limited';
            }

            health.lastProbeResult = 'error';
            return 'error';

        } catch (e: any) {
            logger.warn(`SessionHealth: Probe failed for ${identityId}: ${e.message}`);
            health.lastProbeAt = new Date();
            health.lastProbeResult = 'error';
            return 'error';
        }
    }

    /**
     * Check if any active token is expiring soon and needs refresh.
     */
    needsProactiveRefresh(identityId: string): boolean {
        const tokenStore = this.tokenStores.get(identityId);
        if (!tokenStore) return false;
        return tokenStore.isExpiringSoon(SessionHealthMonitor.TOKEN_REFRESH_BUFFER_S);
    }

    // ═══════════════════════════════════════════════════════════
    //  REFRESH PLANS
    // ═══════════════════════════════════════════════════════════

    /**
     * Create a refresh plan for an identity.
     */
    setRefreshPlan(identityId: string, strategy: RefreshStrategy, opts?: {
        refreshEndpoint?: string;
        refreshTokenField?: string;
        refreshBodyTemplate?: string;
        newAccessTokenPath?: string;
    }): RefreshPlan {
        const plan: RefreshPlan = {
            identityId,
            strategy,
            refreshEndpoint: opts?.refreshEndpoint,
            refreshTokenField: opts?.refreshTokenField,
            refreshBodyTemplate: opts?.refreshBodyTemplate,
            newAccessTokenPath: opts?.newAccessTokenPath,
            estimatedExpiryAt: null,
            refreshAttempts: 0,
            maxRefreshAttempts: 3,
            lastRefreshResult: null,
            cooldownUntil: null,
        };

        // Estimate expiry from token store
        const tokenStore = this.tokenStores.get(identityId);
        if (tokenStore) {
            const activeToken = tokenStore.getActive();
            if (activeToken?.expiresAt) {
                plan.estimatedExpiryAt = activeToken.expiresAt;
            }
        }

        this.refreshPlans.set(identityId, plan);
        return plan;
    }

    /**
     * Auto-detect the best refresh strategy for an identity.
     */
    autoDetectRefreshStrategy(identityId: string): RefreshStrategy {
        const tokenStore = this.tokenStores.get(identityId);
        const identity = this.identityRegistry.get(identityId);

        // Has refresh token → JWT refresh
        if (tokenStore?.getRefreshToken()) return 'jwt_refresh';

        // Has credentials + login URL → API re-login
        if (identity?.credentialSet?.password && identity?.credentialSet?.loginUrl) return 'api_relogin';

        // Has credentials but no login URL → browser re-login
        if (identity?.credentialSet?.password) return 'browser_relogin';

        // OAuth flow → browser re-login
        if (identity?.credentialSet?.oauthFlow) return 'browser_relogin';

        // Fallback → operator manual intervention
        return 'operator_manual';
    }

    /**
     * Execute a token refresh for an identity.
     * Returns true if refresh succeeded.
     */
    async executeRefresh(identityId: string, burpClient: BurpClient): Promise<boolean> {
        const plan = this.refreshPlans.get(identityId);
        if (!plan) {
            logger.warn(`SessionHealth: No refresh plan for ${identityId}`);
            return false;
        }

        // Cooldown check
        if (plan.cooldownUntil && new Date() < plan.cooldownUntil) {
            logger.info(`SessionHealth: Refresh for ${identityId} on cooldown until ${plan.cooldownUntil.toISOString()}`);
            return false;
        }

        // Max attempts check
        if (plan.refreshAttempts >= plan.maxRefreshAttempts) {
            logger.warn(`SessionHealth: Max refresh attempts (${plan.maxRefreshAttempts}) reached for ${identityId}`);
            this.identityRegistry.deactivate(identityId, 'max_refresh_attempts');
            return false;
        }

        plan.refreshAttempts++;
        plan.lastRefreshResult = 'pending';

        const session = this.sessionStates.get(identityId);
        if (session) session.status = 'refreshing';

        try {
            let success = false;

            switch (plan.strategy) {
                case 'jwt_refresh':
                    success = await this.executeJWTRefresh(identityId, burpClient, plan);
                    break;
                case 'api_relogin':
                    success = await this.executeAPIRelogin(identityId, burpClient);
                    break;
                case 'browser_relogin':
                case 'operator_manual':
                    // These require external handling — mark as needing intervention
                    logger.warn(`SessionHealth: ${plan.strategy} required for ${identityId} — cannot auto-refresh`);
                    plan.lastRefreshResult = 'failed';
                    success = false;
                    break;
            }

            if (success) {
                plan.lastRefreshResult = 'success';
                plan.refreshAttempts = 0; // reset on success
                plan.cooldownUntil = null;

                if (session) {
                    session.status = 'active';
                    session.refreshCount++;
                }

                const health = this.healthStates.get(identityId);
                if (health) {
                    health.isAlive = true;
                    health.confidence = 80;
                    health.consecutiveFailures = 0;
                }

                this.identityRegistry.reactivate(identityId);
                logger.info(`SessionHealth: Refresh succeeded for ${identityId}`);
            } else {
                plan.lastRefreshResult = 'failed';
                plan.cooldownUntil = new Date(Date.now() + SessionHealthMonitor.REFRESH_COOLDOWN_MS);
                logger.warn(`SessionHealth: Refresh failed for ${identityId} — cooldown until ${plan.cooldownUntil.toISOString()}`);
            }

            return success;

        } catch (e: any) {
            plan.lastRefreshResult = 'failed';
            plan.cooldownUntil = new Date(Date.now() + SessionHealthMonitor.REFRESH_COOLDOWN_MS);
            logger.error(`SessionHealth: Refresh error for ${identityId}: ${e.message}`);
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  REFRESH STRATEGIES
    // ═══════════════════════════════════════════════════════════

    private async executeJWTRefresh(identityId: string, burpClient: BurpClient, plan: RefreshPlan): Promise<boolean> {
        const tokenStore = this.tokenStores.get(identityId);
        if (!tokenStore) return false;

        const refreshToken = tokenStore.getRefreshToken();
        if (!refreshToken || !plan.refreshEndpoint) return false;

        // Build refresh request
        let body = plan.refreshBodyTemplate || `{"refresh_token":"${refreshToken.value}"}`;
        body = body.replace('{{refresh_token}}', refreshToken.value);

        const response = await burpClient.callTool('send_http_request', {
            method: 'POST',
            url: plan.refreshEndpoint,
            headers: { 'Content-Type': 'application/json' },
            body,
        });

        const statusCode = response?.statusCode || response?.status || 0;
        if (statusCode < 200 || statusCode >= 300) return false;

        // Extract new access token from response
        const responseBody = response?.body || response?.text || '';
        try {
            const parsed = JSON.parse(responseBody);

            // Try common paths: access_token, token, data.token, data.access_token
            const paths = ['access_token', 'token', 'accessToken', 'data.access_token', 'data.token'];
            if (plan.newAccessTokenPath) paths.unshift(plan.newAccessTokenPath);

            let newToken: string | null = null;
            for (const path of paths) {
                const segments = path.split('.');
                let val: any = parsed;
                for (const seg of segments) {
                    val = val?.[seg];
                }
                if (typeof val === 'string' && val.length > 10) {
                    newToken = val;
                    break;
                }
            }

            if (newToken) {
                tokenStore.rotate('Authorization', newToken, 'refresh_response');

                // Check for rotated refresh token
                const newRefresh = parsed.refresh_token || parsed.refreshToken || parsed.data?.refresh_token;
                if (typeof newRefresh === 'string' && newRefresh !== refreshToken.value) {
                    tokenStore.storeRefreshToken(newRefresh, plan.refreshEndpoint!, 'refresh_response');
                }

                return true;
            }
        } catch { /* response wasn't JSON */ }

        return false;
    }

    private async executeAPIRelogin(identityId: string, burpClient: BurpClient): Promise<boolean> {
        const identity = this.identityRegistry.get(identityId);
        if (!identity?.credentialSet?.loginUrl || !identity?.credentialSet?.password) return false;

        const creds = identity.credentialSet;
        let body = creds.loginBodyTemplate || `{"username":"{{user}}","password":"{{pass}}"}`;
        body = body.replace('{{user}}', creds.username).replace('{{pass}}', creds.password!);

        const contentType = creds.loginContentType || 'application/json';

        const response = await burpClient.callTool('send_http_request', {
            method: 'POST',
            url: creds.loginUrl,
            headers: { 'Content-Type': contentType },
            body,
        });

        const statusCode = response?.statusCode || response?.status || 0;
        if (statusCode < 200 || statusCode >= 400) return false;

        // Extract tokens from response body
        const responseBody = response?.body || response?.text || '';
        try {
            const parsed = JSON.parse(responseBody);
            const tokenStore = this.tokenStores.get(identityId);
            if (tokenStore) {
                const token = parsed.token || parsed.access_token || parsed.accessToken || parsed.data?.token;
                if (typeof token === 'string') {
                    tokenStore.rotate('Authorization', token, 'login_response_body');
                    return true;
                }
            }
        } catch { /* not JSON */ }

        // Extract session cookies from response headers (Set-Cookie)
        // The caller (AuthCapture.fromResponse) handles this — return true if we got a 2xx
        return statusCode >= 200 && statusCode < 300;
    }

    // ═══════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════

    private updateTokenExpiry(identityId: string): void {
        const health = this.healthStates.get(identityId);
        const tokenStore = this.tokenStores.get(identityId);
        if (!health || !tokenStore) return;

        health.tokenExpiryCountdown = tokenStore.getSecondsUntilExpiry();
    }

    private incrementRequestCounter(identityId: string): void {
        const count = (this.requestCounters.get(identityId) || 0) + 1;
        this.requestCounters.set(identityId, count);
    }

    /** Summary for serialization / logging. */
    toSummary(): string {
        return this.getHealthReport();
    }
}
