/**
 * PenPard Auth State Management — Type Definitions
 * 
 * All interfaces for identity management, cookie/token storage,
 * CSRF handling, session health, and request injection.
 */

// ═══════════════════════════════════════════════════════════
//  ENUMS & UTILITY TYPES
// ═══════════════════════════════════════════════════════════

export type AuthCaptureSource =
    | 'operator_input'
    | 'burp_proxy_history'
    | 'burp_set_cookie'
    | 'browser_context_cookies'
    | 'browser_local_storage'
    | 'browser_session_storage'
    | 'browser_dom_hidden_input'
    | 'browser_meta_tag'
    | 'browser_js_runtime'
    | 'login_response_header'
    | 'login_response_body'
    | 'redirect_chain'
    | 'graphql_response'
    | 'refresh_response';

export type CredentialSource = 'operator_input' | 'scan_config' | 'browser_login' | 'burp_history';

export type IdentityRole = 'primary' | 'secondary' | 'attacker';

export type SessionStatus = 'active' | 'expired' | 'refreshing' | 'dead' | 'unknown';

export type SessionProbeResult = 'authenticated' | 'unauthenticated' | 'rate_limited' | 'error';

export type TokenType = 'bearer' | 'jwt' | 'api_key' | 'custom' | 'opaque';

export type CSRFDeliveryMechanism = 'hidden_input' | 'meta_tag' | 'cookie_to_header' | 'response_header' | 'set_cookie';

export type RefreshStrategy = 'jwt_refresh' | 'cookie_refresh' | 'browser_relogin' | 'api_relogin' | 'operator_manual';

export type LoginMethod = 'form' | 'api' | 'browser' | 'token-only' | 'unknown';

// ═══════════════════════════════════════════════════════════
//  CORE IDENTITY MODELS
// ═══════════════════════════════════════════════════════════

export interface IdentityProfile {
    id: string;                             // e.g., "user-a", "user-b"
    label: string;                          // "Admin User", "Regular User"
    role: IdentityRole;
    username?: string;
    userId?: string;                        // app-level user ID
    email?: string;
    tenantId?: string;
    roleInApp?: string;                     // "admin", "user", "moderator"
    credentialSet?: CredentialSet;
    createdAt: Date;

    // Status
    isActive: boolean;
    lastValidatedAt: Date | null;
    deactivationReason?: string;            // "session_expired", "locked_out"
}

export interface CredentialSet {
    username: string;
    password?: string;                      // stored only if needed for re-login
    loginUrl?: string;                      // detected or configured
    loginMethod: LoginMethod;
    loginBodyTemplate?: string;             // e.g., '{"email":"{{user}}","password":"{{pass}}"}'
    loginContentType?: string;              // 'application/json', 'application/x-www-form-urlencoded'
    oauthFlow?: 'google' | 'github' | 'saml' | 'custom';
    capturedAt: Date;
    source: CredentialSource;
}

// ═══════════════════════════════════════════════════════════
//  SESSION & TOKEN STATE
// ═══════════════════════════════════════════════════════════

export interface SessionState {
    identityId: string;
    sessionId?: string;                     // server session ID value
    sessionCookieName?: string;             // the cookie name carrying the session
    status: SessionStatus;
    establishedAt: Date;
    lastUsedAt: Date;
    expiresAt: Date | null;
    validationCount: number;
    lastValidationResult: boolean | null;
    refreshCount: number;
}

export interface TokenState {
    id: string;                             // unique token ID
    identityId: string;
    tokenType: TokenType;
    headerName: string;                     // 'Authorization', 'X-API-Key', etc.
    headerValuePrefix: string;              // 'Bearer ', 'Token ', ''
    value: string;                          // the token itself
    expiresAt: Date | null;
    isRefreshToken: boolean;
    refreshTokenValue?: string;
    refreshEndpoint?: string;
    refreshMethod?: 'POST' | 'GET';
    refreshBodyTemplate?: string;
    newAccessTokenJsonPath?: string;        // JSONPath-like to extract new token from response
    source: AuthCaptureSource;
    capturedAt: Date;
    lastRotatedAt?: Date;
    superseded: boolean;                    // replaced by newer token
    jwtPayload?: Record<string, any>;       // decoded payload (exp, sub, role, etc.)
}

// ═══════════════════════════════════════════════════════════
//  COOKIE STATE
// ═══════════════════════════════════════════════════════════

export interface CookieEntry {
    identityId: string;
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: Date | null;                   // null = session cookie
    maxAge: number | null;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'strict' | 'lax' | 'none' | null;
    source: AuthCaptureSource;
    capturedAt: Date;
    lastUpdatedAt: Date;
    isSessionCookie: boolean;               // heuristic detection
    isCSRFCookie: boolean;                  // heuristic detection
}

// ═══════════════════════════════════════════════════════════
//  CSRF STATE
// ═══════════════════════════════════════════════════════════

export interface CSRFState {
    identityId: string;
    tokenName: string;                      // '_csrf', 'csrftoken', etc.
    tokenValue: string;
    deliveryMechanism: CSRFDeliveryMechanism;
    headerName?: string;                    // 'X-CSRF-Token', 'X-XSRF-TOKEN'
    cookieName?: string;                    // for cookie-to-header pattern
    formAction?: string;                    // specific form URL if per-form
    rotatesPerRequest: boolean;
    capturedAt: Date;
    lastRefreshedAt: Date;
}

// ═══════════════════════════════════════════════════════════
//  REFRESH & HEALTH
// ═══════════════════════════════════════════════════════════

export interface RefreshPlan {
    identityId: string;
    strategy: RefreshStrategy;
    refreshEndpoint?: string;
    refreshTokenField?: string;
    refreshBodyTemplate?: string;
    newAccessTokenPath?: string;
    estimatedExpiryAt: Date | null;
    refreshAttempts: number;
    maxRefreshAttempts: number;             // default: 3
    lastRefreshResult: 'success' | 'failed' | 'pending' | null;
    cooldownUntil: Date | null;
}

export interface SessionHealth {
    identityId: string;
    isAlive: boolean;
    confidence: number;                     // 0-100
    lastProbeAt: Date | null;
    lastProbeResult: SessionProbeResult | null;
    consecutiveFailures: number;
    authErrorCount: number;
    redirectToLoginCount: number;
    tokenExpiryCountdown: number | null;    // seconds until JWT exp
}

// ═══════════════════════════════════════════════════════════
//  AUTH CONTEXT (resolved per-request)
// ═══════════════════════════════════════════════════════════

export interface AuthContext {
    identityId: string;
    cookies: string;                        // pre-formatted Cookie header value
    authorizationHeader: string | null;     // pre-formatted Authorization header value
    csrfHeaderName: string | null;
    csrfHeaderValue: string | null;
    csrfBodyField: string | null;
    csrfBodyValue: string | null;
    customHeaders: Record<string, string>;  // X-API-Key etc.
    warning?: string;                       // e.g., "Token expires in 2 minutes"
}

export interface AuthContextHeaders {
    [key: string]: string;
}

// ═══════════════════════════════════════════════════════════
//  EVIDENCE & PROVENANCE
// ═══════════════════════════════════════════════════════════

export interface AuthEvidence {
    captureSource: AuthCaptureSource;
    rawDataRedacted: string;                // first/last 4 chars only
    capturedAt: Date;
    linkedIdentityId: string;
    validated: boolean;
    validatedAt: Date | null;
}

// ═══════════════════════════════════════════════════════════
//  BINDING RULES
// ═══════════════════════════════════════════════════════════

export interface RequestAuthBindingRules {
    /** Host patterns that require auth (glob). Default: target host only. */
    authRequiredHosts: string[];

    /** Paths that should NOT receive auth headers. */
    noAuthPaths: string[];

    /** Methods requiring CSRF token. */
    csrfRequiredMethods: Set<string>;       // default: POST, PUT, PATCH, DELETE

    /** Default identity for requests. */
    defaultIdentityId: string;

    /** Cookie path-scoping enabled (RFC 6265). */
    cookiePathScopingEnabled: boolean;

    /** Strip auth when following redirects to different domains. */
    stripAuthOnRedirect: boolean;
}

// ═══════════════════════════════════════════════════════════
//  EXPORT FORMAT
// ═══════════════════════════════════════════════════════════

export interface AuthExport {
    exportedAt: string;
    scanId: string;
    targetUrl: string;
    identities: AuthExportIdentity[];
}

export interface AuthExportIdentity {
    id: string;
    label: string;
    role: IdentityRole;
    username?: string;
    cookies: string;
    authorizationHeader: string | null;
    csrfToken: { name: string; value: string } | null;
    customHeaders: Record<string, string>;
    curlExample: string;
    sessionHealth: {
        isAlive: boolean;
        confidence: number;
        lastValidated: string | null;
    };
}

// ═══════════════════════════════════════════════════════════
//  EVENTS
// ═══════════════════════════════════════════════════════════

export type AuthEventType =
    | 'cookie_captured'
    | 'token_captured'
    | 'csrf_captured'
    | 'session_refreshed'
    | 'session_expired'
    | 'session_dead'
    | 'identity_activated'
    | 'identity_deactivated'
    | 'contamination_detected'
    | 'auth_exported';

export interface AuthEvent {
    type: AuthEventType;
    identityId: string;
    timestamp: Date;
    detail: string;
    data?: any;
}

// ═══════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════

/** Well-known session cookie name patterns. */
export const SESSION_COOKIE_PATTERNS = [
    /^jsessionid$/i,
    /^phpsessid$/i,
    /^asp\.net_sessionid$/i,
    /^connect\.sid$/i,
    /^session$/i,
    /^_session$/i,
    /^sid$/i,
    /^ssid$/i,
    /^sess_id$/i,
    /^session_id$/i,
    /^laravel_session$/i,
    /^rack\.session$/i,
    /^_rails_session$/i,
    /^express[\._]sess/i,
    /^koa[\._]sess/i,
    /^wp_.*_logged_in/i,
    /^auth[_-]?token/i,
    /^access[_-]?token/i,
    /^id_token/i,
];

/** Well-known CSRF cookie name patterns. */
export const CSRF_COOKIE_PATTERNS = [
    /^csrf/i,
    /^_csrf/i,
    /^xsrf/i,
    /^_xsrf/i,
    /^csrftoken/i,
    /^csrf[_-]token/i,
    /^xsrf[_-]token/i,
    /^__requestverificationtoken/i,
    /^antiforgery/i,
    /^_token$/i,
];

/** Well-known CSRF parameter names. */
export const CSRF_PARAM_NAMES = [
    'csrf', '_csrf', 'csrftoken', 'csrf_token', 'csrf-token',
    'xsrf', '_xsrf', 'xsrf_token', 'xsrf-token',
    '_token', '__requestverificationtoken',
    'authenticity_token', 'antiforgery_token',
    'csrfmiddlewaretoken',
];

/** Well-known CSRF header names. */
export const CSRF_HEADER_NAMES = [
    'x-csrf-token', 'x-xsrf-token', 'x-csrftoken',
    'x-requested-with',
];

/** Paths that typically indicate a login page (for redirect detection). */
export const LOGIN_PATH_PATTERNS = [
    /\/login/i, /\/signin/i, /\/sign-in/i, /\/auth/i,
    /\/authenticate/i, /\/logon/i, /\/sso/i, /\/oauth/i,
    /\/cas\/login/i, /\/saml/i, /\/account\/login/i,
];

/** No-auth paths (logout, public, static). */
export const DEFAULT_NO_AUTH_PATHS = [
    '/logout', '/signout', '/sign-out',
    '/favicon.ico', '/robots.txt', '/sitemap.xml',
];

/** Redaction helper: show first 4 + last 4, mask middle. */
export function redactSecret(value: string, type: 'cookie' | 'token' | 'password'): string {
    if (type === 'password') return '***REDACTED***';
    if (!value || value.length <= 8) return '***';
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
}
