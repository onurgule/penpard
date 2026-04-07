# PenPard Auth-State & Token Management System

## Executive Summary

PenPard's current auth handling is **prompt-injection-based**: session cookies and authorization headers are resolved once during `phaseInit()`, embedded into the system prompt as static strings, and the LLM is instructed to copy them into every `send_http_request`. There is no structured token store, no CookieJar, no refresh logic, no multi-user isolation, no expiry detection, and no deterministic injection layer. Auth state exists only as text inside the LLM's conversation context.

This design replaces that with a **deterministic, multi-identity `AuthStateManager`** that captures, normalizes, stores, refreshes, isolates, and injects authentication material across all execution paths (agent HTTP requests, browser automation, Burp replay, human pentester reuse) without relying on the LLM to remember or copy tokens.

---

## 1. Why PenPard Needs a Dedicated Auth-State System

### Current State — What Actually Happens Today

| OrchestratorAgent code path | What happens with auth | Failure risk |
|---|---|---|
| `phaseInit()` L1022-1062 | Resolves `sessionCookieHeader` and `sessionAuthHeader` once, injects into system prompt | Cookie expires mid-scan → all subsequent requests fail silently |
| `executeSendHttpRequest()` L1831-1925 | Passes `toolCall.args.headers` directly — whatever the LLM decided to include | LLM omits Cookie/Auth header → request runs unauthenticated |
| `executeRepeaterTest()` L3160-3269 | Copies `request.requestHeaders` from harvested request | Harvested cookie may be stale by the time repeater test runs |
| `executeBrowserNavigate()` L2591 | Browser has its own Playwright context cookies — completely disconnected from agent cookies | Browser session and agent HTTP session can be in different auth states |
| Multi-user (idorUsers) | Users are passed as JSON text in system prompt | No separate CookieJar per user; LLM must manually swap headers |
| `SharedContext.SharedSession` L65-70 | Has `cookies?: string` and `authHeader?: string` | Never written to during actual scan execution |

### What Breaks Without a Proper Auth-State System

| Pentest Activity | How It Breaks |
|---|---|
| **Authenticated crawling** | Token expires mid-crawl → agent discovers only unauthenticated pages → incomplete surface mapping |
| **Authenticated fuzzing** | LLM forgets to include Cookie → fuzzer tests unauthenticated endpoint → all results are false negatives |
| **Stateful workflows** | Multi-step checkout/payment flow requires CSRF token refresh per step → LLM doesn't know |
| **Multi-step business logic** | Step 3 of a flow sets a new session token → agent uses old token for step 4 → 403 |
| **IDOR testing** | User A and User B cookies stored in same prompt string → LLM confuses which cookie belongs to which user → wrong user's data compared → false positive/negative |
| **Horizontal privilege testing** | Cannot reliably replay the exact same request with User B's cookies → comparison is unreliable |
| **Vertical privilege testing** | Admin token and regular-user token not properly separated → accidental privilege elevation in testing → invalid results |
| **Request replay as different user** | No structured swap mechanism → LLM has to parse and reconstruct headers → fragile and error-prone |
| **Browser-assisted verification** | Browser has different session state than agent HTTP path → PoC screenshot shows different user than the finding refers to |
| **Human pentester reuse** | No export mechanism → human must manually dig through logs to find the Cookie header that was used |

---

## 2. Exact Scope of the Problem

What PenPard must manage during a scan:

### Identity State
- Who is this session authenticated as (username, user ID, role, tenant)
- Which credential set was used to establish the session
- Whether the identity is the "primary" test user or a "secondary" comparison user

### Session State
- Server-side session validity (alive, expired, revoked)
- Session identifier (JSESSIONID, connect.sid, _session, etc.)
- Session binding to identity

### Token State
- Bearer tokens (opaque, JWT, API keys)
- Access vs refresh token distinction
- Token expiry timestamp (from JWT `exp` or observed behavior)
- Token storage location (header, cookie, localStorage, sessionStorage)

### Cookie State
- Full cookie jar per identity per domain
- Cookie attributes: domain, path, httpOnly, secure, sameSite, expires
- Multiple cookies per domain (session + analytics + CSRF + flags)

### CSRF State
- Current CSRF token value per form/endpoint
- CSRF token name (varies per app: `_csrf`, `csrftoken`, `__RequestVerificationToken`, etc.)
- CSRF delivery mechanism (meta tag, hidden input, cookie-to-header, response header)
- Staleness detection (server rotates token per request or per session)

### Refresh State
- Refresh token value and expiry
- Refresh endpoint URL
- Refresh request format (body, header, cookie)
- Refresh response handling (new access token extraction)
- Rotation detection (refresh token itself changes on use)

### Request-Binding Rules
- Which auth material goes to which host/domain/path
- Cookie path scoping (e.g., `/api` cookies only on `/api/*`)
- Authorization header vs Cookie — some apps use both
- CSRF token required for which methods (POST/PUT/DELETE typically)

### User Separation
- Strict isolation between User A and User B auth material
- No shared cookie jar
- No shared token store
- Deterministic user switching for comparison tests

### Expiration Handling
- JWT `exp` claim parsing
- Server-side 401/403 detection as session death signal
- Login-page redirect detection (302 → `/login`)
- Proactive refresh before expiry

### Recovery Logic
- Refresh token flow
- Re-login via stored credentials
- Re-login via browser automation
- Graceful degradation (mark identity as unavailable, continue with remaining identities)

### Provenance Tracking
- Where each auth artifact was captured (Burp history, browser cookie jar, login response, operator input)
- When it was captured
- Whether it has been validated

---

## 3. Recommended Internal Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AuthStateManager                         │
│  (singleton per scan — source of truth for all auth state)  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐   │
│  │ AuthCapture   │  │ AuthInjector  │  │ IdentityRegistry│  │
│  │              │  │               │  │                │   │
│  │ • Burp proxy │  │ • Host scope  │  │ • User profiles│   │
│  │ • Browser    │  │ • Path scope  │  │ • Credential   │   │
│  │ • Login resp │  │ • Cookie JAR  │  │   sets          │   │
│  │ • Set-Cookie │  │ • Header rules│  │ • Role/tenant  │   │
│  │ • DOM/JS     │  │ • CSRF inject │  │ • Bindings     │   │
│  │ • Operator   │  │ • User select │  │                │   │
│  └──────┬───────┘  └───────┬───────┘  └───────┬────────┘   │
│         │                  │                  │            │
│  ┌──────┴──────────────────┴──────────────────┴────────┐   │
│  │              SessionStore (per identity)             │   │
│  │                                                      │   │
│  │  Identity A: CookieJar + TokenStore + CSRFState      │   │
│  │  Identity B: CookieJar + TokenStore + CSRFState      │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                   │
│  ┌──────────────────────┴───────────────────────────────┐   │
│  │           SessionHealthMonitor                       │   │
│  │                                                      │   │
│  │  • JWT exp parsing      • 401/403 detection          │   │
│  │  • Redirect detection   • Proactive refresh         │   │
│  │  • Validation probes    • Re-login trigger          │   │
│  │  • CSRF staleness       • Lockout avoidance         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           CSRFManager                                │   │
│  │                                                      │   │
│  │  • Detect CSRF delivery mechanism                    │   │
│  │  • Track token name/value per form                   │   │
│  │  • Refresh token from DOM/meta/response              │   │
│  │  • Inject into request body/header                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Where It Plugs In

| Lifecycle Stage | Integration Point |
|---|---|
| `phaseInit()` | `AuthCapture.fromOperatorInput()` + `AuthCapture.fromBurpHistory()` + `AuthCapture.fromBrowser()` |
| `executeSendHttpRequest()` | `AuthInjector.prepareHeaders(url, identityId)` — replaces LLM-driven header copying |
| `executeRepeaterTest()` | `AuthInjector.prepareHeaders(url, identityId)` for original; `AuthInjector.prepareHeaders(url, alternateIdentityId)` for comparison |
| `executeBrowserNavigate()` | `AuthCapture.fromBrowserPostNav()` — sync browser cookies back to AuthStateManager |
| `runHarvestCycle()` | `AuthCapture.fromHarvestedRequest()` — extract auth material from observed traffic |
| `shouldContinueTesting()` | `SessionHealthMonitor.getHealthReport()` — inject session health into replan prompt |
| `phaseReporting()` | `AuthStateManager.exportForHumanReuse()` — dump live auth state for pentester |

### Source of Truth

**`AuthStateManager` is the single source of truth for all auth state during a scan.**

- The LLM system prompt no longer contains raw Cookie/Authorization strings.
- Instead, the system prompt tells the LLM: "Auth is handled automatically. Do not set Cookie or Authorization headers manually."
- `executeToolCall()` intercepts every outgoing request and calls `AuthInjector.prepareHeaders()` before forwarding to Burp.

---

## 4. Internal Data Models

### IdentityProfile

```typescript
interface IdentityProfile {
  id: string;                           // e.g., "user-a", "user-b"
  label: string;                        // "Admin User", "Regular User"
  role: 'primary' | 'secondary' | 'attacker';
  username?: string;
  userId?: string;                      // app-level user ID
  email?: string;
  tenantId?: string;
  roleInApp?: string;                   // "admin", "user", "moderator"
  credentialSet?: CredentialSet;
  createdAt: Date;
  
  // Status
  isActive: boolean;                    // currently usable
  lastValidatedAt: Date | null;
  deactivationReason?: string;          // "session_expired", "locked_out"
}
```

**Lifecycle**: Created during `phaseInit()` from `idorUsers` config + operator-provided cookies. Validated periodically. Deactivated if session dies and re-login fails.

### CredentialSet

```typescript
interface CredentialSet {
  username: string;
  password?: string;                    // stored only if needed for re-login
  loginUrl?: string;                    // detected or configured
  loginMethod: 'form' | 'api' | 'browser' | 'token-only' | 'unknown';
  loginBodyTemplate?: string;           // e.g., '{"email":"{{user}}","password":"{{pass}}"}'
  loginContentType?: string;            // 'application/json', 'application/x-www-form-urlencoded'
  oauthFlow?: 'google' | 'github' | 'saml' | 'custom';
  capturedAt: Date;
  source: CredentialSource;
}

type CredentialSource = 'operator_input' | 'scan_config' | 'browser_login' | 'burp_history';
```

**Security sensitivity**: HIGH. Passwords must be encrypted at rest, never logged in plaintext.

### SessionState

```typescript
interface SessionState {
  identityId: string;                   // FK to IdentityProfile
  sessionId?: string;                   // server session ID value (e.g., JSESSIONID value)
  sessionCookieName?: string;           // the cookie name that carries the session
  status: 'active' | 'expired' | 'refreshing' | 'dead' | 'unknown';
  establishedAt: Date;
  lastUsedAt: Date;
  expiresAt: Date | null;              // from max-age/expires or JWT exp
  validationCount: number;              // how many times validated
  lastValidationResult: boolean | null;
  refreshCount: number;
}
```

### TokenState

```typescript
interface TokenState {
  identityId: string;
  tokenType: 'bearer' | 'jwt' | 'api_key' | 'custom' | 'opaque';
  headerName: string;                   // 'Authorization', 'X-API-Key', etc.
  headerValuePrefix: string;            // 'Bearer ', 'Token ', ''
  value: string;                        // the token itself
  expiresAt: Date | null;              // from JWT exp or observed
  isRefreshToken: boolean;
  refreshTokenValue?: string;
  refreshEndpoint?: string;
  refreshMethod?: 'POST' | 'GET';
  refreshBodyTemplate?: string;
  source: AuthCaptureSource;
  capturedAt: Date;
  lastRotatedAt?: Date;
  jwtPayload?: Record<string, any>;    // decoded payload for exp/sub/role
}
```

### CookieState

```typescript
interface CookieState {
  identityId: string;
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: Date | null;                // null = session cookie
  maxAge: number | null;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none' | null;
  source: AuthCaptureSource;
  capturedAt: Date;
  lastUpdatedAt: Date;
  isSessionCookie: boolean;            // heuristic: name matches known session cookie patterns
  isCSRFCookie: boolean;               // heuristic: name matches CSRF patterns
}
```

### CSRFState

```typescript
interface CSRFState {
  identityId: string;
  tokenName: string;                   // '_csrf', 'csrftoken', etc.
  tokenValue: string;
  deliveryMechanism: 'hidden_input' | 'meta_tag' | 'cookie_to_header' | 'response_header' | 'set_cookie';
  headerName?: string;                 // 'X-CSRF-Token', 'X-XSRF-TOKEN'
  cookieName?: string;                 // for cookie-to-header pattern (XSRF-TOKEN)
  formAction?: string;                 // specific form URL if token is per-form
  rotatesPerRequest: boolean;          // some apps rotate CSRF per request
  capturedAt: Date;
  lastRefreshedAt: Date;
}
```

### RefreshPlan

```typescript
interface RefreshPlan {
  identityId: string;
  strategy: 'jwt_refresh' | 'cookie_refresh' | 'browser_relogin' | 'api_relogin' | 'operator_manual';
  refreshEndpoint?: string;
  refreshTokenField?: string;
  refreshBodyTemplate?: string;
  newAccessTokenPath?: string;          // JSONPath to extract new token from response
  estimatedExpiryAt: Date | null;
  refreshAttempts: number;
  maxRefreshAttempts: number;           // 3
  lastRefreshResult: 'success' | 'failed' | 'pending' | null;
  cooldownUntil: Date | null;          // after failure, wait before retrying
}
```

### SessionHealth

```typescript
interface SessionHealth {
  identityId: string;
  isAlive: boolean;
  confidence: number;                  // 0-100
  lastProbeAt: Date | null;
  lastProbeResult: SessionProbeResult | null;
  consecutiveFailures: number;
  authErrorCount: number;              // 401/403 count since last success
  redirectToLoginCount: number;        // 302→/login count
  tokenExpiryCountdown: number | null; // seconds until JWT exp
}

type SessionProbeResult = 'authenticated' | 'unauthenticated' | 'rate_limited' | 'error';
```

### AuthContext

```typescript
/** Resolved auth context for a single outgoing request. */
interface AuthContext {
  identityId: string;
  cookies: string;                     // pre-formatted Cookie header value
  authorizationHeader: string | null;  // pre-formatted Authorization header value
  csrfHeaderName: string | null;
  csrfHeaderValue: string | null;
  csrfBodyField: string | null;
  csrfBodyValue: string | null;
  customHeaders: Record<string, string>; // X-API-Key etc.
  warning?: string;                    // e.g., "Token expires in 2 minutes"
}
```

### AuthEvidence

```typescript
interface AuthEvidence {
  captureSource: AuthCaptureSource;
  rawData: string;                     // redacted for logging
  capturedAt: Date;
  linkedIdentityId: string;
  validated: boolean;
  validatedAt: Date | null;
}

type AuthCaptureSource =
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
```

### RequestAuthBindingRules

```typescript
interface RequestAuthBindingRules {
  /** Host patterns that require auth (glob). Default: target host only. */
  authRequiredHosts: string[];
  
  /** Paths that should NOT receive auth headers (e.g., public API). */
  noAuthPaths: string[];
  
  /** Methods requiring CSRF token. */
  csrfRequiredMethods: Set<string>;    // default: POST, PUT, PATCH, DELETE
  
  /** Default identity for requests (usually 'primary'). */
  defaultIdentityId: string;
  
  /** Cookie path-scoping enabled. */
  cookiePathScopingEnabled: boolean;   // default: true
  
  /** Whether to strip auth when following redirects to different domains. */
  stripAuthOnRedirect: boolean;        // default: true
}
```

---

## 5. Full Token and Session Lifecycle

```
[1] INITIAL CAPTURE
   Operator input → sessionCookies config field
   Burp proxy history → get_cookies_and_auth_for_host
   Browser context → Playwright cookies + localStorage
   Login response → Set-Cookie + body token
   ↓
[2] NORMALIZATION
   Parse Set-Cookie → CookieState objects
   Parse Authorization → TokenState (detect JWT vs opaque)
   Parse JWT → extract exp, sub, role from payload
   Parse CSRF → detect delivery mechanism
   ↓
[3] IDENTITY BINDING
   Match cookies/tokens to IdentityProfile
   (by user ID in JWT, by capture context, by operator label)
   ↓
[4] STORAGE
   CookieState[] → per-identity CookieJar in AuthStateManager
   TokenState → per-identity token store
   CSRFState → per-identity CSRF tracker
   ↓
[5] VALIDATION PROBE
   Send a known-good request with the captured auth
   Expect 200 (not 401/403/302→login)
   Mark session health as 'active' or 'unknown'
   ↓
[6] SELECTION (per outgoing request)
   Determine target host + path
   Look up identity binding rules
   Select correct identity (default = primary; override for IDOR tests)
   ↓
[7] INJECTION
   AuthInjector builds Cookie header from CookieJar (respecting domain/path/secure)
   AuthInjector sets Authorization header from TokenState
   AuthInjector adds CSRF token (body or header) if method requires it
   AuthInjector returns immutable AuthContext
   ↓
[8] REQUEST EXECUTION
   Burp MCP send_http_request with injected headers
   ↓
[9] RESPONSE MONITORING
   Check response for new Set-Cookie → update CookieJar
   Check response for token rotation indicators
   Check for 401/403 → trigger health check
   Check for 302→login → trigger refresh
   ↓
[10] REFRESH / RELOGIN
   If token near expiry → RefreshPlan.execute()
   If refresh fails → attempt re-login via CredentialSet
   If re-login fails → mark identity as dead
   ↓
[11] ROTATION HANDLING
   New tokens from refresh → replace old in TokenStore
   CSRF rotated → update CSRFState from DOM or response
   ↓
[12] SCAN-END CLEANUP
   Sensitive material (passwords) → zero out from memory
   Tokens/cookies → retain for export if operator requests
   ↓
[13] EXPORT FOR HUMAN REUSE
   Generate redacted auth snapshot
   Include: cookies, tokens, CSRF values, browser storage state
   Format: JSON + curl command examples
   Exclude: passwords (unless operator explicitly opts in)
```

---

## 6. Auth Material Capture Sources

### Source 1: Operator-Provided Session Cookies
**Current path**: `ScanConfig.sessionCookies` → `phaseInit()` L1024-1027
**New path**: `AuthCapture.fromOperatorInput(config.sessionCookies)` → parse as `Cookie` header → split into individual `CookieState` objects → bind to primary identity

### Source 2: Burp Proxy History
**Current path**: `get_cookies_and_auth_for_host` → extracts cookie + authorization from most recent user request
**New path**: `AuthCapture.fromBurpHistory(burpClient, targetHost)` → scan last 50 entries → extract ALL unique cookies (not just from one request) → merge into CookieJar → detect session cookies vs analytics cookies by name pattern

### Source 3: Set-Cookie Response Headers
**Not currently captured.** New path: After every `executeSendHttpRequest()`, parse `Set-Cookie` from response → update CookieJar. This is critical for CSRF cookie rotation and session fixation.

### Source 4: Browser Context Cookies
**Current path**: `context.cookies()` in BrowserService → returned but not fed back to agent
**New path**: `AuthCapture.fromBrowser(sessionId)` → `context.cookies()` → merge into CookieJar for the identity associated with that browser session

### Source 5: Browser localStorage / sessionStorage
**Current path**: `getSessionStorageData()` → returned to LLM but not parsed
**New path**: `AuthCapture.fromBrowserStorage(sessionId)` → scan for JWT patterns (three-dot-separated base64) → parse as TokenState

### Source 6: HTML Hidden Inputs
**Current path**: `getFrontendAnalysis()` detects CSRF inputs → returned as array
**New path**: `AuthCapture.fromDOMHiddenInputs(pageState)` → extract CSRF token name/value → create CSRFState

### Source 7: Meta Tags
Same as above — `<meta name="csrf-token" content="...">` → CSRFState

### Source 8: JS Runtime (fetch/XHR interception)
**New capability**: Install `page.route()` interceptor in Playwright to capture Authorization headers set by JavaScript fetch calls → TokenState

### Source 9: Login Response
**New capability**: When agent performs `browser_fill_and_submit` on a login form, capture the response headers and body. Extract new tokens from `Set-Cookie`, `Authorization`, JSON body (`{ token: "..." }`), or redirect URL parameters.

### Source 10: Redirect Chains
**New capability**: During login, follow 302 redirects and capture cookies set at each hop. Many OAuth flows set session cookies during the redirect chain.

---

## 7. Correct Request Injection Logic

### Decision Algorithm

```
prepareHeaders(url: URL, identityId: string): AuthContext
  1. Resolve identity → lookup CookieJar[identityId] and TokenStore[identityId]
  2. HOST SCOPE CHECK:
     if url.hostname NOT in authRequiredHosts → return EMPTY AuthContext
  3. PATH NO-AUTH CHECK:
     if url.pathname matches noAuthPaths → return EMPTY AuthContext
  4. COOKIE ASSEMBLY:
     for each cookie in CookieJar[identityId]:
       if cookie.domain matches url.hostname
       AND cookie.path is prefix of url.pathname
       AND (cookie.secure === false OR url.protocol === 'https')
       AND cookie is not expired:
         → include in Cookie header
     Sort by path specificity (longest first — RFC 6265)
  5. AUTH HEADER:
     if TokenStore[identityId] has active token:
       → set Authorization: {prefix}{value}
  6. CSRF (if method in csrfRequiredMethods):
     if CSRFState[identityId] exists:
       if deliveryMechanism === 'cookie_to_header':
         → set X-XSRF-TOKEN from XSRF-TOKEN cookie value
       if deliveryMechanism === 'hidden_input':
         → set csrfBodyField + csrfBodyValue for body injection
       if deliveryMechanism === 'response_header':
         → set custom header
  7. CUSTOM HEADERS:
     for each custom auth header in TokenStore[identityId].customHeaders:
       → set header
  8. RETURN AuthContext (immutable)
```

### Precedence Rules

| Condition | Rule |
|---|---|
| LLM explicitly sets a Cookie header in tool args | **AuthInjector's Cookie WINS** — override LLM's value. LLM should not be setting auth headers. |
| LLM explicitly sets Authorization header | **AuthInjector's value WINS** unless LLM is doing an explicit auth bypass test (detected by hypothesis context). |
| Multiple tokens for same host | Use the most recently validated token. |
| Cookie + Bearer both present for same identity | Include BOTH. Many apps accept both simultaneously. |
| Browser-driven request vs agent HTTP request | Browser uses its own context cookies (in-browser). Agent uses `AuthInjector`. They sync after each browser navigation. |
| Explicit "test without auth" (e.g., auth bypass hypothesis) | `AuthInjector` supports `identityId = '__none__'` which returns empty auth context. |

### User Selection for IDOR/BAC Tests

```
When the LLM calls repeater_test with a hypothesis of type 'idor' or 'auth-bypass':
  1. First mutation: use identity A's auth (original)
  2. Second mutation: use identity B's auth
  3. Third mutation: use NO auth (anonymous)
  
The identity selection is passed as an explicit parameter:
  repeater_test({ requestId, mutations, identityId: 'user-b' })
```

---

## 8. Multi-User Isolation

### Isolation Architecture

```
AuthStateManager
├── identities['user-a']
│   ├── CookieJar (Map<domain, CookieState[]>)
│   ├── TokenStore (TokenState[])
│   ├── CSRFState
│   ├── SessionHealth
│   └── BrowserContextId (if browser session exists)
│
├── identities['user-b']
│   ├── CookieJar (Map<domain, CookieState[]>)
│   ├── TokenStore (TokenState[])
│   ├── CSRFState
│   ├── SessionHealth
│   └── BrowserContextId (separate Playwright context)
│
└── bindingRules
```

### Strict Rules

1. **CookieJar isolation**: Each identity has its own `Map<domain, CookieState[]>`. No shared entries.
2. **Token isolation**: Each identity has its own `TokenState[]`. No shared tokens.
3. **Browser context isolation**: Each identity gets its own `BrowserContext` (Playwright built-in isolation — separate cookies, localStorage, sessionStorage).
4. **Request history isolation**: Each identity's requests are tagged with `identityId` in the request tracker.
5. **Refresh flow isolation**: Each identity has its own `RefreshPlan`. Refresh for User A never touches User B's state.
6. **Contamination detection**: After every `AuthInjector.prepareHeaders()`, verify that the returned `AuthContext.identityId` matches the requested identity. If a mismatch is detected (implementation bug), log a `CONTAMINATION_ALERT` and abort the request.

### Safe User Switching for IDOR Tests

```typescript
async function testIDOR(endpoint: string, method: string, body: string): Promise<IDORResult> {
  // Step 1: Request as User A
  const ctxA = authManager.prepareHeaders(endpoint, 'user-a');
  const responseA = await burp.callTool('send_http_request', {
    url: endpoint, method, headers: ctxA.toHeaders(), body
  });
  
  // Step 2: Request as User B (exact same endpoint, different auth)
  const ctxB = authManager.prepareHeaders(endpoint, 'user-b');
  const responseB = await burp.callTool('send_http_request', {
    url: endpoint, method, headers: ctxB.toHeaders(), body
  });
  
  // Step 3: Compare responses
  const diff = diffResponses(responseA, responseB);
  // If both return 200 with different user data → IDOR confirmed
  // If User B gets 403 → access control is working
}
```

---

## 9. Session Health and Expiry Management

### Detection Strategies

| Signal | Detection | Action |
|---|---|---|
| JWT `exp` claim | Parse JWT payload → compare `exp` against current time | Schedule refresh at `exp - 60s` |
| 401 Unauthorized | Response status from any request | Increment `authErrorCount`. If ≥ 2 consecutive → trigger refresh |
| 403 Forbidden | Response status | Check if this was expected (auth bypass test) or unexpected. If unexpected → log warning, don't auto-refresh |
| 302 → /login | Response redirect to login URL pattern | Strong signal of session death → trigger re-login |
| New Set-Cookie with different session value | Response header analysis | Server rotated session → update CookieJar |
| CSRF validation error (422/419) | Response body contains "CSRF" or "token" + 4xx | Refresh CSRF token from DOM/response |
| Rate limit (429) | Response status | Pause all requests for that identity for cooldown period. Do NOT refresh auth. |
| Account lockout | Repeated 401 + body contains "locked" | STOP using that identity. Mark as dead. Alert operator. |

### Validation Probe

Every N requests (default: every 20 requests or every 5 minutes), send a lightweight probe:

```typescript
async function validateSession(identityId: string): Promise<SessionProbeResult> {
  const safeUrl = `${targetUrl}/`; // root page, always exists
  const ctx = authManager.prepareHeaders(safeUrl, identityId);
  const response = await burp.callTool('send_http_request', {
    method: 'HEAD', url: safeUrl, headers: ctx.toHeaders()
  });
  
  if (response.statusCode >= 200 && response.statusCode < 400) return 'authenticated';
  if (response.statusCode === 401 || response.statusCode === 403) return 'unauthenticated';
  if (response.statusCode === 429) return 'rate_limited';
  return 'error';
}
```

### Refresh Decision Tree

```
Session probe returns 'unauthenticated':
  ├── RefreshPlan exists AND refreshAttempts < maxAttempts?
  │   ├── Has refresh token? → Execute refresh flow → update tokens
  │   ├── Has credentials + login URL? → Execute re-login → update tokens
  │   └── Login is browser-only (OAuth)? → 
  │       ├── Browser session alive? → Navigate to login → capture new cookies
  │       └── Browser session dead? → Alert operator: "Session expired. Re-login required."
  │
  └── Refresh exhausted or no refresh plan?
      → Mark identity as DEAD
      → Log: "Identity {id} session expired. No refresh mechanism available."
      → Continue scan with remaining identities
      → Alert operator via scan logs
```

---

## 10. How This Works During Real Pentest Execution

### Authenticated Crawl

1. `browser_navigate(url)` → browser uses its Playwright context cookies
2. After navigation: `AuthCapture.fromBrowser()` syncs new cookies back to AuthStateManager
3. Discovered endpoints registered in CoverageTracker with auth context note
4. Every HTTP request made during crawl: `AuthInjector.prepareHeaders()` injects correct auth

### IDOR Testing

1. LLM identifies object reference parameter (e.g., `/api/orders/123`)
2. LLM calls `repeater_test({ requestId, mutations: [{parameter: 'path_segment_3', originalValue: '123', newValue: '124'}], identityId: 'user-b' })`
3. `AuthInjector` resolves User B's auth context
4. Request sent with User B's cookies/tokens but User A's object ID
5. Response diffed → if User B can access User A's order → IDOR confirmed

### Authorization Differential

1. Same endpoint tested with User A (admin) and User B (regular) 
2. `AuthInjector` provides correct auth for each identity
3. If both get 200 → broken access control
4. If User B gets 403 → properly restricted

### Multi-Step Transaction Flow

1. Step 1: POST /cart/add → sets new CSRF cookie
2. `AuthCapture.fromResponseHeaders()` captures new Set-Cookie → updates CookieJar
3. Step 2: POST /checkout → `AuthInjector` includes updated CSRF token
4. Step 3: POST /payment → fresh CSRF fetched if `rotatesPerRequest: true`

### Browser-Assisted PoC

1. Finding confirmed via HTTP path
2. For PoC screenshot: browser navigates to same URL
3. `AuthCapture.syncToBrowser(identityId, browserSessionId)` pushes current CookieJar into Playwright context
4. Browser renders authenticated page → screenshot captured as evidence

---

## 11. Browser + Burp + Raw Request Interoperability

### Source-of-Truth Model

```
AuthStateManager (backend memory)
     ↑ sync ↓ push
     │       │
     │       └─── Playwright BrowserContext.addCookies()
     │
     ↑ capture
     │
     ├── Burp Proxy (observed traffic has cookies/tokens)
     ├── Browser (Playwright context.cookies())  
     └── Agent HTTP (response Set-Cookie headers)
```

**Rule**: AuthStateManager is ALWAYS authoritative. Browser and Burp are SOURCES (read from) and TARGETS (pushed to).

### Synchronization Rules

| Direction | When | What |
|---|---|---|
| Burp → AuthStateManager | On harvest cycle, on explicit `get_session_cookies` | New cookies from proxy history |
| Browser → AuthStateManager | After every `browser_navigate`, `browser_fill_and_submit` | Context cookies, localStorage tokens |
| AuthStateManager → Browser | Before browser-assisted PoC, when session refreshed | Push updated CookieJar into Playwright context |
| AuthStateManager → Agent HTTP | On every `send_http_request` | `AuthInjector.prepareHeaders()` |
| AuthStateManager → Export | On scan completion or operator request | JSON dump of live auth state |

### What Must NOT Cross Layers

- **Passwords**: Never pushed to browser localStorage or injected into requests
- **Refresh tokens**: Never sent in regular requests — only to refresh endpoints
- **User B's cookies**: Never injected into User A's browser context

---

## 12. Logging, Persistence, and Secret Safety

### What Must Be Persisted (crash recovery)

| Data | Storage | Encryption |
|---|---|---|
| IdentityProfiles (without passwords) | `auth_identities` table | No (non-secret) |
| CookieJar snapshot | `auth_cookies` table | AES-256 at rest |
| TokenState (redacted) | `auth_tokens` table | Token value AES-256 |
| SessionHealth | `auth_health` table | No |
| CSRF state | `auth_csrf` table | No |
| RefreshPlan (without tokens) | `auth_refresh_plans` table | Endpoint only |

### What Remains Ephemeral

- Passwords (only in memory during scan)
- Decrypted token values in working memory
- Browser context state (Playwright manages this)

### Log Hygiene

```typescript
function redactForLog(value: string, type: 'cookie' | 'token' | 'password'): string {
  if (type === 'password') return '***REDACTED***';
  if (value.length <= 8) return '***';
  return value.substring(0, 4) + '***' + value.substring(value.length - 4);
}
```

**Rules**:
- Token values → first 4 + last 4 characters in logs
- Passwords → NEVER logged, not even redacted
- Cookie values → first 4 + last 4 characters
- CookieJar contents → only names logged, not values
- JWT payloads → `sub`, `exp`, `role` logged; full payload NOT logged

### Export Format for Human Reuse

```json
{
  "exportedAt": "2026-04-07T11:00:00Z",
  "scanId": "abc-123",
  "targetUrl": "https://target.com",
  "identities": [
    {
      "id": "user-a",
      "label": "Admin User",
      "cookies": "JSESSIONID=abc123; theme=dark",
      "authorizationHeader": "Bearer eyJhbG...",
      "csrfToken": { "name": "_csrf", "value": "token-value" },
      "curlExample": "curl -H 'Cookie: JSESSIONID=abc123' -H 'Authorization: Bearer eyJ...' https://target.com/api/users"
    }
  ]
}
```

---

## 13. Failure Modes and Hard Cases

| # | Case | Strategy |
|---|---|---|
| 1 | **Token rotation on every request** | Capture new token from response, update TokenStore before next request. Execute sequentially (no parallel requests for this identity). |
| 2 | **Refresh token rotation** | After refresh, replace BOTH access and refresh tokens atomically. If refresh fails, fall back to re-login. |
| 3 | **CSRF changes per request** | Set `CSRFState.rotatesPerRequest = true`. Before each state-changing request, fetch fresh CSRF from GET request to same form page. |
| 4 | **Multiple concurrent valid tokens** | Store all. Use most recently acquired. Mark older ones as `superseded` but retain for fallback. |
| 5 | **Multiple auth schemes in one app** | Cookie for web UI + Bearer for API is common. CookieJar handles cookies; TokenStore handles headers. Both injected simultaneously. |
| 6 | **Login performed in browser only (OAuth)** | Wait for browser login to complete → capture Playwright context cookies → import into AuthStateManager. No re-login possible without browser. Mark `RefreshPlan.strategy = 'browser_relogin'`. |
| 7 | **Token only in JS memory** | Install `page.route()` interceptor to capture Authorization headers from JS fetch calls. Alternatively, `page.evaluate(() => localStorage.getItem('token'))`. |
| 8 | **Cookie + Bearer hybrid** | Both are captured and stored separately. `AuthInjector` includes both in every request. |
| 9 | **Role switch during scan** | Operator sends command "switch to admin role" → activate different identity → all subsequent requests use new identity's auth. |
| 10 | **Tenant switch during scan** | Same as role switch but also updates `TenantBinding`. Auth material specific to old tenant is NOT used for new tenant. |
| 11 | **Accidental logout** | Agent navigates to /logout → session dies. `SessionHealthMonitor` detects 302→login on next request → triggers re-login. Lesson: add `/logout` to `noAuthPaths` or block navigation to logout URLs during automated testing. |
| 12 | **Stale browser context** | Browser session died (tab crash, Playwright error). On next `ensureBrowserSession()`, re-launch browser and push AuthStateManager cookies into new context. |
| 13 | **Partial re-authentication** | Some endpoints work, others return 403. Login partially revoked. Send validation probe to known-good endpoint. If probe succeeds → session is alive but specific endpoint has access control. If probe fails → session is dead. |
| 14 | **Rate limits** | 429 response → pause requests for that identity. Do NOT refresh auth. Different from auth failure. |
| 15 | **Anti-automation (CAPTCHA, WAF)** | Detect CAPTCHA indicators in response body. Alert operator: "CAPTCHA detected. Manual intervention required." Pause identity. |
| 16 | **Account lockout risk** | Track failed login attempts per identity. After 3 failed logins → STOP trying for that identity. Alert: "Account may be locked." |
| 17 | **Server invalidates ALL sessions on password change** | After password-related testing, validate ALL identities. If any die, re-login. |

---

## 14. Exact Engineering Deliverables

### New Backend Modules

| Module | Path | Lines (est.) | Purpose |
|---|---|---|---|
| `AuthStateManager.ts` | `services/auth/AuthStateManager.ts` | ~400 | Singleton per scan. Owns all auth state. Source of truth. |
| `AuthCapture.ts` | `services/auth/AuthCapture.ts` | ~350 | Captures auth from all sources (Burp, browser, responses, operator) |
| `AuthInjector.ts` | `services/auth/AuthInjector.ts` | ~250 | Deterministic request header assembly |
| `IdentityRegistry.ts` | `services/auth/IdentityRegistry.ts` | ~200 | Manages identity profiles and credential sets |
| `SessionHealthMonitor.ts` | `services/auth/SessionHealthMonitor.ts` | ~300 | Monitors session validity, triggers refresh |
| `CSRFManager.ts` | `services/auth/CSRFManager.ts` | ~200 | CSRF token lifecycle |
| `CookieJar.ts` | `services/auth/CookieJar.ts` | ~250 | RFC 6265-compliant cookie storage with domain/path scoping |
| `TokenStore.ts` | `services/auth/TokenStore.ts` | ~200 | Token lifecycle, JWT parsing, expiry tracking |
| `types.ts` | `services/auth/types.ts` | ~200 | All interfaces from Section 4 |

### DB Schema Changes

```sql
-- Auth identities for a scan
CREATE TABLE IF NOT EXISTS auth_identities (
  id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  label TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'primary',
  username TEXT,
  user_id TEXT,
  email TEXT,
  tenant_id TEXT,
  role_in_app TEXT,
  is_active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id, scan_id),
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Cookie jar snapshots  
CREATE TABLE IF NOT EXISTS auth_cookies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  name TEXT NOT NULL,
  value_encrypted BLOB NOT NULL,
  domain TEXT NOT NULL,
  path TEXT DEFAULT '/',
  expires DATETIME,
  http_only INTEGER DEFAULT 0,
  secure INTEGER DEFAULT 0,
  same_site TEXT,
  is_session_cookie INTEGER DEFAULT 0,
  captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Token store
CREATE TABLE IF NOT EXISTS auth_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  token_type TEXT NOT NULL,
  header_name TEXT NOT NULL,
  header_value_prefix TEXT DEFAULT '',
  value_encrypted BLOB NOT NULL,
  expires_at DATETIME,
  is_refresh_token INTEGER DEFAULT 0,
  source TEXT NOT NULL,
  captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Session health log
CREATE TABLE IF NOT EXISTS auth_session_health (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  identity_id TEXT NOT NULL,
  is_alive INTEGER NOT NULL,
  confidence INTEGER NOT NULL,
  probe_result TEXT,
  consecutive_failures INTEGER DEFAULT 0,
  checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

### OrchestratorAgent Changes

| Location | Current | New |
|---|---|---|
| `constructor()` | Creates empty state | `this.authManager = new AuthStateManager(scanId)` |
| `phaseInit()` L1022-1062 | String-based cookie resolution | `await this.authManager.initialize(config, burpClient, browserSessionId)` |
| `executeSendHttpRequest()` L1831 | Passes LLM's headers directly | `const ctx = this.authManager.inject(url, identityId); mergedHeaders = {...toolCall.args.headers, ...ctx.toHeaders()};` |
| `executeRepeaterTest()` L3160 | Uses harvested request headers | `const ctx = this.authManager.inject(request.url, mutation.identityId \|\| 'primary')` |
| System prompt | Contains raw Cookie/Auth strings | "Auth is handled automatically. Do not set Cookie or Authorization headers." |
| After every HTTP response | Nothing | `this.authManager.capture.fromResponse(response)` |
| `runHarvestCycle()` | No auth sync | `this.authManager.capture.fromBurpHistory()` |

### Browser Integration Changes

| Current | New |
|---|---|
| Browser cookies disconnected from agent | `AuthCapture.fromBrowser()` after every navigation |
| No push from agent to browser | `AuthStateManager.syncToBrowser(identityId, browserSessionId)` for PoC |
| Single browser context for all testing | Separate `BrowserContext` per identity for IDOR browser tests |

### Tests

| Test | Type | Validates |
|---|---|---|
| CookieJar domain/path scoping | Unit | Cookies only sent to matching domain/path |
| TokenStore JWT parsing | Unit | Correct exp extraction, rotation handling |
| AuthInjector header assembly | Unit | Correct Cookie + Authorization + CSRF in output |
| Multi-identity isolation | Integration | User A cookies never appear in User B context |
| Session refresh flow | Integration | 401 → refresh → new token → next request succeeds |
| CSRF rotation | Integration | Per-request CSRF fetch + inject |
| Crash recovery | Integration | Kill process mid-scan → restart → auth state restored from DB |
| Browser ↔ AuthStateManager sync | Integration | Browser login → cookies captured → agent HTTP uses them |

---

## 15. Best Final Design

### Architecture
**`AuthStateManager` is a per-scan singleton** that owns all authentication state. It is initialized during `phaseInit()`, updated continuously during execution, and exported at scan completion. No auth state lives in the LLM prompt.

### Source-of-Truth Model
**AuthStateManager in backend memory**, with periodic snapshots to SQLite for crash recovery. Browser and Burp are capture sources and injection targets, never authoritative.

### Token/Session Lifecycle
**Capture → Normalize → Bind to Identity → Store → Validate → Inject per-request → Monitor responses → Refresh proactively → Re-login on failure → Export on completion.** Every stage is deterministic. The LLM never handles tokens.

### Multi-User Isolation
**Per-identity namespaces**: separate CookieJar, TokenStore, CSRFState, BrowserContext, and RequestHistory per `IdentityProfile`. Contamination detection at injection time. The `repeater_test` tool accepts an explicit `identityId` parameter for user-switching.

### Request Injection Strategy
**`AuthInjector.prepareHeaders(url, identityId)`** is called inside `executeToolCall()` for EVERY outgoing request. It assembles the Cookie header from the CookieJar (domain/path scoped), sets the Authorization header from TokenStore, adds CSRF tokens for state-changing methods, and returns an immutable `AuthContext`. This replaces the current model where the LLM must remember to include headers.

### Reuse of Live Auth State
Captured auth state is continuously updated from response headers and browser context changes. At scan end, `exportForHumanReuse()` generates a structured JSON export with curl examples that a human pentester can immediately use in Burp Repeater or terminal.

### What This Eliminates

| Current Problem | Eliminated By |
|---|---|
| LLM forgets Cookie header | `AuthInjector` injects automatically |
| Token expires mid-scan | `SessionHealthMonitor` detects + `RefreshPlan` executes |
| User A/B cookies mixed | Per-identity CookieJar isolation |
| CSRF token stale | `CSRFManager` refreshes per-request when needed |
| Browser and agent in different auth states | Bidirectional sync via `AuthCapture` / `AuthStateManager.syncToBrowser()` |
| No crash recovery for auth state | Encrypted persistence to SQLite |
| No export for human pentester | `exportForHumanReuse()` generates structured JSON + curl |
| Session cookies only captured at init | Continuous capture from every response + harvest cycle |
