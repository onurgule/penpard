/**
 * PenPard Prompt Library Service
 * 
 * Fetches community prompts from https://penpard.com/prompts,
 * caches them locally, and merges with built-in defaults.
 * Supports selecting an active scan prompt from the library.
 */

import { db } from '../db/init';
import { logger } from '../utils/logger';
import axios from 'axios';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface PromptVariable {
    key: string;
    label: string;
    required: boolean;
}

export interface LibraryPrompt {
    id: string;
    name: string;
    description: string;
    category: 'scan_template' | 'focused' | 'report' | 'recheck' | 'system';
    tags: string[];
    author: string;
    prompt_version: string;
    is_default: boolean;
    variables: PromptVariable[];
    template: string;
}

export interface PromptLibraryResponse {
    version: string;
    updated_at: string;
    source: string;
    prompts: LibraryPrompt[];
}

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const REMOTE_URL = 'https://penpard.com/prompts/prompts.json';
const CACHE_KEY = 'prompt_library_cache';
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const ACTIVE_PROMPT_KEY = 'prompt_library_active';
const FETCH_TIMEOUT_MS = 10_000;

// ─────────────────────────────────────────────────────────────
// Built-in fallback prompts (embedded from schema)
// ─────────────────────────────────────────────────────────────

const BUILTIN_PROMPTS: LibraryPrompt[] = [
    {
        id: 'web-pentest-comprehensive',
        name: 'Comprehensive Web Penetration Test',
        description: 'Full-scope OWASP Top 10 assessment with 4-phase methodology: reconnaissance, mapping, vulnerability testing, and deep exploitation. The default PenPard scan prompt.',
        category: 'scan_template',
        tags: ['web', 'owasp', 'comprehensive', 'default'],
        author: 'PenPard Team',
        prompt_version: '2.1',
        is_default: true,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'Test Accounts (for IDOR)', required: false }
        ],
        template: '' // Will be loaded from DEFAULT_WEB_PROMPT in OrchestratorAgent
    },
    {
        id: 'api-security-test',
        name: 'API Security Test',
        description: 'REST/GraphQL API security assessment targeting authentication, authorization, data exposure, and injection vulnerabilities.',
        category: 'scan_template',
        tags: ['api', 'rest', 'graphql', 'jwt', 'authorization'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target API Base URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'API Credentials', required: false }
        ],
        template: `You are conducting an authorized API security assessment.

TARGET API: {TARGET_WEBSITE}
SCOPE: This is a whitelisted, fully authorized ethical penetration test.

TEST CREDENTIALS:
{TARGET_WEBSITE_ACCOUNTS}

Test for:
1. Broken Authentication (JWT issues, session management, token expiry)
2. Broken Authorization (BOLA/IDOR — access other users' resources)
3. Excessive Data Exposure (API returns more data than needed)
4. Lack of Rate Limiting (brute-force, enumeration)
5. Mass Assignment vulnerabilities (modify read-only fields)
6. SQL/NoSQL Injection in all parameters
7. SSRF vulnerabilities in URL parameters
8. GraphQL-specific: introspection, batching attacks, nested query DoS

METHODOLOGY:
- Start by mapping all API endpoints (check /swagger, /openapi, /graphql)
- Test each endpoint with different HTTP methods
- Swap authentication tokens between user roles
- Fuzz all parameters with injection payloads
- Max 2-3 payloads per parameter — use send_to_scanner for deep testing

Analyze each endpoint methodically and report findings with full evidence.`
    },
    {
        id: 'sqli-focused',
        name: 'SQL Injection Focus',
        description: 'Specialized deep-dive into SQL injection testing. Error-based, boolean-blind, time-based, and UNION techniques.',
        category: 'scan_template',
        tags: ['sqli', 'injection', 'focused', 'database'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'Test Accounts', required: false }
        ],
        template: `You are a SQL injection specialist conducting an authorized security test.

TARGET: {TARGET_WEBSITE}
SCOPE: Focus EXCLUSIVELY on SQL Injection vulnerabilities.

TEST ACCOUNTS:
{TARGET_WEBSITE_ACCOUNTS}

TEST METHODOLOGY:

1. DISCOVERY — Find all input points:
   • URL parameters, POST body, cookies, HTTP headers
   • Search forms, login pages, API endpoints with DB queries
   • Hidden parameters in JavaScript source code

2. ERROR-BASED DETECTION (try first — fastest confirmation):
   • Single quote: '
   • Double quote: "
   • Comment injection: --
   • Look for SQL error messages in response (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

3. BOOLEAN-BASED BLIND:
   • TRUE condition: ' AND '1'='1
   • FALSE condition: ' AND '1'='2
   • Compare response length and content

4. TIME-BASED BLIND:
   • MySQL: ' AND SLEEP(5)--
   • PostgreSQL: ' AND pg_sleep(5)--
   • MSSQL: ' WAITFOR DELAY '0:0:5'--
   • Compare response time

5. DEEP TESTING:
   • If basic payloads confirm SQLi → use send_to_scanner for UNION extraction
   • NEVER manually enumerate column count with UNION SELECT null,null,...
   • Let Burp Scanner handle complex exploitation

Max 2-3 payloads per technique per parameter. Report every confirmed injection immediately.`
    },
    {
        id: 'idor-authorization',
        name: 'IDOR & Authorization Check',
        description: 'Deep testing for Insecure Direct Object References and broken access control across user roles.',
        category: 'scan_template',
        tags: ['idor', 'authorization', 'access-control', 'privilege-escalation'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'User Accounts (multi-role)', required: true }
        ],
        template: `You are an authorization testing specialist conducting an authorized security assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: Focus on IDOR and authorization bypass vulnerabilities.

USER ACCOUNTS FOR TESTING:
{TARGET_WEBSITE_ACCOUNTS}

TEST METHODOLOGY:

1. HORIZONTAL PRIVILEGE ESCALATION (user → user):
   • Login as User A, capture requests to User A's resources
   • Replay the same requests with User B's session token
   • Check: Can User B access User A's data?
   • Test all resource identifiers: numeric IDs, UUIDs, usernames, emails

2. VERTICAL PRIVILEGE ESCALATION (user → admin):
   • Access admin-only endpoints with regular user credentials
   • Check /admin, /api/admin, /dashboard, /manage endpoints
   • Try modifying role fields in profile update requests

3. UNAUTHENTICATED ACCESS:
   • Remove authentication tokens entirely
   • Access protected endpoints without any credentials
   • Check for API endpoints that skip auth checks

4. PARAMETER TAMPERING:
   • Modify user_id, account_id, order_id in requests
   • Try sequential IDs (id=1, id=2, id=3...)
   • Try other users' emails or usernames as identifiers

5. FUNCTION-LEVEL ACCESS CONTROL:
   • Can regular users access admin functions?
   • Can users delete/modify other users' data?
   • Check PUT/DELETE methods on resources owned by others

Use check_authorization tool to systematically compare responses. Report any access control failure immediately.`
    },
    {
        id: 'xss-focused',
        name: 'Cross-Site Scripting (XSS) Focus',
        description: 'Comprehensive XSS testing — reflected, stored, and DOM-based. Context-aware payload generation.',
        category: 'scan_template',
        tags: ['xss', 'injection', 'focused', 'client-side'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'Test Accounts', required: false }
        ],
        template: `You are an XSS specialist conducting an authorized security assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: Focus EXCLUSIVELY on Cross-Site Scripting vulnerabilities.

TEST ACCOUNTS:
{TARGET_WEBSITE_ACCOUNTS}

TEST METHODOLOGY:

1. REFLECTED XSS:
   • Test all URL parameters, search fields, error messages
   • Context-aware payloads:
     - HTML context: <script>alert(1)</script>
     - Attribute context: " onmouseover="alert(1)
     - JavaScript context: ';alert(1)//
     - URL context: javascript:alert(1)
   • Check if input is reflected without encoding

2. STORED XSS:
   • Test user profile fields (name, bio, avatar URL)
   • Test comment/review forms
   • Test file upload names
   • Check if stored input renders for OTHER users

3. DOM-BASED XSS:
   • Analyze JavaScript for dangerous sinks:
     - document.write(), innerHTML, eval()
     - location.hash, location.search, document.referrer
   • Test URL fragments (#payload) and query parameters

4. FILTER BYPASS:
   • If basic <script> is filtered, try:
     - <img src=x onerror=alert(1)>
     - <svg onload=alert(1)>
     - <details open ontoggle=alert(1)>
     - Case variation: <ScRiPt>alert(1)</sCrIpT>
     - Encoding: &#x3C;script&#x3E;

IMPORTANT: Always use COMPLETE payloads. Never send incomplete tags.
Max 2-3 payloads per context per parameter. Use send_to_scanner for deep testing.`
    },
    {
        id: 'bug-bounty-quick',
        name: 'Bug Bounty Quick Scan',
        description: 'Fast, targeted scan optimized for bug bounty programs. Focuses on high-impact, low-hanging fruit vulnerabilities.',
        category: 'scan_template',
        tags: ['bug-bounty', 'quick', 'high-impact'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'Test Accounts', required: false }
        ],
        template: `You are a bug bounty hunter performing a quick, targeted security assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: Authorized penetration test — focus on HIGH-IMPACT findings only.

TEST ACCOUNTS:
{TARGET_WEBSITE_ACCOUNTS}

STRATEGY: Quick wins first. Focus on P1/P2 bounty-eligible issues.

1. QUICK RECON (max 2 minutes):
   • Check /robots.txt, /sitemap.xml, /.env, /debug
   • Look for exposed admin panels, API docs, source maps
   • Check response headers for missing security headers

2. HIGH-IMPACT TESTS (priority order):
   a) Authentication bypass — default creds, JWT none algorithm
   b) IDOR — swap user IDs in API requests
   c) SQL Injection — test login and search forms
   d) SSRF — test any URL/webhook parameters
   e) File upload — test for unrestricted upload
   f) Sensitive data exposure — check API responses for over-exposure

3. SKIP:
   • Low-severity issues (missing headers alone, cookie flags)
   • Denial of Service testing
   • Social engineering vectors
   • Already-known public vulnerabilities

Be FAST. Test the most impactful vectors first. Report immediately when you find something. If an endpoint isn't vulnerable after 2 payloads, move on. Use send_to_scanner for complex parameters.

Finish the scan within 5 planning rounds.`
    },
    {
        id: 'owasp-api-top10',
        name: 'OWASP API Top 10 (2023)',
        description: 'Systematic testing against all OWASP API Security Top 10 2023 categories.',
        category: 'scan_template',
        tags: ['api', 'owasp', 'systematic', 'compliance'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target API URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'API Credentials', required: false }
        ],
        template: `You are conducting an OWASP API Security Top 10 (2023) assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: Systematic testing against all OWASP API Top 10 categories.

CREDENTIALS:
{TARGET_WEBSITE_ACCOUNTS}

TEST EACH CATEGORY SYSTEMATICALLY:

API1:2023 — Broken Object Level Authorization (BOLA)
• Swap resource IDs between users, test with different auth tokens

API2:2023 — Broken Authentication
• Test token expiry, JWT vulnerabilities, credential stuffing protection

API3:2023 — Broken Object Property Level Authorization
• Try mass assignment: add admin/role fields in update requests
• Check if API returns sensitive fields (password hashes, internal IDs)

API4:2023 — Unrestricted Resource Consumption
• Check for rate limiting on login, search, and data export endpoints
• Test large payload handling

API5:2023 — Broken Function Level Authorization
• Access admin endpoints with user tokens
• Try HTTP method switching (GET→PUT, POST→DELETE)

API6:2023 — Unrestricted Access to Sensitive Business Flows
• Test for automated abuse of business logic (coupon reuse, race conditions)

API7:2023 — Server-Side Request Forgery (SSRF)
• Test URL parameters with internal addresses (127.0.0.1, 169.254.169.254)

API8:2023 — Security Misconfiguration
• Check CORS, verbose errors, debug mode, default credentials

API9:2023 — Improper Inventory Management
• Discover undocumented endpoints, old API versions, shadow APIs

API10:2023 — Unsafe Consumption of APIs
• Test if the API properly validates data from third-party integrations

Report each finding with the specific OWASP API category. Max 2-3 payloads per test.`
    },
    {
        id: 'authentication-deep-dive',
        name: 'Authentication & Session Deep Dive',
        description: 'Focused testing of login, registration, password reset, session management, and JWT implementation.',
        category: 'scan_template',
        tags: ['authentication', 'session', 'jwt', 'login', 'focused'],
        author: 'PenPard Team',
        prompt_version: '1.0',
        is_default: false,
        variables: [
            { key: 'TARGET_WEBSITE', label: 'Target Website URL', required: true },
            { key: 'TARGET_WEBSITE_ACCOUNTS', label: 'Test Accounts', required: true }
        ],
        template: `You are an authentication security specialist.

TARGET: {TARGET_WEBSITE}
SCOPE: Focus on authentication, session management, and credential handling.

TEST ACCOUNTS:
{TARGET_WEBSITE_ACCOUNTS}

TEST AREAS:

1. LOGIN MECHANISM:
   • SQL injection in username/password fields
   • Brute-force protection (rate limiting, account lockout)
   • Default/weak credentials (admin:admin, test:test)
   • Username enumeration via error messages or timing

2. REGISTRATION:
   • Duplicate registration with existing emails
   • Weak password policy testing
   • Mass assignment (add role=admin during registration)
   • Email verification bypass

3. PASSWORD RESET:
   • Token predictability and expiry
   • Host header injection in reset emails
   • IDOR in reset flow (reset other users' passwords)
   • Rate limiting on reset requests

4. SESSION MANAGEMENT:
   • Session fixation
   • Session doesn't expire after logout
   • Concurrent session handling
   • Cookie security flags (HttpOnly, Secure, SameSite)

5. JWT/TOKEN SECURITY:
   • None algorithm attack
   • Weak signing key (try common secrets)
   • Token expiry validation
   • Information in JWT payload (sensitive data exposure)
   • JWK injection / key confusion attacks

6. MULTI-FACTOR AUTHENTICATION:
   • MFA bypass (skip MFA step, force-browse)
   • MFA code brute-force
   • MFA code reuse

Report each finding with the specific attack technique and full evidence.`
    }
];

// ─────────────────────────────────────────────────────────────
// Service Class
// ─────────────────────────────────────────────────────────────

class PromptLibraryService {
    private cachedPrompts: LibraryPrompt[] = [];
    private lastFetchTime: number = 0;
    private isFetching: boolean = false;

    constructor() {
        // Load cached data from DB on startup
        this.loadFromDB();
    }

    /**
     * Get all library prompts (cached + built-in merged)
     */
    getAll(): LibraryPrompt[] {
        return this.cachedPrompts.length > 0 ? this.cachedPrompts : BUILTIN_PROMPTS;
    }

    /**
     * Get only scan_template prompts (user-selectable)
     */
    getScanTemplates(): LibraryPrompt[] {
        return this.getAll().filter(p => p.category === 'scan_template');
    }

    /**
     * Get the currently active scan prompt ID
     */
    getActivePromptId(): string | null {
        try {
            const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(ACTIVE_PROMPT_KEY) as any;
            return row ? row.value : null;
        } catch {
            return null;
        }
    }

    /**
     * Set the active scan prompt by ID
     */
    setActivePromptId(promptId: string): void {
        db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`).run(ACTIVE_PROMPT_KEY, promptId);
        logger.info(`Active scan prompt set to: ${promptId}`);
    }

    /**
     * Get the active scan prompt template
     * Returns the template for the active prompt, or the default one
     */
    getActivePromptTemplate(): { id: string; template: string } | null {
        const activeId = this.getActivePromptId();
        const prompts = this.getAll();

        if (activeId) {
            const found = prompts.find(p => p.id === activeId);
            if (found && found.template) {
                return { id: found.id, template: found.template };
            }
        }

        // Fallback to default
        const defaultPrompt = prompts.find(p => p.is_default);
        if (defaultPrompt && defaultPrompt.template) {
            return { id: defaultPrompt.id, template: defaultPrompt.template };
        }

        return null;
    }

    /**
     * Fetch prompts from penpard.com/prompts
     * Returns true if new prompts were fetched
     */
    async fetchFromRemote(): Promise<{ success: boolean; count: number; error?: string }> {
        if (this.isFetching) {
            return { success: false, count: 0, error: 'Already fetching' };
        }

        this.isFetching = true;
        try {
            logger.info(`Fetching prompt library from ${REMOTE_URL}...`);

            const response = await axios.get(REMOTE_URL, {
                timeout: FETCH_TIMEOUT_MS,
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'PenPard/1.0'
                }
            });

            const data = response.data as PromptLibraryResponse;

            if (!data.prompts || !Array.isArray(data.prompts)) {
                throw new Error('Invalid response format: missing prompts array');
            }

            // Validate each prompt has required fields
            const validPrompts = data.prompts.filter(p =>
                p.id && p.name && p.template && p.category
            );

            if (validPrompts.length === 0) {
                throw new Error('No valid prompts found in response');
            }

            // Merge: remote prompts take priority, keep built-ins that aren't in remote
            const remoteIds = new Set(validPrompts.map(p => p.id));
            const builtInsNotInRemote = BUILTIN_PROMPTS.filter(p => !remoteIds.has(p.id));
            const merged = [...validPrompts, ...builtInsNotInRemote];

            // Save to DB cache
            this.saveToDB(data.version, data.updated_at, merged);

            this.cachedPrompts = merged;
            this.lastFetchTime = Date.now();

            logger.info(`Prompt library updated: ${validPrompts.length} remote + ${builtInsNotInRemote.length} built-in = ${merged.length} total`);

            return { success: true, count: merged.length };
        } catch (error: any) {
            const errMsg = error.code === 'ECONNABORTED'
                ? 'Fetch timeout (penpard.com unreachable)'
                : error.response
                    ? `HTTP ${error.response.status}: ${error.response.statusText}`
                    : error.message || 'Unknown error';
            logger.warn(`Failed to fetch prompt library: ${errMsg}`);
            return { success: false, count: this.cachedPrompts.length, error: errMsg };
        } finally {
            this.isFetching = false;
        }
    }

    /**
     * Check if cache is stale and should be refreshed
     */
    isCacheStale(): boolean {
        return Date.now() - this.lastFetchTime > CACHE_TTL_MS;
    }

    /**
     * Auto-refresh if stale (non-blocking)
     */
    async refreshIfStale(): Promise<void> {
        if (this.isCacheStale()) {
            // Fire and forget — don't block the caller
            this.fetchFromRemote().catch(() => { });
        }
    }

    // ─── Private helpers ──────────────────────────────────────

    private loadFromDB(): void {
        try {
            const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(CACHE_KEY) as any;
            if (row) {
                const cached = JSON.parse(row.value);
                if (cached.prompts && Array.isArray(cached.prompts) && cached.prompts.length > 0) {
                    this.cachedPrompts = cached.prompts;
                    this.lastFetchTime = cached.fetchedAt || 0;
                    logger.info(`Loaded ${this.cachedPrompts.length} prompts from local cache (version: ${cached.version || 'unknown'})`);
                    return;
                }
            }
        } catch (e) {
            logger.warn('Could not load prompt library cache from DB');
        }

        // Fallback to built-ins
        this.cachedPrompts = BUILTIN_PROMPTS;
        logger.info(`Using ${BUILTIN_PROMPTS.length} built-in prompts`);
    }

    private saveToDB(version: string, updatedAt: string, prompts: LibraryPrompt[]): void {
        try {
            const cacheData = JSON.stringify({
                version,
                updatedAt,
                fetchedAt: Date.now(),
                prompts
            });
            db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`).run(CACHE_KEY, cacheData);
        } catch (e) {
            logger.warn('Could not save prompt library cache to DB');
        }
    }
}

// Singleton
export const promptLibrary = new PromptLibraryService();
