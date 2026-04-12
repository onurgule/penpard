/**
 * ScanCoverageGraphMatchers.ts
 *
 * Pure functions for:
 *  1. Normalizing raw paths to canonical base routes
 *  2. Filtering noise (assets, vendor, telemetry, third-party)
 *  3. Matching vulnerabilities to canonical route nodes
 *  4. Inferring attack types from vulnerability data
 *
 * v3: Semantic resource-level canonicalization.
 *     API routes keep 2–3 meaningful segments.
 *     Auth-sensitive leaf routes are always preserved.
 */

import type { CoverageGraphNode } from './ScanCoverageGraph.types';

// ═══════════════════════════════════════════════════════════════
//  ROUTE NORMALIZATION — raw path → canonical base route
// ═══════════════════════════════════════════════════════════════

/** Auth/security-sensitive leaf names that must never be collapsed */
const AUTH_LEAF_NAMES = new Set([
    'login', 'logout', 'signin', 'signout', 'signup', 'register',
    'forgot-password', 'reset-password', 'change-password', 'verify',
    'confirm', 'token', 'refresh', 'oauth', 'callback', 'sso',
    'whoami', 'me', 'session', 'two-factor', '2fa', 'mfa',
    'forgot', 'reset', 'password',
]);

/** Known API prefixes where we keep resource-level segments */
const API_PREFIXES = new Set(['rest', 'api', 'graphql', 'v1', 'v2', 'v3']);

/** Known action/sub-resource names that should be preserved */
const KNOWN_ACTIONS = new Set([
    'search', 'admin', 'challenges', 'captcha',
]);

/**
 * Normalize a raw URL/path to a canonical base route.
 *
 * v3 Rules:
 *   1. Extract pathname from full URL (strip origin, query, hash)
 *   2. Lowercase
 *   3. Strip trailing slash (keep root '/')
 *   4. For each segment, decide keep vs collapse:
 *      - Always keep API prefix segments (rest, api, v1, v2, v3)
 *      - Always keep auth-sensitive leaf names
 *      - Always keep known action/sub-resource names
 *      - Collapse: UUIDs, numeric IDs, hex hashes, base64, tokens
 *      - For API routes: keep up to 3 meaningful segments after prefix
 *      - For page routes: keep up to 2 meaningful segments
 *   5. Re-join segments
 *
 * Examples:
 *   /rest/user/login                    → /rest/user/login
 *   /rest/user/123                      → /rest/user
 *   /rest/products/search?q=apple       → /rest/products/search
 *   /rest/basket/42/checkout            → /rest/basket/checkout
 *   /api/v1/users/550e8400-e29b-...     → /api/v1/users
 *   /login?next=/dashboard              → /login
 *   /invite/uskopazar                   → /invite
 *   /reset-password/abc123token         → /reset-password
 */
export function normalizeToCanonicalRoute(raw: string): string {
    if (!raw) return '/';
    let p = raw;

    // 1. Extract pathname from full URL
    try {
        const url = new URL(p, 'http://placeholder');
        p = url.pathname;
    } catch {
        // Already a path — strip query/hash manually
        const qIdx = p.indexOf('?');
        if (qIdx !== -1) p = p.substring(0, qIdx);
        const hIdx = p.indexOf('#');
        if (hIdx !== -1) p = p.substring(0, hIdx);
    }

    // 2. Lowercase
    p = p.toLowerCase();

    // 3. Strip trailing slash (keep root)
    if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);

    // 4. Process segments
    const segments = p.split('/');
    const result: string[] = [];
    let isApiRoute = false;
    let meaningfulSegmentCount = 0; // count post-prefix meaningful segments

    for (let i = 0; i < segments.length; i++) {
        const seg = segments[i];
        if (seg === '') { result.push(''); continue; }

        // Always keep API prefix segments and mark the route as API
        if (API_PREFIXES.has(seg)) {
            result.push(seg);
            isApiRoute = true;
            continue;
        }

        // Always keep auth-sensitive leaf names at any depth
        if (AUTH_LEAF_NAMES.has(seg)) {
            result.push(seg);
            meaningfulSegmentCount++;
            continue;
        }

        // Always keep known action/sub-resource names
        if (KNOWN_ACTIONS.has(seg)) {
            result.push(seg);
            meaningfulSegmentCount++;
            continue;
        }

        // --- Collapse rules: skip dynamic/noise segments ---

        // Skip UUIDs
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) continue;
        // Skip pure numeric IDs
        if (/^\d+$/.test(seg)) continue;
        // Skip hex hashes (8+ hex chars that aren't just letters or a known word)
        if (/^[0-9a-f]{8,}$/i.test(seg) && !/^[a-z]+$/i.test(seg)) continue;
        // Skip base64-like segments (long alphanumeric)
        if (seg.length > 20 && /^[a-zA-Z0-9+/=_-]+$/.test(seg)) continue;
        // Skip token-like segments: mixed letters+digits, 8+ chars, not a known route word
        if (seg.length >= 8 && /[a-z]/i.test(seg) && /\d/.test(seg) && !/^(v\d+|api|auth|admin|rest)$/i.test(seg)) continue;

        // --- Depth limit: API routes keep up to 2 meaningful segments, pages up to 2 ---
        // Auth-leaf names always bypass the depth limit.
        const maxMeaningful = 2;
        if (meaningfulSegmentCount >= maxMeaningful) {
            // Check if this is a well-known name worth keeping even beyond depth limit
            const isWellKnown = /^[a-z][a-z-]*$/i.test(seg) && seg.length <= 20 &&
                (AUTH_LEAF_NAMES.has(seg) || KNOWN_ACTIONS.has(seg));
            if (!isWellKnown) continue;
        }

        // For page routes at depth >= 2, collapse slug-like segments
        // (lowercase-alpha only, not a known word) — likely usernames, slugs, product names
        if (!isApiRoute && result.filter(s => s !== '').length >= 1) {
            const isGenericSlug = /^[a-z][a-z0-9-]*$/i.test(seg) &&
                seg.length >= 3 &&
                !AUTH_LEAF_NAMES.has(seg) &&
                !KNOWN_ACTIONS.has(seg) &&
                !API_PREFIXES.has(seg) &&
                !/^(login|logout|register|signup|signin|dashboard|settings|profile|admin|checkout|basket|cart|account)$/i.test(seg);
            if (isGenericSlug) continue;
        }

        result.push(seg);
        meaningfulSegmentCount++;
    }

    const final = result.join('/') || '/';
    return final;
}

// ═══════════════════════════════════════════════════════════════
//  NOISE FILTERING — exclude non-application routes
// ═══════════════════════════════════════════════════════════════

/** Static asset file extensions to exclude */
const NOISE_EXTENSIONS = new Set([
    '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx',
    '.css', '.scss', '.less', '.map',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif', '.bmp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.webm', '.ogg',
    '.pdf', '.zip', '.gz', '.br',
    '.json', '.xml', '.txt', '.csv',
]);

/** Path prefixes that are telemetry/CDN/vendor noise */
const NOISE_PATH_PREFIXES = [
    '/cdn-cgi/', '/_next/', '/__next', '/node_modules/',
    '/sockjs-node/', '/_hmr', '/webpack', '/hot-update',
    '/favicon', '/.well-known/',
    '/rum/', '/beacon/', '/collect',
    '/gtag/', '/gtm', '/analytics', '/telemetry',
    '/signals/', '/_vercel/', '/_nuxt/',
    '/wp-content/', '/wp-includes/', '/wp-admin/',
    '/static/chunks/', '/static/css/', '/static/media/',
    '/assets/vendor/', '/dist/',
];

/** Path patterns that match telemetry/analytics/noise endpoints */
const NOISE_PATH_PATTERNS = [
    /\/cdn-cgi\//i,
    /\/_next\//i,
    /\/sockjs/i,
    /\/hot-update/i,
    /\/webpack/i,
    /\/rum\b/i,
    /\/beacon\b/i,
    /\/signals?\b/i,
    /\/telemetry\b/i,
    /\/analytics\b/i,
    /\/gtag/i,
    /\/collect\b/i,
    /\/__webpack/i,
    /\/hmr/i,
    /\/ws\b/i,
    /\/socket\.io/i,
    // Short Google/CDN telemetry paths
    /^\/as\b/i,
    /^\/gs\b/i,
    /^\/gen\b/i,
    /^\/xjs\b/i,
    /^\/log\b/i,
    /^\/ccm\b/i,
    /^\/recaptcha\b/i,
    /^\/gsi\b/i,
    /^\/pagead\b/i,
    /^\/adsense\b/i,
    /^\/tag\b/i,
    /^\/sw\.js/i,
];

/**
 * Check if a path represents noise (assets, vendor, telemetry, etc.)
 * that should NOT appear as a graph node.
 */
export function isNoisePath(path: string): boolean {
    const lower = path.toLowerCase();

    // Check extension
    const lastDot = lower.lastIndexOf('.');
    if (lastDot !== -1) {
        const ext = lower.substring(lastDot);
        if (NOISE_EXTENSIONS.has(ext)) return true;
    }

    // Check prefixes
    for (const prefix of NOISE_PATH_PREFIXES) {
        if (lower.startsWith(prefix)) return true;
    }

    // Check patterns
    for (const pattern of NOISE_PATH_PATTERNS) {
        if (pattern.test(lower)) return true;
    }

    return false;
}

/**
 * Check if a full URL is from a third-party origin (should be excluded).
 */
export function isThirdPartyUrl(url: string, targetOrigin: string | null): boolean {
    if (!targetOrigin) return false;
    try {
        const urlHost = new URL(url).hostname.toLowerCase();
        const targetHost = new URL(targetOrigin).hostname.toLowerCase();
        const isLocalhost = (h: string) => h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0' || h === '::1';

        // If target IS localhost, allow localhost URLs (same-origin)
        if (isLocalhost(targetHost)) {
            return !isLocalhost(urlHost);
        }

        // Target is NOT localhost — exclude localhost as dev noise
        if (isLocalhost(urlHost)) return true;

        // Same host or subdomain match
        return urlHost !== targetHost && !urlHost.endsWith('.' + targetHost);
    } catch {
        return false;
    }
}

/**
 * Extract origin from URL, null on failure.
 */
export function extractOrigin(url: string): string | null {
    try { return new URL(url).origin; } catch { return null; }
}

// ═══════════════════════════════════════════════════════════════
//  REQUEST PATH EXTRACTION
// ═══════════════════════════════════════════════════════════════

/**
 * Extract the path from a raw HTTP request string.
 */
export function extractPathFromRequest(rawRequest: string | undefined): string | null {
    if (!rawRequest) return null;
    const match = rawRequest.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\/[^\s]*)/im);
    if (match) return match[2];
    const urlMatch = rawRequest.match(/(?:https?:\/\/[^/\s]+)?(\/[^\s"'<>]*)/i);
    if (urlMatch) return urlMatch[1];
    return null;
}

/**
 * Extract pathname from a URL string.
 */
export function extractPathFromUrl(url: string): string | null {
    try { return new URL(url).pathname; }
    catch { return url.startsWith('/') ? url : null; }
}

// ═══════════════════════════════════════════════════════════════
//  VULNERABILITY → NODE MATCHING
// ═══════════════════════════════════════════════════════════════

interface VulnMatchCandidate {
    id: number;
    name: string;
    severity: string;
    request?: string;
    evidence?: string;
    cwe?: string;
}

export interface VulnMatch {
    vulnId: number;
    nodeId: string;
    severity: string;
    cwe?: string;
    vulnName: string;
}

function routeSimilarity(a: string, b: string): number {
    if (a === b) return 1.0;
    const partsA = a.split('/').filter(Boolean);
    const partsB = b.split('/').filter(Boolean);
    if (partsA.length === 0 || partsB.length === 0) return 0;
    let matching = 0;
    const maxLen = Math.max(partsA.length, partsB.length);
    for (let i = 0; i < Math.min(partsA.length, partsB.length); i++) {
        if (partsA[i] === partsB[i]) matching++;
        else break;
    }
    return matching / maxLen;
}

export function matchVulnToNode(vuln: VulnMatchCandidate, nodes: CoverageGraphNode[]): VulnMatch | null {
    if (nodes.length === 0) return null;
    const candidatePaths: string[] = [];

    const requestPath = extractPathFromRequest(vuln.request);
    if (requestPath) candidatePaths.push(normalizeToCanonicalRoute(requestPath));

    // Extract URL from vuln name (e.g. "SQL Injection - http://localhost:3001/rest/products/search")
    const nameUrlMatch = vuln.name.match(/(https?:\/\/[^\s,]+)/i);
    if (nameUrlMatch) {
        const p = extractPathFromUrl(nameUrlMatch[1]);
        if (p) candidatePaths.push(normalizeToCanonicalRoute(p));
    }
    const namePathMatch = vuln.name.match(/(\/[\w\-/.?&=]+)/);
    if (namePathMatch) {
        candidatePaths.push(normalizeToCanonicalRoute(namePathMatch[1]));
    }

    if (vuln.evidence) {
        const urlMatches = vuln.evidence.match(/(?:https?:\/\/[^/\s]+)?(\/[^\s"'<>,;)}\]]{2,})/gi);
        if (urlMatches) {
            for (const urlMatch of urlMatches.slice(0, 5)) {
                const p = extractPathFromUrl(urlMatch);
                if (p) candidatePaths.push(normalizeToCanonicalRoute(p));
            }
        }
    }

    if (candidatePaths.length === 0) return null;

    let bestNode: CoverageGraphNode | null = null;
    let bestScore = 0;
    for (const vulnPath of candidatePaths) {
        for (const node of nodes) {
            const score = routeSimilarity(vulnPath, node.canonicalRoute);
            if (score > bestScore && score >= 0.4) {
                bestScore = score;
                bestNode = node;
            }
        }
    }
    if (!bestNode) return null;
    return { vulnId: vuln.id, nodeId: bestNode.id, severity: vuln.severity, cwe: vuln.cwe, vulnName: vuln.name };
}

export function matchAllVulnsToNodes(vulns: VulnMatchCandidate[], nodes: CoverageGraphNode[]): Map<string, VulnMatch[]> {
    const matches = new Map<string, VulnMatch[]>();
    for (const vuln of vulns) {
        const match = matchVulnToNode(vuln, nodes);
        if (match) {
            const existing = matches.get(match.nodeId) || [];
            existing.push(match);
            matches.set(match.nodeId, existing);
        }
    }
    return matches;
}

// ═══════════════════════════════════════════════════════════════
//  ATTACK TYPE INFERENCE
// ═══════════════════════════════════════════════════════════════

export function inferAttackTypes(vulnName: string, cwe?: string): string[] {
    const types: string[] = [];
    const lower = (vulnName || '').toLowerCase();
    const cweStr = cwe || '';

    if (/xss|cross.?site.?script/i.test(lower) || cweStr === 'CWE-79') types.push('XSS');
    if (/sql.?inject/i.test(lower) || cweStr === 'CWE-89') types.push('SQLi');
    if (/csrf|cross.?site.?request/i.test(lower) || cweStr === 'CWE-352') types.push('CSRF');
    if (/idor|insecure.?direct/i.test(lower) || cweStr === 'CWE-639') types.push('IDOR');
    if (/ssrf|server.?side.?request/i.test(lower) || cweStr === 'CWE-918') types.push('SSRF');
    if (/path.?traversal|directory.?traversal|lfi/i.test(lower) || cweStr === 'CWE-22') types.push('Path Traversal');
    if (/command.?inject|os.?inject|rce/i.test(lower) || cweStr === 'CWE-78') types.push('Command Injection');
    if (/open.?redirect/i.test(lower) || cweStr === 'CWE-601') types.push('Open Redirect');
    if (/auth|broken.?auth|session/i.test(lower) || cweStr === 'CWE-287') types.push('Auth Bypass');
    if (/info.?disclos|info.?leak|sensitive/i.test(lower) || cweStr === 'CWE-200') types.push('Info Disclosure');

    return types.length > 0 ? types : ['Unknown'];
}
