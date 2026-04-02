/**
 * RequestHarvester — Burp traffic harvesting, classification, scoring, and promotion.
 *
 * Pulls proxy history from Burp MCP, normalizes requests, classifies them by purpose,
 * scores them for testing interest, and promotes high-value candidates for active testing.
 * This is the first stage of the Observe → Understand → Hypothesize → Validate loop.
 */

import { logger } from '../utils/logger';
import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface RequestParam {
    name: string;
    value: string;
    location: 'query' | 'body' | 'path' | 'header' | 'cookie';
    type: 'numeric' | 'uuid' | 'string' | 'boolean' | 'json' | 'unknown';
}

export type RequestClass =
    | 'authentication'
    | 'session-bootstrap'
    | 'state-changing'
    | 'object-reference'
    | 'search-query'
    | 'admin-candidate'
    | 'file-operation'
    | 'graphql'
    | 'websocket-bootstrap'
    | 'csrf-protected'
    | 'workflow-transition'
    | 'sensitive-resource'
    | 'static-asset'
    | 'unknown';

export interface HarvestedRequest {
    id: string;
    method: string;
    url: string;
    path: string;
    host: string;
    statusCode: number;
    mimeType: string;
    requestHeaders: Record<string, string>;
    requestBody: string;
    responseBody: string;
    responseHeaders: Record<string, string>;
    params: RequestParam[];
    classification: RequestClass;
    interestScore: number;
    harvestedAt: Date;
    source: 'browser' | 'agent' | 'user';
    promoted: boolean;
    testedHypotheses: string[];
}

export interface PromotedRequest {
    request: HarvestedRequest;
    reason: string;
}

// ─────────────────────────────────────────────────────────────
// Service Class
// ─────────────────────────────────────────────────────────────

export class RequestHarvester {
    private harvested: Map<string, HarvestedRequest> = new Map();
    private harvestCount: number = 0;

    /**
     * Harvest new requests from Burp proxy history.
     * Returns only newly-seen requests (delta since last harvest).
     */
    async harvest(burpClient: any, targetHost: string): Promise<HarvestedRequest[]> {
        try {
            const result = await burpClient.callTool('get_proxy_history', { count: 100, excludePenPard: true });
            const history = this.parseProxyHistory(result);

            if (history.length === 0) {
                logger.debug('[Harvester] No new proxy history entries');
                return [];
            }

            // Filter: target host only, skip static assets, skip already-seen
            const newRequests = history
                .filter((r: any) => this.isTargetHost(r.url, targetHost))
                .filter((r: any) => !this.isStaticAsset(r))
                .filter((r: any) => !this.harvested.has(this.computeRequestId(r)));

            if (newRequests.length === 0) {
                return [];
            }

            // Normalize, classify, score
            const processed: HarvestedRequest[] = newRequests.map((raw: any) => {
                const req = this.normalize(raw);
                req.classification = this.classify(req);
                req.interestScore = this.score(req);
                return req;
            });

            // Store
            processed.forEach(r => this.harvested.set(r.id, r));
            this.harvestCount += processed.length;

            logger.info(`[Harvester] Harvested ${processed.length} new requests (total: ${this.harvested.size})`);
            return processed;

        } catch (e: any) {
            logger.warn(`[Harvester] Harvest failed: ${e.message}`);
            return [];
        }
    }

    /**
     * Get top N candidates for promotion (highest score, not yet promoted).
     */
    getPromotionCandidates(limit: number = 5): PromotedRequest[] {
        const candidates = Array.from(this.harvested.values())
            .filter(r => !r.promoted && r.interestScore >= 30 && r.classification !== 'static-asset')
            .sort((a, b) => b.interestScore - a.interestScore)
            .slice(0, limit);

        return candidates.map(req => {
            req.promoted = true;
            return {
                request: req,
                reason: `Score ${req.interestScore}: ${req.classification} ${req.method} ${req.path}`,
            };
        });
    }

    /**
     * Get a harvested request by ID.
     */
    getById(id: string): HarvestedRequest | undefined {
        return this.harvested.get(id);
    }

    /**
     * Get all harvested requests.
     */
    getAll(): HarvestedRequest[] {
        return Array.from(this.harvested.values());
    }

    /**
     * Get summary statistics.
     */
    getSummary(): {
        total: number;
        promoted: number;
        byClassification: Record<string, number>;
        topScoring: Array<{ id: string; score: number; method: string; path: string; classification: string }>;
    } {
        const all = Array.from(this.harvested.values());
        const byClass: Record<string, number> = {};
        all.forEach(r => {
            byClass[r.classification] = (byClass[r.classification] || 0) + 1;
        });

        return {
            total: all.length,
            promoted: all.filter(r => r.promoted).length,
            byClassification: byClass,
            topScoring: all
                .sort((a, b) => b.interestScore - a.interestScore)
                .slice(0, 10)
                .map(r => ({ id: r.id, score: r.interestScore, method: r.method, path: r.path, classification: r.classification })),
        };
    }

    /**
     * Mark a hypothesis as tested against a request.
     */
    linkHypothesis(requestId: string, hypothesisId: string): void {
        const req = this.harvested.get(requestId);
        if (req && !req.testedHypotheses.includes(hypothesisId)) {
            req.testedHypotheses.push(hypothesisId);
        }
    }

    /**
     * Reset harvester state (for new scan).
     */
    clear(): void {
        this.harvested.clear();
        this.harvestCount = 0;
    }

    // ─────────────────────────────────────────────────────────
    // Internal: Parse, Normalize, Classify, Score
    // ─────────────────────────────────────────────────────────

    private parseProxyHistory(result: any): any[] {
        if (!result) return [];
        try {
            // MCP result format: { content: [{ type: 'text', text: '...' }] }
            if (result.content?.[0]?.text) {
                const parsed = JSON.parse(result.content[0].text);
                return parsed.history || parsed.entries || (Array.isArray(parsed) ? parsed : []);
            }
            // Direct array
            if (Array.isArray(result)) return result;
            if (result.history) return result.history;
            return [];
        } catch {
            return [];
        }
    }

    private isTargetHost(url: string, targetHost: string): boolean {
        try {
            const host = new URL(url).hostname;
            return host === targetHost || host === 'localhost' || host === '127.0.0.1';
        } catch {
            return false;
        }
    }

    private isStaticAsset(entry: any): boolean {
        const url = entry.url || '';
        const mime = (entry.mimeType || entry.mime || '').toLowerCase();
        // File extension check
        if (/\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|ico|map|webp|avif)(\?|$)/i.test(url)) return true;
        // MIME type check
        if (/^(image|font|text\/(css|javascript)|application\/(javascript|x-javascript))/i.test(mime)) return true;
        return false;
    }

    private computeRequestId(raw: any): string {
        const method = (raw.method || 'GET').toUpperCase();
        const url = raw.url || '';
        const body = raw.body || raw.requestBody || '';
        const hash = createHash('sha256').update(`${method}:${url}:${body}`).digest('hex').substring(0, 16);
        return `req-${hash}`;
    }

    private normalize(raw: any): HarvestedRequest {
        const method = (raw.method || 'GET').toUpperCase();
        const url = raw.url || '';
        let path = '';
        let host = '';
        try {
            const u = new URL(url);
            path = u.pathname + u.search;
            host = u.hostname;
        } catch {
            path = url;
        }

        const requestHeaders = this.normalizeHeaders(raw.requestHeaders || raw.headers || {});
        const requestBody = raw.body || raw.requestBody || '';
        const responseBody = raw.response || raw.responseBody || '';
        const responseHeaders = this.normalizeHeaders(raw.responseHeaders || {});
        const statusCode = raw.status || raw.statusCode || 0;
        const mimeType = raw.mimeType || raw.mime || responseHeaders['content-type'] || '';

        const params = this.extractParams(url, requestBody, requestHeaders);

        return {
            id: this.computeRequestId(raw),
            method,
            url,
            path,
            host,
            statusCode,
            mimeType,
            requestHeaders,
            requestBody,
            responseBody,
            responseHeaders,
            params,
            classification: 'unknown',
            interestScore: 0,
            harvestedAt: new Date(),
            source: 'browser',
            promoted: false,
            testedHypotheses: [],
        };
    }

    private normalizeHeaders(headers: any): Record<string, string> {
        if (!headers || typeof headers !== 'object') return {};
        const result: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers)) {
            result[k.toLowerCase()] = String(v);
        }
        return result;
    }

    private extractParams(url: string, body: string, headers: Record<string, string>): RequestParam[] {
        const params: RequestParam[] = [];

        // Query string params
        try {
            const u = new URL(url);
            u.searchParams.forEach((value, name) => {
                params.push({ name, value, location: 'query', type: detectParamType(value) });
            });
        } catch { /* invalid URL */ }

        // Body params (JSON or form-encoded)
        if (body) {
            try {
                const jsonBody = JSON.parse(body);
                if (typeof jsonBody === 'object' && jsonBody !== null) {
                    for (const [name, value] of Object.entries(jsonBody)) {
                        params.push({ name, value: String(value), location: 'body', type: detectParamType(String(value)) });
                    }
                }
            } catch {
                // Try form-encoded
                try {
                    const formParams = new URLSearchParams(body);
                    formParams.forEach((value, name) => {
                        params.push({ name, value, location: 'body', type: detectParamType(value) });
                    });
                } catch { /* not parseable */ }
            }
        }

        // Path params (numeric/UUID segments)
        try {
            const u = new URL(url);
            const segments = u.pathname.split('/').filter(Boolean);
            segments.forEach((seg, i) => {
                if (/^\d+$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}/i.test(seg)) {
                    params.push({
                        name: `path_segment_${i}`,
                        value: seg,
                        location: 'path',
                        type: detectParamType(seg),
                    });
                }
            });
        } catch { /* ignore */ }

        return params;
    }

    /**
     * Classify a request by its purpose.
     */
    classify(req: HarvestedRequest): RequestClass {
        const { method, path, requestBody, params, requestHeaders } = req;
        const pathLower = path.toLowerCase();
        const bodyLower = (requestBody || '').toLowerCase();

        // GraphQL
        if (pathLower.includes('graphql') || bodyLower.includes('"query"')) return 'graphql';

        // WebSocket
        if (pathLower.startsWith('/ws') || pathLower.includes('socket.io') || pathLower.includes('sockjs')) return 'websocket-bootstrap';

        // Authentication
        if (this.isAuthEndpoint(pathLower)) return 'authentication';

        // File operations
        if (this.isFileOperation(pathLower, requestHeaders)) return 'file-operation';

        // Admin paths
        if (this.isAdminPath(pathLower)) return 'admin-candidate';

        // CSRF-protected (has token in body or header)
        if (this.hasCSRFIndicator(params, requestHeaders)) return 'csrf-protected';

        // Object references (has numeric/UUID params in path or body)
        if (this.hasObjectRef(params)) return 'object-reference';

        // State-changing
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return 'state-changing';

        // Search/query
        if (this.isSearchEndpoint(pathLower, params)) return 'search-query';

        // Sensitive resources
        if (this.isSensitiveResource(pathLower)) return 'sensitive-resource';

        // Session bootstrap (initial resource loads, OPTIONS preflight)
        if (method === 'OPTIONS') return 'session-bootstrap';

        return 'unknown';
    }

    /**
     * Score a request for testing interest (0-100).
     */
    score(req: HarvestedRequest): number {
        let score = 0;

        // Method weighting
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) score += 25;
        if (req.method === 'GET' && req.params.length > 0) score += 10;

        // Parameter analysis
        for (const p of req.params) {
            if (p.type === 'numeric') score += 20;
            if (p.type === 'uuid') score += 15;
            const nameLower = p.name.toLowerCase();
            if (['id', 'user_id', 'userid', 'account_id', 'accountid', 'order_id', 'orderid',
                'role', 'admin', 'profile_id', 'invoice_id', 'tenant_id', 'org_id'].includes(nameLower)) {
                score += 25;
            }
            if (['email', 'username', 'phone'].includes(nameLower)) score += 10;
        }

        // Path semantics
        const pathLower = req.path.toLowerCase();
        if (/\/(admin|manage|internal|dashboard|panel|settings)/i.test(pathLower)) score += 25;
        if (/\/(user|account|profile|order|invoice|payment|billing)/i.test(pathLower)) score += 20;
        if (/\/(delete|remove|edit|update|modify|create)/i.test(pathLower)) score += 15;
        if (/\/(upload|file|download|export|import)/i.test(pathLower)) score += 15;

        // Classification boost
        const classBoost: Partial<Record<RequestClass, number>> = {
            'object-reference': 20,
            'state-changing': 15,
            'admin-candidate': 30,
            'csrf-protected': 10,
            'graphql': 20,
            'file-operation': 15,
            'authentication': 20,
            'sensitive-resource': 15,
            'static-asset': -100,
            'session-bootstrap': -20,
            'websocket-bootstrap': -10,
        };
        score += classBoost[req.classification] || 0;

        // Auth material present (authenticated endpoint = more critical)
        if (req.requestHeaders['authorization'] || req.requestHeaders['cookie']) score += 10;

        // Structured JSON response (more testable)
        if (req.mimeType?.includes('json')) score += 10;

        // Successful response (likely valid endpoint)
        if (req.statusCode >= 200 && req.statusCode < 300) score += 5;

        return Math.max(0, Math.min(100, score));
    }

    // ─────────────────────────────────────────────────────────
    // Classification Helpers
    // ─────────────────────────────────────────────────────────

    private isAuthEndpoint(path: string): boolean {
        return /\/(login|signin|signup|register|logout|signout|auth|oauth|token|session|verify|password|reset|forgot|activate|confirm|mfa|2fa)/i.test(path);
    }

    private isFileOperation(path: string, headers: Record<string, string>): boolean {
        const ct = headers['content-type'] || '';
        return ct.includes('multipart/form-data') ||
            /\/(upload|file|download|attachment|media|image|document|import|export)/i.test(path);
    }

    private isAdminPath(path: string): boolean {
        return /\/(admin|administration|manage|manager|panel|backoffice|internal|debug|system|monitoring)/i.test(path);
    }

    private hasCSRFIndicator(params: RequestParam[], headers: Record<string, string>): boolean {
        const csrfNames = ['csrf', '_csrf', 'csrftoken', 'csrf_token', 'xsrf', '_token', '__requestverificationtoken', 'x-csrf-token'];
        if (params.some(p => csrfNames.includes(p.name.toLowerCase()))) return true;
        if (headers['x-csrf-token'] || headers['x-xsrf-token']) return true;
        return false;
    }

    private hasObjectRef(params: RequestParam[]): boolean {
        return params.some(p =>
            p.type === 'numeric' || p.type === 'uuid' ||
            /^(id|user_id|account_id|order_id|item_id|product_id|profile_id|basket_id|bid)$/i.test(p.name)
        );
    }

    private isSearchEndpoint(path: string, params: RequestParam[]): boolean {
        if (/\/(search|find|query|filter|lookup|autocomplete|suggest)/i.test(path)) return true;
        if (params.some(p => ['q', 'query', 'search', 'keyword', 'term', 'filter', 'find'].includes(p.name.toLowerCase()))) return true;
        return false;
    }

    private isSensitiveResource(path: string): boolean {
        return /\/(user|profile|account|wallet|balance|credit|permission|role|config|env|secret)/i.test(path);
    }
}

// ─────────────────────────────────────────────────────────────
// Helpers (exported for testing)
// ─────────────────────────────────────────────────────────────

export function detectParamType(value: string): RequestParam['type'] {
    if (/^\d+$/.test(value)) return 'numeric';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid';
    if (value === 'true' || value === 'false') return 'boolean';
    try {
        const parsed = JSON.parse(value);
        if (typeof parsed === 'object') return 'json';
    } catch { /* not JSON */ }
    return 'string';
}
