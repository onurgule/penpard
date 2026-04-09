/**
 * HypothesisEngine — Vulnerability hypothesis creation, lifecycle, and confidence tracking.
 *
 * Generates explicit vulnerability hypotheses from classified requests,
 * tracks evidence from validation tests, and manages lifecycle transitions:
 * NEW → TESTING → ESCALATED → CONFIRMED / DISCARDED
 */

import { logger } from '../utils/logger';
import type { HarvestedRequest, RequestParam } from './RequestHarvester';
import type { ResponseDiff } from './ResponseDiffer';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export type VulnHypothesisType =
    | 'idor'
    | 'xss-reflected'
    | 'xss-stored'
    | 'sqli'
    | 'ssrf'
    | 'csrf-bypass'
    | 'auth-bypass'
    | 'privilege-escalation'
    | 'mass-assignment'
    | 'path-traversal'
    | 'info-disclosure'
    | 'workflow-bypass'
    | 'graphql-overreach'
    | 'hidden-admin'
    | 'tenant-crossover'
    | 'rate-limit-bypass';

export type HypothesisStatus = 'new' | 'testing' | 'escalated' | 'confirmed' | 'discarded';

export interface HypothesisEvidence {
    timestamp: Date;
    action: string;
    result: string;
    confidenceDelta: number;
}

export interface VulnHypothesis {
    id: string;
    type: VulnHypothesisType;
    targetRequestId: string;
    targetEndpoint: string;
    targetMethod: string;
    parameter: string;
    rationale: string;
    evidence: HypothesisEvidence[];
    confidence: number;             // 0-100
    status: HypothesisStatus;
    nextAction: string;
    createdAt: Date;
    updatedAt: Date;
    coverageLinks: string[];        // coverage entries exercised by this hypothesis
}

export interface MutationTemplate {
    hypothesisId: string;
    parameter: string;
    originalValue: string;
    mutatedValue: string;
    description: string;
    vulnType: VulnHypothesisType;
}

export interface HypothesisCheckpointSummary {
    total: number;
    counts: Record<HypothesisStatus, number>;
    activeHypotheses: Array<{
        id: string;
        type: VulnHypothesisType;
        targetEndpoint: string;
        targetMethod: string;
        parameter: string;
        confidence: number;
        status: HypothesisStatus;
        nextAction: string;
        evidenceCount: number;
    }>;
}

// ─────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────

export class HypothesisEngine {
    private hypotheses: Map<string, VulnHypothesis> = new Map();
    private counter: number = 0;

    /**
     * Generate hypotheses from a classified request.
     * Called when a request is promoted for active testing.
     */
    generateFromRequest(req: HarvestedRequest): VulnHypothesis[] {
        const generated: VulnHypothesis[] = [];

        // ── IDOR hypotheses for object references ──
        const objectParams = req.params.filter(p => p.type === 'numeric' || p.type === 'uuid');
        for (const p of objectParams) {
            const key = this.dedupeKey('idor', req.path, p.name);
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('idor', req, p.name,
                    `${p.type === 'numeric' ? 'Numeric' : 'UUID'} parameter '${p.name}' in ${req.method} ${req.path} may reference a user-owned object. Swapping this value could expose another user's data.`,
                    `Swap '${p.name}' value (${p.value}) to adjacent/other values and compare responses`
                ));
            }
        }

        // ── XSS hypotheses for string query params ──
        const stringQueryParams = req.params.filter(p => p.location === 'query' && p.type === 'string');
        for (const p of stringQueryParams) {
            const key = this.dedupeKey('xss-reflected', req.path, p.name);
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('xss-reflected', req, p.name,
                    `String parameter '${p.name}' in GET ${req.path} may reflect user input in the response without encoding.`,
                    `Inject XSS probe '<script>alert(1)</script>' and check if it appears unencoded in response`
                ));
            }
        }

        // ── SQLi hypotheses for query/body params ──
        const inputParams = req.params.filter(p => (p.location === 'query' || p.location === 'body') && p.type === 'string');
        for (const p of inputParams) {
            const key = this.dedupeKey('sqli', req.path, p.name);
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('sqli', req, p.name,
                    `Parameter '${p.name}' in ${req.method} ${req.path} may be used in a SQL query. Testing for error-based and boolean-based injection.`,
                    `Inject single quote (') and observe for SQL error messages or behavioral changes`
                ));
            }
        }

        // ── CSRF bypass for state-changing without token ──
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
            const hasCSRF = req.params.some(p =>
                ['csrf', '_csrf', 'csrftoken', 'csrf_token', 'xsrf', '_token'].includes(p.name.toLowerCase())
            ) || !!(req.requestHeaders['x-csrf-token'] || req.requestHeaders['x-xsrf-token']);

            if (!hasCSRF) {
                const key = this.dedupeKey('csrf-bypass', req.path, '');
                if (!this.hasDuplicate(key)) {
                    generated.push(this.create('csrf-bypass', req, '',
                        `State-changing ${req.method} ${req.path} has no visible CSRF token. The action may be vulnerable to cross-site request forgery.`,
                        `Replay request from a different origin without any CSRF token and check if it succeeds`
                    ));
                }
            }
        }

        // ── Auth bypass for admin paths ──
        if (/\/(admin|administration|manage|internal|panel|dashboard)/i.test(req.path)) {
            const key = this.dedupeKey('auth-bypass', req.path, '');
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('auth-bypass', req, '',
                    `Path ${req.path} appears to be an admin or internal endpoint. Testing if it is accessible without proper authorization.`,
                    `Replay request without auth token or with a lower-privilege user's token`
                ));
            }
        }

        // ── Mass assignment for POST/PUT with JSON body ──
        if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.mimeType?.includes('json')) {
            const bodyParams = req.params.filter(p => p.location === 'body');
            if (bodyParams.length > 0) {
                const key = this.dedupeKey('mass-assignment', req.path, '');
                if (!this.hasDuplicate(key)) {
                    generated.push(this.create('mass-assignment', req, '',
                        `${req.method} ${req.path} accepts JSON body with fields: ${bodyParams.map(p => p.name).join(', ')}. Server may accept additional fields like 'role', 'admin', or 'isAdmin'.`,
                        `Add 'role: admin' or 'isAdmin: true' field to the JSON body and observe response`
                    ));
                }
            }
        }

        // ── GraphQL overreach ──
        if (req.classification === 'graphql') {
            const key = this.dedupeKey('graphql-overreach', req.path, '');
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('graphql-overreach', req, '',
                    `GraphQL endpoint ${req.path} may expose introspection or overly permissive queries.`,
                    `Send introspection query { __schema { types { name } } } and check if schema is exposed`
                ));
            }
        }

        // ── Info disclosure for error responses ──
        if (req.statusCode >= 400 && req.statusCode < 500) {
            const key = this.dedupeKey('info-disclosure', req.path, '');
            if (!this.hasDuplicate(key)) {
                generated.push(this.create('info-disclosure', req, '',
                    `${req.method} ${req.path} returned ${req.statusCode}. Error response may contain stack traces, internal paths, or debug information.`,
                    `Examine error response body for leaked paths, software versions, or stack traces`
                ));
            }
        }

        if (generated.length > 0) {
            logger.info(`[HypothesisEngine] Generated ${generated.length} hypotheses from ${req.method} ${req.path}`);
        }

        return generated;
    }

    /**
     * Generate mutation templates for a request based on its hypotheses.
     */
    generateMutations(req: HarvestedRequest, hypotheses: VulnHypothesis[]): MutationTemplate[] {
        const mutations: MutationTemplate[] = [];

        for (const hyp of hypotheses) {
            switch (hyp.type) {
                case 'idor': {
                    const param = req.params.find(p => p.name === hyp.parameter);
                    if (param) {
                        if (param.type === 'numeric') {
                            const numVal = parseInt(param.value, 10);
                            mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: String(numVal + 1), description: 'IDOR: increment ID by 1', vulnType: 'idor' });
                            mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: String(Math.max(1, numVal - 1)), description: 'IDOR: decrement ID by 1', vulnType: 'idor' });
                            mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: '1', description: 'IDOR: try ID=1 (common first object)', vulnType: 'idor' });
                        } else if (param.type === 'uuid') {
                            // Modify last char of UUID
                            const lastChar = param.value.slice(-1);
                            const nextChar = lastChar === 'f' ? '0' : String.fromCharCode(lastChar.charCodeAt(0) + 1);
                            mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: param.value.slice(0, -1) + nextChar, description: 'IDOR: modify UUID last character', vulnType: 'idor' });
                        }
                    }
                    break;
                }

                case 'xss-reflected': {
                    const param = req.params.find(p => p.name === hyp.parameter);
                    if (param) {
                        mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: '<script>alert(1)</script>', description: 'XSS: basic script tag', vulnType: 'xss-reflected' });
                        mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: '"><img src=x onerror=alert(1)>', description: 'XSS: img tag with event handler', vulnType: 'xss-reflected' });
                    }
                    break;
                }

                case 'sqli': {
                    const param = req.params.find(p => p.name === hyp.parameter);
                    if (param) {
                        mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: param.value + "'", description: 'SQLi: append single quote', vulnType: 'sqli' });
                        mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: param.value + "' OR '1'='1", description: 'SQLi: boolean-based OR true', vulnType: 'sqli' });
                        mutations.push({ hypothesisId: hyp.id, parameter: param.name, originalValue: param.value, mutatedValue: param.value + "' AND SLEEP(5)--", description: 'SQLi: time-based blind', vulnType: 'sqli' });
                    }
                    break;
                }

                case 'csrf-bypass': {
                    // Mutation: remove any token-like fields
                    const tokenParams = req.params.filter(p => /token|csrf|xsrf/i.test(p.name));
                    for (const tp of tokenParams) {
                        mutations.push({ hypothesisId: hyp.id, parameter: tp.name, originalValue: tp.value, mutatedValue: '', description: 'CSRF: remove token', vulnType: 'csrf-bypass' });
                    }
                    if (tokenParams.length === 0) {
                        mutations.push({ hypothesisId: hyp.id, parameter: '_csrf', originalValue: '', mutatedValue: 'invalid_token', description: 'CSRF: submit with invalid token', vulnType: 'csrf-bypass' });
                    }
                    break;
                }

                case 'auth-bypass': {
                    // Mutation: remove auth header / use empty bearer
                    mutations.push({ hypothesisId: hyp.id, parameter: 'Authorization', originalValue: req.requestHeaders['authorization'] || '', mutatedValue: '', description: 'Auth bypass: remove Authorization header', vulnType: 'auth-bypass' });
                    mutations.push({ hypothesisId: hyp.id, parameter: 'Cookie', originalValue: req.requestHeaders['cookie'] || '', mutatedValue: '', description: 'Auth bypass: remove all cookies', vulnType: 'auth-bypass' });
                    break;
                }

                case 'mass-assignment': {
                    mutations.push({ hypothesisId: hyp.id, parameter: 'role', originalValue: '', mutatedValue: 'admin', description: 'Mass assignment: add role=admin', vulnType: 'mass-assignment' });
                    mutations.push({ hypothesisId: hyp.id, parameter: 'isAdmin', originalValue: '', mutatedValue: 'true', description: 'Mass assignment: add isAdmin=true', vulnType: 'mass-assignment' });
                    break;
                }

                case 'graphql-overreach': {
                    mutations.push({ hypothesisId: hyp.id, parameter: 'query', originalValue: '', mutatedValue: '{"query":"{ __schema { types { name fields { name } } } }"}', description: 'GraphQL: introspection query', vulnType: 'graphql-overreach' });
                    break;
                }

                default:
                    break;
            }
        }

        return mutations;
    }

    /**
     * Update a hypothesis with evidence from a validation test.
     */
    updateFromDiff(hypothesisId: string, mutationDesc: string, diff: ResponseDiff): void {
        const hyp = this.hypotheses.get(hypothesisId);
        if (!hyp) return;

        let confidenceDelta = 0;
        let result = '';

        if (diff.significant) {
            confidenceDelta = 25;
            result = `SIGNIFICANT: ${diff.summary}`;

            // Extra boost for keyword signals
            if (diff.keywordSignals.length > 0) {
                confidenceDelta += 15;
                result += ` | Signals: ${diff.keywordSignals.join(', ')}`;
            }
        } else {
            confidenceDelta = -10;
            result = `Not significant: ${diff.summary}`;
        }

        hyp.confidence = Math.max(0, Math.min(100, hyp.confidence + confidenceDelta));
        hyp.evidence.push({
            timestamp: new Date(),
            action: mutationDesc,
            result,
            confidenceDelta,
        });

        // Lifecycle transitions
        if (hyp.confidence >= 80) {
            hyp.status = 'confirmed';
        } else if (hyp.confidence <= 10 && hyp.evidence.length >= 2) {
            hyp.status = 'discarded';
        } else if (hyp.confidence >= 50) {
            hyp.status = 'escalated';
        } else if (hyp.status === 'new') {
            hyp.status = 'testing';
        }

        hyp.updatedAt = new Date();

        logger.info(`[HypothesisEngine] ${hyp.id} updated: confidence=${hyp.confidence}, status=${hyp.status}`);
    }

    /**
     * Get all hypotheses, optionally filtered by status.
     */
    getAll(statusFilter?: HypothesisStatus | 'all'): VulnHypothesis[] {
        const all = Array.from(this.hypotheses.values());
        if (!statusFilter || statusFilter === 'all') return all;
        return all.filter(h => h.status === statusFilter);
    }

    /**
     * Get a hypothesis by ID.
     */
    getById(id: string): VulnHypothesis | undefined {
        return this.hypotheses.get(id);
    }

    /**
     * Get summary counts by status.
     */
    getStatusCounts(): Record<HypothesisStatus, number> {
        const counts: Record<HypothesisStatus, number> = { new: 0, testing: 0, escalated: 0, confirmed: 0, discarded: 0 };
        for (const h of this.hypotheses.values()) {
            counts[h.status]++;
        }
        return counts;
    }

    /**
     * Get a text summary for the LLM planning prompt.
     */
    getSummaryForPrompt(): string {
        const counts = this.getStatusCounts();
        const total = Array.from(this.hypotheses.values()).length;
        if (total === 0) return 'No vulnerability hypotheses generated yet.';

        const active = this.getAll().filter(h => h.status !== 'discarded');
        const lines: string[] = [
            `Hypotheses: ${total} total (${counts.new} new, ${counts.testing} testing, ${counts.escalated} escalated, ${counts.confirmed} confirmed, ${counts.discarded} discarded)`,
        ];

        // Show escalated and testing hypotheses in detail
        const important = active.filter(h => h.status === 'escalated' || h.status === 'testing').slice(0, 5);
        if (important.length > 0) {
            lines.push('Active hypotheses:');
            for (const h of important) {
                lines.push(`  - [${h.status.toUpperCase()}] ${h.type}: ${h.targetMethod} ${h.targetEndpoint} param='${h.parameter}' (confidence: ${h.confidence}%)`);
                lines.push(`    Rationale: ${h.rationale.substring(0, 120)}`);
                lines.push(`    Next: ${h.nextAction}`);
            }
        }

        // Show confirmed findings
        const confirmed = this.getAll('confirmed');
        if (confirmed.length > 0) {
            lines.push(`Confirmed vulnerabilities from hypotheses:`);
            for (const h of confirmed) {
                lines.push(`  - ✅ ${h.type}: ${h.targetMethod} ${h.targetEndpoint} param='${h.parameter}' (confidence: ${h.confidence}%)`);
            }
        }

        return lines.join('\n');
    }

    getCheckpointSummary(limit: number = 10): HypothesisCheckpointSummary {
        const counts = this.getStatusCounts();
        const all = Array.from(this.hypotheses.values());
        const activeHypotheses = all
            .filter((hypothesis) => hypothesis.status !== 'discarded')
            .sort((left, right) => {
                if (right.confidence !== left.confidence) {
                    return right.confidence - left.confidence;
                }
                return right.updatedAt.getTime() - left.updatedAt.getTime();
            })
            .slice(0, limit)
            .map((hypothesis) => ({
                id: hypothesis.id,
                type: hypothesis.type,
                targetEndpoint: hypothesis.targetEndpoint,
                targetMethod: hypothesis.targetMethod,
                parameter: hypothesis.parameter,
                confidence: hypothesis.confidence,
                status: hypothesis.status,
                nextAction: hypothesis.nextAction,
                evidenceCount: hypothesis.evidence.length,
            }));

        return {
            total: all.length,
            counts,
            activeHypotheses,
        };
    }

    /**
     * Reset engine state.
     */
    clear(): void {
        this.hypotheses.clear();
        this.counter = 0;
    }

    // ─────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────

    private create(
        type: VulnHypothesisType,
        req: HarvestedRequest,
        parameter: string,
        rationale: string,
        nextAction: string
    ): VulnHypothesis {
        this.counter++;
        const id = `hyp-${String(this.counter).padStart(3, '0')}`;
        const hyp: VulnHypothesis = {
            id,
            type,
            targetRequestId: req.id,
            targetEndpoint: req.path,
            targetMethod: req.method,
            parameter,
            rationale,
            evidence: [],
            confidence: 30,     // Initial confidence: suspicious but unvalidated
            status: 'new',
            nextAction,
            createdAt: new Date(),
            updatedAt: new Date(),
            coverageLinks: [],
        };
        this.hypotheses.set(id, hyp);
        return hyp;
    }

    private dedupeKey(type: string, path: string, param: string): string {
        return `${type}:${path}:${param}`;
    }

    private hasDuplicate(key: string): boolean {
        for (const h of this.hypotheses.values()) {
            const existingKey = `${h.type}:${h.targetEndpoint}:${h.parameter}`;
            if (existingKey === key) return true;
        }
        return false;
    }
}
