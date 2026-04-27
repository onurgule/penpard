/**
 * OrchestratorDomainCoordinator
 *
 * Owns the pentester-loop domain engines (RequestHarvester, HypothesisEngine,
 * CoverageTracker) and provides the tool handler implementations that operate
 * on them (harvest_traffic, get_hypotheses, get_coverage, repeater_test).
 *
 * Extracted from OrchestratorAgent to remove domain-engine coordination
 * from the agent body. The agent delegates to this coordinator instead of
 * directly micro-managing every domain-engine transition.
 */

import { RequestHarvester, HarvestedRequest } from '../../services/RequestHarvester';
import { HypothesisEngine } from '../../services/HypothesisEngine';
import { CoverageTracker } from '../../services/CoverageTracker';
import { diffResponses, ResponseSnapshot } from '../../services/ResponseDiffer';
import { normalizeSendHttpResponse } from '../../services/burp-tool-result';
import { AuthStateManager } from '../../services/auth';
import { resolveAuthIdentityId } from './OrchestratorToolPolicy';
import { ToolCall } from './types';
import { ScopedMissionPolicy } from '../../services/runtime/ScopedMissionPolicy';

interface BurpToolClient {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

type LogFn = (channel: string, message: string) => void;

export interface OrchestratorDomainCoordinatorOptions {
    scanId?: string;
    targetUrl: string;
    burp: BurpToolClient;
    authManager: AuthStateManager;
    log: LogFn;
    scopePolicy?: ScopedMissionPolicy;
    onEndpointDiscovered?: (path: string, method: string, source: string) => void;
    onCheckpoint?: (reason: string) => Promise<void>;
    onHypothesisConfirmed?: (finding: any) => void;
}

export class OrchestratorDomainCoordinator {
    public readonly harvester: RequestHarvester;
    public readonly hypothesisEngine: HypothesisEngine;
    public readonly coverageTracker: CoverageTracker;

    constructor(private readonly options: OrchestratorDomainCoordinatorOptions) {
        this.harvester = new RequestHarvester({
            allowRequest: this.options.scopePolicy
                ? (request) => this.options.scopePolicy!.evaluateHarvestedRequest(request)
                : undefined,
            onPolicyBlock: (request, reason) => {
                this.options.log('tool', `[scope] Filtered harvested request outside scoped boundary: ${request.method} ${request.path} - ${reason}`);
            },
        });
        this.hypothesisEngine = new HypothesisEngine();
        this.coverageTracker = new CoverageTracker();
    }

    // ── Harvest Cycle (called at round boundaries by the agent) ──

    public async runHarvestCycle(): Promise<void> {
        let targetHost = '';
        try {
            targetHost = new URL(this.options.targetUrl).hostname;
        } catch {
            return;
        }

        this.options.log('system', '═══ HARVEST CYCLE ═══');

        const newRequests = await this.harvester.harvest(this.options.burp, targetHost);
        if (newRequests.length === 0) {
            this.options.log('system', '  No new requests harvested');
            return;
        }

        this.options.log('system', `  Harvested ${newRequests.length} new request(s)`);

        for (const req of newRequests) {
            this.coverageTracker.addRoute(req.path, req.method, 'burp');
            this.coverageTracker.inferWorkflowFromRoute(req.path);
        }

        this.options.onEndpointDiscovered?.('', '', 'harvest-refresh');

        const promoted = this.harvester.getPromotionCandidates(5);
        if (promoted.length > 0) {
            this.options.log('system', `  Promoted ${promoted.length} request(s) for active testing:`);
            for (const p of promoted) {
                this.options.log('system', `    → ${p.reason}`);
                this.coverageTracker.markPromoted(p.request.path, p.request.method);

                const hypotheses = this.hypothesisEngine.generateFromRequest(p.request);
                for (const h of hypotheses) {
                    this.options.log('system', `    ⚡ Hypothesis ${h.id}: ${h.type} on ${h.parameter || h.targetEndpoint} (confidence: ${h.confidence}%)`);
                }
            }
        } else {
            this.options.log('system', `  No requests scored high enough for promotion`);
        }
    }

    public getHarvestConversationSummary(): string {
        const harvesterSummary = this.harvester.getSummary();
        const hypSummary = this.hypothesisEngine.getSummaryForPrompt();
        const covSummary = this.coverageTracker.getSummaryForPrompt();
        return `[SYSTEM] Harvest cycle complete:\n  Requests: ${harvesterSummary.total} total, ${harvesterSummary.promoted} promoted\n  ${hypSummary}\n  ${covSummary}`;
    }

    // ── Tool Handlers (registered in the tool registry) ──

    public async executeHarvestTraffic(): Promise<any> {
        this.options.log('tool', '📡 harvest_traffic');
        let targetHost = '';
        try {
            targetHost = new URL(this.options.targetUrl).hostname;
        } catch { /* skip */ }

        const newRequests = await this.harvester.harvest(this.options.burp, targetHost);

        for (const req of newRequests) {
            this.coverageTracker.addRoute(req.path, req.method, 'burp');
            this.coverageTracker.inferWorkflowFromRoute(req.path);
        }

        const promoted = this.harvester.getPromotionCandidates(5);
        for (const p of promoted) {
            this.coverageTracker.markPromoted(p.request.path, p.request.method);
            this.hypothesisEngine.generateFromRequest(p.request);
        }

        await this.options.onCheckpoint?.('harvest-traffic-tool');

        return {
            newRequests: newRequests.length,
            promoted: promoted.map((p) => ({
                id: p.request.id,
                method: p.request.method,
                path: p.request.path,
                score: p.request.interestScore,
                classification: p.request.classification,
                reason: p.reason,
            })),
            summary: this.harvester.getSummary(),
        };
    }

    public async executeGetHypotheses(toolCall: ToolCall<'get_hypotheses'>): Promise<any> {
        const status = toolCall.args?.status || 'all';
        this.options.log('tool', `📋 get_hypotheses (status: ${status})`);

        const hypotheses = this.hypothesisEngine.getAll(status as any);
        return {
            count: hypotheses.length,
            statusCounts: this.hypothesisEngine.getStatusCounts(),
            hypotheses: hypotheses.map((h) => ({
                id: h.id,
                type: h.type,
                target: `${h.targetMethod} ${h.targetEndpoint}`,
                parameter: h.parameter,
                confidence: h.confidence,
                status: h.status,
                rationale: h.rationale.substring(0, 150),
                nextAction: h.nextAction,
                evidenceCount: h.evidence.length,
            })),
        };
    }

    public async executeGetCoverage(): Promise<any> {
        this.options.log('tool', '📊 get_coverage');
        return this.coverageTracker.getSummary();
    }

    public async executeRepeaterTest(toolCall: ToolCall<'repeater_test'>): Promise<any> {
        const { requestId, mutations } = toolCall.args || {};
        if (!requestId) return { error: 'Missing required arg: requestId' };
        if (!mutations || !Array.isArray(mutations)) return { error: 'Missing required arg: mutations (array)' };

        const request = this.harvester.getById(requestId);
        if (!request) return { error: `Request ${requestId} not found in harvest pool. Use harvest_traffic first.` };

        this.options.log('tool', `🔬 repeater_test: ${request.method} ${request.path} (${mutations.length} mutation(s))`);

        const results: any[] = [];
        const defaultIdentityId = resolveAuthIdentityId(toolCall.args);
        const defaultPreserveExplicitAuth = toolCall.args?.preserveExplicitAuth === true;

        for (const mutation of mutations) {
            try {
                const mutatedUrl = applyUrlMutation(request.url, mutation.parameter, mutation.newValue);
                const mutatedBody = applyBodyMutation(request.requestBody, mutation.parameter, mutation.newValue);
                const mutatedHeaders = { ...request.requestHeaders };
                const mutationIdentityId = typeof mutation.identityId === 'string' && mutation.identityId.trim()
                    ? mutation.identityId.trim()
                    : defaultIdentityId;

                if (mutation.parameter === 'Authorization') {
                    if (mutation.newValue) mutatedHeaders['authorization'] = mutation.newValue;
                    else delete mutatedHeaders['authorization'];
                }
                if (mutation.parameter === 'Cookie') {
                    if (mutation.newValue) mutatedHeaders['cookie'] = mutation.newValue;
                    else delete mutatedHeaders['cookie'];
                }

                const preserveExplicitAuth = defaultPreserveExplicitAuth ||
                    mutation.parameter === 'Authorization' ||
                    mutation.parameter === 'Cookie';

                const preparedRequest = this.options.authManager.prepareRequest(
                    mutatedHeaders,
                    mutatedBody || '',
                    mutatedUrl,
                    request.method,
                    mutationIdentityId,
                    preserveExplicitAuth,
                );

                const scopeDecision = this.options.scopePolicy?.evaluateTool({
                    toolName: 'repeater_test',
                    method: request.method,
                    url: mutatedUrl,
                    useInitialRequestBaseline: false,
                });
                if (scopeDecision && !scopeDecision.allowed) {
                    results.push({
                        mutation: mutation.description,
                        parameter: mutation.parameter,
                        originalValue: mutation.originalValue,
                        newValue: mutation.newValue,
                        blocked: true,
                        reason: scopeDecision.reason || 'Mutation fell outside the scoped mission boundary.',
                    });
                    continue;
                }

                const response = await this.options.burp.callTool('send_http_request', {
                    method: request.method,
                    url: mutatedUrl,
                    headers: preparedRequest.headers,
                    body: preparedRequest.body || '',
                    use_proxy: true,
                    penpard_source: this.options.scanId
                        ? `Orchestrator/${this.options.scanId}/repeater_test`
                        : 'Orchestrator/repeater_test',
                });

                const originalSnapshot: ResponseSnapshot = {
                    statusCode: request.statusCode,
                    headers: request.responseHeaders,
                    body: request.responseBody,
                    mimeType: request.mimeType,
                };

                const normalizedResponse = normalizeSendHttpResponse(response);
                this.options.scopePolicy?.recordExecutedRequest({
                    url: mutatedUrl,
                    method: request.method,
                    statusCode: normalizedResponse.statusCode,
                    identityId: mutationIdentityId,
                    requestIntent: 'authenticated',
                    result: normalizedResponse,
                });
                const mutatedSnapshot: ResponseSnapshot = {
                    statusCode: normalizedResponse.statusCode,
                    headers: normalizedResponse.headers as Record<string, string>,
                    body: normalizedResponse.body.substring(0, 5000),
                };

                const diff = diffResponses(originalSnapshot, mutatedSnapshot);

                if (mutation.hypothesisId) {
                    this.hypothesisEngine.updateFromDiff(mutation.hypothesisId, mutation.description, diff);
                    this.harvester.linkHypothesis(requestId, mutation.hypothesisId);
                    this.coverageTracker.markVulnTested(request.path, request.method, mutation.vulnType || 'unknown', mutation.hypothesisId);

                    const hyp = this.hypothesisEngine.getById(mutation.hypothesisId);
                    if (hyp && hyp.status === 'confirmed') {
                        this.options.onHypothesisConfirmed?.({
                            name: `${hyp.type} - ${hyp.targetEndpoint}${hyp.parameter ? ` (${hyp.parameter})` : ''}`,
                            severity: hypothesisTypeToSeverity(hyp.type),
                            description: hyp.rationale,
                            evidence: hyp.evidence.map((e) => `${e.action}: ${e.result}`).join('\n'),
                            endpoint: request.url,
                            method: request.method,
                            cwe: hypothesisTypeToCWE(hyp.type),
                        });
                    }
                }

                results.push({
                    mutation: mutation.description,
                    parameter: mutation.parameter,
                    originalValue: mutation.originalValue,
                    newValue: mutation.newValue,
                    burpVisible: true,
                    requestSummary: `${request.method} ${mutatedUrl}`,
                    diff: {
                        significant: diff.significant,
                        summary: diff.summary,
                        statusChange: diff.statusCodeChanged ? `${diff.originalStatus} → ${diff.mutatedStatus}` : null,
                        keywordSignals: diff.keywordSignals,
                    },
                });
            } catch (e: any) {
                results.push({
                    mutation: mutation.description,
                    error: e.message,
                });
            }
        }

        await this.options.onCheckpoint?.('repeater-test');
        return { requestId, path: request.path, method: request.method, results };
    }

    // ── Checkpoint / State Accessors ──

    public getCheckpointSummary() {
        return {
            harvested: this.harvester.getCheckpointSummary(),
            hypotheses: (() => {
                const summary = this.hypothesisEngine.getCheckpointSummary();
                return {
                    total: summary.total,
                    counts: summary.counts,
                    activeHypotheses: summary.activeHypotheses,
                };
            })(),
            coverage: this.coverageTracker.getSummary(),
        };
    }

    public getPentesterLoopState() {
        const harvSummary = this.harvester.getSummary();
        const covSummary = this.coverageTracker.getSummary();
        return {
            harvestedRequestCount: harvSummary.total,
            promotedRequestCount: harvSummary.promoted,
            hypothesisCount: this.hypothesisEngine.getStatusCounts(),
            coverageSummary: {
                routesSeen: covSummary.routesSeen,
                exercised: covSummary.routesExercisedInBrowser,
                promoted: covSummary.requestsPromoted,
                untested: covSummary.untestedRoutes.length,
                coveragePercentage: covSummary.coveragePercentage,
            },
        };
    }
}

// ── Pure helpers (moved from OrchestratorAgent) ──

function applyUrlMutation(url: string, param: string, newValue: string): string {
    try {
        const u = new URL(url);
        if (u.searchParams.has(param)) {
            u.searchParams.set(param, newValue);
            return u.toString();
        }
        const segments = u.pathname.split('/');
        for (let i = 0; i < segments.length; i++) {
            if (param === `path_segment_${i}` || segments[i] === param) {
                segments[i] = newValue;
            }
        }
        u.pathname = segments.join('/');
        return u.toString();
    } catch {
        return url;
    }
}

function applyBodyMutation(body: string, param: string, newValue: string): string {
    if (!body) return body;
    try {
        const obj = JSON.parse(body);
        if (typeof obj === 'object' && obj !== null) {
            obj[param] = newValue;
            return JSON.stringify(obj);
        }
    } catch {
        try {
            const params = new URLSearchParams(body);
            if (params.has(param)) {
                params.set(param, newValue);
                return params.toString();
            }
        } catch { /* return original */ }
    }
    return body;
}

function hypothesisTypeToSeverity(type: string): string {
    const map: Record<string, string> = {
        'idor': 'high', 'sqli': 'critical', 'xss-reflected': 'medium', 'xss-stored': 'high',
        'auth-bypass': 'critical', 'csrf-bypass': 'medium', 'ssrf': 'high',
        'privilege-escalation': 'critical', 'mass-assignment': 'high', 'path-traversal': 'high',
        'info-disclosure': 'low', 'workflow-bypass': 'medium', 'graphql-overreach': 'medium',
        'hidden-admin': 'high', 'tenant-crossover': 'critical', 'rate-limit-bypass': 'low',
    };
    return map[type] || 'medium';
}

function hypothesisTypeToCWE(type: string): string {
    const map: Record<string, string> = {
        'idor': 'CWE-639', 'sqli': 'CWE-89', 'xss-reflected': 'CWE-79', 'xss-stored': 'CWE-79',
        'auth-bypass': 'CWE-287', 'csrf-bypass': 'CWE-352', 'ssrf': 'CWE-918',
        'privilege-escalation': 'CWE-269', 'mass-assignment': 'CWE-915', 'path-traversal': 'CWE-22',
        'info-disclosure': 'CWE-200', 'graphql-overreach': 'CWE-200', 'hidden-admin': 'CWE-862',
    };
    return map[type] || '';
}
