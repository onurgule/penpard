import type { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import { getVulnerabilitiesByScan } from '../../db/init';
import type { AuthStartupConfig } from '../auth';
import { logger } from '../../utils/logger';
import { BurpMCPClient } from '../burp-mcp';
import { defaultAuthStartupConfig } from '../web-auth-startup-config';
import { ScanRuntimeCheckpointService, scanRuntimeCheckpointService } from './ScanRuntimeCheckpointService';
import type { FocusedTestObjective, ScopeEnvelope, ScanMode, StructuredSecurityTestRequest } from './ScopedScanTypes';
import { normalizeScanMode } from './ScopedScanTypes';
import { ScopedMissionPolicy } from './ScopedMissionPolicy';
import type { OrchestratorScanStatusOverrides } from '../../agents/orchestrator/OrchestratorScanStatus';

export interface ScanRecord {
    id: string;
    target: string;
    status: string;
    user_id: number;
    scan_mode?: ScanMode | null;
    initial_request?: string | null;
    [key: string]: any;
}

export interface WebScanRuntimeConfig {
    scanMode?: ScanMode;
    userId?: number;
    rateLimit?: number;
    maxIterations?: number;
    maxPlanRounds?: number;
    useNuclei?: boolean;
    useFfuf?: boolean;
    idorUsers?: any[];
    parallelAgents?: number;
    requestedParallelAgents?: number;
    customSystemPrompt?: string;
    sessionCookies?: string;
    initialRequest?: string;
    sourcePackagePath?: string;
    sourceAnalysisMode?: string;
    authStartup?: AuthStartupConfig;
    focusedTestObjective?: FocusedTestObjective;
    scopeEnvelope?: ScopeEnvelope;
    structuredSecurityTestRequest?: StructuredSecurityTestRequest;
    scopedMissionPolicy?: ScopedMissionPolicy;
    statusOverrides?: OrchestratorScanStatusOverrides;
}

export interface ContinueCompletedScanOptions {
    instruction: string;
    iterations: number;
    planningEnabled: boolean;
}

export interface PreparedContinuationOptions extends ContinueCompletedScanOptions {
    existingFindings: any[];
    existingEndpoints: string[];
}

export interface PreparedAgentRuntime {
    kind: 'agent';
    scanId: string;
    scanMode: ScanMode;
    executionMode: 'single-agent';
    burp: BurpMCPClient;
    agent: OrchestratorAgent;
}

export interface PreparedPoolRuntime {
    kind: 'pool';
    scanId: string;
    scanMode: ScanMode;
    executionMode: 'dormant-multi-agent';
    burp: BurpMCPClient;
    pool: AgentPool;
}

export type PreparedScanRuntime = PreparedAgentRuntime | PreparedPoolRuntime;

export class ScanRuntimeFactory {
    constructor(
        private readonly checkpointService: ScanRuntimeCheckpointService = scanRuntimeCheckpointService,
    ) {}

    public async createWebRuntime(
        scanId: string,
        targetUrl: string,
        config: WebScanRuntimeConfig = {},
    ): Promise<PreparedScanRuntime> {
        const burp = await this.createConnectedBurpClient(
            scanId,
            'Burp MCP connection check failed',
            'Burp Suite is not connected. Cannot start scan without Burp MCP. Please ensure Burp Suite is running with the PenPard extension loaded (port 9876).',
        );

        const requestedParallelAgents = this.resolveRequestedParallelAgents(config);
        if (requestedParallelAgents > 1) {
            logger.warn('Parallel multi-agent web scan execution is intentionally dormant. Ignoring requested parallelAgents so auth-first startup, browser continuity, and finding evidence stay on the hardened single-agent path.', {
                scanId,
                requestedParallelAgents,
            });
        }

        return this.createSingleAgentRuntime(scanId, targetUrl, config, burp, normalizeScanMode(config.scanMode));
    }

    public async createScopedWebRuntime(
        scanId: string,
        targetUrl: string,
        config: WebScanRuntimeConfig = {},
    ): Promise<PreparedScanRuntime> {
        const burp = await this.createConnectedBurpClient(
            scanId,
            'Burp MCP connection check failed for scoped scan',
            'Burp Suite is not connected. Cannot start scoped scan without Burp MCP. Please ensure Burp Suite is running with the PenPard extension loaded (port 9876).',
        );

        return this.createSingleAgentRuntime(
            scanId,
            targetUrl,
            this.buildScopedAgentConfig(targetUrl, config),
            burp,
            'scoped',
        );
    }

    public async createContinuationRuntime(
        scan: ScanRecord,
        options: ContinueCompletedScanOptions,
    ): Promise<{ runtime: PreparedAgentRuntime; continuation: PreparedContinuationOptions }> {
        const burp = await this.createConnectedBurpClient(
            scan.id,
            'Burp MCP not available for continuation',
            'Burp Suite is not connected. Please ensure Burp is running with the PenPard extension.',
        );

        const initialRequest = (scan.initial_request && String(scan.initial_request).trim())
            ? String(scan.initial_request).trim()
            : undefined;
        const existingFindings = getVulnerabilitiesByScan(scan.id);
        const runtime = this.createSingleAgentRuntime(scan.id, scan.target, {
            scanMode: normalizeScanMode(scan.scan_mode),
            userId: scan.user_id,
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            parallelAgents: 1,
            customSystemPrompt: options.instruction,
            initialRequest,
            authStartup: defaultAuthStartupConfig(),
        }, burp, normalizeScanMode(scan.scan_mode));

        return {
            runtime,
            continuation: {
                instruction: options.instruction,
                iterations: this.resolveContinuationIterations(options.iterations),
                planningEnabled: !!options.planningEnabled,
                existingFindings,
                existingEndpoints: this.extractExistingEndpoints(existingFindings),
            },
        };
    }

    private createSingleAgentRuntime(
        scanId: string,
        targetUrl: string,
        config: WebScanRuntimeConfig,
        burp: BurpMCPClient,
        scanMode: ScanMode,
    ): PreparedAgentRuntime {
        const agent = new OrchestratorAgent(scanId, targetUrl, {
            userId: config.userId,
            rateLimit: config.rateLimit || 5,
            maxIterations: config.maxIterations,
            maxPlanRounds: config.maxPlanRounds,
            useNuclei: config.useNuclei || false,
            useFfuf: config.useFfuf || false,
            idorUsers: config.idorUsers || [],
            parallelAgents: 1,
            sessionCookies: config.sessionCookies,
            initialRequest: config.initialRequest,
            sourcePackagePath: config.sourcePackagePath,
            sourceAnalysisMode: config.sourceAnalysisMode,
            authStartup: config.authStartup || defaultAuthStartupConfig(),
            customSystemPrompt: config.customSystemPrompt,
            scopedMissionPolicy: config.scopedMissionPolicy,
            statusOverrides: config.statusOverrides,
        }, burp, {
            checkpoint: (checkpoint) => this.checkpointService.saveCheckpoint(scanId, checkpoint),
        });

        return {
            kind: 'agent',
            scanId,
            scanMode,
            executionMode: 'single-agent',
            burp,
            agent,
        };
    }

    private buildScopedAgentConfig(
        targetUrl: string,
        config: WebScanRuntimeConfig,
    ): WebScanRuntimeConfig {
        const scopedRequest = config.structuredSecurityTestRequest;
        const scopePolicy = config.scopedMissionPolicy
            || (config.focusedTestObjective && config.scopeEnvelope && scopedRequest
                ? new ScopedMissionPolicy({
                    objective: config.focusedTestObjective,
                    envelope: config.scopeEnvelope,
                    request: scopedRequest,
                    targetUrl,
                })
                : undefined);

        const scopedMissionPrompt = config.focusedTestObjective && config.scopeEnvelope && scopedRequest
            ? buildScopedMissionPrompt({
                targetUrl,
                objective: config.focusedTestObjective,
                envelope: config.scopeEnvelope,
                request: scopedRequest,
            })
            : undefined;
        const customSystemPrompt = [scopedMissionPrompt, config.customSystemPrompt]
            .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
            .join('\n\n');

        return {
            ...config,
            scanMode: 'scoped',
            customSystemPrompt: customSystemPrompt || undefined,
            scopedMissionPolicy: scopePolicy,
            statusOverrides: {
                planning: 'scoped_executing',
                testing: 'scoped_executing',
                reporting: 'scoped_executing',
                completed: 'scoped_executed',
                ...(config.statusOverrides || {}),
            },
        };
    }

    private resolveRequestedParallelAgents(config: WebScanRuntimeConfig): number {
        return Math.max(
            1,
            Number(config.requestedParallelAgents ?? config.parallelAgents) || 1,
        );
    }

    private resolveContinuationIterations(iterations: number): number {
        return Math.min(Math.max(Number(iterations), 1), 20);
    }

    private extractExistingEndpoints(findings: any[]): string[] {
        const endpoints = new Set<string>();

        for (const finding of findings) {
            if (!finding.request) {
                continue;
            }

            const urlMatch = finding.request.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(https?:\/\/[^\s]+)/i);
            if (urlMatch) {
                endpoints.add(urlMatch[1]);
            }
        }

        return [...endpoints];
    }

    private async createConnectedBurpClient(
        scanId: string,
        unavailableWarning: string,
        unavailableMessage: string,
    ): Promise<BurpMCPClient> {
        const burp = new BurpMCPClient();
        let mcpAvailable = false;

        try {
            mcpAvailable = await burp.isAvailable();
        } catch {
            logger.warn(unavailableWarning, { scanId });
        }

        if (!mcpAvailable) {
            burp.disconnect();
            throw new Error(unavailableMessage);
        }

        return burp;
    }
}

export const scanRuntimeFactory = new ScanRuntimeFactory();

function buildScopedMissionPrompt(input: {
    targetUrl: string;
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
    request: StructuredSecurityTestRequest;
}): string {
    const allowedRoutes = input.envelope.allowedRoutes.length > 0
        ? input.envelope.allowedRoutes.join(', ')
        : 'discovered feature anchors only';
    const boundaryHints = input.envelope.boundaryHints.length > 0
        ? input.envelope.boundaryHints.join(' | ')
        : 'Stay within the requested feature area only.';
    const outOfScope = input.envelope.outOfScopeNotes.length > 0
        ? input.envelope.outOfScopeNotes.join(' | ')
        : 'Do not broaden to unrelated routes, endpoints, or origin changes.';
    const authHints = input.request.authMechanismHints.length > 0
        ? input.request.authMechanismHints.join(', ')
        : 'Use the current authenticated context when present.';
    const contextLines = [
        input.request.environment ? `Environment: ${input.request.environment}` : null,
        input.request.serviceName ? `Service: ${input.request.serviceName}` : null,
        input.request.testData.length > 0 ? `Test data: ${input.request.testData.join(', ')}` : null,
        input.request.testUsers.length > 0 ? `Named users: ${input.request.testUsers.join(', ')}` : null,
        input.request.operatorNotes ? `Operator notes: ${input.request.operatorNotes}` : null,
    ].filter((entry): entry is string => !!entry);

    return [
        'SCOPED EXPLORATORY MISSION',
        'Operate with the same live request-driven style as exploratory mode, but stay strictly inside the scoped battlefield below.',
        `Mission title: ${input.objective.title}`,
        `Start URL: ${input.request.targetUrl || input.targetUrl}`,
        `Mission goal: ${input.objective.goal || input.request.description}`,
        `Requested feature description: ${input.request.description}`,
        `Allowed hosts: ${input.envelope.allowedHosts.join(', ') || new URL(input.targetUrl).host}`,
        `Allowed routes: ${allowedRoutes}`,
        `Boundary hints: ${boundaryHints}`,
        `Out of scope: ${outOfScope}`,
        `Authentication guidance: ${authHints}`,
        contextLines.length > 0 ? `Mission context:\n- ${contextLines.join('\n- ')}` : null,
        'Execution rules:',
        '- Start working immediately after anchors are ready. Do not wait for manual case approval.',
        '- Use live request-driven reasoning: observe traffic, mutate meaningful in-scope inputs, compare responses, and follow suspicious signals.',
        '- Keep the request rail first-class when request-backed evidence exists. Correlate live actions with visible requests and responses.',
        '- You may be aggressive inside the allowed hosts/routes, but you must not broaden the battlefield.',
        '- Do not spider broadly, enumerate unrelated endpoints, or pivot to other origins.',
        '- If a possible next action would leave scope, explain the boundary reason and choose a different in-scope next step.',
        '- Emit findings as they strengthen or weaken during execution; do not wait until the end to acknowledge them.',
        '- Summaries should stay readable: observation, action, response change, finding update, and stop reason.',
    ].filter((entry): entry is string => !!entry).join('\n');
}
