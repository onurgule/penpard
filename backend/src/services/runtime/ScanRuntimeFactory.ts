import type { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import { getVulnerabilitiesByScan } from '../../db/init';
import type { AuthStartupConfig } from '../auth';
import { logger } from '../../utils/logger';
import { BurpMCPClient } from '../burp-mcp';
import { defaultAuthStartupConfig } from '../web-auth-startup-config';
import { buildFocusedScanPrompt, FocusedScanSuggestion, resolveFocusedScanTarget } from '../FocusedScanPresetCatalog';
import { ScanRuntimeCheckpointService, scanRuntimeCheckpointService } from './ScanRuntimeCheckpointService';

export interface ScanRecord {
    id: string;
    target: string;
    status: string;
    user_id: number;
    initial_request?: string | null;
    [key: string]: any;
}

export interface WebScanRuntimeConfig {
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
    executionMode: 'single-agent';
    burp: BurpMCPClient;
    agent: OrchestratorAgent;
}

export interface PreparedPoolRuntime {
    kind: 'pool';
    scanId: string;
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

        return this.createSingleAgentRuntime(scanId, targetUrl, config, burp);
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
            userId: scan.user_id,
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            parallelAgents: 1,
            customSystemPrompt: options.instruction,
            initialRequest,
            authStartup: defaultAuthStartupConfig(),
        }, burp);

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

    public async createAssistedScanRuntime(scanId: string, suggestion: FocusedScanSuggestion): Promise<PreparedAgentRuntime> {
        const burp = await this.createConnectedBurpClient(
            scanId,
            'Burp MCP connection check failed',
            'Burp MCP not available',
        );

        return this.createSingleAgentRuntime(
            scanId,
            resolveFocusedScanTarget(suggestion),
            {
                rateLimit: 5,
                useNuclei: false,
                useFfuf: false,
                idorUsers: [],
                parallelAgents: 1,
                customSystemPrompt: buildFocusedScanPrompt(suggestion),
                maxIterations: 15,
                authStartup: defaultAuthStartupConfig(),
            },
            burp,
        );
    }

    private createSingleAgentRuntime(
        scanId: string,
        targetUrl: string,
        config: WebScanRuntimeConfig,
        burp: BurpMCPClient,
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
        }, burp, {
            checkpoint: (checkpoint) => this.checkpointService.saveCheckpoint(scanId, checkpoint),
        });

        return {
            kind: 'agent',
            scanId,
            executionMode: 'single-agent',
            burp,
            agent,
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
