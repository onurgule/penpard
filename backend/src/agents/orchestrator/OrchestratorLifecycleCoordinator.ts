import { llmQueue } from '../../services/LLMQueue';
import { EndpointInventorySnapshot } from '../../services/EndpointIntelligenceService';
import { ScanRuntimeCheckpoint } from '../../services/runtime/ScanRuntimeCheckpointService';
import { OrchestratorBrowserSession } from './OrchestratorBrowserSession';
import { OrchestratorContextSignals } from './OrchestratorContextSignals';
import { OrchestratorDomainCoordinator } from './OrchestratorDomainCoordinator';
import {
    OrchestratorPersistenceSeam,
    VulnerabilityRecord,
} from './OrchestratorPersistenceSeam';
import { OrchestratorScanState } from './OrchestratorScanState';
import { OrchestratorScanStatus } from './OrchestratorScanStatus';
import { OrchestratorScanSurface } from './OrchestratorScanSurface';

type RunKind = 'initial' | 'continuation';
type LogFn = (channel: string, message: string) => void;
type DelayFn = (ms: number) => Promise<void>;
type CheckpointHook = (checkpoint: ScanRuntimeCheckpoint) => void | Promise<void>;
type SaveLogsFn = () => void;

interface ReportingSummaryInput {
    targetUrl: string;
    planRound: number;
    endpointsTested: number;
    vulnerabilities: VulnerabilityRecord[];
}

interface OrchestratorLifecycleCoordinatorOptions {
    scanId: string;
    targetUrl: string;
    state: OrchestratorScanState;
    scanStatus: OrchestratorScanStatus;
    browserSession: () => Pick<OrchestratorBrowserSession, 'cleanup'>;
    scanSurface: () => Pick<
        OrchestratorScanSurface,
        'getDiscoveredEndpointCount' | 'getDiscoveredEndpointPreview' | 'getEndpointInventory'
    >;
    domainCoordinator: () => Pick<OrchestratorDomainCoordinator, 'getCheckpointSummary'>;
    contextSignals: Pick<OrchestratorContextSignals, 'resetBudgetSignals'>;
    persistence: Pick<OrchestratorPersistenceSeam, 'loadVulnerabilitiesForReporting'>;
    log: LogFn;
    delay: DelayFn;
    saveLogs: SaveLogsFn;
    checkpoint?: CheckpointHook;
    summarizeReport?: (input: ReportingSummaryInput) => Promise<string | null>;
}

export class OrchestratorLifecycleCoordinator {
    constructor(private readonly options: OrchestratorLifecycleCoordinatorOptions) {}

    public prepareRun(kind: RunKind): void {
        this.options.state.setRunning(true);
        this.options.contextSignals.resetBudgetSignals();

        if (kind === 'initial') {
            this.options.log('system', `Orchestrator Agent started for target: ${this.options.targetUrl}`);
            return;
        }

        this.options.state.setPhase('planning');
    }

    public async finalizeRun(): Promise<void> {
        this.options.state.setRunning(false);
        await this.persistRuntimeCheckpoint('run-finalizing');
        try {
            await this.options.browserSession().cleanup();
        } finally {
            this.options.saveLogs();
        }
        await this.persistRuntimeCheckpoint('run-finalized');
    }

    public handleRunFailure(kind: RunKind, error: any): void {
        if (this.options.state.isStoppedPhase()) {
            return;
        }

        this.options.state.transitionToFailed();
        const message = error?.message || String(error);
        this.options.log(
            'error',
            kind === 'continuation' ? `Continuation failed: ${message}` : `Critical Failure: ${message}`,
        );
        this.options.scanStatus.failed(message);
    }

    public handleStop(): void {
        this.options.state.transitionToStopped();
        this.options.log('system', 'Stop command received. Terminating agent...');
        this.options.scanStatus.stopped('Scan stopped by user');
        void this.options.browserSession().cleanup();
    }

    public handlePause(): boolean {
        if (!this.options.state.isRunning || this.options.state.isPaused) {
            return false;
        }

        this.options.state.setPaused(true);
        this.options.log('system', '⏸ Scan paused by user.');
        return true;
    }

    public handleResume(): boolean {
        if (!this.options.state.isPaused) {
            return false;
        }

        this.options.state.setPaused(false);
        this.options.log('system', '▶ Scan resumed by user.');
        return true;
    }

    public getRuntimeCheckpointSnapshot(reason: string): ScanRuntimeCheckpoint {
        const domainCheckpoint = this.options.domainCoordinator().getCheckpointSummary();
        const stateCheckpoint = this.options.state.getCheckpointSnapshot();
        const endpointInventory = this.options.scanSurface().getEndpointInventory();

        return {
            version: 1,
            executionMode: 'single-agent',
            reason,
            updatedAt: new Date().toISOString(),
            phase: stateCheckpoint.phase,
            isRunning: stateCheckpoint.isRunning,
            isPaused: stateCheckpoint.isPaused,
            planRound: stateCheckpoint.planRound,
            maxPlanRounds: stateCheckpoint.maxPlanRounds,
            maxIterations: stateCheckpoint.maxIterations,
            findingsCount: stateCheckpoint.findingsCount,
            discoveredEndpointsCount: this.options.scanSurface().getDiscoveredEndpointCount(),
            discoveredEndpointsPreview: this.options.scanSurface().getDiscoveredEndpointPreview(25),
            currentPlan: stateCheckpoint.currentPlan,
            harvested: domainCheckpoint.harvested,
            hypotheses: domainCheckpoint.hypotheses,
            coverage: domainCheckpoint.coverage,
            endpointInventory: this.toCheckpointInventory(endpointInventory),
        };
    }

    public async persistRuntimeCheckpoint(reason: string): Promise<void> {
        try {
            await this.options.checkpoint?.(this.getRuntimeCheckpointSnapshot(reason));
        } catch (error: any) {
            this.options.log('error', `Failed to persist runtime checkpoint (${reason}): ${error.message}`);
        }
    }

    public async runReporting(): Promise<void> {
        if (!this.options.state.isRunning || this.options.state.isStoppedPhase()) {
            return;
        }

        this.options.state.setPhase('reporting');
        this.options.scanStatus.reporting();
        this.options.log('system', '═══ PHASE: REPORTING ═══');

        const vulnerabilities = this.options.persistence.loadVulnerabilitiesForReporting(this.options.scanId);
        this.options.log('agent', `Total findings: ${vulnerabilities.length}`);

        if (vulnerabilities.length > 0) {
            try {
                const summary = await (this.options.summarizeReport || defaultSummarizeReport)({
                    targetUrl: this.options.targetUrl,
                    planRound: this.options.state.planRound,
                    endpointsTested: this.options.scanSurface().getDiscoveredEndpointCount(),
                    vulnerabilities,
                });

                if (summary) {
                    this.options.log('agent', `Executive Summary:\n${summary.substring(0, 500)}`);
                }
            } catch (error: any) {
                this.options.log('error', `Summary generation failed: ${error.message}`);
            }
        }

        await this.options.delay(1000);
        this.options.state.setPhase('completed');
        this.options.scanStatus.completed();
        this.options.log('system', '\n═══ SCAN COMPLETED ═══');
        this.options.log(
            'system',
            `Rounds: ${this.options.state.planRound} | Endpoints: ${this.options.scanSurface().getDiscoveredEndpointCount()} | Findings: ${vulnerabilities.length}`,
        );

        await this.options.browserSession().cleanup();
    }

    private toCheckpointInventory(endpointInventory: EndpointInventorySnapshot | null): ScanRuntimeCheckpoint['endpointInventory'] {
        if (!endpointInventory) {
            return null;
        }

        return {
            summary: endpointInventory.summary,
            authSurfaceCount: endpointInventory.authRelevantCount,
            endpointCount: endpointInventory.records.length,
        };
    }
}

async function defaultSummarizeReport(input: ReportingSummaryInput): Promise<string | null> {
    const vulnList = input.vulnerabilities
        .map((vulnerability) => `[${vulnerability.severity.toUpperCase()}] ${vulnerability.name}`)
        .join('\n');

    const summary = await llmQueue.enqueue({
        systemPrompt: 'You are a security report writer. Provide a concise executive summary of the penetration test findings. Include: total vulns by severity, most critical issues, and key recommendations.',
        userPrompt: `Target: ${input.targetUrl}\nPlanning rounds completed: ${input.planRound}\nEndpoints tested: ${input.endpointsTested}\n\nFindings:\n${vulnList}`,
    });

    return summary.text;
}
