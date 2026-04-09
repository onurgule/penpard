/**
 * OrchestratorSingleAgentHarness
 *
 * Owns the execution lifecycle for the single-agent scan mode:
 *   - run/continue contract (prevents overlapping runs)
 *   - plan→execute→replan loop iteration
 *   - phase transitions at loop boundaries
 *   - pause polling
 *   - human command drain
 *   - iteration/budget enforcement
 *   - checkpoint scheduling at round boundaries
 *   - terminal transition (stop/fail/complete)
 *   - finalization (browser cleanup, log persistence)
 *
 * The agent (OrchestratorAgent) retains:
 *   - reasoning: prompt building, LLM calls, plan creation, tool selection
 *   - domain coordination: harvest cycles, hypothesis engine interaction
 *   - instruction analysis
 *   - finding detection and saving
 *
 * This split means the harness answers "when/whether to keep going" and
 * the agent answers "what to do next." A future multi-agent harness would
 * replace this class while the agent reasoning contract remains stable.
 */

import { OrchestratorScanState } from './OrchestratorScanState';

type RunKind = 'initial' | 'continuation';

export interface HarnessAgentContract<TContinuationOptions> {
    // ── lifecycle hooks ──
    beforeRun: (kind: RunKind) => void;
    finalizeRun: () => Promise<void>;
    handleFailure: (kind: RunKind, error: any) => void;

    // ── initialization ──
    runInit: () => Promise<void>;

    // ── continuation setup ──
    prepareContinuation: (options: TContinuationOptions) => Promise<void>;

    // ── per-round agent reasoning ──
    createPlan: () => Promise<{ kind: 'plan'; plan: any } | { kind: 'complete' } | null>;
    executeStep: (step: any, stepToolResults: string[], totalActions: number) => Promise<any>;
    shouldContinueTesting: (roundResults: any[]) => Promise<boolean>;
    processHumanCommand: (command: string) => Promise<void>;

    // ── per-round domain work ──
    runPostRoundWork: () => Promise<void>;

    // ── phase: reporting ──
    runReporting: () => Promise<void>;

    // ── phase: direct execution ──
    runDirectExecution: (instruction: string, maxRounds: number) => Promise<void>;

    // ── logging ──
    log: (channel: string, message: string) => void;

    // ── checkpoint ──
    persistCheckpoint: (reason: string) => Promise<void>;

    // ── delay ──
    delay: (ms: number) => Promise<void>;
}

interface OrchestratorSingleAgentHarnessOptions<TContinuationOptions> {
    state: OrchestratorScanState;
    agent: HarnessAgentContract<TContinuationOptions>;
}

export class OrchestratorSingleAgentHarness<TContinuationOptions> {
    private currentRunPromise: Promise<void> | null = null;
    private readonly state: OrchestratorScanState;
    private readonly agent: HarnessAgentContract<TContinuationOptions>;

    constructor(options: OrchestratorSingleAgentHarnessOptions<TContinuationOptions>) {
        this.state = options.state;
        this.agent = options.agent;
    }

    public async waitForCompletion(): Promise<void> {
        await (this.currentRunPromise ?? Promise.resolve());
    }

    public async start(): Promise<void> {
        await this.run('initial', () => this.executeInitialRun());
    }

    public async continueScan(options: TContinuationOptions): Promise<void> {
        await this.run('continuation', () => this.executeContinuationRun(options));
    }

    // ═════════════════════════════════════════════════════════════
    //  Core run wrapper — prevents overlapping runs, handles errors
    // ═════════════════════════════════════════════════════════════

    private async run(kind: RunKind, executor: () => Promise<void>): Promise<void> {
        if (this.currentRunPromise) {
            throw new Error(kind === 'continuation'
                ? 'Cannot continue while the single-agent harness is already running'
                : 'Single-agent harness is already running');
        }

        this.currentRunPromise = (async () => {
            this.agent.beforeRun(kind);

            try {
                await executor();
            } catch (error: any) {
                this.agent.handleFailure(kind, error);
            } finally {
                await this.agent.finalizeRun();
            }
        })();

        try {
            await this.currentRunPromise;
        } finally {
            this.currentRunPromise = null;
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  Initial run — init → iterative testing → reporting
    // ═════════════════════════════════════════════════════════════

    private async executeInitialRun(): Promise<void> {
        await this.agent.runInit();
        if (!this.state.isRunning || this.state.isStoppedPhase()) {
            return;
        }

        await this.runIterativeTestingLoop();
        if (!this.state.isRunning || this.state.isStoppedPhase()) {
            return;
        }

        await this.agent.runReporting();
    }

    // ═════════════════════════════════════════════════════════════
    //  Continuation run — prepare → iterative or direct → done
    // ═════════════════════════════════════════════════════════════

    private async executeContinuationRun(options: TContinuationOptions): Promise<void> {
        await this.agent.prepareContinuation(options);

        // The continuation run options may specify direct execution or planning.
        // The agent.prepareContinuation sets up state for the appropriate mode.
        // If planningEnabled, we go through the normal loop. Otherwise, direct.
        // The agent signals this through the continuation options.
        const opts = options as any;
        if (opts.planningEnabled === false) {
            await this.agent.runDirectExecution(opts.instruction, opts._resolvedMaxRounds ?? opts.iterations);
        } else {
            await this.runIterativeTestingLoop();
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  The plan → execute → replan loop — now owned by the harness
    // ═════════════════════════════════════════════════════════════

    private async runIterativeTestingLoop(): Promise<void> {
        this.state.setPhase('planning');
        this.agent.log('system', '═══ PHASE: ITERATIVE TESTING ═══');

        while (
            this.state.isRunning &&
            this.state.hasPlanRoundBudget() &&
            this.state.hasIterationBudget()
        ) {
            // ── Pause polling ──
            await this.pollPause();
            if (!this.state.isRunning) break;

            // ── PLAN ──
            this.state.incrementPlanRound();
            this.state.setPhase('planning');
            this.agent.log('system', `\n╔══════════════════════════════════════╗`);
            this.agent.log('system', this.state.maxPlanRounds > 0
                ? `║  PLANNING ROUND ${this.state.planRound}/${this.state.maxPlanRounds}              ║`
                : `║  PLANNING ROUND ${this.state.planRound} (model decides)     ║`);
            this.agent.log('system', `╚══════════════════════════════════════╝`);

            const planDecision = await this.agent.createPlan();
            if (!planDecision || planDecision.kind === 'complete') {
                this.agent.log('system', 'LLM indicates testing is complete or failed to create plan.');
                break;
            }

            const plan = planDecision.plan;
            this.state.setCurrentPlan(plan);
            this.agent.log('agent', `Plan analysis: ${plan.analysis.substring(0, 200)}...`);

            for (const step of plan.steps) {
                this.agent.log('plan', `Step ${step.step}: ${step.objective} [${step.tools.join(', ')}]`);
            }

            // ── EXECUTE ──
            this.state.setPhase('executing');
            const roundResults = await this.executeRoundSteps(plan);

            this.state.appendStepResults(roundResults);

            // ── Post-round work (harvest, delta analysis) ──
            await this.agent.runPostRoundWork();

            // ── REPLAN decision ──
            this.state.setPhase('replanning');
            this.agent.log('system', `\nRound ${this.state.planRound} complete. Findings this round: ${roundResults.reduce((sum: number, r: any) => sum + r.findings.length, 0)}`);
            this.agent.log('system', `Total findings: ${this.state.findingsCount} | Total actions: ${this.state.totalActions}/${this.state.maxIterations}`);
            await this.agent.persistCheckpoint(`planning-round-${this.state.planRound}`);

            if (!this.state.hasIterationBudget()) {
                this.agent.log('system', `Reached max iterations (${this.state.maxIterations}). Moving to reporting.`);
                break;
            }

            const shouldContinue = await this.agent.shouldContinueTesting(roundResults);
            if (!shouldContinue) {
                this.agent.log('system', 'LLM determined testing is thorough enough.');
                break;
            }
        }

        if (this.state.hasReachedMaxPlanRounds()) {
            this.agent.log('system', `Reached max plan rounds (${this.state.maxPlanRounds}).`);
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  Step execution within a plan round
    // ═════════════════════════════════════════════════════════════

    private async executeRoundSteps(plan: any): Promise<any[]> {
        const roundResults: any[] = [];

        for (let i = 0; i < plan.steps.length; i++) {
            if (!this.state.isRunning || !this.state.hasIterationBudget()) break;

            // Handle pause between steps
            await this.pollPause();
            if (!this.state.isRunning) break;

            // Drain human commands
            await this.drainHumanCommands();

            const step = plan.steps[i];
            step.status = 'executing';

            this.agent.log('system', `\n── Executing Step ${step.step}: ${step.objective} ──`);

            const stepFindings: any[] = [];
            const stepToolResults: string[] = [];

            // Each step can do up to 5 tool calls (multi-step execution)
            const maxActionsPerStep = 5;
            let stepActions = 0;

            while (stepActions < maxActionsPerStep && this.state.isRunning && this.state.hasIterationBudget()) {
                await this.agent.delay(2000); // Rate limiting between LLM calls

                try {
                    const response = await this.agent.executeStep(step, stepToolResults, this.state.totalActions);
                    this.state.incrementTotalActions();
                    stepActions++;

                    if (!response) {
                        this.agent.log('error', 'No valid response from LLM for step execution');
                        break;
                    }

                    // Process findings from agent response
                    if (response.stepFindings) {
                        stepFindings.push(...response.stepFindings);
                    }

                    // Collect tool results
                    if (response.toolResultSummary) {
                        stepToolResults.push(response.toolResultSummary);
                    }

                    // Check for step completion
                    if (response.stepComplete) {
                        break;
                    }
                } catch (e: any) {
                    this.agent.log('error', `Step execution error: ${e.message}`);
                    stepToolResults.push(`[ERROR] ${e.message}`);
                    break;
                }
            }

            step.status = 'completed';
            step.result = stepFindings.length > 0
                ? `Found ${stepFindings.length} vulnerabilities`
                : `Completed - ${stepToolResults.length} tool calls`;

            roundResults.push({ step, findings: stepFindings, toolResults: stepToolResults });
        }

        return roundResults;
    }

    // ═════════════════════════════════════════════════════════════
    //  Pause polling — harness responsibility
    // ═════════════════════════════════════════════════════════════

    private async pollPause(): Promise<void> {
        while (this.state.isPaused && this.state.isRunning) {
            // Drain commands even while paused
            await this.drainHumanCommands();
            await this.agent.delay(1000);
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  Human command drain — harness responsibility
    // ═════════════════════════════════════════════════════════════

    private async drainHumanCommands(): Promise<void> {
        while (this.state.hasHumanCommands()) {
            const cmd = this.state.shiftHumanCommand();
            if (cmd) {
                await this.agent.processHumanCommand(cmd);
            }
        }
    }
}
