/**
 * OrchestratorScanState
 *
 * Owns the mutable per-scan execution state that was previously scattered
 * across instance fields on OrchestratorAgent. Provides explicit accessors
 * and transition methods so ownership is visible to both the harness
 * (execution lifecycle) and the agent (reasoning decisions).
 *
 * This container is intentionally NOT a generic state bag. It captures:
 *   - phase machine (planning → executing → replanning → reporting → terminal)
 *   - running/paused flags
 *   - conversation history
 *   - plan round tracking
 *   - iteration budget tracking
 *   - findings accumulator
 *   - step results accumulator
 *   - human command queue
 *   - current plan reference
 *   - rate-limit pause tracking
 *
 * Design rules:
 *   - state transitions happen through named methods, not raw assignment
 *   - the harness reads lifecycle-relevant state (phase, isRunning, isPaused)
 *   - the agent reads/writes reasoning-relevant state (conversation, findings, plan)
 *   - checkpoint snapshot reads from this container
 *   - future multi-agent extension can create one state per agent instance
 */

import {
    AgentPhase,
    AttackPlan,
    ConversationMessage,
    StepExecutionResult,
} from './types';

export interface OrchestratorScanStateInit {
    maxIterations: number;
    maxPlanRounds: number;
}

export class OrchestratorScanState {
    // ── Lifecycle flags ──
    private _isRunning: boolean = false;
    private _isPaused: boolean = false;
    private _phase: AgentPhase = 'planning';

    // ── Iteration budget ──
    private _totalActions: number = 0;
    private _maxIterations: number;
    private _maxPlanRounds: number;

    // ── Planning state ──
    private _planRound: number = 0;
    private _currentPlan: AttackPlan | null = null;
    private _stepResults: StepExecutionResult[] = [];

    // ── Conversation ──
    private _conversationHistory: ConversationMessage[] = [];
    private _systemPromptContent: string = '';

    // ── Findings ──
    private _findings: any[] = [];

    // ── Human command queue ──
    private _humanCommandQueue: string[] = [];

    // ── Rate limit ──
    private _rateLimitPauseUntil: Date | null = null;
    private readonly RATE_LIMIT_PAUSE_MS = 1 * 60 * 1000;

    constructor(init: OrchestratorScanStateInit) {
        this._maxIterations = init.maxIterations;
        this._maxPlanRounds = init.maxPlanRounds;
    }

    // ═════════════════════════════════════════════════════════════
    //  Lifecycle accessors — consumed by harness and agent
    // ═════════════════════════════════════════════════════════════

    get isRunning(): boolean { return this._isRunning; }
    get isPaused(): boolean { return this._isPaused; }
    get phase(): AgentPhase { return this._phase; }

    public setRunning(value: boolean): void {
        this._isRunning = value;
    }

    public setPaused(value: boolean): void {
        this._isPaused = value;
    }

    public setPhase(phase: AgentPhase): void {
        this._phase = phase;
    }

    public isStoppedPhase(): boolean {
        return this._phase === 'stopped';
    }

    public isTerminalPhase(): boolean {
        return this._phase === 'completed' || this._phase === 'failed' || this._phase === 'stopped';
    }

    /**
     * Transition to the stopped state. Clears paused flag.
     */
    public transitionToStopped(): void {
        this._isRunning = false;
        this._isPaused = false;
        this._phase = 'stopped';
    }

    /**
     * Transition to the failed state.
     */
    public transitionToFailed(): void {
        this._phase = 'failed';
    }

    // ═════════════════════════════════════════════════════════════
    //  Iteration budget — consumed by harness for loop control
    // ═════════════════════════════════════════════════════════════

    get totalActions(): number { return this._totalActions; }
    get maxIterations(): number { return this._maxIterations; }
    get maxPlanRounds(): number { return this._maxPlanRounds; }
    get planRound(): number { return this._planRound; }

    public incrementTotalActions(): number {
        return ++this._totalActions;
    }

    public resetTotalActions(): void {
        this._totalActions = 0;
    }

    public incrementPlanRound(): number {
        return ++this._planRound;
    }

    public setPlanRound(value: number): void {
        this._planRound = value;
    }

    public setMaxPlanRounds(value: number): void {
        this._maxPlanRounds = value;
    }

    public setMaxIterations(value: number): void {
        this._maxIterations = value;
    }

    public hasIterationBudget(): boolean {
        return this._totalActions < this._maxIterations;
    }

    public hasPlanRoundBudget(): boolean {
        return this._maxPlanRounds === 0 || this._planRound < this._maxPlanRounds;
    }

    public hasReachedMaxPlanRounds(): boolean {
        return this._maxPlanRounds > 0 && this._planRound >= this._maxPlanRounds;
    }

    // ═════════════════════════════════════════════════════════════
    //  Planning state — consumed by agent for reasoning decisions
    // ═════════════════════════════════════════════════════════════

    get currentPlan(): AttackPlan | null { return this._currentPlan; }

    public setCurrentPlan(plan: AttackPlan | null): void {
        this._currentPlan = plan;
    }

    get stepResults(): StepExecutionResult[] { return this._stepResults; }

    public appendStepResults(results: StepExecutionResult[]): void {
        this._stepResults = [...this._stepResults, ...results];
    }

    // ═════════════════════════════════════════════════════════════
    //  Conversation — consumed by agent for LLM interaction
    // ═════════════════════════════════════════════════════════════

    get conversationHistory(): ConversationMessage[] { return this._conversationHistory; }
    get systemPromptContent(): string { return this._systemPromptContent; }

    public setSystemPromptContent(content: string): void {
        this._systemPromptContent = content;
    }

    public pushMessage(message: ConversationMessage): void {
        this._conversationHistory.push(message);
    }

    public pushMessages(messages: ConversationMessage[]): void {
        this._conversationHistory.push(...messages);
    }

    // ═════════════════════════════════════════════════════════════
    //  Findings — consumed by agent and exposed to harness
    // ═════════════════════════════════════════════════════════════

    get findings(): any[] { return this._findings; }
    get findingsCount(): number { return this._findings.length; }

    public pushFinding(finding: any): void {
        this._findings.push(finding);
    }

    public setFindings(findings: any[]): void {
        this._findings = findings;
    }

    // ═════════════════════════════════════════════════════════════
    //  Human command queue
    // ═════════════════════════════════════════════════════════════

    get humanCommandQueue(): string[] { return this._humanCommandQueue; }

    public pushHumanCommand(command: string): void {
        this._humanCommandQueue.push(command);
    }

    public shiftHumanCommand(): string | undefined {
        return this._humanCommandQueue.shift();
    }

    public hasHumanCommands(): boolean {
        return this._humanCommandQueue.length > 0;
    }

    // ═════════════════════════════════════════════════════════════
    //  Rate limit pause tracking
    // ═════════════════════════════════════════════════════════════

    get rateLimitPauseUntil(): Date | null { return this._rateLimitPauseUntil; }

    public setRateLimitPauseUntil(until: Date | null): void {
        this._rateLimitPauseUntil = until;
    }

    public isRateLimited(): boolean {
        return this._rateLimitPauseUntil !== null && new Date() < this._rateLimitPauseUntil;
    }

    public getRateLimitWaitMs(): number {
        if (!this._rateLimitPauseUntil) return 0;
        return Math.max(0, this._rateLimitPauseUntil.getTime() - Date.now());
    }

    public clearRateLimitPause(): void {
        this._rateLimitPauseUntil = null;
    }

    public applyRateLimitPause(): void {
        this._rateLimitPauseUntil = new Date(Date.now() + this.RATE_LIMIT_PAUSE_MS);
    }

    // ═════════════════════════════════════════════════════════════
    //  Snapshot for checkpoint / getState
    // ═════════════════════════════════════════════════════════════

    public getStateSnapshot() {
        return {
            phase: this._phase,
            isRunning: this._isRunning,
            isPaused: this._isPaused,
            findingsCount: this._findings.length,
            planRound: this._planRound,
            currentPlan: this._currentPlan,
        };
    }

    public getCheckpointSnapshot() {
        return {
            phase: this._phase,
            isRunning: this._isRunning,
            isPaused: this._isPaused,
            planRound: this._planRound,
            maxPlanRounds: this._maxPlanRounds,
            maxIterations: this._maxIterations,
            findingsCount: this._findings.length,
            currentPlan: this._currentPlan ? {
                round: this._currentPlan.round,
                steps: this._currentPlan.steps.map((step) => ({
                    step: step.step,
                    objective: step.objective,
                    status: step.status,
                    tools: [...step.tools],
                })),
            } : null,
        };
    }

    /**
     * Save and replace continuation-scoped budget. Returns a restorer function.
     */
    public swapContinuationBudget(extraRounds: number): () => void {
        const savedRound = this._planRound;
        const savedMaxPlanRounds = this._maxPlanRounds;
        const savedMaxIterations = this._maxIterations;

        this._planRound = 0;
        this._maxPlanRounds = extraRounds;
        this._maxIterations = extraRounds * 10;

        return () => {
            const completedRounds = this._planRound;
            this._planRound = savedRound + completedRounds;
            this._maxPlanRounds = savedMaxPlanRounds;
            this._maxIterations = savedMaxIterations;
        };
    }
}
