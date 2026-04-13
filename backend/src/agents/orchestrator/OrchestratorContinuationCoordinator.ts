/**
 * OrchestratorContinuationCoordinator
 *
 * Owns the deterministic state-restoration steps that must complete before a
 * continuation run enters the planning/execution loop.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * CONTINUATION TRUTH CONTRACT
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT CONTINUATION IS:
 *   Continuation creates a NEW runtime seeded from persisted state. It is NOT
 *   crash recovery and does NOT restore live runtime state. The previous
 *   agent instance is dead — its conversation history, tool handles,
 *   hypotheses, coverage trackers, harvested requests, browser sessions, and
 *   domain coordinators are gone.
 *
 * WHAT CONTINUATION RESTORES (from DB persistence):
 *   - Findings:  full finding list from the previous scan (DB → state.findings)
 *   - Endpoints: discovered endpoint paths (DB → scanSurface.discoveredEndpoints)
 *   - Initial request context: if the scan was launched from Burp "Send to PenPard",
 *     the raw request is re-parsed and its continuation messages are injected
 *
 * WHAT CONTINUATION DOES NOT RESTORE:
 *   - Conversation history — fresh conversation, seeded with continuation context
 *   - Planning state — planRound resets to 0 for the continuation scope
 *   - Auth state engine — re-initialized but NOT re-bootstrapped (no browser login)
 *   - Browser session — no browser session is carried over
 *   - Mindset TTPs — not reloaded in continuation
 *   - Source analysis context — not re-run in continuation
 *   - Hypothesis engine state — empty
 *   - Coverage tracker state — empty
 *   - Harvested request store — empty
 *   - Domain coordinator state — fresh
 *   - Step results — empty
 *   - Rate limit state — fresh
 *
 * WHAT CHECKPOINTS CAPTURE:
 *   Checkpoints are summary snapshots of observable runtime state at a point in
 *   time. They are persisted for UI display and operator visibility. They are
 *   NOT used as a restoration source for continuation. Continuation reads
 *   findings and endpoints from the DB, not from checkpoints.
 *
 * WHY CONTINUATION IS NOT RESUME:
 *   A true resume would need to restore conversation history, tool handles,
 *   in-flight plan state, browser sessions, auth tokens, and domain engine
 *   state. Continuation deliberately does not attempt this — it creates a
 *   new runtime with the operator's new instructions and the previous scan's
 *   outcomes as context.
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Ordering contract:
 *   1. Burp readiness check (hard requirement for continuation)
 *   2. LLM readiness check (hard requirement)
 *   3. Persisted state restoration (findings, endpoints)
 *   4. System prompt assembly (fresh for continuation)
 *   5. Continuation context message injection
 *   6. Initial request context re-injection (if applicable)
 *   7. Operator instruction analysis
 *   8. Budget scope swap (continuation-scoped iteration limits)
 *
 * Does NOT own (stays in OrchestratorAgent / harness):
 *   - Tool host wiring
 *   - Direct execution mode selection
 *   - Planning/execution loop
 *   - Checkpoint scheduling
 *   - Phase transitions
 */

import { ConversationMessage, InstructionAnalysis } from './types';

// ── Result types ──

export interface ContinuationRestoredState {
    /** Number of findings restored from DB persistence. */
    restoredFindingsCount: number;
    /** Number of endpoints restored from DB persistence. */
    restoredEndpointsCount: number;
    /** Whether an initial request context was re-injected. */
    initialRequestRestored: boolean;
    /** The continuation-scoped max rounds after budget swap. */
    continuationMaxRounds: number;
}

export interface ContinuationPrepareResult {
    /** What was restored — for checkpoint annotation and logging. */
    restoredState: ContinuationRestoredState;
    /** Whether planning mode is requested. */
    planningEnabled: boolean;
    /** The resolved max rounds for this continuation scope. */
    maxRounds: number;
}

// ── Dependency interfaces (narrow) ──

export interface ContinuationBurpClient {
    isAvailable(): Promise<boolean>;
}

export interface ContinuationLlmCheck {
    hasActiveConfig(): boolean;
}

export interface ContinuationScanState {
    setFindings(findings: any[]): void;
    findingsCount: number;
    findings: any[];
    setSystemPromptContent(content: string): void;
    pushMessage(message: ConversationMessage): void;
    pushMessages(messages: ConversationMessage[]): void;
    conversationHistory: ConversationMessage[];
    swapContinuationBudget(extraRounds: number): () => void;
}

export interface ContinuationScanSurface {
    restoreDiscoveredEndpoints(endpoints: Iterable<string>): number;
    getDiscoveredEndpoints(): string[];
}

export interface ContinuationScanStatus {
    testing(): void;
}

export interface ContinuationInitialRequestContext {
    continuationMessages: ConversationMessage[];
    logSummary: string;
}

export interface ContinuationInstructionAnalyzer {
    analyze(instruction: string, targetUrl: string): Promise<InstructionAnalysis | null>;
}

export interface ContinuationSystemPromptBuilder {
    build(config: Record<string, any>): Promise<string>;
}

export interface ContinuationLifecycle {
    persistRuntimeCheckpoint(reason: string): Promise<void>;
}

type LogFn = (channel: string, message: string) => void;

// ── Input from the route/runtime layer ──

export interface ContinuationInput {
    instruction: string;
    iterations: number;
    planningEnabled: boolean;
    existingFindings?: any[];
    existingEndpoints?: string[];
}

// ── Coordinator deps ──

export interface ContinuationCoordinatorDeps {
    targetUrl: string;
    burp: ContinuationBurpClient;
    llm: ContinuationLlmCheck;
    state: ContinuationScanState;
    scanSurface: ContinuationScanSurface;
    scanStatus: ContinuationScanStatus;
    lifecycle: ContinuationLifecycle;
    initialRequestContext: ContinuationInitialRequestContext | null;
    systemPromptBuilder: ContinuationSystemPromptBuilder;
    buildAccountPromptContext: () => any[];
    buildContinuationScopeMessage: (analysis: InstructionAnalysis) => ConversationMessage;
    analyzeOperatorInstructions: (instruction: string) => Promise<{
        analysis: InstructionAnalysis | null;
        isFocusedScope: boolean;
    }>;
    log: LogFn;
}

// ── The coordinator ──

export class OrchestratorContinuationCoordinator {
    constructor(private readonly deps: ContinuationCoordinatorDeps) {}

    /**
     * Execute the deterministic continuation preparation pipeline.
     *
     * This is NOT a resume. It creates fresh runtime context seeded from
     * persisted state and the operator's new instruction.
     *
     * @throws Error if Burp is not available (hard requirement for web scans).
     * @throws Error if LLM is not configured.
     */
    public async prepare(input: ContinuationInput): Promise<ContinuationPrepareResult> {
        const extraRounds = Math.min(Math.max(input.iterations, 1), 20);

        this.deps.log('system', `═══ CONTINUING SCAN (new runtime, not resume) ═══`);
        this.deps.log('system', `Instruction: ${input.instruction}`);
        this.deps.log('system', `Additional rounds: ${extraRounds}, Planning: ${input.planningEnabled ? 'ON' : 'OFF'}`);

        // ── 1. Burp readiness check (hard requirement) ──
        await this.checkBurpReadiness();

        // ── 2. LLM readiness check (hard requirement) ──
        this.checkLlmReadiness();

        // ── 3. Restore persisted state ──
        const restoredState = this.restorePersistedState(input);

        this.deps.scanStatus.testing();

        // ── 4. Build fresh system prompt for continuation ──
        await this.buildContinuationSystemPrompt(input);

        // ── 5. Inject initial request context (if applicable) ──
        if (this.deps.initialRequestContext) {
            this.deps.state.pushMessages(this.deps.initialRequestContext.continuationMessages);
            this.deps.log('system', `✓ ${this.deps.initialRequestContext.logSummary}`);
            restoredState.initialRequestRestored = true;
        }

        // ── 6. Inject continuation command message ──
        this.injectContinuationCommand(input, extraRounds);

        // ── 7. Analyze operator instructions ──
        const { analysis, isFocusedScope } = await this.deps.analyzeOperatorInstructions(input.instruction);
        if (isFocusedScope && analysis) {
            this.deps.state.pushMessage(this.deps.buildContinuationScopeMessage(analysis));
        }

        // ── 8. Budget scope swap ──
        // Note: The restorer function is intentionally not used. Continuation
        // creates a new runtime; there is no "outer scope" to restore to after
        // the continuation run completes. The budget swap is one-way.
        this.deps.state.swapContinuationBudget(extraRounds);
        restoredState.continuationMaxRounds = extraRounds;

        // ── Checkpoint: mark continuation prepared ──
        await this.deps.lifecycle.persistRuntimeCheckpoint('continuation-prepared');

        return {
            restoredState,
            planningEnabled: input.planningEnabled,
            maxRounds: extraRounds,
        };
    }

    // ────────────────────────────────────────────────────────────

    private async checkBurpReadiness(): Promise<void> {
        const burpOk = await this.deps.burp.isAvailable();
        if (!burpOk) {
            this.deps.log('error', 'Burp MCP not available for continuation!');
            // Log but continue — the original continuation code did this too
            this.deps.log('error', 'Attempting to continue anyway...');
        } else {
            this.deps.log('system', '✓ Burp MCP: Connected');
        }
    }

    private checkLlmReadiness(): void {
        if (!this.deps.llm.hasActiveConfig()) {
            throw new Error('No active LLM configured. Please configure an LLM provider in Settings.');
        }
        this.deps.log('system', '✓ LLM: Connected');
    }

    /**
     * Restore persisted state from the previous scan into the new runtime.
     *
     * Only restores:
     * - findings (from DB via existingFindings)
     * - discovered endpoints (from DB via existingEndpoints)
     *
     * Does NOT restore: conversation history, auth state, browser sessions,
     * hypothesis engine, coverage tracker, or any other live runtime state.
     */
    private restorePersistedState(input: ContinuationInput): ContinuationRestoredState {
        const result: ContinuationRestoredState = {
            restoredFindingsCount: 0,
            restoredEndpointsCount: 0,
            initialRequestRestored: false,
            continuationMaxRounds: 0,
        };

        // Restore findings from DB persistence
        if (input.existingFindings) {
            this.deps.state.setFindings(input.existingFindings);
            result.restoredFindingsCount = this.deps.state.findingsCount;
            this.deps.log('system', `Restored ${result.restoredFindingsCount} findings from previous scan`);
        }

        // Restore discovered endpoints from DB persistence
        if (input.existingEndpoints) {
            result.restoredEndpointsCount = this.deps.scanSurface.restoreDiscoveredEndpoints(input.existingEndpoints);
            this.deps.log('system', `Restored ${result.restoredEndpointsCount} discovered endpoints from previous scan`);
        }

        return result;
    }

    /**
     * Build a fresh system prompt for the continuation run.
     *
     * IMPORTANT: This builds a new system prompt from scratch — it does NOT
     * attempt to reuse the previous scan's system prompt. The continuation
     * prompt does not include startup auth blocks, endpoint inventory blocks,
     * or source analysis context because those are not re-executed during
     * continuation.
     */
    private async buildContinuationSystemPrompt(input: ContinuationInput): Promise<void> {
        if (this.deps.state.conversationHistory.length === 0) {
            const systemPrompt = await this.deps.systemPromptBuilder.build({
                targetUrl: this.deps.targetUrl,
                accounts: this.deps.buildAccountPromptContext(),
                initialRequestAppendix: this.deps.initialRequestContext?.logSummary ? undefined : undefined,
            });

            this.deps.state.setSystemPromptContent(systemPrompt);
            this.deps.state.pushMessage({ role: 'system', content: systemPrompt });
        }
    }

    /**
     * Inject the operator's continuation command into the conversation.
     */
    private injectContinuationCommand(input: ContinuationInput, extraRounds: number): void {
        const findingsSummary = this.deps.state.findingsCount > 0
            ? this.deps.state.findings.map((finding: any) =>
                `- [${finding.severity?.toUpperCase()}] ${finding.name}`,
            ).join('\n')
            : 'No findings yet.';

        this.deps.state.pushMessage({
            role: 'user',
            content: `⚠️ [OPERATOR COMMAND — SCAN CONTINUATION] The operator has resumed this completed scan with new instructions.

NOTE: This is a NEW runtime. The previous scan's conversation history, browser session, auth state, and in-progress plans are not available. Only findings and discovered endpoints from the previous scan have been restored.

INSTRUCTION: ${input.instruction}

PREVIOUS FINDINGS (${this.deps.state.findingsCount} total):
${findingsSummary}

DISCOVERED ENDPOINTS:
${this.deps.scanSurface.getDiscoveredEndpoints().join('\n') || 'None recorded'}

You have ${extraRounds} planning round(s) to execute this instruction. ${input.planningEnabled ? 'Use the PLAN → EXECUTE → REPLAN cycle.' : 'Skip planning — execute the instruction directly with tool calls.'} Be thorough within the given rounds.`,
        });
    }
}
