export type LlmCallSite =
    | 'plan_creation'
    | 'plan_json_repair'
    | 'replan_check'
    | 'step_execution_reasoning'
    | 'instruction_analysis'
    | 'js_digging_classification'
    | 'executive_summary'
    | 'report_enrichment'
    | 'report_parser_extraction'
    | 'red_team_ttp_derivation'
    | 'scan_post_chat'
    | 'source_analysis';

export type LlmLivenessCategory =
    | 'slow_first_event'
    | 'finalization_missing'
    | 'retry_budget_exhausted'
    | 'queue_timeout'
    | 'watchdog_timeout'
    | 'canceled';

export type LlmFailureCategory =
    | 'retry_budget_exhausted'
    | 'queue_timeout'
    | 'watchdog_timeout'
    | 'transient_provider_error'
    | 'malformed_provider_result'
    | 'canceled';

export type LlmWarningCategory =
    | 'slow_first_event'
    | 'finalization_missing';

export type LlmAttemptPhase =
    | 'queued'
    | 'awaiting_first_event'
    | 'awaiting_first_progress'
    | 'streaming'
    | 'awaiting_finalization'
    | 'completed';

export type LlmCompletionSignal =
    | 'provider_response'
    | 'session_idle'
    | 'assistant_message'
    | 'final_message_silence';

export type LlmCriticality = 'critical' | 'non_critical';
export type LlmQueueMode = 'queued' | 'direct';
export type LlmRetryDecision = 'retry' | 'stop';

export interface LlmPromptMetrics {
    systemPromptChars: number;
    userPromptChars: number;
    totalPromptChars: number;
    imageCount: number;
}

export interface LlmCallOptions {
    scanId?: string;
    userId?: number;
    reportExportId?: string;
    analysisId?: string;
    context?: string;
    callSite: LlmCallSite;
    criticality?: LlmCriticality;
    queueMode?: LlmQueueMode;
    promptMetrics?: LlmPromptMetrics;
    maxAttempts?: number;
    retryBudgetMs?: number | null;
    slowFirstProgressWarningMs?: number | null;
    finalizationGraceMs?: number | null;
    queueWaitTimeoutMs?: number | null;
    executionWatchdogMs?: number | null;
    signal?: AbortSignal;
}

export interface ResolvedLlmCallOptions extends LlmCallOptions {
    criticality: LlmCriticality;
    queueMode: LlmQueueMode;
    promptMetrics: LlmPromptMetrics;
    maxAttempts: number;
    retryBudgetMs: number | null;
    slowFirstProgressWarningMs: number | null;
    finalizationGraceMs: number | null;
    queueWaitTimeoutMs: number | null;
    executionWatchdogMs: number | null;
}

export interface LlmQueueMetrics {
    queueDepthAtEnqueue: number;
    queueWaitMs: number;
}

export interface ProviderAttemptDiagnostics {
    streamingStarted: boolean;
    anyEventReceived: boolean;
    partialOutputReceived: boolean;
    assistantMessageReceived: boolean;
    idleReceived: boolean;
    finalizationReceived: boolean;
    firstEventAtMs: number | null;
    firstProgressAtMs: number | null;
    partialOutputAtMs: number | null;
    lastEventAtMs: number | null;
    lastProgressAtMs: number | null;
    idleAtMs: number | null;
    finalizationAtMs: number | null;
    finalContentLength: number;
    progressEventCount: number;
    attemptPhase: LlmAttemptPhase;
    completionSignal: LlmCompletionSignal | null;
    livenessCategory?: LlmLivenessCategory | null;
    warningCategory?: LlmWarningCategory | null;
    rawProviderError?: string | null;
}

export interface ProviderAttemptResult {
    text: string;
    usage?: {
        input_tokens: number;
        output_tokens: number;
    };
    provider: string;
    model: string;
    executionMs: number;
    promptMetrics: LlmPromptMetrics;
    diagnostics: ProviderAttemptDiagnostics;
}

export interface LlmAttemptTrace {
    attempt: number;
    executionMs: number;
    queueWaitMs: number;
    queueDepthAtEnqueue: number;
    provider: string;
    model: string;
    promptMetrics: LlmPromptMetrics;
    streamingStarted: boolean;
    anyEventReceived: boolean;
    partialOutputReceived: boolean;
    assistantMessageReceived: boolean;
    idleReceived: boolean;
    finalizationReceived: boolean;
    firstEventAtMs: number | null;
    firstProgressAtMs: number | null;
    partialOutputAtMs: number | null;
    lastEventAtMs: number | null;
    lastProgressAtMs: number | null;
    idleAtMs: number | null;
    finalizationAtMs: number | null;
    finalContentLength: number;
    progressEventCount: number;
    attemptPhase: LlmAttemptPhase;
    completionSignal: LlmCompletionSignal | null;
    livenessCategory?: LlmLivenessCategory | null;
    warningCategory?: LlmWarningCategory | null;
    failureCategory?: LlmFailureCategory | null;
    rawError?: string | null;
    retryDecision?: LlmRetryDecision;
    retryReason?: string | null;
}

export interface LlmCallTrace {
    totalMs: number;
    attemptCount: number;
    provider?: string;
    model?: string;
    promptMetrics: LlmPromptMetrics;
    queueWaitMs: number;
    queueDepthAtEnqueue: number;
    attempts: LlmAttemptTrace[];
}

export interface ProviderExecutionOptions {
    signal?: AbortSignal;
    slowFirstProgressWarningMs?: number | null;
    finalizationGraceMs?: number | null;
}

export interface LlmExecutionErrorOptions {
    failureCategory: LlmFailureCategory;
    message: string;
    budgetMs?: number | null;
    rawError?: string | null;
    retryable?: boolean;
    attemptPhase?: LlmAttemptPhase | null;
    livenessCategory?: LlmLivenessCategory | null;
    diagnostics?: Partial<ProviderAttemptDiagnostics> | null;
    cause?: unknown;
}

export class LlmExecutionError extends Error {
    public readonly failureCategory: LlmFailureCategory;
    public readonly budgetMs: number | null;
    public readonly rawError: string | null;
    public readonly retryable: boolean;
    public readonly attemptPhase: LlmAttemptPhase | null;
    public readonly livenessCategory: LlmLivenessCategory | null;
    public readonly diagnostics: Partial<ProviderAttemptDiagnostics> | null;

    constructor(options: LlmExecutionErrorOptions) {
        super(options.message);
        this.name = 'LlmExecutionError';
        this.failureCategory = options.failureCategory;
        this.budgetMs = options.budgetMs ?? null;
        this.rawError = options.rawError ?? null;
        this.retryable = options.retryable ?? false;
        this.attemptPhase = options.attemptPhase ?? null;
        this.livenessCategory = options.livenessCategory ?? null;
        this.diagnostics = options.diagnostics ?? null;
        if (options.cause !== undefined) {
            (this as Error & { cause?: unknown }).cause = options.cause;
        }
    }
}

export function isLlmExecutionError(error: unknown): error is LlmExecutionError {
    return error instanceof LlmExecutionError;
}
