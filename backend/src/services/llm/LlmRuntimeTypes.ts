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

export type LlmFailureCategory =
    | 'provider_call_timeout'
    | 'provider_first_event_timeout'
    | 'provider_idle_timeout'
    | 'retry_budget_exhausted'
    | 'queue_wait_timeout'
    | 'queue_execution_timeout'
    | 'sdk_session_timeout'
    | 'transient_provider_error'
    | 'malformed_provider_result'
    | 'canceled_due_to_scan_state';

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
    firstEventTimeoutMs?: number | null;
    attemptTimeoutMs?: number | null;
    providerIdleTimeoutMs?: number | null;
    queueWaitTimeoutMs?: number | null;
    queueExecutionTimeoutMs?: number | null;
    signal?: AbortSignal;
}

export interface ResolvedLlmCallOptions extends LlmCallOptions {
    criticality: LlmCriticality;
    queueMode: LlmQueueMode;
    promptMetrics: LlmPromptMetrics;
    maxAttempts: number;
    retryBudgetMs: number | null;
    firstEventTimeoutMs: number | null;
    attemptTimeoutMs: number | null;
    providerIdleTimeoutMs: number | null;
    queueWaitTimeoutMs: number | null;
    queueExecutionTimeoutMs: number | null;
}

export interface LlmQueueMetrics {
    queueDepthAtEnqueue: number;
    queueWaitMs: number;
}

export interface ProviderAttemptDiagnostics {
    streamingStarted: boolean;
    anyEventReceived: boolean;
    assistantMessageReceived: boolean;
    idleReceived: boolean;
    firstEventAtMs: number | null;
    idleAtMs: number | null;
    finalContentLength: number;
    warningCategory?: LlmFailureCategory | null;
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
    assistantMessageReceived: boolean;
    idleReceived: boolean;
    firstEventAtMs: number | null;
    idleAtMs: number | null;
    warningCategory?: LlmFailureCategory | null;
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
    firstEventTimeoutMs?: number | null;
    attemptTimeoutMs?: number | null;
    providerIdleTimeoutMs?: number | null;
}

export interface LlmExecutionErrorOptions {
    failureCategory: LlmFailureCategory;
    message: string;
    budgetMs?: number | null;
    rawError?: string | null;
    retryable?: boolean;
    cause?: unknown;
}

export class LlmExecutionError extends Error {
    public readonly failureCategory: LlmFailureCategory;
    public readonly budgetMs: number | null;
    public readonly rawError: string | null;
    public readonly retryable: boolean;

    constructor(options: LlmExecutionErrorOptions) {
        super(options.message);
        this.name = 'LlmExecutionError';
        this.failureCategory = options.failureCategory;
        this.budgetMs = options.budgetMs ?? null;
        this.rawError = options.rawError ?? null;
        this.retryable = options.retryable ?? false;
        if (options.cause !== undefined) {
            (this as Error & { cause?: unknown }).cause = options.cause;
        }
    }
}

export function isLlmExecutionError(error: unknown): error is LlmExecutionError {
    return error instanceof LlmExecutionError;
}
