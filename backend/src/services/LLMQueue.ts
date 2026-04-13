/**
 * LLM Queue - serializes LLM execution and records queue timing.
 * Timeout policy and retry policy live in the LLM runtime layer.
 * The execution watchdog is a last-resort guardrail, not ordinary provider liveness judgement.
 */

import type { GenerationMetadata, GenerationRequest, GenerationResponse } from './LLMProviderService';
import { logger } from '../utils/logger';
import { LlmExecutionError } from './llm/LlmRuntimeTypes';

export interface LlmQueueExecutionContext {
    queueWaitMs: number;
    queueDepthAtEnqueue: number;
    signal: AbortSignal;
}

export interface LlmQueueExecutionOptions {
    waitTimeoutMs?: number | null;
    executionWatchdogMs?: number | null;
    callSite?: string;
    scanId?: string;
}

interface QueuedExecution<T> {
    task: (context: LlmQueueExecutionContext) => Promise<T>;
    resolve: (value: T) => void;
    reject: (error: unknown) => void;
    enqueuedAt: number;
    queueDepthAtEnqueue: number;
    waitTimeoutMs: number | null;
    executionWatchdogMs: number | null;
    callSite?: string;
    scanId?: string;
    waitTimeoutId?: NodeJS.Timeout;
    started: boolean;
}

class LLMQueue {
    private queue: Array<QueuedExecution<unknown>> = [];
    private processing = false;
    private readonly maxConcurrent = 1;
    private readonly requestDelay = 2_000;
    private activeRequests = 0;

    public async execute<T>(
        task: (context: LlmQueueExecutionContext) => Promise<T>,
        options: LlmQueueExecutionOptions = {},
    ): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            const entry: QueuedExecution<T> = {
                task,
                resolve,
                reject,
                enqueuedAt: Date.now(),
                queueDepthAtEnqueue: this.queue.length + this.activeRequests,
                waitTimeoutMs: options.waitTimeoutMs ?? null,
                executionWatchdogMs: options.executionWatchdogMs ?? null,
                callSite: options.callSite,
                scanId: options.scanId,
                started: false,
            };

            if (entry.waitTimeoutMs && entry.waitTimeoutMs > 0) {
                entry.waitTimeoutId = setTimeout(() => {
                    if (entry.started) {
                        return;
                    }

                    const index = this.queue.indexOf(entry as QueuedExecution<unknown>);
                    if (index !== -1) {
                        this.queue.splice(index, 1);
                    }

                    reject(new LlmExecutionError({
                        failureCategory: 'queue_timeout',
                        message: `LLM queue wait exceeded ${entry.waitTimeoutMs}ms before execution started.`,
                        budgetMs: entry.waitTimeoutMs,
                        attemptPhase: 'queued',
                        livenessCategory: 'queue_timeout',
                    }));
                }, entry.waitTimeoutMs);
            }

            this.queue.push(entry as QueuedExecution<unknown>);
            void this.processQueue();
        });
    }

    public async enqueue(
        request: GenerationRequest,
        metadata: GenerationMetadata = {},
    ): Promise<GenerationResponse> {
        const { llmRuntime } = require('./llm/LlmRuntime') as typeof import('./llm/LlmRuntime');
        return llmRuntime.generate(request, {
            scanId: metadata.scanId,
            userId: metadata.userId,
            reportExportId: metadata.reportExportId,
            analysisId: metadata.analysisId,
            context: metadata.context,
            callSite: metadata.callSite || 'source_analysis',
            criticality: metadata.criticality,
            queueMode: metadata.queueMode,
        });
    }

    private async processQueue(): Promise<void> {
        if (this.processing) {
            return;
        }

        this.processing = true;

        while (this.queue.length > 0 && this.activeRequests < this.maxConcurrent) {
            const entry = this.queue.shift();
            if (!entry) {
                break;
            }

            entry.started = true;
            if (entry.waitTimeoutId) {
                clearTimeout(entry.waitTimeoutId);
            }

            this.activeRequests += 1;

            void this.runEntry(entry).finally(() => {
                this.activeRequests -= 1;
                setTimeout(() => {
                    void this.processQueue();
                }, this.requestDelay);
            });

            if (this.activeRequests >= this.maxConcurrent) {
                break;
            }
        }

        this.processing = false;
    }

    private async runEntry<T>(entry: QueuedExecution<T>): Promise<void> {
        const queueWaitMs = Date.now() - entry.enqueuedAt;
        const controller = new AbortController();
        let executionWatchdogExpired = false;
        let executionWatchdogId: NodeJS.Timeout | undefined;

        if (entry.executionWatchdogMs && entry.executionWatchdogMs > 0) {
            executionWatchdogId = setTimeout(() => {
                executionWatchdogExpired = true;
                controller.abort(new Error(`LLM execution watchdog expired after ${entry.executionWatchdogMs}ms.`));
            }, entry.executionWatchdogMs);
        }

        try {
            const result = await entry.task({
                queueWaitMs,
                queueDepthAtEnqueue: entry.queueDepthAtEnqueue,
                signal: controller.signal,
            });

            if (executionWatchdogExpired) {
                throw new LlmExecutionError({
                    failureCategory: 'watchdog_timeout',
                    message: `LLM execution watchdog expired after ${entry.executionWatchdogMs}ms.`,
                    budgetMs: entry.executionWatchdogMs,
                    attemptPhase: 'queued',
                    livenessCategory: 'watchdog_timeout',
                });
            }

            entry.resolve(result);
        } catch (error) {
            if (
                executionWatchdogExpired
                && (
                    !(error instanceof LlmExecutionError)
                    || error.failureCategory === 'canceled'
                )
            ) {
                entry.reject(new LlmExecutionError({
                    failureCategory: 'watchdog_timeout',
                    message: `LLM execution watchdog expired after ${entry.executionWatchdogMs}ms.`,
                    budgetMs: entry.executionWatchdogMs,
                    rawError: error instanceof Error ? error.message : String(error),
                    attemptPhase: 'queued',
                    livenessCategory: 'watchdog_timeout',
                    diagnostics: error instanceof LlmExecutionError ? error.diagnostics : null,
                    cause: error,
                }));
                return;
            }

            entry.reject(error);
        } finally {
            if (executionWatchdogId) {
                clearTimeout(executionWatchdogId);
            }

            logger.debug?.('llm.queue.execution.finished', {
                callSite: entry.callSite,
                scanId: entry.scanId,
                queueWaitMs,
                queueDepthAtEnqueue: entry.queueDepthAtEnqueue,
                executionWatchdogExpired,
            });
        }
    }

    public getQueueLength(): number {
        return this.queue.length;
    }

    public getActiveRequests(): number {
        return this.activeRequests;
    }
}

export const llmQueue = new LLMQueue();
