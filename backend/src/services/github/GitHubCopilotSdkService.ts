import { CopilotClient, approveAll, type ModelInfo } from '@github/copilot-sdk';
import { logger } from '../../utils/logger';
import type { ProviderAttemptDiagnostics, ProviderExecutionOptions } from '../llm/LlmRuntimeTypes';
import { LlmExecutionError } from '../llm/LlmRuntimeTypes';
import type { GitHubCopilotModel } from './types';

export interface CopilotPromptImage {
    data: string;
    mimeType: string;
}

export interface CopilotPromptRequest {
    systemPrompt: string;
    userPrompt: string;
    images?: CopilotPromptImage[];
}

export interface CopilotPromptResponse {
    text: string;
    usage?: {
        input_tokens: number;
        output_tokens: number;
    };
    diagnostics?: Partial<ProviderAttemptDiagnostics>;
}

export interface CopilotSessionLike {
    send(options: {
        prompt: string;
        attachments?: Array<{ type: 'blob'; data: string; mimeType: string; displayName?: string }>;
    }): Promise<unknown>;
    disconnect(): Promise<void>;
    on?(eventName: string, listener: (payload?: any) => void): void;
    off?(eventName: string, listener: (payload?: any) => void): void;
    addListener?(eventName: string, listener: (payload?: any) => void): void;
    removeListener?(eventName: string, listener: (payload?: any) => void): void;
}

export interface GitHubCopilotClientLike {
    start(): Promise<void>;
    stop(): Promise<unknown>;
    listModels(): Promise<ModelInfo[]>;
    getAuthStatus(): Promise<{
        isAuthenticated: boolean;
        login?: string;
        authType?: string;
        statusMessage?: string;
    }>;
    createSession(config: {
        clientName?: string;
        model?: string;
        workingDirectory?: string;
        enableConfigDiscovery?: boolean;
        availableTools?: string[];
        infiniteSessions?: { enabled: boolean };
        systemMessage?: { mode: 'replace'; content: string };
        streaming?: boolean;
        onEvent?: (event: { type?: string; data?: any; id?: string }) => void;
        onPermissionRequest: typeof approveAll;
    }): Promise<CopilotSessionLike>;
}

export class GitHubCopilotAuthError extends Error {
    readonly status = 401;
    readonly isGitHubAuthFailure = true;

    constructor(message: string) {
        super(message);
        this.name = 'GitHubCopilotAuthError';
    }
}

type CopilotClientFactory = (accessToken: string) => GitHubCopilotClientLike;

function normalizeAuthError(message: string): GitHubCopilotAuthError {
    return new GitHubCopilotAuthError(message || 'GitHub Copilot authentication failed.');
}

function normalizeString(value: unknown): string {
    if (typeof value === 'string') {
        return value;
    }
    if (value === undefined || value === null) {
        return '';
    }
    return String(value);
}

function extractTextContent(payload: any): string {
    if (!payload) {
        return '';
    }

    if (typeof payload === 'string') {
        return payload;
    }

    if (Array.isArray(payload)) {
        return payload.map((item) => extractTextContent(item)).join('');
    }

    if (typeof payload.content === 'string') {
        return payload.content;
    }

    if (Array.isArray(payload.content)) {
        return payload.content.map((item: any) => extractTextContent(item)).join('');
    }

    if (typeof payload.text === 'string') {
        return payload.text;
    }

    if (typeof payload.delta === 'string') {
        return payload.delta;
    }

    if (payload.data) {
        return extractTextContent(payload.data);
    }

    if (Array.isArray(payload.parts)) {
        return payload.parts.map((item: any) => extractTextContent(item)).join('');
    }

    return '';
}

function subscribe(
    session: CopilotSessionLike,
    eventName: string,
    listener: (payload?: any) => void,
): () => void {
    if (typeof session.on === 'function') {
        session.on(eventName, listener);
        return () => session.off?.(eventName, listener);
    }

    if (typeof session.addListener === 'function') {
        session.addListener(eventName, listener);
        return () => session.removeListener?.(eventName, listener);
    }

    return () => {};
}

function createEmptyDiagnostics(): ProviderAttemptDiagnostics {
    return {
        streamingStarted: false,
        anyEventReceived: false,
        partialOutputReceived: false,
        assistantMessageReceived: false,
        idleReceived: false,
        finalizationReceived: false,
        firstEventAtMs: null,
        firstProgressAtMs: null,
        partialOutputAtMs: null,
        lastEventAtMs: null,
        lastProgressAtMs: null,
        idleAtMs: null,
        finalizationAtMs: null,
        finalContentLength: 0,
        progressEventCount: 0,
        attemptPhase: 'awaiting_first_event',
        completionSignal: null,
        livenessCategory: null,
        warningCategory: null,
        rawProviderError: null,
    };
}

function snapshotDiagnostics(diagnostics: ProviderAttemptDiagnostics): Partial<ProviderAttemptDiagnostics> {
    return {
        ...diagnostics,
    };
}

function buildSdkSessionError(message: string, diagnostics: ProviderAttemptDiagnostics): LlmExecutionError {
    return new LlmExecutionError({
        failureCategory: 'transient_provider_error',
        message,
        rawError: message,
        retryable: true,
        attemptPhase: diagnostics.attemptPhase,
        diagnostics: snapshotDiagnostics({
            ...diagnostics,
            rawProviderError: message,
        }),
    });
}

export class GitHubCopilotSdkService {
    constructor(
        private readonly createClient: CopilotClientFactory = (accessToken) => new CopilotClient({
            githubToken: accessToken,
            useLoggedInUser: false,
            cwd: process.cwd(),
            logLevel: 'error',
        }),
    ) {}

    private normalizeSdkError(error: unknown): Error {
        if (error instanceof LlmExecutionError) {
            return error;
        }

        const message = error instanceof Error ? error.message : String(error || 'GitHub Copilot SDK request failed.');
        const lowerMessage = message.toLowerCase();

        if (
            lowerMessage.includes('unauthorized')
            || lowerMessage.includes('authentication failed')
            || lowerMessage.includes('invalid token')
            || lowerMessage.includes('forbidden')
        ) {
            return normalizeAuthError(message);
        }

        if (lowerMessage.includes('node') && lowerMessage.includes('20')) {
            return new Error('GitHub Copilot SDK requires a Node.js 20+ runtime.');
        }

        return new Error(message);
    }

    private normalizeModel(model: ModelInfo): GitHubCopilotModel {
        return {
            id: model.id,
            name: model.name,
            isAvailable: model.policy?.state === 'enabled',
            policyState: model.policy?.state,
            billingMultiplier: model.billing?.multiplier,
            supportsVision: model.capabilities.supports.vision,
            supportsReasoningEffort: model.capabilities.supports.reasoningEffort,
            supportedReasoningEfforts: model.supportedReasoningEfforts || [],
            defaultReasoningEffort: model.defaultReasoningEffort,
            maxContextWindowTokens: model.capabilities.limits.max_context_window_tokens,
            maxPromptTokens: model.capabilities.limits.max_prompt_tokens,
            maxPromptImages: model.capabilities.limits.vision?.max_prompt_images,
            supportedImageMimeTypes: model.capabilities.limits.vision?.supported_media_types || [],
        };
    }

    private async withClient<T>(accessToken: string, action: (client: GitHubCopilotClientLike) => Promise<T>): Promise<T> {
        const client = this.createClient(accessToken);

        try {
            await client.start();
            return await action(client);
        } catch (error) {
            throw this.normalizeSdkError(error);
        } finally {
            try {
                await client.stop();
            } catch (stopError) {
                logger.warn('GitHub Copilot SDK client stop reported an error', {
                    error: stopError instanceof Error ? stopError.message : String(stopError),
                });
            }
        }
    }

    async listModels(accessToken: string): Promise<GitHubCopilotModel[]> {
        return this.withClient(accessToken, async (client) => {
            const models = await client.listModels();

            return models
                .map((model) => this.normalizeModel(model))
                .sort((left, right) => {
                    if (left.isAvailable !== right.isAvailable) {
                        return left.isAvailable ? -1 : 1;
                    }
                    return left.name.localeCompare(right.name);
                });
        });
    }

    async getAuthStatus(accessToken: string): Promise<{
        isAuthenticated: boolean;
        login?: string;
        authType?: string;
        statusMessage?: string;
    }> {
        return this.withClient(accessToken, async (client) => client.getAuthStatus());
    }

    async generate(
        accessToken: string,
        model: string,
        request: CopilotPromptRequest,
        executionOptions: ProviderExecutionOptions = {},
    ): Promise<CopilotPromptResponse> {
        return this.withClient(accessToken, async (client) => {
            const startedAtMs = Date.now();
            const diagnostics = createEmptyDiagnostics();
            const slowFirstProgressWarningMs = executionOptions.slowFirstProgressWarningMs === undefined
                ? 20_000
                : executionOptions.slowFirstProgressWarningMs;
            const finalizationGraceMs = executionOptions.finalizationGraceMs === undefined
                ? 15_000
                : executionOptions.finalizationGraceMs;
            let settled = false;
            let deltaText = '';
            let finalMessage = '';
            let slowFirstProgressTimer: NodeJS.Timeout | undefined;
            let finalizationTimer: NodeJS.Timeout | undefined;
            let abortCleanup = () => {};
            const unsubs: Array<() => void> = [];
            let pendingReject: ((reason?: unknown) => void) | null = null;

            const elapsedMs = () => Date.now() - startedAtMs;
            const currentText = () => (finalMessage || deltaText).trim();
            const refreshContentMetrics = () => {
                diagnostics.finalContentLength = currentText().length;
            };
            const setPhase = (phase: ProviderAttemptDiagnostics['attemptPhase']) => {
                diagnostics.attemptPhase = phase;
            };
            const clearTimers = () => {
                if (slowFirstProgressTimer) {
                    clearTimeout(slowFirstProgressTimer);
                }
                if (finalizationTimer) {
                    clearTimeout(finalizationTimer);
                }
            };
            const cleanup = async () => {
                clearTimers();
                abortCleanup();
                for (const unsub of unsubs) {
                    unsub();
                }
                await session.disconnect();
            };
            const attachDiagnostics = (error: LlmExecutionError): LlmExecutionError => new LlmExecutionError({
                failureCategory: error.failureCategory,
                message: error.message,
                budgetMs: error.budgetMs,
                rawError: error.rawError,
                retryable: error.retryable,
                attemptPhase: error.attemptPhase ?? diagnostics.attemptPhase,
                diagnostics: error.diagnostics ?? snapshotDiagnostics(diagnostics),
                livenessCategory: error.livenessCategory ?? diagnostics.livenessCategory ?? null,
                cause: (error as Error & { cause?: unknown }).cause,
            });

            const session = await client.createSession({
                clientName: 'PenPard',
                model,
                workingDirectory: process.cwd(),
                enableConfigDiscovery: false,
                availableTools: [],
                infiniteSessions: { enabled: false },
                streaming: true,
                systemMessage: {
                    mode: 'replace',
                    content: request.systemPrompt,
                },
                onEvent: (event) => {
                    if (!event?.type) {
                        return;
                    }

                    if (
                        event.type === 'assistant.message_delta'
                        || event.type === 'assistant.message'
                        || event.type === 'session.idle'
                        || event.type === 'session.error'
                    ) {
                        return;
                    }

                    diagnostics.anyEventReceived = true;
                    diagnostics.lastEventAtMs = elapsedMs();
                    if (diagnostics.firstEventAtMs === null) {
                        diagnostics.firstEventAtMs = diagnostics.lastEventAtMs;
                    }
                    if (diagnostics.attemptPhase === 'awaiting_first_event') {
                        setPhase('awaiting_first_progress');
                    }
                },
                onPermissionRequest: approveAll,
            });

            const recordProviderEvent = (phaseAfterEvent?: ProviderAttemptDiagnostics['attemptPhase']) => {
                diagnostics.anyEventReceived = true;
                diagnostics.lastEventAtMs = elapsedMs();
                if (diagnostics.firstEventAtMs === null) {
                    diagnostics.firstEventAtMs = diagnostics.lastEventAtMs;
                }
                if (phaseAfterEvent) {
                    setPhase(phaseAfterEvent);
                } else if (diagnostics.attemptPhase === 'awaiting_first_event') {
                    setPhase('awaiting_first_progress');
                }
            };

            const recordProgress = (phaseAfterProgress: ProviderAttemptDiagnostics['attemptPhase']) => {
                recordProviderEvent(phaseAfterProgress);
                diagnostics.partialOutputReceived = true;
                if (diagnostics.firstProgressAtMs === null) {
                    diagnostics.firstProgressAtMs = elapsedMs();
                    if (slowFirstProgressTimer) {
                        clearTimeout(slowFirstProgressTimer);
                    }
                }
                if (diagnostics.partialOutputAtMs === null) {
                    diagnostics.partialOutputAtMs = elapsedMs();
                }
                diagnostics.lastProgressAtMs = elapsedMs();
                diagnostics.progressEventCount += 1;
                refreshContentMetrics();
                if (finalizationTimer) {
                    clearTimeout(finalizationTimer);
                }
            };

            const settleResult = (
                resolve: (value: CopilotPromptResponse) => void,
                reject: (reason?: unknown) => void,
                warningCategory?: ProviderAttemptDiagnostics['warningCategory'],
                completionSignal?: ProviderAttemptDiagnostics['completionSignal'],
                finalizationReceived?: boolean,
            ) => {
                const text = currentText();
                if (!text) {
                    reject(new LlmExecutionError({
                        failureCategory: 'malformed_provider_result',
                        message: 'GitHub Copilot SDK returned an empty response.',
                        attemptPhase: diagnostics.attemptPhase,
                        diagnostics: snapshotDiagnostics(diagnostics),
                    }));
                    return;
                }

                refreshContentMetrics();
                diagnostics.warningCategory = warningCategory ?? diagnostics.warningCategory ?? null;
                diagnostics.livenessCategory = diagnostics.warningCategory ?? diagnostics.livenessCategory ?? null;
                diagnostics.completionSignal = completionSignal
                    ?? (diagnostics.idleReceived ? 'session_idle' : diagnostics.assistantMessageReceived ? 'assistant_message' : null);
                diagnostics.finalizationReceived = finalizationReceived
                    ?? diagnostics.idleReceived
                    ?? diagnostics.finalizationReceived;
                if (diagnostics.finalizationReceived && diagnostics.finalizationAtMs === null) {
                    diagnostics.finalizationAtMs = diagnostics.idleAtMs ?? elapsedMs();
                }
                setPhase('completed');
                resolve({
                    text,
                    diagnostics,
                });
            };

            const settle = (callback: () => void) => {
                if (settled) {
                    return;
                }
                settled = true;
                callback();
            };

            const settleSuccess = (
                resolve: (value: CopilotPromptResponse) => void,
                reject: (reason?: unknown) => void,
                warningCategory?: ProviderAttemptDiagnostics['warningCategory'],
                completionSignal?: ProviderAttemptDiagnostics['completionSignal'],
                finalizationReceived?: boolean,
            ) => {
                settle(() => settleResult(resolve, reject, warningCategory, completionSignal, finalizationReceived));
            };

            const settleError = (error: unknown) => {
                diagnostics.rawProviderError = normalizeString(error instanceof Error ? error.message : error);
                settle(() => {
                    if (!pendingReject) {
                        return;
                    }
                    if (error instanceof LlmExecutionError) {
                        pendingReject(attachDiagnostics(error));
                        return;
                    }
                    pendingReject(error);
                });
            };

            if (slowFirstProgressWarningMs && slowFirstProgressWarningMs > 0) {
                slowFirstProgressTimer = setTimeout(() => {
                    if (diagnostics.firstProgressAtMs !== null) {
                        return;
                    }
                    diagnostics.warningCategory = 'slow_first_event';
                    diagnostics.livenessCategory = diagnostics.livenessCategory ?? 'slow_first_event';
                }, slowFirstProgressWarningMs);
            }

            try {
                const result = await new Promise<CopilotPromptResponse>((resolve, reject) => {
                    pendingReject = reject;
                    if (executionOptions.signal) {
                        const abortHandler = () => {
                            settleError(new LlmExecutionError({
                                failureCategory: 'canceled',
                                message: 'GitHub Copilot session aborted.',
                                rawError: normalizeString(executionOptions.signal?.reason),
                                retryable: false,
                                attemptPhase: diagnostics.attemptPhase,
                                livenessCategory: 'canceled',
                                diagnostics: snapshotDiagnostics(diagnostics),
                            }));
                        };

                        if (executionOptions.signal.aborted) {
                            abortHandler();
                            return;
                        }

                        executionOptions.signal.addEventListener('abort', abortHandler, { once: true });
                        abortCleanup = () => executionOptions.signal?.removeEventListener('abort', abortHandler);
                    }

                    unsubs.push(
                        subscribe(session, 'assistant.message_delta', (payload) => {
                            diagnostics.streamingStarted = true;
                            const text = extractTextContent(payload);
                            if (text) {
                                deltaText += text;
                                recordProgress('streaming');
                            }
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'assistant.message', (payload) => {
                            recordProviderEvent('awaiting_finalization');
                            diagnostics.assistantMessageReceived = true;
                            const text = extractTextContent(payload);
                            if (text) {
                                finalMessage = text;
                                recordProgress('awaiting_finalization');
                            }

                            if (finalizationGraceMs === null) {
                                settleSuccess(resolve, reject, undefined, 'assistant_message', true);
                                return;
                            }

                            if (finalizationGraceMs && finalizationGraceMs > 0) {
                                if (finalizationTimer) {
                                    clearTimeout(finalizationTimer);
                                }
                                finalizationTimer = setTimeout(() => {
                                    diagnostics.finalizationReceived = false;
                                    settleSuccess(resolve, reject, 'finalization_missing', 'final_message_silence', false);
                                }, finalizationGraceMs);
                                return;
                            }

                            settleSuccess(resolve, reject, 'finalization_missing', 'final_message_silence', false);
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'session.idle', () => {
                            recordProviderEvent('awaiting_finalization');
                            diagnostics.idleReceived = true;
                            diagnostics.idleAtMs = elapsedMs();
                            diagnostics.finalizationReceived = true;
                            diagnostics.finalizationAtMs = diagnostics.idleAtMs;
                            settleSuccess(resolve, reject, undefined, 'session_idle', true);
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'session.error', (payload) => {
                            recordProviderEvent();
                            const message = extractTextContent(payload)
                                || normalizeString(payload?.data?.message)
                                || normalizeString(payload?.message)
                                || normalizeString(payload)
                                || 'GitHub Copilot session error.';
                            settleError(buildSdkSessionError(message, diagnostics));
                        }),
                    );

                    void session.send({
                        prompt: request.userPrompt,
                        attachments: request.images?.map((image, index) => ({
                            type: 'blob' as const,
                            data: image.data,
                            mimeType: image.mimeType,
                            displayName: `image-${index + 1}`,
                        })),
                    }).catch((error) => {
                        settleError(buildSdkSessionError(
                            error instanceof Error ? error.message : String(error || 'GitHub Copilot send failed.'),
                            diagnostics,
                        ));
                    });
                });

                return result;
            } finally {
                await cleanup();
            }
        });
    }
}
