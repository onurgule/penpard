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

function buildSdkSessionError(message: string, sendCompleted: boolean): LlmExecutionError {
    const lower = message.toLowerCase();
    const sessionLikeFailure = !sendCompleted
        || lower.includes('session')
        || lower.includes('disconnect')
        || lower.includes('idle');

    return new LlmExecutionError({
        failureCategory: sessionLikeFailure ? 'sdk_session_timeout' : 'transient_provider_error',
        message,
        rawError: message,
        retryable: true,
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
                onPermissionRequest: approveAll,
            });

            const firstEventTimeoutMs = executionOptions.firstEventTimeoutMs !== undefined
                ? executionOptions.firstEventTimeoutMs
                : 20_000;
            const attemptTimeoutMs = executionOptions.attemptTimeoutMs !== undefined
                ? executionOptions.attemptTimeoutMs
                : 60_000;
            const diagnostics: ProviderAttemptDiagnostics = {
                streamingStarted: false,
                anyEventReceived: false,
                assistantMessageReceived: false,
                idleReceived: false,
                firstEventAtMs: null,
                idleAtMs: null,
                finalContentLength: 0,
                warningCategory: null,
                rawProviderError: null,
            };

            const startedAtMs = Date.now();
            let sendCompleted = false;
            let settled = false;
            let deltaText = '';
            let finalMessage = '';
            let firstEventTimer: NodeJS.Timeout | undefined;
            let attemptTimer: NodeJS.Timeout | undefined;
            let abortCleanup = () => {};
            const unsubs: Array<() => void> = [];

            const cleanup = async () => {
                if (firstEventTimer) {
                    clearTimeout(firstEventTimer);
                }
                if (attemptTimer) {
                    clearTimeout(attemptTimer);
                }
                abortCleanup();
                for (const unsub of unsubs) {
                    unsub();
                }
                await session.disconnect();
            };

            try {
                const result = await new Promise<CopilotPromptResponse>((resolve, reject) => {
                    const settle = (callback: () => void) => {
                        if (settled) {
                            return;
                        }
                        settled = true;
                        callback();
                    };

                    const recordAssistantEvent = () => {
                        diagnostics.anyEventReceived = true;
                        if (diagnostics.firstEventAtMs === null) {
                            diagnostics.firstEventAtMs = Date.now() - startedAtMs;
                            if (firstEventTimer) {
                                clearTimeout(firstEventTimer);
                            }
                        }
                    };

                    const settleSuccess = (warningCategory?: ProviderAttemptDiagnostics['warningCategory']) => {
                        const text = (finalMessage || deltaText).trim();
                        if (!text) {
                            settle(() => reject(new LlmExecutionError({
                                failureCategory: 'malformed_provider_result',
                                message: 'GitHub Copilot SDK returned an empty response.',
                            })));
                            return;
                        }

                        diagnostics.finalContentLength = text.length;
                        diagnostics.warningCategory = warningCategory ?? null;
                        settle(() => resolve({
                            text,
                            diagnostics,
                        }));
                    };

                    const settleError = (error: unknown) => {
                        diagnostics.rawProviderError = normalizeString(error instanceof Error ? error.message : error);
                        settle(() => reject(error));
                    };

                    if (firstEventTimeoutMs && firstEventTimeoutMs > 0) {
                        firstEventTimer = setTimeout(() => {
                            settleError(new LlmExecutionError({
                                failureCategory: 'provider_first_event_timeout',
                                message: `No GitHub Copilot event received within ${firstEventTimeoutMs}ms.`,
                                budgetMs: firstEventTimeoutMs,
                                retryable: true,
                            }));
                        }, firstEventTimeoutMs);
                    }

                    if (attemptTimeoutMs && attemptTimeoutMs > 0) {
                        attemptTimer = setTimeout(() => {
                            if (finalMessage.trim()) {
                                settleSuccess('provider_idle_timeout');
                                return;
                            }

                            settleError(new LlmExecutionError({
                                failureCategory: 'provider_call_timeout',
                                message: `GitHub Copilot provider call exceeded ${attemptTimeoutMs}ms.`,
                                budgetMs: attemptTimeoutMs,
                                retryable: true,
                            }));
                        }, attemptTimeoutMs);
                    }

                    if (executionOptions.signal) {
                        const abortHandler = () => {
                            settleError(new LlmExecutionError({
                                failureCategory: 'canceled_due_to_scan_state',
                                message: 'GitHub Copilot session aborted.',
                                rawError: normalizeString(executionOptions.signal?.reason),
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
                            recordAssistantEvent();
                            diagnostics.streamingStarted = true;
                            const text = extractTextContent(payload);
                            if (text) {
                                deltaText += text;
                            }
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'assistant.message', (payload) => {
                            recordAssistantEvent();
                            diagnostics.assistantMessageReceived = true;
                            const text = extractTextContent(payload);
                            if (text) {
                                finalMessage = text;
                            }
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'session.idle', () => {
                            diagnostics.idleReceived = true;
                            diagnostics.idleAtMs = Date.now() - startedAtMs;
                            settleSuccess();
                        }),
                    );
                    unsubs.push(
                        subscribe(session, 'session.error', (payload) => {
                            const message = extractTextContent(payload) || normalizeString(payload) || 'GitHub Copilot session error.';
                            settleError(buildSdkSessionError(message, sendCompleted));
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
                    }).then(() => {
                        sendCompleted = true;
                    }).catch((error) => {
                        settleError(buildSdkSessionError(
                            error instanceof Error ? error.message : String(error || 'GitHub Copilot send failed.'),
                            sendCompleted,
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
