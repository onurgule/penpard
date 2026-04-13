import { CopilotClient, approveAll, type ModelInfo } from '@github/copilot-sdk';
import { logger } from '../../utils/logger';
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
        onPermissionRequest: typeof approveAll;
    }): Promise<{
        sendAndWait(
            options: {
                prompt: string;
                attachments?: Array<{ type: 'blob'; data: string; mimeType: string; displayName?: string }>;
            },
            timeout?: number,
        ): Promise<{ data: { content: string } } | undefined>;
        disconnect(): Promise<void>;
    }>;
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
        timeoutMs = 60_000,
    ): Promise<CopilotPromptResponse> {
        return this.withClient(accessToken, async (client) => {
            const session = await client.createSession({
                clientName: 'PenPard',
                model,
                workingDirectory: process.cwd(),
                enableConfigDiscovery: false,
                availableTools: [],
                infiniteSessions: { enabled: false },
                systemMessage: {
                    mode: 'replace',
                    content: request.systemPrompt,
                },
                onPermissionRequest: approveAll,
            });

            try {
                const response = await session.sendAndWait({
                    prompt: request.userPrompt,
                    attachments: request.images?.map((image, index) => ({
                        type: 'blob' as const,
                        data: image.data,
                        mimeType: image.mimeType,
                        displayName: `image-${index + 1}`,
                    })),
                }, timeoutMs);

                const text = response?.data.content?.trim() || '';
                if (!text) {
                    throw new Error('GitHub Copilot SDK returned an empty response.');
                }

                return { text };
            } finally {
                await session.disconnect();
            }
        });
    }
}
