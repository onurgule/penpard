import test from 'node:test';
import assert from 'node:assert/strict';

import { GitHubCopilotAuthError, GitHubCopilotSdkService } from '../src/services/github/GitHubCopilotSdkService';

test('GitHubCopilotSdkService normalizes Copilot SDK models for the UI and sorts selectable models first', async () => {
    let started = 0;
    let stopped = 0;

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => { started += 1; },
        stop: async () => { stopped += 1; return []; },
        getAuthStatus: async () => ({ isAuthenticated: true, login: 'octocat', authType: 'token' }),
        listModels: async () => ([
            {
                id: 'claude-sonnet-4.5',
                name: 'Claude Sonnet 4.5',
                capabilities: {
                    supports: { vision: false, reasoningEffort: false },
                    limits: { max_context_window_tokens: 200000 },
                },
                policy: { state: 'disabled', terms: 'org-policy' },
                billing: { multiplier: 2 },
            },
            {
                id: 'gpt-5',
                name: 'GPT-5',
                capabilities: {
                    supports: { vision: true, reasoningEffort: true },
                    limits: {
                        max_context_window_tokens: 272000,
                        max_prompt_tokens: 128000,
                        vision: {
                            supported_media_types: ['image/png', 'image/jpeg'],
                            max_prompt_images: 8,
                            max_prompt_image_size: 4_000_000,
                        },
                    },
                },
                policy: { state: 'enabled', terms: 'copilot' },
                billing: { multiplier: 1 },
                supportedReasoningEfforts: ['low', 'medium', 'high'],
                defaultReasoningEffort: 'medium',
            },
        ] as any),
        createSession: async () => {
            throw new Error('createSession should not be called by listModels');
        },
    }) as any);

    const models = await service.listModels('ghu_example');

    assert.equal(started, 1);
    assert.equal(stopped, 1);
    assert.equal(models.length, 2);
    assert.equal(models[0].id, 'gpt-5');
    assert.deepEqual(models[0], {
        id: 'gpt-5',
        name: 'GPT-5',
        isAvailable: true,
        policyState: 'enabled',
        billingMultiplier: 1,
        supportsVision: true,
        supportsReasoningEffort: true,
        supportedReasoningEfforts: ['low', 'medium', 'high'],
        defaultReasoningEffort: 'medium',
        maxContextWindowTokens: 272000,
        maxPromptTokens: 128000,
        maxPromptImages: 8,
        supportedImageMimeTypes: ['image/png', 'image/jpeg'],
    });
    assert.equal(models[1].isAvailable, false);
    assert.equal(models[1].policyState, 'disabled');
});

test('GitHubCopilotSdkService generate uses a tool-free Copilot session and passes blob attachments for images', async () => {
    let createdSessionConfig: any = null;
    let sendArguments: any = null;
    let disconnected = 0;

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async (config: any) => {
            createdSessionConfig = config;
            return {
                sendAndWait: async (options: any, timeout?: number) => {
                    sendArguments = { options, timeout };
                    return {
                        data: {
                            content: 'copilot-answer',
                        },
                    };
                },
                disconnect: async () => {
                    disconnected += 1;
                },
            };
        },
    }) as any);

    const response = await service.generate('ghu_example', 'gpt-5', {
        systemPrompt: 'You are PenPard.',
        userPrompt: 'Summarize this finding.',
        images: [{ data: 'ZmFrZS1pbWFnZQ==', mimeType: 'image/png' }],
    });

    assert.equal(response.text, 'copilot-answer');
    assert.equal(disconnected, 1);
    assert.deepEqual(createdSessionConfig.availableTools, []);
    assert.deepEqual(createdSessionConfig.infiniteSessions, { enabled: false });
    assert.equal(createdSessionConfig.model, 'gpt-5');
    assert.deepEqual(createdSessionConfig.systemMessage, {
        mode: 'replace',
        content: 'You are PenPard.',
    });
    assert.equal(sendArguments.timeout, 60000);
    assert.deepEqual(sendArguments.options.attachments, [
        {
            type: 'blob',
            data: 'ZmFrZS1pbWFnZQ==',
            mimeType: 'image/png',
            displayName: 'image-1',
        },
    ]);
});

test('GitHubCopilotSdkService converts Copilot auth failures into refreshable auth errors', async () => {
    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => {
            throw new Error('Unauthorized: token expired');
        },
        getAuthStatus: async () => ({ isAuthenticated: false }),
        createSession: async () => {
            throw new Error('not used');
        },
    }) as any);

    await assert.rejects(
        async () => service.listModels('ghu_expired'),
        (error: unknown) => error instanceof GitHubCopilotAuthError,
    );
});
