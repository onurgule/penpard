import test from 'node:test';
import assert from 'node:assert/strict';

import { GitHubCopilotAuthError, GitHubCopilotSdkService } from '../src/services/github/GitHubCopilotSdkService';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';

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
    const listeners = new Map<string, Array<(payload?: any) => void>>();

    const emit = (eventName: string, payload?: any) => {
        for (const listener of listeners.get(eventName) || []) {
            listener(payload);
        }
    };

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async (config: any) => {
            createdSessionConfig = config;
            return {
                on: (eventName: string, listener: (payload?: any) => void) => {
                    if (!listeners.has(eventName)) {
                        listeners.set(eventName, []);
                    }
                    listeners.get(eventName)!.push(listener);
                },
                send: async (options: any) => {
                    sendArguments = { options };
                    emit('assistant.message_delta', { data: { delta: 'copilot-' } });
                    emit('assistant.message', { data: { content: 'copilot-answer' } });
                    emit('session.idle');
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
    assert.equal(createdSessionConfig.streaming, true);
    assert.equal(createdSessionConfig.model, 'gpt-5');
    assert.deepEqual(createdSessionConfig.systemMessage, {
        mode: 'replace',
        content: 'You are PenPard.',
    });
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

test('GitHubCopilotSdkService returns content when the final message arrives but session.idle never does', async () => {
    const listeners = new Map<string, Array<(payload?: any) => void>>();

    const emit = (eventName: string, payload?: any) => {
        for (const listener of listeners.get(eventName) || []) {
            listener(payload);
        }
    };

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async () => ({
            on: (eventName: string, listener: (payload?: any) => void) => {
                if (!listeners.has(eventName)) {
                    listeners.set(eventName, []);
                }
                listeners.get(eventName)!.push(listener);
            },
            send: async () => {
                emit('assistant.message', { data: { content: 'final-without-idle' } });
            },
            disconnect: async () => undefined,
        }),
    }) as any);

    const response = await service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            firstEventTimeoutMs: 50,
            attemptTimeoutMs: 30,
        },
    );

    assert.equal(response.text, 'final-without-idle');
    assert.equal(response.diagnostics?.assistantMessageReceived, true);
    assert.equal(response.diagnostics?.idleReceived, false);
    assert.equal(response.diagnostics?.warningCategory, 'provider_idle_timeout');
});

test('GitHubCopilotSdkService classifies no-event sessions as provider_first_event_timeout', async () => {
    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async () => ({
            on: () => undefined,
            send: async () => undefined,
            disconnect: async () => undefined,
        }),
    }) as any);

    await assert.rejects(
        () => service.generate(
            'ghu_example',
            'gpt-5',
            {
                systemPrompt: 'system',
                userPrompt: 'user',
            },
            {
                firstEventTimeoutMs: 20,
                attemptTimeoutMs: 60,
            },
        ),
        (error: any) => {
            assert.ok(error instanceof LlmExecutionError);
            assert.equal(error.failureCategory, 'provider_first_event_timeout');
            return true;
        },
    );
});

test('GitHubCopilotSdkService classifies session errors before completion as sdk_session_timeout', async () => {
    const listeners = new Map<string, Array<(payload?: any) => void>>();

    const emit = (eventName: string, payload?: any) => {
        for (const listener of listeners.get(eventName) || []) {
            listener(payload);
        }
    };

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async () => ({
            on: (eventName: string, listener: (payload?: any) => void) => {
                if (!listeners.has(eventName)) {
                    listeners.set(eventName, []);
                }
                listeners.get(eventName)!.push(listener);
            },
            send: async () => {
                emit('session.error', { data: { content: 'session disconnected' } });
            },
            disconnect: async () => undefined,
        }),
    }) as any);

    await assert.rejects(
        () => service.generate(
            'ghu_example',
            'gpt-5',
            {
                systemPrompt: 'system',
                userPrompt: 'user',
            },
            {
                firstEventTimeoutMs: 50,
                attemptTimeoutMs: 50,
            },
        ),
        (error: any) => {
            assert.ok(error instanceof LlmExecutionError);
            assert.equal(error.failureCategory, 'sdk_session_timeout');
            return true;
        },
    );
});

test('GitHubCopilotSdkService allows slow responses that still finish within budget', async () => {
    const listeners = new Map<string, Array<(payload?: any) => void>>();

    const emit = (eventName: string, payload?: any) => {
        for (const listener of listeners.get(eventName) || []) {
            listener(payload);
        }
    };

    const service = new GitHubCopilotSdkService(() => ({
        start: async () => undefined,
        stop: async () => [],
        listModels: async () => [],
        getAuthStatus: async () => ({ isAuthenticated: true }),
        createSession: async () => ({
            on: (eventName: string, listener: (payload?: any) => void) => {
                if (!listeners.has(eventName)) {
                    listeners.set(eventName, []);
                }
                listeners.get(eventName)!.push(listener);
            },
            send: async () => {
                setTimeout(() => emit('assistant.message_delta', { data: { delta: 'slow-' } }), 10);
                setTimeout(() => emit('assistant.message', { data: { content: 'slow-answer' } }), 20);
                setTimeout(() => emit('session.idle'), 25);
            },
            disconnect: async () => undefined,
        }),
    }) as any);

    const response = await service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            firstEventTimeoutMs: 50,
            attemptTimeoutMs: 80,
        },
    );

    assert.equal(response.text, 'slow-answer');
    assert.equal(response.diagnostics?.idleReceived, true);
    assert.ok((response.diagnostics?.firstEventAtMs || 0) >= 0);
});
