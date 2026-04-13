import test from 'node:test';
import assert from 'node:assert/strict';

import { GitHubCopilotAuthError, GitHubCopilotSdkService } from '../src/services/github/GitHubCopilotSdkService';
import { LlmExecutionError } from '../src/services/llm/LlmRuntimeTypes';

function createEventDrivenService(
    onSend: (emit: (eventName: string, payload?: any) => void, config: any, options: any) => void | Promise<void>,
) {
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
                    sendArguments = options;
                    await onSend(emit, config, options);
                },
                disconnect: async () => {
                    disconnected += 1;
                },
            };
        },
    }) as any);

    return {
        service,
        getCreatedSessionConfig: () => createdSessionConfig,
        getSendArguments: () => sendArguments,
        getDisconnectedCount: () => disconnected,
    };
}

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
    const harness = createEventDrivenService(async (emit) => {
        emit('assistant.message_delta', { data: { delta: 'copilot-' } });
        emit('assistant.message', { data: { content: 'copilot-answer' } });
        emit('session.idle');
    });

    const response = await harness.service.generate('ghu_example', 'gpt-5', {
        systemPrompt: 'You are PenPard.',
        userPrompt: 'Summarize this finding.',
        images: [{ data: 'ZmFrZS1pbWFnZQ==', mimeType: 'image/png' }],
    });

    assert.equal(response.text, 'copilot-answer');
    assert.equal(harness.getDisconnectedCount(), 1);
    assert.deepEqual(harness.getCreatedSessionConfig().availableTools, []);
    assert.deepEqual(harness.getCreatedSessionConfig().infiniteSessions, { enabled: false });
    assert.equal(harness.getCreatedSessionConfig().streaming, true);
    assert.equal(harness.getCreatedSessionConfig().model, 'gpt-5');
    assert.deepEqual(harness.getCreatedSessionConfig().systemMessage, {
        mode: 'replace',
        content: 'You are PenPard.',
    });
    assert.deepEqual(harness.getSendArguments().attachments, [
        {
            type: 'blob',
            data: 'ZmFrZS1pbWFnZQ==',
            mimeType: 'image/png',
            displayName: 'image-1',
        },
    ]);
    assert.equal(response.diagnostics?.partialOutputReceived, true);
    assert.equal(response.diagnostics?.completionSignal, 'session_idle');
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

test('GitHubCopilotSdkService allows long waits before the first assistant output when the session is still alive', async () => {
    const harness = createEventDrivenService(async (emit, config) => {
        config.onEvent?.({ type: 'session.start', data: { sessionId: 'session-1' } });
        setTimeout(() => emit('assistant.message', { data: { content: 'late-answer' } }), 40);
        setTimeout(() => emit('session.idle'), 45);
    });

    const response = await harness.service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            slowFirstProgressWarningMs: 10,
            finalizationGraceMs: 20,
        },
    );

    assert.equal(response.text, 'late-answer');
    assert.equal(response.diagnostics?.warningCategory, 'slow_first_event');
    assert.equal(response.diagnostics?.livenessCategory, 'slow_first_event');
    assert.equal(response.diagnostics?.idleReceived, true);
    assert.ok((response.diagnostics?.firstEventAtMs || 0) < (response.diagnostics?.firstProgressAtMs || 0));
});

test('GitHubCopilotSdkService returns content when the final message arrives but session.idle never does', async () => {
    const harness = createEventDrivenService(async (emit) => {
        emit('assistant.message', { data: { content: 'final-without-idle' } });
    });

    const response = await harness.service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            slowFirstProgressWarningMs: 50,
            finalizationGraceMs: 10,
        },
    );

    assert.equal(response.text, 'final-without-idle');
    assert.equal(response.diagnostics?.assistantMessageReceived, true);
    assert.equal(response.diagnostics?.idleReceived, false);
    assert.equal(response.diagnostics?.warningCategory, 'finalization_missing');
    assert.equal(response.diagnostics?.completionSignal, 'final_message_silence');
    assert.equal(response.diagnostics?.finalizationReceived, false);
    assert.equal(response.diagnostics?.livenessCategory, 'finalization_missing');
});

test('GitHubCopilotSdkService allows delayed session.idle after useful output', async () => {
    const harness = createEventDrivenService(async (emit) => {
        setTimeout(() => emit('assistant.message', { data: { content: 'answer-before-idle' } }), 5);
        setTimeout(() => emit('session.idle'), 40);
    });

    const response = await harness.service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            finalizationGraceMs: 60,
        },
    );

    assert.equal(response.text, 'answer-before-idle');
    assert.equal(response.diagnostics?.completionSignal, 'session_idle');
    assert.equal(response.diagnostics?.idleReceived, true);
    assert.equal(response.diagnostics?.warningCategory, null);
});

test('GitHubCopilotSdkService honors explicit cancellation while waiting for provider completion', async () => {
    const harness = createEventDrivenService(async (_emit, config) => {
        config.onEvent?.({ type: 'session.start', data: { sessionId: 'session-cancel' } });
        await new Promise((resolve) => setTimeout(resolve, 50));
    });
    const controller = new AbortController();

    const promise = harness.service.generate(
        'ghu_example',
        'gpt-5',
        {
            systemPrompt: 'system',
            userPrompt: 'user',
        },
        {
            signal: controller.signal,
            slowFirstProgressWarningMs: null,
            finalizationGraceMs: null,
        },
    );

    setTimeout(() => controller.abort(new Error('operator requested stop')), 10);

    await assert.rejects(
        () => promise,
        (error: any) => {
            assert.ok(error instanceof LlmExecutionError);
            assert.equal(error.failureCategory, 'canceled');
            assert.equal(error.livenessCategory, 'canceled');
            assert.equal(harness.getDisconnectedCount(), 1);
            return true;
        },
    );
});

test('GitHubCopilotSdkService fails on real session errors without fixed-window no-output wording', async () => {
    const harness = createEventDrivenService(async (emit, config) => {
        config.onEvent?.({ type: 'session.start', data: { sessionId: 'session-error' } });
        emit('session.error', { data: { message: 'session disconnected unexpectedly' } });
    });

    await assert.rejects(
        () => harness.service.generate(
            'ghu_example',
            'gpt-5',
            {
                systemPrompt: 'system',
                userPrompt: 'user',
            },
            {
                slowFirstProgressWarningMs: 10,
                finalizationGraceMs: 10,
            },
        ),
        (error: any) => {
            assert.ok(error instanceof LlmExecutionError);
            assert.equal(error.failureCategory, 'transient_provider_error');
            assert.equal(error.diagnostics?.anyEventReceived, true);
            assert.ok(!(error.message || '').includes('no assistant output within'));
            return true;
        },
    );
});
