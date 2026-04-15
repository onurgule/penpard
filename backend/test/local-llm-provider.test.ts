import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-local-llm-provider-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'local-llm-provider-test-secret';

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { llmProvider } = require('../src/services/LLMProviderService') as typeof import('../src/services/LLMProviderService');
const { logger } = require('../src/utils/logger') as typeof import('../src/utils/logger');

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`DELETE FROM llm_config;`);
    dbModule.db.exec(`DELETE FROM token_usage;`);
}

function insertLocalLlmConfig(overrides: Record<string, any> = {}) {
    const defaults = {
        provider: 'local_llm',
        api_key: '',
        model: 'llama3.2',
        is_active: 1,
        is_online: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080, baseUrl: 'http://127.0.0.1:8080' }),
    };
    const config = { ...defaults, ...overrides };
    llmProvider.updateConfig(config as any, 1);
    return config;
}

function mockFetchSequence(responses: Array<{ body: any; status?: number; headers?: Record<string, string> }>) {
    const originalFetch = globalThis.fetch;
    let index = 0;

    (globalThis as any).fetch = async () => {
        const current = responses[Math.min(index, responses.length - 1)];
        index += 1;
        const bodyText = typeof current.body === 'string' ? current.body : JSON.stringify(current.body);
        return new Response(bodyText, {
            status: current.status ?? 200,
            headers: current.headers ?? { 'content-type': 'application/json' },
        });
    };

    return () => {
        (globalThis as any).fetch = originalFetch;
    };
}

test('local_llm config normalization builds baseUrl from host and port', async () => {
    await resetState();

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'llama3.2',
        is_active: 0,
        is_online: 0,
        settings_json: JSON.stringify({ host: '192.168.1.100', port: 11434 }),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    assert.ok(localConfig);
    const settings = JSON.parse(localConfig!.settings_json);
    assert.equal(settings.baseUrl, 'http://192.168.1.100:11434');
});

test('local_llm config normalization defaults to http protocol', async () => {
    await resetState();

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'mistral',
        is_active: 0,
        is_online: 0,
        settings_json: JSON.stringify({ host: 'my-server.local', port: 5000 }),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    const settings = JSON.parse(localConfig!.settings_json);
    assert.ok(settings.baseUrl.startsWith('http://'));
});

test('local_llm config normalization defaults host to 127.0.0.1 and port to 8080', async () => {
    await resetState();

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'llama3',
        is_active: 0,
        is_online: 0,
        settings_json: JSON.stringify({}),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    assert.ok(localConfig);
});

test('local_llm is accepted as a valid provider', async () => {
    await resetState();

    assert.doesNotThrow(() => llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'llama3.2',
        is_active: 0,
        is_online: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    }, 1));
});

test('local_llm appears in getAllConfigs', async () => {
    await resetState();
    insertLocalLlmConfig();

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    assert.ok(localConfig);
    assert.equal(localConfig!.model, 'llama3.2');
});

test('local_llm config persists with empty api_key', async () => {
    await resetState();

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: 'should-be-stripped',
        model: 'llama3',
        is_active: 0,
        is_online: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    assert.ok(localConfig);
    assert.equal(localConfig!.api_key, '');
});

test('activating local_llm deactivates other providers', async () => {
    await resetState();

    llmProvider.updateConfig({
        provider: 'openai' as any,
        api_key: 'sk-test',
        model: 'gpt-4o',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1);

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'llama3.2',
        is_active: 1,
        is_online: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const openai = configs.find(c => c.provider === 'openai');
    const local = configs.find(c => c.provider === 'local_llm');

    assert.equal(openai?.is_active, 0);
    assert.equal(local?.is_active, 1);
});

test('getActiveConfig returns local_llm when it is the active provider', async () => {
    await resetState();
    insertLocalLlmConfig({ is_active: 1 });

    const config = llmProvider.getActiveConfig(1);
    assert.equal(config.provider, 'local_llm');
    assert.equal(config.model, 'llama3.2');
});

test('checkConnection does not reject local_llm for missing API key', async () => {
    await resetState();
    insertLocalLlmConfig();

    const result = await llmProvider.checkConnection('local_llm', 1);
    if (!result.success) {
        assert.ok(!result.error?.includes('API key'), `Error should not mention API key: ${result.error}`);
    }
});

test('getAllConfigSummaries masks api_key for local_llm', async () => {
    await resetState();
    insertLocalLlmConfig();

    const summaries = llmProvider.getAllConfigSummaries(1);
    const localSummary = summaries.find(c => c.provider === 'local_llm');
    assert.ok(localSummary);
    assert.equal(localSummary!.api_key, '');
    assert.equal(localSummary!.has_api_key, false);
});

test('checkVisionSupport returns false for local_llm', async () => {
    await resetState();
    insertLocalLlmConfig({ is_active: 1 });

    const result = llmProvider.checkVisionSupport(1);
    assert.equal(result.supported, false);
    assert.equal(result.provider, 'local_llm');
});

test('local_llm config requires a model name', async () => {
    await resetState();

    assert.throws(
        () => llmProvider.updateConfig({
            provider: 'local_llm' as any,
            api_key: '',
            model: '',
            is_active: 0,
            is_online: 0,
            settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
        }, 1),
        /Model is required/i,
    );
});

test('existing providers still work alongside local_llm', async () => {
    await resetState();

    insertLocalLlmConfig({ is_active: 0 });
    llmProvider.updateConfig({
        provider: 'openai' as any,
        api_key: 'sk-test',
        model: 'gpt-4o',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    assert.ok(configs.find(c => c.provider === 'openai'));
    assert.ok(configs.find(c => c.provider === 'local_llm'));
    assert.equal(configs.find(c => c.provider === 'openai')?.is_active, 1);
    assert.equal(configs.find(c => c.provider === 'local_llm')?.is_active, 0);

    const active = llmProvider.getActiveConfig(1);
    assert.equal(active.provider, 'openai');
});

test('local_llm config can be updated after initial save', async () => {
    await resetState();
    insertLocalLlmConfig();

    llmProvider.updateConfig({
        provider: 'local_llm' as any,
        api_key: '',
        model: 'mistral-7b',
        is_active: 1,
        is_online: 0,
        settings_json: JSON.stringify({ host: '10.0.0.5', port: 11434 }),
    }, 1);

    const configs = llmProvider.getAllConfigs(1);
    const localConfig = configs.find(c => c.provider === 'local_llm');
    assert.equal(localConfig!.model, 'mistral-7b');
    const settings = JSON.parse(localConfig!.settings_json);
    assert.equal(settings.baseUrl, 'http://10.0.0.5:11434');
});

test('unsupported providers are still rejected when local_llm is present', async () => {
    await resetState();
    insertLocalLlmConfig();

    assert.throws(() => llmProvider.updateConfig({
        provider: 'my_custom_ai' as any,
        api_key: 'secret',
        model: 'custom-v1',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1), /Unsupported LLM provider/i);
});

test('local_llm returns visible content and normalized usage metadata', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{ message: { role: 'assistant', content: 'Hello from standard content' }, finish_reason: 'stop' }],
            usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, 'Hello from standard content');
        assert.equal(result.finishReason, 'stop');
        assert.equal(result.usage?.input_tokens, 10);
        assert.equal(result.usage?.output_tokens, 5);
        assert.equal(result.usage?.total_tokens, 15);
    } finally {
        restore();
    }
});

test('local_llm captures reasoning separately without leaking it into text', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{
                message: {
                    role: 'assistant',
                    content: 'Final answer',
                    reasoning: 'Thinking step by step...',
                },
                finish_reason: 'stop',
            }],
            usage: {
                prompt_tokens: 15,
                completion_tokens: 8,
                total_tokens: 23,
                completion_tokens_details: { reasoning_tokens: 0 },
            },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, 'Final answer');
        assert.equal(result.reasoning, 'Thinking step by step...');
        assert.equal(result.usage?.reasoning_tokens, 0);
    } finally {
        restore();
    }
});

test('local_llm rejects reasoning-only responses instead of surfacing hidden reasoning as text', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{ message: { role: 'assistant', content: null, reasoning_content: 'Top-level reasoning text' }, finish_reason: 'stop' }],
        },
    }]);

    try {
        await assert.rejects(
            () => llmProvider.executeAttempt({
                systemPrompt: 'test',
                userPrompt: 'test',
            }, { userId: 1 }),
            (error: any) => {
                assert.match(error.message, /no visible assistant content/i);
                assert.ok(!error.message.includes('Body preview:'));
                assert.ok(!error.message.includes('Top-level reasoning text'));
                return true;
            },
        );
    } finally {
        restore();
    }
});

test('local_llm succeeds when content is an array of visible text blocks', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{
                message: {
                    role: 'assistant',
                    content: [
                        { type: 'text', text: 'First part. ' },
                        { type: 'reasoning', text: 'private reasoning' },
                        { type: 'text', text: 'Second part.' },
                    ],
                },
                finish_reason: 'stop',
            }],
            usage: { prompt_tokens: 12, completion_tokens: 6, total_tokens: 18 },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, 'First part. Second part.');
    } finally {
        restore();
    }
});

test('local_llm allows successful tool-call-only responses with empty visible text', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{
                message: {
                    role: 'assistant',
                    content: null,
                    tool_calls: [{
                        id: 'call_123',
                        type: 'function',
                        function: {
                            name: 'lookup_asset',
                            arguments: '{"asset":"token"}',
                        },
                    }],
                },
                finish_reason: 'tool_calls',
            }],
            usage: { prompt_tokens: 22, completion_tokens: 11, total_tokens: 33 },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, '');
        assert.equal(result.finishReason, 'tool_calls');
        assert.equal(result.toolCalls?.length, 1);
        assert.equal(result.toolCalls?.[0]?.function.name, 'lookup_asset');
        assert.deepEqual(result.toolCalls?.[0]?.function.parsedArguments, { asset: 'token' });
    } finally {
        restore();
    }
});

test('local_llm logs a sanitized response summary instead of a raw preview', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const originalInfo = logger.info.bind(logger);
    const infoCalls: Array<{ message: string; meta: any }> = [];
    (logger as any).info = (message: string, meta: any) => {
        infoCalls.push({ message, meta });
    };

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{
                message: {
                    role: 'assistant',
                    content: 'Visible answer',
                    reasoning: 'Hidden reasoning',
                },
                finish_reason: 'stop',
            }],
            usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, 'Visible answer');

        const summary = infoCalls.find((entry) => entry.message === 'local_llm.response.summary');
        assert.ok(summary);
        assert.equal(summary?.meta.hasContent, true);
        assert.equal(summary?.meta.hasReasoning, true);
        assert.equal(summary?.meta.toolCallCount, 0);
        assert.ok(!Object.hasOwn(summary?.meta || {}, 'preview'));
    } finally {
        (logger as any).info = originalInfo;
        restore();
    }
});

test('local_llm prefers message.content over reasoning fields when both are present', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockFetchSequence([{
        body: {
            model: 'qwen-2.5',
            choices: [{
                message: {
                    role: 'assistant',
                    content: 'Final answer',
                    reasoning_content: 'Internal reasoning',
                },
                finish_reason: 'stop',
            }],
            usage: { prompt_tokens: 20, completion_tokens: 9, total_tokens: 29 },
        },
    }]);

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'test',
            userPrompt: 'test',
        }, { userId: 1 });

        assert.equal(result.text, 'Final answer');
        assert.equal(result.reasoning, 'Internal reasoning');
    } finally {
        restore();
    }
});
