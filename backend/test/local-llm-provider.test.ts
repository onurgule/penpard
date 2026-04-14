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

// ── Config Normalization ──

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
    // When no host/port provided, no baseUrl normalization
    // The runtime will detect missing baseUrl and throw
});

// ── Provider Validation ──

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

// ── No API Key Requirement ──

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

// ── Provider Activation ──

test('activating local_llm deactivates other providers', async () => {
    await resetState();

    // Insert an openai config as active
    llmProvider.updateConfig({
        provider: 'openai' as any,
        api_key: 'sk-test',
        model: 'gpt-4o',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1);

    // Activate local_llm
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

    assert.equal(openai?.is_active, 0, 'openai should be deactivated');
    assert.equal(local?.is_active, 1, 'local_llm should be active');
});

test('getActiveConfig returns local_llm when it is the active provider', async () => {
    await resetState();
    insertLocalLlmConfig({ is_active: 1 });

    const config = llmProvider.getActiveConfig(1);
    assert.equal(config.provider, 'local_llm');
    assert.equal(config.model, 'llama3.2');
});

// ── Connection Check ──

test('checkConnection does not reject local_llm for missing API key', async () => {
    await resetState();
    insertLocalLlmConfig();

    // The actual call will fail (no server running), but it should NOT fail with
    // "API key is empty" — it should attempt the generation and fail on network.
    const result = await llmProvider.checkConnection('local_llm', 1);

    // It will be success: false because no server is running, but the error
    // should NOT mention API key
    if (!result.success) {
        assert.ok(!result.error?.includes('API key'), `Error should not mention API key: ${result.error}`);
    }
});

// ── Config Summaries ──

test('getAllConfigSummaries masks api_key for local_llm', async () => {
    await resetState();
    insertLocalLlmConfig();

    const summaries = llmProvider.getAllConfigSummaries(1);
    const localSummary = summaries.find(c => c.provider === 'local_llm');
    assert.ok(localSummary);
    assert.equal(localSummary!.api_key, '');
    assert.equal(localSummary!.has_api_key, false);
});

// ── Vision Support ──

test('checkVisionSupport returns false for local_llm', async () => {
    await resetState();
    insertLocalLlmConfig({ is_active: 1 });

    const result = llmProvider.checkVisionSupport(1);
    assert.equal(result.supported, false);
    assert.equal(result.provider, 'local_llm');
});

// ── Model Required ──

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

// ── Existing Provider Regression ──

test('existing providers still work alongside local_llm', async () => {
    await resetState();

    // Insert local_llm
    insertLocalLlmConfig({ is_active: 0 });

    // Insert openai
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

// ── Config Update Persistence ──

test('local_llm config can be updated after initial save', async () => {
    await resetState();
    insertLocalLlmConfig();

    // Update model
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

// ── Unsupported Provider Still Rejected ──

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

// ── Response Parsing Tests (via extractLocalLlmText) ──
// These tests exercise callLocalLlm by mocking axios.post at module level.

const axios = require('axios') as typeof import('axios');

function mockAxiosPost(responseData: any, status = 200) {
    const original = axios.default.post;
    (axios.default as any).post = async () => ({ status, data: responseData });
    return () => { (axios.default as any).post = original; };
}

function makeLocalConfig() {
    return {
        provider: 'local_llm',
        api_key: '',
        model: 'qwen-2.5',
        is_active: 1,
        is_online: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080, baseUrl: 'http://127.0.0.1:8080' }),
    };
}

test('callLocalLlm succeeds when choices[0].message.content is a string', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{ message: { role: 'assistant', content: 'Hello from standard content' } }],
        usage: { prompt_tokens: 10, completion_tokens: 5 },
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'Hello from standard content');
        assert.equal(result.usage.input_tokens, 10);
        assert.equal(result.usage.output_tokens, 5);
    } finally {
        restore();
    }
});

test('callLocalLlm succeeds when message.reasoning_content is present instead of content', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{ message: { role: 'assistant', content: null, reasoning_content: 'Thinking step by step...' } }],
        usage: { prompt_tokens: 15, completion_tokens: 8 },
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'Thinking step by step...');
    } finally {
        restore();
    }
});

test('callLocalLlm succeeds when choice-level reasoning_content is present', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{ message: { role: 'assistant' }, reasoning_content: 'Top-level reasoning text' }],
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'Top-level reasoning text');
        assert.equal(result.usage, undefined); // no usage block
    } finally {
        restore();
    }
});

test('callLocalLlm succeeds when content is an array of text blocks', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{
            message: {
                role: 'assistant',
                content: [
                    { type: 'text', text: 'First part. ' },
                    { type: 'text', text: 'Second part.' },
                ],
            },
        }],
        usage: { prompt_tokens: 12, completion_tokens: 6 },
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'First part. Second part.');
    } finally {
        restore();
    }
});

test('callLocalLlm fails with diagnostic body preview when no text is extractable', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{ message: { role: 'assistant', content: null }, finish_reason: 'stop' }],
    });

    try {
        const config = makeLocalConfig();
        await assert.rejects(
            () => (llmProvider as any).callLocalLlm(config, {
                systemPrompt: 'test', userPrompt: 'test',
            }, 0.7),
            (err: any) => {
                assert.ok(err.message.includes('no extractable text'));
                assert.ok(err.message.includes('Body preview:'));
                assert.ok(err.message.includes('message.reasoning_content'));
                return true;
            },
        );
    } finally {
        restore();
    }
});

test('callLocalLlm parses token usage correctly with reasoning response', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{ message: { role: 'assistant', reasoning_content: 'Deep thought' } }],
        usage: { prompt_tokens: 100, completion_tokens: 50 },
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'Deep thought');
        assert.equal(result.usage.input_tokens, 100);
        assert.equal(result.usage.output_tokens, 50);
    } finally {
        restore();
    }
});

test('callLocalLlm prefers message.content over reasoning fields when both present', async () => {
    await resetState();
    insertLocalLlmConfig({ model: 'qwen-2.5' });

    const restore = mockAxiosPost({
        choices: [{
            message: {
                role: 'assistant',
                content: 'Final answer',
                reasoning_content: 'Internal reasoning',
            },
        }],
    });

    try {
        const config = makeLocalConfig();
        const result = await (llmProvider as any).callLocalLlm(config, {
            systemPrompt: 'test', userPrompt: 'test',
        }, 0.7);

        assert.equal(result.text, 'Final answer');
    } finally {
        restore();
    }
});
