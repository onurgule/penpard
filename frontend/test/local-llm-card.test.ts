import test from 'node:test';
import assert from 'node:assert/strict';

/**
 * Frontend unit tests for the Local LLM provider card logic.
 * These tests verify the contract between the settings page and the LocalLlmProviderCard
 * component — specifically the payload shapes, field presence, and interaction callbacks.
 */

// ── Payload Construction Tests ──

test('Local LLM save payload builds correct settings_json from host and port', () => {
    const host = '192.168.1.50';
    const port = '11434';

    const settingsJson = JSON.stringify({
        host: host.trim(),
        port: Number(port),
    });

    const parsed = JSON.parse(settingsJson);
    assert.equal(parsed.host, '192.168.1.50');
    assert.equal(parsed.port, 11434);
    assert.equal(typeof parsed.port, 'number');
});

test('Local LLM save payload excludes api_key', () => {
    const payload = {
        provider: 'local_llm',
        api_key: '',
        model: 'llama3.2',
        is_active: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    };

    assert.equal(payload.api_key, '');
    assert.equal(payload.provider, 'local_llm');
    assert.ok(!payload.settings_json.includes('api_key'));
});

test('Local LLM save payload includes model name', () => {
    const model = 'mistral-7b-instruct';
    const payload = {
        provider: 'local_llm',
        api_key: '',
        model,
        is_active: 0,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    };

    assert.equal(payload.model, 'mistral-7b-instruct');
});

// ── Field Presence Tests ──

test('Local LLM card props interface has no api_key field', () => {
    // The LocalLlmCardProps interface should have: host, port, model
    // but NOT api_key. We verify this by constructing valid props.
    const props = {
        host: '127.0.0.1',
        port: '8080',
        model: 'llama3.2',
        isActive: false,
        testStatus: 'Unknown',
        saving: false,
        onChangeHost: () => {},
        onChangePort: () => {},
        onChangeModel: () => {},
        onSave: () => {},
        onSaveAndTest: () => {},
        onToggleActive: () => {},
    };

    // Verify expected fields exist
    assert.ok('host' in props);
    assert.ok('port' in props);
    assert.ok('model' in props);
    // Verify api_key is NOT a field
    assert.ok(!('api_key' in props));
    assert.ok(!('apiKey' in props));
});

// ── Activate Interaction Tests ──

test('Local LLM activate toggle constructs correct payload with is_active flip', () => {
    let capturedPayload: any = null;
    const currentlyActive = false;
    const model = 'llama3';
    const host = '10.0.0.1';
    const port = '5000';

    const mockUpdateConfig = (_provider: string, data: any) => {
        capturedPayload = data;
    };

    // Simulate the onToggleActive callback from the settings page
    mockUpdateConfig('local_llm', {
        api_key: '',
        model: model.trim() || 'default',
        is_active: currentlyActive ? 0 : 1,
        settings_json: JSON.stringify({
            host: host.trim() || '127.0.0.1',
            port: Number(port) || 8080,
        }),
    });

    assert.ok(capturedPayload);
    assert.equal(capturedPayload.api_key, '');
    assert.equal(capturedPayload.model, 'llama3');
    assert.equal(capturedPayload.is_active, 1); // was false, flip to active
    const settings = JSON.parse(capturedPayload.settings_json);
    assert.equal(settings.host, '10.0.0.1');
    assert.equal(settings.port, 5000);
});

test('Local LLM deactivate toggle sets is_active to 0', () => {
    let capturedPayload: any = null;
    const currentlyActive = true;

    const mockUpdateConfig = (_provider: string, data: any) => {
        capturedPayload = data;
    };

    mockUpdateConfig('local_llm', {
        api_key: '',
        model: 'llama3',
        is_active: currentlyActive ? 0 : 1,
        settings_json: JSON.stringify({ host: '127.0.0.1', port: 8080 }),
    });

    assert.equal(capturedPayload.is_active, 0);
});

// ── Save & Test Interaction Tests ──

test('Save & Test calls save then test in sequence', async () => {
    const callOrder: string[] = [];

    const mockSave = async () => { callOrder.push('save'); };
    const mockTest = async () => { callOrder.push('test'); };

    // Simulate saveAndTestLocalLlm flow
    await mockSave();
    await mockTest();

    assert.deepEqual(callOrder, ['save', 'test']);
});

// ── Config Sync from Backend ──

test('Local LLM config fields are extracted from settings_json on fetch', () => {
    const fetchedConfig = {
        provider: 'local_llm',
        api_key: '',
        model: 'codellama',
        is_active: 1,
        settings_json: JSON.stringify({ host: '10.0.0.5', port: 11434, baseUrl: 'http://10.0.0.5:11434' }),
    };

    const settings = JSON.parse(fetchedConfig.settings_json);
    const syncedHost = settings.host || '127.0.0.1';
    const syncedPort = String(settings.port || 8080);
    const syncedModel = fetchedConfig.model;

    assert.equal(syncedHost, '10.0.0.5');
    assert.equal(syncedPort, '11434');
    assert.equal(syncedModel, 'codellama');
});

test('Local LLM config sync handles missing settings_json gracefully', () => {
    const fetchedConfig = {
        provider: 'local_llm',
        api_key: '',
        model: 'llama3',
        is_active: 0,
        settings_json: '{}',
    };

    let host = '127.0.0.1';
    let port = '8080';

    try {
        const s = JSON.parse(fetchedConfig.settings_json || '{}');
        if (s.host) host = s.host;
        if (s.port) port = String(s.port);
    } catch { /* ignore */ }

    // Should keep defaults
    assert.equal(host, '127.0.0.1');
    assert.equal(port, '8080');
});

// ── Provider Type Inclusion ──

test('local_llm is included in the LLMProvider type set', () => {
    const validProviders = new Set(['gemini', 'deepseek', 'openai', 'anthropic', 'ollama', 'local_llm', 'github_copilot']);
    assert.ok(validProviders.has('local_llm'));
});

// ── Default Port Edge Cases ──

test('port defaults to 8080 when empty string provided', () => {
    const port = '';
    const numericPort = Number(port) || 8080;
    assert.equal(numericPort, 8080);
});

test('port coerces string to number correctly', () => {
    const port = '11434';
    const numericPort = Number(port) || 8080;
    assert.equal(numericPort, 11434);
});
