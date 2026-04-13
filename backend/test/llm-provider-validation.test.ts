import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-llm-provider-validation-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'llm-provider-validation-test-secret';

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { llmProvider } = require('../src/services/LLMProviderService') as typeof import('../src/services/LLMProviderService');

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM llm_config;
    `);
}

test('LLM provider config updates reject unsupported provider names', async () => {
    await resetState();

    assert.throws(() => llmProvider.updateConfig({
        provider: 'qwen' as any,
        api_key: 'secret',
        model: 'qwen-max',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1), /Unsupported LLM provider/i);
});

test('LLM provider reads ignore stale unsupported provider rows', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('qwen', 'legacy-secret', 'qwen-max', 1, 1, '{}')
    `).run();

    const configs = llmProvider.getAllConfigs(1);

    assert.deepEqual(configs, []);
    assert.throws(() => llmProvider.getActiveConfig(1), /No active LLM provider configured/i);
});
