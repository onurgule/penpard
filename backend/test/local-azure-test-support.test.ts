import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';

import { createLocalAzureTestSupportClient, loadLocalAzureTestSupportConfig } from '../src/testing/localAzureTestSupport';

test('local Azure test support stays optional when credentials are absent', () => {
    const config = loadLocalAzureTestSupportConfig({});
    const client = createLocalAzureTestSupportClient({});

    assert.equal(config, null);
    assert.equal(client, null);
});

test('local Azure test support only uses caller-provided placeholder env values', () => {
    const config = loadLocalAzureTestSupportConfig({
        AZURE_OPENAI_ENDPOINT: 'https://example-resource.openai.azure.com/',
        AZURE_OPENAI_API_KEY: 'local-dev-key',
        AZURE_OPENAI_MODEL: 'gpt-test',
        AZURE_OPENAI_API_VERSION: '2025-01-01-preview',
    });

    assert.deepEqual(config, {
        endpoint: 'https://example-resource.openai.azure.com/',
        apiKey: 'local-dev-key',
        model: 'gpt-test',
        apiVersion: '2025-01-01-preview',
    });
    assert.ok(createLocalAzureTestSupportClient({
        AZURE_OPENAI_ENDPOINT: 'https://example-resource.openai.azure.com/',
        AZURE_OPENAI_API_KEY: 'local-dev-key',
        AZURE_OPENAI_MODEL: 'gpt-test',
        AZURE_OPENAI_API_VERSION: '2025-01-01-preview',
    }));
});

test('gitignore and example files keep local Azure test support secret-safe', () => {
    const gitignore = fs.readFileSync(path.join(process.cwd(), '..', '.gitignore'), 'utf8');
    const example = fs.readFileSync(path.join(process.cwd(), '..', '.env.test-support.example'), 'utf8');

    assert.match(gitignore, /^\.env\.test\.local$/m);
    assert.match(gitignore, /^config\/local\.\*$/m);
    assert.match(gitignore, /^secrets\/\*$/m);
    assert.match(example, /^AZURE_OPENAI_ENDPOINT=/m);
    assert.match(example, /^AZURE_OPENAI_API_KEY=your-local-dev-key$/m);
});
