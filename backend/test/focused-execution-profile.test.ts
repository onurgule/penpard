import test from 'node:test';
import assert from 'node:assert/strict';

import { FocusedExecutionProfileResolver } from '../src/services/runtime/FocusedExecutionProfiles';

test('focused execution profile resolver prefers the local Qwen profile when local_llm is active', () => {
    const resolver = new FocusedExecutionProfileResolver({
        generate: (async () => {
            throw new Error('not used');
        }) as any,
        getActiveConfig: (() => ({
            provider: 'local_llm',
            api_key: '',
            model: 'Qwen3-32B',
            is_active: 1,
            is_online: 1,
            settings_json: '{}',
        })) as any,
    });

    const profile = resolver.resolve(1);
    assert.equal(profile.key, 'local_qwen');
    assert.equal(profile.provider, 'local_llm');
});

test('focused execution profile resolver keeps product-level execution generic for non-Qwen providers', () => {
    const resolver = new FocusedExecutionProfileResolver({
        generate: (async () => {
            throw new Error('not used');
        }) as any,
        getActiveConfig: (() => ({
            provider: 'openai',
            api_key: 'sk-test',
            model: 'gpt-5',
            is_active: 1,
            is_online: 1,
            settings_json: '{}',
        })) as any,
    });

    const profile = resolver.resolve(1);
    assert.equal(profile.key, 'generic:openai');
    assert.equal(profile.provider, 'openai');
});

test('focused execution profile resolver falls back cleanly when no provider is configured', () => {
    const resolver = new FocusedExecutionProfileResolver({
        generate: (async () => {
            throw new Error('not used');
        }) as any,
        getActiveConfig: (() => {
            throw new Error('No active LLM provider configured.');
        }) as any,
    });

    const profile = resolver.resolve(1);
    assert.equal(profile.key, 'generic:fallback');
    assert.equal(profile.provider, null);
});
