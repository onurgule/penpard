import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveLlmCallOptions } from '../src/services/llm/LlmTimeoutPolicy';

test('LLM timeout policy applies critical plan budgets to small prompts', () => {
    const options = resolveLlmCallOptions({
        systemPrompt: 'system',
        userPrompt: 'user',
    }, {
        callSite: 'plan_creation',
    });

    assert.equal(options.criticality, 'critical');
    assert.equal(options.firstEventTimeoutMs, 20_000);
    assert.equal(options.attemptTimeoutMs, 45_000);
    assert.equal(options.providerIdleTimeoutMs, 45_000);
    assert.equal(options.maxAttempts, 2);
    assert.equal(options.retryBudgetMs, 150_000);
    assert.equal(options.queueWaitTimeoutMs, null);
    assert.equal(options.queueExecutionTimeoutMs, 155_000);
});

test('LLM timeout policy scales non-critical source-analysis budgets with prompt size tiers', () => {
    const hugePrompt = 'x'.repeat(45_000);
    const options = resolveLlmCallOptions({
        systemPrompt: hugePrompt,
        userPrompt: hugePrompt,
    }, {
        callSite: 'source_analysis',
    });

    assert.equal(options.criticality, 'non_critical');
    assert.equal(options.firstEventTimeoutMs, 15_000);
    assert.equal(options.attemptTimeoutMs, 75_000);
    assert.equal(options.providerIdleTimeoutMs, 75_000);
    assert.equal(options.maxAttempts, 1);
    assert.equal(options.retryBudgetMs, 75_000);
    assert.equal(options.queueWaitTimeoutMs, 30_000);
    assert.equal(options.queueExecutionTimeoutMs, 80_000);
});

