import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveLlmCallOptions } from '../src/services/llm/LlmTimeoutPolicy';

test('LLM timeout policy derives warning and watchdog defaults without provider output deadlines', () => {
    const options = resolveLlmCallOptions({
        systemPrompt: 'system',
        userPrompt: 'user',
    }, {
        callSite: 'plan_creation',
    });

    assert.equal(options.criticality, 'critical');
    assert.equal(options.slowFirstProgressWarningMs, 20_000);
    assert.equal(options.finalizationGraceMs, 15_000);
    assert.equal(options.maxAttempts, 2);
    assert.equal(options.retryBudgetMs, 150_000);
    assert.equal(options.queueWaitTimeoutMs, null);
    assert.equal(options.executionWatchdogMs, 170_000);
});

test('LLM timeout policy keeps non-critical defaults stable for large prompts', () => {
    const hugePrompt = 'x'.repeat(45_000);
    const options = resolveLlmCallOptions({
        systemPrompt: hugePrompt,
        userPrompt: hugePrompt,
    }, {
        callSite: 'source_analysis',
    });

    assert.equal(options.criticality, 'non_critical');
    assert.equal(options.slowFirstProgressWarningMs, 15_000);
    assert.equal(options.finalizationGraceMs, 15_000);
    assert.equal(options.maxAttempts, 1);
    assert.equal(options.retryBudgetMs, 75_000);
    assert.equal(options.queueWaitTimeoutMs, 30_000);
    assert.equal(options.executionWatchdogMs, 95_000);
});
