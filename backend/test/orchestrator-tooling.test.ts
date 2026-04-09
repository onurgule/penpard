import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorToolDispatcher } = require('../src/agents/orchestrator/OrchestratorToolDispatcher') as typeof import('../src/agents/orchestrator/OrchestratorToolDispatcher');
const {
    evaluateToolExecutionGuard,
    hasCustomAuthHeader,
    resolveAuthIdentityId,
    resolveRequestAuthIntent,
} = require('../src/agents/orchestrator/OrchestratorToolPolicy') as typeof import('../src/agents/orchestrator/OrchestratorToolPolicy');

test('dispatcher executes through the extracted handler registry and reports unknown tools cleanly', async () => {
    const logs: string[] = [];
    const dispatcher = new OrchestratorToolDispatcher({
        log: (_channel, message) => logs.push(message),
        guard: () => null,
        handlers: {
            ping: async (toolCall) => ({ echoed: toolCall.args.value }),
        },
    });

    const executed = await dispatcher.execute({ tool: 'ping', args: { value: 'ok' } });
    const missing = await dispatcher.execute({ tool: 'missing', args: {} });

    assert.deepEqual(executed, { echoed: 'ok' });
    assert.match(String(missing.error), /Available: ping/);
    assert.ok(logs.some((entry) => entry.includes('Executing: ping')));
});

test('tool policy blocks focused-scope enumeration and active rate limits', () => {
    const focusedBlock = evaluateToolExecutionGuard({
        toolName: 'spider_url',
        isFocusedScope: true,
        rateLimitPauseUntil: null,
    });

    const rateLimited = evaluateToolExecutionGuard({
        toolName: 'send_http_request',
        isFocusedScope: false,
        rateLimitPauseUntil: new Date(Date.now() + 60_000),
        now: new Date(),
    });

    assert.equal(focusedBlock.allowed, false);
    assert.equal(focusedBlock.response.blocked, true);
    assert.equal(rateLimited.allowed, false);
    assert.equal(rateLimited.response.skipped, true);
});

test('auth helpers preserve explicit control over identity and intent resolution', () => {
    assert.equal(resolveAuthIdentityId({ identityId: 'idor-user-1' }), 'idor-user-1');
    assert.equal(resolveAuthIdentityId({ disableAutoAuth: true }), '__none__');
    assert.equal(resolveAuthIdentityId(undefined), 'primary-user');

    assert.equal(hasCustomAuthHeader({ 'X-Api-Key': 'secret' }), true);
    assert.equal(hasCustomAuthHeader({ Authorization: 'Bearer token' }), false);

    const explicit = resolveRequestAuthIntent({
        requestedIntent: 'session_refresh',
        inferIntent: () => 'authenticated',
    });
    const inferredAnonymous = resolveRequestAuthIntent({
        identityId: '__none__',
        inferIntent: () => 'authenticated',
    });

    assert.equal(explicit, 'session_refresh');
    assert.equal(inferredAnonymous, 'unknown');
});
