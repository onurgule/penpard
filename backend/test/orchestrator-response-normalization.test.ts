import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorLlmResponseParser } = require('../src/agents/orchestrator/OrchestratorLlmResponseParser') as typeof import('../src/agents/orchestrator/OrchestratorLlmResponseParser');
const { OrchestratorContextSignals } = require('../src/agents/orchestrator/OrchestratorContextSignals') as typeof import('../src/agents/orchestrator/OrchestratorContextSignals');

function createParser() {
    return new OrchestratorLlmResponseParser('https://app.example.com', () => false);
}

test('parseAgentResponse recovers tool wrappers and preserves reflection fields', () => {
    const parser = createParser();
    const parsed = parser.parseAgentResponse(`Tool call:
{
  "name": "sendHttpRequest",
  "arguments": "{\\"url\\":\\"https://app.example.com/api/me\\",\\"method\\":\\"post\\"}",
  "evaluation_previous_goal": "Confirmed the SPA bootstrapped an authenticated session",
  "memory": "Preserve explicit auth headers when replaying requests",
  "next_goal": "Replay the JSON API through Burp to validate session correctness"
}`);

    assert.ok(parsed);
    assert.equal(parsed.action.tool, 'send_http_request');
    assert.equal(parsed.action.args.url, 'https://app.example.com/api/me');
    assert.equal(parsed.action.args.method, 'POST');
    assert.equal(parsed.reflection?.evaluationPreviousGoal, 'Confirmed the SPA bootstrapped an authenticated session');
    assert.equal(parsed.reflection?.memory, 'Preserve explicit auth headers when replaying requests');
    assert.equal(parsed.reflection?.nextGoal, 'Replay the JSON API through Burp to validate session correctness');
});

test('parseAgentResponse canonicalizes action names and coerces primitive tool input', () => {
    const parser = createParser();
    const parsed = parser.parseAgentResponse(JSON.stringify({
        action: {
            browserNavigate: 'https://app.example.com/account',
        },
        next_goal: 'Inspect the authenticated account surface',
    }));

    assert.ok(parsed);
    assert.equal(parsed.action.tool, 'browser_navigate');
    assert.equal(parsed.action.args.url, 'https://app.example.com/account');
    assert.equal(parsed.reflection?.nextGoal, 'Inspect the authenticated account surface');
});

test('parseAgentResponse reuses root-level parameters for string action names', () => {
    const parser = createParser();
    const parsed = parser.parseAgentResponse(JSON.stringify({
        action: 'getProxyHistory',
        count: 8,
        memory: 'Stay focused on real user traffic only',
    }));

    assert.ok(parsed);
    assert.equal(parsed.action.tool, 'get_proxy_history');
    assert.equal(parsed.action.args.count, 8);
    assert.equal(parsed.action.args.excludePenPard, true);
    assert.equal(parsed.reflection?.memory, 'Stay focused on real user traffic only');
});

test('budget pressure reminders emit only at tightening and critical thresholds', () => {
    const logs: string[] = [];
    const signals = new OrchestratorContextSignals((_channel, message) => logs.push(message));

    const early = signals.buildBudgetPressureReminder(3, 12);
    const tightening = signals.buildBudgetPressureReminder(7, 12);
    const tighteningAgain = signals.buildBudgetPressureReminder(8, 12);
    const critical = signals.buildBudgetPressureReminder(10, 12);

    assert.equal(early, '');
    assert.match(tightening, /ACTION BUDGET WARNING/);
    assert.match(tighteningAgain, /ACTION BUDGET WARNING/);
    assert.match(critical, /ACTION BUDGET WARNING/);

    const tighteningLogs = logs.filter((line: string) => line.includes('Action budget tightening:'));
    const criticalLogs = logs.filter((line: string) => line.includes('Action budget critical:'));

    assert.equal(tighteningLogs.length, 1);
    assert.equal(criticalLogs.length, 1);
});
