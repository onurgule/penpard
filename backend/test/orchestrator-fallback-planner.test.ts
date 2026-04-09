import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorFallbackPlanner } = require('../src/agents/orchestrator/OrchestratorFallbackPlanner') as typeof import('../src/agents/orchestrator/OrchestratorFallbackPlanner');

test('focused fallback planner locks onto operator-specified endpoints and vuln types', () => {
    const planner = new OrchestratorFallbackPlanner();

    const plan = planner.createPlan({
        targetUrl: 'https://app.example.com',
        planRound: 2,
        instructionAnalysis: {
            is_focused: true,
            focused_endpoints: ['https://app.example.com/api/users', 'https://app.example.com/api/orders'],
            focused_vulns: ['IDOR', 'Broken Access Control'],
            skip_recon: true,
            auto_finish: true,
            summary: 'Only test the listed endpoints for authorization flaws',
        },
        startupAuthInventory: null,
        authStartupMode: 'no_credentials',
        discoveredEndpoints: ['https://app.example.com/ignored'],
    });

    assert.match(plan.analysis, /Focused fallback/);
    assert.equal(plan.steps.length, 4);
    assert.equal(plan.steps[0].objective, 'Test https://app.example.com/api/users for IDOR, Broken Access Control');
    assert.deepEqual(plan.steps[0].tools, ['send_http_request', 'generate_payloads']);
    assert.deepEqual(plan.steps[1].tools, ['send_to_scanner']);
});

test('non-focused fallback planner re-centers on target root when no endpoints have been retained', () => {
    const planner = new OrchestratorFallbackPlanner();

    const plan = planner.createPlan({
        targetUrl: 'https://app.example.com/',
        planRound: 3,
        instructionAnalysis: null,
        startupAuthInventory: null,
        authStartupMode: 'no_credentials',
        discoveredEndpoints: [],
    });

    assert.match(plan.analysis, /target root/i);
    assert.equal(plan.steps.length, 1);
    assert.equal(plan.steps[0].objective, 'Test https://app.example.com for common vulns');
    assert.deepEqual(plan.steps[0].tools, ['send_http_request', 'send_to_scanner']);
});
