import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorPlanner } = require('../src/agents/orchestrator/OrchestratorPlanner') as typeof import('../src/agents/orchestrator/OrchestratorPlanner');
const { OrchestratorLlmResponseParser } = require('../src/agents/orchestrator/OrchestratorLlmResponseParser') as typeof import('../src/agents/orchestrator/OrchestratorLlmResponseParser');
const { llmRuntime } = require('../src/services/llm/LlmRuntime') as typeof import('../src/services/llm/LlmRuntime');

test('planner creates a plan through the extracted LLM decision layer', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const planner = new OrchestratorPlanner({
        parser,
        delay: async () => {},
        handleRateLimitError: () => {},
    });
    const conversationHistory: Array<{ role: string; content: string }> = [];
    const originalGenerate = llmRuntime.generate;

    llmRuntime.generate = (async (request: any, metadata: any) => {
        assert.match(request.userPrompt, /Respond with ONLY a valid JSON object/);
        assert.equal(metadata.scanId, 'scan-test');
        assert.equal(metadata.callSite, 'plan_creation');
        return {
            text: JSON.stringify({
                analysis: 'Continue validating the authenticated API surface',
                plan: [
                    { objective: 'Step 1', approach: 'Approach 1', tools: ['send_http_request'] },
                    { objective: 'Step 2', approach: 'Approach 2', tools: ['send_http_request'] },
                    { objective: 'Step 3', approach: 'Approach 3', tools: ['browser_navigate'] },
                    { objective: 'Step 4', approach: 'Approach 4', tools: ['harvest_traffic'] },
                    { objective: 'Step 5', approach: 'Approach 5', tools: ['repeater_test'] },
                ],
            }),
        };
    }) as any;

    try {
        const result = await planner.createPlan({
            scanId: 'scan-test',
            systemPrompt: 'system',
            conversationHistory,
            rateLimitPauseUntil: null,
            planRound: 2,
            findingsCount: 1,
            endpointsSummary: '/api/me, /api/admin',
            previousResults: 'No repeated tests yet.',
            authStartupSummary: 'Browser-driven auth startup already captured session transport.',
            authStartupDirective: 'Stay auth-surface-first.',
            operatorInstructionsReminder: '',
            mindsetTtps: 'None loaded — no past reports analyzed yet.',
        });

        assert.ok(result);
        assert.equal(result.kind, 'plan');
        assert.equal(result.plan.analysis, 'Continue validating the authenticated API surface');
        assert.equal(result.plan.steps.length, 5);
        assert.equal(result.plan.steps[2].tools[0], 'browser_navigate');
        assert.equal(conversationHistory[0].role, 'user');
        assert.equal(conversationHistory[1].role, 'assistant');
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});
