import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorInstructionAnalyzer } = require('../src/agents/orchestrator/OrchestratorInstructionAnalyzer') as typeof import('../src/agents/orchestrator/OrchestratorInstructionAnalyzer');
const { OrchestratorLlmResponseParser } = require('../src/agents/orchestrator/OrchestratorLlmResponseParser') as typeof import('../src/agents/orchestrator/OrchestratorLlmResponseParser');
const { llmRuntime } = require('../src/services/llm/LlmRuntime') as typeof import('../src/services/llm/LlmRuntime');

test('instruction analyzer returns structured focused scope data', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const analyzer = new OrchestratorInstructionAnalyzer(parser);
    const originalGenerate = llmRuntime.generate;

    llmRuntime.generate = (async (_request: any, metadata: any) => ({
        text: '```json\n{"is_focused":true,"focused_endpoints":["https://app.example.com/login"],"focused_vulns":["SQL Injection"],"skip_recon":true,"auto_finish":true,"summary":"Test only /login for SQL injection, then finish"}\n```',
        usage: undefined,
    })) as any;

    try {
        const analysis = await analyzer.analyze(
            'only focus on /login endpoint and test for sql injection only, then finish',
            'https://app.example.com',
            'scan-test',
        );

        assert.ok(analysis);
        assert.equal(analysis.is_focused, true);
        assert.deepEqual(analysis.focused_endpoints, ['https://app.example.com/login']);
        assert.deepEqual(analysis.focused_vulns, ['SQL Injection']);
        assert.equal(analysis.skip_recon, true);
        assert.equal(analysis.auto_finish, true);
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});
