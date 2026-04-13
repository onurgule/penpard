import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorPlanner } = require('../src/agents/orchestrator/OrchestratorPlanner') as typeof import('../src/agents/orchestrator/OrchestratorPlanner');
const { OrchestratorLlmResponseParser } = require('../src/agents/orchestrator/OrchestratorLlmResponseParser') as typeof import('../src/agents/orchestrator/OrchestratorLlmResponseParser');
const { llmRuntime } = require('../src/services/llm/LlmRuntime') as typeof import('../src/services/llm/LlmRuntime');
const { LlmExecutionError } = require('../src/services/llm/LlmRuntimeTypes') as typeof import('../src/services/llm/LlmRuntimeTypes');
const { EndpointIntelligenceService } = require('../src/services/EndpointIntelligenceService') as typeof import('../src/services/EndpointIntelligenceService');
const { browserService } = require('../src/services/BrowserService') as typeof import('../src/services/BrowserService');
import fs from 'fs';
import os from 'os';
import path from 'path';

test('planner returns null for timed-out plan creation so higher layers can fall back', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const planner = new OrchestratorPlanner({
        parser,
        delay: async () => {},
        handleRateLimitError: () => {},
    });
    const originalGenerate = llmRuntime.generate;

    llmRuntime.generate = (async () => {
        throw new LlmExecutionError({
            failureCategory: 'provider_call_timeout',
            message: 'provider call timed out',
        });
    }) as any;

    try {
        const result = await planner.createPlan({
            scanId: 'scan-timeout',
            systemPrompt: 'system',
            conversationHistory: [],
            rateLimitPauseUntil: null,
            planRound: 1,
            findingsCount: 0,
            endpointsSummary: 'None',
            previousResults: 'None',
            authStartupSummary: 'None',
            authStartupDirective: 'None',
            operatorInstructionsReminder: '',
            mindsetTtps: 'None',
        });

        assert.equal(result, null);
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});

test('planner falls back to continue-testing on replan timeout before the final round', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const planner = new OrchestratorPlanner({
        parser,
        delay: async () => {},
        handleRateLimitError: () => {},
    });
    const originalGenerate = llmRuntime.generate;

    llmRuntime.generate = (async () => {
        throw new LlmExecutionError({
            failureCategory: 'provider_call_timeout',
            message: 'provider call timed out',
        });
    }) as any;

    try {
        const shouldContinue = await planner.shouldContinueTesting({
            scanId: 'scan-timeout',
            systemPrompt: 'system',
            conversationHistory: [],
            rateLimitPauseUntil: null,
            roundResults: [],
            findings: [],
            discoveredEndpoints: [],
            hypothesisStatus: 'None',
            coverageStatus: 'None',
            operatorInstructionsReminder: '',
            planRound: 2,
        });

        assert.equal(shouldContinue, true);
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});

test('planner returns null for step execution timeouts without crashing the round', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const planner = new OrchestratorPlanner({
        parser,
        delay: async () => {},
        handleRateLimitError: () => {},
    });
    const originalGenerate = llmRuntime.generate;

    llmRuntime.generate = (async () => {
        throw new LlmExecutionError({
            failureCategory: 'provider_call_timeout',
            message: 'provider call timed out',
        });
    }) as any;

    try {
        const result = await planner.askForStepExecution({
            scanId: 'scan-timeout',
            systemPrompt: 'system',
            conversationHistory: [],
            rateLimitPauseUntil: null,
            step: {
                step: 1,
                objective: 'Test auth flow',
                approach: 'Probe endpoint',
                tools: ['send_http_request'],
                status: 'pending',
            },
            previousResults: [],
            totalActions: 0,
            budgetPressureReminder: '',
            operatorInstructionsReminder: '',
        });

        assert.equal(result, null);
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});

test('planner parse-failure logging reports only response size instead of raw invalid output', async () => {
    const parser = new OrchestratorLlmResponseParser('https://app.example.com', () => false);
    const logMessages: string[] = [];
    const planner = new OrchestratorPlanner({
        parser,
        delay: async () => {},
        handleRateLimitError: () => {},
        log: (_channel, message) => {
            logMessages.push(message);
        },
    });
    const originalGenerate = llmRuntime.generate;
    let callCount = 0;

    llmRuntime.generate = (async () => {
        callCount += 1;
        return {
            text: callCount === 1
                ? 'not-json https://10.0.0.8/internal Authorization: Bearer top-secret'
                : 'still-not-json',
        } as any;
    }) as any;

    try {
        const result = await planner.createPlan({
            scanId: 'scan-invalid-json-log',
            systemPrompt: 'system',
            conversationHistory: [],
            rateLimitPauseUntil: null,
            planRound: 1,
            findingsCount: 0,
            endpointsSummary: 'None',
            previousResults: 'None',
            authStartupSummary: 'None',
            authStartupDirective: 'None',
            operatorInstructionsReminder: '',
            mindsetTtps: 'None',
        });

        assert.equal(result, null);
        const warning = logMessages.find((message) => message.includes('Plan JSON parse failed'));
        assert.ok(warning);
        assert.ok(!warning?.includes('10.0.0.8'));
        assert.ok(!warning?.includes('top-secret'));
        assert.match(warning || '', /\(\d+ chars\)/);
    } finally {
        llmRuntime.generate = originalGenerate;
    }
});

test('endpoint intelligence continues building deterministic inventory when AI classification times out', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-endpoint-timeout-'));
    const scriptPath = path.join(tempDir, 'app.js');
    fs.writeFileSync(scriptPath, `fetch('/api/profile');`, 'utf8');

    const originalCapture = browserService.captureJavaScriptArtifacts.bind(browserService);
    const originalTraffic = browserService.getTrafficSnapshot.bind(browserService);
    const originalGenerate = llmRuntime.generate;

    (browserService as any).captureJavaScriptArtifacts = async () => ([{
        id: 'artifact-1',
        sessionId: 'session-1',
        pageUrl: 'http://target.local/login',
        scriptUrl: 'http://target.local/assets/app.js',
        origin: 'http://target.local',
        type: 'external',
        contentType: 'application/javascript',
        contentHash: 'hash-1',
        bytes: fs.statSync(scriptPath).size,
        storedAt: new Date().toISOString(),
        filePath: scriptPath,
        evidence: [],
    }]);
    (browserService as any).getTrafficSnapshot = () => ([]);
    llmRuntime.generate = (async () => {
        throw new LlmExecutionError({
            failureCategory: 'provider_first_event_timeout',
            message: 'No first event arrived in time.',
        });
    }) as any;

    try {
        const service = new EndpointIntelligenceService('scan-js-timeout', 'http://target.local', {
            callTool: async () => ({ content: [{ text: '{"items":[]}' }] }),
        } as any);

        const inventory = await service.buildInventory({
            browserSessionId: 'session-1',
            allowAiClassification: true,
        });

        assert.ok(inventory.records.some((record) => record.path.includes('/api/profile')));
        assert.ok(!inventory.records.some((record) => record.inferredOnly));
    } finally {
        (browserService as any).captureJavaScriptArtifacts = originalCapture;
        (browserService as any).getTrafficSnapshot = originalTraffic;
        llmRuntime.generate = originalGenerate;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
