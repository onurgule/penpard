import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorStartupCoordinator } = require('../src/agents/orchestrator/OrchestratorStartupCoordinator') as typeof import('../src/agents/orchestrator/OrchestratorStartupCoordinator');

// ── Helpers ──

function createStubDeps(overrides: Partial<import('../src/agents/orchestrator/OrchestratorStartupCoordinator').StartupCoordinatorDeps> = {}): import('../src/agents/orchestrator/OrchestratorStartupCoordinator').StartupCoordinatorDeps {
    const logs: string[] = [];
    return {
        burp: {
            isAvailable: async () => true,
            callTool: async () => ({ ok: true }),
        },
        llm: {
            hasActiveConfig: () => true,
        },
        mindset: {
            getRelevantTTPs: () => [],
        },
        authManager: {
            initialize: async () => {},
            identityRegistry: { size: 1 },
            getTotalCookies: () => 2,
            getTotalTokens: () => 1,
            getSystemPromptBlock: () => '[session-cookies-block]',
        },
        scanSurface: {
            runAuthStartup: async () => {},
            buildStartupAuthPromptBlock: () => '[startup-auth-block]',
            buildEndpointInventoryPromptBlock: () => '[endpoint-inventory-block]',
            getStartupAuthInventory: () => null,
            getEndpointInventory: () => null,
            buildStartupAuthSummary: () => '',
            buildEndpointInventorySummary: () => '',
        },
        browserSession: {
            getSessionId: () => 'browser-session-1',
        },
        sourceAnalyzer: undefined,
        log: (channel: string, message: string) => { logs.push(`[${channel}] ${message}`); },
        ...overrides,
    };
}

function createBaseConfig(): import('../src/agents/orchestrator/OrchestratorStartupCoordinator').StartupConfig {
    return {
        scanId: 'scan-test-1',
        targetUrl: 'https://target.example.com',
    };
}

// ── Tests ──

test('startup coordinator returns a complete StartupResult with all prompt blocks', async () => {
    const deps = createStubDeps();
    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    assert.deepEqual(result.mindsetTTPs, []);
    assert.equal(result.sourceContextBlock, '');
    assert.equal(result.sessionCookiesBlock, '[session-cookies-block]');
    assert.equal(result.startupAuthBlock, '[startup-auth-block]');
    assert.equal(result.endpointInventoryBlock, '[endpoint-inventory-block]');
});

test('startup coordinator enforces auth-first ordering: auth init → auth startup → source analysis', async () => {
    const callOrder: string[] = [];

    const deps = createStubDeps({
        authManager: {
            initialize: async () => { callOrder.push('auth-init'); },
            identityRegistry: { size: 0 },
            getTotalCookies: () => 0,
            getTotalTokens: () => 0,
            getSystemPromptBlock: () => '',
        },
        scanSurface: {
            runAuthStartup: async () => { callOrder.push('auth-startup'); },
            buildStartupAuthPromptBlock: () => '',
            buildEndpointInventoryPromptBlock: () => '',
            getStartupAuthInventory: () => null,
            getEndpointInventory: () => null,
            buildStartupAuthSummary: () => '',
            buildEndpointInventorySummary: () => '',
        },
        sourceAnalyzer: {
            analyzeSource: async () => {
                callOrder.push('source-analysis');
                return { framework: 'express', dependencies: [], cves: [] };
            },
            buildAgentContextBlock: () => '[source-context]',
        },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = {
        ...createBaseConfig(),
        sourcePackagePath: '/path/to/source',
        sourceAnalysisMode: 'version_aware',
    };

    await coordinator.run(config);

    assert.equal(callOrder[0], 'auth-init', 'Auth init must run first');
    assert.equal(callOrder[1], 'auth-startup', 'Auth startup must run second');
    assert.equal(callOrder[2], 'source-analysis', 'Source analysis must run third (after auth)');
});

test('startup coordinator throws on missing LLM — hard requirement', async () => {
    const deps = createStubDeps({
        llm: { hasActiveConfig: () => false },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);

    await assert.rejects(
        coordinator.run(createBaseConfig()),
        /No active LLM configured/,
    );
});

test('startup coordinator handles Burp unavailability gracefully (logs error, continues)', async () => {
    const logs: string[] = [];
    const deps = createStubDeps({
        burp: {
            isAvailable: async () => false,
            callTool: async () => { throw new Error('should not be called'); },
        },
        log: (channel: string, message: string) => { logs.push(`[${channel}] ${message}`); },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    // Should complete successfully despite Burp being unavailable
    assert.ok(result);
    assert.ok(logs.some(l => l.includes('Burp MCP not available')));
});

test('startup coordinator loads mindset TTPs when enabled', async () => {
    const fakeTTPs = [
        { id: 'ttp-1', name: 'SQL Injection', confidence: 0.9 },
        { id: 'ttp-2', name: 'XSS', confidence: 0.8 },
    ];

    const deps = createStubDeps({
        mindset: { getRelevantTTPs: () => fakeTTPs as any },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    assert.equal(result.mindsetTTPs.length, 2);
    assert.equal(result.mindsetTTPs[0].id, 'ttp-1');
});

test('startup coordinator skips mindset TTPs when disabled', async () => {
    const deps = createStubDeps({
        mindset: { getRelevantTTPs: () => { throw new Error('should not be called'); } },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = { ...createBaseConfig(), useMindsetLibrary: false };
    const result = await coordinator.run(config);

    assert.deepEqual(result.mindsetTTPs, []);
});

test('startup coordinator handles mindset loading failure gracefully', async () => {
    const logs: string[] = [];
    const deps = createStubDeps({
        mindset: { getRelevantTTPs: () => { throw new Error('DB connection failed'); } },
        log: (channel: string, message: string) => { logs.push(`[${channel}] ${message}`); },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    assert.deepEqual(result.mindsetTTPs, []);
    assert.ok(logs.some(l => l.includes('Failed to load mindset library')));
});

test('startup coordinator runs source analysis and returns context block', async () => {
    const deps = createStubDeps({
        sourceAnalyzer: {
            analyzeSource: async () => ({
                framework: 'express',
                dependencies: [{ name: 'express', version: '4.18.2' }],
                cves: [{ id: 'CVE-2024-1234' }],
            }),
            buildAgentContextBlock: (result: any) => `[source: ${result.framework}]`,
        },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = {
        ...createBaseConfig(),
        sourcePackagePath: '/path/to/source',
        sourceAnalysisMode: 'version_aware',
    };

    const result = await coordinator.run(config);
    assert.equal(result.sourceContextBlock, '[source: express]');
});

test('startup coordinator skips source analysis when no path is configured', async () => {
    const sourceAnalyzerCalled = { called: false };
    const deps = createStubDeps({
        sourceAnalyzer: {
            analyzeSource: async () => { sourceAnalyzerCalled.called = true; return {} as any; },
            buildAgentContextBlock: () => 'should not appear',
        },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    assert.equal(result.sourceContextBlock, '');
    assert.equal(sourceAnalyzerCalled.called, false);
});

test('startup coordinator handles source analysis failure gracefully', async () => {
    const logs: string[] = [];
    const deps = createStubDeps({
        sourceAnalyzer: {
            analyzeSource: async () => { throw new Error('Source path not found'); },
            buildAgentContextBlock: () => '',
        },
        log: (channel: string, message: string) => { logs.push(`[${channel}] ${message}`); },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = {
        ...createBaseConfig(),
        sourcePackagePath: '/nonexistent',
        sourceAnalysisMode: 'version_aware',
    };

    const result = await coordinator.run(config);

    assert.equal(result.sourceContextBlock, '');
    assert.ok(logs.some(l => l.includes('Source analysis failed')));
});

test('startup coordinator initializes auth engine with correct config', async () => {
    let capturedConfig: any = null;

    const deps = createStubDeps({
        authManager: {
            initialize: async (config: any) => { capturedConfig = config; },
            identityRegistry: { size: 0 },
            getTotalCookies: () => 0,
            getTotalTokens: () => 0,
            getSystemPromptBlock: () => '',
        },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = {
        ...createBaseConfig(),
        sessionCookies: 'sid=abc123',
        idorUsers: [{ username: 'user2', password: 'pass2' }],
        initialRequest: 'GET /api/me HTTP/1.1\r\nHost: target.example.com',
        authStartup: {
            mode: 'provided_credentials' as const,
            credentials: [{ username: 'admin', password: 'admin123' }],
            allowAccountCreation: false,
            preferSharedPassword: true,
        },
    };

    await coordinator.run(config);

    assert.ok(capturedConfig);
    assert.equal(capturedConfig.sessionCookies, 'sid=abc123');
    assert.equal(capturedConfig.idorUsers.length, 1);
    assert.equal(capturedConfig.initialRequest, config.initialRequest);
    assert.equal(capturedConfig.authStartup.mode, 'provided_credentials');
});

test('startup coordinator Burp scope addition failure is non-fatal', async () => {
    const logs: string[] = [];
    const deps = createStubDeps({
        burp: {
            isAvailable: async () => true,
            callTool: async () => { throw new Error('Scope addition failed'); },
        },
        log: (channel: string, message: string) => { logs.push(`[${channel}] ${message}`); },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    assert.ok(result);
    assert.ok(logs.some(l => l.includes('Scope error')));
});

test('startup coordinator passes auth startup config to scan surface', async () => {
    let capturedAuthConfig: any = null;

    const deps = createStubDeps({
        scanSurface: {
            runAuthStartup: async (config: any) => { capturedAuthConfig = config; },
            buildStartupAuthPromptBlock: () => '',
            buildEndpointInventoryPromptBlock: () => '',
            getStartupAuthInventory: () => null,
            getEndpointInventory: () => null,
            buildStartupAuthSummary: () => '',
            buildEndpointInventorySummary: () => '',
        },
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const config = {
        ...createBaseConfig(),
        authStartup: {
            mode: 'provided_credentials' as const,
            credentials: [{ username: 'test', password: 'test' }],
            allowAccountCreation: true,
            preferSharedPassword: false,
        },
    };

    await coordinator.run(config);

    assert.ok(capturedAuthConfig);
    assert.equal(capturedAuthConfig.mode, 'provided_credentials');
    assert.equal(capturedAuthConfig.credentials.length, 1);
    assert.equal(capturedAuthConfig.allowAccountCreation, true);
});

test('startup coordinator full pipeline produces correct data flow', async () => {
    const callOrder: string[] = [];

    const deps = createStubDeps({
        burp: {
            isAvailable: async () => { callOrder.push('burp-check'); return true; },
            callTool: async () => { callOrder.push('burp-scope'); return {}; },
        },
        llm: {
            hasActiveConfig: () => { callOrder.push('llm-check'); return true; },
        },
        mindset: {
            getRelevantTTPs: () => { callOrder.push('mindset-load'); return []; },
        },
        authManager: {
            initialize: async () => { callOrder.push('auth-init'); },
            identityRegistry: { size: 2 },
            getTotalCookies: () => 3,
            getTotalTokens: () => 1,
            getSystemPromptBlock: () => { callOrder.push('auth-prompt'); return '[cookies]'; },
        },
        scanSurface: {
            runAuthStartup: async () => { callOrder.push('auth-startup'); },
            buildStartupAuthPromptBlock: () => { callOrder.push('auth-block'); return '[auth]'; },
            buildEndpointInventoryPromptBlock: () => { callOrder.push('endpoint-block'); return '[endpoints]'; },
            getStartupAuthInventory: () => null,
            getEndpointInventory: () => null,
            buildStartupAuthSummary: () => '',
            buildEndpointInventorySummary: () => '',
        },
        log: () => {},
    });

    const coordinator = new OrchestratorStartupCoordinator(deps);
    const result = await coordinator.run(createBaseConfig());

    // Verify ordering: burp → llm → mindset → auth-init → auth-startup → blocks
    assert.equal(callOrder[0], 'burp-check');
    assert.equal(callOrder[1], 'burp-scope');
    assert.equal(callOrder[2], 'llm-check');
    assert.equal(callOrder[3], 'mindset-load');
    assert.equal(callOrder[4], 'auth-init');
    assert.equal(callOrder[5], 'auth-startup');

    // Verify result correctness
    assert.equal(result.sessionCookiesBlock, '[cookies]');
    assert.equal(result.startupAuthBlock, '[auth]');
    assert.equal(result.endpointInventoryBlock, '[endpoints]');
});
