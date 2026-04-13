import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorToolHost } = require('../src/agents/orchestrator/OrchestratorToolHost') as typeof import('../src/agents/orchestrator/OrchestratorToolHost');

function createToolHost(overrides: Partial<ConstructorParameters<typeof OrchestratorToolHost>[0]> = {}) {
    const executed: string[] = [];
    const options: ConstructorParameters<typeof OrchestratorToolHost>[0] = {
        burp: {
            callTool: async (tool: string) => ({ tool }),
        } as any,
        targetUrl: 'https://app.example.com',
        requestExecutor: {
            execute: async () => {
                executed.push('request');
                return { ok: true };
            },
        } as any,
        browserTools: {
            navigate: async () => ({ navigated: true }),
            getPageState: async () => ({ title: 'page' }),
            getFrontendAnalysis: async () => ({ apiEndpoints: [] }),
            fillAndSubmit: async () => ({ submitted: true }),
            evaluateJs: async () => ({ result: 'ok' }),
            screenshot: async () => ({ image: 'png' }),
            correlateBurp: async () => ({ correlated: true }),
        } as any,
        domainCoordinator: {
            executeHarvestTraffic: async () => ({ harvested: true }),
            executeGetHypotheses: async () => ({ hypotheses: [] }),
            executeGetCoverage: async () => ({ coverage: 50 }),
            executeRepeaterTest: async () => ({ repeated: true }),
        } as any,
        isFocusedScope: () => false,
        getRateLimitPauseUntil: () => null,
        log: () => {},
    };

    const host = new OrchestratorToolHost({ ...options, ...overrides });
    return { host, executed };
}

test('tool host centralizes active tool execution and parser-facing tool normalization', async () => {
    const { host, executed } = createToolHost();

    const result = await host.execute({
        tool: 'send_http_request',
        args: { url: 'https://app.example.com/api/me', method: 'GET' },
    });
    const parserRegistry = host.getParserToolRegistry();
    const normalized = parserRegistry.normalizeToolCall(
        { name: 'browserNavigate', arguments: 'https://app.example.com/account' },
        (value: any) => value,
    );

    assert.deepEqual(result, { ok: true });
    assert.deepEqual(executed, ['request']);
    assert.equal(parserRegistry.isKnown('getProxyHistory'), true);
    assert.deepEqual(normalized, {
        tool: 'browser_navigate',
        args: { url: 'https://app.example.com/account' },
    });
});

test('tool host preserves execution guards for the canonical single-agent runtime', async () => {
    const { host } = createToolHost({
        isFocusedScope: () => true,
    });

    const blocked = await host.execute({
        tool: 'spider_url',
        args: { url: 'https://app.example.com' },
    });

    assert.equal(blocked.blocked, true);
    assert.match(String(blocked.error), /specific scope/i);
});
