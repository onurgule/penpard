import test from 'node:test';
import assert from 'node:assert/strict';

import { AuthStateManager } from '../src/services/auth';
import { OrchestratorRequestExecutor } from '../src/agents/orchestrator/OrchestratorRequestExecutor';
import { ToolCall } from '../src/agents/orchestrator/types';

class FakeBurp {
    public readonly sent: Array<Record<string, any>> = [];
    private readonly responses: Array<any>;

    constructor(responses: Array<any> = []) {
        this.responses = [...responses];
    }

    async callTool(tool: string, args: Record<string, any>): Promise<any> {
        switch (tool) {
            case 'get_cookies_and_auth_for_host':
                return { entries: [] };
            case 'get_session_cookies':
                return { cookieHeader: '' };
            case 'get_proxy_history':
                return {
                    items: [{
                        request: 'GET /api/me HTTP/1.1\r\nHost: app.example.com\r\n\r\n',
                        response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}',
                    }],
                };
            case 'send_http_request':
                this.sent.push(args);
                return this.responses.shift() || {
                    statusCode: 200,
                    headers: ['content-type: application/json'],
                    body: '{"ok":true}',
                };
            default:
                return {};
        }
    }
}

async function createExecutor(overrides?: {
    burp?: FakeBurp;
    onRequestAftermath?: (event: { url: string; method: string; statusCode: number }) => void;
    setRateLimitPauseUntil?: (until: Date | null) => void;
    disableDuplicateResponseCache?: boolean;
}) {
    const burp = overrides?.burp || new FakeBurp();
    const authManager = new AuthStateManager('scan-executor-test', 'https://app.example.com');
    await authManager.initialize({ idorUsers: [] }, burp as any);

    return new OrchestratorRequestExecutor({
        scanId: 'scan-executor-test',
        burp: burp as any,
        authManager,
        log: () => {},
        delay: async () => {},
        maxSameRequest: 2,
        disableDuplicateResponseCache: overrides?.disableDuplicateResponseCache,
        rateLimitPauseMs: 60_000,
        setRateLimitPauseUntil: overrides?.setRateLimitPauseUntil || (() => {}),
        onRequestAftermath: overrides?.onRequestAftermath,
    });
}

test('request executor runs transport once per uncached request and records the aftermath separately from exchange evidence', async () => {
    const burp = new FakeBurp();
    const aftermath: Array<{ url: string; method: string; statusCode: number }> = [];
    const executor = await createExecutor({
        burp,
        onRequestAftermath: (event) => aftermath.push(event),
    });
    const toolCall: ToolCall<'send_http_request'> = {
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {},
        },
    };

    const first = await executor.execute(toolCall);
    const second = await executor.execute(toolCall);
    const third = await executor.execute(toolCall);
    const lastExchange = executor.getLastExchange();

    assert.equal(first.cached, undefined);
    assert.equal(second.cached, undefined);
    assert.equal(third.cached, true);
    assert.equal(burp.sent.length, 2);
    assert.equal(aftermath.length, 2);
    assert.deepEqual(
        aftermath.map((event) => ({
            url: event.url,
            method: event.method,
            statusCode: event.statusCode,
        })),
        [
            {
                url: 'https://app.example.com/api/me',
                method: 'GET',
                statusCode: 200,
            },
            {
                url: 'https://app.example.com/api/me',
                method: 'GET',
                statusCode: 200,
            },
        ],
    );
    assert.equal(lastExchange?.action?.args.url, 'https://app.example.com/api/me');
    assert.match(String(lastExchange?.rawRequest || ''), /GET \/api\/me HTTP\/1\.1/);
});

test('request executor can force every scoped replay through Burp instead of returning cached pseudo-traffic', async () => {
    const burp = new FakeBurp();
    const aftermath: Array<{ url: string; method: string; statusCode: number }> = [];
    const executor = await createExecutor({
        burp,
        disableDuplicateResponseCache: true,
        onRequestAftermath: (event) => aftermath.push(event),
    });
    const toolCall: ToolCall<'send_http_request'> = {
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {},
        },
    };

    await executor.execute(toolCall);
    await executor.execute(toolCall);
    const third = await executor.execute(toolCall);

    assert.equal(third.cached, undefined);
    assert.equal(burp.sent.length, 3);
    assert.equal(aftermath.length, 3);
});

test('request executor raises the shared rate-limit pause when Burp returns 429', async () => {
    const pauses: Array<Date | null> = [];
    const executor = await createExecutor({
        burp: new FakeBurp([{
            statusCode: 429,
            headers: ['retry-after: 60'],
            body: 'slow down',
        }]),
        setRateLimitPauseUntil: (until) => pauses.push(until),
    });

    const result = await executor.execute({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/rate-limited',
            headers: {},
        },
    });

    assert.equal(result.rateLimited, true);
    assert.equal(pauses.length, 1);
    assert.ok(pauses[0] instanceof Date);
});
