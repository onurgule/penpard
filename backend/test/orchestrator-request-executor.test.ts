import test from 'node:test';
import assert from 'node:assert/strict';

import { AuthStateManager } from '../src/services/auth';
import { OrchestratorRequestExecutor } from '../src/agents/orchestrator/OrchestratorRequestExecutor';

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
    onEndpointDiscovered?: (url: string) => void;
    setRateLimitPauseUntil?: (until: Date | null) => void;
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
        rateLimitPauseMs: 60_000,
        setRateLimitPauseUntil: overrides?.setRateLimitPauseUntil || (() => {}),
        onEndpointDiscovered: overrides?.onEndpointDiscovered,
    });
}

test('request executor caches the third identical request and preserves the last Burp-backed exchange', async () => {
    const burp = new FakeBurp();
    const discovered: string[] = [];
    const executor = await createExecutor({
        burp,
        onEndpointDiscovered: (url) => discovered.push(url),
    });
    const toolCall = {
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
    assert.deepEqual(discovered, [
        'https://app.example.com/api/me',
        'https://app.example.com/api/me',
    ]);
    assert.equal(lastExchange?.action?.args.url, 'https://app.example.com/api/me');
    assert.match(String(lastExchange?.rawRequest || ''), /GET \/api\/me HTTP\/1\.1/);
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
