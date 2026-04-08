import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';

import { AuthStateManager } from '../src/services/auth';
import { parseRawBurpRequest, serializeStructuredBurpRequest } from '../src/services/burp-request';

process.env.DATABASE_PATH = process.env.DATABASE_PATH || path.join(process.cwd(), 'tmp', 'penpard-test.db');
const { OrchestratorAgent } = require('../src/agents/OrchestratorAgent') as typeof import('../src/agents/OrchestratorAgent');

function makeJwt(exp: number): string {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({ sub: 'user-1', exp })}.signature`;
}

function buildRawRequest(authHeader: string, cookieHeader: string = 'session=primary'): string {
    return [
        'GET /api/me HTTP/1.1',
        'Host: app.example.com',
        `Authorization: ${authHeader}`,
        `Cookie: ${cookieHeader}`,
        'Accept: application/json',
        '',
        '',
    ].join('\r\n');
}

class FakeBurp {
    public readonly sent: Array<Record<string, any>> = [];
    private readonly responses: Array<Record<string, any>>;
    private readonly entries: Array<Record<string, any>>;

    constructor(opts?: {
        responses?: Array<Record<string, any>>;
        entries?: Array<Record<string, any>>;
    }) {
        this.responses = [...(opts?.responses || [])];
        this.entries = [...(opts?.entries || [])];
    }

    async callTool(tool: string, args: Record<string, any>): Promise<any> {
        switch (tool) {
            case 'get_cookies_and_auth_for_host':
                return { entries: this.entries };
            case 'get_session_cookies':
                return { cookieHeader: '' };
            case 'get_proxy_history':
                return { items: [] };
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

function createAgent(config: Partial<ConstructorParameters<typeof OrchestratorAgent>[2]>, burp: FakeBurp): OrchestratorAgent {
    return new OrchestratorAgent(
        'scan-test',
        'https://app.example.com',
        {
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            ...config,
        },
        burp as any,
    );
}

async function initializeAuth(agent: OrchestratorAgent, burp: FakeBurp, initialRequest?: string): Promise<void> {
    await agent.authManager.initialize({
        idorUsers: [],
        initialRequest,
    }, burp as any);
}

test('Burp initial raw request seeds Authorization for later managed requests', async () => {
    const jwt = makeJwt(Math.floor(Date.now() / 1000) + 3600);
    const manager = new AuthStateManager('scan-test', 'https://app.example.com');
    const burp = new FakeBurp();

    await manager.initialize({
        initialRequest: buildRawRequest(`Bearer ${jwt}`),
    }, burp as any);

    const prepared = manager.prepareRequest(
        undefined,
        '',
        'https://app.example.com/api/me',
        'GET',
        'primary-user',
        false,
    );

    assert.equal(prepared.headers.Authorization, `Bearer ${jwt}`);
    assert.equal(prepared.headers.Cookie, 'session=primary');
});

test('explicit Authorization is not stripped when managed auth store was missing it', async () => {
    const burp = new FakeBurp();
    const agent = createAgent({}, burp);

    await initializeAuth(agent, burp);

    await (agent as any).executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {
                Authorization: 'Bearer copied-token-1234567890',
            },
        },
    });

    assert.equal(burp.sent.length, 1);
    assert.equal(burp.sent[0].headers.Authorization, 'Bearer copied-token-1234567890');
});

test('structured request serialization preserves Authorization header', () => {
    const raw = serializeStructuredBurpRequest({
        method: 'GET',
        url: 'https://app.example.com/api/me?view=full',
        headers: {
            Authorization: 'Bearer serialized-token-1234567890',
            Accept: 'application/json',
        },
    });

    assert.match(raw, /^GET \/api\/me\?view=full HTTP\/1\.1/m);
    assert.match(raw, /^Authorization: Bearer serialized-token-1234567890$/m);

    const parsed = parseRawBurpRequest(raw);
    assert.ok(parsed);
    assert.equal(parsed?.headers.Authorization, 'Bearer serialized-token-1234567890');
});

test('401 without outgoing auth retries once with stored Burp token', async () => {
    const jwt = makeJwt(Math.floor(Date.now() / 1000) + 3600);
    const initialRequest = buildRawRequest(`Bearer ${jwt}`);
    const burp = new FakeBurp({
        responses: [
            {
                statusCode: 401,
                headers: ['content-type: application/json'],
                body: '{"error":"missing auth"}',
            },
            {
                statusCode: 200,
                headers: ['content-type: application/json'],
                body: '{"ok":true}',
            },
        ],
    });
    const agent = createAgent({ initialRequest }, burp);

    await initializeAuth(agent, burp, initialRequest);

    const result = await (agent as any).executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {},
            preserveExplicitAuth: true,
        },
    });

    assert.equal(burp.sent.length, 2);
    assert.ok(!('Authorization' in burp.sent[0].headers));
    assert.equal(burp.sent[1].headers.Authorization, `Bearer ${jwt}`);
    assert.equal(result.retriedAfterAuthInjection, true);
});

test('expired token path does not falsely pass when no refresh plan exists', async () => {
    const expiredJwt = makeJwt(Math.floor(Date.now() / 1000) - 300);
    const initialRequest = buildRawRequest(`Bearer ${expiredJwt}`);
    const burp = new FakeBurp({
        responses: [{
            statusCode: 401,
            headers: ['content-type: application/json'],
            body: '{"error":"expired"}',
        }],
    });
    const agent = createAgent({ initialRequest }, burp);

    await initializeAuth(agent, burp, initialRequest);

    const result = await (agent as any).executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
        },
    });

    assert.equal(burp.sent.length, 1);
    assert.equal(burp.sent[0].headers.Authorization, `Bearer ${expiredJwt}`);
    assert.equal(result.retriedAfterRefresh, undefined);
    assert.equal(result.statusCode, 401);
});

test('raw request capture remains isolated across multiple identities', async () => {
    const manager = new AuthStateManager('scan-test', 'https://app.example.com');
    const burp = new FakeBurp();

    await manager.initialize({}, burp as any);
    manager.identityRegistry.createSecondary('idor-user-1', 'User B');

    manager.captureFromRawRequest(buildRawRequest('Bearer primary-token-1234567890', 'session=primary'), 'primary-user');
    manager.captureFromRawRequest(buildRawRequest('Bearer secondary-token-1234567890', 'session=secondary'), 'idor-user-1');

    const primary = manager.prepareRequest(undefined, '', 'https://app.example.com/api/me', 'GET', 'primary-user', false);
    const secondary = manager.prepareRequest(undefined, '', 'https://app.example.com/api/me', 'GET', 'idor-user-1', false);

    assert.equal(primary.headers.Authorization, 'Bearer primary-token-1234567890');
    assert.equal(secondary.headers.Authorization, 'Bearer secondary-token-1234567890');
    assert.equal(secondary.headers.Cookie, 'session=secondary');
});

test('warning is emitted when a Burp-originated request leaves without Authorization while auth exists', async () => {
    const jwt = makeJwt(Math.floor(Date.now() / 1000) + 3600);
    const initialRequest = buildRawRequest(`Bearer ${jwt}`);
    const burp = new FakeBurp();
    const agent = createAgent({ initialRequest }, burp);

    await initializeAuth(agent, burp, initialRequest);

    const result = await (agent as any).executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {},
            preserveExplicitAuth: true,
        },
    });

    assert.match(String(result.authWarning || ''), /without Authorization/i);
    assert.ok(agent.getLogs().some(line => line.includes('Auth Warning')));
});

test('round-one fallback plan stays auth-first for no-credential web startup', () => {
    const burp = new FakeBurp();
    const agent = createAgent({
        authStartup: {
            mode: 'no_credentials',
            credentials: [],
            allowAccountCreation: true,
            preferSharedPassword: true,
        },
    }, burp);

    (agent as any).planRound = 1;
    (agent as any).startupAuthInventory = {
        mode: 'no_credentials',
        status: 'completed',
        browserSessionId: 'browser-1',
        authRoutes: ['/login', '/register', '/forgot-password'],
        forms: [],
        domElements: [],
        traffic: [],
        actions: [],
        discoveredCredentials: [],
        ssoProviders: ['Google'],
        blockers: [],
        registrationAvailable: true,
        passwordResetAvailable: true,
        activationRequired: false,
        transport: {
            carriesAuthorizationHeader: false,
            authorizationSchemes: [],
            cookieNames: ['session'],
            localStorageKeys: [],
            sessionStorageKeys: [],
            indexedDbNames: [],
            csrfHeaders: ['x-csrf-token'],
            csrfFormFields: ['_csrf'],
            csrfMetaNames: ['csrf-token'],
            csrfCookieNames: [],
            mixedTransport: false,
            evidence: ['traffic=3'],
        },
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        summary: 'Auth-first startup summary',
    };

    const plan = (agent as any).createFallbackPlan();

    assert.match(plan.analysis, /auth/i);
    assert.match(plan.steps[0].objective, /auth|register|login/i);
    assert.ok(plan.steps[0].tools.includes('browser_navigate'));
    assert.ok(plan.steps[1].tools.includes('browser_fill_and_submit'));
});
