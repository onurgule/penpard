import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorToolDispatcher } = require('../src/agents/orchestrator/OrchestratorToolDispatcher') as typeof import('../src/agents/orchestrator/OrchestratorToolDispatcher');
const { OrchestratorToolRegistry } = require('../src/agents/orchestrator/OrchestratorToolRegistry') as typeof import('../src/agents/orchestrator/OrchestratorToolRegistry');
const {
    evaluateToolExecutionGuard,
    hasCustomAuthHeader,
    resolveAuthIdentityId,
    resolveRequestAuthIntent,
} = require('../src/agents/orchestrator/OrchestratorToolPolicy') as typeof import('../src/agents/orchestrator/OrchestratorToolPolicy');
const { ScopedMissionPolicy } = require('../src/services/runtime/ScopedMissionPolicy') as typeof import('../src/services/runtime/ScopedMissionPolicy');

test('dispatcher executes through the extracted handler registry and reports unknown tools cleanly', async () => {
    const logs: string[] = [];
    const dispatcher = new OrchestratorToolDispatcher({
        log: (_channel, message) => logs.push(message),
        guard: () => null,
        handlers: {
            ping: async (toolCall) => ({ echoed: toolCall.args.value }),
        },
    });

    const executed = await dispatcher.execute({ tool: 'ping', args: { value: 'ok' } });
    const missing = await dispatcher.execute({ tool: 'missing', args: {} });

    assert.deepEqual(executed, { echoed: 'ok' });
    assert.match(String(missing.error), /Available: ping/);
    assert.ok(logs.some((entry) => entry.includes('Executing: ping')));
});

test('tool policy blocks focused-scope enumeration and active rate limits', () => {
    const focusedBlock = evaluateToolExecutionGuard({
        toolName: 'spider_url',
        isFocusedScope: true,
        rateLimitPauseUntil: null,
    });

    const rateLimited = evaluateToolExecutionGuard({
        toolName: 'send_http_request',
        isFocusedScope: false,
        rateLimitPauseUntil: new Date(Date.now() + 60_000),
        now: new Date(),
    });

    assert.equal(focusedBlock.allowed, false);
    assert.equal(focusedBlock.response.blocked, true);
    assert.equal(rateLimited.allowed, false);
    assert.equal(rateLimited.response.skipped, true);
});

test('tool policy enforces scoped request boundaries and records operator-visible boundary reasons', () => {
    const scopePolicy = new ScopedMissionPolicy({
        targetUrl: 'https://app.example.com/api/orders/1',
        objective: {
            id: 'objective-1',
            scanId: 'scan-1',
            title: 'Orders scoped mission',
            scopeType: 'endpoint_scoped',
            goal: 'Stay inside order detail routes.',
            featureDescription: null,
            operatorNotes: null,
            riskTags: ['idor'],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        },
        envelope: {
            id: 'scope-1',
            scanId: 'scan-1',
            version: 1,
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders/:id'],
            selectedEndpoints: [{ method: 'GET', path: '/api/orders/1', host: 'app.example.com' }],
            baselineRequestRefs: [],
            discoveredRequestRefs: [],
            requestBundleRefs: [],
            browserAnchors: [],
            authContext: null,
            boundaryHints: ['Stay inside order detail lookups.'],
            outOfScopeNotes: ['Do not pivot into admin endpoints.'],
            explorationBudget: {
                maxRequests: 4,
                maxRouteVariants: 1,
            },
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        },
        request: {
            id: 'request-1',
            scanId: 'scan-1',
            targetUrl: 'https://app.example.com/api/orders/1',
            description: 'Validate access control around order detail reads.',
            environment: null,
            serviceName: 'orders',
            testData: [],
            testUsers: [],
            loginPresent: true,
            authMechanismHints: [],
            hasScreenshotOrAttachment: false,
            attachmentMetadata: [],
            attachmentSummary: null,
            newScreenCount: 0,
            newInputCount: 0,
            operatorNotes: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        },
    });

    const allowedVariant = evaluateToolExecutionGuard({
        toolName: 'send_http_request',
        toolArgs: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/2',
        },
        isFocusedScope: false,
        scopePolicy,
        rateLimitPauseUntil: null,
    });
    const blockedVariant = evaluateToolExecutionGuard({
        toolName: 'send_http_request',
        toolArgs: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/3',
        },
        isFocusedScope: false,
        scopePolicy,
        rateLimitPauseUntil: null,
    });
    const blockedHost = evaluateToolExecutionGuard({
        toolName: 'browser_navigate',
        toolArgs: {
            url: 'https://admin.example.com/api/orders/1',
        },
        isFocusedScope: false,
        scopePolicy,
        rateLimitPauseUntil: null,
    });

    assert.equal(allowedVariant.allowed, true);
    assert.equal(blockedVariant.allowed, false);
    assert.equal(blockedVariant.severity, 'advisory');
    assert.match(String(blockedVariant.response?.boundaryReason), /route-variant budget/i);
    assert.equal(blockedVariant.response?.boundarySeverity, 'advisory');
    assert.equal(blockedHost.allowed, false);
    assert.equal(blockedHost.severity, 'hard');
    assert.match(String(blockedHost.response?.boundaryReason), /outside the scoped mission boundary/i);
    assert.match(String(scopePolicy.buildBoundarySummary().blockedActionReason), /outside the scoped mission boundary/i);
});

test('dispatcher passes through advisory blocks to the handler and tags the response with the boundary reason', async () => {
    const handlerSnapshots: any[] = [];
    const logs: string[] = [];
    const dispatcher = new OrchestratorToolDispatcher({
        log: (channel, message) => logs.push(`${channel}:${message}`),
        guard: () => ({
            response: { error: 'route advisory', blocked: true, boundaryReason: 'route advisory' },
            severity: 'advisory',
            advisoryReason: 'route advisory',
        }),
        handlers: {
            send_http_request: async (toolCall) => {
                handlerSnapshots.push({ ...(toolCall.args as Record<string, any>) });
                return { statusCode: 200, body: 'ok' };
            },
        },
    });

    const callArgs: Record<string, any> = { url: 'https://app.example.com/anywhere', method: 'GET' };
    const result = await dispatcher.execute({ tool: 'send_http_request', args: callArgs });

    assert.equal(handlerSnapshots.length, 1, 'handler must run on advisory');
    assert.equal(result.statusCode, 200);
    assert.equal(result.boundaryAdvisory, true);
    assert.equal(result.boundaryReason, 'route advisory');
    assert.ok(logs.some((entry) => entry.includes('Advisory boundary')));
    assert.equal(handlerSnapshots[0].__advisoryReason, 'route advisory', 'handler must see __advisoryReason during execution');
    assert.equal(callArgs.__advisoryReason, undefined, 'dispatcher must clean up __advisoryReason after handler returns');
});

test('ScopedMissionPolicy classifies severity correctly across boundary types', () => {
    const baseObjective = {
        id: 'objective-sev',
        scanId: 'scan-sev',
        title: 'Severity coverage',
        scopeType: 'request_scoped' as const,
        goal: 'Prove severity classification.',
        featureDescription: null,
        operatorNotes: null,
        riskTags: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
    const baseEnvelope = {
        id: 'scope-sev',
        scanId: 'scan-sev',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/orders/:id'],
        selectedEndpoints: [{ method: 'GET', path: '/api/orders/1', host: 'app.example.com' }],
        baselineRequestRefs: [{
            kind: 'scan_initial_request',
            method: 'GET',
            path: '/api/orders/1',
            url: 'https://app.example.com/api/orders/1',
            host: 'app.example.com',
        }],
        discoveredRequestRefs: [],
        requestBundleRefs: [],
        browserAnchors: [],
        authContext: null,
        boundaryHints: [],
        outOfScopeNotes: [],
        explorationBudget: { maxRequests: 1, maxRouteVariants: null },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
    const baseRequest = {
        id: 'request-sev',
        scanId: 'scan-sev',
        targetUrl: 'https://app.example.com/api/orders/1',
        description: 'severity test',
        environment: null,
        serviceName: null,
        testData: [],
        testUsers: [],
        loginPresent: null,
        authMechanismHints: [],
        hasScreenshotOrAttachment: false,
        attachmentMetadata: [],
        attachmentSummary: null,
        newScreenCount: null,
        newInputCount: null,
        operatorNotes: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
    };
    const policy = new ScopedMissionPolicy({
        targetUrl: 'https://app.example.com/api/orders/1',
        objective: baseObjective,
        envelope: baseEnvelope,
        request: baseRequest,
    });

    const hostBlock = policy.evaluateTool({
        toolName: 'send_http_request',
        method: 'GET',
        url: 'https://other.example.com/api/orders/1',
    });
    const routeBlock = policy.evaluateTool({
        toolName: 'send_http_request',
        method: 'GET',
        url: 'https://app.example.com/admin/users',
    });
    const baselineDrift = policy.evaluateTool({
        toolName: 'send_http_request',
        method: 'GET',
        url: 'https://app.example.com/api/orders/9999',
        useInitialRequestBaseline: false,
    });
    const allowedFirst = policy.evaluateTool({
        toolName: 'send_http_request',
        method: 'GET',
        url: 'https://app.example.com/api/orders/1',
        useInitialRequestBaseline: true,
    });
    const budgetBlock = policy.evaluateTool({
        toolName: 'send_http_request',
        method: 'GET',
        url: 'https://app.example.com/api/orders/1',
        useInitialRequestBaseline: true,
    });

    assert.equal(hostBlock.allowed, false);
    assert.equal(hostBlock.severity, 'hard');
    assert.equal(routeBlock.allowed, false);
    assert.equal(routeBlock.severity, 'advisory');
    assert.equal(baselineDrift.allowed, false);
    assert.equal(baselineDrift.severity, 'advisory');
    assert.equal(allowedFirst.allowed, true);
    assert.equal(budgetBlock.allowed, false);
    assert.equal(budgetBlock.severity, 'hard');
});

test('dispatcher short-circuits on hard blocks without invoking the handler', async () => {
    const handlerCalls: any[] = [];
    const dispatcher = new OrchestratorToolDispatcher({
        log: () => {},
        guard: () => ({
            response: { error: 'host out of scope', blocked: true, boundaryReason: 'host out of scope' },
            severity: 'hard',
        }),
        handlers: {
            send_http_request: async (toolCall) => {
                handlerCalls.push(toolCall);
                return { statusCode: 200 };
            },
        },
    });

    const result = await dispatcher.execute({
        tool: 'send_http_request',
        args: { url: 'https://evil.example.com/x', method: 'GET' },
    });

    assert.equal(handlerCalls.length, 0, 'handler must not run on hard block');
    assert.equal(result.blocked, true);
    assert.equal(result.boundaryReason, 'host out of scope');
});

test('auth helpers preserve explicit control over identity and intent resolution', () => {
    assert.equal(resolveAuthIdentityId({ identityId: 'idor-user-1' }), 'idor-user-1');
    assert.equal(resolveAuthIdentityId({ disableAutoAuth: true }), '__none__');
    assert.equal(resolveAuthIdentityId(undefined), 'primary-user');

    assert.equal(hasCustomAuthHeader({ 'X-Api-Key': 'secret' }), true);
    assert.equal(hasCustomAuthHeader({ Authorization: 'Bearer token' }), false);

    const explicit = resolveRequestAuthIntent({
        requestedIntent: 'session_refresh',
        inferIntent: () => 'authenticated',
    });
    const inferredAnonymous = resolveRequestAuthIntent({
        identityId: '__none__',
        inferIntent: () => 'authenticated',
    });

    assert.equal(explicit, 'session_refresh');
    assert.equal(inferredAnonymous, 'unknown');
});

test('tool registry centralizes canonical names, aliases, and arg coercion for the active path', () => {
    const registry = new OrchestratorToolRegistry({
        handlers: {
            browser_navigate: async () => ({}),
            get_proxy_history: async () => ({}),
            send_http_request: async () => ({}),
            none: async () => ({}),
        },
    });

    const browserAction = registry.normalizeToolCall(
        {
            name: 'browserNavigate',
            arguments: 'https://app.example.com/account',
        },
        (value: any) => value,
    );
    const proxyAction = registry.normalizeToolCall(
        'getProxyHistory',
        (value: any) => value,
        { count: 8 },
    );

    assert.deepEqual(browserAction, {
        tool: 'browser_navigate',
        args: { url: 'https://app.example.com/account' },
    });
    assert.deepEqual(proxyAction, {
        tool: 'get_proxy_history',
        args: { count: 8, excludePenPard: true },
    });
    assert.equal(registry.canonicalize('sendHttpRequest'), 'send_http_request');
    assert.ok(registry.listToolNames().includes('none'));
});
