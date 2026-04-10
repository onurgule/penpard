import test from 'node:test';
import assert from 'node:assert/strict';

import { RequestAuthDiagnostics } from '../src/services/auth';
import {
    ManagedAuthRequestInterceptor,
    RequestExecutionContext,
    RequestPipelineAuthManager,
} from '../src/agents/orchestrator/OrchestratorRequestPipeline';

function createDiagnostics(overrides: Partial<RequestAuthDiagnostics> = {}): RequestAuthDiagnostics {
    return {
        identityId: 'primary-user',
        method: 'GET',
        url: 'https://app.example.com/api/me',
        intent: 'authenticated',
        likelyRequiresAuth: false,
        authSuppressedForIntent: false,
        isAuthBootstrapRoute: false,
        storedAuthAvailable: false,
        storedAuthorizationAvailable: false,
        storedCookieAvailable: false,
        storedCustomAuthAvailable: false,
        explicitAuthorizationPresent: false,
        explicitAuthorizationKeyPresent: false,
        explicitCookiePresent: false,
        explicitCookieKeyPresent: false,
        explicitCustomAuthPresent: false,
        explicitCustomAuthKeyPresent: false,
        outgoingAuthorizationPresent: false,
        outgoingCookiePresent: false,
        outgoingCustomAuthPresent: false,
        preserveExplicitAuth: false,
        ...overrides,
    };
}

function createContext(overrides: Partial<RequestExecutionContext> = {}): RequestExecutionContext {
    return {
        toolCall: {
            tool: 'send_http_request',
            args: {
                method: 'GET',
                url: 'https://app.example.com/api/me',
                headers: {},
                body: '',
            },
        },
        url: 'https://app.example.com/api/me',
        method: 'GET',
        identityId: 'primary-user',
        preserveExplicitAuth: false,
        requestIntent: 'authenticated',
        originalHeaders: {},
        originalBody: '',
        isBurpOriginatedRequest: false,
        preparedRequest: {
            headers: {},
            body: '',
        },
        requestDiagnostics: createDiagnostics(),
        requestArgs: {},
        result: { statusCode: 200 },
        statusCode: 200,
        responseHeaders: {},
        responseBody: '',
        ...overrides,
    };
}

test('managed auth interceptor captures explicit auth before transport when the managed store has not learned it yet', () => {
    let captured = 0;

    const authManager: RequestPipelineAuthManager = {
        inject: () => ({
            customHeaders: {},
        }),
        captureFromStructuredRequest: () => {
            captured += 1;
            return {};
        },
        prepareRequest: (_headers, body) => ({
            headers: { Authorization: 'Bearer managed-token' },
            body: body || '',
        }),
        assessPreparedRequest: () => createDiagnostics({
            outgoingAuthorizationPresent: true,
            storedAuthAvailable: true,
            storedAuthorizationAvailable: true,
        }),
        handleResponse: () => ({
            needsRefresh: false,
            needsRelogin: false,
            isCSRFFailure: false,
        }),
        refreshSession: async () => false,
    };

    const interceptor = new ManagedAuthRequestInterceptor({
        authManager,
        burp: { callTool: async () => ({}) },
        log: () => {},
    });

    const context = createContext({
        originalHeaders: {
            Authorization: 'Bearer explicit-token',
        },
        preparedRequest: {
            headers: {
                Authorization: 'Bearer explicit-token',
            },
            body: '',
        },
    });

    interceptor.beforeTransport(context);

    assert.equal(captured, 1);
    assert.equal(context.preparedRequest.headers.Authorization, 'Bearer managed-token');
    assert.equal(context.requestDiagnostics?.outgoingAuthorizationPresent, true);
});

test('managed auth interceptor owns 401 recovery as a response-stage retry instead of executor inline control flow', async () => {
    const reexecutedRequests: Array<Record<string, string>> = [];

    const authManager: RequestPipelineAuthManager = {
        inject: () => ({
            customHeaders: {},
        }),
        captureFromStructuredRequest: () => ({}),
        prepareRequest: () => ({
            headers: { Authorization: 'Bearer recovered-token' },
            body: '',
        }),
        assessPreparedRequest: () => createDiagnostics({
            likelyRequiresAuth: true,
            storedAuthAvailable: true,
            storedAuthorizationAvailable: true,
            outgoingAuthorizationPresent: true,
        }),
        handleResponse: () => ({
            needsRefresh: false,
            needsRelogin: false,
            isCSRFFailure: false,
        }),
        refreshSession: async () => false,
    };

    const interceptor = new ManagedAuthRequestInterceptor({
        authManager,
        burp: { callTool: async () => ({}) },
        log: () => {},
    });

    const context = createContext({
        preserveExplicitAuth: true,
        isBurpOriginatedRequest: true,
        requestDiagnostics: createDiagnostics({
            likelyRequiresAuth: true,
            storedAuthAvailable: true,
            storedAuthorizationAvailable: true,
            preserveExplicitAuth: true,
        }),
        result: { statusCode: 401 },
        statusCode: 401,
        responseBody: '{"error":"missing auth"}',
    });

    await interceptor.afterResponse(context, {
        reexecute: async (preparedRequest) => {
            reexecutedRequests.push(preparedRequest.headers);
            context.preparedRequest = preparedRequest;
            context.result = { statusCode: 200 };
            context.statusCode = 200;
            context.responseHeaders = {};
            context.responseBody = '{"ok":true}';
        },
    });

    assert.deepEqual(reexecutedRequests, [
        { Authorization: 'Bearer recovered-token' },
    ]);
    assert.equal(context.result.retriedAfterAuthInjection, true);
    assert.equal(context.statusCode, 200);
});
