import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'node:net';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-github-auth-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'github-auth-test-secret';
process.env.GITHUB_APP_CLIENT_ID = 'Iv1.testclientid';
process.env.GITHUB_APP_CLIENT_SECRET = 'github-app-test-secret';
delete process.env.GITHUB_APP_CALLBACK_URL;

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const express = require('express') as typeof import('express');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const { GitHubAuthSessionStore } = require('../src/services/github/GitHubAuthSessionStore') as typeof import('../src/services/github/GitHubAuthSessionStore');
const { GitHubIntegrationStore } = require('../src/services/github/GitHubIntegrationStore') as typeof import('../src/services/github/GitHubIntegrationStore');
const { GitHubIntegrationService } = require('../src/services/GitHubIntegrationService') as typeof import('../src/services/GitHubIntegrationService');
const { GitHubCallbackServer } = require('../src/services/github/GitHubCallbackServer') as typeof import('../src/services/github/GitHubCallbackServer');
const { getGitHubCallbackListenerConfig } = require('../src/services/github/config') as typeof import('../src/services/github/config');
const { createGitHubIntegrationRouter } = require('../src/routes/github-integration') as typeof import('../src/routes/github-integration');

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM integration_auth_sessions;
        DELETE FROM user_integrations;
        DELETE FROM llm_config;
    `);
}

function createFakeCallbackServer(url = 'http://127.0.0.1:5050/api/integrations/github/callback') {
    return {
        ensureListening: async () => undefined,
        getListenerError: () => null,
        getListenerUrl: () => url,
    } as unknown as InstanceType<typeof GitHubCallbackServer>;
}

function createPendingSession(store: InstanceType<typeof GitHubAuthSessionStore>, state = 'oauth-state-123') {
    return store.createPendingSession({
        userId: 1,
        state,
        codeVerifier: 'verifier',
        redirectUri: 'http://127.0.0.1:5050/api/integrations/github/callback',
        appRedirectUrl: 'http://localhost:3000/settings',
        authorizationUrl: 'https://github.com/login/oauth/authorize?client_id=test',
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
}

async function withApiServer(
    service: InstanceType<typeof GitHubIntegrationService>,
    run: (input: { baseUrl: string; authToken: string }) => Promise<void>,
) {
    const app = express();
    app.use(express.json());
    app.use('/api/integrations', createGitHubIntegrationRouter(service));

    const server = await new Promise<any>((resolve) => {
        const started = app.listen(0, () => resolve(started));
    });

    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
        await run({
            baseUrl,
            authToken: generateToken(1),
        });
    } finally {
        await new Promise<void>((resolve, reject) => {
            server.close((error?: Error | null) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve();
            });
        });
    }
}

test('GitHub auth start route returns a browser authorization payload that points at the 127.0.0.1:5050 callback listener', async () => {
    await resetState();

    let receivedStartOptions: any = null;
    const service = {
        startAuthorization: async (_userId: number, options: any) => {
            receivedStartOptions = options;
            return {
                sessionId: 'session-123',
                authorizationUrl: 'https://github.com/login/oauth/authorize?client_id=test',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
                callbackUrl: 'http://127.0.0.1:5050/api/integrations/github/callback',
            };
        },
        getCallbackUrl: () => 'http://127.0.0.1:5050/api/integrations/github/callback',
        getAuthorizationSession: () => null,
        cancelAuthorizationSession: () => null,
        getResolvedConnectionStatus: async () => ({ connected: false, configured: true, providerReady: false }),
        listModels: async () => [],
        disconnect: () => undefined,
        validateToken: async () => true,
    } as unknown as InstanceType<typeof GitHubIntegrationService>;

    await withApiServer(service, async ({ baseUrl, authToken }) => {
        const response = await fetch(`${baseUrl}/api/integrations/github/auth/start`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                runtime: 'electron',
                origin: 'http://localhost:3000',
            }),
        });
        const payload = await response.json() as { callbackUrl: string; sessionId: string };

        assert.equal(response.status, 200);
        assert.equal(payload.sessionId, 'session-123');
        assert.equal(payload.callbackUrl, 'http://127.0.0.1:5050/api/integrations/github/callback');
    });

    assert.deepEqual(receivedStartOptions, {
        runtime: 'electron',
        origin: 'http://localhost:3000',
    });
});

test('completeAuthorizationCallback persists the GitHub user token and Copilot model cache on success', async () => {
    await resetState();

    const authSessions = new GitHubAuthSessionStore();
    const integrations = new GitHubIntegrationStore();
    const pendingSession = createPendingSession(authSessions, 'callback-success-state');

    const service = new GitHubIntegrationService({
        authSessions,
        integrations,
        oauth: {
            startAuthorization: () => {
                throw new Error('not used');
            },
            exchangeAuthorizationCode: async ({ code, state }: { code: string; state: string }) => {
                assert.equal(code, 'oauth-code');
                assert.equal(state, 'callback-success-state');
                return {
                    sessionId: pendingSession.id,
                    userId: 1,
                    tokenSet: {
                        accessToken: 'ghu_connected',
                        refreshToken: 'ghr_refresh',
                        tokenType: 'bearer',
                        scope: 'models:read',
                        expiresAt: new Date(Date.now() + 60_000).toISOString(),
                        refreshTokenExpiresAt: new Date(Date.now() + 120_000).toISOString(),
                    },
                    metadata: {
                        authType: 'github_app_user_token',
                        externalUserId: 42,
                        displayName: 'The Octocat',
                        tokenExpiresAt: new Date(Date.now() + 60_000).toISOString(),
                        refreshTokenExpiresAt: new Date(Date.now() + 120_000).toISOString(),
                        lastValidatedAt: new Date().toISOString(),
                        lastValidationError: null,
                        lastDiscoveryError: null,
                    },
                    result: {
                        username: 'octocat',
                        avatarUrl: 'https://avatars.example/octocat.png',
                        connected: true,
                    },
                };
            },
            validateCurrentToken: async () => true,
            getUsableAccessToken: async () => 'ghu_connected',
            refreshAccessToken: async () => 'ghu_connected_refreshed',
        } as any,
        copilot: {
            listModels: async () => ([
                {
                    id: 'gpt-5',
                    name: 'GPT-5',
                    isAvailable: true,
                    policyState: 'enabled',
                    billingMultiplier: 1,
                    supportsVision: true,
                    supportsReasoningEffort: true,
                    supportedReasoningEfforts: ['low', 'medium', 'high'],
                    defaultReasoningEffort: 'medium',
                    maxContextWindowTokens: 272000,
                    maxPromptTokens: 128000,
                    maxPromptImages: 8,
                    supportedImageMimeTypes: ['image/png'],
                },
            ]),
            generate: async () => ({ text: 'unused' }),
            getAuthStatus: async () => ({ isAuthenticated: true, login: 'octocat', authType: 'token' }),
        } as any,
        callbackServer: createFakeCallbackServer(),
    });

    const result = await service.completeAuthorizationCallback({
        code: 'oauth-code',
        state: 'callback-success-state',
    });

    const persistedIntegration = dbModule.db.prepare(`
        SELECT external_username, external_avatar_url, is_active, access_token_encrypted, refresh_token_encrypted, metadata_json
        FROM user_integrations
        WHERE user_id = 1 AND provider = 'github'
    `).get() as {
        external_username: string;
        external_avatar_url: string;
        is_active: number;
        access_token_encrypted: string | null;
        refresh_token_encrypted: string | null;
        metadata_json: string;
    };
    const providerConfig = dbModule.db.prepare(`
        SELECT provider, model, is_active
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { provider: string; model: string; is_active: number };

    assert.equal(result.session?.status, 'completed');
    assert.match(result.html, /GitHub connected/);
    assert.equal(persistedIntegration.external_username, 'octocat');
    assert.equal(persistedIntegration.external_avatar_url, 'https://avatars.example/octocat.png');
    assert.equal(persistedIntegration.is_active, 1);
    assert.notEqual(persistedIntegration.access_token_encrypted, 'ghu_connected');
    assert.notEqual(persistedIntegration.refresh_token_encrypted, 'ghr_refresh');
    assert.match(persistedIntegration.metadata_json, /gpt-5/);
    assert.equal(providerConfig.provider, 'github_copilot');
    assert.equal(providerConfig.model, 'gpt-5');
    assert.equal(providerConfig.is_active, 0);
});

test('completeAuthorizationCallback marks the auth session failed when GitHub returns an OAuth error', async () => {
    await resetState();

    const authSessions = new GitHubAuthSessionStore();
    const pendingSession = createPendingSession(authSessions, 'callback-error-state');
    const service = new GitHubIntegrationService({
        authSessions,
        callbackServer: createFakeCallbackServer(),
    });

    const result = await service.completeAuthorizationCallback({
        error: 'access_denied',
        errorDescription: 'The user denied access',
        state: 'callback-error-state',
    });

    const storedSession = service.getAuthorizationSession(1, pendingSession.id);
    assert.equal(result.session?.status, 'failed');
    assert.equal(storedSession?.status, 'failed');
    assert.match(storedSession?.errorMessage || '', /denied access/i);
    assert.match(result.html, /GitHub connection failed/);
});

test('completeAuthorizationCallback rejects invalid callback state values', async () => {
    await resetState();

    const service = new GitHubIntegrationService({
        oauth: {
            startAuthorization: () => {
                throw new Error('not used');
            },
            exchangeAuthorizationCode: async () => {
                throw new Error('GitHub callback state is invalid or expired.');
            },
            validateCurrentToken: async () => true,
            getUsableAccessToken: async () => 'unused',
            refreshAccessToken: async () => 'unused',
        } as any,
        callbackServer: createFakeCallbackServer(),
    });

    const result = await service.completeAuthorizationCallback({
        code: 'oauth-code',
        state: 'unknown-state',
    });

    assert.equal(result.session, null);
    assert.match(result.html, /invalid or expired/i);
});

test('completeAuthorizationCallback surfaces token exchange failures and leaves the session failed', async () => {
    await resetState();

    const authSessions = new GitHubAuthSessionStore();
    const pendingSession = createPendingSession(authSessions, 'exchange-failure-state');
    const service = new GitHubIntegrationService({
        authSessions,
        oauth: {
            startAuthorization: () => {
                throw new Error('not used');
            },
            exchangeAuthorizationCode: async () => {
                throw new Error('GitHub token exchange failed with HTTP 401.');
            },
            validateCurrentToken: async () => true,
            getUsableAccessToken: async () => 'unused',
            refreshAccessToken: async () => 'unused',
        } as any,
        callbackServer: createFakeCallbackServer(),
    });

    const result = await service.completeAuthorizationCallback({
        code: 'oauth-code',
        state: 'exchange-failure-state',
    });

    const storedSession = service.getAuthorizationSession(1, pendingSession.id);
    assert.equal(storedSession?.status, 'failed');
    assert.match(storedSession?.errorMessage || '', /token exchange failed/i);
    assert.match(result.html, /GitHub connection failed/);
});

test('GitHub callback listener defaults to 127.0.0.1:5050 and serves callback responses on the configured path', async () => {
    await resetState();

    const defaultConfig = getGitHubCallbackListenerConfig();
    assert.equal(defaultConfig.host, '127.0.0.1');
    assert.equal(defaultConfig.port, 5050);
    assert.equal(defaultConfig.path, '/api/integrations/github/callback');

    const callbackServer = new GitHubCallbackServer(
        async ({ code, state }) => {
            assert.equal(code, 'callback-code');
            assert.equal(state, 'callback-state');
            return {
                session: {
                    id: 'session-callback',
                    provider: 'github',
                    status: 'completed',
                    createdAt: new Date().toISOString(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                },
                html: '<html><body>callback-ok</body></html>',
            };
        },
        () => ({
            host: '127.0.0.1',
            port: 0,
            path: '/api/integrations/github/callback',
            url: 'http://127.0.0.1/api/integrations/github/callback',
        }),
    );

    await callbackServer.ensureListening();
    const server = (callbackServer as any).server as import('http').Server;
    const address = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${address.port}/api/integrations/github/callback?code=callback-code&state=callback-state`);
    const body = await response.text();

    await callbackServer.stop();

    assert.equal(response.status, 200);
    assert.match(body, /callback-ok/);
});
