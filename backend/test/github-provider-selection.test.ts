import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'node:net';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-github-provider-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'github-provider-test-secret';
process.env.GITHUB_APP_CLIENT_ID = 'Iv1.testclientid';
process.env.GITHUB_APP_CLIENT_SECRET = 'github-app-test-secret';
delete process.env.GITHUB_APP_CALLBACK_URL;

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const express = require('express') as typeof import('express');
const { encryptSecret } = require('../src/services/github/crypto') as typeof import('../src/services/github/crypto');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const { llmProvider } = require('../src/services/LLMProviderService') as typeof import('../src/services/LLMProviderService');
const { GitHubCallbackServer } = require('../src/services/github/GitHubCallbackServer') as typeof import('../src/services/github/GitHubCallbackServer');
const { GitHubIntegrationService, githubIntegration } = require('../src/services/GitHubIntegrationService') as typeof import('../src/services/GitHubIntegrationService');
const configRoutes = require('../src/routes/config').default as typeof import('../src/routes/config').default;
const githubIntegrationRoutes = require('../src/routes/github-integration').default as typeof import('../src/routes/github-integration').default;

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM integration_auth_sessions;
        DELETE FROM user_integrations;
        DELETE FROM llm_config;
    `);
}

function createGitHubMetadata(overrides?: Record<string, unknown>) {
    return JSON.stringify({
        authType: 'github_app_user_token',
        externalUserId: 12345,
        displayName: 'Ghost User',
        tokenExpiresAt: null,
        refreshTokenExpiresAt: null,
        lastValidatedAt: new Date().toISOString(),
        lastValidationError: null,
        lastDiscoveryError: null,
        modelsCache: {
            fetchedAt: new Date().toISOString(),
            models: [
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
            ],
        },
        ...overrides,
    });
}

function createFakeCallbackServer(url = 'http://127.0.0.1:5050/api/integrations/github/callback') {
    return {
        ensureListening: async () => undefined,
        getListenerError: () => null,
        getListenerUrl: () => url,
    } as unknown as InstanceType<typeof GitHubCallbackServer>;
}

async function withApiServer(run: (input: { baseUrl: string; authToken: string }) => Promise<void>) {
    const app = express();
    app.use(express.json());
    app.use('/api/config', configRoutes);
    app.use('/api/integrations', githubIntegrationRoutes);

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

test('stale github_copilot activation is cleared when GitHub is not actually connected', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 1, '{}')
    `).run();

    const configs = llmProvider.getAllConfigs(1);
    const githubConfig = configs.find((config) => config.provider === 'github_copilot');

    assert.ok(githubConfig);
    assert.equal(githubConfig?.is_active, 0);
    assert.equal(
        (dbModule.db.prepare('SELECT is_active FROM llm_config WHERE provider = ?').get('github_copilot') as { is_active: number }).is_active,
        0,
    );
    assert.throws(() => llmProvider.getActiveConfig(1), /No active LLM provider configured/);
});

test('legacy github_models rows are retired on startup and no longer control provider truth', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_models', '', 'openai/gpt-4.1', 1, 1, '{}')
    `).run();

    const cleanup = githubIntegration.reconcilePersistedStateOnStartup();
    const legacyConfig = dbModule.db.prepare('SELECT * FROM llm_config WHERE provider = ?').get('github_models');
    const migratedConfig = dbModule.db.prepare('SELECT provider, model, is_active FROM llm_config WHERE provider = ?').get('github_copilot') as {
        provider: string;
        model: string;
        is_active: number;
    };
    const configs = llmProvider.getAllConfigs(1);

    assert.equal(cleanup.migratedLegacyProviderConfig, true);
    assert.equal(legacyConfig, undefined);
    assert.equal(migratedConfig.provider, 'github_copilot');
    assert.equal(migratedConfig.model, 'openai/gpt-4.1');
    assert.equal(configs.some((config) => config.provider === 'github_models'), false);
});

test('status resolution clears stale github_copilot selection when the GitHub integration row is active but unusable', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO user_integrations (user_id, provider, external_username, is_active, metadata_json)
        VALUES (1, 'github', 'ghost-user', 1, '{}')
    `).run();
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 0, '{}')
    `).run();

    const status = await githubIntegration.getResolvedConnectionStatus(1);
    const configs = llmProvider.getAllConfigs(1);
    const githubConfig = configs.find((config) => config.provider === 'github_copilot');
    const persistedIntegration = dbModule.db.prepare(`
        SELECT is_active, access_token_encrypted, refresh_token_encrypted
        FROM user_integrations
        WHERE user_id = 1 AND provider = 'github'
    `).get() as { is_active: number; access_token_encrypted: string | null; refresh_token_encrypted: string | null };

    assert.equal(status.connected, false);
    assert.equal(status.providerReady, false);
    assert.equal(githubConfig?.is_active, 0);
    assert.equal(persistedIntegration.is_active, 0);
    assert.equal(persistedIntegration.access_token_encrypted, null);
    assert.equal(persistedIntegration.refresh_token_encrypted, null);
});

test('startup cleanup invalidates active GitHub rows that are missing required identity metadata', async () => {
    await resetState();

    const encryptedAccessToken = encryptSecret('valid-looking-access-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, external_username, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, NULL, 1, '{}')
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
    );
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 1, '{}')
    `).run();

    const cleanup = githubIntegration.reconcilePersistedStateOnStartup();
    const status = githubIntegration.getConnectionStatus(1);
    const persistedIntegration = dbModule.db.prepare(`
        SELECT is_active, access_token_encrypted, token_iv
        FROM user_integrations
        WHERE user_id = 1 AND provider = 'github'
    `).get() as { is_active: number; access_token_encrypted: string | null; token_iv: string | null };
    const githubConfig = dbModule.db.prepare(`
        SELECT is_active, is_online
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { is_active: number; is_online: number };

    assert.equal(cleanup.invalidatedConnections, 1);
    assert.equal(status.connected, false);
    assert.equal(status.providerReady, false);
    assert.equal(persistedIntegration.is_active, 0);
    assert.equal(persistedIntegration.access_token_encrypted, null);
    assert.equal(persistedIntegration.token_iv, null);
    assert.equal(githubConfig.is_active, 0);
    assert.equal(githubConfig.is_online, 0);
});

test('startup cleanup purges secrets from inactive GitHub rows and clears stale github_copilot activation on reload', async () => {
    await resetState();

    const encryptedAccessToken = encryptSecret('inactive-access-token');
    const encryptedRefreshToken = encryptSecret('inactive-refresh-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, refresh_token_encrypted, refresh_token_iv, token_scope, expires_at, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, ?, ?, 'models:read', ?, 0, ?)
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
        encryptedRefreshToken.encrypted,
        encryptedRefreshToken.iv,
        new Date(Date.now() + 60_000).toISOString(),
        createGitHubMetadata(),
    );
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 1, '{}')
    `).run();

    const cleanup = githubIntegration.reconcilePersistedStateOnStartup();
    const persistedIntegration = dbModule.db.prepare(`
        SELECT access_token_encrypted, token_iv, refresh_token_encrypted, refresh_token_iv, token_scope, expires_at, is_active
        FROM user_integrations
        WHERE user_id = 1 AND provider = 'github'
    `).get() as {
        access_token_encrypted: string | null;
        token_iv: string | null;
        refresh_token_encrypted: string | null;
        refresh_token_iv: string | null;
        token_scope: string | null;
        expires_at: string | null;
        is_active: number;
    };
    const githubConfig = dbModule.db.prepare(`
        SELECT is_active, is_online
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { is_active: number; is_online: number };

    assert.equal(cleanup.purgedInactiveSecrets, 1);
    assert.equal(cleanup.deactivatedProviderConfig, true);
    assert.equal(persistedIntegration.is_active, 0);
    assert.equal(persistedIntegration.access_token_encrypted, null);
    assert.equal(persistedIntegration.token_iv, null);
    assert.equal(persistedIntegration.refresh_token_encrypted, null);
    assert.equal(persistedIntegration.refresh_token_iv, null);
    assert.equal(persistedIntegration.token_scope, null);
    assert.equal(persistedIntegration.expires_at, null);
    assert.equal(githubConfig.is_active, 0);
    assert.equal(githubConfig.is_online, 0);
});

test('expired GitHub access token without a refresh token is treated as disconnected before configs are returned', async () => {
    await resetState();

    const encryptedAccessToken = encryptSecret('expired-access-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, external_username, expires_at, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, 'ghost-user', ?, 1, ?)
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
        new Date(Date.now() - 60_000).toISOString(),
        createGitHubMetadata({ modelsCache: undefined }),
    );
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 0, '{}')
    `).run();

    const status = githubIntegration.getConnectionStatus(1);
    const githubConfig = llmProvider.getAllConfigs(1).find((config) => config.provider === 'github_copilot');

    assert.equal(status.connected, false);
    assert.equal(status.providerReady, false);
    assert.equal(githubConfig?.is_active, 0);
});

test('/api/integrations/github/status does not return false connected truth from stale GitHub rows', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO user_integrations (user_id, provider, external_username, is_active, metadata_json)
        VALUES (1, 'github', 'ghost-user', 1, ?)
    `).run(createGitHubMetadata({ lastValidatedAt: null, modelsCache: undefined }));
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 0, '{}')
    `).run();

    await withApiServer(async ({ baseUrl, authToken }) => {
        const response = await fetch(`${baseUrl}/api/integrations/github/status`, {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        const payload = await response.json() as { connected: boolean; providerReady: boolean };

        assert.equal(response.status, 200);
        assert.equal(payload.connected, false);
        assert.equal(payload.providerReady, false);
    });
});

test('/api/config/llm does not leak stale active github_copilot provider truth', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO user_integrations (user_id, provider, external_username, is_active, metadata_json)
        VALUES (1, 'github', 'ghost-user', 1, ?)
    `).run(createGitHubMetadata({ lastValidatedAt: null, modelsCache: undefined }));
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 1, '{}')
    `).run();

    await withApiServer(async ({ baseUrl, authToken }) => {
        const response = await fetch(`${baseUrl}/api/config/llm`, {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        const payload = await response.json() as {
            configs: Array<{ provider: string; is_active: number; is_online: number }>;
        };
        const githubConfig = payload.configs.find((config) => config.provider === 'github_copilot');

        assert.equal(response.status, 200);
        assert.equal(githubConfig?.is_active, 0);
        assert.equal(githubConfig?.is_online, 0);
    });
});

test('github_copilot cannot be activated until GitHub auth and Copilot model discovery have really completed', async () => {
    await resetState();

    assert.throws(() => llmProvider.updateConfig({
        provider: 'github_copilot',
        api_key: '',
        model: 'gpt-5',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1), /GitHub is not connected/);

    const encryptedAccessToken = encryptSecret('connected-access-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, external_username, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, 'ghost-user', 1, ?)
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
        createGitHubMetadata({ modelsCache: { fetchedAt: new Date().toISOString(), models: [] }, lastDiscoveryError: 'No models returned' }),
    );

    assert.throws(() => llmProvider.updateConfig({
        provider: 'github_copilot',
        api_key: '',
        model: 'gpt-5',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1), /No models returned/);
});

test('selected Copilot model persistence and active provider resolution stay in sync with the connected GitHub state', async () => {
    await resetState();

    const encryptedAccessToken = encryptSecret('connected-access-token');
    const encryptedRefreshToken = encryptSecret('connected-refresh-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, refresh_token_encrypted, refresh_token_iv, token_scope, external_username, external_avatar_url, expires_at, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, ?, ?, 'models:read', 'ghost-user', 'https://avatars.example/ghost.png', ?, 1, ?)
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
        encryptedRefreshToken.encrypted,
        encryptedRefreshToken.iv,
        new Date(Date.now() + 60_000).toISOString(),
        createGitHubMetadata(),
    );

    llmProvider.updateConfig({
        provider: 'github_copilot',
        api_key: '',
        model: 'gpt-5',
        is_active: 1,
        is_online: 0,
        settings_json: '{}',
    }, 1);

    const active = llmProvider.getActiveConfig(1);
    const persisted = dbModule.db.prepare(`
        SELECT provider, model, is_active
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { provider: string; model: string; is_active: number };

    assert.equal(active.provider, 'github_copilot');
    assert.equal(active.model, 'gpt-5');
    assert.equal(persisted.model, 'gpt-5');
    assert.equal(persisted.is_active, 1);
});

test('disconnect path clears persisted GitHub state and resets github_copilot activation', async () => {
    await resetState();

    const encryptedAccessToken = encryptSecret('connected-access-token');
    const encryptedRefreshToken = encryptSecret('connected-refresh-token');
    dbModule.db.prepare(`
        INSERT INTO user_integrations (
            user_id, provider, access_token_encrypted, token_iv, refresh_token_encrypted, refresh_token_iv, token_scope, external_username, external_avatar_url, expires_at, is_active, metadata_json
        )
        VALUES (1, 'github', ?, ?, ?, ?, 'models:read', 'ghost-user', 'https://avatars.example/ghost.png', ?, 1, ?)
    `).run(
        encryptedAccessToken.encrypted,
        encryptedAccessToken.iv,
        encryptedRefreshToken.encrypted,
        encryptedRefreshToken.iv,
        new Date(Date.now() + 60_000).toISOString(),
        createGitHubMetadata(),
    );
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 1, '{}')
    `).run();

    await withApiServer(async ({ baseUrl, authToken }) => {
        const response = await fetch(`${baseUrl}/api/integrations/github/disconnect`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
            body: '{}',
        });

        assert.equal(response.status, 200);
    });

    const persistedIntegration = dbModule.db.prepare(`
        SELECT is_active, access_token_encrypted, token_iv, refresh_token_encrypted, refresh_token_iv, token_scope, expires_at
        FROM user_integrations
        WHERE user_id = 1 AND provider = 'github'
    `).get() as {
        is_active: number;
        access_token_encrypted: string | null;
        token_iv: string | null;
        refresh_token_encrypted: string | null;
        refresh_token_iv: string | null;
        token_scope: string | null;
        expires_at: string | null;
    };
    const githubConfig = dbModule.db.prepare(`
        SELECT is_active, is_online
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { is_active: number; is_online: number };

    assert.equal(persistedIntegration.is_active, 0);
    assert.equal(persistedIntegration.access_token_encrypted, null);
    assert.equal(persistedIntegration.token_iv, null);
    assert.equal(persistedIntegration.refresh_token_encrypted, null);
    assert.equal(persistedIntegration.refresh_token_iv, null);
    assert.equal(persistedIntegration.token_scope, null);
    assert.equal(persistedIntegration.expires_at, null);
    assert.equal(githubConfig.is_active, 0);
    assert.equal(githubConfig.is_online, 0);
});

test('pending GitHub auth sessions can be cancelled when the browser launch fails', async () => {
    await resetState();

    const service = new GitHubIntegrationService({
        callbackServer: createFakeCallbackServer(),
    });

    const started = await service.startAuthorization(1, {
        runtime: 'web',
        origin: 'http://localhost:3000',
    });

    const pending = service.getAuthorizationSession(1, started.sessionId);
    assert.equal(pending?.status, 'pending');

    const cancelled = service.cancelAuthorizationSession(1, started.sessionId, 'Browser launch failed: test');
    assert.equal(cancelled?.status, 'failed');
    assert.match(cancelled?.errorMessage || '', /Browser launch failed: test/);
    assert.equal(service.getConnectionStatus(1).connected, false);
});
