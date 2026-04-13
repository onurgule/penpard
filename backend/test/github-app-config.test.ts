import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import net, { type AddressInfo } from 'node:net';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-github-app-config-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'github-app-config-test-secret';
process.env.GITHUB_APP_CLIENT_ID = 'Iv1.environment';
process.env.GITHUB_APP_CLIENT_SECRET = 'environment-secret';
delete process.env.GITHUB_APP_CALLBACK_URL;

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const express = require('express') as typeof import('express');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const { GitHubAppConfigService } = require('../src/services/github/GitHubAppConfigService') as typeof import('../src/services/github/GitHubAppConfigService');
const { GitHubIntegrationService } = require('../src/services/GitHubIntegrationService') as typeof import('../src/services/GitHubIntegrationService');
const { createGitHubIntegrationRouter } = require('../src/routes/github-integration') as typeof import('../src/routes/github-integration');

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM integration_auth_sessions;
        DELETE FROM user_integrations;
        DELETE FROM llm_config;
        DELETE FROM settings;
    `);
}

async function getFreePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const address = server.address() as AddressInfo;
            server.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve(address.port);
            });
        });
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

test('GitHubAppConfigService promotes saved UI config over environment fallback and preserves the saved secret on blank updates', async () => {
    await resetState();

    const service = new GitHubAppConfigService();
    assert.equal(service.getConfigSummary().source, 'environment');
    assert.equal(service.getResolvedConfig().clientId, 'Iv1.environment');

    const firstPort = await getFreePort();
    const secondPort = await getFreePort();

    service.saveConfig({
        clientId: 'Iv1.ui-primary',
        clientSecret: 'ui-secret-1',
        callbackUrl: `http://127.0.0.1:${firstPort}/api/integrations/github/callback`,
    });

    let resolved = service.getResolvedConfig();
    assert.equal(resolved.clientId, 'Iv1.ui-primary');
    assert.equal(resolved.clientSecret, 'ui-secret-1');
    assert.equal(resolved.callbackUrl, `http://127.0.0.1:${firstPort}/api/integrations/github/callback`);
    assert.equal(service.getConfigSummary().source, 'ui');
    assert.equal(service.getConfigSummary().hasClientSecret, true);

    service.saveConfig({
        clientId: 'Iv1.ui-updated',
        clientSecret: '',
        callbackUrl: `http://127.0.0.1:${secondPort}/api/integrations/github/callback`,
    });

    resolved = service.getResolvedConfig();
    assert.equal(resolved.clientId, 'Iv1.ui-updated');
    assert.equal(resolved.clientSecret, 'ui-secret-1');
    assert.equal(resolved.callbackUrl, `http://127.0.0.1:${secondPort}/api/integrations/github/callback`);
});

test('GitHub integration config routes round-trip saved GitHub App config without exposing the client secret and update the callback listener URL', async () => {
    await resetState();

    const service = new GitHubIntegrationService();
    const callbackPort = await getFreePort();
    const callbackUrl = `http://127.0.0.1:${callbackPort}/api/integrations/github/callback`;

    try {
        await withApiServer(service, async ({ baseUrl, authToken }) => {
            const saveResponse = await fetch(`${baseUrl}/api/integrations/github/config`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${authToken}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    clientId: 'Iv1.route-save',
                    clientSecret: 'route-secret',
                    callbackUrl,
                }),
            });
            const savedPayload = await saveResponse.json() as {
                source: string;
                clientId: string;
                callbackUrl: string;
                hasClientSecret: boolean;
                configured: boolean;
                requiresCallbackRegistrationConfirmation?: boolean;
                clientSecret?: string;
            };

            assert.equal(saveResponse.status, 200);
            assert.equal(savedPayload.source, 'ui');
            assert.equal(savedPayload.clientId, 'Iv1.route-save');
            assert.equal(savedPayload.callbackUrl, callbackUrl);
            assert.equal(savedPayload.hasClientSecret, true);
            assert.equal(savedPayload.configured, false);
            assert.equal(savedPayload.requiresCallbackRegistrationConfirmation, true);
            assert.equal(savedPayload.clientSecret, undefined);

            const confirmResponse = await fetch(`${baseUrl}/api/integrations/github/config`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${authToken}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    clientId: 'Iv1.route-save',
                    clientSecret: '',
                    callbackUrl,
                    confirmCallbackRegistration: true,
                }),
            });
            const confirmedPayload = await confirmResponse.json() as typeof savedPayload;

            assert.equal(confirmResponse.status, 200);
            assert.equal(confirmedPayload.configured, true);
            assert.equal(confirmedPayload.requiresCallbackRegistrationConfirmation, false);

            const getResponse = await fetch(`${baseUrl}/api/integrations/github/config`, {
                headers: {
                    Authorization: `Bearer ${authToken}`,
                },
            });
            const getPayload = await getResponse.json() as typeof savedPayload;

            assert.equal(getResponse.status, 200);
            assert.equal(getPayload.source, 'ui');
            assert.equal(getPayload.clientId, 'Iv1.route-save');
            assert.equal(getPayload.callbackUrl, callbackUrl);
            assert.equal(getPayload.hasClientSecret, true);
            assert.equal(getPayload.configured, true);
            assert.equal(getPayload.requiresCallbackRegistrationConfirmation, false);
        });

        assert.equal(service.getCallbackUrl(), callbackUrl);
    } finally {
        await (service as any).callbackServer.stop();
    }
});

test('GitHub integration suggests a free callback URL when the configured loopback port is already in use', async () => {
    await resetState();

    const blocker = net.createServer();
    await new Promise<void>((resolve, reject) => {
        blocker.once('error', reject);
        blocker.listen(0, '127.0.0.1', () => resolve());
    });

    const address = blocker.address() as AddressInfo;
    const blockedCallbackUrl = `http://127.0.0.1:${address.port}/api/integrations/github/callback`;
    const service = new GitHubIntegrationService();

    try {
        const summary = await service.saveGitHubAppConfig({
            clientId: 'Iv1.port-conflict',
            clientSecret: 'route-secret',
            callbackUrl: blockedCallbackUrl,
        });

        assert.equal(summary.configured, false);
        assert.match(summary.configurationError || '', /already in use/);
        assert.ok(summary.recommendedCallbackUrl, 'expected a recommended callback URL');
        assert.notEqual(summary.recommendedCallbackUrl, blockedCallbackUrl);
        assert.match(summary.configurationError || '', new RegExp(summary.recommendedCallbackUrl!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

        const suggestedUrl = new URL(summary.recommendedCallbackUrl!);
        assert.equal(suggestedUrl.hostname, '127.0.0.1');
        assert.equal(suggestedUrl.pathname, '/api/integrations/github/callback');
    } finally {
        await new Promise<void>((resolve, reject) => {
            blocker.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve();
            });
        });
        await (service as any).callbackServer.stop();
    }
});

test('GitHub integration requires callback registration confirmation before browser auth can start with a changed callback URL', async () => {
    await resetState();

    const callbackPort = await getFreePort();
    const callbackUrl = `http://127.0.0.1:${callbackPort}/api/integrations/github/callback`;
    let oauthStarted = false;

    const service = new GitHubIntegrationService({
        callbackServer: {
            ensureListening: async () => undefined,
            getListenerError: () => null,
            getListenerUrl: () => callbackUrl,
            getSuggestedCallbackUrl: () => null,
            stop: async () => undefined,
        } as any,
        oauth: {
            startAuthorization: () => {
                oauthStarted = true;
                throw new Error('should not start');
            },
        } as any,
    });

    const firstSave = await service.saveGitHubAppConfig({
        clientId: 'Iv1.confirm-required',
        clientSecret: 'ui-secret-1',
        callbackUrl,
    });

    assert.equal(firstSave.configured, false);
    assert.equal(firstSave.requiresCallbackRegistrationConfirmation, true);
    assert.match(firstSave.configurationError || '', /redirect_uri to exactly match/i);
    assert.equal(service.getConnectionStatus(1).configured, false);

    await assert.rejects(
        service.startAuthorization(1, { runtime: 'web', origin: 'http://localhost:3000' }),
        /redirect_uri to exactly match/i,
    );
    assert.equal(oauthStarted, false);

    const confirmedSave = await service.saveGitHubAppConfig({
        clientId: 'Iv1.confirm-required',
        clientSecret: '',
        callbackUrl,
        confirmCallbackRegistration: true,
    });

    assert.equal(confirmedSave.configured, true);
    assert.equal(confirmedSave.requiresCallbackRegistrationConfirmation, false);
});
