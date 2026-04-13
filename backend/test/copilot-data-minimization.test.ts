import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'node:net';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-copilot-minimization-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');
process.env.JWT_SECRET = 'copilot-minimization-test-secret';
process.env.GITHUB_APP_CLIENT_ID = 'Iv1.testclientid';
process.env.GITHUB_APP_CLIENT_SECRET = 'github-app-test-secret';
delete process.env.GITHUB_APP_CALLBACK_URL;

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const express = require('express') as typeof import('express');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const configRoutes = require('../src/routes/config').default as typeof import('../src/routes/config').default;
const { buildInitialRequestContext } = require('../src/agents/orchestrator/OrchestratorInitialRequestContext') as typeof import('../src/agents/orchestrator/OrchestratorInitialRequestContext');
const { OrchestratorRequestExecutor } = require('../src/agents/orchestrator/OrchestratorRequestExecutor') as typeof import('../src/agents/orchestrator/OrchestratorRequestExecutor');
const { sanitizeLogMessage, sanitizeLogMeta } = require('../src/utils/logger') as typeof import('../src/utils/logger');
const { llmProvider } = require('../src/services/LLMProviderService') as typeof import('../src/services/LLMProviderService');
const { githubIntegration } = require('../src/services/GitHubIntegrationService') as typeof import('../src/services/GitHubIntegrationService');
const { GitHubIntegrationStore } = require('../src/services/github/GitHubIntegrationStore') as typeof import('../src/services/github/GitHubIntegrationStore');

async function resetState() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM integration_auth_sessions;
        DELETE FROM user_integrations;
        DELETE FROM llm_config;
        DELETE FROM mcp_servers;
    `);
}

async function withApiServer(run: (input: { baseUrl: string; authToken: string }) => Promise<void>) {
    const app = express();
    app.use(express.json());
    app.use('/api/config', configRoutes);

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

function createPassthroughAuthManager() {
    return {
        inject: () => ({ authorizationHeader: null, cookies: null, customHeaders: {} }),
        captureFromStructuredRequest: () => undefined,
        prepareRequest: (headers: Record<string, string> | undefined, body: string | undefined) => ({
            headers: { ...(headers || {}) },
            body: body || '',
        }),
        assessPreparedRequest: () => ({
            identityId: 'primary-user',
            method: 'POST',
            url: 'https://app.example.com/api/orders/123?orderId=7',
            intent: 'authenticated',
            likelyRequiresAuth: true,
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
            preserveExplicitAuth: true,
        }),
        handleResponse: () => ({ needsRefresh: false, needsRelogin: false, isCSRFFailure: false }),
        refreshSession: async () => false,
        inferRequestIntent: () => 'authenticated',
    };
}

test('buildInitialRequestContext keeps raw Burp secrets and identifiers out of prompt-visible text', () => {
    const rawRequest = [
        'POST /api/orders/123?orderId=7&token=live-query-secret HTTP/1.1',
        'Host: app.example.com',
        'Authorization: Bearer live-bearer-secret',
        'Cookie: sid=live-session-cookie; csrftoken=live-csrf-cookie',
        'Content-Type: application/json',
        '',
        '{"email":"alice@example.com","amount":1500,"csrf":"body-secret"}',
    ].join('\r\n');

    const context = buildInitialRequestContext(rawRequest);
    const promptText = [
        context.systemPromptAppendix,
        ...context.initialMessages.map((message) => message.content),
        ...context.continuationMessages.map((message) => message.content),
        context.logSummary,
    ].join('\n');

    assert.ok(context.parsed);
    assert.ok(promptText.includes('Stored header names: Host, Authorization, Cookie, Content-Type'));
    assert.ok(promptText.includes('Sensitive header names preserved server-side: Authorization, Cookie'));
    assert.ok(promptText.includes('Body parameter names: email, amount, csrf'));
    assert.ok(!promptText.includes('live-bearer-secret'));
    assert.ok(!promptText.includes('live-session-cookie'));
    assert.ok(!promptText.includes('alice@example.com'));
    assert.ok(!promptText.includes('body-secret'));
    assert.ok(!promptText.includes('orderId=7'));
    assert.ok(!promptText.includes('/api/orders/123'));
    assert.ok(promptText.includes('/api/orders/<preserved>?orderId=<preserved>&token=<preserved>'));
});

test('request executor replays the stored Burp baseline server-side and applies focused mutations', async () => {
    const capturedCalls: Array<{ tool: string; args: Record<string, any> }> = [];
    const executor = new OrchestratorRequestExecutor({
        scanId: 'scan-1',
        burp: {
            callTool: async (tool: string, args: Record<string, any>) => {
                capturedCalls.push({ tool, args });
                if (tool === 'send_http_request') {
                    return { statusCode: 200, headers: {}, body: 'ok' };
                }
                if (tool === 'get_proxy_history') {
                    return { items: [] };
                }
                throw new Error(`Unexpected tool call: ${tool}`);
            },
        } as any,
        authManager: createPassthroughAuthManager() as any,
        initialRequest: [
            'POST /api/orders/123?orderId=7 HTTP/1.1',
            'Host: app.example.com',
            'Authorization: Bearer live-bearer-secret',
            'Cookie: sid=live-session-cookie',
            'Content-Type: application/json',
            '',
            '{"amount":1500,"status":"draft"}',
        ].join('\r\n'),
        log: () => undefined,
        rateLimitPauseMs: 60_000,
        setRateLimitPauseUntil: () => undefined,
        delay: async () => undefined,
    });

    await executor.execute({
        tool: 'send_http_request',
        args: {
            method: 'POST',
            useInitialRequestBaseline: true,
            preserveExplicitAuth: true,
            queryMutations: [{ name: 'orderId', value: '9999' }],
            bodyMutations: [{ name: 'amount', value: 1 }],
        },
    });

    const sendCall = capturedCalls.find((call) => call.tool === 'send_http_request');
    assert.ok(sendCall);
    assert.equal(sendCall?.args.url, 'https://app.example.com/api/orders/123?orderId=9999');
    assert.equal(sendCall?.args.headers.Authorization, 'Bearer live-bearer-secret');
    assert.equal(sendCall?.args.headers.Cookie, 'sid=live-session-cookie');
    assert.equal(sendCall?.args.headers['Content-Type'], 'application/json');
    assert.equal(sendCall?.args.body, '{"amount":1,"status":"draft"}');
    assert.equal('queryMutations' in (sendCall?.args || {}), false);
    assert.equal('bodyMutations' in (sendCall?.args || {}), false);
    assert.equal('useInitialRequestBaseline' in (sendCall?.args || {}), false);
});

test('GitHub Copilot invocation ignores unrelated provider secrets and settings when GitHub is the active provider', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('openai', 'sk-openai-secret', 'gpt-4.1', 0, 0, '{"baseUrl":"https://openai.internal","apiKey":"shadow-secret"}')
    `).run();
    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_copilot', '', 'gpt-5', 1, 0, '{"legacySecret":"should-not-leak","providerBlob":{"apiKey":"nested-secret"}}')
    `).run();

    const originalGetConnectionStatus = githubIntegration.getConnectionStatus.bind(githubIntegration);
    const originalGenerateCopilotResponse = githubIntegration.generateCopilotResponse.bind(githubIntegration);
    let captured: any = null;

    (githubIntegration as any).getConnectionStatus = () => ({
        connected: true,
        providerReady: true,
        configured: true,
    });
    (githubIntegration as any).generateCopilotResponse = async (
        userId: number,
        modelId: string,
        request: Record<string, unknown>,
        executionOptions: Record<string, unknown>,
    ) => {
        captured = { userId, modelId, request, executionOptions };
        return { text: 'copilot-ok' };
    };

    try {
        const result = await llmProvider.executeAttempt({
            systemPrompt: 'system prompt',
            userPrompt: 'user prompt',
        }, {
            scanId: 'scan-1',
            userId: 42,
            context: 'orchestrator',
        });

        assert.equal(result.text, 'copilot-ok');
        assert.deepEqual(captured, {
            userId: 42,
            modelId: 'gpt-5',
            request: {
                systemPrompt: 'system prompt',
                userPrompt: 'user prompt',
                images: undefined,
            },
            executionOptions: {},
        });
        assert.ok(!JSON.stringify(captured).includes('sk-openai-secret'));
        assert.ok(!JSON.stringify(captured).includes('should-not-leak'));
        assert.ok(!JSON.stringify(captured).includes('nested-secret'));
    } finally {
        (githubIntegration as any).getConnectionStatus = originalGetConnectionStatus;
        (githubIntegration as any).generateCopilotResponse = originalGenerateCopilotResponse;
    }
});

test('logger sanitization redacts GitHub, provider, cookie, and env-var secrets', () => {
    const sanitizedMessage = sanitizeLogMessage('Authorization: Bearer live-bearer-secret Cookie: sid=abc github_pat_deadbeef');
    const sanitizedMeta = sanitizeLogMeta({
        accessToken: 'ghu_live_token',
        refresh_token: 'ghr_refresh_secret',
        api_key: 'sk-openai-secret',
        clientSecret: 'github-app-client-secret',
        env_vars: '{"OPENAI_API_KEY":"sk-openai-secret"}',
        headers: {
            Authorization: 'Bearer live-bearer-secret',
            Cookie: 'sid=abc',
            'X-Trace-Id': 'trace-123',
        },
        nested: {
            rawRequest: 'Authorization: Bearer nested-secret',
        },
        rawError: 'token exchange failed for github_pat_deadbeef',
    });

    assert.ok(!sanitizedMessage.includes('live-bearer-secret'));
    assert.ok(!sanitizedMessage.includes('github_pat_deadbeef'));
    assert.equal(sanitizedMeta.accessToken, '[REDACTED]');
    assert.equal(sanitizedMeta.refresh_token, '[REDACTED]');
    assert.equal(sanitizedMeta.api_key, '[REDACTED]');
    assert.equal(sanitizedMeta.clientSecret, '[REDACTED]');
    assert.equal(sanitizedMeta.env_vars, '[REDACTED]');
    assert.equal((sanitizedMeta.headers as Record<string, string>).Authorization, '[REDACTED]');
    assert.equal((sanitizedMeta.headers as Record<string, string>).Cookie, '[REDACTED]');
    assert.equal((sanitizedMeta.headers as Record<string, string>)['X-Trace-Id'], 'trace-123');
    assert.equal((sanitizedMeta.nested as Record<string, string>).rawRequest, '[REDACTED]');
    assert.ok(!String(sanitizedMeta.rawError).includes('github_pat_deadbeef'));
});

test('config routes redact stored secrets and preserve existing provider keys on blank updates', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('openai', 'sk-openai-secret', 'gpt-4.1', 1, 1, '{}')
    `).run();
    dbModule.db.prepare(`
        INSERT INTO mcp_servers (name, command, args, env_vars, status, is_enabled)
        VALUES ('secrets-mcp', 'node', '[]', '{"OPENAI_API_KEY":"sk-openai-secret"}', 'stopped', 1)
    `).run();

    await withApiServer(async ({ baseUrl, authToken }) => {
        const llmResponse = await fetch(`${baseUrl}/api/config/llm`, {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        const llmPayload = await llmResponse.json() as {
            configs: Array<{ provider: string; api_key: string; has_api_key: boolean }>;
        };
        const openaiConfig = llmPayload.configs.find((config) => config.provider === 'openai');

        assert.equal(llmResponse.status, 200);
        assert.equal(openaiConfig?.api_key, '');
        assert.equal(openaiConfig?.has_api_key, true);

        const updateResponse = await fetch(`${baseUrl}/api/config/llm`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                provider: 'openai',
                api_key: '',
                model: 'gpt-4.1-mini',
                is_active: 1,
                is_online: 0,
                settings_json: '{}',
            }),
        });

        assert.equal(updateResponse.status, 200);
        const storedConfig = dbModule.db.prepare('SELECT api_key, model FROM llm_config WHERE provider = ?').get('openai') as {
            api_key: string;
            model: string;
        };
        assert.equal(storedConfig.api_key, 'sk-openai-secret');
        assert.equal(storedConfig.model, 'gpt-4.1-mini');

        const mcpResponse = await fetch(`${baseUrl}/api/config/mcp`, {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        const mcpPayload = await mcpResponse.json() as {
            servers: Array<{ name: string; env_vars: string; has_env_vars: boolean }>;
        };
        const server = mcpPayload.servers.find((entry) => entry.name === 'secrets-mcp');

        assert.equal(mcpResponse.status, 200);
        assert.equal(server?.env_vars, '{}');
        assert.equal(server?.has_env_vars, true);
    });
});

test('legacy github_models migration clears legacy settings_json instead of carrying it into github_copilot', async () => {
    await resetState();

    dbModule.db.prepare(`
        INSERT INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
        VALUES ('github_models', 'legacy-secret', 'gpt-5', 1, 1, '{"legacySecret":"should-not-survive"}')
    `).run();

    const store = new GitHubIntegrationStore();
    const cleanup = store.reconcileCopilotProviderConfig();
    const migrated = dbModule.db.prepare(`
        SELECT provider, api_key, settings_json
        FROM llm_config
        WHERE provider = 'github_copilot'
    `).get() as { provider: string; api_key: string; settings_json: string };

    assert.equal(cleanup.migratedLegacyConfig, true);
    assert.equal(migrated.provider, 'github_copilot');
    assert.equal(migrated.api_key, '');
    assert.equal(migrated.settings_json, '{}');
});
