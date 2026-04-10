import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanLaunchConfigService } = require('../src/services/runtime/ScanLaunchConfigService') as typeof import('../src/services/runtime/ScanLaunchConfigService');

test('prepareWebLaunch centralizes runtime defaults, auth shaping, and persisted redaction', () => {
    const warnings: string[] = [];
    const service = new ScanLaunchConfigService((message) => warnings.push(message));

    const prepared = service.prepareWebLaunch({
        userId: 7,
        rateLimit: '9',
        useNuclei: 'true',
        useFfuf: true,
        idorUsers: JSON.stringify([{ username: 'legacy-user', password: 'legacy-secret' }]),
        parallelAgents: '12',
        scanInstructions: ' probe the authenticated API ',
        sessionCookies: '  session=abc  ',
        iterations: '75',
        maxPlanRounds: '120',
        sourcePackagePath: '  /tmp/source  ',
        sourceAnalysisMode: 'full_source_aware',
        authStartupMode: 'provided_credentials',
        authCredentials: JSON.stringify([{ username: 'primary-user', password: 'top-secret', privilege: 'high' }]),
        allowAccountCreation: 'true',
        preferSharedPassword: 'false',
    });

    assert.equal(prepared.runtimeConfig.rateLimit, 9);
    assert.equal(prepared.runtimeConfig.parallelAgents, 1);
    assert.equal(prepared.runtimeConfig.requestedParallelAgents, 10);
    assert.equal(prepared.runtimeConfig.maxIterations, 75);
    assert.equal(prepared.runtimeConfig.maxPlanRounds, 99);
    assert.equal(prepared.runtimeConfig.useNuclei, false);
    assert.equal(prepared.runtimeConfig.useFfuf, false);
    assert.equal(prepared.runtimeConfig.customSystemPrompt, 'probe the authenticated API');
    assert.equal(prepared.runtimeConfig.sessionCookies, 'session=abc');
    assert.equal(prepared.runtimeConfig.sourcePackagePath, '/tmp/source');
    assert.equal(prepared.runtimeConfig.sourceAnalysisMode, 'full_source_aware');
    assert.equal(prepared.runtimeConfig.authStartup?.mode, 'provided_credentials');
    assert.equal(prepared.runtimeConfig.authStartup?.credentials.length, 1);
    assert.equal(prepared.runtimeConfig.idorUsers?.[0]?.username, 'primary-user');
    assert.equal(prepared.runtimeConfig.idorUsers?.[0]?.password, 'top-secret');
    assert.equal(prepared.persistedConfig.executionMode, 'single-agent');
    assert.equal(prepared.persistedConfig.effectiveParallelAgents, 1);
    assert.equal(prepared.persistedConfig.idorUsers[0].password, '[REDACTED]');
    assert.equal(prepared.persistedConfig.authStartup.credentials[0].password, '[REDACTED]');
    assert.deepEqual(warnings, [
        'nucleiEnabled was requested but Nuclei integration is not yet implemented - ignoring',
        'ffufEnabled was requested but FFUF integration is not yet implemented - ignoring',
    ]);
});

test('prepareBurpLaunch keeps the control plane on the single-agent runtime path', () => {
    const service = new ScanLaunchConfigService();

    const prepared = service.prepareBurpLaunch({
        userId: 11,
        initialRequest: 'GET https://app.example.com/api/me HTTP/1.1',
        parallelAgents: '3',
        iterations: 'not-a-number',
        maxPlanRounds: '',
        scanInstructions: ' continue from raw request ',
        sourcePackagePath: '  /tmp/repo  ',
        sourceAnalysisMode: 'unsupported',
    });

    assert.equal(prepared.runtimeConfig.parallelAgents, 1);
    assert.equal(prepared.runtimeConfig.requestedParallelAgents, 3);
    assert.equal(prepared.runtimeConfig.maxIterations, 50);
    assert.equal(prepared.runtimeConfig.maxPlanRounds, 0);
    assert.equal(prepared.runtimeConfig.customSystemPrompt, 'continue from raw request');
    assert.equal(prepared.runtimeConfig.initialRequest, 'GET https://app.example.com/api/me HTTP/1.1');
    assert.equal(prepared.runtimeConfig.sourcePackagePath, '/tmp/repo');
    assert.equal(prepared.runtimeConfig.sourceAnalysisMode, undefined);
    assert.equal(prepared.runtimeConfig.authStartup?.mode, 'no_credentials');
    assert.deepEqual(prepared.runtimeConfig.idorUsers, []);
    assert.equal(prepared.persistedConfig.executionMode, 'single-agent');
});
