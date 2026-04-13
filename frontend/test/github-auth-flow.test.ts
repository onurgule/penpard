import test from 'node:test';
import assert from 'node:assert/strict';

import { GITHUB_COPILOT_PROVIDER } from '../src/app/settings/github-copilot-types';
import {
    idleGitHubAuthUiState,
    isGitHubProviderSelected,
    normalizeGitHubProviderSelection,
    startGitHubBrowserAuthFlow,
} from '../src/app/settings/github-auth-flow';

test('normalizeGitHubProviderSelection clears stale GitHub provider activation while preserving other providers', () => {
    const normalized = normalizeGitHubProviderSelection([
        { provider: 'github_models', is_active: 1, model: 'openai/gpt-4.1' },
        { provider: GITHUB_COPILOT_PROVIDER, is_active: 1, model: 'gpt-5' },
        { provider: 'openai', is_active: 0, model: 'gpt-4o' },
    ], false);

    assert.equal(normalized[0].is_active, 0);
    assert.equal(normalized[1].is_active, 0);
    assert.equal(normalized[2].is_active, 0);
});

test('isGitHubProviderSelected only returns true when GitHub is both connected and active in config', () => {
    const staleSelectedWhileDisconnected = isGitHubProviderSelected([
        { provider: GITHUB_COPILOT_PROVIDER, is_active: 1 },
        { provider: 'openai', is_active: 0 },
    ], false);
    const connectedAndActive = isGitHubProviderSelected([
        { provider: GITHUB_COPILOT_PROVIDER, is_active: 1 },
    ], true);
    const connectedButInactive = isGitHubProviderSelected([
        { provider: GITHUB_COPILOT_PROVIDER, is_active: 0 },
    ], true);

    assert.equal(staleSelectedWhileDisconnected, false);
    assert.equal(connectedAndActive, true);
    assert.equal(connectedButInactive, false);
});

test('startGitHubBrowserAuthFlow enters waiting state only after the browser launch succeeds', async () => {
    const calls: string[] = [];

    const result = await startGitHubBrowserAuthFlow({
        requestStartAuthorization: async () => {
            calls.push('request');
            return {
                sessionId: 'session-123',
                authorizationUrl: 'https://github.com/login/oauth/authorize?client_id=test',
            };
        },
        openAuthorizationUrl: async (url) => {
            calls.push(`open:${url}`);
        },
        cancelPendingAuthorization: async () => {
            calls.push('cancel');
        },
    });

    assert.deepEqual(calls, [
        'request',
        'open:https://github.com/login/oauth/authorize?client_id=test',
    ]);
    assert.equal(result.errorMessage, undefined);
    assert.deepEqual(result.state, {
        sessionId: 'session-123',
        authorizationUrl: 'https://github.com/login/oauth/authorize?client_id=test',
        busy: true,
        message: 'Approve PenPard in your browser, then return here.',
    });
});

test('startGitHubBrowserAuthFlow clears pending auth state and requests cancellation when browser launch fails', async () => {
    const cancellations: Array<{ sessionId: string; reason: string }> = [];

    const result = await startGitHubBrowserAuthFlow({
        requestStartAuthorization: async () => ({
            sessionId: 'session-456',
            authorizationUrl: 'https://github.com/login/oauth/authorize?client_id=test',
        }),
        openAuthorizationUrl: async () => {
            throw new Error('Default browser could not be opened');
        },
        cancelPendingAuthorization: async (sessionId, reason) => {
            cancellations.push({ sessionId, reason });
        },
    });

    assert.deepEqual(result.state, idleGitHubAuthUiState);
    assert.match(result.errorMessage || '', /Default browser could not be opened/);
    assert.equal(cancellations.length, 1);
    assert.equal(cancellations[0].sessionId, 'session-456');
    assert.match(cancellations[0].reason, /Browser launch failed/);
});
