import test from 'node:test';
import assert from 'node:assert/strict';

import {
    createGitHubAppConfigDraft,
    DEFAULT_GITHUB_CALLBACK_URL,
    isGitHubAppConfigDirty,
    requiresGitHubAppClientSecret,
    toGitHubAppConfigPayload,
} from '../src/app/settings/github-oauth-config';

test('createGitHubAppConfigDraft seeds the editable form from the saved summary but never returns the secret', () => {
    const draft = createGitHubAppConfigDraft({
        source: 'ui',
        clientId: 'Iv1.saved',
        callbackUrl: 'http://127.0.0.1:5050/api/integrations/github/callback',
        hasClientSecret: true,
        configured: true,
    });

    assert.deepEqual(draft, {
        clientId: 'Iv1.saved',
        clientSecret: '',
        callbackUrl: 'http://127.0.0.1:5050/api/integrations/github/callback',
    });
});

test('GitHub OAuth config helpers detect dirty state and normalize payload values', () => {
    const summary = {
        source: 'ui' as const,
        clientId: 'Iv1.saved',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
        hasClientSecret: true,
        configured: true,
    };

    assert.equal(isGitHubAppConfigDirty(summary, createGitHubAppConfigDraft(summary)), false);
    assert.equal(isGitHubAppConfigDirty(summary, {
        clientId: ' Iv1.saved ',
        clientSecret: 'new-secret',
        callbackUrl: ` ${DEFAULT_GITHUB_CALLBACK_URL} `,
    }), true);
    assert.deepEqual(toGitHubAppConfigPayload({
        clientId: ' Iv1.saved ',
        clientSecret: ' new-secret ',
        callbackUrl: ` ${DEFAULT_GITHUB_CALLBACK_URL} `,
    }), {
        clientId: 'Iv1.saved',
        clientSecret: 'new-secret',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
    });
});

test('requiresGitHubAppClientSecret only allows blank secrets when a saved UI secret already exists', () => {
    assert.equal(requiresGitHubAppClientSecret({
        source: 'ui',
        clientId: 'Iv1.saved',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
        hasClientSecret: true,
        configured: true,
    }, {
        clientId: 'Iv1.saved',
        clientSecret: '',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
    }), false);

    assert.equal(requiresGitHubAppClientSecret({
        source: 'environment',
        clientId: 'Iv1.env',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
        hasClientSecret: true,
        configured: true,
    }, {
        clientId: 'Iv1.env',
        clientSecret: '',
        callbackUrl: DEFAULT_GITHUB_CALLBACK_URL,
    }), true);
});
