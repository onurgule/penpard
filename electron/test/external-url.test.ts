import test from 'node:test';
import assert from 'node:assert/strict';

import { isSafeExternalUrl, openExternalUrl } from '../external-url';

test('isSafeExternalUrl only allows https and loopback http URLs', () => {
    assert.equal(isSafeExternalUrl('https://github.com/login/oauth/authorize'), true);
    assert.equal(isSafeExternalUrl('http://127.0.0.1:4000/api/integrations/github/callback'), true);
    assert.equal(isSafeExternalUrl('http://localhost:4000/api/integrations/github/callback'), false);
    assert.equal(isSafeExternalUrl('file:///tmp/test'), false);
});

test('openExternalUrl awaits the browser opener and reports success only after it resolves', async () => {
    const opened: string[] = [];

    const result = await openExternalUrl('https://github.com/login/oauth/authorize', async (url) => {
        opened.push(url);
    });

    assert.deepEqual(opened, ['https://github.com/login/oauth/authorize']);
    assert.deepEqual(result, { success: true });
});

test('openExternalUrl surfaces opener failures instead of pretending success', async () => {
    const result = await openExternalUrl('https://github.com/login/oauth/authorize', async () => {
        throw new Error('No browser handler registered');
    });

    assert.equal(result.success, false);
    assert.match(result.error || '', /No browser handler registered/);
});
