import test from 'node:test';
import assert from 'node:assert/strict';

const {
    categorizeBrowserUrl,
    getTargetOrigin,
    isPenPardInternalUrl,
    resolveBrowserRestoreUrl,
} = require('../src/services/browser/BrowserUrlPolicy') as typeof import('../src/services/browser/BrowserUrlPolicy');

test('browser URL policy distinguishes target, PenPard internal, and external traffic', () => {
    const targetOrigin = getTargetOrigin('https://app.example.com/account');

    assert.equal(categorizeBrowserUrl('https://app.example.com/api/me', targetOrigin), 'target');
    assert.equal(categorizeBrowserUrl('http://127.0.0.1:3000/api/browser/state', targetOrigin), 'internal');
    assert.equal(categorizeBrowserUrl('https://cdn.example.net/app.js', targetOrigin), 'external');
    assert.equal(isPenPardInternalUrl('electron://penpard/browser', targetOrigin), true);
    assert.equal(isPenPardInternalUrl('https://app.example.com/dashboard', targetOrigin), false);
});

test('browser restore policy falls back to the target URL when the last page was internal', () => {
    const targetOrigin = getTargetOrigin('https://app.example.com/account');

    assert.equal(
        resolveBrowserRestoreUrl(
            {
                lastKnownUrl: 'http://127.0.0.1:3000/api/browser/state',
                targetUrl: 'https://app.example.com/account',
                targetOrigin,
            },
            'http://127.0.0.1:3000/api/browser/state',
        ),
        'https://app.example.com/account',
    );

    assert.equal(
        resolveBrowserRestoreUrl(
            {
                lastKnownUrl: 'https://app.example.com/orders/7',
                targetUrl: 'https://app.example.com/account',
                targetOrigin,
            },
            'https://app.example.com/orders/7',
        ),
        'https://app.example.com/orders/7',
    );
});
