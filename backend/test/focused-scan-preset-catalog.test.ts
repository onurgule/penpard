import test from 'node:test';
import assert from 'node:assert/strict';

import { buildFocusedScanPrompt, resolveFocusedScanTarget } from '../src/services/FocusedScanPresetCatalog';

test('focused scan preset catalog returns the stored SQLi attack prompt with injected endpoints', () => {
    const prompt = buildFocusedScanPrompt({
        type: 'sqli',
        endpoints: ['GET https://app.example.com/api/users?id=1'],
        targetHosts: ['https://app.example.com'],
    });

    assert.match(prompt, /FOCUSED SQL INJECTION SCAN/);
    assert.match(prompt, /Time-based blind/);
    assert.match(prompt, /GET https:\/\/app\.example\.com\/api\/users\?id=1/);
});

test('focused scan preset catalog keeps a safe generic fallback for unknown assisted scan types', () => {
    const prompt = buildFocusedScanPrompt({
        type: 'csrf' as any,
        endpoints: ['POST https://app.example.com/api/profile'],
        targetHosts: [],
    });

    assert.equal(
        prompt,
        'Test the following endpoints for csrf vulnerabilities:\nPOST https://app.example.com/api/profile',
    );
});

test('focused scan preset catalog resolves assisted scan targets consistently across callers', () => {
    assert.equal(resolveFocusedScanTarget({
        type: 'xss',
        endpoints: ['GET https://app.example.com/search?q=test'],
        targetHosts: ['https://app.example.com'],
    }), 'https://app.example.com');

    assert.equal(resolveFocusedScanTarget({
        type: 'xss',
        endpoints: ['GET https://app.example.com/search?q=test'],
        targetHosts: [],
    }), 'https://app.example.com/search?q=test');

    assert.equal(resolveFocusedScanTarget({
        type: 'xss',
        endpoints: [],
        targetHosts: [],
    }, 'unknown'), 'unknown');
});
