import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
    buildScopedSecurityTestRequest,
    createDefaultScopedRequestIntake,
    splitMultilineList,
    validateScopedRequestIntake,
} from '../src/app/scan/web/scoped-request-intake';

test('scoped request intake defaults are empty and validation requires description in scoped mode', () => {
    const defaults = createDefaultScopedRequestIntake();

    assert.equal(defaults.description, '');
    assert.equal(defaults.environment, '');
    assert.equal(defaults.loginPresent, 'unknown');
    assert.equal(
        validateScopedRequestIntake('https://app.example.com/feature', defaults),
        'Request description is required in Scoped Test Mode.',
    );
    assert.equal(
        validateScopedRequestIntake('', {
            ...defaults,
            description: 'Test the new checkout confirmation flow.',
        }),
        'Target URL is required.',
    );
});

test('scoped request intake builds the structured payload from url and optional metadata', () => {
    const payload = buildScopedSecurityTestRequest('https://app.example.com/feature', {
        description: 'Validate the new checkout confirmation flow for authz and state leaks.',
        environment: 'staging',
        serviceName: 'Storefront',
        testData: 'order-1001, order-1002',
        testUsers: 'alice@example.com\nbob@example.com',
        loginPresent: 'present',
        authMechanismHints: 'session cookie\nsso',
        hasScreenshotOrAttachment: true,
        attachmentMetadata: 'screenshot:checkout confirmation\nspec:release note',
        attachmentSummary: 'Includes the new confirmation screen and the primary CTA.',
        newScreenCount: '2',
        newInputCount: '1',
        operatorNotes: 'Keep discovery bounded around checkout confirmation.',
    });

    assert.deepEqual(payload, {
        targetUrl: 'https://app.example.com/feature',
        description: 'Validate the new checkout confirmation flow for authz and state leaks.',
        environment: 'staging',
        serviceName: 'Storefront',
        testData: ['order-1001', 'order-1002'],
        testUsers: ['alice@example.com', 'bob@example.com'],
        loginPresent: true,
        authMechanismHints: ['session cookie', 'sso'],
        hasScreenshotOrAttachment: true,
        attachmentMetadata: [
            { kind: 'screenshot', label: 'checkout confirmation' },
            { kind: 'spec', label: 'release note' },
        ],
        attachmentSummary: 'Includes the new confirmation screen and the primary CTA.',
        newScreenCount: 2,
        newInputCount: 1,
        operatorNotes: 'Keep discovery bounded around checkout confirmation.',
    });
});

test('scoped request helper normalizes multiline lists and scan creation page hides endpoint extraction UI', () => {
    assert.deepEqual(
        splitMultilineList('alpha, beta\nalpha\n gamma '),
        ['alpha', 'beta', 'gamma'],
    );

    const pageSource = readFileSync(
        join(process.cwd(), 'src', 'app', 'scan', 'web', 'page.tsx'),
        'utf8',
    );

    assert.match(pageSource, /Structured Security Test Request/);
    assert.doesNotMatch(pageSource, /Extract Endpoints from Codebase/);
    assert.doesNotMatch(pageSource, /Deep Scan with AI/);
    assert.doesNotMatch(pageSource, /selectedEndpointKeys/);
    assert.match(pageSource, /scanMode !== 'scoped' && \(/);
});
