import test from 'node:test';
import assert from 'node:assert/strict';

const {
    ScopeEnvelopeService,
    ScopedScanValidationError,
} = require('../src/services/runtime/ScopeEnvelopeService') as typeof import('../src/services/runtime/ScopeEnvelopeService');

test('buildScopedArtifacts normalizes routes, derives hosts, creates baseline refs, and summarizes auth context without secrets', () => {
    const service = new ScopeEnvelopeService();

    const prepared = service.buildScopedArtifacts({
        scanId: 'scan-scope-1',
        targetUrl: 'https://app.example.com/account',
        focusedObjective: JSON.stringify({
            title: 'Account API bounded test',
            scopeType: 'endpoint_scoped',
            goal: 'Validate object-level access control around profile reads.',
            riskTags: ['idor', 'authz'],
        }),
        scopeEnvelope: JSON.stringify({
            selectedEndpoints: [
                { method: 'get', path: 'api/users' },
                { method: 'GET', url: 'https://app.example.com/api/users?id=1', source: 'ai' },
                { method: 'POST', path: '/api/profile/update', source: 'static' },
            ],
            boundaryHints: ['Stay inside authenticated account APIs'],
            outOfScopeNotes: ['Do not fuzz admin endpoints'],
        }),
        authStartupMode: 'provided_credentials',
        authCredentials: JSON.stringify([{ username: 'alice', password: 'super-secret' }]),
        sessionCookies: 'session=abc123',
        initialRequest: 'GET /api/users?id=1 HTTP/1.1\nHost: app.example.com\n\n',
    });

    assert.equal(prepared.objective.scopeType, 'endpoint_scoped');
    assert.deepEqual(prepared.objective.riskTags, ['idor', 'authz']);
    assert.deepEqual(prepared.envelope.allowedHosts, ['app.example.com']);
    assert.deepEqual(prepared.envelope.allowedRoutes, ['/api/users', '/api/profile/update']);
    assert.equal(prepared.envelope.selectedEndpoints.length, 2);
    assert.equal(prepared.envelope.baselineRequestRefs.length, 1);
    assert.equal(prepared.envelope.baselineRequestRefs[0].kind, 'scan_initial_request');
    assert.equal(prepared.envelope.authContext?.providedCredentialCount, 1);
    assert.equal(prepared.envelope.authContext?.hasSessionCookies, true);
    assert.equal(prepared.envelope.authContext?.hasInitialRequestBaseline, true);
    assert.equal(prepared.envelope.authContext?.continuityStrategy, 'burp_baseline');
    assert.ok(!prepared.envelope.authContext?.summary.includes('super-secret'));
});

test('buildScopedArtifacts rejects malformed scoped payloads', () => {
    const service = new ScopeEnvelopeService();

    assert.throws(() => service.buildScopedArtifacts({
        scanId: 'scan-scope-invalid',
        targetUrl: 'https://app.example.com',
        scopeEnvelope: '{"selectedEndpoints":"oops"}',
    }), ScopedScanValidationError);
});

test('buildScopedArtifacts requires a real scope anchor', () => {
    const service = new ScopeEnvelopeService();

    assert.throws(() => service.buildScopedArtifacts({
        scanId: 'scan-scope-anchor',
        targetUrl: 'https://app.example.com',
        focusedObjective: JSON.stringify({
            scopeType: 'endpoint_scoped',
        }),
        scopeEnvelope: JSON.stringify({
            selectedEndpoints: [],
            boundaryHints: [],
            outOfScopeNotes: [],
        }),
    }), /Scoped scans require selected endpoints, a Burp baseline request, or boundary notes/i);
});
