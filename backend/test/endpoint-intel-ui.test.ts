import test from 'node:test';
import assert from 'node:assert/strict';

import { buildEndpointDisplayRows } from '../../frontend/src/app/scan/[id]/endpoint-intel';

test('buildEndpointDisplayRows exposes source, confidence, classification, and observation labels for Mission Control', () => {
    const rows = buildEndpointDisplayRows({
        scanId: 'scan-1',
        targetUrl: 'http://target.local',
        targetOrigin: 'http://target.local',
        generatedAt: new Date().toISOString(),
        summary: '2 endpoint(s), 1 auth-relevant, 1 seen in Burp, 1 exercised in browser',
        authRelevantCount: 1,
        observedInBurpCount: 1,
        exercisedInBrowserCount: 1,
        jsArtifacts: { count: 1, analyzedCount: 1, totalBytes: 1234 },
        classifications: { login: 1, profile_account: 1 },
        records: [
            {
                id: 'endpoint-1',
                endpoint: 'http://target.local/rest/user/login',
                path: '/rest/user/login',
                methods: ['POST'],
                primarySource: 'js',
                sources: ['js', 'burp'],
                confidence: 0.93,
                classification: 'login',
                likelyAuthRelevant: true,
                observedInBurp: true,
                exercisedInBrowser: true,
                inferredOnly: false,
                notes: ['Login flow'],
                evidence: ['axios-call: api.post("/rest/user/login")'],
                scriptSources: ['http://target.local/assets/app.js'],
                domSources: [],
                authSignals: ['Bearer token'],
                storageKeys: ['token'],
                observedStatusCodes: [200],
            },
        ],
    });

    assert.equal(rows.length, 1);
    assert.equal(rows[0].source, 'js');
    assert.equal(rows[0].classification, 'login');
    assert.equal(rows[0].authBadge, 'auth-relevant');
    assert.equal(rows[0].confidenceLabel, '93%');
    assert.match(rows[0].observedLabel, /Burp/);
    assert.match(rows[0].observedLabel, /Browser/);
    assert.match(rows[0].sourceDetail, /app\.js/);
});
