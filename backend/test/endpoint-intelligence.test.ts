import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { EndpointIntelligenceService } from '../src/services/EndpointIntelligenceService';
import { browserService } from '../src/services/BrowserService';
import { llmProvider } from '../src/services/LLMProviderService';

test('EndpointIntelligenceService extracts auth-relevant endpoints from loaded JS and merges Burp observations', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-endpoint-intel-'));
    const scriptPath = path.join(tempDir, 'app.js');
    fs.writeFileSync(
        scriptPath,
        `
        const api = axios.create({ baseURL: '/rest' });
        api.post('/user/login', payload);
        fetch('/api/profile');
        localStorage.getItem('token');
        sessionStorage.getItem('csrf');
        `,
        'utf8',
    );

    const originalCapture = browserService.captureJavaScriptArtifacts.bind(browserService);
    const originalTraffic = browserService.getTrafficSnapshot.bind(browserService);
    const originalGenerate = llmProvider.generate.bind(llmProvider);

    (browserService as any).captureJavaScriptArtifacts = async () => ([
        {
            id: 'artifact-1',
            sessionId: 'session-1',
            pageUrl: 'http://target.local/login',
            scriptUrl: 'http://target.local/assets/app.js',
            origin: 'http://target.local',
            type: 'external',
            contentType: 'application/javascript',
            contentHash: 'hash-1',
            bytes: fs.statSync(scriptPath).size,
            storedAt: new Date().toISOString(),
            filePath: scriptPath,
            evidence: [],
        },
    ]);
    (browserService as any).getTrafficSnapshot = () => ([
        {
            id: 1,
            kind: 'request',
            method: 'POST',
            url: 'http://target.local/rest/user/login',
            timestamp: new Date().toISOString(),
            originCategory: 'target',
            requestHeaders: {},
        },
    ]);
    (llmProvider as any).generate = async () => ({
        text: JSON.stringify({
            records: [
                {
                    endpoint: 'http://target.local/rest/user/login',
                    classification: 'login',
                    confidence: 0.95,
                    likelyAuthRelevant: true,
                    notes: ['Used in axios login flow'],
                },
            ],
            inferred: [
                {
                    endpoint: 'http://target.local/rest/user/logout',
                    classification: 'logout',
                    confidence: 0.62,
                    notes: ['Logout implied by adjacent session management code'],
                },
            ],
        }),
    });

    const fakeBurp = {
        async callTool() {
            return {
                content: [
                    {
                        text: JSON.stringify({
                            items: [
                                {
                                    method: 'POST',
                                    url: 'http://target.local/rest/user/login',
                                    statusCode: 200,
                                    requestHeaders: { authorization: 'Bearer token' },
                                },
                            ],
                        }),
                    },
                ],
            };
        },
    };

    try {
        const service = new EndpointIntelligenceService('scan-1', 'http://target.local', fakeBurp as any);
        const inventory = await service.buildInventory({
            browserSessionId: 'session-1',
            allowAiClassification: true,
        });

        const login = inventory.records.find((record) => record.path.includes('/rest/user/login'));
        assert.ok(login);
        assert.equal(login?.classification, 'login');
        assert.equal(login?.observedInBurp, true);
        assert.equal(login?.exercisedInBrowser, true);

        const logout = inventory.records.find((record) => record.path.includes('/rest/user/logout'));
        assert.ok(logout);
        assert.equal(logout?.classification, 'logout');
        assert.equal(logout?.inferredOnly, true);

        assert.ok(inventory.records.some((record) => record.storageKeys.includes('token')));
        assert.ok(inventory.summary.includes('auth-relevant'));
    } finally {
        (browserService as any).captureJavaScriptArtifacts = originalCapture;
        (browserService as any).getTrafficSnapshot = originalTraffic;
        (llmProvider as any).generate = originalGenerate;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
