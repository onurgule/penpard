import test from 'node:test';
import assert from 'node:assert/strict';

import { RequestHarvester } from '../src/services/RequestHarvester';

test('RequestHarvester ignores localhost leakage and socket polling noise', async () => {
    const harvester = new RequestHarvester();
    const fakeBurp = {
        async callTool() {
            return {
                content: [
                    {
                        text: JSON.stringify({
                            items: [
                                {
                                    method: 'GET',
                                    url: 'http://localhost:3000/api/status',
                                    statusCode: 200,
                                    requestHeaders: {},
                                    responseHeaders: {},
                                },
                                {
                                    method: 'GET',
                                    url: 'http://target.local/create-account/socket.io/?EIO=4&transport=polling&t=PriFI0R',
                                    statusCode: 200,
                                    requestHeaders: {},
                                    responseHeaders: {},
                                },
                                {
                                    method: 'POST',
                                    url: 'http://target.local/rest/user/login',
                                    statusCode: 401,
                                    requestHeaders: { 'content-type': 'application/json' },
                                    responseHeaders: { 'content-type': 'application/json' },
                                    requestBody: '{"email":"admin@example.com","password":"badpass"}',
                                    responseBody: '{"error":"Unauthorized"}',
                                },
                            ],
                        }),
                    },
                ],
            };
        },
    };

    const harvested = await harvester.harvest(fakeBurp as any, 'target.local');

    assert.equal(harvested.length, 1);
    assert.equal(harvested[0].url, 'http://target.local/rest/user/login');
    assert.equal(harvested[0].classification, 'authentication');

    const promoted = harvester.getPromotionCandidates(5);
    assert.equal(promoted.some((item) => item.request.url.includes('socket.io')), false);
    assert.equal(promoted.some((item) => item.request.url.includes('localhost')), false);
});

test('RequestHarvester filters harvested traffic through the scoped mission policy callback', async () => {
    const blocked: Array<{ url: string; reason: string }> = [];
    const harvester = new RequestHarvester({
        allowRequest(request) {
            if (request.path.startsWith('/api/orders')) {
                return { allowed: true };
            }
            return {
                allowed: false,
                reason: `Scoped mission excludes ${request.path}`,
            };
        },
        onPolicyBlock(request, reason) {
            blocked.push({ url: request.url, reason });
        },
    });
    const fakeBurp = {
        async callTool() {
            return {
                content: [
                    {
                        text: JSON.stringify({
                            items: [
                                {
                                    method: 'GET',
                                    url: 'https://app.example.com/api/orders/1',
                                    statusCode: 200,
                                    requestHeaders: { authorization: 'Bearer token' },
                                    responseHeaders: { 'content-type': 'application/json' },
                                    responseBody: '{"id":1}',
                                },
                                {
                                    method: 'GET',
                                    url: 'https://app.example.com/api/admin/users',
                                    statusCode: 200,
                                    requestHeaders: { authorization: 'Bearer token' },
                                    responseHeaders: { 'content-type': 'application/json' },
                                    responseBody: '{"items":[]}',
                                },
                            ],
                        }),
                    },
                ],
            };
        },
    };

    const harvested = await harvester.harvest(fakeBurp as any, 'app.example.com');
    const promoted = harvester.getPromotionCandidates(5);

    assert.equal(harvested.length, 1);
    assert.equal(harvested[0].path, '/api/orders/1');
    assert.equal(promoted.length, 1);
    assert.equal(promoted[0].request.path, '/api/orders/1');
    assert.deepEqual(blocked, [{
        url: 'https://app.example.com/api/admin/users',
        reason: 'Scoped mission excludes /api/admin/users',
    }]);
});
