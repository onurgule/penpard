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
