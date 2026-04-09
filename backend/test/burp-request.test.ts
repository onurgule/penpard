import test from 'node:test';
import assert from 'node:assert/strict';

import { prepareBurpDispatchRequest, serializeStructuredBurpRequest } from '../src/services/burp-request';

test('prepareBurpDispatchRequest normalizes full-URL request lines for Burp tool dispatch', () => {
    const prepared = prepareBurpDispatchRequest({
        rawRequest: [
            'POST https://app.example.com:8443/api/items?id=7 HTTP/1.1',
            'User-Agent: PenPard-Test',
            'Content-Type: application/json',
            '',
            '{"name":"demo"}',
        ].join('\r\n'),
    });

    assert.ok(prepared);
    assert.equal(prepared.host, 'app.example.com');
    assert.equal(prepared.port, 8443);
    assert.equal(prepared.useHttps, true);
    assert.equal(prepared.fullUrl, 'https://app.example.com:8443/api/items?id=7');
    assert.match(prepared.request, /^POST \/api\/items\?id=7 HTTP\/1\.1/m);
    assert.match(prepared.request, /^Host: app\.example\.com:8443$/m);
});

test('prepareBurpDispatchRequest can rebuild a Burp-ready request from structured fallback input', () => {
    const structuredRaw = serializeStructuredBurpRequest({
        method: 'GET',
        url: 'http://internal.example.com:8080/health',
        headers: {
            Authorization: 'Bearer demo-token',
        },
    });
    const prepared = prepareBurpDispatchRequest({
        rawRequest: structuredRaw,
        url: 'http://internal.example.com:8080/health',
    });

    assert.ok(prepared);
    assert.equal(prepared.host, 'internal.example.com');
    assert.equal(prepared.port, 8080);
    assert.equal(prepared.useHttps, false);
    assert.equal(prepared.fullUrl, 'http://internal.example.com:8080/health');
    assert.match(prepared.request, /^GET \/health HTTP\/1\.1/m);
    assert.match(prepared.request, /^Authorization: Bearer demo-token$/m);
});
