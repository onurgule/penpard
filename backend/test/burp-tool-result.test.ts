import test from 'node:test';
import assert from 'node:assert/strict';

import {
    normalizeCookiesAndAuthEntries,
    normalizeProxyHistoryItems,
    normalizeSendHttpResponse,
    normalizeSessionCookieResult,
} from '../src/services/burp-tool-result';

test('normalizeProxyHistoryItems unwraps MCP-wrapped Burp history payloads', () => {
    const wrapped = {
        content: [{
            text: JSON.stringify({
                items: [
                    { url: 'https://app.example.com/login', method: 'GET' },
                    { url: 'https://app.example.com/api/session', method: 'POST' },
                ],
            }),
        }],
    };

    const items = normalizeProxyHistoryItems(wrapped);
    assert.equal(items.length, 2);
    assert.equal(items[1].url, 'https://app.example.com/api/session');
});

test('normalizeSendHttpResponse unwraps MCP send_http_request payloads', () => {
    const wrapped = {
        content: [{
            text: JSON.stringify({
                statusCode: 302,
                headers: {
                    location: '/dashboard',
                    'set-cookie': 'session=abc123; Path=/; HttpOnly',
                },
                body: '',
            }),
        }],
    };

    const normalized = normalizeSendHttpResponse(wrapped);
    assert.equal(normalized.statusCode, 302);
    assert.equal((normalized.headers as Record<string, string>).location, '/dashboard');
    assert.equal(normalized.body, '');
});

test('cookie/auth and session helpers unwrap MCP-wrapped payloads', () => {
    const authEntries = normalizeCookiesAndAuthEntries({
        content: [{
            text: JSON.stringify({
                entries: [{ url: 'https://app.example.com/api/me', authHeader: 'Bearer token' }],
            }),
        }],
    });
    const sessionCookies = normalizeSessionCookieResult({
        content: [{
            text: JSON.stringify({
                cookieHeader: 'session=abc123',
                fromUrl: 'https://app.example.com/login',
            }),
        }],
    });

    assert.equal(authEntries.length, 1);
    assert.equal(authEntries[0].authHeader, 'Bearer token');
    assert.equal(sessionCookies.cookieHeader, 'session=abc123');
    assert.equal(sessionCookies.fromUrl, 'https://app.example.com/login');
});
