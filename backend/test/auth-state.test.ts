import test from 'node:test';
import assert from 'node:assert/strict';

import {
    AuthStateManager,
    CookieJar,
    CSRFManager,
    IdentityRegistry,
    SessionHealthMonitor,
    TokenStore,
} from '../src/services/auth';

function createManager(targetUrl: string = 'https://app.example.com'): AuthStateManager {
    const manager = new AuthStateManager('scan-test', targetUrl);
    manager.identityRegistry.createPrimary();
    return manager;
}

test('CookieJar keeps host-only cookies on the exact host and preserves same-name path variants', () => {
    const jar = new CookieJar('primary-user');

    jar.parseAndStore('sid=host-only; Path=/; HttpOnly', 'app.example.com', 'operator_input');
    jar.parseAndStore('sid=domain-cookie; Domain=example.com; Path=/; HttpOnly', 'app.example.com', 'operator_input');
    jar.parseAndStore('pref=global; Domain=example.com; Path=/', 'app.example.com', 'operator_input');
    jar.parseAndStore('pref=api; Domain=example.com; Path=/api', 'app.example.com', 'operator_input');

    const subdomainCookies = jar.resolve('https://api.example.com/api/users');
    assert.ok(subdomainCookies.includes('sid=domain-cookie'));
    assert.ok(!subdomainCookies.includes('sid=host-only'));
    assert.ok(subdomainCookies.indexOf('pref=api') < subdomainCookies.indexOf('pref=global'));

    const exactHostCookies = jar.resolve('https://app.example.com/');
    assert.ok(exactHostCookies.includes('sid=host-only'));
});

test('AuthStateManager strips stale explicit auth when switching identities or going anonymous', () => {
    const manager = createManager();

    manager.identityRegistry.createSecondary('idor-user-1', 'User B');
    manager.capture.fromOperatorCookies('session=primary', 'app.example.com', 'primary-user');
    manager.capture.fromOperatorAuthHeader('Bearer primary-token-1234567890', 'primary-user');
    manager.capture.fromOperatorCookies('session=secondary', 'app.example.com', 'idor-user-1');
    manager.capture.fromOperatorAuthHeader('Bearer secondary-token-1234567890', 'idor-user-1');

    const switched = manager.prepareRequest(
        {
            Authorization: 'Bearer stale-token',
            Cookie: 'session=stale',
            'X-API-Key': 'stale-api-key',
        },
        '',
        'https://app.example.com/api/me',
        'GET',
        'idor-user-1',
        false,
    );

    assert.equal(switched.headers.Authorization, 'Bearer secondary-token-1234567890');
    assert.equal(switched.headers.Cookie, 'session=secondary');
    assert.ok(!('X-API-Key' in switched.headers));

    const anonymous = manager.prepareRequest(
        {
            Authorization: 'Bearer stale-token',
            Cookie: 'session=stale',
        },
        '',
        'https://app.example.com/api/me',
        'GET',
        IdentityRegistry.ANONYMOUS_ID,
        false,
    );

    assert.ok(!('Authorization' in anonymous.headers));
    assert.ok(!('Cookie' in anonymous.headers));
});

test('preserveExplicitAuth keeps the explicit request untouched', () => {
    const manager = createManager();

    manager.capture.fromOperatorCookies('session=primary', 'app.example.com', 'primary-user');
    manager.capture.fromOperatorAuthHeader('Bearer primary-token-1234567890', 'primary-user');

    const explicit = manager.prepareRequest(
        {
            Authorization: 'Bearer exact-token',
            Cookie: 'session=exact',
        },
        'name=test',
        'https://app.example.com/api/me',
        'POST',
        'primary-user',
        true,
    );

    assert.equal(explicit.headers.Authorization, 'Bearer exact-token');
    assert.equal(explicit.headers.Cookie, 'session=exact');
    assert.equal(explicit.body, 'name=test');
});

test('AuthStateManager suppresses managed auth on anonymous login and register probes', () => {
    const manager = createManager();

    manager.capture.fromOperatorCookies('session=primary', 'app.example.com', 'primary-user');
    manager.capture.fromOperatorAuthHeader('Bearer primary-token-1234567890', 'primary-user');

    const loginProbe = manager.prepareRequest(
        undefined,
        '{"email":"user@example.com","password":"badpass"}',
        'https://app.example.com/rest/user/login',
        'POST',
        'primary-user',
        false,
        'anonymous_auth_probe',
    );
    assert.ok(!('Authorization' in loginProbe.headers));
    assert.ok(!('Cookie' in loginProbe.headers));

    const registrationProbe = manager.prepareRequest(
        undefined,
        '{"email":"new@example.com","password":"PenPard!123"}',
        'https://app.example.com/create-account',
        'POST',
        'primary-user',
        false,
        'account_creation',
    );
    assert.ok(!('Authorization' in registrationProbe.headers));
    assert.ok(!('Cookie' in registrationProbe.headers));

    const diagnostics = manager.assessPreparedRequest({
        originalHeaders: undefined,
        preparedHeaders: loginProbe.headers,
        url: 'https://app.example.com/rest/user/login',
        method: 'POST',
        identityId: 'primary-user',
        preserveExplicitAuth: false,
        intent: 'anonymous_auth_probe',
    });
    assert.equal(diagnostics.authSuppressedForIntent, true);
    assert.equal(diagnostics.isAuthBootstrapRoute, true);
    assert.equal(diagnostics.likelyRequiresAuth, false);
});

test('CSRFManager uses deterministic precedence for header and body sources', () => {
    const csrf = new CSRFManager('primary-user');

    csrf.store({
        tokenName: 'csrf-token',
        tokenValue: 'meta-token',
        deliveryMechanism: 'meta_tag',
        rotatesPerRequest: false,
    });
    csrf.store({
        tokenName: '_csrf',
        tokenValue: 'body-token',
        deliveryMechanism: 'hidden_input',
        rotatesPerRequest: false,
    });
    csrf.store({
        tokenName: 'X-CSRF-Token',
        tokenValue: 'header-token',
        deliveryMechanism: 'response_header',
        headerName: 'X-CSRF-Token',
        rotatesPerRequest: false,
    });
    csrf.store({
        tokenName: 'XSRF-TOKEN',
        tokenValue: 'cookie-token',
        deliveryMechanism: 'cookie_to_header',
        headerName: 'X-XSRF-TOKEN',
        cookieName: 'XSRF-TOKEN',
        rotatesPerRequest: false,
    });

    const headerFields = csrf.getHeadersForRequest();
    const bodyFields = csrf.getBodyFieldsForRequest();

    assert.equal(Object.keys(headerFields)[0], 'X-XSRF-TOKEN');
    assert.equal(Object.keys(bodyFields)[0], '_csrf');
});

test('SessionHealthMonitor refresh uses stored metadata, rotates tokens, and captures cookies', async () => {
    const identities = new IdentityRegistry('scan-test');
    identities.createPrimary();

    const tokenStore = new TokenStore('primary-user');
    tokenStore.storeRefreshToken(
        'refresh-token-1234567890',
        'https://app.example.com/auth/refresh',
        'operator_input',
        '{"refresh_token":"{{refresh_token}}"}',
        'data.access_token',
    );

    const cookieJar = new CookieJar('primary-user');
    cookieJar.parseCookieHeader('session=old-session', 'app.example.com', 'operator_input');

    const tokenStores = new Map<string, TokenStore>([['primary-user', tokenStore]]);
    const cookieJars = new Map<string, CookieJar>([['primary-user', cookieJar]]);
    const monitor = new SessionHealthMonitor(identities, tokenStores, cookieJars, 'https://app.example.com');
    monitor.initializeHealth('primary-user');

    const strategy = monitor.autoDetectRefreshStrategy('primary-user');
    const plan = monitor.setRefreshPlan('primary-user', strategy);

    assert.equal(strategy, 'jwt_refresh');
    assert.equal(plan.refreshEndpoint, 'https://app.example.com/auth/refresh');
    assert.equal(plan.newAccessTokenPath, 'data.access_token');

    const fakeBurp = {
        async callTool(tool: string, args: Record<string, any>) {
            assert.equal(tool, 'send_http_request');
            assert.equal(args.url, 'https://app.example.com/auth/refresh');
            assert.equal(args.headers.Cookie, 'session=old-session');
            return {
                status: 200,
                headers: {
                    'set-cookie': ['session=new-session; Path=/; HttpOnly'],
                },
                body: JSON.stringify({
                    data: {
                        access_token: 'new-access-token-1234567890',
                    },
                    refresh_token: 'refresh-token-2222222222',
                }),
            };
        },
    };

    const refreshed = await monitor.executeRefresh('primary-user', fakeBurp as any);
    assert.equal(refreshed, true);
    assert.equal(tokenStore.formatAuthHeader(), 'Bearer new-access-token-1234567890');
    assert.equal(tokenStore.getRefreshToken()?.value, 'refresh-token-2222222222');
    assert.ok(cookieJar.resolve('https://app.example.com/').includes('session=new-session'));
});

test('SessionHealthMonitor does not kill the session on anonymous auth probing 401s', () => {
    const identities = new IdentityRegistry('scan-test');
    identities.createPrimary();
    const monitor = new SessionHealthMonitor(
        identities,
        new Map([['primary-user', new TokenStore('primary-user')]]),
        new Map([['primary-user', new CookieJar('primary-user')]]),
        'https://app.example.com',
    );
    monitor.initializeHealth('primary-user');

    const result = monitor.analyzeResponse('primary-user', 401, {}, '', 'anonymous_auth_probe');
    assert.equal(result.needsRefresh, false);
    assert.equal(result.needsRelogin, false);
});

test('AuthStateManager captures browser cookies and storage tokens for later requests', () => {
    const manager = createManager();

    manager.syncFromBrowser([{
        name: 'browser_session',
        value: 'browser-cookie',
        domain: 'app.example.com',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
    }], 'primary-user');

    manager.syncFromBrowserStorage({
        localStorageData: {
            access_token: 'browser-access-token-1234567890',
        },
    }, 'primary-user');

    const prepared = manager.prepareRequest(
        undefined,
        '',
        'https://app.example.com/api/profile',
        'GET',
        'primary-user',
        false,
    );

    assert.equal(prepared.headers.Cookie, 'browser_session=browser-cookie');
    assert.equal(prepared.headers.Authorization, 'Bearer browser-access-token-1234567890');
});
