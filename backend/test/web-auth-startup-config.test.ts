import test from 'node:test';
import assert from 'node:assert/strict';

import {
    defaultAuthStartupConfig,
    redactAuthStartupConfig,
    resolveAuthStartupConfig,
    toLegacyIdorUsers,
} from '../src/services/web-auth-startup-config';

test('resolveAuthStartupConfig keeps explicit provided credentials and booleans', () => {
    const config = resolveAuthStartupConfig({
        authStartupMode: 'provided_credentials',
        authCredentials: JSON.stringify([
            {
                username: 'alice',
                email: 'alice@example.com',
                password: 'Secret123!',
                role: 'user',
                privilege: 'low',
                label: 'User A',
            },
            {
                username: 'admin',
                password: 'AdminSecret!',
                role: 'admin',
                privilege: 'high',
            },
        ]),
        allowAccountCreation: 'true',
        preferSharedPassword: 'false',
    });

    assert.equal(config.mode, 'provided_credentials');
    assert.equal(config.credentials.length, 2);
    assert.equal(config.credentials[0].username, 'alice');
    assert.equal(config.credentials[0].privilege, 'low');
    assert.equal(config.credentials[1].role, 'admin');
    assert.equal(config.allowAccountCreation, true);
    assert.equal(config.preferSharedPassword, false);
});

test('resolveAuthStartupConfig falls back to no_credentials when provided mode is empty', () => {
    const config = resolveAuthStartupConfig({
        authStartupMode: 'provided_credentials',
        authCredentials: '[]',
        allowAccountCreation: 'false',
    });

    assert.deepEqual(config, {
        mode: 'no_credentials',
        credentials: [],
        allowAccountCreation: false,
        preferSharedPassword: true,
    });
});

test('redactAuthStartupConfig and legacy IDOR mapping preserve structure while hiding passwords', () => {
    const config = resolveAuthStartupConfig({
        authStartupMode: 'provided_credentials',
        authCredentials: JSON.stringify([
            { username: 'alice', password: 'Secret123!', role: 'user', privilege: 'low' },
        ]),
    });

    const redacted = redactAuthStartupConfig(config);
    const legacy = toLegacyIdorUsers(config);

    assert.equal(redacted.credentials[0].password, '[REDACTED]');
    assert.equal(legacy[0].username, 'alice');
    assert.equal(legacy[0].password, 'Secret123!');
    assert.equal(defaultAuthStartupConfig().mode, 'no_credentials');
});
