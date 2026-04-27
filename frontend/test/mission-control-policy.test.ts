import test from 'node:test';
import assert from 'node:assert/strict';

import { deriveMissionControlPolicy } from '../src/app/scan/[id]/mission-control-policy';

test('scoped scans stay on the shared Mission Control surface by default', () => {
    const policy = deriveMissionControlPolicy({
        scanMode: 'scoped',
        status: 'scoped_executing',
        legacyRecoveryRequested: false,
    });

    assert.equal(policy.isLegacyScopedRecoveryState, false);
    assert.equal(policy.showLegacyRecoveryTools, false);
    assert.equal(policy.showScopedSecondaryContext, true);
    assert.equal(policy.showSharedLiveFindings, true);
});

test('legacy scoped review states keep recovery tools secondary until requested', () => {
    const policy = deriveMissionControlPolicy({
        scanMode: 'scoped',
        status: 'awaiting_review',
        legacyRecoveryRequested: false,
    });

    assert.equal(policy.isLegacyScopedRecoveryState, true);
    assert.equal(policy.showLegacyRecoveryTools, false);
    assert.equal(policy.showScopedSecondaryContext, true);
    assert.equal(policy.showSharedLiveFindings, true);
});

test('legacy scoped review states expose recovery tools when explicitly requested', () => {
    const policy = deriveMissionControlPolicy({
        scanMode: 'scoped',
        status: 'awaiting_review',
        legacyRecoveryRequested: true,
    });

    assert.equal(policy.isLegacyScopedRecoveryState, true);
    assert.equal(policy.showLegacyRecoveryTools, true);
    assert.equal(policy.showScopedSecondaryContext, true);
    assert.equal(policy.showSharedLiveFindings, true);
});

test('exploratory scans keep the shared Mission Control surface without scoped support UI', () => {
    const policy = deriveMissionControlPolicy({
        scanMode: 'exploratory',
        status: 'testing',
        legacyRecoveryRequested: true,
    });

    assert.equal(policy.isLegacyScopedRecoveryState, false);
    assert.equal(policy.showLegacyRecoveryTools, false);
    assert.equal(policy.showScopedSecondaryContext, false);
    assert.equal(policy.showSharedLiveFindings, true);
});
