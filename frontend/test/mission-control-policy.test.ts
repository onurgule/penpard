import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveMissionControlPolicy } from '../src/app/scan/[id]/mission-control-policy';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('scoped scans stay on the shared Mission Control surface by default', () => {
    const policy = deriveMissionControlPolicy({
        scanMode: 'scoped',
        status: 'scoped_executing',
        legacyRecoveryRequested: false,
    });

    assert.equal(policy.isLegacyScopedRecoveryState, false);
    assert.equal(policy.showLegacyRecoveryTools, false);
    assert.equal(policy.showScopedSecondaryContext, true);
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
});

test('scoped support context renders after the shared primary Mission Control grid', () => {
    const source = fs.readFileSync(path.join(__dirname, '../src/app/scan/[id]/MissionControlClient.tsx'), 'utf8');
    const primaryGridIndex = source.indexOf('className="min-h-[calc(100vh-theme(spacing.10))] grid grid-cols-12 gap-6"');
    const supportStripIndex = source.indexOf('<MissionControlScopedSupportStrip');
    const legacyAlternateIndex = source.indexOf('isScopedScan && !showSharedLiveFindings');

    assert.ok(primaryGridIndex > 0, 'primary Mission Control grid should be present');
    assert.ok(supportStripIndex > primaryGridIndex, 'scoped support context must not precede the shared primary grid');
    assert.equal(legacyAlternateIndex, -1, 'default scoped path must not branch into the old alternate scan surface');
});

test('scoped live findings include the exploratory-core vulnerability stream', () => {
    const source = fs.readFileSync(path.join(__dirname, '../src/app/scan/[id]/MissionControlClient.tsx'), 'utf8');

    assert.match(source, /const scopedStandardFindingItems[\s\S]*vulns\.map/);
    assert.match(source, /\[\.\.\.scopedStandardFindingItems,\s*\.\.\.scopedLiveFindingItems\]/);
    assert.match(source, /Burp-visible request evidence/);
});
