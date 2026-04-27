import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-scoped-launch-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { scanLaunchConfigService } = require('../src/services/runtime/ScanLaunchConfigService') as typeof import('../src/services/runtime/ScanLaunchConfigService');
const { scopeEnvelopeService } = require('../src/services/runtime/ScopeEnvelopeService') as typeof import('../src/services/runtime/ScopeEnvelopeService');
const { ScopedScanLaunchService } = require('../src/services/runtime/ScopedScanLaunchService') as typeof import('../src/services/runtime/ScopedScanLaunchService');

test('ScopedScanLaunchService persists scan mode, objective, envelope, and initial request before launching the scoped mission runtime', async () => {
    await dbModule.initDatabase();

    const launchPlan = scanLaunchConfigService.prepareBurpLaunch({
        userId: 1,
        scanMode: 'scoped',
        initialRequest: 'GET /api/orders/1 HTTP/1.1\nHost: app.example.com\n\n',
        sourcePackagePath: '/tmp/source',
        sourceAnalysisMode: 'full_source_aware',
    });

    const capturedMissionLaunches: any[] = [];
    const service = new ScopedScanLaunchService(
        dbModule.db,
        scopeEnvelopeService,
        {
            launchScopedMission: (scanId, targetUrl) => {
                capturedMissionLaunches.push({ scanId, targetUrl });
            },
        },
        undefined,
    );

    service.launch({
        scanId: 'scoped-launch-1',
        userId: 1,
        targetUrl: 'https://app.example.com',
        requestBody: {
            scanMode: 'scoped',
            focusedObjective: JSON.stringify({
                title: 'Orders API bounded test',
                scopeType: 'request_scoped',
                goal: 'Validate object-level access control around order lookups.',
                riskTags: ['idor'],
            }),
            scopeEnvelope: JSON.stringify({
                boundaryHints: ['Stay within order detail requests'],
                outOfScopeNotes: ['Do not enumerate admin order export routes'],
            }),
            authStartupMode: 'no_credentials',
        },
        scanMetadata: launchPlan.scanMetadata,
        persistedConfig: launchPlan.persistedConfig,
        runtimeConfig: launchPlan.runtimeConfig,
        initialRequest: 'GET /api/orders/1 HTTP/1.1\nHost: app.example.com\n\n',
    });

    const scan = dbModule.getScan('scoped-launch-1');
    const objective = dbModule.getFocusedTestObjective('scoped-launch-1');
    const envelope = dbModule.getScopeEnvelope('scoped-launch-1');
    const structuredRequest = dbModule.getScopedTestRequest('scoped-launch-1');
    const discoveryState = dbModule.getScopedFeatureDiscoveryState('scoped-launch-1');

    assert.equal(scan.scan_mode, 'scoped');
    assert.equal(scan.status, 'scoped_discovering');
    assert.equal(scan.initial_request, 'GET /api/orders/1 HTTP/1.1\nHost: app.example.com');
    assert.ok(objective);
    assert.equal(objective?.title, 'Orders API bounded test');
    assert.ok(envelope);
    assert.deepEqual(envelope?.allowedHosts, ['app.example.com']);
    assert.deepEqual(envelope?.allowedRoutes, ['/api/orders/1']);
    assert.equal(envelope?.baselineRequestRefs.length, 1);
    assert.equal(structuredRequest?.description, 'Validate object-level access control around order lookups.');
    assert.equal(discoveryState?.phase, 'not_started');
    assert.equal(capturedMissionLaunches.length, 1);
    assert.equal(capturedMissionLaunches[0].scanId, 'scoped-launch-1');
    assert.equal(capturedMissionLaunches[0].targetUrl, 'https://app.example.com');
});
