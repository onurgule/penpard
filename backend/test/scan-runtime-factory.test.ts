import test from 'node:test';
import assert from 'node:assert/strict';

const { createScan, addVulnerability, getScan, initDatabase, setScanInitialRequest } = require('../src/db/init') as typeof import('../src/db/init');
const { BurpMCPClient } = require('../src/services/burp-mcp') as typeof import('../src/services/burp-mcp');
const { ScanRuntimeFactory } = require('../src/services/runtime/ScanRuntimeFactory') as typeof import('../src/services/runtime/ScanRuntimeFactory');

async function withAvailableBurp<T>(run: () => Promise<T>): Promise<T> {
    const originalIsAvailable = BurpMCPClient.prototype.isAvailable;
    const originalDisconnect = BurpMCPClient.prototype.disconnect;

    BurpMCPClient.prototype.isAvailable = async () => true;
    BurpMCPClient.prototype.disconnect = () => {};

    try {
        return await run();
    } finally {
        BurpMCPClient.prototype.isAvailable = originalIsAvailable;
        BurpMCPClient.prototype.disconnect = originalDisconnect;
    }
}

test('createWebRuntime keeps the active web path on the composed single-agent runtime', async () => {
    await initDatabase();

    await withAvailableBurp(async () => {
        const factory = new ScanRuntimeFactory();
        const runtime = await factory.createWebRuntime('scan-runtime-factory-web', 'https://app.example.com', {
            parallelAgents: 4,
        });

        assert.equal(runtime.kind, 'agent');
        assert.equal(runtime.scanMode, 'exploratory');
        assert.equal(runtime.executionMode, 'single-agent');
        assert.equal(typeof runtime.agent.start, 'function');
        assert.equal(runtime.agent.getState().isRunning, false);
        runtime.burp.disconnect();
    });
});

test('createScopedWebRuntime keeps scoped launches on the hardened single-agent runtime path', async () => {
    await initDatabase();

    await withAvailableBurp(async () => {
        const factory = new ScanRuntimeFactory();
        const runtime = await factory.createScopedWebRuntime('scan-runtime-factory-scoped', 'https://app.example.com', {
            scanMode: 'scoped',
            focusedTestObjective: {
                id: 'objective-1',
                scanId: 'scan-runtime-factory-scoped',
                title: 'Scoped checkout test',
                scopeType: 'endpoint_scoped',
                riskTags: ['idor'],
            },
            scopeEnvelope: {
                id: 'envelope-1',
                scanId: 'scan-runtime-factory-scoped',
                version: 1,
                allowedHosts: ['app.example.com'],
                allowedRoutes: ['/api/checkout'],
                selectedEndpoints: [{ method: 'POST', path: '/api/checkout' }],
                baselineRequestRefs: [],
                requestBundleRefs: [],
                authContext: null,
                outOfScopeNotes: [],
                boundaryHints: [],
                explorationBudget: null,
            },
        });

        assert.equal(runtime.kind, 'agent');
        assert.equal(runtime.scanMode, 'scoped');
        assert.equal(runtime.executionMode, 'single-agent');
        runtime.burp.disconnect();
    });
});

test('createContinuationRuntime restores existing scan context before lifecycle control resumes', async () => {
    await initDatabase();

    const scanId = `scan-runtime-factory-continuation-${Date.now()}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
    });
    setScanInitialRequest(scanId, 'GET https://app.example.com/api/raw HTTP/1.1');
    addVulnerability({
        scanId,
        name: 'IDOR',
        severity: 'high',
        request: 'GET https://app.example.com/api/users/1 HTTP/1.1',
    });

    await withAvailableBurp(async () => {
        const factory = new ScanRuntimeFactory();
        const { runtime, continuation } = await factory.createContinuationRuntime(getScan(scanId), {
            instruction: 'Continue the authenticated API testing',
            iterations: 25,
            planningEnabled: false,
        });

        assert.equal(runtime.kind, 'agent');
        assert.equal(continuation.instruction, 'Continue the authenticated API testing');
        assert.equal(continuation.iterations, 20);
        assert.equal(continuation.planningEnabled, false);
        assert.equal(continuation.existingFindings.length, 1);
        assert.deepEqual(continuation.existingEndpoints, ['https://app.example.com/api/users/1']);
        runtime.burp.disconnect();
    });
});

test('createWebRuntime disconnects the Burp client when availability checks fail', async () => {
    const originalIsAvailable = BurpMCPClient.prototype.isAvailable;
    const originalDisconnect = BurpMCPClient.prototype.disconnect;
    let disconnectCalls = 0;

    BurpMCPClient.prototype.isAvailable = async () => false;
    BurpMCPClient.prototype.disconnect = () => {
        disconnectCalls += 1;
    };

    try {
        const factory = new ScanRuntimeFactory();
        await assert.rejects(
            () => factory.createWebRuntime('scan-runtime-factory-fail', 'https://app.example.com'),
            /Burp Suite is not connected/i,
        );
    } finally {
        BurpMCPClient.prototype.isAvailable = originalIsAvailable;
        BurpMCPClient.prototype.disconnect = originalDisconnect;
    }

    assert.equal(disconnectCalls, 1);
});
