import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanRuntimeRegistry } = require('../src/services/runtime/ScanRuntimeRegistry') as typeof import('../src/services/runtime/ScanRuntimeRegistry');

function createFakeAgent(phase: string, logs: string[]) {
    return {
        getState: () => ({ phase }),
        getLogs: () => logs,
    } as any;
}

function createFakePool(logs: string[]) {
    return {
        getLogs: () => logs,
    } as any;
}

test('registry tracks active runtimes and resolves their kind explicitly', () => {
    const registry = new ScanRuntimeRegistry();
    const agent = createFakeAgent('planning', ['agent-log']);
    const pool = createFakePool(['pool-log']);

    registry.registerAgent('scan-agent', agent);
    registry.registerPool('scan-pool', pool);

    assert.equal(registry.hasActiveRuntime('scan-agent'), true);
    assert.equal(registry.hasActiveRuntime('scan-pool'), true);
    assert.equal(registry.getRuntime('scan-agent')?.kind, 'agent');
    assert.equal(registry.getRuntime('scan-pool')?.kind, 'pool');
    assert.equal(registry.getActiveAgentCount(), 1);
    assert.equal(registry.getActivePoolCount(), 1);
    assert.equal(registry.getTotalActiveRuntimeCount(), 2);

    registry.unregister('scan-agent');
    registry.unregister('scan-pool');

    assert.equal(registry.hasActiveRuntime('scan-agent'), false);
    assert.equal(registry.hasActiveRuntime('scan-pool'), false);
});

test('registry caches logs and trims oldest snapshots deterministically', () => {
    const registry = new ScanRuntimeRegistry(2);

    registry.cacheLogs('scan-1', { logs: ['one'], phase: 'planning' });
    registry.cacheLogs('scan-2', { logs: ['two'], phase: 'testing' });
    registry.cacheLogs('scan-3', { logs: ['three'], phase: 'completed' });

    assert.equal(registry.getCachedLogs('scan-1'), undefined);
    assert.deepEqual(registry.getCachedLogs('scan-2')?.logs, ['two']);
    assert.deepEqual(registry.getCachedLogs('scan-3')?.logs, ['three']);
});

test('registry captures runtime log snapshots through explicit helpers', () => {
    const registry = new ScanRuntimeRegistry();
    const agent = createFakeAgent('reporting', ['agent-a', 'agent-b']);
    const pool = createFakePool(['pool-a']);

    const agentSnapshot = registry.captureAgentLogs('scan-agent', agent);
    const poolSnapshot = registry.capturePoolLogs('scan-pool', pool, 'stopped');

    assert.equal(agentSnapshot.phase, 'reporting');
    assert.deepEqual(agentSnapshot.logs, ['agent-a', 'agent-b']);
    assert.equal(poolSnapshot.phase, 'stopped');
    assert.deepEqual(poolSnapshot.logs, ['pool-a']);
});
