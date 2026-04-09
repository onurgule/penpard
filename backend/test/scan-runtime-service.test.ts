import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanRuntimeService } = require('../src/services/runtime/ScanRuntimeService') as typeof import('../src/services/runtime/ScanRuntimeService');
const { initDatabase } = require('../src/db/init') as typeof import('../src/db/init');

test('finalizeAgentRuntime captures the resolved terminal phase before unregistering the runtime', () => {
    const callOrder: string[] = [];
    let capturedPhase: string | undefined;

    const registry = {
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push('capture');
            capturedPhase = phase;
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };

    const service = new ScanRuntimeService(registry as any);
    (service as any).resolveAgentFinalPhase = () => 'failed';

    const agent = {
        getState: () => ({ phase: 'planning' }),
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
    };

    const finalPhase = (service as any).finalizeAgentRuntime('scan-runtime-test', agent);

    assert.equal(finalPhase, 'failed');
    assert.equal(capturedPhase, 'failed');
    assert.deepEqual(callOrder, ['capture', 'flush', 'unregister']);
});

test('stopScan stops the agent before caching logs so terminal stop messages are retained', async () => {
    await initDatabase();

    const callOrder: string[] = [];
    const registry = {
        getRuntime: () => ({ kind: 'agent', agent }),
        captureAgentLogs: (_scanId: string, _agent: any, phase?: string) => {
            callOrder.push(`capture:${phase}`);
            return { logs: [], phase };
        },
        unregister: () => {
            callOrder.push('unregister');
        },
    };

    const agent = {
        stop: () => {
            callOrder.push('stop');
        },
        flushLogsToDB: () => {
            callOrder.push('flush');
        },
        getState: () => ({ phase: 'testing' }),
    };

    const service = new ScanRuntimeService(registry as any);
    (service as any).resolveAgentFinalPhase = () => 'stopped';

    const result = await service.stopScan('scan-runtime-stop-test', 1, 'testing');

    assert.match(result.message, /stopped/i);
    assert.deepEqual(callOrder, ['stop', 'capture:stopped', 'flush', 'unregister']);
});
