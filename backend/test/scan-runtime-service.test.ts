import test from 'node:test';
import assert from 'node:assert/strict';

const { ScanRuntimeService } = require('../src/services/runtime/ScanRuntimeService') as typeof import('../src/services/runtime/ScanRuntimeService');

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
