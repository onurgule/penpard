import test from 'node:test';
import assert from 'node:assert/strict';

const { OrchestratorContextSignals } = require('../src/agents/orchestrator/OrchestratorContextSignals') as typeof import('../src/agents/orchestrator/OrchestratorContextSignals');

test('context signals reset budget thresholds between runs', () => {
    const logs: string[] = [];
    const signals = new OrchestratorContextSignals((_channel, message) => logs.push(message));

    signals.buildBudgetPressureReminder(7, 12);
    signals.buildBudgetPressureReminder(10, 12);
    signals.resetBudgetSignals();
    signals.buildBudgetPressureReminder(7, 12);
    signals.buildBudgetPressureReminder(10, 12);

    const tighteningLogs = logs.filter((line) => line.includes('Action budget tightening:'));
    const criticalLogs = logs.filter((line) => line.includes('Action budget critical:'));

    assert.equal(tighteningLogs.length, 2);
    assert.equal(criticalLogs.length, 2);
});

test('auth startup directive stays auth-first in round one and relaxes afterwards', () => {
    const signals = new OrchestratorContextSignals();

    assert.match(signals.buildAuthStartupDirective(1, 'provided_credentials'), /Round 1 MUST stay auth-surface-first/);
    assert.match(signals.buildAuthStartupDirective(1, 'no_credentials'), /self-registration/);
    assert.match(signals.buildAuthStartupDirective(2, 'provided_credentials'), /already executed/);
});
