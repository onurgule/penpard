import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const {
    OrchestratorLogLedger,
    normalizeVisibleLogMessage,
} = require('../src/agents/orchestrator/OrchestratorLogLedger') as typeof import('../src/agents/orchestrator/OrchestratorLogLedger');

test('normalizeVisibleLogMessage repairs mojibake markers into readable output', () => {
    assert.equal(
        normalizeVisibleLogMessage('âœ“ Burp MCP: Connected'),
        '[ok] Burp MCP: Connected',
    );
    assert.equal(
        normalizeVisibleLogMessage('ğŸŒ browser_navigate â†’ https://example.com'),
        '[browser] browser_navigate -> https://example.com',
    );
    assert.equal(
        normalizeVisibleLogMessage('â•â•â• SCAN COMPLETED â•â•â•'),
        '=== SCAN COMPLETED ===',
    );
});

test('normalizeVisibleLogMessage also standardizes clean unicode log markers', () => {
    assert.equal(
        normalizeVisibleLogMessage('✓ Burp MCP: Connected'),
        '[ok] Burp MCP: Connected',
    );
    assert.equal(
        normalizeVisibleLogMessage('🌐 browser_navigate → https://example.com'),
        '[browser] browser_navigate -> https://example.com',
    );
    assert.equal(
        normalizeVisibleLogMessage('═══ SCAN COMPLETED ═══'),
        '=== SCAN COMPLETED ===',
    );
});

test('OrchestratorLogLedger only persists new log entries and writes UTF-8 snapshots', () => {
    const persistedBatches: string[][] = [];
    const logFile = path.join(os.tmpdir(), `penpard-log-ledger-${Date.now()}.log`);
    const ledger = new OrchestratorLogLedger({
        scanId: 'scan-ledger-test',
        timestamp: () => '2026-04-09T12:00:00',
        persistLogs: (_scanId, logs) => {
            persistedBatches.push([...logs]);
        },
    });

    ledger.append('system', 'âœ“ Burp MCP: Connected');
    assert.equal(ledger.flushToDB(), 1);
    assert.equal(ledger.flushToDB(), 0);

    ledger.append('tool', 'ğŸŒ browser_navigate â†’ https://example.com');
    ledger.persistToFile(logFile);

    assert.equal(persistedBatches.length, 2);
    assert.deepEqual(persistedBatches[0], [
        '[2026-04-09T12:00:00] [SYSTEM] [ok] Burp MCP: Connected',
    ]);
    assert.deepEqual(persistedBatches[1], [
        '[2026-04-09T12:00:00] [TOOL] [browser] browser_navigate -> https://example.com',
    ]);

    const fileContents = fs.readFileSync(logFile, 'utf8');
    assert.match(fileContents, /\[SYSTEM\] \[ok\] Burp MCP: Connected/);
    assert.match(fileContents, /\[TOOL\] \[browser\] browser_navigate -> https:\/\/example\.com/);

    fs.unlinkSync(logFile);
});
