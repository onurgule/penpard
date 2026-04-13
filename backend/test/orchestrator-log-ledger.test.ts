import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const {
    OrchestratorLogLedger,
    normalizeVisibleLogMessage,
} = require('../src/agents/orchestrator/OrchestratorLogLedger') as typeof import('../src/agents/orchestrator/OrchestratorLogLedger');
const { OrchestratorLogSink } = require('../src/agents/orchestrator/OrchestratorLogSink') as typeof import('../src/agents/orchestrator/OrchestratorLogSink');

const MOJIBAKE_OK = '\u00E2\u0153\u201C Burp MCP: Connected';
const MOJIBAKE_BROWSER = '\u011F\u0178\u0152\u0090 browser_navigate \u00E2\u2020\u2019 https://example.com';
const MOJIBAKE_DIVIDER = '\u00E2\u2022\u0090\u00E2\u2022\u0090\u00E2\u2022\u0090 SCAN COMPLETED \u00E2\u2022\u0090\u00E2\u2022\u0090\u00E2\u2022\u0090';

test('normalizeVisibleLogMessage repairs mojibake markers into readable output', () => {
    assert.equal(
        normalizeVisibleLogMessage(MOJIBAKE_OK),
        '[ok] Burp MCP: Connected',
    );
    assert.equal(
        normalizeVisibleLogMessage(MOJIBAKE_BROWSER),
        '[browser] browser_navigate -> https://example.com',
    );
    assert.equal(
        normalizeVisibleLogMessage(MOJIBAKE_DIVIDER),
        '=== SCAN COMPLETED ===',
    );
});

test('normalizeVisibleLogMessage also standardizes clean unicode log markers', () => {
    assert.equal(
        normalizeVisibleLogMessage('\u2713 Burp MCP: Connected'),
        '[ok] Burp MCP: Connected',
    );
    assert.equal(
        normalizeVisibleLogMessage('\u{1F310} browser_navigate \u2192 https://example.com'),
        '[browser] browser_navigate -> https://example.com',
    );
    assert.equal(
        normalizeVisibleLogMessage('\u2550\u2550\u2550 SCAN COMPLETED \u2550\u2550\u2550'),
        '=== SCAN COMPLETED ===',
    );
});

test('OrchestratorLogSink persists ledger entries without pushing IO into ledger state', () => {
    const persistedBatches: string[][] = [];
    const mirroredLogs: Array<{ message: string; meta: Record<string, any> }> = [];
    const logFile = path.join(os.tmpdir(), `penpard-log-ledger-${Date.now()}.log`);
    const ledger = new OrchestratorLogLedger({
        timestamp: () => '2026-04-09T12:00:00',
    });
    const sink = new OrchestratorLogSink({
        scanId: 'scan-ledger-test',
        persistLogs: (_scanId, logs) => {
            persistedBatches.push([...logs]);
        },
        writeInfoLog: (message, meta) => {
            mirroredLogs.push({ message, meta });
        },
    });

    sink.record(ledger.append('system', MOJIBAKE_OK), ledger);
    assert.equal(sink.flushToDB(ledger), 1);
    assert.equal(sink.flushToDB(ledger), 0);

    sink.record(ledger.append('tool', MOJIBAKE_BROWSER), ledger);
    sink.persistToFile(ledger, logFile);

    assert.equal(ledger.count, 2);
    assert.equal(sink.getUnflushedCount(ledger), 0);
    assert.equal(persistedBatches.length, 2);
    assert.deepEqual(persistedBatches[0], [
        '[2026-04-09T12:00:00] [SYSTEM] [ok] Burp MCP: Connected',
    ]);
    assert.deepEqual(persistedBatches[1], [
        '[2026-04-09T12:00:00] [TOOL] [browser] browser_navigate -> https://example.com',
    ]);
    assert.deepEqual(mirroredLogs.map((entry) => entry.message), [
        '[ok] Burp MCP: Connected',
        '[browser] browser_navigate -> https://example.com',
    ]);

    const fileContents = fs.readFileSync(logFile, 'utf8');
    assert.match(fileContents, /\[SYSTEM\] \[ok\] Burp MCP: Connected/);
    assert.match(fileContents, /\[TOOL\] \[browser\] browser_navigate -> https:\/\/example\.com/);

    fs.unlinkSync(logFile);
});
