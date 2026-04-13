import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';

const {
    initDatabase,
    createScan,
    updateScanStatus,
    addVulnerability,
    createReportExport,
    updateReportExport,
    getReportExport,
} = require('../src/db/init') as typeof import('../src/db/init');
const { reportSnapshotService } = require('../src/services/reporting/ReportSnapshotService') as typeof import('../src/services/reporting/ReportSnapshotService');
const { reportEnrichmentService } = require('../src/services/reporting/ReportEnrichmentService') as typeof import('../src/services/reporting/ReportEnrichmentService');
const { reportExportService } = require('../src/services/reporting/ReportExportService') as typeof import('../src/services/reporting/ReportExportService');
const { REPORTS_DIR, ensureReportsDir } = require('../src/services/reporting/renderers/shared') as typeof import('../src/services/reporting/renderers/shared');
const { llmProvider } = require('../src/services/LLMProviderService') as typeof import('../src/services/LLMProviderService');
const { llmRuntime } = require('../src/services/llm/LlmRuntime') as typeof import('../src/services/llm/LlmRuntime');

async function createCompletedScanFixture(label: string) {
    await initDatabase();
    ensureReportsDir();

    const scanId = `report-export-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: `https://${label}.example.com`,
    });

    addVulnerability({
        scanId,
        name: 'SQL Injection',
        severity: 'critical',
        description: 'A SQL injection was observed in the login endpoint.',
        cvssScore: 9.8,
        cwe: '89',
        request: 'POST /api/login HTTP/1.1\nHost: app.example.com\n\nusername=admin\' OR 1=1--',
        response: 'HTTP/1.1 500 Internal Server Error\n\nSQL syntax error near users table',
        remediation: 'Use parameterized queries for all database access.',
    });
    addVulnerability({
        scanId,
        name: 'IDOR',
        severity: 'high',
        description: 'Direct object references allow cross-account access.',
        cvssScore: 8.1,
        cwe: '639',
        request: 'GET /api/account/2 HTTP/1.1\nHost: app.example.com',
        response: 'HTTP/1.1 200 OK\n\n{"email":"victim@example.com"}',
    });

    updateScanStatus(scanId, 'completed');
    return scanId;
}

async function createUnicodePdfFixture(label: string) {
    await initDatabase();
    ensureReportsDir();

    const scanId = `report-export-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: `https://${label}.example.com`,
    });

    addVulnerability({
        scanId,
        name: 'Workflow Authorization Drift',
        severity: 'medium',
        description: 'Account flow allows user → admin transitions after a crafted redirect…',
        remediation: 'Normalize role changes, reject unexpected state jumps, and replace “smart” fallbacks with explicit checks.',
        request: 'POST /api/role HTTP/1.1\nHost: app.example.com\n\nstep=review→approve',
        response: 'HTTP/1.1 200 OK\n\n{"result":"approved → elevated"}',
        evidence: 'Observed state machine: guest → user → admin',
    });

    updateScanStatus(scanId, 'completed');
    return scanId;
}

test('report snapshot generation creates a deterministic canonical model without LLM', async () => {
    const scanId = await createCompletedScanFixture('snapshot');
    const { snapshot, report } = reportSnapshotService.getOrCreateSnapshot(scanId);

    assert.ok(snapshot.id);
    assert.equal(report.scan.id, scanId);
    assert.equal(report.summary.totalFindings, 2);
    assert.equal(report.summary.countsBySeverity.critical, 1);
    assert.equal(report.summary.countsBySeverity.high, 1);
    assert.equal(report.narrativeMeta.enrichmentMode, 'deterministic');
    assert.equal(report.findings[0].title, 'SQL Injection');
    assert.match(report.summary.executiveSummary, /PenPard completed a security assessment/i);
});

test('report enrichment succeeds only after structured JSON passes schema validation', async () => {
    const scanId = await createCompletedScanFixture('enrichment-success');
    const { report } = reportSnapshotService.getOrCreateSnapshot(scanId);

    const originalGetActiveConfig = llmProvider.getActiveConfig.bind(llmProvider);
    const originalGenerate = llmRuntime.generate.bind(llmRuntime);
    let capturedGetActiveConfigUserId: number | undefined;
    let capturedGenerateUserId: number | undefined;

    llmProvider.getActiveConfig = ((userId?: number) => {
        capturedGetActiveConfigUserId = userId;
        return { provider: 'openai', model: 'gpt-4.1' } as any;
    }) as any;
    llmRuntime.generate = (async (_request: any, options: any) => {
        capturedGenerateUserId = options?.userId;
        return {
        text: JSON.stringify({
            executiveSummary: 'Validated executive summary from the LLM.',
            findings: [
                { findingId: report.findings[0].id, description: 'Improved description.', impact: 'Improved impact.' },
            ],
        }),
        };
    }) as any;

    try {
        const result = await reportEnrichmentService.enrichReport(report, {
            scanId,
            userId: 55,
            reportExportId: 'job-success',
        });

        assert.equal(result.llmStatus, 'completed');
        assert.equal(result.report.summary.executiveSummary, 'Validated executive summary from the LLM.');
        assert.equal(result.report.findings[0].description, 'Improved description.');
        assert.equal(result.report.narrativeMeta.llmEnriched, true);
        assert.equal(capturedGetActiveConfigUserId, 55);
        assert.equal(capturedGenerateUserId, 55);
    } finally {
        llmProvider.getActiveConfig = originalGetActiveConfig as any;
        llmRuntime.generate = originalGenerate as any;
    }
});

test('report enrichment marks malformed structured output as failed and keeps the deterministic base', async () => {
    const scanId = await createCompletedScanFixture('enrichment-malformed');
    const { report } = reportSnapshotService.getOrCreateSnapshot(scanId);

    const originalGetActiveConfig = llmProvider.getActiveConfig.bind(llmProvider);
    const originalGenerate = llmRuntime.generate.bind(llmRuntime);

    llmProvider.getActiveConfig = (() => ({ provider: 'openai', model: 'gpt-4.1' } as any)) as any;
    llmRuntime.generate = (async () => ({ text: '{"executiveSummary": 42}' })) as any;

    try {
        const result = await reportEnrichmentService.enrichReport(report, {
            scanId,
            reportExportId: 'job-malformed',
        });

        assert.equal(result.llmStatus, 'failed');
        assert.equal(result.report.summary.executiveSummary, report.summary.executiveSummary);
        assert.equal(result.report.narrativeMeta.llmFailed, true);
    } finally {
        llmProvider.getActiveConfig = originalGetActiveConfig as any;
        llmRuntime.generate = originalGenerate as any;
    }
});

test('LLM failure still produces a completed deterministic export artifact', async () => {
    const scanId = await createCompletedScanFixture('llm-fallback');
    const originalEnrich = reportEnrichmentService.enrichReport.bind(reportEnrichmentService);

    reportEnrichmentService.enrichReport = (async () => {
        throw new Error('LLM timeout after 30 seconds');
    }) as any;

    try {
        const job = await reportExportService.createOrReuseExport(scanId, 'pdf', 'llm');
        const completed = await reportExportService.waitForCompletion(job.id, 60000);

        assert.equal(completed.status, 'completed');
        assert.equal(completed.llm_status, 'failed');
        assert.ok(completed.artifact_path && fs.existsSync(completed.artifact_path));
    } finally {
        reportEnrichmentService.enrichReport = originalEnrich as any;
    }
});

test('export jobs dedupe active/completed work and can be retried idempotently after failure', async () => {
    const scanId = await createCompletedScanFixture('dedupe-retry');
    const originalRenderArtifact = (reportExportService as any).renderArtifact.bind(reportExportService);

    const firstJob = await reportExportService.createOrReuseExport(scanId, 'pdf', 'deterministic');
    const firstCompleted = await reportExportService.waitForCompletion(firstJob.id, 60000);

    const reusedJob = await reportExportService.createOrReuseExport(scanId, 'pdf', 'deterministic');
    assert.equal(reusedJob.id, firstCompleted.id);

    (reportExportService as any).renderArtifact = (async () => {
        throw new Error('Synthetic render failure');
    }) as any;

    const failingJob = await reportExportService.createOrReuseExport(scanId, 'docx', 'deterministic');
    const failed = await reportExportService.waitForCompletion(failingJob.id, 60000);
    assert.equal(failed.status, 'failed');

    (reportExportService as any).renderArtifact = originalRenderArtifact;

    const retried = await reportExportService.retryExport(scanId, failingJob.id);
    const retriedCompleted = await reportExportService.waitForCompletion(retried.id, 60000);
    assert.equal(retriedCompleted.status, 'completed');
    assert.ok(retriedCompleted.attempt_count >= 2);
});

test('startup recovery requeues nonterminal export jobs and resumes them to completion', async () => {
    const scanId = await createCompletedScanFixture('recovery');
    const { snapshot } = reportSnapshotService.getOrCreateSnapshot(scanId);

    const jobId = `recover-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    createReportExport({
        id: jobId,
        scanId,
        snapshotId: snapshot.id,
        snapshotFingerprint: snapshot.fingerprint,
        format: 'pdf',
        enrichmentMode: 'deterministic',
    });
    updateReportExport(jobId, {
        status: 'running',
        stage: 'rendering_export',
        resolved_report_json: snapshot.report_json,
    });

    await reportExportService.recoverPendingExports();
    const completed = await reportExportService.waitForCompletion(jobId, 60000);

    assert.equal(completed.status, 'completed');
    assert.ok(completed.artifact_path && fs.existsSync(completed.artifact_path));
});

test('artifact writes are atomic and leave no temporary export files behind', async () => {
    const scanId = await createCompletedScanFixture('atomic-write');
    const job = await reportExportService.createOrReuseExport(scanId, 'pptx', 'deterministic');
    const completed = await reportExportService.waitForCompletion(job.id, 60000);

    assert.equal(completed.status, 'completed');
    const files = fs.readdirSync(REPORTS_DIR);
    const tempFiles = files.filter((fileName: string) => fileName.includes(job.id) && fileName.endsWith('.tmp'));
    assert.deepEqual(tempFiles, []);
});

test('pdf export sanitizes WinAnsi-incompatible unicode characters instead of failing', async () => {
    const scanId = await createUnicodePdfFixture('unicode-pdf');
    const job = await reportExportService.createOrReuseExport(scanId, 'pdf', 'deterministic');
    const completed = await reportExportService.waitForCompletion(job.id, 60000);

    assert.equal(completed.status, 'completed');
    assert.ok(completed.artifact_path && fs.existsSync(completed.artifact_path));
});

test('canceling a long-running LLM enrichment aborts the in-flight report job without relying on a timeout', async () => {
    const scanId = await createCompletedScanFixture('cancel-aborts-enrichment');
    const originalEnrich = reportEnrichmentService.enrichReport.bind(reportEnrichmentService);

    reportEnrichmentService.enrichReport = (async (report: any, options: any) => {
        await new Promise((resolve, reject) => {
            options.signal?.addEventListener('abort', () => {
                reject(options.signal.reason || new Error('aborted'));
            }, { once: true });
        });

        return {
            report,
            llmStatus: 'completed',
            errorMessage: null,
        };
    }) as any;

    try {
        const job = await reportExportService.createOrReuseExport(scanId, 'pdf', 'llm');
        await new Promise((resolve) => setTimeout(resolve, 100));
        const canceled = reportExportService.cancelExport(scanId, job.id);
        assert.equal(canceled.status, 'canceled');

        const terminal = await reportExportService.waitForCompletion(job.id, 60000);
        assert.equal(terminal.status, 'canceled');
        assert.equal(terminal.stage, 'canceled');
    } finally {
        reportEnrichmentService.enrichReport = originalEnrich as any;
    }
});
