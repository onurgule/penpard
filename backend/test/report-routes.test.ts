import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';

const { initDatabase, createScan, updateScanStatus, addVulnerability } = require('../src/db/init') as typeof import('../src/db/init');
const { createApp } = require('../src/app') as typeof import('../src/app');
const { generateToken } = require('../src/middleware/auth') as typeof import('../src/middleware/auth');
const { reportEnrichmentService } = require('../src/services/reporting/ReportEnrichmentService') as typeof import('../src/services/reporting/ReportEnrichmentService');

async function createCompletedScanFixture(label: string) {
    await initDatabase();

    const scanId = `report-route-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
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
        description: 'SQL injection in login.',
        request: 'POST /api/login HTTP/1.1\nHost: route.example.com\n\nusername=admin\' OR 1=1--',
        response: 'HTTP/1.1 500 Internal Server Error\n\nsyntax error',
    });

    updateScanStatus(scanId, 'completed');
    return scanId;
}

async function waitForExport(app: ReturnType<typeof createApp>, token: string, scanId: string, exportId: string, timeoutMs = 60000) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
        const response = await request(app)
            .get(`/api/reports/${scanId}/exports/${exportId}`)
            .set('Authorization', `Bearer ${token}`);
        const data = response.body as any;
        if (data.export && ['completed', 'failed', 'canceled'].includes(data.export.status)) {
            return data.export;
        }
        await new Promise((resolve) => setTimeout(resolve, 150));
    }
    throw new Error(`Timed out waiting for export ${exportId}`);
}

test('report routes create, dedupe, poll, and download completed export jobs', async () => {
    const scanId = await createCompletedScanFixture('happy-path');
    const app = createApp();
    const token = generateToken(1);

    const createResponse = await request(app)
        .post(`/api/reports/${scanId}/exports`)
        .set('Authorization', `Bearer ${token}`)
        .send({ format: 'pdf', enrichmentMode: 'deterministic' });
    assert.equal(createResponse.status, 202);
    const created = createResponse.body as any;
    assert.equal(created.export.format, 'pdf');
    assert.equal(created.export.stage, 'queued');

    const duplicateResponse = await request(app)
        .post(`/api/reports/${scanId}/exports`)
        .set('Authorization', `Bearer ${token}`)
        .send({ format: 'pdf', enrichmentMode: 'deterministic' });
    const duplicate = duplicateResponse.body as any;
    assert.equal(duplicate.export.id, created.export.id);

    const completed = await waitForExport(app, token, scanId, created.export.id);
    assert.equal(completed.status, 'completed');
    assert.equal(completed.artifactReady, true);

    const downloadResponse = await request(app)
        .get(`/api/reports/${scanId}/exports/${created.export.id}/download`)
        .set('Authorization', `Bearer ${token}`);
    assert.equal(downloadResponse.status, 200);
    assert.ok(Buffer.isBuffer(downloadResponse.body));
    assert.ok(downloadResponse.body.length > 0);
});

test('report routes surface real stage state and allow canceling an in-progress export', async () => {
    const scanId = await createCompletedScanFixture('cancel');
    const app = createApp();
    const token = generateToken(1);
    const originalEnrich = reportEnrichmentService.enrichReport.bind(reportEnrichmentService);

    reportEnrichmentService.enrichReport = (async (report: any) => {
        await new Promise((resolve) => setTimeout(resolve, 500));
        return {
            report,
            llmStatus: 'completed',
            errorMessage: null,
        };
    }) as any;

    try {
        const createResponse = await request(app)
            .post(`/api/reports/${scanId}/exports`)
            .set('Authorization', `Bearer ${token}`)
            .send({ format: 'pdf', enrichmentMode: 'llm' });
        const created = createResponse.body as any;

        await new Promise((resolve) => setTimeout(resolve, 100));
        const statusResponse = await request(app)
            .get(`/api/reports/${scanId}/exports/${created.export.id}`)
            .set('Authorization', `Bearer ${token}`);
        const status = statusResponse.body as any;
        assert.equal(status.export.stage, 'enriching_with_llm');

        const cancelResponse = await request(app)
            .post(`/api/reports/${scanId}/exports/${created.export.id}/cancel`)
            .set('Authorization', `Bearer ${token}`);
        assert.equal(cancelResponse.status, 200);

        const canceled = await waitForExport(app, token, scanId, created.export.id);
        assert.equal(canceled.status, 'canceled');
        assert.equal(canceled.stage, 'canceled');
    } finally {
        reportEnrichmentService.enrichReport = originalEnrich as any;
    }
});

test('report routes enforce retry state guards', async () => {
    const scanId = await createCompletedScanFixture('retry-guard');
    const app = createApp();
    const token = generateToken(1);

    const createResponse = await request(app)
        .post(`/api/reports/${scanId}/exports`)
        .set('Authorization', `Bearer ${token}`)
        .send({ format: 'docx', enrichmentMode: 'deterministic' });
    const created = createResponse.body as any;
    const completed = await waitForExport(app, token, scanId, created.export.id);
    assert.equal(completed.status, 'completed');

    const retryResponse = await request(app)
        .post(`/api/reports/${scanId}/exports/${created.export.id}/retry`)
        .set('Authorization', `Bearer ${token}`);
    assert.equal(retryResponse.status, 400);
    const payload = retryResponse.body as any;
    assert.match(payload.message, /failed exports/i);
});
