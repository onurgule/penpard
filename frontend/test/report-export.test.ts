import test from 'node:test';
import assert from 'node:assert/strict';

import {
    compareJobs,
    getReportExportStageDisplay,
    getReportLlmStatusDisplay,
    isTerminalReportExport,
    pickPreferredReportExportJob,
    shouldPollReportExport,
    type ReportExportJob,
} from '../src/lib/report-export';

function createJob(overrides: Partial<ReportExportJob>): ReportExportJob {
    return {
        id: 'job-1',
        scanId: 'scan-1',
        snapshotId: 'snapshot-1',
        format: 'pdf',
        enrichmentMode: 'deterministic',
        status: 'pending',
        stage: 'queued',
        stageLabel: 'Queued',
        llmStatus: 'skipped',
        artifactReady: false,
        errorMessage: null,
        llmErrorMessage: null,
        attemptCount: 1,
        createdAt: '2026-04-13T10:00:00.000Z',
        updatedAt: '2026-04-13T10:00:00.000Z',
        startedAt: null,
        completedAt: null,
        canceledAt: null,
        downloadUrl: '/api/reports/scan-1/exports/job-1/download',
        ...overrides,
    };
}

test('stage display maps rendering state to a format-specific label', () => {
    const job = createJob({
        format: 'pptx',
        stage: 'rendering_export',
        stageLabel: '',
        status: 'running',
    });

    assert.equal(getReportExportStageDisplay(job), 'Rendering PPTX');
    assert.equal(shouldPollReportExport(job), true);
});

test('preferred job selection rehydrates the active job after refresh instead of falling back to an older completed job', () => {
    const completed = createJob({
        id: 'completed-job',
        status: 'completed',
        stage: 'completed',
        artifactReady: true,
        updatedAt: '2026-04-13T10:05:00.000Z',
    });
    const running = createJob({
        id: 'running-job',
        status: 'running',
        stage: 'enriching_with_llm',
        stageLabel: 'Enriching with LLM',
        enrichmentMode: 'llm',
        llmStatus: 'running',
        updatedAt: '2026-04-13T10:01:00.000Z',
    });

    const selected = pickPreferredReportExportJob(
        [completed, running],
        'pdf',
        'llm',
    );

    assert.equal(selected?.id, 'running-job');
    assert.equal(compareJobs(running, completed) < 0, true);
});

test('LLM failure status is rendered separately from overall export completion', () => {
    const job = createJob({
        status: 'completed',
        stage: 'completed',
        enrichmentMode: 'llm',
        llmStatus: 'failed',
        llmErrorMessage: 'Provider timeout',
        artifactReady: true,
    });

    assert.equal(isTerminalReportExport(job), true);
    assert.equal(getReportLlmStatusDisplay(job), 'LLM enrichment failed: Provider timeout');
});

test('failed jobs remain selectable for retry while canceled jobs no longer poll', () => {
    const failed = createJob({
        id: 'failed-job',
        status: 'failed',
        stage: 'failed',
        errorMessage: 'Renderer failed',
        updatedAt: '2026-04-13T10:07:00.000Z',
    });
    const canceled = createJob({
        id: 'canceled-job',
        status: 'canceled',
        stage: 'canceled',
        updatedAt: '2026-04-13T10:08:00.000Z',
    });

    const preferred = pickPreferredReportExportJob([failed, canceled], 'pdf', 'deterministic');

    assert.equal(preferred?.id, 'failed-job');
    assert.equal(shouldPollReportExport(failed), false);
    assert.equal(shouldPollReportExport(canceled), false);
});
