import fs from 'fs';
import path from 'path';
import { db, createReportExport, getReportExport, getReusableReportExport, listRecoverableReportExports, listReportExportsByScan, updateReportExport } from '../../db/init';
import { logger } from '../../utils/logger';
import { reportEnrichmentService } from './ReportEnrichmentService';
import { reportSnapshotService } from './ReportSnapshotService';
import { renderDocxReport } from './renderers/docxRenderer';
import { renderPdfReport } from './renderers/pdfRenderer';
import { renderPptxReport } from './renderers/pptxRenderer';
import { REPORTS_DIR, ensureReportsDir } from './renderers/shared';
import type { CanonicalReportModel, ReportEnrichmentMode, ReportExportFormat, ReportExportRecord } from './types';

export class ReportExportService {
    private readonly activeJobs = new Set<string>();
    private readonly cancelRequested = new Set<string>();

    public async createOrReuseExport(scanId: string, format: ReportExportFormat, enrichmentMode: ReportEnrichmentMode): Promise<ReportExportRecord> {
        const { snapshot } = reportSnapshotService.getOrCreateSnapshot(scanId);
        const existing = getReusableReportExport({
            scanId,
            snapshotId: snapshot.id,
            format,
            enrichmentMode,
        }) as ReportExportRecord | undefined;

        if (existing) {
            if (existing.status === 'completed' && existing.artifact_path && fs.existsSync(existing.artifact_path)) {
                return existing;
            }
            if (existing.status === 'completed' && existing.artifact_path && !fs.existsSync(existing.artifact_path)) {
                updateReportExport(existing.id, {
                    status: 'failed',
                    stage: 'failed',
                    error_message: 'Previously completed artifact was missing from disk.',
                });
            } else {
                this.enqueue(existing.id);
                return getReportExport(existing.id) as ReportExportRecord;
            }
        }

        const created = createReportExport({
            id: cryptoRandomId(),
            scanId,
            snapshotId: snapshot.id,
            snapshotFingerprint: snapshot.fingerprint,
            format,
            enrichmentMode,
        }) as ReportExportRecord;
        this.enqueue(created.id);
        return created;
    }

    public listExports(scanId: string): ReportExportRecord[] {
        return listReportExportsByScan(scanId) as ReportExportRecord[];
    }

    public getExport(exportId: string): ReportExportRecord | undefined {
        return getReportExport(exportId) as ReportExportRecord | undefined;
    }

    public async retryExport(scanId: string, exportId: string): Promise<ReportExportRecord> {
        const job = this.requireOwnedJob(scanId, exportId);
        if (job.status !== 'failed') {
            throw new Error('Only failed exports can be retried');
        }

        updateReportExport(exportId, {
            status: 'pending',
            stage: 'queued',
            error_message: null,
            llm_error_message: null,
            artifact_path: null,
            completed_at: null,
            canceled_at: null,
            llm_status: job.enrichment_mode === 'llm' ? 'queued' : 'skipped',
        });
        this.enqueue(exportId);
        return this.requireOwnedJob(scanId, exportId);
    }

    public cancelExport(scanId: string, exportId: string): ReportExportRecord {
        const job = this.requireOwnedJob(scanId, exportId);
        if (['completed', 'failed', 'canceled'].includes(job.status)) {
            throw new Error('This export can no longer be canceled');
        }

        this.cancelRequested.add(exportId);
        updateReportExport(exportId, {
            status: 'canceled',
            stage: 'canceled',
            canceled_at: new Date().toISOString(),
            error_message: 'Export canceled by user.',
        });
        return this.requireOwnedJob(scanId, exportId);
    }

    public async recoverPendingExports(): Promise<void> {
        const recoverableJobs = listRecoverableReportExports() as ReportExportRecord[];
        for (const job of recoverableJobs) {
            updateReportExport(job.id, {
                status: 'pending',
                stage: 'queued',
                error_message: job.error_message || 'Rescheduled after backend restart.',
            });
            this.enqueue(job.id);
        }
    }

    public async waitForCompletion(exportId: string, timeoutMs = 30000): Promise<ReportExportRecord> {
        const startedAt = Date.now();
        while (Date.now() - startedAt < timeoutMs) {
            const job = this.getExport(exportId);
            if (job && ['completed', 'failed', 'canceled'].includes(job.status)) {
                return job;
            }
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
        throw new Error(`Timed out waiting for export ${exportId}`);
    }

    private requireOwnedJob(scanId: string, exportId: string): ReportExportRecord {
        const job = this.getExport(exportId);
        if (!job || job.scan_id !== scanId) {
            throw new Error('Report export not found');
        }
        return job;
    }

    private enqueue(exportId: string): void {
        if (this.activeJobs.has(exportId)) {
            return;
        }

        setImmediate(() => {
            void this.runExport(exportId);
        });
    }

    private async runExport(exportId: string): Promise<void> {
        if (this.activeJobs.has(exportId)) {
            return;
        }

        const job = this.getExport(exportId);
        if (!job || ['completed', 'failed', 'canceled'].includes(job.status)) {
            return;
        }

        this.activeJobs.add(exportId);
        ensureReportsDir();

        try {
            await this.throwIfCanceled(exportId);

            updateReportExport(exportId, {
                status: 'running',
                stage: 'collecting_data',
                started_at: job.started_at || new Date().toISOString(),
                completed_at: null,
                canceled_at: null,
                error_message: null,
                attempt_count: (job.attempt_count || 0) + 1,
            });

            const { snapshot, report: snapshotReport } = reportSnapshotService.getSnapshotById(job.snapshot_id);
            await this.throwIfCanceled(exportId);

            let resolvedReport = job.resolved_report_json
                ? reportSnapshotService.parseReport(job.resolved_report_json)
                : snapshotReport;
            updateReportExport(exportId, {
                stage: 'composing_report',
                resolved_report_json: JSON.stringify(resolvedReport),
            });

            if (job.enrichment_mode === 'llm') {
                updateReportExport(exportId, {
                    stage: 'enriching_with_llm',
                    llm_status: 'running',
                    llm_error_message: null,
                });

                try {
                    const enrichment = await reportEnrichmentService.enrichReport(resolvedReport, {
                        scanId: job.scan_id,
                        reportExportId: job.id,
                    });
                    resolvedReport = enrichment.report;
                    updateReportExport(exportId, {
                        llm_status: enrichment.llmStatus,
                        llm_error_message: enrichment.errorMessage,
                        resolved_report_json: JSON.stringify(resolvedReport),
                    });
                } catch (error: any) {
                    logger.warn('Report enrichment failed, continuing with deterministic base', {
                        exportId,
                        error: error.message,
                    });
                    resolvedReport = {
                        ...resolvedReport,
                        narrativeMeta: {
                            enrichmentMode: 'llm',
                            llmEnriched: false,
                            llmFailed: true,
                            llmFailureReason: error.message,
                        },
                    };
                    updateReportExport(exportId, {
                        llm_status: 'failed',
                        llm_error_message: error.message,
                        resolved_report_json: JSON.stringify(resolvedReport),
                    });
                }
            } else {
                resolvedReport = {
                    ...resolvedReport,
                    narrativeMeta: {
                        enrichmentMode: 'deterministic',
                        llmEnriched: false,
                        llmFailed: false,
                        llmFailureReason: null,
                    },
                };
                updateReportExport(exportId, {
                    llm_status: 'skipped',
                    resolved_report_json: JSON.stringify(resolvedReport),
                });
            }

            await this.throwIfCanceled(exportId);

            updateReportExport(exportId, {
                stage: 'rendering_export',
            });

            const artifactPath = path.join(REPORTS_DIR, `report-${job.scan_id}-${job.id}.${job.format}`);
            await this.renderArtifact(job.format, resolvedReport, artifactPath);
            await this.throwIfCanceled(exportId);

            updateReportExport(exportId, {
                status: 'completed',
                stage: 'completed',
                artifact_path: artifactPath,
                completed_at: new Date().toISOString(),
                error_message: null,
                resolved_report_json: JSON.stringify(resolvedReport),
            });

            db.prepare(`
                INSERT INTO reports (scan_id, file_path, format, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(scan_id) DO UPDATE SET
                    file_path = excluded.file_path,
                    format = excluded.format,
                    created_at = excluded.created_at
            `).run(job.scan_id, artifactPath, job.format);

            logger.info('Completed report export job', {
                exportId,
                scanId: job.scan_id,
                snapshotId: snapshot.id,
                format: job.format,
            });
        } catch (error: any) {
            const currentJob = this.getExport(exportId);
            if (currentJob?.status === 'canceled' || this.cancelRequested.has(exportId)) {
                updateReportExport(exportId, {
                    status: 'canceled',
                    stage: 'canceled',
                    canceled_at: currentJob?.canceled_at || new Date().toISOString(),
                });
            } else {
                updateReportExport(exportId, {
                    status: 'failed',
                    stage: 'failed',
                    error_message: error.message || 'Report export failed',
                });
                logger.error('Report export job failed', { exportId, error: error.message });
            }
        } finally {
            this.cancelRequested.delete(exportId);
            this.activeJobs.delete(exportId);
        }
    }

    private async renderArtifact(format: ReportExportFormat, report: CanonicalReportModel, artifactPath: string): Promise<void> {
        switch (format) {
            case 'docx':
                await renderDocxReport(report, artifactPath);
                return;
            case 'pptx':
                await renderPptxReport(report, artifactPath);
                return;
            case 'pdf':
            default:
                await renderPdfReport(report, artifactPath);
        }
    }

    private async throwIfCanceled(exportId: string): Promise<void> {
        const job = this.getExport(exportId);
        if (this.cancelRequested.has(exportId) || job?.status === 'canceled' || job?.stage === 'canceled') {
            throw new Error('Export canceled');
        }
    }
}

function cryptoRandomId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export const reportExportService = new ReportExportService();
