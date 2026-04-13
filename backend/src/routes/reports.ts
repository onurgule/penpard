import fs from 'fs';
import { Router, Response } from 'express';
import { getScan } from '../db/init';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { llmProvider } from '../services/LLMProviderService';
import { reportExportService } from '../services/reporting/ReportExportService';
import { reportExportFormatValues, reportEnrichmentModeValues, type ReportExportRecord } from '../services/reporting/types';
import { logger } from '../utils/logger';

const router = Router();

router.get('/capabilities/check', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const userId = req.user?.id || 1;
        const visionCheck = llmProvider.checkVisionSupport(userId);
        let llmAvailable = false;
        try {
            llmProvider.getActiveConfig(userId);
            llmAvailable = true;
        } catch {
            llmAvailable = false;
        }

        res.json({
            llmAvailable,
            visionSupported: visionCheck.supported,
            provider: visionCheck.provider,
            model: visionCheck.model,
        });
    } catch {
        res.json({ llmAvailable: false, visionSupported: false, provider: 'none', model: 'none' });
    }
});

router.get('/:scanId', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        const exportEligible = ['completed', 'stopped'].includes(scan.status);
        res.json({
            scanId: scan.id,
            scanStatus: scan.status,
            exportEligible,
            eligibilityReason: exportEligible
                ? null
                : `Scan status "${scan.status}" is not exportable. Only completed or stopped scans can be exported.`,
            supportedFormats: reportExportFormatValues,
            supportedEnrichmentModes: reportEnrichmentModeValues,
            exports: reportExportService.listExports(scan.id).map(toApiExportJob),
        });
    } catch (error: any) {
        logger.error('Get report metadata error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get report metadata' });
    }
});

router.post('/:scanId/exports', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        if (!['completed', 'stopped'].includes(scan.status)) {
            res.status(400).json({
                error: true,
                message: `Scan status "${scan.status}" is not exportable. Only completed or stopped scans can be exported.`,
            });
            return;
        }

        const format = String(req.body?.format || '').toLowerCase();
        const enrichmentMode = String(req.body?.enrichmentMode || 'deterministic').toLowerCase();
        const forceRegenerate = req.body?.forceRegenerate === true;

        if (!reportExportFormatValues.includes(format as any)) {
            res.status(400).json({ error: true, message: `Invalid export format "${format}"` });
            return;
        }
        if (!reportEnrichmentModeValues.includes(enrichmentMode as any)) {
            res.status(400).json({ error: true, message: `Invalid enrichment mode "${enrichmentMode}"` });
            return;
        }

        const job = await reportExportService.createOrReuseExport(
            scan.id,
            format as any,
            enrichmentMode as any,
            { forceNew: forceRegenerate },
        );

        res.status(202).json({ export: toApiExportJob(job) });
    } catch (error: any) {
        logger.error('Create report export error', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to create report export' });
    }
});

router.get('/:scanId/exports', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        res.json({
            exports: reportExportService.listExports(scan.id).map(toApiExportJob),
        });
    } catch (error: any) {
        logger.error('List report exports error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to list report exports' });
    }
});

router.get('/:scanId/exports/:jobId', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        const job = reportExportService.getExport(req.params.jobId);
        if (!job || job.scan_id !== scan.id) {
            res.status(404).json({ error: true, message: 'Report export not found' });
            return;
        }

        res.json({ export: toApiExportJob(job) });
    } catch (error: any) {
        logger.error('Get report export error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get report export' });
    }
});

router.post('/:scanId/exports/:jobId/retry', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        const job = await reportExportService.retryExport(scan.id, req.params.jobId);
        res.status(202).json({ export: toApiExportJob(job) });
    } catch (error: any) {
        const status = /not found/i.test(error.message) ? 404 : 400;
        res.status(status).json({ error: true, message: error.message || 'Failed to retry export' });
    }
});

router.post('/:scanId/exports/:jobId/cancel', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        const job = reportExportService.cancelExport(scan.id, req.params.jobId);
        res.json({ export: toApiExportJob(job) });
    } catch (error: any) {
        const status = /not found/i.test(error.message) ? 404 : 400;
        res.status(status).json({ error: true, message: error.message || 'Failed to cancel export' });
    }
});

router.get('/:scanId/exports/:jobId/download', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const scan = getOwnedScanOrRespond(req.params.scanId, req.user!, res);
        if (!scan) return;

        const job = reportExportService.getExport(req.params.jobId);
        if (!job || job.scan_id !== scan.id) {
            res.status(404).json({ error: true, message: 'Report export not found' });
            return;
        }
        if (job.status !== 'completed' || job.stage !== 'completed' || !job.artifact_path || !fs.existsSync(job.artifact_path)) {
            res.status(409).json({ error: true, message: 'Export artifact is not ready for download yet.' });
            return;
        }

        const filename = `PenPard-Report-${scan.id}.${job.format}`;
        res.download(job.artifact_path, filename);
    } catch (error: any) {
        logger.error('Download report export error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to download export' });
    }
});

function getOwnedScanOrRespond(scanId: string, user: NonNullable<AuthRequest['user']>, res: Response): any | null {
    const scan = getScan(scanId);
    if (!scan) {
        res.status(404).json({ error: true, message: 'Scan not found' });
        return null;
    }

    if (scan.user_id !== user.id && user.role === 'user') {
        res.status(403).json({ error: true, message: 'Access denied' });
        return null;
    }

    return scan;
}

function toApiExportJob(job: ReportExportRecord) {
    const stageLabel = job.stage === 'rendering_export'
        ? `Rendering ${job.format.toUpperCase()}`
        : job.stage;

    return {
        id: job.id,
        scanId: job.scan_id,
        snapshotId: job.snapshot_id,
        format: job.format,
        enrichmentMode: job.enrichment_mode,
        status: job.status,
        stage: job.stage,
        stageLabel,
        llmStatus: job.llm_status,
        artifactReady: job.status === 'completed' && job.stage === 'completed' && !!job.artifact_path && fs.existsSync(job.artifact_path),
        errorMessage: job.error_message,
        llmErrorMessage: job.llm_error_message,
        attemptCount: job.attempt_count,
        createdAt: job.created_at,
        updatedAt: job.updated_at,
        startedAt: job.started_at,
        completedAt: job.completed_at,
        canceledAt: job.canceled_at,
        downloadUrl: `/api/reports/${job.scan_id}/exports/${job.id}/download`,
    };
}

export default router;
