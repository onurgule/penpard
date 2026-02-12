import { Router, Response } from 'express';
import path from 'path';
import fs from 'fs';
import { db, getScan, getVulnerabilitiesByScan } from '../db/init';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';
import { generatePdfReport } from '../services/report';
import { generateDocxReport } from '../services/report-docx';
import { generatePptxReport } from '../services/report-pptx';
import { enhanceVulnerabilityDescriptions, generateExecutiveSummary, enhanceRemediations } from '../services/report-llm';
import { llmProvider } from '../services/LLMProviderService';

const router = Router();

/**
 * Check if the active LLM supports vision.
 * Used by the frontend to show/hide the image processing toggle.
 * IMPORTANT: This must be defined BEFORE /:scanId routes to avoid Express matching "capabilities" as a scanId.
 */
router.get('/capabilities/check', authenticateToken, async (_req: AuthRequest, res: Response) => {
    try {
        const visionCheck = llmProvider.checkVisionSupport();
        let llmAvailable = false;
        try {
            llmProvider.getActiveConfig();
            llmAvailable = true;
        } catch { /* no active LLM */ }

        res.json({
            llmAvailable,
            visionSupported: visionCheck.supported,
            provider: visionCheck.provider,
            model: visionCheck.model,
        });
    } catch (error: any) {
        res.json({ llmAvailable: false, visionSupported: false, provider: 'none', model: 'none' });
    }
});

// Get report for a scan
router.get('/:scanId', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { scanId } = req.params;
        const user = req.user!;

        const scan = getScan(scanId);

        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        // Check access
        if (scan.user_id !== user.id && user.role === 'user') {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        // Check if report exists
        const report = db.prepare('SELECT * FROM reports WHERE scan_id = ?').get(scanId) as any;

        if (report && fs.existsSync(report.file_path)) {
            res.json({
                scanId,
                reportUrl: `/api/reports/${scanId}/download`,
                createdAt: report.created_at,
            });
            return;
        }

        // Generate report if scan is complete
        if (scan.status !== 'completed') {
            res.status(400).json({ error: true, message: 'Scan not yet completed' });
            return;
        }

        const vulnerabilities = getVulnerabilitiesByScan(scanId);
        const reportPath = await generatePdfReport(scan, vulnerabilities);

        // Save report record
        db.prepare(`
      INSERT OR REPLACE INTO reports (scan_id, file_path)
      VALUES (?, ?)
    `).run(scanId, reportPath);

        res.json({
            scanId,
            reportUrl: `/api/reports/${scanId}/download`,
            createdAt: new Date().toISOString(),
        });
    } catch (error: any) {
        logger.error('Get report error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get report' });
    }
});

/**
 * Download report in the requested format with options.
 * 
 * Query params:
 *   format: 'pdf' | 'docx' | 'pptx'  (default: 'pdf')
 *   mode: 'static' | 'llm'           (default: 'static')
 *   imageProcessing: 'true' | 'false' (default: 'false', only applies to 'llm' mode PDF)
 */
router.get('/:scanId/download', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { scanId } = req.params;
        const format = (req.query.format as string || 'pdf').toLowerCase();
        const mode = (req.query.mode as string || 'static').toLowerCase();
        const imageProcessing = req.query.imageProcessing === 'true';
        const user = req.user!;

        const scan = getScan(scanId);

        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        if (scan.user_id !== user.id && user.role === 'user') {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        if (scan.status !== 'completed' && scan.status !== 'stopped') {
            res.status(400).json({ error: true, message: 'Scan not yet completed. Please wait for the scan to finish.' });
            return;
        }

        const vulnerabilities = getVulnerabilitiesByScan(scanId);

        // ── LLM Enhancement (if mode === 'llm') ──
        let enhancedDescriptions: Map<number, string> | undefined;
        let enhancedRemediations: Map<number, string> | undefined;

        if (mode === 'llm') {
            try {
                logger.info('Running LLM-driven report enhancement...', { scanId });

                // Run description and remediation enhancement in parallel
                const [descResult, remResult] = await Promise.all([
                    enhanceVulnerabilityDescriptions(vulnerabilities).catch(() => new Map<number, string>()),
                    enhanceRemediations(vulnerabilities).catch(() => new Map<number, string>()),
                ]);

                enhancedDescriptions = descResult;
                enhancedRemediations = remResult;

                logger.info(`LLM enhancement complete: ${enhancedDescriptions.size} descriptions, ${enhancedRemediations.size} remediations enhanced`);
            } catch (err: any) {
                logger.warn('LLM enhancement failed, using static content', { error: err.message });
            }
        }

        // ── Generate Report in Requested Format ──
        let reportPath: string;
        let filename: string;
        let contentType: string;

        switch (format) {
            case 'docx':
                reportPath = await generateDocxReport(scan, vulnerabilities, {
                    llmEnhanced: mode === 'llm',
                    enhancedDescriptions,
                });
                filename = `PenPard-Report-${scanId}.docx`;
                contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
                break;

            case 'pptx':
                reportPath = await generatePptxReport(scan, vulnerabilities, {
                    llmEnhanced: mode === 'llm',
                    enhancedDescriptions,
                });
                filename = `PenPard-Report-${scanId}.pptx`;
                contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
                break;

            case 'pdf':
            default:
                // For static PDF, check if we have a cached version
                if (mode === 'static' && !imageProcessing) {
                    const existing = db.prepare('SELECT * FROM reports WHERE scan_id = ?').get(scanId) as any;
                    if (existing && fs.existsSync(existing.file_path)) {
                        res.download(existing.file_path, `PenPard-Report-${scanId}.pdf`);
                        return;
                    }
                }

                reportPath = await generatePdfReport(scan, vulnerabilities);
                filename = `PenPard-Report-${scanId}.pdf`;
                contentType = 'application/pdf';

                // Cache the static PDF
                db.prepare(`INSERT OR REPLACE INTO reports (scan_id, file_path) VALUES (?, ?)`).run(scanId, reportPath);
                break;
        }

        // Set proper headers and download
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(reportPath, filename);

    } catch (error: any) {
        logger.error('Download report error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to generate report. ' + (error.message || '') });
    }
});

export default router;
