
import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import {
    getFocusedCaseHistoricalCompareByCase,
    getFocusedCaseInvestigationSummaryByCase,
    db,
    getFocusedCaseVerdictByExecution,
    getFocusedHistoricalCompareState,
    getFocusedHistoricalCompareSummary,
    getFocusedScanBlockerSummary,
    getFocusedScanVerdictSummary,
    getFocusedExecutionSummaryByCase,
    getFocusedScanFindingSummary,
    getLatestPrimaryFocusedCaseFindingByCase,
    getLatestPrimaryFocusedFindingThreadByCase,
    listFocusedInvestigationIssuesByCase,
    listFocusedInvestigationIssuesByExecution,
    listFocusedInvestigationIssuesByScan,
    listFocusedExecutionTraceEntriesByExecution,
    listFocusedCaseFindingsByExecution,
    listFocusedFindingThreadsByExecution,
    listLatestFocusedCaseFindingsByCase,
    listLatestPrimaryFocusedCaseFindingsByScan,
    listLatestFocusedFindingThreadsByCase,
    listLatestPrimaryFocusedFindingThreadsByScan,
    getFocusedTestCaseExecutionById,
    createScan,
    getFocusedTestObjective,
    getFocusedTestCaseById,
    getLatestFocusedTestCaseExecution,
    getScan,
    getScopedFeatureDiscoveryState,
    getScopedTestRequest,
    getScopeEnvelope,
    listEvidenceBundlesByExecution,
    listLatestFocusedCaseVerdictsByScan,
    listFocusedTestCasesByScan,
    listFocusedTestCasesWithExecutionSummary,
    setScanInitialRequest,
    deleteScans,
    getVulnerabilitiesByScan,
    getUserWhitelists,
    getChatMessages,
    saveScanConfig,
    updateFocusedTestCase,
} from '../db/init';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger, logApiUsage } from '../utils/logger';
import { burpDispatchService } from '../services/BurpDispatchService';
import { mobileScanService } from '../services/MobileScanService';
import { activityMonitor } from '../services/ActivityMonitorService';
import { peekPendingRequest, takePendingRequest } from './penpard';
import { selectLocalDirectory, extractZipArchive, cloneGitRepository } from '../utils/source-fetcher';
import { extractRoutes } from '../services/source-analysis/utils/route-extractor';
import { ScanChatServiceError, scanChatService } from '../services/ScanChatService';
import { scanLaunchConfigService } from '../services/runtime/ScanLaunchConfigService';
import { scanRuntimeService } from '../services/runtime/ScanRuntimeService';
import { scopeEnvelopeService } from '../services/runtime/ScopeEnvelopeService';
import { ScopedScanValidationError } from '../services/runtime/ScopeEnvelopeService';
import { ScopedScanLaunchService } from '../services/runtime/ScopedScanLaunchService';
import { focusedPlanningService, FocusedPlanningPreconditionError, listFocusedPlanningResult } from '../services/runtime/FocusedPlanningService';
import { focusedExecutionRunner, FocusedExecutionConflictError } from '../services/runtime/FocusedExecutionRunner';
import { focusedHistoricalCompareService } from '../services/runtime/FocusedHistoricalCompareService';
import { focusedReasoningVisibilityService } from '../services/runtime/FocusedReasoningVisibilityService';
import { buildFocusedContextInfluence, focusedReasoningTraceService } from '../services/runtime/FocusedReasoningTraceService';
import { focusedVerdictService } from '../services/runtime/FocusedVerdictService';
import {
    applyFocusedCaseFindings,
    applyFocusedFindingThreads,
    applyFocusedCaseVerdict,
    applyFocusedExecutionSummary,
    applyFocusedHistoricalCompare,
    applyFocusedInvestigationSummary,
    buildFocusedPlanSummary,
    buildFocusedRailUsageSummary,
    listPresentFocusedRequestContextFields,
    normalizeFocusedTestCasePriority,
    normalizeFocusedTestCaseReviewState,
    normalizeFocusedTestCaseStatus,
} from '../services/runtime/ScopedScanTypes';
import os from 'os';

const router = Router();
const scopedScanLaunchService = new ScopedScanLaunchService(db, scopeEnvelopeService, scanRuntimeService);

async function loadFocusedHistoricalCompare(scanId: string, userId: number) {
    await focusedHistoricalCompareService.ensureGenerated(scanId, userId);
    return {
        focusedHistoricalCompareState: getFocusedHistoricalCompareState(scanId),
        focusedHistoricalCompareSummary: getFocusedHistoricalCompareSummary(scanId),
    };
}

function buildFocusedVisibilityPayload(scanId: string, focusedTestCases: ReturnType<typeof listFocusedTestCasesWithExecutionSummary>) {
    const decoratedCases = focusedReasoningVisibilityService.decorateCases(scanId, focusedTestCases);
    return {
        focusedTestCases: decoratedCases,
        focusedFindings: listLatestPrimaryFocusedCaseFindingsByScan(scanId),
        focusedFindingThreads: listLatestPrimaryFocusedFindingThreadsByScan(scanId),
        focusedFindingSummary: getFocusedScanFindingSummary(scanId),
        focusedPlanSummary: buildFocusedPlanSummary(decoratedCases),
        focusedStorySummary: focusedReasoningVisibilityService.buildScanStorySummary(scanId, decoratedCases),
        focusedAgentTrace: focusedReasoningVisibilityService.buildScanAgentTrace(scanId),
        focusedRequestContextUsage: focusedReasoningVisibilityService.buildScanContextInfluenceSummary(scanId),
    };
}

function buildMissionControlLiveRuntimePayload(input: {
    scanId: string;
    status: string;
    focusedTestObjective: ReturnType<typeof getFocusedTestObjective>;
    scopeEnvelope: ReturnType<typeof getScopeEnvelope>;
    scopedTestRequest: ReturnType<typeof getScopedTestRequest>;
    focusedTestCases: ReturnType<typeof listFocusedTestCasesWithExecutionSummary>;
    focusedFindingThreads: ReturnType<typeof listLatestPrimaryFocusedFindingThreadsByScan>;
    standardFindingCount?: number;
}) {
    const liveRuntime = scanRuntimeService.getRuntimeSummary(input.scanId);
    if (liveRuntime) {
        return liveRuntime;
    }

    const activeCase = input.focusedTestCases.find((testCase) => testCase.executionState === 'running')
        || input.focusedTestCases.find((testCase) => testCase.executionState === 'blocked' || testCase.executionState === 'failed_to_execute')
        || input.focusedTestCases.find((testCase) => testCase.executionState === 'completed')
        || input.focusedTestCases[0]
        || null;
    const activeFindingThread = activeCase?.activeFindingThread
        || input.focusedFindingThreads[0]
        || null;
    const latestTrace = activeCase?.latestExecutionTracePreview?.[0] || null;

    return {
        missionState: input.status,
        targetUrl: input.scopedTestRequest?.targetUrl || null,
        objectiveTitle: input.focusedTestObjective?.title || null,
        objectiveGoal: input.focusedTestObjective?.goal || null,
        requestDescription: input.scopedTestRequest?.description || null,
        currentRail: activeCase?.executionRailSummary?.rail || null,
        activeCaseId: activeCase?.id || null,
        activeCaseTitle: activeCase?.title || null,
        activeFindingThreadId: activeFindingThread?.id || null,
        activeFindingTitle: activeFindingThread?.title || null,
        observationSummary: latestTrace?.responseSummary?.bodySummary || null,
        nextStepRationale: latestTrace?.nextStepRationale || activeCase?.hypothesis || null,
        lastResponseDeltaSummary: latestTrace?.responseSummary?.bodySummary || null,
        boundaryReason: null,
        lastRequestSummary: latestTrace?.requestSummary
            ? {
                method: latestTrace.requestSummary.method ?? null,
                path: latestTrace.requestSummary.path ?? null,
                url: latestTrace.requestSummary.url ?? null,
                statusCode: latestTrace.responseSummary?.statusCode ?? null,
                summary: [
                    latestTrace.requestSummary.method,
                    latestTrace.requestSummary.path || latestTrace.requestSummary.url,
                ].filter(Boolean).join(' '),
            }
            : null,
        latestSuspiciousSignal: activeFindingThread?.strongestSuspiciousSignal || activeFindingThread?.strongestSupportSummary || null,
        currentDecisionSummary: latestTrace?.nextStepRationale || latestTrace?.reasoningNote || activeCase?.hypothesis || null,
        liveFindingCount: input.focusedFindingThreads.length + Math.max(0, Number(input.standardFindingCount) || 0),
        boundarySummary: input.scopeEnvelope ? {
            allowedHosts: input.scopeEnvelope.allowedHosts,
            allowedRoutes: input.scopeEnvelope.allowedRoutes,
            selectedEndpointCount: input.scopeEnvelope.selectedEndpoints.length,
            browserAnchorCount: input.scopeEnvelope.browserAnchors.length,
            requestAnchorCount: input.scopeEnvelope.discoveredRequestRefs.length + (((input.scopeEnvelope as any).baselineRequestRefs?.length as number | undefined) ?? 0),
            boundaryHints: input.scopeEnvelope.boundaryHints,
            outOfScopeNotes: input.scopeEnvelope.outOfScopeNotes,
            explorationBudget: input.scopeEnvelope.explorationBudget || null,
            blockedActionReason: null,
            activeAnchorSummary: activeCase?.targetArtifact?.path || activeCase?.targetArtifact?.url || null,
            budgetState: {
                maxRequests: input.scopeEnvelope.explorationBudget?.maxRequests ?? null,
                requestActionsUsed: 0,
                remainingRequests: input.scopeEnvelope.explorationBudget?.maxRequests ?? null,
                maxBrowserActions: input.scopeEnvelope.explorationBudget?.maxBrowserActions ?? null,
                browserActionsUsed: 0,
                remainingBrowserActions: input.scopeEnvelope.explorationBudget?.maxBrowserActions ?? null,
                maxRouteVariants: input.scopeEnvelope.explorationBudget?.maxRouteVariants ?? null,
                routeVariantsUsed: 0,
            },
        } : null,
    };
}

function buildScopedRequestIntakeContextInfluence(request: ReturnType<typeof getScopedTestRequest>) {
    if (!request) {
        return [];
    }
    return [
        ...(request.testData.length > 0 ? [buildFocusedContextInfluence(
            'testData',
            'used',
            'Structured test data was preserved from request intake and made available to later bounded planning and execution decisions.',
        )] : []),
        ...(request.testUsers.length > 0 ? [buildFocusedContextInfluence(
            'testUsers',
            'used',
            'Structured user references were preserved from request intake for later role- or tenancy-sensitive reasoning.',
        )] : []),
        ...(request.authMechanismHints.length > 0 ? [buildFocusedContextInfluence(
            'authMechanismHints',
            'used',
            'Authentication hints were preserved from request intake for later bounded auth-sensitive reasoning.',
        )] : []),
        ...(request.attachmentSummary ? [buildFocusedContextInfluence(
            'attachmentSummary',
            'used',
            'Attachment notes were retained from request intake as bounded supporting context.',
        )] : []),
        ...(request.attachmentMetadata.length > 0 ? [buildFocusedContextInfluence(
            'attachmentMetadata',
            'used',
            'Attachment metadata was preserved from request intake as bounded supporting context.',
        )] : []),
        ...(request.operatorNotes ? [buildFocusedContextInfluence(
            'operatorNotes',
            'used',
            'Operator notes were preserved from request intake as bounded planning and execution context.',
        )] : []),
        ...(typeof request.newScreenCount === 'number' && request.newScreenCount > 0 ? [buildFocusedContextInfluence(
            'newScreenCount',
            'insufficient',
            'Screen counts were preserved at intake, but they were not enough by themselves to define a concrete scoped anchor.',
        )] : []),
        ...(typeof request.newInputCount === 'number' && request.newInputCount > 0 ? [buildFocusedContextInfluence(
            'newInputCount',
            'insufficient',
            'Input counts were preserved at intake, but they were not enough by themselves to define a concrete scoped anchor.',
        )] : []),
    ];
}

function recordScopedRequestIntakeReasoning(scanId: string, initialRequestPresent = false) {
    const objective = getFocusedTestObjective(scanId);
    const scopeEnvelope = getScopeEnvelope(scanId);
    const scopedTestRequest = getScopedTestRequest(scanId);
    if (!objective || !scopeEnvelope || !scopedTestRequest) {
        return;
    }

    const contextInfluence = buildScopedRequestIntakeContextInfluence(scopedTestRequest);
    focusedReasoningTraceService.record({
        scanId,
        objectiveId: objective.id,
        stage: 'request_intake',
        entryType: 'context',
        rail: 'system_only',
        summary: 'Scoped request intake persisted the bounded objective, scope envelope, and structured request context.',
        observationSummary: [
            scopedTestRequest.targetUrl,
            objective.title,
            scopeEnvelope.allowedRoutes.length > 0 ? `${scopeEnvelope.allowedRoutes.length} allowed route(s)` : null,
            initialRequestPresent ? 'Burp baseline request preserved' : null,
        ].filter((entry): entry is string => !!entry).join(' | '),
        actionSelectionRationale: 'All later scoped reasoning remains tied to the persisted request, objective, and scope envelope from intake.',
        linkedRequestContextKeys: listPresentFocusedRequestContextFields(scopedTestRequest),
        contextInfluence,
    });
}

// Setup multer for APK uploads
const uploadsDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}-${file.originalname}`;
        cb(null, uniqueName);
    },
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const name = file.originalname.toLowerCase();
        if (name.endsWith('.apk') || name.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('Only APK and ZIP files are allowed'));
        }
    }
});

router.post('/extract-endpoints', authenticateToken, upload.single('sourceZip'), async (req: AuthRequest, res: Response): Promise<any> => {
    try {
        const { sourceType, sourcePackagePath, sourceGitUrl, sourceGitToken } = req.body;
        const sourceZip = req.file;

        if (!sourceType || sourceType === 'none') {
            return res.status(400).json({ status: 'error', message: 'No valid source type provided.' });
        }

        let finalSourcePath = '';
        const cleanupPaths: string[] = [];

        try {
            if (sourceType === 'local') {
                if (!sourcePackagePath) return res.status(400).json({ status: 'error', message: 'Local path not provided' });
                finalSourcePath = sourcePackagePath;
            } else if (sourceType === 'zip') {
                if (!sourceZip) return res.status(400).json({ status: 'error', message: 'ZIP file not provided' });
                const extractDir = path.join(os.tmpdir(), `penpard_source_extract_${Date.now()}`);
                await extractZipArchive(sourceZip.path, extractDir);
                finalSourcePath = extractDir;
                cleanupPaths.push(extractDir);
                cleanupPaths.push(sourceZip.path);
            } else if (sourceType === 'git') {
                if (!sourceGitUrl) return res.status(400).json({ status: 'error', message: 'Git URL not provided' });
                const cloneDir = path.join(os.tmpdir(), `penpard_source_extract_${Date.now()}`);
                await cloneGitRepository(sourceGitUrl, cloneDir, sourceGitToken || undefined);
                finalSourcePath = cloneDir;
                cleanupPaths.push(cloneDir);
            }

            const endpoints = await extractRoutes(finalSourcePath);

            for (const p of cleanupPaths) {
                try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {}
            }

            res.json({ endpoints });
        } catch (err: any) {
            for (const p of cleanupPaths) {
                try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {}
            }
            if (sourceZip?.path) {
                try { fs.rmSync(sourceZip.path, { force: true }); } catch (e) {}
            }
            throw err;
        }
    } catch (error: any) {
        logger.error('Failed to extract endpoints', { error: error.message });
        res.status(500).json({ status: 'error', message: error.message || 'Failed to extract endpoints' });
    }
});

router.post('/extract-endpoints-ai', authenticateToken, upload.single('sourceZip'), async (req: AuthRequest, res: Response): Promise<any> => {
    try {
        const { sourceType, sourcePackagePath, sourceGitUrl, sourceGitToken, existingRoutes } = req.body;
        const sourceZip = req.file;

        if (!sourceType || sourceType === 'none') {
            return res.status(400).json({ status: 'error', message: 'No valid source type provided.' });
        }

        let existingEndpoints: any[] = [];
        try { existingEndpoints = JSON.parse(existingRoutes || '[]'); } catch { existingEndpoints = []; }

        let finalSourcePath = '';
        const cleanupPaths: string[] = [];

        try {
            if (sourceType === 'local') {
                if (!sourcePackagePath) return res.status(400).json({ status: 'error', message: 'Local path not provided' });
                finalSourcePath = sourcePackagePath;
            } else if (sourceType === 'zip') {
                if (!sourceZip) return res.status(400).json({ status: 'error', message: 'ZIP file not provided' });
                const extractDir = path.join(os.tmpdir(), `penpard_source_ai_${Date.now()}`);
                await extractZipArchive(sourceZip.path, extractDir);
                finalSourcePath = extractDir;
                cleanupPaths.push(extractDir);
                cleanupPaths.push(sourceZip.path);
            } else if (sourceType === 'git') {
                if (!sourceGitUrl) return res.status(400).json({ status: 'error', message: 'Git URL not provided' });
                const cloneDir = path.join(os.tmpdir(), `penpard_source_ai_${Date.now()}`);
                await cloneGitRepository(sourceGitUrl, cloneDir, sourceGitToken || undefined);
                finalSourcePath = cloneDir;
                cleanupPaths.push(cloneDir);
            }

            const { extractRoutesWithAI } = await import('../services/source-analysis/utils/ai-route-extractor');
            const aiEndpoints = await extractRoutesWithAI(finalSourcePath, existingEndpoints, req.user?.id);

            for (const p of cleanupPaths) {
                try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {}
            }

            res.json({ endpoints: aiEndpoints });
        } catch (err: any) {
            for (const p of cleanupPaths) {
                try { fs.rmSync(p, { recursive: true, force: true }); } catch (e) {}
            }
            throw err;
        }
    } catch (error: any) {
        logger.error('Failed to extract endpoints with AI', { error: error.message });
        res.status(500).json({ status: 'error', message: error.message || 'Failed to extract endpoints with AI' });
    }
});


// Get dashboard stats (Must be defined before /:id)
router.get('/stats', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const scanCount = db.prepare('SELECT COUNT(*) as count FROM scans WHERE user_id = ?').get(user.id) as any;
        const vulnCount = db.prepare(`
            SELECT COUNT(*) as count FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE s.user_id = ?
         `).get(user.id) as any;
        const reportCount = db.prepare(`
            SELECT COUNT(*) as count FROM reports r
            JOIN scans s ON r.scan_id = s.id
            WHERE s.user_id = ?
         `).get(user.id) as any;

        res.json({
            totalScans: scanCount.count,
            totalVulns: vulnCount.count,
            reportsGenerated: reportCount.count
        });
    } catch (error: any) {
        logger.error('Get stats error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get stats' });
    }
});

// Check if URL matches user's whitelist
function isWhitelisted(url: string, whitelists: any[]): boolean {
    if (whitelists.length === 0) return true; // No whitelist = allow all

    try {
        const hostname = new URL(url).hostname;

        return whitelists.some(w => {
            const pattern = w.domain_pattern.toLowerCase();
            const host = hostname.toLowerCase();

            if (pattern.startsWith('*.')) {
                // Wildcard pattern: *.example.com matches sub.example.com
                const domain = pattern.slice(2);
                return host.endsWith(domain) || host === domain.slice(1);
            }

            return host === pattern || host.endsWith('.' + pattern);
        });
    } catch {
        return false;
    }
}

function getOwnedScanOrRespond(scanId: string, userId: number, res: Response): any | null {
    const scan = getScan(scanId);

    if (!scan) {
        res.status(404).json({ error: true, message: 'Scan not found' });
        return null;
    }

    if (scan.user_id !== userId) {
        res.status(403).json({ error: true, message: 'Access denied' });
        return null;
    }

    return scan;
}

async function resolveScanSourcePath(input: {
    scanId: string;
    sourceType?: unknown;
    sourcePackagePath?: unknown;
    sourceGitUrl?: unknown;
    sourceGitToken?: unknown;
    uploadFile?: Express.Multer.File;
}): Promise<string | undefined> {
    const sourceType = typeof input.sourceType === 'string' ? input.sourceType : undefined;
    const sourcePackagePath = typeof input.sourcePackagePath === 'string' ? input.sourcePackagePath.trim() : undefined;
    const sourceGitUrl = typeof input.sourceGitUrl === 'string' ? input.sourceGitUrl : undefined;
    const sourceGitToken = typeof input.sourceGitToken === 'string' ? input.sourceGitToken : undefined;

    if (sourceType === 'zip' && input.uploadFile) {
        const destDir = path.join(uploadsDir, 'source-zips', input.scanId);
        logger.info(`Extracting ZIP source to ${destDir}`);
        const extractedPath = await extractZipArchive(input.uploadFile.path, destDir);
        try { fs.unlinkSync(input.uploadFile.path); } catch {}
        return extractedPath;
    }

    if (sourceType === 'git' && sourceGitUrl) {
        const destDir = path.join(uploadsDir, 'source-repos', input.scanId);
        logger.info(`Cloning Git source to ${destDir}`);
        return cloneGitRepository(sourceGitUrl, sourceGitToken, destDir);
    }

    if ((!sourceType || sourceType === 'local') && sourcePackagePath) {
        return sourcePackagePath;
    }

    return undefined;
}

function parseStructuredBodyField(value: unknown): any {
    if (value === undefined || value === null || value === '') {
        return undefined;
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return undefined;
        }
        try {
            return JSON.parse(trimmed);
        } catch {
            return undefined;
        }
    }
    return value;
}

function hasScopedSelectionInput(body: Record<string, any>): boolean {
    const legacyTargetEndpoints = parseStructuredBodyField(body.targetEndpoints);
    if (Array.isArray(legacyTargetEndpoints) && legacyTargetEndpoints.length > 0) {
        return true;
    }

    const scopeEnvelope = parseStructuredBodyField(body.scopeEnvelope);
    if (scopeEnvelope && Array.isArray(scopeEnvelope.selectedEndpoints) && scopeEnvelope.selectedEndpoints.length > 0) {
        return true;
    }

    return false;
}

// List user's scans
router.get('/', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const scans = db.prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(user.id);
        res.json({ scans });
    } catch (error: any) {
        logger.error('List scans error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to list scans' });
    }
});

// Permanently delete selected scans (user's scans only; CASCADE removes related data)
router.post('/delete', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const { ids } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ error: true, message: 'ids array is required and must not be empty' });
        }
        const safeIds = ids.filter((id: unknown) => typeof id === 'string' && id.length > 0);
        const result = deleteScans(safeIds, user.id);
        return res.json({ deleted: result.changes, message: `${result.changes} scan(s) permanently deleted` });
    } catch (error: any) {
        logger.error('Delete scans error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to delete scans' });
    }
});

// Initiate web scan
router.get('/system/select-directory', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const path = await selectLocalDirectory();
        res.json({ path });
    } catch (error: any) {
        logger.error('Failed to open directory picker', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to open directory picker on the server' });
    }
});

router.post('/web', authenticateToken, upload.single('sourceZip'), async (req: AuthRequest, res: Response) => {
    try {
        const {
            url,
            sourceType,
            sourcePackagePath,
            sourceGitUrl,
            sourceGitToken,
        } = req.body;
        const user = req.user!;
        if (!url) {
            res.status(400).json({ error: true, message: 'URL is required' });
            return;
        }

        // Validate URL
        let targetUrl: string;
        try {
            targetUrl = new URL(url.startsWith('http') ? url : `https://${url}`).toString();
        } catch {
            res.status(400).json({ error: true, message: 'Invalid URL format' });
            return;
        }

        // Check whitelist
        const whitelists = getUserWhitelists(user.id);
        if (!isWhitelisted(targetUrl, whitelists)) {
            res.status(403).json({
                error: true,
                message: 'Target URL not in your whitelist. Contact admin.'
            });
            return;
        }

        const scanId = uuidv4();
        
        let finalSourcePath: string | undefined = undefined;
        try {
            finalSourcePath = await resolveScanSourcePath({
                scanId,
                sourceType,
                sourcePackagePath,
                sourceGitUrl,
                sourceGitToken,
                uploadFile: req.file || undefined,
            });
        } catch (sourceErr: any) {
            logger.warn(`Failed to process source code input: ${sourceErr.message}`);
            res.status(400).json({ error: true, message: `Source code processing failed: ${sourceErr.message}` });
            return;
        }

        const launchPlan = scanLaunchConfigService.prepareWebLaunch({
            ...req.body,
            securityTestRequest: parseStructuredBodyField(req.body.securityTestRequest),
            userId: user.id,
            sourcePackagePath: finalSourcePath,
        });

        logApiUsage('/api/scans/web', user.id, { target: targetUrl });
        if (launchPlan.scanMetadata.scanMode === 'scoped') {
            scopedScanLaunchService.launch({
                scanId,
                userId: user.id,
                targetUrl,
                requestBody: {
                    ...(req.body as Record<string, any>),
                    securityTestRequest: parseStructuredBodyField(req.body.securityTestRequest),
                },
                scanMetadata: launchPlan.scanMetadata,
                persistedConfig: launchPlan.persistedConfig,
                runtimeConfig: launchPlan.runtimeConfig,
            });
            recordScopedRequestIntakeReasoning(scanId, false);
        } else {
            if (hasScopedSelectionInput(req.body as Record<string, any>)) {
                res.status(400).json({
                    error: true,
                    message: 'Endpoint selections require Scoped Test Mode. Switch scan mode to scoped or clear the scoped inputs.',
                });
                return;
            }

            createScan({
                id: scanId,
                userId: user.id,
                type: 'web',
                target: targetUrl,
                scanMode: launchPlan.scanMetadata.scanMode,
                sourcePackagePath: launchPlan.scanMetadata.sourcePackagePath,
                sourceAnalysisMode: launchPlan.scanMetadata.sourceAnalysisMode,
            });
            saveScanConfig(scanId, JSON.stringify(launchPlan.persistedConfig));
            scanRuntimeService.launchWebScan(scanId, targetUrl, launchPlan.runtimeConfig);
        }

        res.json({
            scanId,
            message: 'Antigravity Scan initiated',
        });
    } catch (error: any) {
        logger.error('Web scan error', { error: error.message });
        const statusCode = error instanceof ScopedScanValidationError ? 400 : 500;
        res.status(statusCode).json({ error: true, message: statusCode === 400 ? error.message : 'Failed to start scan' });
    }
});

// Initiate mobile scan
router.post('/mobile', authenticateToken, upload.single('apk'), async (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const file = req.file;

        if (!file) {
            res.status(400).json({ error: true, message: 'APK file is required' });
            return;
        }

        // Create scan record
        const scanId = uuidv4();
        createScan({
            id: scanId,
            userId: user.id,
            type: 'mobile',
            target: file.originalname,
        });

        logApiUsage('/api/scans/mobile', user.id, { filename: file.originalname });

        mobileScanService.launch(scanId, file.path);

        res.json({
            scanId,
            message: 'Analysis initiated',
        });
    } catch (error: any) {
        logger.error('Mobile scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to start analysis' });
    }
});

// Start scan from Burp "Send to PenPard" (pending request)
router.post('/from-burp', authenticateToken, upload.single('sourceZip'), async (req: AuthRequest, res: Response) => {
    try {
        const {
            pendingId,
            sourceType,
            sourcePackagePath,
            sourceGitUrl,
            sourceGitToken,
        } = req.body;
        const user = req.user!;
        if (!pendingId) {
            return res.status(400).json({ error: true, message: 'pendingId is required' });
        }
        const pendingEntry = peekPendingRequest(pendingId);
        if (!pendingEntry) {
            return res.status(404).json({ error: true, message: 'Pending request not found or already used' });
        }
        let targetUrl: string;
        try {
            targetUrl = new URL(pendingEntry.url.startsWith('http') ? pendingEntry.url : `https://${pendingEntry.url}`).toString();
        } catch {
            return res.status(400).json({ error: true, message: 'Invalid URL in request' });
        }
        const whitelists = getUserWhitelists(user.id);
        if (!isWhitelisted(targetUrl, whitelists)) {
            return res.status(403).json({
                error: true,
                message: 'Target URL not in your whitelist. Contact admin.'
            });
        }
        const entry = takePendingRequest(pendingId);
        if (!entry) {
            return res.status(409).json({ error: true, message: 'Pending request was already consumed by another action' });
        }
        const scanId = uuidv4();
        
        let finalSourcePath: string | undefined = undefined;
        try {
            finalSourcePath = await resolveScanSourcePath({
                scanId,
                sourceType,
                sourcePackagePath,
                sourceGitUrl,
                sourceGitToken,
                uploadFile: req.file || undefined,
            });
        } catch (sourceErr: any) {
            logger.warn(`Failed to process source code input: ${sourceErr.message}`);
            return res.status(400).json({ error: true, message: `Source code processing failed: ${sourceErr.message}` });
        }

        const launchPlan = scanLaunchConfigService.prepareBurpLaunch({
            ...req.body,
            securityTestRequest: parseStructuredBodyField(req.body.securityTestRequest),
            userId: user.id,
            initialRequest: entry.rawRequest,
            sourcePackagePath: finalSourcePath,
        });
        logApiUsage('/api/scans/from-burp', user.id, { target: targetUrl });
        if (launchPlan.scanMetadata.scanMode === 'scoped') {
            scopedScanLaunchService.launch({
                scanId,
                userId: user.id,
                targetUrl,
                requestBody: {
                    ...(req.body as Record<string, any>),
                    securityTestRequest: parseStructuredBodyField(req.body.securityTestRequest),
                },
                scanMetadata: launchPlan.scanMetadata,
                persistedConfig: launchPlan.persistedConfig,
                runtimeConfig: launchPlan.runtimeConfig,
                initialRequest: entry.rawRequest,
            });
            recordScopedRequestIntakeReasoning(scanId, true);
        } else {
            if (hasScopedSelectionInput(req.body as Record<string, any>)) {
                return res.status(400).json({
                    error: true,
                    message: 'Endpoint selections require Scoped Test Mode. Switch scan mode to scoped or clear the scoped inputs.',
                });
            }

            createScan({
                id: scanId,
                userId: user.id,
                type: 'web',
                target: targetUrl,
                scanMode: launchPlan.scanMetadata.scanMode,
                sourcePackagePath: launchPlan.scanMetadata.sourcePackagePath,
                sourceAnalysisMode: launchPlan.scanMetadata.sourceAnalysisMode,
            });
            setScanInitialRequest(scanId, entry.rawRequest);
            saveScanConfig(scanId, JSON.stringify(launchPlan.persistedConfig));
            scanRuntimeService.launchWebScan(scanId, targetUrl, launchPlan.runtimeConfig);
        }
        return res.json({
            scanId,
            message: 'Scan started from Burp request',
        });
    } catch (error: any) {
        logger.error('From-burp scan error', { error: error.message });
        const statusCode = error instanceof ScopedScanValidationError ? 400 : 500;
        res.status(statusCode).json({ error: true, message: statusCode === 400 ? error.message : 'Failed to start scan' });
    }
});

// Get scan status
router.get('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const vulnerabilities = getVulnerabilitiesByScan(id);
        const endpointInventory = scanRuntimeService.getEndpointInventory(id);
        const runtimeCheckpoint = scanRuntimeService.getRuntimeCheckpoint(id);
        const focusedTestObjective = getFocusedTestObjective(id);
        const scopeEnvelope = getScopeEnvelope(id);
        const scopedTestRequest = scan.scan_mode === 'scoped'
            ? getScopedTestRequest(id)
            : null;
        const featureDiscoveryState = scan.scan_mode === 'scoped'
            ? getScopedFeatureDiscoveryState(id)
            : null;
        const focusedVerdictSummary = scan.scan_mode === 'scoped'
            ? getFocusedScanVerdictSummary(id)
            : null;
        const focusedBlockerSummary = scan.scan_mode === 'scoped'
            ? getFocusedScanBlockerSummary(id)
            : null;
        const focusedHistoricalCompare = scan.scan_mode === 'scoped'
            ? await loadFocusedHistoricalCompare(id, scan.user_id)
            : { focusedHistoricalCompareState: null, focusedHistoricalCompareSummary: null };
        const focusedTestCases = scan.scan_mode === 'scoped'
            ? listFocusedTestCasesWithExecutionSummary(id)
            : [];
        const focusedVisibilityPayload = scan.scan_mode === 'scoped'
            ? buildFocusedVisibilityPayload(id, focusedTestCases)
            : {
                focusedTestCases,
                focusedFindings: [],
                focusedFindingThreads: [],
                focusedFindingSummary: null,
                focusedPlanSummary: buildFocusedPlanSummary(focusedTestCases),
                focusedStorySummary: null,
                focusedAgentTrace: [],
                focusedRequestContextUsage: null,
            };
        const liveRuntimeSummary = scan.scan_mode === 'scoped'
            ? buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: scan.status,
                focusedTestObjective,
                scopeEnvelope,
                scopedTestRequest,
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
                standardFindingCount: vulnerabilities.length,
            })
            : null;

        res.json({
            id: scan.id,
            type: scan.type,
            scanMode: scan.scan_mode || 'exploratory',
            target: scan.target,
            status: scan.status,
            createdAt: scan.created_at,
            completedAt: scan.completed_at,
            message: scan.error_message,
            sourcePackagePath: scan.source_package_path || null,
            sourceAnalysisMode: scan.source_analysis_mode || null,
            focusedTestObjective,
            scopeEnvelope,
            scopedTestRequest,
            featureDiscoveryState,
            ...focusedVisibilityPayload,
            liveRuntimeSummary,
            scopedLiveRuntime: liveRuntimeSummary,
            focusedVerdictSummary,
            focusedBlockerSummary,
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
            endpointInventory,
            runtimeCheckpoint,
            vulnerabilities: vulnerabilities.map(v => ({
                id: v.id,
                name: v.name,
                description: v.description,
                severity: v.severity,
                cvssScore: v.cvss_score,
                cwe: v.cwe,
                cve: v.cve,
                request: v.request || '',
                response: v.response || '',
                remediation: v.remediation || '',
                evidence: v.evidence || '',
            })),
        });
    } catch (error: any) {
        logger.error('Get scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get scan' });
    }
});

router.get('/:id/focused-test-cases', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused test cases are only available for scoped scans.' });
        }

        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(id);
        const focusedVisibilityPayload = buildFocusedVisibilityPayload(id, focusedTestCases);
        return res.json({
            status: scan.status,
            scanId: id,
            ...focusedVisibilityPayload,
            liveRuntimeSummary: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            scopedLiveRuntime: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            focusedVerdictSummary: getFocusedScanVerdictSummary(id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Get focused test cases error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused test cases' });
    }
});

router.post('/:id/plan-focused-tests', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Legacy focused planning is only available for scoped scans.' });
        }

        await focusedPlanningService.planNow(id, { reviewMode: 'legacy' });
        const refreshedScan = getScan(id);
        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(id);
        const focusedVisibilityPayload = buildFocusedVisibilityPayload(id, focusedTestCases);
        return res.json({
            status: refreshedScan?.status || 'awaiting_review',
            scanId: id,
            legacyManualOnly: true,
            ...focusedVisibilityPayload,
            liveRuntimeSummary: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: refreshedScan?.status || 'awaiting_review',
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            scopedLiveRuntime: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: refreshedScan?.status || 'awaiting_review',
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            focusedVerdictSummary: getFocusedScanVerdictSummary(id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Plan focused tests error', { error: error.message });
        if (error instanceof FocusedPlanningPreconditionError) {
            return res.status(409).json({ error: true, message: error.message });
        }
        return res.status(500).json({ error: true, message: error.message || 'Failed to plan focused tests' });
    }
});

router.patch('/:id/focused-test-cases/:caseId', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id, caseId } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused test case review is only available for scoped scans.' });
        }

        if (!getFocusedTestCaseById(id, caseId)) {
            return res.status(404).json({ error: true, message: 'Focused test case not found' });
        }

        const updates: Record<string, string> = {};
        if (req.body.priority !== undefined) {
            updates.priority = normalizeFocusedTestCasePriority(req.body.priority);
        }
        if (req.body.status !== undefined) {
            updates.status = normalizeFocusedTestCaseStatus(req.body.status);
        }
        if (req.body.reviewState !== undefined) {
            updates.reviewState = normalizeFocusedTestCaseReviewState(req.body.reviewState);
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ error: true, message: 'Provide at least one of priority, status, or reviewState.' });
        }

        const updatedFocusedTestCase = updateFocusedTestCase(id, caseId, updates);
        if (!updatedFocusedTestCase) {
            return res.status(404).json({ error: true, message: 'Focused test case not found' });
        }

        const latestExecutionSummary = getFocusedExecutionSummaryByCase(id, caseId);
        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(id);
        const focusedVisibilityPayload = buildFocusedVisibilityPayload(id, focusedTestCases);
        const decoratedFocusedTestCase = focusedVisibilityPayload.focusedTestCases.find((entry) => entry.id === caseId)
            || applyFocusedHistoricalCompare(
                applyFocusedInvestigationSummary(
                    applyFocusedCaseVerdict(
                        applyFocusedExecutionSummary(
                            updatedFocusedTestCase,
                            latestExecutionSummary,
                        ),
                        latestExecutionSummary?.lastExecutionId
                            ? getFocusedCaseVerdictByExecution(id, caseId, latestExecutionSummary.lastExecutionId)
                            : null,
                    ),
                    getFocusedCaseInvestigationSummaryByCase(id, caseId),
                ),
                getFocusedCaseHistoricalCompareByCase(id, caseId),
            );
        return res.json({
            focusedTestCase: decoratedFocusedTestCase,
            ...focusedVisibilityPayload,
            liveRuntimeSummary: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: getScan(id)?.status || scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            scopedLiveRuntime: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: getScan(id)?.status || scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            focusedVerdictSummary: getFocusedScanVerdictSummary(id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Update focused test case error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to update focused test case' });
    }
});

router.post('/:id/execute-focused-tests', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Legacy focused execution is only available for scoped scans.' });
        }

        if (scan.status === 'scoped_executing' || focusedExecutionRunner.hasActiveExecution(id)) {
            return res.status(409).json({ error: true, message: 'Focused execution is already running for this scan.' });
        }

        const caseIds = Array.isArray(req.body?.caseIds)
            ? req.body.caseIds.filter((entry: unknown): entry is string => typeof entry === 'string' && entry.trim().length > 0)
            : undefined;
        if (caseIds?.length) {
            const missingCaseId = caseIds.find((caseId: string) => !getFocusedTestCaseById(id, caseId));
            if (missingCaseId) {
                return res.status(404).json({ error: true, message: `Focused test case not found: ${missingCaseId}` });
            }
        }

        focusedExecutionRunner.launchExecution(id, caseIds);
        return res.status(202).json({
            accepted: true,
            scanId: id,
            status: 'scoped_executing',
            caseIds: caseIds || null,
            legacyManualOnly: true,
        });
    } catch (error: any) {
        if (error instanceof FocusedExecutionConflictError) {
            return res.status(409).json({ error: true, message: error.message });
        }
        logger.error('Execute focused tests error', { error: error.message });
        return res.status(500).json({ error: true, message: error.message || 'Failed to launch focused execution' });
    }
});

router.post('/:id/generate-focused-verdicts', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused verdict generation is only available for scoped scans.' });
        }
        if (scan.status === 'scoped_executing' || focusedExecutionRunner.hasActiveExecution(id)) {
            return res.status(409).json({ error: true, message: 'Focused verdict generation is unavailable while scoped execution is still running.' });
        }

        const verdictResult = await focusedVerdictService.generateNow(id, scan.user_id);
        const refreshedScan = getScan(id);
        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(id);
        const focusedVisibilityPayload = buildFocusedVisibilityPayload(id, focusedTestCases);
        return res.json({
            status: refreshedScan?.status || scan.status,
            scanId: id,
            caseVerdicts: verdictResult.caseVerdicts,
            ...focusedVisibilityPayload,
            liveRuntimeSummary: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: refreshedScan?.status || scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            scopedLiveRuntime: buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: refreshedScan?.status || scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
            }),
            focusedVerdictSummary: verdictResult.focusedVerdictSummary,
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Generate focused verdicts error', { error: error.message });
        return res.status(500).json({ error: true, message: error.message || 'Failed to generate focused verdicts' });
    }
});

router.get('/:id/focused-verdicts', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused verdicts are only available for scoped scans.' });
        }

        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        return res.json({
            scanId: id,
            caseVerdicts: listLatestFocusedCaseVerdictsByScan(id),
            focusedVerdictSummary: getFocusedScanVerdictSummary(id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Get focused verdicts error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused verdicts' });
    }
});

router.get('/:id/focused-compare', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused historical compare is only available for scoped scans.' });
        }

        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        return res.json({
            scanId: id,
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
            focusedTestCases: listFocusedTestCasesWithExecutionSummary(id),
        });
    } catch (error: any) {
        logger.error('Get focused historical compare error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused historical compare' });
    }
});

router.get('/:id/focused-test-cases/:caseId/compare', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id, caseId } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused historical compare is only available for scoped scans.' });
        }
        if (!getFocusedTestCaseById(id, caseId)) {
            return res.status(404).json({ error: true, message: 'Focused test case not found' });
        }

        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        return res.json({
            scanId: id,
            caseId,
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
            historicalCompare: getFocusedCaseHistoricalCompareByCase(id, caseId),
        });
    } catch (error: any) {
        logger.error('Get focused case historical compare error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused case historical compare' });
    }
});

router.get('/:id/focused-test-cases/:caseId/evidence', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id, caseId } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused evidence is only available for scoped scans.' });
        }

        if (!getFocusedTestCaseById(id, caseId)) {
            return res.status(404).json({ error: true, message: 'Focused test case not found' });
        }

        const requestedExecutionId = typeof req.query.executionId === 'string' ? req.query.executionId : undefined;
        const execution = requestedExecutionId
            ? getFocusedTestCaseExecutionById(id, caseId, requestedExecutionId)
            : getLatestFocusedTestCaseExecution(id, caseId);
        const latestExecutionSummary = getFocusedExecutionSummaryByCase(id, caseId);
        const latestCaseVerdict = latestExecutionSummary?.lastExecutionId
            ? getFocusedCaseVerdictByExecution(id, caseId, latestExecutionSummary.lastExecutionId)
            : null;
        const latestCaseFindings = listLatestFocusedCaseFindingsByCase(id, caseId);
        const latestPrimaryFinding = getLatestPrimaryFocusedCaseFindingByCase(id, caseId);
        const latestFindingThreads = listLatestFocusedFindingThreadsByCase(id, caseId);
        const latestPrimaryFindingThread = getLatestPrimaryFocusedFindingThreadByCase(id, caseId);
        const focusedHistoricalCompare = await loadFocusedHistoricalCompare(id, scan.user_id);
        const caseHistoricalCompare = getFocusedCaseHistoricalCompareByCase(id, caseId);
        const latestVisibility = focusedReasoningVisibilityService.buildCaseVisibility(id, caseId, latestExecutionSummary?.lastExecutionId);

        if (!execution) {
            return res.json({
                focusedTestCase: applyFocusedFindingThreads(
                    applyFocusedHistoricalCompare(
                        applyFocusedInvestigationSummary(
                            applyFocusedCaseFindings(
                                applyFocusedCaseVerdict(
                                    applyFocusedExecutionSummary(
                                        getFocusedTestCaseById(id, caseId)!,
                                        latestExecutionSummary,
                                    ),
                                    latestCaseVerdict,
                                ),
                                latestCaseFindings,
                            ),
                            getFocusedCaseInvestigationSummaryByCase(id, caseId),
                        ),
                        caseHistoricalCompare,
                    ),
                    latestFindingThreads,
                ),
                execution: null,
                caseVerdict: null,
                findings: latestCaseFindings,
                findingThreads: latestFindingThreads,
                primaryFinding: latestPrimaryFinding,
                primaryFindingThread: latestPrimaryFindingThread,
                evidenceBundles: [],
                executionTrace: [],
                reasoningTrace: latestVisibility.reasoningTrace,
                hypothesisVisibility: latestVisibility.hypothesisVisibility,
                suspicionExplanation: latestVisibility.suspicionExplanation,
                contextInfluenceSummary: latestVisibility.contextInfluenceSummary,
                evidenceReasoningLinks: latestVisibility.evidenceReasoningLinks,
                railSummary: null,
                investigationIssues: [],
                focusedBlockerSummary: getFocusedScanBlockerSummary(id),
                focusedVerdictSummary: getFocusedScanVerdictSummary(id),
                focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
                focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
            });
        }

        const executionTrace = listFocusedExecutionTraceEntriesByExecution(id, caseId, execution.id);
        const railSummary = buildFocusedRailUsageSummary({
            requestActionsUsed: execution.requestActionsUsed,
            browserActionsUsed: execution.browserActionsUsed,
            traceCount: executionTrace.length,
        });
        const caseFindings = listFocusedCaseFindingsByExecution(id, caseId, execution.id);
        const caseFindingThreads = listFocusedFindingThreadsByExecution(id, caseId, execution.id);
        const visibility = focusedReasoningVisibilityService.buildCaseVisibility(id, caseId, execution.id);
        const focusedTestCase = focusedReasoningVisibilityService.decorateCases(id, [
            applyFocusedFindingThreads(
                applyFocusedHistoricalCompare(
                    applyFocusedInvestigationSummary(
                        applyFocusedCaseFindings(
                            applyFocusedCaseVerdict(
                                applyFocusedExecutionSummary(
                                    getFocusedTestCaseById(id, caseId)!,
                                    latestExecutionSummary,
                                ),
                                latestCaseVerdict,
                            ),
                            caseFindings,
                        ),
                        getFocusedCaseInvestigationSummaryByCase(id, caseId),
                    ),
                    caseHistoricalCompare,
                ),
                caseFindingThreads,
            ),
        ])[0];

        return res.json({
            focusedTestCase,
            execution,
            caseVerdict: getFocusedCaseVerdictByExecution(id, caseId, execution.id),
            findings: caseFindings,
            findingThreads: caseFindingThreads,
            primaryFinding: caseFindings.find((entry) => entry.isPrimary) || caseFindings[0] || null,
            primaryFindingThread: caseFindingThreads.find((entry) => entry.isPrimary) || caseFindingThreads[0] || null,
            evidenceBundles: listEvidenceBundlesByExecution(id, caseId, execution.id),
            executionTrace,
            reasoningTrace: visibility.reasoningTrace,
            hypothesisVisibility: visibility.hypothesisVisibility,
            suspicionExplanation: visibility.suspicionExplanation,
            contextInfluenceSummary: visibility.contextInfluenceSummary,
            evidenceReasoningLinks: visibility.evidenceReasoningLinks,
            railSummary,
            investigationIssues: listFocusedInvestigationIssuesByExecution(id, caseId, execution.id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
            focusedVerdictSummary: getFocusedScanVerdictSummary(id),
            focusedHistoricalCompareState: focusedHistoricalCompare.focusedHistoricalCompareState,
            focusedHistoricalCompareSummary: focusedHistoricalCompare.focusedHistoricalCompareSummary,
        });
    } catch (error: any) {
        logger.error('Get focused evidence error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused evidence bundles' });
    }
});

router.get('/:id/focused-investigations', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused investigations are only available for scoped scans.' });
        }

        return res.json({
            scanId: id,
            investigationIssues: listFocusedInvestigationIssuesByScan(id),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
        });
    } catch (error: any) {
        logger.error('Get focused investigations error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused investigations' });
    }
});

router.get('/:id/focused-test-cases/:caseId/investigations', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id, caseId } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused investigations are only available for scoped scans.' });
        }
        if (!getFocusedTestCaseById(id, caseId)) {
            return res.status(404).json({ error: true, message: 'Focused test case not found' });
        }

        const requestedExecutionId = typeof req.query.executionId === 'string' ? req.query.executionId : undefined;
        const investigationIssues = requestedExecutionId
            ? listFocusedInvestigationIssuesByExecution(id, caseId, requestedExecutionId)
            : listFocusedInvestigationIssuesByCase(id, caseId);

        return res.json({
            scanId: id,
            caseId,
            investigationIssues,
            investigationSummary: getFocusedCaseInvestigationSummaryByCase(id, caseId),
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
        });
    } catch (error: any) {
        logger.error('Get focused case investigations error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused case investigations' });
    }
});

router.get('/:id/focused-blockers', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        if (scan.scan_mode !== 'scoped') {
            return res.status(400).json({ error: true, message: 'Focused blocker summaries are only available for scoped scans.' });
        }

        return res.json({
            scanId: id,
            focusedBlockerSummary: getFocusedScanBlockerSummary(id),
        });
    } catch (error: any) {
        logger.error('Get focused blocker summary error', { error: error.message });
        return res.status(500).json({ error: true, message: 'Failed to load focused blocker summary' });
    }
});

// Send command to agent (Human-in-the-Loop) or ask LLM directly when scan is complete
router.post('/:id/command', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const { command } = req.body;
        const user = req.user!;

        if (!command) {
            res.status(400).json({ error: true, message: 'Command is required' });
            return;
        }

        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;
        const result = await scanChatService.handleCommand(scan, command);
        res.json(result);

    } catch (error: any) {
        if (error instanceof ScanChatServiceError) {
            res.status(error.statusCode).json({
                error: true,
                message: error.message,
                details: error.details,
            });
            return;
        }

        logger.error('Command handling error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to process command' });
    }
});

// Stop a running scan
router.post('/:id/stop', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const result = await scanRuntimeService.stopScan(id, user.id, scan.status);
        res.json(result);

    } catch (error: any) {
        logger.error('Stop scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to stop scan' });
    }
});

// Pause a running scan
router.post('/:id/pause', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const result = await scanRuntimeService.pauseScan(id, user.id);

        // Auto-start activity monitor when scan is paused so it can detect user's manual testing
        if (!activityMonitor.getStatus().running) {
            activityMonitor.start().catch(() => {
                logger.warn('Failed to auto-start activity monitor on pause');
            });
        }

        res.json(result);

    } catch (error: any) {
        logger.error('Pause scan error', { error: error.message });
        const statusCode = error.message === 'No active scan to pause' ? 400 : 500;
        res.status(statusCode).json({ error: true, message: statusCode === 400 ? error.message : 'Failed to pause scan' });
    }
});

// Resume a paused scan
router.post('/:id/resume', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const result = await scanRuntimeService.resumeScan(id, user.id);
        res.json(result);

    } catch (error: any) {
        logger.error('Resume scan error', { error: error.message });
        const statusCode = error.message === 'No active scan to resume' ? 400 : 500;
        res.status(statusCode).json({ error: true, message: statusCode === 400 ? error.message : 'Failed to resume scan' });
    }
});

// Continue a completed scan with new instructions
router.post('/:id/continue', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const { instruction, iterations = 3, planningEnabled = true } = req.body;

        if (!instruction || !instruction.trim()) {
            res.status(400).json({ error: true, message: 'Instruction is required' });
            return;
        }

        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        // Check if there's already an active runtime
        if (scanRuntimeService.hasActiveRuntime(id)) {
            res.status(400).json({ error: true, message: 'Scan is already running. Use the command input instead.' });
            return;
        }

        // Only allow continuation for completed or stopped scans
        if (!['completed', 'stopped'].includes(scan.status)) {
            res.status(400).json({ error: true, message: `Cannot continue a scan with status "${scan.status}". Only completed or stopped scans can be continued.` });
            return;
        }

        const result = await scanRuntimeService.continueCompletedScan(scan as any, {
            instruction,
            iterations: Math.min(Math.max(Number(iterations), 1), 20),
            planningEnabled: !!planningEnabled,
        });

        res.json(result);

    } catch (error: any) {
        logger.error('Continue scan error', { error: error.message });
        const statusCode = /Burp Suite is not connected/i.test(error.message) ? 400 : 500;
        res.status(statusCode).json({ error: true, message: statusCode === 400 ? error.message : 'Failed to continue scan' });
    }
});

// Send a request to Burp tools (Repeater / Intruder / Active Scan)
router.post('/burp/send', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { rawRequest, vulnName, target, url } = req.body;
        const result = await burpDispatchService.dispatch({
            rawRequest,
            vulnName,
            target: typeof target === 'string' ? target : undefined,
            url: typeof url === 'string' ? url : undefined,
        });
        res.json({ success: true, message: result.message });
    } catch (error: any) {
        logger.error('Send to Burp error', { error: error.message });
        const message = error.message || 'Failed to send to Burp';
        const statusCode = /rawRequest is required|Could not normalize/i.test(message)
            ? 400
            : /Burp Suite is not connected/i.test(message)
                ? 503
                : 500;
        res.status(statusCode).json({ error: true, message });
    }
});

// Get chat history for a scan (persistent across restarts)
router.get('/:id/chat', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;
        const messages = getChatMessages(id);
        res.json({ messages });
    } catch (error: any) {
        logger.error('Chat history error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get chat history' });
    }
});

// Get live status for a scan (real-time polling endpoint)
router.get('/:id/live', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const since = parseInt(req.query.since as string) || 0;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const liveStatus = scanRuntimeService.getLiveStatus(id, scan as any, since);
        if (scan.scan_mode === 'scoped' && (!liveStatus.liveRuntimeSummary || !liveStatus.scopedRuntime)) {
            const focusedTestCases = listFocusedTestCasesWithExecutionSummary(id);
            const focusedVisibilityPayload = buildFocusedVisibilityPayload(id, focusedTestCases);
            const scopedRuntimeSummary = buildMissionControlLiveRuntimePayload({
                scanId: id,
                status: scan.status,
                focusedTestObjective: getFocusedTestObjective(id),
                scopeEnvelope: getScopeEnvelope(id),
                scopedTestRequest: getScopedTestRequest(id),
                focusedTestCases: focusedVisibilityPayload.focusedTestCases,
                focusedFindingThreads: focusedVisibilityPayload.focusedFindingThreads,
                standardFindingCount: getVulnerabilitiesByScan(id).length,
            });
            liveStatus.liveRuntimeSummary = liveStatus.liveRuntimeSummary || scopedRuntimeSummary;
            liveStatus.scopedRuntime = liveStatus.scopedRuntime || scopedRuntimeSummary;
            if (scan.status === 'scoped_executed') {
                liveStatus.scanCompleted = true;
                if (liveStatus.burpConnected === false) {
                    liveStatus.burpConnected = null;
                }
            }
        }

        res.json(liveStatus);
    } catch (error: any) {
        logger.error('Live status error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get live status' });
    }
});

// Show browser (headless → visible) for an active scan's browser session
router.post('/:id/browser/show', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        if (!getOwnedScanOrRespond(id, user.id, res)) return;
        res.json(await scanRuntimeService.showScanBrowser(id));
    } catch (error: any) {
        logger.error('Show browser for scan failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message });
    }
});

// Hide browser (visible → headless) for an active scan's browser session
router.post('/:id/browser/hide', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        if (!getOwnedScanOrRespond(id, user.id, res)) return;
        res.json(await scanRuntimeService.hideScanBrowser(id));
    } catch (error: any) {
        logger.error('Hide browser for scan failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message });
    }
});

export default router;
