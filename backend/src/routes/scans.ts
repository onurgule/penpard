
import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import {
    db,
    createScan,
    getScan,
    updateScanStatus,
    setScanInitialRequest,
    deleteScans,
    getVulnerabilitiesByScan,
    getUserWhitelists,
    saveChatMessage,
    getChatMessages,
    saveScanConfig,
} from '../db/init';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger, logApiUsage } from '../utils/logger';
import { BurpMCPClient } from '../services/burp-mcp';
import { MobSFService } from '../services/mobsf';
import { llmProvider } from '../services/LLMProviderService';
import { activityMonitor } from '../services/ActivityMonitorService';
import { takePendingRequest } from './penpard';
import { selectLocalDirectory, extractZipArchive, cloneGitRepository } from '../utils/source-fetcher';
import { extractRoutes } from '../services/source-analysis/utils/route-extractor';
import { defaultAuthStartupConfig, redactAuthStartupConfig, resolveAuthStartupConfig, toLegacyIdorUsers } from '../services/web-auth-startup-config';
import { scanRuntimeService } from '../services/runtime/ScanRuntimeService';
import os from 'os';

const router = Router();

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
            const aiEndpoints = await extractRoutesWithAI(finalSourcePath, existingEndpoints);

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
        let {
            url,
            rateLimit,
            useNuclei,
            useFfuf,
            idorUsers,
            parallelAgents,
            scanInstructions,
            sessionCookies,
            iterations,
            maxPlanRounds: reqMaxPlanRounds,
            sourcePackagePath,
            sourceAnalysisMode,
            sourceType,
            sourceGitUrl,
            sourceGitToken,
            authStartupMode,
            authCredentials,
            allowAccountCreation,
            preferSharedPassword,
        } = req.body;
        const user = req.user!;

        if (typeof idorUsers === 'string') {
            try { idorUsers = JSON.parse(idorUsers); } catch { idorUsers = []; }
        }
        useNuclei = useNuclei === 'true' || useNuclei === true;
        useFfuf = useFfuf === 'true' || useFfuf === true;

        // Nuclei and FFUF integrations are not yet implemented — warn if requested
        if (useNuclei) {
            logger.warn('nucleiEnabled was requested but Nuclei integration is not yet implemented — ignoring', { scanId: 'pre-creation' });
            useNuclei = false;
        }
        if (useFfuf) {
            logger.warn('ffufEnabled was requested but FFUF integration is not yet implemented — ignoring', { scanId: 'pre-creation' });
            useFfuf = false;
        }

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

        // Validate source analysis mode if provided
        const validModes = ['version_aware', 'full_source_aware'];
        const resolvedSourceMode = sourceAnalysisMode && validModes.includes(sourceAnalysisMode) ? sourceAnalysisMode : undefined;

        // Create scan record
        const scanId = uuidv4();
        
        let finalSourcePath: string | undefined = undefined;
        try {
            if (sourceType === 'zip' && req.file) {
                const destDir = path.join(uploadsDir, 'source-zips', scanId);
                logger.info(`Extracting ZIP source to ${destDir}`);
                finalSourcePath = await extractZipArchive(req.file.path, destDir);
                try { fs.unlinkSync(req.file.path); } catch { }
            } else if (sourceType === 'git' && sourceGitUrl) {
                const destDir = path.join(uploadsDir, 'source-repos', scanId);
                logger.info(`Cloning Git source to ${destDir}`);
                finalSourcePath = await cloneGitRepository(sourceGitUrl, sourceGitToken, destDir);
            } else if ((!sourceType || sourceType === 'local') && sourcePackagePath) {
                finalSourcePath = String(sourcePackagePath).trim();
            }
        } catch (sourceErr: any) {
            logger.warn(`Failed to process source code input: ${sourceErr.message}`);
            res.status(400).json({ error: true, message: `Source code processing failed: ${sourceErr.message}` });
            return;
        }

        createScan({
            id: scanId,
            userId: user.id,
            type: 'web',
            target: targetUrl,
            sourcePackagePath: finalSourcePath,
            sourceAnalysisMode: resolvedSourceMode,
        });

        logApiUsage('/api/scans/web', user.id, { target: targetUrl });

        const maxIterations = Number(iterations) || 50;
        const maxPlanRounds = reqMaxPlanRounds === undefined || reqMaxPlanRounds === null || reqMaxPlanRounds === ''
            ? 0
            : Math.max(0, Math.min(99, Number(reqMaxPlanRounds)));
        const authStartup = resolveAuthStartupConfig({
            authStartupMode,
            authCredentials,
            allowAccountCreation,
            preferSharedPassword,
            idorUsers,
        });
        const legacyIdorUsers = authStartup.credentials.length > 0
            ? toLegacyIdorUsers(authStartup)
            : (Array.isArray(idorUsers) ? idorUsers : []);
        const scanConfig = {
            userId: user.id,
            rateLimit: Number(rateLimit) || 5,
            useNuclei: !!useNuclei,
            useFfuf: !!useFfuf,
            idorUsers: legacyIdorUsers,
            parallelAgents: Number(parallelAgents) || 1,
            maxIterations,
            maxPlanRounds,
            customSystemPrompt: scanInstructions || undefined,
            sessionCookies: typeof sessionCookies === 'string' ? sessionCookies.trim() || undefined : undefined,
            sourcePackagePath: finalSourcePath,
            sourceAnalysisMode: resolvedSourceMode,
            authStartup,
        };
        saveScanConfig(scanId, JSON.stringify({
            ...scanConfig,
            idorUsers: legacyIdorUsers.map((entry: any) => ({
                ...entry,
                password: entry?.password ? '[REDACTED]' : undefined,
            })),
            authStartup: redactAuthStartupConfig(authStartup),
        }));

        // Start scan asynchronously
        startWebScan(scanId, targetUrl, scanConfig).catch(err => {
            logger.error('Web scan failed', { scanId, error: err.message });
            updateScanStatus(scanId, 'failed', err.message);
        });

        res.json({
            scanId,
            message: 'Antigravity Scan initiated',
        });
    } catch (error: any) {
        logger.error('Web scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to start scan' });
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

        // Start scan asynchronously
        startMobileScan(scanId, file.path).catch(err => {
            logger.error('Mobile scan failed', { scanId, error: err.message });
            updateScanStatus(scanId, 'failed', err.message);
        });

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
        let {
            pendingId,
            scanInstructions,
            iterations,
            rateLimit: reqRateLimit,
            parallelAgents: reqParallelAgents,
            maxPlanRounds: reqMaxPlanRounds,
            sourceType, sourcePackagePath, sourceAnalysisMode, sourceGitUrl, sourceGitToken
        } = req.body;
        const user = req.user!;
        if (!pendingId) {
            return res.status(400).json({ error: true, message: 'pendingId is required' });
        }
        const entry = takePendingRequest(pendingId);
        if (!entry) {
            return res.status(404).json({ error: true, message: 'Pending request not found or already used' });
        }
        let targetUrl: string;
        try {
            targetUrl = new URL(entry.url.startsWith('http') ? entry.url : `https://${entry.url}`).toString();
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
        const validModes = ['version_aware', 'full_source_aware'];
        const resolvedSourceMode = sourceAnalysisMode && validModes.includes(sourceAnalysisMode) ? sourceAnalysisMode : undefined;

        const scanId = uuidv4();
        
        let finalSourcePath: string | undefined = undefined;
        try {
            if (sourceType === 'zip' && req.file) {
                const destDir = path.join(uploadsDir, 'source-zips', scanId);
                logger.info(`Extracting ZIP source to ${destDir}`);
                finalSourcePath = await extractZipArchive(req.file.path, destDir);
                try { fs.unlinkSync(req.file.path); } catch { }
            } else if (sourceType === 'git' && sourceGitUrl) {
                const destDir = path.join(uploadsDir, 'source-repos', scanId);
                logger.info(`Cloning Git source to ${destDir}`);
                finalSourcePath = await cloneGitRepository(sourceGitUrl, sourceGitToken, destDir);
            } else if ((!sourceType || sourceType === 'local') && sourcePackagePath) {
                finalSourcePath = String(sourcePackagePath).trim();
            }
        } catch (sourceErr: any) {
            logger.warn(`Failed to process source code input: ${sourceErr.message}`);
            return res.status(400).json({ error: true, message: `Source code processing failed: ${sourceErr.message}` });
        }

        createScan({
            id: scanId,
            userId: user.id,
            type: 'web',
            target: targetUrl,
            sourcePackagePath: finalSourcePath,
            sourceAnalysisMode: resolvedSourceMode,
        });
        setScanInitialRequest(scanId, entry.rawRequest);
        logApiUsage('/api/scans/from-burp', user.id, { target: targetUrl });
        const rateLimit = Number(reqRateLimit) || 5;
        const parallelAgents = Math.max(1, Math.min(10, Number(reqParallelAgents) || 1));
        const maxIterations = Number(iterations) || 50;
        const maxPlanRounds = reqMaxPlanRounds === undefined || reqMaxPlanRounds === null || reqMaxPlanRounds === ''
            ? 0
            : Math.max(0, Math.min(99, Number(reqMaxPlanRounds)));
        const authStartup = defaultAuthStartupConfig();
        const scanConfig = {
            userId: user.id,
            rateLimit,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [] as any[],
            parallelAgents,
            maxIterations,
            maxPlanRounds,
            customSystemPrompt: scanInstructions || undefined,
            sessionCookies: undefined as string | undefined,
            initialRequest: entry.rawRequest,
            sourcePackagePath: finalSourcePath,
            sourceAnalysisMode: resolvedSourceMode,
            authStartup,
        };
        saveScanConfig(scanId, JSON.stringify({
            ...scanConfig,
            authStartup: redactAuthStartupConfig(authStartup),
        }));
        startWebScan(scanId, targetUrl, scanConfig).catch(err => {
            logger.error('From-Burp scan failed', { scanId, error: err.message });
            updateScanStatus(scanId, 'failed', err.message);
        });
        return res.json({
            scanId,
            message: 'Scan started from Burp request',
        });
    } catch (error: any) {
        logger.error('From-burp scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to start scan' });
    }
});

// Get scan status
router.get('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const scan = getOwnedScanOrRespond(id, user.id, res);
        if (!scan) return;

        const vulnerabilities = getVulnerabilitiesByScan(id);
        const endpointInventory = scanRuntimeService.getEndpointInventory(id);

        res.json({
            id: scan.id,
            type: scan.type,
            target: scan.target,
            status: scan.status,
            createdAt: scan.created_at,
            completedAt: scan.completed_at,
            message: scan.error_message,
            sourcePackagePath: scan.source_package_path || null,
            sourceAnalysisMode: scan.source_analysis_mode || null,
            endpointInventory,
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
        const agent = scanRuntimeService.getActiveAgent(id);

        // Persist user command to DB
        saveChatMessage(id, 'human', command);

        if (agent) {
            // Agent is active - send command to it
            await agent.handleUserCommand(command);
            res.json({ message: 'Command sent to agent' });
        } else {
            // No active agent - use LLM directly with scan context
            // Get vulnerabilities for context
            const vulnerabilities = getVulnerabilitiesByScan(id);

            // Build context for LLM
            const vulnContext = vulnerabilities.length > 0
                ? vulnerabilities.map(v => `- [${v.severity?.toUpperCase()}] ${v.name}: ${v.description}`).join('\n')
                : 'No vulnerabilities found.';

            const systemPrompt = `You are PenPard, an AI security assistant. You have completed a security scan and are now answering follow-up questions.

IMPORTANT: Detect the language of the user's question and ALWAYS respond in the SAME language. If the user writes in Turkish, respond in Turkish. If in English, respond in English.

SCAN DETAILS:
- Target: ${scan.target}
- Type: ${scan.type}
- Status: ${scan.status}
- Created: ${scan.created_at}
- Completed: ${scan.completed_at || 'Not completed'}

FINDINGS (${vulnerabilities.length} total):
${vulnContext}

Answer the user's question based on this scan data. Be helpful, specific, and security-focused. Remember to respond in the user's language.`;

            try {
                const response = await llmProvider.generate({
                    systemPrompt,
                    userPrompt: command
                });

                // Persist assistant response to DB
                saveChatMessage(id, 'assistant', response.text);

                res.json({
                    message: 'Response from LLM',
                    response: response.text,
                    scanStatus: scan.status,
                    isLive: false
                });
            } catch (llmError: any) {
                logger.error('LLM query failed', { scanId: id, error: llmError.message });
                res.status(500).json({
                    error: true,
                    message: 'LLM query failed. Please check your LLM configuration.',
                    details: llmError.message
                });
            }
        }

    } catch (error: any) {
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
        const { rawRequest, vulnName, target } = req.body;
        const validTargets = ['repeater', 'intruder', 'scanner'];
        const sendTarget = validTargets.includes(target) ? target : 'repeater';

        if (!rawRequest && sendTarget !== 'scanner') {
            res.status(400).json({ error: true, message: 'rawRequest is required' });
            return;
        }

        const burp = new BurpMCPClient();
        const available = await burp.isAvailable();
        if (!available) {
            res.status(503).json({ error: true, message: 'Burp Suite is not connected' });
            return;
        }

        // Parse host, port, https from the raw request
        let host = '';
        let port = 443;
        let useHttps = true;
        let finalRequest = rawRequest || '';
        let fullUrl = ''; // Used for active scan

        const lines = finalRequest.split(/\r?\n/);
        const requestLine = lines[0] || '';

        // Check if request line has full URL: "GET https://example.com/path HTTP/1.1"
        const fullUrlMatch = requestLine.match(/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(https?:\/\/[^\s]+)/i);
        if (fullUrlMatch) {
            try {
                const url = new URL(fullUrlMatch[2]);
                host = url.hostname;
                port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                useHttps = url.protocol === 'https:';
                fullUrl = fullUrlMatch[2];
                // Rewrite request line to path only
                finalRequest = finalRequest.replace(fullUrlMatch[2], url.pathname + url.search);
            } catch { /* fallback to Host header */ }
        }

        // Fallback: extract from Host header
        if (!host) {
            const hostLine = lines.find((l: string) => l.toLowerCase().startsWith('host:'));
            if (hostLine) {
                const hostValue = hostLine.replace(/^host:\s*/i, '').trim();
                const parts = hostValue.split(':');
                host = parts[0];
                port = parts[1] ? parseInt(parts[1]) : 443;
                useHttps = port === 443 || port === 8443;
            }
        }

        if (!host) {
            res.status(400).json({ error: true, message: 'Could not determine host from request. Ensure Host header or full URL is present.' });
            return;
        }

        // Build full URL if not already present (needed for scanner)
        if (!fullUrl) {
            const pathMatch = requestLine.match(/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
            const urlPath = pathMatch ? pathMatch[2] : '/';
            fullUrl = `${useHttps ? 'https' : 'http'}://${host}${port !== (useHttps ? 443 : 80) ? ':' + port : ''}${urlPath}`;
        }

        // Ensure Host header is present in the request
        const hasHostHeader = finalRequest.split(/\r?\n/).some((l: string) => l.toLowerCase().startsWith('host:'));
        if (!hasHostHeader) {
            const hostValue = port === (useHttps ? 443 : 80) ? host : `${host}:${port}`;
            const firstNewline = finalRequest.indexOf('\n');
            if (firstNewline !== -1) {
                finalRequest = finalRequest.substring(0, firstNewline + 1) + `Host: ${hostValue}\n` + finalRequest.substring(firstNewline + 1);
            } else {
                finalRequest += `\nHost: ${hostValue}\n\n`;
            }
        }

        // Normalize line endings to \r\n for Burp
        const normalized = finalRequest.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');

        const targetLabels: Record<string, string> = { repeater: 'Repeater', intruder: 'Intruder', scanner: 'Active Scan' };

        if (sendTarget === 'repeater') {
            await burp.callTool('send_to_repeater', {
                host, port, useHttps,
                request: normalized,
                name: vulnName || 'PenPard Finding'
            });
        } else if (sendTarget === 'intruder') {
            await burp.callTool('send_to_intruder', {
                host, port, useHttps,
                request: normalized
            });
        } else if (sendTarget === 'scanner') {
            await burp.callTool('send_to_scanner', {
                host, port, useHttps,
                request: normalized,
                url: fullUrl
            });
        }

        res.json({ success: true, message: `Sent to Burp ${targetLabels[sendTarget]}: ${host}` });
    } catch (error: any) {
        logger.error('Send to Burp error', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to send to Burp' });
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

        res.json(scanRuntimeService.getLiveStatus(id, scan as any, since));
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

// Async scan functions

async function startWebScan(scanId: string, targetUrl: string, config: any = {}): Promise<void> {
    await scanRuntimeService.startWebScan(scanId, targetUrl, config);
}

async function startMobileScan(scanId: string, apkPath: string): Promise<void> {
    logger.info('Starting mobile scan', { scanId, apkPath });

    updateScanStatus(scanId, 'analyzing');

    try {
        const mobsf = new MobSFService();

        // Check if MobSF is available
        const mobsfAvailable = await mobsf.isAvailable();

        if (mobsfAvailable) {
            await mobsf.analyze(scanId, apkPath);
        } else {
            // MobSF is required for mobile scanning — fail loudly instead of simulating
            const errorMsg = 'MobSF is not connected. Cannot start mobile scan without MobSF. Please ensure MobSF is running and configured in Settings.';
            logger.error(errorMsg, { scanId });
            updateScanStatus(scanId, 'failed', errorMsg);
            return;
        }

        updateScanStatus(scanId, 'completed');
        logger.info('Mobile scan completed', { scanId });
    } catch (error: any) {
        logger.error('Mobile scan error', { scanId, error: error.message });
        updateScanStatus(scanId, 'failed', error.message);
        throw error;
    }
}

export default router;

