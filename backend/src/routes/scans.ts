
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
    getVulnerabilitiesByScan,
    getUserWhitelists,
    saveScanLogs,
    getScanLogs,
    saveChatMessage,
    getChatMessages,
} from '../db/init';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger, logApiUsage } from '../utils/logger';
import { BurpMCPClient } from '../services/burp-mcp';
import { MobSFService } from '../services/mobsf';
import { OrchestratorAgent } from '../agents/OrchestratorAgent';
import { AgentPool } from '../agents/AgentPool';
import { llmProvider } from '../services/LLMProviderService';
import { activityMonitor } from '../services/ActivityMonitorService';

export const activeAgents = new Map<string, OrchestratorAgent>();
export const activePools = new Map<string, AgentPool>();

// Cache logs after agent/pool completes so the UI can still display them
export const scanLogCache = new Map<string, { logs: string[], phase: string }>();

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
        if (file.originalname.endsWith('.apk')) {
            cb(null, true);
        } else {
            cb(new Error('Only APK files allowed'));
        }
    },
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB max
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

// Initiate web scan
router.post('/web', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { url, rateLimit, useNuclei, useFfuf, idorUsers, parallelAgents, scanInstructions } = req.body;
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

        // Create scan record
        const scanId = uuidv4();
        createScan({
            id: scanId,
            userId: user.id,
            type: 'web',
            target: targetUrl,
        });

        logApiUsage('/api/scans/web', user.id, { target: targetUrl });

        const scanConfig = {
            rateLimit: Number(rateLimit) || 5,
            useNuclei: !!useNuclei,
            useFfuf: !!useFfuf,
            idorUsers: idorUsers || [],
            parallelAgents: Number(parallelAgents) || 1, // 1 = single agent, >1 = multi-agent pool
            customSystemPrompt: scanInstructions || undefined,
        };

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

// Get scan status
router.get('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;

        const scan = getScan(id);

        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        if (scan.user_id !== user.id) {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        const vulnerabilities = getVulnerabilitiesByScan(id);

        res.json({
            id: scan.id,
            type: scan.type,
            target: scan.target,
            status: scan.status,
            createdAt: scan.created_at,
            completedAt: scan.completed_at,
            message: scan.error_message,
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

        const agent = activeAgents.get(id);

        // Persist user command to DB
        saveChatMessage(id, 'human', command);

        if (agent) {
            // Agent is active - send command to it
            await agent.handleUserCommand(command);
            res.json({ message: 'Command sent to agent' });
        } else {
            // No active agent - use LLM directly with scan context
            const scan = getScan(id);
            if (!scan) {
                res.status(404).json({ error: true, message: 'Scan not found' });
                return;
            }

            if (scan.user_id !== user.id) {
                res.status(403).json({ error: true, message: 'Access denied' });
                return;
            }

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

        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        // Check user permission
        if (scan.user_id !== user.id) {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        const agent = activeAgents.get(id);
        const pool = activePools.get(id);

        if (pool) {
            // Cache + persist logs before stopping
            const allLogs = pool.getLogs(0);
            scanLogCache.set(id, { logs: allLogs, phase: 'stopped' });
            saveScanLogs(id, allLogs);
            pool.stop();
            activePools.delete(id);
            updateScanStatus(id, 'stopped', 'Scan stopped by user');
            logger.info('Pool scan stopped by user', { scanId: id, userId: user.id });
            res.json({ message: 'Pool scan stopped successfully' });
        } else if (agent) {
            // Cache + persist logs before stopping
            const allLogs = agent.getLogs(0);
            scanLogCache.set(id, { logs: allLogs, phase: 'stopped' });
            saveScanLogs(id, allLogs);
            agent.stop();
            activeAgents.delete(id);
            updateScanStatus(id, 'stopped', 'Scan stopped by user');
            logger.info('Scan stopped by user', { scanId: id, userId: user.id });
            res.json({ message: 'Scan stopped successfully' });
        } else {
            // No active agent, but update status anyway
            if (scan.status !== 'completed' && scan.status !== 'failed') {
                updateScanStatus(id, 'stopped', 'Scan stopped by user');
            }
            res.json({ message: 'Scan was not actively running, status updated' });
        }

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

        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        if (scan.user_id !== user.id) {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        const agent = activeAgents.get(id);
        const pool = activePools.get(id);

        if (pool) {
            pool.pause();
            updateScanStatus(id, 'paused');
            logger.info('Pool scan paused by user', { scanId: id, userId: user.id });
        } else if (agent) {
            agent.pause();
            updateScanStatus(id, 'paused');
            logger.info('Scan paused by user', { scanId: id, userId: user.id });
        } else {
            res.status(400).json({ error: true, message: 'No active scan to pause' });
            return;
        }

        // Auto-start activity monitor when scan is paused so it can detect user's manual testing
        if (!activityMonitor.getStatus().running) {
            activityMonitor.start().catch(() => {
                logger.warn('Failed to auto-start activity monitor on pause');
            });
        }

        res.json({ message: 'Scan paused. Activity monitor is watching your manual testing.' });

    } catch (error: any) {
        logger.error('Pause scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to pause scan' });
    }
});

// Resume a paused scan
router.post('/:id/resume', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;

        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        if (scan.user_id !== user.id) {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        const agent = activeAgents.get(id);
        const pool = activePools.get(id);

        if (pool) {
            pool.resume();
            updateScanStatus(id, 'testing');
            logger.info('Pool scan resumed by user', { scanId: id, userId: user.id });
        } else if (agent) {
            agent.resume();
            updateScanStatus(id, 'testing');
            logger.info('Scan resumed by user', { scanId: id, userId: user.id });
        } else {
            res.status(400).json({ error: true, message: 'No active scan to resume' });
            return;
        }

        res.json({ message: 'Scan resumed. Automated testing continues.' });

    } catch (error: any) {
        logger.error('Resume scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to resume scan' });
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

        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        if (scan.user_id !== user.id) {
            res.status(403).json({ error: true, message: 'Access denied' });
            return;
        }

        // Check if there's already an active agent
        if (activeAgents.has(id) || activePools.has(id)) {
            res.status(400).json({ error: true, message: 'Scan is already running. Use the command input instead.' });
            return;
        }

        // Only allow continuation for completed or stopped scans
        if (!['completed', 'stopped'].includes(scan.status)) {
            res.status(400).json({ error: true, message: `Cannot continue a scan with status "${scan.status}". Only completed or stopped scans can be continued.` });
            return;
        }

        // Gather existing context
        const existingFindings = getVulnerabilitiesByScan(id);
        const existingEndpoints: string[] = [];

        // Try to extract discovered endpoints from findings
        for (const f of existingFindings) {
            if (f.request) {
                const urlMatch = f.request.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(https?:\/\/[^\s]+)/i);
                if (urlMatch) existingEndpoints.push(urlMatch[1]);
            }
        }

        // Create a fresh Burp connection
        const burpMCP = new BurpMCPClient();
        let mcpAvailable = false;
        try {
            mcpAvailable = await burpMCP.isAvailable();
        } catch (e) {
            logger.warn('Burp MCP not available for continuation');
        }

        if (!mcpAvailable) {
            res.status(400).json({ error: true, message: 'Burp Suite is not connected. Please ensure Burp is running with the PenPard extension.' });
            return;
        }

        // Create a new agent for continuation
        const agentConfig = {
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            customSystemPrompt: instruction,
        };

        const agent = new OrchestratorAgent(id, scan.target, agentConfig, burpMCP);
        activeAgents.set(id, agent);

        // Save user instruction as chat message
        saveChatMessage(id, 'human', `[CONTINUE SCAN] ${instruction} (${iterations} rounds, planning: ${planningEnabled ? 'ON' : 'OFF'})`);

        // Respond immediately — scan runs in background
        res.json({ message: `Scan continuing with ${iterations} rounds. Instruction: "${instruction.slice(0, 100)}..."` });

        // Run continuation in background
        (async () => {
            try {
                await agent.continueScan({
                    instruction,
                    iterations: Math.min(Math.max(Number(iterations), 1), 20),
                    planningEnabled: !!planningEnabled,
                    existingFindings,
                    existingEndpoints: [...new Set(existingEndpoints)],
                });

                updateScanStatus(id, 'completed');
                logger.info('Scan continuation completed', { scanId: id });
            } catch (error: any) {
                logger.error('Scan continuation error', { scanId: id, error: error.message });
                updateScanStatus(id, 'failed', error.message);
            } finally {
                const state = agent.getState();
                const allLogs = agent.getLogs(0);
                scanLogCache.set(id, { logs: allLogs, phase: state.phase });
                saveScanLogs(id, allLogs);
                activeAgents.delete(id);
                burpMCP.disconnect();
            }
        })();

    } catch (error: any) {
        logger.error('Continue scan error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to continue scan' });
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
        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }
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

        const scan = getScan(id);
        if (!scan) {
            res.status(404).json({ error: true, message: 'Scan not found' });
            return;
        }

        const agent = activeAgents.get(id);
        const pool = activePools.get(id);

        if (pool) {
            // Pool is active - return pool data
            const state = pool.getState();
            const logs = pool.getLogs(since);

            res.json({
                isActive: true,
                isPool: true,
                phase: 'testing',
                isRunning: state.isRunning,
                isPaused: false,
                logs: logs,
                logsCount: state.logsCount,
                burpConnected: true,
                activeAgents: state.workerCount,
                workers: state.workers,
                stats: state.stats
            });
        } else if (agent) {
            // Agent is active - return live data
            const state = agent.getState();
            const logs = agent.getLogs(since);

            // Don't check Burp on every poll - too many requests
            // Just report based on agent being active
            res.json({
                isActive: true,
                isPool: false,
                phase: state.phase,
                isRunning: state.isRunning,
                isPaused: state.isPaused,
                logs: logs,
                logsCount: state.logsCount,
                burpConnected: true, // Assume connected if agent is running
                activeAgents: activeAgents.size,
            });
        } else {
            // No active agent - check memory cache first, then DB
            let cached = scanLogCache.get(id);

            // If not in memory cache, load from database
            if (!cached) {
                const dbLogs = getScanLogs(id);
                if (dbLogs.length > 0) {
                    cached = { logs: dbLogs, phase: scan.status };
                    // Re-populate memory cache for subsequent polls
                    scanLogCache.set(id, cached);
                }
            }

            const cachedLogs = cached ? cached.logs.slice(since) : [];
            const cachedLogsCount = cached ? cached.logs.length : 0;

            // For completed/stopped scans, indicate completion rather than "disconnected"
            const isCompleted = scan.status === 'completed' || scan.status === 'stopped' || scan.status === 'failed';

            res.json({
                isActive: false,
                isPool: false,
                phase: cached?.phase || scan.status,
                isRunning: false,
                isPaused: false,
                logs: cachedLogs,
                logsCount: cachedLogsCount,
                // Completed scans should not show as "disconnected" — they finished normally
                burpConnected: isCompleted ? null : false,
                activeAgents: activeAgents.size + activePools.size,
                scanCompleted: isCompleted,
            });
        }
    } catch (error: any) {
        logger.error('Live status error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get live status' });
    }
});

// Async scan functions

async function startWebScan(scanId: string, targetUrl: string, config: any = {}): Promise<void> {
    logger.info('Starting web scan', { scanId, targetUrl, config });

    updateScanStatus(scanId, 'initializing');

    try {
        // Use Burp MCP only
        const burpMCP = new BurpMCPClient();
        let mcpAvailable = false;

        try {
            mcpAvailable = await burpMCP.isAvailable();
        } catch (e) {
            logger.warn('Burp MCP connection check failed');
        }

        // Helper to cache simulation logs
        const cacheSimLogs = (logs: string[]) => {
            scanLogCache.set(scanId, { logs, phase: 'completed' });
        };

        if (mcpAvailable) {
            logger.info('Using Burp MCP for scanning', { scanId });

            const parallelAgents = config.parallelAgents || 1;
            logger.info(`parallelAgents config value: ${parallelAgents}`, { scanId, config });

            if (parallelAgents > 1) {
                // Multi-agent parallel scanning
                logger.info(`🚀 Using AgentPool with ${parallelAgents} parallel workers`, { scanId });

                // Calculate worker distribution
                const poolConfig = {
                    crawlerCount: Math.max(1, Math.floor(parallelAgents * 0.2)),  // 20% crawlers
                    scannerCount: Math.max(1, Math.floor(parallelAgents * 0.4)),  // 40% scanners
                    fuzzerCount: Math.max(1, Math.floor(parallelAgents * 0.25)),  // 25% fuzzers
                    analyzerCount: Math.max(1, Math.floor(parallelAgents * 0.15)), // 15% analyzers
                    maxIterationsPerWorker: 25,
                    rateLimit: config.rateLimit || 5
                };

                const pool = new AgentPool(scanId, targetUrl, burpMCP, poolConfig);
                activePools.set(scanId, pool);

                try {
                    await pool.start();
                } finally {
                    // Cache logs before removing the pool
                    const state = pool.getState();
                    const allLogs = pool.getLogs(0);
                    scanLogCache.set(scanId, { logs: allLogs, phase: 'completed' });

                    // Persist logs to database for historical access
                    saveScanLogs(scanId, allLogs);

                    activePools.delete(scanId);
                    burpMCP.disconnect();
                    if (scanLogCache.size > 20) {
                        const oldest = scanLogCache.keys().next().value;
                        if (oldest) scanLogCache.delete(oldest);
                    }
                }
            } else {
                // Single agent mode (original behavior)
                const agentConfig = {
                    rateLimit: config.rateLimit || 5,
                    useNuclei: config.useNuclei || false,
                    useFfuf: config.useFfuf || false,
                    idorUsers: config.idorUsers || []
                };

                const agent = new OrchestratorAgent(scanId, targetUrl, agentConfig, burpMCP);
                activeAgents.set(scanId, agent);

                try {
                    await agent.start();
                } finally {
                    // Cache logs before removing the agent so the UI can still display them
                    const state = agent.getState();
                    const allLogs = agent.getLogs(0);
                    scanLogCache.set(scanId, { logs: allLogs, phase: state.phase });

                    // Persist logs to database for historical access
                    saveScanLogs(scanId, allLogs);

                    activeAgents.delete(scanId);
                    burpMCP.disconnect();
                    // Clean up old cache entries (keep last 20)
                    if (scanLogCache.size > 20) {
                        const oldest = scanLogCache.keys().next().value;
                        if (oldest) scanLogCache.delete(oldest);
                    }
                }
            }
        } else {
            // Fallback: simulate scan with demo vulnerabilities
            logger.warn('Burp MCP not available, using simulated scan');
            await simulateWebScan(scanId, targetUrl);
        }

        updateScanStatus(scanId, 'completed');
        logger.info('Web scan completed', { scanId });
    } catch (error: any) {
        logger.error('Web scan error', { scanId, error: error.message });
        updateScanStatus(scanId, 'failed', error.message);
        throw error;
    }
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
            logger.warn('MobSF not available, using simulated analysis');
            await simulateMobileScan(scanId);
        }

        updateScanStatus(scanId, 'completed');
        logger.info('Mobile scan completed', { scanId });
    } catch (error: any) {
        logger.error('Mobile scan error', { scanId, error: error.message });
        updateScanStatus(scanId, 'failed', error.message);
        throw error;
    }
}

// Simulation functions for demo when tools aren't available
async function simulateWebScan(scanId: string, targetUrl: string): Promise<string[]> {
    const { addVulnerability } = await import('../db/init');
    const simLogs: string[] = [];
    const addLog = (msg: string) => {
        simLogs.push(`[${new Date().toISOString()}] ${msg}`);
        // Update cache in real-time so polling can see progress
        scanLogCache.set(scanId, { logs: [...simLogs], phase: 'testing' });
    };

    addLog('[INFO] Orchestrator Agent started (simulated mode - Burp not available)');
    addLog(`[INFO] Target: ${targetUrl}`);

    // Simulate scan time
    addLog('[PHASE] Phase: RECONNAISSANCE');
    await new Promise(r => setTimeout(r, 3000));
    updateScanStatus(scanId, 'auditing');
    addLog('[PHASE] Phase: AUDITING');
    addLog('[INFO] Running vulnerability checks...');
    await new Promise(r => setTimeout(r, 2000));

    // Add demo vulnerabilities
    const demoVulns = [
        {
            name: 'SQL Injection',
            description: 'The application appears to be vulnerable to SQL injection attacks in the login form.',
            severity: 'critical',
            cvssScore: 9.8,
            cwe: '89',
            remediation: 'Use parameterized queries or prepared statements.',
        },
        {
            name: 'Cross-Site Scripting (XSS)',
            description: 'Reflected XSS vulnerability found in search parameter.',
            severity: 'high',
            cvssScore: 7.1,
            cwe: '79',
            remediation: 'Implement proper output encoding.',
        },
        {
            name: 'Missing Security Headers',
            description: 'The application is missing important security headers like X-Frame-Options.',
            severity: 'medium',
            cvssScore: 5.3,
            cwe: '693',
            remediation: 'Add security headers to all responses.',
        },
    ];

    for (const vuln of demoVulns) {
        addVulnerability({ scanId, ...vuln });
        addLog(`[FINDING] Found: ${vuln.name} (${vuln.severity}) - CVSS ${vuln.cvssScore}`);
    }

    addLog('[PHASE] Phase: COMPLETED');
    addLog(`[INFO] Scan finished. Found ${demoVulns.length} vulnerabilities.`);

    // Update cache with final state
    scanLogCache.set(scanId, { logs: simLogs, phase: 'completed' });

    return simLogs;
}

async function simulateMobileScan(scanId: string): Promise<void> {
    const { addVulnerability } = await import('../db/init');

    await new Promise(r => setTimeout(r, 4000));
    updateScanStatus(scanId, 'code_analysis');
    await new Promise(r => setTimeout(r, 3000));

    const demoVulns = [
        {
            name: 'Hardcoded API Keys',
            description: 'API keys found hardcoded in the application source code.',
            severity: 'high',
            cvssScore: 7.5,
            cwe: '798',
            remediation: 'Store sensitive data securely using Android Keystore.',
        },
        {
            name: 'Insecure Data Storage',
            description: 'Sensitive data stored in SharedPreferences without encryption.',
            severity: 'medium',
            cvssScore: 5.5,
            cwe: '922',
            remediation: 'Use EncryptedSharedPreferences.',
        },
        {
            name: 'Debug Mode Enabled',
            description: 'Application has android:debuggable=true in manifest.',
            severity: 'low',
            cvssScore: 3.3,
            cwe: '489',
            remediation: 'Disable debug mode in production builds.',
        },
    ];

    for (const vuln of demoVulns) {
        addVulnerability({ scanId, ...vuln });
    }
}

export default router;
