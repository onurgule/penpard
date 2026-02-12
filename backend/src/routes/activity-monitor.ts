/**
 * Activity Monitor Routes
 * 
 * Endpoints for controlling the activity monitor and retrieving suggestions.
 * The activity monitor watches user's Burp Proxy history and detects testing patterns.
 */

import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { activityMonitor } from '../services/ActivityMonitorService';
import { BurpMCPClient } from '../services/burp-mcp';
import { OrchestratorAgent } from '../agents/OrchestratorAgent';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { createScan, updateScanStatus, saveScanLogs, db } from '../db/init';
import { activeAgents, scanLogCache } from './scans';

const router = Router();

// GET /api/activity-monitor/status - Get monitor status
router.get('/status', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const status = activityMonitor.getStatus();
        res.json(status);
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// POST /api/activity-monitor/start - Start monitoring
router.post('/start', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const started = await activityMonitor.start();
        res.json({ 
            success: started, 
            message: started ? 'Activity monitor started' : 'Failed to start - Burp MCP not available' 
        });
    } catch (error: any) {
        logger.error('[ActivityMonitor Route] Start error', { error: error.message });
        res.status(500).json({ error: true, message: error.message });
    }
});

// POST /api/activity-monitor/stop - Stop monitoring
router.post('/stop', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        activityMonitor.stop();
        res.json({ success: true, message: 'Activity monitor stopped' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// GET /api/activity-monitor/suggestions - Get pending suggestions
router.get('/suggestions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const pending = activityMonitor.getPendingSuggestions();
        res.json({ suggestions: pending });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// GET /api/activity-monitor/suggestions/all - Get all suggestions (history)
router.get('/suggestions/all', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const all = activityMonitor.getAllSuggestions();
        res.json({ suggestions: all });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// POST /api/activity-monitor/suggestions/:id/accept - Accept suggestion & start automated testing
router.post('/suggestions/:id/accept', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        
        const suggestion = activityMonitor.acceptSuggestion(id);
        if (!suggestion) {
            res.status(404).json({ error: true, message: 'Suggestion not found' });
            return;
        }

        // Create a quick scan targeting the detected endpoints
        const scanId = uuidv4();
        const targetUrl = suggestion.endpoints[0]?.split(' ').pop() || suggestion.targetHosts[0] || 'unknown';

        createScan({
            id: scanId,
            userId: user.id,
            type: 'web',
            target: targetUrl,
        });

        logger.info('[ActivityMonitor] Starting assisted scan', {
            scanId,
            type: suggestion.type,
            endpoints: suggestion.endpoints.length
        });

        // Start automated testing in background
        startAssistedScan(scanId, suggestion, user.id).catch(err => {
            logger.error('[ActivityMonitor] Assisted scan failed', { scanId, error: err.message });
            updateScanStatus(scanId, 'failed', err.message);
        });

        res.json({ 
            success: true, 
            scanId,
            message: `PenPard ${suggestion.type.toUpperCase()} scan started. Testing detected endpoints...`
        });
    } catch (error: any) {
        logger.error('[ActivityMonitor Route] Accept error', { error: error.message });
        res.status(500).json({ error: true, message: error.message });
    }
});

// POST /api/activity-monitor/suggestions/:id/dismiss - Dismiss suggestion
router.post('/suggestions/:id/dismiss', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const suggestion = activityMonitor.dismissSuggestion(id);
        
        if (!suggestion) {
            res.status(404).json({ error: true, message: 'Suggestion not found' });
            return;
        }

        res.json({ success: true, message: 'Suggestion dismissed' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/**
 * Start an assisted scan based on the user's detected activity.
 * Uses a focused OrchestratorAgent that targets the specific vulnerability type.
 */
async function startAssistedScan(
    scanId: string, 
    suggestion: any, 
    userId: number
): Promise<void> {
    const burp = new BurpMCPClient();
    
    const available = await burp.isAvailable();
    if (!available) {
        throw new Error('Burp MCP not available');
    }

    updateScanStatus(scanId, 'scanning');

    // Build focused system prompt based on detected activity
    const focusPrompts: Record<string, string> = {
        sqli: `FOCUSED SQL INJECTION SCAN: The user was manually testing SQL injection on the following endpoints. 
Your job is to quickly and efficiently test these endpoints with comprehensive SQLi payloads:
- Time-based blind: ' AND SLEEP(5)--, ' WAITFOR DELAY '0:0:5'--
- Boolean-based: ' AND '1'='1 vs ' AND '1'='2  
- Error-based: ' AND 1=CONVERT(int,@@version)--
- UNION-based: ' UNION SELECT NULL,NULL--
- Stacked queries: '; EXEC xp_cmdshell('whoami')--

Endpoints to test:
${suggestion.endpoints.join('\n')}

Be fast, focused and thorough. Test each parameter systematically.`,
        
        xss: `FOCUSED XSS SCAN: The user was manually testing Cross-Site Scripting. 
Test these endpoints with comprehensive XSS payloads:
- Reflected: <script>alert(1)</script>, <img src=x onerror=alert(1)>
- DOM-based: javascript:alert(1), " onmouseover="alert(1)
- Stored: Check if payloads persist across requests
- Filter bypass: <ScRiPt>alert(1)</ScRiPt>, <svg/onload=alert(1)>
- Encoding bypass: &#60;script&#62;, %3Cscript%3E

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

        lfi: `FOCUSED LFI/PATH TRAVERSAL SCAN: The user was testing file inclusion.
Test these endpoints:
- Basic traversal: ../../etc/passwd, ....//....//etc/passwd
- Null byte: ../../../etc/passwd%00
- Double encoding: ..%252f..%252f..%252fetc/passwd
- PHP wrappers: php://filter/convert.base64-encode/resource=index.php
- Windows: ..\\..\\windows\\system32\\drivers\\etc\\hosts

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

        cmdi: `FOCUSED COMMAND INJECTION SCAN: The user was testing command injection.
Test these endpoints:
- Basic: ; ls, | cat /etc/passwd, \`id\`
- Blind: ; sleep 5, | ping -c 5 127.0.0.1
- Alternative: $( whoami ), \${IFS}cat\${IFS}/etc/passwd
- Windows: & dir, | type C:\\windows\\win.ini

Endpoints to test:
${suggestion.endpoints.join('\n')}`,

        ssrf: `FOCUSED SSRF SCAN: The user was testing Server-Side Request Forgery.
Test these endpoints:
- Internal: http://127.0.0.1, http://localhost, http://[::1]
- Cloud metadata: http://169.254.169.254/latest/meta-data/
- DNS rebinding: Use alternative IP representations
- Protocol: file:///etc/passwd, gopher://, dict://

Endpoints to test:
${suggestion.endpoints.join('\n')}`
    };

    const focusPrompt = focusPrompts[suggestion.type] || `Test the following endpoints for ${suggestion.type} vulnerabilities:\n${suggestion.endpoints.join('\n')}`;

    // Create a focused agent with limited iterations for quick results
    const agent = new OrchestratorAgent(
        scanId, 
        suggestion.targetHosts[0] || suggestion.endpoints[0]?.split(' ').pop() || 'target', 
        {
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            parallelAgents: 1,
            customSystemPrompt: focusPrompt,
            maxIterations: 15 // Quick focused scan
        },
        burp
    );

    // Register agent so /live endpoint can serve its logs
    activeAgents.set(scanId, agent);

    try {
        await agent.start();
    } finally {
        // Cache + persist logs before cleanup
        const allLogs = agent.getLogs(0);
        scanLogCache.set(scanId, { logs: allLogs, phase: 'completed' });
        saveScanLogs(scanId, allLogs);

        agent.stop();
        activeAgents.delete(scanId);
        burp.disconnect();
        updateScanStatus(scanId, 'completed');
    }
}

export default router;
