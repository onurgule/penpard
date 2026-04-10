/**
 * Activity Monitor Routes
 * 
 * Endpoints for controlling the activity monitor and retrieving suggestions.
 * The activity monitor watches user's Burp Proxy history and detects testing patterns.
 */

import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { activityMonitor } from '../services/ActivityMonitorService';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import { createScan, updateScanStatus } from '../db/init';
import { scanRuntimeService } from '../services/runtime/ScanRuntimeService';
import { resolveFocusedScanTarget } from '../services/FocusedScanPresetCatalog';

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
        const targetUrl = resolveFocusedScanTarget(suggestion, 'unknown');

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
        startAssistedScan(scanId, suggestion).catch(err => {
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
    suggestion: any
): Promise<void> {
    await scanRuntimeService.startAssistedScan(scanId, suggestion);
}

export default router;
