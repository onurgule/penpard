/**
 * PenPard Browser — REST API Routes
 *
 * Endpoints for launching, controlling, and managing PenPard Browser sessions.
 * All routes require authentication.
 */

import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { browserService, BrowserAction } from '../services/BrowserService';
import {
    getUserBrowserSessions,
    getBrowserActions,
    getBrowserSession,
} from '../db/init';
import { logger } from '../utils/logger';

const router = Router();

/**
 * POST /api/browser/launch
 * Launch a new PenPard Browser session.
 */
router.post('/launch', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { targetUrl, scanId, findingId, proxyHost, proxyPort } = req.body;
        const userId = req.user!.id;

        logger.info('Browser launch requested', { userId, targetUrl, scanId });

        const sessionId = await browserService.launchSession(userId, {
            targetUrl,
            scanId,
            findingId,
            proxyHost,
            proxyPort,
        });

        const session = await browserService.getSessionInfo(sessionId);
        res.json({ sessionId, session });

    } catch (error: any) {
        logger.error('Failed to launch browser', { error: error.message });

        // Provide helpful error message for common issues
        let message = error.message;
        if (message.includes('Executable doesn\'t exist') || message.includes('browserType.launch')) {
            message = 'Chromium browser not found. Please install Google Chrome or set PLAYWRIGHT_CHROMIUM_PATH environment variable.';
        }

        res.status(500).json({ error: true, message });
    }
});

/**
 * GET /api/browser/sessions
 * List all browser sessions for the current user.
 */
router.get('/sessions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const userId = req.user!.id;
        const sessions = getUserBrowserSessions(userId);

        // Annotate with live status
        const annotated = sessions.map(s => ({
            ...s,
            isLive: browserService.isSessionAlive(s.id),
        }));

        res.json({ sessions: annotated });
    } catch (error: any) {
        logger.error('Failed to list browser sessions', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to list sessions' });
    }
});

/**
 * GET /api/browser/sessions/:id
 * Get detailed info for a specific session (with live state).
 */
router.get('/sessions/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const session = await browserService.getSessionInfo(req.params.id);
        if (!session) {
            res.status(404).json({ error: true, message: 'Session not found' });
            return;
        }
        res.json({ session });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/**
 * POST /api/browser/sessions/:id/action
 * Execute an AI-driven action on the browser.
 */
router.post('/sessions/:id/action', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const sessionId = req.params.id;
        const action: BrowserAction = req.body;

        if (!action.type) {
            res.status(400).json({ error: true, message: 'Action type is required' });
            return;
        }

        logger.info('Browser action requested', { sessionId, action: action.type });

        const result = await browserService.executeAction(sessionId, action);
        res.json({ success: true, result });

    } catch (error: any) {
        logger.error('Browser action failed', { sessionId: req.params.id, error: error.message });
        res.status(400).json({ error: true, message: error.message });
    }
});

/**
 * GET /api/browser/sessions/:id/state
 * Get current page state (URL, title, forms, links, text).
 */
router.get('/sessions/:id/state', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const state = await browserService.getPageState(req.params.id);
        res.json({ state });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/**
 * GET /api/browser/sessions/:id/actions
 * Get action history log for a session.
 */
router.get('/sessions/:id/actions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const actions = getBrowserActions(req.params.id);
        res.json({ actions });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/**
 * POST /api/browser/sessions/:id/screenshot
 * Capture current page screenshot.
 */
router.post('/sessions/:id/screenshot', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const screenshot = await browserService.captureScreenshot(req.params.id);
        res.json({ screenshot });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/**
 * POST /api/browser/sessions/:id/close
 * Close a browser session.
 */
router.post('/sessions/:id/close', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        await browserService.closeSession(req.params.id);
        res.json({ message: 'Session closed' });
    } catch (error: any) {
        logger.error('Failed to close session', { error: error.message });
        res.status(500).json({ error: true, message: error.message });
    }
});

/**
 * GET /api/browser/proxy-config
 * Get the current browser proxy configuration.
 */
router.get('/proxy-config', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { db } = require('../db/init');
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('browser_proxy_config') as any;
        let config = { host: '127.0.0.1', port: 8080 };

        if (row?.value) {
            config = { ...config, ...JSON.parse(row.value) };
        } else {
            // Fall back to burp_config host
            const burpRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
            if (burpRow?.value) {
                const burpCfg = JSON.parse(burpRow.value);
                config.host = burpCfg.host || '127.0.0.1';
            }
        }

        res.json({ config });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get proxy config' });
    }
});

/**
 * POST /api/browser/proxy-config
 * Save browser proxy configuration.
 */
router.post('/proxy-config', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { host, port } = req.body;
        if (!host || !port) {
            res.status(400).json({ error: true, message: 'Host and port are required' });
            return;
        }

        const { db } = require('../db/init');
        db.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES ('browser_proxy_config', ?)
        `).run(JSON.stringify({ host: String(host).trim(), port: Number(port) }));

        res.json({ message: 'Browser proxy configuration saved', config: { host, port } });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to save proxy config' });
    }
});

export default router;
