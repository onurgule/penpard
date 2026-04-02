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
    deleteClosedBrowserSessions,
} from '../db/init';
import { logger } from '../utils/logger';

const router = Router();

/**
 * POST /api/browser/launch
 */
router.post('/launch', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { targetUrl, scanId, findingId, proxyHost, proxyPort, label } = req.body;
        const userId = req.user!.id;
        logger.info('Browser launch requested', { userId, targetUrl, scanId, label });
        const sessionId = await browserService.launchSession(userId, {
            targetUrl, scanId, findingId, proxyHost, proxyPort, label,
        });
        const session = await browserService.getSessionInfo(sessionId);
        res.json({ sessionId, session });
    } catch (error: any) {
        logger.error('Failed to launch browser', { error: error.message });
        let message = error.message;
        if (message.includes('Executable doesn\'t exist') || message.includes('browserType.launch')) {
            message = 'Chromium browser not found. Please install Google Chrome or set PLAYWRIGHT_CHROMIUM_PATH environment variable.';
        }
        res.status(500).json({ error: true, message });
    }
});

/** GET /api/browser/sessions */
router.get('/sessions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const sessions = getUserBrowserSessions(req.user!.id);
        const annotated = sessions.map(s => ({ ...s, isLive: browserService.isSessionAlive(s.id) }));
        res.json({ sessions: annotated });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list sessions' });
    }
});

/** GET /api/browser/sessions/:id */
router.get('/sessions/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const session = await browserService.getSessionInfo(req.params.id);
        if (!session) { res.status(404).json({ error: true, message: 'Session not found' }); return; }
        res.json({ session });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/** POST /api/browser/sessions/:id/action */
router.post('/sessions/:id/action', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const action: BrowserAction = req.body;
        if (!action.type) { res.status(400).json({ error: true, message: 'Action type is required' }); return; }
        const result = await browserService.executeAction(req.params.id, action);
        res.json({ success: true, result });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/state — basic page state (legacy) */
router.get('/sessions/:id/state', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const state = await browserService.getPageState(req.params.id);
        res.json({ state });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/full-state — deep page state */
router.get('/sessions/:id/full-state', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const state = await browserService.getFullPageState(req.params.id);
        res.json({ state });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/scripts — loaded JavaScript analysis */
router.get('/sessions/:id/scripts', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const scripts = await browserService.getLoadedScripts(req.params.id);
        res.json({ scripts });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/frontend-analysis — API endpoints, GraphQL, WS, tokens */
router.get('/sessions/:id/frontend-analysis', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const analysis = await browserService.getFrontendAnalysis(req.params.id);
        res.json({ analysis });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/storage — cookies, localStorage, sessionStorage */
router.get('/sessions/:id/storage', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const storage = await browserService.getSessionStorageData(req.params.id);
        res.json({ storage });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/burp-correlation — browser+Burp merged intelligence */
router.get('/sessions/:id/burp-correlation', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const correlation = await browserService.correlateBrowserWithBurp(req.params.id);
        res.json({ correlation });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/compare/:otherId — compare two sessions */
router.get('/sessions/:id/compare/:otherId', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const comparison = await browserService.compareSessionStates(req.params.id, req.params.otherId);
        res.json({ comparison });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/actions */
router.get('/sessions/:id/actions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const actions = getBrowserActions(req.params.id);
        res.json({ actions });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/** POST /api/browser/sessions/:id/screenshot */
router.post('/sessions/:id/screenshot', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const screenshot = await browserService.captureScreenshot(req.params.id);
        res.json({ screenshot });
    } catch (error: any) {
        res.status(400).json({ error: true, message: error.message });
    }
});

/** POST /api/browser/sessions/:id/close */
router.post('/sessions/:id/close', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        await browserService.closeSession(req.params.id);
        res.json({ message: 'Session closed' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/proxy-config */
router.get('/proxy-config', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { db } = require('../db/init');
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('browser_proxy_config') as any;
        let config = { host: '127.0.0.1', port: 8080 };
        if (row?.value) {
            config = { ...config, ...JSON.parse(row.value) };
        } else {
            const burpRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
            if (burpRow?.value) { config.host = JSON.parse(burpRow.value).host || '127.0.0.1'; }
        }
        res.json({ config });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get proxy config' });
    }
});

/** POST /api/browser/proxy-config */
router.post('/proxy-config', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { host, port } = req.body;
        if (!host || !port) { res.status(400).json({ error: true, message: 'Host and port are required' }); return; }
        const { db } = require('../db/init');
        db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES ('browser_proxy_config', ?)`).run(
            JSON.stringify({ host: String(host).trim(), port: Number(port) })
        );
        res.json({ message: 'Browser proxy configuration saved', config: { host, port } });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to save proxy config' });
    }
});

/** DELETE /api/browser/sessions/closed — purge all closed sessions from DB */
router.delete('/sessions/closed', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const userId = req.user!.id;
        const deleted = deleteClosedBrowserSessions(userId);
        res.json({ message: `Deleted ${deleted} closed session(s)`, deleted });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to delete closed sessions' });
    }
});

/** POST /api/browser/sessions/:id/show — switch from headless to visible */
router.post('/sessions/:id/show', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        logger.info('Show browser requested', { sessionId: id });
        await browserService.showBrowser(id);
        res.json({ message: 'Browser is now visible', isHeadless: false });
    } catch (error: any) {
        logger.error('Show browser failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message });
    }
});

/** POST /api/browser/sessions/:id/hide — switch from visible to headless */
router.post('/sessions/:id/hide', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        logger.info('Hide browser requested', { sessionId: id });
        await browserService.hideBrowser(id);
        res.json({ message: 'Browser is now headless', isHeadless: true });
    } catch (error: any) {
        logger.error('Hide browser failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message });
    }
});

/** GET /api/browser/sessions/:id/visibility — get current visibility state */
router.get('/sessions/:id/visibility', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const visibility = browserService.getSessionVisibility(req.params.id);
        if (!visibility) {
            res.status(404).json({ error: true, message: 'Session not found or not active' });
            return;
        }
        res.json(visibility);
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

export default router;
