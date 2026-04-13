import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { githubIntegration, type GitHubIntegrationService } from '../services/GitHubIntegrationService';
import { logger } from '../utils/logger';

export function createGitHubIntegrationRouter(service: GitHubIntegrationService = githubIntegration) {
const router = Router();

router.get('/github/config', authenticateToken, (_req: AuthRequest, res: Response) => {
    try {
        res.json(service.getGitHubAppConfigSummary());
    } catch (error: any) {
        logger.error('GitHub app config lookup failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to load GitHub App configuration.' });
    }
});

router.post('/github/config', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const summary = await service.saveGitHubAppConfig({
            clientId: typeof req.body?.clientId === 'string' ? req.body.clientId : '',
            clientSecret: typeof req.body?.clientSecret === 'string' ? req.body.clientSecret : '',
            callbackUrl: typeof req.body?.callbackUrl === 'string' ? req.body.callbackUrl : '',
            confirmCallbackRegistration: req.body?.confirmCallbackRegistration === true,
        });
        res.json(summary);
    } catch (error: any) {
        logger.error('GitHub app config save failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message || 'Failed to save GitHub App configuration.' });
    }
});

router.post('/github/auth/start', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const runtime = req.body?.runtime === 'electron' ? 'electron' : 'web';
        const origin = typeof req.body?.origin === 'string' ? req.body.origin : req.get('origin');
        const userId = req.user?.id || 1;

        const result = await service.startAuthorization(userId, { runtime, origin });
        res.json(result);
    } catch (error: any) {
        logger.error('GitHub auth start failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message || 'Failed to start GitHub authentication.' });
    }
});

router.get('/github/callback', (_req, res: Response) => {
    let preferredCallbackUrl = 'http://127.0.0.1:5050/api/integrations/github/callback';
    try {
        preferredCallbackUrl = service.getCallbackUrl();
    } catch {
        // Fall back to the documented default loopback callback URL.
    }

    res.status(410).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GitHub callback moved</title>
</head>
<body style="font-family: Arial, sans-serif; background: #020617; color: #e2e8f0; margin: 0; min-height: 100vh; display: grid; place-items: center;">
  <div style="width: min(520px, calc(100vw - 32px)); background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 16px; padding: 28px;">
    <h1 style="margin-top: 0;">GitHub callback moved</h1>
    <p>PenPard now finishes GitHub OAuth on the dedicated loopback listener instead of the main backend port.</p>
    <p>Update your GitHub App callback URL to <code>${preferredCallbackUrl}</code>, then try connecting again.</p>
  </div>
</body>
</html>`);
});

router.get('/github/auth/session/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const session = service.getAuthorizationSession(req.user?.id || 1, req.params.id);
        if (!session) {
            res.status(404).json({ error: true, message: 'GitHub authorization session not found.' });
            return;
        }

        res.json(session);
    } catch (error: any) {
        logger.error('GitHub auth session lookup failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to load GitHub authorization session.' });
    }
});

router.post('/github/auth/session/:id/cancel', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const reason = typeof req.body?.reason === 'string' && req.body.reason.trim()
            ? req.body.reason.trim()
            : 'GitHub browser launch failed before authorization completed.';
        const session = service.cancelAuthorizationSession(req.user?.id || 1, req.params.id, reason);
        if (!session) {
            res.status(404).json({ error: true, message: 'GitHub authorization session not found.' });
            return;
        }

        res.json(session);
    } catch (error: any) {
        logger.error('GitHub auth session cancellation failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to cancel GitHub authorization session.' });
    }
});

router.get('/github/status', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const status = await service.getResolvedConnectionStatus(req.user?.id || 1);
        res.json(status);
    } catch (error: any) {
        logger.error('GitHub status check failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to load GitHub status.' });
    }
});

router.get('/github/models', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const refresh = req.query.refresh === '1' || req.query.refresh === 'true';
        const models = await service.listModels(req.user?.id || 1, refresh);
        res.json({ models });
    } catch (error: any) {
        logger.error('GitHub model discovery failed', { error: error.message });
        res.status(400).json({ error: true, message: error.message || 'Failed to discover GitHub Copilot models.' });
    }
});

router.post('/github/disconnect', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        service.disconnect(req.user?.id || 1);
        res.json({ success: true, message: 'GitHub disconnected.' });
    } catch (error: any) {
        logger.error('GitHub disconnect failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to disconnect GitHub.' });
    }
});

router.post('/github/validate', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const valid = await service.validateToken(req.user?.id || 1);
        res.json({ valid });
    } catch (error: any) {
        logger.error('GitHub validation failed', { error: error.message });
        res.status(500).json({ error: true, message: error.message || 'Failed to validate GitHub authentication.' });
    }
});

return router;
}

const router = createGitHubIntegrationRouter();
export default router;
