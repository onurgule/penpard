import { Router, Request, Response } from 'express';
import { AnalyticsService } from '../services/analytics';
import { authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// All analytics routes require authentication
router.use(authenticateToken);

/**
 * Track an analytics event
 * POST /api/analytics/event
 */
router.post('/event', (req: Request, res: Response) => {
    try {
        const { category, action, label, value, metadata } = req.body;

        if (!category || !action) {
            return res.status(400).json({ error: 'category and action are required' });
        }

        AnalyticsService.trackEvent({
            category,
            action,
            label,
            value,
            metadata,
        });

        res.json({ success: true });
    } catch (error) {
        logger.error('Error tracking event:', error);
        res.status(500).json({ error: 'Failed to track event' });
    }
});

/**
 * Track page view
 * POST /api/analytics/pageview
 */
router.post('/pageview', (req: Request, res: Response) => {
    try {
        const { page } = req.body;

        if (!page) {
            return res.status(400).json({ error: 'page is required' });
        }

        AnalyticsService.trackPageView(page);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error tracking pageview:', error);
        res.status(500).json({ error: 'Failed to track pageview' });
    }
});

/**
 * Track feature usage
 * POST /api/analytics/feature
 */
router.post('/feature', (req: Request, res: Response) => {
    try {
        const { feature, details } = req.body;

        if (!feature) {
            return res.status(400).json({ error: 'feature is required' });
        }

        AnalyticsService.trackFeatureUsage(feature, details);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error tracking feature:', error);
        res.status(500).json({ error: 'Failed to track feature' });
    }
});

/**
 * Track error
 * POST /api/analytics/error
 */
router.post('/error', (req: Request, res: Response) => {
    try {
        const { errorType, errorCode } = req.body;

        if (!errorType) {
            return res.status(400).json({ error: 'errorType is required' });
        }

        AnalyticsService.trackError(errorType, errorCode);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error tracking error:', error);
        res.status(500).json({ error: 'Failed to track error' });
    }
});

/**
 * Track performance metric
 * POST /api/analytics/performance
 */
router.post('/performance', (req: Request, res: Response) => {
    try {
        const { metric, valueMs } = req.body;

        if (!metric || valueMs === undefined) {
            return res.status(400).json({ error: 'metric and valueMs are required' });
        }

        AnalyticsService.trackPerformance(metric, valueMs);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error tracking performance:', error);
        res.status(500).json({ error: 'Failed to track performance' });
    }
});

/**
 * Get current session summary
 * GET /api/analytics/session
 */
router.get('/session', (req: Request, res: Response) => {
    try {
        const summary = AnalyticsService.getSessionSummary();
        res.json(summary);
    } catch (error) {
        logger.error('Error getting session summary:', error);
        res.status(500).json({ error: 'Failed to get session summary' });
    }
});

/**
 * Get aggregated analytics (admin only)
 * GET /api/analytics/aggregates
 */
router.get('/aggregates', authenticateToken, (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        
        if (user.role !== 'admin' && user.role !== 'super_admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { startDate, endDate } = req.query;
        
        // Default to last 30 days
        const end = endDate as string || new Date().toISOString().split('T')[0];
        const start = startDate as string || (() => {
            const d = new Date();
            d.setDate(d.getDate() - 30);
            return d.toISOString().split('T')[0];
        })();

        const aggregates = AnalyticsService.getAggregatedAnalytics(start, end);
        res.json({ startDate: start, endDate: end, aggregates });
    } catch (error) {
        logger.error('Error getting aggregates:', error);
        res.status(500).json({ error: 'Failed to get aggregates' });
    }
});

/**
 * Get feature usage stats (admin only)
 * GET /api/analytics/features
 */
router.get('/features', authenticateToken, (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        
        if (user.role !== 'admin' && user.role !== 'super_admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const days = parseInt(req.query.days as string) || 30;
        const stats = AnalyticsService.getFeatureUsageStats(days);
        
        res.json({ days, stats });
    } catch (error) {
        logger.error('Error getting feature stats:', error);
        res.status(500).json({ error: 'Failed to get feature stats' });
    }
});

/**
 * Toggle analytics (admin only)
 * POST /api/analytics/toggle
 */
router.post('/toggle', authenticateToken, (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        
        if (user.role !== 'admin' && user.role !== 'super_admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const { enabled } = req.body;
        AnalyticsService.setEnabled(!!enabled);
        
        res.json({ success: true, enabled: !!enabled });
    } catch (error) {
        logger.error('Error toggling analytics:', error);
        res.status(500).json({ error: 'Failed to toggle analytics' });
    }
});

export default router;
