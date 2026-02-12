import { Router, Request, Response } from 'express';
import { db } from '../db/init';
import { authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// All routes require authentication
router.use(authenticateToken);

/**
 * Get token usage records with optional filters
 * GET /api/token-usage?month=2026-02&provider=openai&model=gpt-4o&limit=100&offset=0
 */
router.get('/', (req: Request, res: Response) => {
    try {
        const { month, provider, model, limit = '100', offset = '0' } = req.query;

        let where = 'WHERE 1=1';
        const params: any[] = [];

        if (month) {
            // month format: "2026-02" → filter by year-month
            where += ` AND strftime('%Y-%m', created_at) = ?`;
            params.push(month as string);
        }

        if (provider) {
            where += ' AND provider = ?';
            params.push(provider as string);
        }

        if (model) {
            where += ' AND model = ?';
            params.push(model as string);
        }

        // Get total count
        const countRow = db.prepare(`SELECT COUNT(*) as count FROM token_usage ${where}`).get(...params) as any;

        // Get paginated records
        const rows = db.prepare(`
            SELECT id, provider, model, input_tokens, output_tokens, total_tokens, scan_id, context, created_at
            FROM token_usage
            ${where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `).all(...params, parseInt(limit as string), parseInt(offset as string)) as any[];

        res.json({
            records: rows,
            total: countRow.count,
            limit: parseInt(limit as string),
            offset: parseInt(offset as string),
        });
    } catch (error: any) {
        logger.error('Error fetching token usage:', error);
        res.status(500).json({ error: 'Failed to fetch token usage' });
    }
});

/**
 * Get aggregated summary grouped by model
 * GET /api/token-usage/summary?month=2026-02
 */
router.get('/summary', (req: Request, res: Response) => {
    try {
        const { month } = req.query;

        let where = 'WHERE 1=1';
        const params: any[] = [];

        if (month) {
            where += ` AND strftime('%Y-%m', created_at) = ?`;
            params.push(month as string);
        }

        // Per-model summary
        const byModel = db.prepare(`
            SELECT 
                provider,
                model,
                COUNT(*) as call_count,
                SUM(input_tokens) as total_input,
                SUM(output_tokens) as total_output,
                SUM(total_tokens) as total_tokens,
                AVG(total_tokens) as avg_tokens_per_call,
                MIN(created_at) as first_used,
                MAX(created_at) as last_used
            FROM token_usage
            ${where}
            GROUP BY provider, model
            ORDER BY total_tokens DESC
        `).all(...params) as any[];

        // Grand totals
        const totals = db.prepare(`
            SELECT 
                COUNT(*) as total_calls,
                COALESCE(SUM(input_tokens), 0) as total_input,
                COALESCE(SUM(output_tokens), 0) as total_output,
                COALESCE(SUM(total_tokens), 0) as total_tokens
            FROM token_usage
            ${where}
        `).get(...params) as any;

        // Daily breakdown for chart
        const daily = db.prepare(`
            SELECT 
                DATE(created_at) as date,
                SUM(input_tokens) as input_tokens,
                SUM(output_tokens) as output_tokens,
                SUM(total_tokens) as total_tokens,
                COUNT(*) as call_count
            FROM token_usage
            ${where}
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `).all(...params) as any[];

        res.json({
            byModel,
            totals,
            daily,
            month: month || 'all',
        });
    } catch (error: any) {
        logger.error('Error fetching token usage summary:', error);
        res.status(500).json({ error: 'Failed to fetch token usage summary' });
    }
});

/**
 * Get available months for filtering
 * GET /api/token-usage/months
 */
router.get('/months', (req: Request, res: Response) => {
    try {
        const months = db.prepare(`
            SELECT DISTINCT strftime('%Y-%m', created_at) as month
            FROM token_usage
            ORDER BY month DESC
        `).all() as any[];

        res.json({ months: months.map((m: any) => m.month) });
    } catch (error: any) {
        logger.error('Error fetching token usage months:', error);
        res.status(500).json({ error: 'Failed to fetch months' });
    }
});

export default router;
