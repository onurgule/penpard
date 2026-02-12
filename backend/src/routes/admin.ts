import { Router, Response } from 'express';
import { db } from '../db/init';
import { AuthRequest, authenticateToken, requireRole } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// All admin routes require auth + admin/super_admin role
router.use(authenticateToken);
router.use(requireRole('admin', 'super_admin'));

// Get all whitelists
router.get('/whitelists', (req: AuthRequest, res: Response) => {
    try {
        const whitelists = db.prepare(`
      SELECT id, user_id as userId, domain_pattern as domainPattern, created_at as createdAt
      FROM whitelists ORDER BY created_at DESC
    `).all();

        res.json({ whitelists });
    } catch (error: any) {
        logger.error('Get whitelists error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get whitelists' });
    }
});

// Create whitelist entry
router.post('/whitelists', (req: AuthRequest, res: Response) => {
    try {
        const { domainPattern } = req.body;
        const userId = req.user!.id;

        if (!domainPattern) {
            res.status(400).json({ error: true, message: 'Domain pattern required' });
            return;
        }

        const result = db.prepare(`
      INSERT INTO whitelists (user_id, domain_pattern)
      VALUES (?, ?)
    `).run(userId, domainPattern.toLowerCase());

        logger.info('Whitelist created', { userId, domainPattern, createdBy: req.user?.id });

        res.json({
            id: result.lastInsertRowid,
            message: 'Whitelist entry added',
        });
    } catch (error: any) {
        logger.error('Create whitelist error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to create whitelist' });
    }
});

// Delete whitelist entry
router.delete('/whitelists/:id', (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;

        const whitelist = db.prepare('SELECT * FROM whitelists WHERE id = ?').get(id) as any;
        if (!whitelist) {
            res.status(404).json({ error: true, message: 'Whitelist entry not found' });
            return;
        }

        // Ownership check: only owner or super_admin can delete
        if (whitelist.user_id !== req.user!.id && req.user!.role !== 'super_admin') {
            res.status(403).json({ error: true, message: 'You can only delete your own whitelist entries' });
            return;
        }

        db.prepare('DELETE FROM whitelists WHERE id = ?').run(id);

        logger.info('Whitelist deleted', { whitelistId: id, deletedBy: req.user?.id });

        res.json({ message: 'Whitelist entry deleted' });
    } catch (error: any) {
        logger.error('Delete whitelist error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to delete whitelist' });
    }
});

// Get scan logs
router.get('/logs', (req: AuthRequest, res: Response) => {
    try {
        const scans = db.prepare(`
      SELECT s.*, u.username
      FROM scans s
      JOIN users u ON s.user_id = u.id
      ORDER BY s.created_at DESC
      LIMIT 100
    `).all();

        res.json({ scans });
    } catch (error: any) {
        logger.error('Get logs error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get logs' });
    }
});

export default router;
