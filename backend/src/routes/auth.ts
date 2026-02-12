import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import { findUserById, db } from '../db/init';
import { AuthRequest, authenticateToken, generateToken } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Verify lock key and return JWT
router.post('/verify-key', async (req, res: Response) => {
    try {
        const { key } = req.body;

        if (!key) {
            res.status(400).json({ error: true, message: 'Key is required' });
            return;
        }

        const row = db.prepare("SELECT value FROM settings WHERE key = 'lock_key_hash'").get() as { value: string } | undefined;
        const storedHash = row?.value;

        if (!storedHash) {
            logger.warn('Lock key hash not found in settings');
            res.status(401).json({ error: true, message: 'Invalid key' });
            return;
        }

        const valid = await bcrypt.compare(key, storedHash);

        if (!valid) {
            logger.warn('Verify key failed - invalid key');
            res.status(401).json({ error: true, message: 'Invalid key' });
            return;
        }

        const token = generateToken(1);
        const user = findUserById(1);

        logger.info('Key verified successfully');

        res.json({
            token,
            user: {
                id: user?.id ?? 1,
                username: user?.username ?? 'operator',
                role: user?.role ?? 'super_admin',
            },
        });
    } catch (error) {
        logger.error('Verify key error', { error });
        res.status(500).json({ error: true, message: 'Server error' });
    }
});

// Change lock key (requires valid JWT)
router.post('/change-key', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { currentKey, newKey } = req.body;

        if (!currentKey || !newKey) {
            res.status(400).json({ error: true, message: 'Current key and new key required' });
            return;
        }

        const row = db.prepare("SELECT value FROM settings WHERE key = 'lock_key_hash'").get() as { value: string } | undefined;
        const storedHash = row?.value;

        if (!storedHash) {
            res.status(500).json({ error: true, message: 'Lock key not configured' });
            return;
        }

        const valid = await bcrypt.compare(currentKey, storedHash);
        if (!valid) {
            res.status(401).json({ error: true, message: 'Current key is incorrect' });
            return;
        }

        const newHash = bcrypt.hashSync(newKey, 12);
        db.prepare("UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'lock_key_hash'").run(newHash);

        logger.info('Lock key changed');

        res.json({ success: true, message: 'Lock key changed successfully' });
    } catch (error) {
        logger.error('Change key error', { error });
        res.status(500).json({ error: true, message: 'Server error' });
    }
});

// Get current operator user info (no credits)
router.get('/me', authenticateToken, (req: AuthRequest, res: Response) => {
    if (!req.user) {
        res.status(401).json({ error: true, message: 'Not authenticated' });
        return;
    }

    const user = findUserById(req.user.id);

    res.json({
        user: {
            id: user?.id ?? req.user.id,
            username: user?.username ?? req.user.username,
            role: user?.role ?? req.user.role,
        },
    });
});

export default router;
