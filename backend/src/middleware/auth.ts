import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { findUserById } from '../db/init';
import { logger } from '../utils/logger';

// JWT Secret: require env var or generate a random ephemeral one (will invalidate tokens on restart)
let JWT_SECRET: string;
if (process.env.JWT_SECRET && process.env.JWT_SECRET !== 'change-this-to-a-random-secret-key') {
    JWT_SECRET = process.env.JWT_SECRET;
} else {
    JWT_SECRET = crypto.randomBytes(64).toString('hex');
    logger.warn('⚠️  JWT_SECRET is not set! Using a random ephemeral secret. Sessions will be invalidated on server restart. Set JWT_SECRET in your environment for persistent sessions.');
}

export interface AuthRequest extends Request {
    user?: {
        id: number;
        username: string;
        role: 'super_admin' | 'admin' | 'user';
    };
}

export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: true, message: 'Authentication required' });
        return;
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
        const user = findUserById(decoded.userId);

        if (!user) {
            res.status(401).json({ error: true, message: 'User not found' });
            return;
        }

        req.user = { id: user.id, username: user.username, role: user.role };
        next();
    } catch (error) {
        logger.warn('Invalid token', { error });
        res.status(403).json({ error: true, message: 'Invalid or expired token' });
        return;
    }
};

export const generateToken = (userId: number): string => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
};

/**
 * Middleware to require specific roles.
 * Must be used AFTER authenticateToken.
 */
export const requireRole = (...roles: string[]) => {
    return (req: AuthRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({ error: true, message: 'Authentication required' });
            return;
        }
        if (!roles.includes(req.user.role)) {
            res.status(403).json({ error: true, message: 'Insufficient permissions' });
            return;
        }
        next();
    };
};
