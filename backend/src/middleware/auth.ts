import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { findUserById } from '../db/init';
import { logger } from '../utils/logger';

function getDefaultDataDir(): string {
    let appDataPath: string;

    if (process.platform === 'win32') {
        appDataPath = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    } else if (process.platform === 'darwin') {
        appDataPath = path.join(os.homedir(), 'Library', 'Application Support');
    } else {
        appDataPath = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    }

    return path.join(appDataPath, 'penpard', 'data');
}

function resolveJwtSecret(): string {
    if (process.env.JWT_SECRET && process.env.JWT_SECRET !== 'change-this-to-a-random-secret-key') {
        return process.env.JWT_SECRET;
    }

    const configuredPath = process.env.JWT_SECRET_PATH;
    const derivedPath = process.env.DATABASE_PATH
        ? path.join(path.dirname(process.env.DATABASE_PATH), 'jwt-secret')
        : path.join(getDefaultDataDir(), 'jwt-secret');
    const secretPath = configuredPath || derivedPath;

    try {
        fs.mkdirSync(path.dirname(secretPath), { recursive: true });

        if (fs.existsSync(secretPath)) {
            const persistedSecret = fs.readFileSync(secretPath, 'utf8').trim();
            if (persistedSecret) {
                logger.warn(`JWT_SECRET is not set; using persistent local secret from ${secretPath}.`);
                return persistedSecret;
            }
        }

        const generatedSecret = crypto.randomBytes(64).toString('hex');
        fs.writeFileSync(secretPath, generatedSecret, { mode: 0o600 });
        logger.warn(`JWT_SECRET is not set; generated persistent local secret at ${secretPath}.`);
        return generatedSecret;
    } catch (error) {
        logger.warn('JWT_SECRET is not set and a persistent fallback could not be initialized. Using an ephemeral secret for this process.', { error });
        return crypto.randomBytes(64).toString('hex');
    }
}

const JWT_SECRET = resolveJwtSecret();

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
