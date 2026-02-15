/**
 * PenPard / Burp integration: "Send to PenPard" from Burp context menu.
 * Pending requests queue and endpoints for Burp extension.
 */

import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { authenticateToken } from '../middleware/auth';
import { AuthRequest } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

const MAX_PENDING = 50;
const TTL_MS = 60 * 60 * 1000; // 1 hour

interface PendingRequest {
    rawRequest: string;
    url: string;
    createdAt: number;
}

const pendingFromBurp = new Map<string, PendingRequest>();

function parseUrlFromRawRequest(rawRequest: string): string | null {
    const firstLine = rawRequest.split('\n')[0];
    const match = firstLine?.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(https?:\/\/[^\s]+)/i);
    if (match) return match[1];
    const hostMatch = rawRequest.match(/\r?\nHost:\s*([^\r\n]+)/i);
    const methodPath = firstLine?.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
    if (hostMatch && methodPath) {
        const host = hostMatch[1].trim();
        const path = methodPath[1];
        const scheme = rawRequest.trimStart().toUpperCase().startsWith('GET ') ? 'http' : 'https';
        return `${scheme}://${host}${path.startsWith('/') ? path : '/' + path}`;
    }
    return null;
}

function cleanupPending(): void {
    const now = Date.now();
    for (const [id, entry] of pendingFromBurp.entries()) {
        if (now - entry.createdAt > TTL_MS) pendingFromBurp.delete(id);
    }
    while (pendingFromBurp.size > MAX_PENDING) {
        const oldest = [...pendingFromBurp.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
        if (oldest) pendingFromBurp.delete(oldest[0]);
    }
}

function allowSendRequest(req: Request): boolean {
    const token = req.get('X-PenPard-Send-Token');
    const envToken = process.env.PENPARD_BURP_SEND_TOKEN;
    if (envToken && token === envToken) return true;
    const ip = req.ip || req.socket?.remoteAddress || '';
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
    return false;
}

/** POST /api/penpard/send-request — Burp extension sends a request (no auth; localhost or token). */
router.post('/send-request', (req: Request, res: Response) => {
    if (!allowSendRequest(req)) {
        logger.warn('[PenPard] send-request rejected: not localhost and no valid token');
        return res.status(403).json({ error: true, message: 'Forbidden' });
    }
    const { rawRequest } = req.body;
    if (!rawRequest || typeof rawRequest !== 'string') {
        return res.status(400).json({ error: true, message: 'rawRequest is required' });
    }
    cleanupPending();
    const url = parseUrlFromRawRequest(rawRequest) || 'unknown';
    const pendingId = uuidv4();
    pendingFromBurp.set(pendingId, {
        rawRequest: rawRequest.trim(),
        url,
        createdAt: Date.now(),
    });
    logger.info('[PenPard] Request queued from Burp', { pendingId, url });
    return res.status(201).json({
        pendingId,
        message: 'Request queued. Open PenPard to start the test.',
    });
});

/** GET /api/penpard/pending — List pending requests (auth required). */
router.get('/pending', authenticateToken, (req: AuthRequest, res: Response) => {
    cleanupPending();
    const list = [...pendingFromBurp.entries()].map(([pendingId, entry]) => ({
        pendingId,
        url: entry.url,
        createdAt: entry.createdAt,
    }));
    return res.json({ pending: list });
});

/** Export for scans/from-burp: get and remove a pending request. */
export function takePendingRequest(pendingId: string): PendingRequest | null {
    const entry = pendingFromBurp.get(pendingId);
    if (entry) {
        pendingFromBurp.delete(pendingId);
        return entry;
    }
    return null;
}

export default router;
