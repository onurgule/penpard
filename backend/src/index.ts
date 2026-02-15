import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import dotenv from 'dotenv';

import { logger } from './utils/logger';
import { initDatabase } from './db/init';
import authRoutes from './routes/auth';
import scanRoutes from './routes/scans';
import adminRoutes from './routes/admin';
import reportsRoutes from './routes/reports';
import configRoutes from './routes/config';
import statusRoutes from './routes/status';
import analyticsRoutes from './routes/analytics';
import activityMonitorRoutes from './routes/activity-monitor';
import tokenUsageRoutes from './routes/token-usage';
import penpardRoutes from './routes/penpard';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Security middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// CORS: configurable via CORS_ORIGINS env var (comma-separated), with sensible defaults
const defaultOrigins = ['http://localhost:3000', 'http://frontend:3000', 'penpard://app'];
const corsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
    : defaultOrigins;
app.use(cors({
    origin: corsOrigins,
    credentials: true,
}));

// Rate limiting - only for auth endpoints to prevent brute force
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30, // 30 attempts per 15 min
    message: { error: 'Too many attempts, please try again later' },
});
app.use('/api/auth/verify-key', authLimiter);

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static files for reports/uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use('/reports', express.static(path.join(__dirname, '../reports')));

// Request logging
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    next();
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/config', configRoutes);
app.use('/api/status', statusRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/activity-monitor', activityMonitorRoutes);
app.use('/api/token-usage', tokenUsageRoutes);
app.use('/api/penpard', penpardRoutes);

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
    });
});

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(err.status || 500).json({
        error: true,
        message: err.message || 'Internal server error',
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: true, message: 'Not found' });
});

// Initialize database and start server
async function start() {
    try {
        await initDatabase();
        logger.info('Database initialized');

        app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
            console.log(`
╔═══════════════════════════════════════════╗
║       PENPARD BACKEND SERVER              ║
║       Running on http://localhost:${PORT}    ║
╚═══════════════════════════════════════════╝
      `);

            // Background: fetch latest prompt library from penpard.com
            import('./services/PromptLibraryService').then(({ promptLibrary }) => {
                promptLibrary.fetchFromRemote().then(result => {
                    if (result.success) {
                        logger.info(`Prompt Library: fetched ${result.count} prompts from penpard.com`);
                    } else {
                        logger.info(`Prompt Library: using ${result.count} cached/built-in prompts (${result.error || 'remote unavailable'})`);
                    }
                }).catch(() => { /* silent */ });
            }).catch(() => { /* silent */ });
        });
    } catch (error) {
        logger.error('Failed to start server', { error });
        process.exit(1);
    }
}

start();

export default app;
