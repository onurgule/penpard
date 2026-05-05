import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';

import { logger } from './utils/logger';
import authRoutes from './routes/auth';
import scanRoutes from './routes/scans';
import adminRoutes from './routes/admin';
import reportsRoutes from './routes/reports';
import configRoutes from './routes/config';
import statusRoutes from './routes/status';
import analyticsRoutes from './routes/analytics';
import tokenUsageRoutes from './routes/token-usage';
import penpardRoutes from './routes/penpard';
import reportAnalysisRoutes from './routes/report-analysis';
import presenceScanRoutes from './routes/presence-scan';
import browserRoutes from './routes/browser';
import githubIntegrationRoutes from './routes/github-integration';

export function createApp() {
    const app = express();

    app.use(helmet({
        crossOriginResourcePolicy: { policy: 'cross-origin' },
    }));

    const defaultOrigins = ['http://localhost:3000', 'http://frontend:3000', 'penpard://app'];
    const corsOrigins = process.env.CORS_ORIGINS
        ? process.env.CORS_ORIGINS.split(',').map((origin) => origin.trim())
        : defaultOrigins;
    app.use(cors({
        origin: corsOrigins,
        credentials: true,
    }));

    const authLimiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 30,
        message: { error: 'Too many attempts, please try again later' },
    });
    app.use('/api/auth/verify-key', authLimiter);

    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
    app.use('/reports', express.static(path.join(__dirname, '../reports')));

    app.use((req, _res, next) => {
        logger.info(`${req.method} ${req.path}`, {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
        });
        next();
    });

    app.use('/api/auth', authRoutes);
    app.use('/api/scans', scanRoutes);
    app.use('/api/admin', adminRoutes);
    app.use('/api/reports', reportsRoutes);
    app.use('/api/config', configRoutes);
    app.use('/api/status', statusRoutes);
    app.use('/api/analytics', analyticsRoutes);
    app.use('/api/token-usage', tokenUsageRoutes);
    app.use('/api/penpard', penpardRoutes);
    app.use('/api/report-analysis', reportAnalysisRoutes);
    app.use('/api/presence-scan', presenceScanRoutes);
    app.use('/api/browser', browserRoutes);
    app.use('/api/integrations', githubIntegrationRoutes);

    app.get('/api/health', (_req, res) => {
        res.json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
        });
    });

    app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        logger.error('Unhandled error', { error: err.message, stack: err.stack });
        res.status(err.status || 500).json({
            error: true,
            message: err.message || 'Internal server error',
        });
    });

    app.use((_req, res) => {
        res.status(404).json({ error: true, message: 'Not found' });
    });

    return app;
}
