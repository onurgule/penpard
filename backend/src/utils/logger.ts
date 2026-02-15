import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
        return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaStr}`;
    })
);

export const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        // Console output
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                logFormat
            ),
        }),
        // File output
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
        }),
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
        }),
    ],
});

/** Format current time for agent logs using system/local timezone (LOG_TZ or TZ env, else OS default). */
export function formatLogTimestamp(): string {
    const now = new Date();
    const tz = process.env.LOG_TZ || process.env.TZ || Intl.DateTimeFormat().resolvedOptions().timeZone;
    return now.toLocaleString('sv-SE', { hour12: false, timeZone: tz }).replace(' ', 'T');
}

// Log API usage for analytics
export const logApiUsage = (endpoint: string, userId: number, metadata?: any) => {
    const usageLog = path.join(logsDir, 'api-usage.log');
    const entry = JSON.stringify({
        timestamp: new Date().toISOString(),
        endpoint,
        userId,
        ...metadata,
    });

    fs.appendFileSync(usageLog, entry + '\n');
};
