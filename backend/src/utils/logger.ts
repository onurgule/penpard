import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const REDACTED = '[REDACTED]';
const SENSITIVE_KEY_PATTERN = /(^|_)(authorization|cookie|set_cookie|access_token|refresh_token|token|api_key|client_secret|password|secret|env_vars|raw_request|raw_response)(_|$)/i;

function normalizeKey(key: string): string {
    return key
        .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
        .replace(/-/g, '_')
        .toLowerCase();
}

function isSensitiveKey(key: string | undefined): boolean {
    return !!key && SENSITIVE_KEY_PATTERN.test(normalizeKey(key));
}

function sanitizeString(value: string, keyHint?: string): string {
    if (!value) {
        return value;
    }

    if (isSensitiveKey(keyHint)) {
        return REDACTED;
    }

    return value
        .replace(/(authorization\s*:\s*bearer\s+)[^\s"'`]+/gi, `$1${REDACTED}`)
        .replace(/(authorization["']?\s*[:=]\s*["']?bearer\s+)[^\s"',`]+/gi, `$1${REDACTED}`)
        .replace(/((?:cookie|set-cookie)\s*:\s*)[^\r\n]+/gi, `$1${REDACTED}`)
        .replace(/((?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|password)\s*[:=]\s*["']?)[^"',\s\r\n]+/gi, `$1${REDACTED}`)
        .replace(/\b(gh[opurs]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g, REDACTED)
        .replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, REDACTED)
        .replace(/\bsk-ant-[A-Za-z0-9_-]{10,}\b/g, REDACTED);
}

function sanitizeValue(value: unknown, keyHint?: string, seen: WeakSet<object> = new WeakSet()): unknown {
    if (value === null || value === undefined) {
        return value;
    }

    if (typeof value === 'string') {
        return sanitizeString(value, keyHint);
    }

    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
        return value;
    }

    if (typeof value === 'function') {
        return '[Function]';
    }

    if (value instanceof Error) {
        return {
            name: value.name,
            message: sanitizeString(value.message, keyHint),
            stack: value.stack ? sanitizeString(value.stack, keyHint) : undefined,
        };
    }

    if (Array.isArray(value)) {
        return value.map((entry) => sanitizeValue(entry, keyHint, seen));
    }

    if (typeof value === 'object') {
        if (seen.has(value as object)) {
            return '[Circular]';
        }
        seen.add(value as object);

        if (isSensitiveKey(keyHint)) {
            return REDACTED;
        }

        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
                key,
                sanitizeValue(entry, key, seen),
            ]),
        );
    }

    return sanitizeString(String(value), keyHint);
}

export function sanitizeLogMessage(message: unknown): string {
    return sanitizeString(typeof message === 'string' ? message : String(message || ''), 'message');
}

export function sanitizeLogMeta(meta: Record<string, unknown>): Record<string, unknown> {
    return sanitizeValue(meta) as Record<string, unknown>;
}

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const sanitizedMeta = sanitizeLogMeta(meta);
        const metaStr = Object.keys(sanitizedMeta).length ? JSON.stringify(sanitizedMeta) : '';
        return `${timestamp} [${level.toUpperCase()}]: ${sanitizeLogMessage(message)} ${metaStr}`;
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
        ...sanitizeLogMeta(metadata || {}),
    });

    fs.appendFileSync(usageLog, entry + '\n');
};
