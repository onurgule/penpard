import { db } from '../db/init';
import { logger } from '../utils/logger';
import os from 'os';

export type EventCategory = 
    | 'app_lifecycle'
    | 'feature_usage'
    | 'error'
    | 'performance';

export interface AnalyticsEvent {
    category: EventCategory;
    action: string;
    label?: string;
    value?: number;
    metadata?: Record<string, any>;
}

interface SessionInfo {
    sessionId: string;
    startedAt: number;
    platform: string;
    osVersion: string;
    appVersion: string;
    screenResolution?: string;
}

/**
 * Privacy-focused analytics service.
 * Tracks app usage patterns WITHOUT collecting customer scan data or PII.
 */
export class AnalyticsService {
    private static sessionInfo: SessionInfo | null = null;
    private static isEnabled: boolean = true;
    private static eventQueue: AnalyticsEvent[] = [];
    private static flushInterval: NodeJS.Timeout | null = null;

    /**
     * Initialize analytics tables and session.
     */
    static initialize(): void {
        this.initializeTables();
        this.startSession();
        this.startFlushInterval();
        
        // Track app start
        this.trackEvent({
            category: 'app_lifecycle',
            action: 'app_started',
            metadata: {
                platform: os.platform(),
                arch: os.arch(),
                nodeVersion: process.version,
            },
        });
    }

    /**
     * Initialize database tables for analytics.
     */
    private static initializeTables(): void {
        db.exec(`
            CREATE TABLE IF NOT EXISTS analytics_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                platform TEXT,
                os_version TEXT,
                app_version TEXT,
                screen_resolution TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                label TEXT,
                value INTEGER,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES analytics_sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS analytics_daily_aggregates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                total_value INTEGER DEFAULT 0,
                UNIQUE(date, category, action)
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON analytics_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_category ON analytics_events(category);
            CREATE INDEX IF NOT EXISTS idx_events_created ON analytics_events(created_at);
            CREATE INDEX IF NOT EXISTS idx_aggregates_date ON analytics_daily_aggregates(date);
        `);
    }

    /**
     * Start a new analytics session.
     */
    private static startSession(): void {
        const sessionId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        this.sessionInfo = {
            sessionId,
            startedAt: Date.now(),
            platform: os.platform(),
            osVersion: os.release(),
            appVersion: process.env.APP_VERSION || '1.0.0',
        };

        db.prepare(`
            INSERT INTO analytics_sessions (session_id, started_at, platform, os_version, app_version)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            this.sessionInfo.sessionId,
            this.sessionInfo.startedAt,
            this.sessionInfo.platform,
            this.sessionInfo.osVersion,
            this.sessionInfo.appVersion
        );

        logger.info(`Analytics session started: ${sessionId}`);
    }

    /**
     * End the current session.
     */
    static endSession(): void {
        if (!this.sessionInfo) return;

        this.flushEvents();

        db.prepare(`UPDATE analytics_sessions SET ended_at = ? WHERE session_id = ?`)
            .run(Date.now(), this.sessionInfo.sessionId);

        this.trackEvent({
            category: 'app_lifecycle',
            action: 'app_closed',
            value: Math.floor((Date.now() - this.sessionInfo.startedAt) / 1000), // Session duration in seconds
        });

        if (this.flushInterval) {
            clearInterval(this.flushInterval);
        }

        logger.info(`Analytics session ended: ${this.sessionInfo.sessionId}`);
        this.sessionInfo = null;
    }

    /**
     * Track an analytics event.
     * IMPORTANT: Never include customer data, scan results, or PII.
     */
    static trackEvent(event: AnalyticsEvent): void {
        if (!this.isEnabled || !this.sessionInfo) return;

        // Sanitize metadata to ensure no PII or sensitive data
        const sanitizedMetadata = this.sanitizeMetadata(event.metadata);

        const eventWithSession = {
            ...event,
            metadata: sanitizedMetadata,
        };

        this.eventQueue.push(eventWithSession);

        // Flush immediately if queue is large
        if (this.eventQueue.length >= 50) {
            this.flushEvents();
        }
    }

    /**
     * Track a page view.
     */
    static trackPageView(page: string): void {
        this.trackEvent({
            category: 'feature_usage',
            action: 'page_view',
            label: page,
        });
    }

    /**
     * Track a feature usage.
     */
    static trackFeatureUsage(feature: string, details?: Record<string, any>): void {
        this.trackEvent({
            category: 'feature_usage',
            action: 'feature_used',
            label: feature,
            metadata: details,
        });
    }

    /**
     * Track an error (without sensitive details).
     */
    static trackError(errorType: string, errorCode?: string): void {
        this.trackEvent({
            category: 'error',
            action: errorType,
            label: errorCode,
        });
    }

    /**
     * Track performance metric.
     */
    static trackPerformance(metric: string, valueMs: number): void {
        this.trackEvent({
            category: 'performance',
            action: metric,
            value: Math.round(valueMs),
        });
    }

    /**
     * Sanitize metadata to remove any potential PII or sensitive data.
     */
    private static sanitizeMetadata(metadata?: Record<string, any>): Record<string, any> | undefined {
        if (!metadata) return undefined;

        const sensitiveKeys = [
            'email', 'password', 'token', 'key', 'secret', 'url', 'target',
            'ip', 'address', 'phone', 'name', 'user', 'scan', 'vuln',
            'finding', 'report', 'credential', 'api_key'
        ];

        const sanitized: Record<string, any> = {};

        for (const [key, value] of Object.entries(metadata)) {
            const lowerKey = key.toLowerCase();
            
            // Skip sensitive keys
            if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
                continue;
            }

            // Only include primitive values or arrays of primitives
            if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
                sanitized[key] = value;
            } else if (Array.isArray(value) && value.every(v => typeof v !== 'object')) {
                sanitized[key] = value;
            }
        }

        return Object.keys(sanitized).length > 0 ? sanitized : undefined;
    }

    /**
     * Flush queued events to database.
     */
    private static flushEvents(): void {
        if (this.eventQueue.length === 0 || !this.sessionInfo) return;

        const insertStmt = db.prepare(`
            INSERT INTO analytics_events (session_id, category, action, label, value, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        `);

        const updateAggregate = db.prepare(`
            INSERT INTO analytics_daily_aggregates (date, category, action, count, total_value)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(date, category, action) DO UPDATE SET
                count = count + 1,
                total_value = total_value + excluded.total_value
        `);

        const today = new Date().toISOString().split('T')[0];

        const transaction = db.transaction(() => {
            for (const event of this.eventQueue) {
                insertStmt.run(
                    this.sessionInfo!.sessionId,
                    event.category,
                    event.action,
                    event.label || null,
                    event.value || null,
                    event.metadata ? JSON.stringify(event.metadata) : null
                );

                // Update daily aggregates
                updateAggregate.run(today, event.category, event.action, event.value || 0);
            }
        });

        try {
            transaction();
            this.eventQueue = [];
        } catch (error) {
            logger.error('Failed to flush analytics events:', error);
        }
    }

    /**
     * Start periodic flush interval.
     */
    private static startFlushInterval(): void {
        // Flush every 30 seconds
        this.flushInterval = setInterval(() => {
            this.flushEvents();
        }, 30000);
    }

    /**
     * Enable or disable analytics tracking.
     */
    static setEnabled(enabled: boolean): void {
        this.isEnabled = enabled;
        logger.info(`Analytics tracking ${enabled ? 'enabled' : 'disabled'}`);
    }

    /**
     * Get analytics summary for the current session.
     */
    static getSessionSummary(): Record<string, any> {
        if (!this.sessionInfo) return {};

        const events = db.prepare(`
            SELECT category, action, COUNT(*) as count
            FROM analytics_events
            WHERE session_id = ?
            GROUP BY category, action
        `).all(this.sessionInfo.sessionId);

        return {
            sessionId: this.sessionInfo.sessionId,
            duration: Date.now() - this.sessionInfo.startedAt,
            eventCount: events.reduce((sum: number, e: any) => sum + e.count, 0),
            eventsByCategory: events,
        };
    }

    /**
     * Get aggregated analytics for a date range.
     */
    static getAggregatedAnalytics(startDate: string, endDate: string): any[] {
        return db.prepare(`
            SELECT date, category, action, count, total_value
            FROM analytics_daily_aggregates
            WHERE date >= ? AND date <= ?
            ORDER BY date DESC, count DESC
        `).all(startDate, endDate);
    }

    /**
     * Get feature usage stats.
     */
    static getFeatureUsageStats(days: number = 30): any[] {
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);
        
        return db.prepare(`
            SELECT action, label, SUM(count) as total_count
            FROM analytics_daily_aggregates
            WHERE category = 'feature_usage' AND date >= ?
            GROUP BY action, label
            ORDER BY total_count DESC
        `).all(startDate.toISOString().split('T')[0]);
    }
}

// Initialize on module load
AnalyticsService.initialize();

// Handle graceful shutdown
process.on('SIGINT', () => AnalyticsService.endSession());
process.on('SIGTERM', () => AnalyticsService.endSession());
process.on('exit', () => AnalyticsService.endSession());
