/**
 * Activity Monitor Service
 * 
 * Monitors user's Burp Proxy history in real-time to detect testing patterns.
 * When a pattern is detected (e.g., SQLi testing), it creates a suggestion
 * offering automated assistance.
 * 
 * Flow:
 * 1. Polls Burp extension's get_user_activity tool periodically
 * 2. Analyzes detected patterns (SQLi, XSS, LFI, etc.)
 * 3. Creates suggestions for the user
 * 4. Frontend polls for suggestions and shows alerts
 */

import { BurpMCPClient } from './burp-mcp';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

export interface ActivitySuggestion {
    id: string;
    type: 'sqli' | 'xss' | 'lfi' | 'cmdi' | 'ssrf' | 'general';
    title: string;
    message: string;
    endpoints: string[];
    targetHosts: string[];
    payloadExamples: string[];
    confidence: number; // 0-100
    createdAt: Date;
    status: 'pending' | 'accepted' | 'dismissed';
    dominantActivity: string;
}

interface ActivitySnapshot {
    totalUserRequests: number;
    dominantActivity: string;
    patterns: Record<string, number>;
    uniqueEndpoints: number;
    endpoints: string[];
    targetHosts: string[];
    payloadExamples: string[];
}

const SUGGESTION_MESSAGES: Record<string, { title: string; message: string }> = {
    sqli: {
        title: 'SQL Injection Testing Detected',
        message: 'It looks like you are testing SQL Injection payloads. PenPard can assist by running automated SQLi tests on these endpoints with comprehensive payloads, including time-based and boolean-based techniques.'
    },
    xss: {
        title: 'XSS Testing Detected',
        message: 'It looks like you are testing Cross-Site Scripting payloads. PenPard can run automated XSS tests with advanced payloads — including DOM-based, Stored, and Reflected XSS checks.'
    },
    lfi: {
        title: 'Local File Inclusion Testing Detected',
        message: 'It looks like you are testing path traversal / LFI payloads. PenPard can automatically test advanced directory traversal techniques (double encoding, null byte, filter bypass).'
    },
    cmdi: {
        title: 'Command Injection Testing Detected',
        message: 'It looks like you are testing command injection payloads. PenPard can automatically test blind command injection, out-of-band, and alternative delimiter techniques.'
    },
    ssrf: {
        title: 'SSRF Testing Detected',
        message: 'It looks like you are testing Server-Side Request Forgery payloads. PenPard can automatically test internal network scanning, cloud metadata, and DNS rebinding techniques.'
    }
};

export class ActivityMonitorService {
    private burp: BurpMCPClient;
    private isRunning: boolean = false;
    private pollInterval: NodeJS.Timeout | null = null;
    private suggestions: ActivitySuggestion[] = [];
    private lastPatternCounts: Record<string, number> = {};
    private pollIntervalMs: number = 8000; // Poll every 8 seconds
    private minRequestsForSuggestion: number = 3; // Minimum pattern hits to trigger suggestion
    private cooldownMs: number = 120000; // 2 minutes cooldown per pattern type
    private lastSuggestionTime: Record<string, number> = {};

    constructor() {
        this.burp = new BurpMCPClient();
    }

    async start(): Promise<boolean> {
        if (this.isRunning) {
            logger.info('[ActivityMonitor] Already running');
            return true;
        }

        // Check if Burp is available
        const burpAvailable = await this.burp.isAvailable();
        if (!burpAvailable) {
            logger.warn('[ActivityMonitor] Cannot start - Burp MCP not available');
            return false;
        }

        this.isRunning = true;
        this.lastPatternCounts = {};
        logger.info('[ActivityMonitor] Started monitoring user activity');

        // Start polling
        this.pollInterval = setInterval(() => this.poll(), this.pollIntervalMs);
        
        // Initial poll
        this.poll();
        
        return true;
    }

    stop(): void {
        this.isRunning = false;
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        logger.info('[ActivityMonitor] Stopped');
    }

    getStatus(): { running: boolean; suggestionCount: number; pendingCount: number } {
        return {
            running: this.isRunning,
            suggestionCount: this.suggestions.length,
            pendingCount: this.suggestions.filter(s => s.status === 'pending').length
        };
    }

    getPendingSuggestions(): ActivitySuggestion[] {
        return this.suggestions.filter(s => s.status === 'pending');
    }

    getAllSuggestions(): ActivitySuggestion[] {
        return [...this.suggestions];
    }

    acceptSuggestion(id: string): ActivitySuggestion | null {
        const suggestion = this.suggestions.find(s => s.id === id);
        if (suggestion) {
            suggestion.status = 'accepted';
            logger.info(`[ActivityMonitor] Suggestion accepted: ${suggestion.type}`, {
                endpoints: suggestion.endpoints
            });
        }
        return suggestion ?? null;
    }

    dismissSuggestion(id: string): ActivitySuggestion | null {
        const suggestion = this.suggestions.find(s => s.id === id);
        if (suggestion) {
            suggestion.status = 'dismissed';
            logger.info(`[ActivityMonitor] Suggestion dismissed: ${suggestion.type}`);
        }
        return suggestion ?? null;
    }

    private async poll(): Promise<void> {
        if (!this.isRunning) return;

        try {
            // Call the Burp extension's get_user_activity tool
            const result = await this.burp.callTool('get_user_activity', {
                count: 50,
                sinceMinutes: 5
            });

            if (!result) return;

            // Parse the result - it comes as MCP content
            let activity: ActivitySnapshot;
            try {
                const content = result.content?.[0]?.text || result.text || JSON.stringify(result);
                activity = JSON.parse(content);
            } catch (e) {
                // Result might already be parsed
                activity = result as any;
            }

            if (!activity || activity.totalUserRequests === 0) return;

            this.analyzeAndSuggest(activity);

        } catch (error: any) {
            // Don't log connection errors every 8 seconds - only log if it was previously working
            if (error.message && !error.message.includes('ECONNREFUSED')) {
                logger.warn('[ActivityMonitor] Poll error', { error: error.message });
            }
        }
    }

    private analyzeAndSuggest(activity: ActivitySnapshot): void {
        const { patterns, endpoints, targetHosts, payloadExamples, dominantActivity } = activity;

        if (!patterns || Object.keys(patterns).length === 0) return;

        // Check each detected pattern
        for (const [patternType, count] of Object.entries(patterns)) {
            // Need minimum requests to avoid false triggers
            if (count < this.minRequestsForSuggestion) continue;

            // Check if this is a NEW pattern (count increased since last check)
            const lastCount = this.lastPatternCounts[patternType] || 0;
            if (count <= lastCount) continue;

            // Cooldown check - don't suggest the same type too frequently
            const lastTime = this.lastSuggestionTime[patternType] || 0;
            if (Date.now() - lastTime < this.cooldownMs) continue;

            // Check if there's already a pending suggestion for this type
            const hasPending = this.suggestions.some(
                s => s.type === patternType && s.status === 'pending'
            );
            if (hasPending) continue;

            // Create suggestion
            const msgConfig = SUGGESTION_MESSAGES[patternType] || {
                title: `${patternType.toUpperCase()} Testing Detected`,
                message: `It looks like you are testing for ${patternType}. PenPard can assist with automated testing.`
            };

            const suggestion: ActivitySuggestion = {
                id: uuidv4(),
                type: patternType as ActivitySuggestion['type'],
                title: msgConfig.title,
                message: msgConfig.message,
                endpoints: endpoints.slice(0, 10),
                targetHosts: targetHosts || [],
                payloadExamples: payloadExamples.filter(p => 
                    p.toLowerCase().includes(patternType.toLowerCase())
                ).slice(0, 5),
                confidence: Math.min(100, Math.round((count / 10) * 100)),
                createdAt: new Date(),
                status: 'pending',
                dominantActivity: dominantActivity
            };

            this.suggestions.push(suggestion);
            this.lastSuggestionTime[patternType] = Date.now();

            logger.info(`[ActivityMonitor] New suggestion created: ${patternType}`, {
                confidence: suggestion.confidence,
                endpointCount: endpoints.length,
                patternCount: count
            });
        }

        // Update last known counts
        this.lastPatternCounts = { ...patterns };

        // Cleanup old suggestions (keep last 20)
        if (this.suggestions.length > 20) {
            this.suggestions = this.suggestions.slice(-20);
        }
    }
}

// Singleton instance
export const activityMonitor = new ActivityMonitorService();
