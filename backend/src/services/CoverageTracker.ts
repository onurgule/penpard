/**
 * CoverageTracker — Coverage-aware testing model.
 *
 * Tracks what has been seen, exercised, tested, and what remains.
 * Feeds coverage summaries into the LLM replanning prompt to prevent
 * shallow repetition and guide testing toward untested surface.
 */

import { logger } from '../utils/logger';

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface CoverageEntry {
    route: string;
    method: string;
    discoveredFrom: 'burp' | 'frontend-js' | 'browser-navigation' | 'sitemap' | 'manual';
    exercisedInBrowser: boolean;
    observedInBurp: boolean;
    promotedForTesting: boolean;
    hypothesisIds: string[];
    vulnClassesTested: Set<string>;
    lastTestedAt: Date | null;
}

export interface WorkflowCoverage {
    name: string;
    explored: boolean;
    steps: string[];
    completedSteps: string[];
}

export interface CoverageSummary {
    routesSeen: number;
    routesFromFrontend: number;
    routesExercisedInBrowser: number;
    requestsObservedInBurp: number;
    requestsPromoted: number;
    hypothesesActive: number;
    untestedRoutes: string[];
    weaklyTestedRoutes: string[];
    workflowStatus: Record<string, { explored: boolean; completeness: string }>;
    coveragePercentage: number;
}

// ─────────────────────────────────────────────────────────────
// Tracker
// ─────────────────────────────────────────────────────────────

export class CoverageTracker {
    private entries: Map<string, CoverageEntry> = new Map();
    private workflows: Map<string, WorkflowCoverage> = new Map();

    constructor() {
        // Initialize common workflows that get tracked
        const defaultWorkflows = ['login', 'registration', 'password-reset', 'checkout', 'profile-update', 'admin-access', 'file-upload', 'search'];
        for (const wf of defaultWorkflows) {
            this.workflows.set(wf, { name: wf, explored: false, steps: [], completedSteps: [] });
        }
    }

    // ─────────────────────────────────────────────────────────
    // Route Registration
    // ─────────────────────────────────────────────────────────

    /**
     * Register a discovered route.
     */
    addRoute(route: string, method: string, source: CoverageEntry['discoveredFrom']): void {
        const key = this.routeKey(method, route);
        if (this.entries.has(key)) {
            // Update source if discovered from a more authoritative source
            const existing = this.entries.get(key)!;
            if (source === 'burp' && !existing.observedInBurp) {
                existing.observedInBurp = true;
            }
            if (source === 'browser-navigation' && !existing.exercisedInBrowser) {
                existing.exercisedInBrowser = true;
            }
            return;
        }

        this.entries.set(key, {
            route,
            method,
            discoveredFrom: source,
            exercisedInBrowser: source === 'browser-navigation',
            observedInBurp: source === 'burp',
            promotedForTesting: false,
            hypothesisIds: [],
            vulnClassesTested: new Set(),
            lastTestedAt: null,
        });
    }

    /**
     * Register multiple routes at once (e.g., from frontend analysis).
     */
    addRoutesFromFrontend(endpoints: string[]): void {
        for (const ep of endpoints) {
            // Frontend endpoints don't have method info, default to GET
            this.addRoute(ep, 'GET', 'frontend-js');
        }
    }

    /**
     * Register routes observed in Burp proxy history.
     */
    addRoutesFromBurp(entries: Array<{ method: string; path: string }>): void {
        for (const entry of entries) {
            this.addRoute(entry.path, entry.method, 'burp');
        }
    }

    // ─────────────────────────────────────────────────────────
    // State Updates
    // ─────────────────────────────────────────────────────────

    /**
     * Mark a route as exercised in the browser.
     */
    markExercisedInBrowser(route: string, method: string = 'GET'): void {
        const key = this.routeKey(method, route);
        const entry = this.entries.get(key);
        if (entry) {
            entry.exercisedInBrowser = true;
        } else {
            this.addRoute(route, method, 'browser-navigation');
        }
    }

    /**
     * Mark a route as observed in Burp traffic.
     */
    markObservedInBurp(route: string, method: string): void {
        const key = this.routeKey(method, route);
        const entry = this.entries.get(key);
        if (entry) {
            entry.observedInBurp = true;
        } else {
            this.addRoute(route, method, 'burp');
        }
    }

    /**
     * Mark a route as promoted for active testing.
     */
    markPromoted(route: string, method: string): void {
        const key = this.routeKey(method, route);
        const entry = this.entries.get(key);
        if (entry) {
            entry.promotedForTesting = true;
        }
    }

    /**
     * Record that a vulnerability class was tested on a route.
     */
    markVulnTested(route: string, method: string, vulnClass: string, hypothesisId?: string): void {
        const key = this.routeKey(method, route);
        const entry = this.entries.get(key);
        if (entry) {
            entry.vulnClassesTested.add(vulnClass);
            entry.lastTestedAt = new Date();
            if (hypothesisId && !entry.hypothesisIds.includes(hypothesisId)) {
                entry.hypothesisIds.push(hypothesisId);
            }
        }
    }

    // ─────────────────────────────────────────────────────────
    // Workflow Tracking
    // ─────────────────────────────────────────────────────────

    /**
     * Mark a workflow as explored.
     */
    markWorkflowExplored(name: string): void {
        const wf = this.workflows.get(name);
        if (wf) {
            wf.explored = true;
        } else {
            this.workflows.set(name, { name, explored: true, steps: [], completedSteps: [] });
        }
    }

    /**
     * Auto-detect workflow from route.
     */
    inferWorkflowFromRoute(route: string): void {
        const routeLower = route.toLowerCase();
        if (/\/(login|signin|auth)/i.test(routeLower)) this.markWorkflowExplored('login');
        if (/\/(register|signup|create.account)/i.test(routeLower)) this.markWorkflowExplored('registration');
        if (/\/(password|reset|forgot)/i.test(routeLower)) this.markWorkflowExplored('password-reset');
        if (/\/(checkout|cart|order|purchase)/i.test(routeLower)) this.markWorkflowExplored('checkout');
        if (/\/(profile|account|settings)/i.test(routeLower)) this.markWorkflowExplored('profile-update');
        if (/\/(admin|manage|dashboard|panel)/i.test(routeLower)) this.markWorkflowExplored('admin-access');
        if (/\/(upload|file|attachment)/i.test(routeLower)) this.markWorkflowExplored('file-upload');
        if (/\/(search|find|query)/i.test(routeLower)) this.markWorkflowExplored('search');
    }

    // ─────────────────────────────────────────────────────────
    // Queries
    // ─────────────────────────────────────────────────────────

    /**
     * Get routes discovered in frontend JS but never observed in Burp traffic.
     */
    getFrontendOnlyRoutes(): string[] {
        return Array.from(this.entries.values())
            .filter(e => e.discoveredFrom === 'frontend-js' && !e.observedInBurp)
            .map(e => `${e.method} ${e.route}`);
    }

    /**
     * Get routes that were seen but never tested with any hypothesis.
     */
    getUntestedRoutes(): string[] {
        return Array.from(this.entries.values())
            .filter(e => e.vulnClassesTested.size === 0 && e.discoveredFrom !== 'frontend-js')
            .map(e => `${e.method} ${e.route}`);
    }

    /**
     * Get routes tested for fewer than 2 vulnerability classes.
     */
    getWeaklyTestedRoutes(): string[] {
        return Array.from(this.entries.values())
            .filter(e => e.promotedForTesting && e.vulnClassesTested.size < 2)
            .map(e => `${e.method} ${e.route} (tested: ${[...e.vulnClassesTested].join(', ')})`);
    }

    /**
     * Get complete coverage summary.
     */
    getSummary(): CoverageSummary {
        const all = Array.from(this.entries.values());
        const total = all.length;
        const promoted = all.filter(e => e.promotedForTesting).length;
        const tested = all.filter(e => e.vulnClassesTested.size > 0).length;
        const coveragePercentage = total > 0 ? Math.round((tested / total) * 100) : 0;

        const workflowStatus: Record<string, { explored: boolean; completeness: string }> = {};
        for (const [name, wf] of this.workflows) {
            workflowStatus[name] = {
                explored: wf.explored,
                completeness: wf.explored ? '✓' : '✗',
            };
        }

        return {
            routesSeen: total,
            routesFromFrontend: all.filter(e => e.discoveredFrom === 'frontend-js').length,
            routesExercisedInBrowser: all.filter(e => e.exercisedInBrowser).length,
            requestsObservedInBurp: all.filter(e => e.observedInBurp).length,
            requestsPromoted: promoted,
            hypothesesActive: all.reduce((sum, e) => sum + e.hypothesisIds.length, 0),
            untestedRoutes: this.getUntestedRoutes().slice(0, 10),
            weaklyTestedRoutes: this.getWeaklyTestedRoutes().slice(0, 10),
            workflowStatus,
            coveragePercentage,
        };
    }

    /**
     * Get a text summary for the LLM replanning prompt.
     */
    getSummaryForPrompt(): string {
        const s = this.getSummary();
        const lines: string[] = [
            `COVERAGE STATUS:`,
            `  Routes seen: ${s.routesSeen} | Browser-exercised: ${s.routesExercisedInBrowser} | Burp-observed: ${s.requestsObservedInBurp}`,
            `  Promoted for testing: ${s.requestsPromoted} | Coverage: ${s.coveragePercentage}%`,
        ];

        if (s.untestedRoutes.length > 0) {
            lines.push(`  Untested routes: ${s.untestedRoutes.slice(0, 5).join(', ')}`);
        }

        if (s.weaklyTestedRoutes.length > 0) {
            lines.push(`  Weakly tested: ${s.weaklyTestedRoutes.slice(0, 3).join(', ')}`);
        }

        const frontendOnly = this.getFrontendOnlyRoutes();
        if (frontendOnly.length > 0) {
            lines.push(`  Frontend-only (not yet in Burp): ${frontendOnly.slice(0, 5).join(', ')}`);
        }

        // Workflow summary
        const workflows = Array.from(this.workflows.values());
        const explored = workflows.filter(w => w.explored).map(w => w.name);
        const unexplored = workflows.filter(w => !w.explored).map(w => w.name);
        if (explored.length > 0) lines.push(`  Workflows explored: ${explored.join(', ')}`);
        if (unexplored.length > 0) lines.push(`  Workflows NOT explored: ${unexplored.join(', ')}`);

        return lines.join('\n');
    }

    /**
     * Reset tracker state.
     */
    clear(): void {
        this.entries.clear();
        for (const wf of this.workflows.values()) {
            wf.explored = false;
            wf.steps = [];
            wf.completedSteps = [];
        }
    }

    // ─────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────

    private routeKey(method: string, route: string): string {
        // Normalize: strip query string for key purposes, keep path
        let normalizedRoute = route;
        try {
            const idx = route.indexOf('?');
            if (idx !== -1) normalizedRoute = route.substring(0, idx);
        } catch { /* keep as-is */ }
        return `${method.toUpperCase()}:${normalizedRoute}`;
    }
}
