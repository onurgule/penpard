/**
 * ScanCoverageGraphScoring.ts
 *
 * Pure functions for computing risk scores and severity ordering
 * on coverage graph nodes. Risk scores drive the visual color gradient
 * from slate (safe) through amber/orange to red (critical).
 */

// ─────────────────────────────────────────────────────────────
// Severity Weights
// ─────────────────────────────────────────────────────────────

const SEVERITY_WEIGHT: Record<string, number> = {
    critical: 1.0,
    high: 0.8,
    medium: 0.5,
    low: 0.2,
    info: 0.1,
    informational: 0.1,
};

const SEVERITY_ORDER: string[] = ['critical', 'high', 'medium', 'low', 'info', 'informational'];

/**
 * Convert a severity string to a numeric weight (0.0–1.0).
 */
export function severityToWeight(severity: string): number {
    return SEVERITY_WEIGHT[severity?.toLowerCase()] ?? 0;
}

// ─────────────────────────────────────────────────────────────
// Risk Scoring
// ─────────────────────────────────────────────────────────────

/**
 * Compute a risk score (0.0–1.0) for a node based on its matched
 * vulnerability severities. The score is the max of all matched
 * severity weights, with a small additive bonus per extra vulnerability
 * (so 3 mediums ranks higher than 1 medium).
 */
export function computeNodeRiskScore(vulnSeverities: string[]): number {
    if (vulnSeverities.length === 0) return 0;

    const maxWeight = Math.max(...vulnSeverities.map(severityToWeight));
    // Small additive bonus: each additional vuln adds 0.02, capped at 0.15
    const countBonus = Math.min((vulnSeverities.length - 1) * 0.02, 0.15);

    return Math.min(1.0, maxWeight + countBonus);
}

/**
 * Return the highest (most severe) severity from a list.
 */
export function computeHighestSeverity(severities: string[]): string | null {
    if (severities.length === 0) return null;

    let bestIndex = SEVERITY_ORDER.length;
    let bestSeverity: string | null = null;

    for (const sev of severities) {
        const idx = SEVERITY_ORDER.indexOf(sev?.toLowerCase());
        if (idx !== -1 && idx < bestIndex) {
            bestIndex = idx;
            bestSeverity = sev.toLowerCase();
        }
    }

    return bestSeverity;
}
