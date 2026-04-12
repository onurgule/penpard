/**
 * ScanCoverageGraph.types.ts
 *
 * Shared type definitions for the coverage graph projection layer.
 * The graph represents CANONICAL APPLICATION ROUTES, not raw network requests.
 * Nodes are normalized, deduplicated base routes.  Edges are directed
 * navigation transitions with counts.
 *
 * Design rule: DERIVED READ MODEL — recomputed every poll cycle.
 */

// ─────────────────────────────────────────────────────────────
// Node
// ─────────────────────────────────────────────────────────────

/** A single raw request variant folded into a canonical route node. */
export interface RequestVariant {
    /** Full original path including query/hash */
    fullPath: string;
    /** HTTP method */
    method: string;
    /** Last observed status code (null if unknown) */
    statusCode: number | null;
    /** Discovery source: browser, burp, js, inferred */
    source: string;
    /** When this variant was last seen (ISO string or null) */
    lastSeen: string | null;
}

export interface CoverageGraphNode {
    /** Stable identifier = canonical normalized route (e.g. '/login') */
    id: string;
    /** Short human-readable label for graph display (e.g. '/login') */
    label: string;
    /** Canonical normalized base route */
    canonicalRoute: string;
    /** HTTP methods observed across all request variants */
    methods: string[];
    /** Cluster this node belongs to */
    clusterId: string;
    /** Auth classification from endpoint intelligence */
    classification: string;
    /** Whether this endpoint is auth-relevant */
    authRelevant: boolean;
    /** Discovery sources (browser, burp, js, inferred) */
    sources: string[];
    /** All raw request variants folded into this canonical route */
    requestVariants: RequestVariant[];
    /** Number of original endpoint records folded into this node */
    foldedCount: number;
    /** Attack types attempted against this route */
    attemptedAttackTypes: string[];
    /** Confirmed vulnerability types */
    confirmedIssueTypes: string[];
    /** IDs of vulnerabilities matched to this route */
    matchedVulnerabilityIds: number[];
    /** Matched vulnerability summaries for detail panel */
    matchedVulnerabilities: Array<{
        id: number;
        name: string;
        severity: string;
        cwe?: string;
    }>;
    /** The highest severity among matched vulnerabilities */
    highestSeverity: string | null;
    /** Risk score 0.0–1.0 */
    riskScore: number;
    /** Whether this is the currently active route */
    isActive: boolean;
}

// ─────────────────────────────────────────────────────────────
// Edge — directed with counts
// ─────────────────────────────────────────────────────────────

export type CoverageGraphEdgeType = 'navigation' | 'structural';

export interface CoverageGraphEdge {
    id: string;
    /** Source node id (from) */
    source: string;
    /** Target node id (to) */
    target: string;
    type: CoverageGraphEdgeType;
    /** Number of times this transition was observed */
    count: number;
}

// ─────────────────────────────────────────────────────────────
// Cluster
// ─────────────────────────────────────────────────────────────

export interface CoverageGraphCluster {
    id: string;
    label: string;
    nodeCount: number;
    maxSeverity: string | null;
}

// ─────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────

export interface CoverageGraphStats {
    totalNodes: number;
    vulnerableNodes: number;
    coveragePercentage: number;
    activePath: string | null;
    /** Recent navigation path chain, e.g. ['/', '/invite', '/login'] */
    recentPath: string[];
    /** Count of navigation (observed transition) edges */
    navigationEdgeCount: number;
    /** Count of structural (inferred cluster) edges */
    structuralEdgeCount: number;
}

// ─────────────────────────────────────────────────────────────
// Snapshot
// ─────────────────────────────────────────────────────────────

export interface CoverageGraphSnapshot {
    scanId: string;
    generatedAt: string;
    currentUrl: string | null;
    activeNodeId: string | null;
    stats: CoverageGraphStats;
    clusters: CoverageGraphCluster[];
    nodes: CoverageGraphNode[];
    edges: CoverageGraphEdge[];
}

// ─────────────────────────────────────────────────────────────
// Projector Input (internal)
// ─────────────────────────────────────────────────────────────

export interface CoverageGraphProjectorInput {
    scanId: string;
    /** Target URL origin for the scan (used for third-party filtering) */
    targetOrigin: string | null;
    endpointInventory: {
        records: Array<{
            id: string;
            endpoint: string;
            path: string;
            methods: string[];
            classification: string;
            likelyAuthRelevant: boolean;
            observedInBurp: boolean;
            exercisedInBrowser: boolean;
            inferredOnly: boolean;
        }>;
    } | null;
    vulnerabilities: Array<{
        id: number;
        name: string;
        severity: string;
        request?: string;
        response?: string;
        evidence?: string;
        cwe?: string;
    }>;
    browserActions: Array<{
        page_url?: string;
        action_type: string;
        timestamp?: string;
    }>;
    currentUrl: string | null;
    coverageSummary: {
        coveragePercentage: number;
    } | null;
}
