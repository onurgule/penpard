/**
 * ScanCoverageGraph.types.ts — Frontend mirror of backend graph types.
 */

export interface RequestVariant {
    fullPath: string;
    method: string;
    statusCode: number | null;
    source: string;
    lastSeen: string | null;
}

export interface CoverageGraphNode {
    id: string;
    label: string;
    canonicalRoute: string;
    methods: string[];
    clusterId: string;
    classification: string;
    authRelevant: boolean;
    sources: string[];
    requestVariants: RequestVariant[];
    foldedCount: number;
    attemptedAttackTypes: string[];
    confirmedIssueTypes: string[];
    matchedVulnerabilityIds: number[];
    matchedVulnerabilities: Array<{
        id: number;
        name: string;
        severity: string;
        cwe?: string;
    }>;
    highestSeverity: string | null;
    riskScore: number;
    isActive: boolean;
}

export type CoverageGraphEdgeType = 'navigation' | 'structural';

export interface CoverageGraphEdge {
    id: string;
    source: string;
    target: string;
    type: CoverageGraphEdgeType;
    count: number;
}

export interface CoverageGraphCluster {
    id: string;
    label: string;
    nodeCount: number;
    maxSeverity: string | null;
}

export interface CoverageGraphStats {
    totalNodes: number;
    vulnerableNodes: number;
    coveragePercentage: number;
    activePath: string | null;
    recentPath: string[];
    navigationEdgeCount: number;
    structuralEdgeCount: number;
}

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
