/**
 * ScanCoverageGraphProjector.ts
 *
 * Projects a CoverageGraphSnapshot from existing scan data.
 *
 * v3 Pipeline:
 *   1. Filter noise (assets, vendor, telemetry, third-party origins)
 *   2. Normalize each endpoint path to canonical base route (resource-level)
 *   3. Fold duplicate base routes into single nodes with RequestVariant[]
 *   4. Assign business-oriented clusters (Authentication, Commerce, Admin, etc.)
 *   5. Match vulnerabilities to canonical nodes
 *   6. Build directed edges from browser navigation with counts
 *   7. Fill structural edges for isolated cluster members
 *   8. Mark active node + compute recent path chain
 *   9. Compute aggregate stats with edge counts
 */

import type {
    CoverageGraphCluster,
    CoverageGraphEdge,
    CoverageGraphNode,
    CoverageGraphProjectorInput,
    CoverageGraphSnapshot,
    CoverageGraphStats,
    RequestVariant,
} from './ScanCoverageGraph.types';
import {
    normalizeToCanonicalRoute,
    isNoisePath,
    isThirdPartyUrl,
    matchAllVulnsToNodes,
    inferAttackTypes,
    extractPathFromUrl,
} from './ScanCoverageGraphMatchers';
import { computeHighestSeverity, computeNodeRiskScore } from './ScanCoverageGraphScoring';

// =====================================================================
//  CLUSTERING - business-oriented route groups (v3)
// =====================================================================

/** Cluster assignment rules - evaluated in order, first match wins. */
const CLUSTER_RULES: Array<{ id: string; label: string; test: (route: string, classification: string) => boolean }> = [
    // System cluster FIRST to prevent socket/engine.io misclassification
    {
        id: 'cluster-system',
        label: 'System',
        test: (route) => {
            if (/^\/(socket\.?io|engine\.?io|health|status|metrics|version|actuator|robots)\b/i.test(route)) return true;
            if (/^\/:[a-z]/i.test(route)) return true;
            return false;
        },
    },
    {
        id: 'cluster-auth',
        label: 'Authentication',
        test: (route, cls) => {
            // Path-based auth detection
            if (/\/(login|logout|signin|signup|register|auth|forgot|reset|verify|confirm|password|token|oauth|sso|whoami|session|2fa|mfa)\b/i.test(route)) return true;
            if (/^\/rest\/user\b/i.test(route)) return true;
            // Classification-based fallback
            const authCls = new Set(['login', 'register', 'forgot_password', 'reset_password', 'session_bootstrap', 'auth_refresh', 'logout', 'auth_gateway']);
            return authCls.has(cls);
        },
    },
    {
        id: 'cluster-admin',
        label: 'Admin',
        test: (route) => /^\/(dashboard|admin|panel|management|console)\b/i.test(route) ||
            /^\/rest\/admin\b/i.test(route) ||
            /^\/api\/admin\b/i.test(route),
    },
    {
        id: 'cluster-commerce',
        label: 'Commerce',
        test: (route) => /^\/(checkout|basket|cart|order|payment|billing|purchase|shop|products?)\b/i.test(route) ||
            /^\/rest\/(basket|products?|orders?|delivery|address|payment|quantitychange)\b/i.test(route) ||
            /^\/api\/(basket|products?|orders?|delivery|payment)\b/i.test(route),
    },
    {
        id: 'cluster-account',
        label: 'Account',
        test: (route) => /^\/(account|settings|profile|preferences|users?|member)\b/i.test(route) ||
            /^\/rest\/(wallet|addresss?|recycles?|erasure|data-export|security)\b/i.test(route),
    },
    {
        id: 'cluster-api',
        label: 'API',
        test: (route) => /^\/(api|graphql|rest)\b/i.test(route),
    },
    {
        id: 'cluster-public',
        label: 'Public',
        test: (route) => {
            if (route === '/') return true;
            return /^\/(blog|posts?|pages?|articles?|news|docs|help|faq|about|contact|terms|privacy|score-?board|challenges?|invite|join|share|referral|captcha|track-result|complain|chatbot|snippet|promotion|redirect|video|photo-wall)\b/i.test(route) ||
                /^\/rest\/(captcha|track-result|chatbot|country-mapping|languages|continue-code|memories)\b/i.test(route);
        },
    },
];

function assignCluster(route: string, classification: string): { id: string; label: string } {
    for (const rule of CLUSTER_RULES) {
        if (rule.test(route, classification)) {
            return { id: rule.id, label: rule.label };
        }
    }
    return { id: 'cluster-misc', label: 'Misc' };
}

// =====================================================================
//  NODE LABEL - full canonical for API, short for pages (v3)
// =====================================================================

function deriveNodeLabel(canonicalRoute: string): string {
    if (canonicalRoute === '/') return '/';
    // Show full canonical route for readability - truncation happens in frontend
    return canonicalRoute;
}

// =====================================================================
//  DIRECTED EDGE BUILDING - navigation transitions with counts
// =====================================================================

interface DirectedEdgeData {
    edges: CoverageGraphEdge[];
    recentPath: string[]; // last N distinct canonical routes visited
}

function buildDirectedNavigationEdges(
    browserActions: CoverageGraphProjectorInput['browserActions'],
    nodesByCanonical: Map<string, string>, // canonical route -> node id
    targetOrigin: string | null,
): DirectedEdgeData {
    const edgeCounts = new Map<string, number>(); // "sourceId->targetId" -> count
    const recentCanonical: string[] = [];

    // Sort by timestamp
    const sorted = [...browserActions]
        .filter(a => a.page_url)
        .sort((a, b) => {
            const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
            const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
            return ta - tb;
        });

    let prevNodeId: string | null = null;

    for (const action of sorted) {
        if (!action.page_url) continue;

        // Filter third-party URLs
        if (targetOrigin && isThirdPartyUrl(action.page_url, targetOrigin)) continue;

        let pathStr: string;
        try { pathStr = new URL(action.page_url).pathname; }
        catch { pathStr = action.page_url; }

        // Filter noise paths
        if (isNoisePath(pathStr)) continue;

        const canonical = normalizeToCanonicalRoute(pathStr);
        const nodeId = nodesByCanonical.get(canonical);

        if (nodeId && prevNodeId && nodeId !== prevNodeId) {
            const edgeKey = `${prevNodeId}->${nodeId}`;
            edgeCounts.set(edgeKey, (edgeCounts.get(edgeKey) || 0) + 1);
        }

        if (nodeId) {
            prevNodeId = nodeId;
            // Track recent path
            if (recentCanonical.length === 0 || recentCanonical[recentCanonical.length - 1] !== canonical) {
                recentCanonical.push(canonical);
            }
        }
    }

    // Build edge objects
    const edges: CoverageGraphEdge[] = [];
    let idx = 0;
    for (const [key, count] of edgeCounts) {
        const [source, target] = key.split('->');
        edges.push({
            id: `edge-nav-${++idx}`,
            source,
            target,
            type: 'navigation',
            count,
        });
    }

    // Keep last 8 unique routes as the recent path chain
    const recentPath = recentCanonical.slice(-8);

    return { edges, recentPath };
}

function buildStructuralEdges(
    nodes: CoverageGraphNode[],
    navEdgeNodeIds: Set<string>,
): CoverageGraphEdge[] {
    const edges: CoverageGraphEdge[] = [];
    let idx = 0;

    // Group nodes by cluster
    const clusterGroups = new Map<string, CoverageGraphNode[]>();
    for (const node of nodes) {
        const group = clusterGroups.get(node.clusterId) || [];
        group.push(node);
        clusterGroups.set(node.clusterId, group);
    }

    // Connect isolated nodes within a cluster
    for (const [, group] of clusterGroups) {
        if (group.length < 2) continue;
        for (let i = 0; i < group.length - 1; i++) {
            const src = group[i].id;
            const tgt = group[i + 1].id;
            // Only if at least one node has no nav edges
            if (navEdgeNodeIds.has(src) && navEdgeNodeIds.has(tgt)) continue;
            edges.push({
                id: `edge-struct-${++idx}`,
                source: src,
                target: tgt,
                type: 'structural',
                count: 0,
            });
        }
    }

    return edges;
}

// =====================================================================
//  MAIN PROJECTOR
// =====================================================================

export function projectCoverageGraph(input: CoverageGraphProjectorInput): CoverageGraphSnapshot | null {
    const { scanId, targetOrigin, endpointInventory, vulnerabilities, browserActions, currentUrl, coverageSummary } = input;

    if (!endpointInventory?.records?.length) return null;

    // 1. Filter + normalize + fold
    const foldMap = new Map<string, {
        canonicalRoute: string;
        methods: Set<string>;
        classifications: string[];
        authRelevant: boolean;
        sources: Set<string>;
        variants: RequestVariant[];
        originalIds: string[];
    }>();

    for (const record of endpointInventory.records) {
        // Filter: skip noise paths
        if (isNoisePath(record.path)) continue;

        // Filter: skip third-party origins
        if (record.endpoint && targetOrigin && isThirdPartyUrl(record.endpoint, targetOrigin)) continue;

        // Normalize to canonical base route (v3: resource-level)
        const canonical = normalizeToCanonicalRoute(record.path);

        // Skip root-level noise that slipped through
        if (canonical === '/' && record.path !== '/' && record.path !== '') continue;

        // Skip extremely short paths (1-2 char segments) - almost always noise
        const canonicalSegments = canonical.split('/').filter(Boolean);
        if (canonicalSegments.length === 1 && canonicalSegments[0].length <= 2) continue;

        const existing = foldMap.get(canonical);
        const source = record.observedInBurp ? 'burp' : record.exercisedInBrowser ? 'browser' : record.inferredOnly ? 'inferred' : 'js';

        const variant: RequestVariant = {
            fullPath: record.path,
            method: record.methods.join(', '),
            statusCode: null,
            source,
            lastSeen: null,
        };

        if (existing) {
            for (const m of record.methods) existing.methods.add(m);
            existing.classifications.push(record.classification);
            existing.authRelevant = existing.authRelevant || record.likelyAuthRelevant;
            existing.sources.add(source);
            existing.variants.push(variant);
            existing.originalIds.push(record.id);
        } else {
            foldMap.set(canonical, {
                canonicalRoute: canonical,
                methods: new Set(record.methods),
                classifications: [record.classification],
                authRelevant: record.likelyAuthRelevant,
                sources: new Set([source]),
                variants: [variant],
                originalIds: [record.id],
            });
        }
    }

    if (foldMap.size === 0) return null;

    // 2. Build nodes from folded data
    const nodes: CoverageGraphNode[] = [];
    const nodesByCanonical = new Map<string, string>(); // canonical -> nodeId

    for (const [canonical, data] of foldMap) {
        const nodeId = `route-${canonical.replace(/[^a-z0-9/-]/g, '_')}`;
        const primaryClassification = data.classifications[0] || 'general';
        const cluster = assignCluster(canonical, primaryClassification);

        const node: CoverageGraphNode = {
            id: nodeId,
            label: deriveNodeLabel(canonical),
            canonicalRoute: canonical,
            methods: Array.from(data.methods),
            clusterId: cluster.id,
            classification: primaryClassification,
            authRelevant: data.authRelevant,
            sources: Array.from(data.sources),
            requestVariants: data.variants,
            foldedCount: data.originalIds.length,
            attemptedAttackTypes: [],
            confirmedIssueTypes: [],
            matchedVulnerabilityIds: [],
            matchedVulnerabilities: [],
            highestSeverity: null,
            riskScore: 0,
            isActive: false,
        };

        nodes.push(node);
        nodesByCanonical.set(canonical, nodeId);
    }

    // 3. Match vulnerabilities to nodes
    const vulnMatches = matchAllVulnsToNodes(vulnerabilities, nodes);

    for (const node of nodes) {
        const matches = vulnMatches.get(node.id);
        if (!matches?.length) continue;

        node.matchedVulnerabilityIds = matches.map(m => m.vulnId);
        node.matchedVulnerabilities = matches.map(m => ({
            id: m.vulnId,
            name: m.vulnName,
            severity: m.severity,
            cwe: m.cwe,
        }));
        const severities = matches.map(m => m.severity);
        node.highestSeverity = computeHighestSeverity(severities);
        node.riskScore = computeNodeRiskScore(severities);

        const attackTypes = new Set<string>();
        const issueTypes = new Set<string>();
        for (const match of matches) {
            const vuln = vulnerabilities.find(v => v.id === match.vulnId);
            if (vuln) {
                for (const t of inferAttackTypes(vuln.name, vuln.cwe)) {
                    attackTypes.add(t);
                    issueTypes.add(t);
                }
            }
        }
        node.attemptedAttackTypes = Array.from(attackTypes);
        node.confirmedIssueTypes = Array.from(issueTypes);
    }

    // 4. Mark active node
    let activeNodeId: string | null = null;
    if (currentUrl) {
        let currentPath: string;
        try { currentPath = new URL(currentUrl).pathname; } catch { currentPath = currentUrl; }
        const currentCanonical = normalizeToCanonicalRoute(currentPath);
        const directMatch = nodesByCanonical.get(currentCanonical);
        if (directMatch) {
            activeNodeId = directMatch;
        } else {
            // Partial match: find node whose canonical route is a prefix of current
            let bestLen = 0;
            for (const node of nodes) {
                if (currentCanonical.startsWith(node.canonicalRoute) && node.canonicalRoute.length > bestLen) {
                    bestLen = node.canonicalRoute.length;
                    activeNodeId = node.id;
                }
            }
        }
        if (activeNodeId) {
            const activeNode = nodes.find(n => n.id === activeNodeId);
            if (activeNode) activeNode.isActive = true;
        }
    }

    // 5. Build clusters
    const clusterMap = new Map<string, CoverageGraphCluster>();
    for (const node of nodes) {
        const existing = clusterMap.get(node.clusterId);
        if (existing) {
            existing.nodeCount++;
            if (node.highestSeverity) {
                existing.maxSeverity = computeHighestSeverity(
                    [existing.maxSeverity, node.highestSeverity].filter(Boolean) as string[]
                );
            }
        } else {
            const cluster = assignCluster(node.canonicalRoute, node.classification);
            clusterMap.set(node.clusterId, {
                id: node.clusterId,
                label: cluster.label,
                nodeCount: 1,
                maxSeverity: node.highestSeverity,
            });
        }
    }
    const clusters = Array.from(clusterMap.values());

    // 6. Build directed edges
    const { edges: navEdges, recentPath } = buildDirectedNavigationEdges(
        browserActions, nodesByCanonical, targetOrigin
    );

    const navEdgeNodeIds = new Set<string>();
    for (const edge of navEdges) {
        navEdgeNodeIds.add(edge.source);
        navEdgeNodeIds.add(edge.target);
    }

    const structEdges = buildStructuralEdges(nodes, navEdgeNodeIds);
    const edges = [...navEdges, ...structEdges];

    // 7. Compute stats (v3: include edge counts)
    const vulnerableNodes = nodes.filter(n => n.matchedVulnerabilityIds.length > 0).length;
    const activePath = activeNodeId
        ? (nodes.find(n => n.id === activeNodeId)?.canonicalRoute || null)
        : null;

    const stats: CoverageGraphStats = {
        totalNodes: nodes.length,
        vulnerableNodes,
        coveragePercentage: coverageSummary?.coveragePercentage ?? 0,
        activePath,
        recentPath,
        navigationEdgeCount: navEdges.length,
        structuralEdgeCount: structEdges.length,
    };

    return {
        scanId,
        generatedAt: new Date().toISOString(),
        currentUrl,
        activeNodeId,
        stats,
        clusters,
        nodes,
        edges,
    };
}
