/**
 * scan-coverage-graph.utils.ts
 *
 * Layout, color mapping, and label utilities for the SVG graph renderer.
 *
 * v4 Visual Language:
 *  - Cluster background = category color (soft tint)
 *  - Node fill = neutral gray (always)
 *  - Node border/ring = risk level
 *  - Badge = vulnerability count
 *  - Glow = active/current node
 *  - Edge = flow
 */

import type { CoverageGraphNode, CoverageGraphCluster, CoverageGraphEdge } from './ScanCoverageGraph.types';

// =====================================================================
// COLOR CONSTANTS (v4 design tokens)
// =====================================================================

export const COLORS = {
    // Backgrounds
    appBg: '#0f172a',
    panelBg: '#111827',
    canvasBg: '#0b1220',

    // Nodes
    nodeFill: '#6b7280',
    nodeFillHover: '#7c8594',
    nodeBorderDefault: '#94a3b8',

    // Risk borders
    riskLow: '#f59e0b',
    riskMedium: '#fb923c',
    riskHigh: '#ef4444',
    riskCritical: '#ef4444',

    // Active / selection
    activeRing: '#22d3ee',
    activeGlow: 'rgba(34,211,238,0.25)',
    selectedRing: '#22d3ee',

    // Inferred
    inferredBorder: '#a78bfa',

    // Edges
    edgeDefault: 'rgba(148,163,184,0.22)',
    edgeNav: 'rgba(148,163,184,0.32)',
    edgeSelected: 'rgba(34,211,238,0.75)',

    // Badge
    badgeFill: '#dc2626',
    badgeStroke: '#0f172a',
    authBadge: '#f59e0b',

    // Text
    labelDefault: '#94a3b8',
    labelSelected: '#e2e8f0',
    labelDimmed: '#475569',
    methodText: '#64748b',
} as const;

// =====================================================================
// CLUSTER COLOR PALETTE (v4: softer, category-only)
// =====================================================================

interface ClusterPalette {
    clusterBg: string;
    clusterBgSelected: string;
    labelColor: string;
    borderColor: string;
}

const CLUSTER_PALETTES: Record<string, ClusterPalette> = {
    'cluster-auth': {
        clusterBg: 'rgba(251,191,36,0.06)',
        clusterBgSelected: 'rgba(251,191,36,0.12)',
        labelColor: '#d97706',
        borderColor: 'rgba(251,191,36,0.12)',
    },
    'cluster-api': {
        clusterBg: 'rgba(96,165,250,0.06)',
        clusterBgSelected: 'rgba(96,165,250,0.12)',
        labelColor: '#3b82f6',
        borderColor: 'rgba(96,165,250,0.10)',
    },
    'cluster-admin': {
        clusterBg: 'rgba(192,132,252,0.06)',
        clusterBgSelected: 'rgba(192,132,252,0.12)',
        labelColor: '#a855f7',
        borderColor: 'rgba(192,132,252,0.10)',
    },
    'cluster-commerce': {
        clusterBg: 'rgba(251,146,60,0.06)',
        clusterBgSelected: 'rgba(251,146,60,0.12)',
        labelColor: '#f97316',
        borderColor: 'rgba(251,146,60,0.10)',
    },
    'cluster-account': {
        clusterBg: 'rgba(52,211,153,0.06)',
        clusterBgSelected: 'rgba(52,211,153,0.12)',
        labelColor: '#10b981',
        borderColor: 'rgba(52,211,153,0.10)',
    },
    'cluster-public': {
        clusterBg: 'rgba(129,140,248,0.06)',
        clusterBgSelected: 'rgba(129,140,248,0.12)',
        labelColor: '#6366f1',
        borderColor: 'rgba(129,140,248,0.10)',
    },
    'cluster-system': {
        clusterBg: 'rgba(148,163,184,0.04)',
        clusterBgSelected: 'rgba(148,163,184,0.08)',
        labelColor: '#94a3b8',
        borderColor: 'rgba(148,163,184,0.08)',
    },
    'cluster-root': {
        clusterBg: 'rgba(148,163,184,0.04)',
        clusterBgSelected: 'rgba(148,163,184,0.08)',
        labelColor: '#94a3b8',
        borderColor: 'rgba(148,163,184,0.08)',
    },
};

const DEFAULT_PALETTE: ClusterPalette = {
    clusterBg: 'rgba(100,116,139,0.05)',
    clusterBgSelected: 'rgba(100,116,139,0.10)',
    labelColor: '#64748b',
    borderColor: 'rgba(100,116,139,0.08)',
};

export function getClusterPalette(clusterId: string): ClusterPalette {
    return CLUSTER_PALETTES[clusterId] || DEFAULT_PALETTE;
}

// =====================================================================
// NODE COLORS (v4: always gray fill, risk on border only)
// =====================================================================

/** Node fill is ALWAYS neutral gray. Risk is indicated via border. */
export function nodeColor(_node: CoverageGraphNode): string {
    return COLORS.nodeFill;
}

/** Risk border color based on score */
export function riskBorderColor(riskScore: number): string {
    if (riskScore <= 0) return COLORS.nodeBorderDefault;
    if (riskScore <= 0.15) return COLORS.riskLow;
    if (riskScore <= 0.4) return COLORS.riskMedium;
    return COLORS.riskHigh;
}

/** Node stroke: active > risk > inferred > default */
export function nodeStrokeColor(node: CoverageGraphNode): string {
    if (node.isActive) return COLORS.activeRing;
    if (node.riskScore > 0) return riskBorderColor(node.riskScore);
    const isInferredOnly = node.sources.length === 1 && node.sources[0] === 'inferred';
    if (isInferredOnly) return COLORS.inferredBorder;
    return COLORS.nodeBorderDefault;
}

/** Stroke width varies with risk */
export function nodeStrokeWidth(node: CoverageGraphNode, isSelected: boolean): number {
    if (isSelected) return 2.5;
    if (node.riskScore > 0.4) return 2.5;
    if (node.riskScore > 0) return 2;
    return 1.5;
}

/** Risk glow ring color (subtle background ring behind vulnerable nodes) */
export function riskGlowColor(riskScore: number): string {
    if (riskScore <= 0) return 'transparent';
    if (riskScore <= 0.15) return 'rgba(245,158,11,0.20)';
    if (riskScore <= 0.4) return 'rgba(251,146,60,0.25)';
    return 'rgba(239,68,68,0.30)';
}

export function severityToColor(sev: string | null): string {
    switch (sev?.toLowerCase()) {
        case 'critical': return '#dc2626';
        case 'high': return '#ef4444';
        case 'medium': return '#fb923c';
        case 'low': return '#f59e0b';
        case 'info': case 'informational': return '#22d3ee';
        default: return '#475569';
    }
}

export function clusterBgColor(cluster: CoverageGraphCluster, isSelected: boolean): string {
    const palette = getClusterPalette(cluster.id);
    return isSelected ? palette.clusterBgSelected : palette.clusterBg;
}

export function clusterLabelColor(cluster: CoverageGraphCluster): string {
    return getClusterPalette(cluster.id).labelColor;
}

export function clusterBorderColor(cluster: CoverageGraphCluster, isSelected: boolean): string {
    const palette = getClusterPalette(cluster.id);
    return isSelected ? palette.labelColor + '33' : palette.borderColor;
}

// =====================================================================
// DYNAMIC SCALE - adapt sizes to node count
// =====================================================================

export interface DynamicScale {
    nodeRadius: number;
    nodeSpacing: number;
    maxNodesPerRow: number;
    labelFontSize: number;
    methodFontSize: number;
    clusterHeaderFontSize: number;
    clusterPad: number;
    padding: number;
    isCompact: boolean;
}

export function computeDynamicScale(totalNodes: number, _width: number, _height: number): DynamicScale {
    if (totalNodes <= 8) {
        return {
            nodeRadius: 16, nodeSpacing: 65, maxNodesPerRow: 4,
            labelFontSize: 10, methodFontSize: 7.5,
            clusterHeaderFontSize: 10, clusterPad: 18, padding: 30,
            isCompact: false,
        };
    }
    if (totalNodes <= 20) {
        return {
            nodeRadius: 13, nodeSpacing: 52, maxNodesPerRow: 4,
            labelFontSize: 9, methodFontSize: 7,
            clusterHeaderFontSize: 9, clusterPad: 14, padding: 24,
            isCompact: false,
        };
    }
    if (totalNodes <= 40) {
        return {
            nodeRadius: 10, nodeSpacing: 42, maxNodesPerRow: 5,
            labelFontSize: 7.5, methodFontSize: 0, // hide methods in compact
            clusterHeaderFontSize: 8, clusterPad: 10, padding: 18,
            isCompact: true,
        };
    }
    // 40+ nodes - ultra compact
    return {
        nodeRadius: 7, nodeSpacing: 30, maxNodesPerRow: 6,
        labelFontSize: 6, methodFontSize: 0,
        clusterHeaderFontSize: 7, clusterPad: 8, padding: 12,
        isCompact: true,
    };
}

// =====================================================================
// LAYOUT - clustered grid with dynamic sizing
// =====================================================================

export interface LayoutResult {
    nodePositions: Map<string, { x: number; y: number }>;
    clusterBounds: Map<string, { x: number; y: number; w: number; h: number }>;
    scale: DynamicScale;
    totalContentHeight: number;
}

export function computeLayout(
    nodes: CoverageGraphNode[],
    clusters: CoverageGraphCluster[],
    width: number,
    height: number,
): LayoutResult {
    const nodePositions = new Map<string, { x: number; y: number }>();
    const clusterBounds = new Map<string, { x: number; y: number; w: number; h: number }>();
    const scale = computeDynamicScale(nodes.length, width, height);

    if (nodes.length === 0 || clusters.length === 0) {
        return { nodePositions, clusterBounds, scale, totalContentHeight: height };
    }

    const clusterNodeMap = new Map<string, CoverageGraphNode[]>();
    for (const c of clusters) clusterNodeMap.set(c.id, []);
    for (const n of nodes) {
        const group = clusterNodeMap.get(n.clusterId);
        if (group) group.push(n);
        else clusterNodeMap.set(n.clusterId, [n]);
    }

    const activeClusterIds = clusters
        .filter(c => (clusterNodeMap.get(c.id)?.length || 0) > 0)
        .map(c => c.id);

    if (activeClusterIds.length === 0) {
        return { nodePositions, clusterBounds, scale, totalContentHeight: height };
    }

    const { padding, clusterPad, nodeSpacing, maxNodesPerRow, nodeRadius } = scale;
    const clusterHeaderH = 22;
    const clusterGap = 14;
    const usableW = width - padding * 2;

    const clusterSizes = activeClusterIds.map(cid => {
        const count = clusterNodeMap.get(cid)?.length || 0;
        const cols = Math.min(count, maxNodesPerRow);
        const rows = Math.ceil(count / maxNodesPerRow);
        const w = clusterPad * 2 + cols * nodeSpacing;
        const h = clusterPad + clusterHeaderH + rows * nodeSpacing + clusterPad;
        return { id: cid, cols, rows, count, w, h };
    });

    const totalW = clusterSizes.reduce((s, c) => s + c.w, 0) + (activeClusterIds.length - 1) * clusterGap;
    const wrapThreshold = usableW * 1.1;

    let curX = padding;
    let curY = padding;
    let rowMaxH = 0;
    let maxY = 0;

    if (totalW <= wrapThreshold) {
        curX = padding + Math.max(0, (usableW - totalW) / 2);
        const rowH = Math.max(...clusterSizes.map(c => c.h));
        const usableH = height - padding * 2;
        for (const cs of clusterSizes) {
            const y = padding + Math.max(0, (usableH - rowH) / 2);
            clusterBounds.set(cs.id, { x: curX, y, w: cs.w, h: cs.h });
            layoutClusterNodes(cs.id, curX, y, cs, clusterNodeMap, nodePositions, clusterPad, clusterHeaderH, nodeSpacing, maxNodesPerRow, nodeRadius);
            curX += cs.w + clusterGap;
            maxY = Math.max(maxY, y + cs.h);
        }
    } else {
        for (const cs of clusterSizes) {
            if (curX + cs.w > width - padding && curX > padding) {
                curX = padding;
                curY += rowMaxH + clusterGap;
                rowMaxH = 0;
            }
            clusterBounds.set(cs.id, { x: curX, y: curY, w: cs.w, h: cs.h });
            layoutClusterNodes(cs.id, curX, curY, cs, clusterNodeMap, nodePositions, clusterPad, clusterHeaderH, nodeSpacing, maxNodesPerRow, nodeRadius);
            curX += cs.w + clusterGap;
            rowMaxH = Math.max(rowMaxH, cs.h);
            maxY = Math.max(maxY, curY + cs.h);
        }
    }

    return { nodePositions, clusterBounds, scale, totalContentHeight: maxY + padding };
}

function layoutClusterNodes(
    clusterId: string,
    cx: number, cy: number,
    cs: { cols: number; rows: number },
    clusterNodeMap: Map<string, CoverageGraphNode[]>,
    nodePositions: Map<string, { x: number; y: number }>,
    clusterPad: number, headerH: number,
    spacing: number, maxPerRow: number, nodeR: number,
) {
    const nodes = clusterNodeMap.get(clusterId) || [];
    nodes.forEach((node, idx) => {
        const col = idx % maxPerRow;
        const row = Math.floor(idx / maxPerRow);
        const x = cx + clusterPad + nodeR + col * spacing;
        const y = cy + clusterPad + headerH + nodeR + row * spacing;
        nodePositions.set(node.id, { x, y });
    });
}

// =====================================================================
// LABELS
// =====================================================================

export function truncateLabel(path: string, maxLen: number = 14): string {
    // Always show only the clean last segment: /login, /whoami, etc.
    const parts = path.replace(/^\/+/, '').split('/').filter(Boolean);
    if (parts.length === 0) return '/';
    const last = parts[parts.length - 1];
    if (last.length + 1 <= maxLen) return '/' + last;
    return '/' + last.substring(0, maxLen - 1) + '…';
}

export function formatMethods(methods: string[]): string {
    if (methods.length === 0) return '';
    if (methods.length === 1) return methods[0];
    return `${methods[0]} +${methods.length - 1}`;
}

// =====================================================================
// FLOW CONTEXT - compute incoming/outgoing for a node
// =====================================================================

export interface FlowContext {
    incomingFrom: Array<{ nodeId: string; label: string; count: number }>;
    outgoingTo: Array<{ nodeId: string; label: string; count: number }>;
}

export function computeFlowContext(
    nodeId: string,
    edges: CoverageGraphEdge[],
    nodes: CoverageGraphNode[],
): FlowContext {
    const nodeMap = new Map<string, CoverageGraphNode>();
    for (const n of nodes) nodeMap.set(n.id, n);

    const incoming: FlowContext['incomingFrom'] = [];
    const outgoing: FlowContext['outgoingTo'] = [];

    for (const edge of edges) {
        if (edge.type !== 'navigation') continue;
        if (edge.target === nodeId) {
            const src = nodeMap.get(edge.source);
            if (src) incoming.push({ nodeId: edge.source, label: src.label, count: edge.count });
        }
        if (edge.source === nodeId) {
            const tgt = nodeMap.get(edge.target);
            if (tgt) outgoing.push({ nodeId: edge.target, label: tgt.label, count: edge.count });
        }
    }

    return { incomingFrom: incoming, outgoingTo: outgoing };
}
