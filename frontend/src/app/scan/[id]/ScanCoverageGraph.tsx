'use client';

/**
 * ScanCoverageGraph.tsx
 *
 * SVG renderer v4 — visual language:
 *  - Node fill: always neutral gray (#6b7280)
 *  - Node border: risk-based (default #94a3b8 / low #f59e0b / med #fb923c / high #ef4444)
 *  - Inferred-only: dashed purple border (#a78bfa)
 *  - Active node: cyan ring + soft pulse
 *  - Selected node: scales up slightly
 *  - Cluster backgrounds: category-colored soft tints
 *  - Edges: always visible, brighten on selection
 *  - Compact mode: hides method labels
 */

import React, { useMemo, memo, useRef, useEffect, useCallback } from 'react';
import type { CoverageGraphSnapshot, CoverageGraphNode } from './ScanCoverageGraph.types';
import {
    computeLayout,
    nodeColor,
    nodeStrokeColor,
    nodeStrokeWidth,
    riskGlowColor,
    clusterBgColor,
    clusterLabelColor,
    clusterBorderColor,
    truncateLabel,
    formatMethods,
    COLORS,
} from './scan-coverage-graph.utils';

interface ScanCoverageGraphProps {
    snapshot: CoverageGraphSnapshot;
    width: number;
    height: number;
    selectedNodeId?: string | null;
    onNodeClick?: (node: CoverageGraphNode) => void;
    transform?: { x: number; y: number; scale: number };
    showTooltip?: boolean;
}

const ScanCoverageGraph = memo(function ScanCoverageGraph({
    snapshot, width, height, selectedNodeId, onNodeClick, transform, showTooltip,
}: ScanCoverageGraphProps) {
    const { nodes, edges, clusters } = snapshot;
    const wrapperRef = useRef<HTMLDivElement>(null);
    const tooltipRef = useRef<HTMLDivElement>(null);
    const hideTimer = useRef<ReturnType<typeof setTimeout>>(null);
    const currentTooltipNode = useRef<string | null>(null);

    // Ref-based tooltip: deterministic mousemove tracking, no React re-renders
    useEffect(() => {
        if (!showTooltip) return;
        const wrapper = wrapperRef.current;
        const tooltip = tooltipRef.current;
        if (!wrapper || !tooltip) return;

        const showForElement = (g: Element) => {
            if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null; }
            const id = g.getAttribute('data-tooltip') || '';
            if (currentTooltipNode.current === id) return; // already showing this node
            currentTooltipNode.current = id;

            const wrapperRect = wrapper.getBoundingClientRect();
            const gRect = g.getBoundingClientRect();
            const cx = gRect.left + gRect.width / 2 - wrapperRect.left;
            const top = gRect.top - wrapperRect.top - 8;
            tooltip.textContent = id;
            tooltip.style.left = `${cx}px`;
            tooltip.style.top = `${top}px`;
            tooltip.style.opacity = '1';
            tooltip.style.visibility = 'visible';
        };

        const hideTooltip = () => {
            if (hideTimer.current) return; // already scheduled
            hideTimer.current = setTimeout(() => {
                hideTimer.current = null;
                currentTooltipNode.current = null;
                tooltip.style.opacity = '0';
                setTimeout(() => { tooltip.style.visibility = 'hidden'; }, 120);
            }, 80);
        };

        // mousemove: continuously check what's under cursor
        const onMove = (e: MouseEvent) => {
            const target = e.target as Element;
            const g = target.closest('[data-tooltip]');
            if (g) {
                showForElement(g);
            } else if (currentTooltipNode.current) {
                hideTooltip();
            }
        };

        // mouseleave on wrapper: guaranteed hide
        const onLeave = () => {
            if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null; }
            currentTooltipNode.current = null;
            tooltip.style.opacity = '0';
            setTimeout(() => { tooltip.style.visibility = 'hidden'; }, 120);
        };

        wrapper.addEventListener('mousemove', onMove);
        wrapper.addEventListener('mouseleave', onLeave);
        return () => {
            wrapper.removeEventListener('mousemove', onMove);
            wrapper.removeEventListener('mouseleave', onLeave);
            if (hideTimer.current) clearTimeout(hideTimer.current);
        };
    }, [showTooltip]);

    const layout = useMemo(() =>
        computeLayout(nodes, clusters, width, height),
        [nodes, clusters, width, height]
    );

    const { nodePositions, clusterBounds, scale } = layout;
    const getPos = (nodeId: string) => nodePositions.get(nodeId) || { x: 0, y: 0 };

    const highlightedEdgeIds = useMemo(() => {
        if (!selectedNodeId) return new Set<string>();
        return new Set(
            edges.filter(e => e.source === selectedNodeId || e.target === selectedNodeId).map(e => e.id)
        );
    }, [selectedNodeId, edges]);

    const connectedNodeIds = useMemo(() => {
        if (!selectedNodeId) return null;
        const ids = new Set<string>([selectedNodeId]);
        for (const e of edges) {
            if (e.source === selectedNodeId) ids.add(e.target);
            if (e.target === selectedNodeId) ids.add(e.source);
        }
        return ids;
    }, [selectedNodeId, edges]);

    if (nodes.length === 0) {
        return (
            <svg width={width} height={height} className="select-none">
                <text x={width / 2} y={height / 2} textAnchor="middle"
                    fill="#475569" fontSize="13" fontFamily="'Inter',system-ui,sans-serif">
                    No application routes discovered yet...
                </text>
            </svg>
        );
    }

    const tx = transform?.x ?? 0;
    const ty = transform?.y ?? 0;
    const sc = transform?.scale ?? 1;
    const { nodeRadius, labelFontSize, methodFontSize, clusterHeaderFontSize, isCompact } = scale;
    const svgH = Math.max(height, layout.totalContentHeight);

    return (
        <div ref={wrapperRef} style={{ position: 'relative', width, height: svgH }}>
        {/* Custom hover tooltip (fullscreen only) */}
        {showTooltip && (
            <div
                ref={tooltipRef}
                style={{
                    position: 'absolute',
                    zIndex: 50,
                    visibility: 'hidden',
                    opacity: 0,
                    transform: 'translateX(-50%) translateY(-100%)',
                    transition: 'opacity 0.15s ease',
                    pointerEvents: 'none',
                    maxWidth: 360,
                    padding: '5px 12px',
                    borderRadius: 7,
                    background: 'rgba(15, 23, 42, 0.92)',
                    border: '1px solid rgba(148, 163, 184, 0.18)',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.45), 0 0 0 1px rgba(34,211,238,0.06)',
                    backdropFilter: 'blur(12px)',
                    fontSize: 11,
                    fontWeight: 500,
                    fontFamily: "'JetBrains Mono','Fira Code','Inter',monospace",
                    color: '#e2e8f0',
                    letterSpacing: '0.01em',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                }}
            />
        )}
        <svg width={width} height={svgH} className="select-none"
            viewBox={`0 0 ${width} ${svgH}`}
            style={{ background: COLORS.canvasBg }}>
            <defs>
                {/* Navigation arrow */}
                <marker id="arrowNav" viewBox="0 0 10 10" refX="10" refY="5"
                    markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(148,163,184,0.45)" />
                </marker>
                <marker id="arrowNavHi" viewBox="0 0 10 10" refX="10" refY="5"
                    markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill={COLORS.edgeSelected} />
                </marker>

                {/* Active glow filter */}
                <filter id="activeGlow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>

                {/* Subtle drop shadow for nodes */}
                <filter id="nodeShadow" x="-30%" y="-30%" width="160%" height="160%">
                    <feDropShadow dx="0" dy="1" stdDeviation="1.5" floodColor="rgba(0,0,0,0.35)" />
                </filter>
            </defs>

            <g transform={`translate(${tx}, ${ty}) scale(${sc})`}>
                {/* Cluster backgrounds */}
                {clusters.map(cluster => {
                    const bounds = clusterBounds.get(cluster.id);
                    if (!bounds) return null;
                    const hasSelected = selectedNodeId && nodes.some(n => n.clusterId === cluster.id && n.id === selectedNodeId);
                    return (
                        <g key={`cl-${cluster.id}`} style={{ pointerEvents: 'none' }}>
                            <rect x={bounds.x} y={bounds.y} width={bounds.w} height={bounds.h}
                                rx={10} ry={10}
                                fill={clusterBgColor(cluster, !!hasSelected)}
                                stroke={clusterBorderColor(cluster, !!hasSelected)}
                                strokeWidth={hasSelected ? 1 : 0.5} />
                            <text x={bounds.x + 10} y={bounds.y + 15}
                                fill={clusterLabelColor(cluster)} fontSize={clusterHeaderFontSize}
                                fontWeight="700" fontFamily="'Inter',system-ui,sans-serif"
                                style={{ textTransform: 'uppercase' }} letterSpacing="1">
                                {cluster.label}
                            </text>
                        </g>
                    );
                })}

                {/* Edges - always visible */}
                {edges.map(edge => {
                    const from = getPos(edge.source);
                    const to = getPos(edge.target);
                    if ((from.x === 0 && from.y === 0) || (to.x === 0 && to.y === 0)) return null;

                    const isNav = edge.type === 'navigation';
                    const isHighlighted = highlightedEdgeIds.has(edge.id);
                    const isDimmed = selectedNodeId && !isHighlighted;

                    const dx = to.x - from.x;
                    const dy = to.y - from.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 1) return null;

                    const sx = from.x + (dx / dist) * (nodeRadius + 2);
                    const sy = from.y + (dy / dist) * (nodeRadius + 2);
                    const ex = to.x - (dx / dist) * (nodeRadius + 4);
                    const ey = to.y - (dy / dist) * (nodeRadius + 4);

                    const midX = (sx + ex) / 2;
                    const midY = (sy + ey) / 2;
                    const offset = Math.min(dist * 0.1, 14);
                    const cpX = midX + (dy / dist || 0) * offset;
                    const cpY = midY - (dx / dist || 0) * offset;

                    // v4: edges always visible, just dimmer when unrelated
                    let strokeColor: string;
                    let strokeW: number;
                    if (isHighlighted) {
                        strokeColor = COLORS.edgeSelected;
                        strokeW = 2;
                    } else if (isDimmed) {
                        strokeColor = isNav ? 'rgba(148,163,184,0.10)' : 'rgba(148,163,184,0.06)';
                        strokeW = isNav ? 1 : 0.7;
                    } else {
                        strokeColor = isNav ? COLORS.edgeNav : COLORS.edgeDefault;
                        strokeW = isNav ? 1.2 : 0.8;
                    }

                    return (
                        <g key={edge.id} style={{ pointerEvents: 'none' }}>
                            <path
                                d={`M ${sx} ${sy} Q ${cpX} ${cpY} ${ex} ${ey}`}
                                fill="none" stroke={strokeColor} strokeWidth={strokeW}
                                strokeDasharray={isNav ? undefined : '4 3'}
                                markerEnd={isNav ? (isHighlighted ? 'url(#arrowNavHi)' : 'url(#arrowNav)') : undefined}
                            />
                            {/* Transition count label on highlighted edges */}
                            {isHighlighted && isNav && edge.count > 1 && (
                                <text x={cpX} y={cpY - 5} textAnchor="middle"
                                    fill={COLORS.activeRing} fontSize="7.5" fontWeight="600"
                                    fontFamily="'Inter',system-ui,sans-serif">
                                    x{edge.count}
                                </text>
                            )}
                        </g>
                    );
                })}

                {/* Nodes */}
                {nodes.map(node => {
                    const pos = nodePositions.get(node.id);
                    if (!pos) return null;

                    const isSelected = selectedNodeId === node.id;
                    const isDimmed = connectedNodeIds && !connectedNodeIds.has(node.id);
                    const fillColor = nodeColor(node);
                    const stroke = isSelected ? COLORS.selectedRing : nodeStrokeColor(node);
                    const sw = nodeStrokeWidth(node, isSelected);
                    const r = isSelected ? nodeRadius + 2 : nodeRadius;
                    const hasVulns = node.matchedVulnerabilityIds.length > 0;
                    const glowColor = riskGlowColor(node.riskScore);

                    return (
                        <g key={node.id} className="cursor-pointer"
                            data-tooltip={showTooltip ? node.canonicalRoute : undefined}
                            onClick={() => onNodeClick?.(node)}
                            opacity={isDimmed ? 0.3 : 1}
                            style={{ transition: 'opacity 0.2s ease' }}>

                            {/* Invisible hit area — covers circle + label gap */}
                            <circle cx={pos.x} cy={pos.y} r={r + labelFontSize + 8}
                                fill="transparent" stroke="none" />

                            {/* Active node: soft cyan pulse */}
                            {node.isActive && !isSelected && (
                                <circle cx={pos.x} cy={pos.y} r={r + 6} fill="none"
                                    stroke={COLORS.activeRing} strokeWidth={1} opacity={0.4}
                                    filter="url(#activeGlow)">
                                    <animate attributeName="r"
                                        values={`${r + 4};${r + 8};${r + 4}`}
                                        dur="2.5s" repeatCount="indefinite" />
                                    <animate attributeName="opacity"
                                        values="0.4;0.12;0.4"
                                        dur="2.5s" repeatCount="indefinite" />
                                </circle>
                            )}

                            {/* Selection ring */}
                            {isSelected && (
                                <circle cx={pos.x} cy={pos.y} r={r + 5}
                                    fill="none" stroke={COLORS.selectedRing}
                                    strokeWidth={2} opacity={0.7} />
                            )}

                            {/* Risk glow ring (subtle) */}
                            {hasVulns && glowColor !== 'transparent' && (
                                <circle cx={pos.x} cy={pos.y} r={r + 3}
                                    fill={glowColor} opacity={0.6} />
                            )}

                            {/* Main node circle - always gray fill, risk on border */}
                            <circle cx={pos.x} cy={pos.y} r={r}
                                fill={fillColor} stroke={stroke}
                                strokeWidth={sw}
                                filter="url(#nodeShadow)" />

                            {/* Vulnerability count badge */}
                            {hasVulns && (
                                <g>
                                    <circle cx={pos.x + r - 1} cy={pos.y - r + 1}
                                        r={Math.max(5, r * 0.4)}
                                        fill={COLORS.badgeFill} stroke={COLORS.badgeStroke}
                                        strokeWidth={1.2} />
                                    <text x={pos.x + r - 1}
                                        y={pos.y - r + 1 + Math.max(5, r * 0.4) * 0.38}
                                        textAnchor="middle" fill="white"
                                        fontSize={Math.max(5, r * 0.35)} fontWeight="700"
                                        fontFamily="'Inter',system-ui,sans-serif">
                                        {node.matchedVulnerabilityIds.length}
                                    </text>
                                </g>
                            )}



                            {/* Label */}
                            <text x={pos.x} y={pos.y + r + labelFontSize + 3}
                                textAnchor="middle"
                                fill={isSelected ? COLORS.labelSelected : isDimmed ? COLORS.labelDimmed : COLORS.labelDefault}
                                fontSize={labelFontSize} fontWeight="600"
                                fontFamily="'Inter',system-ui,sans-serif">
                                {truncateLabel(node.label, isCompact ? 9 : 14)}
                            </text>

                            {/* Methods - hidden in compact mode */}
                            {!isCompact && methodFontSize > 0 && node.methods.length > 0 && !isDimmed && (
                                <text x={pos.x}
                                    y={pos.y + r + labelFontSize + methodFontSize + 6}
                                    textAnchor="middle" fill={COLORS.methodText}
                                    fontSize={methodFontSize} fontWeight="600"
                                    fontFamily="'JetBrains Mono','Fira Code',monospace">
                                    {formatMethods(node.methods)}
                                </text>
                            )}
                        </g>
                    );
                })}
            </g>
        </svg>
        </div>
    );
});

export default ScanCoverageGraph;
