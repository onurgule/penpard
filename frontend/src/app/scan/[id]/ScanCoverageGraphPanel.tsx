'use client';

/**
 * ScanCoverageGraphPanel.tsx
 *
 * v4 Panel with:
 *  - Internal scroll for graph canvas (reachable clusters)
 *  - Investigation drawer: 7 organized sections
 *  - Compact panel header with stats
 *  - Endpoint intelligence toggle
 */

import React, { useRef, useState, useEffect, useCallback } from 'react';
import { GitBranch, Maximize2, List, EyeOff, ChevronRight } from 'lucide-react';
import ScanCoverageGraph from './ScanCoverageGraph';
import type { CoverageGraphSnapshot, CoverageGraphNode } from './ScanCoverageGraph.types';
import { COLORS } from './scan-coverage-graph.utils';

interface ScanCoverageGraphPanelProps {
    coverageGraph: CoverageGraphSnapshot | null;
    endpointRows: any[];
    endpointSummary: string;
    endpointStats: { total: number; authRelevant: number; burpSeen: number; jsArtifacts: number };
    showEndpointIntelligence: boolean;
    onToggleEndpoints: () => void;
    onOpenFullscreen: () => void;
    renderEndpointRows: () => React.ReactNode;
    targetUrl?: string | null;
}

export default function ScanCoverageGraphPanel({
    coverageGraph, endpointRows, endpointSummary, endpointStats,
    showEndpointIntelligence, onToggleEndpoints, onOpenFullscreen,
    renderEndpointRows, targetUrl,
}: ScanCoverageGraphPanelProps) {
    const graphContainerRef = useRef<HTMLDivElement>(null);
    const [graphSize, setGraphSize] = useState({ width: 400, height: 280 });
    const [selectedNode, setSelectedNode] = useState<CoverageGraphNode | null>(null);

    useEffect(() => {
        let rafId: number | null = null;
        let timeout: ReturnType<typeof setTimeout> | null = null;
        const prevSize = { width: 0, height: 0 };
        const measure = () => {
            if (graphContainerRef.current) {
                const rect = graphContainerRef.current.getBoundingClientRect();
                const w = Math.max(Math.floor(rect.width), 200);
                const h = Math.max(Math.floor(rect.height), 150);
                // Only update if change is significant (prevents scrollbar thrashing)
                const dw = Math.abs(w - prevSize.width);
                const dh = Math.abs(h - prevSize.height);
                if (dw > 20 || dh > 30 || prevSize.width === 0) {
                    prevSize.width = w;
                    prevSize.height = h;
                    setGraphSize({ width: w, height: h });
                }
            }
        };
        const debouncedMeasure = () => {
            if (timeout) clearTimeout(timeout);
            timeout = setTimeout(() => {
                if (rafId) cancelAnimationFrame(rafId);
                rafId = requestAnimationFrame(measure);
            }, 200);
        };
        measure(); // initial
        const ro = new ResizeObserver(debouncedMeasure);
        if (graphContainerRef.current) ro.observe(graphContainerRef.current);
        return () => {
            ro.disconnect();
            if (timeout) clearTimeout(timeout);
            if (rafId) cancelAnimationFrame(rafId);
        };
    }, []);

    const handleNodeClick = useCallback((node: CoverageGraphNode) => {
        setSelectedNode(prev => prev?.id === node.id ? null : node);
    }, []);

    const stats = coverageGraph?.stats;
    const hasGraph = coverageGraph && coverageGraph.nodes.length > 0;
    const recentPath = stats?.recentPath || [];

    return (
        <div className="flex-[1.1] flex flex-col rounded-xl border border-white/8 overflow-hidden min-h-0"
            style={{ background: COLORS.panelBg }}>
            {/* Header */}
            <div className="px-3 py-2.5 border-b border-white/8 flex-shrink-0"
                style={{ background: 'rgba(0,0,0,0.25)' }}>
                <div className="flex justify-between items-center mb-1">
                    <h2 className="font-semibold text-sm text-white flex items-center gap-2">
                        <GitBranch className="w-4 h-4 text-cyan-400" />
                        Coverage Graph
                    </h2>
                    <div className="flex items-center gap-1">
                        <button onClick={onToggleEndpoints}
                            className={`p-1.5 rounded-lg text-xs transition-all ${
                                showEndpointIntelligence
                                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/20'
                                    : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                            }`}
                            title={showEndpointIntelligence ? 'Show graph' : 'Show endpoint list'}>
                            {showEndpointIntelligence ? <EyeOff className="w-3.5 h-3.5" /> : <List className="w-3.5 h-3.5" />}
                        </button>
                        <button onClick={onOpenFullscreen} disabled={!hasGraph}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                            title="Fullscreen">
                            <Maximize2 className="w-3.5 h-3.5" />
                        </button>
                    </div>
                </div>

                {/* Stats */}
                <div className="flex items-center gap-3 text-[10px]">
                    {stats ? (
                        <>
                            <span className="text-slate-400">
                                <span className="text-white font-medium">{stats.totalNodes}</span> routes
                            </span>
                            {stats.navigationEdgeCount > 0 && (
                                <span className="text-cyan-400/70 font-medium">
                                    {stats.navigationEdgeCount} transitions
                                </span>
                            )}
                            {stats.vulnerableNodes > 0 && (
                                <span className="text-red-400 font-medium">
                                    {stats.vulnerableNodes} vulnerable
                                </span>
                            )}
                            {stats.coveragePercentage > 0 && (
                                <span className={`font-medium ${
                                    stats.coveragePercentage >= 70 ? 'text-green-400' :
                                    stats.coveragePercentage >= 40 ? 'text-amber-400' : 'text-red-400'
                                }`}>
                                    {stats.coveragePercentage}%
                                </span>
                            )}
                        </>
                    ) : (
                        <span className="text-slate-500">Waiting for route discovery...</span>
                    )}
                </div>

                {/* Recent path chain */}
                {recentPath.length > 1 && !showEndpointIntelligence && (
                    <div className="flex items-center gap-0.5 mt-1.5 overflow-x-auto text-[9px] scrollbar-none">
                        {recentPath.slice(-5).map((r, i, arr) => (
                            <React.Fragment key={`path-${i}`}>
                                <span className={`shrink-0 px-1 py-0.5 rounded ${
                                    i === arr.length - 1
                                        ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/15'
                                        : 'text-slate-500'
                                }`}>
                                    {r}
                                </span>
                                {i < arr.length - 1 && (
                                    <ChevronRight className="w-2.5 h-2.5 text-slate-600 shrink-0" />
                                )}
                            </React.Fragment>
                        ))}
                    </div>
                )}
            </div>

            {/* Graph canvas - internal scroll for overflow */}
            {!showEndpointIntelligence && (
                <div ref={graphContainerRef}
                    className="flex-1 overflow-y-auto overflow-x-hidden min-h-0 scrollbar-thin scrollbar-thumb-slate-700/50 scrollbar-track-transparent"
                    style={{ scrollbarGutter: 'stable' }}>
                    {hasGraph ? (
                        <ScanCoverageGraph
                            snapshot={coverageGraph}
                            width={graphSize.width}
                            height={graphSize.height}
                            selectedNodeId={selectedNode?.id || null}
                            onNodeClick={handleNodeClick}
                        />
                    ) : (
                        <div className="flex items-center justify-center h-full">
                            <div className="text-center opacity-40">
                                <GitBranch className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                                <div className="text-sm text-slate-500">No routes discovered yet.</div>
                                <div className="text-[10px] text-slate-600 mt-1">The graph will appear as the scan maps routes.</div>
                            </div>
                        </div>
                    )}
                </div>
            )}


            {/* Endpoint Intelligence */}
            {showEndpointIntelligence && (
                <>
                    <div className="p-3 border-b border-white/8 text-[10px] text-slate-400 grid grid-cols-3 gap-2 flex-shrink-0"
                        style={{ background: 'rgba(0,0,0,0.15)' }}>
                        <div>Auth Relevant: <span className="text-white">{endpointStats.authRelevant}</span></div>
                        <div>Burp Seen: <span className="text-white">{endpointStats.burpSeen}</span></div>
                        <div>JS Artifacts: <span className="text-white">{endpointStats.jsArtifacts}</span></div>
                    </div>
                    <div className="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 min-h-0">
                        {renderEndpointRows()}
                    </div>
                </>
            )}
        </div>
    );
}
