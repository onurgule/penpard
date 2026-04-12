'use client';

/**
 * ScanCoverageGraphModal.tsx
 *
 * v4 Fullscreen modal with:
 *  - Body scroll lock (prevents background page scroll)
 *  - ESC to close
 *  - Mouse wheel zoom isolated to graph canvas
 *  - Click+drag pan
 *  - 7-section investigation drawer
 *  - Accurate transition stats
 */

import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { X, ZoomIn, ZoomOut, Maximize } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import ScanCoverageGraph from './ScanCoverageGraph';
import type { CoverageGraphSnapshot, CoverageGraphNode } from './ScanCoverageGraph.types';
import { COLORS } from './scan-coverage-graph.utils';
import { WideNodeInspector } from './ScanCoverageGraphInspector';

interface ScanCoverageGraphModalProps {
    isOpen: boolean;
    onClose: () => void;
    snapshot: CoverageGraphSnapshot | null;
    initialSelectedNodeId?: string | null;
    targetUrl?: string | null;
}

export default function ScanCoverageGraphModal({
    isOpen, onClose, snapshot, initialSelectedNodeId, targetUrl,
}: ScanCoverageGraphModalProps) {
    const [selectedNode, setSelectedNode] = useState<CoverageGraphNode | null>(null);
    const [zoom, setZoom] = useState({ x: 0, y: 0, scale: 1 });
    const [isPanning, setIsPanning] = useState(false);
    const [inspectorHeight, setInspectorHeight] = useState(260);
    const panStart = useRef({ x: 0, y: 0, tx: 0, ty: 0 });
    const canvasRef = useRef<HTMLDivElement>(null);
    const inspectorRef = useRef<HTMLDivElement>(null);
    const isDraggingDivider = useRef(false);
    const dragStartY = useRef(0);
    const dragStartH = useRef(0);

    // Auto-select initial node
    useEffect(() => {
        if (isOpen && initialSelectedNodeId && snapshot) {
            const node = snapshot.nodes.find(n => n.id === initialSelectedNodeId);
            if (node) setSelectedNode(node);
        }
    }, [isOpen, initialSelectedNodeId, snapshot]);

    // Body scroll lock when modal is open
    useEffect(() => {
        if (!isOpen) return;
        const prevOverflow = document.body.style.overflow;
        const prevPaddingRight = document.body.style.paddingRight;
        const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
        document.body.style.overflow = 'hidden';
        if (scrollbarWidth > 0) {
            document.body.style.paddingRight = `${scrollbarWidth}px`;
        }
        return () => {
            document.body.style.overflow = prevOverflow;
            document.body.style.paddingRight = prevPaddingRight;
        };
    }, [isOpen]);

    // ESC key handler
    useEffect(() => {
        if (!isOpen) return;
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                handleClose();
            }
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [isOpen]);

    // Block wheel/touchmove on the overlay (not the canvas)
    useEffect(() => {
        if (!isOpen) return;
        const blockWheel = (e: WheelEvent) => {
            if (canvasRef.current && canvasRef.current.contains(e.target as Node)) return;
            e.preventDefault();
        };
        const blockTouch = (e: TouchEvent) => {
            if (canvasRef.current && canvasRef.current.contains(e.target as Node)) return;
            if (e.touches.length > 1) e.preventDefault();
        };
        document.addEventListener('wheel', blockWheel, { passive: false });
        document.addEventListener('touchmove', blockTouch, { passive: false });
        return () => {
            document.removeEventListener('wheel', blockWheel);
            document.removeEventListener('touchmove', blockTouch);
        };
    }, [isOpen]);

    // --- Resizable inspector divider: CSS-only during drag ---
    const handleDividerPointerDown = useCallback((e: React.PointerEvent) => {
        e.preventDefault();
        e.stopPropagation();
        isDraggingDivider.current = true;
        dragStartY.current = e.clientY;
        dragStartH.current = inspectorHeight;
        (e.target as HTMLElement).setPointerCapture(e.pointerId);
        document.body.style.cursor = 'row-resize';
        document.body.style.userSelect = 'none';
    }, [inspectorHeight]);

    const handleDividerPointerMove = useCallback((e: React.PointerEvent) => {
        if (!isDraggingDivider.current) return;
        const dy = dragStartY.current - e.clientY;
        const newH = Math.max(120, Math.min(500, dragStartH.current + dy));
        // CSS-only update — no React state, no graph recompute
        if (inspectorRef.current) {
            inspectorRef.current.style.height = `${newH}px`;
        }
    }, []);

    const handleDividerPointerUp = useCallback((e: React.PointerEvent) => {
        if (!isDraggingDivider.current) return;
        isDraggingDivider.current = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        // Commit final height to React state (single recompute)
        const dy = dragStartY.current - e.clientY;
        const finalH = Math.max(120, Math.min(500, dragStartH.current + dy));
        setInspectorHeight(finalH);
    }, []);

    const handleNodeClick = useCallback((node: CoverageGraphNode) => {
        setSelectedNode(prev => prev?.id === node.id ? null : node);
    }, []);

    // Mouse wheel zoom - centered on cursor, only affects graph canvas
    const handleWheel = useCallback((e: React.WheelEvent) => {
        e.preventDefault();
        e.stopPropagation();
        const rect = canvasRef.current?.getBoundingClientRect();
        if (!rect) return;

        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        const delta = e.deltaY > 0 ? 0.92 : 1.08;
        const newScale = Math.max(0.25, Math.min(5, zoom.scale * delta));

        const newX = mouseX - (mouseX - zoom.x) * (newScale / zoom.scale);
        const newY = mouseY - (mouseY - zoom.y) * (newScale / zoom.scale);

        setZoom({ x: newX, y: newY, scale: newScale });
    }, [zoom]);

    const handleMouseDown = useCallback((e: React.MouseEvent) => {
        if (e.button !== 0) return;
        setIsPanning(true);
        panStart.current = { x: e.clientX, y: e.clientY, tx: zoom.x, ty: zoom.y };
    }, [zoom]);

    const handleMouseMove = useCallback((e: React.MouseEvent) => {
        if (!isPanning) return;
        const dx = e.clientX - panStart.current.x;
        const dy = e.clientY - panStart.current.y;
        setZoom(z => ({ ...z, x: panStart.current.tx + dx, y: panStart.current.ty + dy }));
    }, [isPanning]);

    const handleMouseUp = useCallback(() => {
        setIsPanning(false);
    }, []);

    const resetZoom = useCallback(() => {
        setZoom({ x: 0, y: 0, scale: 1 });
    }, []);

    const handleClose = useCallback(() => {
        setSelectedNode(null);
        setZoom({ x: 0, y: 0, scale: 1 });
        onClose();
    }, [onClose]);

    // Memoize graph dimensions — only recalc when modal opens
    const graphW = useMemo(() =>
        typeof window !== 'undefined' ? window.innerWidth * 0.88 : 1200,
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [isOpen]
    );
    const graphH = useMemo(() =>
        typeof window !== 'undefined' ? window.innerHeight * 0.55 : 600,
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [isOpen]
    );

    if (!isOpen || !snapshot) return null;

    const stats = snapshot.stats;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="fixed inset-0 z-50 flex items-center justify-center p-4"
                style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(4px)' }}
                onClick={(e) => { if (e.target === e.currentTarget) handleClose(); }}>
                <motion.div
                    initial={{ scale: 0.96, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.96, opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className="rounded-2xl border border-white/10 w-full max-w-[92vw] h-[88vh] flex flex-col overflow-hidden shadow-2xl"
                    style={{ background: COLORS.panelBg }}>

                    {/* Header */}
                    <div className="flex items-center justify-between px-5 py-3 border-b border-white/8 shrink-0"
                        style={{ background: 'rgba(0,0,0,0.3)' }}>
                        <div>
                            <h2 className="text-base font-bold text-white">Coverage Graph</h2>
                            <p className="text-[11px] text-slate-400 mt-0.5">
                                {stats.totalNodes} routes
                                {stats.navigationEdgeCount > 0 && (
                                    <> &middot; <span className="text-cyan-400">{stats.navigationEdgeCount} transitions</span></>
                                )}
                                {stats.vulnerableNodes > 0 && (
                                    <> &middot; <span className="text-red-400">{stats.vulnerableNodes} vulnerable</span></>
                                )}
                                {stats.recentPath.length > 0 && (
                                    <span className="ml-2 text-slate-500">
                                        Recent: {stats.recentPath.slice(-4).join(' > ')}
                                    </span>
                                )}
                            </p>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-slate-500 mr-1 tabular-nums">{Math.round(zoom.scale * 100)}%</span>
                            <button onClick={() => setZoom(z => ({ ...z, scale: Math.min(5, z.scale * 1.2) }))}
                                className="p-1.5 rounded-lg hover:bg-white/8 text-slate-400 hover:text-white transition-colors" title="Zoom in">
                                <ZoomIn className="w-4 h-4" />
                            </button>
                            <button onClick={() => setZoom(z => ({ ...z, scale: Math.max(0.25, z.scale * 0.8) }))}
                                className="p-1.5 rounded-lg hover:bg-white/8 text-slate-400 hover:text-white transition-colors" title="Zoom out">
                                <ZoomOut className="w-4 h-4" />
                            </button>
                            <button onClick={resetZoom}
                                className="p-1.5 rounded-lg hover:bg-white/8 text-slate-400 hover:text-white transition-colors" title="Reset">
                                <Maximize className="w-4 h-4" />
                            </button>
                            <div className="w-px h-5 bg-white/8 mx-0.5" />
                            <button onClick={handleClose}
                                className="p-1.5 rounded-lg hover:bg-white/8 transition-colors" title="Close (ESC)">
                                <X className="w-4.5 h-4.5 text-slate-400" />
                            </button>
                        </div>
                    </div>

                    {/* Graph canvas with zoom/pan - stable height */}
                    <div ref={canvasRef}
                        className={`flex-1 relative overflow-hidden ${isPanning ? 'cursor-grabbing' : 'cursor-grab'}`}
                        style={{ background: COLORS.canvasBg }}
                        onWheel={handleWheel}
                        onMouseDown={handleMouseDown}
                        onMouseMove={handleMouseMove}
                        onMouseUp={handleMouseUp}
                        onMouseLeave={handleMouseUp}>
                        <ScanCoverageGraph
                            snapshot={snapshot}
                            width={graphW}
                            height={graphH}
                            selectedNodeId={selectedNode?.id || null}
                            onNodeClick={handleNodeClick}
                            transform={zoom}
                            showTooltip
                        />
                        {/* Zoom hint */}
                        {zoom.scale === 1 && (
                            <div className="absolute bottom-3 left-4 text-[9px] text-slate-600 pointer-events-none select-none">
                                Scroll to zoom &middot; Drag to pan &middot; ESC to close
                            </div>
                        )}
                    </div>

                    {/* Resizable divider handle */}
                    <div
                        className="flex-shrink-0 flex items-center justify-center cursor-row-resize group"
                        style={{ height: 8, background: 'rgba(0,0,0,0.3)' }}
                        onPointerDown={handleDividerPointerDown}
                        onPointerMove={handleDividerPointerMove}
                        onPointerUp={handleDividerPointerUp}
                        onPointerCancel={handleDividerPointerUp}
                    >
                        {/* Visual grip dots */}
                        <div className="flex gap-1 opacity-30 group-hover:opacity-60 transition-opacity">
                            <div className="w-1 h-1 rounded-full bg-slate-400" />
                            <div className="w-1 h-1 rounded-full bg-slate-400" />
                            <div className="w-1 h-1 rounded-full bg-slate-400" />
                        </div>
                    </div>

                    {/* Persistent inspector region - resizable, ref-controlled */}
                    <div ref={inspectorRef}
                        className="flex-shrink-0 overflow-hidden"
                        style={{ height: inspectorHeight }}>
                        {selectedNode ? (
                            <WideNodeInspector
                                node={selectedNode}
                                onClose={() => setSelectedNode(null)}
                                targetUrl={targetUrl}
                                snapshot={snapshot}
                            />
                        ) : (
                            <div className="flex items-center justify-center h-full select-none">
                                <span className="text-slate-700 text-[11px]">Select a node to inspect</span>
                            </div>
                        )}
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}



