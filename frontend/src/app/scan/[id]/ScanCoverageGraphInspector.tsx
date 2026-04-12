'use client';

/**
 * ScanCoverageGraphInspector.tsx
 *
 * Shared node investigation content used by both the in-panel drawer
 * and the fullscreen modal inspector.
 *
 * Renders 7 sections:
 *  1) Route Summary  2) Flow Context  3) Discovery Sources
 *  4) Attempted Attacks  5) Confirmed Findings
 *  6) Request Variants  7) Evidence Preview
 *
 * layout='compact'  → single-column, smaller text (panel drawer)
 * layout='wide'     → 3-column grid, larger text (fullscreen modal)
 */

import React from 'react';
import {
    X, Shield, Globe, Code, Search, ArrowRight, ArrowLeft,
    Crosshair, Key, Activity, FileText, Zap,
} from 'lucide-react';
import type { CoverageGraphSnapshot, CoverageGraphNode, CoverageGraphEdge } from './ScanCoverageGraph.types';
import { severityToColor, computeFlowContext } from './scan-coverage-graph.utils';
import toast from 'react-hot-toast';

// =====================================================================
// SHARED HELPERS
// =====================================================================

/** Extract and copy a URL from a vulnerability name to clipboard. */
function copyVulnUrl(vulnName: string, targetUrl?: string | null): void {
    const fullUrlMatch = vulnName.match(/(https?:\/\/[^\s,]+)/i);
    if (fullUrlMatch) {
        navigator.clipboard.writeText(fullUrlMatch[1]);
        toast.success(`Copied: ${fullUrlMatch[1]}`, { duration: 2000 });
        return;
    }
    const pathMatch = vulnName.match(/(\/[\w\-/.?&=]+)/g);
    if (pathMatch && pathMatch[0]) {
        const baseUrl = targetUrl ? targetUrl.replace(/\/$/, '') : '';
        const fullUrl = baseUrl + pathMatch[0];
        navigator.clipboard.writeText(fullUrl);
        toast.success(`Copied: ${fullUrl}`, { duration: 2000 });
        return;
    }
    toast.error('Could not extract URL from vulnerability name');
}

/** Section header — adapts size to layout. */
function InspectorSectionHeader({ icon, title, layout }: { icon: React.ReactNode; title: string; layout: 'compact' | 'wide' }) {
    return (
        <div className={`text-slate-500 uppercase tracking-wider font-bold flex items-center gap-1 ${
            layout === 'wide' ? 'text-[10px]' : 'text-[9px]'
        }`}>
            {icon}{title}
        </div>
    );
}

// =====================================================================
// COMPACT LAYOUT WRAPPER (used by ScanCoverageGraphPanel — unused today,
// kept for future in-panel inspector activation)
// =====================================================================

export interface CompactInspectorProps {
    node: CoverageGraphNode;
    onClose: () => void;
    targetUrl?: string | null;
    edges: CoverageGraphEdge[];
    allNodes: CoverageGraphNode[];
    recentPath: string[];
}

export function CompactNodeInspector({ node, onClose, targetUrl, edges, allNodes, recentPath }: CompactInspectorProps) {
    return (
        <div className="h-full overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700/50"
            style={{ background: 'rgba(0,0,0,0.35)' }}>
            {/* Drawer header */}
            <div className="flex items-center justify-between px-3 py-2 border-b border-white/5 sticky top-0 z-10"
                style={{ background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(8px)' }}>
                <div className="flex items-center gap-2 min-w-0">
                    <code className="text-cyan-300 text-xs font-bold truncate">{node.canonicalRoute}</code>
                    {node.isActive && (
                        <span className="text-[8px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/20 shrink-0 flex items-center gap-0.5">
                            <Activity className="w-2 h-2" /> ACTIVE
                        </span>
                    )}
                </div>
                <button onClick={onClose} className="p-1 hover:bg-white/5 rounded transition-colors shrink-0">
                    <X className="w-3.5 h-3.5 text-slate-500" />
                </button>
            </div>

            <div className="p-3 space-y-3 text-[11px]">
                <InspectorSections
                    node={node}
                    edges={edges}
                    allNodes={allNodes}
                    recentPath={recentPath}
                    targetUrl={targetUrl}
                    layout="compact"
                />
            </div>
        </div>
    );
}

// =====================================================================
// WIDE LAYOUT WRAPPER (used by ScanCoverageGraphModal)
// =====================================================================

export interface WideInspectorProps {
    node: CoverageGraphNode;
    onClose: () => void;
    targetUrl?: string | null;
    snapshot: CoverageGraphSnapshot;
}

export function WideNodeInspector({ node, onClose, targetUrl, snapshot }: WideInspectorProps) {
    return (
        <div className="h-full overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700/50"
            style={{ background: 'rgba(0,0,0,0.45)' }}>
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-2.5 border-b border-white/5 sticky top-0 z-10"
                style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)' }}>
                <div className="flex items-center gap-3 min-w-0">
                    <code className="text-cyan-300 text-sm font-bold truncate">{node.canonicalRoute}</code>
                    <div className="flex gap-1 shrink-0">
                        {node.methods.map(m => (
                            <span key={m} className="px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/15 text-cyan-300 font-mono text-[10px] font-bold">{m}</span>
                        ))}
                    </div>
                    <span className="text-[10px] text-slate-500 shrink-0">{node.foldedCount} variant{node.foldedCount !== 1 ? 's' : ''}</span>
                    {node.isActive && (
                        <span className="text-[9px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/15 shrink-0 flex items-center gap-0.5">
                            <Activity className="w-2.5 h-2.5" /> ACTIVE
                        </span>
                    )}
                    {node.authRelevant && (
                        <span className="text-[9px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/15 shrink-0 flex items-center gap-0.5">
                            <Key className="w-2.5 h-2.5" /> Auth
                        </span>
                    )}
                </div>
                <button onClick={onClose} className="p-1.5 hover:bg-white/5 rounded transition-colors shrink-0">
                    <X className="w-4 h-4 text-slate-500" />
                </button>
            </div>

            <div className="p-5 grid grid-cols-1 lg:grid-cols-3 gap-5 text-xs">
                <InspectorSections
                    node={node}
                    edges={snapshot.edges}
                    allNodes={snapshot.nodes}
                    recentPath={snapshot.stats.recentPath}
                    targetUrl={targetUrl}
                    layout="wide"
                />
            </div>
        </div>
    );
}

// =====================================================================
// SHARED SECTION CONTENT
// =====================================================================

interface InspectorSectionsProps {
    node: CoverageGraphNode;
    edges: CoverageGraphEdge[];
    allNodes: CoverageGraphNode[];
    recentPath: string[];
    targetUrl?: string | null;
    layout: 'compact' | 'wide';
}

function InspectorSections({ node, edges, allNodes, recentPath, targetUrl, layout }: InspectorSectionsProps) {
    const flow = computeFlowContext(node.id, edges, allNodes);
    const hasFlow = flow.incomingFrom.length > 0 || flow.outgoingTo.length > 0;

    if (layout === 'wide') {
        return <WideColumns node={node} flow={flow} hasFlow={hasFlow} recentPath={recentPath} targetUrl={targetUrl} layout={layout} />;
    }

    return <CompactSections node={node} flow={flow} hasFlow={hasFlow} recentPath={recentPath} targetUrl={targetUrl} layout={layout} />;
}

// =====================================================================
// COMPACT SECTIONS (single-column, used by compact drawer)
// =====================================================================

function CompactSections({ node, flow, hasFlow, recentPath, targetUrl, layout }: {
    node: CoverageGraphNode;
    flow: ReturnType<typeof computeFlowContext>;
    hasFlow: boolean;
    recentPath: string[];
    targetUrl?: string | null;
    layout: 'compact' | 'wide';
}) {
    return (
        <>
            {/* 1. Route Summary */}
            <section>
                <InspectorSectionHeader icon={<Crosshair className="w-3 h-3" />} title="Route Summary" layout={layout} />
                <div className="flex flex-wrap gap-1.5 mt-1">
                    {node.methods.map(m => (
                        <span key={m} className="px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/15 text-cyan-300 font-mono text-[9px] font-bold">
                            {m}
                        </span>
                    ))}
                    <span className="px-1.5 py-0.5 rounded bg-white/5 border border-white/8 text-slate-400 text-[9px]">
                        {node.foldedCount} variant{node.foldedCount !== 1 ? 's' : ''}
                    </span>
                    {node.authRelevant && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/15 text-amber-400 text-[9px] flex items-center gap-0.5">
                            <Key className="w-2.5 h-2.5" /> auth-relevant
                        </span>
                    )}
                </div>
            </section>

            {/* 2. Flow Context */}
            {hasFlow && (
                <FlowContextSection flow={flow} recentPath={recentPath} node={node} layout={layout} />
            )}

            {/* 3. Discovery Sources */}
            <DiscoverySourcesSection node={node} layout={layout} />

            {/* 4. Attempted Attacks */}
            {node.attemptedAttackTypes.length > 0 && (
                <AttacksSection node={node} layout={layout} />
            )}

            {/* 5. Confirmed Findings */}
            {node.matchedVulnerabilities.length > 0 && (
                <FindingsSection node={node} targetUrl={targetUrl} layout={layout} />
            )}

            {/* 6. Request Variants */}
            {node.requestVariants.length > 0 && (
                <VariantsSection node={node} layout={layout} maxH="100px" methodWidth="w-8" />
            )}

            {/* 7. Evidence Preview */}
            {node.matchedVulnerabilities.length > 0 && (
                <EvidenceSection node={node} layout={layout} />
            )}

            {/* Empty state */}
            {node.matchedVulnerabilities.length === 0 && node.attemptedAttackTypes.length === 0 && !hasFlow && (
                <div className="text-center py-3 text-slate-600 text-[10px]">
                    No attack coverage, findings, or navigation flow recorded yet.
                </div>
            )}
        </>
    );
}

// =====================================================================
// WIDE COLUMNS (3-column grid, used by fullscreen modal)
// =====================================================================

function WideColumns({ node, flow, hasFlow, recentPath, targetUrl, layout }: {
    node: CoverageGraphNode;
    flow: ReturnType<typeof computeFlowContext>;
    hasFlow: boolean;
    recentPath: string[];
    targetUrl?: string | null;
    layout: 'compact' | 'wide';
}) {
    return (
        <>
            {/* Col 1: Flow + Sources + Attacks */}
            <div className="space-y-3">
                {hasFlow && (
                    <FlowContextSection flow={flow} recentPath={recentPath} node={node} layout={layout} />
                )}
                <DiscoverySourcesSection node={node} layout={layout} />
                {node.attemptedAttackTypes.length > 0 && (
                    <AttacksSection node={node} layout={layout} />
                )}
            </div>

            {/* Col 2: Findings */}
            <div className="space-y-2">
                <InspectorSectionHeader icon={<Shield className="w-3 h-3" />}
                    title={`Confirmed Findings (${node.matchedVulnerabilities.length})`} layout={layout} />
                {node.matchedVulnerabilities.length === 0 ? (
                    <div className="text-slate-600 text-[10px] py-2">No confirmed findings.</div>
                ) : (
                    <div className="space-y-1.5 mt-1.5">
                        {node.matchedVulnerabilities.map(v => {
                            const hasUrl = /(https?:\/\/[^\s,]+)/i.test(v.name) || /(\/[\w\-/.]+)/.test(v.name);
                            return (
                                <div key={v.id}
                                    className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${hasUrl ? 'cursor-pointer hover:bg-white/5 transition-colors group' : ''}`}
                                    style={{ background: 'rgba(239,68,68,0.04)', borderColor: 'rgba(239,68,68,0.10)' }}
                                    onClick={() => hasUrl && copyVulnUrl(v.name, targetUrl)}
                                    title={hasUrl ? 'Click to copy URL' : undefined}
                                >
                                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: severityToColor(v.severity) }} />
                                    <span className="text-slate-300 truncate flex-1 font-medium">{v.name}</span>
                                    <span className="uppercase font-bold shrink-0 text-[9px] px-1.5 py-0.5 rounded"
                                        style={{ color: severityToColor(v.severity), background: severityToColor(v.severity) + '12' }}>
                                        {v.severity}
                                    </span>
                                    {hasUrl && <span className="text-[9px] shrink-0 opacity-40 group-hover:opacity-100 transition-opacity">📋</span>}
                                    {v.cwe && <span className="text-[9px] text-slate-500 shrink-0">{v.cwe}</span>}
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* Col 3: Request Variants */}
            <div className="space-y-2">
                <VariantsSection node={node} layout={layout} maxH="200px" methodWidth="w-10" />
            </div>
        </>
    );
}

// =====================================================================
// REUSABLE SECTION COMPONENTS
// =====================================================================

function FlowContextSection({ flow, recentPath, node, layout }: {
    flow: ReturnType<typeof computeFlowContext>;
    recentPath: string[];
    node: CoverageGraphNode;
    layout: 'compact' | 'wide';
}) {
    const mtClass = layout === 'wide' ? 'mt-1.5' : 'mt-1';
    return (
        <section>
            <InspectorSectionHeader icon={<Activity className="w-3 h-3" />} title="Flow Context" layout={layout} />
            <div className={`${mtClass} space-y-1`}>
                {flow.incomingFrom.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                        <ArrowLeft className="w-3 h-3 text-slate-600 shrink-0" />
                        <span className="text-[9px] text-slate-500 shrink-0">from:</span>
                        {flow.incomingFrom.map(f => (
                            <span key={f.nodeId} className="px-1.5 py-0.5 rounded bg-white/3 border border-white/8 text-slate-300 text-[9px] font-mono">
                                {f.label}{f.count > 1 ? ` x${f.count}` : ''}
                            </span>
                        ))}
                    </div>
                )}
                {flow.outgoingTo.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                        <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                        <span className="text-[9px] text-slate-500 shrink-0">to:</span>
                        {flow.outgoingTo.map(f => (
                            <span key={f.nodeId} className="px-1.5 py-0.5 rounded bg-white/3 border border-white/8 text-slate-300 text-[9px] font-mono">
                                {f.label}{f.count > 1 ? ` x${f.count}` : ''}
                            </span>
                        ))}
                    </div>
                )}
                {/* Recent path — compact shows within flow only if node is in path; wide always shows */}
                {layout === 'compact' && recentPath.length > 1 && recentPath.includes(node.canonicalRoute) && (
                    <div className="flex items-center gap-0.5 mt-1 text-[8px] text-slate-600 overflow-x-auto scrollbar-none">
                        {recentPath.slice(-6).map((p, i, a) => (
                            <React.Fragment key={i}>
                                <span className={p === node.canonicalRoute ? 'text-cyan-400 font-bold' : ''}>{p}</span>
                                {i < a.length - 1 && <span>{'>'}</span>}
                            </React.Fragment>
                        ))}
                    </div>
                )}
                {layout === 'wide' && recentPath.length > 1 && (
                    <div className="text-[8px] text-slate-600 mt-1">
                        Recent: {recentPath.slice(-5).join(' > ')}
                    </div>
                )}
            </div>
        </section>
    );
}

function DiscoverySourcesSection({ node, layout }: { node: CoverageGraphNode; layout: 'compact' | 'wide' }) {
    const sizeClass = layout === 'wide' ? 'px-2 py-1 text-[10px]' : 'px-1.5 py-0.5 text-[9px]';
    const iconSize = layout === 'wide' ? 'w-3 h-3' : 'w-2.5 h-2.5';
    const mtClass = layout === 'wide' ? 'mt-1.5' : 'mt-1';
    return (
        <section>
            <InspectorSectionHeader icon={<Search className="w-3 h-3" />} title="Discovery Sources" layout={layout} />
            <div className={`flex flex-wrap gap-1 ${mtClass}`}>
                {node.sources.map(s => (
                    <span key={s} className={`rounded border flex items-center gap-1 ${sizeClass} ${
                        s === 'inferred'
                            ? 'bg-white/2 border-white/5 text-slate-500 italic'
                            : 'bg-white/4 border-white/8 text-slate-300'
                    }`}>
                        {s === 'burp' && <Search className={iconSize} />}
                        {s === 'browser' && <Globe className={iconSize} />}
                        {s === 'js' && <Code className={iconSize} />}
                        {s}
                    </span>
                ))}
            </div>
        </section>
    );
}

function AttacksSection({ node, layout }: { node: CoverageGraphNode; layout: 'compact' | 'wide' }) {
    const sizeClass = layout === 'wide' ? 'px-2 py-1 text-[10px]' : 'px-1.5 py-0.5 text-[9px]';
    const mtClass = layout === 'wide' ? 'mt-1.5' : 'mt-1';
    return (
        <section>
            <InspectorSectionHeader icon={<Zap className="w-3 h-3" />} title="Attempted Attacks" layout={layout} />
            <div className={`flex flex-wrap gap-1 ${mtClass}`}>
                {node.attemptedAttackTypes.map(t => (
                    <span key={t} className={`rounded bg-purple-500/8 border border-purple-500/15 text-purple-300 ${sizeClass}`}>
                        {t}
                    </span>
                ))}
            </div>
        </section>
    );
}

function FindingsSection({ node, targetUrl, layout }: { node: CoverageGraphNode; targetUrl?: string | null; layout: 'compact' | 'wide' }) {
    return (
        <section>
            <InspectorSectionHeader icon={<Shield className="w-3 h-3" />}
                title={`Confirmed Findings (${node.matchedVulnerabilities.length})`} layout={layout} />
            <div className="space-y-1 mt-1">
                {node.matchedVulnerabilities.map(v => {
                    const hasUrl = /(https?:\/\/[^\s,]+)/i.test(v.name) || /(\/[\w\-/.]+)/.test(v.name);
                    return (
                        <div key={v.id}
                            className={`flex items-center gap-2 px-2 py-1.5 rounded border ${
                                hasUrl ? 'cursor-pointer hover:bg-white/5 transition-colors group' : ''
                            }`}
                            style={{
                                background: 'rgba(239,68,68,0.04)',
                                borderColor: 'rgba(239,68,68,0.10)',
                            }}
                            onClick={() => hasUrl && copyVulnUrl(v.name, targetUrl)}
                            title={hasUrl ? 'Click to copy URL' : undefined}
                        >
                            <span className="w-1.5 h-1.5 rounded-full shrink-0"
                                style={{ backgroundColor: severityToColor(v.severity) }} />
                            <span className="text-[10px] text-slate-300 truncate flex-1 font-medium">{v.name}</span>
                            <span className="text-[8px] uppercase font-bold shrink-0 px-1 py-0.5 rounded"
                                style={{
                                    color: severityToColor(v.severity),
                                    background: severityToColor(v.severity) + '15',
                                }}>
                                {v.severity}
                            </span>
                            {hasUrl && <span className="text-[8px] shrink-0 opacity-40 group-hover:opacity-100 transition-opacity">📋</span>}
                            {v.cwe && <span className="text-[8px] text-slate-600 shrink-0">{v.cwe}</span>}
                        </div>
                    );
                })}
            </div>
        </section>
    );
}

function VariantsSection({ node, layout, maxH, methodWidth }: {
    node: CoverageGraphNode;
    layout: 'compact' | 'wide';
    maxH: string;
    methodWidth: string;
}) {
    const mtClass = layout === 'wide' ? 'mt-1.5' : 'mt-1';
    const textSize = layout === 'wide' ? 'text-[10px]' : 'text-[9px]';
    return (
        <section>
            <InspectorSectionHeader icon={<FileText className="w-3 h-3" />}
                title={`Request Variants (${node.requestVariants.length})`} layout={layout} />
            <div className={`space-y-0.5 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700/50 ${mtClass}`}
                style={{ maxHeight: maxH }}>
                {node.requestVariants.map((rv, i) => {
                    const hasVuln = node.matchedVulnerabilities.some(v => v.name.includes(rv.fullPath));
                    return (
                        <div key={i} className={`flex items-center gap-2 px-2 rounded ${textSize}`}
                            style={{
                                background: 'rgba(255,255,255,0.02)',
                                borderBottom: '1px solid rgba(255,255,255,0.03)',
                                paddingTop: layout === 'wide' ? '6px' : '4px',
                                paddingBottom: layout === 'wide' ? '6px' : '4px',
                            }}>
                            <span className={`text-cyan-400 font-mono font-bold shrink-0 ${methodWidth}`}>{rv.method.split(',')[0]}</span>
                            <span className="text-slate-400 truncate flex-1 font-mono">{rv.fullPath}</span>
                            <span className={`shrink-0 ${rv.source === 'inferred' ? 'text-slate-600 italic' : 'text-slate-500'}`}>{rv.source}</span>
                            {hasVuln && <span className={`text-red-400 shrink-0 ${layout === 'wide' ? 'text-[8px] font-bold' : 'text-[7px]'}`}>FINDING</span>}
                        </div>
                    );
                })}
            </div>
        </section>
    );
}

function EvidenceSection({ node, layout }: { node: CoverageGraphNode; layout: 'compact' | 'wide' }) {
    return (
        <section>
            <InspectorSectionHeader icon={<FileText className="w-3 h-3" />} title="Evidence Preview" layout={layout} />
            <div className="mt-1 text-[9px] text-slate-600 italic px-2 py-1.5 rounded"
                style={{ background: 'rgba(255,255,255,0.02)' }}>
                {node.matchedVulnerabilities.length} finding{node.matchedVulnerabilities.length !== 1 ? 's' : ''} matched to this route.
                Click a finding above to copy the affected URL.
            </div>
        </section>
    );
}
