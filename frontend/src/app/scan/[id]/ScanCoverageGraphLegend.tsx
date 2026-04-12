'use client';

/**
 * ScanCoverageGraphLegend.tsx
 *
 * v4 Legend matching the new visual language:
 *  - Gray nodes with risk borders
 *  - Edge types
 *  - Badge indicators
 */

import React from 'react';
import { COLORS } from './scan-coverage-graph.utils';

export default function ScanCoverageGraphLegend() {
    return (
        <div className="border border-white/8 rounded-lg p-2.5 text-[8px] text-slate-400 space-y-1.5"
            style={{ background: 'rgba(17,24,39,0.95)', backdropFilter: 'blur(8px)' }}>
            <div className="font-bold text-[9px] text-slate-300 mb-1">Legend</div>

            {/* Node borders = risk */}
            <div className="flex items-center gap-3">
                {[
                    { border: COLORS.nodeBorderDefault, label: 'No risk' },
                    { border: COLORS.riskLow, label: 'Low' },
                    { border: COLORS.riskMedium, label: 'Medium' },
                    { border: COLORS.riskHigh, label: 'High/Crit' },
                ].map(({ border, label }) => (
                    <div key={label} className="flex items-center gap-1">
                        <span className="w-2.5 h-2.5 rounded-full border-2 inline-block"
                            style={{ backgroundColor: COLORS.nodeFill, borderColor: border }} />
                        <span>{label}</span>
                    </div>
                ))}
            </div>

            {/* Edge types */}
            <div className="flex items-center gap-3">
                <div className="flex items-center gap-1">
                    <span className="w-4 h-0.5 inline-block" style={{ background: COLORS.edgeNav }} />
                    <span>Navigation</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-4 h-0.5 border-t border-dashed inline-block" style={{ borderColor: COLORS.edgeDefault }} />
                    <span>Structural</span>
                </div>
            </div>

            {/* Badges */}
            <div className="flex items-center gap-3">
                <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full inline-block"
                        style={{ background: COLORS.authBadge }} />
                    <span>Auth</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full text-white text-[6px] font-bold inline-flex items-center justify-center"
                        style={{ background: COLORS.badgeFill }}>3</span>
                    <span>Vulns</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full border inline-block animate-pulse"
                        style={{ borderColor: COLORS.activeRing }} />
                    <span>Active</span>
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-full border border-dashed inline-block"
                        style={{ borderColor: COLORS.inferredBorder }} />
                    <span>Inferred</span>
                </div>
            </div>
        </div>
    );
}
