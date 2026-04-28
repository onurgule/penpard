'use client';

import { AnimatePresence, motion } from 'framer-motion';
import { Activity, CheckCircle, Crosshair, Shield } from 'lucide-react';

import {
    buildScopedAnchorSummary,
    formatScopedFeatureDiscoveryOutcome,
    formatScopedFeatureDiscoveryPhase,
    type MissionControlLiveRuntimeSummary,
    type FocusedTestObjectiveSummary,
    type ScopedFeatureDiscoveryStateSummary,
    type ScopeEnvelopeSummary,
    type StructuredSecurityTestRequestSummary,
} from './focused-plan';

export interface MissionControlVulnerability {
    id: number | string;
    name: string;
    severity: string;
    description: string;
    cwe?: string;
    cve?: string;
    cvssScore?: number;
    request?: string;
    response?: string;
    remediation?: string;
    badgeLabel?: string;
    metadata?: string[];
    actionRequest?: {
        rawRequest?: string;
        method?: string;
        url?: string;
        headers?: Record<string, string>;
        body?: string;
        host?: string;
        evidenceId?: string;
        source?: string;
    };
}

interface MissionControlScopedSupportStripProps {
    liveRuntimeSummary: MissionControlLiveRuntimeSummary | null;
    focusedTestObjective: FocusedTestObjectiveSummary | null;
    scopeEnvelope: ScopeEnvelopeSummary | null;
    scopedTestRequest: StructuredSecurityTestRequestSummary | null;
    featureDiscoveryState: ScopedFeatureDiscoveryStateSummary | null;
    isLegacyScopedRecoveryState: boolean;
    showLegacyRecoveryTools: boolean;
    onToggleLegacyRecovery: () => void;
}

interface MissionControlLiveFindingsProps {
    findings: MissionControlVulnerability[];
    getSeverityColor: (severity: string) => string;
    onSelectFinding: (finding: MissionControlVulnerability) => void;
}

export function MissionControlScopedSupportStrip(props: MissionControlScopedSupportStripProps) {
    const {
        liveRuntimeSummary,
        focusedTestObjective,
        scopeEnvelope,
        scopedTestRequest,
        featureDiscoveryState,
        isLegacyScopedRecoveryState,
        showLegacyRecoveryTools,
        onToggleLegacyRecovery,
    } = props;

    return (
        <section className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr),minmax(0,1fr),minmax(320px,0.8fr)]">
            <div className="card p-4 border-white/10">
                <div className="flex items-start justify-between gap-3">
                    <div className="space-y-3 min-w-0">
                        <div>
                            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Scoped Context</div>
                            <h2 className="mt-2 text-lg font-semibold text-white">Structured security test request</h2>
                        </div>
                        {scopedTestRequest ? (
                            <>
                                <div className="flex flex-wrap gap-2">
                                    <span className="px-2.5 py-1 rounded-full border border-cyan-500/20 bg-cyan-500/10 text-cyan-100 text-xs break-all">
                                        {scopedTestRequest.targetUrl}
                                    </span>
                                    {scopedTestRequest.serviceName && (
                                        <span className="px-2.5 py-1 rounded-full border border-slate-700 bg-slate-900/70 text-slate-200 text-xs">
                                            {scopedTestRequest.serviceName}
                                        </span>
                                    )}
                                    {scopedTestRequest.environment && (
                                        <span className="px-2.5 py-1 rounded-full border border-slate-700 bg-slate-900/70 text-slate-300 text-xs uppercase">
                                            {scopedTestRequest.environment}
                                        </span>
                                    )}
                                </div>
                                <div className="text-sm leading-7 text-slate-200">{scopedTestRequest.description}</div>
                            </>
                        ) : (
                            <div className="text-sm leading-7 text-slate-400">
                                Request details will appear here once the scoped run is initialized.
                            </div>
                        )}
                        {focusedTestObjective?.goal && (
                            <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                                <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Mission</div>
                                <div className="mt-2 text-sm leading-7 text-slate-200">{focusedTestObjective.goal}</div>
                            </div>
                        )}
                        {!focusedTestObjective?.goal && liveRuntimeSummary?.currentDecisionSummary && (
                            <div className="text-sm leading-7 text-slate-300">{liveRuntimeSummary.currentDecisionSummary}</div>
                        )}
                    </div>
                    <div className="hidden lg:flex w-14 h-14 rounded-2xl border border-cyan-500/20 bg-cyan-500/10 items-center justify-center shrink-0">
                        <Crosshair className="w-6 h-6 text-cyan-300" />
                    </div>
                </div>
                {(focusedTestObjective?.riskTags?.length || scopeEnvelope?.boundaryHints?.length || scopeEnvelope?.outOfScopeNotes?.length) && (
                    <div className="mt-4 flex flex-wrap gap-2">
                        {focusedTestObjective?.riskTags?.map((tag) => (
                            <span key={tag} className="px-2.5 py-1 rounded-full border border-violet-500/20 bg-violet-500/10 text-violet-200 text-xs">
                                {tag}
                            </span>
                        ))}
                        {scopeEnvelope?.boundaryHints?.slice(0, 2).map((hint) => (
                            <span key={hint} className="px-2.5 py-1 rounded-full border border-slate-700 bg-slate-900/70 text-slate-300 text-xs">
                                {hint}
                            </span>
                        ))}
                        {scopeEnvelope?.outOfScopeNotes?.slice(0, 1).map((note) => (
                            <span key={note} className="px-2.5 py-1 rounded-full border border-amber-500/20 bg-amber-500/10 text-amber-200 text-xs">
                                {note}
                            </span>
                        ))}
                    </div>
                )}
            </div>

            <div className="card p-4 border-white/10">
                <div className="space-y-4">
                    <div className="flex flex-wrap items-center gap-2">
                        {featureDiscoveryState && (
                            <>
                                <span className="px-2.5 py-1 rounded-full border border-blue-500/20 bg-blue-500/10 text-blue-200 text-xs">
                                    {formatScopedFeatureDiscoveryPhase(featureDiscoveryState.phase)}
                                </span>
                                <span className="px-2.5 py-1 rounded-full border border-slate-700 bg-slate-900/70 text-slate-200 text-xs">
                                    {formatScopedFeatureDiscoveryOutcome(featureDiscoveryState.outcome)}
                                </span>
                            </>
                        )}
                        {scopeEnvelope?.allowedRoutes?.length ? (
                            <span className="px-2.5 py-1 rounded-full border border-white/10 bg-black/20 text-slate-300 text-xs">
                                {scopeEnvelope.allowedRoutes.length} scoped route{scopeEnvelope.allowedRoutes.length === 1 ? '' : 's'}
                            </span>
                        ) : null}
                    </div>
                    <div>
                        <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Boundaries</div>
                        <h2 className="mt-2 text-lg font-semibold text-white">Anchors and mission envelope</h2>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 space-y-2">
                        <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Anchors</div>
                        <div className="text-sm text-slate-200">{buildScopedAnchorSummary(scopeEnvelope, featureDiscoveryState)}</div>
                        {featureDiscoveryState?.summary || featureDiscoveryState?.errorMessage ? (
                            <div className="text-xs text-slate-400 leading-6">
                                {featureDiscoveryState.errorMessage || featureDiscoveryState.summary}
                            </div>
                        ) : null}
                        {scopeEnvelope?.allowedRoutes?.length ? (
                            <div className="text-xs text-slate-400 leading-6">
                                Scoped routes: {scopeEnvelope.allowedRoutes.slice(0, 3).join(', ')}
                                {scopeEnvelope.allowedRoutes.length > 3 ? ` +${scopeEnvelope.allowedRoutes.length - 3} more` : ''}
                            </div>
                        ) : null}
                        {liveRuntimeSummary?.boundarySummary?.explorationBudget ? (
                            <div className="text-xs text-slate-500 leading-6">
                                Budget: requests {liveRuntimeSummary.boundarySummary.explorationBudget.maxRequests ?? 'unbounded'} · browser {liveRuntimeSummary.boundarySummary.explorationBudget.maxBrowserActions ?? 'unbounded'}
                            </div>
                        ) : null}
                    </div>
                </div>
            </div>

            <div className={`card p-4 border ${isLegacyScopedRecoveryState ? 'border-amber-500/20 bg-amber-950/10' : 'border-white/10'}`}>
                <div className="space-y-4">
                    <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Recovery</div>
                            <h2 className="mt-2 text-lg font-semibold text-white">
                                {isLegacyScopedRecoveryState ? 'Legacy review tools are secondary' : 'Scoped support tools'}
                            </h2>
                        </div>
                        <div className="w-11 h-11 rounded-2xl border border-white/10 bg-black/20 flex items-center justify-center shrink-0">
                            {isLegacyScopedRecoveryState ? (
                                <CheckCircle className="w-5 h-5 text-amber-200" />
                            ) : (
                                <Activity className="w-5 h-5 text-cyan-300" />
                            )}
                        </div>
                    </div>
                    <div className="text-sm leading-7 text-slate-300">
                        {isLegacyScopedRecoveryState
                            ? 'This older scoped scan still has a manual review state available, but the shared live Mission Control experience remains the primary surface.'
                            : 'Scoped-specific controls stay tucked behind recovery mode so operators keep the same primary Mission Control experience as exploratory runs.'}
                    </div>
                    {liveRuntimeSummary?.boundarySummary?.outOfScopeNotes?.length ? (
                        <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Out of scope</div>
                            <div className="mt-2 text-xs leading-6 text-slate-300">
                                {liveRuntimeSummary.boundarySummary.outOfScopeNotes.slice(0, 2).join(' | ')}
                            </div>
                        </div>
                    ) : null}
                    <button
                        onClick={onToggleLegacyRecovery}
                        className="w-full px-4 py-2 rounded-2xl border border-slate-700 bg-slate-900/70 text-slate-200 hover:bg-slate-800 text-sm font-medium"
                    >
                        {showLegacyRecoveryTools ? 'Hide Legacy Recovery Tools' : 'Show Legacy Recovery Tools'}
                    </button>
                </div>
            </div>
        </section>
    );
}

export function MissionControlLiveFindings(props: MissionControlLiveFindingsProps) {
    const { findings, getSeverityColor, onSelectFinding } = props;

    return (
        <div className="flex-1 flex flex-col bg-white/5 rounded-xl border border-white/10 overflow-hidden min-h-0">
            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-black/20 flex-shrink-0">
                <h2 className="font-bold text-sm text-white">Live Findings</h2>
                <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-xs border border-red-500/20">{findings.length} Issues</span>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 min-h-0">
                {findings.length === 0 ? (
                    <div className="text-center py-10 opacity-50">
                        <Shield className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                        <div className="text-sm text-slate-500">No vulnerabilities found yet.</div>
                    </div>
                ) : (
                    <AnimatePresence>
                        {findings.map((finding) => (
                            <motion.div
                                key={finding.id}
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                onClick={() => onSelectFinding(finding)}
                                className={`p-3 rounded-lg border cursor-pointer hover:bg-white/5 transition-colors ${getSeverityColor(finding.severity)}`}
                            >
                                <div className="flex justify-between items-start mb-1">
                                    <div className="font-bold text-sm truncate pr-2">{finding.name}</div>
                                    <div className="text-[10px] uppercase font-bold opacity-70">{finding.badgeLabel || finding.severity}</div>
                                </div>
                                <div className="text-xs opacity-80 line-clamp-2">{finding.description}</div>
                                {finding.metadata?.length ? (
                                    <div className="mt-2 flex flex-wrap gap-1.5 text-[10px] opacity-75">
                                        {finding.metadata.slice(0, 4).map((entry) => (
                                            <span key={`${finding.id}-${entry}`} className="px-1.5 py-0.5 rounded border border-white/10 bg-black/20">
                                                {entry}
                                            </span>
                                        ))}
                                    </div>
                                ) : null}
                            </motion.div>
                        ))}
                    </AnimatePresence>
                )}
            </div>
        </div>
    );
}
