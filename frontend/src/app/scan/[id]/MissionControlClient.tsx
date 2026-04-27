'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import axios from 'axios';
import {
    ArrowLeft,
    Terminal,
    Shield,
    AlertTriangle,
    CheckCircle,
    Send,
    Activity,
    Lock,
    Eye,
    EyeOff,
    StopCircle,
    Download,
    Pause,
    Play,
    Repeat,
    Loader2,
    Crosshair,
    ScanSearch,
    Globe,
    Route,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';
import { MarkdownRenderer } from '@/components/MarkdownRenderer';
import { API_URL } from '@/lib/api-config';
import ReportOptionsModal from '@/components/modals/ReportOptionsModal';
import { buildEndpointDisplayRows, EndpointInventorySnapshot } from './endpoint-intel';
import {
    MissionControlLiveFindings,
    MissionControlScopedSupportStrip,
    type MissionControlVulnerability,
} from './MissionControlPanels';
import { deriveMissionControlPolicy } from './mission-control-policy';
import {
    buildFocusedCaseRows,
    buildFocusedEvidenceEmptyState,
    buildFocusedReasoningTracePreview,
    buildFocusedScanFindingRows,
    buildFocusedTracePreview,
    buildScopedAnchorSummary,
    formatFocusedPriority,
    formatFocusedReviewState,
    formatFocusedBlockerRecurrence,
    formatFocusedCaseCompareStatus,
    formatScopedFeatureDiscoveryOutcome,
    formatScopedFeatureDiscoveryPhase,
    formatFocusedEvidenceDriftClassification,
    formatFocusedInvestigationImpact,
    formatFocusedInvestigationStatus,
    formatFocusedInvestigationType,
    formatFocusedBrowserEvidenceCount,
    formatFocusedEvidenceCount,
    formatFocusedEvidenceSufficiencyState,
    formatFocusedExecutionPresentationState,
    formatFocusedExecutionRail,
    formatFocusedConfirmationKind,
    formatFocusedFindingConfidenceBand,
    formatFocusedFindingFamily,
    formatFocusedFindingStatus,
    formatFocusedFindingThreadStatus,
    formatFocusedHypothesisStatus,
    formatFocusedReasoningEntryType,
    formatFocusedReasoningRail,
    formatFocusedReasoningStage,
    formatFocusedRequestContextField,
    formatFocusedSuspicionProofStatus,
    formatFocusedExecutionState,
    formatFocusedExecutionTraceActionType,
    formatFocusedHistoricalCompareStatus,
    formatFocusedHistoricalOutcome,
    formatFocusedOverallChangeClassification,
    formatFocusedRailSummary,
    formatFocusedRequestEvidenceRef,
    formatFocusedSupportProvenanceRail,
    formatFocusedSupportProvenanceSummary,
    formatFocusedVerdictState,
    formatFocusedVerdictTransition,
    summarizeScopedPlanReviewCounts,
    type EvidenceBundle,
    type FocusedCaseFinding,
    type FocusedCaseHistoricalCompare,
    type FocusedContextInfluenceSummary,
    type FocusedEvidenceReasoningLink,
    type FocusedFindingThread,
    type FocusedInvestigationIssue,
    type FocusedHistoricalCompareState,
    type FocusedHistoricalCompareSummary,
    type FocusedHypothesisVisibility,
    type FocusedScanBlockerSummary,
    type FocusedCaseVerdict,
    type FocusedReasoningTraceEntry,
    type FocusedExecutionTraceEntry,
    type FocusedRailUsageSummary,
    type FocusedScanFindingSummary,
    type FocusedStorySummary,
    type FocusedScanVerdictSummary,
    type FocusedSuspicionExplanation,
    type MissionControlLiveRuntimeSummary,
    type FocusedTestCaseExecution,
    type FocusedPlanSummary,
    type FocusedTestCase,
    type FocusedTestObjectiveSummary,
    projectFocusedFindingThread,
    type ScopedFeatureDiscoveryStateSummary,
    type ScanMode,
    type ScopeEnvelopeSummary,
    type StructuredSecurityTestRequestSummary,
} from './focused-plan';

interface LogEntry {
    timestamp: string;
    type: string;
    message: string;
}

interface Vulnerability extends MissionControlVulnerability {}

export default function MissionControlClient() {
    const params = useParams();
    const router = useRouter();
    const { token, isAuthenticated } = useAuthStore();

    // In static export, useParams() returns the placeholder '_' from generateStaticParams.
    // Parse the real scan ID from the URL. Use ref so interval callbacks always have the latest value.
    const scanIdRef = useRef('');
    const [scanId, setScanId] = useState('');

    useEffect(() => {
        let id = '';
        const paramId = params.id as string;
        if (paramId && paramId !== '_') {
            id = paramId;
        } else if (typeof window !== 'undefined') {
            const parts = window.location.pathname.split('/').filter(Boolean);
            if (parts.length >= 2 && parts[0] === 'scan') {
                id = parts[1];
            }
        }
        if (id && id !== '_') {
            scanIdRef.current = id;
            setScanId(id);
        }
    }, [params.id]);

    const [status, setStatus] = useState('initializing');
    const [progress, setProgress] = useState(0);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [vulns, setVulns] = useState<Vulnerability[]>([]);

    // Live status
    const [isAgentActive, setIsAgentActive] = useState(false);
    const [isPaused, setIsPaused] = useState(false);
    const [reportModalOpen, setReportModalOpen] = useState(false);
    const [burpConnected, setBurpConnected] = useState<boolean | null>(null);
    const [activeAgentCount, setActiveAgentCount] = useState(0);
    const [scanCompleted, setScanCompleted] = useState(false);
    const logIndexRef = useRef(0);

    // Chat
    const [command, setCommand] = useState('');
    const [isSending, setIsSending] = useState(false);
    const logsEndRef = useRef<HTMLDivElement>(null);
    const systemLogsEndRef = useRef<HTMLDivElement>(null);
    const systemLogsContainerRef = useRef<HTMLDivElement>(null);
    const chatContainerRef = useRef<HTMLDivElement>(null);

    // Continue Scan
    const [showContinuePanel, setShowContinuePanel] = useState(false);
    const [continueIterations, setContinueIterations] = useState(3);
    const [continuePlanning, setContinuePlanning] = useState(true);
    const [isContinuing, setIsContinuing] = useState(false);

    // Browser visibility state
    const [browserSessionId, setBrowserSessionId] = useState<string | null>(null);
    const [browserIsHeadless, setBrowserIsHeadless] = useState<boolean | null>(null);
    const [browserTransitioning, setBrowserTransitioning] = useState(false);
    const [browserLifecycleState, setBrowserLifecycleState] = useState<string | null>(null);
    const [browserIsLive, setBrowserIsLive] = useState(false);
    const [supportsPause, setSupportsPause] = useState(true);
    const [supportsBrowserVisibility, setSupportsBrowserVisibility] = useState(true);

    // Pentester Loop v2 state
    const [hypothesisCount, setHypothesisCount] = useState<Record<string, number>>({ new: 0, testing: 0, escalated: 0, confirmed: 0, discarded: 0 });
    const [coverageSummary, setCoverageSummary] = useState<{ routesSeen: number; exercised: number; promoted: number; untested: number; coveragePercentage: number } | null>(null);
    const [harvestedCount, setHarvestedCount] = useState(0);
    const [promotedCount, setPromotedCount] = useState(0);
    const [endpointInventory, setEndpointInventory] = useState<EndpointInventorySnapshot | null>(null);
    const [scanMode, setScanMode] = useState<ScanMode>('exploratory');
    const [focusedTestObjective, setFocusedTestObjective] = useState<FocusedTestObjectiveSummary | null>(null);
    const [scopeEnvelope, setScopeEnvelope] = useState<ScopeEnvelopeSummary | null>(null);
    const [scopedTestRequest, setScopedTestRequest] = useState<StructuredSecurityTestRequestSummary | null>(null);
    const [featureDiscoveryState, setFeatureDiscoveryState] = useState<ScopedFeatureDiscoveryStateSummary | null>(null);
    const [focusedTestCases, setFocusedTestCases] = useState<FocusedTestCase[]>([]);
    const [focusedFindings, setFocusedFindings] = useState<FocusedCaseFinding[]>([]);
    const [focusedFindingThreads, setFocusedFindingThreads] = useState<FocusedFindingThread[]>([]);
    const [focusedFindingSummary, setFocusedFindingSummary] = useState<FocusedScanFindingSummary | null>(null);
    const [focusedStorySummary, setFocusedStorySummary] = useState<FocusedStorySummary | null>(null);
    const [focusedPlanSummary, setFocusedPlanSummary] = useState<FocusedPlanSummary | null>(null);
    const [focusedVerdictSummary, setFocusedVerdictSummary] = useState<FocusedScanVerdictSummary | null>(null);
    const [focusedBlockerSummary, setFocusedBlockerSummary] = useState<FocusedScanBlockerSummary | null>(null);
    const [focusedHistoricalCompareState, setFocusedHistoricalCompareState] = useState<FocusedHistoricalCompareState | null>(null);
    const [focusedHistoricalCompareSummary, setFocusedHistoricalCompareSummary] = useState<FocusedHistoricalCompareSummary | null>(null);
    const [focusedAgentTrace, setFocusedAgentTrace] = useState<FocusedReasoningTraceEntry[]>([]);
    const [focusedRequestContextUsage, setFocusedRequestContextUsage] = useState<FocusedContextInfluenceSummary | null>(null);
    const [liveRuntimeSummary, setLiveRuntimeSummary] = useState<MissionControlLiveRuntimeSummary | null>(null);
    const [planActionCaseId, setPlanActionCaseId] = useState<string | null>(null);
    const [planRefreshPending, setPlanRefreshPending] = useState(false);
    const [executePending, setExecutePending] = useState(false);
    const [verdictRefreshPending, setVerdictRefreshPending] = useState(false);
    const [showLegacyRecovery, setShowLegacyRecovery] = useState(false);
    const [evidenceLoadingCaseId, setEvidenceLoadingCaseId] = useState<string | null>(null);
    const [selectedEvidenceCaseId, setSelectedEvidenceCaseId] = useState<string | null>(null);
    const [selectedExecution, setSelectedExecution] = useState<FocusedTestCaseExecution | null>(null);
    const [selectedCaseVerdict, setSelectedCaseVerdict] = useState<FocusedCaseVerdict | null>(null);
    const [selectedPrimaryFinding, setSelectedPrimaryFinding] = useState<FocusedCaseFinding | null>(null);
    const [selectedPrimaryFindingThread, setSelectedPrimaryFindingThread] = useState<FocusedFindingThread | null>(null);
    const [selectedCaseFindings, setSelectedCaseFindings] = useState<FocusedCaseFinding[]>([]);
    const [selectedCaseFindingThreads, setSelectedCaseFindingThreads] = useState<FocusedFindingThread[]>([]);
    const [selectedCaseHistoricalCompare, setSelectedCaseHistoricalCompare] = useState<FocusedCaseHistoricalCompare | null>(null);
    const [selectedHypothesisVisibility, setSelectedHypothesisVisibility] = useState<FocusedHypothesisVisibility | null>(null);
    const [selectedSuspicionExplanation, setSelectedSuspicionExplanation] = useState<FocusedSuspicionExplanation | null>(null);
    const [selectedContextInfluenceSummary, setSelectedContextInfluenceSummary] = useState<FocusedContextInfluenceSummary | null>(null);
    const [selectedEvidenceReasoningLinks, setSelectedEvidenceReasoningLinks] = useState<FocusedEvidenceReasoningLink[]>([]);
    const [selectedReasoningTrace, setSelectedReasoningTrace] = useState<FocusedReasoningTraceEntry[]>([]);
    const [selectedEvidenceBundles, setSelectedEvidenceBundles] = useState<EvidenceBundle[]>([]);
    const [selectedExecutionTrace, setSelectedExecutionTrace] = useState<FocusedExecutionTraceEntry[]>([]);
    const [selectedRailSummary, setSelectedRailSummary] = useState<FocusedRailUsageSummary | null>(null);
    const [selectedInvestigationIssues, setSelectedInvestigationIssues] = useState<FocusedInvestigationIssue[]>([]);

    // Initial fetch
    // Modal State
    const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
    const [vulnChatCommand, setVulnChatCommand] = useState('');
    const [vulnChatHistory, setVulnChatHistory] = useState<{ role: string, content: string }[]>([]);
    const [burpSending, setBurpSending] = useState<string | null>(null); // 'repeater' | 'intruder' | 'scanner' | null
    const [isVulnChatSending, setIsVulnChatSending] = useState(false);

    // Track whether historical data has been loaded (for completed scans)
    const historyLoadedRef = useRef(false);

    function formatLogTime(ts: string): string {
        try {
            const d = new Date(ts);
            return !isNaN(d.getTime())
                ? d.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
                : '00:00:00';
        } catch {
            return '00:00:00';
        }
    }

    useEffect(() => {
        if (!isAuthenticated || !scanId) return;

        // Initial fetch
        fetchScanState();
        fetchLiveStatus();
        loadChatHistory();

        // Polling loops
        const scanInterval = setInterval(fetchScanState, 5000);
        const liveInterval = setInterval(fetchLiveStatus, 2000);

        return () => {
            clearInterval(scanInterval);
            clearInterval(liveInterval);
        };
    }, [isAuthenticated, scanId]);

    useEffect(() => {
        // Auto-scroll system logs only within its own container
        const container = systemLogsContainerRef.current;
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    }, [logs]);

    const fetchScanState = async () => {
        const id = scanIdRef.current;
        if (!id) return;
        try {
            const res = await axios.get(`${API_URL}/scans/${id}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = res.data;

            setStatus(data.status);
            setScanMode(data.scanMode === 'scoped' ? 'scoped' : 'exploratory');
            setVulns(data.vulnerabilities || []);
            setFocusedTestObjective(data.focusedTestObjective || null);
            setScopeEnvelope(data.scopeEnvelope || null);
            setScopedTestRequest(data.scopedTestRequest || null);
            setFeatureDiscoveryState(data.featureDiscoveryState || null);
            setFocusedTestCases(Array.isArray(data.focusedTestCases) ? data.focusedTestCases : []);
            setFocusedFindings(Array.isArray(data.focusedFindings) ? data.focusedFindings : []);
            setFocusedFindingThreads(Array.isArray(data.focusedFindingThreads) ? data.focusedFindingThreads : []);
            setFocusedFindingSummary(data.focusedFindingSummary || null);
            setFocusedStorySummary(data.focusedStorySummary || null);
            setFocusedPlanSummary(data.focusedPlanSummary || null);
            setFocusedVerdictSummary(data.focusedVerdictSummary || null);
            setFocusedBlockerSummary(data.focusedBlockerSummary || null);
            setFocusedHistoricalCompareState(data.focusedHistoricalCompareState || null);
            setFocusedHistoricalCompareSummary(data.focusedHistoricalCompareSummary || null);
            setFocusedAgentTrace(Array.isArray(data.focusedAgentTrace) ? data.focusedAgentTrace : []);
            setFocusedRequestContextUsage(data.focusedRequestContextUsage || null);
            setLiveRuntimeSummary(data.liveRuntimeSummary || data.scopedLiveRuntime || null);
            if (data.endpointInventory !== undefined) {
                setEndpointInventory(data.endpointInventory || null);
            }
            if (selectedEvidenceCaseId) {
                const refreshedCase = Array.isArray(data.focusedTestCases)
                    ? data.focusedTestCases.find((entry: FocusedTestCase) => entry.id === selectedEvidenceCaseId)
                    : null;
                setSelectedPrimaryFinding(refreshedCase?.primaryFinding || null);
                setSelectedPrimaryFindingThread(refreshedCase?.activeFindingThread || null);
                setSelectedCaseFindings(Array.isArray(refreshedCase?.findings) ? refreshedCase.findings : []);
                setSelectedCaseFindingThreads(Array.isArray(refreshedCase?.findingThreads) ? refreshedCase.findingThreads : []);
                setSelectedCaseVerdict(refreshedCase?.latestVerdict || null);
                setSelectedCaseHistoricalCompare(refreshedCase?.historicalCompare || null);
                setSelectedHypothesisVisibility(refreshedCase?.hypothesisVisibility || null);
                setSelectedSuspicionExplanation(refreshedCase?.suspicionExplanation || null);
            }

            // Derive progress from status
            const map: Record<string, number> = {
                'queued': 5,
                'initializing': 10,
                'scoped_discovering': 22,
                'planning': 45,
                'awaiting_review': 58,
                'scoped_executing': 82,
                'scoped_executed': 100,
                'recon': 30,
                'crawling': 50,
                'testing': 60,
                'paused': -1, // Keep current progress when paused
                'attacking': 70,
                'reporting': 90,
                'completed': 100,
                'failed': 100
            };
            const mapped = map[data.status];
            if (mapped !== -1) {
                setProgress(mapped ?? 0);
            }
        } catch (e) {
            console.error(e);
        }
    };

    const fetchLiveStatus = async () => {
        const id = scanIdRef.current;
        if (!id) return;
        try {
            const res = await axios.get(`${API_URL}/scans/${id}/live?since=${logIndexRef.current}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = res.data;

            setIsAgentActive(data.isActive);
            setIsPaused(data.isPaused || false);
            setBurpConnected(data.burpConnected);
            setActiveAgentCount(data.activeAgents || 0);
            setScanCompleted(data.scanCompleted || false);
            setSupportsPause(data.supportsPause !== false);
            setSupportsBrowserVisibility(data.supportsBrowserVisibility !== false);
            if (data.liveRuntimeSummary !== undefined || data.scopedRuntime !== undefined) {
                setLiveRuntimeSummary(data.liveRuntimeSummary || data.scopedRuntime || null);
            }

            // Track browser state
            if (data.browserSessionId) {
                setBrowserSessionId(data.browserSessionId);
                setBrowserIsHeadless(data.browserIsHeadless ?? null);
                setBrowserTransitioning(data.browserTransitioning ?? false);
                setBrowserLifecycleState(data.browserLifecycleState ?? null);
                setBrowserIsLive(Boolean(data.browserIsLive));
            } else {
                setBrowserSessionId(null);
                setBrowserIsHeadless(null);
                setBrowserTransitioning(false);
                setBrowserLifecycleState(null);
                setBrowserIsLive(false);
            }

            // Track pentester loop v2 state
            if (data.hypothesisCount) setHypothesisCount(data.hypothesisCount);
            if (data.coverageSummary) setCoverageSummary(data.coverageSummary);
            if (data.harvestedRequestCount !== undefined) setHarvestedCount(data.harvestedRequestCount);
            if (data.promotedRequestCount !== undefined) setPromotedCount(data.promotedRequestCount);
            if (data.endpointInventory !== undefined) setEndpointInventory(data.endpointInventory || null);

            // Append new logs (only if there are actually new ones)
            if (data.logs && data.logs.length > 0 && data.logsCount > logIndexRef.current) {
                const newLogs = data.logs.map((msg: string) => {
                    // Parse the log message - format: [timestamp] [TYPE] message (e.g. [2026-02-16T00:24:54] [SYSTEM] ...)
                    const tsMatch = msg.match(/^\[([\dT:-]+)\]\s*\[/);
                    let timestamp: string;
                    if (tsMatch) {
                        const parsed = tsMatch[1];
                        const d = new Date(parsed);
                        timestamp = !isNaN(d.getTime()) ? parsed : new Date().toISOString();
                    } else {
                        timestamp = new Date().toISOString();
                    }
                    const typeMatch = msg.match(/\[([A-Z]+)\]/);
                    const type = typeMatch ? typeMatch[1].toLowerCase() : 'agent';
                    return {
                        timestamp,
                        type,
                        message: msg
                    };
                });
                setLogs(prev => [...prev, ...newLogs]);
                logIndexRef.current = data.logsCount;
            }

            // Update phase from live if agent is active
            if (data.isActive && data.phase) {
                setStatus(data.phase);
            }
        } catch (e) {
            // Silently fail - live endpoint may not be critical
        }
    };

    const loadChatHistory = async () => {
        const id = scanIdRef.current;
        if (!id || historyLoadedRef.current) return;
        try {
            const res = await axios.get(`${API_URL}/scans/${id}/chat`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const messages = res.data.messages;
            if (messages && messages.length > 0) {
                historyLoadedRef.current = true;
                // Convert DB chat messages to log entries so they appear in the chat UI
                const chatLogs: LogEntry[] = messages.map((msg: { role: string; content: string; created_at: string }) => ({
                    timestamp: msg.created_at || new Date().toISOString(),
                    type: msg.role === 'human' ? 'human' : 'agent',
                    message: msg.role === 'human' ? `> ${msg.content}` : `[PENPARD] ${msg.content}`
                }));
                setLogs(prev => {
                    // Only add if logs are empty (avoid duplicating on re-render)
                    if (prev.some(l => l.type === 'human' || (l.type === 'agent' && l.message.includes('[PENPARD]')))) return prev;
                    return [...chatLogs, ...prev];
                });
            }
        } catch {
            // Silently fail
        }
    };

    const scrollChatToBottom = () => {
        setTimeout(() => {
            const container = chatContainerRef.current;
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
        }, 50);
    };

    const handleSendCommand = async () => {
        if (!command.trim()) return;

        setIsSending(true);
        const userCommand = command;
        // Add optimistic log for user message
        setLogs(prev => [...prev, { timestamp: new Date().toISOString(), type: 'human', message: `> ${userCommand}` }]);
        scrollChatToBottom();

        try {
            const res = await axios.post(`${API_URL}/scans/${scanIdRef.current}/command`, { command: userCommand }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setCommand('');

            // If we got an LLM response (scan completed, no active agent), display it
            if (res.data.response) {
                setLogs(prev => [...prev, {
                    timestamp: new Date().toISOString(),
                    type: 'agent',
                    message: `[PENPARD] ${res.data.response}`
                }]);
                scrollChatToBottom();
                toast.success('Response received');
            } else {
                toast.success('Command sent to Agent');
            }
        } catch (e: any) {
            const errorMsg = e.response?.data?.message || 'Failed to send command';
            toast.error(errorMsg);
        } finally {
            setIsSending(false);
        }
    };

    const handleStop = async () => {
        if (confirm('Are you sure you want to abort the scan?')) {
            try {
                await axios.post(`${API_URL}/scans/${scanIdRef.current}/stop`, {}, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                toast.success('Scan stopped successfully');
                setStatus('stopped');
                setIsAgentActive(false);
            } catch (e: any) {
                const errorMsg = e.response?.data?.message || 'Failed to stop scan';
                toast.error(errorMsg);
            }
        }
    };

    const handlePause = async () => {
        try {
            await axios.post(`${API_URL}/scans/${scanIdRef.current}/pause`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            toast.success('Scan paused. You can now test manually — PenPard is watching.');
            setIsPaused(true);
            setStatus('paused');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to pause scan');
        }
    };

    const handleResume = async () => {
        try {
            await axios.post(`${API_URL}/scans/${scanIdRef.current}/resume`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            toast.success('Scan resumed!');
            setIsPaused(false);
            setStatus('testing');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to resume scan');
        }
    };

    const handleContinueScan = async () => {
        if (!command.trim()) {
            toast.error('Please type an instruction for the continued scan.');
            return;
        }

        setIsContinuing(true);
        const instruction = command;

        setLogs(prev => [...prev, {
            timestamp: new Date().toISOString(),
            type: 'human',
            message: `> [CONTINUE SCAN] ${instruction} (${continueIterations} rounds, planning: ${continuePlanning ? 'ON' : 'OFF'})`
        }]);

        try {
            const res = await axios.post(`${API_URL}/scans/${scanIdRef.current}/continue`, {
                instruction,
                iterations: continueIterations,
                planningEnabled: continuePlanning,
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });

            setCommand('');
            setShowContinuePanel(false);
            setScanCompleted(false);
            setIsAgentActive(true);
            setStatus('testing');
            logIndexRef.current = 0; // Reset log polling index to get new logs

            toast.success(res.data.message || 'Scan continuing!');
        } catch (e: any) {
            const errorMsg = e.response?.data?.message || 'Failed to continue scan';
            toast.error(errorMsg);
            setLogs(prev => [...prev, {
                timestamp: new Date().toISOString(),
                type: 'error',
                message: `[ERROR] ${errorMsg}`
            }]);
        } finally {
            setIsContinuing(false);
        }
    };

    const getSeverityColor = (sev: string) => {
        switch (sev?.toLowerCase()) {
            case 'critical': return 'text-purple-500 border-purple-500/50 bg-purple-500/10';
            case 'high': return 'text-red-500 border-red-500/50 bg-red-500/10';
            case 'medium': return 'text-orange-500 border-orange-500/50 bg-orange-500/10';
            case 'low': return 'text-yellow-500 border-yellow-500/50 bg-yellow-500/10';
            default: return 'text-blue-500 border-blue-500/50 bg-blue-500/10';
        }
    };

    const handleVulnChatSend = async () => {
        if (!vulnChatCommand.trim() || !selectedVuln) return;

        setIsVulnChatSending(true);
        const userQuestion = vulnChatCommand;
        const userMsg = { role: 'user', content: userQuestion };
        setVulnChatHistory(prev => [...prev, userMsg]);
        setVulnChatCommand('');

        try {
            // Build rich context for LLM including vulnerability details
            const vulnContext = `
Vulnerability Details:
- Name: ${selectedVuln.name}
- Severity: ${selectedVuln.severity}
- Description: ${selectedVuln.description}
- CWE: ${selectedVuln.cwe || 'N/A'}
- CVE: ${selectedVuln.cve || 'N/A'}
- CVSS Score: ${selectedVuln.cvssScore || 'N/A'}
- Request: ${selectedVuln.request || 'Not captured'}
- Response: ${selectedVuln.response || 'Not captured'}
- Remediation: ${selectedVuln.remediation || 'Not specified'}

User Question: ${userQuestion}`;

            const res = await axios.post(`${API_URL}/scans/${scanIdRef.current}/command`, {
                command: vulnContext
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });

            // Use the actual LLM response if available
            const llmResponse = res.data.response || res.data.message || 'Analysis complete.';
            setVulnChatHistory(prev => [...prev, { role: 'assistant', content: llmResponse }]);

        } catch (e: any) {
            const errorMsg = e.response?.data?.message || 'Connection failed. Please try again.';
            setVulnChatHistory(prev => [...prev, { role: 'assistant', content: errorMsg }]);
        } finally {
            setIsVulnChatSending(false);
        }
    };

    const handleSendToBurp = async (target: 'repeater' | 'intruder' | 'scanner') => {
        if (!selectedVuln?.request || burpSending) return;
        setBurpSending(target);
        const labels: Record<string, string> = { repeater: 'Repeater', intruder: 'Intruder', scanner: 'Active Scan' };
        const icons: Record<string, string> = { repeater: '🔁', intruder: '🎯', scanner: '🔍' };
        try {
            await axios.post(`${API_URL}/scans/burp/send`, {
                rawRequest: selectedVuln.request,
                vulnName: selectedVuln.name,
                target
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            toast.success(`Sent to Burp ${labels[target]}!`, { icon: icons[target] });
        } catch (e: any) {
            const msg = e.response?.data?.message || `Failed to send to ${labels[target]}`;
            toast.error(msg);
        } finally {
            setBurpSending(null);
        }
    };

    const handleRefreshFocusedPlan = async () => {
        if (!scanIdRef.current) return;
        setPlanRefreshPending(true);

        try {
            const response = await axios.post(`${API_URL}/scans/${scanIdRef.current}/plan-focused-tests`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = response.data;

            if (data.status) {
                setStatus(data.status);
                if (data.status === 'awaiting_review') {
                    setProgress(100);
                } else if (data.status === 'scoped_discovering') {
                    setProgress(22);
                } else if (data.status === 'planning') {
                    setProgress(35);
                }
            }
            if (Array.isArray(data.focusedTestCases)) {
                setFocusedTestCases(data.focusedTestCases);
            }
            setFocusedFindings(Array.isArray(data.focusedFindings) ? data.focusedFindings : []);
            setFocusedFindingThreads(Array.isArray(data.focusedFindingThreads) ? data.focusedFindingThreads : []);
            setFocusedFindingSummary(data.focusedFindingSummary || null);
            setFocusedStorySummary(data.focusedStorySummary || null);
            if (data.scopedTestRequest !== undefined) {
                setScopedTestRequest(data.scopedTestRequest || null);
            }
            if (data.featureDiscoveryState !== undefined) {
                setFeatureDiscoveryState(data.featureDiscoveryState || null);
            }
            if (data.focusedPlanSummary) {
                setFocusedPlanSummary(data.focusedPlanSummary);
            }
            setFocusedVerdictSummary(data.focusedVerdictSummary || null);
            setFocusedBlockerSummary(data.focusedBlockerSummary || null);
            setFocusedHistoricalCompareState(data.focusedHistoricalCompareState || null);
            setFocusedHistoricalCompareSummary(data.focusedHistoricalCompareSummary || null);
            setFocusedAgentTrace(Array.isArray(data.focusedAgentTrace) ? data.focusedAgentTrace : []);
            setFocusedRequestContextUsage(data.focusedRequestContextUsage || null);
            if (data.liveRuntimeSummary !== undefined || data.scopedLiveRuntime !== undefined) {
                setLiveRuntimeSummary(data.liveRuntimeSummary || data.scopedLiveRuntime || null);
            }

            toast.success(status === 'awaiting_review' ? 'Legacy scoped plan refreshed.' : 'Scoped mission hints refreshed.');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to re-seed the scoped mission');
        } finally {
            setPlanRefreshPending(false);
        }
    };

    const handleFocusedCaseUpdate = async (
        caseId: string,
        updates: Partial<Pick<FocusedTestCase, 'priority' | 'status' | 'reviewState'>>,
    ) => {
        setPlanActionCaseId(caseId);

        try {
            const response = await axios.patch(`${API_URL}/scans/${scanIdRef.current}/focused-test-cases/${caseId}`, updates, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = response.data;

            if (data.focusedTestCase) {
                setFocusedTestCases((current) => current.map((testCase) => (
                    testCase.id === caseId ? data.focusedTestCase : testCase
                )));
                if (selectedEvidenceCaseId === caseId) {
                    setSelectedPrimaryFinding(data.focusedTestCase.primaryFinding || null);
                    setSelectedPrimaryFindingThread(data.focusedTestCase.activeFindingThread || null);
                    setSelectedCaseFindings(Array.isArray(data.focusedTestCase.findings) ? data.focusedTestCase.findings : []);
                    setSelectedCaseFindingThreads(Array.isArray(data.focusedTestCase.findingThreads) ? data.focusedTestCase.findingThreads : []);
                    setSelectedHypothesisVisibility(data.focusedTestCase.hypothesisVisibility || null);
                    setSelectedSuspicionExplanation(data.focusedTestCase.suspicionExplanation || null);
                }
            }
            if (data.focusedFindings !== undefined) {
                setFocusedFindings(Array.isArray(data.focusedFindings) ? data.focusedFindings : []);
            }
            if (data.focusedFindingThreads !== undefined) {
                setFocusedFindingThreads(Array.isArray(data.focusedFindingThreads) ? data.focusedFindingThreads : []);
            }
            if (data.focusedFindingSummary !== undefined) {
                setFocusedFindingSummary(data.focusedFindingSummary || null);
            }
            if (data.focusedStorySummary !== undefined) {
                setFocusedStorySummary(data.focusedStorySummary || null);
            }
            if (data.focusedPlanSummary) {
                setFocusedPlanSummary(data.focusedPlanSummary);
            }
            if (data.focusedVerdictSummary !== undefined) {
                setFocusedVerdictSummary(data.focusedVerdictSummary || null);
            }
            if (data.focusedBlockerSummary !== undefined) {
                setFocusedBlockerSummary(data.focusedBlockerSummary || null);
            }
            if (data.focusedHistoricalCompareState !== undefined) {
                setFocusedHistoricalCompareState(data.focusedHistoricalCompareState || null);
            }
            if (data.focusedHistoricalCompareSummary !== undefined) {
                setFocusedHistoricalCompareSummary(data.focusedHistoricalCompareSummary || null);
            }
            if (data.focusedAgentTrace !== undefined) {
                setFocusedAgentTrace(Array.isArray(data.focusedAgentTrace) ? data.focusedAgentTrace : []);
            }
            if (data.focusedRequestContextUsage !== undefined) {
                setFocusedRequestContextUsage(data.focusedRequestContextUsage || null);
            }
            if (data.liveRuntimeSummary !== undefined || data.scopedLiveRuntime !== undefined) {
                setLiveRuntimeSummary(data.liveRuntimeSummary || data.scopedLiveRuntime || null);
            }

            toast.success('Focused test case updated.');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to update focused test case');
        } finally {
            setPlanActionCaseId(null);
        }
    };

    const handleRunFocusedExecution = async (caseIds?: string[]) => {
        if (!scanIdRef.current) return;
        setExecutePending(true);

        try {
            const response = await axios.post(`${API_URL}/scans/${scanIdRef.current}/execute-focused-tests`, caseIds?.length ? { caseIds } : {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (response.data?.status) {
                setStatus(response.data.status);
                setProgress(response.data.status === 'scoped_executing' ? 85 : progress);
            } else {
                setStatus('scoped_executing');
                setProgress(85);
            }
            setFocusedVerdictSummary(null);
            setFocusedBlockerSummary(null);
            setFocusedHistoricalCompareState(null);
            setFocusedHistoricalCompareSummary(null);
            setFocusedFindings([]);
            setFocusedFindingThreads([]);
            setFocusedFindingSummary(null);
            setFocusedStorySummary(null);
            setSelectedPrimaryFinding(null);
            setSelectedPrimaryFindingThread(null);
            setSelectedCaseFindings([]);
            setSelectedCaseFindingThreads([]);
            setSelectedHypothesisVisibility(null);
            setSelectedSuspicionExplanation(null);
            setSelectedContextInfluenceSummary(null);
            setSelectedEvidenceReasoningLinks([]);
            setSelectedReasoningTrace([]);
            setSelectedCaseVerdict(null);
            setSelectedPrimaryFinding(null);
            setSelectedPrimaryFindingThread(null);
            setSelectedCaseFindings([]);
            setSelectedCaseFindingThreads([]);
            setSelectedCaseHistoricalCompare(null);
            setSelectedExecutionTrace([]);
            setSelectedRailSummary(null);
            setSelectedInvestigationIssues([]);
            toast.success(caseIds?.length
                ? 'Focused test case queued for retry.'
                : isLegacyScopedReviewMode
                    ? 'Approved legacy cases are now executing.'
                    : 'Bounded live mission execution is now running.');
            await fetchScanState();
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to launch focused execution');
        } finally {
            setExecutePending(false);
        }
    };

    const handleRefreshFocusedVerdicts = async () => {
        if (!scanIdRef.current) return;
        setVerdictRefreshPending(true);

        try {
            const response = await axios.post(`${API_URL}/scans/${scanIdRef.current}/generate-focused-verdicts`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const data = response.data;
            if (Array.isArray(data.focusedTestCases)) {
                setFocusedTestCases(data.focusedTestCases);
            }
            if (data.focusedFindings !== undefined) {
                setFocusedFindings(Array.isArray(data.focusedFindings) ? data.focusedFindings : []);
            }
            if (data.focusedFindingThreads !== undefined) {
                setFocusedFindingThreads(Array.isArray(data.focusedFindingThreads) ? data.focusedFindingThreads : []);
            }
            if (data.focusedFindingSummary !== undefined) {
                setFocusedFindingSummary(data.focusedFindingSummary || null);
            }
            if (data.focusedPlanSummary) {
                setFocusedPlanSummary(data.focusedPlanSummary);
            }
            if (data.focusedVerdictSummary !== undefined) {
                setFocusedVerdictSummary(data.focusedVerdictSummary || null);
            }
            if (data.focusedBlockerSummary !== undefined) {
                setFocusedBlockerSummary(data.focusedBlockerSummary || null);
            }
            if (data.focusedHistoricalCompareState !== undefined) {
                setFocusedHistoricalCompareState(data.focusedHistoricalCompareState || null);
            }
            if (data.focusedHistoricalCompareSummary !== undefined) {
                setFocusedHistoricalCompareSummary(data.focusedHistoricalCompareSummary || null);
            }
            if (data.focusedAgentTrace !== undefined) {
                setFocusedAgentTrace(Array.isArray(data.focusedAgentTrace) ? data.focusedAgentTrace : []);
            }
            if (data.focusedRequestContextUsage !== undefined) {
                setFocusedRequestContextUsage(data.focusedRequestContextUsage || null);
            }
            if (data.liveRuntimeSummary !== undefined || data.scopedLiveRuntime !== undefined) {
                setLiveRuntimeSummary(data.liveRuntimeSummary || data.scopedLiveRuntime || null);
            }
            if (selectedEvidenceCaseId) {
                const refreshedCase = Array.isArray(data.focusedTestCases)
                    ? data.focusedTestCases.find((entry: FocusedTestCase) => entry.id === selectedEvidenceCaseId)
                    : null;
                setSelectedPrimaryFinding(refreshedCase?.primaryFinding || null);
                setSelectedPrimaryFindingThread(refreshedCase?.activeFindingThread || null);
                setSelectedCaseFindings(Array.isArray(refreshedCase?.findings) ? refreshedCase.findings : []);
                setSelectedCaseFindingThreads(Array.isArray(refreshedCase?.findingThreads) ? refreshedCase.findingThreads : []);
                setSelectedCaseVerdict(refreshedCase?.latestVerdict || null);
                setSelectedCaseHistoricalCompare(refreshedCase?.historicalCompare || null);
                setSelectedHypothesisVisibility(refreshedCase?.hypothesisVisibility || null);
                setSelectedSuspicionExplanation(refreshedCase?.suspicionExplanation || null);
            }
            toast.success('Focused verdicts refreshed.');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to refresh focused verdicts');
        } finally {
            setVerdictRefreshPending(false);
        }
    };

    const handleInspectEvidence = async (caseId: string) => {
        if (!scanIdRef.current) return;
        setEvidenceLoadingCaseId(caseId);

        try {
            const response = await axios.get(`${API_URL}/scans/${scanIdRef.current}/focused-test-cases/${caseId}/evidence`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setSelectedEvidenceCaseId(caseId);
            setSelectedExecution(response.data?.execution || null);
            setSelectedCaseVerdict(response.data?.caseVerdict || null);
            setSelectedPrimaryFinding(response.data?.primaryFinding || response.data?.focusedTestCase?.primaryFinding || null);
            setSelectedPrimaryFindingThread(response.data?.primaryFindingThread || response.data?.focusedTestCase?.activeFindingThread || null);
            setSelectedCaseFindings(Array.isArray(response.data?.findings)
                ? response.data.findings
                : Array.isArray(response.data?.focusedTestCase?.findings)
                    ? response.data.focusedTestCase.findings
                    : []);
            setSelectedCaseFindingThreads(Array.isArray(response.data?.findingThreads)
                ? response.data.findingThreads
                : Array.isArray(response.data?.focusedTestCase?.findingThreads)
                    ? response.data.focusedTestCase.findingThreads
                    : []);
            setSelectedCaseHistoricalCompare(response.data?.focusedTestCase?.historicalCompare || null);
            setSelectedHypothesisVisibility(response.data?.hypothesisVisibility || response.data?.focusedTestCase?.hypothesisVisibility || null);
            setSelectedSuspicionExplanation(response.data?.suspicionExplanation || response.data?.focusedTestCase?.suspicionExplanation || null);
            setSelectedContextInfluenceSummary(response.data?.contextInfluenceSummary || null);
            setSelectedEvidenceReasoningLinks(Array.isArray(response.data?.evidenceReasoningLinks) ? response.data.evidenceReasoningLinks : []);
            setSelectedReasoningTrace(Array.isArray(response.data?.reasoningTrace) ? response.data.reasoningTrace : []);
            setSelectedEvidenceBundles(Array.isArray(response.data?.evidenceBundles) ? response.data.evidenceBundles : []);
            setSelectedExecutionTrace(Array.isArray(response.data?.executionTrace) ? response.data.executionTrace : []);
            setSelectedRailSummary(response.data?.railSummary || null);
            setSelectedInvestigationIssues(Array.isArray(response.data?.investigationIssues) ? response.data.investigationIssues : []);
            if (response.data?.focusedTestCase?.id === caseId) {
                setFocusedTestCases((prev) => prev.map((entry) => (
                    entry.id === caseId ? response.data.focusedTestCase : entry
                )));
            }
            if (response.data?.focusedVerdictSummary !== undefined) {
                setFocusedVerdictSummary(response.data.focusedVerdictSummary || null);
            }
            if (response.data?.focusedFindingSummary !== undefined) {
                setFocusedFindingSummary(response.data.focusedFindingSummary || null);
            }
            if (response.data?.focusedStorySummary !== undefined) {
                setFocusedStorySummary(response.data.focusedStorySummary || null);
            }
            if (response.data?.focusedFindings !== undefined) {
                setFocusedFindings(Array.isArray(response.data.focusedFindings) ? response.data.focusedFindings : []);
            }
            if (response.data?.focusedFindingThreads !== undefined) {
                setFocusedFindingThreads(Array.isArray(response.data.focusedFindingThreads) ? response.data.focusedFindingThreads : []);
            }
            if (response.data?.focusedBlockerSummary !== undefined) {
                setFocusedBlockerSummary(response.data.focusedBlockerSummary || null);
            }
            if (response.data?.focusedHistoricalCompareState !== undefined) {
                setFocusedHistoricalCompareState(response.data.focusedHistoricalCompareState || null);
            }
            if (response.data?.focusedHistoricalCompareSummary !== undefined) {
                setFocusedHistoricalCompareSummary(response.data.focusedHistoricalCompareSummary || null);
            }
            if (response.data?.focusedAgentTrace !== undefined) {
                setFocusedAgentTrace(Array.isArray(response.data.focusedAgentTrace) ? response.data.focusedAgentTrace : []);
            }
            if (response.data?.focusedRequestContextUsage !== undefined) {
                setFocusedRequestContextUsage(response.data.focusedRequestContextUsage || null);
            }
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to load focused evidence');
        } finally {
            setEvidenceLoadingCaseId(null);
        }
    };

    const buildScreenshotDataUrl = (screenshotRef?: EvidenceBundle['screenshotRef'] | null) => {
        if (!screenshotRef?.value) {
            return null;
        }
        const mimeType = screenshotRef.mimeType || 'image/png';
        return `data:${mimeType};base64,${screenshotRef.value}`;
    };

    const formatExpectationSummary = (bundle: EvidenceBundle) => {
        const expectations = bundle.browserState?.expectations || [];
        if (expectations.length === 0) {
            return null;
        }
        const matched = expectations.filter((entry) => entry.matched).length;
        return `${matched}/${expectations.length} browser checks matched`;
    };

    // Show loading until scanId is resolved from URL
    const isScopedScan = scanMode === 'scoped';
    const endpointRows = buildEndpointDisplayRows(endpointInventory, 24);
    const focusedCaseRows = buildFocusedCaseRows(focusedTestCases);
    const focusedCaseMap = new Map(focusedTestCases.map((testCase) => [testCase.id, testCase]));
    const focusedFindingRows = buildFocusedScanFindingRows(focusedFindings, focusedTestCases, focusedFindingThreads);
    const visibleFocusedFindingRows = focusedFindingRows.filter((entry) => entry.finding.status !== 'not_confirmed');
    const scopedFindingCaseMap = new Map(visibleFocusedFindingRows.map((entry) => [String(entry.finding.id), entry.caseId]));
    const scopedLiveFindingItems: MissionControlVulnerability[] = visibleFocusedFindingRows.map(({ finding, source, caseTitle, targetLabel }) => ({
        id: finding.id,
        name: finding.title,
        severity: finding.status === 'confirmed' ? 'high' : finding.status === 'likely' ? 'medium' : finding.status === 'suspicious' ? 'low' : 'info',
        badgeLabel: formatFocusedFindingStatus(finding.status),
        description: finding.strongestSupportSummary || finding.nextStepSummary || `${caseTitle} on ${targetLabel}`,
        metadata: [
            source === 'runtime_thread' ? 'Provisional live thread' : caseTitle,
            targetLabel,
            formatFocusedFindingFamily(finding.family),
            `${finding.suspicionScore}% suspicion`,
        ].filter(Boolean),
    }));
    const scopedStandardFindingItems: MissionControlVulnerability[] = vulns.map((vulnerability) => ({
        ...vulnerability,
        badgeLabel: vulnerability.severity,
        metadata: [
            vulnerability.request ? 'Burp-visible request evidence' : 'Evidence pending request capture',
            vulnerability.cwe,
            vulnerability.cvssScore ? `CVSS ${vulnerability.cvssScore}` : null,
        ].filter((entry): entry is string => !!entry),
    }));
    const liveFindingItems: MissionControlVulnerability[] = isScopedScan
        ? [...scopedStandardFindingItems, ...scopedLiveFindingItems]
        : vulns;
    const selectedEvidenceCase = selectedEvidenceCaseId ? focusedCaseMap.get(selectedEvidenceCaseId) || null : null;
    const selectedEvidenceRow = selectedEvidenceCaseId
        ? focusedCaseRows.find((row) => row.id === selectedEvidenceCaseId) || null
        : null;
    const effectiveSelectedFindingThread = selectedPrimaryFindingThread || selectedEvidenceCase?.activeFindingThread || null;
    const effectiveSelectedThreadFindings = selectedCaseFindingThreads.length > 0
        ? selectedCaseFindingThreads
        : (Array.isArray(selectedEvidenceCase?.findingThreads) ? selectedEvidenceCase.findingThreads : []);
    const effectiveSelectedCaseVerdict = selectedCaseVerdict || selectedEvidenceCase?.latestVerdict || null;
    const effectiveSelectedPrimaryFinding = selectedPrimaryFinding
        || selectedEvidenceCase?.primaryFinding
        || (effectiveSelectedFindingThread ? projectFocusedFindingThread(effectiveSelectedFindingThread) : null);
    const effectiveSelectedCaseFindings = selectedCaseFindings.length > 0
        ? selectedCaseFindings
        : (Array.isArray(selectedEvidenceCase?.findings) && selectedEvidenceCase.findings.length > 0
            ? selectedEvidenceCase.findings
            : effectiveSelectedThreadFindings.map((thread) => projectFocusedFindingThread(thread)));
    const effectiveSelectedCaseHistoricalCompare = selectedCaseHistoricalCompare || selectedEvidenceCase?.historicalCompare || null;
    const effectiveSelectedHypothesisVisibility = selectedHypothesisVisibility || selectedEvidenceCase?.hypothesisVisibility || null;
    const effectiveSelectedSuspicionExplanation = selectedSuspicionExplanation || selectedEvidenceCase?.suspicionExplanation || null;
    const effectiveSelectedContextInfluenceSummary = selectedContextInfluenceSummary || focusedRequestContextUsage || null;
    const effectiveSelectedRailSummary = selectedRailSummary || selectedEvidenceCase?.executionRailSummary || null;
    const effectiveSelectedSupportProvenance = effectiveSelectedPrimaryFinding?.supportProvenance
        || effectiveSelectedFindingThread?.supportProvenance
        || effectiveSelectedCaseVerdict?.supportProvenance
        || null;
    const effectiveSelectedRequestEvidenceStory = effectiveSelectedPrimaryFinding?.requestEvidenceStory
        || effectiveSelectedFindingThread?.requestEvidenceStory
        || effectiveSelectedCaseVerdict?.requestEvidenceStory
        || null;
    const effectiveSelectedExecutionTrace = selectedExecutionTrace.length > 0
        ? selectedExecutionTrace
        : (selectedEvidenceCase?.latestExecutionTracePreview || []);
    const effectiveSelectedReasoningTrace = selectedReasoningTrace.length > 0
        ? selectedReasoningTrace
        : (selectedEvidenceCase?.latestReasoningTracePreview || []);
    const selectedEvidenceEmptyState = buildFocusedEvidenceEmptyState({
        presentationState: selectedEvidenceRow?.executionPresentationState || selectedEvidenceCase?.executionPresentationState,
        reviewState: selectedEvidenceCase?.reviewState,
        status: selectedEvidenceCase?.status,
    });
    const missionControlPolicy = deriveMissionControlPolicy({
        scanMode,
        status,
        legacyRecoveryRequested: showLegacyRecovery,
    });
    const isLegacyScopedReviewMode = missionControlPolicy.isLegacyScopedRecoveryState;
    const showLegacyRecoveryPanel = missionControlPolicy.showLegacyRecoveryTools;
    const showScopedSecondaryContext = missionControlPolicy.showScopedSecondaryContext;
    const isPrimaryMissionActive = isAgentActive || [
        'scoped_discovering',
        'planning',
        'scoped_executing',
        'scanning',
        'crawling',
        'testing',
        'executing',
        'replanning',
        'reporting',
    ].includes(status);
    const scopedReviewCounts = summarizeScopedPlanReviewCounts(focusedTestCases, focusedPlanSummary);
    const runnableFocusedCaseCount = scopedReviewCounts.approvedCount;
    const scopedExecutionLabel = status === 'scoped_executing'
        ? 'Running'
        : status === 'scoped_executed'
            ? 'Completed'
            : runnableFocusedCaseCount > 0
                ? 'Ready'
                : 'Not Started';
    const scopedLiveRuntime = liveRuntimeSummary;
    const scopedRuntimeBoundary = scopedLiveRuntime?.boundarySummary || null;
    const scopedRuntimeRequest = scopedLiveRuntime?.lastRequestSummary || null;
    const scopedActiveCaseLabel = scopedLiveRuntime?.activeCaseTitle || focusedCaseRows[0]?.title || null;
    const scopedActiveFindingLabel = scopedLiveRuntime?.activeFindingTitle || focusedFindingRows[0]?.finding.title || null;
    const focusedVerdictCounts = focusedVerdictSummary?.countsByVerdict || {
        pass: 0,
        fail: 0,
        inconclusive: 0,
        needs_review: 0,
    };
    const focusedFindingCounts = focusedFindingSummary?.countsByStatus || {
        confirmed: 0,
        likely: 0,
        suspicious: 0,
        inconclusive: 0,
        not_confirmed: 0,
    };
    const scopedAgentTracePreview = buildFocusedReasoningTracePreview(focusedAgentTrace, 18);
    const blockerImpactCounts = focusedBlockerSummary?.countsByImpact || {
        informational: 0,
        degrading: 0,
        blocking: 0,
    };
    const focusedHistoricalCounts = focusedHistoricalCompareSummary || {
        improvedCount: 0,
        regressedCount: 0,
        unchangedCount: 0,
        weakerConfidenceCount: 0,
        strongerConfidenceCount: 0,
        newlyIntroducedCount: 0,
        notComparableCount: 0,
        removedPriorCaseCount: 0,
        repeatedBlockerFamilies: [],
        newBlockerFamilies: [],
        resolvedBlockerFamilies: [],
        stabilityNotes: [],
        manualReviewRecommended: false,
        overallChangeClassification: 'no_material_change' as const,
    };
    const focusedStoryCaseMap = new Map((focusedStorySummary?.cases || []).map((entry) => [entry.caseId, entry]));
    const unresolvedBlockerTypes = Object.entries(focusedBlockerSummary?.unresolvedByType || {})
        .filter(([, count]) => Number(count) > 0)
        .sort((left, right) => Number(right[1]) - Number(left[1]));
    const summarizeFocusedCaseInputs = (row: typeof focusedCaseRows[number]) => (
        row.caseIntelligence?.candidateInputs
            ?.slice(0, 3)
            .map((entry) => `${entry.location}:${entry.name}`)
            || focusedStoryCaseMap.get(row.id)?.targetedInputs?.slice(0, 3)
            || []
    );
    const summarizeFocusedCaseStopReason = (row: typeof focusedCaseRows[number]) => (
        row.suspicionExplanation?.boundedStopReason
        || row.primaryFinding?.blockingConstraintSummary
        || focusedStoryCaseMap.get(row.id)?.blockedBy?.[0]
        || row.latestVerdict?.interpretationSummary?.followUpDecisionSummary
        || row.investigationSummary?.latestIssueTitle
        || null
    );
    const summarizeFocusedCaseNextStep = (row: typeof focusedCaseRows[number]) => (
        row.primaryFinding?.nextStepSummary
        || focusedStoryCaseMap.get(row.id)?.nextStep
        || row.latestVerdict?.interpretationSummary?.nextStepSummary
        || null
    );
    const browserToggleAction = browserLifecycleState === 'visible_active' ? 'hide' : 'show';
    const browserStatusLabel = (() => {
        switch (browserLifecycleState) {
            case 'visible_active':
                return 'Visible';
            case 'headless_active':
                return 'Headless';
            case 'hidden':
                return 'Hidden';
            case 'manually_closed':
                return 'Closed';
            case 'crashed_or_disconnected':
                return 'Unavailable';
            case 'stale_reference':
                return 'Stale';
            case 'closing':
                return 'Closing';
            default:
                return browserIsHeadless ? 'Headless' : 'Visible';
        }
    })();
    const browserStatusDotClass = (() => {
        switch (browserLifecycleState) {
            case 'visible_active':
                return 'bg-green-500';
            case 'headless_active':
            case 'hidden':
                return 'bg-purple-500';
            case 'manually_closed':
            case 'crashed_or_disconnected':
            case 'stale_reference':
                return 'bg-amber-500';
            case 'closing':
                return 'bg-slate-500';
            default:
                return browserIsHeadless ? 'bg-purple-500' : 'bg-green-500';
        }
    })();
    const browserButtonLabel = (() => {
        if (browserTransitioning) return 'Switching...';
        switch (browserLifecycleState) {
            case 'visible_active':
                return 'Hide Browser';
            case 'manually_closed':
            case 'crashed_or_disconnected':
            case 'stale_reference':
            case 'closed':
                return 'Reopen Browser';
            default:
                return 'Show Browser';
        }
    })();
    const browserButtonClass = browserLifecycleState === 'visible_active'
        ? 'bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20'
        : browserLifecycleState === 'manually_closed'
            || browserLifecycleState === 'crashed_or_disconnected'
            || browserLifecycleState === 'stale_reference'
            || browserLifecycleState === 'closed'
            ? 'bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20'
            : 'bg-purple-500/10 border border-purple-500/30 text-purple-400 hover:bg-purple-500/20';
    const getCaseCardClassName = (row: typeof focusedCaseRows[number]) => {
        if (row.status === 'disabled') {
            return 'border-slate-800 bg-slate-950/60 opacity-80';
        }
        if (row.reviewState === 'approved') {
            return 'border-emerald-500/30 bg-emerald-500/5 shadow-[0_0_0_1px_rgba(16,185,129,0.08)]';
        }
        if (selectedEvidenceCaseId === row.id) {
            return 'border-cyan-500/40 bg-cyan-500/5 shadow-[0_0_0_1px_rgba(34,211,238,0.1)]';
        }
        return 'border-violet-500/20 bg-black/30 hover:border-violet-500/35';
    };

    const getReviewBadgeClassName = (row: typeof focusedCaseRows[number]) => {
        if (row.reviewState === 'approved') {
            return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
        }
        if (row.reviewState === 'rejected') {
            return 'border-red-500/30 bg-red-500/10 text-red-200';
        }
        return 'border-violet-500/30 bg-violet-500/10 text-violet-200';
    };

    const getPriorityBadgeClassName = (priority: typeof focusedCaseRows[number]['priority']) => {
        switch (priority) {
            case 'high':
                return 'border-red-500/30 bg-red-500/10 text-red-200';
            case 'low':
                return 'border-slate-600 bg-slate-800/60 text-slate-300';
            default:
                return 'border-amber-500/30 bg-amber-500/10 text-amber-200';
        }
    };

    const getExecutionBadgeClassName = (presentationState: typeof focusedCaseRows[number]['executionPresentationState']) => {
        switch (presentationState) {
            case 'completed_with_evidence':
                return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
            case 'completed_without_evidence':
                return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200';
            case 'running':
                return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200';
            case 'failed_to_execute':
                return 'border-red-500/30 bg-red-500/10 text-red-200';
            case 'blocked':
                return 'border-amber-500/30 bg-amber-500/10 text-amber-200';
            case 'awaiting_approval':
                return 'border-violet-500/30 bg-violet-500/10 text-violet-200';
            case 'skipped_not_approved':
            case 'skipped_disabled':
            case 'not_run_yet':
                return 'border-slate-600 bg-slate-800/60 text-slate-300';
            default:
                return 'border-slate-600 bg-slate-800/60 text-slate-200';
        }
    };

    const getVerdictBadgeClassName = (verdictState: string | null | undefined) => {
        switch (verdictState) {
            case 'pass':
                return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
            case 'fail':
                return 'border-red-500/30 bg-red-500/10 text-red-200';
            case 'needs_review':
                return 'border-violet-500/30 bg-violet-500/10 text-violet-200';
            case 'inconclusive':
                return 'border-amber-500/30 bg-amber-500/10 text-amber-200';
            default:
                return 'border-slate-600 bg-slate-800/60 text-slate-300';
        }
    };

    const getSupportProvenanceBadgeClassName = (rail: string | null | undefined) => {
        switch (rail) {
            case 'request':
                return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-100';
            case 'browser':
                return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100';
            case 'hybrid':
                return 'border-violet-500/30 bg-violet-500/10 text-violet-100';
            default:
                return 'border-slate-600 bg-slate-800/60 text-slate-300';
        }
    };

    if (!scanId) {
        return (
            <div className="min-h-screen bg-black text-slate-200 flex items-center justify-center">
                <div className="text-center space-y-4">
                    <div className="w-12 h-12 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
                    <p className="text-slate-400">Loading Mission Control...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-black text-slate-200 font-sans selection:bg-cyan-500/30">
            {/* Header */}
            <header className="border-b border-white/10 bg-black/50 backdrop-blur fixed top-10 w-full z-50">
                <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link href="/dashboard" className="p-2 hover:bg-white/5 rounded-lg transition-colors">
                            <ArrowLeft className="w-5 h-5 text-slate-400" />
                        </Link>
                        <div>
                            <h1 className="font-bold text-white flex items-center gap-2">
                                <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
                                Mission Control
                            </h1>
                            <div className="text-xs text-slate-500 font-mono">ID: {scanId.substring(0, 8)}...</div>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        {/* Browser Show/Hide Toggle */}
                        {isAgentActive && browserSessionId && status !== 'completed' && status !== 'failed' && status !== 'stopped' && (
                            <button
                                onClick={async () => {
                                    if (browserTransitioning) return;
                                    setBrowserTransitioning(true);
                                    try {
                                        const endpoint = browserToggleAction;
                                        const response = await axios.post(`${API_URL}/scans/${scanIdRef.current}/browser/${endpoint}`, {}, {
                                            headers: { Authorization: `Bearer ${token}` }
                                        });
                                        const visibility = response.data || {};
                                        setBrowserIsHeadless(visibility.isHeadless ?? null);
                                        setBrowserTransitioning(Boolean(visibility.transitioning));
                                        setBrowserLifecycleState(visibility.lifecycleState ?? null);
                                        setBrowserIsLive(Boolean(visibility.isLive));
                                        toast.success(
                                            visibility.message
                                                || (endpoint === 'show' ? 'Browser window opened' : 'Browser hidden')
                                        );
                                    } catch (e: any) {
                                        toast.error(e.response?.data?.message || 'Failed to toggle browser');
                                    } finally {
                                        setBrowserTransitioning(false);
                                    }
                                }}
                                disabled={browserTransitioning}
                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${browserButtonClass} disabled:opacity-50`}
                                title={browserToggleAction === 'show' ? 'Show or reopen the Chromium browser window' : 'Hide browser back to headless mode'}
                            >
                                {browserTransitioning ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                ) : browserToggleAction === 'show' ? (
                                    <Eye className="w-3.5 h-3.5" />
                                ) : (
                                    <EyeOff className="w-3.5 h-3.5" />
                                )}
                                {browserButtonLabel}
                            </button>
                        )}
                        {/* Pause / Resume Button */}
                        {isAgentActive && !isPaused && status !== 'completed' && status !== 'failed' && status !== 'stopped' && (
                            <button
                                onClick={handlePause}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 transition-colors text-xs font-medium"
                            >
                                <Pause className="w-3.5 h-3.5" /> Pause
                            </button>
                        )}
                        {isPaused && (
                            <button
                                onClick={handleResume}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors text-xs font-medium animate-pulse"
                            >
                                <Play className="w-3.5 h-3.5" /> Resume
                            </button>
                        )}
                        {(status === 'completed' || status === 'stopped' || status === 'scoped_executed') && (
                            <button
                                onClick={() => setReportModalOpen(true)}
                                className="btn-primary flex items-center gap-2 text-xs"
                            >
                                <Download className="w-4 h-4" /> Export Report
                            </button>
                        )}
                        <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                            isPaused ? 'bg-amber-500/20 text-amber-400' :
                            status === 'scoped_discovering' ? 'bg-blue-500/20 text-blue-300 animate-pulse' :
                            status === 'planning' ? 'bg-cyan-500/20 text-cyan-300 animate-pulse' :
                            status === 'awaiting_review' ? 'bg-violet-500/20 text-violet-300' :
                            status === 'scoped_executing' ? 'bg-emerald-500/20 text-emerald-300 animate-pulse' :
                            status === 'scoped_executed' ? 'bg-emerald-500/20 text-emerald-300' :
                            status === 'scanning' || status === 'crawling' || status === 'testing' ? 'bg-cyan-500/20 text-cyan-400 animate-pulse' :
                            status === 'completed' ? 'bg-green-500/20 text-green-400' :
                            status === 'failed' ? 'bg-red-500/20 text-red-300' :
                            status === 'stopped' ? 'bg-cyan-500/20 text-cyan-400' :
                            'bg-slate-800 text-slate-400'
                            }`}>
                            {isPaused ? 'paused' : status}
                        </div>
                    </div>
                </div>
            </header>

            <main className="pt-20 pb-8 px-4 max-w-[1600px] mx-auto space-y-4">
                <div className="min-h-[calc(100vh-theme(spacing.10))] grid grid-cols-12 gap-6">

                {/* Left: Agent Status & Logs */}
                <div className="col-span-12 lg:col-span-3 flex flex-col gap-6 h-[calc(100vh-8rem)]">
                    <div className="card p-5 border-cyan-500/20 relative overflow-hidden flex-shrink-0">
                        <div className="absolute top-0 right-0 p-3 opacity-20">
                            <Eye className="w-12 h-12 text-cyan-500" />
                        </div>
                        <h2 className="text-sm uppercase tracking-widest text-slate-400 mb-4 font-bold">Orchestrator Status</h2>
                        <div className="space-y-4 relative z-10">
                            <div>
                                <div className="flex justify-between text-xs mb-1">
                                    <span>Progress</span>
                                    <span>{progress}%</span>
                                </div>
                                <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${progress}%` }}
                                        className="h-full bg-cyan-500"
                                    />
                                </div>
                            </div>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                    <div className="p-3 bg-white/5 rounded-lg border border-white/5">
                                    <div className="text-slate-500 mb-1">Phase</div>
                                    <div className="text-white font-mono capitalize">{status}</div>
                                    </div>
                                    <div className="p-3 bg-white/5 rounded-lg border border-white/5">
                                        <div className="text-slate-500 mb-1">Agents</div>
                                        <div className={`font-mono ${
                                            scanCompleted ? 'text-blue-400' : isAgentActive ? 'text-green-400' : 'text-slate-500'
                                        }`}>
                                        {scanCompleted ? 'Done' : isAgentActive ? `${activeAgentCount} Active` : 'Idle'}
                                        </div>
                                    </div>
                                </div>
                        </div>
                    </div>

                    <div className="card flex-1 flex flex-col border-white/10 min-h-0">
                        <div className="p-3 border-b border-white/10 flex items-center justify-between bg-white/5 flex-shrink-0">
                            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                                <Terminal className="w-4 h-4" />
                                Agent Logs
                            </div>
                            <span className="text-[10px] text-slate-600">{logs.length} entries</span>
                        </div>
                        <div ref={systemLogsContainerRef} className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-1.5 text-slate-300 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                            {logs.length === 0 ? (
                                <div className="text-slate-600 italic">Waiting for agent output...</div>
                            ) : logs.map((log, i) => (
                                <div key={i} className="flex gap-2 hover:bg-white/5 px-1 py-0.5 rounded transition-colors break-words">
                                    <span className="text-slate-600 flex-shrink-0 select-none">[{formatLogTime(log.timestamp)}]</span>
                                    <span className={
                                        log.type === 'error' ? 'text-red-400' :
                                            log.type === 'human' ? 'text-cyan-400' :
                                                log.type === 'burp' ? 'text-orange-400' :
                                                    log.type === 'vuln' ? 'text-purple-400' :
                                                        log.type === 'tool' ? 'text-yellow-400' :
                                                            log.type === 'system' ? 'text-green-400' :
                                                                'text-slate-300'
                                    }>
                                        {log.type === 'human' ? '' : `[${log.type.toUpperCase()}] `}{log.message}
                                    </span>
                                </div>
                            ))}
                            <div ref={systemLogsEndRef} />
                        </div>
                    </div>
                </div>

                {/* Center: Command Interface & Chat */}
                <div className="col-span-12 lg:col-span-6 flex flex-col gap-4 h-[calc(100vh-8rem)]">
                    {/* Visualizer (Compact) */}
                    <div className={`h-48 flex-shrink-0 card relative overflow-hidden flex items-center justify-center ${
                        isPaused ? 'border-amber-500/30' : 'border-cyan-500/30'
                    }`}>
                        <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
                        {isPaused ? (
                            <div className="relative z-10 flex items-center gap-6">
                                <div className="w-24 h-24 relative flex items-center justify-center">
                                    <div className="absolute inset-0 border-2 border-dashed border-amber-500/30 rounded-full" />
                                    <div className="absolute inset-4 border-2 border-amber-500/20 rounded-full" />
                                    <Pause className="w-8 h-8 text-amber-400" />
                                </div>
                                <div className="text-left">
                                    <h3 className="font-bold text-amber-400 text-lg">Scan Paused</h3>
                                    <p className="text-slate-400 text-xs max-w-[250px] leading-relaxed">
                                        Manual testing mode active. PenPard is monitoring your Burp proxy traffic. 
                                        If it detects you testing a vulnerability, it will offer to assist.
                                    </p>
                                    <button
                                        onClick={handleResume}
                                        className="mt-2 flex items-center gap-1.5 px-3 py-1 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors text-xs font-medium"
                                    >
                                        <Play className="w-3 h-3" /> Resume Scan
                                    </button>
                                </div>
                            </div>
                        ) : isPrimaryMissionActive ? (
                            <div className="relative z-10 flex items-center gap-6">
                                <div className="w-24 h-24 relative">
                                    <motion.div
                                        animate={{ rotate: 360 }}
                                        transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
                                        className="absolute inset-0 border-2 border-dashed border-cyan-500/30 rounded-full"
                                    />
                                    <motion.div
                                        animate={{ rotate: -360 }}
                                        transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
                                        className="absolute inset-4 border-2 border-dashed border-purple-500/30 rounded-full"
                                    />
                                    <div className="absolute inset-0 flex items-center justify-center">
                                        <Shield className="w-8 h-8 text-cyan-500" />
                                    </div>
                                </div>
                                <div className="text-left">
                                    <h3 className="font-bold text-white text-lg">Active Analysis</h3>
                                    <p className="text-slate-400 text-xs max-w-[260px] leading-relaxed">
                                        {liveRuntimeSummary?.currentDecisionSummary || liveRuntimeSummary?.observationSummary || 'Orchestrator is analyzing target topology...'}
                                    </p>
                                </div>
                            </div>
                        ) : (
                            <div className="text-center text-slate-500">
                                <CheckCircle className="w-12 h-12 mx-auto mb-2 opacity-20" />
                                <p className="text-sm">Ready for instructions</p>
                            </div>
                        )}
                    </div>

                    {/* Chat Interface */}
                    <div className="flex-1 card flex flex-col border-white/10 overflow-hidden bg-slate-900/50 backdrop-blur-sm">

                        {/* Chat History - Only user messages and PenPard responses */}
                        <div ref={chatContainerRef} className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-dark-600">
                            {logs.filter(l => l.type === 'human' || (l.type === 'agent' && l.message.includes('[PENPARD]'))).length === 0 ? (
                                <div className="text-center py-8 opacity-30 text-sm">
                                    <Terminal className="w-8 h-8 mx-auto mb-2" />
                                    <p>No commands sent yet.</p>
                                    <p className="text-xs mt-1">
                                        Type a message to ask PenPard about the scan...
                                    </p>
                                </div>
                            ) : (
                                logs.filter(l => l.type === 'human' || (l.type === 'agent' && l.message.includes('[PENPARD]'))).map((log, i) => {
                                    const isUser = log.type === 'human';
                                    const isPenPardResponse = log.type === 'agent' && log.message.includes('[PENPARD]');

                                    // Extract actual message content
                                    let displayMessage = log.message
                                        .replace(/^User Command: /, '')
                                        .replace(/^\[PENPARD\]\s*/, '')
                                        .replace(/^\[.*?\]\s*/, '');

                                    return (
                                        <div key={i} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                                            <div className={`
                                                max-w-[85%] rounded-2xl px-4 py-3 text-sm font-sans leading-relaxed
                                                ${isUser
                                                    ? 'bg-cyan-600 text-white rounded-tr-sm'
                                                    : 'bg-slate-800 text-slate-300 rounded-tl-sm border border-cyan-500/20 prose prose-invert prose-sm max-w-none'
                                                }
                                            `}>
                                                {isPenPardResponse && <div className="flex items-center gap-1 text-xs font-bold uppercase mb-2 text-cyan-400"><Shield className="w-3 h-3" /> PenPard</div>}
                                                {isPenPardResponse ? (
                                                    <MarkdownRenderer content={displayMessage} />
                                                ) : (
                                                    displayMessage
                                                )}
                                            </div>
                                        </div>
                                    );
                                })
                            )}
                            <div ref={logsEndRef} />
                        </div>

                        {/* Continue Scan Panel (visible when completed and toggled) */}
                        {scanCompleted && !isScopedScan && showContinuePanel && (
                            <div className="px-3 pt-3 bg-black/40 border-t border-cyan-500/20">
                                <div className="flex items-center gap-3 mb-2">
                                    <div className="flex items-center gap-2">
                                        <label className="text-[10px] uppercase text-slate-500 font-bold">Rounds</label>
                                        <select
                                            value={continueIterations}
                                            onChange={e => setContinueIterations(Number(e.target.value))}
                                            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-xs text-white focus:border-cyan-500 outline-none"
                                        >
                                            {[1, 2, 3, 5, 8, 10, 15, 20].map(n => (
                                                <option key={n} value={n}>{n}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <label className="text-[10px] uppercase text-slate-500 font-bold">Planning</label>
                                        <button
                                            onClick={() => setContinuePlanning(!continuePlanning)}
                                            className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition-all ${
                                                continuePlanning
                                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                                    : 'bg-slate-800 text-slate-500 border border-slate-700'
                                            }`}
                                        >
                                            {continuePlanning ? 'ON' : 'OFF'}
                                        </button>
                                    </div>
                                    <button
                                        onClick={() => setShowContinuePanel(false)}
                                        className="ml-auto text-slate-500 hover:text-slate-300 text-xs"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </div>
                        )}

                        {/* Input Area */}
                        <div className="p-3 bg-black/40 border-t border-white/5">
                            <div className="relative">
                                <input
                                    type="text"
                                    value={command}
                                    onChange={e => setCommand(e.target.value)}
                                    onKeyDown={e => {
                                        if (e.key === 'Enter') {
                                            if (showContinuePanel && scanCompleted) {
                                                handleContinueScan();
                                            } else {
                                                handleSendCommand();
                                            }
                                        }
                                    }}
                                    placeholder={showContinuePanel && scanCompleted
                                            ? 'Enter instructions to continue scanning...'
                                            : 'Type instructions for PenPard...'
                                    }
                                    className={`w-full bg-slate-800/50 border rounded-xl px-4 py-3 text-white placeholder-slate-500 text-sm focus:ring-1 outline-none transition-all ${
                                        showContinuePanel && scanCompleted
                                                ? 'border-cyan-500/40 focus:border-cyan-500 focus:ring-cyan-500/50 pr-28'
                                                : 'border-slate-700 focus:border-cyan-500/50 focus:ring-cyan-500/50 pr-12'
                                    }`}
                                />
                                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                                    {/* Continue Scan button — only when completed + panel open */}
                                    {showContinuePanel && scanCompleted && !isScopedScan && (
                                        <button
                                            onClick={handleContinueScan}
                                            disabled={!command.trim() || isContinuing}
                                            className="px-2.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-black text-[10px] font-bold rounded-lg transition-all disabled:opacity-50 flex items-center gap-1"
                                        >
                                            {isContinuing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Repeat className="w-3 h-3" />}
                                            {isContinuing ? 'Starting...' : 'Continue'}
                                        </button>
                                    )}
                                    {/* Regular send button */}
                                    {(!showContinuePanel || !scanCompleted) && (
                                        <button
                                            onClick={handleSendCommand}
                                            disabled={!command.trim() || isSending}
                                            className="p-2 text-cyan-400 hover:bg-cyan-500/10 rounded-lg transition-colors disabled:opacity-50"
                                        >
                                            <Send className="w-4 h-4" />
                                        </button>
                                    )}
                                </div>
                            </div>
                            {/* Toggle button for continue scan */}
                            {scanCompleted && !isScopedScan && !showContinuePanel && (
                                <button
                                    onClick={() => setShowContinuePanel(true)}
                                    className="mt-2 w-full text-center py-1.5 rounded-lg bg-cyan-500/5 hover:bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium transition-all flex items-center justify-center gap-1.5"
                                >
                                    <Repeat className="w-3 h-3" />
                                    Continue Scan with New Instructions
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="flex justify-between items-center px-1">
                        <div className="text-xs text-slate-500 flex gap-4">
	                            <span className="flex items-center gap-1">
	                                <div className={`w-1.5 h-1.5 rounded-full ${
	                                    scanCompleted ? 'bg-blue-500' :
	                                    isPaused ? 'bg-amber-500' : isAgentActive ? 'bg-green-500' : 'bg-slate-500'
	                                }`}></div>
	                                {scanCompleted
	                                    ? 'Scan Finished'
	                                    : isPaused
	                                            ? 'Paused (Monitoring)'
	                                            : isAgentActive ? 'Agent Online' : 'Agent Offline'}
	                            </span>
	                            <span className="flex items-center gap-1">
	                                <div className={`w-1.5 h-1.5 rounded-full ${
	                                    scanCompleted ? 'bg-blue-500' :
	                                    burpConnected === true ? 'bg-green-500' : burpConnected === false ? 'bg-red-500' : 'bg-slate-500'
	                                }`}></div>
	                                {scanCompleted
	                                    ? 'Burp Session Ended'
	                                    : burpConnected === true ? 'Burp Connected' : 'Burp Disconnected'}
	                            </span>
                            {/* Browser status indicator */}
                            {isAgentActive && supportsBrowserVisibility && browserSessionId && (
                                <span className="flex items-center gap-1">
                                    <div className={`w-1.5 h-1.5 rounded-full ${browserStatusDotClass}`}></div>
                                    <Globe className="w-3 h-3 text-slate-500" />
                                    {browserStatusLabel}{browserIsLive ? '' : ' (offline)'}
                                </span>
                            )}
                            {/* Hypothesis status badges */}
                            {isAgentActive && (hypothesisCount.testing > 0 || hypothesisCount.escalated > 0 || hypothesisCount.confirmed > 0) && (
                                <span className="flex items-center gap-1.5">
                                    {hypothesisCount.escalated > 0 && (
                                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-500/20 text-amber-400 font-medium">
                                            ⚡ {hypothesisCount.escalated} escalated
                                        </span>
                                    )}
                                    {hypothesisCount.confirmed > 0 && (
                                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-green-500/20 text-green-400 font-medium">
                                            ✅ {hypothesisCount.confirmed} confirmed
                                        </span>
                                    )}
                                    {hypothesisCount.testing > 0 && (
                                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-blue-500/20 text-blue-400 font-medium">
                                            🔬 {hypothesisCount.testing} testing
                                        </span>
                                    )}
                                </span>
                            )}
                            {/* Coverage indicator */}
                            {isAgentActive && coverageSummary && coverageSummary.routesSeen > 0 && (
                                <span className="flex items-center gap-1 text-[10px] text-slate-500">
                                    Routes: {coverageSummary.exercised}/{coverageSummary.routesSeen}
                                    {coverageSummary.coveragePercentage > 0 && (
                                        <span className={`font-medium ${
                                            coverageSummary.coveragePercentage >= 70 ? 'text-green-400' :
                                            coverageSummary.coveragePercentage >= 40 ? 'text-amber-400' : 'text-red-400'
                                        }`}>
                                            ({coverageSummary.coveragePercentage}%)
                                        </span>
                                    )}
                                    {harvestedCount > 0 && <span>| Harvested: {harvestedCount}</span>}
                                    {promotedCount > 0 && <span>| Promoted: {promotedCount}</span>}
                                </span>
                            )}
                        </div>
                        <div className="flex items-center gap-3">
                            {supportsPause && isAgentActive && !isPaused && status !== 'completed' && status !== 'failed' && (
                                <button onClick={handlePause} className="text-xs text-amber-400 hover:text-amber-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
                                    <Pause className="w-3 h-3" /> PAUSE
                                </button>
                            )}
                            {supportsPause && isPaused && (
                                <button onClick={handleResume} className="text-xs text-green-400 hover:text-green-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
                                    <Play className="w-3 h-3" /> RESUME
                                </button>
                            )}
	                            {status !== 'completed' && status !== 'failed' && status !== 'stopped' && status !== 'scoped_executed' && (
	                                <button onClick={handleStop} className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
	                                    <StopCircle className="w-3 h-3" /> STOP
	                                </button>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right: Endpoint Intelligence + Findings */}
                <div className="col-span-12 lg:col-span-3 flex flex-col gap-4 h-[calc(100vh-8rem)]">
                    <div className="flex-[1.1] flex flex-col bg-white/5 rounded-xl border border-cyan-500/20 overflow-hidden min-h-0">
                        <div className="p-4 border-b border-white/10 flex justify-between items-center bg-black/20 flex-shrink-0">
                            <div>
                                <h2 className="font-bold text-sm text-white flex items-center gap-2">
                                    <Route className="w-4 h-4 text-cyan-400" />
                                    Endpoint Intelligence
                                </h2>
                                <div className="text-[10px] text-slate-500 mt-1">
                                    {endpointInventory?.summary || 'Waiting for JS, DOM, browser, and Burp endpoint intelligence...'}
                                </div>
                            </div>
                            <span className="bg-cyan-500/15 text-cyan-300 px-2 py-0.5 rounded text-xs border border-cyan-500/20">
                                {endpointInventory?.records?.length || 0} Endpoints
                            </span>
                        </div>
                        <div className="p-3 border-b border-white/10 bg-black/10 text-[10px] text-slate-400 grid grid-cols-3 gap-2 flex-shrink-0">
                            <div>Auth Relevant: <span className="text-white">{endpointInventory?.authRelevantCount || 0}</span></div>
                            <div>Burp Seen: <span className="text-white">{endpointInventory?.observedInBurpCount || 0}</span></div>
                            <div>JS Artifacts: <span className="text-white">{endpointInventory?.jsArtifacts?.count || 0}</span></div>
                        </div>
                        <div className="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 min-h-0">
                            {endpointRows.length === 0 ? (
                                <div className="text-center py-10 opacity-50">
                                    <Route className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                                    <div className="text-sm text-slate-500">No extracted endpoints yet.</div>
                                </div>
                            ) : (
                                endpointRows.map((row) => (
                                    <div key={row.id} className="rounded-lg border border-cyan-500/10 bg-black/20 p-3 space-y-2">
                                        <div className="flex items-start justify-between gap-2">
                                            <div className="min-w-0">
                                                <div className="text-sm font-semibold text-white break-all">{row.title}</div>
                                                <div className="text-[10px] text-slate-500 mt-1 break-all">{row.sourceDetail}</div>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="text-[10px] font-bold uppercase text-cyan-300">{row.methods}</div>
                                                <div className="text-[10px] text-slate-500">{row.confidenceLabel}</div>
                                            </div>
                                        </div>
                                        <div className="flex flex-wrap gap-1.5 text-[10px]">
                                            <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">{row.source}</span>
                                            <span className={`px-2 py-0.5 rounded border ${row.authBadge === 'auth-relevant' ? 'border-amber-500/20 bg-amber-500/10 text-amber-300' : 'border-slate-600 bg-slate-800/60 text-slate-300'}`}>
                                                {row.classification}
                                            </span>
                                            {row.inferredOnly && (
                                                <span className="px-2 py-0.5 rounded border border-purple-500/20 bg-purple-500/10 text-purple-300">
                                                    JS inferred only
                                                </span>
                                            )}
                                        </div>
                                        <div className="text-[11px] text-slate-300">{row.observedLabel}</div>
                                        <div className="text-[11px] text-slate-400 leading-relaxed">{row.evidence}</div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                    {isScopedScan && showLegacyRecoveryPanel ? (
                        <div className="flex-1 flex flex-col bg-white/5 rounded-xl border border-violet-500/20 overflow-hidden min-h-0">
                            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-black/20 flex-shrink-0 gap-3">
                                <div className="min-w-0">
                                    <h2 className="font-bold text-sm text-white">Live Findings</h2>
                                    <div className="text-[10px] text-slate-500 mt-1 truncate">
                                        {scopedLiveRuntime?.currentDecisionSummary || focusedTestObjective?.title || 'Scoped findings now ride on the shared Mission Control surface.'}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <span className="bg-red-500/20 text-red-300 px-2 py-0.5 rounded text-xs border border-red-500/20">
                                        {focusedFindingSummary?.actionableCount ?? visibleFocusedFindingRows.length} Live
                                    </span>
                                    {showLegacyRecoveryPanel && isLegacyScopedReviewMode && (
                                        <button
                                            onClick={() => handleRunFocusedExecution()}
                                            disabled={executePending || status === 'scoped_discovering' || status === 'planning' || status === 'scoped_executing' || runnableFocusedCaseCount === 0}
                                            className="px-2.5 py-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 text-[10px] font-semibold disabled:opacity-50"
                                        >
                                            {executePending || status === 'scoped_executing' ? 'Executing...' : 'Run Legacy Cases'}
                                        </button>
                                    )}
                                    {showLegacyRecoveryPanel && (
                                        <button
                                            onClick={handleRefreshFocusedPlan}
                                            disabled={planRefreshPending || status === 'scoped_discovering' || status === 'planning' || status === 'scoped_executing'}
                                            className="px-2.5 py-1 rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20 text-[10px] font-semibold disabled:opacity-50"
                                        >
                                            {planRefreshPending || status === 'planning' ? 'Planning...' : isLegacyScopedReviewMode ? 'Regenerate Legacy Plan' : 'Re-seed Mission'}
                                        </button>
                                    )}
                                    {showLegacyRecoveryPanel && status === 'scoped_executed' && (
                                        <button
                                            onClick={handleRefreshFocusedVerdicts}
                                            disabled={verdictRefreshPending}
                                            className="px-2.5 py-1 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 text-[10px] font-semibold disabled:opacity-50"
                                        >
                                            {verdictRefreshPending ? 'Refreshing...' : 'Refresh Verdicts'}
                                        </button>
                                    )}
                                </div>
                            </div>
                            <div className="p-3 border-b border-white/10 bg-black/10 text-[10px] text-slate-400 grid grid-cols-2 gap-2 flex-shrink-0">
                                <div>Cases: <span className="text-white">{focusedPlanSummary?.totalCases ?? focusedTestCases.length}</span></div>
                                <div>Enabled: <span className="text-white">{focusedPlanSummary?.enabledCases ?? focusedTestCases.filter((testCase) => testCase.status === 'planned').length}</span></div>
                                <div>{isLegacyScopedReviewMode ? 'Legacy approved' : 'Live finding threads'}: <span className="text-white">{isLegacyScopedReviewMode ? runnableFocusedCaseCount : (scopedLiveRuntime?.liveFindingCount ?? focusedFindingThreads.length)}</span></div>
                                <div>Scoped routes: <span className="text-white">{scopeEnvelope?.allowedRoutes.length || 0}</span></div>
                                <div>Active case: <span className="text-white">{scopedActiveCaseLabel || 'Waiting'}</span></div>
                                <div>Rail: <span className="text-white">{scopedLiveRuntime?.currentRail ? formatFocusedExecutionRail(scopedLiveRuntime.currentRail) : scopedExecutionLabel}</span></div>
                            </div>
                            <div className="p-3 border-b border-white/10 bg-amber-950/10 text-[11px] text-slate-300 space-y-3 flex-shrink-0">
                                <div className="flex items-start justify-between gap-3">
                                    <div className="min-w-0">
                                        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-200">Findings</div>
                                        <div className="mt-1 text-[10px] text-slate-400 leading-relaxed">
                                            {focusedFindingSummary
                                                ? `${focusedFindingSummary.actionableCount} actionable primary finding${focusedFindingSummary.actionableCount === 1 ? '' : 's'} currently surfaced.`
                                                : focusedFindingThreads.length > 0
                                                    ? `${focusedFindingThreads.length} live provisional finding thread${focusedFindingThreads.length === 1 ? '' : 's'} currently tracked during scoped execution.`
                                                    : 'Primary findings and provisional threads will appear here as scoped execution gathers evidence.'}
                                        </div>
                                    </div>
                                    {focusedFindingSummary && (
                                        <div className="text-right shrink-0 text-[10px] text-slate-400 space-y-1">
                                            <div>{focusedFindingSummary.primaryFindings} primary</div>
                                            {focusedFindingSummary.hiddenNotConfirmedCount > 0 && (
                                                <div>{focusedFindingSummary.hiddenNotConfirmedCount} hidden not confirmed</div>
                                            )}
                                        </div>
                                    )}
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    <span className="px-2 py-0.5 rounded border border-red-500/20 bg-red-500/10 text-red-300 text-[10px]">
                                        Confirmed {focusedFindingCounts.confirmed}
                                    </span>
                                    <span className="px-2 py-0.5 rounded border border-orange-500/20 bg-orange-500/10 text-orange-300 text-[10px]">
                                        Likely {focusedFindingCounts.likely}
                                    </span>
                                    <span className="px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/10 text-amber-300 text-[10px]">
                                        Suspicious {focusedFindingCounts.suspicious}
                                    </span>
                                    <span className="px-2 py-0.5 rounded border border-slate-500/20 bg-slate-500/10 text-slate-300 text-[10px]">
                                        Inconclusive {focusedFindingCounts.inconclusive}
                                    </span>
                                </div>
                                {visibleFocusedFindingRows.length === 0 ? (
                                    <div className="text-[10px] text-slate-500 leading-relaxed">
                                        No actionable primary finding is surfaced yet. Provisional threads, blockers, verdicts, and traces below still remain available for review.
                                    </div>
                                ) : (
                                    <div className="space-y-2 max-h-64 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-700">
                                        {visibleFocusedFindingRows.map(({ finding, thread, source, caseId, caseTitle, targetLabel }) => (
                                            <button
                                                key={finding.id}
                                                type="button"
                                                onClick={() => handleInspectEvidence(caseId)}
                                                className="w-full text-left rounded-lg border border-white/10 bg-black/20 p-3 hover:bg-black/30 transition-colors space-y-2"
                                            >
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div className="min-w-0">
                                                        <div className="text-[11px] font-semibold text-white truncate">{finding.title}</div>
                                                        <div className="text-[10px] text-slate-500 truncate">{caseTitle} · {targetLabel}</div>
                                                    </div>
                                                    <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                                                        finding.status === 'confirmed'
                                                            ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                            : finding.status === 'likely'
                                                                ? 'border-orange-500/30 bg-orange-500/10 text-orange-300'
                                                                : finding.status === 'suspicious'
                                                                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                                    : 'border-slate-500/30 bg-slate-500/10 text-slate-300'
                                                    }`}>
                                                        {formatFocusedFindingStatus(finding.status)}
                                                    </span>
                                                </div>
                                                <div className="flex flex-wrap gap-2 text-[10px] text-slate-400">
                                                    {source === 'runtime_thread' && (
                                                        <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200">
                                                            Provisional {thread ? formatFocusedFindingThreadStatus(thread.status) : 'Live'}
                                                        </span>
                                                    )}
                                                    <span>{formatFocusedFindingFamily(finding.family)}</span>
                                                    <span>{formatFocusedFindingConfidenceBand(finding.confidenceBand)}</span>
                                                    <span>Suspicion {finding.suspicionScore}%</span>
                                                    <span>Confirmation {finding.confirmationProgress}%</span>
                                                </div>
                                                <div className="text-[10px] text-slate-200 leading-relaxed">
                                                    Strongest signal: {finding.strongestSupportSummary}
                                                </div>
                                                {finding.blockingConstraintSummary && (
                                                    <div className="text-[10px] text-red-200 leading-relaxed">
                                                        Blocker: {finding.blockingConstraintSummary}
                                                    </div>
                                                )}
                                                {finding.nextStepSummary && (
                                                    <div className="text-[10px] text-cyan-100 leading-relaxed">
                                                        Next step: {finding.nextStepSummary}
                                                    </div>
                                                )}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                            {focusedVerdictSummary && (
                                <div className="p-3 border-b border-white/10 bg-black/10 text-[11px] text-slate-300 space-y-2 flex-shrink-0">
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-0.5 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-300 text-[10px]">
                                            Pass {focusedVerdictCounts.pass}
                                        </span>
                                        <span className="px-2 py-0.5 rounded border border-red-500/20 bg-red-500/10 text-red-300 text-[10px]">
                                            Fail {focusedVerdictCounts.fail}
                                        </span>
                                        <span className="px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/10 text-amber-300 text-[10px]">
                                            Inconclusive {focusedVerdictCounts.inconclusive}
                                        </span>
                                        <span className="px-2 py-0.5 rounded border border-violet-500/20 bg-violet-500/10 text-violet-200 text-[10px]">
                                            Needs review {focusedVerdictCounts.needs_review}
                                        </span>
                                    </div>
                                    {focusedVerdictSummary.majorBlockers.length > 0 && (
                                        <div className="text-[10px] text-slate-500 leading-relaxed">
                                            {focusedVerdictSummary.majorBlockers.slice(0, 2).join(' | ')}
                                        </div>
                                    )}
                                </div>
                            )}
                            {focusedBlockerSummary && (
                                <div className="p-3 border-b border-white/10 bg-red-950/10 text-[11px] text-slate-300 space-y-2 flex-shrink-0">
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-0.5 rounded border border-red-500/20 bg-red-500/10 text-red-300 text-[10px]">
                                            Blocking {blockerImpactCounts.blocking}
                                        </span>
                                        <span className="px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/10 text-amber-300 text-[10px]">
                                            Degrading {blockerImpactCounts.degrading}
                                        </span>
                                        <span className="px-2 py-0.5 rounded border border-slate-500/20 bg-slate-500/10 text-slate-300 text-[10px]">
                                            Informational {blockerImpactCounts.informational}
                                        </span>
                                    </div>
                                    {focusedBlockerSummary.latestMajorBlockerSummary && (
                                        <div className="text-[10px] text-slate-300 leading-relaxed">
                                            {focusedBlockerSummary.latestMajorBlockerSummary}
                                        </div>
                                    )}
                                    {unresolvedBlockerTypes.length > 0 && (
                                        <div className="text-[10px] text-slate-500 leading-relaxed">
                                            {unresolvedBlockerTypes.slice(0, 3).map(([issueType, count]) => (
                                                `${formatFocusedInvestigationType(issueType as any)} ${count}`
                                            )).join(' | ')}
                                        </div>
                                    )}
                                    {focusedBlockerSummary.repeatedBlockers.length > 0 && (
                                        <div className="text-[10px] text-slate-500 leading-relaxed">
                                            {focusedBlockerSummary.repeatedBlockers.slice(0, 2).join(' | ')}
                                        </div>
                                    )}
                                </div>
                            )}
                            {(focusedHistoricalCompareState || focusedHistoricalCompareSummary) && (
                                <div className="p-3 border-b border-white/10 bg-cyan-950/10 text-[11px] text-slate-300 space-y-2 flex-shrink-0">
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-[10px]">
                                            {formatFocusedHistoricalCompareStatus(focusedHistoricalCompareState?.comparisonStatus)}
                                        </span>
                                        {focusedHistoricalCompareSummary && (
                                            <span className="px-2 py-0.5 rounded border border-white/10 bg-black/20 text-slate-200 text-[10px]">
                                                {formatFocusedOverallChangeClassification(focusedHistoricalCompareSummary.overallChangeClassification)}
                                            </span>
                                        )}
                                        {focusedHistoricalCompareState?.comparedAgainstScanId && (
                                            <span className="px-2 py-0.5 rounded border border-white/10 bg-black/20 text-slate-300 text-[10px]">
                                                Against {focusedHistoricalCompareState.comparedAgainstScanId.slice(0, 8)}
                                            </span>
                                        )}
                                        {focusedHistoricalCompareState?.baselineScanId && (
                                            <span className="px-2 py-0.5 rounded border border-white/10 bg-black/20 text-slate-300 text-[10px]">
                                                Baseline {focusedHistoricalCompareState.baselineScanId.slice(0, 8)}
                                            </span>
                                        )}
                                        {focusedHistoricalCounts.manualReviewRecommended && (
                                            <span className="px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/10 text-amber-200 text-[10px]">
                                                Manual review recommended
                                            </span>
                                        )}
                                    </div>
                                    <div className="text-[10px] text-slate-400 leading-relaxed">
                                        {focusedHistoricalCompareState?.statusReason
                                            || focusedHistoricalCompareSummary?.compareNarrative
                                            || 'Historical compare facts are persisted once scoped verdicts exist.'}
                                    </div>
                                    {focusedHistoricalCompareState?.comparisonStatus === 'baseline_created' ? (
                                        <div className="text-[10px] text-cyan-100 leading-relaxed">
                                            First observed scoped run for this lineage. Baseline created and comparison will start on the next comparable run.
                                        </div>
                                    ) : focusedHistoricalCompareSummary ? (
                                        <>
                                            <div className="flex flex-wrap gap-2">
                                                <span className="px-2 py-0.5 rounded border border-emerald-500/20 bg-emerald-500/10 text-emerald-300 text-[10px]">
                                                    Improved {focusedHistoricalCounts.improvedCount}
                                                </span>
                                                <span className="px-2 py-0.5 rounded border border-red-500/20 bg-red-500/10 text-red-300 text-[10px]">
                                                    Regressed {focusedHistoricalCounts.regressedCount}
                                                </span>
                                                <span className="px-2 py-0.5 rounded border border-amber-500/20 bg-amber-500/10 text-amber-300 text-[10px]">
                                                    Weaker {focusedHistoricalCounts.weakerConfidenceCount}
                                                </span>
                                                <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-[10px]">
                                                    Stronger {focusedHistoricalCounts.strongerConfidenceCount}
                                                </span>
                                                {focusedHistoricalCounts.newlyIntroducedCount > 0 && (
                                                    <span className="px-2 py-0.5 rounded border border-violet-500/20 bg-violet-500/10 text-violet-200 text-[10px]">
                                                        New {focusedHistoricalCounts.newlyIntroducedCount}
                                                    </span>
                                                )}
                                            </div>
                                            {(focusedHistoricalCounts.repeatedBlockerFamilies.length > 0 || focusedHistoricalCounts.newBlockerFamilies.length > 0) && (
                                                <div className="text-[10px] text-slate-500 leading-relaxed">
                                                    {focusedHistoricalCounts.repeatedBlockerFamilies.length > 0
                                                        ? `Recurring blockers: ${focusedHistoricalCounts.repeatedBlockerFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`
                                                        : `New blockers: ${focusedHistoricalCounts.newBlockerFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`}
                                                </div>
                                            )}
                                            {focusedHistoricalCompareSummary.stabilityNotes.length > 0 && (
                                                <div className="text-[10px] text-slate-500 leading-relaxed">
                                                    {focusedHistoricalCompareSummary.stabilityNotes.slice(0, 2).join(' | ')}
                                                </div>
                                            )}
                                        </>
                                    ) : null}
                                </div>
                            )}
                            {(focusedTestObjective || scopeEnvelope || scopedTestRequest || featureDiscoveryState) && (
                                <div className="p-3 border-b border-white/10 bg-black/5 text-[11px] text-slate-400 space-y-2 flex-shrink-0">
                                    {scopedTestRequest && (
                                        <div className="space-y-1.5">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-[10px]">
                                                    {scopedTestRequest.targetUrl}
                                                </span>
                                                {scopedTestRequest.serviceName && (
                                                    <span className="px-2 py-0.5 rounded border border-slate-600 bg-slate-800/60 text-slate-200 text-[10px]">
                                                        {scopedTestRequest.serviceName}
                                                    </span>
                                                )}
                                                {scopedTestRequest.environment && (
                                                    <span className="px-2 py-0.5 rounded border border-slate-600 bg-slate-800/60 text-slate-300 text-[10px] uppercase">
                                                        {scopedTestRequest.environment}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="text-slate-200 leading-relaxed">{scopedTestRequest.description}</div>
                                        </div>
                                    )}
                                    {focusedTestObjective?.goal && (
                                        <div className="text-slate-200 leading-relaxed">{focusedTestObjective.goal}</div>
                                    )}
                                    {scopedLiveRuntime?.currentDecisionSummary && !focusedTestObjective?.goal && (
                                        <div className="text-slate-200 leading-relaxed">{scopedLiveRuntime.currentDecisionSummary}</div>
                                    )}
                                    {focusedTestObjective?.riskTags?.length ? (
                                        <div className="flex flex-wrap gap-1.5">
                                            {focusedTestObjective.riskTags.map((tag) => (
                                                <span key={tag} className="px-2 py-0.5 rounded border border-violet-500/20 bg-violet-500/10 text-violet-200 text-[10px]">
                                                    {tag}
                                                </span>
                                            ))}
                                        </div>
                                    ) : null}
                                    {scopeEnvelope?.boundaryHints?.length ? (
                                        <div className="text-[10px] text-slate-500">
                                            Boundary hints: {scopeEnvelope.boundaryHints.slice(0, 2).join(' | ')}
                                        </div>
                                    ) : null}
                                    {(scopedRuntimeRequest?.summary || scopedActiveFindingLabel || scopedLiveRuntime?.latestSuspiciousSignal || scopedLiveRuntime?.observationSummary || scopedLiveRuntime?.boundaryReason || scopedRuntimeBoundary?.blockedActionReason) && (
                                        <div className="space-y-1 text-[10px] text-slate-400">
                                            {scopedRuntimeRequest?.summary && (
                                                <div>
                                                    Last bounded request: <span className="text-slate-200">{scopedRuntimeRequest.summary}{typeof scopedRuntimeRequest.statusCode === 'number' ? ` · HTTP ${scopedRuntimeRequest.statusCode}` : ''}</span>
                                                </div>
                                            )}
                                            {scopedLiveRuntime?.observationSummary && (
                                                <div>
                                                    Observation: <span className="text-slate-200">{scopedLiveRuntime.observationSummary}</span>
                                                </div>
                                            )}
                                            {scopedActiveFindingLabel && (
                                                <div>
                                                    Active finding thread: <span className="text-slate-200">{scopedActiveFindingLabel}</span>
                                                </div>
                                            )}
                                            {scopedLiveRuntime?.latestSuspiciousSignal && (
                                                <div>
                                                    Suspicious signal: <span className="text-slate-200">{scopedLiveRuntime.latestSuspiciousSignal}</span>
                                                </div>
                                            )}
                                            {(scopedLiveRuntime?.boundaryReason || scopedRuntimeBoundary?.blockedActionReason) && (
                                                <div>
                                                    Boundary reason: <span className="text-amber-200">{scopedLiveRuntime?.boundaryReason || scopedRuntimeBoundary?.blockedActionReason}</span>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    {featureDiscoveryState && (
                                        <div className="space-y-1">
                                            <div className="flex flex-wrap items-center gap-2 text-[10px]">
                                                <span className="px-2 py-0.5 rounded border border-blue-500/20 bg-blue-500/10 text-blue-200">
                                                    {formatScopedFeatureDiscoveryPhase(featureDiscoveryState.phase)}
                                                </span>
                                                <span className="px-2 py-0.5 rounded border border-slate-600 bg-slate-800/60 text-slate-200">
                                                    {formatScopedFeatureDiscoveryOutcome(featureDiscoveryState.outcome)}
                                                </span>
                                                <span className="text-slate-500">
                                                    {buildScopedAnchorSummary(scopeEnvelope, featureDiscoveryState)}
                                                </span>
                                            </div>
                                            {(featureDiscoveryState.summary || featureDiscoveryState.errorMessage) && (
                                                <div className="text-[10px] text-slate-500 leading-relaxed">
                                                    {featureDiscoveryState.errorMessage || featureDiscoveryState.summary}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}
                            {selectedEvidenceCase && (
                                <div className="p-3 border-b border-white/10 bg-black/20 text-[11px] text-slate-300 space-y-2 flex-shrink-0">
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="min-w-0">
                                            <div className="text-white font-semibold truncate">Evidence: {selectedEvidenceCase.title}</div>
                                            <div className="text-[10px] text-slate-500 mt-1">
                                                {selectedExecution
                                                    ? `${formatFocusedExecutionPresentationState(selectedEvidenceRow?.executionPresentationState || selectedEvidenceCase.executionPresentationState)} | ${selectedExecution.executionProfileKey}`
                                                    : 'No persisted execution selected yet.'}
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => {
                                                setSelectedEvidenceCaseId(null);
                                                setSelectedExecution(null);
                                                setSelectedCaseVerdict(null);
                                                setSelectedPrimaryFinding(null);
                                                setSelectedPrimaryFindingThread(null);
                                                setSelectedCaseFindings([]);
                                                setSelectedCaseFindingThreads([]);
                                                setSelectedCaseHistoricalCompare(null);
                                                setSelectedEvidenceBundles([]);
                                                setSelectedExecutionTrace([]);
                                                setSelectedRailSummary(null);
                                                setSelectedInvestigationIssues([]);
                                            }}
                                            className="text-[10px] text-slate-400 hover:text-white"
                                        >
                                            Close
                                        </button>
                                    </div>
                                    {selectedExecution?.notesSummary && (
                                        <div className="text-[10px] text-slate-400 leading-relaxed">{selectedExecution.notesSummary}</div>
                                    )}
                                    {selectedExecution && (
                                        <div className="text-[10px] text-slate-500 flex flex-wrap gap-x-3 gap-y-1">
                                            <span>{formatFocusedExecutionRail(effectiveSelectedRailSummary?.rail)}</span>
                                            <span>Request actions: {selectedExecution.requestActionsUsed}</span>
                                            <span>Browser actions: {selectedExecution.browserActionsUsed}</span>
                                            {selectedExecution.browserSessionId && (
                                                <span>Browser session: {selectedExecution.browserSessionId}</span>
                                            )}
                                        </div>
                                    )}
                                    {effectiveSelectedRailSummary && (
                                        <div className="text-[10px] text-cyan-100 leading-relaxed">
                                            {formatFocusedRailSummary(effectiveSelectedRailSummary)}
                                        </div>
                                    )}
                                    {effectiveSelectedCaseVerdict && (
                                        <div className="rounded-lg border border-white/10 bg-black/20 p-2 space-y-1">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                                                    effectiveSelectedCaseVerdict.verdictState === 'pass'
                                                        ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                                        : effectiveSelectedCaseVerdict.verdictState === 'fail'
                                                            ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                            : effectiveSelectedCaseVerdict.verdictState === 'needs_review'
                                                                ? 'border-violet-500/30 bg-violet-500/10 text-violet-200'
                                                                : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                }`}>
                                                    {formatFocusedVerdictState(effectiveSelectedCaseVerdict.verdictState)}
                                                </span>
                                                <span className="text-[10px] text-slate-500">
                                                    {formatFocusedEvidenceSufficiencyState(effectiveSelectedCaseVerdict.evidenceSufficiency.state)}
                                                </span>
                                            </div>
                                            <div className="text-[11px] text-slate-200 leading-relaxed">{effectiveSelectedCaseVerdict.verdictReason}</div>
                                            <div className="text-[10px] text-slate-400 leading-relaxed">
                                                {effectiveSelectedCaseVerdict.evidenceSufficiency.summary}
                                            </div>
                                            <div className="text-[10px] text-slate-500 leading-relaxed">
                                                Case family: {effectiveSelectedCaseVerdict.interpretationSummary.caseFamily.replace(/_/g, ' ')} | Suspiciousness: {effectiveSelectedCaseVerdict.interpretationSummary.suspiciousness}
                                            </div>
                                            {effectiveSelectedCaseVerdict.interpretationSummary.summary && (
                                                <div className="text-[10px] text-violet-200 leading-relaxed">
                                                    {effectiveSelectedCaseVerdict.interpretationSummary.summary}
                                                </div>
                                            )}
                                            {effectiveSelectedCaseVerdict.scopeViolationImpact.reasons.length > 0 && (
                                                <div className="text-[10px] text-red-300 leading-relaxed">
                                                    {effectiveSelectedCaseVerdict.scopeViolationImpact.reasons[0]}
                                                </div>
                                            )}
                                            {effectiveSelectedCaseVerdict.assistanceNarrative && (
                                                <div className="text-[10px] text-cyan-200 leading-relaxed">
                                                    {effectiveSelectedCaseVerdict.assistanceNarrative}
                                                </div>
                                            )}
                                            {effectiveSelectedCaseVerdict.supportingEvidenceRefs.length > 0 && (
                                                <div className="text-[10px] text-slate-500 leading-relaxed">
                                                    Supporting evidence: {effectiveSelectedCaseVerdict.supportingEvidenceRefs.slice(0, 3).map((entry) => entry.role.replace(/_/g, ' ')).join(', ')}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    {effectiveSelectedCaseHistoricalCompare && (
                                        <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/10 p-2 space-y-2">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-[10px] font-semibold uppercase">
                                                    {formatFocusedHistoricalOutcome(effectiveSelectedCaseHistoricalCompare.historicalOutcome)}
                                                </span>
                                                <span className="text-[10px] text-slate-400">
                                                    {formatFocusedCaseCompareStatus(effectiveSelectedCaseHistoricalCompare.compareStatus)}
                                                </span>
                                                {effectiveSelectedCaseHistoricalCompare.verdictTransition && (
                                                    <span className="text-[10px] text-slate-300">
                                                        {formatFocusedVerdictTransition(effectiveSelectedCaseHistoricalCompare.verdictTransition)}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="text-[10px] text-slate-400 leading-relaxed">
                                                {effectiveSelectedCaseHistoricalCompare.compareNarrative
                                                    || (effectiveSelectedCaseHistoricalCompare.compareStatus === 'baseline_only'
                                                        ? 'First observed case for this baseline-producing run.'
                                                        : effectiveSelectedCaseHistoricalCompare.previousCaseId
                                                            ? `Compared against case ${effectiveSelectedCaseHistoricalCompare.previousCaseId.slice(0, 8)} from scan ${effectiveSelectedCaseHistoricalCompare.previousScanId?.slice(0, 8) || 'unknown'}.`
                                                            : 'No prior comparable case was available.')}
                                            </div>
                                            {effectiveSelectedCaseHistoricalCompare.evidenceDriftClassification && (
                                                <div className="text-[10px] text-slate-300">
                                                    Evidence drift: {formatFocusedEvidenceDriftClassification(effectiveSelectedCaseHistoricalCompare.evidenceDriftClassification)}
                                                </div>
                                            )}
                                            {(effectiveSelectedCaseHistoricalCompare.priorVerdict || effectiveSelectedCaseHistoricalCompare.priorEvidenceSummary) && (
                                                <div className="text-[10px] text-slate-500 leading-relaxed">
                                                    Prior: {formatFocusedVerdictState(effectiveSelectedCaseHistoricalCompare.priorVerdict)} · {formatFocusedEvidenceSufficiencyState(effectiveSelectedCaseHistoricalCompare.priorEvidenceSufficiency)}
                                                    {effectiveSelectedCaseHistoricalCompare.priorEvidenceSummary ? ` · ${effectiveSelectedCaseHistoricalCompare.priorEvidenceSummary}` : ''}
                                                </div>
                                            )}
                                            {formatFocusedBlockerRecurrence(effectiveSelectedCaseHistoricalCompare) && (
                                                <div className="text-[10px] text-amber-200 leading-relaxed">
                                                    {formatFocusedBlockerRecurrence(effectiveSelectedCaseHistoricalCompare)}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    {selectedExecution && (
                                        <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/10 p-2 space-y-2">
                                            <div className="flex flex-wrap items-center gap-2">
                                                <span className="text-[10px] font-semibold uppercase tracking-wide text-cyan-200">
                                                    Execution Trace
                                                </span>
                                                <span className="text-[10px] text-slate-400">
                                                    {formatFocusedExecutionRail(effectiveSelectedRailSummary?.rail)}
                                                </span>
                                                <span className="text-[10px] text-slate-500">
                                                    {effectiveSelectedExecutionTrace.length} step{effectiveSelectedExecutionTrace.length === 1 ? '' : 's'}
                                                </span>
                                            </div>
                                            {effectiveSelectedExecutionTrace.length === 0 ? (
                                                <div className="text-[10px] text-slate-500">
                                                    Bounded execution did not persist an operator-facing trace for this execution.
                                                </div>
                                            ) : (
                                                <div className="space-y-2 max-h-52 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-700">
                                                    {effectiveSelectedExecutionTrace.map((entry) => (
                                                        <div key={entry.id} className="rounded-md border border-white/10 bg-black/20 p-2 space-y-1">
                                                            <div className="flex flex-wrap items-center justify-between gap-2">
                                                                <div className="flex flex-wrap items-center gap-2">
                                                                    <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-200 text-[10px]">
                                                                        {formatFocusedExecutionTraceActionType(entry.actionType)}
                                                                    </span>
                                                                    <span className="text-[10px] text-slate-400">
                                                                        {formatFocusedExecutionRail(entry.rail)}
                                                                    </span>
                                                                </div>
                                                                <span className="text-[10px] text-slate-500">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                                                            </div>
                                                            <div className="text-[11px] text-slate-200 leading-relaxed">{entry.actionSummary}</div>
                                                            {entry.targetSummary && (
                                                                <div className="text-[10px] text-slate-500 leading-relaxed">Target: {entry.targetSummary}</div>
                                                            )}
                                                            {entry.requestSummary && (
                                                                <div className="text-[10px] text-slate-400 leading-relaxed">
                                                                    Request: {[entry.requestSummary.method, entry.requestSummary.path || entry.requestSummary.url, entry.requestSummary.mutationSummary].filter(Boolean).join(' | ')}
                                                                </div>
                                                            )}
                                                            {entry.responseSummary && (
                                                                <div className="text-[10px] text-slate-400 leading-relaxed">
                                                                    Response: {[
                                                                        typeof entry.responseSummary.statusCode === 'number' ? `HTTP ${entry.responseSummary.statusCode}` : null,
                                                                        entry.responseSummary.structureChanged ? 'Structure changed' : null,
                                                                        typeof entry.responseSummary.bodyLengthDelta === 'number' ? `Body delta ${entry.responseSummary.bodyLengthDelta}` : null,
                                                                        entry.responseSummary.keywordSignals?.length ? entry.responseSummary.keywordSignals.join(', ') : null,
                                                                        entry.responseSummary.bodySummary,
                                                                    ].filter(Boolean).join(' | ')}
                                                                </div>
                                                            )}
                                                            {entry.reasoningNote && (
                                                                <div className="text-[10px] text-violet-200 leading-relaxed">Why: {entry.reasoningNote}</div>
                                                            )}
                                                            {entry.nextStepRationale && (
                                                                <div className="text-[10px] text-cyan-100 leading-relaxed">Next step: {entry.nextStepRationale}</div>
                                                            )}
                                                            {entry.stopReason && (
                                                                <div className="text-[10px] text-red-200 leading-relaxed">Stop reason: {entry.stopReason}</div>
                                                            )}
                                                            {entry.retryReason && (
                                                                <div className="text-[10px] text-amber-200 leading-relaxed">Retry context: {entry.retryReason}</div>
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                    {selectedInvestigationIssues.length > 0 && (
                                        <div className="rounded-lg border border-red-500/20 bg-red-950/10 p-2 space-y-2">
                                            <div className="text-[10px] font-semibold uppercase tracking-wide text-red-200">
                                                Investigation
                                            </div>
                                            {selectedInvestigationIssues.map((issue) => (
                                                <div key={issue.id} className="rounded-md border border-white/10 bg-black/20 p-2 space-y-1">
                                                    <div className="flex flex-wrap items-center gap-2">
                                                        <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                                                            issue.impact === 'blocking'
                                                                ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                : issue.impact === 'degrading'
                                                                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                                    : 'border-slate-500/30 bg-slate-500/10 text-slate-300'
                                                        }`}>
                                                            {formatFocusedInvestigationImpact(issue.impact)}
                                                        </span>
                                                        <span className="text-[10px] text-slate-400">
                                                            {formatFocusedInvestigationStatus(issue.issueStatus)} · {formatFocusedInvestigationType(issue.issueType)}
                                                        </span>
                                                    </div>
                                                    <div className="text-[11px] text-white leading-relaxed">{issue.issueTitle}</div>
                                                    {issue.issueDetails && (
                                                        <div className="text-[10px] text-slate-300 leading-relaxed">{issue.issueDetails}</div>
                                                    )}
                                                    {issue.assistanceSummary && (
                                                        <div className="text-[10px] text-cyan-200 leading-relaxed">{issue.assistanceSummary}</div>
                                                    )}
                                                    {(issue.correlation?.caseFamily || issue.correlation?.railSummary || issue.correlation?.latestTraceSummary) && (
                                                        <div className="text-[10px] text-slate-500 leading-relaxed">
                                                            {[
                                                                issue.correlation?.caseFamily ? `Family ${issue.correlation.caseFamily.replace(/_/g, ' ')}` : null,
                                                                issue.correlation?.railSummary || null,
                                                                issue.correlation?.latestTraceSummary ? `Latest trace: ${issue.correlation.latestTraceSummary}` : null,
                                                            ].filter(Boolean).join(' | ')}
                                                        </div>
                                                    )}
                                                    {issue.expertFollowupHint && (
                                                        <div className="text-[10px] text-amber-200 leading-relaxed">
                                                            Expert follow-up: {issue.expertFollowupHint}
                                                        </div>
                                                    )}
                                                    {issue.workaroundAttempts.length > 0 && (
                                                        <div className="text-[10px] text-slate-400 leading-relaxed">
                                                            Workaround: {issue.workaroundAttempts[issue.workaroundAttempts.length - 1]?.summary} ({issue.workaroundAttempts[issue.workaroundAttempts.length - 1]?.outcome.replace(/_/g, ' ')})
                                                        </div>
                                                    )}
                                                    {(issue.linkedEvidenceIds.length > 0 || issue.linkedVerdictIds.length > 0) && (
                                                        <div className="text-[10px] text-slate-500 leading-relaxed">
                                                            {issue.linkedEvidenceIds.length > 0 ? `Evidence ${issue.linkedEvidenceIds.slice(0, 3).join(', ')}` : ''}
                                                            {issue.linkedEvidenceIds.length > 0 && issue.linkedVerdictIds.length > 0 ? ' | ' : ''}
                                                            {issue.linkedVerdictIds.length > 0 ? `Verdicts ${issue.linkedVerdictIds.slice(0, 2).join(', ')}` : ''}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    {selectedEvidenceBundles.length === 0 ? (
                                        <div className="text-[10px] text-slate-500">{selectedEvidenceEmptyState}</div>
                                    ) : (
                                        <div className="space-y-2 max-h-40 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-700">
                                            {selectedEvidenceBundles.map((bundle) => (
                                                    <div key={bundle.id} className="rounded-lg border border-white/10 bg-black/20 p-2 space-y-1">
                                                        <div className="flex items-center justify-between gap-2">
                                                            <span className="text-[10px] font-semibold uppercase text-cyan-300">{bundle.source.replace(/_/g, ' ')}</span>
                                                            <span className="text-[10px] text-slate-500">{new Date(bundle.capturedAt).toLocaleString()}</span>
                                                        </div>
                                                        <div className="text-[11px] text-slate-200 leading-relaxed">{bundle.summary}</div>
                                                        {bundle.executionNotes && (
                                                            <div className="text-[10px] text-slate-400 leading-relaxed">{bundle.executionNotes}</div>
                                                        )}
                                                        {bundle.relatedEvidenceIds && bundle.relatedEvidenceIds.length > 0 && (
                                                            <div className="text-[10px] text-slate-500 leading-relaxed">
                                                                Linked evidence: {bundle.relatedEvidenceIds.slice(0, 3).join(', ')}
                                                            </div>
                                                        )}
                                                        {bundle.responseDiffSummary?.summary && (
                                                            <div className="text-[10px] text-amber-300 leading-relaxed">{bundle.responseDiffSummary.summary}</div>
                                                        )}
                                                        {bundle.browserState && (
                                                            <div className="rounded-md border border-cyan-500/10 bg-slate-950/60 p-2 space-y-1">
                                                                <div className="text-[10px] text-cyan-200 leading-relaxed">
                                                                    {bundle.browserState.actionSummary}
                                                                </div>
                                                                <div className="text-[10px] text-slate-500 flex flex-wrap gap-x-3 gap-y-1">
                                                                    <span>Page: {bundle.browserState.finalPath || bundle.browserState.finalUrl || bundle.browserState.startUrl}</span>
                                                                    <span>{formatExpectationSummary(bundle) || 'No browser checks recorded'}</span>
                                                                    <span>{bundle.browserState.actionCount} action(s)</span>
                                                                </div>
                                                                {bundle.browserState.pageTitle && (
                                                                    <div className="text-[10px] text-slate-400">Title: {bundle.browserState.pageTitle}</div>
                                                                )}
                                                                {bundle.browserState.stateNotes.length > 0 && (
                                                                    <div className="text-[10px] text-slate-400 leading-relaxed">
                                                                        {bundle.browserState.stateNotes.join(' | ')}
                                                                    </div>
                                                                )}
                                                                {bundle.browserState.expectations.length > 0 && (
                                                                    <div className="space-y-1">
                                                                        {bundle.browserState.expectations.slice(0, 4).map((expectation, index) => (
                                                                            <div
                                                                                key={`${bundle.id}-expectation-${index}`}
                                                                                className={`text-[10px] leading-relaxed ${expectation.matched ? 'text-emerald-300' : 'text-amber-300'}`}
                                                                            >
                                                                                {expectation.description}: {expectation.observedSummary}
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        )}
                                                        {bundle.scopeViolation?.reason && (
                                                            <div className="text-[10px] text-red-300 leading-relaxed">{bundle.scopeViolation.reason}</div>
                                                        )}
                                                        {buildScreenshotDataUrl(bundle.screenshotRef) && (
                                                            <img
                                                                src={buildScreenshotDataUrl(bundle.screenshotRef)!}
                                                                alt={bundle.screenshotRef?.label || 'Focused evidence screenshot'}
                                                                className="w-full rounded-md border border-white/10"
                                                            />
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                    )}
                                </div>
                            )}
                            <div className="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin scrollbar-thumb-slate-700 min-h-0">
                                {focusedStorySummary && (
                                    <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 p-3 space-y-2">
                                        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-amber-200">Scoped Story</div>
                                        <div className="text-[11px] leading-relaxed text-amber-50">{focusedStorySummary.headline}</div>
                                        <div className="text-[10px] leading-relaxed text-slate-300">
                                            {focusedStorySummary.currentBeliefs.length > 0
                                                ? focusedStorySummary.currentBeliefs.slice(0, 2).join(' | ')
                                                : 'Signals will appear here as soon as the bounded run starts producing evidence.'}
                                        </div>
                                    </div>
                                )}
                                {focusedCaseRows.length === 0 ? (
                                    <div className="text-center py-10 opacity-50">
                                        <CheckCircle className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                                        <div className="text-sm text-slate-500">
                                            {status === 'planning' ? 'Planner is generating focused cases...' : 'No focused test cases have been generated yet.'}
                                        </div>
                                    </div>
                                ) : (
                                    focusedCaseRows.map((row) => {
                                        const focusedCase = focusedCaseMap.get(row.id);
                                        const caseStory = focusedStoryCaseMap.get(row.id) || null;
                                        const candidateInputs = summarizeFocusedCaseInputs(row);
                                        const boundedStopReason = summarizeFocusedCaseStopReason(row);
                                        const nextStepSummary = summarizeFocusedCaseNextStep(row);
                                        const actionPending = planActionCaseId === row.id;
                                        const tracePreview = buildFocusedTracePreview(row.latestExecutionTracePreview, 2);

                                        return (
                                            <div key={row.id} className="rounded-lg border border-violet-500/10 bg-black/20 p-3 space-y-3">
                                                <div className="flex items-start justify-between gap-2">
                                                    <div className="min-w-0">
                                                        <div className="text-sm font-semibold text-white break-words">{row.title}</div>
                                                        <div className="text-[10px] text-violet-200 mt-1 break-all">{row.targetLabel}</div>
                                                    </div>
                                                    <div className="flex flex-wrap justify-end gap-1.5 shrink-0">
                                                        <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                                                            row.priority === 'high'
                                                                ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                : row.priority === 'medium'
                                                                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                                    : 'border-slate-600 bg-slate-800/60 text-slate-300'
                                                        }`}>
                                                            {row.priority}
                                                        </span>
                                                        <span className={`px-2 py-0.5 rounded border text-[10px] ${
                                                            row.reviewState === 'approved'
                                                                ? 'border-green-500/30 bg-green-500/10 text-green-300'
                                                                : row.reviewState === 'rejected'
                                                                    ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                    : 'border-violet-500/30 bg-violet-500/10 text-violet-200'
                                                        }`}>
                                                            {formatFocusedReviewState(row.reviewState)}
                                                        </span>
                                                        <span className={`px-2 py-0.5 rounded border text-[10px] ${getExecutionBadgeClassName(row.executionPresentationState)}`}>
                                                            {formatFocusedExecutionPresentationState(row.executionPresentationState)}
                                                        </span>
                                                        {row.executionRailSummary && (
                                                            <span className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-100 text-[10px]">
                                                                {formatFocusedExecutionRail(row.executionRailSummary.rail)}
                                                            </span>
                                                        )}
                                                        {row.latestVerdict && (
                                                            <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${
                                                                row.latestVerdict.verdictState === 'pass'
                                                                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                                                    : row.latestVerdict.verdictState === 'fail'
                                                                        ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                        : row.latestVerdict.verdictState === 'needs_review'
                                                                            ? 'border-violet-500/30 bg-violet-500/10 text-violet-200'
                                                                            : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                            }`}>
                                                                {formatFocusedVerdictState(row.latestVerdict.verdictState)}
                                                            </span>
                                                        )}
                                                        {row.investigationSummary && row.investigationSummary.unresolvedCount > 0 && (
                                                            <span className={`px-2 py-0.5 rounded border text-[10px] ${
                                                                row.investigationSummary.blockingCount > 0
                                                                    ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                    : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                            }`}>
                                                                {row.investigationSummary.blockingCount > 0
                                                                    ? `${row.investigationSummary.blockingCount} blocking`
                                                                    : `${row.investigationSummary.unresolvedCount} issue${row.investigationSummary.unresolvedCount === 1 ? '' : 's'}`}
                                                            </span>
                                                        )}
                                                        {row.historicalCompare && (
                                                            <span className={`px-2 py-0.5 rounded border text-[10px] ${
                                                                row.historicalCompare.historicalOutcome === 'improved'
                                                                    ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                                                                    : row.historicalCompare.historicalOutcome === 'regressed'
                                                                        ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                                        : row.historicalCompare.historicalOutcome === 'weaker_confidence'
                                                                            ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                                                                            : row.historicalCompare.historicalOutcome === 'stronger_confidence'
                                                                                ? 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200'
                                                                                : 'border-slate-600 bg-slate-800/60 text-slate-300'
                                                            }`}>
                                                                {formatFocusedHistoricalOutcome(row.historicalCompare.historicalOutcome)}
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                                <div className="text-[11px] text-slate-300 leading-relaxed">{row.rationale}</div>
                                                {focusedCase?.hypothesis && (
                                                    <div className="text-[11px] text-slate-500 leading-relaxed">{focusedCase.hypothesis}</div>
                                                )}
                                                {(row.caseIntelligence || caseStory) && (
                                                    <div className="rounded-lg border border-white/10 bg-slate-950/60 p-2.5 space-y-2">
                                                        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Why / What / Next</div>
                                                        <div className="text-[10px] leading-relaxed text-slate-300">
                                                            {row.caseIntelligence?.selectionSummary || caseStory?.currentBelief || 'The runtime preserved this case because it remained plausible inside the current anchors.'}
                                                        </div>
                                                        {candidateInputs.length > 0 && (
                                                            <div className="flex flex-wrap gap-1.5">
                                                                {candidateInputs.map((inputLabel) => (
                                                                    <span key={`${row.id}-compact-${inputLabel}`} className="px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-[10px] text-cyan-100">
                                                                        {inputLabel}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        )}
                                                        {(caseStory?.whyItMatters || boundedStopReason || nextStepSummary) && (
                                                            <div className="space-y-1">
                                                                {caseStory?.whyItMatters && (
                                                                    <div className="text-[10px] leading-relaxed text-slate-400">
                                                                        Why it matters: {caseStory.whyItMatters}
                                                                    </div>
                                                                )}
                                                                {boundedStopReason && (
                                                                    <div className="text-[10px] leading-relaxed text-red-200">
                                                                        Bounded stop: {boundedStopReason}
                                                                    </div>
                                                                )}
                                                                {nextStepSummary && (
                                                                    <div className="text-[10px] leading-relaxed text-cyan-200">
                                                                        Next step: {nextStepSummary}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                                <div className="text-[10px] text-slate-500 flex flex-wrap gap-x-3 gap-y-1">
                                                    <span>{formatFocusedEvidenceCount(row.evidenceCount, row.scopeViolationCount)}</span>
                                                    <span>{formatFocusedBrowserEvidenceCount(row.browserEvidenceCount, row.browserActionsUsed)}</span>
                                                    {row.lastRunAt && (
                                                        <span>Last run: {new Date(row.lastRunAt).toLocaleString()}</span>
                                                    )}
                                                    {row.executionProfileKey && (
                                                        <span>Profile: {row.executionProfileKey}</span>
                                                    )}
                                                    {row.browserSessionId && (
                                                        <span>Browser session: {row.browserSessionId}</span>
                                                    )}
                                                    {row.latestVerdict && (
                                                        <span>{formatFocusedEvidenceSufficiencyState(row.latestVerdict.evidenceSufficiency.state)}</span>
                                                    )}
                                                    {row.executionRailSummary && (
                                                        <span>{formatFocusedExecutionRail(row.executionRailSummary.rail)}</span>
                                                    )}
                                                    {row.historicalCompare?.verdictTransition && (
                                                        <span>{formatFocusedVerdictTransition(row.historicalCompare.verdictTransition)}</span>
                                                    )}
                                                    {row.historicalCompare?.evidenceDriftClassification && row.historicalCompare.evidenceDriftClassification !== 'unchanged' && (
                                                        <span>{formatFocusedEvidenceDriftClassification(row.historicalCompare.evidenceDriftClassification)}</span>
                                                    )}
                                                    {row.investigationSummary && row.investigationSummary.unresolvedCount > 0 && (
                                                        <span>{row.investigationSummary.unresolvedCount} unresolved issue{row.investigationSummary.unresolvedCount === 1 ? '' : 's'}</span>
                                                    )}
                                                </div>
                                                {row.latestVerdict && (
                                                    <div className="text-[10px] text-slate-300 leading-relaxed">
                                                        {row.latestVerdict.verdictReason}
                                                    </div>
                                                )}
                                                {row.latestVerdict?.evidenceSufficiency.summary && (
                                                    <div className="text-[10px] text-slate-500 leading-relaxed">
                                                        {row.latestVerdict.evidenceSufficiency.summary}
                                                    </div>
                                                )}
                                                {row.historicalCompare && (
                                                    <div className="text-[10px] text-cyan-100 leading-relaxed">
                                                        {row.historicalCompare.compareStatus === 'baseline_only'
                                                            ? 'First observed case in this baseline-producing run.'
                                                            : row.historicalCompare.compareNarrative
                                                                || formatFocusedBlockerRecurrence(row.historicalCompare)
                                                                || (row.historicalCompare.compareStatus === 'newly_introduced'
                                                                    ? 'Newly introduced case with no prior comparable case.'
                                                                    : row.historicalCompare.compareStatus === 'not_comparable'
                                                                        ? 'No safe prior case match was available.'
                                                                        : row.historicalCompare.verdictTransition
                                                                            ? formatFocusedVerdictTransition(row.historicalCompare.verdictTransition)
                                                                            : 'Historical comparison available for this case.')}
                                                    </div>
                                                )}
                                                {row.executionNotesSummary && (
                                                    <div className={`text-[10px] leading-relaxed ${row.scopeViolationCount > 0 || row.executionError ? 'text-red-300' : 'text-slate-400'}`}>
                                                        {row.executionError || row.executionNotesSummary}
                                                    </div>
                                                )}
                                                {row.executionRailSummary && (
                                                    <div className="text-[10px] text-slate-500 leading-relaxed">
                                                        {formatFocusedRailSummary(row.executionRailSummary)}
                                                    </div>
                                                )}
                                                {tracePreview.length > 0 && (
                                                    <div className="text-[10px] text-cyan-100 leading-relaxed">
                                                        {tracePreview.map((entry) => `${formatFocusedExecutionTraceActionType(entry.actionType)}: ${entry.actionSummary}`).join(' | ')}
                                                    </div>
                                                )}
                                                {row.investigationSummary?.latestIssueTitle && row.investigationSummary.unresolvedCount > 0 && (
                                                    <div className={`text-[10px] leading-relaxed ${
                                                        row.investigationSummary.blockingCount > 0 ? 'text-red-200' : 'text-amber-200'
                                                    }`}>
                                                        {row.investigationSummary.latestIssueTitle}
                                                    </div>
                                                )}
                                                {row.investigationSummary?.latestExpertFollowupHint && row.investigationSummary.unresolvedCount > 0 && (
                                                    <div className="text-[10px] text-cyan-200 leading-relaxed">
                                                        Expert follow-up: {row.investigationSummary.latestExpertFollowupHint}
                                                    </div>
                                                )}
                                                <div className="flex flex-wrap gap-2 items-center">
                                                    {showLegacyRecoveryPanel && isLegacyScopedReviewMode && (
                                                        <button
                                                            onClick={() => handleFocusedCaseUpdate(row.id, {
                                                                reviewState: row.reviewState === 'approved' ? 'pending_review' : 'approved',
                                                            })}
                                                            disabled={actionPending}
                                                            className="px-2.5 py-1 rounded-lg border border-green-500/30 bg-green-500/10 text-green-300 hover:bg-green-500/20 text-[10px] font-semibold disabled:opacity-50"
                                                        >
                                                            {row.reviewState === 'approved' ? 'Re-open' : 'Approve'}
                                                        </button>
                                                    )}
                                                    {showLegacyRecoveryPanel && (
                                                        <>
                                                            <button
                                                                onClick={() => handleFocusedCaseUpdate(row.id, {
                                                                    status: row.status === 'disabled' ? 'planned' : 'disabled',
                                                                })}
                                                                disabled={actionPending}
                                                                className="px-2.5 py-1 rounded-lg border border-slate-600 bg-slate-800/60 text-slate-200 hover:bg-slate-700 text-[10px] font-semibold disabled:opacity-50"
                                                            >
                                                                {row.status === 'disabled' ? 'Enable' : 'Disable'}
                                                            </button>
                                                            <select
                                                                value={row.priority}
                                                                onChange={(event) => handleFocusedCaseUpdate(row.id, {
                                                                    priority: event.target.value as FocusedTestCase['priority'],
                                                                })}
                                                                disabled={actionPending}
                                                                className="px-2 py-1 rounded-lg border border-violet-500/20 bg-slate-900 text-[10px] text-slate-200 disabled:opacity-50"
                                                            >
                                                                <option value="high">High priority</option>
                                                                <option value="medium">Medium priority</option>
                                                                <option value="low">Low priority</option>
                                                            </select>
                                                        </>
                                                    )}
                                                    <span className="text-[10px] text-slate-500 uppercase">{row.status}</span>
                                                    {showLegacyRecoveryPanel && (
                                                        <button
                                                            onClick={() => handleRunFocusedExecution([row.id])}
                                                            disabled={executePending || row.status === 'disabled' || (isLegacyScopedReviewMode && row.reviewState !== 'approved') || status === 'scoped_executing'}
                                                            className="px-2.5 py-1 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 text-[10px] font-semibold disabled:opacity-50"
                                                        >
                                                            Retry
                                                        </button>
                                                    )}
                                                    <button
                                                        onClick={() => handleInspectEvidence(row.id)}
                                                        disabled={evidenceLoadingCaseId === row.id}
                                                        className="px-2.5 py-1 rounded-lg border border-slate-600 bg-slate-800/60 text-slate-200 hover:bg-slate-700 text-[10px] font-semibold disabled:opacity-50"
                                                    >
                                                        {evidenceLoadingCaseId === row.id ? 'Loading...' : 'Inspect Evidence'}
                                                    </button>
                                                </div>
                                            </div>
                                        );
                                    })
                                )}
                            </div>
                        </div>
                    ) : (
                        <MissionControlLiveFindings
                            findings={liveFindingItems}
                            getSeverityColor={getSeverityColor}
                            onSelectFinding={(finding) => {
                                if (isScopedScan) {
                                    const caseId = scopedFindingCaseMap.get(String(finding.id));
                                    if (caseId) {
                                        void handleInspectEvidence(caseId);
                                        return;
                                    }
                                }
                                setSelectedVuln(finding);
                                setVulnChatHistory([]);
                            }}
                        />
                    )}
                </div>
                </div>

                {showScopedSecondaryContext && (
                    <MissionControlScopedSupportStrip
                        liveRuntimeSummary={liveRuntimeSummary}
                        focusedTestObjective={focusedTestObjective}
                        scopeEnvelope={scopeEnvelope}
                        scopedTestRequest={scopedTestRequest}
                        featureDiscoveryState={featureDiscoveryState}
                        isLegacyScopedRecoveryState={isLegacyScopedReviewMode}
                        showLegacyRecoveryTools={showLegacyRecoveryPanel}
                        onToggleLegacyRecovery={() => setShowLegacyRecovery((current) => !current)}
                    />
                )}

            </main>

            {/* VULNERABILITY DETAILS MODAL */}
            {selectedVuln && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="bg-dark-900 border border-white/10 w-full max-w-4xl max-h-[90vh] rounded-2xl flex flex-col shadow-2xl overflow-hidden"
                    >
                        {/* Header */}
                        <div className="p-6 border-b border-white/10 flex justify-between items-start bg-slate-900">
                            <div>
                                <div className="flex items-center gap-3 mb-2">
                                    <h2 className="text-xl font-bold text-white">{selectedVuln.name}</h2>
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${getSeverityColor(selectedVuln.severity)}`}>
                                        {selectedVuln.severity}
                                    </span>
                                </div>
                                <div className="flex gap-4 text-xs text-slate-400 font-mono">
                                    {selectedVuln.cwe && <span className="flex items-center gap-1"><span className="text-cyan-500">CWE:</span> {selectedVuln.cwe}</span>}
                                    {selectedVuln.cve && <span className="flex items-center gap-1"><span className="text-purple-500">CVE:</span> {selectedVuln.cve}</span>}
                                    {selectedVuln.cvssScore && <span className="flex items-center gap-1"><span className="text-orange-500">CVSS:</span> {selectedVuln.cvssScore}</span>}
                                </div>
                            </div>
                            <button onClick={() => setSelectedVuln(null)} className="p-2 hover:bg-white/10 rounded-lg text-slate-400 hover:text-white transition-colors">
                                <div className="w-6 h-6 flex items-center justify-center font-mono text-xl">✕</div>
                            </button>
                        </div>

                        {/* Content Scrollable */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-6">

                            {/* Description */}
                            <div>
                                <h3 className="text-xs font-bold text-cyan-400 uppercase mb-2 tracking-wider">Description & Impact</h3>
                                <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{selectedVuln.description}</p>
                            </div>

                            {/* Evidence Tabs (Req/Res) */}
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase flex items-center justify-between">
                                        Request
                                        <div className="flex items-center gap-1.5">
                                            {selectedVuln.request && (
                                                <>
                                                    <button
                                                        onClick={() => handleSendToBurp('repeater')}
                                                        disabled={!!burpSending}
                                                        className="flex items-center gap-1 text-[10px] font-semibold text-orange-400 hover:text-orange-300 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 px-2 py-0.5 rounded transition-all disabled:opacity-50"
                                                        title="Send to Burp Repeater"
                                                    >
                                                        {burpSending === 'repeater' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Repeat className="w-3 h-3" />}
                                                        Repeater
                                                    </button>
                                                    <button
                                                        onClick={() => handleSendToBurp('intruder')}
                                                        disabled={!!burpSending}
                                                        className="flex items-center gap-1 text-[10px] font-semibold text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 px-2 py-0.5 rounded transition-all disabled:opacity-50"
                                                        title="Send to Burp Intruder"
                                                    >
                                                        {burpSending === 'intruder' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Crosshair className="w-3 h-3" />}
                                                        Intruder
                                                    </button>
                                                    <button
                                                        onClick={() => handleSendToBurp('scanner')}
                                                        disabled={!!burpSending}
                                                        className="flex items-center gap-1 text-[10px] font-semibold text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 px-2 py-0.5 rounded transition-all disabled:opacity-50"
                                                        title="Send to Burp Active Scan"
                                                    >
                                                        {burpSending === 'scanner' ? <Loader2 className="w-3 h-3 animate-spin" /> : <ScanSearch className="w-3 h-3" />}
                                                        Scan
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </label>
                                    <div className="bg-black/50 p-4 rounded-lg font-mono text-xs text-green-400 h-64 overflow-auto border border-white/5 whitespace-pre-wrap scrollbar-thin scrollbar-thumb-slate-800">
                                        {selectedVuln.request || 'No request captured.'}
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <label className="text-xs font-bold text-slate-500 uppercase flex items-center justify-between">
                                        Response
                                        <span className="text-[10px] text-slate-600 font-mono bg-white/5 px-2 py-0.5 rounded">RAW</span>
                                    </label>
                                    <div className="bg-black/50 p-4 rounded-lg font-mono text-xs text-blue-400 h-64 overflow-auto border border-white/5 whitespace-pre-wrap scrollbar-thin scrollbar-thumb-slate-800">
                                        {selectedVuln.response || 'No response captured.'}
                                    </div>
                                </div>
                            </div>

                            {/* Remediation */}
                            {selectedVuln.remediation && (
                                <div>
                                    <h3 className="text-xs font-bold text-green-400 uppercase mb-2 tracking-wider">Remediation</h3>
                                    <div className="bg-green-900/10 border border-green-500/20 p-4 rounded-lg text-slate-300 text-sm leading-relaxed">
                                        {selectedVuln.remediation}
                                    </div>
                                </div>
                            )}

                            {/* Contextual AI Chat */}
                            <div className="border-t border-white/10 pt-6 mt-6">
                                <h3 className="text-xs font-bold text-purple-400 uppercase mb-4 flex items-center gap-2 tracking-wider">
                                    <Activity className="w-4 h-4" /> AI Security Analyst - Vulnerability Context
                                </h3>

                                <div className="bg-slate-950 rounded-xl border border-white/5 overflow-hidden flex flex-col h-[300px]">
                                    <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-slate-800">
                                        {vulnChatHistory.length === 0 ? (
                                            <div className="text-center text-slate-600 text-sm py-8 flex flex-col items-center gap-2">
                                                <div className="p-3 bg-white/5 rounded-full"><Terminal className="w-6 h-6 opacity-50" /></div>
                                                <p>Ask AI specific questions about this {selectedVuln.name}...</p>
                                                <div className="text-xs mt-2 opacity-50">Example: "Is this a false positive?" or "Generate a python exploit PoC"</div>
                                            </div>
                                        ) : (
                                            vulnChatHistory.map((msg, i) => (
                                                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                                    <div className={`max-w-[85%] p-3 rounded-lg text-sm leading-relaxed ${msg.role === 'user' ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-300 prose prose-invert prose-sm max-w-none'}`}>
                                                        {msg.role === 'user' ? (
                                                            msg.content
                                                        ) : (
                                                            <MarkdownRenderer content={msg.content} />
                                                        )}
                                                    </div>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                    <div className="p-3 bg-white/5 border-t border-white/5 flex gap-2 items-center">
                                        <input
                                            className="flex-1 bg-transparent border-none focus:ring-0 text-sm text-white placeholder-slate-500 outline-none"
                                            placeholder="Ask a question..."
                                            value={vulnChatCommand}
                                            onChange={e => setVulnChatCommand(e.target.value)}
                                            onKeyDown={e => e.key === 'Enter' && handleVulnChatSend()}
                                            autoFocus
                                        />
                                        <button
                                            onClick={handleVulnChatSend}
                                            disabled={isVulnChatSending || !vulnChatCommand.trim()}
                                            className="p-2 text-cyan-400 hover:text-white disabled:opacity-30 transition-colors"
                                        >
                                            <Send className="w-4 h-4" />
                                        </button>
                                    </div>
                                </div>
                            </div>

                        </div>
                    </motion.div>
                </div>
            )}

            {/* Report Options Modal */}
            <ReportOptionsModal
                isOpen={reportModalOpen}
                onClose={() => setReportModalOpen(false)}
                scanId={scanIdRef.current}
            />
        </div>
    );
}
