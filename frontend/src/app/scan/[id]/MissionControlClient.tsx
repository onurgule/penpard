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
    StopCircle,
    Download,
    Pause,
    Play,
    Repeat,
    Loader2,
    Crosshair,
    ScanSearch,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';
import { MarkdownRenderer } from '@/components/MarkdownRenderer';
import { API_URL } from '@/lib/api-config';
import ReportOptionsModal from '@/components/modals/ReportOptionsModal';

interface LogEntry {
    timestamp: string;
    type: string;
    message: string;
}

interface Vulnerability {
    id: number;
    name: string;
    severity: string;
    description: string;
    // New fields
    cwe?: string;
    cve?: string;
    cvssScore?: number;
    request?: string;
    response?: string;
    remediation?: string;
}

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
            setVulns(data.vulnerabilities || []);

            // Derive progress from status
            const map: Record<string, number> = {
                'queued': 5,
                'initializing': 10,
                'planning': 20,
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

    // Show loading until scanId is resolved from URL
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
                        {status === 'completed' && (
                            <button
                                onClick={() => setReportModalOpen(true)}
                                className="btn-primary flex items-center gap-2 text-xs"
                            >
                                <Download className="w-4 h-4" /> Export Report
                            </button>
                        )}
                        <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                            isPaused ? 'bg-amber-500/20 text-amber-400' :
                            status === 'scanning' || status === 'crawling' || status === 'testing' ? 'bg-cyan-500/20 text-cyan-400 animate-pulse' :
                            status === 'completed' ? 'bg-green-500/20 text-green-400' : 'bg-slate-800 text-slate-400'
                            }`}>
                            {isPaused ? 'paused' : status}
                        </div>
                    </div>
                </div>
            </header>

            <main className="pt-20 pb-8 px-4 max-w-[1600px] mx-auto min-h-[calc(100vh-theme(spacing.10))] grid grid-cols-12 gap-6">

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
                        ) : (status === 'scanning' || status === 'crawling' || status === 'testing') ? (
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
                                    <p className="text-slate-400 text-xs max-w-[200px]">
                                        Orchestrator is analyzing target topology...
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
                                    <p className="text-xs mt-1">Type a message to ask PenPard about the scan...</p>
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
                        {scanCompleted && showContinuePanel && (
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
                                        ? "Enter instructions to continue scanning..."
                                        : "Type instructions for PenPard..."
                                    }
                                    className={`w-full bg-slate-800/50 border rounded-xl px-4 py-3 text-white placeholder-slate-500 text-sm focus:ring-1 outline-none transition-all ${
                                        showContinuePanel && scanCompleted
                                            ? 'border-cyan-500/40 focus:border-cyan-500 focus:ring-cyan-500/50 pr-28'
                                            : 'border-slate-700 focus:border-cyan-500/50 focus:ring-cyan-500/50 pr-12'
                                    }`}
                                />
                                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                                    {/* Continue Scan button — only when completed + panel open */}
                                    {showContinuePanel && scanCompleted && (
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
                            {scanCompleted && !showContinuePanel && (
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
                                {scanCompleted ? 'Scan Finished' : isPaused ? 'Paused (Monitoring)' : isAgentActive ? 'Agent Online' : 'Agent Offline'}
                            </span>
                            <span className="flex items-center gap-1">
                                <div className={`w-1.5 h-1.5 rounded-full ${
                                    scanCompleted ? 'bg-blue-500' :
                                    burpConnected === true ? 'bg-green-500' : burpConnected === false ? 'bg-red-500' : 'bg-slate-500'
                                }`}></div>
                                {scanCompleted ? 'Burp Session Ended' : burpConnected === true ? 'Burp Connected' : 'Burp Disconnected'}
                            </span>
                        </div>
                        <div className="flex items-center gap-3">
                            {isAgentActive && !isPaused && status !== 'completed' && status !== 'failed' && (
                                <button onClick={handlePause} className="text-xs text-amber-400 hover:text-amber-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
                                    <Pause className="w-3 h-3" /> PAUSE
                                </button>
                            )}
                            {isPaused && (
                                <button onClick={handleResume} className="text-xs text-green-400 hover:text-green-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
                                    <Play className="w-3 h-3" /> RESUME
                                </button>
                            )}
                            <button onClick={handleStop} className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 opacity-80 hover:opacity-100 transition-opacity">
                                <StopCircle className="w-3 h-3" /> STOP
                            </button>
                        </div>
                    </div>
                </div>

                {/* Right: Findings */}
                <div className="col-span-12 lg:col-span-3 flex flex-col bg-white/5 rounded-xl border border-white/10 overflow-hidden h-[calc(100vh-8rem)]">
                    <div className="p-4 border-b border-white/10 flex justify-between items-center bg-black/20 flex-shrink-0">
                        <h2 className="font-bold text-sm text-white">Live Findings</h2>
                        <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-xs border border-red-500/20">{vulns.length} Issues</span>
                    </div>
                    <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin scrollbar-thumb-slate-700">
                        {vulns.length === 0 ? (
                            <div className="text-center py-10 opacity-50">
                                <Shield className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                                <div className="text-sm text-slate-500">No vulnerabilities found yet.</div>
                            </div>
                        ) : (
                            <AnimatePresence>
                                {vulns.map((vuln) => (
                                    <motion.div
                                        key={vuln.id}
                                        initial={{ opacity: 0, x: 20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        onClick={() => {
                                            setSelectedVuln(vuln);
                                            setVulnChatHistory([]);
                                        }}
                                        className={`p-3 rounded-lg border cursor-pointer hover:bg-white/5 transition-colors ${getSeverityColor(vuln.severity)}`}
                                    >
                                        <div className="flex justify-between items-start mb-1">
                                            <div className="font-bold text-sm truncate pr-2">{vuln.name}</div>
                                            <div className="text-[10px] uppercase font-bold opacity-70">{vuln.severity}</div>
                                        </div>
                                        <div className="text-xs opacity-80 line-clamp-2">{vuln.description}</div>
                                    </motion.div>
                                ))}
                            </AnimatePresence>
                        )}
                    </div>
                </div>

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
