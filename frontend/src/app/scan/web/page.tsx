'use client';

import {
    useState, useEffect
} from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import axios from 'axios';
import toast from 'react-hot-toast';
import {
    ArrowLeft,
    Globe,
    Search,
    Shield,
    Loader2,
    CheckCircle,
    XCircle,
    Download,
    Zap,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import ReportOptionsModal from '@/components/modals/ReportOptionsModal';
import SourceModeSelector, { SourceMode } from '@/components/SourceModeSelector';
import SourceProviderInput, { SourceType } from '@/components/SourceProviderInput';
import { FolderOpen } from 'lucide-react';

const SOURCE_ANALYSIS_MODES: SourceMode[] = [
    {
        id: 'version_aware',
        title: 'Version Aware',
        description: [
            'Lightweight source intelligence',
            'Dependency/version/CVE-aware testing',
            'Lower token cost',
        ],
        tokenCost: 'low',
        icon: 'zap',
    },
    {
        id: 'full_source_aware',
        title: 'Full Source Aware',
        description: [
            'Deep code understanding',
            'Function/endpoint/flow-aware testing',
            'Higher token cost, richer analysis',
        ],
        tokenCost: 'high',
        icon: 'brain',
    },
];

const SCAN_OPTIONS_KEY = 'penpard-scan-options';

function getDefaultScanOptions() {
    if (typeof window === 'undefined') return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
    try {
        const s = localStorage.getItem(SCAN_OPTIONS_KEY);
        if (!s) return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
        const o = JSON.parse(s);
        return {
            iterations: Math.max(10, Math.min(500, Number(o.iterations) || 50)),
            parallelAgents: Math.max(1, Math.min(10, Number(o.parallelAgents) || 1)),
            rateLimit: Number(o.rateLimit) || 5,
            maxPlanRounds: Math.max(0, Math.min(99, Number(o.maxPlanRounds) ?? 0)),
        };
    } catch {
        return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
    }
}

interface ScanStatus {
    id: string | null;
    status: 'idle' | 'validating' | 'scanning' | 'analyzing' | 'complete' | 'error';
    message: string;
    progress: number;
    vulnerabilities: any[];
}

export default function WebScanPage() {
    const router = useRouter();
    const { isAuthenticated } = useAuthStore();

    const [targetUrl, setTargetUrl] = useState('');
    const [scanInstructions, setScanInstructions] = useState('');
    const [sessionCookies, setSessionCookies] = useState('');
    const [rateLimit, setRateLimit] = useState(() => getDefaultScanOptions().rateLimit);
    const [parallelAgents, setParallelAgents] = useState(() => getDefaultScanOptions().parallelAgents);
    const [iterations, setIterations] = useState(() => getDefaultScanOptions().iterations);
    const [maxPlanRounds, setMaxPlanRounds] = useState(() => getDefaultScanOptions().maxPlanRounds);
    const [userAccounts, setUserAccounts] = useState([{ username: '', password: '', role: 'user' }]);
    const [sourcePackagePath, setSourcePackagePath] = useState('');
    const [sourceAnalysisMode, setSourceAnalysisMode] = useState<string | null>(null);
    const [sourceType, setSourceType] = useState<SourceType>('local');
    const [zipFile, setZipFile] = useState<File | null>(null);
    const [gitUrl, setGitUrl] = useState('');
    const [gitToken, setGitToken] = useState('');
    const [reportModalOpen, setReportModalOpen] = useState(false);
    const [externalTools, setExternalTools] = useState({
        nuclei: false,
        ffuf: false,
    });
    const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'agent', content: string }[]>([]);
    const [chatInput, setChatInput] = useState('');
    const [extractedEndpoints, setExtractedEndpoints] = useState<any[] | null>(null);
    const [isExtracting, setIsExtracting] = useState(false);
    const [selectedEndpointKeys, setSelectedEndpointKeys] = useState<Set<string>>(new Set());
    const [isDeepScanning, setIsDeepScanning] = useState(false);
    const [endpointFilter, setEndpointFilter] = useState<'all' | 'static' | 'ai'>('all');

    const [scanStatus, setScanStatus] = useState<ScanStatus>({
        id: null,
        status: 'idle',
        message: '',
        progress: 0,
        vulnerabilities: [],
    });

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
            return;
        }
    }, [isAuthenticated, router]);

    const validateUrl = (url: string) => {
        try {
            new URL(url.startsWith('http') ? url : `https://${url}`);
            return true;
        } catch {
            return false;
        }
    };

    const handleExtractEndpoints = async () => {
        setIsExtracting(true);
        setExtractedEndpoints(null);

        const formData = new FormData();
        formData.append('sourceType', sourceType);
        if (sourceType === 'local') {
            formData.append('sourcePackagePath', String(sourcePackagePath).trim());
        } else if (sourceType === 'zip' && zipFile) {
            formData.append('sourceZip', zipFile);
        } else if (sourceType === 'git') {
            formData.append('sourceGitUrl', String(gitUrl).trim());
            if (gitToken?.trim()) formData.append('sourceGitToken', String(gitToken).trim());
        }

        try {
            const res = await fetch(`${API_URL}/scans/extract-endpoints`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${useAuthStore.getState().token}` },
                body: formData,
            });
            const data = await res.json();
            if (data.endpoints) {
                const tagged = data.endpoints.map((ep: any) => ({ ...ep, source: 'static' }));
                setExtractedEndpoints(tagged);
                setSelectedEndpointKeys(new Set(tagged.map((ep: any) => `${ep.method}:${ep.path}`)));
                setEndpointFilter('all');
                toast.success(`Extracted ${tagged.length} backend endpoints`);
            } else {
                toast.error(data.message || 'Failed to extract endpoints');
            }
        } catch (e: any) {
            toast.error(e.message || 'Error executing request');
        } finally {
            setIsExtracting(false);
        }
    };

    const handleDeepScanAI = async () => {
        if (!extractedEndpoints) return;
        setIsDeepScanning(true);

        const formData = new FormData();
        formData.append('sourceType', sourceType);
        if (sourceType === 'local') {
            formData.append('sourcePackagePath', String(sourcePackagePath).trim());
        } else if (sourceType === 'zip' && zipFile) {
            formData.append('sourceZip', zipFile);
        } else if (sourceType === 'git') {
            formData.append('sourceGitUrl', String(gitUrl).trim());
            if (gitToken?.trim()) formData.append('sourceGitToken', String(gitToken).trim());
        }
        formData.append('existingRoutes', JSON.stringify(extractedEndpoints));

        try {
            const res = await fetch(`${API_URL}/scans/extract-endpoints-ai`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${useAuthStore.getState().token}` },
                body: formData,
            });
            const data = await res.json();
            if (data.endpoints && data.endpoints.length > 0) {
                const taggedAi = data.endpoints.map((ep: any) => ({ ...ep, source: 'ai' }));
                // Deduplicate AI results against existing endpoints
                const existingKeys = new Set(extractedEndpoints.map((ep: any) => `${ep.method}:${ep.path}`));
                const uniqueAi = taggedAi.filter((ep: any) => {
                    const key = `${ep.method}:${ep.path}`;
                    if (existingKeys.has(key)) return false;
                    existingKeys.add(key);
                    return true;
                });
                if (uniqueAi.length > 0) {
                    const merged = [...extractedEndpoints, ...uniqueAi];
                    setExtractedEndpoints(merged);
                    const newKeys = new Set(selectedEndpointKeys);
                    uniqueAi.forEach((ep: any) => newKeys.add(`${ep.method}:${ep.path}`));
                    setSelectedEndpointKeys(newKeys);
                    toast.success(`AI discovered ${uniqueAi.length} additional dynamic route${uniqueAi.length !== 1 ? 's' : ''}`);
                } else {
                    toast.success('AI analysis complete — all found routes were already in the list');
                }
            } else {
                toast.success('AI analysis complete — no additional dynamic routes found');
            }
        } catch (e: any) {
            toast.error(e.message || 'AI deep scan failed');
        } finally {
            setIsDeepScanning(false);
        }
    };

    const handleStartScan = async () => {
        if (!targetUrl) {
            toast.error('Please enter a target URL');
            return;
        }

        if (!validateUrl(targetUrl)) {
            toast.error('Invalid URL format');
            return;
        }

        const fullUrl = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;

        setScanStatus({
            id: null,
            status: 'validating',
            message: 'Validating target and whitelist...',
            progress: 10,
            vulnerabilities: [],
        });

        try {
            // Start the scan
            const formData = new FormData();
            formData.append('url', fullUrl);
            formData.append('rateLimit', String(rateLimit));
            formData.append('parallelAgents', String(parallelAgents));
            formData.append('iterations', String(iterations));
            formData.append('maxPlanRounds', String(maxPlanRounds));
            formData.append('useNuclei', String(externalTools.nuclei));
            formData.append('useFfuf', String(externalTools.ffuf));
            formData.append('idorUsers', JSON.stringify(userAccounts.filter(u => u.username && u.password)));
            if (scanInstructions.trim()) formData.append('scanInstructions', scanInstructions.trim());
            if (sessionCookies.trim()) formData.append('sessionCookies', sessionCookies.trim());

            const wantsSource = (sourceType === 'local' && sourcePackagePath.trim()) || 
                                (sourceType === 'zip' && zipFile) || 
                                (sourceType === 'git' && gitUrl.trim());

            if (wantsSource && sourceAnalysisMode) {
                formData.append('sourceAnalysisMode', sourceAnalysisMode);
                formData.append('sourceType', sourceType);
                if (sourceType === 'local') {
                    formData.append('sourcePackagePath', sourcePackagePath.trim());
                } else if (sourceType === 'zip' && zipFile) {
                    formData.append('sourceZip', zipFile);
                } else if (sourceType === 'git') {
                    formData.append('sourceGitUrl', gitUrl.trim());
                    if (gitToken.trim()) formData.append('sourceGitToken', gitToken.trim());
                }
            }

            // Pass selected endpoints to the scan
            if (extractedEndpoints && selectedEndpointKeys.size > 0) {
                const selected = extractedEndpoints.filter(ep => selectedEndpointKeys.has(`${ep.method}:${ep.path}`));
                formData.append('targetEndpoints', JSON.stringify(selected));
            }

            if (typeof window !== 'undefined') {
                try {
                    localStorage.setItem(SCAN_OPTIONS_KEY, JSON.stringify({
                        iterations,
                        parallelAgents,
                        rateLimit,
                        maxPlanRounds,
                    }));
                } catch { /* ignore */ }
            }
            const response = await axios.post(`${API_URL}/scans/web`, formData, {
                headers: { 
                    Authorization: `Bearer ${useAuthStore.getState().token}`,
                    'Content-Type': 'multipart/form-data'
                }
            });

            const { scanId } = response.data;

            toast.success('Scan initiated! Redirecting to Mission Control...');
            // Use full navigation for dynamic routes (static export compatibility)
            window.location.href = `/scan/${scanId}`;

        } catch (error: any) {
            const message = error.response?.data?.message || 'Failed to start scan';
            setScanStatus({
                id: null,
                status: 'error',
                message,
                progress: 0,
                vulnerabilities: [],
            });
            toast.error(message);
        }
    };

    const pollScanStatus = async (scanId: string) => {
        let attempts = 0;
        const maxAttempts = 60; // 5 minutes max

        const poll = async () => {
            try {
                const response = await axios.get(`${API_URL}/scans/${scanId}`);
                const { status, vulnerabilities, message } = response.data;

                if (status === 'completed') {
                    setScanStatus({
                        id: scanId,
                        status: 'complete',
                        message: 'Scan completed successfully!',
                        progress: 100,
                        vulnerabilities: vulnerabilities || [],
                    });
                    toast.success('Scan completed!');
                    return;
                }

                if (status === 'failed') {
                    setScanStatus({
                        id: scanId,
                        status: 'error',
                        message: message || 'Scan failed',
                        progress: 0,
                        vulnerabilities: [],
                    });
                    toast.error('Scan failed');
                    return;
                }

                // Update progress
                const progressMap: Record<string, number> = {
                    queued: 15,
                    crawling: 30,
                    auditing: 50,
                    analyzing: 75,
                    reporting: 90,
                };

                setScanStatus((prev) => ({
                    ...prev,
                    status: 'scanning',
                    message: `Status: ${status}`,
                    progress: progressMap[status] || prev.progress,
                }));

                attempts++;
                if (attempts < maxAttempts) {
                    setTimeout(poll, 5000);
                } else {
                    setScanStatus((prev) => ({
                        ...prev,
                        status: 'error',
                        message: 'Scan timed out',
                    }));
                }
            } catch (error) {
                console.error('Poll error:', error);
                attempts++;
                if (attempts < maxAttempts) {
                    setTimeout(poll, 5000);
                }
            }
        };

        poll();
    };

    const getStatusIcon = () => {
        switch (scanStatus.status) {
            case 'scanning':
            case 'validating':
            case 'analyzing':
                return <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />;
            case 'complete':
                return <CheckCircle className="w-6 h-6 text-green-400" />;
            case 'error':
                return <XCircle className="w-6 h-6 text-red-400" />;
            default:
                return <Search className="w-6 h-6 text-gray-400" />;
        }
    };

    const getSeverityClass = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'severity-critical';
            case 'high':
                return 'severity-high';
            case 'medium':
                return 'severity-medium';
            case 'low':
                return 'severity-low';
            default:
                return 'severity-info';
        }
    };

    const isScanning = ['validating', 'scanning', 'analyzing'].includes(scanStatus.status);

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="glass-darker border-b border-dark-600/50 sticky top-10 z-40">
                <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link
                        href="/dashboard"
                        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                    >
                        <ArrowLeft className="w-5 h-5" />
                        <span>Back to Dashboard</span>
                    </Link>
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-4xl mx-auto px-4 py-8">
                {/* Title */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 mb-4">
                        <Globe className="w-8 h-8 text-cyan-400" />
                    </div>
                    <h1 className="text-3xl font-bold text-white mb-2">Web Application Scan</h1>
                    <p className="text-gray-400">Enter a target URL to begin vulnerability analysis</p>
                </div>

                {/* URL Input - Minimalist PenPard Style */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="card p-6 mb-8"
                >
                    <div className="relative">
                        <input
                            type="text"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            placeholder="Enter target URL (e.g., example.com)"
                            disabled={isScanning}
                            className="w-full px-6 py-4 bg-dark-900 border-2 border-dark-600 rounded-xl text-white text-lg terminal-text placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50"
                            onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleStartScan()}
                        />

                        <button
                            onClick={handleStartScan}
                            disabled={isScanning}
                            className="absolute right-2 top-1/2 -translate-y-1/2 px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-lg transition-all hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                        >
                            {isScanning ? (
                                <>
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    <span>Scanning...</span>
                                </>
                            ) : (
                                <>
                                    <Search className="w-5 h-5" />
                                    <span>Scan</span>
                                </>
                            )}
                        </button>
                    </div>

                    {/* Scan Instructions */}
                    <div className="mt-4">
                        <label className="block text-gray-400 text-sm mb-2">Scan Instructions <span className="text-gray-600">(optional)</span></label>
                        <textarea
                            value={scanInstructions}
                            onChange={(e) => setScanInstructions(e.target.value)}
                            placeholder='Guide the AI scanner, e.g. "Focus only on /admin endpoints" or "Test the login form for SQLi" or "Check IDOR on /api/users/{id}"'
                            disabled={isScanning}
                            rows={3}
                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50 resize-y"
                        />
                    </div>

                    {/* Authenticated testing tip */}
                    <div className="mt-4 p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-sm text-gray-300">
                        <strong className="text-cyan-400">Authenticated test:</strong> Browse the target in your browser through Burp and log in first; PenPard will use cookies from proxy history for authenticated requests. You can also paste a Cookie header below.
                    </div>

                    {/* Session cookies (authenticated testing, e.g. Google login) */}
                    <div className="mt-4">
                        <label className="block text-gray-400 text-sm mb-2">Session cookies <span className="text-gray-600">(optional)</span></label>
                        <textarea
                            value={sessionCookies}
                            onChange={(e) => setSessionCookies(e.target.value)}
                            placeholder='Paste Cookie header from browser/Burp after logging in (e.g. Google). Or leave empty: agent will use cookies from Burp proxy history (newest first).'
                            disabled={isScanning}
                            rows={2}
                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50 resize-y font-mono"
                        />
                    </div>
                </motion.div>

                {/* Advanced Configuration */}
                {scanStatus.status === 'idle' && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.1 }}
                        className="card p-6 mb-8 space-y-6"
                    >
                        <h3 className="text-lg font-semibold text-white border-b border-dark-600 pb-2">Scan Configuration</h3>

                        {/* Rate Limit */}
                        <div>
                            <label className="block text-gray-400 text-sm mb-2">
                                Rate Limit: <span className="text-cyan-400 font-bold">{rateLimit} req/sec</span>
                            </label>
                            <div className="flex items-center gap-4">
                                <input
                                    type="range"
                                    value={rateLimit}
                                    onChange={(e) => setRateLimit(parseInt(e.target.value))}
                                    min="1"
                                    max="30"
                                    step="1"
                                    className="flex-1 h-2 bg-dark-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                                />
                                <div className="flex gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setRateLimit(2)}
                                        className={`px-2 py-1 text-xs rounded ${rateLimit === 2 ? 'bg-cyan-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        Stealth
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setRateLimit(5)}
                                        className={`px-2 py-1 text-xs rounded ${rateLimit === 5 ? 'bg-cyan-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        Normal
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setRateLimit(15)}
                                        className={`px-2 py-1 text-xs rounded ${rateLimit === 15 ? 'bg-amber-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        Fast
                                    </button>
                                </div>
                            </div>
                            <p className="text-gray-500 text-xs mt-2">
                                {rateLimit <= 3
                                    ? 'Slow & stealthy — minimal footprint on the target'
                                    : rateLimit <= 8
                                        ? 'Balanced — good speed without overloading the target'
                                        : rateLimit <= 20
                                            ? 'Fast — may trigger WAF/rate limiting on some targets'
                                            : 'Aggressive — use only on targets you control'
                                }
                            </p>
                        </div>

                        {/* Parallel Agents */}
                        <div>
                            <label className="block text-gray-400 text-sm mb-2 flex items-center gap-2">
                                <Zap className="w-4 h-4 text-amber-400" />
                                Parallel Agents: <span className="text-cyan-400 font-bold">{parallelAgents}</span>
                                {parallelAgents > 1 && <span className="text-amber-400 text-xs">(Multi-Agent Mode)</span>}
                            </label>
                            <div className="flex items-center gap-4">
                                <input
                                    type="range"
                                    value={parallelAgents}
                                    onChange={(e) => setParallelAgents(parseInt(e.target.value))}
                                    min="1"
                                    max="10"
                                    className="flex-1 h-2 bg-dark-700 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                                />
                                <div className="flex gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setParallelAgents(1)}
                                        className={`px-2 py-1 text-xs rounded ${parallelAgents === 1 ? 'bg-cyan-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        Single
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setParallelAgents(5)}
                                        className={`px-2 py-1 text-xs rounded ${parallelAgents === 5 ? 'bg-cyan-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        5x
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setParallelAgents(10)}
                                        className={`px-2 py-1 text-xs rounded ${parallelAgents === 10 ? 'bg-amber-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                    >
                                        10x Turbo
                                    </button>
                                </div>
                            </div>
                            <p className="text-gray-500 text-xs mt-2">
                                {parallelAgents === 1
                                    ? 'Standard single-agent scan'
                                    : `${parallelAgents} agents scanning in parallel (faster but uses more resources)`
                                }
                            </p>
                        </div>

                        {/* Iterations (max actions) */}
                        <div>
                            <label className="block text-gray-400 text-sm mb-2">
                                Iterations (max actions): <span className="text-cyan-400 font-bold">{iterations}</span>
                            </label>
                            <input
                                type="number"
                                min={10}
                                max={500}
                                value={iterations}
                                onChange={(e) => setIterations(Math.max(10, Math.min(500, Number(e.target.value) || 50)))}
                                className="input-field w-full max-w-[120px]"
                            />
                            <p className="text-gray-500 text-xs mt-1">Max tool/action steps per scan (10–500).</p>
                        </div>

                        {/* Planning rounds */}
                        <div>
                            <label className="block text-gray-400 text-sm mb-2">
                                Planning rounds: <span className="text-cyan-400 font-bold">{maxPlanRounds === 0 ? 'Default (model decides)' : maxPlanRounds}</span>
                            </label>
                            <input
                                type="number"
                                min={0}
                                max={99}
                                value={maxPlanRounds}
                                onChange={(e) => setMaxPlanRounds(Math.max(0, Math.min(99, Number(e.target.value) ?? 0)))}
                                className="input-field w-full max-w-[120px]"
                            />
                            <p className="text-gray-500 text-xs mt-1">0 = model decides when to finish; 1–99 = fixed number of planning rounds.</p>
                        </div>

                        {/* User Accounts */}
                        <div>
                            <div className="flex items-center justify-between mb-3">
                                <label className="block text-gray-400 text-sm">User Accounts (IDOR Testing)</label>
                                <button
                                    onClick={() => setUserAccounts([...userAccounts, { username: '', password: '', role: 'user' }])}
                                    className="text-cyan-400 text-xs hover:underline"
                                >
                                    + Add Account
                                </button>
                            </div>
                            <div className="space-y-3">
                                {userAccounts.map((acc, idx) => (
                                    <div key={idx} className="grid grid-cols-[1fr_1fr_auto_auto] gap-3 items-center">
                                        <input
                                            type="text"
                                            placeholder="Username or email"
                                            value={acc.username}
                                            onChange={(e) => {
                                                const newAccs = [...userAccounts];
                                                newAccs[idx].username = e.target.value;
                                                setUserAccounts(newAccs);
                                            }}
                                            className="input-field text-sm w-full min-w-0"
                                        />
                                        <input
                                            type="password"
                                            placeholder="Password / Token / Cookie"
                                            value={acc.password}
                                            onChange={(e) => {
                                                const newAccs = [...userAccounts];
                                                newAccs[idx].password = e.target.value;
                                                setUserAccounts(newAccs);
                                            }}
                                            className="input-field text-sm w-full min-w-0"
                                        />
                                        <select
                                            value={acc.role}
                                            onChange={(e) => {
                                                const newAccs = [...userAccounts];
                                                newAccs[idx].role = e.target.value;
                                                setUserAccounts(newAccs);
                                            }}
                                            className="input-field text-sm w-28"
                                        >
                                            <option value="user">User</option>
                                            <option value="admin">Admin</option>
                                        </select>
                                        {userAccounts.length > 1 ? (
                                            <button
                                                onClick={() => setUserAccounts(userAccounts.filter((_, i) => i !== idx))}
                                                className="text-red-400 hover:bg-red-500/10 p-2 rounded flex-shrink-0"
                                            >
                                                <XCircle className="w-4 h-4" />
                                            </button>
                                        ) : (
                                            <div className="w-8" />
                                        )}
                                    </div>
                                ))}
                            </div>
                            <p className="text-gray-500 text-xs mt-2">
                                Add multiple user accounts to test for IDOR and privilege escalation vulnerabilities
                            </p>
                        </div>

                        {/* External Tools */}
                        <div>
                            <label className="block text-gray-400 text-sm mb-2">External Tools</label>
                            <div className="flex gap-4">
                                <label className="flex items-center gap-2 card p-3 border border-dark-600 opacity-50 cursor-not-allowed" title="Nuclei integration is not yet implemented">
                                    <input
                                        type="checkbox"
                                        checked={false}
                                        disabled
                                        className="checkbox"
                                    />
                                    <span className="text-gray-400">Nuclei Vulnerability Scanner</span>
                                    <span className="text-[10px] text-yellow-500/80 font-mono ml-1">(Coming Soon)</span>
                                </label>
                                <label className="flex items-center gap-2 card p-3 border border-dark-600 opacity-50 cursor-not-allowed" title="FFUF integration is not yet implemented">
                                    <input
                                        type="checkbox"
                                        checked={false}
                                        disabled
                                        className="checkbox"
                                    />
                                    <span className="text-gray-400">FFUF Fuzzing</span>
                                    <span className="text-[10px] text-yellow-500/80 font-mono ml-1">(Coming Soon)</span>
                                </label>
                            </div>
                        </div>

                        {/* Source Package / Source Analysis */}
                        <div className="border-t border-dark-600 pt-6">
                            <h4 className="text-white font-medium mb-4 flex items-center gap-2">
                                <FolderOpen className="w-4 h-4 text-cyan-400" />
                                Source-Aware Scanning
                                <span className="text-gray-600 text-xs font-normal">(optional)</span>
                            </h4>

                            <div className="mb-4">
                                <SourceProviderInput
                                    sourceType={sourceType} setSourceType={setSourceType}
                                    localPath={sourcePackagePath} setLocalPath={(val) => {
                                        setSourcePackagePath(val);
                                        if (!val.trim() && sourceType === 'local') setSourceAnalysisMode(null);
                                    }}
                                    zipFile={zipFile} setZipFile={(val) => {
                                        setZipFile(val);
                                        if (!val && sourceType === 'zip') setSourceAnalysisMode(null);
                                    }}
                                    gitUrl={gitUrl} setGitUrl={(val) => {
                                        setGitUrl(val);
                                        if (!val.trim() && sourceType === 'git') setSourceAnalysisMode(null);
                                    }}
                                    gitToken={gitToken} setGitToken={setGitToken}
                                    disabled={isScanning}
                                />
                            </div>

                            {((sourceType === 'local' && sourcePackagePath.trim()) || (sourceType === 'zip' && zipFile) || (sourceType === 'git' && gitUrl.trim())) && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    transition={{ duration: 0.2 }}
                                >
                                    <SourceModeSelector
                                        modes={SOURCE_ANALYSIS_MODES}
                                        selected={sourceAnalysisMode}
                                        onSelect={setSourceAnalysisMode}
                                        disabled={isScanning}
                                    />
                                    
                                    <div className="mt-6 flex flex-col gap-4">
                                        {!extractedEndpoints && (
                                            <button
                                                type="button"
                                                onClick={handleExtractEndpoints}
                                                disabled={isExtracting || isScanning}
                                                className="btn btn-secondary w-full sm:w-auto"
                                            >
                                                {isExtracting ? (
                                                    <span className="flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin text-cyan-400" /> Analyzing Source Code...</span>
                                                ) : (
                                                    <span className="flex items-center gap-2"><Search className="w-4 h-4 text-cyan-400" /> Extract Endpoints from Codebase</span>
                                                )}
                                            </button>
                                        )}
                                                                      {extractedEndpoints && (
                                            <div className="bg-dark-800 rounded-lg border border-dark-600 p-4">
                                                {/* Header — outside scroll */}
                                                <div className="flex justify-between items-center mb-3 pb-2 border-b border-dark-700">
                                                    <h4 className="text-sm font-semibold text-white">Extracted Routes <span className="text-cyan-400 ml-1">{selectedEndpointKeys.size}/{extractedEndpoints.length} selected</span></h4>
                                                    <div className="flex items-center gap-3">
                                                        {endpointFilter === 'all' && (
                                                            <>
                                                                <button type="button" onClick={() => setSelectedEndpointKeys(new Set(extractedEndpoints.map(ep => `${ep.method}:${ep.path}`)))} className="text-xs text-cyan-400 hover:text-white">All</button>
                                                                <button type="button" onClick={() => setSelectedEndpointKeys(new Set())} className="text-xs text-gray-400 hover:text-white">None</button>
                                                            </>
                                                        )}
                                                        <button type="button" onClick={() => { setExtractedEndpoints(null); setSelectedEndpointKeys(new Set()); setEndpointFilter('all'); }} className="text-xs text-gray-500 hover:text-white">Clear</button>
                                                    </div>
                                                </div>
                                                {/* Filter Tabs */}
                                                {(() => {
                                                    const staticCount = extractedEndpoints.filter(ep => ep.source !== 'ai').length;
                                                    const aiCount = extractedEndpoints.filter(ep => ep.source === 'ai').length;
                                                    return (
                                                        <div className="flex items-center gap-1 mb-3">
                                                            {(['all', 'static', 'ai'] as const).map((tab) => {
                                                                const count = tab === 'all' ? extractedEndpoints.length : tab === 'static' ? staticCount : aiCount;
                                                                const label = tab === 'all' ? 'All' : tab === 'static' ? 'Static' : '🧠 AI';
                                                                if (tab === 'ai' && aiCount === 0) return null;
                                                                return (
                                                                    <button
                                                                        key={tab}
                                                                        type="button"
                                                                        onClick={() => setEndpointFilter(tab)}
                                                                        className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                                                                            endpointFilter === tab
                                                                                ? tab === 'ai' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40' : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                                                                                : 'bg-dark-700 text-gray-500 border border-dark-600 hover:text-gray-300'
                                                                        }`}
                                                                    >
                                                                        {label} <span className="ml-1 opacity-70">{count}</span>
                                                                    </button>
                                                                );
                                                            })}
                                                        </div>
                                                    );
                                                })()}
                                                {/* Scrollable list only */}
                                                <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
                                                    {extractedEndpoints
                                                        .filter(ep => endpointFilter === 'all' ? true : endpointFilter === 'ai' ? ep.source === 'ai' : ep.source !== 'ai')
                                                        .map((ep, i) => {
                                                        const key = `${ep.method}:${ep.path}`;
                                                        const isSelected = selectedEndpointKeys.has(key);
                                                        const isAllTab = endpointFilter === 'all';
                                                        const isAiEntry = ep.source === 'ai';
                                                        return (
                                                            <label key={i} className={`flex items-center justify-between text-xs p-2.5 rounded border transition-colors ${
                                                                isAllTab ? 'cursor-pointer' : 'cursor-default'
                                                            } ${
                                                                isAllTab
                                                                    ? (isSelected ? 'bg-cyan-500/10 border-cyan-500/30' : 'bg-dark-900 border-dark-700 opacity-60')
                                                                    : (isAiEntry ? 'bg-purple-500/5 border-purple-500/20' : 'bg-dark-900 border-dark-700')
                                                            }`}>
                                                                <div className="flex items-center gap-3 truncate">
                                                                    {isAllTab && (
                                                                        <input
                                                                            type="checkbox"
                                                                            className="accent-cyan-500 w-3.5 h-3.5 flex-shrink-0"
                                                                            checked={isSelected}
                                                                            onChange={() => {
                                                                                const next = new Set(selectedEndpointKeys);
                                                                                isSelected ? next.delete(key) : next.add(key);
                                                                                setSelectedEndpointKeys(next);
                                                                            }}
                                                                        />
                                                                    )}
                                                                    <span className={`font-mono font-bold px-1.5 py-0.5 rounded flex-shrink-0 ${
                                                                        ep.method === 'GET' ? 'bg-blue-500/20 text-blue-400' :
                                                                        ep.method === 'POST' ? 'bg-green-500/20 text-green-400' :
                                                                        ep.method === 'PUT' ? 'bg-amber-500/20 text-amber-400' :
                                                                        ep.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                                                                        'bg-gray-500/20 text-gray-400'
                                                                    }`}>{ep.method}</span>
                                                                    <span className="text-gray-300 font-mono truncate" title={ep.handler}>{ep.path}</span>
                                                                </div>
                                                                <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                                                                    {ep.source === 'ai' && <span className="text-purple-400 text-[9px] bg-purple-400/10 px-1 rounded border border-purple-400/20">AI</span>}
                                                                    {ep.authRequired && <span className="text-amber-400 text-[10px] bg-amber-400/10 px-1 rounded uppercase border border-amber-400/20">Auth</span>}
                                                                    {ep.userInputs?.length > 0 && <span className="text-cyan-400 text-[10px] bg-cyan-400/10 px-1 rounded uppercase border border-cyan-400/20">Inputs</span>}
                                                                </div>
                                                            </label>
                                                        );
                                                    })}
                                                    {extractedEndpoints.length === 0 && <p className="text-gray-500 text-sm italic">No dynamic routes found in source.</p>}
                                                </div>
                                                {/* Footer — outside scroll */}
                                                <div className="mt-3 pt-3 border-t border-dark-700 space-y-3">
                                                    {endpointFilter === 'all' && selectedEndpointKeys.size > 0 && (
                                                        <p className="text-gray-500 text-xs">
                                                            ✅ Scan will focus on the <span className="text-cyan-400 font-semibold">{selectedEndpointKeys.size}</span> selected endpoint{selectedEndpointKeys.size !== 1 ? 's' : ''}.
                                                        </p>
                                                    )}
                                                    <button
                                                        type="button"
                                                        onClick={handleDeepScanAI}
                                                        disabled={isDeepScanning || isScanning}
                                                        className="w-full px-3 py-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 transition-colors disabled:opacity-50 text-xs flex items-center justify-center gap-2"
                                                    >
                                                        {isDeepScanning ? (
                                                            <span className="flex items-center gap-2"><Loader2 className="w-3.5 h-3.5 animate-spin" /> AI is analyzing dynamic routes...</span>
                                                        ) : (
                                                            <span className="flex items-center gap-2">🧠 Deep Scan with AI <span className="text-[9px] opacity-60">(uses tokens)</span></span>
                                                        )}
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </motion.div>
                            )}
                        </div>
                    </motion.div>
                )}

                {/* Scan Progress */}
                {scanStatus.status !== 'idle' && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6 mb-8"
                    >
                        <div className="flex items-center gap-4 mb-4">
                            {getStatusIcon()}
                            <div className="flex-1">
                                <h3 className="text-lg font-semibold text-white">
                                    {scanStatus.status === 'complete'
                                        ? 'Scan Complete'
                                        : scanStatus.status === 'error'
                                            ? 'Scan Failed'
                                            : 'Scanning in Progress'}
                                </h3>
                                <p className="text-gray-400 text-sm">{scanStatus.message}</p>
                            </div>
                        </div>

                        {/* Progress Bar */}
                        <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${scanStatus.progress}%` }}
                                transition={{ duration: 0.5 }}
                                className={`h-full rounded-full ${scanStatus.status === 'error'
                                    ? 'bg-red-500'
                                    : scanStatus.status === 'complete'
                                        ? 'bg-green-500'
                                        : 'bg-gradient-to-r from-cyan-500 to-blue-500'
                                    }`}
                            />
                        </div>
                    </motion.div>
                )}

                {/* Vulnerabilities */}
                {scanStatus.vulnerabilities.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6"
                    >
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                <Shield className="w-5 h-5 text-red-400" />
                                Vulnerabilities Found ({scanStatus.vulnerabilities.length})
                            </h3>
                            {scanStatus.id && (
                                <button
                                    onClick={() => setReportModalOpen(true)}
                                    className="text-cyan-400 text-sm hover:underline flex items-center gap-1 bg-cyan-500/10 px-3 py-1 rounded-lg border border-cyan-500/30"
                                >
                                    <Download className="w-4 h-4" /> Download Report
                                </button>
                            )}
                        </div>

                        <div className="space-y-3">
                            {scanStatus.vulnerabilities.map((vuln, index) => (
                                <div
                                    key={index}
                                    className="p-4 bg-dark-800/50 rounded-lg border border-dark-600/50"
                                >
                                    <div className="flex items-start justify-between">
                                        <div>
                                            <h4 className="font-medium text-white">{vuln.name}</h4>
                                            <p className="text-gray-400 text-sm mt-1">{vuln.description}</p>
                                        </div>
                                        <span className={getSeverityClass(vuln.severity)}>
                                            {vuln.severity}
                                        </span>
                                    </div>
                                    {vuln.cwe && (
                                        <p className="text-gray-500 text-xs mt-2">CWE-{vuln.cwe}</p>
                                    )}
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}

                {/* Info Section */}
                {scanStatus.status === 'idle' && (
                    <div className="grid md:grid-cols-2 gap-4">
                        <div className="card p-4">
                            <h4 className="font-medium text-white mb-2">What we scan for:</h4>
                            <ul className="text-gray-400 text-sm space-y-1">
                                <li>• SQL Injection (SQLi)</li>
                                <li>• Cross-Site Scripting (XSS)</li>
                                <li>• Insecure Direct Object References (IDOR)</li>
                                <li>• Authentication Issues</li>
                                <li>• Sensitive Data Exposure</li>
                            </ul>
                        </div>

                        <div className="card p-4">
                            <h4 className="font-medium text-white mb-2">How it works:</h4>
                            <ul className="text-gray-400 text-sm space-y-1">
                                <li>1. URL validation & whitelist check</li>
                                <li>2. Burp Suite automated crawl</li>
                                <li>3. AI-enhanced vulnerability testing</li>
                                <li>4. Recheck agent validation</li>
                                <li>5. PDF report generation</li>
                            </ul>
                        </div>
                    </div>
                )}
            </main>

            {/* Report Options Modal */}
            {scanStatus.id && (
                <ReportOptionsModal
                    isOpen={reportModalOpen}
                    onClose={() => setReportModalOpen(false)}
                    scanId={scanStatus.id}
                />
            )}
        </div>
    );
}
