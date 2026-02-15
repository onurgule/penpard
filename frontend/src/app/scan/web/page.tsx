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
    const [reportModalOpen, setReportModalOpen] = useState(false);
    const [externalTools, setExternalTools] = useState({
        nuclei: false,
        ffuf: false,
    });
    const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'agent', content: string }[]>([]);
    const [chatInput, setChatInput] = useState('');

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
            const payload = {
                url: fullUrl,
                rateLimit,
                parallelAgents,
                iterations,
                maxPlanRounds,
                useNuclei: externalTools.nuclei,
                useFfuf: externalTools.ffuf,
                idorUsers: userAccounts.filter(u => u.username && u.password),
                scanInstructions: scanInstructions.trim() || undefined,
                sessionCookies: sessionCookies.trim() || undefined,
            };
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
            const response = await axios.post(`${API_URL}/scans/web`, payload, {
                headers: { Authorization: `Bearer ${useAuthStore.getState().token}` }
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
                                <label className="flex items-center gap-2 cursor-pointer card p-3 border border-dark-600 hover:border-cyan-500/50 transition-colors">
                                    <input
                                        type="checkbox"
                                        checked={externalTools.nuclei}
                                        onChange={(e) => setExternalTools({ ...externalTools, nuclei: e.target.checked })}
                                        className="checkbox"
                                    />
                                    <span className="text-white">Nuclei Vulnerability Scanner</span>
                                </label>
                                <label className="flex items-center gap-2 cursor-pointer card p-3 border border-dark-600 hover:border-cyan-500/50 transition-colors">
                                    <input
                                        type="checkbox"
                                        checked={externalTools.ffuf}
                                        onChange={(e) => setExternalTools({ ...externalTools, ffuf: e.target.checked })}
                                        className="checkbox"
                                    />
                                    <span className="text-white">FFUF Fuzzing</span>
                                </label>
                            </div>
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
