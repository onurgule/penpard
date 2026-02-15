'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import {
    Globe,
    Smartphone,
    Shield,
    Activity,
    History,
    Settings,
    LogOut,
    AlertTriangle,
    CheckCircle,
    BarChart3,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

const SCAN_OPTIONS_KEY = 'penpard-scan-options';

function getLastScanOptions() {
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

export default function DashboardPage() {
    const router = useRouter();
    const { isAuthenticated, lock } = useAuthStore();

    const [recentScans, setRecentScans] = useState<any[]>([]);
    const [stats, setStats] = useState({
        totalScans: 0,
        totalVulns: 0,
        reportsGenerated: 0
    });
    const [totalTokens, setTotalTokens] = useState(0);
    const [pendingFromBurp, setPendingFromBurp] = useState<{ pendingId: string; url: string; createdAt: number }[]>([]);
    const [startingPendingId, setStartingPendingId] = useState<string | null>(null);
    const [burpStartModal, setBurpStartModal] = useState<{ pendingId: string; url: string } | null>(null);
    const [burpOptions, setBurpOptions] = useState({
        iterations: 50,
        parallelAgents: 1,
        rateLimit: 5,
        maxPlanRounds: 0,
    });

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
            return;
        }

        // Fetch stats & recent scans
        const loadDashboardData = async () => {
            const token = useAuthStore.getState().token;
            if (!token) return;

            try {
                // Stats
                const statsRes = await fetch(`${API_URL}/scans/stats`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (statsRes.ok) {
                    setStats(await statsRes.json());
                }

                // Recent Scans
                const scansRes = await fetch(`${API_URL}/scans`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (scansRes.ok) {
                    const data = await scansRes.json();
                    if (data.scans) {
                        setRecentScans(data.scans.slice(0, 5));
                    }
                }

                // Token Usage
                const tokenRes = await fetch(`${API_URL}/token-usage/summary`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (tokenRes.ok) {
                    const tokenData = await tokenRes.json();
                    setTotalTokens(tokenData.totals?.total_tokens || 0);
                }

                // Pending requests from Burp (Send to PenPard)
                const pendingRes = await fetch(`${API_URL}/penpard/pending`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (pendingRes.ok) {
                    const pendingData = await pendingRes.json();
                    setPendingFromBurp(pendingData.pending || []);
                }

            } catch {
                // Backend may not be ready yet
            }
        };
        loadDashboardData();

        // Poll for updates every 10s
        const interval = setInterval(loadDashboardData, 10000);
        return () => clearInterval(interval);

    }, [isAuthenticated, router]);

    const handleLock = () => {
        lock();
        router.push('/');
    };

    const openBurpStartModal = (p: { pendingId: string; url: string }) => {
        setBurpStartModal(p);
        setBurpOptions(getLastScanOptions());
    };

    const handleStartFromBurp = async () => {
        if (!burpStartModal) return;
        const token = useAuthStore.getState().token;
        if (!token) return;
        const { pendingId } = burpStartModal;
        setStartingPendingId(pendingId);
        try {
            const res = await fetch(`${API_URL}/scans/from-burp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    pendingId,
                    iterations: burpOptions.iterations,
                    parallelAgents: burpOptions.parallelAgents,
                    rateLimit: burpOptions.rateLimit,
                    maxPlanRounds: burpOptions.maxPlanRounds,
                }),
            });
            const data = await res.json();
            if (data.scanId) {
                try {
                    localStorage.setItem(SCAN_OPTIONS_KEY, JSON.stringify({
                        iterations: burpOptions.iterations,
                        parallelAgents: burpOptions.parallelAgents,
                        rateLimit: burpOptions.rateLimit,
                        maxPlanRounds: burpOptions.maxPlanRounds,
                    }));
                } catch { /* ignore */ }
                setBurpStartModal(null);
                window.location.href = `/scan/${data.scanId}`;
                return;
            }
            alert(data.message || 'Failed to start scan');
        } catch (e: any) {
            alert(e?.message || 'Failed to start scan');
        } finally {
            setStartingPendingId(null);
        }
    };

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="glass-darker border-b border-dark-600/50 sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3" data-tour="logo">
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                            <Shield className="w-6 h-6 text-white" />
                        </div>
                        <div>
                            <h1 className="text-lg font-bold text-white">PENPARD</h1>
                            <p className="text-xs text-gray-500 terminal-text">CONTROL CENTER</p>
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        {/* Menu */}
                        <div className="flex items-center gap-4">
                            <Link
                                href="/settings"
                                className="p-2 rounded-lg bg-dark-700 text-gray-400 hover:text-white hover:bg-dark-600 transition-colors"
                            >
                                <Settings className="w-5 h-5" />
                            </Link>

                            <button
                                onClick={handleLock}
                                className="p-2 rounded-lg bg-dark-700 text-gray-400 hover:text-red-400 hover:bg-dark-600 transition-colors"
                            >
                                <LogOut className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-7xl mx-auto px-4 py-8">
                {/* Welcome Section */}
                <div className="mb-8">
                    <h2 className="text-2xl font-bold text-white mb-2">
                        Welcome back
                    </h2>
                    <p className="text-gray-400">Select a scan type to begin vulnerability analysis</p>
                    <p className="text-gray-500 text-sm mt-2">
                        For authenticated testing: browse the target through Burp and log in first; PenPard will use cookies from proxy history.
                    </p>
                </div>

                {/* From Burp — pending requests (Send to PenPard) */}
                {pendingFromBurp.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6 mb-8 border border-cyan-500/30"
                    >
                        <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
                            <Activity className="w-5 h-5 text-cyan-400" />
                            Requests from Burp
                        </h3>
                        <p className="text-gray-400 text-sm mb-4">
                            Right-clicked &quot;Send to PenPard&quot; in Burp. Start a test for one of these requests (same headers and body).
                        </p>
                        <ul className="space-y-3">
                            {pendingFromBurp.map((p) => (
                                <li key={p.pendingId} className="flex items-center justify-between gap-4 py-2 border-b border-dark-600 last:border-0">
                                    <span className="text-gray-300 font-mono text-sm truncate flex-1" title={p.url}>{p.url}</span>
                                    <button
                                        type="button"
                                        onClick={() => openBurpStartModal(p)}
                                        disabled={startingPendingId !== null}
                                        className="px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 border border-cyan-500/50 disabled:opacity-50 text-sm font-medium whitespace-nowrap"
                                    >
                                        Start test
                                    </button>
                                </li>
                            ))}
                        </ul>
                    </motion.div>
                )}

                {/* Start from Burp — options modal */}
                {burpStartModal && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70" onClick={() => !startingPendingId && setBurpStartModal(null)}>
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            onClick={(e) => e.stopPropagation()}
                            className="card p-6 w-full max-w-md border border-cyan-500/30"
                        >
                            <h3 className="text-lg font-bold text-white mb-1">Scan options</h3>
                            <p className="text-gray-400 font-mono text-sm truncate mb-4" title={burpStartModal.url}>{burpStartModal.url}</p>
                            <div className="space-y-4 mb-6">
                                <div>
                                    <label className="block text-gray-400 text-sm mb-1">Iterations (max actions)</label>
                                    <input
                                        type="number"
                                        min={10}
                                        max={500}
                                        value={burpOptions.iterations}
                                        onChange={(e) => setBurpOptions(o => ({ ...o, iterations: Number(e.target.value) || 50 }))}
                                        className="input-field w-full"
                                    />
                                </div>
                                <div>
                                    <label className="block text-gray-400 text-sm mb-1">Agent count</label>
                                    <select
                                        value={burpOptions.parallelAgents}
                                        onChange={(e) => setBurpOptions(o => ({ ...o, parallelAgents: Number(e.target.value) }))}
                                        className="input-field w-full"
                                    >
                                        {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => (
                                            <option key={n} value={n}>{n} agent{n > 1 ? 's' : ''}</option>
                                        ))}
                                    </select>
                                </div>
                                <div>
                                    <label className="block text-gray-400 text-sm mb-1">Rate limit (req/sec)</label>
                                    <div className="flex gap-2">
                                        {[2, 5, 15].map((r) => (
                                            <button
                                                key={r}
                                                type="button"
                                                onClick={() => setBurpOptions(o => ({ ...o, rateLimit: r }))}
                                                className={`px-3 py-1.5 rounded text-sm ${burpOptions.rateLimit === r ? 'bg-cyan-500 text-white' : 'bg-dark-700 text-gray-400'}`}
                                            >
                                                {r}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-gray-400 text-sm mb-1">Planning rounds</label>
                                    <input
                                        type="number"
                                        min={0}
                                        max={99}
                                        value={burpOptions.maxPlanRounds}
                                        onChange={(e) => setBurpOptions(o => ({ ...o, maxPlanRounds: Number(e.target.value) || 0 }))}
                                        className="input-field w-full"
                                    />
                                    <p className="text-gray-500 text-xs mt-1">0 = default (model decides when to finish)</p>
                                </div>
                            </div>
                            <div className="flex gap-3">
                                <button
                                    type="button"
                                    onClick={() => setBurpStartModal(null)}
                                    disabled={!!startingPendingId}
                                    className="flex-1 px-4 py-2 rounded-lg bg-dark-700 text-gray-400 hover:bg-dark-600 disabled:opacity-50"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="button"
                                    onClick={handleStartFromBurp}
                                    disabled={!!startingPendingId}
                                    className="flex-1 px-4 py-2 rounded-lg bg-cyan-500 text-white hover:bg-cyan-400 disabled:opacity-50"
                                >
                                    {startingPendingId === burpStartModal.pendingId ? 'Starting…' : 'Start test'}
                                </button>
                            </div>
                        </motion.div>
                    </div>
                )}

                {/* Scan Options */}
                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                    {/* Web Scan Card */}
                    <Link href="/scan/web" data-tour="new-web-scan">
                        <motion.div
                            whileHover={{ scale: 1.02, y: -4 }}
                            whileTap={{ scale: 0.98 }}
                            className="card card-hover p-8 cursor-pointer group"
                        >
                            <div className="flex items-start gap-4">
                                <div className="p-4 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 group-hover:from-cyan-500/30 group-hover:to-blue-500/30 transition-colors">
                                    <Globe className="w-8 h-8 text-cyan-400" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-xl font-bold text-white mb-2 group-hover:text-cyan-400 transition-colors">
                                        Web Application Scan
                                    </h3>
                                    <p className="text-gray-400 text-sm mb-4">
                                        Analyze web applications for OWASP Top 10 vulnerabilities using Burp Suite
                                        and AI-powered testing.
                                    </p>
                                    <div className="flex items-center gap-4 text-sm">
                                        <span className="flex items-center gap-1 text-gray-500">
                                            <CheckCircle className="w-4 h-4 text-green-400" />
                                            SQLi, XSS, IDOR
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    </Link>

                    {/* Mobile Scan Card — Coming Soon */}
                    <div
                        data-tour="new-mobile-scan"
                        onClick={() => window.open('https://github.com/onurgule/penpard', '_blank')}
                        className="relative cursor-pointer"
                    >
                        {/* "COMING SOON" ribbon */}
                        <div className="absolute top-0 right-0 z-10 overflow-hidden w-28 h-28 pointer-events-none">
                            <div className="absolute top-[14px] right-[-34px] w-[170px] text-center rotate-45 bg-gradient-to-r from-purple-600 to-pink-500 text-white text-[11px] font-bold py-1 shadow-lg tracking-wider uppercase">
                                Coming Soon
                            </div>
                        </div>
                        <motion.div
                            whileHover={{ scale: 1.01 }}
                            className="card p-8 group opacity-60 hover:opacity-80 transition-opacity border border-purple-500/20 relative overflow-hidden rounded-xl"
                        >
                            <div className="flex items-start gap-4">
                                <div className="p-4 rounded-xl bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20">
                                    <Smartphone className="w-8 h-8 text-purple-400/60" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-xl font-bold text-gray-400 mb-2">
                                        Mobile App Scan
                                    </h3>
                                    <p className="text-gray-500 text-sm mb-4">
                                        Analyze Android APK files for mobile-specific vulnerabilities using MobSF
                                        and AI assessment.
                                    </p>
                                    <div className="flex items-center gap-4 text-sm">
                                        <span className="flex items-center gap-1 text-gray-600">
                                            <CheckCircle className="w-4 h-4 text-gray-600" />
                                            OWASP Mobile Top 10
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    </div>

                    {/* System Config Card */}
                    <Link href="/settings">
                        <motion.div
                            whileHover={{ scale: 1.02, y: -4 }}
                            whileTap={{ scale: 0.98 }}
                            className="card card-hover p-8 cursor-pointer group h-full"
                        >
                            <div className="flex items-start gap-4">
                                <div className="p-4 rounded-xl bg-gradient-to-br from-slate-700/50 to-slate-600/50 border border-slate-500/30 group-hover:from-cyan-500/20 group-hover:to-cyan-600/20 group-hover:border-cyan-500/30 transition-colors">
                                    <Settings className="w-8 h-8 text-gray-300 group-hover:text-cyan-400 transition-colors" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-xl font-bold text-white mb-2 group-hover:text-cyan-400 transition-colors">
                                        System Configuration
                                    </h3>
                                    <p className="text-gray-400 text-sm mb-4">
                                        Configure LLM providers (Gemini, GPT) and manage MCP servers for the Antigravity Engine.
                                    </p>
                                    <div className="flex items-center gap-4 text-sm mt-auto">
                                        <span className="flex items-center gap-1 text-gray-500 group-hover:text-cyan-400 transition-colors">
                                            Manage Engine &rarr;
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </motion.div>
                    </Link>
                </div>

                {/* Stats Section */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                    <div className="card p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-cyan-500/10">
                                <Activity className="w-5 h-5 text-cyan-400" />
                            </div>
                            <div>
                                <p className="text-2xl font-bold text-white">{stats.totalScans}</p>
                                <p className="text-xs text-gray-500">Total Scans</p>
                            </div>
                        </div>
                    </div>

                    <div className="card p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-red-500/10">
                                <AlertTriangle className="w-5 h-5 text-red-400" />
                            </div>
                            <div>
                                <p className="text-2xl font-bold text-white">{stats.totalVulns}</p>
                                <p className="text-xs text-gray-500">Vulnerabilities</p>
                            </div>
                        </div>
                    </div>

                    <div className="card p-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-green-500/10">
                                <CheckCircle className="w-5 h-5 text-green-400" />
                            </div>
                            <div>
                                <p className="text-2xl font-bold text-white">{stats.reportsGenerated}</p>
                                <p className="text-xs text-gray-500">Reports Generated</p>
                            </div>
                        </div>
                    </div>

                    <Link href="/settings/token-usage" className="card p-4 hover:border-blue-500/30 transition-colors group">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-blue-500/10">
                                <BarChart3 className="w-5 h-5 text-blue-400" />
                            </div>
                            <div>
                                <p className="text-2xl font-bold text-white group-hover:text-blue-400 transition-colors">
                                    {totalTokens >= 1_000_000
                                        ? (totalTokens / 1_000_000).toFixed(1) + 'M'
                                        : totalTokens >= 1_000
                                            ? (totalTokens / 1_000).toFixed(1) + 'K'
                                            : totalTokens}
                                </p>
                                <p className="text-xs text-gray-500">Tokens Used</p>
                            </div>
                        </div>
                    </Link>
                </div>

                {/* PenPard Attribution Divider */}
                <div className="flex items-center gap-3 mb-8">
                    <div className="flex-1 h-px bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
                    <p className="text-xs text-slate-500 flex items-center gap-1.5 flex-shrink-0">
                        <a
                            href="https://github.com/onurgule/penpard"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-bold text-cyan-500 hover:text-cyan-400 transition-colors"
                        >
                            PenPard
                        </a>
                        <span className="text-slate-600">—</span>
                        <span className="text-slate-500">Pentester Pard</span>
                        <span className="text-slate-600">—</span>
                        <span className="text-slate-600">Developed by</span>
                        <a
                            href="https://linkedin.com/in/onurgule"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-semibold text-slate-400 hover:text-cyan-400 transition-colors"
                        >
                            onurgule
                        </a>
                        <span className="text-slate-600">&</span>
                        <a
                            href="https://linkedin.com/in/emrecangerede"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-semibold text-slate-400 hover:text-cyan-400 transition-colors"
                        >
                            emrecangerede
                        </a>
                    </p>
                    <div className="flex-1 h-px bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
                </div>

                {/* Recent Scans */}
                <div className="card p-6" data-tour="recent-scans">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-bold text-white flex items-center gap-2">
                            <History className="w-5 h-5 text-gray-400" />
                            Recent Scans
                        </h3>
                        <Link href="/reports" className="text-cyan-400 text-sm hover:underline">
                            View all
                        </Link>
                    </div>

                    {recentScans.length > 0 ? (
                        <div className="space-y-3">
                            {recentScans.map((scan) => (
                                <a key={scan.id} href={`/scan/${scan.id}`}>
                                    <div className="flex items-center justify-between p-3 rounded-lg bg-dark-700/50 hover:bg-dark-700 border border-dark-600 transition-colors cursor-pointer group">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-2 h-2 rounded-full ${scan.status === 'completed' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : scan.status === 'failed' ? 'bg-red-500' : 'bg-cyan-500 animate-pulse'}`} />
                                            <div>
                                                <p className="font-medium text-white group-hover:text-cyan-400 transition-colors truncate max-w-[200px] md:max-w-md">
                                                    {scan.target}
                                                </p>
                                                <p className="text-xs text-gray-500 uppercase tracking-wider">
                                                    {scan.type} • {new Date(scan.created_at).toLocaleDateString()}
                                                </p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <span className={`text-xs px-2 py-1 rounded font-medium ${scan.status === 'completed' ? 'bg-green-500/10 text-green-400' :
                                                scan.status === 'failed' ? 'bg-red-500/10 text-red-400' :
                                                    'bg-cyan-500/10 text-cyan-400'
                                                }`}>
                                                {scan.status.replace('_', ' ')}
                                            </span>
                                        </div>
                                    </div>
                                </a>
                            ))}
                        </div>
                    ) : (
                        <div className="text-center py-8 text-gray-500">
                            <Activity className="w-12 h-12 mx-auto mb-3 opacity-30" />
                            <p>No scans yet. Start your first scan above.</p>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}
