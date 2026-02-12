'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import {
    ArrowLeft,
    BarChart3,
    Cpu,
    ArrowDownUp,
    Calendar,
    ChevronLeft,
    ChevronRight,
    Zap,
    TrendingUp,
    Hash,
    Download,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';
import { API_URL } from '@/lib/api-config';

interface ModelSummary {
    provider: string;
    model: string;
    call_count: number;
    total_input: number;
    total_output: number;
    total_tokens: number;
    avg_tokens_per_call: number;
    first_used: string;
    last_used: string;
}

interface DailyUsage {
    date: string;
    input_tokens: number;
    output_tokens: number;
    total_tokens: number;
    call_count: number;
}

interface UsageRecord {
    id: number;
    provider: string;
    model: string;
    input_tokens: number;
    output_tokens: number;
    total_tokens: number;
    scan_id: string | null;
    context: string | null;
    created_at: string;
}

interface Summary {
    byModel: ModelSummary[];
    totals: {
        total_calls: number;
        total_input: number;
        total_output: number;
        total_tokens: number;
    };
    daily: DailyUsage[];
    month: string;
}

const PROVIDER_COLORS: Record<string, string> = {
    openai: 'from-green-500/20 to-emerald-500/20 border-green-500/30',
    anthropic: 'from-orange-500/20 to-amber-500/20 border-orange-500/30',
    gemini: 'from-blue-500/20 to-indigo-500/20 border-blue-500/30',
    deepseek: 'from-purple-500/20 to-violet-500/20 border-purple-500/30',
    ollama: 'from-slate-500/20 to-gray-500/20 border-slate-500/30',
    qwen: 'from-red-500/20 to-rose-500/20 border-red-500/30',
};

const PROVIDER_TEXT_COLORS: Record<string, string> = {
    openai: 'text-green-400',
    anthropic: 'text-orange-400',
    gemini: 'text-blue-400',
    deepseek: 'text-purple-400',
    ollama: 'text-slate-400',
    qwen: 'text-red-400',
};

function formatNumber(n: number): string {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
    return n.toLocaleString();
}

function getMonthLabel(monthStr: string): string {
    if (!monthStr || monthStr === 'all') return 'All Time';
    const [year, month] = monthStr.split('-');
    const date = new Date(parseInt(year), parseInt(month) - 1);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
}

export default function TokenUsagePage() {
    const router = useRouter();
    const { token, isAuthenticated } = useAuthStore();

    const [summary, setSummary] = useState<Summary | null>(null);
    const [records, setRecords] = useState<UsageRecord[]>([]);
    const [months, setMonths] = useState<string[]>([]);
    const [selectedMonth, setSelectedMonth] = useState<string>('');
    const [isLoading, setIsLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<'overview' | 'details'>('overview');
    const [recordsTotal, setRecordsTotal] = useState(0);
    const [recordsOffset, setRecordsOffset] = useState(0);
    const recordsLimit = 50;

    // Auth guard
    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    const fetchMonths = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/token-usage/months`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (res.ok) {
                const data = await res.json();
                setMonths(data.months || []);
                // Default to current month if available
                if (data.months?.length > 0 && !selectedMonth) {
                    setSelectedMonth(data.months[0]);
                }
            }
        } catch (err) {
            console.error('Failed to fetch months', err);
        }
    }, [token, selectedMonth]);

    const fetchSummary = useCallback(async () => {
        try {
            const monthParam = selectedMonth ? `?month=${selectedMonth}` : '';
            const res = await fetch(`${API_URL}/token-usage/summary${monthParam}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (res.ok) {
                setSummary(await res.json());
            }
        } catch (err) {
            console.error('Failed to fetch summary', err);
        }
    }, [token, selectedMonth]);

    const fetchRecords = useCallback(async () => {
        try {
            const params = new URLSearchParams();
            if (selectedMonth) params.set('month', selectedMonth);
            params.set('limit', String(recordsLimit));
            params.set('offset', String(recordsOffset));

            const res = await fetch(`${API_URL}/token-usage?${params}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (res.ok) {
                const data = await res.json();
                setRecords(data.records || []);
                setRecordsTotal(data.total || 0);
            }
        } catch (err) {
            console.error('Failed to fetch records', err);
        }
    }, [token, selectedMonth, recordsOffset]);

    useEffect(() => {
        if (!token) return;
        fetchMonths();
    }, [token, fetchMonths]);

    useEffect(() => {
        if (!token) return;
        setIsLoading(true);
        Promise.all([fetchSummary(), fetchRecords()]).finally(() => setIsLoading(false));
    }, [token, selectedMonth, fetchSummary, fetchRecords]);

    // Re-fetch records when offset changes
    useEffect(() => {
        if (!token || activeTab !== 'details') return;
        fetchRecords();
    }, [recordsOffset, token, activeTab, fetchRecords]);

    const handlePrevMonth = () => {
        const idx = months.indexOf(selectedMonth);
        if (idx < months.length - 1) {
            setSelectedMonth(months[idx + 1]);
            setRecordsOffset(0);
        }
    };

    const handleNextMonth = () => {
        const idx = months.indexOf(selectedMonth);
        if (idx > 0) {
            setSelectedMonth(months[idx - 1]);
            setRecordsOffset(0);
        }
    };

    const handleAllTime = () => {
        setSelectedMonth('');
        setRecordsOffset(0);
    };

    if (!isAuthenticated) return null;

    // Calculate bar chart max for daily usage
    const maxDaily = summary?.daily?.reduce((max, d) => Math.max(max, d.total_tokens), 0) || 1;

    return (
        <div className="min-h-screen bg-slate-950">
            {/* Header */}
            <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <Link
                            href="/settings"
                            className="p-2 rounded-lg bg-slate-800 text-gray-400 hover:text-white hover:bg-slate-700 transition-colors"
                        >
                            <ArrowLeft className="w-5 h-5" />
                        </Link>
                        <div className="flex items-center gap-2">
                            <BarChart3 className="w-6 h-6 text-cyan-400" />
                            <h1 className="text-lg font-bold text-white">Token Usage</h1>
                        </div>
                    </div>

                    {/* Month Navigation */}
                    <div className="flex items-center gap-2">
                        <button
                            onClick={handleAllTime}
                            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                                !selectedMonth
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                    : 'bg-slate-800 text-gray-400 hover:text-white'
                            }`}
                        >
                            All
                        </button>
                        <div className="flex items-center gap-1 bg-slate-800 rounded-lg px-1">
                            <button
                                onClick={handlePrevMonth}
                                disabled={months.indexOf(selectedMonth) >= months.length - 1}
                                className="p-1.5 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            >
                                <ChevronLeft className="w-4 h-4" />
                            </button>
                            <span className="px-3 py-1.5 text-sm font-medium text-white min-w-[140px] text-center">
                                <Calendar className="w-3.5 h-3.5 inline mr-1.5 opacity-50" />
                                {getMonthLabel(selectedMonth)}
                            </span>
                            <button
                                onClick={handleNextMonth}
                                disabled={months.indexOf(selectedMonth) <= 0}
                                className="p-1.5 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            >
                                <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                {isLoading ? (
                    <div className="flex items-center justify-center py-20">
                        <div className="spinner" />
                    </div>
                ) : (
                    <>
                        {/* Grand Totals */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0 }}
                                className="rounded-xl bg-slate-900 border border-slate-800 p-4"
                            >
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-cyan-500/10">
                                        <Hash className="w-5 h-5 text-cyan-400" />
                                    </div>
                                    <div>
                                        <p className="text-2xl font-bold text-white">
                                            {formatNumber(summary?.totals?.total_calls || 0)}
                                        </p>
                                        <p className="text-xs text-gray-500">Total Calls</p>
                                    </div>
                                </div>
                            </motion.div>

                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.05 }}
                                className="rounded-xl bg-slate-900 border border-slate-800 p-4"
                            >
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-blue-500/10">
                                        <ArrowDownUp className="w-5 h-5 text-blue-400" />
                                    </div>
                                    <div>
                                        <p className="text-2xl font-bold text-white">
                                            {formatNumber(summary?.totals?.total_tokens || 0)}
                                        </p>
                                        <p className="text-xs text-gray-500">Total Tokens</p>
                                    </div>
                                </div>
                            </motion.div>

                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.1 }}
                                className="rounded-xl bg-slate-900 border border-slate-800 p-4"
                            >
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-green-500/10">
                                        <Download className="w-5 h-5 text-green-400" />
                                    </div>
                                    <div>
                                        <p className="text-2xl font-bold text-white">
                                            {formatNumber(summary?.totals?.total_input || 0)}
                                        </p>
                                        <p className="text-xs text-gray-500">Input Tokens</p>
                                    </div>
                                </div>
                            </motion.div>

                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: 0.15 }}
                                className="rounded-xl bg-slate-900 border border-slate-800 p-4"
                            >
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-purple-500/10">
                                        <TrendingUp className="w-5 h-5 text-purple-400" />
                                    </div>
                                    <div>
                                        <p className="text-2xl font-bold text-white">
                                            {formatNumber(summary?.totals?.total_output || 0)}
                                        </p>
                                        <p className="text-xs text-gray-500">Output Tokens</p>
                                    </div>
                                </div>
                            </motion.div>
                        </div>

                        {/* Tabs */}
                        <div className="flex gap-1 mb-6 bg-slate-900 rounded-lg p-1 w-fit">
                            <button
                                onClick={() => setActiveTab('overview')}
                                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                                    activeTab === 'overview'
                                        ? 'bg-cyan-500/20 text-cyan-400'
                                        : 'text-gray-400 hover:text-white'
                                }`}
                            >
                                Overview
                            </button>
                            <button
                                onClick={() => setActiveTab('details')}
                                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                                    activeTab === 'details'
                                        ? 'bg-cyan-500/20 text-cyan-400'
                                        : 'text-gray-400 hover:text-white'
                                }`}
                            >
                                Detailed Log
                            </button>
                        </div>

                        {activeTab === 'overview' ? (
                            <>
                                {/* Per-Model Breakdown */}
                                <div className="mb-8">
                                    <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                                        <Cpu className="w-5 h-5 text-gray-400" />
                                        Usage by Model
                                    </h2>

                                    {summary?.byModel && summary.byModel.length > 0 ? (
                                        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                                            {summary.byModel.map((m, i) => (
                                                <motion.div
                                                    key={`${m.provider}-${m.model}`}
                                                    initial={{ opacity: 0, y: 10 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    transition={{ delay: i * 0.05 }}
                                                    className={`rounded-xl bg-gradient-to-br ${
                                                        PROVIDER_COLORS[m.provider] || PROVIDER_COLORS.openai
                                                    } border p-5`}
                                                >
                                                    <div className="flex items-center justify-between mb-3">
                                                        <div>
                                                            <p className={`text-sm font-medium uppercase tracking-wider ${
                                                                PROVIDER_TEXT_COLORS[m.provider] || 'text-cyan-400'
                                                            }`}>
                                                                {m.provider}
                                                            </p>
                                                            <p className="text-white font-bold text-lg">{m.model}</p>
                                                        </div>
                                                        <div className="text-right">
                                                            <p className="text-2xl font-bold text-white">
                                                                {formatNumber(m.total_tokens)}
                                                            </p>
                                                            <p className="text-xs text-gray-400">tokens</p>
                                                        </div>
                                                    </div>

                                                    <div className="grid grid-cols-3 gap-3 text-center">
                                                        <div className="bg-black/20 rounded-lg p-2">
                                                            <p className="text-white font-semibold">{m.call_count}</p>
                                                            <p className="text-xs text-gray-400">Calls</p>
                                                        </div>
                                                        <div className="bg-black/20 rounded-lg p-2">
                                                            <p className="text-white font-semibold">{formatNumber(m.total_input)}</p>
                                                            <p className="text-xs text-gray-400">In</p>
                                                        </div>
                                                        <div className="bg-black/20 rounded-lg p-2">
                                                            <p className="text-white font-semibold">{formatNumber(m.total_output)}</p>
                                                            <p className="text-xs text-gray-400">Out</p>
                                                        </div>
                                                    </div>

                                                    <div className="mt-3 flex justify-between text-xs text-gray-400">
                                                        <span>Avg: {formatNumber(Math.round(m.avg_tokens_per_call))}/call</span>
                                                        <span>Last: {new Date(m.last_used).toLocaleDateString()}</span>
                                                    </div>
                                                </motion.div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="rounded-xl bg-slate-900 border border-slate-800 p-12 text-center">
                                            <BarChart3 className="w-12 h-12 mx-auto mb-3 text-gray-600" />
                                            <p className="text-gray-500">No token usage data yet.</p>
                                            <p className="text-gray-600 text-sm mt-1">Usage will appear here after LLM calls.</p>
                                        </div>
                                    )}
                                </div>

                                {/* Daily Usage Chart */}
                                {summary?.daily && summary.daily.length > 0 && (
                                    <div className="rounded-xl bg-slate-900 border border-slate-800 p-6">
                                        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                                            <Zap className="w-5 h-5 text-amber-400" />
                                            Daily Usage
                                        </h2>

                                        <div className="flex items-end gap-1 h-48">
                                            {summary.daily.map((d, i) => {
                                                const inputHeight = maxDaily > 0 ? (d.input_tokens / maxDaily) * 100 : 0;
                                                const outputHeight = maxDaily > 0 ? (d.output_tokens / maxDaily) * 100 : 0;
                                                const dayLabel = new Date(d.date).getDate();

                                                return (
                                                    <div
                                                        key={d.date}
                                                        className="flex-1 flex flex-col items-center gap-0.5 group relative min-w-0"
                                                    >
                                                        {/* Tooltip */}
                                                        <div className="absolute bottom-full mb-2 hidden group-hover:block z-10">
                                                            <div className="bg-slate-800 border border-slate-700 rounded-lg p-2 text-xs whitespace-nowrap shadow-xl">
                                                                <p className="text-white font-medium">{d.date}</p>
                                                                <p className="text-green-400">In: {formatNumber(d.input_tokens)}</p>
                                                                <p className="text-purple-400">Out: {formatNumber(d.output_tokens)}</p>
                                                                <p className="text-gray-400">{d.call_count} calls</p>
                                                            </div>
                                                        </div>

                                                        {/* Bars */}
                                                        <div className="w-full flex flex-col gap-0.5" style={{ height: '160px', justifyContent: 'flex-end' }}>
                                                            <div
                                                                className="w-full bg-purple-500/60 rounded-t-sm transition-all group-hover:bg-purple-400/80"
                                                                style={{ height: `${outputHeight}%`, minHeight: outputHeight > 0 ? '2px' : '0' }}
                                                            />
                                                            <div
                                                                className="w-full bg-green-500/60 rounded-b-sm transition-all group-hover:bg-green-400/80"
                                                                style={{ height: `${inputHeight}%`, minHeight: inputHeight > 0 ? '2px' : '0' }}
                                                            />
                                                        </div>

                                                        {/* Day label */}
                                                        <span className="text-[10px] text-gray-500 mt-1">{dayLabel}</span>
                                                    </div>
                                                );
                                            })}
                                        </div>

                                        {/* Legend */}
                                        <div className="flex items-center gap-6 mt-4 justify-center text-xs text-gray-400">
                                            <span className="flex items-center gap-1.5">
                                                <span className="w-3 h-3 rounded-sm bg-green-500/60" />
                                                Input Tokens
                                            </span>
                                            <span className="flex items-center gap-1.5">
                                                <span className="w-3 h-3 rounded-sm bg-purple-500/60" />
                                                Output Tokens
                                            </span>
                                        </div>
                                    </div>
                                )}
                            </>
                        ) : (
                            /* Detailed Records Tab */
                            <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
                                <div className="overflow-x-auto">
                                    <table className="w-full text-sm">
                                        <thead>
                                            <tr className="border-b border-slate-800 text-left">
                                                <th className="px-4 py-3 text-gray-400 font-medium">Time</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium">Provider</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium">Model</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium text-right">Input</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium text-right">Output</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium text-right">Total</th>
                                                <th className="px-4 py-3 text-gray-400 font-medium">Context</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {records.length > 0 ? (
                                                records.map((r) => (
                                                    <tr key={r.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                                                        <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                                                            {new Date(r.created_at).toLocaleString()}
                                                        </td>
                                                        <td className="px-4 py-3">
                                                            <span className={`text-xs px-2 py-0.5 rounded-full font-medium uppercase ${
                                                                PROVIDER_TEXT_COLORS[r.provider] || 'text-cyan-400'
                                                            } bg-slate-800`}>
                                                                {r.provider}
                                                            </span>
                                                        </td>
                                                        <td className="px-4 py-3 text-white font-mono text-xs">{r.model}</td>
                                                        <td className="px-4 py-3 text-green-400 text-right font-mono">{r.input_tokens.toLocaleString()}</td>
                                                        <td className="px-4 py-3 text-purple-400 text-right font-mono">{r.output_tokens.toLocaleString()}</td>
                                                        <td className="px-4 py-3 text-white font-bold text-right font-mono">{r.total_tokens.toLocaleString()}</td>
                                                        <td className="px-4 py-3 text-gray-500 text-xs truncate max-w-[200px]">{r.context || '—'}</td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                                                        No records found for this period.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>

                                {/* Pagination */}
                                {recordsTotal > recordsLimit && (
                                    <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
                                        <span className="text-sm text-gray-400">
                                            Showing {recordsOffset + 1}–{Math.min(recordsOffset + recordsLimit, recordsTotal)} of {recordsTotal}
                                        </span>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setRecordsOffset(Math.max(0, recordsOffset - recordsLimit))}
                                                disabled={recordsOffset === 0}
                                                className="px-3 py-1.5 rounded-lg bg-slate-800 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed text-sm transition-colors"
                                            >
                                                Previous
                                            </button>
                                            <button
                                                onClick={() => setRecordsOffset(recordsOffset + recordsLimit)}
                                                disabled={recordsOffset + recordsLimit >= recordsTotal}
                                                className="px-3 py-1.5 rounded-lg bg-slate-800 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed text-sm transition-colors"
                                            >
                                                Next
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </>
                )}
            </main>
        </div>
    );
}
