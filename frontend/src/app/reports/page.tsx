
'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
    ArrowLeft,
    FileText,
    Download,
    ExternalLink,
    Shield,
    AlertTriangle,
    CheckCircle,
    Clock,
    Globe,
    Smartphone,
    Filter,
    Trash2,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import axios from 'axios';
import toast from 'react-hot-toast';
import { API_URL } from '@/lib/api-config';
import ReportOptionsModal from '@/components/modals/ReportOptionsModal';

interface Scan {
    id: string;
    type: 'web' | 'mobile';
    target: string;
    status: 'queued' | 'running' | 'completed' | 'failed';
    created_at: string;
    completed_at: string | null;
    vulnerabilities?: any[];
}

export default function ReportsPage() {
    const { token, isAuthenticated } = useAuthStore();
    const [scans, setScans] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<'all' | 'completed' | 'running'>('all');
    const [reportModalOpen, setReportModalOpen] = useState(false);
    const [selectedScanId, setSelectedScanId] = useState<string>('');
    const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
    const [deleting, setDeleting] = useState(false);

    useEffect(() => {
        if (isAuthenticated && token) {
            fetchScans();
        }
    }, [isAuthenticated, token]);

    const fetchScans = async () => {
        try {
            const res = await axios.get(`${API_URL}/scans`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setScans(res.data.scans || []);
        } catch (e) {
            console.error(e);
            toast.error('Failed to load scans');
        } finally {
            setLoading(false);
        }
    };

    const openReportOptions = (scanId: string) => {
        setSelectedScanId(scanId);
        setReportModalOpen(true);
    };

    const filteredScans = scans.filter(s => {
        if (filter === 'all') return true;
        if (filter === 'completed') return s.status === 'completed';
        if (filter === 'running') return s.status === 'running' || s.status === 'queued';
        return true;
    });

    const toggleSelect = (id: string) => {
        setSelectedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const selectAllFiltered = () => {
        const ids = filteredScans.map(s => s.id);
        if (selectedIds.size === ids.length) setSelectedIds(new Set());
        else setSelectedIds(new Set(ids));
    };

    const handleDeleteSelected = async () => {
        if (selectedIds.size === 0) return;
        if (!confirm(`Permanently delete ${selectedIds.size} scan(s)? This cannot be undone.`)) return;
        setDeleting(true);
        try {
            const res = await axios.post(`${API_URL}/scans/delete`, { ids: [...selectedIds] }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setSelectedIds(new Set());
            await fetchScans();
            toast.success(res.data?.message || 'Scans deleted');
        } catch (e: any) {
            toast.error(e.response?.data?.message || 'Failed to delete scans');
        } finally {
            setDeleting(false);
        }
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'completed': return <CheckCircle className="w-4 h-4 text-green-400" />;
            case 'running': return <Clock className="w-4 h-4 text-yellow-400 animate-spin" />;
            case 'failed': return <AlertTriangle className="w-4 h-4 text-red-400" />;
            default: return <Clock className="w-4 h-4 text-slate-400" />;
        }
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'completed': return 'text-green-400 bg-green-500/10 border-green-500/30';
            case 'running': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
            case 'failed': return 'text-red-400 bg-red-500/10 border-red-500/30';
            default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link href="/dashboard" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                        <span>Dashboard</span>
                    </Link>
                    <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
                        <FileText className="w-5 h-5 text-cyan-400" />
                        Scan Reports
                    </h1>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                {/* Filter Bar */}
                <div className="flex items-center gap-4 mb-6 flex-wrap">
                    <Filter className="w-4 h-4 text-slate-400" />
                    <div className="flex gap-2">
                        {['all', 'completed', 'running'].map(f => (
                            <button
                                key={f}
                                onClick={() => setFilter(f as any)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider transition-all ${filter === f
                                    ? 'bg-cyan-500 text-white'
                                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                                    }`}
                            >
                                {f}
                            </button>
                        ))}
                    </div>
                    <span className="text-slate-500 text-sm">{filteredScans.length} scans</span>
                    {filteredScans.length > 0 && (
                        <>
                            <label className="flex items-center gap-2 text-slate-400 text-sm cursor-pointer ml-auto">
                                <input
                                    type="checkbox"
                                    checked={selectedIds.size === filteredScans.length && filteredScans.length > 0}
                                    onChange={selectAllFiltered}
                                    className="rounded border-slate-600 bg-slate-800 text-cyan-500"
                                />
                                Select all
                            </label>
                            <button
                                type="button"
                                onClick={handleDeleteSelected}
                                disabled={selectedIds.size === 0 || deleting}
                                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <Trash2 className="w-4 h-4" />
                                {deleting ? 'Deleting…' : `Delete selected (${selectedIds.size})`}
                            </button>
                        </>
                    )}
                </div>

                {/* Scan List */}
                {loading ? (
                    <div className="text-center py-12 text-slate-500">Loading...</div>
                ) : filteredScans.length === 0 ? (
                    <div className="text-center py-12">
                        <Shield className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                        <p className="text-slate-500">No scans found</p>
                        <Link href="/dashboard" className="text-cyan-400 text-sm mt-2 inline-block hover:underline">
                            Start a new scan →
                        </Link>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {filteredScans.map((scan, i) => (
                            <motion.div
                                key={scan.id}
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: i * 0.05 }}
                                className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
                            >
                                <div className="flex items-start justify-between">
                                    <div className="flex items-start gap-4">
                                        <label className="flex items-center pt-3 cursor-pointer shrink-0">
                                            <input
                                                type="checkbox"
                                                checked={selectedIds.has(scan.id)}
                                                onChange={() => toggleSelect(scan.id)}
                                                className="rounded border-slate-600 bg-slate-800 text-cyan-500 w-4 h-4"
                                            />
                                        </label>
                                        <div className={`p-3 rounded-lg ${scan.type === 'web' ? 'bg-blue-500/10 text-blue-400' : 'bg-purple-500/10 text-purple-400'}`}>
                                            {scan.type === 'web' ? <Globe className="w-5 h-5" /> : <Smartphone className="w-5 h-5" />}
                                        </div>
                                        <div>
                                            <h3 className="font-bold text-lg">{scan.target}</h3>
                                            <div className="flex items-center gap-3 mt-1 text-sm text-slate-400">
                                                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-medium ${getStatusColor(scan.status)}`}>
                                                    {getStatusIcon(scan.status)}
                                                    {scan.status}
                                                </span>
                                                <span>{new Date(scan.created_at).toLocaleString()}</span>
                                            </div>
                                            <p className="text-xs text-slate-500 mt-1 font-mono">ID: {scan.id}</p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-2">
                                        <a
                                            href={`/scan/${scan.id}`}
                                            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                                            title="View Details"
                                        >
                                            <ExternalLink className="w-4 h-4" />
                                        </a>
                                        {scan.status === 'completed' && (
                                            <button
                                                onClick={() => openReportOptions(scan.id)}
                                                className="p-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 transition-colors"
                                                title="Export Report"
                                            >
                                                <Download className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                </div>
                            </motion.div>
                        ))}
                    </div>
                )}
            </main>

            {/* Report Options Modal */}
            <ReportOptionsModal
                isOpen={reportModalOpen}
                onClose={() => setReportModalOpen(false)}
                scanId={selectedScanId}
            />
        </div>
    );
}
