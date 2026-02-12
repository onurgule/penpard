'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import axios from 'axios';
import toast from 'react-hot-toast';
import {
    ArrowLeft,
    Globe,
    Plus,
    Trash2,
    Save,
    X,
    History,
    Settings,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

interface Whitelist {
    id: number;
    userId: number;
    domainPattern: string;
    createdAt: string;
}

type Tab = 'whitelists' | 'logs';

export default function AdminPage() {
    const router = useRouter();
    const { isAuthenticated, token } = useAuthStore();

    const [activeTab, setActiveTab] = useState<Tab>('whitelists');
    const [whitelists, setWhitelists] = useState<Whitelist[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    // Whitelist form state
    const [showWhitelistForm, setShowWhitelistForm] = useState(false);
    const [whitelistForm, setWhitelistForm] = useState({
        domainPattern: '',
    });

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
            return;
        }
        loadData();
    }, [isAuthenticated, router]);

    const loadData = async () => {
        setIsLoading(true);
        try {
            const whitelistsRes = await axios.get(`${API_URL}/admin/whitelists`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setWhitelists(whitelistsRes.data.whitelists || []);
        } catch (error) {
            console.error('Failed to load admin data:', error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleCreateWhitelist = async () => {
        if (!whitelistForm.domainPattern) {
            toast.error('Domain pattern required');
            return;
        }

        try {
            await axios.post(`${API_URL}/admin/whitelists`, whitelistForm, {
                headers: { Authorization: `Bearer ${token}` },
            });
            toast.success('Whitelist entry added');
            setShowWhitelistForm(false);
            setWhitelistForm({ domainPattern: '' });
            loadData();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to add whitelist');
        }
    };

    const handleDeleteWhitelist = async (whitelistId: number) => {
        if (!confirm('Delete this whitelist entry?')) return;

        try {
            await axios.delete(`${API_URL}/admin/whitelists/${whitelistId}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            toast.success('Whitelist entry deleted');
            loadData();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to delete whitelist');
        }
    };

    const tabs = [
        { id: 'whitelists' as Tab, label: 'Whitelists', icon: Globe },
        { id: 'logs' as Tab, label: 'Scan Logs', icon: History },
    ];

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="glass-darker border-b border-dark-600/50 sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link
                        href="/dashboard"
                        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                    >
                        <ArrowLeft className="w-5 h-5" />
                        <span>Back to Dashboard</span>
                    </Link>

                    <div className="flex items-center gap-3">
                        <Settings className="w-5 h-5 text-cyan-400" />
                        <span className="text-white font-medium">Admin Panel</span>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                {/* Tabs */}
                <div className="flex gap-2 mb-6 border-b border-dark-600/50 pb-4">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${activeTab === tab.id
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                    : 'text-gray-400 hover:text-white hover:bg-dark-700'
                                }`}
                        >
                            <tab.icon className="w-4 h-4" />
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* Whitelists Tab */}
                {activeTab === 'whitelists' && (
                    <div>
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-xl font-bold text-white">Domain Whitelists</h2>
                            <button
                                onClick={() => setShowWhitelistForm(true)}
                                className="btn-primary flex items-center gap-2 text-sm py-2"
                            >
                                <Plus className="w-4 h-4" />
                                Add Whitelist
                            </button>
                        </div>

                        {isLoading ? (
                            <div className="card p-8 text-center">
                                <div className="spinner mx-auto mb-4" />
                                <p className="text-gray-400">Loading...</p>
                            </div>
                        ) : (
                            <div className="table-container">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>Domain Pattern</th>
                                            <th>Created</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {whitelists.map((w) => (
                                            <tr key={w.id}>
                                                <td className="terminal-text text-cyan-400">{w.domainPattern}</td>
                                                <td className="text-gray-400">
                                                    {new Date(w.createdAt).toLocaleDateString()}
                                                </td>
                                                <td>
                                                    <button
                                                        onClick={() => handleDeleteWhitelist(w.id)}
                                                        className="p-2 rounded bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                )}

                {/* Logs Tab */}
                {activeTab === 'logs' && (
                    <div className="card p-6 text-center">
                        <History className="w-12 h-12 mx-auto text-gray-500 mb-4" />
                        <p className="text-gray-400">Scan logs will appear here</p>
                    </div>
                )}

                {/* Whitelist Form Modal */}
                <AnimatePresence>
                    {showWhitelistForm && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
                            onClick={() => setShowWhitelistForm(false)}
                        >
                            <motion.div
                                initial={{ scale: 0.9, opacity: 0 }}
                                animate={{ scale: 1, opacity: 1 }}
                                exit={{ scale: 0.9, opacity: 0 }}
                                className="card p-6 w-full max-w-md"
                                onClick={(e) => e.stopPropagation()}
                            >
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-lg font-bold text-white">Add Whitelist Entry</h3>
                                    <button
                                        onClick={() => setShowWhitelistForm(false)}
                                        className="text-gray-400 hover:text-white"
                                    >
                                        <X className="w-5 h-5" />
                                    </button>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-gray-400 text-sm mb-1">
                                            Domain Pattern
                                        </label>
                                        <input
                                            type="text"
                                            value={whitelistForm.domainPattern}
                                            onChange={(e) =>
                                                setWhitelistForm({
                                                    ...whitelistForm,
                                                    domainPattern: e.target.value,
                                                })
                                            }
                                            placeholder="*.example.com"
                                            className="input-field terminal-text"
                                        />
                                        <p className="text-gray-500 text-xs mt-1">
                                            Use * for wildcards (e.g., *.example.com)
                                        </p>
                                    </div>

                                    <button
                                        onClick={handleCreateWhitelist}
                                        className="w-full btn-primary flex items-center justify-center gap-2"
                                    >
                                        <Save className="w-4 h-4" />
                                        Add Whitelist
                                    </button>
                                </div>
                            </motion.div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
}
