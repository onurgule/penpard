'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
    ArrowLeft,
    BookOpen,
    RefreshCw,
    Check,
    Star,
    Tag,
    User,
    ChevronDown,
    ChevronUp,
    Search,
    Zap,
    Shield,
    Globe,
    Database,
    Lock,
    Bug,
    Layers,
    Crosshair,
    ExternalLink,
    Sparkles,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import axios from 'axios';
import toast from 'react-hot-toast';
import { API_URL } from '@/lib/api-config';

interface PromptVariable {
    key: string;
    label: string;
    required: boolean;
}

interface LibraryPrompt {
    id: string;
    name: string;
    description: string;
    category: string;
    tags: string[];
    author: string;
    prompt_version: string;
    is_default: boolean;
    variables: PromptVariable[];
    template: string;
}

// Tag icon mapping
const TAG_ICONS: Record<string, any> = {
    'web': Globe,
    'owasp': Shield,
    'api': Layers,
    'sqli': Database,
    'xss': Zap,
    'idor': Lock,
    'authorization': Lock,
    'authentication': Lock,
    'bug-bounty': Bug,
    'focused': Crosshair,
    'comprehensive': Star,
    'quick': Zap,
};

// Category color mapping
const CATEGORY_COLORS: Record<string, string> = {
    'web': 'from-cyan-500 to-blue-500',
    'api': 'from-purple-500 to-pink-500',
    'sqli': 'from-red-500 to-orange-500',
    'xss': 'from-yellow-500 to-amber-500',
    'idor': 'from-green-500 to-emerald-500',
    'authentication': 'from-indigo-500 to-purple-500',
    'bug-bounty': 'from-pink-500 to-rose-500',
    'owasp': 'from-blue-500 to-indigo-500',
};

function getPromptColor(tags: string[]): string {
    for (const tag of tags) {
        if (CATEGORY_COLORS[tag]) return CATEGORY_COLORS[tag];
    }
    return 'from-slate-500 to-slate-600';
}

function getPromptIcon(tags: string[]) {
    for (const tag of tags) {
        if (TAG_ICONS[tag]) return TAG_ICONS[tag];
    }
    return Shield;
}

export default function PromptLibraryPage() {
    const router = useRouter();
    const { token, isAuthenticated } = useAuthStore();

    const [prompts, setPrompts] = useState<LibraryPrompt[]>([]);
    const [activePromptId, setActivePromptId] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedTag, setSelectedTag] = useState<string | null>(null);
    const [expandedPrompt, setExpandedPrompt] = useState<string | null>(null);
    const [activating, setActivating] = useState<string | null>(null);

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    useEffect(() => {
        if (isAuthenticated) {
            loadLibrary();
        }
    }, [isAuthenticated]);

    const loadLibrary = async () => {
        try {
            setLoading(true);
            const res = await axios.get(`${API_URL}/config/prompt-library`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setPrompts(res.data.prompts || []);
            setActivePromptId(res.data.activePromptId || null);
        } catch (e) {
            toast.error('Failed to load prompt library');
        } finally {
            setLoading(false);
        }
    };

    const handleRefresh = async () => {
        setRefreshing(true);
        try {
            const res = await axios.post(`${API_URL}/config/prompt-library/refresh`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.data.success) {
                toast.success(`Library updated! ${res.data.count} prompts available.`);
                await loadLibrary();
            } else {
                toast.error(res.data.error || 'Could not reach penpard.com');
            }
        } catch (e) {
            toast.error('Failed to refresh from penpard.com');
        } finally {
            setRefreshing(false);
        }
    };

    const handleActivate = async (promptId: string) => {
        setActivating(promptId);
        try {
            await axios.post(`${API_URL}/config/prompt-library/activate`,
                { promptId },
                { headers: { Authorization: `Bearer ${token}` } }
            );
            setActivePromptId(promptId);
            const prompt = prompts.find(p => p.id === promptId);
            toast.success(`"${prompt?.name}" is now your active scan prompt!`);
        } catch (e) {
            toast.error('Failed to activate prompt');
        } finally {
            setActivating(null);
        }
    };

    // Filter prompts
    const allTags = Array.from(new Set(prompts.flatMap(p => p.tags)));
    const filteredPrompts = prompts.filter(p => {
        const matchesSearch = !searchQuery ||
            p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
            p.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
        const matchesTag = !selectedTag || p.tags.includes(selectedTag);
        return matchesSearch && matchesTag;
    });

    if (!isAuthenticated) return null;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            {/* Header */}
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link href="/settings" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                        <span>Settings</span>
                    </Link>
                    <div className="flex items-center gap-3">
                        <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
                            <BookOpen className="w-5 h-5 text-cyan-400" />
                            Prompt Library
                        </h1>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                            {prompts.length} prompts
                        </span>
                    </div>
                    <button
                        onClick={handleRefresh}
                        disabled={refreshing}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm font-medium transition-all flex items-center gap-2 border border-slate-700 disabled:opacity-50"
                    >
                        <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                        {refreshing ? 'Syncing...' : 'Sync from penpard.com'}
                    </button>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                {/* Info Banner */}
                <div className="mb-8 p-4 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 border border-cyan-500/20 rounded-xl flex items-start gap-4">
                    <Sparkles className="w-6 h-6 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <div>
                        <h3 className="font-bold text-cyan-300 mb-1">Community Prompt Library</h3>
                        <p className="text-sm text-slate-400">
                            Browse and activate scan prompts from the PenPard community. Select a prompt and click
                            <span className="text-cyan-400 font-medium"> "Use This Prompt" </span>
                            to make it your default web scan template. New prompts are added regularly at{' '}
                            <a href="https://penpard.com/prompts" target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">
                                penpard.com/prompts <ExternalLink className="w-3 h-3" />
                            </a>
                        </p>
                    </div>
                </div>

                {/* Search & Filter */}
                <div className="mb-6 flex flex-col sm:flex-row gap-4">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={e => setSearchQuery(e.target.value)}
                            placeholder="Search prompts by name, description, or tag..."
                            className="w-full bg-slate-900/50 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-sm focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-600"
                        />
                    </div>
                    <div className="flex gap-2 flex-wrap">
                        <button
                            onClick={() => setSelectedTag(null)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${!selectedTag
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                                }`}
                        >
                            All
                        </button>
                        {allTags.slice(0, 10).map(tag => (
                            <button
                                key={tag}
                                onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${selectedTag === tag
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                                    }`}
                            >
                                {tag}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Loading state */}
                {loading && (
                    <div className="text-center py-20">
                        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-4" />
                        <p className="text-slate-500">Loading prompt library...</p>
                    </div>
                )}

                {/* Prompt Grid */}
                {!loading && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <AnimatePresence mode="popLayout">
                            {filteredPrompts.map((prompt, i) => {
                                const isActive = activePromptId === prompt.id;
                                const isExpanded = expandedPrompt === prompt.id;
                                const PromptIcon = getPromptIcon(prompt.tags);
                                const colorGrad = getPromptColor(prompt.tags);

                                return (
                                    <motion.div
                                        key={prompt.id}
                                        initial={{ opacity: 0, y: 20 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        exit={{ opacity: 0, y: -10 }}
                                        transition={{ delay: i * 0.05 }}
                                        className={`rounded-xl border overflow-hidden transition-all ${isActive
                                            ? 'border-cyan-500/50 bg-cyan-500/5 shadow-[0_0_30px_rgba(6,182,212,0.08)]'
                                            : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
                                            }`}
                                    >
                                        {/* Card Header */}
                                        <div className="p-5">
                                            <div className="flex items-start gap-4">
                                                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${colorGrad} flex items-center justify-center flex-shrink-0 shadow-lg`}>
                                                    <PromptIcon className="w-6 h-6 text-white" />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <h3 className="font-bold text-sm truncate">{prompt.name}</h3>
                                                        {prompt.is_default && (
                                                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold flex-shrink-0">
                                                                DEFAULT
                                                            </span>
                                                        )}
                                                        {isActive && (
                                                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-bold flex items-center gap-1 flex-shrink-0">
                                                                <Check className="w-3 h-3" /> ACTIVE
                                                            </span>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-slate-500 line-clamp-2">{prompt.description}</p>
                                                </div>
                                            </div>

                                            {/* Tags */}
                                            <div className="flex items-center gap-2 mt-3 flex-wrap">
                                                {prompt.tags.slice(0, 5).map(tag => (
                                                    <span key={tag} className="text-[10px] px-2 py-0.5 bg-slate-800 rounded text-slate-400 flex items-center gap-1">
                                                        <Tag className="w-2.5 h-2.5" />
                                                        {tag}
                                                    </span>
                                                ))}
                                                <span className="text-[10px] text-slate-600 flex items-center gap-1 ml-auto">
                                                    <User className="w-3 h-3" />
                                                    {prompt.author}
                                                </span>
                                                <span className="text-[10px] text-slate-600">
                                                    v{prompt.prompt_version}
                                                </span>
                                            </div>

                                            {/* Actions */}
                                            <div className="flex items-center gap-2 mt-4">
                                                <button
                                                    onClick={() => handleActivate(prompt.id)}
                                                    disabled={isActive || activating === prompt.id}
                                                    className={`flex-1 px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center justify-center gap-2 ${isActive
                                                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 cursor-default'
                                                        : activating === prompt.id
                                                            ? 'bg-slate-800 text-slate-400 border border-slate-700'
                                                            : 'bg-cyan-500 hover:bg-cyan-400 text-black border border-cyan-500 shadow-lg shadow-cyan-900/20 hover:scale-[1.02] active:scale-[0.98]'
                                                        }`}
                                                >
                                                    {isActive ? (
                                                        <><Check className="w-4 h-4" /> Currently Active</>
                                                    ) : activating === prompt.id ? (
                                                        <><RefreshCw className="w-4 h-4 animate-spin" /> Activating...</>
                                                    ) : (
                                                        <><Zap className="w-4 h-4" /> Use This Prompt</>
                                                    )}
                                                </button>
                                                <button
                                                    onClick={() => setExpandedPrompt(isExpanded ? null : prompt.id)}
                                                    className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm transition-colors"
                                                    title={isExpanded ? 'Hide template' : 'View template'}
                                                >
                                                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                                                </button>
                                            </div>
                                        </div>

                                        {/* Expanded Template View */}
                                        <AnimatePresence>
                                            {isExpanded && (
                                                <motion.div
                                                    initial={{ height: 0, opacity: 0 }}
                                                    animate={{ height: 'auto', opacity: 1 }}
                                                    exit={{ height: 0, opacity: 0 }}
                                                    transition={{ duration: 0.2 }}
                                                    className="overflow-hidden"
                                                >
                                                    <div className="border-t border-slate-800 p-4 bg-slate-950/50">
                                                        {/* Variables */}
                                                        <div className="mb-3">
                                                            <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Variables</span>
                                                            <div className="flex gap-2 mt-1.5 flex-wrap">
                                                                {prompt.variables.map(v => (
                                                                    <span key={v.key} className={`text-[10px] px-2 py-1 rounded border ${v.required
                                                                        ? 'bg-cyan-500/5 text-cyan-400 border-cyan-500/20'
                                                                        : 'bg-slate-800 text-slate-400 border-slate-700'
                                                                        }`}>
                                                                        {'{' + v.key + '}'}
                                                                        {v.required && <span className="ml-1 text-cyan-500">*</span>}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        </div>

                                                        {/* Template */}
                                                        <div className="relative">
                                                            <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Template</span>
                                                            <pre className="mt-1.5 p-3 bg-black/50 border border-slate-800 rounded-lg text-xs text-slate-400 font-mono overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap leading-relaxed scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                                                                {prompt.template || '(Uses built-in DEFAULT_WEB_PROMPT — see OrchestratorAgent.ts)'}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                </motion.div>
                                            )}
                                        </AnimatePresence>
                                    </motion.div>
                                );
                            })}
                        </AnimatePresence>
                    </div>
                )}

                {/* Empty state */}
                {!loading && filteredPrompts.length === 0 && (
                    <div className="text-center py-20">
                        <BookOpen className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                        <p className="text-slate-500 mb-2">No prompts match your search.</p>
                        <button onClick={() => { setSearchQuery(''); setSelectedTag(null); }} className="text-cyan-400 text-sm hover:text-cyan-300">
                            Clear filters
                        </button>
                    </div>
                )}

                {/* Footer */}
                <div className="mt-12 text-center border-t border-slate-800 pt-6">
                    <p className="text-xs text-slate-600">
                        Prompts are synced from{' '}
                        <a href="https://penpard.com/prompts" target="_blank" rel="noopener noreferrer" className="text-cyan-500 hover:text-cyan-400">
                            penpard.com/prompts
                        </a>
                        {' '} — New prompts are added regularly by the PenPard community.
                    </p>
                </div>
            </main>
        </div>
    );
}
