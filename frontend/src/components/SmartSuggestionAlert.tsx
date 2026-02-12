'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
    Shield, X, Zap, AlertTriangle, 
    Syringe, Code, FolderSearch, Terminal, Globe,
    ArrowRight, Loader2
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';

interface Suggestion {
    id: string;
    type: 'sqli' | 'xss' | 'lfi' | 'cmdi' | 'ssrf' | 'general';
    title: string;
    message: string;
    endpoints: string[];
    targetHosts: string[];
    payloadExamples: string[];
    confidence: number;
    createdAt: string;
    status: string;
    dominantActivity: string;
}

const TYPE_CONFIG: Record<string, { icon: any; color: string; gradient: string }> = {
    sqli: { 
        icon: Syringe, 
        color: 'text-red-400', 
        gradient: 'from-red-500/20 to-orange-500/20' 
    },
    xss: { 
        icon: Code, 
        color: 'text-yellow-400', 
        gradient: 'from-yellow-500/20 to-amber-500/20' 
    },
    lfi: { 
        icon: FolderSearch, 
        color: 'text-purple-400', 
        gradient: 'from-purple-500/20 to-pink-500/20' 
    },
    cmdi: { 
        icon: Terminal, 
        color: 'text-green-400', 
        gradient: 'from-green-500/20 to-emerald-500/20' 
    },
    ssrf: { 
        icon: Globe, 
        color: 'text-blue-400', 
        gradient: 'from-blue-500/20 to-cyan-500/20' 
    },
    general: { 
        icon: Shield, 
        color: 'text-cyan-400', 
        gradient: 'from-cyan-500/20 to-blue-500/20' 
    }
};

export default function SmartSuggestionAlert() {
    const { token, isAuthenticated } = useAuthStore();
    const router = useRouter();
    const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
    const [currentSuggestion, setCurrentSuggestion] = useState<Suggestion | null>(null);
    const [isAccepting, setIsAccepting] = useState(false);
    const [monitorRunning, setMonitorRunning] = useState(false);

    // Poll for suggestions - only when monitor is confirmed running
    useEffect(() => {
        if (!isAuthenticated || !token) return;

        let backendReady = false;

        const checkStatus = async () => {
            try {
                const res = await fetch(`${API_URL}/activity-monitor/status`, {
                    headers: { 'Authorization': `Bearer ${token}` },
                    signal: AbortSignal.timeout(3000),
                });
                if (res.ok) {
                    const data = await res.json();
                    setMonitorRunning(data.running);
                    backendReady = true;
                }
            } catch {
                backendReady = false;
            }
        };

        const poll = async () => {
            if (!backendReady) return; // Don't poll if backend isn't reachable
            try {
                const res = await fetch(`${API_URL}/activity-monitor/suggestions`, {
                    headers: { 'Authorization': `Bearer ${token}` },
                    signal: AbortSignal.timeout(3000),
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.suggestions && data.suggestions.length > 0) {
                        setSuggestions(data.suggestions);
                        if (!currentSuggestion) {
                            setCurrentSuggestion(data.suggestions[0]);
                        }
                    }
                }
            } catch {
                // Silently fail
            }
        };

        // Delay initial check to let backend start
        const initialTimeout = setTimeout(checkStatus, 5000);
        const statusInterval = setInterval(checkStatus, 30000);
        const pollInterval = setInterval(poll, 8000);

        return () => {
            clearTimeout(initialTimeout);
            clearInterval(statusInterval);
            clearInterval(pollInterval);
        };
    }, [isAuthenticated, token, currentSuggestion]);

    const handleAccept = useCallback(async () => {
        if (!currentSuggestion || isAccepting) return;
        
        setIsAccepting(true);
        try {
            const res = await fetch(
                `${API_URL}/activity-monitor/suggestions/${currentSuggestion.id}/accept`,
                {
                    method: 'POST',
                    headers: { 
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            if (res.ok) {
                const data = await res.json();
                toast.success(`PenPard ${currentSuggestion.type.toUpperCase()} scan started!`, {
                    duration: 5000,
                    icon: '🤖'
                });
                
                // Navigate to scan page if we got a scanId
                if (data.scanId) {
                    // Use full navigation for dynamic routes (static export compatibility)
                    window.location.href = `/scan/${data.scanId}`;
                }
                
                setCurrentSuggestion(null);
            } else {
                toast.error('Failed to start scan');
            }
        } catch (error) {
            toast.error('Connection error');
        } finally {
            setIsAccepting(false);
        }
    }, [currentSuggestion, isAccepting, token, router]);

    const handleDismiss = useCallback(async () => {
        if (!currentSuggestion) return;

        try {
            await fetch(
                `${API_URL}/activity-monitor/suggestions/${currentSuggestion.id}/dismiss`,
                {
                    method: 'POST',
                    headers: { 
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
        } catch (error) {
            // Silently fail
        }
        
        setCurrentSuggestion(null);
        
        // Show next suggestion if any
        const remaining = suggestions.filter(s => s.id !== currentSuggestion.id && s.status === 'pending');
        if (remaining.length > 0) {
            setTimeout(() => setCurrentSuggestion(remaining[0]), 1000);
        }
    }, [currentSuggestion, suggestions, token]);

    // Don't render if no suggestion or not authenticated
    if (!isAuthenticated || !currentSuggestion) return null;

    const config = TYPE_CONFIG[currentSuggestion.type] || TYPE_CONFIG.general;
    const Icon = config.icon;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0, y: 50, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 50, scale: 0.95 }}
                transition={{ type: 'spring', damping: 20, stiffness: 300 }}
                className="fixed bottom-28 right-4 z-[100] w-[420px] max-w-[calc(100vw-2rem)]"
            >
                <div className={`relative overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-br ${config.gradient} backdrop-blur-xl shadow-2xl shadow-black/50`}>
                    {/* Glow effect */}
                    <div className="absolute -top-20 -right-20 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl" />
                    <div className="absolute -bottom-20 -left-20 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl" />

                    {/* Content */}
                    <div className="relative p-5">
                        {/* Header */}
                        <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                                <div className={`p-2.5 rounded-xl bg-black/30 border border-white/10 ${config.color}`}>
                                    <Icon className="w-5 h-5" />
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <h3 className="text-sm font-bold text-white">
                                            {currentSuggestion.title}
                                        </h3>
                                        <span className="px-1.5 py-0.5 text-[10px] font-mono bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/30">
                                            AI
                                        </span>
                                    </div>
                                    <p className="text-[10px] text-gray-400 font-mono mt-0.5">
                                        {currentSuggestion.confidence}% confidence | {currentSuggestion.endpoints.length} endpoint
                                    </p>
                                </div>
                            </div>
                            <button 
                                onClick={handleDismiss}
                                className="p-1 hover:bg-white/10 rounded-lg transition-colors"
                            >
                                <X className="w-4 h-4 text-gray-500" />
                            </button>
                        </div>

                        {/* Message */}
                        <p className="text-xs text-gray-300 leading-relaxed mb-3">
                            {currentSuggestion.message}
                        </p>

                        {/* Detected endpoints preview */}
                        {currentSuggestion.endpoints.length > 0 && (
                            <div className="mb-4 max-h-20 overflow-y-auto">
                                <div className="space-y-1">
                                    {currentSuggestion.endpoints.slice(0, 3).map((ep, i) => (
                                        <div 
                                            key={i} 
                                            className="text-[10px] font-mono text-gray-400 bg-black/20 px-2 py-1 rounded truncate"
                                        >
                                            {ep}
                                        </div>
                                    ))}
                                    {currentSuggestion.endpoints.length > 3 && (
                                        <div className="text-[10px] text-gray-500 pl-2">
                                            +{currentSuggestion.endpoints.length - 3} more endpoints...
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Action buttons */}
                        <div className="flex gap-2">
                            <button
                                onClick={handleAccept}
                                disabled={isAccepting}
                                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-white text-sm font-semibold rounded-xl transition-all disabled:opacity-50 shadow-lg shadow-cyan-500/20"
                            >
                                {isAccepting ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Starting...
                                    </>
                                ) : (
                                    <>
                                        <Zap className="w-4 h-4" />
                                        Assist
                                        <ArrowRight className="w-3.5 h-3.5" />
                                    </>
                                )}
                            </button>
                            <button
                                onClick={handleDismiss}
                                className="px-4 py-2.5 bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white text-sm font-medium rounded-xl transition-all border border-white/10"
                            >
                                Dismiss
                            </button>
                        </div>
                    </div>

                    {/* Animated border glow */}
                    <div className="absolute inset-0 rounded-2xl border border-cyan-500/20 pointer-events-none" />
                </div>
            </motion.div>
        </AnimatePresence>
    );
}
