'use client';

import { useRouter, usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import { Home, ChevronLeft, ChevronRight, Settings, Zap, Shield, Activity, Server, Wifi, WifiOff } from 'lucide-react';
import { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

interface SystemStatus {
    llm: {
        provider: string;
        model: string;
        configured: boolean;
    };
    mcp: {
        total: number;
        active: number;
        servers: Array<{ name: string; status: string }>;
    };
    burp: string;
    nuclei: string;
    mobsf: string;
}

export default function BottomNavigation() {
    const router = useRouter();
    const pathname = usePathname();
    const { token, isAuthenticated } = useAuthStore();
    const [status, setStatus] = useState<SystemStatus | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [historyStack, setHistoryStack] = useState<string[]>([]);
    const [historyIndex, setHistoryIndex] = useState(-1);

    // Track navigation history
    useEffect(() => {
        if (pathname && pathname !== historyStack[historyIndex]) {
            const newStack = historyStack.slice(0, historyIndex + 1);
            newStack.push(pathname);
            setHistoryStack(newStack);
            setHistoryIndex(newStack.length - 1);
        }
    }, [pathname]);

    const fetchStatus = useCallback(async () => {
        if (!token) return;
        try {
            const res = await fetch(`${API_URL}/status`, {
                headers: { 'Authorization': `Bearer ${token}` },
                signal: AbortSignal.timeout(5000),
            });
            if (res.ok) {
                const data = await res.json();
                setStatus(data);
                setIsConnected(true);
            } else {
                setIsConnected(false);
            }
        } catch {
            setIsConnected(false);
        }
    }, [token]);

    // Poll status
    useEffect(() => {
        if (!isAuthenticated || !token) return;

        const initialTimeout = setTimeout(fetchStatus, 2000);
        const interval = setInterval(fetchStatus, 15000);
        return () => { clearTimeout(initialTimeout); clearInterval(interval); };
    }, [isAuthenticated, token, fetchStatus]);

    const canGoBack = historyIndex > 0;
    const canGoForward = historyIndex < historyStack.length - 1;

    const handleBack = () => {
        if (canGoBack) {
            setHistoryIndex(historyIndex - 1);
            router.push(historyStack[historyIndex - 1]);
        }
    };

    const handleForward = () => {
        if (canGoForward) {
            setHistoryIndex(historyIndex + 1);
            router.push(historyStack[historyIndex + 1]);
        }
    };

    const handleHome = () => {
        router.push(isAuthenticated ? '/dashboard' : '/');
    };

    const handleSettings = () => {
        router.push('/settings');
    };

    const isActive = (path: string) => pathname === path;

    // Don't show on lock screen
    if (!isAuthenticated || pathname === '/') {
        return null;
    }

    // Status chip component
    const StatusChip = ({ label, online, icon: Icon, color }: {
        label: string;
        online: boolean;
        icon: React.ElementType;
        color: string;
    }) => (
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-all duration-300 ${
            online
                ? `bg-${color}-500/10 border border-${color}-500/20 text-${color}-400`
                : 'bg-gray-800/50 border border-gray-700/30 text-gray-600'
        }`}>
            <div className="relative">
                <Icon className="w-3 h-3" />
                <div className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full border border-black ${
                    online ? 'bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.6)]' : 'bg-gray-600'
                }`} />
            </div>
            <span>{label}</span>
        </div>
    );

    const llmOnline = status?.llm?.configured ?? false;
    const burpOnline = status?.burp === 'online';
    const mobsfOnline = status?.mobsf === 'online';
    const mcpCount = status?.mcp ? `${status.mcp.active}/${status.mcp.total}` : '0/0';
    const llmLabel = status?.llm?.provider?.toUpperCase() || 'LLM';

    return (
        <motion.div
            initial={{ y: 100 }}
            animate={{ y: 0 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="fixed bottom-0 left-0 right-0 z-50"
        >
            {/* Status Bar */}
            <div className="bg-black/80 backdrop-blur-xl border-t border-white/[0.06]">
                <div className="px-4 py-1.5 flex items-center justify-between">
                    {/* Service Status Chips */}
                    <div className="flex items-center gap-2 overflow-x-auto no-scrollbar">
                        {/* Using inline styles for dynamic colors since Tailwind can't JIT arbitrary values */}
                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-all duration-300 ${
                            llmOnline
                                ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400'
                                : 'bg-gray-800/50 border border-gray-700/30 text-gray-600'
                        }`}>
                            <div className="relative">
                                <Zap className="w-3 h-3" />
                                <div className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full border border-black ${
                                    llmOnline ? 'bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.6)]' : 'bg-gray-600'
                                }`} />
                            </div>
                            <span>{llmLabel}</span>
                        </div>

                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-all duration-300 ${
                            burpOnline
                                ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400'
                                : 'bg-gray-800/50 border border-gray-700/30 text-gray-600'
                        }`}>
                            <div className="relative">
                                <Shield className="w-3 h-3" />
                                <div className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full border border-black ${
                                    burpOnline ? 'bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.6)]' : 'bg-gray-600'
                                }`} />
                            </div>
                            <span>BURP</span>
                        </div>

                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-all duration-300 ${
                            mobsfOnline
                                ? 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-400'
                                : 'bg-gray-800/50 border border-gray-700/30 text-gray-600'
                        }`}>
                            <div className="relative">
                                <Activity className="w-3 h-3" />
                                <div className={`absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full border border-black ${
                                    mobsfOnline ? 'bg-green-400 shadow-[0_0_4px_rgba(74,222,128,0.6)]' : 'bg-gray-600'
                                }`} />
                            </div>
                            <span>MOBSF</span>
                        </div>

                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-all duration-300 ${
                            (status?.mcp?.active ?? 0) > 0
                                ? 'bg-purple-500/10 border border-purple-500/20 text-purple-400'
                                : 'bg-gray-800/50 border border-gray-700/30 text-gray-600'
                        }`}>
                            <Server className="w-3 h-3" />
                            <span>MCP {mcpCount}</span>
                        </div>
                    </div>

                    {/* Connection + Version */}
                    <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                        <div className={`flex items-center gap-1 text-[10px] font-mono ${isConnected ? 'text-green-500' : 'text-gray-600'}`}>
                            {isConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                        </div>
                        <span className="text-[10px] font-mono text-gray-700">v1.0.1</span>
                    </div>
                </div>
            </div>

            {/* Navigation Bar */}
            <div className="bg-black/95 backdrop-blur-xl border-t border-white/[0.04]">
                <div className="h-12 px-4 flex items-center justify-around max-w-md mx-auto">
                    <button
                        onClick={handleBack}
                        disabled={!canGoBack}
                        className={`flex flex-col items-center justify-center p-2 rounded-lg transition-all ${
                            canGoBack ? 'text-gray-400 hover:text-white active:scale-90' : 'text-gray-700 cursor-not-allowed'
                        }`}
                    >
                        <ChevronLeft className="w-5 h-5" />
                        <span className="text-[9px] mt-0.5">Back</span>
                    </button>

                    <button
                        onClick={handleHome}
                        className={`flex flex-col items-center justify-center p-2 rounded-lg transition-all active:scale-90 ${
                            isActive('/dashboard') ? 'text-cyan-400' : 'text-gray-400 hover:text-white'
                        }`}
                    >
                        <Home className="w-5 h-5" />
                        <span className="text-[9px] mt-0.5">Home</span>
                    </button>

                    <button
                        onClick={handleForward}
                        disabled={!canGoForward}
                        className={`flex flex-col items-center justify-center p-2 rounded-lg transition-all ${
                            canGoForward ? 'text-gray-400 hover:text-white active:scale-90' : 'text-gray-700 cursor-not-allowed'
                        }`}
                    >
                        <ChevronRight className="w-5 h-5" />
                        <span className="text-[9px] mt-0.5">Forward</span>
                    </button>

                    <button
                        onClick={handleSettings}
                        className={`flex flex-col items-center justify-center p-2 rounded-lg transition-all active:scale-90 ${
                            isActive('/settings') ? 'text-cyan-400' : 'text-gray-400 hover:text-white'
                        }`}
                    >
                        <Settings className="w-5 h-5" />
                        <span className="text-[9px] mt-0.5">Settings</span>
                    </button>
                </div>
            </div>
        </motion.div>
    );
}

