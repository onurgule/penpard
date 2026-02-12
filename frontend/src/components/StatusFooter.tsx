'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import { motion } from 'framer-motion';
import { Activity, Server, Shield, Zap } from 'lucide-react';

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

export default function StatusFooter() {
    const { token, isAuthenticated } = useAuthStore();
    const [status, setStatus] = useState<SystemStatus | null>(null);
    const router = useRouter();

    const goToSettings = () => router.push('/settings');

    // Poll status every 30 seconds
    useEffect(() => {
        if (!isAuthenticated || !token) return;

        const fetchStatus = async () => {
            try {
                const res = await fetch(`${API_URL}/status`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                if (res.ok) {
                    const data = await res.json();
                    setStatus(data);
                }
            } catch (error) {
                console.error('Failed to fetch system status', error);
            }
        };

        fetchStatus();
        const interval = setInterval(fetchStatus, 30000);
        return () => clearInterval(interval);
    }, [isAuthenticated, token]);

    if (!isAuthenticated || !status) return null;

    return (
        <motion.div
            initial={{ y: 100 }}
            animate={{ y: 0 }}
            className="fixed bottom-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-md border-t border-white/10 text-[10px] md:text-xs py-1 px-4 flex items-center justify-between font-mono text-gray-400 select-none h-8"
        >
            <div className="flex items-center space-x-6 overflow-x-auto no-scrollbar">
                {/* LLM Status — click to go to Settings */}
                <div onClick={goToSettings} className="flex items-center space-x-2 whitespace-nowrap cursor-pointer hover:text-white transition-colors" title="Configure LLM in Settings">
                    <div className={`w-2 h-2 rounded-full ${status.llm.configured ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-red-500'}`} />
                    <Zap className="w-3 h-3 text-yellow-500" />
                    <span className="font-semibold text-gray-300">LLM:</span>
                    <span className="text-gray-400">{status.llm.provider ? status.llm.provider.toUpperCase() : 'NONE'}</span>
                </div>

                {/* Burp Status — click to go to Settings */}
                <div onClick={goToSettings} className="flex items-center space-x-2 whitespace-nowrap cursor-pointer hover:text-white transition-colors" title="Configure Burp Suite in Settings">
                    <div className={`w-2 h-2 rounded-full ${status.burp === 'online' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-red-500'}`} />
                    <Shield className="w-3 h-3 text-orange-500" />
                    <span className="font-semibold text-gray-300">BURP:</span>
                    <span className="uppercase">{status.burp}</span>
                </div>

                {/* MobSF Status — click to go to Settings */}
                <div onClick={goToSettings} className="flex items-center space-x-2 whitespace-nowrap cursor-pointer hover:text-white transition-colors" title="Configure MobSF in Settings">
                    <div className={`w-2 h-2 rounded-full ${status.mobsf === 'online' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-red-500'}`} />
                    <Shield className="w-3 h-3 text-cyan-500" />
                    <span className="font-semibold text-gray-300">MOBSF:</span>
                    <span className="uppercase">{status.mobsf}</span>
                </div>

                {/* Nuclei Status */}
                <div className="flex items-center space-x-2 whitespace-nowrap">
                    <div className={`w-2 h-2 rounded-full ${status.nuclei !== 'not found' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-gray-500'}`} />
                    <Activity className="w-3 h-3 text-blue-500" />
                    <span className="font-semibold text-gray-300">NUCLEI:</span>
                    <span className="uppercase">{status.nuclei}</span>
                </div>
            </div>

            <div className="flex items-center space-x-6 ml-4 hidden md:flex">
                {/* MCP Servers */}
                <div className="flex items-center space-x-2">
                    <Server className="w-3 h-3 text-purple-500" />
                    <span className="font-semibold text-gray-300">MCP:</span>
                    <span>{status.mcp.active}/{status.mcp.total} Active</span>
                </div>
            </div>
        </motion.div>
    );
}
