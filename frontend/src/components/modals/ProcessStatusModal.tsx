'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Activity, RefreshCw, Check, AlertCircle } from 'lucide-react';

interface ProcessStatusModalProps {
    isOpen: boolean;
    onClose: () => void;
}

interface BackendStatus {
    running: boolean;
    healthy: boolean;
    pid: number | null;
    uptime: number;
    port: number;
}

function formatUptime(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
}

export default function ProcessStatusModal({ isOpen, onClose }: ProcessStatusModalProps) {
    const [status, setStatus] = useState<BackendStatus | null>(null);
    const [isRestarting, setIsRestarting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!isOpen) return;

        const fetchStatus = async () => {
            if (window.electronAPI) {
                try {
                    const s = await window.electronAPI.getBackendStatus();
                    setStatus(s);
                    setError(null);
                } catch (e) {
                    setError('Failed to fetch status');
                }
            }
        };

        fetchStatus();
        const interval = setInterval(fetchStatus, 2000);

        return () => clearInterval(interval);
    }, [isOpen]);

    const handleRestart = async () => {
        if (!window.electronAPI || isRestarting) return;
        
        setIsRestarting(true);
        setError(null);
        
        try {
            const result = await window.electronAPI.backendRestart();
            if (!result.success) {
                setError(result.error || 'Restart failed');
            }
        } catch (e) {
            setError('Failed to restart backend');
        } finally {
            setIsRestarting(false);
        }
    };

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm"
                onClick={onClose}
            >
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full max-w-md glass-darker rounded-xl border border-white/10 shadow-2xl overflow-hidden"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
                        <div className="flex items-center gap-3">
                            <Activity className="w-5 h-5 text-cyan-400" />
                            <h2 className="text-lg font-semibold text-white">Process Status</h2>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-1 text-gray-400 hover:text-white transition-colors"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Content */}
                    <div className="p-6 space-y-4">
                        {/* Backend Status */}
                        <div className="p-4 rounded-lg bg-white/5 border border-white/10">
                            <div className="flex items-center justify-between mb-3">
                                <span className="text-sm font-medium text-gray-300">Backend Server</span>
                                <div className="flex items-center gap-2">
                                    {status?.running ? (
                                        <>
                                            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                                            <span className="text-xs text-green-400">Running</span>
                                        </>
                                    ) : (
                                        <>
                                            <span className="w-2 h-2 rounded-full bg-red-500" />
                                            <span className="text-xs text-red-400">Stopped</span>
                                        </>
                                    )}
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-3 text-sm">
                                <div>
                                    <span className="text-gray-500">PID:</span>
                                    <span className="ml-2 text-gray-300">{status?.pid || '-'}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500">Port:</span>
                                    <span className="ml-2 text-gray-300">{status?.port || '-'}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500">Uptime:</span>
                                    <span className="ml-2 text-gray-300">
                                        {status?.uptime ? formatUptime(status.uptime) : '-'}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-gray-500">Health:</span>
                                    <span className={`ml-2 ${status?.healthy ? 'text-green-400' : 'text-yellow-400'}`}>
                                        {status?.healthy ? 'Healthy' : 'Unknown'}
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Error Message */}
                        {error && (
                            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                                <span>{error}</span>
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex justify-end gap-3 px-6 py-4 border-t border-white/10 bg-white/5">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
                        >
                            Close
                        </button>
                        <button
                            onClick={handleRestart}
                            disabled={isRestarting}
                            className="flex items-center gap-2 px-4 py-2 text-sm bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white rounded-lg transition-colors"
                        >
                            <RefreshCw className={`w-4 h-4 ${isRestarting ? 'animate-spin' : ''}`} />
                            {isRestarting ? 'Restarting...' : 'Restart Backend'}
                        </button>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
