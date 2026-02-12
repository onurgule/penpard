'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    ServerCrash,
    RefreshCw,
    RotateCcw,
    Wifi,
    WifiOff,
    Loader2,
    CheckCircle,
    AlertTriangle,
    Monitor,
    HardDrive,
    ExternalLink,
} from 'lucide-react';
import { API_URL } from '@/lib/api-config';

type ConnectionStatus = 'checking' | 'connected' | 'backend_down' | 'frontend_error';

interface DiagnosticResult {
    backend: boolean;
    backendLatency: number | null;
    isElectron: boolean;
    apiUrl: string;
    error: string | null;
}

export default function ConnectionGuard({ children }: { children: React.ReactNode }) {
    const [status, setStatus] = useState<ConnectionStatus>('checking');
    const [diagnostic, setDiagnostic] = useState<DiagnosticResult | null>(null);
    const [isRestarting, setIsRestarting] = useState<string | null>(null); // 'backend' | 'frontend' | null
    const [retryCount, setRetryCount] = useState(0);
    const [initialCheckDone, setInitialCheckDone] = useState(false);

    const isElectron = typeof window !== 'undefined' && !!window.electronAPI;

    const checkBackendHealth = useCallback(async (): Promise<DiagnosticResult> => {
        const start = Date.now();
        const result: DiagnosticResult = {
            backend: false,
            backendLatency: null,
            isElectron,
            apiUrl: API_URL,
            error: null,
        };

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            const res = await fetch(`${API_URL}/status`, {
                signal: controller.signal,
                headers: { 'Cache-Control': 'no-cache' },
            });
            clearTimeout(timeout);

            result.backendLatency = Date.now() - start;

            if (res.ok || res.status === 401) {
                // 401 = backend is running but auth required — that's fine
                result.backend = true;
            } else {
                result.error = `Backend responded with status ${res.status}`;
            }
        } catch (e: any) {
            result.backendLatency = Date.now() - start;
            if (e.name === 'AbortError') {
                result.error = 'Backend connection timed out (5s)';
            } else if (e.message?.includes('Failed to fetch') || e.message?.includes('NetworkError')) {
                result.error = 'Cannot reach backend — connection refused';
            } else {
                result.error = e.message || 'Unknown connection error';
            }
        }

        return result;
    }, [isElectron]);

    const runCheck = useCallback(async () => {
        const diag = await checkBackendHealth();
        setDiagnostic(diag);

        if (diag.backend) {
            setStatus('connected');
            setRetryCount(0);
        } else {
            setStatus('backend_down');
            setRetryCount(prev => prev + 1);
        }

        setInitialCheckDone(true);
    }, [checkBackendHealth]);

    // Initial check
    useEffect(() => {
        runCheck();
    }, [runCheck]);

    // Auto-retry every 10s when backend is down
    useEffect(() => {
        if (status !== 'backend_down') return;

        const interval = setInterval(() => {
            runCheck();
        }, 10000);

        return () => clearInterval(interval);
    }, [status, runCheck]);

    // Periodic health check when connected (every 60s)
    useEffect(() => {
        if (status !== 'connected') return;

        const interval = setInterval(() => {
            runCheck();
        }, 60000);

        return () => clearInterval(interval);
    }, [status, runCheck]);

    const handleRetry = async () => {
        setStatus('checking');
        await runCheck();
    };

    const handleBackendRestart = async () => {
        if (!isElectron) return;
        setIsRestarting('backend');
        try {
            await window.electronAPI!.backendRestart();
            // Wait for backend to come back up
            await new Promise(resolve => setTimeout(resolve, 3000));
            await runCheck();
        } catch (e) {
            console.error('Backend restart failed:', e);
        }
        setIsRestarting(null);
    };

    const handleFrontendRestart = async () => {
        if (isElectron) {
            setIsRestarting('frontend');
            try {
                await window.electronAPI!.frontendRestart();
            } catch {
                window.location.reload();
            }
        } else {
            window.location.reload();
        }
    };

    const handleClearCache = () => {
        // Clear Next.js client-side cache and reload
        if (typeof window !== 'undefined') {
            // Clear service workers
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.getRegistrations().then(registrations => {
                    registrations.forEach(r => r.unregister());
                });
            }
            // Hard reload bypassing cache
            window.location.href = window.location.href;
        }
    };

    // Don't show anything while initial check is running (avoid flash)
    if (!initialCheckDone) {
        return (
            <div className="min-h-screen bg-dark-950 flex items-center justify-center">
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-center"
                >
                    <Loader2 className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-4" />
                    <p className="text-gray-400 text-sm font-mono">Connecting to PenPard...</p>
                </motion.div>
            </div>
        );
    }

    // Connected — render the app
    if (status === 'connected') {
        return <>{children}</>;
    }

    // Backend is down — show diagnostic screen
    return (
        <div className="min-h-screen bg-dark-950 flex items-center justify-center p-6">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="max-w-lg w-full"
            >
                <div className="glass-darker rounded-2xl p-8 border border-red-500/20 relative overflow-hidden">
                    {/* Animated background pulse */}
                    <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-orange-500/5 animate-pulse" />

                    <div className="relative z-10">
                        {/* Icon */}
                        <div className="w-20 h-20 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-6">
                            <ServerCrash className="w-10 h-10 text-red-400" />
                        </div>

                        {/* Title */}
                        <h1 className="text-2xl font-bold text-white text-center mb-2">
                            Backend Not Responding
                        </h1>
                        <p className="text-gray-400 text-center mb-6 text-sm">
                            PenPard cannot connect to the backend server. The application needs the backend to function.
                        </p>

                        {/* Diagnostic Info */}
                        <div className="bg-dark-900/80 rounded-xl p-4 mb-6 border border-dark-600/50 space-y-3 font-mono text-xs">
                            <div className="flex items-center justify-between">
                                <span className="flex items-center gap-2 text-gray-400">
                                    <HardDrive className="w-3.5 h-3.5" />
                                    Backend API
                                </span>
                                <span className="flex items-center gap-1.5 text-red-400">
                                    <WifiOff className="w-3.5 h-3.5" />
                                    Offline
                                </span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="flex items-center gap-2 text-gray-400">
                                    <Monitor className="w-3.5 h-3.5" />
                                    Frontend
                                </span>
                                <span className="flex items-center gap-1.5 text-green-400">
                                    <CheckCircle className="w-3.5 h-3.5" />
                                    Running
                                </span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-500">API URL</span>
                                <span className="text-gray-400">{diagnostic?.apiUrl}</span>
                            </div>
                            {diagnostic?.error && (
                                <div className="pt-2 border-t border-dark-600/50">
                                    <span className="text-orange-400/80">{diagnostic.error}</span>
                                </div>
                            )}
                            <div className="flex items-center justify-between pt-2 border-t border-dark-600/50">
                                <span className="text-gray-500">Retry attempts</span>
                                <span className="text-gray-400">{retryCount}</span>
                            </div>
                        </div>

                        {/* Action Buttons */}
                        <div className="space-y-3">
                            {/* Primary: Retry Connection */}
                            <button
                                onClick={handleRetry}
                                disabled={status === 'checking'}
                                className="w-full btn-primary flex items-center justify-center gap-2 py-3 disabled:opacity-50"
                            >
                                {status === 'checking' ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Checking Connection...
                                    </>
                                ) : (
                                    <>
                                        <RefreshCw className="w-4 h-4" />
                                        Retry Connection
                                    </>
                                )}
                            </button>

                            {/* Electron: Backend Restart */}
                            {isElectron && (
                                <button
                                    onClick={handleBackendRestart}
                                    disabled={isRestarting === 'backend'}
                                    className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 text-orange-400 rounded-xl text-sm font-medium transition-colors disabled:opacity-50"
                                >
                                    {isRestarting === 'backend' ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Restarting Backend...
                                        </>
                                    ) : (
                                        <>
                                            <RotateCcw className="w-4 h-4" />
                                            Restart Backend
                                        </>
                                    )}
                                </button>
                            )}

                            {/* Secondary row */}
                            <div className="flex gap-3">
                                <button
                                    onClick={handleFrontendRestart}
                                    disabled={isRestarting === 'frontend'}
                                    className="flex-1 flex items-center justify-center gap-2 py-2.5 px-4 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-gray-300 rounded-xl text-sm transition-colors disabled:opacity-50"
                                >
                                    <RefreshCw className="w-3.5 h-3.5" />
                                    Reload App
                                </button>
                                <button
                                    onClick={handleClearCache}
                                    className="flex-1 flex items-center justify-center gap-2 py-2.5 px-4 bg-dark-800 hover:bg-dark-700 border border-dark-600 text-gray-300 rounded-xl text-sm transition-colors"
                                >
                                    <RotateCcw className="w-3.5 h-3.5" />
                                    Clear Cache
                                </button>
                            </div>
                        </div>

                        {/* Help text */}
                        <div className="mt-6 pt-4 border-t border-dark-600/30">
                            <p className="text-xs text-gray-500 text-center mb-2">Possible solutions:</p>
                            <ul className="text-xs text-gray-500 space-y-1 list-disc list-inside">
                                <li>Make sure the backend is running (<code className="text-cyan-400/60">npm run dev</code> in project root)</li>
                                <li>Check if port <code className="text-cyan-400/60">4000</code> is available</li>
                                {isElectron && <li>Try the &quot;Restart Backend&quot; button above</li>}
                                <li>Check the terminal/console for error messages</li>
                            </ul>
                        </div>

                        {/* Auto-retry indicator */}
                        <p className="text-[10px] text-gray-600 text-center mt-4 font-mono">
                            Auto-retrying every 10 seconds...
                        </p>
                    </div>
                </div>
            </motion.div>
        </div>
    );
}
