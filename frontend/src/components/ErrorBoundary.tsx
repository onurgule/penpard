'use client';

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home, Bug, ChevronDown, ChevronUp, RotateCcw, ServerCrash, Monitor, Loader2 } from 'lucide-react';
import { API_URL } from '@/lib/api-config';

interface Props {
    children: ReactNode;
    fallback?: ReactNode;
}

interface State {
    hasError: boolean;
    error: Error | null;
    errorInfo: ErrorInfo | null;
    showDetails: boolean;
    diagnosis: 'unknown' | 'checking' | 'backend_down' | 'frontend_crash';
    isRestarting: string | null;
}

class ErrorBoundary extends Component<Props, State> {
    constructor(props: Props) {
        super(props);
        this.state = {
            hasError: false,
            error: null,
            errorInfo: null,
            showDetails: false,
            diagnosis: 'unknown',
            isRestarting: null,
        };
    }

    static getDerivedStateFromError(error: Error): Partial<State> {
        return {
            hasError: true,
            error,
            diagnosis: 'checking',
        };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('Error Boundary Caught:', error, errorInfo);

        this.setState({
            error,
            errorInfo,
        });

        // Diagnose: is the backend down?
        this.diagnoseError();
        this.reportError(error, errorInfo);
    }

    diagnoseError = async () => {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const res = await fetch(`${API_URL}/status`, { signal: controller.signal });
            clearTimeout(timeout);

            if (res.ok || res.status === 401) {
                this.setState({ diagnosis: 'frontend_crash' });
            } else {
                this.setState({ diagnosis: 'backend_down' });
            }
        } catch {
            this.setState({ diagnosis: 'backend_down' });
        }
    };

    reportError = (error: Error, errorInfo: ErrorInfo) => {
        const errorReport = {
            message: error.message,
            stack: error.stack,
            componentStack: errorInfo.componentStack,
            timestamp: new Date().toISOString(),
            userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
            url: typeof window !== 'undefined' ? window.location.href : 'unknown',
        };

        console.error('Error Report:', errorReport);
    };

    handleReload = () => {
        window.location.reload();
    };

    handleGoHome = () => {
        window.location.href = '/dashboard';
    };

    handleReset = () => {
        this.setState({
            hasError: false,
            error: null,
            errorInfo: null,
            showDetails: false,
            diagnosis: 'unknown',
            isRestarting: null,
        });
    };

    handleBackendRestart = async () => {
        if (typeof window === 'undefined' || !window.electronAPI) return;
        this.setState({ isRestarting: 'backend' });
        try {
            await window.electronAPI.backendRestart();
            await new Promise(resolve => setTimeout(resolve, 3000));
            window.location.reload();
        } catch (e) {
            console.error('Backend restart failed:', e);
            this.setState({ isRestarting: null });
        }
    };

    handleFrontendRestart = async () => {
        if (typeof window !== 'undefined' && window.electronAPI) {
            this.setState({ isRestarting: 'frontend' });
            try {
                await window.electronAPI.frontendRestart();
            } catch {
                window.location.reload();
            }
        } else {
            window.location.reload();
        }
    };

    handleClearCacheAndReload = () => {
        if (typeof window !== 'undefined') {
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.getRegistrations().then(registrations => {
                    registrations.forEach(r => r.unregister());
                });
            }
            // Clear caches
            if ('caches' in window) {
                caches.keys().then(names => {
                    names.forEach(name => caches.delete(name));
                });
            }
            setTimeout(() => window.location.reload(), 500);
        }
    };

    toggleDetails = () => {
        this.setState(prev => ({ showDetails: !prev.showDetails }));
    };

    render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }

            const { diagnosis, isRestarting } = this.state;
            const isElectron = typeof window !== 'undefined' && !!window.electronAPI;
            const isBackendDown = diagnosis === 'backend_down';
            const isChecking = diagnosis === 'checking';

            return (
                <div className="min-h-screen bg-dark-950 flex items-center justify-center p-6">
                    <div className="max-w-2xl w-full">
                        {/* Error Card */}
                        <div className={`glass-darker rounded-2xl p-8 border ${isBackendDown ? 'border-orange-500/20' : 'border-red-500/20'}`}>
                            {/* Icon */}
                            <div className={`w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6 ${isBackendDown ? 'bg-orange-500/10' : 'bg-red-500/10'}`}>
                                {isChecking ? (
                                    <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                                ) : isBackendDown ? (
                                    <ServerCrash className="w-8 h-8 text-orange-400" />
                                ) : (
                                    <AlertTriangle className="w-8 h-8 text-red-400" />
                                )}
                            </div>

                            {/* Title */}
                            <h1 className="text-2xl font-bold text-white text-center mb-3">
                                {isChecking
                                    ? 'Diagnosing Issue...'
                                    : isBackendDown
                                        ? 'Backend Not Running'
                                        : 'Frontend Crashed'
                                }
                            </h1>

                            {/* Description */}
                            <p className="text-gray-400 text-center mb-6">
                                {isChecking
                                    ? 'Checking system status to identify the problem...'
                                    : isBackendDown
                                        ? 'The backend server is not responding. PenPard needs the backend to work. Start it or click restart below.'
                                        : 'The frontend encountered an unexpected error. This is usually fixed by reloading the page or clearing the cache.'
                                }
                            </p>

                            {/* Diagnosis badges */}
                            {!isChecking && (
                                <div className="flex justify-center gap-3 mb-6">
                                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${isBackendDown ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
                                        <ServerCrash className="w-3.5 h-3.5" />
                                        Backend: {isBackendDown ? 'Offline' : 'Online'}
                                    </div>
                                    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${!isBackendDown ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}`}>
                                        <Monitor className="w-3.5 h-3.5" />
                                        Frontend: {!isBackendDown ? 'Error' : 'Running'}
                                    </div>
                                </div>
                            )}

                            {/* Error Details (Collapsible) */}
                            <div className="mb-6">
                                <button
                                    onClick={this.toggleDetails}
                                    className="w-full flex items-center justify-between px-4 py-3 bg-dark-900/50 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-dark-900/80 transition-colors"
                                >
                                    <span className="flex items-center gap-2">
                                        <Bug className="w-4 h-4" />
                                        Error Details
                                    </span>
                                    {this.state.showDetails ? (
                                        <ChevronUp className="w-4 h-4" />
                                    ) : (
                                        <ChevronDown className="w-4 h-4" />
                                    )}
                                </button>
                                
                                {this.state.showDetails && (
                                    <div className="mt-2 bg-dark-900/80 rounded-lg p-4 border border-dark-600 overflow-x-auto max-h-64 overflow-y-auto">
                                        <div className="mb-3">
                                            <span className="text-xs text-red-400 font-semibold uppercase">Error Message</span>
                                            <pre className="text-xs text-gray-300 font-mono mt-1 whitespace-pre-wrap">
                                                {this.state.error?.toString()}
                                            </pre>
                                        </div>
                                        {this.state.error?.stack && (
                                            <div className="mb-3">
                                                <span className="text-xs text-orange-400 font-semibold uppercase">Stack Trace</span>
                                                <pre className="text-xs text-gray-400 font-mono mt-1 whitespace-pre-wrap">
                                                    {this.state.error.stack}
                                                </pre>
                                            </div>
                                        )}
                                        {this.state.errorInfo?.componentStack && (
                                            <div>
                                                <span className="text-xs text-cyan-400 font-semibold uppercase">Component Stack</span>
                                                <pre className="text-xs text-gray-400 font-mono mt-1 whitespace-pre-wrap">
                                                    {this.state.errorInfo.componentStack}
                                                </pre>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>

                            {/* Action Buttons — context-aware */}
                            <div className="space-y-3">
                                {isBackendDown ? (
                                    <>
                                        {/* Backend is down — primary action is restart */}
                                        {isElectron && (
                                            <button
                                                onClick={this.handleBackendRestart}
                                                disabled={isRestarting === 'backend'}
                                                className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 text-white rounded-xl text-sm font-bold transition-all disabled:opacity-50"
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
                                        <div className="flex gap-3">
                                            <button
                                                onClick={this.handleReload}
                                                className="flex-1 btn-secondary flex items-center justify-center gap-2"
                                            >
                                                <RefreshCw className="w-4 h-4" />
                                                Reload Page
                                            </button>
                                            <button
                                                onClick={this.handleGoHome}
                                                className="flex-1 btn-secondary flex items-center justify-center gap-2"
                                            >
                                                <Home className="w-4 h-4" />
                                                Dashboard
                                            </button>
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        {/* Frontend crash — primary actions are reload/clear cache */}
                                        <div className="flex gap-3">
                                            <button
                                                onClick={this.handleReload}
                                                className="flex-1 btn-primary flex items-center justify-center gap-2"
                                            >
                                                <RefreshCw className="w-4 h-4" />
                                                Reload Page
                                            </button>
                                            <button
                                                onClick={this.handleClearCacheAndReload}
                                                className="flex-1 btn-primary flex items-center justify-center gap-2"
                                            >
                                                <RotateCcw className="w-4 h-4" />
                                                Clear Cache & Reload
                                            </button>
                                        </div>
                                        {isElectron && (
                                            <button
                                                onClick={this.handleFrontendRestart}
                                                disabled={isRestarting === 'frontend'}
                                                className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 rounded-xl text-sm font-medium transition-colors disabled:opacity-50"
                                            >
                                                {isRestarting === 'frontend' ? (
                                                    <>
                                                        <Loader2 className="w-4 h-4 animate-spin" />
                                                        Restarting Frontend...
                                                    </>
                                                ) : (
                                                    <>
                                                        <RotateCcw className="w-4 h-4" />
                                                        Restart Frontend
                                                    </>
                                                )}
                                            </button>
                                        )}
                                        <button
                                            onClick={this.handleGoHome}
                                            className="w-full btn-secondary flex items-center justify-center gap-2"
                                        >
                                            <Home className="w-4 h-4" />
                                            Go to Dashboard
                                        </button>
                                    </>
                                )}
                            </div>

                            {/* Help Text */}
                            <p className="text-xs text-gray-600 text-center mt-6">
                                If this problem persists, check the terminal for errors or restart the application.
                            </p>
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
