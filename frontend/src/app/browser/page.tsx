'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Globe,
    Play,
    Square,
    Compass,
    Monitor,
    Bot,
    User,
    ArrowRight,
    ExternalLink,
    Clock,
    Activity,
    MousePointerClick,
    Type,
    Camera,
    ChevronDown,
    ChevronRight as ChevronRightIcon,
    RefreshCw,
    Settings,
    X,
    AlertTriangle,
    Terminal,
    Navigation,
    Wifi,
    WifiOff,
    Loader2,
    Shield,
    Eye,
    Code,
    Link as LinkIcon,
    FormInput,
    Send,
    RotateCw,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { useBrowserStore, BrowserSession, BrowserActionRecord } from '@/lib/store/browser';

// ── Action type metadata for display ──
const ACTION_ICONS: Record<string, React.ElementType> = {
    navigate: Navigation,
    goto: ArrowRight,
    page_load: Globe,
    click: MousePointerClick,
    fill: Type,
    type: Type,
    submit: Send,
    screenshot: Camera,
    evaluate: Code,
    select: FormInput,
    waitForNavigation: Clock,
    waitForSelector: Eye,
    back: ChevronRightIcon,
    forward: ChevronRightIcon,
    reload: RotateCw,
    ai_command: Bot,
    custom: Terminal,
};

const SOURCE_COLORS: Record<string, string> = {
    human: 'text-green-400 bg-green-500/10 border-green-500/20',
    ai: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    system: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
};

const STATUS_STYLES: Record<string, { color: string; pulse: boolean }> = {
    launching: { color: 'bg-yellow-400', pulse: true },
    active: { color: 'bg-green-400', pulse: true },
    paused: { color: 'bg-orange-400', pulse: false },
    closed: { color: 'bg-gray-600', pulse: false },
};

export default function PenPardBrowserPage() {
    const router = useRouter();
    const { isAuthenticated } = useAuthStore();
    const {
        sessions, selectedSessionId, sessionDetail, sessionActions,
        proxyConfig, isLaunching, isExecutingAction, error,
        fetchSessions, fetchSessionDetail, fetchSessionActions,
        fetchProxyConfig, launchSession, executeAction, captureScreenshot,
        closeSession, selectSession, saveProxyConfig, clearError,
    } = useBrowserStore();

    // Local state
    const [targetUrl, setTargetUrl] = useState('');
    const [showProxySettings, setShowProxySettings] = useState(false);
    const [proxyHost, setProxyHost] = useState('127.0.0.1');
    const [proxyPort, setProxyPort] = useState('8080');
    const [aiActionType, setAiActionType] = useState('goto');
    const [aiActionUrl, setAiActionUrl] = useState('');
    const [aiActionSelector, setAiActionSelector] = useState('');
    const [aiActionValue, setAiActionValue] = useState('');
    const [aiActionScript, setAiActionScript] = useState('');
    const [screenshotData, setScreenshotData] = useState<string | null>(null);
    const [detailTab, setDetailTab] = useState<'actions' | 'state' | 'ai'>('actions');
    const [pageState, setPageState] = useState<any>(null);
    const [isLoadingState, setIsLoadingState] = useState(false);

    // Auth guard
    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    // Initial data load
    useEffect(() => {
        fetchSessions();
        fetchProxyConfig();
    }, []);

    // Proxy config sync
    useEffect(() => {
        if (proxyConfig) {
            setProxyHost(proxyConfig.host);
            setProxyPort(String(proxyConfig.port));
        }
    }, [proxyConfig]);

    // Auto-refresh session detail
    useEffect(() => {
        if (!selectedSessionId) return;
        const interval = setInterval(() => {
            fetchSessionDetail(selectedSessionId);
            fetchSessionActions(selectedSessionId);
        }, 3000);
        return () => clearInterval(interval);
    }, [selectedSessionId]);



    // Auto-refresh sessions list
    useEffect(() => {
        const interval = setInterval(fetchSessions, 10000);
        return () => clearInterval(interval);
    }, []);

    // Handlers
    const handleLaunch = async () => {
        const url = targetUrl.trim();
        const sessionId = await launchSession(url || undefined);
        if (sessionId) {
            selectSession(sessionId);
            setTargetUrl('');
        }
    };

    const handleAiAction = async () => {
        if (!selectedSessionId) return;
        const action: any = { type: aiActionType };
        if (aiActionType === 'goto') action.url = aiActionUrl;
        if (['click', 'fill', 'select', 'submit', 'waitForSelector'].includes(aiActionType)) action.selector = aiActionSelector;
        if (['fill', 'select'].includes(aiActionType)) action.value = aiActionValue;
        if (aiActionType === 'evaluate') action.script = aiActionScript;

        await executeAction(selectedSessionId, action);
    };

    const handleScreenshot = async () => {
        if (!selectedSessionId) return;
        const base64 = await captureScreenshot(selectedSessionId);
        if (base64) setScreenshotData(base64);
    };

    const handleFetchPageState = async () => {
        if (!selectedSessionId) return;
        setIsLoadingState(true);
        try {
            const token = useAuthStore.getState().token;
            const res = await fetch(`http://localhost:4000/api/browser/sessions/${selectedSessionId}/state`, {
                headers: { 'Authorization': `Bearer ${token}` },
            });
            if (res.ok) {
                const data = await res.json();
                setPageState(data.state);
            }
        } catch { /* ignore */ }
        setIsLoadingState(false);
    };

    const handleSaveProxy = async () => {
        await saveProxyConfig({ host: proxyHost, port: Number(proxyPort) || 8080 });
        setShowProxySettings(false);
    };

    const activeSessions = sessions.filter(s => s.status !== 'closed');
    const closedSessions = sessions.filter(s => s.status === 'closed');

    // Figure out the selected session details
    const selectedSession = sessionDetail || sessions.find(s => s.id === selectedSessionId);

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="glass-darker border-b border-dark-600/50 sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center shadow-lg shadow-violet-500/20">
                            <Compass className="w-6 h-6 text-white" />
                        </div>
                        <div>
                            <h1 className="text-lg font-bold text-white">PENPARD BROWSER</h1>
                            <p className="text-xs text-gray-500 terminal-text">
                                BURP-ROUTED TESTING SURFACE
                                <span className="text-violet-400/70 font-semibold ml-1">
                                    {activeSessions.length > 0 ? `${activeSessions.length} active` : 'no sessions'}
                                </span>
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        {/* Proxy Config Button */}
                        <button
                            onClick={() => setShowProxySettings(!showProxySettings)}
                            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-dark-700 text-gray-400 hover:text-white hover:bg-dark-600 transition-colors text-sm"
                        >
                            <Shield className="w-4 h-4" />
                            <span className="hidden md:inline">Proxy: {proxyConfig?.host || '127.0.0.1'}:{proxyConfig?.port || 8080}</span>
                        </button>
                    </div>
                </div>
            </header>

            {/* Error Banner */}
            <AnimatePresence>
                {error && (
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        className="max-w-7xl mx-auto px-4 mt-2"
                    >
                        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                            <span className="flex-1">{error}</span>
                            <button onClick={clearError} className="hover:text-white"><X className="w-4 h-4" /></button>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Proxy Settings Panel */}
            <AnimatePresence>
                {showProxySettings && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="max-w-7xl mx-auto px-4 mt-2 overflow-hidden"
                    >
                        <div className="card p-4 border border-violet-500/20">
                            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                                <Shield className="w-4 h-4 text-violet-400" />
                                Burp Proxy Configuration
                            </h3>
                            <p className="text-xs text-gray-500 mb-3">
                                Traffic from PenPard Browser will be routed through this proxy. This should point to Burp Suite&apos;s proxy listener (default: 127.0.0.1:8080).
                            </p>
                            <div className="flex items-center gap-3">
                                <div className="flex-1">
                                    <label className="text-xs text-gray-400 mb-1 block">Host</label>
                                    <input
                                        type="text"
                                        value={proxyHost}
                                        onChange={(e) => setProxyHost(e.target.value)}
                                        className="input-field w-full text-sm"
                                        placeholder="127.0.0.1"
                                    />
                                </div>
                                <div className="w-32">
                                    <label className="text-xs text-gray-400 mb-1 block">Port</label>
                                    <input
                                        type="number"
                                        value={proxyPort}
                                        onChange={(e) => setProxyPort(e.target.value)}
                                        className="input-field w-full text-sm"
                                        placeholder="8080"
                                    />
                                </div>
                                <div className="flex items-end gap-2 pb-0.5">
                                    <button
                                        onClick={handleSaveProxy}
                                        className="px-4 py-2 rounded-lg bg-violet-500/20 text-violet-400 hover:bg-violet-500/30 border border-violet-500/40 text-sm font-medium"
                                    >
                                        Save
                                    </button>
                                    <button
                                        onClick={() => setShowProxySettings(false)}
                                        className="px-3 py-2 rounded-lg bg-dark-700 text-gray-400 hover:bg-dark-600 text-sm"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <main className="max-w-7xl mx-auto px-4 py-6">
                <div className="grid lg:grid-cols-[360px_1fr] gap-6">
                    {/* ─── Left Panel: Launch + Sessions ─── */}
                    <div className="space-y-4">
                        {/* Launch Card */}
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="card p-5 border border-violet-500/20"
                        >
                            <h2 className="text-sm font-bold text-white mb-3 flex items-center gap-2 uppercase tracking-wider">
                                <Play className="w-4 h-4 text-violet-400" />
                                Launch Browser
                            </h2>
                            <div className="space-y-3">
                                <div>
                                    <label className="text-xs text-gray-400 mb-1 block">Target URL (optional)</label>
                                    <input
                                        type="text"
                                        value={targetUrl}
                                        onChange={(e) => setTargetUrl(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleLaunch()}
                                        placeholder="https://example.com"
                                        className="input-field w-full text-sm"
                                        disabled={isLaunching}
                                    />
                                </div>
                                <button
                                    onClick={handleLaunch}
                                    disabled={isLaunching}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg bg-gradient-to-r from-violet-600 to-purple-600 text-white font-semibold hover:from-violet-500 hover:to-purple-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-violet-500/20 hover:shadow-violet-500/40"
                                >
                                    {isLaunching ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Launching Browser...
                                        </>
                                    ) : (
                                        <>
                                            <Compass className="w-4 h-4" />
                                            Open PenPard Browser
                                        </>
                                    )}
                                </button>
                                <p className="text-[11px] text-gray-600 text-center">
                                    Opens a Chromium browser with traffic routed through Burp Suite
                                </p>
                            </div>
                        </motion.div>

                        {/* Active Sessions */}
                        <div className="card p-4">
                            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <Monitor className="w-3.5 h-3.5" />
                                Active Sessions ({activeSessions.length})
                            </h3>
                            {activeSessions.length === 0 ? (
                                <div className="text-center py-6 text-gray-600">
                                    <Compass className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                    <p className="text-xs">No active sessions</p>
                                </div>
                            ) : (
                                <div className="space-y-2">
                                    {activeSessions.map(session => (
                                        <SessionCard
                                            key={session.id}
                                            session={session}
                                            isSelected={selectedSessionId === session.id}
                                            onSelect={() => selectSession(session.id)}
                                            onClose={() => closeSession(session.id)}
                                        />
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Closed Sessions (collapsed) */}
                        {closedSessions.length > 0 && (
                            <ClosedSessionsList sessions={closedSessions} onSelect={selectSession} selectedId={selectedSessionId} />
                        )}
                    </div>

                    {/* ─── Right Panel: Session Detail & AI Control ─── */}
                    <div>
                        {selectedSession ? (
                            <motion.div
                                key={selectedSession.id}
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                className="space-y-4"
                            >
                                {/* Session Header */}
                                <div className="card p-4 border border-violet-500/10">
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-center gap-3 flex-1 min-w-0">
                                            <SessionStatusDot status={selectedSession.status} />
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <h3 className="text-white font-semibold truncate">
                                                        {selectedSession.current_url || selectedSession.target_url || 'New Session'}
                                                    </h3>
                                                    <span className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-semibold ${selectedSession.mode === 'ai' ? 'text-purple-400 bg-purple-500/10 border-purple-500/20' : selectedSession.mode === 'mixed' ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-green-400 bg-green-500/10 border-green-500/20'}`}>
                                                        {selectedSession.mode === 'ai' ? <Bot className="w-3 h-3" /> : <User className="w-3 h-3" />}
                                                        {selectedSession.mode?.toUpperCase()}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-gray-500 mt-0.5">
                                                    Session {selectedSession.id.substring(0, 8)}...
                                                    {selectedSession.scan_id && <span className="ml-2 text-cyan-500">• Linked to scan</span>}
                                                </p>
                                            </div>
                                        </div>
                                        {selectedSession.status !== 'closed' && (
                                            <button
                                                onClick={() => closeSession(selectedSession.id)}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 text-xs font-medium"
                                            >
                                                <Square className="w-3 h-3" />
                                                Close
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {/* Tab Navigation */}
                                <div className="flex gap-1 bg-dark-800/50 rounded-lg p-1">
                                    {([
                                        { id: 'actions', label: 'Action Log', icon: Activity },
                                        { id: 'ai', label: 'AI Control', icon: Bot },
                                        { id: 'state', label: 'Page State', icon: Eye },
                                    ] as const).map(tab => (
                                        <button
                                            key={tab.id}
                                            onClick={() => setDetailTab(tab.id)}
                                            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-xs font-medium transition-all ${detailTab === tab.id
                                                ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                                                : 'text-gray-500 hover:text-gray-300 hover:bg-dark-700/50'
                                                }`}
                                        >
                                            <tab.icon className="w-3.5 h-3.5" />
                                            {tab.label}
                                        </button>
                                    ))}
                                </div>

                                {/* Tab Content */}
                                {detailTab === 'actions' && (
                                    <div className="card p-4 max-h-[600px] overflow-y-auto">
                                        <div className="flex items-center justify-between mb-3">
                                            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Navigation & Action Log</h3>
                                            <button
                                                onClick={() => fetchSessionActions(selectedSession.id)}
                                                className="text-gray-500 hover:text-white"
                                            >
                                                <RefreshCw className="w-3.5 h-3.5" />
                                            </button>
                                        </div>
                                        {sessionActions.length === 0 ? (
                                            <div className="text-center py-8 text-gray-600">
                                                <Activity className="w-6 h-6 mx-auto mb-2 opacity-30" />
                                                <p className="text-xs">No actions recorded yet</p>
                                            </div>
                                        ) : (
                                            <div className="space-y-1">
                                                {sessionActions.map((action) => (
                                                    <ActionLogEntry key={action.id} action={action} />
                                                ))}

                                            </div>
                                        )}
                                    </div>
                                )}

                                {detailTab === 'ai' && selectedSession.status !== 'closed' && (
                                    <div className="card p-5 border border-purple-500/10">
                                        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                                            <Bot className="w-4 h-4 text-purple-400" />
                                            AI Browser Control
                                        </h3>

                                        <div className="space-y-4">
                                            {/* Action Type Selector */}
                                            <div>
                                                <label className="text-xs text-gray-400 mb-1 block">Action Type</label>
                                                <select
                                                    value={aiActionType}
                                                    onChange={(e) => setAiActionType(e.target.value)}
                                                    className="input-field w-full text-sm"
                                                >
                                                    <option value="goto">Navigate to URL</option>
                                                    <option value="click">Click Element</option>
                                                    <option value="fill">Type into Field</option>
                                                    <option value="submit">Submit (Click + Wait)</option>
                                                    <option value="select">Select Option</option>
                                                    <option value="evaluate">Execute JavaScript</option>
                                                    <option value="waitForSelector">Wait for Element</option>
                                                    <option value="waitForNavigation">Wait for Navigation</option>
                                                    <option value="back">Go Back</option>
                                                    <option value="forward">Go Forward</option>
                                                    <option value="reload">Reload Page</option>
                                                </select>
                                            </div>

                                            {/* Conditional Fields */}
                                            {aiActionType === 'goto' && (
                                                <div>
                                                    <label className="text-xs text-gray-400 mb-1 block">URL</label>
                                                    <input
                                                        type="text"
                                                        value={aiActionUrl}
                                                        onChange={(e) => setAiActionUrl(e.target.value)}
                                                        placeholder="https://example.com/login"
                                                        className="input-field w-full text-sm"
                                                    />
                                                </div>
                                            )}

                                            {['click', 'fill', 'select', 'submit', 'waitForSelector'].includes(aiActionType) && (
                                                <div>
                                                    <label className="text-xs text-gray-400 mb-1 block">CSS Selector</label>
                                                    <input
                                                        type="text"
                                                        value={aiActionSelector}
                                                        onChange={(e) => setAiActionSelector(e.target.value)}
                                                        placeholder="#login-btn, input[name='username'], .submit-form"
                                                        className="input-field w-full text-sm font-mono"
                                                    />
                                                </div>
                                            )}

                                            {['fill', 'select'].includes(aiActionType) && (
                                                <div>
                                                    <label className="text-xs text-gray-400 mb-1 block">Value</label>
                                                    <input
                                                        type="text"
                                                        value={aiActionValue}
                                                        onChange={(e) => setAiActionValue(e.target.value)}
                                                        placeholder="Enter text or select value..."
                                                        className="input-field w-full text-sm"
                                                    />
                                                </div>
                                            )}

                                            {aiActionType === 'evaluate' && (
                                                <div>
                                                    <label className="text-xs text-gray-400 mb-1 block">JavaScript</label>
                                                    <textarea
                                                        value={aiActionScript}
                                                        onChange={(e) => setAiActionScript(e.target.value)}
                                                        placeholder="document.title"
                                                        className="input-field w-full text-sm font-mono h-24 resize-y"
                                                    />
                                                </div>
                                            )}

                                            <div className="flex gap-2">
                                                <button
                                                    onClick={handleAiAction}
                                                    disabled={isExecutingAction}
                                                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-violet-600 text-white font-semibold hover:from-purple-500 hover:to-violet-500 disabled:opacity-50 text-sm shadow-lg shadow-purple-500/20"
                                                >
                                                    {isExecutingAction ? (
                                                        <Loader2 className="w-4 h-4 animate-spin" />
                                                    ) : (
                                                        <Play className="w-4 h-4" />
                                                    )}
                                                    Execute
                                                </button>
                                                <button
                                                    onClick={handleScreenshot}
                                                    className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-dark-700 text-gray-400 hover:text-white hover:bg-dark-600 text-sm border border-dark-600"
                                                    title="Capture Screenshot"
                                                >
                                                    <Camera className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </div>

                                        {/* Screenshot Preview */}
                                        {screenshotData && (
                                            <div className="mt-4 border-t border-dark-600 pt-4">
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="text-xs text-gray-400 font-semibold">Screenshot</span>
                                                    <button onClick={() => setScreenshotData(null)} className="text-gray-500 hover:text-white">
                                                        <X className="w-3.5 h-3.5" />
                                                    </button>
                                                </div>
                                                <img
                                                    src={`data:image/png;base64,${screenshotData}`}
                                                    alt="Browser screenshot"
                                                    className="w-full rounded-lg border border-dark-600 shadow-lg"
                                                />
                                            </div>
                                        )}
                                    </div>
                                )}

                                {detailTab === 'ai' && selectedSession.status === 'closed' && (
                                    <div className="card p-8 text-center text-gray-500">
                                        <Square className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                        <p className="text-sm">Session is closed. AI control is not available.</p>
                                    </div>
                                )}

                                {detailTab === 'state' && (
                                    <div className="card p-4">
                                        <div className="flex items-center justify-between mb-3">
                                            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Page State</h3>
                                            <button
                                                onClick={handleFetchPageState}
                                                disabled={isLoadingState || selectedSession.status === 'closed'}
                                                className="flex items-center gap-1.5 text-xs text-violet-400 hover:text-violet-300 disabled:opacity-50"
                                            >
                                                {isLoadingState ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                                                Refresh
                                            </button>
                                        </div>

                                        {pageState ? (
                                            <div className="space-y-4">
                                                <div>
                                                    <p className="text-xs text-gray-500 mb-1">URL</p>
                                                    <p className="text-sm text-white font-mono truncate">{pageState.url}</p>
                                                </div>
                                                <div>
                                                    <p className="text-xs text-gray-500 mb-1">Title</p>
                                                    <p className="text-sm text-white">{pageState.title || '(no title)'}</p>
                                                </div>

                                                {/* Forms */}
                                                {pageState.forms?.length > 0 && (
                                                    <div>
                                                        <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
                                                            <FormInput className="w-3 h-3" />
                                                            Forms ({pageState.forms.length})
                                                        </p>
                                                        <div className="space-y-2">
                                                            {pageState.forms.map((form: any, i: number) => (
                                                                <div key={i} className="p-2 rounded bg-dark-700/50 border border-dark-600 text-xs">
                                                                    <p className="text-gray-300">
                                                                        <span className="text-cyan-400 font-mono">{form.method}</span> {form.action || '(no action)'}
                                                                    </p>
                                                                    <div className="flex flex-wrap gap-1 mt-1">
                                                                        {form.fields?.map((f: any, j: number) => (
                                                                            <span key={j} className="px-1.5 py-0.5 rounded bg-dark-600 text-gray-400 text-[10px] font-mono">
                                                                                {f.name || f.id || f.type}
                                                                            </span>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Links */}
                                                {pageState.links?.length > 0 && (
                                                    <div>
                                                        <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
                                                            <LinkIcon className="w-3 h-3" />
                                                            Links ({pageState.links.length})
                                                        </p>
                                                        <div className="max-h-48 overflow-y-auto space-y-0.5">
                                                            {pageState.links.slice(0, 30).map((link: any, i: number) => (
                                                                <div key={i} className="text-[11px] text-gray-500 truncate font-mono hover:text-gray-300">
                                                                    {link.text && <span className="text-gray-400 mr-1">{link.text.substring(0, 40)}</span>}
                                                                    <span className="text-cyan-500/60">{link.href}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Text Summary */}
                                                {pageState.textSummary && (
                                                    <div>
                                                        <p className="text-xs text-gray-500 mb-1">Page Text (preview)</p>
                                                        <pre className="text-[11px] text-gray-500 whitespace-pre-wrap max-h-32 overflow-y-auto bg-dark-800/50 p-2 rounded border border-dark-600 font-mono">
                                                            {pageState.textSummary.substring(0, 600)}
                                                        </pre>
                                                    </div>
                                                )}
                                            </div>
                                        ) : (
                                            <div className="text-center py-8 text-gray-600">
                                                <Eye className="w-6 h-6 mx-auto mb-2 opacity-30" />
                                                <p className="text-xs">Click &ldquo;Refresh&rdquo; to inspect current page state</p>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </motion.div>
                        ) : (
                            /* No session selected */
                            <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                className="card p-12 text-center border border-dashed border-dark-600"
                            >
                                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500/10 to-purple-500/10 border border-violet-500/20 flex items-center justify-center mx-auto mb-4">
                                    <Compass className="w-8 h-8 text-violet-400/40" />
                                </div>
                                <h3 className="text-lg font-bold text-gray-400 mb-2">PenPard Browser</h3>
                                <p className="text-sm text-gray-600 max-w-md mx-auto mb-4">
                                    Launch a Burp-routed browser for manual testing, AI-driven exploration, or vulnerability validation. 
                                    All traffic flows through your Burp proxy for full visibility.
                                </p>
                                <div className="flex flex-wrap justify-center gap-3 text-[11px] text-gray-500">
                                    <span className="flex items-center gap-1 px-2 py-1 rounded bg-dark-700/50 border border-dark-600">
                                        <User className="w-3 h-3 text-green-400" /> Human Control
                                    </span>
                                    <span className="flex items-center gap-1 px-2 py-1 rounded bg-dark-700/50 border border-dark-600">
                                        <Bot className="w-3 h-3 text-purple-400" /> AI Control
                                    </span>
                                    <span className="flex items-center gap-1 px-2 py-1 rounded bg-dark-700/50 border border-dark-600">
                                        <Shield className="w-3 h-3 text-orange-400" /> Burp Routed
                                    </span>
                                    <span className="flex items-center gap-1 px-2 py-1 rounded bg-dark-700/50 border border-dark-600">
                                        <Activity className="w-3 h-3 text-cyan-400" /> Action Logging
                                    </span>
                                </div>
                            </motion.div>
                        )}
                    </div>
                </div>
            </main>
        </div>
    );
}

// ── Sub-components ──

function SessionCard({ session, isSelected, onSelect, onClose }: {
    session: BrowserSession;
    isSelected: boolean;
    onSelect: () => void;
    onClose: () => void;
}) {
    const statusStyle = STATUS_STYLES[session.status] || STATUS_STYLES.closed;

    return (
        <motion.div
            onClick={onSelect}
            whileHover={{ scale: 1.01 }}
            className={`p-3 rounded-lg cursor-pointer transition-all border ${isSelected
                ? 'bg-violet-500/10 border-violet-500/30 shadow-lg shadow-violet-500/5'
                : 'bg-dark-700/30 border-dark-600/50 hover:bg-dark-700/60 hover:border-dark-500'
                }`}
        >
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                    <SessionStatusDot status={session.status} />
                    <div className="flex-1 min-w-0">
                        <p className="text-sm text-white truncate font-mono">{session.current_url || session.target_url || 'about:blank'}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${session.mode === 'ai' ? 'text-purple-400 bg-purple-500/10 border-purple-500/20' : 'text-green-400 bg-green-500/10 border-green-500/20'}`}>
                                {session.mode === 'ai' ? 'AI' : 'Human'}
                            </span>
                            <span className="text-[10px] text-gray-600">
                                {new Date(session.last_activity_at || session.launched_at).toLocaleTimeString()}
                            </span>
                        </div>
                    </div>
                </div>
                <button
                    onClick={(e) => { e.stopPropagation(); onClose(); }}
                    className="text-gray-600 hover:text-red-400 p-1"
                    title="Close session"
                >
                    <X className="w-3.5 h-3.5" />
                </button>
            </div>
        </motion.div>
    );
}

function SessionStatusDot({ status }: { status: string }) {
    const style = STATUS_STYLES[status] || STATUS_STYLES.closed;
    return (
        <div className="relative flex-shrink-0">
            <div className={`w-2.5 h-2.5 rounded-full ${style.color}`} />
            {style.pulse && (
                <div className={`absolute inset-0 w-2.5 h-2.5 rounded-full ${style.color} animate-ping opacity-40`} />
            )}
        </div>
    );
}

function ActionLogEntry({ action }: { action: BrowserActionRecord }) {
    const Icon = ACTION_ICONS[action.action_type] || Activity;
    const sourceClass = SOURCE_COLORS[action.source] || SOURCE_COLORS.system;
    let detail = '';
    try {
        const data = JSON.parse(action.action_data || '{}');
        if (data.url) detail = data.url;
        else if (data.selector) detail = data.selector;
        else if (data.error) detail = `⚠ ${data.error}`;
    } catch { /* ignore */ }

    return (
        <div className="flex items-start gap-2 py-1.5 px-2 rounded hover:bg-dark-700/30 group">
            <div className={`p-1 rounded mt-0.5 ${sourceClass} border`}>
                <Icon className="w-3 h-3" />
            </div>
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                    <span className="text-xs text-white font-medium">{action.action_type}</span>
                    <span className={`text-[9px] px-1 rounded ${sourceClass} border font-medium uppercase`}>{action.source}</span>
                    <span className="text-[10px] text-gray-600 ml-auto opacity-0 group-hover:opacity-100 transition-opacity">
                        {new Date(action.timestamp).toLocaleTimeString()}
                    </span>
                </div>
                {detail && <p className="text-[11px] text-gray-500 truncate font-mono mt-0.5">{detail}</p>}
                {action.page_url && action.action_type !== 'page_load' && (
                    <p className="text-[10px] text-gray-700 truncate">{action.page_url}</p>
                )}
            </div>
        </div>
    );
}

function ClosedSessionsList({ sessions, onSelect, selectedId }: {
    sessions: BrowserSession[];
    onSelect: (id: string) => void;
    selectedId: string | null;
}) {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="card p-3">
            <button
                onClick={() => setExpanded(!expanded)}
                className="w-full flex items-center justify-between text-xs font-bold text-gray-500 uppercase tracking-wider hover:text-gray-400"
            >
                <span className="flex items-center gap-2">
                    <Clock className="w-3.5 h-3.5" />
                    Closed Sessions ({sessions.length})
                </span>
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${expanded ? 'rotate-180' : ''}`} />
            </button>
            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="space-y-1 mt-2 max-h-48 overflow-y-auto">
                            {sessions.slice(0, 20).map(s => (
                                <div
                                    key={s.id}
                                    onClick={() => onSelect(s.id)}
                                    className={`p-2 rounded cursor-pointer text-xs transition-colors ${selectedId === s.id ? 'bg-dark-700 text-white' : 'text-gray-600 hover:text-gray-400 hover:bg-dark-700/30'}`}
                                >
                                    <p className="truncate font-mono">{s.current_url || s.target_url || 'about:blank'}</p>
                                    <p className="text-[10px] text-gray-700 mt-0.5">
                                        {new Date(s.launched_at).toLocaleString()} — {new Date(s.closed_at || s.last_activity_at).toLocaleTimeString()}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
