/**
 * PenPard Browser — Zustand Store
 *
 * Manages browser session state in the frontend. Handles API communication
 * for launching, controlling, monitoring, and analyzing browser sessions.
 * Supports multi-session, frontend analysis, Burp correlation, and session comparison.
 */

import { create } from 'zustand';
import { API_URL } from '@/lib/api-config';
import { useAuthStore } from '@/lib/store/auth';

export interface BrowserSession {
    id: string;
    user_id: number;
    scan_id: string | null;
    finding_id: number | null;
    target_url: string;
    status: 'launching' | 'active' | 'paused' | 'closed';
    mode: 'human' | 'ai' | 'mixed';
    current_url: string;
    proxy_host: string;
    proxy_port: number;
    launched_at: string;
    last_activity_at: string;
    closed_at: string | null;
    label?: string;
    isLive?: boolean;
    title?: string;
}

export interface BrowserActionRecord {
    id: number;
    session_id: string;
    action_type: string;
    action_data: string | null;
    page_url: string | null;
    page_title: string | null;
    timestamp: string;
    source: 'human' | 'ai' | 'system';
}

export interface ProxyConfig {
    host: string;
    port: number;
}

interface BrowserState {
    sessions: BrowserSession[];
    selectedSessionId: string | null;
    sessionDetail: BrowserSession | null;
    sessionActions: BrowserActionRecord[];
    proxyConfig: ProxyConfig | null;
    isLaunching: boolean;
    isLoadingSessions: boolean;
    isExecutingAction: boolean;
    error: string | null;

    // Frontend analysis state
    frontendAnalysis: any | null;
    burpCorrelation: any | null;
    sessionComparison: any | null;
    fullPageState: any | null;
    isLoadingAnalysis: boolean;

    // Actions
    fetchSessions: () => Promise<void>;
    fetchSessionDetail: (id: string) => Promise<void>;
    fetchSessionActions: (id: string) => Promise<void>;
    fetchProxyConfig: () => Promise<void>;
    launchSession: (targetUrl?: string, scanId?: string, label?: string) => Promise<string | null>;
    executeAction: (sessionId: string, action: any) => Promise<any>;
    captureScreenshot: (sessionId: string) => Promise<string | null>;
    closeSession: (sessionId: string) => Promise<void>;
    selectSession: (id: string | null) => void;
    saveProxyConfig: (config: ProxyConfig) => Promise<void>;
    clearError: () => void;
    clearClosedSessions: () => Promise<void>;

    // Frontend analysis actions
    fetchFullPageState: (sessionId: string) => Promise<void>;
    fetchFrontendAnalysis: (sessionId: string) => Promise<void>;
    fetchBurpCorrelation: (sessionId: string) => Promise<void>;
    compareSessions: (sessionIdA: string, sessionIdB: string) => Promise<void>;
}

function getAuthHeaders(): Record<string, string> {
    const token = useAuthStore.getState().token;
    return token ? { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
}

export const useBrowserStore = create<BrowserState>()((set, get) => ({
    sessions: [],
    selectedSessionId: null,
    sessionDetail: null,
    sessionActions: [],
    proxyConfig: null,
    isLaunching: false,
    isLoadingSessions: false,
    isExecutingAction: false,
    error: null,
    frontendAnalysis: null,
    burpCorrelation: null,
    sessionComparison: null,
    fullPageState: null,
    isLoadingAnalysis: false,

    fetchSessions: async () => {
        set({ isLoadingSessions: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ sessions: data.sessions || [], isLoadingSessions: false });
            } else { set({ isLoadingSessions: false }); }
        } catch { set({ isLoadingSessions: false }); }
    },

    fetchSessionDetail: async (id: string) => {
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${id}`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ sessionDetail: data.session });
            }
        } catch { /* ignore */ }
    },

    fetchSessionActions: async (id: string) => {
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${id}/actions`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ sessionActions: data.actions || [] });
            }
        } catch { /* ignore */ }
    },

    fetchProxyConfig: async () => {
        try {
            const res = await fetch(`${API_URL}/browser/proxy-config`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ proxyConfig: data.config });
            }
        } catch { /* ignore */ }
    },

    launchSession: async (targetUrl?: string, scanId?: string, label?: string) => {
        set({ isLaunching: true, error: null });
        try {
            const res = await fetch(`${API_URL}/browser/launch`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ targetUrl, scanId, label }),
            });
            const data = await res.json();
            if (res.ok && data.sessionId) {
                set({ isLaunching: false });
                get().fetchSessions();
                return data.sessionId;
            } else {
                set({ isLaunching: false, error: data.message || 'Failed to launch browser' });
                return null;
            }
        } catch (e: any) {
            set({ isLaunching: false, error: e.message || 'Failed to launch browser' });
            return null;
        }
    },

    executeAction: async (sessionId: string, action: any) => {
        set({ isExecutingAction: true, error: null });
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionId}/action`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(action),
            });
            const data = await res.json();
            set({ isExecutingAction: false });
            if (!res.ok) { set({ error: data.message || 'Action failed' }); }
            get().fetchSessionDetail(sessionId);
            get().fetchSessionActions(sessionId);
            return data.result || null;
        } catch (e: any) {
            set({ isExecutingAction: false, error: e.message || 'Action failed' });
            return null;
        }
    },

    captureScreenshot: async (sessionId: string) => {
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionId}/screenshot`, {
                method: 'POST', headers: getAuthHeaders(),
            });
            if (res.ok) {
                const data = await res.json();
                return data.screenshot?.base64 || null;
            }
        } catch { /* ignore */ }
        return null;
    },

    closeSession: async (sessionId: string) => {
        try {
            await fetch(`${API_URL}/browser/sessions/${sessionId}/close`, {
                method: 'POST', headers: getAuthHeaders(),
            });
            set((state) => ({
                sessions: state.sessions.map(s => s.id === sessionId ? { ...s, status: 'closed' as const } : s),
                selectedSessionId: state.selectedSessionId === sessionId ? null : state.selectedSessionId,
                sessionDetail: state.sessionDetail?.id === sessionId ? null : state.sessionDetail,
            }));
            get().fetchSessions();
        } catch { /* ignore */ }
    },

    selectSession: (id: string | null) => {
        set({ selectedSessionId: id, sessionDetail: null, sessionActions: [], frontendAnalysis: null, burpCorrelation: null, sessionComparison: null, fullPageState: null });
        if (id) {
            get().fetchSessionDetail(id);
            get().fetchSessionActions(id);
        }
    },

    saveProxyConfig: async (config: ProxyConfig) => {
        try {
            await fetch(`${API_URL}/browser/proxy-config`, {
                method: 'POST', headers: getAuthHeaders(),
                body: JSON.stringify(config),
            });
            set({ proxyConfig: config });
        } catch { /* ignore */ }
    },

    clearError: () => set({ error: null }),

    clearClosedSessions: async () => {
        try {
            const res = await fetch(`${API_URL}/browser/sessions/closed`, {
                method: 'DELETE', headers: getAuthHeaders(),
            });
            if (res.ok) {
                set((state) => ({ sessions: state.sessions.filter(s => s.status !== 'closed') }));
            }
        } catch { /* ignore */ }
    },

    // ── Frontend Analysis Actions ──

    fetchFullPageState: async (sessionId: string) => {
        set({ isLoadingAnalysis: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionId}/full-state`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ fullPageState: data.state, isLoadingAnalysis: false });
            } else { set({ isLoadingAnalysis: false }); }
        } catch { set({ isLoadingAnalysis: false }); }
    },

    fetchFrontendAnalysis: async (sessionId: string) => {
        set({ isLoadingAnalysis: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionId}/frontend-analysis`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ frontendAnalysis: data.analysis, isLoadingAnalysis: false });
            } else { set({ isLoadingAnalysis: false }); }
        } catch { set({ isLoadingAnalysis: false }); }
    },

    fetchBurpCorrelation: async (sessionId: string) => {
        set({ isLoadingAnalysis: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionId}/burp-correlation`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ burpCorrelation: data.correlation, isLoadingAnalysis: false });
            } else { set({ isLoadingAnalysis: false }); }
        } catch { set({ isLoadingAnalysis: false }); }
    },

    compareSessions: async (sessionIdA: string, sessionIdB: string) => {
        set({ isLoadingAnalysis: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions/${sessionIdA}/compare/${sessionIdB}`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ sessionComparison: data.comparison, isLoadingAnalysis: false });
            } else { set({ isLoadingAnalysis: false }); }
        } catch { set({ isLoadingAnalysis: false }); }
    },
}));
