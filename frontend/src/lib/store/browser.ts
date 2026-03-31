/**
 * PenPard Browser — Zustand Store
 *
 * Manages browser session state in the frontend. Handles API communication
 * for launching, controlling, and monitoring browser sessions.
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

    // Actions
    fetchSessions: () => Promise<void>;
    fetchSessionDetail: (id: string) => Promise<void>;
    fetchSessionActions: (id: string) => Promise<void>;
    fetchProxyConfig: () => Promise<void>;
    launchSession: (targetUrl?: string, scanId?: string) => Promise<string | null>;
    executeAction: (sessionId: string, action: any) => Promise<any>;
    captureScreenshot: (sessionId: string) => Promise<string | null>;
    closeSession: (sessionId: string) => Promise<void>;
    selectSession: (id: string | null) => void;
    saveProxyConfig: (config: ProxyConfig) => Promise<void>;
    clearError: () => void;
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

    fetchSessions: async () => {
        set({ isLoadingSessions: true });
        try {
            const res = await fetch(`${API_URL}/browser/sessions`, { headers: getAuthHeaders() });
            if (res.ok) {
                const data = await res.json();
                set({ sessions: data.sessions || [], isLoadingSessions: false });
            } else {
                set({ isLoadingSessions: false });
            }
        } catch {
            set({ isLoadingSessions: false });
        }
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

    launchSession: async (targetUrl?: string, scanId?: string) => {
        set({ isLaunching: true, error: null });
        try {
            const res = await fetch(`${API_URL}/browser/launch`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ targetUrl, scanId }),
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
            if (!res.ok) {
                set({ error: data.message || 'Action failed' });
            }
            // Refresh session detail + actions after AI action
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
                method: 'POST',
                headers: getAuthHeaders(),
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
                method: 'POST',
                headers: getAuthHeaders(),
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
        set({ selectedSessionId: id, sessionDetail: null, sessionActions: [] });
        if (id) {
            get().fetchSessionDetail(id);
            get().fetchSessionActions(id);
        }
    },

    saveProxyConfig: async (config: ProxyConfig) => {
        try {
            await fetch(`${API_URL}/browser/proxy-config`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(config),
            });
            set({ proxyConfig: config });
        } catch { /* ignore */ }
    },

    clearError: () => set({ error: null }),
}));
