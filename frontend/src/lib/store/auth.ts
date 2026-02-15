import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import axios from 'axios';
import { API_URL } from '@/lib/api-config';

const SAVED_KEY_STORAGE = 'penpard-saved-key';

interface AuthState {
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
    token: string | null;
    unlock: (key: string, options?: { rememberKey?: boolean }) => Promise<void>;
    lock: () => void;
    changeKey: (currentKey: string, newKey: string) => Promise<void>;
    getSavedKey: () => string | null;
    clearSavedKey: () => void;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            isAuthenticated: false,
            isLoading: false,
            error: null,
            token: null,

            unlock: async (key: string, options?: { rememberKey?: boolean }) => {
                set({ isLoading: true, error: null });
                try {
                    const response = await axios.post(`${API_URL}/auth/verify-key`, { key });

                    const { token } = response.data;

                    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

                    if (options?.rememberKey && typeof window !== 'undefined') {
                        localStorage.setItem(SAVED_KEY_STORAGE, key);
                    }

                    set({
                        token,
                        isAuthenticated: true,
                        isLoading: false,
                        error: null,
                    });
                } catch (error: any) {
                    const message = error.response?.data?.message || 'Invalid key';
                    set({
                        isLoading: false,
                        error: message,
                        isAuthenticated: false,
                    });
                    throw new Error(message);
                }
            },

            lock: () => {
                delete axios.defaults.headers.common['Authorization'];
                set({
                    token: null,
                    isAuthenticated: false,
                    error: null,
                });
            },

            getSavedKey: () => {
                if (typeof window === 'undefined') return null;
                return localStorage.getItem(SAVED_KEY_STORAGE);
            },

            clearSavedKey: () => {
                if (typeof window !== 'undefined') localStorage.removeItem(SAVED_KEY_STORAGE);
            },

            changeKey: async (currentKey: string, newKey: string) => {
                set({ isLoading: true, error: null });
                try {
                    await axios.post(`${API_URL}/auth/change-key`, {
                        currentKey,
                        newKey,
                    }, {
                        headers: { Authorization: `Bearer ${get().token}` },
                    });
                    set({ isLoading: false, error: null });
                } catch (error: any) {
                    const message = error.response?.data?.message || 'Failed to change key';
                    set({ isLoading: false, error: message });
                    throw new Error(message);
                }
            },
        }),
        {
            name: 'penpard-auth',
            partialize: (state) => ({
                token: state.token,
                isAuthenticated: state.isAuthenticated,
            }),
        }
    )
);

// Setup axios defaults & interceptors
if (typeof window !== 'undefined') {
    // Restore token from persisted storage
    const stored = localStorage.getItem('penpard-auth');
    if (stored) {
        try {
            const parsed = JSON.parse(stored);
            if (parsed.state?.token) {
                axios.defaults.headers.common['Authorization'] = `Bearer ${parsed.state.token}`;
            }
        } catch (e) {
            // Invalid token data
        }
    }

    // Global response interceptor — redirect to lock screen on auth failures
    axios.interceptors.response.use(
        (response) => response,
        (error) => {
            const status = error?.response?.status;
            // 401 = no/missing token, 403 = invalid/expired token
            if (status === 401 || status === 403) {
                const url = error?.config?.url || '';
                // Don't intercept the lock-screen auth request itself
                if (!url.includes('/auth/verify-key')) {
                    const state = useAuthStore.getState();
                    if (state.isAuthenticated) {
                        state.lock();
                        // Redirect to lock screen
                        window.location.href = '/';
                    }
                }
            }
            return Promise.reject(error);
        }
    );
}
