import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import axios from 'axios';
import { API_URL } from '@/lib/api-config';

interface AuthState {
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
    token: string | null;
    unlock: (key: string) => Promise<void>;
    lock: () => void;
    changeKey: (currentKey: string, newKey: string) => Promise<void>;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            isAuthenticated: false,
            isLoading: false,
            error: null,
            token: null,

            unlock: async (key: string) => {
                set({ isLoading: true, error: null });
                try {
                    const response = await axios.post(`${API_URL}/auth/verify-key`, { key });

                    const { token } = response.data;

                    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

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

// Setup axios interceptor for token
if (typeof window !== 'undefined') {
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
}
