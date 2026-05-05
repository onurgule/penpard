'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';
import { useShortcutsStore } from '@/lib/store/shortcuts';
import { useTourStore } from '@/lib/store/tour';
import { shouldInvalidateSession, useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

interface ClientProvidersProps {
    children: React.ReactNode;
}

export default function ClientProviders({ children }: ClientProvidersProps) {
    const router = useRouter();
    const { openHelpModal } = useShortcutsStore();
    const { startTour, hasCompletedTour } = useTourStore();

    // Initialize keyboard shortcuts
    useKeyboardShortcuts();

    useEffect(() => {
        if (typeof window === 'undefined') return;

        const originalFetch = window.fetch.bind(window);

        const requestHasAuthorization = (input: RequestInfo | URL, init?: RequestInit): boolean => {
            const requestHeaders = input instanceof Request ? input.headers : undefined;
            const headers = new Headers(init?.headers || requestHeaders);
            return headers.has('Authorization');
        };

        const resolveRequestUrl = (input: RequestInfo | URL): string => {
            if (typeof input === 'string') return input;
            if (input instanceof URL) return input.toString();
            return input.url;
        };

        window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
            const response = await originalFetch(input, init);
            const requestUrl = resolveRequestUrl(input);

            if (requestHasAuthorization(input, init) && requestUrl.startsWith(API_URL)) {
                let message: string | undefined;
                const contentType = response.headers.get('content-type') || '';

                if (contentType.includes('application/json')) {
                    try {
                        const data = await response.clone().json();
                        if (data && typeof data.message === 'string') {
                            message = data.message;
                        }
                    } catch {
                        // Ignore malformed error bodies and fall back to status-only handling.
                    }
                }

                if (shouldInvalidateSession(response.status, message, requestUrl)) {
                    const authState = useAuthStore.getState();
                    if (authState.isAuthenticated) {
                        authState.lock();
                        if (window.location.pathname !== '/') {
                            window.location.href = '/';
                        }
                    }
                }
            }

            return response;
        };

        return () => {
            window.fetch = originalFetch;
        };
    }, []);

    useEffect(() => {
        // Listen for navigation events from Electron menu
        if (typeof window !== 'undefined' && window.electronAPI) {
            window.electronAPI.onNavigate((route: string) => {
                // Auth guard: protect all routes except the login page
                const publicRoutes = ['/'];
                const authState = useAuthStore.getState();
                if (!publicRoutes.includes(route) && !authState.isAuthenticated) {
                    router.push('/');
                    return;
                }
                router.push(route);
            });

            // Listen for shortcuts modal trigger from menu
            window.electronAPI.onShowShortcuts(() => {
                openHelpModal();
            });

            // Listen for tour start from menu
            window.electronAPI.onStartTour(() => {
                startTour();
            });
        }
    }, [router, openHelpModal, startTour]);

    // Auto-start tour for first-time users after a short delay
    useEffect(() => {
        if (!hasCompletedTour && typeof window !== 'undefined') {
            const timeout = setTimeout(() => {
                // Only auto-start if on dashboard
                if (window.location.pathname === '/dashboard') {
                    startTour();
                }
            }, 1500);
            return () => clearTimeout(timeout);
        }
    }, [hasCompletedTour, startTour]);

    return (
        <>
            {children}
        </>
    );
}
