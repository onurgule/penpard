'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';
import { useShortcutsStore } from '@/lib/store/shortcuts';
import { useTourStore } from '@/lib/store/tour';
import { useAuthStore } from '@/lib/store/auth';
import SmartSuggestionAlert from '@/components/SmartSuggestionAlert';
import { API_URL } from '@/lib/api-config';

interface ClientProvidersProps {
    children: React.ReactNode;
}

export default function ClientProviders({ children }: ClientProvidersProps) {
    const router = useRouter();
    const { openHelpModal } = useShortcutsStore();
    const { startTour, hasCompletedTour } = useTourStore();
    const { token, isAuthenticated } = useAuthStore();

    // Initialize keyboard shortcuts
    useKeyboardShortcuts();

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

    // Auto-start Activity Monitor when user is authenticated and Burp is available
    useEffect(() => {
        if (!isAuthenticated || !token) return;

        const startMonitor = async () => {
            try {
                await fetch(`${API_URL}/activity-monitor/start`, {
                    method: 'POST',
                    headers: { 
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                // Silently fail - Burp might not be available
            }
        };

        // Start monitor after a delay to let everything initialize
        const timeout = setTimeout(startMonitor, 5000);
        return () => clearTimeout(timeout);
    }, [isAuthenticated, token]);

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
            {/* Smart Suggestion Alert - shows AI-detected testing patterns */}
            <SmartSuggestionAlert />
        </>
    );
}
