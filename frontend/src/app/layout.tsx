import type { Metadata } from 'next';
import '@/styles/globals.css';
import { Toaster } from 'react-hot-toast';
import BottomNavigation from '@/components/BottomNavigation';
import CustomTitlebar from '@/components/CustomTitlebar';
import ClientProviders from '@/components/ClientProviders';
import ShortcutsHelpModal from '@/components/ShortcutsHelpModal';
import ErrorBoundary from '@/components/ErrorBoundary';
import TourOverlay from '@/components/TourOverlay';
import ConnectionGuard from '@/components/ConnectionGuard';

export const metadata: Metadata = {
    title: 'PenPard - Penetration Partner',
    description: 'Local vulnerability scanning application with AI-powered analysis',
    keywords: ['security', 'vulnerability', 'scanner', 'pentest', 'burp suite'],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en" className="dark">
            <body className="min-h-screen bg-dark-950 text-gray-100 antialiased">
                <ErrorBoundary>
                    <ConnectionGuard>
                        {/* Custom Titlebar (Electron only - rendered client-side) */}
                        <CustomTitlebar />

                        {/* Animated scan line effect */}
                        <div className="scan-line" />

                        {/* Grid background */}
                        <div className="fixed inset-0 bg-grid pointer-events-none opacity-50" />

                        {/* Main content - extra padding for titlebar (40px) and bottom nav */}
                        <ClientProviders>
                            <main className="relative z-10 pt-10 pb-24">
                                {children}
                            </main>

                            {/* Keyboard Shortcuts Help Modal */}
                            <ShortcutsHelpModal />

                            {/* Interactive Onboarding Tour */}
                            <TourOverlay />
                        </ClientProviders>

                        {/* Toast notifications */}
                        <Toaster
                            position="top-right"
                            toastOptions={{
                                duration: 4000,
                                style: {
                                    background: '#1a1a25',
                                    color: '#e2e8f0',
                                    border: '1px solid rgba(0, 240, 255, 0.2)',
                                    borderRadius: '8px',
                                },
                                success: {
                                    iconTheme: {
                                        primary: '#22c55e',
                                        secondary: '#1a1a25',
                                    },
                                },
                                error: {
                                    iconTheme: {
                                        primary: '#ef4444',
                                        secondary: '#1a1a25',
                                    },
                                },
                            }}
                        />

                        {/* Bottom Navigation with Status */}
                        <BottomNavigation />
                    </ConnectionGuard>
                </ErrorBoundary>
            </body>
        </html>
    );
}
