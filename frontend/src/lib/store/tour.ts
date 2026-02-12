import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface TourStep {
    id: string;
    target: string; // CSS selector for the element to highlight
    title: string;
    content: string;
    placement?: 'top' | 'bottom' | 'left' | 'right';
    route?: string; // Navigate to this route before showing step
}

interface TourState {
    isActive: boolean;
    currentStepIndex: number;
    hasCompletedTour: boolean;
    steps: TourStep[];

    // Actions
    startTour: () => void;
    nextStep: () => void;
    prevStep: () => void;
    skipTour: () => void;
    endTour: () => void;
    goToStep: (index: number) => void;
    resetTour: () => void;
}

const defaultSteps: TourStep[] = [
    {
        id: 'welcome',
        target: '[data-tour="logo"]',
        title: 'Welcome to PenPard',
        content: 'PenPard is your AI-powered security scanning companion. Let\'s take a quick tour of the main features.',
        placement: 'bottom',
        route: '/dashboard',
    },
    {
        id: 'new-scan',
        target: '[data-tour="new-web-scan"]',
        title: 'Start a Web Scan',
        content: 'Click here to start a new web vulnerability scan. Enter a URL and PenPard will analyze it for security issues.',
        placement: 'bottom',
        route: '/dashboard',
    },
    {
        id: 'mobile-scan',
        target: '[data-tour="new-mobile-scan"]',
        title: 'Mobile App Analysis',
        content: 'Upload APK or IPA files to scan mobile applications for vulnerabilities and security misconfigurations.',
        placement: 'bottom',
        route: '/dashboard',
    },
    {
        id: 'recent-scans',
        target: '[data-tour="recent-scans"]',
        title: 'Recent Scans',
        content: 'View your scan history here. Click on any scan to see detailed vulnerability reports.',
        placement: 'top',
        route: '/dashboard',
    },
    {
        id: 'settings',
        target: '[data-tour="settings"]',
        title: 'Settings',
        content: 'Configure API keys, notification preferences, and manage your settings from the Settings page.',
        placement: 'right',
        route: '/settings',
    },
    {
        id: 'keyboard-shortcuts',
        target: '[data-tour="shortcuts-hint"]',
        title: 'Keyboard Shortcuts',
        content: 'Press Ctrl+/ anytime to see all available keyboard shortcuts for faster navigation.',
        placement: 'top',
        route: '/settings',
    },
];

export const useTourStore = create<TourState>()(
    persist(
        (set, get) => ({
            isActive: false,
            currentStepIndex: 0,
            hasCompletedTour: false,
            steps: defaultSteps,

            startTour: () => {
                set({ isActive: true, currentStepIndex: 0 });
            },

            nextStep: () => {
                const { currentStepIndex, steps } = get();
                if (currentStepIndex < steps.length - 1) {
                    set({ currentStepIndex: currentStepIndex + 1 });
                } else {
                    // Tour complete
                    set({ isActive: false, hasCompletedTour: true });
                }
            },

            prevStep: () => {
                const { currentStepIndex } = get();
                if (currentStepIndex > 0) {
                    set({ currentStepIndex: currentStepIndex - 1 });
                }
            },

            skipTour: () => {
                set({ isActive: false, hasCompletedTour: true });
            },

            endTour: () => {
                set({ isActive: false, hasCompletedTour: true });
            },

            goToStep: (index: number) => {
                const { steps } = get();
                if (index >= 0 && index < steps.length) {
                    set({ currentStepIndex: index });
                }
            },

            resetTour: () => {
                set({ isActive: false, currentStepIndex: 0, hasCompletedTour: false });
            },
        }),
        {
            name: 'penpard-tour',
            partialize: (state) => ({
                hasCompletedTour: state.hasCompletedTour,
            }),
        }
    )
);
