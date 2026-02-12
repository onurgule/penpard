import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface ShortcutDefinition {
    id: string;
    label: string;
    category: string;
    defaultKey: string;
    currentKey: string;
}

interface ShortcutsState {
    shortcuts: ShortcutDefinition[];
    isHelpModalOpen: boolean;
    
    // Actions
    setShortcut: (id: string, key: string) => void;
    resetShortcut: (id: string) => void;
    resetAll: () => void;
    openHelpModal: () => void;
    closeHelpModal: () => void;
    toggleHelpModal: () => void;
    initializeShortcuts: (shortcuts: Omit<ShortcutDefinition, 'currentKey'>[]) => void;
    getShortcutByKey: (key: string) => ShortcutDefinition | undefined;
}

// Default shortcuts configuration
const defaultShortcuts: Omit<ShortcutDefinition, 'currentKey'>[] = [
    // Navigation
    { id: 'nav-dashboard', label: 'Go to Dashboard', category: 'Navigation', defaultKey: 'ctrl+h' },
    { id: 'nav-reports', label: 'Go to Reports', category: 'Navigation', defaultKey: 'ctrl+o' },
    { id: 'nav-settings', label: 'Open Settings', category: 'Navigation', defaultKey: 'ctrl+,' },
    { id: 'nav-back', label: 'Go Back', category: 'Navigation', defaultKey: 'alt+arrowleft' },
    
    // Scanning
    { id: 'scan-new-web', label: 'New Web Scan', category: 'Scanning', defaultKey: 'ctrl+n' },
    { id: 'scan-new-mobile', label: 'New Mobile Scan', category: 'Scanning', defaultKey: 'ctrl+shift+n' },
    
    // Settings
    { id: 'settings-llm', label: 'LLM Configuration', category: 'Settings', defaultKey: 'ctrl+l' },
    { id: 'settings-prompts', label: 'Custom Prompts', category: 'Settings', defaultKey: 'ctrl+p' },
    
    // Help
    { id: 'help-shortcuts', label: 'Show Keyboard Shortcuts', category: 'Help', defaultKey: 'ctrl+/' },
    { id: 'help-shortcuts-alt', label: 'Show Keyboard Shortcuts (Alt)', category: 'Help', defaultKey: 'ctrl+shift+/' },
];

export const useShortcutsStore = create<ShortcutsState>()(
    persist(
        (set, get) => ({
            shortcuts: defaultShortcuts.map(s => ({ ...s, currentKey: s.defaultKey })),
            isHelpModalOpen: false,

            setShortcut: (id: string, key: string) => {
                set((state) => ({
                    shortcuts: state.shortcuts.map((s) =>
                        s.id === id ? { ...s, currentKey: key } : s
                    ),
                }));
            },

            resetShortcut: (id: string) => {
                set((state) => ({
                    shortcuts: state.shortcuts.map((s) =>
                        s.id === id ? { ...s, currentKey: s.defaultKey } : s
                    ),
                }));
            },

            resetAll: () => {
                set((state) => ({
                    shortcuts: state.shortcuts.map((s) => ({
                        ...s,
                        currentKey: s.defaultKey,
                    })),
                }));
            },

            openHelpModal: () => set({ isHelpModalOpen: true }),
            closeHelpModal: () => set({ isHelpModalOpen: false }),
            toggleHelpModal: () => set((state) => ({ isHelpModalOpen: !state.isHelpModalOpen })),

            initializeShortcuts: (newShortcuts) => {
                const existingShortcuts = get().shortcuts;
                const mergedShortcuts = newShortcuts.map((shortcut) => {
                    const existing = existingShortcuts.find((s) => s.id === shortcut.id);
                    return {
                        ...shortcut,
                        currentKey: existing?.currentKey || shortcut.defaultKey,
                    };
                });
                set({ shortcuts: mergedShortcuts });
            },

            getShortcutByKey: (key: string) => {
                return get().shortcuts.find((s) => s.currentKey.toLowerCase() === key.toLowerCase());
            },
        }),
        {
            name: 'penpard-shortcuts',
            partialize: (state) => ({
                shortcuts: state.shortcuts.map(({ id, currentKey }) => ({
                    id,
                    currentKey,
                })),
            }),
            merge: (persisted: any, current) => {
                if (persisted && persisted.shortcuts) {
                    const shortcuts = current.shortcuts.map(s => {
                        const saved = persisted.shortcuts.find((p: any) => p.id === s.id);
                        return saved ? { ...s, currentKey: saved.currentKey } : s;
                    });
                    return { ...current, shortcuts };
                }
                return current;
            },
        }
    )
);
