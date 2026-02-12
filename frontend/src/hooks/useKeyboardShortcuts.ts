'use client';

import { useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useShortcutsStore } from '@/lib/store/shortcuts';

export function useKeyboardShortcuts() {
    const router = useRouter();
    const { shortcuts, openHelpModal } = useShortcutsStore();

    // Define action handlers
    const handleAction = useCallback((shortcutId: string) => {
        switch (shortcutId) {
            // Navigation
            case 'nav-dashboard':
                router.push('/dashboard');
                break;
            case 'nav-reports':
                router.push('/reports');
                break;
            case 'nav-settings':
                router.push('/settings');
                break;
            case 'nav-back':
                router.back();
                break;
            
            // Scanning
            case 'scan-new-web':
                router.push('/scan/web');
                break;
            case 'scan-new-mobile':
                router.push('/scan/mobile');
                break;
            
            // Settings
            case 'settings-llm':
                router.push('/settings');
                break;
            case 'settings-prompts':
                router.push('/settings/prompts');
                break;
            
            // Help
            case 'help-shortcuts':
            case 'help-shortcuts-alt':
                openHelpModal();
                break;
            
            default:
                break; // Unknown shortcut, ignore silently
        }
    }, [router, openHelpModal]);

    // Build key combination from event
    const buildKeyCombo = useCallback((event: KeyboardEvent): string => {
        const parts: string[] = [];
        
        if (event.ctrlKey || event.metaKey) parts.push('ctrl');
        if (event.shiftKey) parts.push('shift');
        if (event.altKey) parts.push('alt');
        
        const key = event.key.toLowerCase();
        
        // Don't add modifier keys as the main key
        if (!['control', 'shift', 'alt', 'meta'].includes(key)) {
            // Handle special keys
            if (key === ' ') {
                parts.push('space');
            } else if (key === '/') {
                parts.push('/');
            } else {
                parts.push(key);
            }
        }
        
        return parts.join('+');
    }, []);

    // Global keyboard event listener
    useEffect(() => {
        const handleKeyDown = (event: KeyboardEvent) => {
            // Don't trigger shortcuts when typing in input fields
            const target = event.target as HTMLElement;
            if (
                target.tagName === 'INPUT' ||
                target.tagName === 'TEXTAREA' ||
                target.isContentEditable
            ) {
                // Allow shortcuts modal to open even in inputs with Ctrl+/
                const keyCombo = buildKeyCombo(event);
                if (keyCombo === 'ctrl+/' || keyCombo === 'ctrl+shift+/') {
                    event.preventDefault();
                    openHelpModal();
                }
                return;
            }

            const keyCombo = buildKeyCombo(event);
            
            // Find matching shortcut
            const matchingShortcut = shortcuts.find(
                (s) => s.currentKey.toLowerCase() === keyCombo
            );

            if (matchingShortcut) {
                event.preventDefault();
                event.stopPropagation();
                handleAction(matchingShortcut.id);
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [shortcuts, buildKeyCombo, handleAction, openHelpModal]);
}
