'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { X, Keyboard } from 'lucide-react';
import { useShortcutsStore } from '@/lib/store/shortcuts';

export default function ShortcutsHelpModal() {
    const { isHelpModalOpen, closeHelpModal, shortcuts } = useShortcutsStore();

    // Group shortcuts by category
    const groupedShortcuts = shortcuts.reduce((acc, shortcut) => {
        // Skip alternate shortcuts
        if (shortcut.id.endsWith('-alt')) return acc;
        
        if (!acc[shortcut.category]) {
            acc[shortcut.category] = [];
        }
        acc[shortcut.category].push(shortcut);
        return acc;
    }, {} as Record<string, typeof shortcuts>);

    const formatKey = (key: string): string => {
        return key
            .split('+')
            .map((k) => {
                switch (k.toLowerCase()) {
                    case 'ctrl':
                        return 'Ctrl';
                    case 'shift':
                        return 'Shift';
                    case 'alt':
                        return 'Alt';
                    case 'arrowleft':
                        return '\u2190';
                    case 'arrowright':
                        return '\u2192';
                    case 'arrowup':
                        return '\u2191';
                    case 'arrowdown':
                        return '\u2193';
                    case '/':
                        return '/';
                    case ',':
                        return ',';
                    default:
                        return k.charAt(0).toUpperCase() + k.slice(1);
                }
            })
            .join(' + ');
    };

    return (
        <AnimatePresence>
            {isHelpModalOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={closeHelpModal}
                        className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[70]"
                    />

                    {/* Modal */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 20 }}
                        transition={{ type: 'spring', duration: 0.4 }}
                        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[71] w-full max-w-2xl max-h-[80vh] glass-darker rounded-2xl shadow-2xl overflow-hidden border border-cyan-500/20"
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-dark-900/50">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                                    <Keyboard className="w-5 h-5 text-cyan-400" />
                                </div>
                                <div>
                                    <h2 className="text-xl font-semibold text-white">
                                        Keyboard Shortcuts
                                    </h2>
                                    <p className="text-xs text-gray-400">
                                        Master PenPard with these shortcuts
                                    </p>
                                </div>
                            </div>
                            <button
                                onClick={closeHelpModal}
                                className="w-8 h-8 rounded-lg hover:bg-white/10 flex items-center justify-center text-gray-400 hover:text-white transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        {/* Content */}
                        <div className="overflow-y-auto max-h-[calc(80vh-140px)] p-6">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {Object.entries(groupedShortcuts).map(([category, categoryShortcuts]) => (
                                    <div key={category}>
                                        <h3 className="text-sm font-semibold text-cyan-400 mb-3 uppercase tracking-wider">
                                            {category}
                                        </h3>
                                        <div className="space-y-2">
                                            {categoryShortcuts.map((shortcut) => (
                                                <div
                                                    key={shortcut.id}
                                                    className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/5 transition-colors"
                                                >
                                                    <span className="text-sm text-gray-300">
                                                        {shortcut.label}
                                                    </span>
                                                    <kbd className="px-2 py-1 bg-dark-900/80 border border-dark-600 rounded text-xs font-mono text-gray-400 min-w-[60px] text-center">
                                                        {formatKey(shortcut.currentKey)}
                                                    </kbd>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Footer */}
                        <div className="px-6 py-4 border-t border-white/10 bg-dark-950/50">
                            <p className="text-xs text-gray-500 text-center">
                                Press{' '}
                                <kbd className="px-2 py-0.5 bg-dark-900/80 border border-dark-600 rounded text-xs font-mono text-gray-400 mx-1">
                                    Ctrl + /
                                </kbd>{' '}
                                or{' '}
                                <kbd className="px-2 py-0.5 bg-dark-900/80 border border-dark-600 rounded text-xs font-mono text-gray-400 mx-1">
                                    ?
                                </kbd>{' '}
                                anytime to toggle this help
                            </p>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}
