'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Trash2, AlertTriangle, Database, HardDrive, FileText } from 'lucide-react';

interface ClearDataModalProps {
    isOpen: boolean;
    onClose: () => void;
}

interface ClearOptions {
    cache: boolean;
    data: boolean;
    logs: boolean;
}

export default function ClearDataModal({ isOpen, onClose }: ClearDataModalProps) {
    const [options, setOptions] = useState<ClearOptions>({
        cache: true,
        data: false,
        logs: false,
    });
    const [isClearing, setIsClearing] = useState(false);
    const [result, setResult] = useState<ClearOptions | null>(null);

    const handleClear = async () => {
        if (!window.electronAPI || isClearing) return;
        
        // Check if at least one option is selected
        if (!options.cache && !options.data && !options.logs) {
            return;
        }

        setIsClearing(true);
        setResult(null);

        try {
            const cleared = await window.electronAPI.clearCacheData(options);
            setResult(cleared);
            
            // If database was cleared, restart backend
            if (cleared.data) {
                await window.electronAPI.backendRestart();
            }
        } catch (e) {
            console.error('Failed to clear data:', e);
        } finally {
            setIsClearing(false);
        }
    };

    const handleClose = () => {
        setResult(null);
        setOptions({ cache: true, data: false, logs: false });
        onClose();
    };

    const toggleOption = (key: keyof ClearOptions) => {
        setOptions(prev => ({ ...prev, [key]: !prev[key] }));
    };

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm"
                onClick={handleClose}
            >
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full max-w-md glass-darker rounded-xl border border-white/10 shadow-2xl overflow-hidden"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
                        <div className="flex items-center gap-3">
                            <Trash2 className="w-5 h-5 text-red-400" />
                            <h2 className="text-lg font-semibold text-white">Clear Cache & Data</h2>
                        </div>
                        <button
                            onClick={handleClose}
                            className="p-1 text-gray-400 hover:text-white transition-colors"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Content */}
                    <div className="p-6 space-y-4">
                        {/* Warning */}
                        <div className="flex items-start gap-3 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                            <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                            <p className="text-sm text-yellow-200">
                                This action cannot be undone. Selected data will be permanently deleted.
                            </p>
                        </div>

                        {/* Options */}
                        <div className="space-y-3">
                            {/* Cache */}
                            <label className="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-white/10 cursor-pointer hover:bg-white/10 transition-colors">
                                <input
                                    type="checkbox"
                                    checked={options.cache}
                                    onChange={() => toggleOption('cache')}
                                    className="w-4 h-4 rounded border-gray-600 text-cyan-600 focus:ring-cyan-500"
                                />
                                <HardDrive className="w-5 h-5 text-gray-400" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-white">HTTP Cache & Storage</p>
                                    <p className="text-xs text-gray-500">Browser cache, local storage, cookies</p>
                                </div>
                            </label>

                            {/* Database */}
                            <label className="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-white/10 cursor-pointer hover:bg-white/10 transition-colors">
                                <input
                                    type="checkbox"
                                    checked={options.data}
                                    onChange={() => toggleOption('data')}
                                    className="w-4 h-4 rounded border-gray-600 text-cyan-600 focus:ring-cyan-500"
                                />
                                <Database className="w-5 h-5 text-red-400" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-white">Database</p>
                                    <p className="text-xs text-gray-500">All scans, reports, and settings</p>
                                </div>
                                <span className="text-xs text-red-400 font-medium">DESTRUCTIVE</span>
                            </label>

                            {/* Logs */}
                            <label className="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-white/10 cursor-pointer hover:bg-white/10 transition-colors">
                                <input
                                    type="checkbox"
                                    checked={options.logs}
                                    onChange={() => toggleOption('logs')}
                                    className="w-4 h-4 rounded border-gray-600 text-cyan-600 focus:ring-cyan-500"
                                />
                                <FileText className="w-5 h-5 text-gray-400" />
                                <div className="flex-1">
                                    <p className="text-sm font-medium text-white">Log Files</p>
                                    <p className="text-xs text-gray-500">Application and error logs</p>
                                </div>
                            </label>
                        </div>

                        {/* Result */}
                        {result && (
                            <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                                <p className="text-sm text-green-400 font-medium mb-1">Successfully cleared:</p>
                                <ul className="text-xs text-green-300 space-y-1">
                                    {result.cache && <li>- HTTP cache and storage</li>}
                                    {result.data && <li>- Database (backend restarted)</li>}
                                    {result.logs && <li>- Log files</li>}
                                </ul>
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex justify-end gap-3 px-6 py-4 border-t border-white/10 bg-white/5">
                        <button
                            onClick={handleClose}
                            className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
                        >
                            {result ? 'Done' : 'Cancel'}
                        </button>
                        {!result && (
                            <button
                                onClick={handleClear}
                                disabled={isClearing || (!options.cache && !options.data && !options.logs)}
                                className="flex items-center gap-2 px-4 py-2 text-sm bg-red-600 hover:bg-red-500 disabled:bg-red-600/50 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                            >
                                <Trash2 className="w-4 h-4" />
                                {isClearing ? 'Clearing...' : 'Clear Selected'}
                            </button>
                        )}
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
