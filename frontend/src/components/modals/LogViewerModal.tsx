'use client';

import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, FileText, RefreshCw, FolderOpen } from 'lucide-react';

interface LogViewerModalProps {
    isOpen: boolean;
    onClose: () => void;
}

type LogType = 'combined' | 'error';

export default function LogViewerModal({ isOpen, onClose }: LogViewerModalProps) {
    const [activeTab, setActiveTab] = useState<LogType>('combined');
    const [logs, setLogs] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const logContainerRef = useRef<HTMLDivElement>(null);

    const fetchLogs = async (type: LogType) => {
        if (!window.electronAPI) return;
        
        setIsLoading(true);
        try {
            const logLines = await window.electronAPI.getLogs(type, 500);
            setLogs(logLines);
        } catch (e) {
            setLogs(['Failed to load logs']);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        if (isOpen) {
            fetchLogs(activeTab);
        }
    }, [isOpen, activeTab]);

    useEffect(() => {
        // Scroll to bottom when logs change
        if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [logs]);

    const handleOpenFolder = () => {
        window.electronAPI?.openLogsFolder();
    };

    const handleRefresh = () => {
        fetchLogs(activeTab);
    };

    const getLogLineStyle = (line: string): string => {
        if (line.includes('"level":"error"') || line.includes('[ERROR]')) {
            return 'text-red-400';
        }
        if (line.includes('"level":"warn"') || line.includes('[WARN]')) {
            return 'text-yellow-400';
        }
        if (line.includes('"level":"info"') || line.includes('[INFO]')) {
            return 'text-blue-400';
        }
        return 'text-gray-400';
    };

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 backdrop-blur-sm"
                onClick={onClose}
            >
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full max-w-4xl h-[600px] glass-darker rounded-xl border border-white/10 shadow-2xl overflow-hidden flex flex-col"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
                        <div className="flex items-center gap-3">
                            <FileText className="w-5 h-5 text-cyan-400" />
                            <h2 className="text-lg font-semibold text-white">View Logs</h2>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-1 text-gray-400 hover:text-white transition-colors"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Tabs */}
                    <div className="flex items-center gap-2 px-6 py-3 border-b border-white/10">
                        <button
                            onClick={() => setActiveTab('combined')}
                            className={`px-4 py-1.5 text-sm rounded-lg transition-colors ${
                                activeTab === 'combined'
                                    ? 'bg-cyan-600 text-white'
                                    : 'text-gray-400 hover:text-white hover:bg-white/10'
                            }`}
                        >
                            Combined
                        </button>
                        <button
                            onClick={() => setActiveTab('error')}
                            className={`px-4 py-1.5 text-sm rounded-lg transition-colors ${
                                activeTab === 'error'
                                    ? 'bg-red-600 text-white'
                                    : 'text-gray-400 hover:text-white hover:bg-white/10'
                            }`}
                        >
                            Errors
                        </button>
                        <div className="flex-1" />
                        <button
                            onClick={handleRefresh}
                            disabled={isLoading}
                            className="p-2 text-gray-400 hover:text-white transition-colors"
                            title="Refresh"
                        >
                            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                        </button>
                        <button
                            onClick={handleOpenFolder}
                            className="p-2 text-gray-400 hover:text-white transition-colors"
                            title="Open Logs Folder"
                        >
                            <FolderOpen className="w-4 h-4" />
                        </button>
                    </div>

                    {/* Log Content */}
                    <div 
                        ref={logContainerRef}
                        className="flex-1 overflow-auto p-4 font-mono text-xs bg-black/30"
                    >
                        {isLoading ? (
                            <div className="flex items-center justify-center h-full text-gray-500">
                                Loading logs...
                            </div>
                        ) : logs.length === 0 ? (
                            <div className="flex items-center justify-center h-full text-gray-500">
                                No logs found
                            </div>
                        ) : (
                            <div className="space-y-0.5">
                                {logs.map((line, index) => (
                                    <div 
                                        key={index} 
                                        className={`${getLogLineStyle(line)} break-all leading-relaxed`}
                                    >
                                        {line}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex justify-between items-center px-6 py-3 border-t border-white/10 bg-white/5">
                        <span className="text-xs text-gray-500">
                            {logs.length} lines (last 500)
                        </span>
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
                        >
                            Close
                        </button>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
