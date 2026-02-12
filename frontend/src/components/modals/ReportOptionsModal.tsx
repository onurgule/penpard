'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    X, Download, FileText, Presentation, FileSpreadsheet,
    Sparkles, Cpu, Image, ChevronRight, Loader2, ExternalLink,
    Zap, Brain, Eye, CheckCircle
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

interface ReportOptionsModalProps {
    isOpen: boolean;
    onClose: () => void;
    scanId: string;
}

type ReportFormat = 'pdf' | 'docx' | 'pptx';
type ReportMode = 'static' | 'llm';

interface Capabilities {
    llmAvailable: boolean;
    visionSupported: boolean;
    provider: string;
    model: string;
}

export default function ReportOptionsModal({ isOpen, onClose, scanId }: ReportOptionsModalProps) {
    const { token } = useAuthStore();
    const [format, setFormat] = useState<ReportFormat>('pdf');
    const [mode, setMode] = useState<ReportMode>('static');
    const [imageProcessing, setImageProcessing] = useState(false);
    const [downloading, setDownloading] = useState(false);
    const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
    const [loadingCaps, setLoadingCaps] = useState(true);

    // Fetch LLM capabilities on open
    useEffect(() => {
        if (isOpen) {
            setLoadingCaps(true);
            axios.get(`${API_URL}/reports/capabilities/check`, {
                headers: { Authorization: `Bearer ${token}` }
            }).then(res => {
                setCapabilities(res.data);
                // If LLM not available, force static mode
                if (!res.data.llmAvailable) {
                    setMode('static');
                }
            }).catch(() => {
                setCapabilities({ llmAvailable: false, visionSupported: false, provider: 'none', model: 'none' });
                setMode('static');
            }).finally(() => setLoadingCaps(false));
        }
    }, [isOpen, token]);

    const handleDownload = async () => {
        setDownloading(true);
        try {
            const params = new URLSearchParams({
                format,
                mode,
                imageProcessing: String(imageProcessing && mode === 'llm'),
            });

            const response = await axios.get(
                `${API_URL}/reports/${scanId}/download?${params.toString()}`,
                {
                    headers: { Authorization: `Bearer ${token}` },
                    responseType: 'blob',
                    timeout: mode === 'llm' ? 300000 : 120000, // 5min for LLM, 2min for static
                }
            );

            const ext = format;
            const blob = new Blob([response.data]);
            const blobUrl = window.URL.createObjectURL(blob);
            const filename = `PenPard-Report-${scanId}.${ext}`;

            // Trigger download
            const link = document.createElement('a');
            link.href = blobUrl;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();

            // Show persistent toast with "Open Report" button (10 seconds)
            toast.custom(
                (t) => (
                    <div
                        className={`${
                            t.visible ? 'animate-enter' : 'animate-leave'
                        } max-w-sm w-full bg-slate-800 border border-slate-700 shadow-2xl rounded-xl pointer-events-auto flex items-center gap-3 p-4`}
                    >
                        <div className="flex-shrink-0 p-2 rounded-lg bg-green-500/10">
                            <CheckCircle className="w-5 h-5 text-green-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-semibold text-white">
                                {format.toUpperCase()} Report Ready
                            </p>
                            <p className="text-xs text-slate-400 truncate">{filename}</p>
                        </div>
                        <button
                            onClick={() => {
                                // Open the downloaded file in a new tab
                                window.open(blobUrl, '_blank');
                                toast.dismiss(t.id);
                            }}
                            className="flex-shrink-0 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-600 text-white text-xs font-bold transition-colors whitespace-nowrap"
                        >
                            Open Report
                        </button>
                        <button
                            onClick={() => {
                                toast.dismiss(t.id);
                                // Revoke after dismiss
                                setTimeout(() => window.URL.revokeObjectURL(blobUrl), 1000);
                            }}
                            className="flex-shrink-0 p-1 rounded hover:bg-slate-700 transition-colors"
                        >
                            <X className="w-4 h-4 text-slate-500" />
                        </button>
                    </div>
                ),
                { duration: 10000, position: 'top-right' }
            );

            // Revoke blob URL after toast disappears (cleanup)
            setTimeout(() => window.URL.revokeObjectURL(blobUrl), 12000);

            onClose();
        } catch (e: any) {
            const msg = e.response?.data?.message || e.message || 'Failed to generate report';
            toast.error(msg);
        } finally {
            setDownloading(false);
        }
    };

    const formats: Array<{ id: ReportFormat; label: string; desc: string; icon: any }> = [
        { id: 'pdf', label: 'PDF', desc: 'Professional report with Burp-style panels', icon: FileText },
        { id: 'docx', label: 'DOCX', desc: 'Editable Word document', icon: FileSpreadsheet },
        { id: 'pptx', label: 'PPTX', desc: 'Presentation for security briefings', icon: Presentation },
    ];

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
            >
                <motion.div
                    initial={{ scale: 0.95, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.95, opacity: 0, y: 20 }}
                    className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between p-5 border-b border-slate-800">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-xl bg-cyan-500/10">
                                <Download className="w-5 h-5 text-cyan-400" />
                            </div>
                            <div>
                                <h2 className="text-lg font-bold text-white">Export Report</h2>
                                <p className="text-xs text-slate-500">Choose format and options</p>
                            </div>
                        </div>
                        <button onClick={onClose} className="p-2 rounded-lg hover:bg-slate-800 transition-colors">
                            <X className="w-5 h-5 text-slate-400" />
                        </button>
                    </div>

                    <div className="p-5 space-y-6">
                        {/* Report Mode */}
                        <div>
                            <label className="text-sm font-semibold text-slate-300 mb-3 block">Report Mode</label>
                            <div className="grid grid-cols-2 gap-3">
                                {/* Static */}
                                <button
                                    onClick={() => { setMode('static'); setImageProcessing(false); }}
                                    className={`relative p-4 rounded-xl border-2 transition-all text-left ${mode === 'static'
                                        ? 'border-cyan-500 bg-cyan-500/10'
                                        : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                        }`}
                                >
                                    <Zap className={`w-5 h-5 mb-2 ${mode === 'static' ? 'text-cyan-400' : 'text-slate-500'}`} />
                                    <div className={`font-bold text-sm ${mode === 'static' ? 'text-white' : 'text-slate-300'}`}>
                                        Static Report
                                    </div>
                                    <div className="text-xs text-slate-500 mt-1">
                                        Instant generation, pattern-based highlights
                                    </div>
                                </button>

                                {/* LLM-Driven */}
                                <button
                                    onClick={() => {
                                        if (capabilities?.llmAvailable) {
                                            setMode('llm');
                                        }
                                    }}
                                    disabled={!capabilities?.llmAvailable}
                                    className={`relative p-4 rounded-xl border-2 transition-all text-left ${mode === 'llm'
                                        ? 'border-purple-500 bg-purple-500/10'
                                        : capabilities?.llmAvailable
                                            ? 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                            : 'border-slate-800 bg-slate-900/50 opacity-50 cursor-not-allowed'
                                        }`}
                                >
                                    {mode === 'llm' && (
                                        <div className="absolute top-2 right-2">
                                            <Sparkles className="w-4 h-4 text-purple-400 animate-pulse" />
                                        </div>
                                    )}
                                    <Brain className={`w-5 h-5 mb-2 ${mode === 'llm' ? 'text-purple-400' : 'text-slate-500'}`} />
                                    <div className={`font-bold text-sm ${mode === 'llm' ? 'text-white' : 'text-slate-300'}`}>
                                        LLM-Driven Report
                                    </div>
                                    <div className="text-xs text-slate-500 mt-1">
                                        {capabilities?.llmAvailable
                                            ? 'AI-enhanced descriptions & analysis'
                                            : 'No active LLM configured'
                                        }
                                    </div>
                                    {capabilities?.llmAvailable && (
                                        <div className="mt-2 text-[10px] text-slate-600 font-mono">
                                            {capabilities.provider}/{capabilities.model}
                                        </div>
                                    )}
                                </button>
                            </div>
                        </div>

                        {/* Image Processing (only for LLM mode) */}
                        {mode === 'llm' && (
                            <motion.div
                                initial={{ opacity: 0, height: 0 }}
                                animate={{ opacity: 1, height: 'auto' }}
                                exit={{ opacity: 0, height: 0 }}
                            >
                                <div
                                    onClick={() => {
                                        if (capabilities?.visionSupported) {
                                            setImageProcessing(!imageProcessing);
                                        }
                                    }}
                                    className={`flex items-center justify-between p-4 rounded-xl border-2 transition-all cursor-pointer ${imageProcessing
                                        ? 'border-purple-500 bg-purple-500/5'
                                        : capabilities?.visionSupported
                                            ? 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                            : 'border-slate-800 bg-slate-900/50 opacity-50 cursor-not-allowed'
                                        }`}
                                >
                                    <div className="flex items-center gap-3">
                                        <Eye className={`w-5 h-5 ${imageProcessing ? 'text-purple-400' : 'text-slate-500'}`} />
                                        <div>
                                            <div className={`font-bold text-sm ${imageProcessing ? 'text-white' : 'text-slate-300'}`}>
                                                AI Vision Analysis
                                            </div>
                                            <div className="text-xs text-slate-500">
                                                {capabilities?.visionSupported
                                                    ? 'Screenshot capture + LLM-powered highlight detection'
                                                    : `Vision not supported by ${capabilities?.provider}/${capabilities?.model}`
                                                }
                                            </div>
                                        </div>
                                    </div>
                                    <div className={`w-10 h-6 rounded-full transition-colors relative ${imageProcessing ? 'bg-purple-500' : 'bg-slate-700'
                                        }`}>
                                        <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${imageProcessing ? 'left-5' : 'left-1'
                                            }`} />
                                    </div>
                                </div>
                            </motion.div>
                        )}

                        {/* Format Selection */}
                        <div>
                            <label className="text-sm font-semibold text-slate-300 mb-3 block">Format</label>
                            <div className="grid grid-cols-3 gap-3">
                                {formats.map(f => {
                                    const Icon = f.icon;
                                    return (
                                        <button
                                            key={f.id}
                                            onClick={() => setFormat(f.id)}
                                            className={`p-3 rounded-xl border-2 transition-all text-center ${format === f.id
                                                ? 'border-cyan-500 bg-cyan-500/10'
                                                : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                                }`}
                                        >
                                            <Icon className={`w-6 h-6 mx-auto mb-1.5 ${format === f.id ? 'text-cyan-400' : 'text-slate-500'
                                                }`} />
                                            <div className={`font-bold text-sm ${format === f.id ? 'text-white' : 'text-slate-300'}`}>
                                                {f.label}
                                            </div>
                                            <div className="text-[10px] text-slate-500 mt-1">{f.desc}</div>
                                        </button>
                                    );
                                })}
                            </div>
                        </div>

                        {/* LLM-Driven Info Box */}
                        {mode === 'llm' && (
                            <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                className="p-3 rounded-lg bg-purple-500/5 border border-purple-500/20 text-xs text-slate-400"
                            >
                                <div className="flex items-start gap-2">
                                    <Sparkles className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                                    <div>
                                        <span className="font-bold text-purple-300">LLM-Driven Mode</span> enhances your report with:
                                        <ul className="mt-1 ml-3 space-y-0.5 list-disc text-slate-500">
                                            <li>Professionally rewritten vulnerability descriptions</li>
                                            <li>Specific, actionable remediation advice with code examples</li>
                                            <li>AI-analyzed evidence highlights in request/response</li>
                                            {imageProcessing && <li>Vision-powered screenshot analysis and annotations</li>}
                                        </ul>
                                        <div className="mt-2 text-[10px] text-slate-600">
                                            This will use your active LLM ({capabilities?.provider}) and may take 1-3 minutes.
                                        </div>
                                    </div>
                                </div>
                            </motion.div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between p-5 border-t border-slate-800 bg-slate-900/50">
                        <a
                            href="https://github.com/onurgule/penpard"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[10px] text-slate-600 hover:text-slate-400 flex items-center gap-1 transition-colors"
                        >
                            <ExternalLink className="w-3 h-3" />
                            github.com/onurgule/penpard
                        </a>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={onClose}
                                className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:bg-slate-800 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleDownload}
                                disabled={downloading}
                                className={`px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 transition-all ${downloading
                                    ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                                    : mode === 'llm'
                                        ? 'bg-gradient-to-r from-purple-500 to-cyan-500 text-white hover:from-purple-600 hover:to-cyan-600 shadow-lg shadow-purple-500/25'
                                        : 'bg-cyan-500 text-white hover:bg-cyan-600 shadow-lg shadow-cyan-500/25'
                                    }`}
                            >
                                {downloading ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        {mode === 'llm' ? 'AI is enhancing...' : 'Generating...'}
                                    </>
                                ) : (
                                    <>
                                        <Download className="w-4 h-4" />
                                        Export {format.toUpperCase()}
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}
