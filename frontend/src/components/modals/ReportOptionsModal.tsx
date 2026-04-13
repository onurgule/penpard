'use client';

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    X, Download, FileText, Presentation, FileSpreadsheet,
    Sparkles, Loader2, ExternalLink, Zap, Brain, CheckCircle, AlertTriangle, RotateCcw, Ban,
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import {
    type ReportEnrichmentMode,
    type ReportExportFormat,
    type ReportExportJob,
    getReportExportStageDisplay,
    getReportLlmStatusDisplay,
    isTerminalReportExport,
    pickPreferredReportExportJob,
    shouldPollReportExport,
} from '@/lib/report-export';

interface ReportOptionsModalProps {
    isOpen: boolean;
    onClose: () => void;
    scanId: string;
}

interface Capabilities {
    llmAvailable: boolean;
    visionSupported: boolean;
    provider: string;
    model: string;
}

export default function ReportOptionsModal({ isOpen, onClose, scanId }: ReportOptionsModalProps) {
    const { token } = useAuthStore();
    const [format, setFormat] = useState<ReportExportFormat>('pdf');
    const [enrichmentMode, setEnrichmentMode] = useState<ReportEnrichmentMode>('deterministic');
    const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
    const [jobs, setJobs] = useState<ReportExportJob[]>([]);
    const [loadingCaps, setLoadingCaps] = useState(false);
    const [loadingJobs, setLoadingJobs] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [downloading, setDownloading] = useState(false);

    const selectedJob = pickPreferredReportExportJob(jobs, format, enrichmentMode);

    useEffect(() => {
        if (!isOpen) return;

        void loadCapabilities();
        void loadJobs();
    }, [isOpen, scanId, token]);

    useEffect(() => {
        if (!isOpen || !selectedJob || !shouldPollReportExport(selectedJob)) {
            return;
        }

        const interval = setInterval(() => {
            void refreshJob(selectedJob.id);
        }, 2000);

        return () => clearInterval(interval);
    }, [isOpen, selectedJob?.id, selectedJob?.status, selectedJob?.stage, token, scanId]);

    async function loadCapabilities() {
        setLoadingCaps(true);
        try {
            const response = await axios.get(`${API_URL}/reports/capabilities/check`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setCapabilities(response.data);
            if (!response.data.llmAvailable && enrichmentMode === 'llm') {
                setEnrichmentMode('deterministic');
            }
        } catch {
            setCapabilities({ llmAvailable: false, visionSupported: false, provider: 'none', model: 'none' });
            setEnrichmentMode('deterministic');
        } finally {
            setLoadingCaps(false);
        }
    }

    async function loadJobs() {
        setLoadingJobs(true);
        try {
            const response = await axios.get(`${API_URL}/reports/${scanId}/exports`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setJobs(response.data.exports || []);
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to load export jobs');
        } finally {
            setLoadingJobs(false);
        }
    }

    async function refreshJob(jobId: string) {
        try {
            const response = await axios.get(`${API_URL}/reports/${scanId}/exports/${jobId}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            mergeJob(response.data.export);
        } catch {
            // keep polling resilient; the next cycle may succeed
        }
    }

    async function handleCreateOrReuseExport() {
        await createExport(false);
    }

    async function handleRegenerate() {
        await createExport(true);
    }

    async function createExport(forceRegenerate: boolean) {
        setSubmitting(true);
        try {
            const response = await axios.post(`${API_URL}/reports/${scanId}/exports`, {
                format,
                enrichmentMode,
                forceRegenerate,
            }, {
                headers: { Authorization: `Bearer ${token}` },
            });
            mergeJob(response.data.export);
            toast.success(forceRegenerate ? 'Report regeneration started' : 'Export job created');
        } catch (error: any) {
            toast.error(error.response?.data?.message || (forceRegenerate ? 'Failed to regenerate export' : 'Failed to create export job'));
        } finally {
            setSubmitting(false);
        }
    }

    async function handleRetry() {
        if (!selectedJob) return;
        setSubmitting(true);
        try {
            const response = await axios.post(`${API_URL}/reports/${scanId}/exports/${selectedJob.id}/retry`, {}, {
                headers: { Authorization: `Bearer ${token}` },
            });
            mergeJob(response.data.export);
            toast.success('Export retry started');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to retry export');
        } finally {
            setSubmitting(false);
        }
    }

    async function handleCancel() {
        if (!selectedJob) return;
        setSubmitting(true);
        try {
            const response = await axios.post(`${API_URL}/reports/${scanId}/exports/${selectedJob.id}/cancel`, {}, {
                headers: { Authorization: `Bearer ${token}` },
            });
            mergeJob(response.data.export);
            toast.success('Export canceled');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to cancel export');
        } finally {
            setSubmitting(false);
        }
    }

    async function handleDownload() {
        if (!selectedJob) return;

        setDownloading(true);
        try {
            const response = await axios.get(`${API_URL}/reports/${scanId}/exports/${selectedJob.id}/download`, {
                headers: { Authorization: `Bearer ${token}` },
                responseType: 'blob',
            });

            const blob = new Blob([response.data]);
            const blobUrl = window.URL.createObjectURL(blob);
            const filename = `PenPard-Report-${scanId}.${selectedJob.format}`;

            const link = document.createElement('a');
            link.href = blobUrl;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();

            toast.success(`${selectedJob.format.toUpperCase()} download started`);
            setTimeout(() => window.URL.revokeObjectURL(blobUrl), 15000);
        } catch (error: any) {
            toast.error(await readBlobError(error, 'Failed to download export'));
        } finally {
            setDownloading(false);
        }
    }

    function mergeJob(job: ReportExportJob) {
        setJobs((previous) => {
            const others = previous.filter((entry) => entry.id !== job.id);
            return [job, ...others];
        });
    }

    const formats: Array<{ id: ReportExportFormat; label: string; desc: string; icon: any }> = [
        { id: 'pdf', label: 'PDF', desc: 'Deterministic document export', icon: FileText },
        { id: 'docx', label: 'DOCX', desc: 'Editable Word document', icon: FileSpreadsheet },
        { id: 'pptx', label: 'PPTX', desc: 'Presentation-ready slides', icon: Presentation },
    ];

    const stageDisplay = getReportExportStageDisplay(selectedJob);
    const llmStatusDisplay = getReportLlmStatusDisplay(selectedJob);
    const activeJob = !!selectedJob && !isTerminalReportExport(selectedJob);
    const primaryBusy = submitting || downloading;

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
                onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}
            >
                <motion.div
                    initial={{ scale: 0.95, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.95, opacity: 0, y: 20 }}
                    className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl"
                >
                    <div className="flex items-center justify-between p-5 border-b border-slate-800">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded-xl bg-cyan-500/10">
                                <Download className="w-5 h-5 text-cyan-400" />
                            </div>
                            <div>
                                <h2 className="text-lg font-bold text-white">Export Report</h2>
                                <p className="text-xs text-slate-500">Persisted export jobs with resumable status</p>
                            </div>
                        </div>
                        <button onClick={onClose} className="p-2 rounded-lg hover:bg-slate-800 transition-colors">
                            <X className="w-5 h-5 text-slate-400" />
                        </button>
                    </div>

                    <div className="p-5 space-y-6">
                        <div className="grid md:grid-cols-2 gap-4">
                            <div>
                                <label className="text-sm font-semibold text-slate-300 mb-3 block">Report Mode</label>
                                <div className="grid grid-cols-2 gap-3">
                                    <button
                                        onClick={() => setEnrichmentMode('deterministic')}
                                        disabled={activeJob}
                                        className={`relative p-4 rounded-xl border-2 transition-all text-left ${enrichmentMode === 'deterministic'
                                            ? 'border-cyan-500 bg-cyan-500/10'
                                            : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                            } ${activeJob ? 'opacity-70 cursor-not-allowed' : ''}`}
                                    >
                                        <Zap className={`w-5 h-5 mb-2 ${enrichmentMode === 'deterministic' ? 'text-cyan-400' : 'text-slate-500'}`} />
                                        <div className={`font-bold text-sm ${enrichmentMode === 'deterministic' ? 'text-white' : 'text-slate-300'}`}>
                                            Deterministic
                                        </div>
                                        <div className="text-xs text-slate-500 mt-1">
                                            No LLM required. Always renders from the persisted findings snapshot.
                                        </div>
                                    </button>

                                    <button
                                        onClick={() => capabilities?.llmAvailable && setEnrichmentMode('llm')}
                                        disabled={activeJob || !capabilities?.llmAvailable}
                                        className={`relative p-4 rounded-xl border-2 transition-all text-left ${enrichmentMode === 'llm'
                                            ? 'border-purple-500 bg-purple-500/10'
                                            : capabilities?.llmAvailable
                                                ? 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                                : 'border-slate-800 bg-slate-900/50 opacity-50 cursor-not-allowed'
                                            } ${activeJob ? 'opacity-70 cursor-not-allowed' : ''}`}
                                    >
                                        <Brain className={`w-5 h-5 mb-2 ${enrichmentMode === 'llm' ? 'text-purple-400' : 'text-slate-500'}`} />
                                        <div className={`font-bold text-sm ${enrichmentMode === 'llm' ? 'text-white' : 'text-slate-300'}`}>
                                            LLM-Assisted
                                        </div>
                                        <div className="text-xs text-slate-500 mt-1">
                                            Structured narrative enrichment with deterministic fallback on failure.
                                        </div>
                                        {capabilities?.llmAvailable && (
                                            <div className="mt-2 text-[10px] text-slate-600 font-mono">
                                                {capabilities.provider}/{capabilities.model}
                                            </div>
                                        )}
                                    </button>
                                </div>
                            </div>

                            <div>
                                <label className="text-sm font-semibold text-slate-300 mb-3 block">Format</label>
                                <div className="grid grid-cols-3 gap-3">
                                    {formats.map((entry) => {
                                        const Icon = entry.icon;
                                        return (
                                            <button
                                                key={entry.id}
                                                onClick={() => setFormat(entry.id)}
                                                disabled={activeJob}
                                                className={`p-3 rounded-xl border-2 transition-all text-center ${format === entry.id
                                                    ? 'border-cyan-500 bg-cyan-500/10'
                                                    : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                                                    } ${activeJob ? 'opacity-70 cursor-not-allowed' : ''}`}
                                            >
                                                <Icon className={`w-6 h-6 mx-auto mb-1.5 ${format === entry.id ? 'text-cyan-400' : 'text-slate-500'}`} />
                                                <div className={`font-bold text-sm ${format === entry.id ? 'text-white' : 'text-slate-300'}`}>
                                                    {entry.label}
                                                </div>
                                                <div className="text-[10px] text-slate-500 mt-1">{entry.desc}</div>
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>

                        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                            <div className="flex items-center justify-between gap-4">
                                <div>
                                    <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Current Job</div>
                                    <div className="text-base font-semibold text-white mt-1">{stageDisplay}</div>
                                </div>
                                {selectedJob ? (
                                    <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                                        selectedJob.status === 'completed'
                                            ? 'border-green-500/30 bg-green-500/10 text-green-300'
                                            : selectedJob.status === 'failed'
                                                ? 'border-red-500/30 bg-red-500/10 text-red-300'
                                                : selectedJob.status === 'canceled'
                                                    ? 'border-slate-500/30 bg-slate-500/10 text-slate-300'
                                                    : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
                                    }`}>
                                        {selectedJob.status}
                                    </span>
                                ) : (
                                    <span className="px-3 py-1 rounded-full text-xs font-bold border border-slate-700 bg-slate-800 text-slate-300">
                                        ready
                                    </span>
                                )}
                            </div>

                            {selectedJob ? (
                                <div className="space-y-2 text-sm text-slate-300">
                                    <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500">
                                        <span>Attempts: {selectedJob.attemptCount}</span>
                                        <span>Created: {new Date(selectedJob.createdAt).toLocaleString()}</span>
                                        {selectedJob.completedAt && <span>Completed: {new Date(selectedJob.completedAt).toLocaleString()}</span>}
                                    </div>
                                    {selectedJob.errorMessage && (
                                        <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-red-200 text-sm">
                                            {selectedJob.errorMessage}
                                        </div>
                                    )}
                                    {llmStatusDisplay && (
                                        <div className={`rounded-lg px-3 py-2 text-sm border ${
                                            selectedJob.llmStatus === 'failed'
                                                ? 'border-amber-500/20 bg-amber-500/10 text-amber-200'
                                                : 'border-purple-500/20 bg-purple-500/10 text-purple-200'
                                        }`}>
                                            {llmStatusDisplay}
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="text-sm text-slate-400">
                                    No export exists yet for this format/mode combination. Starting one will create or reuse a persisted backend job.
                                </div>
                            )}
                        </div>

                        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 text-xs text-slate-400">
                            <div className="flex items-start gap-2">
                                <Sparkles className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                                <div className="space-y-1">
                                    <div>
                                        Deterministic mode always succeeds without an LLM as long as rendering succeeds.
                                    </div>
                                    <div>
                                        LLM-assisted mode validates structured narrative output before rendering and falls back to the deterministic base report if enrichment fails.
                                    </div>
                                    {!loadingCaps && capabilities && (
                                        <div className="text-[11px] text-slate-500">
                                            Active provider: {capabilities.llmAvailable ? `${capabilities.provider}/${capabilities.model}` : 'none'}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                            <div className="flex items-center justify-between mb-3">
                                <div className="text-sm font-semibold text-white">Recent Jobs</div>
                                <button
                                    onClick={() => void loadJobs()}
                                    className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                                    disabled={loadingJobs}
                                >
                                    {loadingJobs ? 'Refreshing...' : 'Refresh'}
                                </button>
                            </div>

                            {jobs.length === 0 ? (
                                <div className="text-sm text-slate-500">No export jobs have been created for this scan yet.</div>
                            ) : (
                                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                                    {jobs.map((job) => (
                                        <button
                                            key={job.id}
                                            onClick={() => {
                                                setFormat(job.format);
                                                setEnrichmentMode(job.enrichmentMode);
                                            }}
                                            className={`w-full text-left rounded-lg border px-3 py-2 transition-colors ${
                                                selectedJob?.id === job.id
                                                    ? 'border-cyan-500/40 bg-cyan-500/10'
                                                    : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                                            }`}
                                        >
                                            <div className="flex items-center justify-between gap-3">
                                                <div className="text-sm text-white font-medium">
                                                    {job.format.toUpperCase()} / {job.enrichmentMode === 'llm' ? 'LLM-assisted' : 'Deterministic'}
                                                </div>
                                                <div className="text-xs text-slate-400">{job.status}</div>
                                            </div>
                                            <div className="text-xs text-slate-500 mt-1">{getReportExportStageDisplay(job)}</div>
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

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
                            {selectedJob && !isTerminalReportExport(selectedJob) && (
                                <button
                                    onClick={() => void handleCancel()}
                                    disabled={primaryBusy}
                                    className="px-4 py-2 rounded-lg text-sm text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
                                >
                                    <span className="inline-flex items-center gap-2">
                                        <Ban className="w-4 h-4" />
                                        Cancel
                                    </span>
                                </button>
                            )}

                            {selectedJob?.status === 'failed' && (
                                <button
                                    onClick={() => void handleRetry()}
                                    disabled={primaryBusy}
                                    className="px-4 py-2 rounded-lg text-sm text-white bg-slate-700 hover:bg-slate-600 transition-colors disabled:opacity-50"
                                >
                                    <span className="inline-flex items-center gap-2">
                                        <RotateCcw className="w-4 h-4" />
                                        Retry
                                    </span>
                                </button>
                            )}

                            <button
                                onClick={onClose}
                                className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:bg-slate-800 transition-colors"
                            >
                                Close
                            </button>

                            {selectedJob?.status === 'completed' && selectedJob.artifactReady ? (
                                <>
                                    <button
                                        onClick={() => void handleRegenerate()}
                                        disabled={primaryBusy}
                                        className="px-4 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 bg-slate-700 text-white hover:bg-slate-600 transition-colors disabled:opacity-50"
                                    >
                                        {submitting ? (
                                            <>
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                                Regenerating...
                                            </>
                                        ) : (
                                            <>
                                                <RotateCcw className="w-4 h-4" />
                                                Regenerate
                                            </>
                                        )}
                                    </button>

                                    <button
                                        onClick={() => void handleDownload()}
                                        disabled={primaryBusy}
                                        className="px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 bg-green-500 text-white hover:bg-green-600 shadow-lg shadow-green-500/25 disabled:opacity-50"
                                    >
                                        {downloading ? (
                                            <>
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                                Downloading...
                                            </>
                                        ) : (
                                            <>
                                                <CheckCircle className="w-4 h-4" />
                                                Download {selectedJob.format.toUpperCase()}
                                            </>
                                        )}
                                    </button>
                                </>
                            ) : selectedJob?.status === 'failed' ? (
                                <button
                                    onClick={() => void handleRetry()}
                                    disabled={primaryBusy}
                                    className="px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 bg-red-500 text-white hover:bg-red-600 shadow-lg shadow-red-500/25 disabled:opacity-50"
                                >
                                    <AlertTriangle className="w-4 h-4" />
                                    Retry Export
                                </button>
                            ) : selectedJob?.status === 'canceled' ? (
                                <button
                                    onClick={() => void handleCreateOrReuseExport()}
                                    disabled={primaryBusy}
                                    className="px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 bg-cyan-500 text-white hover:bg-cyan-600 shadow-lg shadow-cyan-500/25 disabled:opacity-50"
                                >
                                    <Download className="w-4 h-4" />
                                    Start New Export
                                </button>
                            ) : selectedJob ? (
                                <button
                                    disabled
                                    className="px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 bg-slate-700 text-slate-300 cursor-not-allowed"
                                >
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    {stageDisplay}
                                </button>
                            ) : (
                                <button
                                    onClick={() => void handleCreateOrReuseExport()}
                                    disabled={primaryBusy || (enrichmentMode === 'llm' && !capabilities?.llmAvailable)}
                                    className={`px-6 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 transition-all ${
                                        primaryBusy
                                            ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                                            : enrichmentMode === 'llm'
                                                ? 'bg-gradient-to-r from-purple-500 to-cyan-500 text-white hover:from-purple-600 hover:to-cyan-600 shadow-lg shadow-purple-500/25'
                                                : 'bg-cyan-500 text-white hover:bg-cyan-600 shadow-lg shadow-cyan-500/25'
                                    }`}
                                >
                                    {submitting ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            Creating Job...
                                        </>
                                    ) : (
                                        <>
                                            <Download className="w-4 h-4" />
                                            Start Export
                                        </>
                                    )}
                                </button>
                            )}
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}

async function readBlobError(error: any, fallback: string): Promise<string> {
    const data = error?.response?.data;
    if (data instanceof Blob) {
        try {
            const text = await data.text();
            const parsed = JSON.parse(text);
            return parsed.message || fallback;
        } catch {
            return fallback;
        }
    }

    return error?.response?.data?.message || error?.message || fallback;
}
