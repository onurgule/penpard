'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import axios from 'axios';
import toast from 'react-hot-toast';
import {
    ArrowLeft,
    Smartphone,
    Upload,
    Shield,
    Loader2,
    CheckCircle,
    XCircle,
    FileText,
    X,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';

interface ScanStatus {
    id: string | null;
    status: 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';
    message: string;
    progress: number;
    vulnerabilities: any[];
}

export default function MobileScanPage() {
    const router = useRouter();
    const { isAuthenticated } = useAuthStore();

    const [file, setFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [scanStatus, setScanStatus] = useState<ScanStatus>({
        id: null,
        status: 'idle',
        message: '',
        progress: 0,
        vulnerabilities: [],
    });

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
            return;
        }
    }, [isAuthenticated, router]);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);

        const droppedFile = e.dataTransfer.files[0];
        if (droppedFile && droppedFile.name.endsWith('.apk')) {
            setFile(droppedFile);
        } else {
            toast.error('Please upload an APK file');
        }
    }, []);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0];
        if (selectedFile && selectedFile.name.endsWith('.apk')) {
            setFile(selectedFile);
        } else {
            toast.error('Please upload an APK file');
        }
    };

    const handleStartScan = async () => {
        if (!file) {
            toast.error('Please upload an APK file');
            return;
        }

        setScanStatus({
            id: null,
            status: 'uploading',
            message: 'Uploading APK file...',
            progress: 10,
            vulnerabilities: [],
        });

        try {
            const formData = new FormData();
            formData.append('apk', file);

            const response = await axios.post(`${API_URL}/scans/mobile`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
                onUploadProgress: (progressEvent) => {
                    const percentCompleted = Math.round(
                        (progressEvent.loaded * 100) / (progressEvent.total || 1)
                    );
                    setScanStatus((prev) => ({
                        ...prev,
                        progress: Math.min(percentCompleted * 0.3, 30),
                        message: `Uploading: ${percentCompleted}%`,
                    }));
                },
            });

            const { scanId } = response.data;

            setScanStatus((prev) => ({
                ...prev,
                id: scanId,
                status: 'analyzing',
                message: 'Analyzing with MobSF...',
                progress: 35,
            }));

            // Poll for scan status
            pollScanStatus(scanId);

        } catch (error: any) {
            const message = error.response?.data?.message || 'Failed to start scan';
            setScanStatus({
                id: null,
                status: 'error',
                message,
                progress: 0,
                vulnerabilities: [],
            });
            toast.error(message);
        }
    };

    const pollScanStatus = async (scanId: string) => {
        let attempts = 0;
        const maxAttempts = 60;

        const poll = async () => {
            try {
                const response = await axios.get(`${API_URL}/scans/${scanId}`);
                const { status, vulnerabilities, message } = response.data;

                if (status === 'completed') {
                    setScanStatus({
                        id: scanId,
                        status: 'complete',
                        message: 'Analysis completed successfully!',
                        progress: 100,
                        vulnerabilities: vulnerabilities || [],
                    });
                    toast.success('Analysis completed!');
                    return;
                }

                if (status === 'failed') {
                    setScanStatus({
                        id: scanId,
                        status: 'error',
                        message: message || 'Analysis failed',
                        progress: 0,
                        vulnerabilities: [],
                    });
                    toast.error('Analysis failed');
                    return;
                }

                const progressMap: Record<string, number> = {
                    uploaded: 35,
                    analyzing: 50,
                    permissions: 60,
                    components: 70,
                    code_analysis: 80,
                    reporting: 90,
                };

                setScanStatus((prev) => ({
                    ...prev,
                    message: `Status: ${status}`,
                    progress: progressMap[status] || prev.progress,
                }));

                attempts++;
                if (attempts < maxAttempts) {
                    setTimeout(poll, 5000);
                } else {
                    setScanStatus((prev) => ({
                        ...prev,
                        status: 'error',
                        message: 'Analysis timed out',
                    }));
                }
            } catch (error) {
                attempts++;
                if (attempts < maxAttempts) {
                    setTimeout(poll, 5000);
                }
            }
        };

        poll();
    };

    const getSeverityClass = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'severity-critical';
            case 'high':
                return 'severity-high';
            case 'medium':
                return 'severity-medium';
            case 'low':
                return 'severity-low';
            default:
                return 'severity-info';
        }
    };

    const isScanning = ['uploading', 'analyzing'].includes(scanStatus.status);

    return (
        <div className="min-h-screen">
            {/* Header */}
            <header className="glass-darker border-b border-dark-600/50 sticky top-10 z-40">
                <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link
                        href="/dashboard"
                        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
                    >
                        <ArrowLeft className="w-5 h-5" />
                        <span>Back to Dashboard</span>
                    </Link>
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-4xl mx-auto px-4 py-8">
                {/* Title */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30 mb-4">
                        <Smartphone className="w-8 h-8 text-purple-400" />
                    </div>
                    <h1 className="text-3xl font-bold text-white mb-2">Mobile App Scan</h1>
                    <p className="text-gray-400">Upload an Android APK for security analysis</p>
                </div>

                {/* Upload Zone */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="card p-6 mb-8"
                >
                    <div
                        onDrop={handleDrop}
                        onDragOver={(e) => {
                            e.preventDefault();
                            setIsDragging(true);
                        }}
                        onDragLeave={() => setIsDragging(false)}
                        className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-colors ${isDragging
                                ? 'border-purple-500 bg-purple-500/10'
                                : file
                                    ? 'border-green-500/50 bg-green-500/5'
                                    : 'border-dark-600 hover:border-purple-500/50'
                            } ${isScanning ? 'opacity-50 pointer-events-none' : ''}`}
                    >
                        <input
                            type="file"
                            accept=".apk"
                            onChange={handleFileChange}
                            disabled={isScanning}
                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed"
                        />

                        {file ? (
                            <div className="flex items-center justify-center gap-4">
                                <FileText className="w-10 h-10 text-green-400" />
                                <div className="text-left">
                                    <p className="text-white font-medium">{file.name}</p>
                                    <p className="text-gray-400 text-sm">
                                        {(file.size / (1024 * 1024)).toFixed(2)} MB
                                    </p>
                                </div>
                                {!isScanning && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            setFile(null);
                                        }}
                                        className="p-2 rounded-lg bg-dark-700 text-gray-400 hover:text-red-400 hover:bg-dark-600 transition-colors"
                                    >
                                        <X className="w-5 h-5" />
                                    </button>
                                )}
                            </div>
                        ) : (
                            <>
                                <Upload className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                                <p className="text-white font-medium mb-2">
                                    Drag & drop or click to upload
                                </p>
                                <p className="text-gray-500 text-sm">APK files only</p>
                            </>
                        )}
                    </div>

                    {file && scanStatus.status === 'idle' && (
                        <button
                            onClick={handleStartScan}
                            className="w-full mt-4 btn-primary flex items-center justify-center gap-2"
                        >
                            <Shield className="w-5 h-5" />
                            <span>Start Analysis</span>
                        </button>
                    )}
                </motion.div>

                {/* Scan Progress */}
                {scanStatus.status !== 'idle' && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6 mb-8"
                    >
                        <div className="flex items-center gap-4 mb-4">
                            {scanStatus.status === 'complete' ? (
                                <CheckCircle className="w-6 h-6 text-green-400" />
                            ) : scanStatus.status === 'error' ? (
                                <XCircle className="w-6 h-6 text-red-400" />
                            ) : (
                                <Loader2 className="w-6 h-6 text-purple-400 animate-spin" />
                            )}
                            <div className="flex-1">
                                <h3 className="text-lg font-semibold text-white">
                                    {scanStatus.status === 'complete'
                                        ? 'Analysis Complete'
                                        : scanStatus.status === 'error'
                                            ? 'Analysis Failed'
                                            : 'Analyzing...'}
                                </h3>
                                <p className="text-gray-400 text-sm">{scanStatus.message}</p>
                            </div>
                        </div>

                        <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${scanStatus.progress}%` }}
                                transition={{ duration: 0.5 }}
                                className={`h-full rounded-full ${scanStatus.status === 'error'
                                        ? 'bg-red-500'
                                        : scanStatus.status === 'complete'
                                            ? 'bg-green-500'
                                            : 'bg-gradient-to-r from-purple-500 to-pink-500'
                                    }`}
                            />
                        </div>
                    </motion.div>
                )}

                {/* Vulnerabilities */}
                {scanStatus.vulnerabilities.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6"
                    >
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
                            <Shield className="w-5 h-5 text-red-400" />
                            Findings ({scanStatus.vulnerabilities.length})
                        </h3>

                        <div className="space-y-3">
                            {scanStatus.vulnerabilities.map((vuln, index) => (
                                <div
                                    key={index}
                                    className="p-4 bg-dark-800/50 rounded-lg border border-dark-600/50"
                                >
                                    <div className="flex items-start justify-between">
                                        <div>
                                            <h4 className="font-medium text-white">{vuln.name}</h4>
                                            <p className="text-gray-400 text-sm mt-1">{vuln.description}</p>
                                        </div>
                                        <span className={getSeverityClass(vuln.severity)}>
                                            {vuln.severity}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}

                {/* Info Section */}
                {scanStatus.status === 'idle' && !file && (
                    <div className="grid md:grid-cols-2 gap-4">
                        <div className="card p-4">
                            <h4 className="font-medium text-white mb-2">Mobile Top 10:</h4>
                            <ul className="text-gray-400 text-sm space-y-1">
                                <li>• Improper Platform Usage</li>
                                <li>• Insecure Data Storage</li>
                                <li>• Insecure Communication</li>
                                <li>• Insecure Authentication</li>
                                <li>• Insufficient Cryptography</li>
                            </ul>
                        </div>

                        <div className="card p-4">
                            <h4 className="font-medium text-white mb-2">Analysis includes:</h4>
                            <ul className="text-gray-400 text-sm space-y-1">
                                <li>• Manifest analysis</li>
                                <li>• Permission review</li>
                                <li>• Code security analysis</li>
                                <li>• Hardcoded secrets detection</li>
                                <li>• Network security configuration</li>
                            </ul>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
}
