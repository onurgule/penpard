'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import axios from 'axios';
import { motion } from 'framer-motion';
import toast from 'react-hot-toast';
import {
    ArrowLeft,
    CheckCircle,
    Download,
    Globe,
    Loader2,
    Shield,
    XCircle,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import { API_URL } from '@/lib/api-config';
import ReportOptionsModal from '@/components/modals/ReportOptionsModal';
import SourceModeSelector, { type SourceMode } from '@/components/SourceModeSelector';
import SourceProviderInput, { type SourceType } from '@/components/SourceProviderInput';
import {
    buildScopedSecurityTestRequest,
    createDefaultScopedRequestIntake,
    type ScopedRequestIntakeFormValues,
    validateScopedRequestIntake,
} from './scoped-request-intake';

const SOURCE_ANALYSIS_MODES: SourceMode[] = [
    {
        id: 'version_aware',
        title: 'Version Aware',
        description: [
            'Lightweight source intelligence',
            'Dependency and CVE-aware enrichment',
            'Good default for most launches',
        ],
        tokenCost: 'low',
        icon: 'zap',
    },
    {
        id: 'full_source_aware',
        title: 'Full Source Aware',
        description: [
            'Deeper route and flow awareness',
            'Richer security hints from source',
            'Higher token cost',
        ],
        tokenCost: 'high',
        icon: 'brain',
    },
];

const SCAN_OPTIONS_KEY = 'penpard-scan-options';

type ScanMode = 'exploratory' | 'scoped';
type AuthStartupMode = 'no_credentials' | 'provided_credentials';
type CredentialPrivilege = 'low' | 'high' | 'unknown';

interface StartupCredentialRow {
    username: string;
    email: string;
    password: string;
    role: string;
    privilege: CredentialPrivilege;
    label: string;
}

interface ScanStatus {
    id: string | null;
    status: 'idle' | 'validating' | 'scanning' | 'analyzing' | 'complete' | 'error';
    message: string;
    progress: number;
    vulnerabilities: any[];
}

function getDefaultScanOptions() {
    if (typeof window === 'undefined') return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
    try {
        const raw = localStorage.getItem(SCAN_OPTIONS_KEY);
        if (!raw) return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
        const parsed = JSON.parse(raw);
        return {
            iterations: Math.max(10, Math.min(500, Number(parsed.iterations) || 50)),
            parallelAgents: Math.max(1, Math.min(10, Number(parsed.parallelAgents) || 1)),
            rateLimit: Number(parsed.rateLimit) || 5,
            maxPlanRounds: Math.max(0, Math.min(99, Number(parsed.maxPlanRounds) || 0)),
        };
    } catch {
        return { iterations: 50, parallelAgents: 1, rateLimit: 5, maxPlanRounds: 0 };
    }
}

function createEmptyCredentialRow(): StartupCredentialRow {
    return {
        username: '',
        email: '',
        password: '',
        role: 'user',
        privilege: 'unknown',
        label: '',
    };
}

function getSeverityClass(severity: string) {
    switch (String(severity || '').toLowerCase()) {
        case 'critical':
            return 'px-2 py-0.5 rounded text-xs font-semibold border border-red-500/30 bg-red-500/10 text-red-300';
        case 'high':
            return 'px-2 py-0.5 rounded text-xs font-semibold border border-orange-500/30 bg-orange-500/10 text-orange-300';
        case 'medium':
            return 'px-2 py-0.5 rounded text-xs font-semibold border border-amber-500/30 bg-amber-500/10 text-amber-300';
        default:
            return 'px-2 py-0.5 rounded text-xs font-semibold border border-cyan-500/30 bg-cyan-500/10 text-cyan-300';
    }
}

function normalizeUrlInput(url: string): string {
    return url.startsWith('http') ? url : `https://${url}`;
}

export default function WebScanPage() {
    const router = useRouter();
    const { isAuthenticated } = useAuthStore();

    const [targetUrl, setTargetUrl] = useState('');
    const [scanInstructions, setScanInstructions] = useState('');
    const [scanMode, setScanMode] = useState<ScanMode>('exploratory');
    const [scopedRequest, setScopedRequest] = useState<ScopedRequestIntakeFormValues>(createDefaultScopedRequestIntake());
    const [sessionCookies, setSessionCookies] = useState('');
    const [authStartupMode, setAuthStartupMode] = useState<AuthStartupMode>('no_credentials');
    const [allowAccountCreation, setAllowAccountCreation] = useState(false);
    const [preferSharedPassword, setPreferSharedPassword] = useState(true);
    const [userAccounts, setUserAccounts] = useState<StartupCredentialRow[]>([createEmptyCredentialRow()]);
    const [rateLimit, setRateLimit] = useState(() => getDefaultScanOptions().rateLimit);
    const [parallelAgents, setParallelAgents] = useState(() => getDefaultScanOptions().parallelAgents);
    const [iterations, setIterations] = useState(() => getDefaultScanOptions().iterations);
    const [maxPlanRounds, setMaxPlanRounds] = useState(() => getDefaultScanOptions().maxPlanRounds);
    const [sourcePackagePath, setSourcePackagePath] = useState('');
    const [sourceAnalysisMode, setSourceAnalysisMode] = useState<string | null>(null);
    const [sourceType, setSourceType] = useState<SourceType>('local');
    const [zipFile, setZipFile] = useState<File | null>(null);
    const [gitUrl, setGitUrl] = useState('');
    const [gitToken, setGitToken] = useState('');
    const [externalTools, setExternalTools] = useState({
        nuclei: false,
        ffuf: false,
    });
    const [scanStatus, setScanStatus] = useState<ScanStatus>({
        id: null,
        status: 'idle',
        message: '',
        progress: 0,
        vulnerabilities: [],
    });
    const [reportModalOpen, setReportModalOpen] = useState(false);

    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    const isScanning = scanStatus.status === 'validating' || scanStatus.status === 'scanning' || scanStatus.status === 'analyzing';

    const validateUrl = (url: string) => {
        try {
            new URL(normalizeUrlInput(url));
            return true;
        } catch {
            return false;
        }
    };

    const handleCredentialChange = (index: number, field: keyof StartupCredentialRow, value: string) => {
        setUserAccounts((current) => current.map((account, accountIndex) => (
            accountIndex === index
                ? { ...account, [field]: value }
                : account
        )));
    };

    const handleAddCredential = () => {
        setUserAccounts((current) => [...current, createEmptyCredentialRow()]);
    };

    const handleRemoveCredential = (index: number) => {
        setUserAccounts((current) => current.length === 1
            ? [createEmptyCredentialRow()]
            : current.filter((_, accountIndex) => accountIndex !== index));
    };

    const handleStartScan = async () => {
        if (!targetUrl.trim()) {
            toast.error('Please enter a target URL.');
            return;
        }
        if (!validateUrl(targetUrl)) {
            toast.error('Invalid URL format.');
            return;
        }

        const normalizedTargetUrl = normalizeUrlInput(targetUrl.trim());
        if (scanMode === 'scoped') {
            const validationError = validateScopedRequestIntake(normalizedTargetUrl, scopedRequest);
            if (validationError) {
                toast.error(validationError);
                return;
            }
        }

        const providedCredentials = userAccounts
            .map((account) => ({
                username: account.username.trim(),
                email: account.email.trim(),
                password: account.password,
                role: account.role,
                privilege: account.privilege,
                label: account.label.trim(),
            }))
            .filter((account) => (account.username || account.email) && account.password.trim());

        if (scanMode !== 'scoped' && authStartupMode === 'provided_credentials' && providedCredentials.length === 0) {
            toast.error('Add at least one username/email and password for provided-credential startup.');
            return;
        }

        setScanStatus({
            id: null,
            status: 'validating',
            message: scanMode === 'scoped'
                ? 'Persisting request intake and preparing bounded feature discovery...'
                : 'Validating target and launching exploratory runtime...',
            progress: 10,
            vulnerabilities: [],
        });

        try {
            const formData = new FormData();
            formData.append('url', normalizedTargetUrl);
            formData.append('scanMode', scanMode);
            formData.append('rateLimit', String(rateLimit));
            formData.append('parallelAgents', String(parallelAgents));
            formData.append('iterations', String(iterations));
            formData.append('maxPlanRounds', String(maxPlanRounds));
            formData.append('useNuclei', String(externalTools.nuclei));
            formData.append('useFfuf', String(externalTools.ffuf));
            if (scanInstructions.trim()) formData.append('scanInstructions', scanInstructions.trim());
            if (scanMode !== 'scoped') {
                formData.append('authStartupMode', authStartupMode);
                formData.append('authCredentials', JSON.stringify(authStartupMode === 'provided_credentials' ? providedCredentials : []));
                formData.append('allowAccountCreation', String(allowAccountCreation));
                formData.append('preferSharedPassword', String(preferSharedPassword));
                formData.append('idorUsers', JSON.stringify(authStartupMode === 'provided_credentials' ? providedCredentials : []));
                if (sessionCookies.trim()) formData.append('sessionCookies', sessionCookies.trim());
            }

            const wantsSource = (sourceType === 'local' && sourcePackagePath.trim())
                || (sourceType === 'zip' && zipFile)
                || (sourceType === 'git' && gitUrl.trim());

            if (wantsSource && sourceAnalysisMode) {
                formData.append('sourceAnalysisMode', sourceAnalysisMode);
                formData.append('sourceType', sourceType);
                if (sourceType === 'local') {
                    formData.append('sourcePackagePath', sourcePackagePath.trim());
                } else if (sourceType === 'zip' && zipFile) {
                    formData.append('sourceZip', zipFile);
                } else if (sourceType === 'git') {
                    formData.append('sourceGitUrl', gitUrl.trim());
                    if (gitToken.trim()) formData.append('sourceGitToken', gitToken.trim());
                }
            }

            if (scanMode === 'scoped') {
                formData.append('securityTestRequest', JSON.stringify(
                    buildScopedSecurityTestRequest(normalizedTargetUrl, scopedRequest),
                ));
            }

            if (typeof window !== 'undefined') {
                try {
                    localStorage.setItem(SCAN_OPTIONS_KEY, JSON.stringify({
                        iterations,
                        parallelAgents,
                        rateLimit,
                        maxPlanRounds,
                    }));
                } catch {
                    // ignore
                }
            }

            const response = await axios.post(`${API_URL}/scans/web`, formData, {
                headers: {
                    Authorization: `Bearer ${useAuthStore.getState().token}`,
                    'Content-Type': 'multipart/form-data',
                },
            });

            const { scanId } = response.data;
            toast.success(scanMode === 'scoped'
                ? 'Scoped mission accepted. Mission Control will show bounded discovery and then live execution.'
                : 'Scan initiated. Redirecting to Mission Control...');
            window.location.href = `/scan/${scanId}`;
        } catch (error: any) {
            const message = error.response?.data?.message || 'Failed to start scan.';
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

    const getStatusIcon = () => {
        if (scanStatus.status === 'error') {
            return <XCircle className="w-6 h-6 text-red-400" />;
        }
        if (scanStatus.status === 'complete') {
            return <CheckCircle className="w-6 h-6 text-green-400" />;
        }
        return <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />;
    };

    return (
        <div className="min-h-screen bg-dark-950 text-white">
            <main className="max-w-6xl mx-auto px-4 py-8">
                <div className="flex items-center justify-between gap-4 mb-8">
                    <div>
                        <Link href="/dashboard" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors">
                            <ArrowLeft className="w-4 h-4" />
                            Back to Dashboard
                        </Link>
                        <h1 className="text-3xl font-bold mt-3">Start Web Scan</h1>
                        <p className="text-gray-400 mt-2 max-w-3xl">
                            Exploratory mode stays unchanged. Scoped Test Mode now starts from a structured security testing request, with the target URL and description as the core required inputs.
                        </p>
                    </div>
                </div>

                <div className="grid gap-6 lg:grid-cols-[1.25fr,0.75fr]">
                    <div className="space-y-6">
                        <motion.section
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="card p-6 space-y-6"
                        >
                            <div className="grid gap-5 md:grid-cols-2">
                                <div className="md:col-span-2">
                                    <label className="block text-sm text-gray-300 mb-2">Target URL</label>
                                    <div className="relative">
                                        <Globe className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400" />
                                        <input
                                            type="text"
                                            value={targetUrl}
                                            onChange={(event) => setTargetUrl(event.target.value)}
                                            placeholder="https://app.example.com/feature"
                                            disabled={isScanning}
                                            className="w-full pl-10 pr-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500"
                                        />
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">Scan Mode</label>
                                    <div className="grid grid-cols-2 gap-2">
                                        {(['exploratory', 'scoped'] as ScanMode[]).map((mode) => (
                                            <button
                                                key={mode}
                                                type="button"
                                                onClick={() => setScanMode(mode)}
                                                disabled={isScanning}
                                                className={`px-4 py-3 rounded-xl border text-sm font-medium transition-colors ${
                                                    scanMode === mode
                                                        ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                                                        : 'border-dark-600 bg-dark-900 text-gray-300 hover:border-dark-500'
                                                }`}
                                            >
                                                {mode === 'scoped' ? 'Scoped Test Mode' : 'Exploratory Mode'}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">General Instructions</label>
                                    <textarea
                                        value={scanInstructions}
                                        onChange={(event) => setScanInstructions(event.target.value)}
                                        rows={4}
                                        placeholder="Optional operator guidance for the run."
                                        disabled={isScanning}
                                        className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500 resize-none"
                                    />
                                </div>
                            </div>
                        </motion.section>

                        {scanMode === 'scoped' && (
                            <motion.section
                                initial={{ opacity: 0, y: 12 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="card p-6 space-y-6 border border-violet-500/20"
                            >
                                <div className="flex items-start justify-between gap-4">
                                    <div>
                                        <h2 className="text-xl font-semibold">Structured Security Test Request</h2>
                                        <p className="text-sm text-gray-400 mt-1 max-w-2xl">
                                            This is the new primary scoped intake contract. URL and description are required; everything else is optional enrichment for bounded feature anchoring.
                                        </p>
                                    </div>
                                    <span className="px-3 py-1 rounded-full border border-violet-500/20 bg-violet-500/10 text-violet-200 text-xs font-semibold uppercase">
                                        Request Driven
                                    </span>
                                </div>

                                <div className="grid gap-5 md:grid-cols-2">
                                    <div className="md:col-span-2">
                                        <label className="block text-sm text-gray-300 mb-2">Request Description</label>
                                        <textarea
                                            value={scopedRequest.description}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, description: event.target.value }))}
                                            rows={5}
                                            placeholder="Describe the feature, screen, behavior, or changed area that should be security tested."
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Environment</label>
                                        <input
                                            type="text"
                                            value={scopedRequest.environment}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, environment: event.target.value }))}
                                            placeholder="staging, qa, preview..."
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Service / Application Name</label>
                                        <input
                                            type="text"
                                            value={scopedRequest.serviceName}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, serviceName: event.target.value }))}
                                            placeholder="Orders Portal"
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Test Data</label>
                                        <textarea
                                            value={scopedRequest.testData}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, testData: event.target.value }))}
                                            rows={4}
                                            placeholder="One item per line or comma separated"
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Test Users</label>
                                        <textarea
                                            value={scopedRequest.testUsers}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, testUsers: event.target.value }))}
                                            rows={4}
                                            placeholder="One user or role per line"
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Login Present</label>
                                        <select
                                            value={scopedRequest.loginPresent}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, loginPresent: event.target.value as ScopedRequestIntakeFormValues['loginPresent'] }))}
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500"
                                        >
                                            <option value="unknown">Unknown</option>
                                            <option value="present">Yes</option>
                                            <option value="absent">No</option>
                                        </select>
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Auth Mechanism Hints</label>
                                        <textarea
                                            value={scopedRequest.authMechanismHints}
                                            onChange={(event) => setScopedRequest((current) => ({ ...current, authMechanismHints: event.target.value }))}
                                            rows={4}
                                            placeholder="SSO, session cookie, bearer token, magic link..."
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                        />
                                    </div>

                                    <div className="md:col-span-2 grid gap-5 md:grid-cols-2">
                                        <div className="p-4 rounded-xl border border-dark-600 bg-dark-900/60 space-y-3">
                                            <label className="inline-flex items-center gap-3 text-sm text-gray-200">
                                                <input
                                                    type="checkbox"
                                                    checked={scopedRequest.hasScreenshotOrAttachment}
                                                    onChange={(event) => setScopedRequest((current) => ({ ...current, hasScreenshotOrAttachment: event.target.checked }))}
                                                    disabled={isScanning}
                                                    className="accent-violet-500"
                                                />
                                                Screenshot or attachment available
                                            </label>
                                            <textarea
                                                value={scopedRequest.attachmentMetadata}
                                                onChange={(event) => setScopedRequest((current) => ({ ...current, attachmentMetadata: event.target.value }))}
                                                rows={3}
                                                placeholder="Optional metadata, one per line. Use kind:label for quick structure."
                                                disabled={isScanning}
                                                className="w-full px-4 py-3 bg-dark-950 border border-dark-700 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                            />
                                            <textarea
                                                value={scopedRequest.attachmentSummary}
                                                onChange={(event) => setScopedRequest((current) => ({ ...current, attachmentSummary: event.target.value }))}
                                                rows={3}
                                                placeholder="Attachment content summary"
                                                disabled={isScanning}
                                                className="w-full px-4 py-3 bg-dark-950 border border-dark-700 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                            />
                                        </div>

                                        <div className="p-4 rounded-xl border border-dark-600 bg-dark-900/60 grid gap-4">
                                            <div className="grid grid-cols-2 gap-4">
                                                <div>
                                                    <label className="block text-sm text-gray-300 mb-2">New Screen Count</label>
                                                    <input
                                                        type="number"
                                                        min="0"
                                                        value={scopedRequest.newScreenCount}
                                                        onChange={(event) => setScopedRequest((current) => ({ ...current, newScreenCount: event.target.value }))}
                                                        disabled={isScanning}
                                                        className="w-full px-4 py-3 bg-dark-950 border border-dark-700 rounded-xl text-white focus:outline-none focus:border-violet-500"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm text-gray-300 mb-2">New Input Count</label>
                                                    <input
                                                        type="number"
                                                        min="0"
                                                        value={scopedRequest.newInputCount}
                                                        onChange={(event) => setScopedRequest((current) => ({ ...current, newInputCount: event.target.value }))}
                                                        disabled={isScanning}
                                                        className="w-full px-4 py-3 bg-dark-950 border border-dark-700 rounded-xl text-white focus:outline-none focus:border-violet-500"
                                                    />
                                                </div>
                                            </div>
                                            <div>
                                                <label className="block text-sm text-gray-300 mb-2">Operator Notes</label>
                                                <textarea
                                                    value={scopedRequest.operatorNotes}
                                                    onChange={(event) => setScopedRequest((current) => ({ ...current, operatorNotes: event.target.value }))}
                                                    rows={4}
                                                    placeholder="Optional notes for discovery and planning."
                                                    disabled={isScanning}
                                                    className="w-full px-4 py-3 bg-dark-950 border border-dark-700 rounded-xl text-white focus:outline-none focus:border-violet-500 resize-none"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </motion.section>
                        )}

                        <motion.section
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="card p-6 space-y-5"
                        >
                            <div>
                                <h2 className="text-xl font-semibold">{scanMode === 'scoped' ? 'Runtime Controls' : 'Auth and Runtime Controls'}</h2>
                                <p className="text-sm text-gray-400 mt-1">
                                    {scanMode === 'scoped'
                                        ? 'Scoped mode keeps only the generic runtime tuning here. Auth-specific startup controls are intentionally hidden for this request-driven flow.'
                                        : 'These controls remain runtime-specific. They are separate from the structured request metadata.'}
                                </p>
                            </div>

                            {scanMode !== 'scoped' && (
                                <div className="grid gap-5 md:grid-cols-2">
                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Auth Startup Mode</label>
                                        <div className="grid grid-cols-2 gap-2">
                                            <button
                                                type="button"
                                                onClick={() => setAuthStartupMode('no_credentials')}
                                                disabled={isScanning}
                                                className={`px-4 py-3 rounded-xl border text-sm ${
                                                    authStartupMode === 'no_credentials'
                                                        ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                                                        : 'border-dark-600 bg-dark-900 text-gray-300'
                                                }`}
                                            >
                                                Browser Discovery
                                            </button>
                                            <button
                                                type="button"
                                                onClick={() => setAuthStartupMode('provided_credentials')}
                                                disabled={isScanning}
                                                className={`px-4 py-3 rounded-xl border text-sm ${
                                                    authStartupMode === 'provided_credentials'
                                                        ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                                                        : 'border-dark-600 bg-dark-900 text-gray-300'
                                                }`}
                                            >
                                                Provided Credentials
                                            </button>
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-sm text-gray-300 mb-2">Session Cookies</label>
                                        <textarea
                                            value={sessionCookies}
                                            onChange={(event) => setSessionCookies(event.target.value)}
                                            rows={4}
                                            placeholder="Optional raw Cookie header value for runtime continuity"
                                            disabled={isScanning}
                                            className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500 resize-none font-mono text-sm"
                                        />
                                    </div>
                                </div>
                            )}

                            {scanMode !== 'scoped' && authStartupMode === 'provided_credentials' && (
                                <div className="space-y-4">
                                    {userAccounts.map((account, index) => (
                                        <div key={`credential-${index}`} className="grid gap-3 md:grid-cols-6 p-4 rounded-xl border border-dark-600 bg-dark-900/60">
                                            <input
                                                value={account.username}
                                                onChange={(event) => handleCredentialChange(index, 'username', event.target.value)}
                                                placeholder="Username"
                                                disabled={isScanning}
                                                className="px-3 py-2 bg-dark-950 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                                            />
                                            <input
                                                value={account.email}
                                                onChange={(event) => handleCredentialChange(index, 'email', event.target.value)}
                                                placeholder="Email"
                                                disabled={isScanning}
                                                className="px-3 py-2 bg-dark-950 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                                            />
                                            <input
                                                type="password"
                                                value={account.password}
                                                onChange={(event) => handleCredentialChange(index, 'password', event.target.value)}
                                                placeholder="Password"
                                                disabled={isScanning}
                                                className="px-3 py-2 bg-dark-950 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                                            />
                                            <input
                                                value={account.role}
                                                onChange={(event) => handleCredentialChange(index, 'role', event.target.value)}
                                                placeholder="Role"
                                                disabled={isScanning}
                                                className="px-3 py-2 bg-dark-950 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                                            />
                                            <input
                                                value={account.label}
                                                onChange={(event) => handleCredentialChange(index, 'label', event.target.value)}
                                                placeholder="Label"
                                                disabled={isScanning}
                                                className="px-3 py-2 bg-dark-950 border border-dark-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                                            />
                                            <button
                                                type="button"
                                                onClick={() => handleRemoveCredential(index)}
                                                disabled={isScanning}
                                                className="px-3 py-2 rounded-lg border border-red-500/20 bg-red-500/10 text-red-300 hover:bg-red-500/20"
                                            >
                                                Remove
                                            </button>
                                        </div>
                                    ))}

                                    <div className="flex flex-wrap gap-3">
                                        <button
                                            type="button"
                                            onClick={handleAddCredential}
                                            disabled={isScanning}
                                            className="px-4 py-2 rounded-lg border border-cyan-500/20 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20"
                                        >
                                            Add Credential
                                        </button>
                                        <label className="inline-flex items-center gap-2 text-sm text-gray-300">
                                            <input
                                                type="checkbox"
                                                checked={allowAccountCreation}
                                                onChange={(event) => setAllowAccountCreation(event.target.checked)}
                                                disabled={isScanning}
                                                className="accent-cyan-500"
                                            />
                                            Allow account creation
                                        </label>
                                        <label className="inline-flex items-center gap-2 text-sm text-gray-300">
                                            <input
                                                type="checkbox"
                                                checked={preferSharedPassword}
                                                onChange={(event) => setPreferSharedPassword(event.target.checked)}
                                                disabled={isScanning}
                                                className="accent-cyan-500"
                                            />
                                            Prefer shared password heuristics
                                        </label>
                                    </div>
                                </div>
                            )}

                            <div className="grid gap-4 md:grid-cols-4">
                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">Iterations</label>
                                    <input
                                        type="number"
                                        min="10"
                                        max="500"
                                        value={iterations}
                                        onChange={(event) => setIterations(Number(event.target.value))}
                                        disabled={isScanning}
                                        className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">Parallel Agents</label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="10"
                                        value={parallelAgents}
                                        onChange={(event) => setParallelAgents(Number(event.target.value))}
                                        disabled={isScanning}
                                        className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">Rate Limit</label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="20"
                                        value={rateLimit}
                                        onChange={(event) => setRateLimit(Number(event.target.value))}
                                        disabled={isScanning}
                                        className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm text-gray-300 mb-2">Max Plan Rounds</label>
                                    <input
                                        type="number"
                                        min="0"
                                        max="99"
                                        value={maxPlanRounds}
                                        onChange={(event) => setMaxPlanRounds(Number(event.target.value))}
                                        disabled={isScanning}
                                        className="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-white focus:outline-none focus:border-cyan-500"
                                    />
                                </div>
                            </div>

                            <div className="flex flex-wrap gap-4">
                                <label className="inline-flex items-center gap-2 text-sm text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={externalTools.nuclei}
                                        onChange={(event) => setExternalTools((current) => ({ ...current, nuclei: event.target.checked }))}
                                        disabled={isScanning}
                                        className="accent-cyan-500"
                                    />
                                    Enable Nuclei
                                </label>
                                <label className="inline-flex items-center gap-2 text-sm text-gray-300">
                                    <input
                                        type="checkbox"
                                        checked={externalTools.ffuf}
                                        onChange={(event) => setExternalTools((current) => ({ ...current, ffuf: event.target.checked }))}
                                        disabled={isScanning}
                                        className="accent-cyan-500"
                                    />
                                    Enable ffuf
                                </label>
                            </div>
                        </motion.section>

                        <motion.section
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="card p-6 space-y-5"
                        >
                            <div>
                                <h2 className="text-xl font-semibold">Source Enrichment</h2>
                                <p className="text-sm text-gray-400 mt-1">
                                    Source analysis remains optional internal enrichment for planning and discovery. Endpoint intelligence is no longer part of scan creation.
                                </p>
                            </div>

                            <SourceModeSelector
                                modes={SOURCE_ANALYSIS_MODES}
                                selected={sourceAnalysisMode}
                                onSelect={setSourceAnalysisMode}
                                disabled={isScanning}
                            />

                            <SourceProviderInput
                                sourceType={sourceType}
                                setSourceType={setSourceType}
                                localPath={sourcePackagePath}
                                setLocalPath={setSourcePackagePath}
                                zipFile={zipFile}
                                setZipFile={setZipFile}
                                gitUrl={gitUrl}
                                setGitUrl={setGitUrl}
                                gitToken={gitToken}
                                setGitToken={setGitToken}
                                disabled={isScanning}
                            />
                        </motion.section>
                    </div>

                    <div className="space-y-6">
                        <motion.aside
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="card p-6 space-y-5 sticky top-6"
                        >
                            <div>
                                <h2 className="text-xl font-semibold">Launch Summary</h2>
                                <p className="text-sm text-gray-400 mt-1">
                                    {scanMode === 'scoped'
                                    ? 'Scoped launch will persist the structured request, derive bounded feature anchors, seed internal hypotheses, and move straight into live bounded execution.'
                                        : 'Exploratory launch keeps the current runtime-driven workflow.'}
                                </p>
                            </div>

                            <div className="space-y-3 text-sm text-gray-300">
                                <div className="flex items-center justify-between">
                                    <span>Mode</span>
                                    <span className="text-white font-medium">{scanMode === 'scoped' ? 'Scoped Test Mode' : 'Exploratory Mode'}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span>Target</span>
                                    <span className="text-white font-medium truncate max-w-[220px] text-right">{targetUrl || 'Not set'}</span>
                                </div>
                                {scanMode === 'scoped' && (
                                    <>
                                        <div className="flex items-center justify-between">
                                            <span>Description</span>
                                            <span className="text-white font-medium">{scopedRequest.description.trim() ? 'Provided' : 'Required'}</span>
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <span>Optional Metadata</span>
                                            <span className="text-white font-medium">
                                                {[
                                                    scopedRequest.environment,
                                                    scopedRequest.serviceName,
                                                    scopedRequest.testData,
                                                    scopedRequest.testUsers,
                                                    scopedRequest.authMechanismHints,
                                                    scopedRequest.operatorNotes,
                                                ].filter((value) => String(value || '').trim()).length}
                                            </span>
                                        </div>
                                    </>
                                )}
                                <div className="flex items-center justify-between">
                                    <span>Source Enrichment</span>
                                    <span className="text-white font-medium">{sourceAnalysisMode || 'Disabled'}</span>
                                </div>
                            </div>

                            <button
                                type="button"
                                onClick={handleStartScan}
                                disabled={isScanning}
                                className="w-full px-4 py-3 rounded-xl bg-cyan-500 text-black font-semibold hover:bg-cyan-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                        {isScanning ? 'Launching...' : scanMode === 'scoped' ? 'Start Scoped Mission' : 'Start Exploratory Scan'}
                            </button>
                        </motion.aside>
                    </div>
                </div>

                {scanStatus.status !== 'idle' && (
                    <motion.section
                        initial={{ opacity: 0, y: 16 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6 mt-8"
                    >
                        <div className="flex items-center gap-4 mb-4">
                            {getStatusIcon()}
                            <div className="flex-1">
                                <h3 className="text-lg font-semibold text-white">
                                    {scanStatus.status === 'complete'
                                        ? 'Scan Complete'
                                        : scanStatus.status === 'error'
                                            ? 'Launch Failed'
                                            : 'Launch In Progress'}
                                </h3>
                                <p className="text-gray-400 text-sm">{scanStatus.message}</p>
                            </div>
                        </div>
                        <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${scanStatus.progress}%` }}
                                transition={{ duration: 0.4 }}
                                className={`h-full rounded-full ${
                                    scanStatus.status === 'error'
                                        ? 'bg-red-500'
                                        : scanStatus.status === 'complete'
                                            ? 'bg-green-500'
                                            : 'bg-gradient-to-r from-cyan-500 to-blue-500'
                                }`}
                            />
                        </div>
                    </motion.section>
                )}

                {scanStatus.vulnerabilities.length > 0 && (
                    <motion.section
                        initial={{ opacity: 0, y: 16 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="card p-6 mt-8"
                    >
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                                <Shield className="w-5 h-5 text-red-400" />
                                Vulnerabilities Found ({scanStatus.vulnerabilities.length})
                            </h3>
                            {scanStatus.id && (
                                <button
                                    onClick={() => setReportModalOpen(true)}
                                    className="text-cyan-400 text-sm hover:underline flex items-center gap-1 bg-cyan-500/10 px-3 py-1 rounded-lg border border-cyan-500/30"
                                >
                                    <Download className="w-4 h-4" /> Download Report
                                </button>
                            )}
                        </div>

                        <div className="space-y-3">
                            {scanStatus.vulnerabilities.map((vulnerability, index) => (
                                <div key={index} className="p-4 bg-dark-800/50 rounded-lg border border-dark-600/50">
                                    <div className="flex items-start justify-between gap-4">
                                        <div>
                                            <h4 className="font-medium text-white">{vulnerability.name}</h4>
                                            <p className="text-gray-400 text-sm mt-1">{vulnerability.description}</p>
                                        </div>
                                        <span className={getSeverityClass(vulnerability.severity)}>
                                            {vulnerability.severity}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </motion.section>
                )}

                {scanStatus.id && (
                    <ReportOptionsModal
                        isOpen={reportModalOpen}
                        onClose={() => setReportModalOpen(false)}
                        scanId={scanStatus.id}
                    />
                )}
            </main>
        </div>
    );
}
