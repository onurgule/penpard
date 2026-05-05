'use client';

import { useMemo, useState } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { CheckCircle, ClipboardList, Loader2, Play, X, XCircle } from 'lucide-react';
import { API_URL } from '@/lib/api-config';
import type { FocusedCaseFamily, FocusedTestCase, FocusedTestCaseReviewState } from './focused-plan';

interface PlanReviewModalProps {
    open: boolean;
    onClose: () => void;
    scanId: string;
    scanStatus: string;
    focusedTestCases: FocusedTestCase[];
    token: string;
    onCasesUpdated: () => void;
    onStartRequested: () => void;
}

const FAMILY_LABELS: Record<FocusedCaseFamily, string> = {
    sqli: 'SQL Injection',
    xss: 'Cross-Site Scripting',
    access_control: 'Access Control',
    workflow_logic: 'Workflow Logic',
    error_handling: 'Error Handling',
    input_validation: 'Input Validation',
    generic: 'Generic',
};

const FAMILY_ORDER: FocusedCaseFamily[] = [
    'sqli',
    'xss',
    'access_control',
    'workflow_logic',
    'error_handling',
    'input_validation',
    'generic',
];

function getFamily(testCase: FocusedTestCase): FocusedCaseFamily {
    return testCase.caseFamily || 'generic';
}

function summarizeTarget(testCase: FocusedTestCase): string {
    const target = testCase.targetArtifact;
    const pieces = [
        target.kind,
        target.method,
        target.path || target.url || target.label || target.referenceId,
    ].filter(Boolean);
    return pieces.join(' · ') || 'Scoped target';
}

function priorityClass(priority: FocusedTestCase['priority']): string {
    if (priority === 'high') {
        return 'border-red-500/30 bg-red-500/10 text-red-300';
    }
    if (priority === 'medium') {
        return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
    }
    return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300';
}

function reviewStateClass(reviewState: FocusedTestCaseReviewState): string {
    if (reviewState === 'approved') {
        return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
    }
    if (reviewState === 'rejected') {
        return 'border-red-500/30 bg-red-500/10 text-red-300';
    }
    return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
}

function reviewStateLabel(reviewState: FocusedTestCaseReviewState): string {
    if (reviewState === 'pending_review') {
        return 'Pending Review';
    }
    return reviewState.charAt(0).toUpperCase() + reviewState.slice(1);
}

export default function PlanReviewModal({
    open,
    onClose,
    scanId,
    scanStatus,
    focusedTestCases,
    token,
    onCasesUpdated,
    onStartRequested,
}: PlanReviewModalProps) {
    const [caseActionId, setCaseActionId] = useState<string | null>(null);
    const [bulkAction, setBulkAction] = useState<'approve' | 'reject' | null>(null);
    const [startPending, setStartPending] = useState(false);
    const reviewOpen = scanStatus === 'awaiting_review';
    const approvedCount = focusedTestCases.filter((testCase) => testCase.reviewState === 'approved').length;
    const pendingCases = focusedTestCases.filter((testCase) => testCase.reviewState === 'pending_review');
    const groups = useMemo(() => {
        const grouped = new Map<FocusedCaseFamily, FocusedTestCase[]>();
        for (const testCase of focusedTestCases) {
            const family = getFamily(testCase);
            grouped.set(family, [...(grouped.get(family) || []), testCase]);
        }
        return FAMILY_ORDER
            .filter((family) => grouped.has(family))
            .map((family) => ({
                family,
                cases: grouped.get(family) || [],
            }));
    }, [focusedTestCases]);

    if (!open) {
        return null;
    }

    const patchCase = async (caseId: string, reviewState: FocusedTestCaseReviewState) => {
        setCaseActionId(caseId);
        try {
            await axios.patch(`${API_URL}/scans/${scanId}/focused-test-cases/${caseId}`, { reviewState }, {
                headers: { Authorization: `Bearer ${token}` },
            });
            await onCasesUpdated();
            toast.success(reviewState === 'approved' ? 'Test case approved.' : 'Test case rejected.');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to update test case.');
        } finally {
            setCaseActionId(null);
        }
    };

    const patchPendingCases = async (reviewState: FocusedTestCaseReviewState) => {
        if (pendingCases.length === 0) return;
        setBulkAction(reviewState === 'approved' ? 'approve' : 'reject');
        try {
            await Promise.all(pendingCases.map((testCase) => (
                axios.patch(`${API_URL}/scans/${scanId}/focused-test-cases/${testCase.id}`, { reviewState }, {
                    headers: { Authorization: `Bearer ${token}` },
                })
            )));
            await onCasesUpdated();
            toast.success(reviewState === 'approved' ? 'Pending cases approved.' : 'Pending cases rejected.');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to update pending cases.');
        } finally {
            setBulkAction(null);
        }
    };

    const startTesting = async () => {
        setStartPending(true);
        try {
            await axios.post(`${API_URL}/scans/${scanId}/plan/start`, {}, {
                headers: { Authorization: `Bearer ${token}` },
            });
            await onStartRequested();
            toast.success('Approved test cases are starting.');
            onClose();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to start testing.');
        } finally {
            setStartPending(false);
        }
    };

    return (
        <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 px-4 py-8">
            <div className="w-full max-w-2xl max-h-[80vh] overflow-hidden rounded-2xl border border-white/10 bg-slate-950 shadow-2xl">
                <div className="flex items-start justify-between gap-4 border-b border-white/10 px-5 py-4">
                    <div>
                        <div className="flex items-center gap-2 text-white">
                            <ClipboardList className="h-5 w-5 text-amber-300" />
                            <h2 className="text-lg font-semibold">
                                Test Plan — {focusedTestCases.length} cases · {groups.length} vulnerability types
                            </h2>
                        </div>
                        <p className="mt-1 text-xs text-slate-400">Auto-accept: {reviewOpen ? 'OFF' : 'ON'}</p>
                    </div>
                    <button
                        type="button"
                        onClick={onClose}
                        className="rounded-lg p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
                        aria-label="Close plan review"
                    >
                        <X className="h-4 w-4" />
                    </button>
                </div>

                <div className="max-h-[calc(80vh-8.5rem)] overflow-y-auto px-5 py-4 space-y-5">
                    {groups.map((group) => (
                        <section key={group.family} className="space-y-2">
                            <div className="flex items-center justify-between gap-3">
                                <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-300">
                                    {FAMILY_LABELS[group.family]}
                                </h3>
                                <span className="text-[10px] text-slate-500">{group.cases.length} cases</span>
                            </div>
                            <div className="space-y-2">
                                {group.cases.map((testCase) => (
                                    <div key={testCase.id} className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                                        <div className="flex items-start justify-between gap-3">
                                            <div className="min-w-0">
                                                <div className="text-sm font-medium text-white">{testCase.title}</div>
                                                <div className="mt-1 text-xs text-slate-400">{summarizeTarget(testCase)}</div>
                                            </div>
                                            <div className="flex flex-wrap justify-end gap-1.5">
                                                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${priorityClass(testCase.priority)}`}>
                                                    {testCase.priority}
                                                </span>
                                                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${reviewStateClass(testCase.reviewState)}`}>
                                                    {reviewStateLabel(testCase.reviewState)}
                                                </span>
                                            </div>
                                        </div>
                                        {reviewOpen && (
                                            <div className="mt-3 flex items-center gap-2">
                                                <button
                                                    type="button"
                                                    onClick={() => patchCase(testCase.id, 'approved')}
                                                    disabled={caseActionId === testCase.id}
                                                    className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                                                >
                                                    {caseActionId === testCase.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle className="h-3 w-3" />}
                                                    Approve
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => patchCase(testCase.id, 'rejected')}
                                                    disabled={caseActionId === testCase.id}
                                                    className="inline-flex items-center gap-1 rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-500/20 disabled:opacity-50"
                                                >
                                                    {caseActionId === testCase.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <XCircle className="h-3 w-3" />}
                                                    Reject
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </section>
                    ))}
                </div>

                <div className="flex flex-wrap items-center justify-end gap-2 border-t border-white/10 px-5 py-3">
                    {reviewOpen ? (
                        <>
                            <button
                                type="button"
                                onClick={() => patchPendingCases('approved')}
                                disabled={pendingCases.length === 0 || bulkAction !== null}
                                className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                            >
                                {bulkAction === 'approve' && <Loader2 className="h-3 w-3 animate-spin" />}
                                Approve All
                            </button>
                            <button
                                type="button"
                                onClick={() => patchPendingCases('rejected')}
                                disabled={pendingCases.length === 0 || bulkAction !== null}
                                className="inline-flex items-center gap-1 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20 disabled:opacity-50"
                            >
                                {bulkAction === 'reject' && <Loader2 className="h-3 w-3 animate-spin" />}
                                Reject All
                            </button>
                            <button
                                type="button"
                                onClick={startTesting}
                                disabled={approvedCount === 0 || startPending}
                                className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                                {startPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                                Start Testing
                            </button>
                        </>
                    ) : (
                        <button
                            type="button"
                            onClick={onClose}
                            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/10"
                        >
                            Close
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
