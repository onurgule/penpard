import { v4 as uuidv4 } from 'uuid';
import {
    getFocusedCaseVerdictByExecution,
    getFocusedFindingThreadByExecution,
    getFocusedScanFindingSummary,
    getFocusedTestObjective,
    getLatestFocusedTestCaseExecution,
    listEvidenceBundlesByExecution,
    listFocusedFindingThreadsByExecution,
    listFocusedInvestigationIssuesByExecution,
    listFocusedTestCasesByScan,
    listLatestPrimaryFocusedCaseFindingsByScan,
    upsertFocusedFindingThread,
    upsertFocusedCaseFinding,
} from '../../db/init';
import { focusedReasoningVisibilityService, type FocusedReasoningVisibilityService } from './FocusedReasoningVisibilityService';
import { interpretFocusedSignals, resolveFocusedCaseFamily } from './FocusedSignalInterpreter';
import type {
    EvidenceBundle,
    FocusedCaseFamily,
    FocusedCaseFinding,
    FocusedCaseVerdict,
    FocusedConfirmationState,
    FocusedFindingConfidenceBand,
    FocusedFindingStatus,
    FocusedFindingThread,
    FocusedFindingThreadStatus,
    FocusedInvestigationIssue,
    FocusedRequestEvidenceStory,
    FocusedVerdictEvidenceRef,
    FocusedScanFindingSummary,
    FocusedSignalMarker,
    FocusedSignalSuspiciousness,
    FocusedSupportProvenanceSummary,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedTestObjective,
} from './ScopedScanTypes';

interface FindingDependencies {
    visibilityService: Pick<FocusedReasoningVisibilityService, 'buildCaseVisibility'>;
    now: () => string;
    createId: () => string;
}

interface SynthesizedCaseFindingContext {
    objective: FocusedTestObjective;
    testCase: FocusedTestCase;
    execution: FocusedTestCaseExecution;
    verdict: FocusedCaseVerdict | null;
    evidenceBundles: EvidenceBundle[];
    investigationIssues: FocusedInvestigationIssue[];
    visibility: ReturnType<FocusedReasoningVisibilityService['buildCaseVisibility']>;
    findingThreads?: FocusedFindingThread[];
}

interface RuntimeThreadUpdateInput {
    objective: FocusedTestObjective;
    testCase: FocusedTestCase;
    execution: FocusedTestCaseExecution;
    evidenceBundles: EvidenceBundle[];
    investigationIssues: FocusedInvestigationIssue[];
    linkedTraceIds?: string[];
    linkedVerdictIds?: string[];
    linkedInvestigationIds?: string[];
    confirmationState?: FocusedConfirmationState | null;
    previousThread?: FocusedFindingThread | null;
    verdict?: FocusedCaseVerdict | null;
}

interface FindingFamilyCandidate {
    family: FocusedCaseFamily;
    orderHint: number;
}

const MAX_FINDINGS_PER_CASE = 3;

const SUSPICIOUSNESS_BASE: Record<FocusedSignalSuspiciousness, number> = {
    none: 10,
    low: 30,
    moderate: 55,
    high: 75,
};

const FINDING_STATUS_RANK: Record<FocusedFindingStatus, number> = {
    confirmed: 0,
    likely: 1,
    suspicious: 2,
    inconclusive: 3,
    not_confirmed: 4,
};

const PRIMARY_MARKER_BONUS = new Set<FocusedSignalMarker>([
    'authz_bypass',
    'strong_fail_keyword',
    'sql_error_marker',
    'script_reflection_marker',
    'state_mismatch_marker',
    'workflow_state_shift',
]);

const SECONDARY_MARKER_BONUS = new Set<FocusedSignalMarker>([
    'server_error_transition',
    'strong_structural_delta',
    'browser_expectation_missed',
]);

function uniqueStrings(values: Array<string | null | undefined>): string[] {
    const seen = new Set<string>();
    const output: string[] = [];

    for (const value of values) {
        const normalized = String(value || '').trim();
        if (!normalized) {
            continue;
        }
        if (seen.has(normalized)) {
            continue;
        }
        seen.add(normalized);
        output.push(normalized);
    }

    return output;
}

function clampScore(value: number): number {
    return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function buildMissingEvidenceSummaries(verdict: FocusedCaseVerdict | null): string[] {
    if (!verdict) {
        return [];
    }

    return uniqueStrings([
        ...verdict.evidenceSufficiency.missingRequirements.map((entry) => `Missing required evidence: ${entry}.`),
        ...verdict.evidenceSufficiency.unsupportedRequirements.map((entry) => `Unsupported verification primitive: ${entry}.`),
        ...verdict.evidenceSufficiency.contradictorySignals.map((entry) => `Contradictory evidence: ${entry}`),
    ]);
}

function formatFamilyLabel(family: FocusedCaseFamily): string {
    switch (family) {
        case 'sqli':
            return 'SQL Injection';
        case 'xss':
            return 'XSS';
        case 'access_control':
            return 'Access Control Bypass';
        case 'input_validation':
            return 'Input Validation Weakness';
        case 'error_handling':
            return 'Error Handling / Information Exposure Weakness';
        case 'workflow_logic':
            return 'Business Logic / Workflow Weakness';
        default:
            return 'Scoped Security Finding';
    }
}

function formatTargetLabel(testCase: FocusedTestCase): string {
    return [
        testCase.targetArtifact.method?.toUpperCase(),
        testCase.targetArtifact.path || testCase.targetArtifact.label || testCase.targetArtifact.url,
    ].filter(Boolean).join(' ');
}

function buildFindingTitle(family: FocusedCaseFamily, testCase: FocusedTestCase, parameterHint?: string | null): string {
    const prefix = `Potential ${formatFamilyLabel(family)}`;
    const trimmedParameter = String(parameterHint || '').trim();
    if (trimmedParameter) {
        return `${prefix} in ${trimmedParameter} parameter`;
    }

    const targetLabel = formatTargetLabel(testCase);
    if (targetLabel) {
        return `${prefix} on ${targetLabel}`;
    }

    return prefix;
}

function buildFamilyCandidates(
    objective: FocusedTestObjective,
    testCase: FocusedTestCase,
    verdict: FocusedCaseVerdict | null,
): FindingFamilyCandidate[] {
    const candidates: FindingFamilyCandidate[] = [];
    const push = (family: FocusedCaseFamily) => {
        if (!candidates.some((entry) => entry.family === family)) {
            candidates.push({ family, orderHint: candidates.length });
        }
    };

    push(verdict?.interpretationSummary.caseFamily || resolveFocusedCaseFamily(objective, testCase));

    const markers = new Set(verdict?.interpretationSummary.signalMarkers || []);
    if (markers.has('sql_error_marker') || markers.has('server_error_transition')) {
        push('sqli');
        push('error_handling');
    }
    if (markers.has('script_reflection_marker')) {
        push('xss');
    }
    if (markers.has('authz_bypass')) {
        push('access_control');
    }
    if (markers.has('validation_rejected')) {
        push('input_validation');
    }
    if (markers.has('workflow_state_shift') || markers.has('state_mismatch_marker')) {
        push('workflow_logic');
    }

    return candidates.slice(0, MAX_FINDINGS_PER_CASE);
}

function buildSupportSignals(
    verdict: FocusedCaseVerdict | null,
    visibility: ReturnType<FocusedReasoningVisibilityService['buildCaseVisibility']>,
): string[] {
    return uniqueStrings([
        ...(verdict?.interpretationSummary.failSignals || []),
        ...(verdict?.interpretationSummary.reviewSignals || []),
        ...(verdict?.interpretationSummary.suspiciousSignals || []),
        ...(visibility.suspicionExplanation?.supportingSignals || []),
        visibility.suspicionExplanation?.whySuspicious || null,
        verdict?.interpretationSummary.summary || null,
    ]);
}

function buildBlockingConstraints(
    verdict: FocusedCaseVerdict | null,
    execution: FocusedTestCaseExecution,
    investigationIssues: FocusedInvestigationIssue[],
    visibility: ReturnType<FocusedReasoningVisibilityService['buildCaseVisibility']>,
): string[] {
    const unresolvedIssues = investigationIssues
        .filter((issue) => issue.issueStatus === 'open' || issue.issueStatus === 'unresolved' || issue.issueStatus === 'partially_resolved')
        .sort((left, right) => {
            const impactRank = { blocking: 2, degrading: 1, informational: 0 };
            return impactRank[right.impact] - impactRank[left.impact];
        });

    return uniqueStrings([
        ...buildMissingEvidenceSummaries(verdict),
        ...(verdict?.scopeViolationImpact.reasons || []),
        visibility.suspicionExplanation?.boundedStopReason || null,
        ...unresolvedIssues.map((issue) => issue.issueTitle),
        execution.executionState === 'blocked' ? execution.notesSummary || 'Execution was blocked before confirmation could complete.' : null,
        execution.executionState === 'failed_to_execute' ? execution.errorMessage || execution.notesSummary || 'Execution failed before confirmation could complete.' : null,
    ]);
}

function buildNextStepSummary(input: {
    family: FocusedCaseFamily;
    verdict: FocusedCaseVerdict | null;
    investigationIssues: FocusedInvestigationIssue[];
    supportSignals: string[];
    blockingConstraints: string[];
    execution: FocusedTestCaseExecution;
}): string {
    const missingRequirements = input.verdict?.evidenceSufficiency.missingRequirements || [];
    const unsupportedRequirements = input.verdict?.evidenceSufficiency.unsupportedRequirements || [];
    const issueTypes = new Set(input.investigationIssues.map((issue) => issue.issueType));

    if (input.verdict?.supportProvenance?.requestHeavy && !input.verdict.supportProvenance.requestBackedEvidence) {
        return 'Capture a Burp-visible baseline replay and bounded mutation before increasing confidence.';
    }

    if (missingRequirements.some((entry) => /response|excerpt|body|status|diff/i.test(entry))) {
        return 'Capture the missing response excerpt from the strongest suspicious replay.';
    }
    if (unsupportedRequirements.length > 0 || issueTypes.has('unsupported_verification_primitive')) {
        return 'Manually replay the strongest suspicious request in Burp because the verification primitive is unsupported.';
    }
    if (issueTypes.has('browser_state_mismatch') || issueTypes.has('unexpected_navigation') || issueTypes.has('blocked_flow')) {
        return 'Rerun with slightly richer bounded browser verification.';
    }
    if (issueTypes.has('execution_budget_exhausted') || issueTypes.has('retry_failure')) {
        return 'Retry one additional bounded payload variation against the strongest suspicious request.';
    }
    if (input.verdict?.scopeViolationImpact.underminesConfidence) {
        return 'Rerun inside the current allowed anchors so the confirmation evidence stays in scope.';
    }
    if ((input.verdict?.supportingEvidenceRefs.length || 0) === 0) {
        return 'Persist the strongest suspicious request and response pair for this case.';
    }

    switch (input.family) {
        case 'xss':
            return 'Rerun with one additional bounded render-sensitive payload variation.';
        case 'sqli':
            return 'Retry one additional bounded payload variation and compare the response delta.';
        case 'access_control':
            return 'Manually replay the strongest suspicious request in Burp to validate the access boundary.';
        default:
            return 'Retry one bounded confirmation variation against the strongest suspicious case path.';
    }
}

function mapEvidenceRole(source: EvidenceBundle['source']): import('./ScopedScanTypes').FocusedVerdictEvidenceRef['role'] {
    switch (source) {
        case 'baseline_replay':
            return 'baseline';
        case 'mutated_replay':
            return 'mutated';
        case 'comparison':
            return 'comparison';
        case 'browser_flow':
            return 'browser_flow';
        case 'browser_verification':
            return 'browser_verification';
        case 'scope_guard':
            return 'scope_violation';
        case 'screenshot':
            return 'screenshot';
        default:
            return 'note';
    }
}

function buildEvidenceRefsFromBundles(evidenceBundles: EvidenceBundle[]): FocusedVerdictEvidenceRef[] {
    return evidenceBundles.map((bundle) => {
        const supportRail: FocusedVerdictEvidenceRef['supportRail'] = bundle.source === 'baseline_replay'
            || bundle.source === 'mutated_replay'
            || bundle.source === 'comparison'
            || bundle.requestRef
            || bundle.responseRef
            ? 'request'
            : (bundle.source === 'browser_flow'
                || bundle.source === 'browser_verification'
                || bundle.source === 'screenshot'
                || bundle.browserState
                || bundle.screenshotRef)
                ? 'browser'
                : 'system_only';

        return {
        evidenceId: bundle.id,
        source: bundle.source,
        role: mapEvidenceRole(bundle.source),
        summary: bundle.summary,
        capturedAt: bundle.capturedAt,
        relatedEvidenceIds: bundle.relatedEvidenceIds || [],
        browserActionCount: bundle.browserState?.actionCount ?? null,
        supportRail,
        requestMethod: bundle.requestRef?.method ?? null,
        requestPath: bundle.requestRef?.path ?? null,
        responseStatusCode: bundle.responseRef?.statusCode ?? null,
        executionPhase: bundle.provenance?.executionPhase ?? null,
        confirmationKind: bundle.provenance?.confirmationKind ?? null,
        confirmationOrdinal: bundle.provenance?.confirmationOrdinal ?? null,
        generatedFromFindingThreadId: bundle.provenance?.generatedFromFindingThreadId ?? null,
        };
    });
}

function isRequestHeavyCase(
    testCase: FocusedTestCase,
    family: FocusedCaseFamily,
    evidenceBundles: EvidenceBundle[],
): boolean {
    const requiredEvidenceKinds = new Set(
        (testCase.requiredEvidence || [])
            .map((entry) => String(entry.kind || '').trim().toLowerCase())
            .filter(Boolean),
    );
    return testCase.targetArtifact.kind === 'endpoint'
        || testCase.targetArtifact.kind === 'baseline_request'
        || testCase.preferredRail === 'request'
        || family === 'sqli'
        || family === 'access_control'
        || family === 'input_validation'
        || family === 'error_handling'
        || ['response_diff', 'status_code', 'response_excerpt', 'request_trace', 'payload_trace', 'scope_respected']
            .some((kind) => requiredEvidenceKinds.has(kind))
        || evidenceBundles.some((bundle) => !!bundle.requestRef || !!bundle.responseRef || bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay');
}

function buildRuntimeRequestEvidenceStory(
    testCase: FocusedTestCase,
    family: FocusedCaseFamily,
    interpretation: Pick<FocusedCaseVerdict['interpretationSummary'], 'caseFamily' | 'failSignals' | 'reviewSignals' | 'suspiciousSignals' | 'controlSignals'>,
    evidenceBundles: EvidenceBundle[],
): FocusedRequestEvidenceStory | null {
    const requestHeavy = isRequestHeavyCase(testCase, family, evidenceBundles);
    const requestRefs = evidenceBundles
        .filter((bundle) => bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay' || !!bundle.requestRef || !!bundle.responseRef)
        .map((bundle) => ({
            evidenceId: bundle.id,
            source: bundle.source,
            summary: bundle.summary,
            capturedAt: bundle.capturedAt,
            method: bundle.requestRef?.method || bundle.responseRef?.method || null,
            url: bundle.requestRef?.url || bundle.responseRef?.url || null,
            path: bundle.requestRef?.path || bundle.responseRef?.path || null,
            host: bundle.requestRef?.host || bundle.responseRef?.host || null,
            rawRequest: bundle.requestRef?.raw || null,
            rawResponse: bundle.responseRef?.raw || null,
            requestHeaders: bundle.requestRef?.headers || null,
            requestBody: bundle.requestRef?.body || null,
            statusCode: bundle.responseRef?.statusCode ?? null,
            executionPhase: bundle.provenance?.executionPhase ?? null,
            confirmationKind: bundle.provenance?.confirmationKind ?? null,
            confirmationOrdinal: bundle.provenance?.confirmationOrdinal ?? null,
            generatedFromFindingThreadId: bundle.provenance?.generatedFromFindingThreadId ?? null,
            relatedEvidenceIds: bundle.relatedEvidenceIds || [],
        }));

    if (!requestHeavy && requestRefs.length === 0) {
        return null;
    }

    const mutatedRefs = requestRefs.filter((entry) => entry.source === 'mutated_replay');
    const supportingRequestRefs = (interpretation.failSignals.length > 0 || interpretation.reviewSignals.length > 0 || interpretation.suspiciousSignals.length > 0)
        ? mutatedRefs.slice(-1)
        : [];
    const contradictingRequestRefs = interpretation.controlSignals.length > 0
        ? mutatedRefs.slice(-1)
        : [];
    const confirmationRequestRefs = requestRefs.filter((entry) => entry.executionPhase === 'adaptive_confirmation');
    const hasRequestBackedEvidence = requestRefs.length > 0;
    const lowConfidenceReason = requestHeavy && (!hasRequestBackedEvidence || supportingRequestRefs.length === 0)
        ? 'No request-backed confirmation was captured; confidence remains low.'
        : null;

    return {
        requestHeavy,
        hasRequestBackedEvidence,
        baselineRequestRef: requestRefs.find((entry) => entry.source === 'baseline_replay') || requestRefs[0] || null,
        strongestSuspiciousRequestRef: confirmationRequestRefs[0] || supportingRequestRefs[0] || null,
        supportingRequestRefs,
        contradictingRequestRefs,
        confirmationRequestRefs,
        summary: !hasRequestBackedEvidence
            ? 'No request-backed confirmation was captured; confidence remains low.'
            : confirmationRequestRefs.length > 0 && supportingRequestRefs.length > 0
                ? 'Adaptive confirmation replay strengthened the same request-backed hypothesis.'
                : supportingRequestRefs.length > 0
                    ? 'Request-backed suspicious signal observed.'
                    : contradictingRequestRefs.length > 0
                        ? 'Request-backed control contrast weakened the hypothesis.'
                        : 'Burp-visible request evidence was captured, but it did not materially strengthen suspicion yet.',
        lowConfidenceReason,
    };
}

function buildRuntimeSupportProvenance(
    testCase: FocusedTestCase,
    family: FocusedCaseFamily,
    evidenceBundles: EvidenceBundle[],
    requestEvidenceStory: FocusedRequestEvidenceStory | null,
): FocusedSupportProvenanceSummary {
    const requestHeavy = requestEvidenceStory?.requestHeavy || isRequestHeavyCase(testCase, family, evidenceBundles);
    const requestEvidenceIds = evidenceBundles
        .filter((bundle) => bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay' || bundle.source === 'comparison')
        .map((bundle) => bundle.id);
    const browserEvidenceIds = evidenceBundles
        .filter((bundle) => bundle.source === 'browser_flow' || bundle.source === 'browser_verification' || bundle.source === 'screenshot' || !!bundle.browserState || !!bundle.screenshotRef)
        .map((bundle) => bundle.id);
    const requestBackedEvidence = Boolean(requestEvidenceStory?.hasRequestBackedEvidence);
    const browserBackedEvidence = browserEvidenceIds.length > 0;
    const systemEvidenceIds = evidenceBundles
        .filter((bundle) => !requestEvidenceIds.includes(bundle.id) && !browserEvidenceIds.includes(bundle.id))
        .map((bundle) => bundle.id);

    const rail: FocusedSupportProvenanceSummary['rail'] = requestBackedEvidence && browserBackedEvidence
        ? 'hybrid'
        : requestBackedEvidence
            ? 'request'
            : browserBackedEvidence
                ? 'browser'
                : 'system_only';

    return {
        rail,
        requestHeavy,
        requestBackedEvidence,
        browserBackedEvidence,
        requestEvidenceIds,
        browserEvidenceIds,
        systemEvidenceIds,
        summary: requestHeavy && !requestBackedEvidence
            ? (browserBackedEvidence
                ? 'Browser-backed support only; this request-heavy case still lacks Burp-visible request confirmation.'
                : 'No Burp-visible request confirmation was captured for this request-heavy case.')
            : rail === 'hybrid'
                ? 'Hybrid support: Burp-visible request evidence is present alongside browser-backed confirmation.'
                : rail === 'request'
                    ? 'Request-backed support: Burp-visible request evidence is anchoring the current conclusion.'
                    : rail === 'browser'
                        ? 'Browser-backed support: browser/state observations are the primary evidence for this case.'
                        : 'System-only support: confidence remains bounded because no request-backed or browser-backed proof was captured.',
        lowConfidenceReason: requestHeavy && !requestBackedEvidence
            ? 'No request-backed confirmation was captured; confidence remains low.'
            : (requestEvidenceStory?.lowConfidenceReason || null),
    };
}

function computeRuntimeConfirmationProgress(
    execution: FocusedTestCaseExecution,
    evidenceBundles: EvidenceBundle[],
    investigationIssues: FocusedInvestigationIssue[],
    suspicionScore: number,
): number {
    const baseByExecutionState: Record<FocusedTestCaseExecution['executionState'], number> = {
        ready: 0,
        running: 18,
        completed: 34,
        blocked: 22,
        failed_to_execute: 18,
        skipped: 10,
    };
    let progress = baseByExecutionState[execution.executionState] || 0;
    progress += Math.min(evidenceBundles.length * 7, 28);
    progress += evidenceBundles.some((bundle) => !!bundle.responseDiffSummary) ? 12 : 0;
    progress += evidenceBundles.some((bundle) => !!bundle.browserState || !!bundle.screenshotRef) ? 10 : 0;
    progress += suspicionScore >= 45 ? 8 : suspicionScore >= 25 ? 4 : 0;
    const blockingIssues = investigationIssues.filter((issue) => issue.impact === 'blocking' && (issue.issueStatus === 'open' || issue.issueStatus === 'unresolved' || issue.issueStatus === 'partially_resolved')).length;
    const degradingIssues = investigationIssues.filter((issue) => issue.impact === 'degrading' && (issue.issueStatus === 'open' || issue.issueStatus === 'unresolved' || issue.issueStatus === 'partially_resolved')).length;
    progress -= Math.min(blockingIssues * 10, 20);
    progress -= Math.min(degradingIssues * 4, 8);
    return clampScore(progress);
}

function determineThreadStatus(input: {
    execution: FocusedTestCaseExecution;
    suspicionScore: number;
    confirmationProgress: number;
    blockingConstraints: string[];
    confirmationState: FocusedConfirmationState;
}): FocusedFindingThreadStatus {
    if (input.execution.executionState === 'blocked' || input.execution.executionState === 'failed_to_execute') {
        return input.confirmationState.exhausted ? 'exhausted' : 'blocked';
    }
    if (input.confirmationState.exhausted) {
        return 'exhausted';
    }
    if (input.confirmationState.readyForAdaptiveConfirmation && input.suspicionScore >= 45) {
        return 'confirming';
    }
    if (input.suspicionScore >= 25 || input.confirmationProgress >= 35) {
        return 'strengthening';
    }
    if (input.blockingConstraints.length > 0 && input.confirmationProgress < 35) {
        return 'blocked';
    }
    return 'collecting';
}

function computeSuspicionScore(
    family: FocusedCaseFamily,
    verdict: FocusedCaseVerdict | null,
    supportSignals: string[],
    blockingConstraints: string[],
): number {
    if (!verdict) {
        return 10;
    }

    const markers = verdict.interpretationSummary.signalMarkers || [];
    const primaryMarkerCount = markers.filter((entry) => PRIMARY_MARKER_BONUS.has(entry)).length;
    const secondaryMarkerCount = markers.filter((entry) => SECONDARY_MARKER_BONUS.has(entry)).length;
    const contradictionPenalty = verdict.interpretationSummary.contradictorySignals.length > 0 ? 14 : 0;
    const controlHeldPenalty = markers.includes('control_held') ? 16 : 0;

    let score = SUSPICIOUSNESS_BASE[verdict.interpretationSummary.suspiciousness];

    if (verdict.verdictState === 'fail') {
        score += 15;
    } else if (verdict.verdictState === 'needs_review') {
        score += 10;
    } else if (verdict.verdictState === 'pass') {
        score -= 14;
    }

    score += Math.min(verdict.interpretationSummary.failSignals.length * 6, 18);
    score += Math.min(verdict.interpretationSummary.reviewSignals.length * 5, 15);
    score += Math.min(verdict.interpretationSummary.suspiciousSignals.length * 4, 12);
    score += Math.min(primaryMarkerCount * 8, 20);
    score += Math.min(secondaryMarkerCount * 5, 10);
    score += verdict.evidenceSufficiency.state === 'sufficient' ? 8 : 0;
    score += supportSignals.length > 0 ? 4 : 0;
    score -= contradictionPenalty;
    score -= controlHeldPenalty;
    score -= verdict.scopeViolationImpact.underminesConfidence ? 8 : 0;
    score -= blockingConstraints.some((entry) => /unsupported verification primitive/i.test(entry)) ? 3 : 0;

    if (family === 'generic' && primaryMarkerCount === 0) {
        score -= 5;
    }

    return clampScore(score);
}

function computeRuntimeSuspicionScore(
    family: FocusedCaseFamily,
    interpretation: Pick<FocusedCaseVerdict['interpretationSummary'], 'suspiciousness' | 'signalMarkers' | 'failSignals' | 'reviewSignals' | 'suspiciousSignals' | 'contradictorySignals'>,
    supportSignals: string[],
    blockingConstraints: string[],
): number {
    const markers = interpretation.signalMarkers || [];
    const primaryMarkerCount = markers.filter((entry) => PRIMARY_MARKER_BONUS.has(entry)).length;
    const secondaryMarkerCount = markers.filter((entry) => SECONDARY_MARKER_BONUS.has(entry)).length;
    const contradictionPenalty = interpretation.contradictorySignals.length > 0 ? 12 : 0;
    const controlHeldPenalty = markers.includes('control_held') ? 12 : 0;
    let score = SUSPICIOUSNESS_BASE[interpretation.suspiciousness];

    score += Math.min(interpretation.failSignals.length * 7, 18);
    score += Math.min(interpretation.reviewSignals.length * 6, 18);
    score += Math.min(interpretation.suspiciousSignals.length * 5, 15);
    score += Math.min(primaryMarkerCount * 8, 20);
    score += Math.min(secondaryMarkerCount * 5, 10);
    score += supportSignals.length > 0 ? 5 : 0;
    score -= contradictionPenalty;
    score -= controlHeldPenalty;
    score -= blockingConstraints.some((entry) => /unsupported verification primitive/i.test(entry)) ? 3 : 0;

    if (family === 'generic' && primaryMarkerCount === 0) {
        score -= 5;
    }

    return clampScore(score);
}

function computeConfirmationProgress(
    execution: FocusedTestCaseExecution,
    verdict: FocusedCaseVerdict | null,
    investigationIssues: FocusedInvestigationIssue[],
): number {
    const baseByExecutionState: Record<FocusedTestCaseExecution['executionState'], number> = {
        ready: 0,
        running: 15,
        completed: 35,
        blocked: 20,
        failed_to_execute: 18,
        skipped: 12,
    };

    let progress = baseByExecutionState[execution.executionState] || 0;

    if (!verdict) {
        return progress;
    }

    const satisfiedRequirements = verdict.evidenceSufficiency.requirementEvaluations.filter((entry) => entry.supported && entry.satisfied).length;
    const missingRequirements = verdict.evidenceSufficiency.missingRequirements.length;
    const unsupportedRequirements = verdict.evidenceSufficiency.unsupportedRequirements.length;
    const contradictorySignals = verdict.evidenceSufficiency.contradictorySignals.length;
    const blockingIssues = investigationIssues.filter((issue) => issue.impact === 'blocking' && (issue.issueStatus === 'open' || issue.issueStatus === 'unresolved' || issue.issueStatus === 'partially_resolved')).length;
    const degradingIssues = investigationIssues.filter((issue) => issue.impact === 'degrading' && (issue.issueStatus === 'open' || issue.issueStatus === 'unresolved' || issue.issueStatus === 'partially_resolved')).length;

    progress += verdict.evidenceSufficiency.anchoredToTarget ? 12 : 0;
    progress += Math.min((verdict.supportingEvidenceRefs.length || 0) * 4, 12);
    progress += Math.min(satisfiedRequirements * 6, 18);

    switch (verdict.evidenceSufficiency.state) {
        case 'sufficient':
            progress += 28;
            break;
        case 'unsupported':
            progress += 10;
            break;
        case 'insufficient':
            progress += 8;
            break;
        case 'contradictory':
            progress += 5;
            break;
        default:
            break;
    }

    if (verdict.interpretationSummary.signalMarkers.includes('browser_expectation_met') || verdict.interpretationSummary.signalMarkers.includes('browser_expectation_missed')) {
        progress += 6;
    }

    progress -= Math.min(missingRequirements * 7, 21);
    progress -= Math.min(unsupportedRequirements * 8, 16);
    progress -= Math.min(contradictorySignals * 10, 20);
    progress -= verdict.scopeViolationImpact.underminesConfidence ? 20 : 0;
    progress -= Math.min(blockingIssues * 10, 20);
    progress -= Math.min(degradingIssues * 5, 10);

    return clampScore(progress);
}

function determineFindingStatus(input: {
    verdict: FocusedCaseVerdict | null;
    suspicionScore: number;
    confirmationProgress: number;
    blockingConstraints: string[];
}): FocusedFindingStatus {
    const verdict = input.verdict;
    const hasNonTrivialSignal = input.suspicionScore >= 25
        || (verdict?.interpretationSummary.reviewSignals.length || 0) > 0
        || (verdict?.interpretationSummary.failSignals.length || 0) > 0
        || (verdict?.interpretationSummary.suspiciousSignals.length || 0) > 0;
    const hasBlockingCondition = input.blockingConstraints.length > 0
        || verdict?.scopeViolationImpact.underminesConfidence
        || verdict?.evidenceSufficiency.state === 'insufficient'
        || verdict?.evidenceSufficiency.state === 'unsupported'
        || verdict?.evidenceSufficiency.state === 'contradictory';

    if (
        verdict
        && verdict.verdictState === 'fail'
        && verdict.evidenceSufficiency.state === 'sufficient'
        && !verdict.scopeViolationImpact.underminesConfidence
        && verdict.interpretationSummary.contradictorySignals.length === 0
        && input.confirmationProgress >= 85
    ) {
        return 'confirmed';
    }

    if (verdict?.verdictState !== 'pass' && input.suspicionScore >= 70 && input.confirmationProgress >= 55) {
        return 'likely';
    }

    if (verdict?.verdictState !== 'pass' && input.suspicionScore >= 45) {
        return 'suspicious';
    }

    if (hasNonTrivialSignal && hasBlockingCondition) {
        return 'inconclusive';
    }

    return 'not_confirmed';
}

function determineConfidenceBand(status: FocusedFindingStatus, suspicionScore: number, confirmationProgress: number): FocusedFindingConfidenceBand {
    if (status === 'confirmed' || (status === 'likely' && suspicionScore >= 85 && confirmationProgress >= 70)) {
        return 'high';
    }
    if (suspicionScore >= 55 || confirmationProgress >= 45 || status === 'likely' || status === 'suspicious') {
        return 'medium';
    }
    return 'low';
}

export class FocusedFindingService {
    private readonly deps: FindingDependencies;

    constructor(
        deps: Partial<FindingDependencies> = {},
    ) {
        this.deps = {
            visibilityService: focusedReasoningVisibilityService,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public seedRuntimeThread(input: {
        objective: FocusedTestObjective;
        testCase: FocusedTestCase;
        execution: FocusedTestCaseExecution;
    }): FocusedFindingThread {
        return this.updateRuntimeThread({
            objective: input.objective,
            testCase: input.testCase,
            execution: input.execution,
            evidenceBundles: [],
            investigationIssues: [],
            linkedTraceIds: [],
            linkedVerdictIds: [],
            linkedInvestigationIds: [],
            confirmationState: {
                maxAdaptiveFollowUps: Math.max(0, Number(input.testCase.maxAdaptiveFollowUps) || 0),
                usedAdaptiveFollowUps: 0,
                preferredRail: input.testCase.preferredRail || 'request',
                allowedConfirmationKinds: input.testCase.allowedConfirmationKinds || [],
                recommendedConfirmationKinds: [],
                nextKind: null,
                nextStepSummary: null,
                readyForAdaptiveConfirmation: false,
                exhausted: false,
                stopReason: null,
                steps: [],
            },
            previousThread: null,
            verdict: null,
        });
    }

    public updateRuntimeThread(input: RuntimeThreadUpdateInput): FocusedFindingThread {
        const previousThread = input.previousThread
            || getFocusedFindingThreadByExecution(input.testCase.scanId, input.testCase.id, input.execution.id, `family:${input.testCase.caseFamily || resolveFocusedCaseFamily(input.objective, input.testCase)}:runtime`);
        const visibility = this.deps.visibilityService.buildCaseVisibility(input.testCase.scanId, input.testCase.id, input.execution.id);
        const family = input.testCase.caseFamily || resolveFocusedCaseFamily(input.objective, input.testCase);
        const liveInterpretation = input.verdict?.interpretationSummary || interpretFocusedSignals({
            objective: input.objective,
            testCase: {
                ...input.testCase,
                caseFamily: family,
            },
            execution: input.execution,
            evidenceBundles: input.evidenceBundles,
        });
        const supportSignals = uniqueStrings([
            ...buildSupportSignals(input.verdict || null, visibility),
            ...liveInterpretation.failSignals,
            ...liveInterpretation.reviewSignals,
            ...liveInterpretation.suspiciousSignals,
            liveInterpretation.strongestSupport || null,
        ]);
        const requestEvidenceStory = input.verdict?.requestEvidenceStory || buildRuntimeRequestEvidenceStory(
            input.testCase,
            family,
            liveInterpretation,
            input.evidenceBundles,
        );
        const supportProvenance = input.verdict?.supportProvenance || buildRuntimeSupportProvenance(
            input.testCase,
            family,
            input.evidenceBundles,
            requestEvidenceStory,
        );
        const blockingConstraints = uniqueStrings([
            ...buildBlockingConstraints(input.verdict || null, input.execution, input.investigationIssues, visibility),
            ...(input.verdict?.interpretationSummary.controlSignals || []).map((entry) => `Control held: ${entry}`),
            ...liveInterpretation.contradictorySignals,
            ...liveInterpretation.controlSignals.map((entry) => `Control held: ${entry}`),
            ...liveInterpretation.missingEvidence,
            ...liveInterpretation.uncertaintyReasons,
            liveInterpretation.strongestBlocker || null,
            supportProvenance.lowConfidenceReason || null,
        ]);
        let suspicionScore = input.verdict
            ? computeSuspicionScore(family, input.verdict || null, supportSignals, blockingConstraints)
            : computeRuntimeSuspicionScore(family, liveInterpretation, supportSignals, blockingConstraints);
        let confirmationProgress = input.verdict
            ? computeConfirmationProgress(input.execution, input.verdict, input.investigationIssues)
            : computeRuntimeConfirmationProgress(input.execution, input.evidenceBundles, input.investigationIssues, suspicionScore);
        if (supportProvenance.requestHeavy && !supportProvenance.requestBackedEvidence) {
            suspicionScore = Math.min(suspicionScore, 30);
            confirmationProgress = Math.min(confirmationProgress, 34);
        }
        const confidenceBand = determineConfidenceBand(
            input.verdict
                ? determineFindingStatus({
                    verdict: input.verdict,
                    suspicionScore,
                    confirmationProgress,
                    blockingConstraints,
                })
                : suspicionScore >= 70
                    ? 'likely'
                    : suspicionScore >= 45
                        ? 'suspicious'
                        : blockingConstraints.length > 0
                            ? 'inconclusive'
                            : 'not_confirmed',
            suspicionScore,
            confirmationProgress,
        );
        const evidenceRefs = buildEvidenceRefsFromBundles(input.evidenceBundles);
        const blockingEvidenceRefs = evidenceRefs.filter((entry) => entry.role === 'scope_violation' || entry.role === 'note');
        const strongestSupportSummary = liveInterpretation.strongestSupport
            || supportSignals[0]
            || input.verdict?.verdictReason
            || visibility.suspicionExplanation?.whySuspicious
            || `Bounded execution is still collecting ${formatFamilyLabel(family).toLowerCase()} evidence.`;
        const strongestBlockerSummary = liveInterpretation.strongestBlocker || blockingConstraints[0] || null;
        const mergedConfirmationState: FocusedConfirmationState = {
            maxAdaptiveFollowUps: Math.max(0, Number(input.confirmationState?.maxAdaptiveFollowUps ?? previousThread?.confirmationState.maxAdaptiveFollowUps ?? input.testCase.maxAdaptiveFollowUps) || 0),
            usedAdaptiveFollowUps: Math.max(0, Number(input.confirmationState?.usedAdaptiveFollowUps ?? previousThread?.confirmationState.usedAdaptiveFollowUps) || 0),
            preferredRail: input.confirmationState?.preferredRail || previousThread?.confirmationState.preferredRail || input.testCase.preferredRail || 'request',
            allowedConfirmationKinds: input.confirmationState?.allowedConfirmationKinds || previousThread?.confirmationState.allowedConfirmationKinds || input.testCase.allowedConfirmationKinds || [],
            recommendedConfirmationKinds: Array.isArray(input.confirmationState?.recommendedConfirmationKinds)
                ? input.confirmationState!.recommendedConfirmationKinds
                : (liveInterpretation.recommendedConfirmationKinds || previousThread?.confirmationState.recommendedConfirmationKinds || input.testCase.allowedConfirmationKinds || []),
            nextKind: input.confirmationState?.nextKind !== undefined
                ? input.confirmationState.nextKind
                : (liveInterpretation.recommendedConfirmationKinds?.[0]
                    || previousThread?.confirmationState.nextKind
                    || input.testCase.allowedConfirmationKinds?.[0]
                    || null),
            nextStepSummary: input.confirmationState?.nextStepSummary
                || liveInterpretation.nextStepSummary
                || previousThread?.confirmationState.nextStepSummary
                || buildNextStepSummary({
                    family,
                    verdict: input.verdict || null,
                    investigationIssues: input.investigationIssues,
                    supportSignals,
                    blockingConstraints,
                    execution: input.execution,
                }),
            readyForAdaptiveConfirmation: (
                input.confirmationState?.readyForAdaptiveConfirmation
                ?? Boolean(
                    liveInterpretation.confirmationReadiness === 'ready'
                    || (suspicionScore >= 45 && blockingConstraints.length === 0),
                )
            ) && !(supportProvenance.requestHeavy && !supportProvenance.requestBackedEvidence),
            exhausted: input.confirmationState?.exhausted
                ?? ((Number(input.confirmationState?.usedAdaptiveFollowUps ?? previousThread?.confirmationState.usedAdaptiveFollowUps) || 0)
                    >= (Number(input.confirmationState?.maxAdaptiveFollowUps ?? previousThread?.confirmationState.maxAdaptiveFollowUps ?? input.testCase.maxAdaptiveFollowUps) || 0)),
            stopReason: input.confirmationState?.stopReason
                || previousThread?.confirmationState.stopReason
                || supportProvenance.lowConfidenceReason
                || liveInterpretation.followUpDecisionSummary
                || strongestBlockerSummary
                || null,
            steps: input.confirmationState?.steps
                || previousThread?.confirmationState.steps
                || [],
        };
        const status = determineThreadStatus({
            execution: input.execution,
            suspicionScore,
            confirmationProgress,
            blockingConstraints,
            confirmationState: mergedConfirmationState,
        });
        const thread: FocusedFindingThread = {
            id: previousThread?.id || this.deps.createId(),
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            executionId: input.execution.id,
            objectiveId: input.testCase.objectiveId,
            findingKey: previousThread?.findingKey || `family:${family}:runtime`,
            title: previousThread?.title || buildFindingTitle(family, input.testCase, input.verdict?.interpretationSummary.parameterHints?.[0] || null),
            family,
            status,
            suspicionScore,
            confirmationProgress,
            confidenceBand,
            isPrimary: true,
            strongestSupportSummary,
            strongestSuspiciousSignal: liveInterpretation.strongestSupport || supportSignals[0] || strongestSupportSummary,
            strongestBlockerSummary,
            nextStepSummary: mergedConfirmationState.nextStepSummary || null,
            stopReason: mergedConfirmationState.stopReason || null,
            supportingSignals: supportSignals.slice(0, 6),
            blockingConstraints: blockingConstraints.slice(0, 6),
            supportingEvidenceRefs: evidenceRefs.slice(0, 8),
            blockingEvidenceRefs: blockingEvidenceRefs.slice(0, 8),
            supportProvenance,
            requestEvidenceStory,
            linkedTraceIds: [...new Set([...(previousThread?.linkedTraceIds || []), ...(input.linkedTraceIds || [])])],
            linkedVerdictIds: [...new Set([...(previousThread?.linkedVerdictIds || []), ...(input.linkedVerdictIds || [])])],
            linkedInvestigationIds: [...new Set([...(previousThread?.linkedInvestigationIds || []), ...(input.linkedInvestigationIds || []), ...input.investigationIssues.map((issue) => issue.id)])],
            confirmationState: mergedConfirmationState,
            publishedFindingId: previousThread?.publishedFindingId || null,
            createdAt: previousThread?.createdAt || this.deps.now(),
            updatedAt: this.deps.now(),
        };
        upsertFocusedFindingThread(thread);
        return thread;
    }

    public async generateNow(scanId: string): Promise<{
        scanId: string;
        focusedFindings: FocusedCaseFinding[];
        focusedFindingSummary: FocusedScanFindingSummary | null;
    }> {
        return this.publishFindings(scanId);
    }

    public async publishFindings(scanId: string): Promise<{
        scanId: string;
        focusedFindings: FocusedCaseFinding[];
        focusedFindingSummary: FocusedScanFindingSummary | null;
    }> {
        const objective = getFocusedTestObjective(scanId);
        if (!objective) {
            return {
                scanId,
                focusedFindings: [],
                focusedFindingSummary: getFocusedScanFindingSummary(scanId),
            };
        }

        for (const testCase of listFocusedTestCasesByScan(scanId)) {
            const execution = getLatestFocusedTestCaseExecution(scanId, testCase.id);
            if (!execution) {
                continue;
            }

            const verdict = getFocusedCaseVerdictByExecution(scanId, testCase.id, execution.id);
            const evidenceBundles = listEvidenceBundlesByExecution(scanId, testCase.id, execution.id);
            const investigationIssues = listFocusedInvestigationIssuesByExecution(scanId, testCase.id, execution.id);
            const visibility = this.deps.visibilityService.buildCaseVisibility(scanId, testCase.id, execution.id);
            const findingThreads = listFocusedFindingThreadsByExecution(scanId, testCase.id, execution.id);
            const findings = this.synthesizeCaseFindings({
                objective,
                testCase,
                execution,
                verdict,
                evidenceBundles,
                investigationIssues,
                visibility,
                findingThreads,
            });

            for (const finding of findings) {
                upsertFocusedCaseFinding(finding);
            }

            if (findingThreads.length > 0 && findings[0]) {
                const primaryThread = findingThreads.find((entry) => entry.isPrimary) || findingThreads[0];
                upsertFocusedFindingThread({
                    ...primaryThread,
                    status: 'published',
                    publishedFindingId: findings[0].id,
                    linkedVerdictIds: verdict ? [verdict.id, ...primaryThread.linkedVerdictIds] : primaryThread.linkedVerdictIds,
                    updatedAt: this.deps.now(),
                });
            }
        }

        return {
            scanId,
            focusedFindings: listLatestPrimaryFocusedCaseFindingsByScan(scanId),
            focusedFindingSummary: getFocusedScanFindingSummary(scanId),
        };
    }

    private synthesizeCaseFindings(input: SynthesizedCaseFindingContext): FocusedCaseFinding[] {
        const familyCandidates = buildFamilyCandidates(input.objective, input.testCase, input.verdict);
        const parameterHint = input.verdict?.interpretationSummary.parameterHints?.[0]
            || input.testCase.targetArtifact.referenceId
            || null;
        const supportSignals = buildSupportSignals(input.verdict, input.visibility);
        const blockingConstraints = buildBlockingConstraints(input.verdict, input.execution, input.investigationIssues, input.visibility);
        const requestEvidenceStory = input.verdict?.requestEvidenceStory || null;
        const supportProvenance = input.verdict?.supportProvenance || buildRuntimeSupportProvenance(
            input.testCase,
            input.verdict?.interpretationSummary.caseFamily || resolveFocusedCaseFamily(input.objective, input.testCase),
            input.evidenceBundles,
            requestEvidenceStory,
        );
        const findings = familyCandidates.map(({ family, orderHint }) => {
            let suspicionScore = computeSuspicionScore(family, input.verdict, supportSignals, blockingConstraints);
            let confirmationProgress = computeConfirmationProgress(input.execution, input.verdict, input.investigationIssues);
            if (supportProvenance.requestHeavy && !supportProvenance.requestBackedEvidence) {
                suspicionScore = Math.min(suspicionScore, 30);
                confirmationProgress = Math.min(confirmationProgress, 34);
            }
            const status = determineFindingStatus({
                verdict: input.verdict,
                suspicionScore,
                confirmationProgress,
                blockingConstraints,
            });
            const confidenceBand = determineConfidenceBand(status, suspicionScore, confirmationProgress);
            const strongestSupportSummary = supportSignals[0]
                || input.verdict?.verdictReason
                || input.visibility.suspicionExplanation?.whySuspicious
                || `Bounded execution produced limited ${formatFamilyLabel(family).toLowerCase()} evidence.`;

            return {
                id: this.deps.createId(),
                scanId: input.testCase.scanId,
                caseId: input.testCase.id,
                executionId: input.execution.id,
                objectiveId: input.testCase.objectiveId,
                findingKey: `family:${family}`,
                title: buildFindingTitle(family, input.testCase, parameterHint),
                family,
                status,
                suspicionScore,
                confirmationProgress,
                confidenceBand,
                rankOrder: orderHint,
                isPrimary: false,
                strongestSupportSummary,
                blockingConstraintSummary: blockingConstraints[0] || null,
                nextStepSummary: buildNextStepSummary({
                    family,
                    verdict: input.verdict,
                    investigationIssues: input.investigationIssues,
                    supportSignals,
                    blockingConstraints,
                    execution: input.execution,
                }),
                supportingSignals: supportSignals.slice(0, 5),
                blockingConstraints: blockingConstraints.slice(0, 5),
                supportingEvidenceRefs: input.verdict?.supportingEvidenceRefs || [],
                supportProvenance,
                requestEvidenceStory,
                linkedVerdictIds: input.verdict ? [input.verdict.id] : [],
                linkedInvestigationIds: input.investigationIssues.map((issue) => issue.id),
                createdAt: this.deps.now(),
                updatedAt: this.deps.now(),
            } satisfies FocusedCaseFinding;
        });
        const primaryThread = input.findingThreads?.find((entry) => entry.isPrimary) || input.findingThreads?.[0] || null;
        const threadBackedFinding = primaryThread
            ? ({
                id: primaryThread.publishedFindingId || this.deps.createId(),
                scanId: primaryThread.scanId,
                caseId: primaryThread.caseId,
                executionId: primaryThread.executionId,
                objectiveId: primaryThread.objectiveId,
                findingKey: primaryThread.findingKey.replace(':runtime', ''),
                title: primaryThread.title,
                family: primaryThread.family,
                status: input.verdict
                    ? determineFindingStatus({
                        verdict: input.verdict,
                        suspicionScore: primaryThread.suspicionScore,
                        confirmationProgress: primaryThread.confirmationProgress,
                        blockingConstraints: primaryThread.blockingConstraints,
                    })
                    : (primaryThread.suspicionScore >= 70
                        ? 'likely'
                        : primaryThread.suspicionScore >= 45
                            ? 'suspicious'
                            : primaryThread.blockingConstraints.length > 0
                                ? 'inconclusive'
                                : 'not_confirmed'),
                suspicionScore: primaryThread.suspicionScore,
                confirmationProgress: primaryThread.confirmationProgress,
                confidenceBand: primaryThread.confidenceBand,
                rankOrder: -1,
                isPrimary: true,
                strongestSupportSummary: primaryThread.strongestSupportSummary || supportSignals[0] || input.visibility.suspicionExplanation?.whySuspicious || primaryThread.title,
                blockingConstraintSummary: primaryThread.strongestBlockerSummary || primaryThread.blockingConstraints[0] || null,
                nextStepSummary: primaryThread.nextStepSummary || null,
                supportingSignals: primaryThread.supportingSignals.slice(0, 5),
                blockingConstraints: primaryThread.blockingConstraints.slice(0, 5),
                supportingEvidenceRefs: primaryThread.supportingEvidenceRefs,
                supportProvenance: primaryThread.supportProvenance || supportProvenance,
                requestEvidenceStory: primaryThread.requestEvidenceStory || requestEvidenceStory,
                linkedVerdictIds: input.verdict ? [input.verdict.id, ...primaryThread.linkedVerdictIds] : primaryThread.linkedVerdictIds,
                linkedInvestigationIds: primaryThread.linkedInvestigationIds,
                createdAt: primaryThread.createdAt || this.deps.now(),
                updatedAt: this.deps.now(),
            } satisfies FocusedCaseFinding)
            : null;

        return (threadBackedFinding
            ? [threadBackedFinding, ...findings.filter((finding) => finding.family !== threadBackedFinding.family)]
            : findings)
            .sort((left, right) => {
                if (FINDING_STATUS_RANK[left.status] !== FINDING_STATUS_RANK[right.status]) {
                    return FINDING_STATUS_RANK[left.status] - FINDING_STATUS_RANK[right.status];
                }
                if (left.suspicionScore !== right.suspicionScore) {
                    return right.suspicionScore - left.suspicionScore;
                }
                if (left.confirmationProgress !== right.confirmationProgress) {
                    return right.confirmationProgress - left.confirmationProgress;
                }
                if (left.rankOrder !== right.rankOrder) {
                    return left.rankOrder - right.rankOrder;
                }
                return left.title.localeCompare(right.title);
            })
            .slice(0, MAX_FINDINGS_PER_CASE)
            .map((finding, index) => ({
                ...finding,
                isPrimary: index === 0,
                rankOrder: index,
            }));
    }
}

export const focusedFindingService = new FocusedFindingService();
