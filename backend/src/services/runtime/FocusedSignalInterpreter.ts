import type {
    EvidenceBundle,
    FocusedCaseFamily,
    FocusedConfirmationKind,
    FocusedSignalMarker,
    FocusedSignalInterpretationSummary,
    FocusedSignalSuspiciousness,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedTestObjective,
} from './ScopedScanTypes';
import {
    normalizeFocusedCaseFamily,
    normalizeFocusedConfirmationReadiness,
    normalizeFocusedSignalSuspiciousness,
} from './ScopedScanTypes';

const ACCESS_CONTROL_ASSERTION_KINDS = new Set([
    'authz',
    'authz_enforced',
    'object_isolation',
    'idor',
    'access_control',
    'forbidden',
    'scope_respected',
]);

const INPUT_VALIDATION_ASSERTION_KINDS = new Set([
    'validation',
    'validation_enforced',
    'contract_enforced',
    'csrf_enforced',
    'security_control',
    'state_change_blocked',
]);

const ERROR_HANDLING_ASSERTION_KINDS = new Set([
    'error_safety',
    'safe_failure',
    'error_handling',
]);

const WORKFLOW_LOGIC_ASSERTION_KINDS = new Set([
    'workflow_logic',
    'business_logic',
    'state_change',
    'state_unchanged',
    'state_transition',
    'state_mismatch',
    'sequence_integrity',
    'duplicate_effect',
    'workflow',
    'flow',
]);

const XSS_ASSERTION_KINDS = new Set([
    'xss',
    'dom_xss',
    'script_reflection',
    'rendered_output',
]);

const SQLI_MARKERS = new Set([
    'SQL_ERROR',
    'INTERNAL_ERROR',
    'STACK_TRACE_LEAKED',
]);

const STRONG_FAIL_KEYWORDS = new Set([
    'FORBIDDEN_BYPASSED',
    'PASSWORD_FIELD_EXPOSED',
    'EMAIL_DATA_LEAKED',
    'SCRIPT_TAG_REFLECTED',
    'EVENT_HANDLER_REFLECTED',
]);

const WORKFLOW_LOGIC_KEYWORDS = new Set([
    'STATE_MISMATCH',
    'STATE_REGRESSION',
    'UNEXPECTED_PERSISTENCE',
    'MISSING_PERSISTENCE',
    'DUPLICATE_SIDE_EFFECT',
    'SEQUENCE_OUT_OF_ORDER',
]);

function normalizeTokens(values: Array<string | null | undefined>): string[] {
    return values
        .map((value) => String(value || '').trim().toLowerCase())
        .filter((value) => value.length > 0);
}

function hasAnyToken(tokens: string[], expected: string[]): boolean {
    return tokens.some((token) => expected.some((entry) => token.includes(entry)));
}

function summarizeSignal(values: string[], fallback: string): string {
    return values.find((value) => value.trim().length > 0) || fallback;
}

function toKeywordSet(evidenceBundles: EvidenceBundle[]): string[] {
    return [...new Set(evidenceBundles.flatMap((bundle) => bundle.responseDiffSummary?.keywordSignals || []).map((entry) => String(entry || '').trim()).filter(Boolean))];
}

function addMarker(target: Set<FocusedSignalMarker>, marker: FocusedSignalMarker): void {
    target.add(marker);
}

function recommendedConfirmationKindsForFamily(caseFamily: FocusedCaseFamily): FocusedConfirmationKind[] {
    switch (caseFamily) {
        case 'sqli':
            return ['repeat_mutation', 'error_surface_compare'];
        case 'xss':
            return ['render_check', 'control_contrast'];
        case 'access_control':
            return ['alternate_id_compare', 'control_contrast'];
        case 'workflow_logic':
            return ['state_replay', 'control_contrast'];
        case 'error_handling':
            return ['error_surface_compare', 'repeat_mutation'];
        case 'input_validation':
            return ['control_contrast', 'error_surface_compare'];
        default:
            return ['control_contrast', 'repeat_mutation'];
    }
}

function estimateScoreDelta(input: {
    failSignals: string[];
    reviewSignals: string[];
    suspiciousSignals: string[];
    passSignals: string[];
    contradictorySignals: string[];
    signalMarkers: Set<FocusedSignalMarker>;
}): number {
    let delta = 0;
    delta += Math.min(input.failSignals.length * 16, 30);
    delta += Math.min(input.reviewSignals.length * 11, 22);
    delta += Math.min(input.suspiciousSignals.length * 8, 16);
    delta += Math.min(input.passSignals.length * -6, 0);
    delta -= Math.min(input.contradictorySignals.length * 12, 20);
    if (input.signalMarkers.has('authz_bypass')) {
        delta += 18;
    }
    if (input.signalMarkers.has('sql_error_marker')) {
        delta += 15;
    }
    if (input.signalMarkers.has('script_reflection_marker')) {
        delta += 15;
    }
    if (input.signalMarkers.has('workflow_state_shift')) {
        delta += 12;
    }
    if (input.signalMarkers.has('control_held')) {
        delta -= 10;
    }
    if (input.signalMarkers.has('contradictory_signal')) {
        delta -= 12;
    }
    return delta;
}

function buildMissingEvidence(input: {
    evidenceBundles: EvidenceBundle[];
    caseFamily: FocusedCaseFamily;
    suspiciousSignals: string[];
    reviewSignals: string[];
}): string[] {
    const missing: string[] = [];
    const hasComparison = input.evidenceBundles.some((bundle) => !!bundle.responseDiffSummary);
    const hasBrowserEvidence = input.evidenceBundles.some((bundle) => !!bundle.browserState || !!bundle.screenshotRef);
    const hasMutatedReplay = input.evidenceBundles.some((bundle) => bundle.source === 'mutated_replay');
    const hasBaselineReplay = input.evidenceBundles.some((bundle) => bundle.source === 'baseline_replay');

    if (!hasBaselineReplay) {
        missing.push('Baseline replay evidence is still missing.');
    }
    if (!hasMutatedReplay && (input.reviewSignals.length > 0 || input.suspiciousSignals.length > 0)) {
        missing.push('A bounded mutated replay is still missing.');
    }
    if (!hasComparison && (hasBaselineReplay || hasMutatedReplay)) {
        missing.push('A bounded response comparison is still missing.');
    }
    if ((input.caseFamily === 'xss' || input.caseFamily === 'workflow_logic') && !hasBrowserEvidence) {
        missing.push('Browser-backed verification evidence is still missing.');
    }
    return missing;
}

function extractParameterHints(evidenceBundles: EvidenceBundle[]): string[] {
    const candidates = evidenceBundles
        .filter((bundle) => bundle.source === 'mutated_replay' || bundle.source === 'baseline_replay')
        .flatMap((bundle) => [bundle.requestRef?.url, bundle.requestRef?.raw]);
    const hints = new Set<string>();

    for (const value of candidates) {
        const text = String(value || '').trim();
        if (!text) {
            continue;
        }

        const queryStart = text.indexOf('?');
        if (queryStart >= 0) {
            const queryText = text.slice(queryStart + 1).split(/[ #\r\n]/, 1)[0];
            for (const part of queryText.split('&')) {
                const key = part.split('=', 1)[0]?.trim();
                if (key) {
                    hints.add(key);
                }
            }
        }

        const formMatches = text.matchAll(/(?:^|[?&\r\n])([A-Za-z0-9_.-]{2,64})=/g);
        for (const match of formMatches) {
            const key = String(match[1] || '').trim();
            if (key) {
                hints.add(key);
            }
        }

        const jsonMatches = text.matchAll(/"([A-Za-z0-9_.-]{2,64})"\s*:/g);
        for (const match of jsonMatches) {
            const key = String(match[1] || '').trim();
            if (key) {
                hints.add(key);
            }
        }
    }

    return [...hints].slice(0, 8);
}

function isRequestHeavyCase(input: {
    caseFamily: FocusedCaseFamily;
    testCase: FocusedTestCase;
    evidenceBundles: EvidenceBundle[];
}): boolean {
    const requiredEvidenceKinds = new Set(normalizeTokens((input.testCase.requiredEvidence || []).map((entry) => entry.kind)));
    const assertionKinds = normalizeTokens((input.testCase.assertions || []).map((entry) => entry.kind));
    const requestBackedKinds = new Set([
        'response_diff',
        'status_code',
        'response_excerpt',
        'request_trace',
        'payload_trace',
        'scope_respected',
    ]);

    return input.testCase.targetArtifact.kind === 'endpoint'
        || input.testCase.targetArtifact.kind === 'baseline_request'
        || input.testCase.preferredRail === 'request'
        || input.caseFamily === 'sqli'
        || input.caseFamily === 'access_control'
        || input.caseFamily === 'input_validation'
        || input.caseFamily === 'error_handling'
        || [...requiredEvidenceKinds].some((kind) => requestBackedKinds.has(kind))
        || hasAnyToken(assertionKinds, ['authz', 'validation', 'contract', 'error', 'request', 'payload'])
        || input.evidenceBundles.some((bundle) => !!bundle.requestRef || !!bundle.responseRef || bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay');
}

export function resolveFocusedCaseFamily(
    objective: Pick<FocusedTestObjective, 'riskTags'> | null | undefined,
    testCase: Pick<FocusedTestCase, 'assertions' | 'requiredEvidence' | 'targetArtifact' | 'title' | 'hypothesis'>,
): FocusedCaseFamily {
    const riskTags = normalizeTokens(objective?.riskTags || []);
    const assertionKinds = normalizeTokens((testCase.assertions || []).map((entry) => entry.kind));
    const evidenceKinds = normalizeTokens((testCase.requiredEvidence || []).map((entry) => entry.kind));
    const freeText = normalizeTokens([
        testCase.targetArtifact.kind,
        testCase.title,
        testCase.hypothesis,
        ...riskTags,
        ...assertionKinds,
        ...evidenceKinds,
    ]);

    if (hasAnyToken(freeText, ['sqli', 'sql injection', 'sql', 'query manipulation', 'backend query'])) {
        return 'sqli';
    }
    if (hasAnyToken(freeText, ['xss', 'cross site', 'script', 'dom xss', 'render'])) {
        return 'xss';
    }
    if (assertionKinds.some((kind) => ACCESS_CONTROL_ASSERTION_KINDS.has(kind)) || hasAnyToken(freeText, ['authz', 'idor', 'access control', 'authorization'])) {
        return 'access_control';
    }
    if (assertionKinds.some((kind) => ERROR_HANDLING_ASSERTION_KINDS.has(kind)) || hasAnyToken(freeText, ['error safety', 'safe failure', 'error handling', 'internal error'])) {
        return 'error_handling';
    }
    if (
        assertionKinds.some((kind) => WORKFLOW_LOGIC_ASSERTION_KINDS.has(kind))
        || hasAnyToken(freeText, ['workflow', 'business logic', 'stateful', 'state mismatch', 'sequence', 'duplicate effect'])
    ) {
        return 'workflow_logic';
    }
    if (assertionKinds.some((kind) => INPUT_VALIDATION_ASSERTION_KINDS.has(kind)) || hasAnyToken(freeText, ['validation', 'contract', 'csrf'])) {
        return 'input_validation';
    }
    return 'generic';
}

export function interpretFocusedSignals(input: {
    objective?: FocusedTestObjective | null;
    testCase: FocusedTestCase;
    execution?: FocusedTestCaseExecution | null;
    evidenceBundles: EvidenceBundle[];
}): FocusedSignalInterpretationSummary {
    const caseFamily = normalizeFocusedCaseFamily(resolveFocusedCaseFamily(input.objective, input.testCase));
    const requestHeavy = isRequestHeavyCase({
        caseFamily,
        testCase: input.testCase,
        evidenceBundles: input.evidenceBundles,
    });
    const requestBackedEvidence = input.evidenceBundles.some((bundle) => bundle.source === 'baseline_replay'
        || bundle.source === 'mutated_replay'
        || !!bundle.requestRef
        || !!bundle.responseRef);
    const browserBackedEvidence = input.evidenceBundles.some((bundle) => !!bundle.browserState || !!bundle.screenshotRef);
    const assertionKinds = new Set(normalizeTokens((input.testCase.assertions || []).map((entry) => entry.kind)));
    const keywordSignals = toKeywordSet(input.evidenceBundles);
    const passSignals: string[] = [];
    const failSignals: string[] = [];
    const reviewSignals: string[] = [];
    const suspiciousSignals: string[] = [];
    const signalMarkers = new Set<FocusedSignalMarker>();
    const parameterHints = extractParameterHints(input.evidenceBundles);

    for (const bundle of input.evidenceBundles.filter((entry) => !!entry.responseDiffSummary)) {
        const diff = bundle.responseDiffSummary;
        if (!diff) {
            continue;
        }

        const originalStatus = typeof diff.originalStatus === 'number' ? diff.originalStatus : null;
        const mutatedStatus = typeof diff.mutatedStatus === 'number' ? diff.mutatedStatus : null;
        const keywords = (diff.keywordSignals || []).map((entry) => String(entry).split(':')[0]?.trim()).filter(Boolean) as string[];
        const hasStrongFailKeyword = keywords.some((entry) => STRONG_FAIL_KEYWORDS.has(entry));
        const hasSqliMarker = keywords.some((entry) => SQLI_MARKERS.has(entry));
        const hasWorkflowKeyword = keywords.some((entry) => WORKFLOW_LOGIC_KEYWORDS.has(entry));
        const controlExpected = [...assertionKinds].some((kind) => ACCESS_CONTROL_ASSERTION_KINDS.has(kind) || INPUT_VALIDATION_ASSERTION_KINDS.has(kind));
        const serverErrorTransition = originalStatus !== null
            && originalStatus >= 200
            && originalStatus < 400
            && mutatedStatus !== null
            && mutatedStatus >= 500;
        const workflowStateShift = diff.significant
            && originalStatus !== null
            && mutatedStatus !== null
            && originalStatus !== mutatedStatus;
        const validationBlocked = controlExpected
            && diff.significant
            && originalStatus !== null
            && originalStatus >= 200
            && originalStatus < 400
            && mutatedStatus !== null
            && mutatedStatus >= 400
            && mutatedStatus < 500;
        const authzBypass = (originalStatus === 401 || originalStatus === 403)
            && mutatedStatus !== null
            && mutatedStatus >= 200
            && mutatedStatus < 400;
        const strongStructuralDelta = diff.significant
            && (diff.structureChanged || Math.abs(diff.bodyLengthDelta || 0) >= 1200);

        if (authzBypass) {
            failSignals.push(diff.summary || 'The bounded mutation bypassed an authorization boundary.');
            addMarker(signalMarkers, 'authz_bypass');
            continue;
        }

        if (validationBlocked && (caseFamily === 'access_control' || caseFamily === 'input_validation' || caseFamily === 'error_handling')) {
            passSignals.push(diff.summary || 'The bounded mutation was rejected while the baseline flow succeeded.');
            addMarker(signalMarkers, 'validation_rejected');
            continue;
        }

        if (hasStrongFailKeyword) {
            addMarker(signalMarkers, 'strong_fail_keyword');
            if (keywords.some((entry) => entry === 'SCRIPT_TAG_REFLECTED' || entry === 'EVENT_HANDLER_REFLECTED')) {
                addMarker(signalMarkers, 'script_reflection_marker');
            }
            if (keywords.some((entry) => WORKFLOW_LOGIC_KEYWORDS.has(entry))) {
                addMarker(signalMarkers, 'state_mismatch_marker');
            }
            if (caseFamily === 'xss' || caseFamily === 'access_control') {
                failSignals.push(diff.summary || bundle.summary);
            } else {
                reviewSignals.push(diff.summary || bundle.summary);
                suspiciousSignals.push(diff.summary || bundle.summary);
            }
            continue;
        }

        if (caseFamily === 'sqli') {
            if (hasSqliMarker) {
                reviewSignals.push(diff.summary || 'The bounded mutation surfaced an internal backend error pattern.');
                suspiciousSignals.push(diff.summary || 'Observed a SQLi-style internal error signal.');
                addMarker(signalMarkers, 'sql_error_marker');
                continue;
            }
            if (serverErrorTransition) {
                reviewSignals.push(diff.summary || 'The bounded mutation shifted the response from success to server error.');
                suspiciousSignals.push(diff.summary || 'Observed a 200/300 to 500 transition during a SQLi-oriented case.');
                addMarker(signalMarkers, 'server_error_transition');
                continue;
            }
            if (strongStructuralDelta) {
                suspiciousSignals.push(diff.summary || 'Observed a strong response-structure change during a SQLi-oriented case.');
                addMarker(signalMarkers, 'strong_structural_delta');
            }
            continue;
        }

        if (caseFamily === 'workflow_logic') {
            if (hasWorkflowKeyword) {
                reviewSignals.push(diff.summary || 'The bounded workflow mutation changed persisted state in an unexpected way.');
                suspiciousSignals.push(diff.summary || 'Observed a workflow/state mismatch signal.');
                addMarker(signalMarkers, 'workflow_state_shift');
                addMarker(signalMarkers, 'state_mismatch_marker');
                continue;
            }
            if (workflowStateShift || strongStructuralDelta) {
                suspiciousSignals.push(diff.summary || 'Observed a material state or workflow delta during a workflow-logic case.');
                addMarker(signalMarkers, workflowStateShift ? 'workflow_state_shift' : 'strong_structural_delta');
                continue;
            }
        }

        if (caseFamily === 'error_handling' || caseFamily === 'generic') {
            if (hasSqliMarker || serverErrorTransition) {
                reviewSignals.push(diff.summary || 'The bounded mutation triggered an internal-error response that needs review.');
                suspiciousSignals.push(diff.summary || 'Observed an internal-error style response change.');
                addMarker(signalMarkers, hasSqliMarker ? 'sql_error_marker' : 'server_error_transition');
                continue;
            }
        }

        if (strongStructuralDelta && (caseFamily === 'xss' || caseFamily === 'generic')) {
            suspiciousSignals.push(diff.summary || 'Observed a material bounded response delta.');
            addMarker(signalMarkers, 'strong_structural_delta');
        }
    }

    for (const bundle of input.evidenceBundles.filter((entry) => !!entry.browserState)) {
        for (const expectation of bundle.browserState?.expectations || []) {
            if (expectation.matched) {
                addMarker(signalMarkers, 'browser_expectation_met');
                if (expectation.matcher === 'state_changed'
                    || expectation.matcher === 'state_unchanged'
                    || expectation.matcher === 'text_contains'
                    || expectation.matcher === 'text_absent'
                    || expectation.matcher === 'title_contains') {
                    passSignals.push(expectation.observedSummary);
                }
                continue;
            }

            addMarker(signalMarkers, 'browser_expectation_missed');
            if (expectation.matcher === 'state_changed'
                || expectation.matcher === 'state_unchanged'
                || expectation.matcher === 'text_contains'
                || expectation.matcher === 'text_absent'
                || expectation.matcher === 'title_contains') {
                if (caseFamily === 'xss') {
                    failSignals.push(expectation.observedSummary);
                    addMarker(signalMarkers, 'script_reflection_marker');
                } else if (caseFamily === 'workflow_logic') {
                    reviewSignals.push(expectation.observedSummary);
                    suspiciousSignals.push(expectation.observedSummary);
                    addMarker(signalMarkers, 'workflow_state_shift');
                } else {
                    reviewSignals.push(expectation.observedSummary);
                }
            }
        }
    }

    const contradictorySignals = passSignals.length > 0 && (failSignals.length > 0 || reviewSignals.length > 0)
        ? ['Persisted evidence contains both control-holding and suspicious outcome signals.']
        : [];
    const controlSignals = [...new Set(passSignals)];
    if (passSignals.length > 0) {
        addMarker(signalMarkers, 'control_held');
    }
    if (contradictorySignals.length > 0) {
        addMarker(signalMarkers, 'contradictory_signal');
    }

    let suspiciousness = normalizeFocusedSignalSuspiciousness(
        caseFamily === 'sqli' && (reviewSignals.length > 0 || suspiciousSignals.length > 0)
            ? 'high'
            : failSignals.length > 0 || reviewSignals.length > 1 || suspiciousSignals.length > 1
            ? 'high'
            : reviewSignals.length > 0 || suspiciousSignals.length > 0
                ? 'moderate'
                : passSignals.length > 0
                    ? 'low'
                    : 'none',
    );

    let summary = failSignals.length > 0
        ? summarizeSignal(failSignals, 'Completed execution produced a strong case-aware failure signal.')
        : reviewSignals.length > 0
            ? caseFamily === 'sqli'
                ? summarizeSignal(reviewSignals, 'SQLi-oriented suspicious signals warrant review, but they are not being treated as automatic exploit proof.')
                : summarizeSignal(reviewSignals, 'Suspicious bounded signals warrant review before the case is treated as final.')
            : passSignals.length > 0
                ? summarizeSignal(passSignals, 'Completed execution captured the expected control-enforcement signal.')
                : suspiciousSignals.length > 0
                    ? summarizeSignal(suspiciousSignals, 'Completed execution produced a material bounded signal that increases suspicion.')
                    : 'No strong case-aware pass, fail, or review signal was detected from persisted evidence.';
    const strongestSupport = failSignals[0]
        || reviewSignals[0]
        || suspiciousSignals[0]
        || passSignals[0]
        || summary;
    const strongestBlocker = contradictorySignals[0]
        || (passSignals.length > 0 && (reviewSignals.length > 0 || suspiciousSignals.length > 0)
            ? passSignals[0]
            : null);
    const missingEvidence = buildMissingEvidence({
        evidenceBundles: input.evidenceBundles,
        caseFamily,
        suspiciousSignals,
        reviewSignals,
    });
    const recommendedConfirmationKinds = recommendedConfirmationKindsForFamily(caseFamily);
    const scoreDelta = estimateScoreDelta({
        failSignals,
        reviewSignals,
        suspiciousSignals,
        passSignals,
        contradictorySignals,
        signalMarkers,
    });
    let confirmationReadiness = normalizeFocusedConfirmationReadiness(
        failSignals.length > 0 || reviewSignals.length > 0
            ? 'ready'
            : suspiciousSignals.length > 0
                ? 'watch'
                : 'not_ready',
    );
    const nextStepSummary = confirmationReadiness === 'ready'
        ? (() => {
            switch (recommendedConfirmationKinds[0]) {
                case 'alternate_id_compare':
                    return 'Run one alternate-id or contrast replay against the same scoped target.';
                case 'render_check':
                    return 'Run one bounded render-sensitive browser verification step.';
                case 'state_replay':
                    return 'Run one state-confirming replay tied to the same workflow artifact.';
                case 'error_surface_compare':
                    return 'Run one additional bounded error-surface comparison on the same target.';
                case 'control_contrast':
                    return 'Run one bounded control-contrast follow-up on the same target.';
                default:
                    return 'Run one additional bounded mutation and compare the result.';
            }
        })()
        : missingEvidence[0] || null;
    const uncertaintyReasons = [
        ...contradictorySignals,
        ...missingEvidence,
        ...(reviewSignals.length > 0 && failSignals.length === 0
            ? ['Suspicious same-scope evidence exists, but it still needs a stronger confirmation contrast.']
            : []),
        ...(suspiciousSignals.length > 0 && reviewSignals.length === 0 && failSignals.length === 0
            ? ['The signal is interesting, but the bounded run does not yet have enough evidence to treat it as strong proof.']
            : []),
    ].slice(0, 6);
    let followUpDecisionSummary = confirmationReadiness === 'ready'
        ? `Queue one bounded ${recommendedConfirmationKinds[0]?.replace(/_/g, ' ') || 'confirmation'} follow-up because suspicion materially increased inside scope.`
        : confirmationReadiness === 'watch'
            ? 'Preserve the suspicious signal, but wait for a stronger same-scope marker before queuing confirmation.'
            : controlSignals.length > 0
                ? 'Do not queue confirmation because the strongest persisted outcome is still a control-held result.'
                : missingEvidence[0] || 'No adaptive follow-up is justified from the currently persisted bounded evidence.';

    if (requestHeavy && !requestBackedEvidence) {
        suspiciousness = normalizeFocusedSignalSuspiciousness(
            suspiciousness === 'none'
                ? 'none'
                : 'low',
        );
        confirmationReadiness = normalizeFocusedConfirmationReadiness(
            confirmationReadiness === 'ready'
                ? 'watch'
                : confirmationReadiness,
        );
        summary = browserBackedEvidence
            ? 'No Burp-visible request confirmation was captured; browser observations remain supporting evidence only.'
            : 'No Burp-visible request confirmation was captured for this request-heavy case.';
        uncertaintyReasons.unshift(
            browserBackedEvidence
                ? 'Request-heavy suspicion is still missing Burp-visible request evidence, so browser observations remain supporting only.'
                : 'Request-heavy suspicion is still missing Burp-visible request evidence.',
        );
        followUpDecisionSummary = 'No request-backed confirmation was captured; confidence remains low until a Burp-visible replay exists.';
    }

    return {
        caseFamily,
        suspiciousness,
        summary,
        suspiciousSignals: [...new Set(suspiciousSignals)],
        passSignals: [...new Set(passSignals)],
        failSignals: [...new Set(failSignals)],
        reviewSignals: [...new Set(reviewSignals)],
        contradictorySignals,
        controlSignals,
        keywordSignals,
        signalMarkers: [...signalMarkers],
        parameterHints,
        scoreDelta,
        strongestSupport,
        strongestBlocker,
        missingEvidence,
        uncertaintyReasons,
        nextStepSummary,
        followUpDecisionSummary,
        confirmationReadiness,
        recommendedConfirmationKinds,
    };
}
