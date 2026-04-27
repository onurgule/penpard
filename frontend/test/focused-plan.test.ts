import test from 'node:test';
import assert from 'node:assert/strict';

import {
    buildScopedAnchorSummary,
    buildFocusedCaseRows,
    buildFocusedEvidenceEmptyState,
    buildFocusedReasoningTracePreview,
    buildFocusedScanFindingRows,
    formatFocusedBlockerRecurrence,
    formatFocusedCaseCompareStatus,
    formatFocusedEvidenceDriftClassification,
    formatFocusedEvidenceCount,
    formatFocusedEvidenceSufficiencyState,
    formatFocusedExecutionPresentationState,
    formatFocusedExecutionState,
    formatFocusedConfirmationKind,
    formatFocusedFindingConfidenceBand,
    formatFocusedFindingFamily,
    formatFocusedFindingStatus,
    formatFocusedFindingThreadStatus,
    formatFocusedHypothesisStatus,
    formatFocusedHistoricalCompareStatus,
    formatFocusedHistoricalOutcome,
    formatFocusedInvestigationImpact,
    formatFocusedInvestigationStatus,
    formatFocusedInvestigationType,
    formatFocusedOverallChangeClassification,
    formatFocusedPriority,
    formatFocusedRailSummary,
    formatFocusedReasoningEntryType,
    formatFocusedReasoningRail,
    formatFocusedReasoningStage,
    formatFocusedRequestEvidenceRef,
    formatFocusedReviewState,
    formatFocusedRequestContextField,
    formatFocusedSupportProvenanceRail,
    formatFocusedSupportProvenanceSummary,
    formatFocusedSuspicionProofStatus,
    formatScopedFeatureDiscoveryOutcome,
    formatScopedFeatureDiscoveryPhase,
    formatScopedWorkflowStage,
    formatFocusedTargetArtifact,
    formatFocusedVerdictTransition,
    formatFocusedVerdictState,
    getScopedRecommendedAction,
    isScopedExecutionStage,
    isScopedReviewStage,
    summarizeScopedPlanReviewCounts,
    type FocusedFindingThread,
    type FocusedTestCase,
} from '../src/app/scan/[id]/focused-plan';

const sampleCases: FocusedTestCase[] = [
    {
        id: 'case-disabled',
        scanId: 'scan-1',
        objectiveId: 'objective-1',
        title: 'Disabled low-priority case',
        hypothesis: 'Disabled hypothesis',
        targetArtifact: { kind: 'feature', label: 'Billing export' },
        preconditions: [],
        steps: [{ order: 1, action: 'Do a thing' }],
        assertions: [{ kind: 'control', description: 'Should block' }],
        requiredEvidence: [{ kind: 'response', description: 'Capture response' }],
        priority: 'low',
        plannerRationaleSummary: 'Disabled rationale',
        status: 'disabled',
        reviewState: 'rejected',
        executionState: 'skipped',
        executionPresentationState: 'skipped_disabled',
    },
    {
        id: 'case-high',
        scanId: 'scan-1',
        objectiveId: 'objective-1',
        title: 'Authorization boundary',
        hypothesis: 'High priority hypothesis',
        targetArtifact: { kind: 'endpoint', method: 'get', path: '/api/orders/:id' },
        preconditions: [],
        steps: [{ order: 1, action: 'Replay the request' }],
        assertions: [{ kind: 'authz', description: 'Should deny unauthorized access' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture response diff' }],
        priority: 'high',
        plannerRationaleSummary: 'High priority rationale',
        status: 'planned',
        reviewState: 'pending_review',
        executionState: 'ready',
        executionPresentationState: 'awaiting_approval',
    },
    {
        id: 'case-medium',
        scanId: 'scan-1',
        objectiveId: 'objective-1',
        title: 'API contract misuse',
        hypothesis: 'Medium priority hypothesis',
        targetArtifact: { kind: 'baseline_request', method: 'POST', path: '/api/orders', label: 'POST /api/orders' },
        preconditions: [],
        steps: [{ order: 1, action: 'Alter a field' }],
        assertions: [{ kind: 'validation', description: 'Should reject invalid payloads' }],
        requiredEvidence: [{ kind: 'status_code', description: 'Capture status code' }],
        priority: 'medium',
        plannerRationaleSummary: 'Medium priority rationale',
        caseFamily: 'input_validation',
        caseIntelligence: {
            selectionSummary: 'POST /api/orders stayed inside the persisted scoped anchors and exposed a quantity-style input worth checking.',
            anchorSummary: 'Execution stays anchored to the persisted POST /api/orders baseline request.',
            candidateInputs: [{
                name: 'quantity',
                location: 'body',
                reason: 'Observed body field from the seeded request.',
                mutationStrategy: 'boundary_value',
                observedValuePreview: '5',
            }],
            securityConcerns: [{
                family: 'input_validation',
                title: 'Contract enforcement on quantity',
                whyRelevant: 'Quantity accepts bounded one-field variations without widening scope.',
                strengtheningSignals: ['Invalid quantity is unexpectedly accepted.'],
                weakeningSignals: ['Invalid quantity is rejected cleanly.'],
                boundedChecks: ['Keep the variation on the quantity field only.'],
            }],
            followUpPolicy: {
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['control_contrast'],
                queueThresholdScore: 40,
                strongSignalMarkers: ['validation_rejected'],
                boundedBy: ['Observed fields only'],
                stopConditions: ['Missing evidence blocks further follow-up'],
            },
        },
        status: 'planned',
        reviewState: 'approved',
        executionState: 'completed',
        executionPresentationState: 'completed_with_evidence',
        lastExecutionId: 'exec-1',
        evidenceCount: 2,
        scopeViolationCount: 1,
        executionRailSummary: {
            rail: 'request',
            summary: 'Request-backed bounded execution used 2 Burp/MCP-backed action(s).',
            requestActionsUsed: 2,
            browserActionsUsed: 0,
            usedRequestRail: true,
            usedBrowserRail: false,
            usedBurpMcp: true,
            traceCount: 3,
        },
        latestExecutionTracePreview: [{
            id: 'trace-1',
            scanId: 'scan-1',
            caseId: 'case-medium',
            executionId: 'exec-1',
            timestamp: '2026-04-18T10:00:00.000Z',
            actionType: 'execution_started',
            actionSummary: 'Focused execution started.',
            rail: 'system',
            linkedEvidenceIds: [],
        }],
        latestReasoningTracePreview: [{
            id: 'reasoning-1',
            scanId: 'scan-1',
            objectiveId: 'objective-1',
            caseId: 'case-medium',
            executionId: 'exec-1',
            timestamp: '2026-04-18T10:00:10.000Z',
            stage: 'execution',
            entryType: 'observation',
            rail: 'request',
            caseFamily: 'input_validation',
            summary: 'The bounded mutation was rejected with a 403 response.',
            requestResponseImpactSummary: 'POST /api/orders => HTTP 403',
            linkedEvidenceIds: ['evidence-1'],
            linkedRequestContextKeys: ['testData'],
            contextInfluence: [{
                field: 'testData',
                effect: 'used',
                summary: 'Seeded order data focused the bounded mutation.',
            }],
        }],
        hypothesisVisibility: {
            caseFamily: 'input_validation',
            initialSupport: ['Planner kept the case bounded to POST /api/orders.'],
            strengtheningSignals: ['Status 200 to 403 after bounded mutation'],
            weakeningSignals: [],
            blockingConstraints: [],
            currentStatus: 'strengthened',
            latestConfidenceSummary: 'Confidence increased because the bounded control held.',
        },
        suspicionExplanation: {
            caseFamily: 'input_validation',
            suspiciousness: 'low',
            whySuspicious: 'The bounded mutation was rejected while the baseline request succeeded.',
            supportingSignals: ['Status 200 to 403 after bounded mutation'],
            weakeningSignals: [],
            contradictorySignals: [],
            proofStatus: 'supported',
            boundedStopReason: null,
            missingEvidence: [],
        },
        investigationSummary: {
            caseId: 'case-medium',
            totalIssues: 2,
            unresolvedCount: 1,
            blockingCount: 1,
            degradingCount: 0,
            latestIssueTitle: 'Focused verification exhausted the approved browser budget.',
            latestIssueStatus: 'unresolved',
            latestImpact: 'blocking',
            latestIssueType: 'execution_budget_exhausted',
            latestDetectedAt: '2026-04-18T10:00:45.000Z',
        },
        latestVerdict: {
            id: 'verdict-1',
            scanId: 'scan-1',
            caseId: 'case-medium',
            executionId: 'exec-1',
            objectiveId: 'objective-1',
            verdictState: 'pass',
            verdictReason: 'Bounded mutation was rejected while the baseline request succeeded.',
            evidenceSufficiency: {
                state: 'sufficient',
                summary: 'Required supported evidence was captured and anchored to the intended scoped target.',
                anchoredToTarget: true,
                anchoredMethod: 'POST',
                anchoredPath: '/api/orders',
                supportingEvidenceIds: ['evidence-1'],
                missingRequirements: [],
                unsupportedRequirements: [],
                contradictorySignals: [],
                underminedByScopeViolation: false,
                requirementEvaluations: [],
            },
            interpretationSummary: {
                caseFamily: 'input_validation',
                suspiciousness: 'low',
                summary: 'Completed execution captured the expected control-enforcement signal.',
                suspiciousSignals: [],
                passSignals: ['Status 200 to 403 after bounded mutation'],
                failSignals: [],
                reviewSignals: [],
                contradictorySignals: [],
                keywordSignals: [],
                signalMarkers: ['validation_rejected', 'control_held'],
                parameterHints: ['quantity'],
            },
            supportingEvidenceRefs: [],
            scopeViolationImpact: {
                hasScopeViolation: false,
                severity: 'none',
                underminesConfidence: false,
                reasons: [],
            },
            executionSnapshot: {
                executionId: 'exec-1',
                executionState: 'completed',
                executionProfileKey: 'generic:test',
                requestActionsUsed: 2,
                browserActionsUsed: 0,
            },
            verdictAt: '2026-04-18T10:01:00.000Z',
        },
        primaryFinding: {
            id: 'finding-1',
            scanId: 'scan-1',
            caseId: 'case-medium',
            executionId: 'exec-1',
            objectiveId: 'objective-1',
            findingKey: 'family:input_validation',
            title: 'Potential Input Validation Weakness in quantity parameter',
            family: 'input_validation',
            status: 'suspicious',
            suspicionScore: 58,
            confirmationProgress: 42,
            confidenceBand: 'medium',
            rankOrder: 0,
            isPrimary: true,
            strongestSupportSummary: 'Status 200 to 403 after bounded mutation',
            blockingConstraintSummary: 'Missing required evidence: response_excerpt.',
            nextStepSummary: 'Capture the missing response excerpt from the strongest suspicious replay.',
            supportingSignals: ['Status 200 to 403 after bounded mutation'],
            blockingConstraints: ['Missing required evidence: response_excerpt.'],
            supportingEvidenceRefs: [],
            linkedVerdictIds: ['verdict-1'],
            linkedInvestigationIds: ['issue-1'],
        },
        findings: [{
            id: 'finding-1',
            scanId: 'scan-1',
            caseId: 'case-medium',
            executionId: 'exec-1',
            objectiveId: 'objective-1',
            findingKey: 'family:input_validation',
            title: 'Potential Input Validation Weakness in quantity parameter',
            family: 'input_validation',
            status: 'suspicious',
            suspicionScore: 58,
            confirmationProgress: 42,
            confidenceBand: 'medium',
            rankOrder: 0,
            isPrimary: true,
            strongestSupportSummary: 'Status 200 to 403 after bounded mutation',
            blockingConstraintSummary: 'Missing required evidence: response_excerpt.',
            nextStepSummary: 'Capture the missing response excerpt from the strongest suspicious replay.',
            supportingSignals: ['Status 200 to 403 after bounded mutation'],
            blockingConstraints: ['Missing required evidence: response_excerpt.'],
            supportingEvidenceRefs: [],
            linkedVerdictIds: ['verdict-1'],
            linkedInvestigationIds: ['issue-1'],
        }],
        historicalCompare: {
            id: 'compare-1',
            currentScanId: 'scan-1',
            currentCaseId: 'case-medium',
            currentExecutionId: 'exec-1',
            caseIdentityKey: 'identity-1',
            caseVariantKey: 'variant-1',
            previousScanId: 'scan-0',
            previousCaseId: 'case-medium-old',
            previousExecutionId: 'exec-0',
            compareStatus: 'exact_match',
            historicalOutcome: 'weaker_confidence',
            priorVerdict: 'pass',
            currentVerdict: 'pass',
            verdictTransition: 'pass_to_pass',
            priorEvidenceSufficiency: 'sufficient',
            currentEvidenceSufficiency: 'sufficient',
            priorVerdictReason: 'Older run passed.',
            currentVerdictReason: 'Current run passed with weaker evidence.',
            priorEvidenceSummary: 'Previous evidence was fully anchored.',
            currentEvidenceSummary: 'Current evidence was captured with a scope warning.',
            evidenceDriftClassification: 'weaker_confidence',
            blockerRecurrence: {
                recurringUnresolvedIssueFamilies: ['execution_budget_exhausted'],
                resolvedIssueFamilies: [],
                newlyIntroducedIssueFamilies: [],
                recurringWorkaroundFailureFamilies: [],
                blockingCountDelta: 0,
                degradingCountDelta: 0,
                notes: ['Recurring unresolved blocker families: execution_budget_exhausted.'],
            },
            latestCompareAt: '2026-04-18T10:02:00.000Z',
        },
    },
];

test('buildFocusedCaseRows sorts suspicious cases first while preserving execution metadata', () => {
    const rows = buildFocusedCaseRows(sampleCases);

    assert.deepEqual(rows.map((row) => row.id), ['case-medium', 'case-high', 'case-disabled']);
    assert.equal(rows[0]?.targetLabel, 'POST /api/orders');
    assert.equal(rows[0]?.executionPresentationState, 'completed_with_evidence');
    assert.equal(rows[0]?.evidenceCount, 2);
    assert.equal(rows[0]?.executionRailSummary?.rail, 'request');
    assert.equal(rows[0]?.investigationSummary?.latestIssueType, 'execution_budget_exhausted');
    assert.equal(rows[0]?.latestVerdict?.verdictState, 'pass');
    assert.equal(rows[0]?.historicalCompare?.historicalOutcome, 'weaker_confidence');
    assert.equal(rows[0]?.hypothesisVisibility?.currentStatus, 'strengthened');
    assert.equal(rows[0]?.suspicionExplanation?.proofStatus, 'supported');
    assert.equal(rows[0]?.caseIntelligence?.candidateInputs[0]?.name, 'quantity');
    assert.equal(rows[1]?.targetLabel, 'GET /api/orders/:id');
    assert.equal(rows[1]?.hypothesis, 'High priority hypothesis');
});

test('focused finding helpers surface primary findings and operator-facing labels for Mission Control', () => {
    const rows = buildFocusedCaseRows(sampleCases);
    const findingRows = buildFocusedScanFindingRows(
        sampleCases.flatMap((testCase) => testCase.findings || []),
        sampleCases,
    );

    assert.equal(rows[0]?.primaryFinding?.title, 'Potential Input Validation Weakness in quantity parameter');
    assert.equal(rows[0]?.secondaryFindingsCount, 0);
    assert.equal(findingRows.length, 1);
    assert.equal(findingRows[0]?.caseTitle, 'API contract misuse');
    assert.equal(formatFocusedFindingStatus('suspicious'), 'Suspicious');
    assert.equal(formatFocusedFindingConfidenceBand('medium'), 'Medium confidence');
    assert.equal(formatFocusedFindingFamily('input_validation'), 'Input Validation');
});

test('focused plan helpers format target artifacts and review stages consistently', () => {
    assert.equal(formatFocusedTargetArtifact({ kind: 'flow', label: 'Password reset journey' }), 'Password reset journey');
    assert.equal(isScopedReviewStage('scoped', 'planning'), false);
    assert.equal(isScopedReviewStage('scoped', 'awaiting_review'), true);
    assert.equal(isScopedExecutionStage('scoped', 'scoped_executing'), true);
    assert.equal(isScopedReviewStage('exploratory', 'planning'), false);
    assert.equal(formatFocusedExecutionState('failed_to_execute'), 'Failed');
    assert.equal(formatFocusedExecutionPresentationState('skipped_not_approved'), 'Skipped - not approved');
    assert.equal(formatFocusedEvidenceCount(2, 1), '2 evidence (1 scope violation)');
    assert.equal(formatFocusedRailSummary(sampleCases[2].executionRailSummary), 'Request-backed bounded execution used 2 Burp/MCP-backed action(s).');
    assert.equal(formatFocusedReasoningRail('system_only'), 'System-only');
    assert.equal(formatFocusedReasoningStage('historical_compare'), 'Historical compare');
    assert.equal(formatFocusedReasoningEntryType('constraint'), 'Constraint');
    assert.equal(formatFocusedHypothesisStatus('stalled'), 'Stalled');
    assert.equal(formatFocusedSuspicionProofStatus('blocked'), 'Blocked');
    assert.equal(formatFocusedRequestContextField('attachmentSummary'), 'Attachment summary');
    assert.equal(formatFocusedSupportProvenanceRail('request'), 'Request-backed');
    assert.equal(
        formatFocusedSupportProvenanceSummary({
            rail: 'browser',
            requestHeavy: true,
            requestBackedEvidence: false,
            browserBackedEvidence: true,
            requestEvidenceIds: [],
            browserEvidenceIds: ['evidence-1'],
            systemEvidenceIds: [],
            summary: 'Browser-backed support only; this request-heavy case still lacks Burp-visible request confirmation.',
            lowConfidenceReason: 'No request-backed confirmation was captured; confidence remains low.',
        }),
        'Browser-backed support only; this request-heavy case still lacks Burp-visible request confirmation.',
    );
    assert.equal(
        formatFocusedRequestEvidenceRef({
            evidenceId: 'evidence-1',
            source: 'mutated_replay',
            summary: 'Mutated replay on the same request rail.',
            capturedAt: '2026-04-18T10:00:30.000Z',
            method: 'GET',
            url: 'https://app.example.com/api/orders/2',
            path: '/api/orders/2',
            host: 'app.example.com',
            statusCode: 403,
            executionPhase: 'adaptive_confirmation',
            confirmationKind: 'alternate_id_compare',
            confirmationOrdinal: 1,
            relatedEvidenceIds: ['evidence-baseline'],
        }),
        'GET /api/orders/2 · HTTP 403 · confirmation 1',
    );
    assert.equal(formatFocusedInvestigationStatus('partially_resolved'), 'Partially Resolved');
    assert.equal(formatFocusedInvestigationImpact('blocking'), 'Blocking');
    assert.equal(formatFocusedInvestigationType('blocked_flow'), 'Blocked Flow');
    assert.equal(formatFocusedVerdictState('needs_review'), 'Needs Review');
    assert.equal(formatFocusedEvidenceSufficiencyState('unsupported'), 'Unsupported');
    assert.equal(formatFocusedHistoricalCompareStatus('baseline_created'), 'Baseline Created');
    assert.equal(formatFocusedCaseCompareStatus('not_comparable'), 'Not comparable');
    assert.equal(formatFocusedHistoricalOutcome('regressed'), 'Regressed');
    assert.equal(formatFocusedVerdictTransition('pass_to_inconclusive'), 'Pass -> Inconclusive');
    assert.equal(formatFocusedEvidenceDriftClassification('scope_risk_increased'), 'Scope risk increased');
    assert.equal(formatFocusedOverallChangeClassification('instability'), 'Instability');
    assert.equal(formatFocusedPriority('high'), 'High Priority');
    assert.equal(formatFocusedReviewState('pending_review'), 'Legacy Manual Review');
    assert.equal(formatScopedWorkflowStage('awaiting_review'), 'Legacy Manual Review');
    assert.equal(
        formatFocusedBlockerRecurrence(sampleCases[2].historicalCompare),
        'Recurring blockers: Budget Exhausted',
    );
    assert.equal(
        buildFocusedEvidenceEmptyState({ presentationState: 'awaiting_approval', reviewState: 'pending_review', status: 'planned' }),
        'This legacy scoped case has not run yet because it is still waiting for manual review.',
    );
});

test('reasoning helpers build previews and preserve latest reasoning state for Mission Control', () => {
    const preview = buildFocusedReasoningTracePreview(sampleCases[2].latestReasoningTracePreview, 1);

    assert.equal(preview.length, 1);
    assert.equal(preview[0]?.stage, 'execution');
    assert.equal(preview[0]?.summary, 'The bounded mutation was rejected with a 403 response.');
    assert.equal(sampleCases[2].latestReasoningTracePreview?.[0]?.linkedRequestContextKeys[0], 'testData');
});

test('scoped discovery helpers format phases, outcomes, and anchor summaries', () => {
    assert.equal(formatScopedFeatureDiscoveryPhase('discovering'), 'Discovering');
    assert.equal(formatScopedFeatureDiscoveryPhase('ready_to_plan'), 'Ready to Plan');
    assert.equal(formatScopedFeatureDiscoveryPhase(undefined), 'Not Started');
    assert.equal(formatScopedFeatureDiscoveryOutcome('candidate_anchors_found'), 'Candidate Anchors Found');
    assert.equal(formatScopedFeatureDiscoveryOutcome('partial_anchors_found'), 'Partial Anchors Found');
    assert.equal(formatScopedFeatureDiscoveryOutcome(undefined), 'Pending');
    assert.equal(
        buildScopedAnchorSummary(
            {
                allowedHosts: ['app.example.com'],
                allowedRoutes: ['/feature', '/api/feature'],
                selectedEndpoints: [{ method: 'GET', path: '/api/feature' }],
                discoveredRequestRefs: [{ id: 'req-1', source: 'browser', path: '/api/feature' }],
                browserAnchors: [{ id: 'browser-1', startUrl: 'https://app.example.com/feature', source: 'request_url' }],
                boundaryHints: [],
                outOfScopeNotes: [],
            },
            null,
        ),
        '1 endpoint anchor | 1 request ref | 1 browser anchor | 2 routes',
    );
    assert.equal(
        buildScopedAnchorSummary(
            null,
            {
                phase: 'discovering',
                outcome: null,
                requestAnchorCount: 2,
                browserAnchorCount: 1,
                selectedEndpointCount: 0,
                allowedRouteCount: 3,
            },
        ),
        '0 endpoint anchors | 2 request refs | 1 browser anchor | 3 routes',
    );
});

test('scoped review summary helpers count cases and recommend the next operator action', () => {
    const counts = summarizeScopedPlanReviewCounts(sampleCases, null);

    assert.deepEqual(counts, {
        totalCases: 3,
        enabledCount: 2,
        disabledCount: 1,
        pendingReviewCount: 1,
        approvedCount: 1,
        rejectedCount: 1,
    });
    assert.equal(getScopedRecommendedAction('scoped_discovering', counts), 'Watching feature anchors form');
    assert.equal(getScopedRecommendedAction('planning', counts), 'Seeding internal bounded hypotheses');
    assert.equal(getScopedRecommendedAction('awaiting_review', counts), 'Legacy recovery: review pending cases');
    assert.equal(getScopedRecommendedAction('scoped_executing', counts), 'Follow live logs, requests, and findings');
    assert.equal(
        getScopedRecommendedAction('scoped_executed', counts),
        'Inspect findings and bounded evidence',
    );
    assert.equal(
        getScopedRecommendedAction('awaiting_review', {
            ...counts,
            pendingReviewCount: 0,
            approvedCount: 2,
        }),
        'Legacy recovery: run approved cases',
    );
});

test('focused finding helpers also surface provisional runtime threads for Mission Control', () => {
    const runtimeThread: FocusedFindingThread = {
        id: 'thread-1',
        scanId: 'scan-1',
        caseId: 'case-high',
        executionId: 'exec-thread-1',
        objectiveId: 'objective-1',
        findingKey: 'family:access_control:runtime',
        title: 'Potential Access Control Bypass on GET /api/orders/:id',
        family: 'access_control',
        status: 'confirming',
        suspicionScore: 67,
        confirmationProgress: 59,
        confidenceBand: 'medium',
        isPrimary: true,
        strongestSupportSummary: 'The bounded signal is strong enough to justify one extra confirmation replay.',
        strongestSuspiciousSignal: 'The bounded signal is strong enough to justify one extra confirmation replay.',
        strongestBlockerSummary: 'Alternate-id confirmation has not run yet.',
        nextStepSummary: 'Run one bounded alternate-id compare.',
        stopReason: null,
        supportingSignals: ['The bounded signal is strong enough to justify one extra confirmation replay.'],
        blockingConstraints: ['Alternate-id confirmation has not run yet.'],
        supportingEvidenceRefs: [],
        blockingEvidenceRefs: [],
        linkedTraceIds: ['trace-thread-1'],
        linkedVerdictIds: [],
        linkedInvestigationIds: [],
        confirmationState: {
            maxAdaptiveFollowUps: 1,
            usedAdaptiveFollowUps: 0,
            preferredRail: 'request',
            allowedConfirmationKinds: ['alternate_id_compare'],
            recommendedConfirmationKinds: ['alternate_id_compare'],
            nextKind: 'alternate_id_compare',
            nextStepSummary: 'Run one bounded alternate-id compare.',
            readyForAdaptiveConfirmation: true,
            exhausted: false,
            stopReason: null,
            steps: [],
        },
    };

    const rows = buildFocusedScanFindingRows([], sampleCases, [runtimeThread]);

    assert.equal(rows.length, 1);
    assert.equal(rows[0].source, 'runtime_thread');
    assert.equal(rows[0].thread?.id, 'thread-1');
    assert.equal(rows[0].finding.title, 'Potential Access Control Bypass on GET /api/orders/:id');
    assert.equal(rows[0].finding.status, 'suspicious');
    assert.equal(formatFocusedFindingThreadStatus(runtimeThread.status), 'Confirming');
    assert.equal(formatFocusedConfirmationKind(runtimeThread.confirmationState.nextKind), 'Alternate-id compare');
});
