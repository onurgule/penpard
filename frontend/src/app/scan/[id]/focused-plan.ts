export type ScanMode = 'exploratory' | 'scoped';
export type ScopedFeatureDiscoveryPhase = 'not_started' | 'discovering' | 'ready_to_plan' | 'blocked';
export type ScopedFeatureDiscoveryOutcome = 'candidate_anchors_found' | 'partial_anchors_found' | 'no_useful_anchors';
export type FocusedTestCasePriority = 'high' | 'medium' | 'low';
export type FocusedTestCaseStatus = 'planned' | 'disabled';
export type FocusedTestCaseReviewState = 'pending_review' | 'approved' | 'rejected';
export type FocusedExecutionState = 'ready' | 'running' | 'completed' | 'blocked' | 'failed_to_execute' | 'skipped';
export type FocusedCaseFamily = 'generic' | 'sqli' | 'xss' | 'access_control' | 'input_validation' | 'error_handling' | 'workflow_logic';
export type FocusedCaseInputLocation = 'path' | 'query' | 'body' | 'header' | 'rendered_content' | 'identity' | 'workflow_state';
export type FocusedCaseMutationStrategy =
    | 'adjacent_identifier'
    | 'identity_contrast'
    | 'benign_render_marker'
    | 'boundary_value'
    | 'malformed_value'
    | 'type_contract_variation'
    | 'duplicate_replay'
    | 'state_toggle';
export type FocusedExecutionRail = 'system' | 'request' | 'browser' | 'hybrid';
export type FocusedSupportProvenanceRail = 'request' | 'browser' | 'hybrid' | 'system_only';
export type FocusedExecutionPhase = 'planned' | 'adaptive_confirmation';
export type FocusedFindingThreadStatus = 'collecting' | 'strengthening' | 'confirming' | 'blocked' | 'exhausted' | 'published';
export type FocusedConfirmationKind = 'repeat_mutation' | 'alternate_id_compare' | 'render_check' | 'state_replay' | 'error_surface_compare' | 'control_contrast';
export type FocusedConfirmationStepStatus = 'pending' | 'completed' | 'blocked' | 'skipped';
export type FocusedConfirmationReadiness = 'not_ready' | 'watch' | 'ready';
export type FocusedReasoningStage = 'request_intake' | 'feature_discovery' | 'planning' | 'review_gate' | 'execution' | 'verdict' | 'investigation' | 'historical_compare';
export type FocusedReasoningEntryType = 'context' | 'observation' | 'hypothesis' | 'decision' | 'action' | 'result' | 'constraint';
export type FocusedReasoningRail = 'request' | 'browser' | 'hybrid' | 'system_only';
export type FocusedRequestContextField = 'testData' | 'testUsers' | 'authMechanismHints' | 'attachmentSummary' | 'attachmentMetadata' | 'operatorNotes' | 'newScreenCount' | 'newInputCount';
export type FocusedReasoningContextEffect = 'used' | 'ignored' | 'insufficient';
export type FocusedExecutionPresentationState =
    | 'not_run_yet'
    | 'awaiting_approval'
    | 'skipped_not_approved'
    | 'skipped_disabled'
    | 'running'
    | 'blocked'
    | 'failed_to_execute'
    | 'completed_with_evidence'
    | 'completed_without_evidence';
export type FocusedExecutionTraceActionType =
    | 'execution_started'
    | 'retry_context'
    | 'action_planned'
    | 'request_dispatch'
    | 'response_observed'
    | 'response_compared'
    | 'browser_sequence_started'
    | 'browser_sequence_result'
    | 'screenshot_captured'
    | 'note_recorded'
    | 'blocked'
    | 'skipped'
    | 'execution_completed'
    | 'execution_failed';
export type FocusedSignalSuspiciousness = 'none' | 'low' | 'moderate' | 'high';
export type FocusedSignalMarker =
    | 'authz_bypass'
    | 'validation_rejected'
    | 'strong_fail_keyword'
    | 'sql_error_marker'
    | 'server_error_transition'
    | 'workflow_state_shift'
    | 'strong_structural_delta'
    | 'browser_expectation_met'
    | 'browser_expectation_missed'
    | 'script_reflection_marker'
    | 'state_mismatch_marker'
    | 'control_held'
    | 'contradictory_signal';
export type FocusedVerdictState = 'pass' | 'fail' | 'inconclusive' | 'needs_review';
export type FocusedEvidenceSufficiencyState = 'sufficient' | 'insufficient' | 'contradictory' | 'unsupported';
export type FocusedFindingStatus = 'confirmed' | 'likely' | 'suspicious' | 'inconclusive' | 'not_confirmed';
export type FocusedFindingConfidenceBand = 'low' | 'medium' | 'high';
export type FocusedHypothesisStatus = 'plausible' | 'strengthened' | 'weakened' | 'stalled' | 'contradicted';
export type FocusedSuspicionProofStatus = 'supported' | 'weak' | 'contradictory' | 'blocked';
export type FocusedEvidenceReasoningEffect = 'supports' | 'weakens' | 'contradicts' | 'bounds';
export type FocusedHistoricalCompareStatus = 'comparison_unavailable' | 'baseline_created' | 'compared' | 'not_comparable';
export type FocusedCaseCompareStatus = 'baseline_only' | 'exact_match' | 'likely_match' | 'newly_introduced' | 'not_comparable';
export type FocusedHistoricalOutcome = 'improved' | 'regressed' | 'unchanged' | 'weaker_confidence' | 'stronger_confidence' | 'newly_introduced' | 'not_comparable';
export type FocusedEvidenceDriftClassification = 'unchanged' | 'stronger_confidence' | 'weaker_confidence' | 'unsupported_gap_introduced' | 'contradiction_introduced' | 'scope_risk_increased';
export type FocusedOverallChangeClassification = 'baseline_only' | 'improvement' | 'regression' | 'instability' | 'no_material_change';
export type FocusedVerdictTransition =
    | 'pass_to_pass'
    | 'pass_to_fail'
    | 'pass_to_inconclusive'
    | 'pass_to_needs_review'
    | 'fail_to_pass'
    | 'fail_to_fail'
    | 'fail_to_inconclusive'
    | 'fail_to_needs_review'
    | 'inconclusive_to_pass'
    | 'inconclusive_to_fail'
    | 'inconclusive_to_inconclusive'
    | 'inconclusive_to_needs_review'
    | 'needs_review_to_pass'
    | 'needs_review_to_fail'
    | 'needs_review_to_inconclusive'
    | 'needs_review_to_needs_review';
export type FocusedInvestigationIssueType =
    | 'scope_violation'
    | 'auth_session_drift'
    | 'missing_anchor'
    | 'browser_state_mismatch'
    | 'evidence_insufficient'
    | 'execution_budget_exhausted'
    | 'request_replay_mismatch'
    | 'unexpected_navigation'
    | 'unsupported_verification_primitive'
    | 'environment_instability'
    | 'contradictory_signals'
    | 'retry_failure'
    | 'blocked_flow';
export type FocusedInvestigationIssueStatus = 'open' | 'resolved' | 'partially_resolved' | 'unresolved' | 'not_applicable';
export type FocusedInvestigationImpact = 'informational' | 'degrading' | 'blocking';
export type FocusedWorkaroundOutcome = 'resolved' | 'partially_resolved' | 'no_change' | 'introduced_uncertainty' | 'not_applicable';
export type FocusedTargetKind = 'endpoint' | 'baseline_request' | 'flow' | 'feature';
export type EvidenceBundleSource =
    | 'baseline_replay'
    | 'mutated_replay'
    | 'comparison'
    | 'browser_flow'
    | 'browser_verification'
    | 'execution_note'
    | 'scope_guard'
    | 'screenshot';

export interface FocusedExecutionTraceRequestSummary {
    method?: string | null;
    url?: string | null;
    path?: string | null;
    host?: string | null;
    mutationSummary?: string | null;
    targetInputs?: string[];
    expectedSignals?: string[];
    selectionReason?: string | null;
    executionPhase?: FocusedExecutionPhase | null;
    confirmationKind?: FocusedConfirmationKind | null;
    confirmationOrdinal?: number | null;
    generatedFromFindingThreadId?: string | null;
}

export interface FocusedExecutionTraceResponseSummary {
    statusCode?: number | null;
    bodySummary?: string | null;
    structureChanged?: boolean | null;
    bodyLengthDelta?: number | null;
    keywordSignals?: string[];
}

export interface FocusedExecutionTraceEntry {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    timestamp: string;
    actionType: FocusedExecutionTraceActionType;
    actionSummary: string;
    targetSummary?: string | null;
    requestSummary?: FocusedExecutionTraceRequestSummary | null;
    responseSummary?: FocusedExecutionTraceResponseSummary | null;
    reasoningNote?: string | null;
    nextStepRationale?: string | null;
    stopReason?: string | null;
    retryReason?: string | null;
    rail: FocusedExecutionRail;
    toolSummary?: string | null;
    linkedEvidenceIds: string[];
    createdAt?: string;
}

export interface FocusedRailUsageSummary {
    rail: FocusedExecutionRail;
    summary: string;
    requestActionsUsed: number;
    browserActionsUsed: number;
    usedRequestRail: boolean;
    usedBrowserRail: boolean;
    usedBurpMcp: boolean;
    traceCount: number;
}

export interface FocusedReasoningContextInfluence {
    field: FocusedRequestContextField;
    effect: FocusedReasoningContextEffect;
    summary: string;
}

export interface FocusedReasoningTraceEntry {
    id: string;
    scanId: string;
    objectiveId: string;
    caseId?: string | null;
    executionId?: string | null;
    timestamp: string;
    stage: FocusedReasoningStage;
    entryType: FocusedReasoningEntryType;
    rail: FocusedReasoningRail;
    caseFamily?: FocusedCaseFamily | null;
    summary: string;
    observationSummary?: string | null;
    hypothesisRationaleSummary?: string | null;
    actionSelectionRationale?: string | null;
    requestResponseImpactSummary?: string | null;
    browserStateImpactSummary?: string | null;
    confidenceShiftSummary?: string | null;
    stopRetryBlockRationale?: string | null;
    linkedEvidenceIds: string[];
    linkedRequestContextKeys: FocusedRequestContextField[];
    contextInfluence: FocusedReasoningContextInfluence[];
    createdAt?: string;
}

export interface FocusedHypothesisVisibility {
    caseFamily: FocusedCaseFamily;
    initialSupport: string[];
    strengtheningSignals: string[];
    weakeningSignals: string[];
    blockingConstraints: string[];
    currentStatus: FocusedHypothesisStatus;
    latestConfidenceSummary?: string | null;
}

export interface FocusedSuspicionExplanation {
    caseFamily: FocusedCaseFamily;
    suspiciousness: FocusedSignalSuspiciousness;
    whySuspicious: string;
    supportingSignals: string[];
    weakeningSignals: string[];
    contradictorySignals: string[];
    proofStatus: FocusedSuspicionProofStatus;
    boundedStopReason?: string | null;
    missingEvidence?: string[];
}

export interface FocusedContextInfluenceSummary {
    presentFields: FocusedRequestContextField[];
    usedFields: FocusedReasoningContextInfluence[];
    ignoredFields: FocusedReasoningContextInfluence[];
    insufficientFields: FocusedReasoningContextInfluence[];
    summary: string;
}

export interface FocusedEvidenceReasoningLink {
    evidenceId: string;
    role: 'baseline' | 'mutated' | 'comparison' | 'browser_flow' | 'browser_verification' | 'note' | 'scope_violation' | 'screenshot';
    whyItMatters: string;
    effect: FocusedEvidenceReasoningEffect;
    reasoningEntryIds: string[];
}

export interface FocusedSignalInterpretationSummary {
    caseFamily: FocusedCaseFamily;
    suspiciousness: FocusedSignalSuspiciousness;
    summary: string;
    suspiciousSignals: string[];
    passSignals: string[];
    failSignals: string[];
    reviewSignals: string[];
    contradictorySignals: string[];
    controlSignals?: string[];
    keywordSignals: string[];
    signalMarkers: FocusedSignalMarker[];
    parameterHints: string[];
    scoreDelta?: number;
    strongestSupport?: string | null;
    strongestBlocker?: string | null;
    missingEvidence?: string[];
    uncertaintyReasons?: string[];
    nextStepSummary?: string | null;
    followUpDecisionSummary?: string | null;
    confirmationReadiness?: FocusedConfirmationReadiness;
    recommendedConfirmationKinds?: FocusedConfirmationKind[];
}

export interface FocusedCaseIntelligenceCandidateInput {
    name: string;
    location: FocusedCaseInputLocation;
    reason: string;
    mutationStrategy: FocusedCaseMutationStrategy;
    observedValuePreview?: string | null;
}

export interface FocusedCaseIntelligenceConcern {
    family: FocusedCaseFamily;
    title: string;
    whyRelevant: string;
    strengtheningSignals: string[];
    weakeningSignals: string[];
    boundedChecks: string[];
}

export interface FocusedCaseFollowUpPolicy {
    maxAdaptiveFollowUps: number;
    allowedConfirmationKinds: FocusedConfirmationKind[];
    queueThresholdScore: number;
    strongSignalMarkers: FocusedSignalMarker[];
    boundedBy: string[];
    stopConditions: string[];
}

export interface FocusedCaseIntelligence {
    selectionSummary: string;
    anchorSummary: string;
    candidateInputs: FocusedCaseIntelligenceCandidateInput[];
    securityConcerns: FocusedCaseIntelligenceConcern[];
    followUpPolicy: FocusedCaseFollowUpPolicy;
}

export interface FocusedStoryCaseSummary {
    caseId: string;
    title: string;
    targetLabel: string;
    caseFamily: FocusedCaseFamily;
    suspiciousness: FocusedSignalSuspiciousness;
    currentBelief: string;
    whatWasTested: string;
    whatWasObserved: string;
    whyItMatters: string;
    targetedInputs: string[];
    blockedBy: string[];
    nextStep: string | null;
}

export interface FocusedStorySummary {
    headline: string;
    suspiciousCaseCount: number;
    blockedCaseCount: number;
    provisionalFindingCount: number;
    currentBeliefs: string[];
    unresolvedQuestions: string[];
    recommendedNextSteps: string[];
    cases: FocusedStoryCaseSummary[];
}

export interface FocusedTestObjectiveSummary {
    id: string;
    title: string;
    scopeType: 'request_scoped' | 'endpoint_scoped' | 'flow_scoped' | 'feature_scoped';
    featureDescription?: string;
    goal?: string;
    operatorNotes?: string;
    riskTags: string[];
}

export interface StructuredAttachmentMetadataSummary {
    label?: string;
    kind?: string;
    mimeType?: string;
    note?: string;
}

export interface StructuredSecurityTestRequestSummary {
    targetUrl: string;
    description: string;
    environment?: string;
    serviceName?: string;
    testData: string[];
    testUsers: string[];
    loginPresent?: boolean | null;
    authMechanismHints: string[];
    hasScreenshotOrAttachment?: boolean | null;
    attachmentMetadata: StructuredAttachmentMetadataSummary[];
    attachmentSummary?: string;
    newScreenCount?: number | null;
    newInputCount?: number | null;
    operatorNotes?: string;
}

export interface ScopedFeatureDiscoveryStateSummary {
    phase: ScopedFeatureDiscoveryPhase;
    outcome?: ScopedFeatureDiscoveryOutcome | null;
    summary?: string | null;
    errorMessage?: string | null;
    requestAnchorCount: number;
    browserAnchorCount: number;
    selectedEndpointCount: number;
    allowedRouteCount: number;
}

export interface ScopeEnvelopeSummary {
    allowedHosts: string[];
    allowedRoutes: string[];
    selectedEndpoints?: Array<{ method: string; path: string; url?: string; host?: string; source?: string; notes?: string[] }>;
    discoveredRequestRefs?: Array<{ id: string; source: string; method?: string; path?: string; url?: string; label?: string }>;
    browserAnchors?: Array<{ id: string; startUrl: string; startPath?: string; source: string; label?: string }>;
    boundaryHints: string[];
    outOfScopeNotes: string[];
    explorationBudget?: {
        maxRequests?: number | null;
        maxRouteVariants?: number | null;
        maxBrowserActions?: number | null;
        maxNavigationDepth?: number | null;
        maxVerificationRetries?: number | null;
        notes?: string | null;
    } | null;
}

export interface MissionControlLiveRuntimeSummary {
    missionState: string;
    targetUrl: string | null;
    objectiveTitle: string | null;
    objectiveGoal: string | null;
    requestDescription: string | null;
    currentRail: FocusedExecutionRail | null;
    activeCaseId: string | null;
    activeCaseTitle: string | null;
    activeFindingThreadId: string | null;
    activeFindingTitle: string | null;
    observationSummary: string | null;
    nextStepRationale: string | null;
    lastResponseDeltaSummary: string | null;
    boundaryReason: string | null;
    lastRequestSummary: {
        method?: string | null;
        path?: string | null;
        url?: string | null;
        statusCode?: number | null;
        summary: string;
    } | null;
    latestSuspiciousSignal: string | null;
    currentDecisionSummary: string | null;
    liveFindingCount: number;
    boundarySummary: {
        allowedHosts: string[];
        allowedRoutes: string[];
        selectedEndpointCount: number;
        browserAnchorCount: number;
        requestAnchorCount: number;
        boundaryHints: string[];
        outOfScopeNotes: string[];
        explorationBudget: Record<string, any> | null;
        blockedActionReason: string | null;
        activeAnchorSummary: string | null;
        budgetState: {
            maxRequests: number | null;
            requestActionsUsed: number;
            remainingRequests: number | null;
            maxBrowserActions: number | null;
            browserActionsUsed: number;
            remainingBrowserActions: number | null;
            maxRouteVariants: number | null;
            routeVariantsUsed: number;
        };
    } | null;
}

export type ScopedLiveRuntimeSummary = MissionControlLiveRuntimeSummary;

export interface FocusedTestCaseTargetArtifact {
    kind: FocusedTargetKind;
    method?: string;
    path?: string;
    url?: string;
    referenceKind?: string;
    referenceId?: string;
    label?: string;
}

export interface FocusedConfirmationStep {
    id: string;
    threadId: string;
    kind: FocusedConfirmationKind;
    status: FocusedConfirmationStepStatus;
    summary: string;
    actionType?: string | null;
    actionSummary?: string | null;
    evidenceIds: string[];
    traceIds: string[];
    startedAt?: string | null;
    completedAt?: string | null;
}

export interface FocusedConfirmationState {
    maxAdaptiveFollowUps: number;
    usedAdaptiveFollowUps: number;
    preferredRail: FocusedExecutionRail;
    allowedConfirmationKinds: FocusedConfirmationKind[];
    recommendedConfirmationKinds: FocusedConfirmationKind[];
    nextKind?: FocusedConfirmationKind | null;
    nextStepSummary?: string | null;
    readyForAdaptiveConfirmation: boolean;
    exhausted: boolean;
    stopReason?: string | null;
    steps: FocusedConfirmationStep[];
}

export interface FocusedFindingThread {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    objectiveId: string;
    findingKey: string;
    title: string;
    family: FocusedCaseFamily;
    status: FocusedFindingThreadStatus;
    suspicionScore: number;
    confirmationProgress: number;
    confidenceBand: FocusedFindingConfidenceBand;
    isPrimary: boolean;
    strongestSupportSummary?: string | null;
    strongestSuspiciousSignal?: string | null;
    strongestBlockerSummary?: string | null;
    nextStepSummary?: string | null;
    stopReason?: string | null;
    supportingSignals: string[];
    blockingConstraints: string[];
    supportingEvidenceRefs: FocusedVerdictEvidenceRef[];
    blockingEvidenceRefs: FocusedVerdictEvidenceRef[];
    supportProvenance?: FocusedSupportProvenanceSummary | null;
    requestEvidenceStory?: FocusedRequestEvidenceStory | null;
    linkedTraceIds: string[];
    linkedVerdictIds: string[];
    linkedInvestigationIds: string[];
    confirmationState: FocusedConfirmationState;
    publishedFindingId?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedTestCase {
    id: string;
    scanId: string;
    objectiveId: string;
    title: string;
    hypothesis: string;
    targetArtifact: FocusedTestCaseTargetArtifact;
    preconditions: string[];
    steps: Array<{ order: number; action: string }>;
    assertions: Array<{ kind: string; description: string }>;
    requiredEvidence: Array<{ kind: string; description: string }>;
    priority: FocusedTestCasePriority;
    plannerRationaleSummary: string;
    caseFamily?: FocusedCaseFamily | null;
    caseIntelligence?: FocusedCaseIntelligence | null;
    maxAdaptiveFollowUps?: number | null;
    preferredRail?: FocusedExecutionRail | null;
    allowedConfirmationKinds?: FocusedConfirmationKind[];
    status: FocusedTestCaseStatus;
    reviewState: FocusedTestCaseReviewState;
    executionState?: FocusedExecutionState;
    executionPresentationState?: FocusedExecutionPresentationState;
    lastRunAt?: string | null;
    lastCompletedAt?: string | null;
    lastExecutionId?: string | null;
    executionNotesSummary?: string | null;
    executionError?: string | null;
    evidenceCount?: number;
    browserEvidenceCount?: number;
    scopeViolationCount?: number;
    browserActionsUsed?: number;
    executionProfileKey?: string | null;
    browserSessionId?: string | null;
    executionRailSummary?: FocusedRailUsageSummary | null;
    latestExecutionTracePreview?: FocusedExecutionTraceEntry[];
    latestReasoningTracePreview?: FocusedReasoningTraceEntry[];
    hypothesisVisibility?: FocusedHypothesisVisibility | null;
    suspicionExplanation?: FocusedSuspicionExplanation | null;
    activeFindingThread?: FocusedFindingThread | null;
    findingThreads?: FocusedFindingThread[] | null;
    confirmationState?: FocusedConfirmationState | null;
    primaryFinding?: FocusedCaseFinding | null;
    findings?: FocusedCaseFinding[] | null;
    latestVerdict?: FocusedCaseVerdict | null;
    investigationSummary?: FocusedCaseInvestigationSummary | null;
    historicalCompare?: FocusedCaseHistoricalCompare | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedEvidenceRequirementEvaluation {
    kind: string;
    description: string;
    supported: boolean;
    satisfied: boolean;
    supportingEvidenceIds: string[];
    note?: string | null;
}

export interface FocusedEvidenceSufficiencyReport {
    state: FocusedEvidenceSufficiencyState;
    summary: string;
    anchoredToTarget: boolean;
    anchoredMethod?: string | null;
    anchoredPath?: string | null;
    supportingEvidenceIds: string[];
    missingRequirements: string[];
    unsupportedRequirements: string[];
    contradictorySignals: string[];
    underminedByScopeViolation: boolean;
    requirementEvaluations: FocusedEvidenceRequirementEvaluation[];
}

export interface FocusedVerdictEvidenceRef {
    evidenceId: string;
    source: EvidenceBundle['source'];
    role: 'baseline' | 'mutated' | 'comparison' | 'browser_flow' | 'browser_verification' | 'note' | 'scope_violation' | 'screenshot';
    summary: string;
    capturedAt: string;
    relatedEvidenceIds?: string[];
    browserActionCount?: number | null;
    supportRail?: FocusedSupportProvenanceRail | null;
    requestMethod?: string | null;
    requestPath?: string | null;
    responseStatusCode?: number | null;
    executionPhase?: FocusedExecutionPhase | null;
    confirmationKind?: FocusedConfirmationKind | null;
    confirmationOrdinal?: number | null;
    generatedFromFindingThreadId?: string | null;
}

export interface FocusedVerdictScopeViolationImpact {
    hasScopeViolation: boolean;
    severity: 'none' | 'advisory' | 'blocking';
    underminesConfidence: boolean;
    reasons: string[];
}

export interface FocusedVerdictExecutionSnapshot {
    executionId: string;
    executionState: FocusedExecutionState;
    executionProfileKey: string;
    runReason?: string | null;
    notesSummary?: string | null;
    errorMessage?: string | null;
    requestActionsUsed: number;
    browserActionsUsed: number;
    browserSessionId?: string | null;
    startedAt?: string;
    completedAt?: string | null;
}

export interface FocusedCaseVerdict {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    objectiveId: string;
    verdictState: FocusedVerdictState;
    verdictReason: string;
    evidenceSufficiency: FocusedEvidenceSufficiencyReport;
    interpretationSummary: FocusedSignalInterpretationSummary;
    supportingEvidenceRefs: FocusedVerdictEvidenceRef[];
    supportProvenance?: FocusedSupportProvenanceSummary | null;
    requestEvidenceStory?: FocusedRequestEvidenceStory | null;
    scopeViolationImpact: FocusedVerdictScopeViolationImpact;
    executionSnapshot: FocusedVerdictExecutionSnapshot;
    assistanceProfileKey?: string | null;
    assistanceProvider?: string | null;
    assistanceModel?: string | null;
    assistanceNarrative?: string | null;
    verdictAt: string;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedCaseFinding {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    objectiveId: string;
    findingKey: string;
    title: string;
    family: FocusedCaseFamily;
    status: FocusedFindingStatus;
    suspicionScore: number;
    confirmationProgress: number;
    confidenceBand: FocusedFindingConfidenceBand;
    rankOrder: number;
    isPrimary: boolean;
    strongestSupportSummary: string;
    blockingConstraintSummary?: string | null;
    nextStepSummary?: string | null;
    supportingSignals: string[];
    blockingConstraints: string[];
    supportingEvidenceRefs: FocusedVerdictEvidenceRef[];
    supportProvenance?: FocusedSupportProvenanceSummary | null;
    requestEvidenceStory?: FocusedRequestEvidenceStory | null;
    linkedVerdictIds: string[];
    linkedInvestigationIds: string[];
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedScanFindingSummary {
    scanId: string;
    objectiveId: string;
    totalFindings: number;
    primaryFindings: number;
    actionableCount: number;
    hiddenNotConfirmedCount: number;
    countsByStatus: Record<FocusedFindingStatus, number>;
    latestFindingAt: string | null;
}

export interface FocusedScanVerdictSummary {
    scanId: string;
    objectiveId: string;
    overallVerdict: FocusedVerdictState;
    totalCases: number;
    countsByVerdict: Record<FocusedVerdictState, number>;
    manualReviewRecommended: boolean;
    majorBlockers: string[];
    latestVerdictAt: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedBlockerRecurrenceSummary {
    recurringUnresolvedIssueFamilies: FocusedInvestigationIssueType[];
    resolvedIssueFamilies: FocusedInvestigationIssueType[];
    newlyIntroducedIssueFamilies: FocusedInvestigationIssueType[];
    recurringWorkaroundFailureFamilies: FocusedInvestigationIssueType[];
    blockingCountDelta: number;
    degradingCountDelta: number;
    notes: string[];
}

export interface FocusedHistoricalCompareState {
    scanId: string;
    scopeType: FocusedTestObjectiveSummary['scopeType'];
    targetOrigin: string;
    scopeIdentityKey: string;
    comparisonStatus: FocusedHistoricalCompareStatus;
    baselineScanId?: string | null;
    comparedAgainstScanId?: string | null;
    firstObservedAt: string | null;
    latestCompareAt: string | null;
    statusReason?: string | null;
    assistanceProfileKey?: string | null;
    assistanceProvider?: string | null;
    assistanceModel?: string | null;
    assistanceNarrative?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedRemovedHistoricalCase {
    previousCaseId: string;
    title: string;
    previousVerdict: FocusedVerdictState | null;
    previousEvidenceSufficiency: FocusedEvidenceSufficiencyState | null;
}

export interface FocusedCaseHistoricalCompare {
    id: string;
    currentScanId: string;
    currentCaseId: string;
    currentExecutionId?: string | null;
    caseIdentityKey: string;
    caseVariantKey: string;
    previousScanId?: string | null;
    previousCaseId?: string | null;
    previousExecutionId?: string | null;
    compareStatus: FocusedCaseCompareStatus;
    historicalOutcome?: FocusedHistoricalOutcome | null;
    priorVerdict?: FocusedVerdictState | null;
    currentVerdict?: FocusedVerdictState | null;
    verdictTransition?: FocusedVerdictTransition | null;
    priorEvidenceSufficiency?: FocusedEvidenceSufficiencyState | null;
    currentEvidenceSufficiency?: FocusedEvidenceSufficiencyState | null;
    priorVerdictReason?: string | null;
    currentVerdictReason?: string | null;
    priorEvidenceSummary?: string | null;
    currentEvidenceSummary?: string | null;
    evidenceDriftClassification?: FocusedEvidenceDriftClassification | null;
    blockerRecurrence: FocusedBlockerRecurrenceSummary;
    compareNarrative?: string | null;
    assistanceProfileKey?: string | null;
    assistanceProvider?: string | null;
    assistanceModel?: string | null;
    latestCompareAt: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedHistoricalCompareSummary {
    scanId: string;
    baselineScanId?: string | null;
    comparedAgainstScanId?: string | null;
    comparisonStatus: FocusedHistoricalCompareStatus;
    overallChangeClassification: FocusedOverallChangeClassification;
    countsByVerdictTransition: Record<FocusedVerdictTransition, number>;
    improvedCount: number;
    regressedCount: number;
    unchangedCount: number;
    weakerConfidenceCount: number;
    strongerConfidenceCount: number;
    newlyIntroducedCount: number;
    notComparableCount: number;
    removedPriorCaseCount: number;
    improvedCases: string[];
    regressedCases: string[];
    unstableCases: string[];
    repeatedBlockerFamilies: FocusedInvestigationIssueType[];
    newBlockerFamilies: FocusedInvestigationIssueType[];
    resolvedBlockerFamilies: FocusedInvestigationIssueType[];
    removedPriorCases: FocusedRemovedHistoricalCase[];
    stabilityNotes: string[];
    manualReviewRecommended: boolean;
    latestCompareAt: string | null;
    assistanceProfileKey?: string | null;
    assistanceProvider?: string | null;
    assistanceModel?: string | null;
    compareNarrative?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedWorkaroundAttempt {
    attemptedAt: string;
    summary: string;
    outcome: FocusedWorkaroundOutcome;
    details?: string | null;
    linkedEvidenceIds?: string[];
    linkedVerdictIds?: string[];
}

export interface FocusedInvestigationCorrelation {
    caseFamily?: FocusedCaseFamily | null;
    executionState?: FocusedExecutionState | null;
    executionRail?: FocusedExecutionRail | null;
    railSummary?: string | null;
    verdictState?: FocusedVerdictState | null;
    evidenceSufficiencyState?: FocusedEvidenceSufficiencyState | null;
    evidenceSources?: EvidenceBundleSource[];
    scopeViolationKinds?: Array<'host' | 'route' | 'endpoint_target' | 'baseline_anchor' | 'budget'>;
    traceActionTypes?: FocusedExecutionTraceActionType[];
    latestTraceSummary?: string | null;
    latestTraceReasoning?: string | null;
    requestActionType?: string | null;
    browserActionType?: string | null;
    anchorMethod?: string | null;
    anchorPath?: string | null;
    observedMethod?: string | null;
    observedPath?: string | null;
    observedStatusCode?: number | null;
}

export interface FocusedInvestigationIssue {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    objectiveId: string;
    issueType: FocusedInvestigationIssueType;
    issueTitle: string;
    issueDetails?: string | null;
    issueStatus: FocusedInvestigationIssueStatus;
    impact: FocusedInvestigationImpact;
    source: 'system' | 'profile_assistance' | 'operator';
    correlation?: FocusedInvestigationCorrelation | null;
    linkedEvidenceIds: string[];
    linkedVerdictIds: string[];
    workaroundAttempts: FocusedWorkaroundAttempt[];
    expertFollowupHint?: string | null;
    assistanceSummary?: string | null;
    assistanceProfileKey?: string | null;
    assistanceProvider?: string | null;
    assistanceModel?: string | null;
    detectedAt: string;
    resolvedAt?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedCaseInvestigationSummary {
    caseId: string;
    totalIssues: number;
    unresolvedCount: number;
    blockingCount: number;
    degradingCount: number;
    latestDetectedAt: string | null;
    latestIssueType?: FocusedInvestigationIssueType | null;
    latestIssueTitle?: string | null;
    latestIssueStatus?: FocusedInvestigationIssueStatus | null;
    latestImpact?: FocusedInvestigationImpact | null;
    latestExpertFollowupHint?: string | null;
    latestAssistanceSummary?: string | null;
}

export interface FocusedScanBlockerSummary {
    scanId: string;
    objectiveId: string;
    countsByStatus: Record<FocusedInvestigationIssueStatus, number>;
    countsByImpact: Record<FocusedInvestigationImpact, number>;
    unresolvedByType: Record<FocusedInvestigationIssueType, number>;
    repeatedBlockers: string[];
    casesNeedingReview: string[];
    latestMajorBlockerSummary: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedTestCaseExecution {
    id: string;
    scanId: string;
    caseId: string;
    objectiveId: string;
    executionState: FocusedExecutionState;
    executionProfileKey: string;
    runReason?: string | null;
    notesSummary?: string | null;
    errorMessage?: string | null;
    requestActionsUsed: number;
    browserActionsUsed: number;
    browserSessionId?: string | null;
    startedAt?: string;
    completedAt?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedEvidenceScreenshotRef {
    kind: string;
    value: string;
    mimeType?: string;
    label?: string | null;
    capturedAt?: string | null;
}

export interface FocusedBrowserExpectationResult {
    kind: string;
    description: string;
    matcher: 'page_loaded' | 'path_matches' | 'text_contains' | 'text_absent' | 'title_contains' | 'state_changed' | 'state_unchanged';
    matched: boolean;
    expected?: string | null;
    observedSummary: string;
}

export interface FocusedBrowserActionRecord {
    action: 'goto' | 'click' | 'fill' | 'select' | 'submit' | 'waitForNavigation' | 'waitForSelector' | 'reload';
    summary: string;
    targetUrl?: string | null;
    selector?: string | null;
    valuePreview?: string | null;
    resultingUrl?: string | null;
    resultingPath?: string | null;
    resultingTitle?: string | null;
    capturedAt: string;
}

export interface FocusedBrowserEvidence {
    sessionId?: string | null;
    startUrl: string;
    finalUrl?: string | null;
    finalPath?: string | null;
    pageTitle?: string | null;
    actionCount: number;
    navigationDepth: number;
    verificationRetries: number;
    actionSummary: string;
    domSummary?: string | null;
    stateNotes: string[];
    detectedChanges: string[];
    actions: FocusedBrowserActionRecord[];
    expectations: FocusedBrowserExpectationResult[];
    screenshots: FocusedEvidenceScreenshotRef[];
    relatedRequestEvidenceIds: string[];
}

export interface FocusedRequestEvidenceRef {
    evidenceId: string;
    source: EvidenceBundleSource;
    summary: string;
    capturedAt: string;
    method?: string | null;
    url?: string | null;
    path?: string | null;
    host?: string | null;
    statusCode?: number | null;
    executionPhase?: FocusedExecutionPhase | null;
    confirmationKind?: FocusedConfirmationKind | null;
    confirmationOrdinal?: number | null;
    generatedFromFindingThreadId?: string | null;
    relatedEvidenceIds?: string[];
}

export interface FocusedRequestEvidenceStory {
    requestHeavy: boolean;
    hasRequestBackedEvidence: boolean;
    baselineRequestRef?: FocusedRequestEvidenceRef | null;
    strongestSuspiciousRequestRef?: FocusedRequestEvidenceRef | null;
    supportingRequestRefs: FocusedRequestEvidenceRef[];
    contradictingRequestRefs: FocusedRequestEvidenceRef[];
    confirmationRequestRefs: FocusedRequestEvidenceRef[];
    summary: string;
    lowConfidenceReason?: string | null;
}

export interface FocusedSupportProvenanceSummary {
    rail: FocusedSupportProvenanceRail;
    requestHeavy: boolean;
    requestBackedEvidence: boolean;
    browserBackedEvidence: boolean;
    requestEvidenceIds: string[];
    browserEvidenceIds: string[];
    systemEvidenceIds: string[];
    summary: string;
    lowConfidenceReason?: string | null;
}

export interface EvidenceBundle {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    summary: string;
    source: EvidenceBundleSource;
    capturedAt: string;
    requestRef?: {
        method?: string;
        url?: string;
        path?: string;
        host?: string;
        statusCode?: number;
        raw?: string;
    } | null;
    responseRef?: {
        method?: string;
        url?: string;
        path?: string;
        host?: string;
        statusCode?: number;
        raw?: string;
    } | null;
    responseDiffSummary?: {
        summary: string;
        significant: boolean;
        originalStatus?: number;
        mutatedStatus?: number;
        bodyLengthDelta?: number;
        structureChanged?: boolean;
        keywordSignals?: string[];
    } | null;
    screenshotRef?: FocusedEvidenceScreenshotRef | null;
    browserState?: FocusedBrowserEvidence | null;
    relatedEvidenceIds?: string[];
    executionNotes?: string | null;
    provenance?: {
        profileKey: string;
        actionType: string;
        provider?: string;
        model?: string;
        source: 'system' | 'model';
        executionPhase?: FocusedExecutionPhase | null;
        confirmationKind?: FocusedConfirmationKind | null;
        confirmationOrdinal?: number | null;
        generatedFromFindingThreadId?: string | null;
    } | null;
    scopeViolation?: {
        reason: string;
        attemptedAction: string;
        attemptedHost?: string;
        attemptedPath?: string;
        attemptedMethod?: string;
        violationKind: 'host' | 'route' | 'endpoint_target' | 'baseline_anchor' | 'budget';
        blockedAt: string;
    } | null;
}

export interface FocusedPlanSummary {
    totalCases: number;
    enabledCases: number;
    disabledCases: number;
    latestPlannedAt: string | null;
    countsByPriority: Record<FocusedTestCasePriority, number>;
    countsByReviewState: Record<FocusedTestCaseReviewState, number>;
}

export interface FocusedCaseListRow {
    id: string;
    title: string;
    targetLabel: string;
    hypothesis: string;
    priority: FocusedTestCasePriority;
    status: FocusedTestCaseStatus;
    reviewState: FocusedTestCaseReviewState;
    rationale: string;
    caseIntelligence: FocusedCaseIntelligence | null;
    executionState: FocusedExecutionState;
    executionPresentationState: FocusedExecutionPresentationState;
    lastRunAt: string | null;
    executionNotesSummary: string | null;
    executionError: string | null;
    evidenceCount: number;
    browserEvidenceCount: number;
    scopeViolationCount: number;
    browserActionsUsed: number;
    executionProfileKey: string | null;
    browserSessionId: string | null;
    executionRailSummary: FocusedRailUsageSummary | null;
    latestExecutionTracePreview: FocusedExecutionTraceEntry[];
    latestReasoningTracePreview: FocusedReasoningTraceEntry[];
    hypothesisVisibility: FocusedHypothesisVisibility | null;
    suspicionExplanation: FocusedSuspicionExplanation | null;
    activeFindingThread: FocusedFindingThread | null;
    findingThreads: FocusedFindingThread[];
    confirmationState: FocusedConfirmationState | null;
    primaryFinding: FocusedCaseFinding | null;
    findings: FocusedCaseFinding[];
    secondaryFindingsCount: number;
    latestVerdict: FocusedCaseVerdict | null;
    investigationSummary: FocusedCaseInvestigationSummary | null;
    historicalCompare: FocusedCaseHistoricalCompare | null;
}

const priorityRank: Record<FocusedTestCasePriority, number> = {
    high: 0,
    medium: 1,
    low: 2,
};

const reviewRank: Record<FocusedTestCaseReviewState, number> = {
    pending_review: 0,
    approved: 1,
    rejected: 2,
};

const focusedFindingStatusRank: Record<FocusedFindingStatus, number> = {
    confirmed: 0,
    likely: 1,
    suspicious: 2,
    inconclusive: 3,
    not_confirmed: 4,
};

export function projectFocusedFindingThread(thread: FocusedFindingThread): FocusedCaseFinding {
    return {
        id: thread.publishedFindingId || thread.id,
        scanId: thread.scanId,
        caseId: thread.caseId,
        executionId: thread.executionId,
        objectiveId: thread.objectiveId,
        findingKey: thread.findingKey,
        title: thread.title,
        family: thread.family,
        status: thread.suspicionScore >= 70
            ? 'likely'
            : thread.suspicionScore >= 45
                ? 'suspicious'
                : thread.blockingConstraints.length > 0
                    ? 'inconclusive'
                    : 'not_confirmed',
        suspicionScore: thread.suspicionScore,
        confirmationProgress: thread.confirmationProgress,
        confidenceBand: thread.confidenceBand,
        rankOrder: 0,
        isPrimary: thread.isPrimary,
        strongestSupportSummary: thread.strongestSupportSummary || thread.strongestSuspiciousSignal || thread.title,
        blockingConstraintSummary: thread.strongestBlockerSummary || thread.blockingConstraints[0] || null,
        nextStepSummary: thread.nextStepSummary || thread.confirmationState.nextStepSummary || null,
        supportingSignals: thread.supportingSignals,
        blockingConstraints: thread.blockingConstraints,
        supportingEvidenceRefs: thread.supportingEvidenceRefs,
        linkedVerdictIds: thread.linkedVerdictIds,
        linkedInvestigationIds: thread.linkedInvestigationIds,
        createdAt: thread.createdAt,
        updatedAt: thread.updatedAt,
    };
}

export interface FocusedScanFindingRow {
    finding: FocusedCaseFinding;
    thread?: FocusedFindingThread | null;
    source: 'published' | 'runtime_thread';
    caseId: string;
    caseTitle: string;
    targetLabel: string;
}

export function formatFocusedTargetArtifact(target: FocusedTestCaseTargetArtifact): string {
    switch (target.kind) {
        case 'endpoint':
            return [target.method?.toUpperCase(), target.path || target.url || target.label].filter(Boolean).join(' ');
        case 'baseline_request':
            return target.label || [target.method?.toUpperCase(), target.path || target.referenceId].filter(Boolean).join(' ');
        case 'flow':
            return target.label || 'Scoped flow';
        case 'feature':
            return target.label || 'Scoped feature';
        default:
            return target.label || target.path || target.url || 'Scoped target';
    }
}

export function deriveFocusedExecutionPresentationState(input: {
    status: FocusedTestCaseStatus;
    reviewState: FocusedTestCaseReviewState;
    executionState?: FocusedExecutionState | null;
    lastExecutionId?: string | null;
    evidenceCount?: number | null;
}): FocusedExecutionPresentationState {
    if (!input.lastExecutionId) {
        if (input.status === 'disabled') {
            return 'skipped_disabled';
        }
        if (input.reviewState === 'rejected') {
            return 'skipped_not_approved';
        }
        if (input.reviewState === 'pending_review') {
            return 'awaiting_approval';
        }
        return 'not_run_yet';
    }

    switch (input.executionState) {
        case 'running':
            return 'running';
        case 'blocked':
            return 'blocked';
        case 'failed_to_execute':
            return 'failed_to_execute';
        case 'completed':
            return (Number(input.evidenceCount) || 0) > 0
                ? 'completed_with_evidence'
                : 'completed_without_evidence';
        case 'skipped':
            return input.status === 'disabled'
                ? 'skipped_disabled'
                : 'skipped_not_approved';
        default:
            return input.reviewState === 'pending_review'
                ? 'awaiting_approval'
                : 'not_run_yet';
    }
}

export function buildFocusedCaseRows(cases: FocusedTestCase[]): FocusedCaseListRow[] {
    return [...cases]
        .sort((left, right) => {
            const leftSuspicionScore = left.primaryFinding?.suspicionScore || left.activeFindingThread?.suspicionScore || 0;
            const rightSuspicionScore = right.primaryFinding?.suspicionScore || right.activeFindingThread?.suspicionScore || 0;
            if (leftSuspicionScore !== rightSuspicionScore) {
                return rightSuspicionScore - leftSuspicionScore;
            }
            const suspiciousnessRank: Record<FocusedSignalSuspiciousness, number> = {
                high: 0,
                moderate: 1,
                low: 2,
                none: 3,
            };
            const leftSuspiciousness = left.suspicionExplanation?.suspiciousness || left.latestVerdict?.interpretationSummary?.suspiciousness || 'none';
            const rightSuspiciousness = right.suspicionExplanation?.suspiciousness || right.latestVerdict?.interpretationSummary?.suspiciousness || 'none';
            if (suspiciousnessRank[leftSuspiciousness] !== suspiciousnessRank[rightSuspiciousness]) {
                return suspiciousnessRank[leftSuspiciousness] - suspiciousnessRank[rightSuspiciousness];
            }
            const leftPresentationState = deriveFocusedExecutionPresentationState(left);
            const rightPresentationState = deriveFocusedExecutionPresentationState(right);
            if (leftPresentationState !== rightPresentationState) {
                const executionRank: Record<FocusedExecutionPresentationState, number> = {
                    running: 0,
                    not_run_yet: 1,
                    awaiting_approval: 2,
                    failed_to_execute: 3,
                    blocked: 4,
                    completed_with_evidence: 5,
                    completed_without_evidence: 6,
                    skipped_not_approved: 7,
                    skipped_disabled: 8,
                };
                return executionRank[leftPresentationState] - executionRank[rightPresentationState];
            }
            if (left.status !== right.status) {
                return left.status === 'planned' ? -1 : 1;
            }
            if (reviewRank[left.reviewState] !== reviewRank[right.reviewState]) {
                return reviewRank[left.reviewState] - reviewRank[right.reviewState];
            }
            if (priorityRank[left.priority] !== priorityRank[right.priority]) {
                return priorityRank[left.priority] - priorityRank[right.priority];
            }
            return left.title.localeCompare(right.title);
        })
        .map((testCase) => ({
            id: testCase.id,
            title: testCase.title,
            targetLabel: formatFocusedTargetArtifact(testCase.targetArtifact),
            hypothesis: testCase.hypothesis,
            priority: testCase.priority,
            status: testCase.status,
            reviewState: testCase.reviewState,
            rationale: testCase.plannerRationaleSummary,
            caseIntelligence: testCase.caseIntelligence || null,
            executionState: testCase.executionState || (testCase.reviewState === 'approved' ? 'ready' : 'skipped'),
            executionPresentationState: testCase.executionPresentationState || deriveFocusedExecutionPresentationState(testCase),
            lastRunAt: testCase.lastRunAt || null,
            executionNotesSummary: testCase.executionNotesSummary || null,
            executionError: testCase.executionError || null,
            evidenceCount: testCase.evidenceCount || 0,
            browserEvidenceCount: testCase.browserEvidenceCount || 0,
            scopeViolationCount: testCase.scopeViolationCount || 0,
            browserActionsUsed: testCase.browserActionsUsed || 0,
            executionProfileKey: testCase.executionProfileKey || null,
            browserSessionId: testCase.browserSessionId || null,
            executionRailSummary: testCase.executionRailSummary || null,
            latestExecutionTracePreview: Array.isArray(testCase.latestExecutionTracePreview) ? testCase.latestExecutionTracePreview : [],
            latestReasoningTracePreview: Array.isArray(testCase.latestReasoningTracePreview) ? testCase.latestReasoningTracePreview : [],
            hypothesisVisibility: testCase.hypothesisVisibility || null,
            suspicionExplanation: testCase.suspicionExplanation || null,
            activeFindingThread: testCase.activeFindingThread || null,
            findingThreads: Array.isArray(testCase.findingThreads) ? testCase.findingThreads : [],
            confirmationState: testCase.confirmationState || testCase.activeFindingThread?.confirmationState || null,
            primaryFinding: testCase.primaryFinding || null,
            findings: Array.isArray(testCase.findings) ? testCase.findings : [],
            secondaryFindingsCount: Math.max((Array.isArray(testCase.findings) ? testCase.findings.length : 0) - 1, 0),
            latestVerdict: testCase.latestVerdict || null,
            investigationSummary: testCase.investigationSummary || null,
            historicalCompare: testCase.historicalCompare || null,
        }));
}

export function getFocusedFindingStatusRank(status: FocusedFindingStatus | null | undefined): number {
    return focusedFindingStatusRank[status || 'not_confirmed'] ?? focusedFindingStatusRank.not_confirmed;
}

export function buildFocusedScanFindingRows(
    findings: FocusedCaseFinding[],
    cases: FocusedTestCase[],
    findingThreads: FocusedFindingThread[] = [],
): FocusedScanFindingRow[] {
    const caseMap = new Map(cases.map((testCase) => [testCase.id, testCase]));
    const publishedCaseIds = new Set(findings.map((finding) => finding.caseId));
    const publishedRows = findings
        .map((finding): FocusedScanFindingRow | null => {
            const testCase = caseMap.get(finding.caseId);
            if (!testCase) {
                return null;
            }

            return {
                finding,
                source: 'published',
                thread: null,
                caseId: testCase.id,
                caseTitle: testCase.title,
                targetLabel: formatFocusedTargetArtifact(testCase.targetArtifact),
            };
        })
        .filter((entry): entry is FocusedScanFindingRow => !!entry);
    const runtimeRows = findingThreads
        .filter((thread) => !publishedCaseIds.has(thread.caseId))
        .map((thread): FocusedScanFindingRow | null => {
            const testCase = caseMap.get(thread.caseId);
            if (!testCase) {
                return null;
            }

            return {
                finding: projectFocusedFindingThread(thread),
                thread,
                source: 'runtime_thread',
                caseId: testCase.id,
                caseTitle: testCase.title,
                targetLabel: formatFocusedTargetArtifact(testCase.targetArtifact),
            };
        })
        .filter((entry): entry is FocusedScanFindingRow => !!entry);

    return [...publishedRows, ...runtimeRows]
        .sort((left, right) => {
            const leftRank = getFocusedFindingStatusRank(left.finding.status);
            const rightRank = getFocusedFindingStatusRank(right.finding.status);
            if (leftRank !== rightRank) {
                return leftRank - rightRank;
            }
            if (left.finding.suspicionScore !== right.finding.suspicionScore) {
                return right.finding.suspicionScore - left.finding.suspicionScore;
            }
            if (left.finding.confirmationProgress !== right.finding.confirmationProgress) {
                return right.finding.confirmationProgress - left.finding.confirmationProgress;
            }
            return left.caseTitle.localeCompare(right.caseTitle);
        });
}

export interface ScopedPlanReviewCounts {
    totalCases: number;
    enabledCount: number;
    disabledCount: number;
    pendingReviewCount: number;
    approvedCount: number;
    rejectedCount: number;
}

export function summarizeScopedPlanReviewCounts(
    cases: FocusedTestCase[],
    summary?: FocusedPlanSummary | null,
): ScopedPlanReviewCounts {
    const pendingReviewCount = cases.filter((testCase) => testCase.reviewState === 'pending_review').length;
    const approvedCount = cases.filter((testCase) => testCase.reviewState === 'approved' && testCase.status === 'planned').length;
    const rejectedCount = cases.filter((testCase) => testCase.reviewState === 'rejected').length;
    const disabledCount = summary?.disabledCases ?? cases.filter((testCase) => testCase.status === 'disabled').length;
    const enabledCount = summary?.enabledCases ?? cases.filter((testCase) => testCase.status === 'planned').length;

    return {
        totalCases: summary?.totalCases ?? cases.length,
        enabledCount,
        disabledCount,
        pendingReviewCount,
        approvedCount,
        rejectedCount,
    };
}

export function formatFocusedPriority(priority: FocusedTestCasePriority | null | undefined): string {
    switch (priority) {
        case 'high':
            return 'High Priority';
        case 'low':
            return 'Low Priority';
        default:
            return 'Medium Priority';
    }
}

export function formatFocusedReviewState(reviewState: FocusedTestCaseReviewState | null | undefined): string {
    switch (reviewState) {
        case 'approved':
            return 'Approved';
        case 'rejected':
            return 'Rejected';
        default:
            return 'Legacy Manual Review';
    }
}

export function formatScopedWorkflowStage(status: string): string {
    switch (status) {
        case 'scoped_discovering':
            return 'Feature Discovery';
        case 'planning':
            return 'Mission Seeding';
        case 'awaiting_review':
            return 'Legacy Manual Review';
        case 'scoped_executing':
            return 'Live Execution';
        case 'scoped_executed':
            return 'Results Ready';
        case 'failed':
            return 'Run Failed';
        case 'completed':
            return 'Completed';
        default:
            return 'Preparing Scoped Mission';
    }
}

export function getScopedRecommendedAction(status: string, counts: ScopedPlanReviewCounts): string {
    switch (status) {
        case 'scoped_discovering':
            return 'Watching feature anchors form';
        case 'planning':
            return 'Seeding internal bounded hypotheses';
        case 'awaiting_review':
            return counts.pendingReviewCount > 0
                ? 'Legacy recovery: review pending cases'
                : counts.approvedCount > 0
                    ? 'Legacy recovery: run approved cases'
                    : 'Legacy recovery: tune the persisted case list';
        case 'scoped_executing':
            return 'Follow live logs, requests, and findings';
        case 'scoped_executed':
            return 'Inspect findings and bounded evidence';
        case 'failed':
            return 'Check the latest activity and retry when ready';
        default:
            return 'Keep the scoped mission moving forward';
    }
}

export function isScopedReviewStage(scanMode: ScanMode, status: string): boolean {
    return scanMode === 'scoped' && status === 'awaiting_review';
}

export function isScopedExecutionStage(scanMode: ScanMode, status: string): boolean {
    return scanMode === 'scoped' && (status === 'scoped_executing' || status === 'scoped_executed');
}

export function formatScopedFeatureDiscoveryPhase(phase: ScopedFeatureDiscoveryPhase | null | undefined): string {
    switch (phase) {
        case 'discovering':
            return 'Discovering';
        case 'ready_to_plan':
            return 'Ready to Plan';
        case 'blocked':
            return 'Blocked';
        default:
            return 'Not Started';
    }
}

export function formatScopedFeatureDiscoveryOutcome(outcome: ScopedFeatureDiscoveryOutcome | null | undefined): string {
    switch (outcome) {
        case 'candidate_anchors_found':
            return 'Candidate Anchors Found';
        case 'partial_anchors_found':
            return 'Partial Anchors Found';
        case 'no_useful_anchors':
            return 'No Useful Anchors';
        default:
            return 'Pending';
    }
}

export function buildScopedAnchorSummary(
    scopeEnvelope: ScopeEnvelopeSummary | null | undefined,
    discoveryState: ScopedFeatureDiscoveryStateSummary | null | undefined,
): string {
    const selectedEndpointCount = scopeEnvelope?.selectedEndpoints?.length ?? discoveryState?.selectedEndpointCount ?? 0;
    const requestAnchorCount = scopeEnvelope?.discoveredRequestRefs?.length ?? discoveryState?.requestAnchorCount ?? 0;
    const browserAnchorCount = scopeEnvelope?.browserAnchors?.length ?? discoveryState?.browserAnchorCount ?? 0;
    const allowedRouteCount = scopeEnvelope?.allowedRoutes?.length ?? discoveryState?.allowedRouteCount ?? 0;

    return `${selectedEndpointCount} endpoint anchor${selectedEndpointCount === 1 ? '' : 's'} | ${requestAnchorCount} request ref${requestAnchorCount === 1 ? '' : 's'} | ${browserAnchorCount} browser anchor${browserAnchorCount === 1 ? '' : 's'} | ${allowedRouteCount} route${allowedRouteCount === 1 ? '' : 's'}`;
}

export function formatFocusedExecutionState(state: FocusedExecutionState | null | undefined): string {
    switch (state) {
        case 'running':
            return 'Running';
        case 'completed':
            return 'Completed';
        case 'blocked':
            return 'Blocked';
        case 'failed_to_execute':
            return 'Failed';
        case 'skipped':
            return 'Skipped';
        default:
            return 'Ready';
    }
}

export function formatFocusedExecutionPresentationState(state: FocusedExecutionPresentationState | null | undefined): string {
    switch (state) {
        case 'awaiting_approval':
            return 'Awaiting legacy approval';
        case 'skipped_not_approved':
            return 'Skipped - not approved';
        case 'skipped_disabled':
            return 'Skipped - disabled';
        case 'running':
            return 'Running';
        case 'blocked':
            return 'Blocked during execution';
        case 'failed_to_execute':
            return 'Failed to execute';
        case 'completed_with_evidence':
            return 'Completed with evidence';
        case 'completed_without_evidence':
            return 'Completed without evidence';
        default:
            return 'Not run yet';
    }
}

export function formatFocusedExecutionRail(rail: FocusedExecutionRail | null | undefined): string {
    switch (rail) {
        case 'request':
            return 'Request rail';
        case 'browser':
            return 'Browser rail';
        case 'hybrid':
            return 'Hybrid rail';
        default:
            return 'System-only';
    }
}

export function formatFocusedSupportProvenanceRail(rail: FocusedSupportProvenanceRail | null | undefined): string {
    switch (rail) {
        case 'request':
            return 'Request-backed';
        case 'browser':
            return 'Browser-backed';
        case 'hybrid':
            return 'Hybrid support';
        default:
            return 'System-only';
    }
}

export function formatFocusedReasoningRail(rail: FocusedReasoningRail | null | undefined): string {
    switch (rail) {
        case 'request':
            return 'Request rail';
        case 'browser':
            return 'Browser rail';
        case 'hybrid':
            return 'Hybrid rail';
        default:
            return 'System-only';
    }
}

export function formatFocusedReasoningStage(stage: FocusedReasoningStage | null | undefined): string {
    switch (stage) {
        case 'request_intake':
            return 'Request intake';
        case 'feature_discovery':
            return 'Feature discovery';
        case 'planning':
            return 'Planning';
        case 'review_gate':
            return 'Review gate';
        case 'verdict':
            return 'Verdict';
        case 'investigation':
            return 'Investigation';
        case 'historical_compare':
            return 'Historical compare';
        default:
            return 'Execution';
    }
}

export function formatFocusedReasoningEntryType(entryType: FocusedReasoningEntryType | null | undefined): string {
    switch (entryType) {
        case 'context':
            return 'Context';
        case 'observation':
            return 'Observation';
        case 'hypothesis':
            return 'Hypothesis';
        case 'decision':
            return 'Decision';
        case 'action':
            return 'Action';
        case 'result':
            return 'Result';
        default:
            return 'Constraint';
    }
}

export function formatFocusedHypothesisStatus(status: FocusedHypothesisStatus | null | undefined): string {
    switch (status) {
        case 'strengthened':
            return 'Strengthened';
        case 'weakened':
            return 'Weakened';
        case 'stalled':
            return 'Stalled';
        case 'contradicted':
            return 'Contradicted';
        default:
            return 'Plausible';
    }
}

export function formatFocusedSuspicionProofStatus(status: FocusedSuspicionProofStatus | null | undefined): string {
    switch (status) {
        case 'supported':
            return 'Supported';
        case 'contradictory':
            return 'Contradictory';
        case 'blocked':
            return 'Blocked';
        default:
            return 'Weak';
    }
}

export function formatFocusedRequestContextField(field: FocusedRequestContextField | null | undefined): string {
    switch (field) {
        case 'testData':
            return 'Test data';
        case 'testUsers':
            return 'Test users';
        case 'authMechanismHints':
            return 'Auth hints';
        case 'attachmentSummary':
            return 'Attachment summary';
        case 'attachmentMetadata':
            return 'Attachment metadata';
        case 'operatorNotes':
            return 'Operator notes';
        case 'newScreenCount':
            return 'New screens';
        case 'newInputCount':
            return 'New inputs';
        default:
            return 'Request context';
    }
}

export function formatFocusedRailSummary(summary: FocusedRailUsageSummary | null | undefined): string {
    if (!summary) {
        return 'No request-backed or browser-backed actions were recorded.';
    }
    return summary.summary;
}

export function formatFocusedExecutionTraceActionType(actionType: FocusedExecutionTraceActionType | null | undefined): string {
    switch (actionType) {
        case 'execution_started':
            return 'Execution started';
        case 'retry_context':
            return 'Retry context';
        case 'action_planned':
            return 'Action planned';
        case 'request_dispatch':
            return 'Request sent';
        case 'response_observed':
            return 'Response observed';
        case 'response_compared':
            return 'Responses compared';
        case 'browser_sequence_started':
            return 'Browser sequence started';
        case 'browser_sequence_result':
            return 'Browser sequence result';
        case 'screenshot_captured':
            return 'Screenshot captured';
        case 'blocked':
            return 'Blocked';
        case 'skipped':
            return 'Skipped';
        case 'execution_completed':
            return 'Execution completed';
        case 'execution_failed':
            return 'Execution failed';
        default:
            return 'Execution note';
    }
}

export function buildFocusedTracePreview(traceEntries: FocusedExecutionTraceEntry[] | null | undefined, limit = 3): FocusedExecutionTraceEntry[] {
    if (!Array.isArray(traceEntries) || traceEntries.length === 0) {
        return [];
    }
    return traceEntries.slice(0, Math.max(limit, 1));
}

export function formatFocusedSupportProvenanceSummary(summary: FocusedSupportProvenanceSummary | null | undefined): string {
    if (!summary) {
        return 'No request-backed or browser-backed support was recorded.';
    }
    return summary.summary;
}

export function formatFocusedRequestEvidenceRef(ref: FocusedRequestEvidenceRef | null | undefined): string {
    if (!ref) {
        return 'Not captured';
    }
    const location = ref.path || ref.url || ref.summary;
    const status = typeof ref.statusCode === 'number' ? ` · HTTP ${ref.statusCode}` : '';
    const phase = ref.executionPhase === 'adaptive_confirmation'
        ? ` · confirmation${typeof ref.confirmationOrdinal === 'number' ? ` ${ref.confirmationOrdinal}` : ''}`
        : '';
    return `${[ref.method, location].filter(Boolean).join(' ')}${status}${phase}`.trim();
}

export function buildFocusedReasoningTracePreview(traceEntries: FocusedReasoningTraceEntry[] | null | undefined, limit = 3): FocusedReasoningTraceEntry[] {
    if (!Array.isArray(traceEntries) || traceEntries.length === 0) {
        return [];
    }
    return traceEntries.slice(Math.max(traceEntries.length - Math.max(limit, 1), 0));
}

export function buildFocusedEvidenceEmptyState(input: {
    presentationState?: FocusedExecutionPresentationState | null;
    reviewState?: FocusedTestCaseReviewState | null;
    status?: FocusedTestCaseStatus | null;
}): string {
    switch (input.presentationState) {
        case 'awaiting_approval':
            return 'This legacy scoped case has not run yet because it is still waiting for manual review.';
        case 'skipped_not_approved':
            return 'This case was not executed because it was not approved.';
        case 'skipped_disabled':
            return 'This case is disabled, so no execution evidence was captured.';
        case 'running':
            return 'Execution is still in progress. Evidence will appear here as bounded actions complete.';
        case 'blocked':
            return 'Execution stopped during a bounded block before evidence could be captured.';
        case 'failed_to_execute':
            return 'Execution failed before evidence could be captured.';
        case 'completed_without_evidence':
            return 'Execution completed, but no evidence bundles were persisted for this case.';
        default:
            return 'This case has not produced persisted evidence yet.';
    }
}

export function formatFocusedEvidenceCount(evidenceCount: number | null | undefined, scopeViolationCount?: number | null): string {
    const safeEvidenceCount = evidenceCount || 0;
    const safeScopeViolationCount = scopeViolationCount || 0;
    if (safeScopeViolationCount > 0) {
        return `${safeEvidenceCount} evidence (${safeScopeViolationCount} scope violation${safeScopeViolationCount === 1 ? '' : 's'})`;
    }
    return `${safeEvidenceCount} evidence`;
}

export function formatFocusedBrowserEvidenceCount(browserEvidenceCount: number | null | undefined, browserActionsUsed?: number | null): string {
    const safeBrowserEvidenceCount = browserEvidenceCount || 0;
    const safeBrowserActionsUsed = browserActionsUsed || 0;
    if (safeBrowserEvidenceCount === 0 && safeBrowserActionsUsed === 0) {
        return 'No browser proof';
    }
    if (safeBrowserActionsUsed > 0) {
        return `${safeBrowserEvidenceCount} browser bundle${safeBrowserEvidenceCount === 1 ? '' : 's'} (${safeBrowserActionsUsed} action${safeBrowserActionsUsed === 1 ? '' : 's'})`;
    }
    return `${safeBrowserEvidenceCount} browser bundle${safeBrowserEvidenceCount === 1 ? '' : 's'}`;
}

export function formatFocusedVerdictState(state: FocusedVerdictState | null | undefined): string {
    switch (state) {
        case 'pass':
            return 'Pass';
        case 'fail':
            return 'Fail';
        case 'inconclusive':
            return 'Inconclusive';
        case 'needs_review':
            return 'Needs Review';
        default:
            return 'Not Verdicted';
    }
}

export function formatFocusedEvidenceSufficiencyState(state: FocusedEvidenceSufficiencyState | null | undefined): string {
    switch (state) {
        case 'sufficient':
            return 'Sufficient';
        case 'unsupported':
            return 'Unsupported';
        case 'contradictory':
            return 'Contradictory';
        default:
            return 'Insufficient';
    }
}

export function formatFocusedFindingStatus(status: FocusedFindingStatus | null | undefined): string {
    switch (status) {
        case 'confirmed':
            return 'Confirmed';
        case 'likely':
            return 'Likely';
        case 'suspicious':
            return 'Suspicious';
        case 'inconclusive':
            return 'Inconclusive';
        default:
            return 'Not Confirmed';
    }
}

export function formatFocusedFindingThreadStatus(status: FocusedFindingThreadStatus | null | undefined): string {
    switch (status) {
        case 'strengthening':
            return 'Strengthening';
        case 'confirming':
            return 'Confirming';
        case 'blocked':
            return 'Blocked';
        case 'exhausted':
            return 'Exhausted';
        case 'published':
            return 'Published';
        default:
            return 'Collecting';
    }
}

export function formatFocusedConfirmationKind(kind: FocusedConfirmationKind | null | undefined): string {
    switch (kind) {
        case 'repeat_mutation':
            return 'Repeat mutation';
        case 'alternate_id_compare':
            return 'Alternate-id compare';
        case 'render_check':
            return 'Render check';
        case 'state_replay':
            return 'State replay';
        case 'error_surface_compare':
            return 'Error-surface compare';
        case 'control_contrast':
            return 'Control contrast';
        default:
            return 'Bounded confirmation';
    }
}

export function formatFocusedFindingConfidenceBand(confidenceBand: FocusedFindingConfidenceBand | null | undefined): string {
    switch (confidenceBand) {
        case 'high':
            return 'High confidence';
        case 'medium':
            return 'Medium confidence';
        default:
            return 'Low confidence';
    }
}

export function formatFocusedFindingFamily(family: FocusedCaseFamily | null | undefined): string {
    switch (family) {
        case 'sqli':
            return 'SQL Injection';
        case 'xss':
            return 'XSS';
        case 'access_control':
            return 'Access Control';
        case 'input_validation':
            return 'Input Validation';
        case 'error_handling':
            return 'Error Handling / Exposure';
        case 'workflow_logic':
            return 'Business Logic / Workflow';
        default:
            return 'Scoped Security Finding';
    }
}

export function formatFocusedHistoricalCompareStatus(status: FocusedHistoricalCompareStatus | null | undefined): string {
    switch (status) {
        case 'baseline_created':
            return 'Baseline Created';
        case 'compared':
            return 'Compared';
        case 'not_comparable':
            return 'Not Comparable';
        default:
            return 'Comparison Unavailable';
    }
}

export function formatFocusedCaseCompareStatus(status: FocusedCaseCompareStatus | null | undefined): string {
    switch (status) {
        case 'exact_match':
            return 'Exact match';
        case 'likely_match':
            return 'Likely match';
        case 'newly_introduced':
            return 'Newly introduced';
        case 'not_comparable':
            return 'Not comparable';
        default:
            return 'Baseline only';
    }
}

export function formatFocusedHistoricalOutcome(outcome: FocusedHistoricalOutcome | null | undefined): string {
    switch (outcome) {
        case 'improved':
            return 'Improved';
        case 'regressed':
            return 'Regressed';
        case 'weaker_confidence':
            return 'Weaker Confidence';
        case 'stronger_confidence':
            return 'Stronger Confidence';
        case 'newly_introduced':
            return 'New';
        case 'not_comparable':
            return 'Not Comparable';
        default:
            return 'Unchanged';
    }
}

export function formatFocusedVerdictTransition(transition: FocusedVerdictTransition | null | undefined): string {
    if (!transition) {
        return 'No verdict transition';
    }

    const [from, to] = transition.split('_to_');
    return `${formatFocusedVerdictState(from as FocusedVerdictState)} -> ${formatFocusedVerdictState(to as FocusedVerdictState)}`;
}

export function formatFocusedEvidenceDriftClassification(classification: FocusedEvidenceDriftClassification | null | undefined): string {
    switch (classification) {
        case 'stronger_confidence':
            return 'Stronger confidence';
        case 'weaker_confidence':
            return 'Weaker confidence';
        case 'unsupported_gap_introduced':
            return 'Unsupported gap introduced';
        case 'contradiction_introduced':
            return 'Contradiction introduced';
        case 'scope_risk_increased':
            return 'Scope risk increased';
        default:
            return 'Evidence unchanged';
    }
}

export function formatFocusedOverallChangeClassification(classification: FocusedOverallChangeClassification | null | undefined): string {
    switch (classification) {
        case 'improvement':
            return 'Improvement';
        case 'regression':
            return 'Regression';
        case 'instability':
            return 'Instability';
        case 'baseline_only':
            return 'Baseline Only';
        default:
            return 'No Material Change';
    }
}

export function formatFocusedBlockerRecurrence(compare: FocusedCaseHistoricalCompare | null | undefined): string | null {
    if (!compare) {
        return null;
    }

    const recurrence = compare.blockerRecurrence;
    if (recurrence.recurringUnresolvedIssueFamilies.length > 0) {
        return `Recurring blockers: ${recurrence.recurringUnresolvedIssueFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`;
    }
    if (recurrence.newlyIntroducedIssueFamilies.length > 0) {
        return `New blockers: ${recurrence.newlyIntroducedIssueFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`;
    }
    if (recurrence.resolvedIssueFamilies.length > 0) {
        return `Resolved blockers: ${recurrence.resolvedIssueFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`;
    }
    if (recurrence.recurringWorkaroundFailureFamilies.length > 0) {
        return `Workaround still failing for ${recurrence.recurringWorkaroundFailureFamilies.map((issueType) => formatFocusedInvestigationType(issueType)).join(', ')}`;
    }
    return null;
}

export function formatFocusedInvestigationStatus(status: FocusedInvestigationIssueStatus | null | undefined): string {
    switch (status) {
        case 'resolved':
            return 'Resolved';
        case 'partially_resolved':
            return 'Partially Resolved';
        case 'unresolved':
            return 'Unresolved';
        case 'not_applicable':
            return 'Not Applicable';
        default:
            return 'Open';
    }
}

export function formatFocusedInvestigationImpact(impact: FocusedInvestigationImpact | null | undefined): string {
    switch (impact) {
        case 'blocking':
            return 'Blocking';
        case 'degrading':
            return 'Degrading';
        default:
            return 'Informational';
    }
}

export function formatFocusedInvestigationType(issueType: FocusedInvestigationIssueType | null | undefined): string {
    switch (issueType) {
        case 'scope_violation':
            return 'Scope Violation';
        case 'auth_session_drift':
            return 'Auth/Session Drift';
        case 'missing_anchor':
            return 'Missing Anchor';
        case 'browser_state_mismatch':
            return 'Browser State Mismatch';
        case 'evidence_insufficient':
            return 'Evidence Insufficient';
        case 'execution_budget_exhausted':
            return 'Budget Exhausted';
        case 'request_replay_mismatch':
            return 'Replay Mismatch';
        case 'unexpected_navigation':
            return 'Unexpected Navigation';
        case 'unsupported_verification_primitive':
            return 'Unsupported Verification';
        case 'environment_instability':
            return 'Environment Instability';
        case 'contradictory_signals':
            return 'Contradictory Signals';
        case 'retry_failure':
            return 'Retry Failure';
        case 'blocked_flow':
            return 'Blocked Flow';
        default:
            return 'Issue';
    }
}
