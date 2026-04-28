export const SCAN_MODE_VALUES = ['exploratory', 'scoped'] as const;
export type ScanMode = typeof SCAN_MODE_VALUES[number];

export const SCOPED_TARGET_TYPE_VALUES = [
    'request_scoped',
    'endpoint_scoped',
    'flow_scoped',
    'feature_scoped',
] as const;
export type ScopedTargetType = typeof SCOPED_TARGET_TYPE_VALUES[number];

export const SCOPED_FEATURE_DISCOVERY_PHASE_VALUES = [
    'not_started',
    'discovering',
    'ready_to_plan',
    'blocked',
] as const;
export type ScopedFeatureDiscoveryPhase = typeof SCOPED_FEATURE_DISCOVERY_PHASE_VALUES[number];

export const SCOPED_FEATURE_DISCOVERY_OUTCOME_VALUES = [
    'candidate_anchors_found',
    'partial_anchors_found',
    'no_useful_anchors',
] as const;
export type ScopedFeatureDiscoveryOutcome = typeof SCOPED_FEATURE_DISCOVERY_OUTCOME_VALUES[number];

export const DEFAULT_SCOPE_ENVELOPE_VERSION = 1 as const;
export const FOCUSED_TEST_CASE_PRIORITY_VALUES = ['high', 'medium', 'low'] as const;
export type FocusedTestCasePriority = typeof FOCUSED_TEST_CASE_PRIORITY_VALUES[number];

export const FOCUSED_TEST_CASE_STATUS_VALUES = ['planned', 'disabled'] as const;
export type FocusedTestCaseStatus = typeof FOCUSED_TEST_CASE_STATUS_VALUES[number];

export const FOCUSED_TEST_CASE_REVIEW_STATE_VALUES = ['pending_review', 'approved', 'rejected'] as const;
export type FocusedTestCaseReviewState = typeof FOCUSED_TEST_CASE_REVIEW_STATE_VALUES[number];

export const FOCUSED_TEST_CASE_TARGET_KIND_VALUES = ['endpoint', 'baseline_request', 'flow', 'feature'] as const;
export type FocusedTestCaseTargetKind = typeof FOCUSED_TEST_CASE_TARGET_KIND_VALUES[number];

export const FOCUSED_CASE_INPUT_LOCATION_VALUES = ['path', 'query', 'body', 'header', 'rendered_content', 'identity', 'workflow_state'] as const;
export type FocusedCaseInputLocation = typeof FOCUSED_CASE_INPUT_LOCATION_VALUES[number];

export const FOCUSED_CASE_MUTATION_STRATEGY_VALUES = [
    'adjacent_identifier',
    'identity_contrast',
    'benign_render_marker',
    'boundary_value',
    'malformed_value',
    'type_contract_variation',
    'duplicate_replay',
    'state_toggle',
] as const;
export type FocusedCaseMutationStrategy = typeof FOCUSED_CASE_MUTATION_STRATEGY_VALUES[number];

export const FOCUSED_EXECUTION_STATE_VALUES = [
    'ready',
    'running',
    'completed',
    'blocked',
    'failed_to_execute',
    'skipped',
] as const;
export type FocusedExecutionState = typeof FOCUSED_EXECUTION_STATE_VALUES[number];

export const FOCUSED_CASE_FAMILY_VALUES = [
    'generic',
    'sqli',
    'xss',
    'access_control',
    'input_validation',
    'error_handling',
    'workflow_logic',
] as const;
export type FocusedCaseFamily = typeof FOCUSED_CASE_FAMILY_VALUES[number];

export const FOCUSED_REASONING_STAGE_VALUES = [
    'request_intake',
    'feature_discovery',
    'planning',
    'review_gate',
    'execution',
    'verdict',
    'investigation',
    'historical_compare',
] as const;
export type FocusedReasoningStage = typeof FOCUSED_REASONING_STAGE_VALUES[number];

export const FOCUSED_REASONING_ENTRY_TYPE_VALUES = [
    'context',
    'observation',
    'hypothesis',
    'decision',
    'action',
    'result',
    'constraint',
] as const;
export type FocusedReasoningEntryType = typeof FOCUSED_REASONING_ENTRY_TYPE_VALUES[number];

export const FOCUSED_REASONING_RAIL_VALUES = [
    'request',
    'browser',
    'hybrid',
    'system_only',
] as const;
export type FocusedReasoningRail = typeof FOCUSED_REASONING_RAIL_VALUES[number];

export const FOCUSED_REQUEST_CONTEXT_FIELD_VALUES = [
    'testData',
    'testUsers',
    'authMechanismHints',
    'attachmentSummary',
    'attachmentMetadata',
    'operatorNotes',
    'newScreenCount',
    'newInputCount',
] as const;
export type FocusedRequestContextField = typeof FOCUSED_REQUEST_CONTEXT_FIELD_VALUES[number];

export const FOCUSED_REASONING_CONTEXT_EFFECT_VALUES = [
    'used',
    'ignored',
    'insufficient',
] as const;
export type FocusedReasoningContextEffect = typeof FOCUSED_REASONING_CONTEXT_EFFECT_VALUES[number];

export const FOCUSED_HYPOTHESIS_STATUS_VALUES = [
    'plausible',
    'strengthened',
    'weakened',
    'stalled',
    'contradicted',
] as const;
export type FocusedHypothesisStatus = typeof FOCUSED_HYPOTHESIS_STATUS_VALUES[number];

export const FOCUSED_SUSPICION_PROOF_STATUS_VALUES = [
    'supported',
    'weak',
    'contradictory',
    'blocked',
] as const;
export type FocusedSuspicionProofStatus = typeof FOCUSED_SUSPICION_PROOF_STATUS_VALUES[number];

export const FOCUSED_EVIDENCE_REASONING_EFFECT_VALUES = [
    'supports',
    'weakens',
    'contradicts',
    'bounds',
] as const;
export type FocusedEvidenceReasoningEffect = typeof FOCUSED_EVIDENCE_REASONING_EFFECT_VALUES[number];

export const FOCUSED_SUPPORT_PROVENANCE_RAIL_VALUES = [
    'request',
    'browser',
    'hybrid',
    'system_only',
] as const;
export type FocusedSupportProvenanceRail = typeof FOCUSED_SUPPORT_PROVENANCE_RAIL_VALUES[number];

export const FOCUSED_EXECUTION_RAIL_VALUES = [
    'system',
    'request',
    'browser',
    'hybrid',
] as const;
export type FocusedExecutionRail = typeof FOCUSED_EXECUTION_RAIL_VALUES[number];

export const FOCUSED_EXECUTION_PRESENTATION_STATE_VALUES = [
    'not_run_yet',
    'awaiting_approval',
    'skipped_not_approved',
    'skipped_disabled',
    'running',
    'blocked',
    'failed_to_execute',
    'completed_with_evidence',
    'completed_without_evidence',
] as const;
export type FocusedExecutionPresentationState = typeof FOCUSED_EXECUTION_PRESENTATION_STATE_VALUES[number];

export const FOCUSED_EXECUTION_TRACE_ACTION_VALUES = [
    'execution_started',
    'retry_context',
    'action_planned',
    'request_dispatch',
    'response_observed',
    'response_compared',
    'browser_sequence_started',
    'browser_sequence_result',
    'screenshot_captured',
    'note_recorded',
    'blocked',
    'skipped',
    'execution_completed',
    'execution_failed',
] as const;
export type FocusedExecutionTraceActionType = typeof FOCUSED_EXECUTION_TRACE_ACTION_VALUES[number];

export const FOCUSED_SIGNAL_SUSPICIOUSNESS_VALUES = [
    'none',
    'low',
    'moderate',
    'high',
] as const;
export type FocusedSignalSuspiciousness = typeof FOCUSED_SIGNAL_SUSPICIOUSNESS_VALUES[number];

export const FOCUSED_SIGNAL_MARKER_VALUES = [
    'authz_bypass',
    'validation_rejected',
    'strong_fail_keyword',
    'sql_error_marker',
    'server_error_transition',
    'workflow_state_shift',
    'strong_structural_delta',
    'browser_expectation_met',
    'browser_expectation_missed',
    'script_reflection_marker',
    'state_mismatch_marker',
    'control_held',
    'contradictory_signal',
] as const;
export type FocusedSignalMarker = typeof FOCUSED_SIGNAL_MARKER_VALUES[number];

export const FOCUSED_EXECUTION_ACTION_VALUES = [
    'baseline_replay',
    'mutated_replay',
    'compare_responses',
    'browser_sequence',
    'browser_state_check',
    'capture_note',
    'capture_screenshot_if_available',
    'complete_case',
    'block_case',
] as const;
export type FocusedExecutionActionType = typeof FOCUSED_EXECUTION_ACTION_VALUES[number];

export const FOCUSED_EXECUTION_PHASE_VALUES = [
    'planned',
    'adaptive_confirmation',
] as const;
export type FocusedExecutionPhase = typeof FOCUSED_EXECUTION_PHASE_VALUES[number];

export const FOCUSED_FINDING_THREAD_STATUS_VALUES = [
    'collecting',
    'strengthening',
    'confirming',
    'blocked',
    'exhausted',
    'published',
] as const;
export type FocusedFindingThreadStatus = typeof FOCUSED_FINDING_THREAD_STATUS_VALUES[number];

export const FOCUSED_CONFIRMATION_KIND_VALUES = [
    'repeat_mutation',
    'alternate_id_compare',
    'render_check',
    'state_replay',
    'error_surface_compare',
    'control_contrast',
] as const;
export type FocusedConfirmationKind = typeof FOCUSED_CONFIRMATION_KIND_VALUES[number];

export const FOCUSED_CONFIRMATION_STEP_STATUS_VALUES = [
    'pending',
    'completed',
    'blocked',
    'skipped',
] as const;
export type FocusedConfirmationStepStatus = typeof FOCUSED_CONFIRMATION_STEP_STATUS_VALUES[number];

export const FOCUSED_CONFIRMATION_READINESS_VALUES = [
    'not_ready',
    'watch',
    'ready',
] as const;
export type FocusedConfirmationReadiness = typeof FOCUSED_CONFIRMATION_READINESS_VALUES[number];

export const FOCUSED_BROWSER_STEP_ACTION_VALUES = [
    'goto',
    'click',
    'fill',
    'select',
    'submit',
    'waitForNavigation',
    'waitForSelector',
    'reload',
] as const;
export type FocusedBrowserStepAction = typeof FOCUSED_BROWSER_STEP_ACTION_VALUES[number];

export const FOCUSED_VERDICT_STATE_VALUES = [
    'pass',
    'fail',
    'inconclusive',
    'needs_review',
] as const;
export type FocusedVerdictState = typeof FOCUSED_VERDICT_STATE_VALUES[number];

export const FOCUSED_EVIDENCE_SUFFICIENCY_STATE_VALUES = [
    'sufficient',
    'insufficient',
    'contradictory',
    'unsupported',
] as const;
export type FocusedEvidenceSufficiencyState = typeof FOCUSED_EVIDENCE_SUFFICIENCY_STATE_VALUES[number];

export const FOCUSED_FINDING_STATUS_VALUES = [
    'confirmed',
    'likely',
    'suspicious',
    'inconclusive',
    'not_confirmed',
] as const;
export type FocusedFindingStatus = typeof FOCUSED_FINDING_STATUS_VALUES[number];

export const FOCUSED_FINDING_CONFIDENCE_BAND_VALUES = [
    'low',
    'medium',
    'high',
] as const;
export type FocusedFindingConfidenceBand = typeof FOCUSED_FINDING_CONFIDENCE_BAND_VALUES[number];

export const FOCUSED_HISTORICAL_COMPARE_STATUS_VALUES = [
    'comparison_unavailable',
    'baseline_created',
    'compared',
    'not_comparable',
] as const;
export type FocusedHistoricalCompareStatus = typeof FOCUSED_HISTORICAL_COMPARE_STATUS_VALUES[number];

export const FOCUSED_CASE_COMPARE_STATUS_VALUES = [
    'baseline_only',
    'exact_match',
    'likely_match',
    'newly_introduced',
    'not_comparable',
] as const;
export type FocusedCaseCompareStatus = typeof FOCUSED_CASE_COMPARE_STATUS_VALUES[number];

export const FOCUSED_HISTORICAL_OUTCOME_VALUES = [
    'improved',
    'regressed',
    'unchanged',
    'weaker_confidence',
    'stronger_confidence',
    'newly_introduced',
    'not_comparable',
] as const;
export type FocusedHistoricalOutcome = typeof FOCUSED_HISTORICAL_OUTCOME_VALUES[number];

export const FOCUSED_EVIDENCE_DRIFT_CLASSIFICATION_VALUES = [
    'unchanged',
    'stronger_confidence',
    'weaker_confidence',
    'unsupported_gap_introduced',
    'contradiction_introduced',
    'scope_risk_increased',
] as const;
export type FocusedEvidenceDriftClassification = typeof FOCUSED_EVIDENCE_DRIFT_CLASSIFICATION_VALUES[number];

export const FOCUSED_OVERALL_CHANGE_CLASSIFICATION_VALUES = [
    'baseline_only',
    'improvement',
    'regression',
    'instability',
    'no_material_change',
] as const;
export type FocusedOverallChangeClassification = typeof FOCUSED_OVERALL_CHANGE_CLASSIFICATION_VALUES[number];

export const FOCUSED_VERDICT_TRANSITION_VALUES = [
    'pass_to_pass',
    'pass_to_fail',
    'pass_to_inconclusive',
    'pass_to_needs_review',
    'fail_to_pass',
    'fail_to_fail',
    'fail_to_inconclusive',
    'fail_to_needs_review',
    'inconclusive_to_pass',
    'inconclusive_to_fail',
    'inconclusive_to_inconclusive',
    'inconclusive_to_needs_review',
    'needs_review_to_pass',
    'needs_review_to_fail',
    'needs_review_to_inconclusive',
    'needs_review_to_needs_review',
] as const;
export type FocusedVerdictTransition = typeof FOCUSED_VERDICT_TRANSITION_VALUES[number];

export const FOCUSED_INVESTIGATION_ISSUE_TYPE_VALUES = [
    'scope_violation',
    'auth_session_drift',
    'missing_anchor',
    'browser_state_mismatch',
    'evidence_insufficient',
    'execution_budget_exhausted',
    'request_replay_mismatch',
    'unexpected_navigation',
    'unsupported_verification_primitive',
    'environment_instability',
    'contradictory_signals',
    'retry_failure',
    'blocked_flow',
] as const;
export type FocusedInvestigationIssueType = typeof FOCUSED_INVESTIGATION_ISSUE_TYPE_VALUES[number];

export const FOCUSED_INVESTIGATION_ISSUE_STATUS_VALUES = [
    'open',
    'resolved',
    'partially_resolved',
    'unresolved',
    'not_applicable',
] as const;
export type FocusedInvestigationIssueStatus = typeof FOCUSED_INVESTIGATION_ISSUE_STATUS_VALUES[number];

export const FOCUSED_INVESTIGATION_IMPACT_VALUES = [
    'informational',
    'degrading',
    'blocking',
] as const;
export type FocusedInvestigationImpact = typeof FOCUSED_INVESTIGATION_IMPACT_VALUES[number];

export const FOCUSED_WORKAROUND_OUTCOME_VALUES = [
    'resolved',
    'partially_resolved',
    'no_change',
    'introduced_uncertainty',
    'not_applicable',
] as const;
export type FocusedWorkaroundOutcome = typeof FOCUSED_WORKAROUND_OUTCOME_VALUES[number];

export const EVIDENCE_BUNDLE_SOURCE_VALUES = [
    'baseline_replay',
    'mutated_replay',
    'comparison',
    'browser_flow',
    'browser_verification',
    'execution_note',
    'scope_guard',
    'screenshot',
] as const;
export type EvidenceBundleSource = typeof EVIDENCE_BUNDLE_SOURCE_VALUES[number];

export const CONTEXT_PACK_SCHEMA_VERSION = 1 as const;

export interface SelectedScopedEndpoint {
    method: string;
    path: string;
    url?: string;
    host?: string;
    source?: string;
    notes?: string[];
}

export interface BaselineRequestRef {
    kind: 'scan_initial_request';
    source: 'burp_send_to_penpard';
    requestSlot: 'initial_request';
    method?: string;
    url?: string;
    host?: string;
    path?: string;
}

export interface RequestBundleRef {
    kind: string;
    id: string;
    label?: string;
}

export interface StructuredAttachmentMetadata {
    label?: string;
    kind?: string;
    mimeType?: string;
    note?: string;
}

export interface StructuredSecurityTestRequest {
    scanId?: string;
    targetUrl: string;
    description: string;
    environment?: string;
    serviceName?: string;
    testData: string[];
    testUsers: string[];
    loginPresent?: boolean | null;
    authMechanismHints: string[];
    hasScreenshotOrAttachment?: boolean | null;
    attachmentMetadata: StructuredAttachmentMetadata[];
    attachmentSummary?: string;
    newScreenCount?: number | null;
    newInputCount?: number | null;
    operatorNotes?: string;
    createdAt?: string;
    updatedAt?: string;
}

export type StructuredSecurityTestRequestSummary = StructuredSecurityTestRequest;

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
    missingEvidence: string[];
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

export interface DiscoveredRequestRef {
    id: string;
    source: 'request_url' | 'endpoint_inventory' | 'source_analysis' | 'browser_observed' | 'manual_override' | 'burp_observed';
    method?: string;
    url?: string;
    host?: string;
    path?: string;
    statusCode?: number;
    label?: string;
    matchReason?: string;
}

export interface ScopedBrowserAnchorRef {
    id: string;
    startUrl: string;
    startPath?: string;
    source: 'request_url' | 'page_link' | 'page_form' | 'endpoint_inventory' | 'source_analysis' | 'manual_override';
    label?: string;
    matchReason?: string;
}

export interface ScopedFeatureDiscoveryState {
    id: string;
    scanId: string;
    phase: ScopedFeatureDiscoveryPhase;
    outcome?: ScopedFeatureDiscoveryOutcome | null;
    summary?: string | null;
    errorMessage?: string | null;
    requestAnchorCount: number;
    browserAnchorCount: number;
    selectedEndpointCount: number;
    allowedRouteCount: number;
    startedAt?: string | null;
    completedAt?: string | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface AuthContextSummary {
    authStartupMode: 'no_credentials' | 'provided_credentials' | 'unknown';
    providedCredentialCount: number;
    hasSessionCookies: boolean;
    hasInitialRequestBaseline: boolean;
    continuityStrategy: 'browser_discovery' | 'provided_credentials' | 'session_cookies' | 'burp_baseline';
    summary: string;
}

export interface ExplorationBudget {
    maxRequests?: number | null;
    maxRouteVariants?: number | null;
    maxBrowserActions?: number | null;
    maxNavigationDepth?: number | null;
    maxVerificationRetries?: number | null;
    notes?: string | null;
}

export interface FocusedTestObjective {
    id: string;
    scanId: string;
    title: string;
    scopeType: ScopedTargetType;
    featureDescription?: string;
    goal?: string;
    operatorNotes?: string;
    riskTags: string[];
    createdAt?: string;
    updatedAt?: string;
}

export interface ScopeEnvelope {
    id: string;
    scanId: string;
    version: typeof DEFAULT_SCOPE_ENVELOPE_VERSION;
    allowedHosts: string[];
    allowedRoutes: string[];
    selectedEndpoints: SelectedScopedEndpoint[];
    baselineRequestRefs: BaselineRequestRef[];
    discoveredRequestRefs: DiscoveredRequestRef[];
    browserAnchors: ScopedBrowserAnchorRef[];
    requestBundleRefs: RequestBundleRef[];
    authContext: AuthContextSummary | null;
    outOfScopeNotes: string[];
    boundaryHints: string[];
    explorationBudget: ExplorationBudget | null;
    createdAt?: string;
    updatedAt?: string;
}

export interface FocusedTestCaseTargetArtifact {
    kind: FocusedTestCaseTargetKind;
    method?: string;
    path?: string;
    url?: string;
    referenceKind?: string;
    referenceId?: string;
    label?: string;
}

export interface FocusedTestStep {
    order: number;
    action: string;
}

export interface FocusedTestAssertion {
    kind: string;
    description: string;
}

export interface FocusedTestEvidenceRequirement {
    kind: string;
    description: string;
}

export interface FocusedEvidenceScreenshotRef {
    kind: string;
    value: string;
    mimeType?: string;
    label?: string | null;
    capturedAt?: string | null;
}

export interface EvidenceHttpReference {
    method?: string;
    url?: string;
    path?: string;
    host?: string;
    headers?: Record<string, string>;
    body?: string;
    statusCode?: number;
    raw?: string;
}

export interface EvidenceResponseDiffSummary {
    summary: string;
    significant: boolean;
    originalStatus?: number;
    mutatedStatus?: number;
    bodyLengthDelta?: number;
    structureChanged?: boolean;
    keywordSignals?: string[];
}

export interface ScopeViolationRecord {
    reason: string;
    attemptedAction: FocusedExecutionActionType | FocusedBrowserStepAction;
    attemptedHost?: string;
    attemptedPath?: string;
    attemptedMethod?: string;
    violationKind: 'host' | 'route' | 'endpoint_target' | 'baseline_anchor' | 'budget';
    blockedAt: string;
}

export interface EvidenceProvenance {
    profileKey: string;
    actionType: FocusedExecutionActionType;
    provider?: string;
    model?: string;
    source: 'system' | 'model';
    executionPhase?: FocusedExecutionPhase | null;
    confirmationKind?: FocusedConfirmationKind | null;
    confirmationOrdinal?: number | null;
    generatedFromFindingThreadId?: string | null;
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
    rawRequest?: string | null;
    rawResponse?: string | null;
    requestHeaders?: Record<string, string> | null;
    requestBody?: string | null;
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

export interface FocusedBrowserStep {
    action: FocusedBrowserStepAction;
    summary: string;
    url?: string;
    selector?: string;
    value?: string;
    timeoutMs?: number;
}

export interface FocusedBrowserExpectation {
    kind: string;
    description: string;
    matcher:
        | 'page_loaded'
        | 'path_matches'
        | 'text_contains'
        | 'text_absent'
        | 'title_contains'
        | 'state_changed'
        | 'state_unchanged';
    value?: string | null;
}

export interface FocusedBrowserExpectationResult {
    kind: string;
    description: string;
    matcher: FocusedBrowserExpectation['matcher'];
    matched: boolean;
    expected?: string | null;
    observedSummary: string;
}

export interface FocusedBrowserActionRecord {
    action: FocusedBrowserStepAction;
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

export interface FocusedSignalInterpretationSummary {
    caseFamily: FocusedCaseFamily;
    suspiciousness: FocusedSignalSuspiciousness;
    summary: string;
    suspiciousSignals: string[];
    passSignals: string[];
    failSignals: string[];
    reviewSignals: string[];
    contradictorySignals: string[];
    controlSignals: string[];
    keywordSignals: string[];
    signalMarkers: FocusedSignalMarker[];
    parameterHints: string[];
    scoreDelta: number;
    strongestSupport?: string | null;
    strongestBlocker?: string | null;
    missingEvidence: string[];
    uncertaintyReasons: string[];
    nextStepSummary?: string | null;
    followUpDecisionSummary?: string | null;
    confirmationReadiness: FocusedConfirmationReadiness;
    recommendedConfirmationKinds: FocusedConfirmationKind[];
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

export interface EvidenceBundle {
    id: string;
    scanId: string;
    caseId: string;
    executionId: string;
    summary: string;
    source: EvidenceBundleSource;
    capturedAt: string;
    requestRef?: EvidenceHttpReference | null;
    responseRef?: EvidenceHttpReference | null;
    responseDiffSummary?: EvidenceResponseDiffSummary | null;
    screenshotRef?: FocusedEvidenceScreenshotRef | null;
    browserState?: FocusedBrowserEvidence | null;
    relatedEvidenceIds?: string[];
    executionNotes?: string | null;
    provenance?: EvidenceProvenance | null;
    scopeViolation?: ScopeViolationRecord | null;
    createdAt?: string;
}

export interface FocusedExecutionMutation {
    name: string;
    value: string | number | boolean | null;
}

export interface FocusedExecutionAction {
    type: FocusedExecutionActionType;
    summary: string;
    phase?: FocusedExecutionPhase;
    confirmationKind?: FocusedConfirmationKind | null;
    generatedFromFindingThreadId?: string | null;
    confirmationOrdinal?: number | null;
    method?: string;
    url?: string;
    preserveExplicitAuth?: boolean;
    useInitialRequestBaseline?: boolean;
    queryMutations?: FocusedExecutionMutation[];
    bodyMutations?: FocusedExecutionMutation[];
    targetInputs?: FocusedCaseIntelligenceCandidateInput[];
    expectedSignals?: string[];
    selectionReason?: string;
    note?: string;
    reason?: string;
}

export interface FocusedBrowserPlan {
    summary: string;
    steps: FocusedBrowserStep[];
    expectations: FocusedBrowserExpectation[];
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

export interface FocusedExecutionSummary {
    caseId: string;
    executionState: FocusedExecutionState;
    executionPresentationState: FocusedExecutionPresentationState;
    lastRunAt: string | null;
    lastCompletedAt: string | null;
    lastExecutionId: string | null;
    executionNotesSummary: string | null;
    executionError: string | null;
    evidenceCount: number;
    browserEvidenceCount: number;
    scopeViolationCount: number;
    browserActionsUsed: number;
    executionProfileKey: string | null;
    browserSessionId: string | null;
    executionRailSummary: FocusedRailUsageSummary;
    latestTracePreview: FocusedExecutionTraceEntry[];
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
    source: EvidenceBundleSource;
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

export interface FocusedConfirmationStep {
    id: string;
    threadId: string;
    kind: FocusedConfirmationKind;
    status: FocusedConfirmationStepStatus;
    summary: string;
    actionType?: FocusedExecutionActionType | null;
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
    scopeType: ScopedTargetType;
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
    scopeViolationKinds?: Array<ScopeViolationRecord['violationKind']>;
    traceActionTypes?: FocusedExecutionTraceActionType[];
    latestTraceSummary?: string | null;
    latestTraceReasoning?: string | null;
    requestActionType?: FocusedExecutionActionType | null;
    browserActionType?: FocusedBrowserStepAction | null;
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

export interface FocusedTestCase {
    id: string;
    scanId: string;
    objectiveId: string;
    title: string;
    hypothesis: string;
    targetArtifact: FocusedTestCaseTargetArtifact;
    preconditions: string[];
    steps: FocusedTestStep[];
    assertions: FocusedTestAssertion[];
    requiredEvidence: FocusedTestEvidenceRequirement[];
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

export interface FocusedTestCaseDraft {
    title: string;
    hypothesis: string;
    targetArtifact: FocusedTestCaseTargetArtifact;
    preconditions: string[];
    steps: FocusedTestStep[];
    assertions: FocusedTestAssertion[];
    requiredEvidence: FocusedTestEvidenceRequirement[];
    priority: FocusedTestCasePriority;
    plannerRationaleSummary: string;
    caseFamily?: FocusedCaseFamily;
    caseIntelligence?: FocusedCaseIntelligence | null;
    maxAdaptiveFollowUps?: number | null;
    preferredRail?: FocusedExecutionRail | null;
    allowedConfirmationKinds?: FocusedConfirmationKind[];
    status?: FocusedTestCaseStatus;
    reviewState?: FocusedTestCaseReviewState;
}

export interface ContextPackSelectedTarget {
    kind: FocusedTestCaseTargetKind;
    method?: string;
    path?: string;
    url?: string;
    label?: string;
    referenceKind?: string;
    referenceId?: string;
}

export interface ContextPackObjectiveSummary {
    id: string;
    title: string;
    scopeType: ScopedTargetType;
    featureDescription?: string;
    goal?: string;
    operatorNotes?: string;
    riskTags: string[];
}

export interface ContextPackScopeSummary {
    allowedHosts: string[];
    allowedRoutes: string[];
    selectedEndpoints: SelectedScopedEndpoint[];
    baselineRequestRefs: BaselineRequestRef[];
    discoveredRequestRefs: DiscoveredRequestRef[];
    browserAnchors: ScopedBrowserAnchorRef[];
    requestBundleRefs: RequestBundleRef[];
    boundaryHints: string[];
    outOfScopeNotes: string[];
    explorationBudget: ExplorationBudget | null;
}

export interface ContextPackAuthSummary {
    continuityStrategy: string;
    summary: string;
    authContext: AuthContextSummary | null;
    inventorySummary?: {
        status?: string;
        summary?: string;
        authRoutes: string[];
        formsCount: number;
        trafficCount: number;
        ssoProviders: string[];
        registrationAvailable?: boolean;
        passwordResetAvailable?: boolean;
    };
}

export interface ContextPackEndpointIntelligenceRecordSummary {
    endpoint: string;
    path: string;
    methods: string[];
    classification: string;
    likelyAuthRelevant: boolean;
    observedInBurp: boolean;
    exercisedInBrowser: boolean;
    confidence: number;
    notes: string[];
    evidence: string[];
}

export interface ContextPackEndpointIntelligenceSummary {
    summary: string;
    authRelevantCount: number;
    observedInBurpCount: number;
    exercisedInBrowserCount: number;
    records: ContextPackEndpointIntelligenceRecordSummary[];
}

export interface ContextPackSourceAnalysisSummary {
    mode: string;
    framework: string;
    technologyStack: string[];
    testingHints: Array<{
        category: string;
        hint: string;
    }>;
    endpoints?: Array<{
        method: string;
        path: string;
        authRequired: boolean;
        description: string;
    }>;
    securityFlows?: Array<{
        category: string;
        description: string;
        riskLevel: string;
    }>;
}

export interface ContextPackSupportingContext {
    operatorInstructions?: string;
    requestBundles: RequestBundleRef[];
    securityTestRequest?: StructuredSecurityTestRequestSummary;
    featureDiscovery?: Pick<ScopedFeatureDiscoveryState, 'phase' | 'outcome' | 'summary' | 'requestAnchorCount' | 'browserAnchorCount' | 'selectedEndpointCount' | 'allowedRouteCount'>;
    endpointIntelligence?: ContextPackEndpointIntelligenceSummary;
    sourceAnalysis?: ContextPackSourceAnalysisSummary;
    observedInputHints?: string[];
}

export interface ContextPackPlannerConstraints {
    schemaVersion: typeof CONTEXT_PACK_SCHEMA_VERSION;
    noScopeExpansion: true;
    maxCases: number;
}

export interface ContextPack {
    scanId: string;
    objective: ContextPackObjectiveSummary;
    scope: ContextPackScopeSummary;
    authSummary: ContextPackAuthSummary;
    selectedTargets: ContextPackSelectedTarget[];
    supportingContext: ContextPackSupportingContext;
    plannerConstraints: ContextPackPlannerConstraints;
}

export interface FocusedPlannerRequest {
    contextPack: ContextPack;
    seedCases: FocusedTestCaseDraft[];
    maxCases: number;
}

export interface FocusedPlannerResponse {
    cases: FocusedTestCaseDraft[];
}

export interface FocusedPlanSummary {
    totalCases: number;
    enabledCases: number;
    disabledCases: number;
    latestPlannedAt: string | null;
    countsByPriority: Record<FocusedTestCasePriority, number>;
    countsByReviewState: Record<FocusedTestCaseReviewState, number>;
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

export function normalizeScanMode(value: unknown): ScanMode {
    return value === 'scoped' ? 'scoped' : 'exploratory';
}

export function normalizeScopedFeatureDiscoveryPhase(value: unknown): ScopedFeatureDiscoveryPhase {
    switch (value) {
        case 'discovering':
        case 'ready_to_plan':
        case 'blocked':
            return value;
        default:
            return 'not_started';
    }
}

export function normalizeScopedFeatureDiscoveryOutcome(value: unknown): ScopedFeatureDiscoveryOutcome | null {
    switch (value) {
        case 'candidate_anchors_found':
        case 'partial_anchors_found':
        case 'no_useful_anchors':
            return value;
        default:
            return null;
    }
}

export function normalizeFocusedTestCasePriority(value: unknown): FocusedTestCasePriority {
    return value === 'high' || value === 'medium' || value === 'low' ? value : 'medium';
}

export function normalizeFocusedTestCaseStatus(value: unknown): FocusedTestCaseStatus {
    return value === 'disabled' ? 'disabled' : 'planned';
}

export function normalizeFocusedTestCaseReviewState(
    value: unknown,
    defaultState: FocusedTestCaseReviewState = 'pending_review',
): FocusedTestCaseReviewState {
    return value === 'approved' || value === 'rejected' ? value : defaultState;
}

export function normalizeFocusedExecutionState(value: unknown): FocusedExecutionState {
    switch (value) {
        case 'running':
        case 'completed':
        case 'blocked':
        case 'failed_to_execute':
        case 'skipped':
            return value;
        default:
            return 'ready';
    }
}

export function normalizeFocusedCaseFamily(value: unknown): FocusedCaseFamily {
    switch (value) {
        case 'sqli':
        case 'xss':
        case 'access_control':
        case 'input_validation':
        case 'error_handling':
        case 'workflow_logic':
            return value;
        default:
            return 'generic';
    }
}

export function normalizeFocusedCaseInputLocation(value: unknown): FocusedCaseInputLocation {
    return FOCUSED_CASE_INPUT_LOCATION_VALUES.includes(value as FocusedCaseInputLocation)
        ? value as FocusedCaseInputLocation
        : 'body';
}

export function normalizeFocusedCaseMutationStrategy(value: unknown): FocusedCaseMutationStrategy {
    return FOCUSED_CASE_MUTATION_STRATEGY_VALUES.includes(value as FocusedCaseMutationStrategy)
        ? value as FocusedCaseMutationStrategy
        : 'type_contract_variation';
}

export function normalizeFocusedReasoningStage(value: unknown): FocusedReasoningStage {
    return FOCUSED_REASONING_STAGE_VALUES.includes(value as FocusedReasoningStage)
        ? value as FocusedReasoningStage
        : 'execution';
}

export function normalizeFocusedReasoningEntryType(value: unknown): FocusedReasoningEntryType {
    return FOCUSED_REASONING_ENTRY_TYPE_VALUES.includes(value as FocusedReasoningEntryType)
        ? value as FocusedReasoningEntryType
        : 'observation';
}

export function normalizeFocusedReasoningRail(value: unknown): FocusedReasoningRail {
    return FOCUSED_REASONING_RAIL_VALUES.includes(value as FocusedReasoningRail)
        ? value as FocusedReasoningRail
        : 'system_only';
}

export function normalizeFocusedRequestContextField(value: unknown): FocusedRequestContextField {
    return FOCUSED_REQUEST_CONTEXT_FIELD_VALUES.includes(value as FocusedRequestContextField)
        ? value as FocusedRequestContextField
        : 'operatorNotes';
}

export function normalizeFocusedReasoningContextEffect(value: unknown): FocusedReasoningContextEffect {
    switch (value) {
        case 'ignored':
        case 'insufficient':
            return value;
        default:
            return 'used';
    }
}

export function normalizeFocusedHypothesisStatus(value: unknown): FocusedHypothesisStatus {
    switch (value) {
        case 'strengthened':
        case 'weakened':
        case 'stalled':
        case 'contradicted':
            return value;
        default:
            return 'plausible';
    }
}

export function normalizeFocusedSuspicionProofStatus(value: unknown): FocusedSuspicionProofStatus {
    switch (value) {
        case 'weak':
        case 'contradictory':
        case 'blocked':
            return value;
        default:
            return 'supported';
    }
}

export function normalizeFocusedEvidenceReasoningEffect(value: unknown): FocusedEvidenceReasoningEffect {
    switch (value) {
        case 'weakens':
        case 'contradicts':
        case 'bounds':
            return value;
        default:
            return 'supports';
    }
}

export function normalizeFocusedExecutionRail(value: unknown): FocusedExecutionRail {
    switch (value) {
        case 'request':
        case 'browser':
        case 'hybrid':
            return value;
        default:
            return 'system';
    }
}

export function normalizeFocusedExecutionPhase(value: unknown): FocusedExecutionPhase {
    return value === 'adaptive_confirmation' ? 'adaptive_confirmation' : 'planned';
}

export function normalizeFocusedExecutionPresentationState(value: unknown): FocusedExecutionPresentationState {
    switch (value) {
        case 'awaiting_approval':
        case 'skipped_not_approved':
        case 'skipped_disabled':
        case 'running':
        case 'blocked':
        case 'failed_to_execute':
        case 'completed_with_evidence':
        case 'completed_without_evidence':
            return value;
        default:
            return 'not_run_yet';
    }
}

export function normalizeFocusedExecutionTraceActionType(value: unknown): FocusedExecutionTraceActionType {
    return FOCUSED_EXECUTION_TRACE_ACTION_VALUES.includes(value as FocusedExecutionTraceActionType)
        ? value as FocusedExecutionTraceActionType
        : 'note_recorded';
}

export function normalizeFocusedSignalSuspiciousness(value: unknown): FocusedSignalSuspiciousness {
    switch (value) {
        case 'low':
        case 'moderate':
        case 'high':
            return value;
        default:
            return 'none';
    }
}

export function normalizeFocusedConfirmationKind(value: unknown): FocusedConfirmationKind {
    switch (value) {
        case 'alternate_id_compare':
        case 'render_check':
        case 'state_replay':
        case 'error_surface_compare':
        case 'control_contrast':
            return value;
        default:
            return 'repeat_mutation';
    }
}

export function normalizeFocusedConfirmationStepStatus(value: unknown): FocusedConfirmationStepStatus {
    switch (value) {
        case 'completed':
        case 'blocked':
        case 'skipped':
            return value;
        default:
            return 'pending';
    }
}

export function normalizeFocusedConfirmationReadiness(value: unknown): FocusedConfirmationReadiness {
    switch (value) {
        case 'watch':
        case 'ready':
            return value;
        default:
            return 'not_ready';
    }
}

export function normalizeFocusedCaseIntelligence(value: unknown): FocusedCaseIntelligence | null {
    if (!value || typeof value !== 'object') {
        return null;
    }
    const record = value as Record<string, any>;
    const candidateInputs = Array.isArray(record.candidateInputs)
        ? record.candidateInputs.map((entry) => ({
            name: String(entry?.name || '').trim().slice(0, 80),
            location: normalizeFocusedCaseInputLocation(entry?.location),
            reason: String(entry?.reason || '').trim().slice(0, 220),
            mutationStrategy: normalizeFocusedCaseMutationStrategy(entry?.mutationStrategy),
            observedValuePreview: entry?.observedValuePreview == null
                ? null
                : String(entry.observedValuePreview).trim().slice(0, 120),
        })).filter((entry) => entry.name && entry.reason)
        : [];
    const securityConcerns = Array.isArray(record.securityConcerns)
        ? record.securityConcerns.map((entry) => ({
            family: normalizeFocusedCaseFamily(entry?.family),
            title: String(entry?.title || '').trim().slice(0, 120),
            whyRelevant: String(entry?.whyRelevant || '').trim().slice(0, 240),
            strengtheningSignals: (Array.isArray(entry?.strengtheningSignals) ? entry.strengtheningSignals : [])
                .map((item: unknown) => String(item || '').trim())
                .filter(Boolean)
                .slice(0, 6),
            weakeningSignals: (Array.isArray(entry?.weakeningSignals) ? entry.weakeningSignals : [])
                .map((item: unknown) => String(item || '').trim())
                .filter(Boolean)
                .slice(0, 6),
            boundedChecks: (Array.isArray(entry?.boundedChecks) ? entry.boundedChecks : [])
                .map((item: unknown) => String(item || '').trim())
                .filter(Boolean)
                .slice(0, 6),
        })).filter((entry) => entry.title && entry.whyRelevant)
        : [];
    const followUpPolicy = record.followUpPolicy && typeof record.followUpPolicy === 'object'
        ? {
            maxAdaptiveFollowUps: Math.max(0, Math.min(2, Number(record.followUpPolicy.maxAdaptiveFollowUps) || 0)),
            allowedConfirmationKinds: (Array.isArray(record.followUpPolicy.allowedConfirmationKinds) ? record.followUpPolicy.allowedConfirmationKinds : [])
                .map((entry: unknown) => normalizeFocusedConfirmationKind(entry))
                .slice(0, 4),
            queueThresholdScore: Math.max(0, Math.min(100, Number(record.followUpPolicy.queueThresholdScore) || 40)),
            strongSignalMarkers: (Array.isArray(record.followUpPolicy.strongSignalMarkers) ? record.followUpPolicy.strongSignalMarkers : [])
                .filter((entry: unknown) => typeof entry === 'string')
                .slice(0, 6) as FocusedSignalMarker[],
            boundedBy: (Array.isArray(record.followUpPolicy.boundedBy) ? record.followUpPolicy.boundedBy : [])
                .map((entry: unknown) => String(entry || '').trim())
                .filter(Boolean)
                .slice(0, 6),
            stopConditions: (Array.isArray(record.followUpPolicy.stopConditions) ? record.followUpPolicy.stopConditions : [])
                .map((entry: unknown) => String(entry || '').trim())
                .filter(Boolean)
                .slice(0, 6),
        }
        : null;

    const selectionSummary = String(record.selectionSummary || '').trim().slice(0, 280);
    const anchorSummary = String(record.anchorSummary || '').trim().slice(0, 280);
    if (!selectionSummary || !anchorSummary) {
        return null;
    }

    return {
        selectionSummary,
        anchorSummary,
        candidateInputs: candidateInputs.slice(0, 8),
        securityConcerns: securityConcerns.slice(0, 3),
        followUpPolicy: followUpPolicy || {
            maxAdaptiveFollowUps: 1,
            allowedConfirmationKinds: [],
            queueThresholdScore: 40,
            strongSignalMarkers: [],
            boundedBy: [],
            stopConditions: [],
        },
    };
}

export function normalizeFocusedSignalMarker(value: unknown): FocusedSignalMarker {
    return FOCUSED_SIGNAL_MARKER_VALUES.includes(value as FocusedSignalMarker)
        ? value as FocusedSignalMarker
        : 'control_held';
}

export function normalizeFocusedVerdictState(value: unknown): FocusedVerdictState {
    switch (value) {
        case 'pass':
        case 'fail':
        case 'inconclusive':
            return value;
        default:
            return 'needs_review';
    }
}

export function normalizeFocusedEvidenceSufficiencyState(value: unknown): FocusedEvidenceSufficiencyState {
    switch (value) {
        case 'sufficient':
        case 'contradictory':
        case 'unsupported':
            return value;
        default:
            return 'insufficient';
    }
}

export function normalizeFocusedFindingStatus(value: unknown): FocusedFindingStatus {
    switch (value) {
        case 'confirmed':
        case 'likely':
        case 'suspicious':
        case 'inconclusive':
            return value;
        default:
            return 'not_confirmed';
    }
}

export function normalizeFocusedFindingThreadStatus(value: unknown): FocusedFindingThreadStatus {
    switch (value) {
        case 'strengthening':
        case 'confirming':
        case 'blocked':
        case 'exhausted':
        case 'published':
            return value;
        default:
            return 'collecting';
    }
}

export function normalizeFocusedFindingConfidenceBand(value: unknown): FocusedFindingConfidenceBand {
    switch (value) {
        case 'medium':
        case 'high':
            return value;
        default:
            return 'low';
    }
}

export function normalizeFocusedHistoricalCompareStatus(value: unknown): FocusedHistoricalCompareStatus {
    switch (value) {
        case 'baseline_created':
        case 'compared':
        case 'not_comparable':
            return value;
        default:
            return 'comparison_unavailable';
    }
}

export function normalizeFocusedCaseCompareStatus(value: unknown): FocusedCaseCompareStatus {
    switch (value) {
        case 'exact_match':
        case 'likely_match':
        case 'newly_introduced':
        case 'not_comparable':
            return value;
        default:
            return 'baseline_only';
    }
}

export function normalizeFocusedHistoricalOutcome(value: unknown): FocusedHistoricalOutcome {
    switch (value) {
        case 'improved':
        case 'regressed':
        case 'weaker_confidence':
        case 'stronger_confidence':
        case 'newly_introduced':
        case 'not_comparable':
            return value;
        default:
            return 'unchanged';
    }
}

export function normalizeFocusedEvidenceDriftClassification(value: unknown): FocusedEvidenceDriftClassification {
    switch (value) {
        case 'stronger_confidence':
        case 'weaker_confidence':
        case 'unsupported_gap_introduced':
        case 'contradiction_introduced':
        case 'scope_risk_increased':
            return value;
        default:
            return 'unchanged';
    }
}

export function normalizeFocusedOverallChangeClassification(value: unknown): FocusedOverallChangeClassification {
    switch (value) {
        case 'improvement':
        case 'regression':
        case 'instability':
        case 'no_material_change':
            return value;
        default:
            return 'baseline_only';
    }
}

export function normalizeFocusedVerdictTransition(value: unknown): FocusedVerdictTransition {
    return FOCUSED_VERDICT_TRANSITION_VALUES.includes(value as FocusedVerdictTransition)
        ? value as FocusedVerdictTransition
        : 'needs_review_to_needs_review';
}

export function normalizeFocusedInvestigationIssueType(value: unknown): FocusedInvestigationIssueType {
    return FOCUSED_INVESTIGATION_ISSUE_TYPE_VALUES.includes(value as FocusedInvestigationIssueType)
        ? value as FocusedInvestigationIssueType
        : 'blocked_flow';
}

export function normalizeFocusedInvestigationIssueStatus(value: unknown): FocusedInvestigationIssueStatus {
    switch (value) {
        case 'resolved':
        case 'partially_resolved':
        case 'unresolved':
        case 'not_applicable':
            return value;
        default:
            return 'open';
    }
}

export function normalizeFocusedInvestigationImpact(value: unknown): FocusedInvestigationImpact {
    switch (value) {
        case 'degrading':
        case 'blocking':
            return value;
        default:
            return 'informational';
    }
}

export function normalizeFocusedWorkaroundOutcome(value: unknown): FocusedWorkaroundOutcome {
    switch (value) {
        case 'resolved':
        case 'partially_resolved':
        case 'introduced_uncertainty':
        case 'not_applicable':
            return value;
        default:
            return 'no_change';
    }
}

export function listPresentFocusedRequestContextFields(
    request: StructuredSecurityTestRequest | null | undefined,
): FocusedRequestContextField[] {
    if (!request) {
        return [];
    }

    const fields: FocusedRequestContextField[] = [];
    if (Array.isArray(request.testData) && request.testData.length > 0) {
        fields.push('testData');
    }
    if (Array.isArray(request.testUsers) && request.testUsers.length > 0) {
        fields.push('testUsers');
    }
    if (Array.isArray(request.authMechanismHints) && request.authMechanismHints.length > 0) {
        fields.push('authMechanismHints');
    }
    if (request.attachmentSummary) {
        fields.push('attachmentSummary');
    }
    if (Array.isArray(request.attachmentMetadata) && request.attachmentMetadata.length > 0) {
        fields.push('attachmentMetadata');
    }
    if (request.operatorNotes) {
        fields.push('operatorNotes');
    }
    if (typeof request.newScreenCount === 'number' && request.newScreenCount > 0) {
        fields.push('newScreenCount');
    }
    if (typeof request.newInputCount === 'number' && request.newInputCount > 0) {
        fields.push('newInputCount');
    }

    return [...new Set(fields)];
}

export function isFocusedTestCaseEnabled(testCase: Pick<FocusedTestCase, 'status'>): boolean {
    return testCase.status !== 'disabled';
}

export function isFocusedTestCaseApproved(testCase: Pick<FocusedTestCase, 'reviewState'>): boolean {
    return testCase.reviewState === 'approved';
}

export function projectFocusedExecutionSummary(testCase: Pick<FocusedTestCase, 'id' | 'status' | 'reviewState'>): FocusedExecutionSummary {
    const isRunnable = isFocusedTestCaseEnabled(testCase) && isFocusedTestCaseApproved(testCase);
    const projectedExecutionState = testCase.status === 'disabled' || testCase.reviewState === 'rejected'
        ? 'skipped'
        : 'ready';
    const executionNotesSummary = isRunnable
        ? 'Approved and ready for bounded execution.'
        : testCase.status === 'disabled'
            ? 'Execution was intentionally skipped because the case is disabled.'
            : testCase.reviewState === 'rejected'
                ? 'Execution was intentionally skipped because the case was not approved.'
                : 'Execution is waiting for operator approval.';

    return {
        caseId: testCase.id,
        executionState: projectedExecutionState,
        executionPresentationState: deriveFocusedExecutionPresentationState({
            status: testCase.status,
            reviewState: testCase.reviewState,
            executionState: projectedExecutionState,
            lastExecutionId: null,
            evidenceCount: 0,
        }),
        lastRunAt: null,
        lastCompletedAt: null,
        lastExecutionId: null,
        executionNotesSummary,
        executionError: null,
        evidenceCount: 0,
        browserEvidenceCount: 0,
        scopeViolationCount: 0,
        browserActionsUsed: 0,
        executionProfileKey: null,
        browserSessionId: null,
        executionRailSummary: buildFocusedRailUsageSummary({
            requestActionsUsed: 0,
            browserActionsUsed: 0,
            traceCount: 0,
        }),
        latestTracePreview: [],
    };
}

export function applyFocusedExecutionSummary(
    testCase: FocusedTestCase,
    summary: FocusedExecutionSummary | null | undefined,
): FocusedTestCase {
    const projected = summary || projectFocusedExecutionSummary(testCase);
    const executionPresentationState = deriveFocusedExecutionPresentationState({
        status: testCase.status,
        reviewState: testCase.reviewState,
        executionState: projected.executionState,
        lastExecutionId: projected.lastExecutionId,
        evidenceCount: projected.evidenceCount,
    });
    return {
        ...testCase,
        executionState: projected.executionState,
        executionPresentationState,
        lastRunAt: projected.lastRunAt,
        lastCompletedAt: projected.lastCompletedAt,
        lastExecutionId: projected.lastExecutionId,
        executionNotesSummary: projected.executionNotesSummary,
        executionError: projected.executionError,
        evidenceCount: projected.evidenceCount,
        browserEvidenceCount: projected.browserEvidenceCount,
        scopeViolationCount: projected.scopeViolationCount,
        browserActionsUsed: projected.browserActionsUsed,
        executionProfileKey: projected.executionProfileKey,
        browserSessionId: projected.browserSessionId,
        executionRailSummary: projected.executionRailSummary,
        latestExecutionTracePreview: projected.latestTracePreview,
        latestVerdict: testCase.latestVerdict ?? null,
    };
}

export function applyFocusedCaseVerdict(
    testCase: FocusedTestCase,
    verdict: FocusedCaseVerdict | null | undefined,
): FocusedTestCase {
    return {
        ...testCase,
        latestVerdict: verdict || null,
    };
}

export function applyFocusedCaseFindings(
    testCase: FocusedTestCase,
    findings: FocusedCaseFinding[] | null | undefined,
): FocusedTestCase {
    const sortedFindings = Array.isArray(findings)
        ? [...findings].sort((left, right) => {
            if ((left.isPrimary ? 1 : 0) !== (right.isPrimary ? 1 : 0)) {
                return Number(right.isPrimary) - Number(left.isPrimary);
            }
            if (left.rankOrder !== right.rankOrder) {
                return left.rankOrder - right.rankOrder;
            }
            if (left.suspicionScore !== right.suspicionScore) {
                return right.suspicionScore - left.suspicionScore;
            }
            if (left.confirmationProgress !== right.confirmationProgress) {
                return right.confirmationProgress - left.confirmationProgress;
            }
            return left.title.localeCompare(right.title);
        })
        : [];
    return {
        ...testCase,
        primaryFinding: sortedFindings.find((entry) => entry.isPrimary) || sortedFindings[0] || null,
        findings: sortedFindings,
    };
}

export function applyFocusedFindingThreads(
    testCase: FocusedTestCase,
    findingThreads: FocusedFindingThread[] | null | undefined,
): FocusedTestCase {
    const sortedThreads = Array.isArray(findingThreads)
        ? [...findingThreads].sort((left, right) => {
            const statusRank: Record<FocusedFindingThreadStatus, number> = {
                confirming: 0,
                strengthening: 1,
                collecting: 2,
                blocked: 3,
                exhausted: 4,
                published: 5,
            };
            if ((left.isPrimary ? 1 : 0) !== (right.isPrimary ? 1 : 0)) {
                return Number(right.isPrimary) - Number(left.isPrimary);
            }
            if (statusRank[left.status] !== statusRank[right.status]) {
                return statusRank[left.status] - statusRank[right.status];
            }
            if (left.suspicionScore !== right.suspicionScore) {
                return right.suspicionScore - left.suspicionScore;
            }
            if (left.confirmationProgress !== right.confirmationProgress) {
                return right.confirmationProgress - left.confirmationProgress;
            }
            return left.title.localeCompare(right.title);
        })
        : [];
    const activeFindingThread = sortedThreads.find((entry) => entry.isPrimary) || sortedThreads[0] || null;
    return {
        ...testCase,
        activeFindingThread,
        findingThreads: sortedThreads,
        confirmationState: activeFindingThread?.confirmationState || null,
    };
}

export function applyFocusedInvestigationSummary(
    testCase: FocusedTestCase,
    summary: FocusedCaseInvestigationSummary | null | undefined,
): FocusedTestCase {
    return {
        ...testCase,
        investigationSummary: summary || null,
    };
}

export function applyFocusedHistoricalCompare(
    testCase: FocusedTestCase,
    compare: FocusedCaseHistoricalCompare | null | undefined,
): FocusedTestCase {
    return {
        ...testCase,
        historicalCompare: compare || null,
    };
}

export function createEmptyFocusedVerdictCounts(): Record<FocusedVerdictState, number> {
    return {
        pass: 0,
        fail: 0,
        inconclusive: 0,
        needs_review: 0,
    };
}

export function createEmptyFocusedFindingStatusCounts(): Record<FocusedFindingStatus, number> {
    return {
        confirmed: 0,
        likely: 0,
        suspicious: 0,
        inconclusive: 0,
        not_confirmed: 0,
    };
}

export function createEmptyFocusedVerdictTransitionCounts(): Record<FocusedVerdictTransition, number> {
    return {
        pass_to_pass: 0,
        pass_to_fail: 0,
        pass_to_inconclusive: 0,
        pass_to_needs_review: 0,
        fail_to_pass: 0,
        fail_to_fail: 0,
        fail_to_inconclusive: 0,
        fail_to_needs_review: 0,
        inconclusive_to_pass: 0,
        inconclusive_to_fail: 0,
        inconclusive_to_inconclusive: 0,
        inconclusive_to_needs_review: 0,
        needs_review_to_pass: 0,
        needs_review_to_fail: 0,
        needs_review_to_inconclusive: 0,
        needs_review_to_needs_review: 0,
    };
}

export function createEmptyFocusedBlockerRecurrenceSummary(): FocusedBlockerRecurrenceSummary {
    return {
        recurringUnresolvedIssueFamilies: [],
        resolvedIssueFamilies: [],
        newlyIntroducedIssueFamilies: [],
        recurringWorkaroundFailureFamilies: [],
        blockingCountDelta: 0,
        degradingCountDelta: 0,
        notes: [],
    };
}

export function createEmptyFocusedInvestigationStatusCounts(): Record<FocusedInvestigationIssueStatus, number> {
    return {
        open: 0,
        resolved: 0,
        partially_resolved: 0,
        unresolved: 0,
        not_applicable: 0,
    };
}

export function createEmptyFocusedInvestigationImpactCounts(): Record<FocusedInvestigationImpact, number> {
    return {
        informational: 0,
        degrading: 0,
        blocking: 0,
    };
}

export function createEmptyFocusedInvestigationTypeCounts(): Record<FocusedInvestigationIssueType, number> {
    return {
        scope_violation: 0,
        auth_session_drift: 0,
        missing_anchor: 0,
        browser_state_mismatch: 0,
        evidence_insufficient: 0,
        execution_budget_exhausted: 0,
        request_replay_mismatch: 0,
        unexpected_navigation: 0,
        unsupported_verification_primitive: 0,
        environment_instability: 0,
        contradictory_signals: 0,
        retry_failure: 0,
        blocked_flow: 0,
    };
}

export function isFocusedInvestigationIssueUnresolved(status: FocusedInvestigationIssueStatus | null | undefined): boolean {
    return status === 'open' || status === 'partially_resolved' || status === 'unresolved';
}

export function createEmptyFocusedPlanSummary(): FocusedPlanSummary {
    return {
        totalCases: 0,
        enabledCases: 0,
        disabledCases: 0,
        latestPlannedAt: null,
        countsByPriority: {
            high: 0,
            medium: 0,
            low: 0,
        },
        countsByReviewState: {
            pending_review: 0,
            approved: 0,
            rejected: 0,
        },
    };
}

export function buildFocusedPlanSummary(cases: FocusedTestCase[]): FocusedPlanSummary {
    const summary = createEmptyFocusedPlanSummary();

    for (const testCase of cases) {
        summary.totalCases += 1;
        summary.countsByPriority[testCase.priority] += 1;
        summary.countsByReviewState[testCase.reviewState] += 1;
        if (testCase.status === 'disabled') {
            summary.disabledCases += 1;
        } else {
            summary.enabledCases += 1;
        }

        const candidateTimestamp = testCase.updatedAt || testCase.createdAt || null;
        if (candidateTimestamp && (!summary.latestPlannedAt || candidateTimestamp > summary.latestPlannedAt)) {
            summary.latestPlannedAt = candidateTimestamp;
        }
    }

    return summary;
}

export function deriveFocusedExecutionRail(input: {
    requestActionsUsed?: number | null;
    browserActionsUsed?: number | null;
}): FocusedExecutionRail {
    const requestActionsUsed = Number(input.requestActionsUsed) || 0;
    const browserActionsUsed = Number(input.browserActionsUsed) || 0;

    if (requestActionsUsed > 0 && browserActionsUsed > 0) {
        return 'hybrid';
    }
    if (browserActionsUsed > 0) {
        return 'browser';
    }
    if (requestActionsUsed > 0) {
        return 'request';
    }
    return 'system';
}

export function buildFocusedRailUsageSummary(input: {
    requestActionsUsed?: number | null;
    browserActionsUsed?: number | null;
    traceCount?: number | null;
}): FocusedRailUsageSummary {
    const requestActionsUsed = Number(input.requestActionsUsed) || 0;
    const browserActionsUsed = Number(input.browserActionsUsed) || 0;
    const traceCount = Number(input.traceCount) || 0;
    const rail = deriveFocusedExecutionRail({
        requestActionsUsed,
        browserActionsUsed,
    });

    const summary = rail === 'hybrid'
        ? `Hybrid bounded execution used ${requestActionsUsed} request-backed Burp/MCP action${requestActionsUsed === 1 ? '' : 's'} and ${browserActionsUsed} browser-backed action${browserActionsUsed === 1 ? '' : 's'}.`
        : rail === 'request'
            ? `Request-backed bounded execution used ${requestActionsUsed} Burp/MCP action${requestActionsUsed === 1 ? '' : 's'}.`
            : rail === 'browser'
                ? `Browser-backed bounded execution used ${browserActionsUsed} browser action${browserActionsUsed === 1 ? '' : 's'}.`
                : 'No request-backed or browser-backed execution actions were persisted for this case.';

    return {
        rail,
        summary,
        requestActionsUsed,
        browserActionsUsed,
        usedRequestRail: requestActionsUsed > 0,
        usedBrowserRail: browserActionsUsed > 0,
        usedBurpMcp: requestActionsUsed > 0,
        traceCount,
    };
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
