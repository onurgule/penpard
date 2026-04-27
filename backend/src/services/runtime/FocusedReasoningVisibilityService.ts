import {
    getFocusedCaseVerdictByExecution,
    getFocusedTestCaseById,
    getFocusedTestObjective,
    getLatestFocusedCaseVerdictByCase,
    getScopedTestRequest,
    listEvidenceBundlesByCase,
    listEvidenceBundlesByExecution,
    listFocusedInvestigationIssuesByCase,
    listFocusedInvestigationIssuesByExecution,
} from '../../db/init';
import type {
    EvidenceBundle,
    FocusedCaseFamily,
    FocusedContextInfluenceSummary,
    FocusedEvidenceReasoningEffect,
    FocusedEvidenceReasoningLink,
    FocusedHypothesisStatus,
    FocusedHypothesisVisibility,
    FocusedInvestigationIssue,
    FocusedReasoningContextInfluence,
    FocusedReasoningTraceEntry,
    FocusedRequestEvidenceStory,
    FocusedRequestContextField,
    FocusedSignalInterpretationSummary,
    FocusedStoryCaseSummary,
    FocusedStorySummary,
    FocusedSupportProvenanceSummary,
    FocusedSuspicionExplanation,
    FocusedSuspicionProofStatus,
    FocusedTestCase,
    StructuredSecurityTestRequest,
} from './ScopedScanTypes';
import {
    listPresentFocusedRequestContextFields,
    normalizeFocusedCaseFamily,
    normalizeFocusedEvidenceReasoningEffect,
    normalizeFocusedHypothesisStatus,
    normalizeFocusedSuspicionProofStatus,
} from './ScopedScanTypes';
import { focusedReasoningTraceService } from './FocusedReasoningTraceService';
import { resolveFocusedCaseFamily } from './FocusedSignalInterpreter';

interface FocusedReasoningVisibilityDependencies {
    traceService: typeof focusedReasoningTraceService;
}

export class FocusedReasoningVisibilityService {
    private readonly deps: FocusedReasoningVisibilityDependencies;

    constructor(
        deps: Partial<FocusedReasoningVisibilityDependencies> = {},
    ) {
        this.deps = {
            traceService: focusedReasoningTraceService,
            ...deps,
        };
    }

    public buildScanAgentTrace(scanId: string, limit = 60): FocusedReasoningTraceEntry[] {
        return this.deps.traceService.listByScan(scanId, limit);
    }

    public buildScanContextInfluenceSummary(scanId: string): FocusedContextInfluenceSummary | null {
        const request = getScopedTestRequest(scanId);
        if (!request) {
            return null;
        }
        return this.buildContextInfluenceSummaryFromTrace(
            request,
            this.deps.traceService.listByScan(scanId, 400),
        );
    }

    public decorateCases(scanId: string, cases: FocusedTestCase[]): FocusedTestCase[] {
        return cases.map((testCase) => {
            const visibility = this.buildCaseVisibility(scanId, testCase.id);
            return {
                ...testCase,
                hypothesisVisibility: visibility.hypothesisVisibility,
                suspicionExplanation: visibility.suspicionExplanation,
                latestReasoningTracePreview: visibility.reasoningTrace.slice(-3),
            };
        });
    }

    public buildScanStorySummary(scanId: string, cases: FocusedTestCase[]): FocusedStorySummary {
        const decoratedCases = this.decorateCases(scanId, cases);
        const caseStories = decoratedCases.map((testCase) => this.buildCaseStorySummary(testCase));
        const suspiciousCaseCount = caseStories.filter((entry) => entry.suspiciousness === 'high' || entry.suspiciousness === 'moderate').length;
        const blockedCaseCount = caseStories.filter((entry) => entry.blockedBy.length > 0).length;
        const provisionalFindingCount = decoratedCases.filter((entry) => (entry.activeFindingThread?.status || '') !== 'published' && (entry.activeFindingThread?.suspicionScore || 0) >= 45).length;

        return {
            headline: [
                `${suspiciousCaseCount} suspicious case${suspiciousCaseCount === 1 ? '' : 's'}`,
                `${blockedCaseCount} blocked or uncertain`,
                `${decoratedCases.length} total bounded case${decoratedCases.length === 1 ? '' : 's'}`,
            ].join(' • '),
            suspiciousCaseCount,
            blockedCaseCount,
            provisionalFindingCount,
            currentBeliefs: uniqueStrings(caseStories.map((entry) => entry.currentBelief)).slice(0, 6),
            unresolvedQuestions: uniqueStrings(caseStories.flatMap((entry) => entry.blockedBy)).slice(0, 6),
            recommendedNextSteps: uniqueStrings(caseStories.map((entry) => entry.nextStep)).slice(0, 6),
            cases: caseStories
                .sort((left, right) => {
                    const rank = { high: 0, moderate: 1, low: 2, none: 3 } as const;
                    if (rank[left.suspiciousness] !== rank[right.suspiciousness]) {
                        return rank[left.suspiciousness] - rank[right.suspiciousness];
                    }
                    if (left.blockedBy.length !== right.blockedBy.length) {
                        return right.blockedBy.length - left.blockedBy.length;
                    }
                    return left.title.localeCompare(right.title);
                })
                .slice(0, 8),
        };
    }

    public buildCaseVisibility(scanId: string, caseId: string, executionId?: string | null): {
        reasoningTrace: FocusedReasoningTraceEntry[];
        hypothesisVisibility: FocusedHypothesisVisibility | null;
        suspicionExplanation: FocusedSuspicionExplanation | null;
        contextInfluenceSummary: FocusedContextInfluenceSummary | null;
        evidenceReasoningLinks: FocusedEvidenceReasoningLink[];
    } {
        const testCase = getFocusedTestCaseById(scanId, caseId);
        const objective = getFocusedTestObjective(scanId);
        if (!testCase) {
            return {
                reasoningTrace: [],
                hypothesisVisibility: null,
                suspicionExplanation: null,
                contextInfluenceSummary: this.buildScanContextInfluenceSummary(scanId),
                evidenceReasoningLinks: [],
            };
        }

        const trace = executionId
            ? this.deps.traceService.listByExecution(scanId, caseId, executionId)
            : this.deps.traceService.listByCase(scanId, caseId);
        const verdict = executionId
            ? getFocusedCaseVerdictByExecution(scanId, caseId, executionId)
            : getLatestFocusedCaseVerdictByCase(scanId, caseId);
        const evidenceBundles = executionId
            ? listEvidenceBundlesByExecution(scanId, caseId, executionId)
            : listEvidenceBundlesByCase(scanId, caseId);
        const investigationIssues = executionId
            ? listFocusedInvestigationIssuesByExecution(scanId, caseId, executionId)
            : listFocusedInvestigationIssuesByCase(scanId, caseId);
        const caseFamily = verdict?.interpretationSummary.caseFamily
            || (objective ? resolveFocusedCaseFamily(objective, testCase) : 'generic');
        const hypothesisVisibility = this.buildHypothesisVisibility({
            testCase,
            caseFamily,
            reasoningTrace: trace,
            verdictInterpretation: verdict?.interpretationSummary || null,
            investigationIssues,
            verdictReason: verdict?.verdictReason || null,
        });
        const suspicionExplanation = this.buildSuspicionExplanation({
            testCase,
            caseFamily,
            reasoningTrace: trace,
            verdictInterpretation: verdict?.interpretationSummary || null,
            supportProvenance: verdict?.supportProvenance || null,
            requestEvidenceStory: verdict?.requestEvidenceStory || null,
            evidenceMissing: verdict
                ? [...verdict.evidenceSufficiency.missingRequirements, ...verdict.evidenceSufficiency.unsupportedRequirements]
                : [],
            sufficiencyState: verdict?.evidenceSufficiency.state || null,
            verdictState: verdict?.verdictState || null,
            verdictReason: verdict?.verdictReason || null,
            blockingReasons: [
                ...(verdict?.scopeViolationImpact.reasons || []),
                ...investigationIssues
                    .filter((issue) => issue.impact === 'blocking' || issue.issueStatus === 'unresolved')
                    .map((issue) => issue.issueTitle),
            ],
        });
        const contextInfluenceSummary = this.buildContextInfluenceSummaryFromTrace(
            getScopedTestRequest(scanId),
            trace,
        );
        const evidenceReasoningLinks = this.buildEvidenceReasoningLinks({
            evidenceBundles,
            reasoningTrace: trace,
            verdictInterpretation: verdict?.interpretationSummary || null,
            verdictEvidenceRefs: verdict?.supportingEvidenceRefs || [],
            sufficiencyState: verdict?.evidenceSufficiency.state || null,
        });

        return {
            reasoningTrace: trace,
            hypothesisVisibility,
            suspicionExplanation,
            contextInfluenceSummary,
            evidenceReasoningLinks,
        };
    }

    private buildHypothesisVisibility(input: {
        testCase: FocusedTestCase;
        caseFamily: FocusedCaseFamily;
        reasoningTrace: FocusedReasoningTraceEntry[];
        verdictInterpretation: FocusedSignalInterpretationSummary | null;
        investigationIssues: FocusedInvestigationIssue[];
        verdictReason: string | null;
    }): FocusedHypothesisVisibility {
        const initialSupport = uniqueStrings([
            ...input.reasoningTrace
                .filter((entry) => entry.stage === 'planning' || entry.entryType === 'hypothesis')
                .flatMap((entry) => [entry.hypothesisRationaleSummary, entry.observationSummary, entry.summary]),
            input.testCase.plannerRationaleSummary,
        ]).slice(0, 5);
        const strengtheningSignals = uniqueStrings([
            ...(input.verdictInterpretation?.suspiciousSignals || []),
            ...(input.verdictInterpretation?.failSignals || []),
            ...input.reasoningTrace
                .map((entry) => entry.confidenceShiftSummary)
                .filter((entry): entry is string => !!entry)
                .filter((entry) => /increase|strong|strength|support|confidence/i.test(entry)),
        ]).slice(0, 6);
        const weakeningSignals = uniqueStrings([
            ...(input.verdictInterpretation?.contradictorySignals || []),
            ...input.reasoningTrace
                .map((entry) => entry.confidenceShiftSummary)
                .filter((entry): entry is string => !!entry)
                .filter((entry) => /weak|downgrad|reduce|lower|stabil|contradict|undermin/i.test(entry)),
        ]).slice(0, 6);
        const blockingConstraints = uniqueStrings([
            ...input.reasoningTrace
                .map((entry) => entry.stopRetryBlockRationale)
                .filter((entry): entry is string => !!entry),
            ...input.investigationIssues
                .filter((issue) => issue.impact === 'blocking' || issue.issueStatus === 'unresolved')
                .map((issue) => issue.issueTitle),
        ]).slice(0, 6);

        const currentStatus = normalizeFocusedHypothesisStatus(this.resolveHypothesisStatus({
            strengtheningSignals,
            weakeningSignals,
            blockingConstraints,
            contradictorySignals: input.verdictInterpretation?.contradictorySignals || [],
        }));
        const latestConfidenceSummary = input.reasoningTrace
            .slice()
            .reverse()
            .map((entry) => entry.confidenceShiftSummary)
            .find((entry): entry is string => !!entry)
            || input.verdictReason
            || input.verdictInterpretation?.summary
            || null;

        return {
            caseFamily: normalizeFocusedCaseFamily(input.caseFamily),
            initialSupport,
            strengtheningSignals,
            weakeningSignals,
            blockingConstraints,
            currentStatus,
            latestConfidenceSummary,
        };
    }

    private buildSuspicionExplanation(input: {
        testCase: FocusedTestCase;
        caseFamily: FocusedCaseFamily;
        reasoningTrace: FocusedReasoningTraceEntry[];
        verdictInterpretation: FocusedSignalInterpretationSummary | null;
        supportProvenance: FocusedSupportProvenanceSummary | null;
        requestEvidenceStory: FocusedRequestEvidenceStory | null;
        evidenceMissing: string[];
        sufficiencyState: string | null;
        verdictState: string | null;
        verdictReason: string | null;
        blockingReasons: string[];
    }): FocusedSuspicionExplanation {
        const supportingSignals = uniqueStrings([
            ...(input.verdictInterpretation?.suspiciousSignals || []),
            ...(input.verdictInterpretation?.failSignals || []),
            ...(input.verdictInterpretation?.reviewSignals || []),
            ...input.reasoningTrace
                .flatMap((entry) => [entry.requestResponseImpactSummary, entry.browserStateImpactSummary])
                .filter((entry): entry is string => !!entry),
        ]).slice(0, 6);
        const weakeningSignals = uniqueStrings([
            ...(input.verdictInterpretation?.passSignals || []),
            ...(input.verdictInterpretation?.controlSignals || []),
            ...input.reasoningTrace
                .map((entry) => entry.confidenceShiftSummary)
                .filter((entry): entry is string => !!entry)
                .filter((entry) => /weak|downgrad|reduce|lower|stabil|held|rejected/i.test(entry)),
        ]).slice(0, 6);
        const contradictorySignals = uniqueStrings(input.verdictInterpretation?.contradictorySignals || []).slice(0, 4);
        const boundedStopReason = input.reasoningTrace
            .slice()
            .reverse()
            .map((entry) => entry.stopRetryBlockRationale)
            .find((entry): entry is string => !!entry)
            || input.blockingReasons[0]
            || input.verdictInterpretation?.followUpDecisionSummary
            || null;
        const whySuspicious = input.requestEvidenceStory?.summary
            || input.verdictInterpretation?.summary
            || supportingSignals[0]
            || weakeningSignals[0]
            || input.verdictReason
            || `No strong ${String(input.caseFamily).replace(/_/g, ' ')} suspiciousness signal was persisted for this bounded case.`;
        const proofStatus = normalizeFocusedSuspicionProofStatus(this.resolveProofStatus({
            contradictorySignals,
            boundedStopReason,
            sufficiencyState: input.sufficiencyState,
            verdictState: input.verdictState,
            supportingSignals,
        }));

        return {
            caseFamily: normalizeFocusedCaseFamily(input.caseFamily),
            suspiciousness: input.verdictInterpretation?.suspiciousness || 'none',
            whySuspicious,
            supportingSignals,
            weakeningSignals,
            contradictorySignals,
            proofStatus,
            boundedStopReason,
            missingEvidence: uniqueStrings([
                ...input.evidenceMissing,
                ...(input.verdictInterpretation?.uncertaintyReasons || []),
                input.supportProvenance?.lowConfidenceReason || null,
                input.requestEvidenceStory?.lowConfidenceReason || null,
            ]).slice(0, 8),
        };
    }

    private buildCaseStorySummary(testCase: FocusedTestCase): FocusedStoryCaseSummary {
        const suspicion = testCase.suspicionExplanation;
        const interpretation = testCase.latestVerdict?.interpretationSummary || null;
        return {
            caseId: testCase.id,
            title: testCase.title,
            targetLabel: formatFocusedTargetLabel(testCase),
            caseFamily: interpretation?.caseFamily || testCase.caseFamily || 'generic',
            suspiciousness: suspicion?.suspiciousness || interpretation?.suspiciousness || 'none',
            currentBelief: suspicion?.whySuspicious
                || testCase.primaryFinding?.strongestSupportSummary
                || testCase.hypothesisVisibility?.latestConfidenceSummary
                || testCase.plannerRationaleSummary,
            whatWasTested: testCase.caseIntelligence?.selectionSummary
                || `${testCase.title} stayed anchored to ${formatFocusedTargetLabel(testCase)}.`,
            whatWasObserved: testCase.executionNotesSummary
                || interpretation?.summary
                || testCase.primaryFinding?.strongestSupportSummary
                || 'Execution has not yet produced a material observation.',
            whyItMatters: testCase.caseIntelligence?.securityConcerns?.[0]?.whyRelevant
                || testCase.plannerRationaleSummary,
            targetedInputs: (testCase.caseIntelligence?.candidateInputs || [])
                .map((entry) => `${entry.location}:${entry.name}`)
                .slice(0, 4),
            blockedBy: uniqueStrings([
                ...(suspicion?.missingEvidence || []),
                testCase.confirmationState?.stopReason || null,
                testCase.activeFindingThread?.stopReason || null,
                testCase.investigationSummary?.latestIssueTitle || null,
            ]).slice(0, 4),
            nextStep: testCase.activeFindingThread?.nextStepSummary
                || testCase.confirmationState?.nextStepSummary
                || testCase.primaryFinding?.nextStepSummary
                || suspicion?.boundedStopReason
                || null,
        };
    }

    private buildContextInfluenceSummaryFromTrace(
        request: StructuredSecurityTestRequest | null | undefined,
        trace: FocusedReasoningTraceEntry[],
    ): FocusedContextInfluenceSummary | null {
        if (!request) {
            return null;
        }

        const presentFields = listPresentFocusedRequestContextFields(request);
        const aggregate = new Map<string, FocusedReasoningContextInfluence>();

        for (const entry of trace) {
            for (const influence of entry.contextInfluence || []) {
                const key = `${influence.field}:${influence.effect}:${influence.summary}`;
                if (!aggregate.has(key)) {
                    aggregate.set(key, influence);
                }
            }
            for (const field of entry.linkedRequestContextKeys || []) {
                const key = `${field}:used:${entry.stage}:${entry.summary}`;
                if (!aggregate.has(key)) {
                    aggregate.set(key, {
                        field,
                        effect: 'used',
                        summary: `Referenced during ${entry.stage.replace(/_/g, ' ')}: ${entry.summary}`,
                    });
                }
            }
        }

        const usedFields = [...aggregate.values()].filter((entry) => entry.effect === 'used');
        const insufficientFields = [...aggregate.values()].filter((entry) => entry.effect === 'insufficient');
        const touched = new Set<FocusedRequestContextField>([
            ...usedFields.map((entry) => entry.field),
            ...insufficientFields.map((entry) => entry.field),
        ]);
        const ignoredFields = presentFields
            .filter((field) => !touched.has(field))
            .map((field) => ({
                field,
                effect: 'ignored' as const,
                summary: 'Present in the structured request but not referenced by the persisted bounded reasoning steps.',
            }));

        return {
            presentFields,
            usedFields,
            ignoredFields,
            insufficientFields,
            summary: buildContextSummaryText(presentFields, usedFields, ignoredFields, insufficientFields),
        };
    }

    private buildEvidenceReasoningLinks(input: {
        evidenceBundles: EvidenceBundle[];
        reasoningTrace: FocusedReasoningTraceEntry[];
        verdictInterpretation: FocusedSignalInterpretationSummary | null;
        verdictEvidenceRefs: Array<{ evidenceId: string; role: FocusedEvidenceReasoningLink['role']; summary: string }>;
        sufficiencyState: string | null;
    }): FocusedEvidenceReasoningLink[] {
        return input.evidenceBundles.map((bundle) => {
            const linkedEntries = input.reasoningTrace.filter((entry) => entry.linkedEvidenceIds.includes(bundle.id));
            const verdictRef = input.verdictEvidenceRefs.find((entry) => entry.evidenceId === bundle.id);
            const whyItMatters = linkedEntries
                .flatMap((entry) => [
                    entry.requestResponseImpactSummary,
                    entry.browserStateImpactSummary,
                    entry.confidenceShiftSummary,
                    entry.observationSummary,
                ])
                .find((entry): entry is string => !!entry)
                || verdictRef?.summary
                || bundle.responseDiffSummary?.summary
                || bundle.browserState?.actionSummary
                || bundle.scopeViolation?.reason
                || bundle.summary;
            const effect = normalizeFocusedEvidenceReasoningEffect(this.resolveEvidenceEffect({
                bundle,
                linkedEntries,
                verdictInterpretation: input.verdictInterpretation,
                verdictRefPresent: !!verdictRef,
                sufficiencyState: input.sufficiencyState,
            }));

            return {
                evidenceId: bundle.id,
                role: verdictRef?.role || mapEvidenceRole(bundle),
                whyItMatters,
                effect,
                reasoningEntryIds: linkedEntries.map((entry) => entry.id),
            };
        });
    }

    private resolveHypothesisStatus(input: {
        strengtheningSignals: string[];
        weakeningSignals: string[];
        blockingConstraints: string[];
        contradictorySignals: string[];
    }): FocusedHypothesisStatus {
        if (input.contradictorySignals.length > 0) {
            return 'contradicted';
        }
        if (input.strengtheningSignals.length > 0 && input.weakeningSignals.length === 0) {
            return 'strengthened';
        }
        if (input.weakeningSignals.length > 0 && input.strengtheningSignals.length === 0) {
            return 'weakened';
        }
        if (input.blockingConstraints.length > 0 && input.strengtheningSignals.length === 0) {
            return 'stalled';
        }
        return 'plausible';
    }

    private resolveProofStatus(input: {
        contradictorySignals: string[];
        boundedStopReason: string | null;
        sufficiencyState: string | null;
        verdictState: string | null;
        supportingSignals: string[];
    }): FocusedSuspicionProofStatus {
        if (input.contradictorySignals.length > 0 || input.sufficiencyState === 'contradictory') {
            return 'contradictory';
        }
        if (
            input.boundedStopReason
            && (input.sufficiencyState === 'insufficient' || input.verdictState === 'inconclusive' || input.verdictState === 'needs_review')
        ) {
            return 'blocked';
        }
        if (
            (input.verdictState === 'fail' || input.sufficiencyState === 'sufficient')
            && input.supportingSignals.length > 0
        ) {
            return 'supported';
        }
        return 'weak';
    }

    private resolveEvidenceEffect(input: {
        bundle: EvidenceBundle;
        linkedEntries: FocusedReasoningTraceEntry[];
        verdictInterpretation: FocusedSignalInterpretationSummary | null;
        verdictRefPresent: boolean;
        sufficiencyState: string | null;
    }): FocusedEvidenceReasoningEffect {
        if (input.bundle.scopeViolation || input.bundle.source === 'scope_guard') {
            return 'bounds';
        }
        if (
            input.sufficiencyState === 'contradictory'
            || input.linkedEntries.some((entry) => /contradict/i.test(entry.confidenceShiftSummary || ''))
            || (input.verdictInterpretation?.contradictorySignals.length || 0) > 0
        ) {
            return 'contradicts';
        }
        if (
            input.linkedEntries.some((entry) => /weak|downgrad|reduce|lower/i.test(entry.confidenceShiftSummary || ''))
            || input.bundle.source === 'execution_note'
        ) {
            return 'weakens';
        }
        if (input.verdictRefPresent || input.linkedEntries.length > 0) {
            return 'supports';
        }
        return 'supports';
    }
}

function mapEvidenceRole(bundle: EvidenceBundle): FocusedEvidenceReasoningLink['role'] {
    switch (bundle.source) {
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

function uniqueStrings(values: Array<string | null | undefined>): string[] {
    return [...new Set(values.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0).map((entry) => entry.trim()))];
}

function buildContextSummaryText(
    presentFields: FocusedRequestContextField[],
    usedFields: FocusedReasoningContextInfluence[],
    ignoredFields: FocusedReasoningContextInfluence[],
    insufficientFields: FocusedReasoningContextInfluence[],
): string {
    if (presentFields.length === 0) {
        return 'No optional request context was provided for the scoped run.';
    }
    const parts = [
        usedFields.length > 0 ? `${usedFields.length} request context field(s) influenced bounded reasoning.` : null,
        insufficientFields.length > 0 ? `${insufficientFields.length} field(s) were present but still insufficient for stronger bounded decisions.` : null,
        ignoredFields.length > 0 ? `${ignoredFields.length} field(s) were carried through intake without a persisted downstream use.` : null,
    ].filter((entry): entry is string => !!entry);

    return parts.join(' ') || 'Optional request context was provided, but no persisted reasoning link was recorded.';
}

function formatFocusedTargetLabel(testCase: Pick<FocusedTestCase, 'title' | 'targetArtifact'>): string {
    return [
        testCase.targetArtifact.method?.toUpperCase(),
        testCase.targetArtifact.path || testCase.targetArtifact.label || testCase.targetArtifact.url || testCase.title,
    ].filter(Boolean).join(' ');
}

export const focusedReasoningVisibilityService = new FocusedReasoningVisibilityService();
