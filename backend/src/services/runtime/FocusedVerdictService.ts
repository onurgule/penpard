import { v4 as uuidv4 } from 'uuid';
import { Database as DatabaseType } from 'better-sqlite3';
import {
    db,
    getFocusedTestObjective,
    getLatestFocusedTestCaseExecution,
    getScan,
    getScopeEnvelope,
    listEvidenceBundlesByExecution,
    listFocusedTestCasesByScan,
    upsertFocusedCaseVerdict,
    upsertFocusedScanVerdictSummary,
} from '../../db/init';
import { logger } from '../../utils/logger';
import {
    focusedInvestigationService,
    type FocusedInvestigationService,
} from './FocusedInvestigationService';
import {
    focusedHistoricalCompareService,
    type FocusedHistoricalCompareService,
} from './FocusedHistoricalCompareService';
import {
    focusedFindingService,
    type FocusedFindingService,
} from './FocusedFindingService';
import { focusedReasoningTraceService } from './FocusedReasoningTraceService';
import {
    focusedVerdictAssistanceProfileResolver,
    type FocusedVerdictAssistanceProfile,
    type FocusedVerdictAssistanceProfileResolver,
} from './FocusedVerdictProfiles';
import { interpretFocusedSignals } from './FocusedSignalInterpreter';
import type {
    EvidenceBundle,
    FocusedCaseVerdict,
    FocusedEvidenceRequirementEvaluation,
    FocusedRequestEvidenceRef,
    FocusedRequestEvidenceStory,
    FocusedEvidenceSufficiencyReport,
    FocusedCaseFinding,
    FocusedScanFindingSummary,
    FocusedSignalInterpretationSummary,
    FocusedScanVerdictSummary,
    FocusedSupportProvenanceSummary,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedTestObjective,
    FocusedVerdictEvidenceRef,
    FocusedVerdictScopeViolationImpact,
    FocusedVerdictState,
    ScopeEnvelope,
} from './ScopedScanTypes';
import {
    createEmptyFocusedVerdictCounts,
    normalizeScanMode,
} from './ScopedScanTypes';

interface VerdictDependencies {
    database: DatabaseType;
    profileResolver: FocusedVerdictAssistanceProfileResolver;
    investigationService: Pick<FocusedInvestigationService, 'recordVerdictObservations' | 'summarizeScanBlockers'>;
    historicalCompareService: Pick<FocusedHistoricalCompareService, 'ensureGenerated'>;
    findingService: Pick<FocusedFindingService, 'generateNow'>;
    now: () => string;
    createId: () => string;
}

interface RequirementSupportResult {
    supported: boolean;
    satisfied: boolean;
    supportingEvidenceIds: string[];
    note?: string;
}

interface EvaluatedSignals {
    passSignals: string[];
    failSignals: string[];
    contradictorySignals: string[];
}

interface EvaluatedEvidenceContext {
    sufficiency: FocusedEvidenceSufficiencyReport;
    supportingEvidenceRefs: FocusedVerdictEvidenceRef[];
    supportProvenance: FocusedSupportProvenanceSummary | null;
    requestEvidenceStory: FocusedRequestEvidenceStory | null;
    scopeViolationImpact: FocusedVerdictScopeViolationImpact;
    interpretationSummary: FocusedSignalInterpretationSummary;
    signals: EvaluatedSignals;
}

export class FocusedVerdictService {
    private readonly deps: VerdictDependencies;

    constructor(
        deps: Partial<VerdictDependencies> = {},
    ) {
        this.deps = {
            database: db,
            profileResolver: focusedVerdictAssistanceProfileResolver,
            investigationService: focusedInvestigationService,
            historicalCompareService: focusedHistoricalCompareService,
            findingService: focusedFindingService,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public async generateNow(scanId: string, userId?: number): Promise<{
        scanId: string;
        caseVerdicts: FocusedCaseVerdict[];
        focusedVerdictSummary: FocusedScanVerdictSummary;
        focusedFindings: FocusedCaseFinding[];
        focusedFindingSummary: FocusedScanFindingSummary | null;
    }> {
        const scan = getScan(scanId);
        if (!scan) {
            throw new Error(`Focused verdict generation could not find scan ${scanId}.`);
        }
        if (normalizeScanMode(scan.scan_mode) !== 'scoped') {
            throw new Error('Focused verdict generation is only available for scoped scans.');
        }

        const objective = getFocusedTestObjective(scanId);
        const scopeEnvelope = getScopeEnvelope(scanId);
        if (!objective || !scopeEnvelope) {
            throw new Error('Focused verdict generation requires a persisted objective and scope envelope.');
        }

        const assistanceProfile = this.deps.profileResolver.resolve(userId ?? scan.user_id);
        const cases = listFocusedTestCasesByScan(scanId);
        const caseVerdicts: FocusedCaseVerdict[] = [];

        for (const testCase of cases) {
            const execution = getLatestFocusedTestCaseExecution(scanId, testCase.id);
            if (!execution) {
                continue;
            }

            const evidenceBundles = listEvidenceBundlesByExecution(scanId, testCase.id, execution.id);
            try {
                const verdict = await this.evaluateCase({
                    objective,
                    scopeEnvelope,
                    testCase,
                    execution,
                    evidenceBundles,
                    profile: assistanceProfile,
                    userId: userId ?? scan.user_id,
                });
                const saved = upsertFocusedCaseVerdict(verdict) || verdict;
                await this.deps.investigationService.recordVerdictObservations({
                    scanId,
                    caseId: testCase.id,
                    executionId: execution.id,
                    objectiveId: testCase.objectiveId,
                    userId: userId ?? scan.user_id,
                    verdict: saved,
                    observations: this.buildVerdictInvestigationObservations(testCase, execution, evidenceBundles, saved),
                });
                this.recordVerdictReasoning(objective, testCase, saved);
                caseVerdicts.push(saved);
            } catch (error: any) {
                logger.warn('Focused verdict generation degraded to fallback case verdict', {
                    scanId,
                    caseId: testCase.id,
                    executionId: execution.id,
                    error: error.message,
                });
                const fallbackVerdict = this.buildFallbackVerdict({
                    objective,
                    testCase,
                    execution,
                    evidenceBundles,
                    errorMessage: error.message,
                });
                const saved = upsertFocusedCaseVerdict(fallbackVerdict) || fallbackVerdict;
                await this.deps.investigationService.recordVerdictObservations({
                    scanId,
                    caseId: testCase.id,
                    executionId: execution.id,
                    objectiveId: testCase.objectiveId,
                    userId: userId ?? scan.user_id,
                    verdict: saved,
                    observations: this.buildVerdictInvestigationObservations(testCase, execution, evidenceBundles, saved),
                });
                this.recordVerdictReasoning(objective, testCase, saved);
                caseVerdicts.push(saved);
            }
        }

        const blockerSummary = await this.deps.investigationService.summarizeScanBlockers(scanId, userId ?? scan.user_id);
        const summary = this.buildSummary(scanId, objective.id, cases.length, caseVerdicts, blockerSummary);
        const savedSummary = upsertFocusedScanVerdictSummary(summary) || summary;
        const findingResult = await this.deps.findingService.generateNow(scanId);
        await this.deps.historicalCompareService.ensureGenerated(scanId, userId ?? scan.user_id);

        return {
            scanId,
            caseVerdicts,
            focusedVerdictSummary: savedSummary,
            focusedFindings: findingResult.focusedFindings,
            focusedFindingSummary: findingResult.focusedFindingSummary,
        };
    }

    private async evaluateCase(input: {
        objective: FocusedTestObjective;
        scopeEnvelope: ScopeEnvelope;
        testCase: FocusedTestCase;
        execution: FocusedTestCaseExecution;
        evidenceBundles: EvidenceBundle[];
        profile: FocusedVerdictAssistanceProfile;
        userId?: number;
    }): Promise<FocusedCaseVerdict> {
        const evaluatedEvidence = this.evaluateEvidence(input.objective, input.testCase, input.execution, input.evidenceBundles);
        const verdictState = this.determineVerdictState(input.execution, evaluatedEvidence);
        const verdictReason = this.buildVerdictReason(input.testCase, input.execution, evaluatedEvidence, verdictState);
        const verdictAt = this.deps.now();
        const narrative = await input.profile.explainVerdict({
            scanId: input.testCase.scanId,
            userId: input.userId,
            objective: input.objective,
            scopeEnvelope: input.scopeEnvelope,
            testCase: input.testCase,
            execution: input.execution,
            evidenceBundles: input.evidenceBundles,
            verdictState,
            verdictReason,
            evidenceSufficiency: evaluatedEvidence.sufficiency,
            interpretationSummary: evaluatedEvidence.interpretationSummary,
            supportingEvidenceRefs: evaluatedEvidence.supportingEvidenceRefs,
            scopeViolationImpact: evaluatedEvidence.scopeViolationImpact,
        });

        return {
            id: this.deps.createId(),
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            executionId: input.execution.id,
            objectiveId: input.testCase.objectiveId,
            verdictState,
            verdictReason,
            evidenceSufficiency: evaluatedEvidence.sufficiency,
            interpretationSummary: evaluatedEvidence.interpretationSummary,
            supportingEvidenceRefs: evaluatedEvidence.supportingEvidenceRefs,
            supportProvenance: evaluatedEvidence.supportProvenance,
            requestEvidenceStory: evaluatedEvidence.requestEvidenceStory,
            scopeViolationImpact: evaluatedEvidence.scopeViolationImpact,
            executionSnapshot: this.buildExecutionSnapshot(input.execution),
            assistanceProfileKey: narrative ? input.profile.key : null,
            assistanceProvider: narrative ? input.profile.provider : null,
            assistanceModel: narrative ? input.profile.model : null,
            assistanceNarrative: narrative,
            verdictAt,
        };
    }

    private buildFallbackVerdict(input: {
        objective: FocusedTestObjective;
        testCase: FocusedTestCase;
        execution: FocusedTestCaseExecution;
        evidenceBundles: EvidenceBundle[];
        errorMessage: string;
    }): FocusedCaseVerdict {
        const scopeViolationImpact = this.buildScopeViolationImpact(input.execution, input.evidenceBundles);
        const supportingEvidenceRefs = this.buildSupportingEvidenceRefs(input.evidenceBundles);
        const sufficiency: FocusedEvidenceSufficiencyReport = {
            state: 'insufficient',
            summary: 'Verdict generation degraded before the evidence could be fully evaluated.',
            anchoredToTarget: false,
            anchoredMethod: null,
            anchoredPath: null,
            supportingEvidenceIds: supportingEvidenceRefs.map((entry) => entry.evidenceId),
            missingRequirements: input.testCase.requiredEvidence.map((entry) => entry.kind),
            unsupportedRequirements: [],
            contradictorySignals: [],
            underminedByScopeViolation: scopeViolationImpact.underminesConfidence,
            requirementEvaluations: [],
        };

        return {
            id: this.deps.createId(),
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            executionId: input.execution.id,
            objectiveId: input.objective.id,
            verdictState: input.execution.executionState === 'failed_to_execute' ? 'inconclusive' : 'needs_review',
            verdictReason: `Verdict generation degraded: ${input.errorMessage}`.slice(0, 320),
            evidenceSufficiency: sufficiency,
            interpretationSummary: {
                caseFamily: 'generic',
                suspiciousness: 'none',
                summary: 'Case-aware interpretation was unavailable because verdict generation degraded.',
                suspiciousSignals: [],
                passSignals: [],
                failSignals: [],
                reviewSignals: [],
                contradictorySignals: [],
                controlSignals: [],
                keywordSignals: [],
                signalMarkers: [],
                parameterHints: [],
                scoreDelta: 0,
                strongestSupport: null,
                strongestBlocker: null,
                missingEvidence: [],
                uncertaintyReasons: [],
                nextStepSummary: null,
                followUpDecisionSummary: null,
                confirmationReadiness: 'not_ready',
                recommendedConfirmationKinds: [],
            },
            supportingEvidenceRefs,
            supportProvenance: null,
            requestEvidenceStory: null,
            scopeViolationImpact,
            executionSnapshot: this.buildExecutionSnapshot(input.execution),
            assistanceProfileKey: null,
            assistanceProvider: null,
            assistanceModel: null,
            assistanceNarrative: null,
            verdictAt: this.deps.now(),
        };
    }

    private recordVerdictReasoning(
        objective: FocusedTestObjective,
        testCase: FocusedTestCase,
        verdict: FocusedCaseVerdict,
    ): void {
        const blockingReason = verdict.verdictState === 'needs_review' || verdict.verdictState === 'inconclusive'
            ? [
                verdict.evidenceSufficiency.missingRequirements.length > 0
                    ? `Missing evidence: ${verdict.evidenceSufficiency.missingRequirements.join(', ')}`
                    : null,
                verdict.scopeViolationImpact.reasons[0] || null,
            ].filter((entry): entry is string => !!entry)[0] || null
            : null;

        focusedReasoningTraceService.record({
            scanId: verdict.scanId,
            objectiveId: objective.id,
            caseId: verdict.caseId,
            executionId: verdict.executionId,
            stage: 'verdict',
            entryType: blockingReason ? 'constraint' : 'result',
            rail: verdict.supportProvenance?.rail === 'request'
                || verdict.supportProvenance?.rail === 'browser'
                || verdict.supportProvenance?.rail === 'hybrid'
                ? verdict.supportProvenance.rail
                : 'system_only',
            caseFamily: verdict.interpretationSummary.caseFamily,
            summary: verdict.verdictReason,
            observationSummary: [
                verdict.evidenceSufficiency.summary,
                verdict.supportProvenance?.summary || null,
            ].filter((entry): entry is string => !!entry).join(' | '),
            actionSelectionRationale: verdict.assistanceNarrative || verdict.interpretationSummary.summary || null,
            confidenceShiftSummary: [
                `Suspiciousness ${verdict.interpretationSummary.suspiciousness}.`,
                verdict.interpretationSummary.summary,
                verdict.requestEvidenceStory?.summary || null,
            ].filter(Boolean).join(' '),
            stopRetryBlockRationale: blockingReason,
            linkedEvidenceIds: verdict.supportingEvidenceRefs.map((entry) => entry.evidenceId),
        });
    }

    private evaluateEvidence(
        objective: FocusedTestObjective,
        testCase: FocusedTestCase,
        execution: FocusedTestCaseExecution,
        evidenceBundles: EvidenceBundle[],
    ): EvaluatedEvidenceContext {
        const supportingEvidenceRefs = this.buildSupportingEvidenceRefs(evidenceBundles);
        const scopeViolationImpact = this.buildScopeViolationImpact(execution, evidenceBundles);
        const anchoring = this.evaluateAnchoring(testCase, evidenceBundles);
        const interpretationSummary = interpretFocusedSignals({
            objective,
            testCase,
            execution,
            evidenceBundles,
        });
        const requestEvidenceStory = this.buildRequestEvidenceStory(testCase, interpretationSummary.caseFamily, interpretationSummary, evidenceBundles);
        const supportProvenance = this.buildSupportProvenance(testCase, interpretationSummary.caseFamily, evidenceBundles, requestEvidenceStory);
        const signals = {
            passSignals: interpretationSummary.passSignals,
            failSignals: interpretationSummary.failSignals,
            contradictorySignals: interpretationSummary.contradictorySignals,
        };
        const requirementEvaluations = testCase.requiredEvidence.map((requirement) => ({
            kind: requirement.kind,
            description: requirement.description,
            ...this.evaluateRequirement(requirement.kind, evidenceBundles, scopeViolationImpact),
        } satisfies FocusedEvidenceRequirementEvaluation));
        const missingRequirements = requirementEvaluations
            .filter((entry) => entry.supported && !entry.satisfied)
            .map((entry) => entry.kind);
        const unsupportedRequirements = requirementEvaluations
            .filter((entry) => !entry.supported)
            .map((entry) => entry.kind);
        const supportingEvidenceIds = [...new Set([
            ...supportingEvidenceRefs.map((entry) => entry.evidenceId),
            ...requirementEvaluations.flatMap((entry) => entry.supportingEvidenceIds),
        ])];

        let state: FocusedEvidenceSufficiencyReport['state'];
        if (signals.contradictorySignals.length > 0) {
            state = 'contradictory';
        } else if (unsupportedRequirements.length > 0) {
            state = 'unsupported';
        } else if (evidenceBundles.length === 0 || !anchoring.anchoredToTarget || missingRequirements.length > 0) {
            state = 'insufficient';
        } else {
            state = 'sufficient';
        }

        const sufficiency: FocusedEvidenceSufficiencyReport = {
            state,
            summary: this.buildSufficiencySummary({
                state,
                anchoring,
                evidenceCount: evidenceBundles.length,
                missingRequirements,
                unsupportedRequirements,
                contradictorySignals: signals.contradictorySignals,
                scopeViolationImpact,
                interpretationSummary,
            }),
            anchoredToTarget: anchoring.anchoredToTarget,
            anchoredMethod: anchoring.anchoredMethod,
            anchoredPath: anchoring.anchoredPath,
            supportingEvidenceIds,
            missingRequirements,
            unsupportedRequirements,
            contradictorySignals: signals.contradictorySignals,
            underminedByScopeViolation: scopeViolationImpact.underminesConfidence,
            requirementEvaluations,
        };

        return {
            sufficiency,
            supportingEvidenceRefs,
            supportProvenance,
            requestEvidenceStory,
            scopeViolationImpact,
            interpretationSummary,
            signals,
        };
    }

    private determineVerdictState(
        execution: FocusedTestCaseExecution,
        evaluatedEvidence: EvaluatedEvidenceContext,
    ): FocusedVerdictState {
        const { sufficiency, scopeViolationImpact, signals, interpretationSummary, supportProvenance } = evaluatedEvidence;

        switch (execution.executionState) {
            case 'blocked':
            case 'skipped':
            case 'running':
            case 'ready':
                return 'needs_review';
            case 'failed_to_execute':
                return scopeViolationImpact.severity === 'blocking'
                    ? 'needs_review'
                    : 'inconclusive';
            case 'completed':
                break;
            default:
                return 'needs_review';
        }

        if (scopeViolationImpact.underminesConfidence) {
            return 'needs_review';
        }
        if (supportProvenance?.requestHeavy && !supportProvenance.requestBackedEvidence) {
            return 'inconclusive';
        }
        if (sufficiency.state !== 'sufficient') {
            return 'inconclusive';
        }
        if (signals.contradictorySignals.length > 0) {
            return 'inconclusive';
        }
        if (signals.failSignals.length > 0) {
            return 'fail';
        }
        if (signals.passSignals.length > 0) {
            return 'pass';
        }
        if (interpretationSummary.reviewSignals.length > 0) {
            return 'needs_review';
        }

        return 'inconclusive';
    }

    private buildVerdictReason(
        testCase: FocusedTestCase,
        execution: FocusedTestCaseExecution,
        evaluatedEvidence: EvaluatedEvidenceContext,
        verdictState: FocusedVerdictState,
    ): string {
        const { sufficiency, scopeViolationImpact, signals, interpretationSummary, supportProvenance, requestEvidenceStory } = evaluatedEvidence;

        if (supportProvenance?.requestHeavy && !supportProvenance.requestBackedEvidence) {
            return supportProvenance.lowConfidenceReason
                || requestEvidenceStory?.lowConfidenceReason
                || 'No request-backed confirmation was captured; confidence remains low.';
        }

        if (execution.executionState === 'blocked') {
            return execution.notesSummary || 'Execution was blocked by scoped runtime rails and requires review.';
        }
        if (execution.executionState === 'skipped') {
            return execution.notesSummary || 'The case was skipped and does not have an execution-backed final verdict.';
        }
        if (execution.executionState === 'failed_to_execute') {
            if (scopeViolationImpact.severity === 'blocking') {
                return scopeViolationImpact.reasons[0] || execution.errorMessage || 'Execution failed under a blocking scope or budget condition.';
            }
            return execution.errorMessage || execution.notesSummary || 'Execution failed before sufficient evidence could be collected.';
        }
        if (verdictState === 'needs_review' && scopeViolationImpact.underminesConfidence) {
            return scopeViolationImpact.reasons[0] || 'Scope violations undermined confidence in the completed execution.';
        }
        if (verdictState === 'inconclusive' && sufficiency.state === 'unsupported') {
            return `Evidence capture for ${sufficiency.unsupportedRequirements.join(', ')} is not fully supported in Phase 1D.`;
        }
        if (verdictState === 'inconclusive' && sufficiency.state === 'contradictory') {
            return signals.contradictorySignals[0] || 'Persisted evidence contained contradictory control and failure signals.';
        }
        if (verdictState === 'inconclusive' && sufficiency.state !== 'sufficient') {
            return interpretationSummary.reviewSignals[0]
                || `Completed execution did not capture enough required evidence for ${testCase.title}.`;
        }
        if (verdictState === 'fail') {
            const failReason = signals.failSignals[0] || interpretationSummary.summary || 'Completed execution produced a strong evidence-backed failure signal.';
            if (requestEvidenceStory?.confirmationRequestRefs.length) {
                return `Adaptive confirmation replay strengthened the same request-backed hypothesis. ${failReason}`.trim();
            }
            if (supportProvenance?.rail === 'request' || supportProvenance?.rail === 'hybrid') {
                return `Request-backed suspicious signal observed. ${failReason}`.trim();
            }
            return failReason;
        }
        if (verdictState === 'pass') {
            const passReason = signals.passSignals[0] || interpretationSummary.summary || 'Completed execution captured evidence that the expected control held.';
            if (supportProvenance?.requestBackedEvidence) {
                return `Request-backed control contrast held. ${passReason}`.trim();
            }
            return passReason;
        }
        if (verdictState === 'needs_review' && interpretationSummary.reviewSignals.length > 0) {
            return interpretationSummary.reviewSignals[0] || interpretationSummary.summary;
        }
        if (
            verdictState === 'inconclusive'
            && supportProvenance?.requestBackedEvidence
            && !supportProvenance.browserBackedEvidence
            && interpretationSummary.missingEvidence.some((entry) => /browser/i.test(entry))
        ) {
            return 'Browser proof was blocked, but request-backed anomaly remains strong.';
        }

        return execution.notesSummary || 'Operator review is recommended before treating this case as final.';
    }

    private buildSummary(
        scanId: string,
        objectiveId: string,
        totalCases: number,
        caseVerdicts: FocusedCaseVerdict[],
        blockerSummary?: { repeatedBlockers?: string[]; latestMajorBlockerSummary?: string | null; casesNeedingReview?: string[] } | null,
    ): FocusedScanVerdictSummary {
        const countsByVerdict = createEmptyFocusedVerdictCounts();
        let latestVerdictAt: string | null = null;

        for (const verdict of caseVerdicts) {
            countsByVerdict[verdict.verdictState] += 1;
            if (verdict.verdictAt && (!latestVerdictAt || verdict.verdictAt > latestVerdictAt)) {
                latestVerdictAt = verdict.verdictAt;
            }
        }

        const missingVerdictCount = Math.max(totalCases - caseVerdicts.length, 0);
        const majorBlockers = [
            ...(missingVerdictCount > 0 ? [`${missingVerdictCount} focused case(s) do not have a persisted execution verdict yet.`] : []),
            ...(blockerSummary?.latestMajorBlockerSummary ? [blockerSummary.latestMajorBlockerSummary] : []),
            ...((blockerSummary?.repeatedBlockers || []).slice(0, 3)),
            ...caseVerdicts
                .filter((entry) => entry.verdictState === 'needs_review' || entry.verdictState === 'inconclusive')
                .map((entry) => entry.verdictReason),
        ].filter((value, index, values) => value && values.indexOf(value) === index).slice(0, 6);

        const overallVerdict: FocusedVerdictState = countsByVerdict.fail > 0
            ? 'fail'
            : (missingVerdictCount > 0 || countsByVerdict.needs_review > 0)
                ? 'needs_review'
                : countsByVerdict.inconclusive > 0
                    ? 'inconclusive'
                    : countsByVerdict.pass > 0 && countsByVerdict.pass === totalCases
                        ? 'pass'
                        : 'needs_review';

        return {
            scanId,
            objectiveId,
            overallVerdict,
            totalCases,
            countsByVerdict,
            manualReviewRecommended: missingVerdictCount > 0
                || countsByVerdict.needs_review > 0
                || countsByVerdict.inconclusive > 0
                || (blockerSummary?.casesNeedingReview?.length || 0) > 0,
            majorBlockers,
            latestVerdictAt,
        };
    }

    private buildVerdictInvestigationObservations(
        testCase: FocusedTestCase,
        execution: FocusedTestCaseExecution,
        evidenceBundles: EvidenceBundle[],
        verdict: FocusedCaseVerdict,
    ) {
        const linkedEvidenceIds = [...new Set([
            ...verdict.evidenceSufficiency.supportingEvidenceIds,
            ...evidenceBundles.map((bundle) => bundle.id),
        ])];
        const linkedVerdictIds = [verdict.id];
        const baseCorrelation = {
            caseFamily: verdict.interpretationSummary.caseFamily,
            executionState: execution.executionState,
            verdictState: verdict.verdictState,
            evidenceSufficiencyState: verdict.evidenceSufficiency.state,
            evidenceSources: evidenceBundles.map((bundle) => bundle.source),
        };
        const observations: Array<{
            issueType: 'evidence_insufficient' | 'unsupported_verification_primitive' | 'contradictory_signals' | 'scope_violation' | 'environment_instability';
            issueTitle: string;
            issueDetails: string;
            issueStatus: 'unresolved';
            impact: 'degrading' | 'blocking';
            source: 'system';
            linkedEvidenceIds: string[];
            linkedVerdictIds: string[];
            correlation: typeof baseCorrelation;
        }> = [];

        if (verdict.evidenceSufficiency.state === 'insufficient') {
            observations.push({
                issueType: 'evidence_insufficient',
                issueTitle: 'Verdict confidence is limited because required evidence was missing or weak.',
                issueDetails: verdict.evidenceSufficiency.summary,
                issueStatus: 'unresolved',
                impact: verdict.verdictState === 'needs_review' ? 'blocking' : 'degrading',
                source: 'system',
                linkedEvidenceIds,
                linkedVerdictIds,
                correlation: baseCorrelation,
            });
        }

        if (verdict.evidenceSufficiency.state === 'unsupported') {
            observations.push({
                issueType: 'unsupported_verification_primitive',
                issueTitle: 'Verdict confidence is limited because the required verification primitive is not fully supported.',
                issueDetails: verdict.evidenceSufficiency.summary,
                issueStatus: 'unresolved',
                impact: 'degrading',
                source: 'system',
                linkedEvidenceIds,
                linkedVerdictIds,
                correlation: baseCorrelation,
            });
        }

        if (verdict.evidenceSufficiency.state === 'contradictory') {
            observations.push({
                issueType: 'contradictory_signals',
                issueTitle: 'Verdict confidence is blocked by contradictory scoped evidence.',
                issueDetails: verdict.evidenceSufficiency.summary,
                issueStatus: 'unresolved',
                impact: 'blocking',
                source: 'system',
                linkedEvidenceIds,
                linkedVerdictIds,
                correlation: baseCorrelation,
            });
        }

        if (verdict.scopeViolationImpact.hasScopeViolation && verdict.scopeViolationImpact.underminesConfidence) {
            observations.push({
                issueType: 'scope_violation',
                issueTitle: 'Recorded scope violations undermined confidence in the final verdict.',
                issueDetails: verdict.scopeViolationImpact.reasons[0] || verdict.verdictReason,
                issueStatus: 'unresolved',
                impact: verdict.scopeViolationImpact.severity === 'blocking' ? 'blocking' : 'degrading',
                source: 'system',
                linkedEvidenceIds,
                linkedVerdictIds,
                correlation: baseCorrelation,
            });
        }

        if (verdict.verdictState === 'needs_review' && verdict.interpretationSummary.reviewSignals.length > 0) {
            observations.push({
                issueType: 'environment_instability',
                issueTitle: 'Strong suspicious signals require review before this case is treated as a confirmed failure.',
                issueDetails: verdict.interpretationSummary.summary,
                issueStatus: 'unresolved',
                impact: verdict.interpretationSummary.caseFamily === 'sqli' ? 'blocking' : 'degrading',
                source: 'system',
                linkedEvidenceIds,
                linkedVerdictIds,
                correlation: baseCorrelation,
            });
        }

        return observations;
    }

    private isRequestHeavyCase(
        testCase: FocusedTestCase,
        caseFamily: FocusedSignalInterpretationSummary['caseFamily'],
        evidenceBundles: EvidenceBundle[],
    ): boolean {
        const requiredEvidenceKinds = new Set(
            (testCase.requiredEvidence || [])
                .map((entry) => String(entry.kind || '').trim().toLowerCase())
                .filter(Boolean),
        );
        const assertionKinds = (testCase.assertions || [])
            .map((entry) => String(entry.kind || '').trim().toLowerCase())
            .filter(Boolean);
        const requestBackedKinds = new Set([
            'response_diff',
            'status_code',
            'response_excerpt',
            'request_trace',
            'payload_trace',
            'scope_respected',
        ]);

        return testCase.targetArtifact.kind === 'endpoint'
            || testCase.targetArtifact.kind === 'baseline_request'
            || testCase.preferredRail === 'request'
            || caseFamily === 'sqli'
            || caseFamily === 'access_control'
            || caseFamily === 'input_validation'
            || caseFamily === 'error_handling'
            || [...requiredEvidenceKinds].some((kind) => requestBackedKinds.has(kind))
            || assertionKinds.some((kind) => /authz|validation|contract|error|request|payload/.test(kind))
            || evidenceBundles.some((bundle) => !!bundle.requestRef || !!bundle.responseRef || bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay');
    }

    private mapSupportRail(bundle: EvidenceBundle): FocusedSupportProvenanceSummary['rail'] {
        const hasRequest = bundle.source === 'baseline_replay'
            || bundle.source === 'mutated_replay'
            || bundle.source === 'comparison'
            || !!bundle.requestRef
            || !!bundle.responseRef;
        const hasBrowser = bundle.source === 'browser_flow'
            || bundle.source === 'browser_verification'
            || bundle.source === 'screenshot'
            || !!bundle.browserState
            || !!bundle.screenshotRef;

        if (hasRequest && hasBrowser) {
            return 'hybrid';
        }
        if (hasRequest) {
            return 'request';
        }
        if (hasBrowser) {
            return 'browser';
        }
        return 'system_only';
    }

    private buildRequestEvidenceRef(bundle: EvidenceBundle): FocusedRequestEvidenceRef | null {
        if (!bundle.requestRef && !bundle.responseRef) {
            return null;
        }
        return {
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
        };
    }

    private comparisonSupportsHypothesis(
        caseFamily: FocusedSignalInterpretationSummary['caseFamily'],
        diff: NonNullable<EvidenceBundle['responseDiffSummary']>,
    ): boolean {
        const originalStatus = typeof diff.originalStatus === 'number' ? diff.originalStatus : null;
        const mutatedStatus = typeof diff.mutatedStatus === 'number' ? diff.mutatedStatus : null;
        const keywords = (diff.keywordSignals || []).map((entry) => String(entry).split(':')[0]?.trim()).filter(Boolean);
        const hasStrongFailKeyword = keywords.some((entry) => ['FORBIDDEN_BYPASSED', 'PASSWORD_FIELD_EXPOSED', 'EMAIL_DATA_LEAKED', 'SCRIPT_TAG_REFLECTED', 'EVENT_HANDLER_REFLECTED'].includes(entry));
        const hasSqliMarker = keywords.some((entry) => ['SQL_ERROR', 'INTERNAL_ERROR', 'STACK_TRACE_LEAKED'].includes(entry));
        const hasWorkflowKeyword = keywords.some((entry) => ['STATE_MISMATCH', 'STATE_REGRESSION', 'UNEXPECTED_PERSISTENCE', 'MISSING_PERSISTENCE', 'DUPLICATE_SIDE_EFFECT', 'SEQUENCE_OUT_OF_ORDER'].includes(entry));
        const authzBypass = (originalStatus === 401 || originalStatus === 403)
            && mutatedStatus !== null
            && mutatedStatus >= 200
            && mutatedStatus < 400;
        const serverErrorTransition = originalStatus !== null
            && originalStatus >= 200
            && originalStatus < 400
            && mutatedStatus !== null
            && mutatedStatus >= 500;
        const strongStructuralDelta = diff.significant
            && (diff.structureChanged || Math.abs(diff.bodyLengthDelta || 0) >= 1200);

        if (authzBypass || hasStrongFailKeyword || hasSqliMarker || hasWorkflowKeyword || serverErrorTransition) {
            return true;
        }

        switch (caseFamily) {
            case 'workflow_logic':
                return Boolean(diff.significant && originalStatus !== null && mutatedStatus !== null && originalStatus !== mutatedStatus);
            case 'generic':
            case 'error_handling':
            case 'xss':
            case 'sqli':
                return strongStructuralDelta;
            case 'access_control':
            case 'input_validation':
                return strongStructuralDelta && !this.comparisonContradictsHypothesis(caseFamily, diff);
            default:
                return strongStructuralDelta;
        }
    }

    private comparisonContradictsHypothesis(
        caseFamily: FocusedSignalInterpretationSummary['caseFamily'],
        diff: NonNullable<EvidenceBundle['responseDiffSummary']>,
    ): boolean {
        const originalStatus = typeof diff.originalStatus === 'number' ? diff.originalStatus : null;
        const mutatedStatus = typeof diff.mutatedStatus === 'number' ? diff.mutatedStatus : null;
        const validationBlocked = diff.significant
            && originalStatus !== null
            && originalStatus >= 200
            && originalStatus < 400
            && mutatedStatus !== null
            && mutatedStatus >= 400
            && mutatedStatus < 500;

        return validationBlocked && (
            caseFamily === 'access_control'
            || caseFamily === 'input_validation'
            || caseFamily === 'error_handling'
        );
    }

    private buildRequestEvidenceStory(
        testCase: FocusedTestCase,
        caseFamily: FocusedSignalInterpretationSummary['caseFamily'],
        interpretationSummary: FocusedSignalInterpretationSummary,
        evidenceBundles: EvidenceBundle[],
    ): FocusedRequestEvidenceStory | null {
        const requestHeavy = this.isRequestHeavyCase(testCase, caseFamily, evidenceBundles);
        const requestBundles = evidenceBundles.filter((bundle) => bundle.source === 'baseline_replay' || bundle.source === 'mutated_replay' || !!bundle.requestRef || !!bundle.responseRef);
        if (!requestHeavy && requestBundles.length === 0) {
            return null;
        }

        const requestRefs = requestBundles
            .map((bundle) => this.buildRequestEvidenceRef(bundle))
            .filter((entry): entry is FocusedRequestEvidenceRef => !!entry);
        const requestRefById = new Map(requestRefs.map((entry) => [entry.evidenceId, entry]));
        const mutatedRefs = requestRefs.filter((entry) => entry.source === 'mutated_replay');
        const supportingIds = new Set<string>();
        const contradictingIds = new Set<string>();

        for (const bundle of evidenceBundles.filter((entry) => entry.source === 'comparison' && !!entry.responseDiffSummary)) {
            const relatedMutatedIds = (bundle.relatedEvidenceIds || []).filter((evidenceId) => requestRefById.has(evidenceId) && requestRefById.get(evidenceId)?.source === 'mutated_replay');
            if (relatedMutatedIds.length === 0 || !bundle.responseDiffSummary) {
                continue;
            }
            if (this.comparisonContradictsHypothesis(caseFamily, bundle.responseDiffSummary)) {
                relatedMutatedIds.forEach((evidenceId) => contradictingIds.add(evidenceId));
                continue;
            }
            if (this.comparisonSupportsHypothesis(caseFamily, bundle.responseDiffSummary)) {
                relatedMutatedIds.forEach((evidenceId) => supportingIds.add(evidenceId));
            }
        }

        if (supportingIds.size === 0 && (interpretationSummary.failSignals.length > 0 || interpretationSummary.reviewSignals.length > 0 || interpretationSummary.suspiciousSignals.length > 0)) {
            const fallback = [...mutatedRefs].reverse()[0];
            if (fallback) {
                supportingIds.add(fallback.evidenceId);
            }
        }
        if (contradictingIds.size === 0 && interpretationSummary.controlSignals.length > 0) {
            const fallback = [...mutatedRefs].reverse()[0];
            if (fallback) {
                contradictingIds.add(fallback.evidenceId);
            }
        }

        const supportingRequestRefs = mutatedRefs.filter((entry) => supportingIds.has(entry.evidenceId));
        const contradictingRequestRefs = mutatedRefs.filter((entry) => contradictingIds.has(entry.evidenceId));
        const confirmationRequestRefs = requestRefs.filter((entry) => entry.executionPhase === 'adaptive_confirmation');
        const strongestSuspiciousRequestRef = [...supportingRequestRefs].sort((left, right) => {
            if ((left.executionPhase === 'adaptive_confirmation' ? 1 : 0) !== (right.executionPhase === 'adaptive_confirmation' ? 1 : 0)) {
                return Number(right.executionPhase === 'adaptive_confirmation') - Number(left.executionPhase === 'adaptive_confirmation');
            }
            if ((left.confirmationOrdinal || 0) !== (right.confirmationOrdinal || 0)) {
                return (right.confirmationOrdinal || 0) - (left.confirmationOrdinal || 0);
            }
            return right.capturedAt.localeCompare(left.capturedAt);
        })[0] || null;
        const hasRequestBackedEvidence = requestRefs.length > 0;
        const lowConfidenceReason = requestHeavy && (!hasRequestBackedEvidence || supportingRequestRefs.length === 0)
            ? 'No request-backed confirmation was captured; confidence remains low.'
            : null;
        const summary = !hasRequestBackedEvidence
            ? 'No request-backed confirmation was captured; confidence remains low.'
            : confirmationRequestRefs.some((entry) => supportingIds.has(entry.evidenceId))
                ? 'Adaptive confirmation replay strengthened the same request-backed hypothesis.'
                : supportingRequestRefs.length > 0
                    ? 'Request-backed suspicious signal observed.'
                    : contradictingRequestRefs.length > 0
                        ? 'Request-backed control contrast weakened the hypothesis.'
                        : 'Burp-visible request evidence was captured, but it did not materially strengthen suspicion yet.';

        return {
            requestHeavy,
            hasRequestBackedEvidence,
            baselineRequestRef: requestRefs.find((entry) => entry.source === 'baseline_replay') || requestRefs[0] || null,
            strongestSuspiciousRequestRef,
            supportingRequestRefs,
            contradictingRequestRefs,
            confirmationRequestRefs,
            summary,
            lowConfidenceReason,
        };
    }

    private buildSupportProvenance(
        testCase: FocusedTestCase,
        caseFamily: FocusedSignalInterpretationSummary['caseFamily'],
        evidenceBundles: EvidenceBundle[],
        requestEvidenceStory: FocusedRequestEvidenceStory | null,
    ): FocusedSupportProvenanceSummary {
        const requestHeavy = requestEvidenceStory?.requestHeavy || this.isRequestHeavyCase(testCase, caseFamily, evidenceBundles);
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
        const lowConfidenceReason = requestHeavy && !requestBackedEvidence
            ? 'No request-backed confirmation was captured; confidence remains low.'
            : (requestEvidenceStory?.lowConfidenceReason || null);
        const summary = requestHeavy && !requestBackedEvidence
            ? browserBackedEvidence
                ? 'Browser-backed support only; this request-heavy case still lacks Burp-visible request confirmation.'
                : 'No Burp-visible request confirmation was captured for this request-heavy case.'
            : rail === 'hybrid'
                ? 'Hybrid support: Burp-visible request evidence is present alongside browser-backed confirmation.'
                : rail === 'request'
                    ? 'Request-backed support: Burp-visible request evidence is anchoring the current conclusion.'
                    : rail === 'browser'
                        ? 'Browser-backed support: browser/state observations are the primary evidence for this case.'
                        : 'System-only support: confidence remains bounded because no request-backed or browser-backed proof was captured.';

        return {
            rail,
            requestHeavy,
            requestBackedEvidence,
            browserBackedEvidence,
            requestEvidenceIds,
            browserEvidenceIds,
            systemEvidenceIds,
            summary,
            lowConfidenceReason,
        };
    }

    private buildSupportingEvidenceRefs(evidenceBundles: EvidenceBundle[]): FocusedVerdictEvidenceRef[] {
        return evidenceBundles.map((bundle) => ({
            evidenceId: bundle.id,
            source: bundle.source,
            role: this.mapEvidenceRole(bundle.source),
            summary: bundle.summary,
            capturedAt: bundle.capturedAt,
            relatedEvidenceIds: bundle.relatedEvidenceIds || [],
            browserActionCount: bundle.browserState?.actionCount ?? null,
            supportRail: this.mapSupportRail(bundle),
            requestMethod: bundle.requestRef?.method ?? null,
            requestPath: bundle.requestRef?.path ?? null,
            responseStatusCode: bundle.responseRef?.statusCode ?? null,
            executionPhase: bundle.provenance?.executionPhase ?? null,
            confirmationKind: bundle.provenance?.confirmationKind ?? null,
            confirmationOrdinal: bundle.provenance?.confirmationOrdinal ?? null,
            generatedFromFindingThreadId: bundle.provenance?.generatedFromFindingThreadId ?? null,
        }));
    }

    private mapEvidenceRole(source: EvidenceBundle['source']): FocusedVerdictEvidenceRef['role'] {
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

    private buildScopeViolationImpact(
        execution: FocusedTestCaseExecution,
        evidenceBundles: EvidenceBundle[],
    ): FocusedVerdictScopeViolationImpact {
        const reasons = evidenceBundles
            .map((bundle) => bundle.scopeViolation?.reason)
            .filter((entry): entry is string => !!entry);
        const hasScopeViolation = reasons.length > 0;
        const blocking = execution.executionState === 'blocked' || evidenceBundles.some((bundle) => {
            const violationKind = bundle.scopeViolation?.violationKind;
            return violationKind === 'host'
                || violationKind === 'route'
                || violationKind === 'endpoint_target'
                || violationKind === 'baseline_anchor'
                || violationKind === 'budget';
        });

        return {
            hasScopeViolation,
            severity: blocking ? 'blocking' : (hasScopeViolation ? 'advisory' : 'none'),
            underminesConfidence: hasScopeViolation,
            reasons,
        };
    }

    private evaluateRequirement(
        kind: string,
        evidenceBundles: EvidenceBundle[],
        scopeViolationImpact: FocusedVerdictScopeViolationImpact,
    ): RequirementSupportResult {
        const normalizedKind = String(kind || '').trim().toLowerCase();
        const requestEvidence = evidenceBundles.filter((bundle) => !!bundle.requestRef);
        const responseEvidence = evidenceBundles.filter((bundle) => !!bundle.responseRef);
        const comparisonEvidence = evidenceBundles.filter((bundle) => !!bundle.responseDiffSummary);
        const screenshotEvidence = evidenceBundles.filter((bundle) => !!bundle.screenshotRef);
        const browserEvidence = evidenceBundles.filter((bundle) => !!bundle.browserState);
        const mutatedEvidence = evidenceBundles.filter((bundle) => bundle.source === 'mutated_replay' && !!bundle.requestRef);
        const browserExpectationMatches = browserEvidence.filter((bundle) => bundle.browserState?.expectations?.some((entry) => entry.matched));
        const browserStateChangeEvidence = browserEvidence.filter((bundle) => {
            const expectations = bundle.browserState?.expectations || [];
            return expectations.some((entry) => entry.matcher === 'state_changed' && entry.matched)
                || (bundle.browserState?.detectedChanges?.length || 0) > 0;
        });

        switch (normalizedKind) {
            case 'response_diff':
                return {
                    supported: true,
                    satisfied: comparisonEvidence.length > 0,
                    supportingEvidenceIds: comparisonEvidence.map((bundle) => bundle.id),
                    note: comparisonEvidence.length > 0 ? undefined : 'No persisted response comparison evidence was captured.',
                };
            case 'status_code':
                return {
                    supported: true,
                    satisfied: responseEvidence.some((bundle) => typeof bundle.responseRef?.statusCode === 'number')
                        || comparisonEvidence.some((bundle) => typeof bundle.responseDiffSummary?.originalStatus === 'number'
                            || typeof bundle.responseDiffSummary?.mutatedStatus === 'number'),
                    supportingEvidenceIds: [
                        ...responseEvidence
                            .filter((bundle) => typeof bundle.responseRef?.statusCode === 'number')
                            .map((bundle) => bundle.id),
                        ...comparisonEvidence
                            .filter((bundle) => typeof bundle.responseDiffSummary?.originalStatus === 'number'
                                || typeof bundle.responseDiffSummary?.mutatedStatus === 'number')
                            .map((bundle) => bundle.id),
                    ],
                    note: 'Requires persisted status code evidence from the bounded request flow.',
                };
            case 'response_excerpt':
                return {
                    supported: true,
                    satisfied: responseEvidence.some((bundle) => !!bundle.responseRef?.raw)
                        || browserEvidence.some((bundle) => !!bundle.browserState?.domSummary),
                    supportingEvidenceIds: responseEvidence
                        .filter((bundle) => !!bundle.responseRef?.raw)
                        .map((bundle) => bundle.id)
                        .concat(browserEvidence.filter((bundle) => !!bundle.browserState?.domSummary).map((bundle) => bundle.id)),
                    note: 'Requires a persisted response excerpt, DOM summary, or raw response reference.',
                };
            case 'request_trace':
                return {
                    supported: true,
                    satisfied: requestEvidence.some((bundle) => !!bundle.requestRef?.raw || !!bundle.requestRef?.url),
                    supportingEvidenceIds: requestEvidence
                        .filter((bundle) => !!bundle.requestRef?.raw || !!bundle.requestRef?.url)
                        .map((bundle) => bundle.id),
                    note: 'Requires a persisted request reference tied to the scoped target.',
                };
            case 'payload_trace':
                return {
                    supported: true,
                    satisfied: mutatedEvidence.some((bundle) => !!bundle.requestRef?.raw || !!bundle.requestRef?.url),
                    supportingEvidenceIds: mutatedEvidence
                        .filter((bundle) => !!bundle.requestRef?.raw || !!bundle.requestRef?.url)
                        .map((bundle) => bundle.id),
                    note: 'Requires a persisted mutated request trace.',
                };
            case 'rendered_output':
                return {
                    supported: true,
                    satisfied: screenshotEvidence.length > 0 || browserExpectationMatches.length > 0,
                    supportingEvidenceIds: screenshotEvidence.map((bundle) => bundle.id)
                        .concat(browserExpectationMatches.map((bundle) => bundle.id)),
                    note: 'Satisfied by screenshot-backed evidence or matched browser verification results.',
                };
            case 'state_change':
                return {
                    supported: true,
                    satisfied: browserStateChangeEvidence.length > 0
                        || comparisonEvidence.some((bundle) => !!bundle.responseDiffSummary?.significant),
                    supportingEvidenceIds: browserStateChangeEvidence.map((bundle) => bundle.id)
                        .concat(comparisonEvidence.filter((bundle) => !!bundle.responseDiffSummary?.significant).map((bundle) => bundle.id)),
                    note: 'Satisfied by matched browser state-change proof or significant linked request diffs.',
                };
            case 'scope_respected':
                return {
                    supported: true,
                    satisfied: evidenceBundles.length > 0 && !scopeViolationImpact.hasScopeViolation,
                    supportingEvidenceIds: evidenceBundles.map((bundle) => bundle.id),
                    note: 'Satisfied only when persisted evidence exists and no scope violation was recorded.',
                };
            default:
                return {
                    supported: false,
                    satisfied: false,
                    supportingEvidenceIds: [],
                    note: `Evidence kind "${kind}" is not fully supported by the Phase 1D verdict rails.`,
                };
        }
    }

    private evaluateAnchoring(
        testCase: FocusedTestCase,
        evidenceBundles: EvidenceBundle[],
    ): {
        anchoredToTarget: boolean;
        anchoredMethod: string | null;
        anchoredPath: string | null;
    } {
        if (testCase.targetArtifact.kind === 'flow' || testCase.targetArtifact.kind === 'feature') {
            const browserEvidence = evidenceBundles.find((bundle) => !!bundle.browserState?.finalPath || !!bundle.browserState?.startUrl);
            return {
                anchoredToTarget: evidenceBundles.length > 0,
                anchoredMethod: null,
                anchoredPath: this.normalizeRoutePath(browserEvidence?.browserState?.finalPath
                    || browserEvidence?.browserState?.finalUrl
                    || browserEvidence?.browserState?.startUrl
                    || null),
            };
        }

        const requestLikeEvidence = evidenceBundles.find((bundle) => bundle.requestRef || bundle.responseRef);
        const browserLikeEvidence = evidenceBundles.find((bundle) => !!bundle.browserState?.finalPath || !!bundle.browserState?.finalUrl || !!bundle.browserState?.startUrl);
        const anchoredMethod = (requestLikeEvidence?.requestRef?.method
            || requestLikeEvidence?.responseRef?.method
            || null);
        const anchoredPath = this.normalizeRoutePath(
            requestLikeEvidence?.requestRef?.path
            || requestLikeEvidence?.requestRef?.url
            || requestLikeEvidence?.responseRef?.path
            || requestLikeEvidence?.responseRef?.url
            || browserLikeEvidence?.browserState?.finalPath
            || browserLikeEvidence?.browserState?.finalUrl
            || browserLikeEvidence?.browserState?.startUrl
            || null,
        );
        const targetMethod = testCase.targetArtifact.method?.toUpperCase() || null;
        const targetPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url || null);

        const methodMatches = !targetMethod || !anchoredMethod || targetMethod === anchoredMethod.toUpperCase();
        const pathMatches = !targetPath || !anchoredPath || this.routeMatches(targetPath, anchoredPath);

        return {
            anchoredToTarget: !!requestLikeEvidence && methodMatches && pathMatches,
            anchoredMethod,
            anchoredPath,
        };
    }

    private buildSufficiencySummary(input: {
        state: FocusedEvidenceSufficiencyReport['state'];
        anchoring: { anchoredToTarget: boolean };
        evidenceCount: number;
        missingRequirements: string[];
        unsupportedRequirements: string[];
        contradictorySignals: string[];
        scopeViolationImpact: FocusedVerdictScopeViolationImpact;
        interpretationSummary: FocusedSignalInterpretationSummary;
    }): string {
        if (input.state === 'contradictory') {
            return input.contradictorySignals[0] || 'Persisted evidence contains contradictory signals.';
        }
        if (input.state === 'unsupported') {
            return `Scoped verdicting does not fully support ${input.unsupportedRequirements.join(', ')} as verdict-grade evidence yet.`;
        }
        if (input.evidenceCount === 0) {
            return 'No persisted evidence bundles were available for verdicting.';
        }
        if (!input.anchoring.anchoredToTarget) {
            return 'Persisted evidence could not be cleanly anchored to the intended scoped target.';
        }
        if (input.missingRequirements.length > 0) {
            return `Missing required evidence: ${input.missingRequirements.join(', ')}.`;
        }
        if (input.interpretationSummary.reviewSignals.length > 0) {
            return input.interpretationSummary.summary;
        }
        if (input.scopeViolationImpact.underminesConfidence) {
            return 'Evidence was captured, but recorded scope violations undermine verdict confidence.';
        }
        return 'Required supported evidence was captured and anchored to the intended scoped target.';
    }

    private buildExecutionSnapshot(execution: FocusedTestCaseExecution): FocusedCaseVerdict['executionSnapshot'] {
        return {
            executionId: execution.id,
            executionState: execution.executionState,
            executionProfileKey: execution.executionProfileKey,
            runReason: execution.runReason ?? null,
            notesSummary: execution.notesSummary ?? null,
            errorMessage: execution.errorMessage ?? null,
            requestActionsUsed: execution.requestActionsUsed,
            browserActionsUsed: execution.browserActionsUsed,
            browserSessionId: execution.browserSessionId ?? null,
            startedAt: execution.startedAt,
            completedAt: execution.completedAt ?? null,
        };
    }

    private normalizeRoutePath(value?: string | null): string | null {
        if (!value) {
            return null;
        }

        try {
            return new URL(value).pathname || '/';
        } catch {
            const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
            if (!withoutQuery) {
                return null;
            }
            return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
        }
    }

    private routeMatches(pattern: string, candidate: string): boolean {
        const escaped = pattern
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\/:([A-Za-z0-9_]+)/g, '/[^/]+');
        return new RegExp(`^${escaped}$`).test(candidate);
    }
}

export const focusedVerdictService = new FocusedVerdictService();
