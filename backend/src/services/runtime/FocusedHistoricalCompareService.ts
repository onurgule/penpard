import { v4 as uuidv4 } from 'uuid';
import { Database as DatabaseType } from 'better-sqlite3';
import {
    db,
    getFocusedHistoricalCompareState,
    getFocusedHistoricalCompareSummary,
    getFocusedScanBlockerSummary,
    getFocusedScanVerdictSummary,
    getFocusedTestObjective,
    getScan,
    getScopeEnvelope,
    listFocusedCaseHistoricalComparesByScan,
    listFocusedInvestigationIssuesByExecution,
    listFocusedTestCasesWithExecutionSummary,
    upsertFocusedCaseHistoricalCompare,
    upsertFocusedHistoricalCompareState,
    upsertFocusedHistoricalCompareSummary,
} from '../../db/init';
import { logger } from '../../utils/logger';
import {
    focusedHistoricalCompareAssistanceProfileResolver,
    type FocusedHistoricalCompareAssistanceProfileResolver,
} from './FocusedHistoricalCompareProfiles';
import { focusedReasoningTraceService } from './FocusedReasoningTraceService';
import type {
    FocusedBlockerRecurrenceSummary,
    FocusedCaseHistoricalCompare,
    FocusedHistoricalCompareState,
    FocusedHistoricalCompareStatus,
    FocusedHistoricalCompareSummary,
    FocusedHistoricalOutcome,
    FocusedInvestigationIssue,
    FocusedScanBlockerSummary,
    FocusedScanVerdictSummary,
    FocusedTestCase,
    FocusedTestObjective,
    ScopeEnvelope,
} from './ScopedScanTypes';
import {
    createEmptyFocusedBlockerRecurrenceSummary,
    createEmptyFocusedVerdictTransitionCounts,
    isFocusedInvestigationIssueUnresolved,
    normalizeFocusedEvidenceSufficiencyState,
    normalizeFocusedOverallChangeClassification,
    normalizeScanMode,
} from './ScopedScanTypes';

interface HistoricalRunContext {
    scan: any;
    objective: FocusedTestObjective;
    scopeEnvelope: ScopeEnvelope;
    focusedVerdictSummary: FocusedScanVerdictSummary | null;
    focusedBlockerSummary: FocusedScanBlockerSummary | null;
    focusedTestCases: FocusedTestCase[];
    targetOrigin: string;
    scopeIdentityKey: string;
}

interface CaseDescriptor {
    testCase: FocusedTestCase;
    caseIdentityKey: string;
    caseVariantKey: string;
    targetAnchorKey: string;
    assertionKinds: string[];
    evidenceKinds: string[];
    titleTokens: string[];
}

interface CaseMatchResult {
    compareStatus: FocusedCaseHistoricalCompare['compareStatus'];
    previousCase: FocusedTestCase | null;
    caseIdentityKey: string;
    caseVariantKey: string;
}

interface HistoricalCompareResult {
    scanId: string;
    focusedHistoricalCompareState: FocusedHistoricalCompareState;
    focusedHistoricalCompareSummary: FocusedHistoricalCompareSummary | null;
    caseComparisons: FocusedCaseHistoricalCompare[];
}

interface HistoricalCompareDependencies {
    database: DatabaseType;
    profileResolver: FocusedHistoricalCompareAssistanceProfileResolver;
    now: () => string;
    createId: () => string;
}

const CASE_MATCH_THRESHOLD = 0.7;
const CASE_MATCH_NOT_COMPARABLE_THRESHOLD = 0.38;

export class FocusedHistoricalCompareService {
    private readonly deps: HistoricalCompareDependencies;

    constructor(
        deps: Partial<HistoricalCompareDependencies> = {},
    ) {
        this.deps = {
            database: db,
            profileResolver: focusedHistoricalCompareAssistanceProfileResolver,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public async ensureGenerated(scanId: string, userId?: number): Promise<HistoricalCompareResult | null> {
        const scan = getScan(scanId);
        if (!scan || normalizeScanMode(scan.scan_mode) !== 'scoped') {
            return null;
        }

        const focusedVerdictSummary = getFocusedScanVerdictSummary(scanId);
        const focusedBlockerSummary = getFocusedScanBlockerSummary(scanId);
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(scanId);
        const persistedState = getFocusedHistoricalCompareState(scanId);
        const persistedSummary = getFocusedHistoricalCompareSummary(scanId);
        const persistedCaseComparisons = listFocusedCaseHistoricalComparesByScan(scanId);
        const latestFactAt = this.computeLatestFactTimestamp(focusedTestCases, focusedVerdictSummary, focusedBlockerSummary);

        if (!focusedVerdictSummary) {
            if (
                persistedState?.comparisonStatus === 'comparison_unavailable'
                && persistedState.latestCompareAt
                && (!latestFactAt || persistedState.latestCompareAt >= latestFactAt)
            ) {
                return {
                    scanId,
                    focusedHistoricalCompareState: persistedState,
                    focusedHistoricalCompareSummary: persistedSummary,
                    caseComparisons: persistedCaseComparisons,
                };
            }
        } else if (
            persistedState
            && persistedSummary
            && persistedCaseComparisons.length === focusedTestCases.length
            && persistedState.latestCompareAt
            && (!latestFactAt || persistedState.latestCompareAt >= latestFactAt)
        ) {
            return {
                scanId,
                focusedHistoricalCompareState: persistedState,
                focusedHistoricalCompareSummary: persistedSummary,
                caseComparisons: persistedCaseComparisons,
            };
        }

        return this.generateNow(scanId, userId ?? scan.user_id);
    }

    public async generateNow(scanId: string, userId?: number): Promise<HistoricalCompareResult | null> {
        const scan = getScan(scanId);
        if (!scan) {
            throw new Error(`Focused historical compare generation could not find scan ${scanId}.`);
        }
        if (normalizeScanMode(scan.scan_mode) !== 'scoped') {
            throw new Error('Focused historical compare generation is only available for scoped scans.');
        }

        const objective = getFocusedTestObjective(scanId);
        const scopeEnvelope = getScopeEnvelope(scanId);
        if (!objective || !scopeEnvelope) {
            logger.warn('Focused historical compare skipped because scoped objective or scope envelope was missing', {
                scanId,
            });
            return null;
        }

        const currentRun = this.buildRunContext(scan, objective, scopeEnvelope);
        if (!currentRun) {
            return null;
        }

        const latestCompareAt = this.deps.now();
        const priorRuns = this.loadPriorRunContexts(scan, currentRun.targetOrigin);
        const sameLineageRuns = priorRuns.filter((entry) => entry.scopeIdentityKey === currentRun.scopeIdentityKey);
        const sameTargetDifferentLineageRuns = priorRuns.filter((entry) => entry.scopeIdentityKey !== currentRun.scopeIdentityKey);
        const baselineRun = sameLineageRuns[0] || null;
        const comparedRun = sameLineageRuns.length > 0 ? sameLineageRuns[sameLineageRuns.length - 1] : null;

        const comparisonStatus = this.determineCompareStatus({
            currentRun,
            comparedRun,
            sameTargetDifferentLineageRuns,
        });
        const statusReason = this.buildStatusReason(comparisonStatus, sameTargetDifferentLineageRuns.length);
        const profile = this.deps.profileResolver.resolve(userId ?? scan.user_id);

        const compareStateBase: FocusedHistoricalCompareState = {
            scanId,
            scopeType: objective.scopeType,
            targetOrigin: currentRun.targetOrigin,
            scopeIdentityKey: currentRun.scopeIdentityKey,
            comparisonStatus,
            baselineScanId: comparisonStatus === 'baseline_created'
                ? scanId
                : (baselineRun?.scan.id || null),
            comparedAgainstScanId: comparedRun?.scan.id || null,
            firstObservedAt: baselineRun?.scan.created_at || scan.created_at || latestCompareAt,
            latestCompareAt,
            statusReason,
            assistanceProfileKey: null,
            assistanceProvider: null,
            assistanceModel: null,
            assistanceNarrative: null,
        };

        const caseComparisons = await this.buildCaseComparisons({
            currentRun,
            comparedRun,
            comparisonStatus,
            userId: userId ?? scan.user_id,
            objective,
            assistanceEnabled: comparisonStatus !== 'comparison_unavailable',
            profileKey: profile.key,
        });
        const compareSummaryBase = this.buildCompareSummary({
            currentRun,
            baselineRun,
            comparedRun,
            comparisonStatus,
            caseComparisons,
        });

        let compareState = compareStateBase;
        let compareSummary = compareSummaryBase;

        if (comparisonStatus !== 'comparison_unavailable' && compareSummaryBase) {
            const runNarrative = await profile.describeRunCompare({
                scanId,
                userId: userId ?? scan.user_id,
                objective,
                compareState: compareStateBase,
                compareSummary: compareSummaryBase,
            });

            if (runNarrative) {
                compareState = {
                    ...compareStateBase,
                    assistanceProfileKey: profile.key,
                    assistanceProvider: profile.provider,
                    assistanceModel: profile.model,
                    assistanceNarrative: comparisonStatus === 'baseline_created' ? null : runNarrative,
                };
                compareSummary = {
                    ...compareSummaryBase,
                    assistanceProfileKey: profile.key,
                    assistanceProvider: profile.provider,
                    assistanceModel: profile.model,
                    compareNarrative: runNarrative,
                };
            }
        }

        this.persistCompareArtifacts(scanId, compareState, caseComparisons, compareSummary);
        focusedReasoningTraceService.record({
            scanId,
            objectiveId: objective.id,
            stage: 'historical_compare',
            entryType: comparisonStatus === 'compared' || comparisonStatus === 'baseline_created'
                ? 'result'
                : 'constraint',
            rail: 'system_only',
            summary: compareState.statusReason
                || compareSummary?.compareNarrative
                || `Historical compare status: ${comparisonStatus.replace(/_/g, ' ')}.`,
            observationSummary: compareSummary
                ? [
                    compareSummary.improvedCount > 0 ? `${compareSummary.improvedCount} improved` : null,
                    compareSummary.regressedCount > 0 ? `${compareSummary.regressedCount} regressed` : null,
                    compareSummary.weakerConfidenceCount > 0 ? `${compareSummary.weakerConfidenceCount} weaker confidence` : null,
                    compareSummary.strongerConfidenceCount > 0 ? `${compareSummary.strongerConfidenceCount} stronger confidence` : null,
                ].filter((entry): entry is string => !!entry).join(' | ') || 'Historical comparison ran without material case deltas.'
                : 'Historical comparison is waiting for comparable verdict material.',
            confidenceShiftSummary: compareSummary?.compareNarrative || null,
            stopRetryBlockRationale: comparisonStatus === 'compared' || comparisonStatus === 'baseline_created'
                ? null
                : compareState.statusReason || null,
        });

        return {
            scanId,
            focusedHistoricalCompareState: compareState,
            focusedHistoricalCompareSummary: compareSummary,
            caseComparisons,
        };
    }

    private buildRunContext(scan: any, objective: FocusedTestObjective, scopeEnvelope: ScopeEnvelope): HistoricalRunContext | null {
        const focusedTestCases = listFocusedTestCasesWithExecutionSummary(scan.id);
        const focusedVerdictSummary = getFocusedScanVerdictSummary(scan.id);
        const focusedBlockerSummary = getFocusedScanBlockerSummary(scan.id);
        const targetOrigin = this.computeTargetOrigin(scan.target, scopeEnvelope);
        const scopeIdentityKey = this.computeScopeIdentityKey(targetOrigin, objective, scopeEnvelope);

        return {
            scan,
            objective,
            scopeEnvelope,
            focusedVerdictSummary,
            focusedBlockerSummary,
            focusedTestCases,
            targetOrigin,
            scopeIdentityKey,
        };
    }

    private loadPriorRunContexts(scan: any, targetOrigin: string): HistoricalRunContext[] {
        const rows = this.deps.database.prepare(`
            SELECT s.id
            FROM scans s
            INNER JOIN focused_test_objectives o ON o.scan_id = s.id
            INNER JOIN scope_envelopes e ON e.scan_id = s.id
            INNER JOIN focused_scan_verdict_summaries v ON v.scan_id = s.id
            WHERE s.user_id = ?
              AND s.scan_mode = 'scoped'
              AND s.id != ?
              AND (
                COALESCE(s.created_at, '') < COALESCE(?, '')
                OR COALESCE(s.created_at, '') = COALESCE(?, '')
              )
            ORDER BY COALESCE(s.created_at, '') ASC, s.id ASC
        `).all(scan.user_id, scan.id, scan.created_at, scan.created_at) as Array<{ id: string }>;

        return rows
            .map((row) => {
                const priorScan = getScan(row.id);
                const objective = getFocusedTestObjective(row.id);
                const scopeEnvelope = getScopeEnvelope(row.id);
                if (!priorScan || !objective || !scopeEnvelope) {
                    return null;
                }
                const context = this.buildRunContext(priorScan, objective, scopeEnvelope);
                if (!context || !context.focusedVerdictSummary) {
                    return null;
                }
                return context.targetOrigin === targetOrigin ? context : null;
            })
            .filter((entry): entry is HistoricalRunContext => !!entry);
    }

    private determineCompareStatus(input: {
        currentRun: HistoricalRunContext;
        comparedRun: HistoricalRunContext | null;
        sameTargetDifferentLineageRuns: HistoricalRunContext[];
    }): FocusedHistoricalCompareStatus {
        const hasVerdictMaterial = !!input.currentRun.focusedVerdictSummary;
        if (!hasVerdictMaterial) {
            return 'comparison_unavailable';
        }
        if (input.comparedRun) {
            return 'compared';
        }
        if (input.sameTargetDifferentLineageRuns.length > 0) {
            return 'not_comparable';
        }
        return 'baseline_created';
    }

    private buildStatusReason(
        comparisonStatus: FocusedHistoricalCompareStatus,
        sameTargetDifferentLineageCount: number,
    ): string | null {
        switch (comparisonStatus) {
            case 'baseline_created':
                return 'First observed scoped run for this comparable lineage. Historical comparison will start from this baseline.';
            case 'comparison_unavailable':
                return 'Historical comparison is unavailable until scoped verdict material has been persisted for this run.';
            case 'not_comparable':
                return sameTargetDifferentLineageCount > 0
                    ? 'Earlier scoped runs exist for the same target, but the persisted scope lineage changed enough that deterministic comparison was not considered safe.'
                    : 'No safe comparable predecessor was found for deterministic historical comparison.';
            default:
                return null;
        }
    }

    private async buildCaseComparisons(input: {
        currentRun: HistoricalRunContext;
        comparedRun: HistoricalRunContext | null;
        comparisonStatus: FocusedHistoricalCompareStatus;
        userId?: number;
        objective: FocusedTestObjective;
        assistanceEnabled: boolean;
        profileKey: string;
    }): Promise<FocusedCaseHistoricalCompare[]> {
        if (input.comparisonStatus === 'comparison_unavailable') {
            return [];
        }

        const currentDescriptors = input.currentRun.focusedTestCases.map((testCase) => this.buildCaseDescriptor(testCase));
        const priorDescriptors = (input.comparedRun?.focusedTestCases || []).map((testCase) => this.buildCaseDescriptor(testCase));
        const unmatchedPrior = new Set(priorDescriptors.map((entry) => entry.testCase.id));
        const exactIdentityBuckets = this.buildCaseDescriptorBuckets(priorDescriptors, 'caseIdentityKey');
        const exactVariantBuckets = this.buildCaseDescriptorBuckets(priorDescriptors, 'caseVariantKey');
        const profile = this.deps.profileResolver.resolve(input.userId);
        const comparisons: FocusedCaseHistoricalCompare[] = [];
        const compareTimestamp = this.deps.now();

        for (const descriptor of currentDescriptors) {
            const matchResult = this.matchCase({
                descriptor,
                priorDescriptors,
                unmatchedPrior,
                exactIdentityBuckets,
                exactVariantBuckets,
                comparisonStatus: input.comparisonStatus,
            });

            if (matchResult.previousCase) {
                unmatchedPrior.delete(matchResult.previousCase.id);
            }

            const priorCase = matchResult.previousCase;
            const blockerRecurrence = priorCase
                ? this.compareBlockerRecurrence(priorCase, descriptor.testCase)
                : createEmptyFocusedBlockerRecurrenceSummary();
            const evidenceDriftClassification = priorCase
                ? this.classifyEvidenceDrift(priorCase, descriptor.testCase, blockerRecurrence)
                : null;
            const historicalOutcome = this.classifyHistoricalOutcome({
                compareStatus: matchResult.compareStatus,
                priorCase,
                currentCase: descriptor.testCase,
                evidenceDriftClassification,
                blockerRecurrence,
            });
            const compare: FocusedCaseHistoricalCompare = {
                id: this.deps.createId(),
                currentScanId: input.currentRun.scan.id,
                currentCaseId: descriptor.testCase.id,
                currentExecutionId: descriptor.testCase.latestVerdict?.executionId || descriptor.testCase.lastExecutionId || null,
                caseIdentityKey: matchResult.caseIdentityKey,
                caseVariantKey: matchResult.caseVariantKey,
                previousScanId: priorCase?.scanId || null,
                previousCaseId: priorCase?.id || null,
                previousExecutionId: priorCase?.latestVerdict?.executionId || priorCase?.lastExecutionId || null,
                compareStatus: matchResult.compareStatus,
                historicalOutcome,
                priorVerdict: priorCase?.latestVerdict?.verdictState || null,
                currentVerdict: descriptor.testCase.latestVerdict?.verdictState || null,
                verdictTransition: priorCase?.latestVerdict?.verdictState && descriptor.testCase.latestVerdict?.verdictState
                    ? `${priorCase.latestVerdict.verdictState}_to_${descriptor.testCase.latestVerdict.verdictState}`
                    : null,
                priorEvidenceSufficiency: priorCase?.latestVerdict?.evidenceSufficiency?.state
                    ? normalizeFocusedEvidenceSufficiencyState(priorCase.latestVerdict.evidenceSufficiency.state)
                    : null,
                currentEvidenceSufficiency: descriptor.testCase.latestVerdict?.evidenceSufficiency?.state
                    ? normalizeFocusedEvidenceSufficiencyState(descriptor.testCase.latestVerdict.evidenceSufficiency.state)
                    : null,
                priorVerdictReason: priorCase?.latestVerdict?.verdictReason || null,
                currentVerdictReason: descriptor.testCase.latestVerdict?.verdictReason || null,
                priorEvidenceSummary: priorCase?.latestVerdict?.evidenceSufficiency?.summary || null,
                currentEvidenceSummary: descriptor.testCase.latestVerdict?.evidenceSufficiency?.summary || null,
                evidenceDriftClassification,
                blockerRecurrence,
                compareNarrative: null,
                assistanceProfileKey: null,
                assistanceProvider: null,
                assistanceModel: null,
                latestCompareAt: compareTimestamp,
            };

            if (input.assistanceEnabled && this.shouldGenerateCaseNarrative(compare)) {
                const narrative = await profile.describeCaseCompare({
                    scanId: input.currentRun.scan.id,
                    userId: input.userId,
                    objective: input.objective,
                    testCase: descriptor.testCase,
                    previousCase: priorCase,
                    compare,
                });

                if (narrative) {
                    compare.compareNarrative = narrative;
                    compare.assistanceProfileKey = profile.key;
                    compare.assistanceProvider = profile.provider;
                    compare.assistanceModel = profile.model;
                }
            }

            comparisons.push(compare);
        }

        return comparisons;
    }

    private buildCompareSummary(input: {
        currentRun: HistoricalRunContext;
        baselineRun: HistoricalRunContext | null;
        comparedRun: HistoricalRunContext | null;
        comparisonStatus: FocusedHistoricalCompareStatus;
        caseComparisons: FocusedCaseHistoricalCompare[];
    }): FocusedHistoricalCompareSummary | null {
        const countsByVerdictTransition = createEmptyFocusedVerdictTransitionCounts();
        const improvedCases: string[] = [];
        const regressedCases: string[] = [];
        const unstableCases: string[] = [];
        const repeatedBlockerFamilies = new Set<string>();
        const newBlockerFamilies = new Set<string>();
        const resolvedBlockerFamilies = new Set<string>();

        let improvedCount = 0;
        let regressedCount = 0;
        let unchangedCount = 0;
        let weakerConfidenceCount = 0;
        let strongerConfidenceCount = 0;
        let newlyIntroducedCount = 0;
        let notComparableCount = 0;

        for (const compare of input.caseComparisons) {
            if (compare.verdictTransition) {
                countsByVerdictTransition[compare.verdictTransition] += 1;
            }

            switch (compare.historicalOutcome) {
                case 'improved':
                    improvedCount += 1;
                    improvedCases.push(compare.currentCaseId);
                    break;
                case 'regressed':
                    regressedCount += 1;
                    regressedCases.push(compare.currentCaseId);
                    unstableCases.push(compare.currentCaseId);
                    break;
                case 'weaker_confidence':
                    weakerConfidenceCount += 1;
                    unstableCases.push(compare.currentCaseId);
                    break;
                case 'stronger_confidence':
                    strongerConfidenceCount += 1;
                    break;
                case 'newly_introduced':
                    newlyIntroducedCount += 1;
                    break;
                case 'not_comparable':
                    notComparableCount += 1;
                    break;
                default:
                    unchangedCount += 1;
                    break;
            }

            for (const issueType of compare.blockerRecurrence.recurringUnresolvedIssueFamilies) {
                repeatedBlockerFamilies.add(issueType);
            }
            for (const issueType of compare.blockerRecurrence.newlyIntroducedIssueFamilies) {
                newBlockerFamilies.add(issueType);
            }
            for (const issueType of compare.blockerRecurrence.resolvedIssueFamilies) {
                resolvedBlockerFamilies.add(issueType);
            }
            if (
                compare.evidenceDriftClassification === 'unsupported_gap_introduced'
                || compare.evidenceDriftClassification === 'contradiction_introduced'
                || compare.evidenceDriftClassification === 'scope_risk_increased'
            ) {
                unstableCases.push(compare.currentCaseId);
            }
        }

        const removedPriorCases = input.comparedRun
            ? this.buildRemovedPriorCases(input.comparedRun.focusedTestCases, input.caseComparisons)
            : [];
        const removedPriorCaseCount = removedPriorCases.length;
        const comparisonStatus = input.comparisonStatus;
        const manualReviewRecommended = comparisonStatus === 'compared'
            ? regressedCount > 0
                || weakerConfidenceCount > 0
                || [...repeatedBlockerFamilies].length > 0
                || [...newBlockerFamilies].length > 0
                || unstableCases.length > 0
            : comparisonStatus === 'not_comparable';

        const overallChangeClassification = normalizeFocusedOverallChangeClassification(
            comparisonStatus === 'baseline_created'
                ? 'baseline_only'
                : regressedCount > 0
                    ? 'regression'
                    : weakerConfidenceCount > 0 || [...repeatedBlockerFamilies].length > 0 || unstableCases.length > 0
                        ? 'instability'
                        : improvedCount > 0 || strongerConfidenceCount > 0 || [...resolvedBlockerFamilies].length > 0
                            ? 'improvement'
                            : 'no_material_change',
        );

        const stabilityNotes = this.buildStabilityNotes({
            comparisonStatus,
            improvedCount,
            regressedCount,
            weakerConfidenceCount,
            strongerConfidenceCount,
            newlyIntroducedCount,
            notComparableCount,
            removedPriorCaseCount,
            repeatedBlockerFamilies: [...repeatedBlockerFamilies],
            newBlockerFamilies: [...newBlockerFamilies],
            resolvedBlockerFamilies: [...resolvedBlockerFamilies],
            unstableCases,
        });

        return {
            scanId: input.currentRun.scan.id,
            baselineScanId: comparisonStatus === 'baseline_created'
                ? input.currentRun.scan.id
                : (input.baselineRun?.scan.id || null),
            comparedAgainstScanId: input.comparedRun?.scan.id || null,
            comparisonStatus,
            overallChangeClassification,
            countsByVerdictTransition,
            improvedCount,
            regressedCount,
            unchangedCount,
            weakerConfidenceCount,
            strongerConfidenceCount,
            newlyIntroducedCount,
            notComparableCount,
            removedPriorCaseCount,
            improvedCases: this.uniqueStrings(improvedCases),
            regressedCases: this.uniqueStrings(regressedCases),
            unstableCases: this.uniqueStrings(unstableCases),
            repeatedBlockerFamilies: [...repeatedBlockerFamilies] as FocusedHistoricalCompareSummary['repeatedBlockerFamilies'],
            newBlockerFamilies: [...newBlockerFamilies] as FocusedHistoricalCompareSummary['newBlockerFamilies'],
            resolvedBlockerFamilies: [...resolvedBlockerFamilies] as FocusedHistoricalCompareSummary['resolvedBlockerFamilies'],
            removedPriorCases,
            stabilityNotes,
            manualReviewRecommended,
            latestCompareAt: this.deps.now(),
            assistanceProfileKey: null,
            assistanceProvider: null,
            assistanceModel: null,
            compareNarrative: null,
        };
    }

    private matchCase(input: {
        descriptor: CaseDescriptor;
        priorDescriptors: CaseDescriptor[];
        unmatchedPrior: Set<string>;
        exactIdentityBuckets: Map<string, CaseDescriptor[]>;
        exactVariantBuckets: Map<string, CaseDescriptor[]>;
        comparisonStatus: FocusedHistoricalCompareStatus;
    }): CaseMatchResult {
        if (input.comparisonStatus === 'baseline_created') {
            return {
                compareStatus: 'baseline_only',
                previousCase: null,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        if (input.comparisonStatus === 'comparison_unavailable' || input.comparisonStatus === 'not_comparable') {
            return {
                compareStatus: 'not_comparable',
                previousCase: null,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        const exactIdentityMatches = (input.exactIdentityBuckets.get(input.descriptor.caseIdentityKey) || [])
            .filter((entry) => input.unmatchedPrior.has(entry.testCase.id));
        if (exactIdentityMatches.length === 1) {
            return {
                compareStatus: 'exact_match',
                previousCase: exactIdentityMatches[0].testCase,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        const exactVariantMatches = (input.exactVariantBuckets.get(input.descriptor.caseVariantKey) || [])
            .filter((entry) => input.unmatchedPrior.has(entry.testCase.id));
        if (exactVariantMatches.length === 1) {
            return {
                compareStatus: 'likely_match',
                previousCase: exactVariantMatches[0].testCase,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        let bestScore = 0;
        let bestDescriptor: CaseDescriptor | null = null;
        for (const priorDescriptor of input.priorDescriptors) {
            if (!input.unmatchedPrior.has(priorDescriptor.testCase.id)) {
                continue;
            }
            const score = this.scoreCaseMatch(input.descriptor, priorDescriptor);
            if (score > bestScore) {
                bestScore = score;
                bestDescriptor = priorDescriptor;
            }
        }

        if (bestDescriptor && bestScore >= CASE_MATCH_THRESHOLD) {
            return {
                compareStatus: 'likely_match',
                previousCase: bestDescriptor.testCase,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        if (bestDescriptor && bestScore >= CASE_MATCH_NOT_COMPARABLE_THRESHOLD) {
            return {
                compareStatus: 'not_comparable',
                previousCase: null,
                caseIdentityKey: input.descriptor.caseIdentityKey,
                caseVariantKey: input.descriptor.caseVariantKey,
            };
        }

        return {
            compareStatus: 'newly_introduced',
            previousCase: null,
            caseIdentityKey: input.descriptor.caseIdentityKey,
            caseVariantKey: input.descriptor.caseVariantKey,
        };
    }

    private buildCaseDescriptorBuckets(
        descriptors: CaseDescriptor[],
        key: 'caseIdentityKey' | 'caseVariantKey',
    ): Map<string, CaseDescriptor[]> {
        const buckets = new Map<string, CaseDescriptor[]>();
        for (const descriptor of descriptors) {
            const bucket = buckets.get(descriptor[key]) || [];
            bucket.push(descriptor);
            buckets.set(descriptor[key], bucket);
        }
        return buckets;
    }

    private buildCaseDescriptor(testCase: FocusedTestCase): CaseDescriptor {
        const assertionKinds = this.uniqueStrings(
            (testCase.assertions || [])
                .map((entry) => this.normalizeText(entry.kind))
                .filter((entry) => entry.length > 0),
        );
        const evidenceKinds = this.uniqueStrings(
            (testCase.requiredEvidence || [])
                .map((entry) => this.normalizeText(entry.kind))
                .filter((entry) => entry.length > 0),
        );
        const titleTokens = this.extractTokens([
            testCase.title,
            testCase.hypothesis,
        ].join(' '));
        const targetAnchorKey = this.buildTargetArtifactAnchor(testCase);
        const caseIdentityKey = JSON.stringify({
            targetAnchorKey,
            assertionKinds,
            evidenceKinds,
        });
        const caseVariantKey = JSON.stringify({
            targetAnchorKey,
            assertionKinds,
            evidenceKinds,
            titleTokens,
        });

        return {
            testCase,
            caseIdentityKey,
            caseVariantKey,
            targetAnchorKey,
            assertionKinds,
            evidenceKinds,
            titleTokens,
        };
    }

    private buildTargetArtifactAnchor(testCase: FocusedTestCase): string {
        const artifact = testCase.targetArtifact || { kind: 'feature' as const };
        return JSON.stringify({
            kind: artifact.kind,
            method: String(artifact.method || '').trim().toUpperCase() || null,
            path: this.normalizeRoutePath(artifact.path || artifact.url || null),
            referenceKind: this.normalizeText(artifact.referenceKind),
            referenceId: this.normalizeText(artifact.referenceId),
            label: this.normalizeText(artifact.label),
        });
    }

    private scoreCaseMatch(current: CaseDescriptor, prior: CaseDescriptor): number {
        const targetScore = current.targetAnchorKey === prior.targetAnchorKey ? 0.5 : 0;
        const assertionScore = 0.2 * this.computeJaccard(current.assertionKinds, prior.assertionKinds);
        const evidenceScore = 0.2 * this.computeJaccard(current.evidenceKinds, prior.evidenceKinds);
        const titleScore = 0.1 * this.computeJaccard(current.titleTokens, prior.titleTokens);
        return targetScore + assertionScore + evidenceScore + titleScore;
    }

    private computeJaccard(left: string[], right: string[]): number {
        if (left.length === 0 && right.length === 0) {
            return 1;
        }

        const leftSet = new Set(left);
        const rightSet = new Set(right);
        let intersection = 0;
        for (const value of leftSet) {
            if (rightSet.has(value)) {
                intersection += 1;
            }
        }
        const union = new Set([...leftSet, ...rightSet]).size;
        return union > 0 ? intersection / union : 0;
    }

    private compareBlockerRecurrence(previousCase: FocusedTestCase, currentCase: FocusedTestCase): FocusedBlockerRecurrenceSummary {
        const previousIssues = previousCase.latestVerdict
            ? listFocusedInvestigationIssuesByExecution(previousCase.scanId, previousCase.id, previousCase.latestVerdict.executionId)
            : [];
        const currentIssues = currentCase.latestVerdict
            ? listFocusedInvestigationIssuesByExecution(currentCase.scanId, currentCase.id, currentCase.latestVerdict.executionId)
            : [];
        const previousUnresolved = previousIssues.filter((issue) => isFocusedInvestigationIssueUnresolved(issue.issueStatus));
        const currentUnresolved = currentIssues.filter((issue) => isFocusedInvestigationIssueUnresolved(issue.issueStatus));
        const previousFamilies = new Set(previousUnresolved.map((issue) => issue.issueType));
        const currentFamilies = new Set(currentUnresolved.map((issue) => issue.issueType));
        const recurringUnresolvedIssueFamilies = [...currentFamilies].filter((issueType) => previousFamilies.has(issueType));
        const resolvedIssueFamilies = [...previousFamilies].filter((issueType) => !currentFamilies.has(issueType));
        const newlyIntroducedIssueFamilies = [...currentFamilies].filter((issueType) => !previousFamilies.has(issueType));
        const recurringWorkaroundFailureFamilies = this.collectRecurringWorkaroundFailureFamilies(previousUnresolved, currentUnresolved);
        const previousBlocking = previousUnresolved.filter((issue) => issue.impact === 'blocking').length;
        const currentBlocking = currentUnresolved.filter((issue) => issue.impact === 'blocking').length;
        const previousDegrading = previousUnresolved.filter((issue) => issue.impact === 'degrading').length;
        const currentDegrading = currentUnresolved.filter((issue) => issue.impact === 'degrading').length;
        const notes: string[] = [];

        if (recurringUnresolvedIssueFamilies.length > 0) {
            notes.push(`Recurring unresolved blocker families: ${recurringUnresolvedIssueFamilies.join(', ')}.`);
        }
        if (newlyIntroducedIssueFamilies.length > 0) {
            notes.push(`New blocker families appeared: ${newlyIntroducedIssueFamilies.join(', ')}.`);
        }
        if (resolvedIssueFamilies.length > 0) {
            notes.push(`Previously unresolved blocker families no longer recur: ${resolvedIssueFamilies.join(', ')}.`);
        }
        if (recurringWorkaroundFailureFamilies.length > 0) {
            notes.push(`Workarounds continued to fail for: ${recurringWorkaroundFailureFamilies.join(', ')}.`);
        }

        return {
            recurringUnresolvedIssueFamilies,
            resolvedIssueFamilies,
            newlyIntroducedIssueFamilies,
            recurringWorkaroundFailureFamilies,
            blockingCountDelta: currentBlocking - previousBlocking,
            degradingCountDelta: currentDegrading - previousDegrading,
            notes,
        };
    }

    private collectRecurringWorkaroundFailureFamilies(
        previousIssues: FocusedInvestigationIssue[],
        currentIssues: FocusedInvestigationIssue[],
    ): FocusedBlockerRecurrenceSummary['recurringWorkaroundFailureFamilies'] {
        const previousFailureFamilies = new Set(
            previousIssues
                .filter((issue) => issue.workaroundAttempts.some((attempt) => attempt.outcome === 'no_change' || attempt.outcome === 'introduced_uncertainty'))
                .map((issue) => issue.issueType),
        );
        return this.uniqueStrings(
            currentIssues
                .filter((issue) => previousFailureFamilies.has(issue.issueType))
                .filter((issue) => issue.workaroundAttempts.some((attempt) => attempt.outcome === 'no_change' || attempt.outcome === 'introduced_uncertainty'))
                .map((issue) => issue.issueType),
        ) as FocusedBlockerRecurrenceSummary['recurringWorkaroundFailureFamilies'];
    }

    private classifyEvidenceDrift(
        previousCase: FocusedTestCase,
        currentCase: FocusedTestCase,
        blockerRecurrence: FocusedBlockerRecurrenceSummary,
    ): FocusedCaseHistoricalCompare['evidenceDriftClassification'] {
        const previousReport = previousCase.latestVerdict?.evidenceSufficiency || null;
        const currentReport = currentCase.latestVerdict?.evidenceSufficiency || null;

        if (!previousReport && !currentReport) {
            return 'unchanged';
        }
        if (currentReport?.state === 'contradictory' && previousReport?.state !== 'contradictory') {
            return 'contradiction_introduced';
        }
        if (
            (currentReport?.state === 'unsupported' && previousReport?.state !== 'unsupported')
            || ((currentReport?.unsupportedRequirements.length || 0) > (previousReport?.unsupportedRequirements.length || 0))
        ) {
            return 'unsupported_gap_introduced';
        }
        if ((currentReport?.underminedByScopeViolation && !previousReport?.underminedByScopeViolation) || blockerRecurrence.blockingCountDelta > 0) {
            return 'scope_risk_increased';
        }
        if (!previousReport && currentReport) {
            return 'stronger_confidence';
        }
        if (previousReport && !currentReport) {
            return 'weaker_confidence';
        }

        const previousScore = this.scoreEvidenceConfidence(previousReport);
        const currentScore = this.scoreEvidenceConfidence(currentReport);
        const delta = currentScore - previousScore;
        if (delta >= 2 || blockerRecurrence.blockingCountDelta < 0 || blockerRecurrence.degradingCountDelta < 0) {
            return 'stronger_confidence';
        }
        if (delta <= -2 || blockerRecurrence.degradingCountDelta > 0) {
            return 'weaker_confidence';
        }
        return 'unchanged';
    }

    private scoreEvidenceConfidence(report: {
        state: 'sufficient' | 'insufficient' | 'contradictory' | 'unsupported';
        supportingEvidenceIds: string[];
        anchoredToTarget: boolean;
        missingRequirements: string[];
        unsupportedRequirements: string[];
        contradictorySignals: string[];
        underminedByScopeViolation: boolean;
    } | null | undefined): number {
        if (!report) {
            return -3;
        }

        const baseScore = report.state === 'sufficient'
            ? 6
            : report.state === 'insufficient'
                ? 2
                : report.state === 'unsupported'
                    ? 0
                    : -1;

        return baseScore
            + Math.min(report.supportingEvidenceIds.length, 3)
            + (report.anchoredToTarget ? 1 : -1)
            - report.missingRequirements.length
            - (report.unsupportedRequirements.length * 2)
            - (report.contradictorySignals.length * 2)
            - (report.underminedByScopeViolation ? 2 : 0);
    }

    private classifyHistoricalOutcome(input: {
        compareStatus: FocusedCaseHistoricalCompare['compareStatus'];
        priorCase: FocusedTestCase | null;
        currentCase: FocusedTestCase;
        evidenceDriftClassification: FocusedCaseHistoricalCompare['evidenceDriftClassification'];
        blockerRecurrence: FocusedBlockerRecurrenceSummary;
    }): FocusedHistoricalOutcome | null {
        if (input.compareStatus === 'baseline_only') {
            return null;
        }
        if (input.compareStatus === 'newly_introduced') {
            return 'newly_introduced';
        }
        if (input.compareStatus === 'not_comparable') {
            return 'not_comparable';
        }

        const priorVerdict = input.priorCase?.latestVerdict?.verdictState || null;
        const currentVerdict = input.currentCase.latestVerdict?.verdictState || null;
        const evidenceDrift = input.evidenceDriftClassification;
        const blockerWorsened = input.blockerRecurrence.blockingCountDelta > 0 || input.blockerRecurrence.degradingCountDelta > 0;
        const blockerImproved = input.blockerRecurrence.blockingCountDelta < 0 || input.blockerRecurrence.degradingCountDelta < 0;

        if (priorVerdict && currentVerdict === 'pass' && priorVerdict !== 'pass') {
            return 'improved';
        }
        if (priorVerdict === 'pass' && currentVerdict !== 'pass') {
            return 'regressed';
        }
        if (currentVerdict === 'fail' && priorVerdict !== 'fail' && priorVerdict !== 'pass') {
            return 'regressed';
        }
        if (!currentVerdict && priorVerdict === 'pass') {
            return 'regressed';
        }
        if (evidenceDrift === 'unsupported_gap_introduced' || evidenceDrift === 'contradiction_introduced' || evidenceDrift === 'scope_risk_increased') {
            return 'weaker_confidence';
        }
        if ((evidenceDrift === 'weaker_confidence' || blockerWorsened) && priorVerdict === currentVerdict) {
            return 'weaker_confidence';
        }
        if ((evidenceDrift === 'stronger_confidence' || blockerImproved) && priorVerdict === currentVerdict) {
            return 'stronger_confidence';
        }
        return 'unchanged';
    }

    private shouldGenerateCaseNarrative(compare: FocusedCaseHistoricalCompare): boolean {
        return compare.compareStatus === 'newly_introduced'
            || compare.compareStatus === 'not_comparable'
            || compare.historicalOutcome === 'improved'
            || compare.historicalOutcome === 'regressed'
            || compare.historicalOutcome === 'weaker_confidence'
            || compare.historicalOutcome === 'stronger_confidence';
    }

    private buildRemovedPriorCases(previousCases: FocusedTestCase[], caseComparisons: FocusedCaseHistoricalCompare[]) {
        const matchedPreviousCaseIds = new Set(
            caseComparisons
                .map((compare) => compare.previousCaseId)
                .filter((entry): entry is string => typeof entry === 'string' && entry.length > 0),
        );

        return previousCases
            .filter((testCase) => !matchedPreviousCaseIds.has(testCase.id))
            .map((testCase) => ({
                previousCaseId: testCase.id,
                title: testCase.title,
                previousVerdict: testCase.latestVerdict?.verdictState || null,
                previousEvidenceSufficiency: testCase.latestVerdict?.evidenceSufficiency?.state || null,
            }));
    }

    private buildStabilityNotes(input: {
        comparisonStatus: FocusedHistoricalCompareStatus;
        improvedCount: number;
        regressedCount: number;
        weakerConfidenceCount: number;
        strongerConfidenceCount: number;
        newlyIntroducedCount: number;
        notComparableCount: number;
        removedPriorCaseCount: number;
        repeatedBlockerFamilies: string[];
        newBlockerFamilies: string[];
        resolvedBlockerFamilies: string[];
        unstableCases: string[];
    }): string[] {
        if (input.comparisonStatus === 'baseline_created') {
            return ['Baseline created from the first observed scoped run for this lineage.'];
        }
        if (input.comparisonStatus === 'comparison_unavailable') {
            return ['Historical comparison is unavailable until scoped verdict data exists for this run.'];
        }
        if (input.comparisonStatus === 'not_comparable') {
            return ['No prior scoped run was comparable enough to support deterministic historical comparison.'];
        }

        const notes: string[] = [];
        if (input.improvedCount > 0) {
            notes.push(`${input.improvedCount} case(s) improved versus the previous comparable run.`);
        }
        if (input.regressedCount > 0) {
            notes.push(`${input.regressedCount} case(s) regressed versus the previous comparable run.`);
        }
        if (input.weakerConfidenceCount > 0) {
            notes.push(`${input.weakerConfidenceCount} case(s) kept a similar outcome but lost evidence confidence.`);
        }
        if (input.strongerConfidenceCount > 0) {
            notes.push(`${input.strongerConfidenceCount} case(s) kept a similar outcome with stronger evidence confidence.`);
        }
        if (input.newlyIntroducedCount > 0) {
            notes.push(`${input.newlyIntroducedCount} case(s) were newly introduced in the current scoped plan.`);
        }
        if (input.removedPriorCaseCount > 0) {
            notes.push(`${input.removedPriorCaseCount} prior case(s) were not present in the current scoped plan.`);
        }
        if (input.notComparableCount > 0) {
            notes.push(`${input.notComparableCount} case(s) did not have a safe historical match.`);
        }
        if (input.repeatedBlockerFamilies.length > 0) {
            notes.push(`Repeated unresolved blocker families: ${input.repeatedBlockerFamilies.join(', ')}.`);
        }
        if (input.newBlockerFamilies.length > 0) {
            notes.push(`New blocker families were introduced: ${input.newBlockerFamilies.join(', ')}.`);
        }
        if (input.resolvedBlockerFamilies.length > 0) {
            notes.push(`Previously recurring blockers resolved for: ${input.resolvedBlockerFamilies.join(', ')}.`);
        }
        if (input.unstableCases.length > 0) {
            notes.push(`${this.uniqueStrings(input.unstableCases).length} case(s) show instability or require manual review.`);
        }

        return notes;
    }

    private computeLatestFactTimestamp(
        focusedTestCases: FocusedTestCase[],
        focusedVerdictSummary: FocusedScanVerdictSummary | null,
        focusedBlockerSummary: FocusedScanBlockerSummary | null,
    ): string | null {
        const timestamps = [
            focusedVerdictSummary?.updatedAt,
            focusedVerdictSummary?.latestVerdictAt,
            focusedBlockerSummary?.updatedAt,
            ...focusedTestCases.flatMap((testCase) => [
                testCase.updatedAt || null,
                testCase.latestVerdict?.updatedAt || null,
                testCase.latestVerdict?.verdictAt || null,
                testCase.investigationSummary?.latestDetectedAt || null,
            ]),
        ].filter((entry): entry is string => typeof entry === 'string' && entry.length > 0);

        return timestamps.sort((left, right) => right.localeCompare(left))[0] || null;
    }

    private persistCompareArtifacts(
        scanId: string,
        state: FocusedHistoricalCompareState,
        caseComparisons: FocusedCaseHistoricalCompare[],
        summary: FocusedHistoricalCompareSummary | null,
    ): void {
        this.deps.database.transaction(() => {
            this.deps.database.prepare('DELETE FROM focused_test_case_historical_compares WHERE current_scan_id = ?').run(scanId);
            this.deps.database.prepare('DELETE FROM focused_scan_historical_compare_summaries WHERE scan_id = ?').run(scanId);
            this.deps.database.prepare('DELETE FROM focused_scan_historical_compare_states WHERE scan_id = ?').run(scanId);

            upsertFocusedHistoricalCompareState(state);
            for (const compare of caseComparisons) {
                upsertFocusedCaseHistoricalCompare(compare);
            }
            if (summary) {
                upsertFocusedHistoricalCompareSummary(summary);
            }
        })();
    }

    private computeTargetOrigin(target: string, scopeEnvelope: ScopeEnvelope): string {
        const candidates = [
            target,
            ...scopeEnvelope.selectedEndpoints.flatMap((entry) => [entry.url, entry.host]),
            ...scopeEnvelope.baselineRequestRefs.flatMap((entry) => [entry.url, entry.host]),
        ];

        for (const candidate of candidates) {
            const normalized = this.normalizeOrigin(candidate);
            if (normalized) {
                return normalized;
            }
        }

        return this.normalizeText(target) || 'unknown_target';
    }

    private computeScopeIdentityKey(
        targetOrigin: string,
        objective: FocusedTestObjective,
        scopeEnvelope: ScopeEnvelope,
    ): string {
        const selectedEndpointAnchors = this.uniqueStrings(scopeEnvelope.selectedEndpoints.map((entry) => [
            String(entry.method || '').trim().toUpperCase() || 'GET',
            this.normalizeRoutePath(entry.path || entry.url || null) || '/',
        ].join(':'))).sort();
        const baselineRequestAnchors = this.uniqueStrings(scopeEnvelope.baselineRequestRefs.map((entry) => [
            String(entry.method || '').trim().toUpperCase() || 'GET',
            this.normalizeRoutePath(entry.path || entry.url || null) || '/',
        ].join(':'))).sort();
        const allowedRoutes = this.uniqueStrings(scopeEnvelope.allowedRoutes.map((entry) => this.normalizeRoutePath(entry) || '/')).sort();
        const allowedHosts = this.uniqueStrings(scopeEnvelope.allowedHosts.map((entry) => this.normalizeHost(entry))).sort();
        const featureText = objective.scopeType === 'flow_scoped' || objective.scopeType === 'feature_scoped'
            ? this.normalizeText([objective.title, objective.featureDescription, objective.goal].filter(Boolean).join(' '))
            : null;

        return JSON.stringify({
            targetOrigin,
            scopeType: objective.scopeType,
            selectedEndpointAnchors,
            baselineRequestAnchors,
            allowedRoutes,
            allowedHosts,
            featureText,
        });
    }

    private normalizeOrigin(value?: string | null): string | null {
        if (!value) {
            return null;
        }

        const trimmed = String(value).trim();
        if (!trimmed) {
            return null;
        }

        try {
            const url = trimmed.includes('://')
                ? new URL(trimmed)
                : new URL(`https://${trimmed.replace(/^\/+/, '')}`);
            if (url.hostname) {
                return `${url.protocol}//${url.hostname.toLowerCase()}${url.port ? `:${url.port}` : ''}`;
            }
        } catch {
            return this.normalizeHost(trimmed) || this.normalizeText(trimmed);
        }

        return null;
    }

    private normalizeHost(value?: string | null): string {
        if (!value) {
            return '';
        }

        const trimmed = String(value).trim().toLowerCase();
        if (!trimmed) {
            return '';
        }

        try {
            return new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`).host.toLowerCase();
        } catch {
            return trimmed.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        }
    }

    private normalizeRoutePath(value?: string | null): string | null {
        if (!value) {
            return null;
        }

        try {
            return new URL(value).pathname || '/';
        } catch {
            const withoutQuery = String(value).split('?')[0]?.split('#')[0]?.trim();
            if (!withoutQuery) {
                return null;
            }
            return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
        }
    }

    private normalizeText(value?: string | null): string {
        return String(value || '')
            .trim()
            .toLowerCase()
            .replace(/[^a-z0-9/_\-\s]+/g, ' ')
            .replace(/\s+/g, ' ');
    }

    private extractTokens(value: string): string[] {
        return this.uniqueStrings(
            this.normalizeText(value)
                .split(' ')
                .map((entry) => entry.trim())
                .filter((entry) => entry.length >= 3),
        );
    }

    private uniqueStrings(values: string[]): string[] {
        return [...new Set(values.filter((entry) => typeof entry === 'string' && entry.trim().length > 0))];
    }
}

export const focusedHistoricalCompareService = new FocusedHistoricalCompareService();
