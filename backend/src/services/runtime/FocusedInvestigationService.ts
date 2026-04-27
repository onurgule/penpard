import { v4 as uuidv4 } from 'uuid';
import {
    createFocusedInvestigationIssue,
    getFocusedCaseInvestigationSummaryByCase,
    getFocusedCaseVerdictByExecution,
    getFocusedScanBlockerSummary,
    getFocusedTestCaseById,
    getFocusedTestCaseExecutionById,
    getFocusedTestObjective,
    getScan,
    getScopeEnvelope,
    listEvidenceBundlesByExecution,
    listFocusedExecutionTraceEntriesByExecution,
    listFocusedInvestigationIssuesByExecution,
    listFocusedInvestigationIssuesByScan,
    upsertFocusedScanBlockerSummary,
    updateFocusedInvestigationIssue,
} from '../../db/init';
import {
    focusedInvestigationAssistanceProfileResolver,
    type FocusedInvestigationAssistanceProfileResolver,
} from './FocusedInvestigationProfiles';
import { focusedReasoningTraceService } from './FocusedReasoningTraceService';
import type {
    FocusedCaseInvestigationSummary,
    FocusedCaseVerdict,
    FocusedInvestigationCorrelation,
    FocusedInvestigationImpact,
    FocusedInvestigationIssue,
    FocusedInvestigationIssueStatus,
    FocusedInvestigationIssueType,
    FocusedScanBlockerSummary,
    FocusedTestCase,
    FocusedTestCaseExecution,
    FocusedWorkaroundAttempt,
} from './ScopedScanTypes';
import {
    buildFocusedRailUsageSummary,
    createEmptyFocusedInvestigationImpactCounts,
    createEmptyFocusedInvestigationStatusCounts,
    createEmptyFocusedInvestigationTypeCounts,
    isFocusedInvestigationIssueUnresolved,
    normalizeFocusedInvestigationImpact,
    normalizeFocusedInvestigationIssueStatus,
} from './ScopedScanTypes';
import { resolveFocusedCaseFamily } from './FocusedSignalInterpreter';

export interface FocusedInvestigationObservation {
    issueType: FocusedInvestigationIssueType;
    issueTitle: string;
    issueDetails?: string | null;
    issueStatus?: FocusedInvestigationIssueStatus;
    impact?: FocusedInvestigationImpact;
    source?: FocusedInvestigationIssue['source'];
    correlation?: FocusedInvestigationCorrelation | null;
    linkedEvidenceIds?: string[];
    linkedVerdictIds?: string[];
    workaroundAttempts?: FocusedWorkaroundAttempt[];
    expertFollowupHint?: string | null;
    assistanceSummary?: string | null;
    resolvedAt?: string | null;
}

interface RecordObservationInput {
    scanId: string;
    caseId: string;
    executionId: string;
    objectiveId: string;
    userId?: number;
    observations: FocusedInvestigationObservation[];
    verdict?: FocusedCaseVerdict | null;
    applyAssistance?: boolean;
}

interface InvestigationDependencies {
    profileResolver: FocusedInvestigationAssistanceProfileResolver;
    now: () => string;
    createId: () => string;
}

const IMPACT_RANK: Record<FocusedInvestigationImpact, number> = {
    informational: 0,
    degrading: 1,
    blocking: 2,
};

export class FocusedInvestigationService {
    private readonly deps: InvestigationDependencies;

    constructor(
        deps: Partial<InvestigationDependencies> = {},
    ) {
        this.deps = {
            profileResolver: focusedInvestigationAssistanceProfileResolver,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public async recordExecutionObservations(input: RecordObservationInput): Promise<FocusedInvestigationIssue[]> {
        const issues = await this.recordObservations(input);
        await this.summarizeScanBlockers(input.scanId, input.userId);
        return issues;
    }

    public async recordVerdictObservations(input: RecordObservationInput): Promise<FocusedInvestigationIssue[]> {
        const issues = await this.recordObservations(input);
        await this.summarizeScanBlockers(input.scanId, input.userId);
        return issues;
    }

    public async finalizeExecutionIssues(
        scanId: string,
        caseId: string,
        executionId: string,
        userId?: number,
    ): Promise<FocusedInvestigationIssue[]> {
        const issues = listFocusedInvestigationIssuesByExecution(scanId, caseId, executionId);

        for (const issue of issues) {
            if (issue.issueStatus === 'open') {
                updateFocusedInvestigationIssue(scanId, caseId, issue.id, {
                    issueStatus: 'unresolved',
                    resolvedAt: null,
                });
            }
        }

        const updated = listFocusedInvestigationIssuesByExecution(scanId, caseId, executionId);
        await this.summarizeScanBlockers(scanId, userId);
        return updated;
    }

    public buildCaseInvestigationSummary(scanId: string, caseId: string): FocusedCaseInvestigationSummary | null {
        return getFocusedCaseInvestigationSummaryByCase(scanId, caseId);
    }

    public async summarizeScanBlockers(scanId: string, userId?: number): Promise<FocusedScanBlockerSummary | null> {
        const objective = getFocusedTestObjective(scanId);
        if (!objective) {
            return getFocusedScanBlockerSummary(scanId);
        }

        const allIssues = listFocusedInvestigationIssuesByScan(scanId);
        const unresolvedIssues = allIssues.filter((issue) => isFocusedInvestigationIssueUnresolved(issue.issueStatus));
        const countsByStatus = createEmptyFocusedInvestigationStatusCounts();
        const countsByImpact = createEmptyFocusedInvestigationImpactCounts();
        const unresolvedByType = createEmptyFocusedInvestigationTypeCounts();

        for (const issue of allIssues) {
            countsByStatus[issue.issueStatus] += 1;
        }
        for (const issue of unresolvedIssues) {
            countsByImpact[issue.impact] += 1;
            unresolvedByType[issue.issueType] += 1;
        }

        const repeatedBlockers = Object.entries(unresolvedByType)
            .filter(([, count]) => count > 1)
            .map(([issueType, count]) => `${this.formatIssueType(issueType as FocusedInvestigationIssueType)} repeated across ${count} issue(s).`);

        const casesNeedingReview = [...new Set(unresolvedIssues.map((issue) => issue.caseId))];
        const latestMajorBlockerSummary = await this.buildLatestMajorBlockerSummary({
            scanId,
            userId,
            objective,
            unresolvedIssues,
            draftSummary: {
                scanId,
                objectiveId: objective.id,
                countsByStatus,
                countsByImpact,
                unresolvedByType,
                repeatedBlockers,
                casesNeedingReview,
                latestMajorBlockerSummary: null,
            },
        });

        return upsertFocusedScanBlockerSummary({
            scanId,
            objectiveId: objective.id,
            countsByStatus,
            countsByImpact,
            unresolvedByType,
            repeatedBlockers,
            casesNeedingReview,
            latestMajorBlockerSummary,
        });
    }

    private async recordObservations(input: RecordObservationInput): Promise<FocusedInvestigationIssue[]> {
        const scan = getScan(input.scanId);
        const testCase = getFocusedTestCaseById(input.scanId, input.caseId);
        const execution = getFocusedTestCaseExecutionById(input.scanId, input.caseId, input.executionId);
        if (!scan || !testCase || !execution || input.observations.length === 0) {
            return [];
        }

        const existingIssues = listFocusedInvestigationIssuesByExecution(input.scanId, input.caseId, input.executionId);
        const objective = getFocusedTestObjective(input.scanId);
        const scopeEnvelope = getScopeEnvelope(input.scanId);
        const evidenceBundles = listEvidenceBundlesByExecution(input.scanId, input.caseId, input.executionId);
        const verdict = input.verdict || getFocusedCaseVerdictByExecution(input.scanId, input.caseId, input.executionId);
        const executionTrace = listFocusedExecutionTraceEntriesByExecution(input.scanId, input.caseId, input.executionId);
        const latestTraceEntry = executionTrace.length > 0 ? executionTrace[executionTrace.length - 1] : null;
        const railSummary = buildFocusedRailUsageSummary({
            requestActionsUsed: execution.requestActionsUsed,
            browserActionsUsed: execution.browserActionsUsed,
            traceCount: executionTrace.length,
        });
        const caseFamily = verdict?.interpretationSummary?.caseFamily
            || (objective ? resolveFocusedCaseFamily(objective, testCase) : 'generic');
        const profile = this.deps.profileResolver.resolve(input.userId ?? scan.user_id);
        const persistedIssues: FocusedInvestigationIssue[] = [];

        for (const observation of input.observations) {
            const matching = existingIssues.find((issue) => (
                issue.issueType === observation.issueType
                && issue.issueTitle === observation.issueTitle
            ));
            const enrichedObservation: FocusedInvestigationObservation = {
                ...observation,
                correlation: {
                    ...(observation.correlation || {}),
                    caseFamily,
                    executionRail: railSummary.rail,
                    railSummary: railSummary.summary,
                    traceActionTypes: executionTrace.map((entry) => entry.actionType),
                    latestTraceSummary: latestTraceEntry?.actionSummary || null,
                    latestTraceReasoning: latestTraceEntry?.reasoningNote || latestTraceEntry?.nextStepRationale || null,
                },
            };
            const merged = this.mergeObservation(matching, enrichedObservation, {
                scanId: input.scanId,
                caseId: input.caseId,
                executionId: input.executionId,
                objectiveId: input.objectiveId,
            });

            if (
                objective
                && input.applyAssistance !== false
                && merged.source !== 'operator'
                && merged.impact !== 'informational'
                && (!merged.assistanceSummary || !merged.expertFollowupHint)
            ) {
                const assistance = await profile.enhanceIssue({
                    scanId: input.scanId,
                    userId: input.userId ?? scan.user_id,
                    objective,
                    scopeEnvelope,
                    testCase,
                    execution,
                    evidenceBundles,
                    verdict,
                    issue: merged,
                });

                if (assistance.assistanceSummary && !merged.assistanceSummary) {
                    merged.assistanceSummary = assistance.assistanceSummary;
                }
                if (assistance.expertFollowupHint && !merged.expertFollowupHint) {
                    merged.expertFollowupHint = assistance.expertFollowupHint;
                }
                if (assistance.assistanceSummary || assistance.expertFollowupHint) {
                    merged.assistanceProfileKey = profile.key;
                    merged.assistanceProvider = profile.provider;
                    merged.assistanceModel = profile.model;
                }
            }

            const saved = matching
                ? updateFocusedInvestigationIssue(input.scanId, input.caseId, matching.id, merged)
                : (createFocusedInvestigationIssue(merged), merged);
            const persisted = saved || merged;
            persistedIssues.push(persisted);
            focusedReasoningTraceService.record({
                scanId: input.scanId,
                objectiveId: input.objectiveId,
                caseId: input.caseId,
                executionId: input.executionId,
                stage: 'investigation',
                entryType: persisted.impact === 'blocking' || persisted.issueStatus === 'unresolved'
                    ? 'constraint'
                    : 'result',
                rail: persisted.correlation?.executionRail === 'request'
                    ? 'request'
                    : persisted.correlation?.executionRail === 'browser'
                        ? 'browser'
                        : persisted.correlation?.executionRail === 'hybrid'
                            ? 'hybrid'
                            : 'system_only',
                caseFamily: persisted.correlation?.caseFamily || null,
                summary: persisted.issueTitle,
                observationSummary: persisted.issueDetails || null,
                confidenceShiftSummary: persisted.assistanceSummary || persisted.correlation?.latestTraceReasoning || null,
                stopRetryBlockRationale: persisted.impact === 'blocking' || persisted.issueStatus === 'unresolved'
                    ? persisted.issueTitle
                    : null,
                linkedEvidenceIds: persisted.linkedEvidenceIds,
            });

            const index = existingIssues.findIndex((issue) => issue.id === persisted.id);
            if (index >= 0) {
                existingIssues[index] = persisted;
            } else {
                existingIssues.push(persisted);
            }
        }

        return persistedIssues;
    }

    private mergeObservation(
        existing: FocusedInvestigationIssue | undefined,
        observation: FocusedInvestigationObservation,
        identity: {
            scanId: string;
            caseId: string;
            executionId: string;
            objectiveId: string;
        },
    ): FocusedInvestigationIssue {
        const status = normalizeFocusedInvestigationIssueStatus(observation.issueStatus ?? existing?.issueStatus ?? 'open');
        const impact = this.maxImpact(existing?.impact, observation.impact);
        const resolvedAt = status === 'resolved' || status === 'not_applicable'
            ? (observation.resolvedAt ?? existing?.resolvedAt ?? this.deps.now())
            : null;

        return {
            id: existing?.id || this.deps.createId(),
            scanId: identity.scanId,
            caseId: identity.caseId,
            executionId: identity.executionId,
            objectiveId: identity.objectiveId,
            issueType: observation.issueType,
            issueTitle: observation.issueTitle,
            issueDetails: observation.issueDetails ?? existing?.issueDetails ?? null,
            issueStatus: status,
            impact,
            source: observation.source || existing?.source || 'system',
            correlation: this.mergeCorrelation(existing?.correlation || null, observation.correlation || null),
            linkedEvidenceIds: this.dedupeStrings([...(existing?.linkedEvidenceIds || []), ...(observation.linkedEvidenceIds || [])]),
            linkedVerdictIds: this.dedupeStrings([...(existing?.linkedVerdictIds || []), ...(observation.linkedVerdictIds || [])]),
            workaroundAttempts: this.mergeWorkaroundAttempts(existing?.workaroundAttempts || [], observation.workaroundAttempts || []),
            expertFollowupHint: observation.expertFollowupHint ?? existing?.expertFollowupHint ?? null,
            assistanceSummary: observation.assistanceSummary ?? existing?.assistanceSummary ?? null,
            assistanceProfileKey: existing?.assistanceProfileKey ?? null,
            assistanceProvider: existing?.assistanceProvider ?? null,
            assistanceModel: existing?.assistanceModel ?? null,
            detectedAt: existing?.detectedAt || this.deps.now(),
            resolvedAt,
        };
    }

    private mergeCorrelation(
        existing: FocusedInvestigationCorrelation | null,
        incoming: FocusedInvestigationCorrelation | null,
    ): FocusedInvestigationCorrelation | null {
        if (!existing && !incoming) {
            return null;
        }

        return {
            ...existing,
            ...incoming,
            evidenceSources: this.dedupeStrings([...(existing?.evidenceSources || []), ...(incoming?.evidenceSources || [])]) as any,
            scopeViolationKinds: this.dedupeStrings([...(existing?.scopeViolationKinds || []), ...(incoming?.scopeViolationKinds || [])]) as any,
            traceActionTypes: this.dedupeStrings([...(existing?.traceActionTypes || []), ...(incoming?.traceActionTypes || [])]) as any,
        };
    }

    private mergeWorkaroundAttempts(
        existing: FocusedWorkaroundAttempt[],
        incoming: FocusedWorkaroundAttempt[],
    ): FocusedWorkaroundAttempt[] {
        const merged = [...existing];

        for (const attempt of incoming) {
            const normalized: FocusedWorkaroundAttempt = {
                attemptedAt: attempt.attemptedAt || this.deps.now(),
                summary: String(attempt.summary || '').trim(),
                outcome: attempt.outcome || 'no_change',
                details: attempt.details ?? null,
                linkedEvidenceIds: this.dedupeStrings(attempt.linkedEvidenceIds || []),
                linkedVerdictIds: this.dedupeStrings(attempt.linkedVerdictIds || []),
            };
            if (!normalized.summary) {
                continue;
            }

            const exists = merged.some((entry) => (
                entry.attemptedAt === normalized.attemptedAt
                && entry.summary === normalized.summary
                && entry.outcome === normalized.outcome
            ));
            if (!exists) {
                merged.push(normalized);
            }
        }

        return merged;
    }

    private maxImpact(
        left: FocusedInvestigationImpact | undefined,
        right: FocusedInvestigationImpact | undefined,
    ): FocusedInvestigationImpact {
        const normalizedLeft = normalizeFocusedInvestigationImpact(left);
        const normalizedRight = normalizeFocusedInvestigationImpact(right);
        return IMPACT_RANK[normalizedRight] > IMPACT_RANK[normalizedLeft]
            ? normalizedRight
            : normalizedLeft;
    }

    private dedupeStrings(values: string[]): string[] {
        return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.trim().length > 0))];
    }

    private formatIssueType(issueType: FocusedInvestigationIssueType): string {
        switch (issueType) {
            case 'scope_violation':
                return 'Scope violation';
            case 'auth_session_drift':
                return 'Auth/session drift';
            case 'missing_anchor':
                return 'Missing anchor';
            case 'browser_state_mismatch':
                return 'Browser state mismatch';
            case 'evidence_insufficient':
                return 'Evidence insufficiency';
            case 'execution_budget_exhausted':
                return 'Execution budget exhaustion';
            case 'request_replay_mismatch':
                return 'Request replay mismatch';
            case 'unexpected_navigation':
                return 'Unexpected navigation';
            case 'unsupported_verification_primitive':
                return 'Unsupported verification primitive';
            case 'environment_instability':
                return 'Environment instability';
            case 'contradictory_signals':
                return 'Contradictory signals';
            case 'retry_failure':
                return 'Retry failure';
            default:
                return 'Blocked flow';
        }
    }

    private async buildLatestMajorBlockerSummary(input: {
        scanId: string;
        userId?: number;
        objective: NonNullable<ReturnType<typeof getFocusedTestObjective>>;
        unresolvedIssues: FocusedInvestigationIssue[];
        draftSummary: Omit<FocusedScanBlockerSummary, 'createdAt' | 'updatedAt'>;
    }): Promise<string | null> {
        if (input.unresolvedIssues.length === 0) {
            return null;
        }

        const rankedIssues = [...input.unresolvedIssues].sort((left, right) => {
            const rankDiff = IMPACT_RANK[right.impact] - IMPACT_RANK[left.impact];
            if (rankDiff !== 0) {
                return rankDiff;
            }
            const leftTs = left.detectedAt || left.createdAt || '';
            const rightTs = right.detectedAt || right.createdAt || '';
            return rightTs.localeCompare(leftTs);
        });
        const highestPriorityIssue = rankedIssues[0];
        const fallback = highestPriorityIssue.assistanceSummary
            || highestPriorityIssue.expertFollowupHint
            || highestPriorityIssue.issueDetails
            || highestPriorityIssue.issueTitle;

        const profile = this.deps.profileResolver.resolve(input.userId);
        const headline = await profile.summarizeBlockers({
            scanId: input.scanId,
            userId: input.userId,
            objective: input.objective,
            blockerSummary: input.draftSummary,
            unresolvedIssues: rankedIssues,
        });

        return headline || fallback || null;
    }
}

export const focusedInvestigationService = new FocusedInvestigationService();
