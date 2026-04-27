import { v4 as uuidv4 } from 'uuid';
import { Database as DatabaseType } from 'better-sqlite3';
import {
    db,
    getFocusedTestObjective,
    getScan,
    getScopedFeatureDiscoveryState,
    getScopeEnvelope,
    listFocusedTestCasesByScan,
    replaceFocusedTestCasesByScan,
    updateScanStatus,
} from '../../db/init';
import { logger } from '../../utils/logger';
import { ContextPackBuilder, contextPackBuilder } from './ContextPackBuilder';
import { FocusedTestPlanner, focusedTestPlanner } from './FocusedTestPlanner';
import { buildFocusedContextInfluence, focusedReasoningTraceService } from './FocusedReasoningTraceService';
import type {
    FocusedConfirmationKind,
    FocusedPlanSummary,
    FocusedTestCase,
    FocusedTestCaseDraft,
} from './ScopedScanTypes';
import {
    buildFocusedPlanSummary,
    normalizeFocusedTestCasePriority,
    normalizeFocusedTestCaseReviewState,
    normalizeFocusedTestCaseStatus,
    normalizeFocusedExecutionRail,
    normalizeScanMode,
} from './ScopedScanTypes';
import { resolveFocusedCaseFamily } from './FocusedSignalInterpreter';

interface FocusedPlanningResult {
    scanId: string;
    focusedTestCases: FocusedTestCase[];
    focusedPlanSummary: FocusedPlanSummary;
}

export interface FocusedPlanningOptions {
    reviewMode?: 'auto' | 'legacy';
}

interface FocusedPlanningDependencies {
    database: DatabaseType;
    contextPackBuilder: ContextPackBuilder;
    planner: FocusedTestPlanner;
}

export class FocusedPlanningPreconditionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'FocusedPlanningPreconditionError';
    }
}

export class FocusedPlanningService {
    private readonly activePlans = new Map<string, Promise<FocusedPlanningResult>>();

    constructor(
        private readonly deps: FocusedPlanningDependencies = {
            database: db,
            contextPackBuilder,
            planner: focusedTestPlanner,
        },
    ) {}

    public launchPlanning(scanId: string): void {
        void this.planNow(scanId, { reviewMode: 'legacy' }).catch((error: any) => {
            logger.error('Scoped planning job failed', {
                scanId,
                error: error.message,
            });
        });
    }

    public planNow(scanId: string, options: FocusedPlanningOptions = {}): Promise<FocusedPlanningResult> {
        const existing = this.activePlans.get(scanId);
        if (existing) {
            return existing;
        }

        const pending = this.executePlanning(scanId, options)
            .finally(() => {
                this.activePlans.delete(scanId);
            });

        this.activePlans.set(scanId, pending);
        return pending;
    }

    private async executePlanning(scanId: string, options: FocusedPlanningOptions = {}): Promise<FocusedPlanningResult> {
        const scan = getScan(scanId);
        if (!scan) {
            throw new Error(`Scoped planning could not find scan ${scanId}.`);
        }
        if (normalizeScanMode(scan.scan_mode) !== 'scoped') {
            throw new Error('Focused planning is only available for scoped scans.');
        }

        const discoveryState = getScopedFeatureDiscoveryState(scanId);
        if (discoveryState) {
            if (discoveryState.phase === 'discovering' || discoveryState.phase === 'not_started') {
                throw new FocusedPlanningPreconditionError('Feature anchoring is still running. Planning will start automatically when discovery is ready.');
            }
            if (discoveryState.phase === 'blocked') {
                throw new FocusedPlanningPreconditionError(discoveryState.summary || 'Feature anchoring did not find enough anchors to start planning.');
            }
        }

        const reviewMode = options.reviewMode === 'legacy' ? 'legacy' : 'auto';
        const defaultReviewState = reviewMode === 'legacy' ? 'pending_review' : 'approved';

        this.markPlanning(scanId);

        try {
            const objective = getFocusedTestObjective(scanId);
            const envelope = getScopeEnvelope(scanId);
            if (!objective || !envelope) {
                throw new Error('Scoped planning requires a persisted focused objective and scope envelope.');
            }

            const contextPack = await this.deps.contextPackBuilder.build(scanId);
            const planned = await this.deps.planner.plan(contextPack, scan.user_id);
            const focusedTestCases = planned.cases.map((draft) => this.materializeFocusedTestCase(
                scanId,
                objective,
                draft,
                defaultReviewState,
            ));
            const planningContextInfluence = buildPlanningContextInfluence(contextPack.supportingContext.securityTestRequest);

            this.deps.database.transaction(() => {
                replaceFocusedTestCasesByScan(scanId, focusedTestCases);
                if (reviewMode === 'legacy') {
                    updateScanStatus(scanId, 'awaiting_review');
                }
            })();
            focusedReasoningTraceService.record({
                scanId,
                objectiveId: objective.id,
                stage: 'planning',
                entryType: 'decision',
                rail: 'system_only',
                summary: reviewMode === 'legacy'
                    ? `Focused planning persisted ${focusedTestCases.length} bounded test case(s) for operator review.`
                    : `Focused planning persisted ${focusedTestCases.length} bounded hypothesis hint(s) and marked runnable cases for immediate scoped execution.`,
                observationSummary: [
                    contextPack.selectedTargets.length > 0
                        ? `${contextPack.selectedTargets.length} selected target(s) were available to the planner.`
                        : null,
                    contextPack.scope.outOfScopeNotes.length > 0
                        ? `${contextPack.scope.outOfScopeNotes.length} out-of-scope note(s) remained active during planning.`
                        : null,
                ].filter((entry): entry is string => !!entry).join(' | ') || 'Planning stayed inside the persisted scope envelope and selected targets.',
                actionSelectionRationale: reviewMode === 'legacy'
                    ? 'Only persisted anchors, scope notes, and structured request context were used to plan bounded cases for review.'
                    : 'Only persisted anchors, scope notes, and structured request context were used to plan bounded cases, and the resulting hints stay internal to the live scoped mission loop.',
                linkedRequestContextKeys: planningContextInfluence.map((entry) => entry.field),
                contextInfluence: planningContextInfluence,
            });
            for (const testCase of focusedTestCases) {
                focusedReasoningTraceService.record({
                    scanId,
                    objectiveId: objective.id,
                    caseId: testCase.id,
                    stage: 'planning',
                    entryType: 'hypothesis',
                    rail: 'system_only',
                    caseFamily: resolveFocusedCaseFamily(objective, testCase),
                    summary: `Planned bounded case: ${testCase.title}`,
                    observationSummary: testCase.hypothesis,
                    hypothesisRationaleSummary: testCase.plannerRationaleSummary,
                    actionSelectionRationale: 'This case was retained because it stays inside the approved scope and targets a persisted anchor or feature description.',
                    linkedRequestContextKeys: planningContextInfluence.map((entry) => entry.field),
                    contextInfluence: planningContextInfluence,
                });
            }

            logger.info('Scoped planning completed', {
                scanId,
                cases: focusedTestCases.length,
                scopeType: objective.scopeType,
            });

            return {
                scanId,
                focusedTestCases,
                focusedPlanSummary: buildFocusedPlanSummary(focusedTestCases),
            };
        } catch (error: any) {
            if (error instanceof FocusedPlanningPreconditionError) {
                throw error;
            }
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        }
    }

    private markPlanning(scanId: string): void {
        this.deps.database.prepare(`
            UPDATE scans
            SET status = ?, error_message = NULL, completed_at = NULL
            WHERE id = ?
        `).run('planning', scanId);
    }

    private materializeFocusedTestCase(
        scanId: string,
        objective: import('./ScopedScanTypes').FocusedTestObjective,
        draft: FocusedTestCaseDraft,
        defaultReviewState: import('./ScopedScanTypes').FocusedTestCaseReviewState,
    ): FocusedTestCase {
        const caseFamily = draft.caseFamily || resolveFocusedCaseFamily(objective, {
            assertions: draft.assertions,
            requiredEvidence: draft.requiredEvidence,
            targetArtifact: draft.targetArtifact,
            title: draft.title,
            hypothesis: draft.hypothesis,
        } as any);
        const adaptiveHints = this.buildAdaptiveHints(caseFamily, draft.targetArtifact.kind);
        return {
            id: uuidv4(),
            scanId,
            objectiveId: objective.id,
            title: draft.title,
            hypothesis: draft.hypothesis,
            targetArtifact: draft.targetArtifact,
            preconditions: draft.preconditions,
            steps: draft.steps,
            assertions: draft.assertions,
            requiredEvidence: draft.requiredEvidence,
            priority: normalizeFocusedTestCasePriority(draft.priority),
            plannerRationaleSummary: draft.plannerRationaleSummary,
            caseFamily,
            maxAdaptiveFollowUps: draft.maxAdaptiveFollowUps ?? adaptiveHints.maxAdaptiveFollowUps,
            preferredRail: normalizeFocusedExecutionRail(draft.preferredRail ?? adaptiveHints.preferredRail),
            allowedConfirmationKinds: draft.allowedConfirmationKinds?.length
                ? draft.allowedConfirmationKinds
                : adaptiveHints.allowedConfirmationKinds,
            status: normalizeFocusedTestCaseStatus(draft.status),
            reviewState: normalizeFocusedTestCaseReviewState(draft.reviewState, defaultReviewState),
        };
    }

    private buildAdaptiveHints(
        caseFamily: import('./ScopedScanTypes').FocusedCaseFamily,
        targetKind: FocusedTestCaseDraft['targetArtifact']['kind'],
    ): {
        maxAdaptiveFollowUps: number;
        preferredRail: import('./ScopedScanTypes').FocusedExecutionRail;
        allowedConfirmationKinds: FocusedConfirmationKind[];
    } {
        switch (caseFamily) {
            case 'sqli':
                return {
                    maxAdaptiveFollowUps: 1,
                    preferredRail: 'request',
                    allowedConfirmationKinds: ['repeat_mutation', 'error_surface_compare'],
                };
            case 'xss':
                return {
                    maxAdaptiveFollowUps: 2,
                    preferredRail: targetKind === 'feature' || targetKind === 'flow' ? 'browser' : 'hybrid',
                    allowedConfirmationKinds: ['render_check', 'control_contrast'],
                };
            case 'access_control':
                return {
                    maxAdaptiveFollowUps: 1,
                    preferredRail: 'request',
                    allowedConfirmationKinds: ['alternate_id_compare', 'control_contrast'],
                };
            case 'workflow_logic':
                return {
                    maxAdaptiveFollowUps: 2,
                    preferredRail: targetKind === 'endpoint' || targetKind === 'baseline_request' ? 'hybrid' : 'browser',
                    allowedConfirmationKinds: ['state_replay', 'control_contrast'],
                };
            case 'error_handling':
                return {
                    maxAdaptiveFollowUps: 1,
                    preferredRail: 'request',
                    allowedConfirmationKinds: ['error_surface_compare', 'repeat_mutation'],
                };
            case 'input_validation':
                return {
                    maxAdaptiveFollowUps: 1,
                    preferredRail: 'request',
                    allowedConfirmationKinds: ['control_contrast', 'error_surface_compare'],
                };
            default:
                return {
                    maxAdaptiveFollowUps: 1,
                    preferredRail: targetKind === 'feature' || targetKind === 'flow' ? 'hybrid' : 'request',
                    allowedConfirmationKinds: ['control_contrast', 'repeat_mutation'],
                };
        }
    }
}

export function listFocusedPlanningResult(scanId: string): FocusedPlanningResult {
    const focusedTestCases = listFocusedTestCasesByScan(scanId);
    return {
        scanId,
        focusedTestCases,
        focusedPlanSummary: buildFocusedPlanSummary(focusedTestCases),
    };
}

function buildPlanningContextInfluence(
    request: import('./ScopedScanTypes').StructuredSecurityTestRequest | undefined,
) {
    if (!request) {
        return [];
    }

    return [
        ...(request.testData.length > 0 ? [buildFocusedContextInfluence(
            'testData',
            'used',
            'Test data was passed into planning so bounded cases could stay aligned to the requested feature area.',
        )] : []),
        ...(request.testUsers.length > 0 ? [buildFocusedContextInfluence(
            'testUsers',
            'used',
            'User references were retained so planning could keep access-control and role-sensitive cases anchored.',
        )] : []),
        ...(request.authMechanismHints.length > 0 ? [buildFocusedContextInfluence(
            'authMechanismHints',
            'used',
            'Authentication hints were included in the planning context for bounded auth-sensitive case selection.',
        )] : []),
        ...(request.attachmentSummary ? [buildFocusedContextInfluence(
            'attachmentSummary',
            'used',
            'Attachment notes were carried into the planning context when choosing bounded hypotheses.',
        )] : []),
        ...(request.attachmentMetadata.length > 0 ? [buildFocusedContextInfluence(
            'attachmentMetadata',
            'used',
            'Attachment metadata labels and notes were available to bounded planning.',
        )] : []),
        ...(request.operatorNotes ? [buildFocusedContextInfluence(
            'operatorNotes',
            'used',
            'Operator notes were included in the planning context and planner constraints.',
        )] : []),
        ...(typeof request.newScreenCount === 'number' && request.newScreenCount > 0 ? [buildFocusedContextInfluence(
            'newScreenCount',
            'used',
            'Recorded screen counts were available to planning as lightweight feature-shape hints.',
        )] : []),
        ...(typeof request.newInputCount === 'number' && request.newInputCount > 0 ? [buildFocusedContextInfluence(
            'newInputCount',
            'used',
            'Recorded input counts were available to planning as lightweight form-complexity hints.',
        )] : []),
    ];
}

export const focusedPlanningService = new FocusedPlanningService();
