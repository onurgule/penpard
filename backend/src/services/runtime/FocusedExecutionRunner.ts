import { v4 as uuidv4 } from 'uuid';
import { Database as DatabaseType } from 'better-sqlite3';
import { OrchestratorRequestExecutor } from '../../agents/orchestrator/OrchestratorRequestExecutor';
import type { ToolCall } from '../../agents/orchestrator/types';
import {
    createEvidenceBundle,
    createFocusedExecutionTraceEntry,
    createFocusedTestCaseExecution,
    db,
    getFocusedTestObjective,
    listLatestFocusedFindingThreadsByScan,
    getScan,
    getScanAuthInventory,
    getScanConfig,
    getScopeEnvelope,
    listFocusedTestCaseExecutionsByCase,
    listFocusedTestCasesByScan,
    updateFocusedTestCaseExecution,
    updateScanStatus,
} from '../../db/init';
import { normalizeSendHttpResponse } from '../burp-tool-result';
import { parseRawBurpRequest } from '../burp-request';
import { BurpMCPClient } from '../burp-mcp';
import { browserService } from '../BrowserService';
import { diffResponses, type ResponseSnapshot } from '../ResponseDiffer';
import { AuthStateManager } from '../auth/AuthStateManager';
import { logger } from '../../utils/logger';
import {
    focusedExecutionProfileResolver,
    type FocusedBrowserAnchor,
    type FocusedExecutionAnchor,
    type FocusedExecutionProfile,
    type FocusedExecutionProfileResolver,
} from './FocusedExecutionProfiles';
import {
    focusedBrowserFlowRunner,
    type FocusedBrowserFlowRunner,
} from './FocusedBrowserFlowRunner';
import { focusedScopeGuard, type FocusedScopeGuard } from './FocusedScopeGuard';
import {
    focusedInvestigationService,
    type FocusedInvestigationObservation,
    type FocusedInvestigationService,
} from './FocusedInvestigationService';
import {
    focusedFindingService,
    type FocusedFindingService,
} from './FocusedFindingService';
import { focusedReasoningTraceService } from './FocusedReasoningTraceService';
import { focusedVerdictService, type FocusedVerdictService } from './FocusedVerdictService';
import type {
    EvidenceBundle,
    FocusedExecutionAction,
    FocusedCaseFamily,
    FocusedConfirmationState,
    FocusedFindingThread,
    FocusedExecutionRail,
    FocusedExecutionState,
    FocusedExecutionTraceActionType,
    FocusedExecutionTraceEntry,
    FocusedTestCase,
    FocusedTestCaseExecution,
    ScopeViolationRecord,
} from './ScopedScanTypes';
import {
    isFocusedTestCaseApproved,
    isFocusedTestCaseEnabled,
    normalizeScanMode,
} from './ScopedScanTypes';
import { interpretFocusedSignals, resolveFocusedCaseFamily } from './FocusedSignalInterpreter';

const DEFAULT_REQUEST_ACTIONS_PER_CASE = 4;
const DEFAULT_ROUTE_VARIANT_CAP = 2;

export interface FocusedExecutionLiveObserver {
    onCaseStarted?(testCase: FocusedTestCase): void;
    onTrace?(traceEntry: FocusedExecutionTraceEntry, context: { testCase: FocusedTestCase }): void;
    onFindingThread?(thread: FocusedFindingThread | null, context: { testCase: FocusedTestCase; executionState: FocusedExecutionState }): void;
    onScanNote?(message: string, context?: { scanId: string; caseId?: string | null }): void;
}

export class FocusedExecutionConflictError extends Error {
    constructor(message = 'Focused execution is already running for this scan.') {
        super(message);
        this.name = 'FocusedExecutionConflictError';
    }
}

interface ExecutionDependencies {
    database: DatabaseType;
    createBurpClient: () => BurpMCPClient;
    profileResolver: FocusedExecutionProfileResolver;
    browserFlowRunner: Pick<FocusedBrowserFlowRunner, 'execute'>;
    scopeGuard: FocusedScopeGuard;
    investigationService: Pick<FocusedInvestigationService, 'recordExecutionObservations' | 'finalizeExecutionIssues'>;
    findingService: Pick<FocusedFindingService, 'seedRuntimeThread' | 'updateRuntimeThread'>;
    verdictService: Pick<FocusedVerdictService, 'generateNow'>;
    now: () => string;
    createId: () => string;
}

export class FocusedExecutionRunner {
    private readonly activeExecutions = new Map<string, Promise<void>>();
    private readonly deps: ExecutionDependencies;

    constructor(
        deps: Partial<ExecutionDependencies> = {},
    ) {
        this.deps = {
            database: db,
            createBurpClient: () => new BurpMCPClient(),
            profileResolver: focusedExecutionProfileResolver,
            browserFlowRunner: focusedBrowserFlowRunner,
            scopeGuard: focusedScopeGuard,
            investigationService: focusedInvestigationService,
            findingService: focusedFindingService,
            verdictService: focusedVerdictService,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public hasActiveExecution(scanId: string): boolean {
        return this.activeExecutions.has(scanId);
    }

    public launchExecution(scanId: string, caseIds?: string[], observer?: FocusedExecutionLiveObserver): void {
        if (this.activeExecutions.has(scanId)) {
            throw new FocusedExecutionConflictError();
        }

        const pending = this.runExecution(scanId, caseIds, observer)
            .catch((error: any) => {
                logger.error('Focused execution job failed', {
                    scanId,
                    error: error.message,
                });
            })
            .finally(() => {
                this.activeExecutions.delete(scanId);
            });

        this.activeExecutions.set(scanId, pending);
    }

    public async executeNow(scanId: string, caseIds?: string[], observer?: FocusedExecutionLiveObserver): Promise<void> {
        if (this.activeExecutions.has(scanId)) {
            throw new FocusedExecutionConflictError();
        }

        const pending = this.runExecution(scanId, caseIds, observer)
            .finally(() => {
                this.activeExecutions.delete(scanId);
            });
        this.activeExecutions.set(scanId, pending);
        return pending;
    }

    private async runExecution(scanId: string, caseIds?: string[], observer?: FocusedExecutionLiveObserver): Promise<void> {
        const scan = getScan(scanId);
        if (!scan) {
            throw new Error(`Focused execution could not find scan ${scanId}.`);
        }
        if (normalizeScanMode(scan.scan_mode) !== 'scoped') {
            throw new Error('Focused execution is only available for scoped scans.');
        }

        const objective = getFocusedTestObjective(scanId);
        const scopeEnvelope = getScopeEnvelope(scanId);
        if (!objective || !scopeEnvelope) {
            throw new Error('Focused execution requires a persisted objective and scope envelope.');
        }

        const requestedCaseIds = caseIds?.length ? new Set(caseIds) : null;
        const allCases = listFocusedTestCasesByScan(scanId);
        const candidateCases = requestedCaseIds
            ? allCases.filter((testCase) => requestedCaseIds.has(testCase.id))
            : allCases;
        const orderedCases = this.orderCandidateCases(scanId, candidateCases);

        if (orderedCases.length === 0) {
            throw new Error('No focused test cases were available for execution.');
        }

        this.markExecuting(scanId);

        const burp = this.deps.createBurpClient();
        const burpAvailable = await burp.isAvailable();
        if (!burpAvailable) {
            updateScanStatus(scanId, 'failed', 'Burp Suite is not connected. Focused execution requires Burp MCP.');
            throw new Error('Burp Suite is not connected. Focused execution requires Burp MCP.');
        }

        const authManager = new AuthStateManager(scanId, scan.target);
        const persistedConfig = getScanConfig(scanId) || {};
        await authManager.initialize({
            sessionCookies: typeof persistedConfig.sessionCookies === 'string' ? persistedConfig.sessionCookies : undefined,
            initialRequest: typeof scan.initial_request === 'string' ? scan.initial_request : undefined,
            authStartup: persistedConfig.authStartup,
            idorUsers: Array.isArray(persistedConfig.idorUsers) ? persistedConfig.idorUsers : [],
        }, burp);
        const authInventory = getScanAuthInventory(scanId);
        if (authInventory) {
            authManager.setStartupInventory(authInventory);
        }

        const requestExecutor = new OrchestratorRequestExecutor({
            scanId,
            burp,
            authManager,
            initialRequest: typeof scan.initial_request === 'string' ? scan.initial_request : undefined,
            log: (channel, message) => logger.info(`Focused execution [${channel}] ${message}`, { scanId }),
            rateLimitPauseMs: 60_000,
            setRateLimitPauseUntil: () => undefined,
        });
        const profile = this.deps.profileResolver.resolve(scan.user_id);
        let remainingScanRequestBudget = scopeEnvelope.explorationBudget?.maxRequests ?? null;

        try {
            observer?.onScanNote?.(`Selected ${orderedCases.length} bounded case${orderedCases.length === 1 ? '' : 's'} for live execution ordering.`, {
                scanId,
            });

            for (const testCase of orderedCases) {
                const runReason = requestedCaseIds ? 'retry' : 'batch';
                if (!isFocusedTestCaseEnabled(testCase) || !isFocusedTestCaseApproved(testCase)) {
                    observer?.onScanNote?.(
                        !isFocusedTestCaseEnabled(testCase)
                            ? `Skipped ${testCase.title} because the bounded hint is disabled.`
                            : `Skipped ${testCase.title} because its legacy review state is ${testCase.reviewState}.`,
                        {
                            scanId,
                            caseId: testCase.id,
                        },
                    );
                    await this.persistSkippedExecution(scanId, testCase, profile, runReason);
                    continue;
                }

                if (remainingScanRequestBudget !== null && remainingScanRequestBudget <= 0) {
                    await this.persistTerminalExecution({
                        testCase,
                        profile,
                        runReason,
                        userId: scan.user_id,
                        executionState: 'failed_to_execute',
                        notesSummary: 'Execution budget was exhausted before this case could run.',
                        errorMessage: 'Scoped request budget exhausted.',
                        investigationObservations: [{
                            issueType: 'execution_budget_exhausted',
                            issueTitle: 'Focused execution could not start because the scan-level request budget was already exhausted.',
                            issueDetails: 'Execution budget was exhausted before this case could run.',
                            issueStatus: 'open',
                            impact: 'degrading',
                            source: 'system',
                            correlation: {
                                executionState: 'failed_to_execute',
                            },
                        }],
                    });
                    continue;
                }

                const requestAnchor = this.resolveRequestAnchor(scan.target, testCase, scopeEnvelope, scan.initial_request);
                const browserAnchor = this.resolveBrowserAnchor(scan.target, testCase, scopeEnvelope, scan.initial_request);

                if (!requestAnchor && !browserAnchor) {
                    await this.persistTerminalExecution({
                        testCase,
                        profile,
                        runReason,
                        userId: scan.user_id,
                        executionState: 'blocked',
                        notesSummary: 'Focused execution requires a concrete request or browser anchor inside the persisted scope envelope.',
                        investigationObservations: [{
                            issueType: 'missing_anchor',
                            issueTitle: 'Focused execution could not start because no approved request or browser anchor was available.',
                            issueDetails: 'Focused execution requires a concrete request or browser anchor inside the persisted scope envelope.',
                            issueStatus: 'open',
                            impact: 'blocking',
                            source: 'system',
                            correlation: {
                                executionState: 'blocked',
                            },
                        }],
                    });
                    continue;
                }

                observer?.onCaseStarted?.(testCase);
                remainingScanRequestBudget = await this.executeCase({
                    scan,
                    objective,
                    scopeEnvelope,
                    testCase,
                    profile,
                    requestAnchor,
                    browserAnchor,
                    runReason,
                    requestExecutor,
                    authManager,
                    remainingScanRequestBudget,
                    observer,
                });
            }

            try {
                await this.deps.verdictService.generateNow(scanId, scan.user_id);
            } catch (error: any) {
                logger.warn('Focused verdict generation failed after execution; keeping scoped execution complete', {
                    scanId,
                    error: error.message,
                });
            }

            observer?.onScanNote?.('Scoped execution completed and verdict consolidation ran on the bounded evidence set.', {
                scanId,
            });

            updateScanStatus(scanId, 'scoped_executed');
        } catch (error: any) {
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        } finally {
            burp.disconnect();
        }
    }

    private markExecuting(scanId: string): void {
        this.deps.database.prepare(`
            UPDATE scans
            SET status = ?, error_message = NULL, completed_at = NULL
            WHERE id = ?
        `).run('scoped_executing', scanId);
    }

    private async executeCase(input: {
        scan: any;
        objective: any;
        scopeEnvelope: any;
        testCase: FocusedTestCase;
        profile: FocusedExecutionProfile;
        requestAnchor: FocusedExecutionAnchor | null;
        browserAnchor: FocusedBrowserAnchor | null;
        runReason: string;
        requestExecutor: OrchestratorRequestExecutor;
        authManager: AuthStateManager;
        remainingScanRequestBudget: number | null;
        observer?: FocusedExecutionLiveObserver;
    }): Promise<number | null> {
        const previousExecutions = listFocusedTestCaseExecutionsByCase(input.testCase.scanId, input.testCase.id);
        const executionId = this.deps.createId();
        const startedAt = this.deps.now();
        const execution: FocusedTestCaseExecution = {
            id: executionId,
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            objectiveId: input.testCase.objectiveId,
            executionState: 'running',
            executionProfileKey: input.profile.key,
            runReason: input.runReason,
            notesSummary: 'Focused execution started.',
            requestActionsUsed: 0,
            browserActionsUsed: 0,
            browserSessionId: null,
            startedAt,
        };
        createFocusedTestCaseExecution(execution);
        const caseFamily = resolveFocusedCaseFamily(input.objective, input.testCase);
        const recordTrace = (entry: Omit<FocusedExecutionTraceEntry, 'id' | 'scanId' | 'caseId' | 'executionId' | 'timestamp' | 'linkedEvidenceIds'> & {
            timestamp?: string | null;
            linkedEvidenceIds?: string[];
        }) => {
            const traceEntry: FocusedExecutionTraceEntry = {
                id: this.deps.createId(),
                scanId: input.testCase.scanId,
                caseId: input.testCase.id,
                executionId,
                timestamp: entry.timestamp || this.deps.now(),
                actionType: entry.actionType,
                actionSummary: entry.actionSummary,
                targetSummary: entry.targetSummary ?? null,
                requestSummary: entry.requestSummary ?? null,
                responseSummary: entry.responseSummary ?? null,
                reasoningNote: entry.reasoningNote ?? null,
                nextStepRationale: entry.nextStepRationale ?? null,
                stopReason: entry.stopReason ?? null,
                retryReason: entry.retryReason ?? null,
                rail: entry.rail,
                toolSummary: entry.toolSummary ?? null,
                linkedEvidenceIds: entry.linkedEvidenceIds || [],
            };
            createFocusedExecutionTraceEntry(traceEntry);
            focusedReasoningTraceService.record(this.buildReasoningEntryFromExecutionTrace({
                objectiveId: input.testCase.objectiveId,
                caseFamily,
                traceEntry,
            }));
            input.observer?.onTrace?.(traceEntry, {
                testCase: input.testCase,
            });
            return traceEntry;
        };

        const executionStartedTrace = recordTrace({
            actionType: 'execution_started',
            actionSummary: 'Focused execution started.',
            targetSummary: this.buildTraceTargetSummary(input.testCase),
            reasoningNote: `Case family resolved as ${caseFamily.replace(/_/g, ' ')} and execution remains bounded to persisted scope.`,
            nextStepRationale: 'Plan the next bounded action from the approved focused execution profile.',
            rail: 'system',
            toolSummary: `Execution profile ${input.profile.key}`,
        });

        let retryContextTraceId: string | null = null;
        if (input.runReason === 'retry' && previousExecutions.length > 0) {
            const previousExecution = previousExecutions[0];
            const retryContextTrace = recordTrace({
                actionType: 'retry_context',
                actionSummary: 'Retrying a previously blocked or failed focused execution.',
                reasoningNote: previousExecution.notesSummary || previousExecution.errorMessage || 'Retrying after an earlier incomplete execution.',
                retryReason: previousExecution.errorMessage || previousExecution.notesSummary || 'Retry requested by the operator.',
                rail: 'system',
                toolSummary: 'Focused retry flow',
            });
            retryContextTraceId = retryContextTrace.id;
        }

        const planningAnchor = input.requestAnchor || {
            defaultMethod: input.testCase.targetArtifact.method?.toUpperCase() || 'GET',
            defaultUrl: input.browserAnchor?.startUrl || input.scan.target,
            defaultPath: input.browserAnchor?.startPath,
            useInitialRequestBaseline: false,
            baselineAvailable: !!input.scopeEnvelope.baselineRequestRefs?.length,
        };
        const maxRouteVariants = input.scopeEnvelope.explorationBudget?.maxRouteVariants ?? DEFAULT_ROUTE_VARIANT_CAP;
        const planningInput = {
            scanId: input.testCase.scanId,
            userId: input.scan.user_id,
            objective: input.objective,
            scopeEnvelope: input.scopeEnvelope,
            testCase: input.testCase,
            anchor: planningAnchor,
            remainingRequestBudget: input.remainingScanRequestBudget ?? DEFAULT_REQUEST_ACTIONS_PER_CASE,
            maxRouteVariants,
            recentEvidence: [] as EvidenceBundle[],
        };
        const actionQueue = await input.profile.planActions(planningInput);
        let requestActionsUsed = 0;
        let browserActionsUsed = 0;
        let browserSessionId: string | null = null;
        let remainingScanRequestBudget = input.remainingScanRequestBudget;
        let remainingCaseRequestBudget = input.remainingScanRequestBudget === null
            ? DEFAULT_REQUEST_ACTIONS_PER_CASE
            : null;
        const noteSnippets: string[] = [];
        const routeVariants = new Set<string>();
        let baselineSnapshot: ResponseSnapshot | null = null;
        let mutatedSnapshot: ResponseSnapshot | null = null;
        let latestBaselineEvidenceId: string | null = null;
        let latestMutatedEvidenceId: string | null = null;
        const persistedEvidence: EvidenceBundle[] = [];
        const recordedIssues: Awaited<ReturnType<ExecutionDependencies['investigationService']['recordExecutionObservations']>> = [];
        let currentFindingThread = this.deps.findingService.seedRuntimeThread({
            objective: input.objective,
            testCase: input.testCase,
            execution,
        });
        input.observer?.onFindingThread?.(currentFindingThread, {
            testCase: input.testCase,
            executionState: 'running',
        });

        const recordIssues = async (observations: FocusedInvestigationObservation[]) => {
            if (observations.length === 0) {
                return [];
            }
            const saved = await this.deps.investigationService.recordExecutionObservations({
                scanId: input.testCase.scanId,
                caseId: input.testCase.id,
                executionId,
                objectiveId: input.testCase.objectiveId,
                userId: input.scan.user_id,
                observations,
            });
            recordedIssues.push(...saved);
            return saved;
        };

        const currentExecutionSnapshot = (executionState: FocusedExecutionState = execution.executionState, notesSummary?: string | null, errorMessage?: string | null): FocusedTestCaseExecution => ({
            ...execution,
            executionState,
            requestActionsUsed,
            browserActionsUsed,
            browserSessionId,
            notesSummary: notesSummary ?? execution.notesSummary ?? null,
            errorMessage: errorMessage ?? execution.errorMessage ?? null,
        });

        const refreshFindingThread = (params: {
            executionState?: FocusedExecutionState;
            linkedTraceIds?: string[];
            linkedVerdictIds?: string[];
            confirmationState?: FocusedConfirmationState | null;
            notesSummary?: string | null;
            errorMessage?: string | null;
        } = {}) => {
            currentFindingThread = this.deps.findingService.updateRuntimeThread({
                objective: input.objective,
                testCase: input.testCase,
                execution: currentExecutionSnapshot(params.executionState || 'running', params.notesSummary, params.errorMessage),
                evidenceBundles: persistedEvidence,
                investigationIssues: recordedIssues,
                linkedTraceIds: params.linkedTraceIds,
                linkedVerdictIds: params.linkedVerdictIds,
                linkedInvestigationIds: recordedIssues.map((issue) => issue.id),
                confirmationState: params.confirmationState,
                previousThread: currentFindingThread,
                verdict: null,
            });
            input.observer?.onFindingThread?.(currentFindingThread, {
                testCase: input.testCase,
                executionState: params.executionState || 'running',
            });
            return currentFindingThread;
        };

        const buildConfirmationState = (overrides: Partial<FocusedConfirmationState> = {}): FocusedConfirmationState => {
            const currentState = currentFindingThread?.confirmationState;
            return {
                maxAdaptiveFollowUps: Math.max(0, Number(currentState?.maxAdaptiveFollowUps ?? input.testCase.maxAdaptiveFollowUps) || 0),
                usedAdaptiveFollowUps: Math.max(0, Number(currentState?.usedAdaptiveFollowUps) || 0),
                preferredRail: currentState?.preferredRail || input.testCase.preferredRail || 'request',
                allowedConfirmationKinds: [...(currentState?.allowedConfirmationKinds || input.testCase.allowedConfirmationKinds || [])],
                recommendedConfirmationKinds: [...(currentState?.recommendedConfirmationKinds || [])],
                nextKind: currentState?.nextKind ?? null,
                nextStepSummary: currentState?.nextStepSummary ?? null,
                readyForAdaptiveConfirmation: currentState?.readyForAdaptiveConfirmation ?? false,
                exhausted: currentState?.exhausted ?? false,
                stopReason: currentState?.stopReason ?? null,
                steps: [...(currentState?.steps || [])].map((step) => ({
                    ...step,
                    evidenceIds: [...step.evidenceIds],
                    traceIds: [...step.traceIds],
                })),
                ...overrides,
            };
        };

        const mergeUniqueStrings = (current: string[], next: string[]) => {
            const seen = new Set<string>();
            const merged: string[] = [];
            for (const value of [...current, ...next]) {
                const normalized = String(value || '').trim();
                if (!normalized || seen.has(normalized)) {
                    continue;
                }
                seen.add(normalized);
                merged.push(normalized);
            }
            return merged;
        };

        const hasPendingAdaptiveConfirmation = (actionIndex: number) => actionQueue
            .slice(actionIndex + 1)
            .some((queuedAction) => queuedAction.phase === 'adaptive_confirmation');

        const updateAdaptiveConfirmationStep = (
            action: FocusedExecutionAction,
            status: 'pending' | 'completed' | 'blocked' | 'skipped',
            evidenceIds: string[] = [],
            traceIds: string[] = [],
            stopReason?: string | null,
        ): FocusedConfirmationState | null => {
            if (action.phase !== 'adaptive_confirmation' || !action.confirmationKind) {
                return null;
            }

            const nextState = buildConfirmationState();
            const stepIndex = [...nextState.steps]
                .reverse()
                .findIndex((entry) => entry.kind === action.confirmationKind && entry.status === 'pending');
            if (stepIndex < 0) {
                return null;
            }

            const actualIndex = nextState.steps.length - 1 - stepIndex;
            const existingStep = nextState.steps[actualIndex];
            nextState.steps[actualIndex] = {
                ...existingStep,
                status,
                actionType: action.type,
                actionSummary: action.summary,
                evidenceIds: mergeUniqueStrings(existingStep.evidenceIds, evidenceIds),
                traceIds: mergeUniqueStrings(existingStep.traceIds, traceIds),
                completedAt: status === 'pending' ? existingStep.completedAt ?? null : this.deps.now(),
            };
            if (status !== 'pending') {
                const maxAdaptiveFollowUps = Math.max(0, Number(nextState.maxAdaptiveFollowUps) || 0);
                const adaptiveBudgetUsed = Math.max(0, Number(nextState.usedAdaptiveFollowUps) || 0);
                const exhausted = adaptiveBudgetUsed >= maxAdaptiveFollowUps;
                nextState.readyForAdaptiveConfirmation = false;
                nextState.exhausted = exhausted;
                nextState.stopReason = stopReason
                    || (status === 'blocked'
                        ? existingStep.summary
                        : exhausted
                            ? `Adaptive confirmation budget exhausted after ${adaptiveBudgetUsed} follow-up${adaptiveBudgetUsed === 1 ? '' : 's'}.`
                            : null);
            }
            return nextState;
        };

        const maybeQueueAdaptiveConfirmation = async (actionIndex: number, traceIds: string[] = []) => {
            if (!currentFindingThread) {
                return;
            }

            const confirmationState = buildConfirmationState();
            if (confirmationState.exhausted || hasPendingAdaptiveConfirmation(actionIndex)) {
                return;
            }
            if (currentFindingThread.status === 'blocked' || currentFindingThread.status === 'exhausted' || currentFindingThread.status === 'published') {
                return;
            }
            const liveInterpretation = interpretFocusedSignals({
                objective: input.objective,
                testCase: input.testCase,
                execution: currentExecutionSnapshot('running', null, null),
                evidenceBundles: persistedEvidence,
            });
            const strongSignalMarkers = new Set(
                input.testCase.caseIntelligence?.followUpPolicy?.strongSignalMarkers
                || [],
            );
            const thresholdScore = Math.max(0, Number(input.testCase.caseIntelligence?.followUpPolicy?.queueThresholdScore) || 40);
            const strongMarkerPresent = liveInterpretation.signalMarkers.some((marker) => strongSignalMarkers.has(marker));
            if ((currentFindingThread.suspicionScore < thresholdScore && !strongMarkerPresent) || currentFindingThread.confirmationProgress >= 85) {
                const skipReason = currentFindingThread.confirmationProgress >= 85
                    ? 'Adaptive follow-up stopped because the bounded case already has enough confirmation progress.'
                    : 'Adaptive follow-up was not queued because suspicion stayed below the bounded threshold and no strong same-family marker appeared.';
                const noteTrace = recordTrace({
                    actionType: 'note_recorded',
                    actionSummary: skipReason,
                    targetSummary: this.buildTraceTargetSummary(input.testCase),
                    reasoningNote: liveInterpretation.summary,
                    nextStepRationale: liveInterpretation.followUpDecisionSummary || liveInterpretation.nextStepSummary || 'Preserve the current bounded finding state without widening scope.',
                    stopReason: skipReason,
                    rail: 'system',
                    toolSummary: 'Adaptive follow-up gate',
                });
                refreshFindingThread({
                    linkedTraceIds: [...traceIds, noteTrace.id],
                    confirmationState: buildConfirmationState({
                        readyForAdaptiveConfirmation: false,
                        nextStepSummary: liveInterpretation.nextStepSummary || confirmationState.nextStepSummary,
                        stopReason: confirmationState.stopReason || skipReason,
                    }),
                });
                return;
            }

            const maxAdaptiveFollowUps = Math.max(0, Number(confirmationState.maxAdaptiveFollowUps) || 0);
            const usedAdaptiveFollowUps = Math.max(0, Number(confirmationState.usedAdaptiveFollowUps) || 0);
            if (usedAdaptiveFollowUps >= maxAdaptiveFollowUps) {
                refreshFindingThread({
                    linkedTraceIds: traceIds,
                    confirmationState: buildConfirmationState({
                        readyForAdaptiveConfirmation: false,
                        exhausted: true,
                        stopReason: confirmationState.stopReason || `Adaptive confirmation budget exhausted after ${usedAdaptiveFollowUps} follow-up${usedAdaptiveFollowUps === 1 ? '' : 's'}.`,
                    }),
                });
                return;
            }

            if (
                usedAdaptiveFollowUps >= 1
                && liveInterpretation.scoreDelta <= 0
                && liveInterpretation.failSignals.length === 0
                && liveInterpretation.reviewSignals.length === 0
            ) {
                const stopReason = 'A second adaptive confirmation was not queued because the first same-scope follow-up did not strengthen the active hypothesis.';
                const noteTrace = recordTrace({
                    actionType: 'note_recorded',
                    actionSummary: stopReason,
                    targetSummary: this.buildTraceTargetSummary(input.testCase),
                    reasoningNote: liveInterpretation.summary,
                    nextStepRationale: liveInterpretation.followUpDecisionSummary || liveInterpretation.nextStepSummary || 'Escalate to operator review if the provisional signal still matters.',
                    stopReason,
                    rail: 'system',
                    toolSummary: 'Adaptive follow-up gate',
                });
                refreshFindingThread({
                    linkedTraceIds: [...traceIds, noteTrace.id],
                    confirmationState: buildConfirmationState({
                        readyForAdaptiveConfirmation: false,
                        exhausted: usedAdaptiveFollowUps >= maxAdaptiveFollowUps,
                        nextStepSummary: liveInterpretation.nextStepSummary || confirmationState.nextStepSummary,
                        stopReason,
                    }),
                });
                return;
            }

            const nextKind = confirmationState.nextKind
                || confirmationState.recommendedConfirmationKinds.find((kind) => confirmationState.allowedConfirmationKinds.length === 0 || confirmationState.allowedConfirmationKinds.includes(kind))
                || confirmationState.allowedConfirmationKinds[0]
                || null;
            if (!nextKind) {
                return;
            }

            const remainingRequestBudget = Math.max(0, remainingScanRequestBudget ?? remainingCaseRequestBudget ?? DEFAULT_REQUEST_ACTIONS_PER_CASE);
            const plannedConfirmationActions = await input.profile.planConfirmationActions({
                scanId: input.testCase.scanId,
                userId: input.scan.user_id,
                objective: input.objective,
                scopeEnvelope: input.scopeEnvelope,
                testCase: input.testCase,
                anchor: planningAnchor,
                browserAnchor: input.browserAnchor,
                findingThread: currentFindingThread,
                confirmationKind: nextKind,
                remainingRequestBudget,
                recentEvidence: persistedEvidence,
                confirmationOrdinal: usedAdaptiveFollowUps + 1,
            });

            if (plannedConfirmationActions.length === 0) {
                refreshFindingThread({
                    linkedTraceIds: traceIds,
                    confirmationState: buildConfirmationState({
                        readyForAdaptiveConfirmation: false,
                        exhausted: usedAdaptiveFollowUps + 1 >= maxAdaptiveFollowUps,
                        stopReason: confirmationState.stopReason || 'No bounded adaptive confirmation step could be planned inside the current scope and budgets.',
                    }),
                });
                return;
            }

            const confirmationStep = {
                id: this.deps.createId(),
                threadId: currentFindingThread.id,
                kind: nextKind,
                status: 'pending' as const,
                summary: plannedConfirmationActions[0]?.summary || currentFindingThread.nextStepSummary || 'Adaptive confirmation queued.',
                actionType: plannedConfirmationActions[0]?.type || null,
                actionSummary: plannedConfirmationActions[0]?.summary || null,
                evidenceIds: [],
                traceIds: [],
                startedAt: this.deps.now(),
                completedAt: null,
            };

            const queuedState = buildConfirmationState({
                usedAdaptiveFollowUps: usedAdaptiveFollowUps + 1,
                nextKind: nextKind,
                nextStepSummary: plannedConfirmationActions[0]?.summary || currentFindingThread.nextStepSummary || null,
                readyForAdaptiveConfirmation: true,
                exhausted: false,
                stopReason: null,
                steps: [...confirmationState.steps, confirmationStep],
            });

            actionQueue.splice(actionIndex + 1, 0, ...plannedConfirmationActions);
            const queueTrace = recordTrace({
                actionType: 'note_recorded',
                actionSummary: `Queued adaptive follow-up ${usedAdaptiveFollowUps + 1} for ${nextKind.replace(/_/g, ' ')}.`,
                targetSummary: this.buildTraceTargetSummary(input.testCase),
                reasoningNote: plannedConfirmationActions[0]?.selectionReason || liveInterpretation.summary,
                nextStepRationale: plannedConfirmationActions[0]?.expectedSignals?.length
                    ? `Next follow-up watches for ${plannedConfirmationActions[0].expectedSignals.slice(0, 2).join(' and ')}.`
                    : (liveInterpretation.followUpDecisionSummary || liveInterpretation.nextStepSummary || null),
                rail: 'system',
                toolSummary: 'Adaptive follow-up queue',
            });
            refreshFindingThread({
                linkedTraceIds: [...traceIds, queueTrace.id],
                confirmationState: queuedState,
            });
        };

        const finalizeAdaptiveConfirmationAction = (
            actionIndex: number,
            action: FocusedExecutionAction,
            evidenceIds: string[] = [],
            traceIds: string[] = [],
            status: 'completed' | 'blocked' | 'skipped' = 'completed',
            stopReason?: string | null,
        ) => {
            if (action.phase !== 'adaptive_confirmation' || !action.confirmationKind) {
                return;
            }
            const nextAction = actionQueue[actionIndex + 1];
            if (
                nextAction?.phase === 'adaptive_confirmation'
                && nextAction.confirmationKind === action.confirmationKind
                && nextAction.confirmationOrdinal === action.confirmationOrdinal
            ) {
                return;
            }

            const nextState = updateAdaptiveConfirmationStep(action, status, evidenceIds, traceIds, stopReason);
            if (!nextState) {
                return;
            }

            refreshFindingThread({
                linkedTraceIds: traceIds,
                confirmationState: nextState,
            });
        };

        refreshFindingThread({
            linkedTraceIds: [executionStartedTrace.id, ...(retryContextTraceId ? [retryContextTraceId] : [])],
        });

        const finalize = async (executionState: FocusedExecutionState, notesSummary: string, errorMessage?: string | null) => {
            const finalTrace = recordTrace({
                actionType: executionState === 'completed'
                    ? 'execution_completed'
                    : executionState === 'failed_to_execute'
                        ? 'execution_failed'
                        : 'blocked',
                actionSummary: notesSummary,
                reasoningNote: notesSummary,
                stopReason: executionState === 'completed' ? null : (errorMessage || notesSummary),
                rail: this.traceRailFromCounts(requestActionsUsed, browserActionsUsed),
                toolSummary: browserSessionId
                    ? `Browser session ${browserSessionId}`
                    : requestActionsUsed > 0
                        ? 'Burp/MCP request rail'
                        : 'System-owned runtime state',
            });
            updateFocusedTestCaseExecution(input.testCase.scanId, input.testCase.id, executionId, {
                executionState,
                notesSummary,
                errorMessage: errorMessage ?? null,
                requestActionsUsed,
                browserActionsUsed,
                browserSessionId,
                completedAt: this.deps.now(),
            });
            refreshFindingThread({
                executionState,
                linkedTraceIds: [finalTrace.id],
                notesSummary,
                errorMessage,
                confirmationState: currentFindingThread?.confirmationState
                    ? {
                        ...currentFindingThread.confirmationState,
                        stopReason: executionState === 'completed' ? currentFindingThread.confirmationState.stopReason : (errorMessage || notesSummary),
                        exhausted: currentFindingThread.confirmationState.exhausted || executionState !== 'completed',
                      }
                    : null,
            });
            await this.deps.investigationService.finalizeExecutionIssues(
                input.testCase.scanId,
                input.testCase.id,
                executionId,
                input.scan.user_id,
            );
        };

        try {
            for (let actionIndex = 0; actionIndex < actionQueue.length; actionIndex += 1) {
                const action = actionQueue[actionIndex];
                const actionTraceIds: string[] = [];
                const actionEvidenceIds: string[] = [];
                const plannedTrace = recordTrace({
                    actionType: 'action_planned',
                    actionSummary: action.summary,
                    targetSummary: action.url || action.note || this.buildTraceTargetSummary(input.testCase),
                    reasoningNote: action.selectionReason || action.reason || action.note || `Planned bounded action ${action.type.replace(/_/g, ' ')} for this case.`,
                    nextStepRationale: action.type === 'compare_responses'
                        ? 'Compare the most recent bounded baseline and mutated responses before deciding whether to continue.'
                        : action.type === 'browser_sequence' || action.type === 'browser_state_check'
                            ? 'Use the approved browser anchor to gather bounded state evidence.'
                            : action.expectedSignals?.length
                                ? `Watch for ${action.expectedSignals.slice(0, 2).join(' and ')} before deciding whether to continue.`
                                : 'Continue with the next bounded runtime step without expanding scope.',
                    rail: this.traceRailForAction(action.type),
                    toolSummary: this.buildToolSummaryForRail(this.traceRailForAction(action.type)),
                });
                actionTraceIds.push(plannedTrace.id);
                switch (action.type) {
                    case 'baseline_replay':
                    case 'mutated_replay': {
                        if (!input.requestAnchor) {
                            const reason = 'A request-backed scoped action could not run through the Burp/MCP rail because no in-scope request anchor was available.';
                            const bundle = await this.persistExecutionNote(input.testCase, executionId, input.profile, action.type, reason, persistedEvidence, action);
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const noteTrace = recordTrace({
                                actionType: 'note_recorded',
                                actionSummary: reason,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'A request-backed action was planned, but no persisted request anchor was available.',
                                nextStepRationale: 'Stop the request-backed branch and record a bounded missing-anchor issue.',
                                rail: 'system',
                                toolSummary: 'System-owned guard',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(noteTrace.id);
                            noteSnippets.push(reason);
                            await recordIssues([{
                                issueType: 'missing_anchor',
                                issueTitle: 'Focused request replay could not start because no request anchor was available.',
                                issueDetails: reason,
                                issueStatus: 'open',
                                impact: 'blocking',
                                source: 'system',
                                correlation: {
                                    executionState: 'running',
                                    requestActionType: action.type,
                                },
                            }]);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                notesSummary: reason,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', reason);
                            continue;
                        }

                        const requestBudget = remainingScanRequestBudget ?? remainingCaseRequestBudget ?? DEFAULT_REQUEST_ACTIONS_PER_CASE;
                        if (requestBudget <= 0) {
                            const budgetEvidence = await this.persistBudgetEvidence(input.testCase, executionId, input.profile, action.type, 'Scoped request budget exhausted before this request could run.', action);
                            persistedEvidence.push(budgetEvidence);
                            actionEvidenceIds.push(budgetEvidence.id);
                            const budgetTrace = recordTrace({
                                actionType: 'execution_failed',
                                actionSummary: 'Scoped request budget exhausted before this request could run.',
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'No bounded request budget remained for the planned request action.',
                                stopReason: 'Scoped request budget exhausted.',
                                rail: 'request',
                                toolSummary: 'Burp/MCP request rail',
                                linkedEvidenceIds: [budgetEvidence.id],
                            });
                            actionTraceIds.push(budgetTrace.id);
                            await recordIssues([{
                                issueType: 'execution_budget_exhausted',
                                issueTitle: 'Focused request execution exhausted the scoped request budget.',
                                issueDetails: 'Scoped request budget exhausted before this request could run.',
                                issueStatus: 'open',
                                impact: 'degrading',
                                source: 'system',
                                linkedEvidenceIds: [budgetEvidence.id],
                                correlation: {
                                    executionState: 'failed_to_execute',
                                    requestActionType: action.type,
                                },
                            }]);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                executionState: 'failed_to_execute',
                                notesSummary: 'Scoped request budget exhausted.',
                                errorMessage: 'Scoped request budget exhausted.',
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', 'Scoped request budget exhausted.');
                            await finalize('failed_to_execute', 'Scoped request budget exhausted.', 'Scoped request budget exhausted.');
                            return remainingScanRequestBudget;
                        }

                        const resolvedRequest = this.resolveRequestAction(action, input.requestAnchor);
                        const dispatchTrace = recordTrace({
                            actionType: 'request_dispatch',
                            actionSummary: action.summary,
                            targetSummary: resolvedRequest.url,
                            requestSummary: this.buildTraceRequestSummary(action, resolvedRequest),
                            reasoningNote: action.reason || `Dispatching a bounded ${action.type.replace(/_/g, ' ')} request.`,
                            nextStepRationale: 'Observe the bounded response before deciding whether comparison or follow-up verification is needed.',
                            rail: 'request',
                            toolSummary: 'Burp/MCP send_http_request',
                        });
                        actionTraceIds.push(dispatchTrace.id);
                        const guardDecision = this.deps.scopeGuard.evaluate({
                            action: {
                                type: action.type,
                                method: resolvedRequest.method,
                                url: resolvedRequest.url,
                                useInitialRequestBaseline: resolvedRequest.useInitialRequestBaseline,
                            },
                            testCase: input.testCase,
                            envelope: input.scopeEnvelope,
                        });
                        if (!guardDecision.allowed && guardDecision.violation) {
                            const scopeEvidence = await this.persistScopeViolation(input.testCase, executionId, input.profile, guardDecision.violation);
                            persistedEvidence.push(scopeEvidence);
                            actionEvidenceIds.push(scopeEvidence.id);
                            await recordIssues(this.buildScopeViolationObservations(guardDecision.violation, [scopeEvidence.id], {
                                executionState: 'blocked',
                                requestActionType: action.type,
                                observedMethod: resolvedRequest.method,
                                observedPath: guardDecision.normalizedPath,
                                anchorMethod: input.requestAnchor.defaultMethod,
                                anchorPath: input.requestAnchor.defaultPath,
                            }));
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                executionState: 'blocked',
                                notesSummary: guardDecision.violation.reason,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', guardDecision.violation.reason);
                            await finalize('blocked', guardDecision.violation.reason);
                            return remainingScanRequestBudget;
                        }

                        if (action.type === 'mutated_replay' && guardDecision.normalizedPath) {
                            routeVariants.add(guardDecision.normalizedPath);
                            if (routeVariants.size > maxRouteVariants) {
                                const budgetEvidence = await this.persistBudgetEvidence(input.testCase, executionId, input.profile, action.type, 'Scoped route-variant budget exhausted for this case.', action);
                                persistedEvidence.push(budgetEvidence);
                                actionEvidenceIds.push(budgetEvidence.id);
                                await recordIssues([{
                                    issueType: 'execution_budget_exhausted',
                                    issueTitle: 'Focused execution exhausted the scoped route-variant budget.',
                                    issueDetails: 'Scoped route-variant budget exhausted for this case.',
                                    issueStatus: 'open',
                                    impact: 'degrading',
                                    source: 'system',
                                    linkedEvidenceIds: [budgetEvidence.id],
                                    correlation: {
                                        executionState: 'failed_to_execute',
                                        requestActionType: action.type,
                                        observedPath: guardDecision.normalizedPath,
                                    },
                                }]);
                                refreshFindingThread({
                                    linkedTraceIds: actionTraceIds,
                                    executionState: 'failed_to_execute',
                                    notesSummary: 'Scoped route-variant budget exhausted for this case.',
                                    errorMessage: 'Scoped route-variant budget exhausted.',
                                });
                                finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', 'Scoped route-variant budget exhausted.');
                                await finalize('failed_to_execute', 'Scoped route-variant budget exhausted for this case.', 'Scoped route-variant budget exhausted.');
                                return remainingScanRequestBudget;
                            }
                        }

                        const result = await input.requestExecutor.execute({
                            tool: 'send_http_request',
                            args: {
                                url: resolvedRequest.url,
                                method: resolvedRequest.method,
                                preserveExplicitAuth: resolvedRequest.preserveExplicitAuth,
                                useInitialRequestBaseline: resolvedRequest.useInitialRequestBaseline,
                                queryMutations: action.queryMutations,
                                bodyMutations: action.bodyMutations,
                            },
                        } as ToolCall<'send_http_request'>);
                        const exchange = input.requestExecutor.getLastExchange();
                        const normalizedResult = normalizeSendHttpResponse(result);
                        const snapshot = this.buildResponseSnapshot(normalizedResult);
                        requestActionsUsed += 1;
                        remainingScanRequestBudget = remainingScanRequestBudget === null ? null : remainingScanRequestBudget - 1;
                        remainingCaseRequestBudget = remainingCaseRequestBudget === null ? null : remainingCaseRequestBudget - 1;

                        if (action.type === 'baseline_replay') {
                            baselineSnapshot = snapshot;
                        } else {
                            mutatedSnapshot = snapshot;
                        }

                        const bundle = await this.persistRequestEvidence({
                            testCase: input.testCase,
                            executionId,
                            profile: input.profile,
                            action,
                            summary: `${action.summary} (HTTP ${snapshot.statusCode || normalizedResult.statusCode || 0}).`,
                            requestRef: {
                                method: resolvedRequest.method,
                                url: resolvedRequest.url,
                                path: guardDecision.normalizedPath,
                                host: guardDecision.normalizedHost,
                                raw: exchange?.rawRequest,
                            },
                            responseRef: {
                                method: resolvedRequest.method,
                                url: resolvedRequest.url,
                                path: guardDecision.normalizedPath,
                                host: guardDecision.normalizedHost,
                                statusCode: normalizedResult.statusCode,
                                raw: exchange?.rawResponse,
                            },
                        });
                        if (action.type === 'baseline_replay') {
                            latestBaselineEvidenceId = bundle.id;
                        } else {
                            latestMutatedEvidenceId = bundle.id;
                        }
                        persistedEvidence.push(bundle);
                        actionEvidenceIds.push(bundle.id);
                        const observedTrace = recordTrace({
                            actionType: 'response_observed',
                            actionSummary: `${action.summary} observed HTTP ${normalizedResult.statusCode}.`,
                            targetSummary: guardDecision.normalizedPath || resolvedRequest.url,
                            requestSummary: this.buildTraceRequestSummary(action, resolvedRequest),
                            responseSummary: this.buildTraceResponseSummary({
                                statusCode: normalizedResult.statusCode,
                                body: normalizedResult.body,
                            }),
                            reasoningNote: action.type === 'mutated_replay'
                                ? 'The mutated bounded response was captured and can now be compared against the baseline.'
                                : 'The baseline bounded response was captured and can anchor the next comparison step.',
                            nextStepRationale: action.type === 'mutated_replay'
                                ? 'If a baseline response exists, compare the two responses to decide whether bounded follow-up is needed.'
                                : 'Capture a bounded mutated response before comparing.',
                            rail: 'request',
                            toolSummary: 'Burp/MCP send_http_request',
                            linkedEvidenceIds: [bundle.id],
                        });
                        actionTraceIds.push(observedTrace.id);
                        const authDriftObservation = this.buildAuthSessionDriftObservation({
                            scopeEnvelope: input.scopeEnvelope,
                            actionType: action.type,
                            statusCode: normalizedResult.statusCode,
                            path: guardDecision.normalizedPath,
                            executionState: 'running',
                            linkedEvidenceIds: [bundle.id],
                        });
                        if (authDriftObservation) {
                            await recordIssues([authDriftObservation]);
                        }
                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                        });
                        break;
                    }
                    case 'compare_responses': {
                        if (baselineSnapshot && mutatedSnapshot) {
                            const responseDiff = diffResponses(baselineSnapshot, mutatedSnapshot);
                            noteSnippets.push(responseDiff.summary);
                            const bundle: EvidenceBundle = {
                                id: this.deps.createId(),
                                scanId: input.testCase.scanId,
                                caseId: input.testCase.id,
                                executionId,
                                summary: action.summary,
                                source: 'comparison',
                                capturedAt: this.deps.now(),
                                responseDiffSummary: {
                                    summary: responseDiff.summary,
                                    significant: responseDiff.significant,
                                    originalStatus: responseDiff.originalStatus,
                                    mutatedStatus: responseDiff.mutatedStatus,
                                    bodyLengthDelta: responseDiff.bodyLengthDelta,
                                    structureChanged: responseDiff.structureChanged,
                                    keywordSignals: responseDiff.keywordSignals,
                                },
                                executionNotes: responseDiff.summary,
                                relatedEvidenceIds: [latestBaselineEvidenceId, latestMutatedEvidenceId].filter((entry): entry is string => !!entry),
                                provenance: this.buildProvenance(input.profile, action.type, action),
                            };
                            createEvidenceBundle(bundle);
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const interpretation = interpretFocusedSignals({
                                objective: input.objective,
                                testCase: input.testCase,
                                execution: {
                                    ...execution,
                                    requestActionsUsed,
                                    browserActionsUsed,
                                },
                                evidenceBundles: persistedEvidence,
                            });
                            const compareTrace = recordTrace({
                                actionType: 'response_compared',
                                actionSummary: action.summary,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                responseSummary: {
                                    statusCode: responseDiff.mutatedStatus ?? responseDiff.originalStatus ?? null,
                                    bodySummary: responseDiff.summary,
                                    structureChanged: responseDiff.structureChanged ?? false,
                                    bodyLengthDelta: responseDiff.bodyLengthDelta ?? 0,
                                    keywordSignals: responseDiff.keywordSignals || [],
                                },
                                reasoningNote: interpretation.summary,
                                nextStepRationale: interpretation.reviewSignals.length > 0
                                    ? 'Keep the next step bounded and gather verification evidence without treating the suspicious signal as confirmed proof.'
                                    : interpretation.failSignals.length > 0
                                        ? 'The bounded comparison produced a strong failure signal; no broader scope expansion is needed.'
                                        : 'Use the comparison result to decide whether bounded state verification is still required.',
                                rail: 'request',
                                toolSummary: 'Persisted response diff',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(compareTrace.id);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'completed');
                            await maybeQueueAdaptiveConfirmation(actionIndex, actionTraceIds);
                        } else {
                            const bundle = await this.persistExecutionNote(
                                input.testCase,
                                executionId,
                                input.profile,
                                action.type,
                                'Response comparison skipped because a baseline or mutated snapshot was missing.',
                                persistedEvidence,
                                action,
                            );
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const noteTrace = recordTrace({
                                actionType: 'note_recorded',
                                actionSummary: bundle.summary,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'Response comparison could not run because one side of the bounded replay pair was missing.',
                                nextStepRationale: 'Record the replay mismatch and stop relying on a missing comparison.',
                                rail: 'system',
                                toolSummary: 'System-owned comparison guard',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(noteTrace.id);
                            noteSnippets.push(bundle.executionNotes || bundle.summary);
                            await recordIssues([{
                                issueType: 'request_replay_mismatch',
                                issueTitle: 'Focused response comparison could not be completed because replay evidence was incomplete.',
                                issueDetails: 'Response comparison skipped because a baseline or mutated snapshot was missing.',
                                issueStatus: 'open',
                                impact: 'degrading',
                                source: 'system',
                                linkedEvidenceIds: [bundle.id, ...persistedEvidence.map((entry) => entry.id)],
                                correlation: {
                                    executionState: 'running',
                                    requestActionType: action.type,
                                    evidenceSources: persistedEvidence.map((entry) => entry.source),
                                },
                            }]);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                notesSummary: bundle.executionNotes || bundle.summary,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', 'Response comparison skipped because a baseline or mutated snapshot was missing.');
                        }
                        break;
                    }
                    case 'browser_sequence':
                    case 'browser_state_check': {
                        if (!input.browserAnchor || !input.profile.planBrowserSequence) {
                            const reason = 'Browser/stateful verification was requested, but this case does not have a concrete approved browser anchor.';
                            const bundle = await this.persistExecutionNote(input.testCase, executionId, input.profile, action.type, reason, persistedEvidence, action);
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const noteTrace = recordTrace({
                                actionType: 'note_recorded',
                                actionSummary: reason,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'A browser-backed action was planned, but no approved browser anchor was available.',
                                nextStepRationale: 'Block the browser-backed branch and surface the missing-anchor issue.',
                                rail: 'system',
                                toolSummary: 'System-owned guard',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(noteTrace.id);
                            await recordIssues([{
                                issueType: 'missing_anchor',
                                issueTitle: 'Focused browser verification could not start because no browser anchor was available.',
                                issueDetails: reason,
                                issueStatus: 'open',
                                impact: 'blocking',
                                source: 'system',
                                linkedEvidenceIds: [bundle.id],
                                correlation: {
                                    executionState: 'blocked',
                                    requestActionType: action.type,
                                },
                            }]);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                executionState: 'blocked',
                                notesSummary: reason,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', reason);
                            await finalize('blocked', reason);
                            return remainingScanRequestBudget;
                        }

                        const browserPlan = await input.profile.planBrowserSequence({
                            scanId: input.testCase.scanId,
                            userId: input.scan.user_id,
                            objective: input.objective,
                            scopeEnvelope: input.scopeEnvelope,
                            testCase: input.testCase,
                            browserAnchor: input.browserAnchor,
                            relatedEvidence: persistedEvidence,
                        });

                        if (!browserPlan) {
                            const reason = 'Browser/stateful verification could not produce a bounded approved browser sequence.';
                            const bundle = await this.persistExecutionNote(input.testCase, executionId, input.profile, action.type, reason, persistedEvidence, action);
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const noteTrace = recordTrace({
                                actionType: 'note_recorded',
                                actionSummary: reason,
                                targetSummary: input.browserAnchor.startPath || input.browserAnchor.startUrl,
                                reasoningNote: 'No safe bounded browser sequence was available for this case.',
                                nextStepRationale: 'Block execution instead of widening the stateful flow.',
                                rail: 'browser',
                                toolSummary: 'Bounded browser planner',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(noteTrace.id);
                            await recordIssues([{
                                issueType: 'blocked_flow',
                                issueTitle: 'Focused browser/stateful verification could not produce a bounded flow.',
                                issueDetails: reason,
                                issueStatus: 'open',
                                impact: 'blocking',
                                source: 'system',
                                linkedEvidenceIds: [bundle.id],
                                correlation: {
                                    executionState: 'blocked',
                                    requestActionType: action.type,
                                    anchorPath: input.browserAnchor.startPath,
                                },
                            }]);
                            refreshFindingThread({
                                linkedTraceIds: actionTraceIds,
                                executionState: 'blocked',
                                notesSummary: reason,
                            });
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', reason);
                            await finalize('blocked', reason);
                            return remainingScanRequestBudget;
                        }

                        const browserStartTrace = recordTrace({
                            actionType: 'browser_sequence_started',
                            actionSummary: browserPlan.summary,
                            targetSummary: input.browserAnchor.startPath || input.browserAnchor.startUrl,
                            reasoningNote: 'Starting the approved browser-backed sequence within the persisted scope envelope.',
                            nextStepRationale: 'Observe bounded browser state and verification expectations before deciding whether execution can complete.',
                            rail: 'browser',
                            toolSummary: 'Browser flow runner',
                        });
                        actionTraceIds.push(browserStartTrace.id);
                        const browserResult = await this.deps.browserFlowRunner.execute({
                            scanId: input.testCase.scanId,
                            userId: input.scan.user_id,
                            executionId,
                            testCase: input.testCase,
                            envelope: input.scopeEnvelope,
                            authManager: input.authManager,
                            anchor: input.browserAnchor,
                            plan: browserPlan,
                            profileKey: input.profile.key,
                            profileProvider: input.profile.provider,
                            profileModel: input.profile.model,
                            relatedEvidenceBundles: persistedEvidence,
                        });
                        browserActionsUsed += browserResult.browserActionsUsed;
                        browserSessionId = browserResult.browserSessionId;
                        if (browserResult.evidenceBundle) {
                            persistedEvidence.push(browserResult.evidenceBundle);
                            actionEvidenceIds.push(browserResult.evidenceBundle.id);
                        }
                        const browserResultTrace = recordTrace({
                            actionType: 'browser_sequence_result',
                            actionSummary: browserResult.notesSummary || browserPlan.summary,
                            targetSummary: browserResult.evidenceBundle?.browserState?.finalPath
                                || browserResult.evidenceBundle?.browserState?.finalUrl
                                || input.browserAnchor.startPath
                                || input.browserAnchor.startUrl,
                            responseSummary: {
                                bodySummary: browserResult.evidenceBundle?.browserState?.actionSummary || browserResult.notesSummary || null,
                                keywordSignals: [],
                            },
                            reasoningNote: browserResult.errorMessage || browserResult.notesSummary || 'Browser-backed verification completed inside the approved boundary.',
                            nextStepRationale: browserResult.executionState === 'completed'
                                ? 'Use the browser evidence to decide whether the case is complete.'
                                : 'Stop the bounded browser path and preserve the blocker details for review.',
                            stopReason: browserResult.executionState === 'completed' ? null : (browserResult.errorMessage || browserResult.notesSummary || null),
                            rail: 'browser',
                            toolSummary: browserResult.browserSessionId
                                ? `Browser session ${browserResult.browserSessionId}`
                                : 'Browser flow runner',
                            linkedEvidenceIds: browserResult.evidenceIds,
                        });
                        actionTraceIds.push(browserResultTrace.id);
                        if (browserResult.investigationObservations.length > 0) {
                            await recordIssues(browserResult.investigationObservations.map((observation) => ({
                                ...observation,
                                workaroundAttempts: observation.workaroundAttempts?.length
                                    ? observation.workaroundAttempts
                                    : (persistedEvidence.some((entry) => entry.requestRef || entry.responseDiffSummary)
                                        ? [{
                                            attemptedAt: this.deps.now(),
                                            summary: 'Attempted bounded browser verification after collecting request evidence.',
                                            outcome: browserResult.executionState === 'completed' ? 'no_change' : 'introduced_uncertainty',
                                            linkedEvidenceIds: browserResult.evidenceIds,
                                          }]
                                        : []),
                            })));
                        }

                        const browserSummary = input.profile.summarizeStatefulExecution
                            ? await input.profile.summarizeStatefulExecution({
                                testCase: input.testCase,
                                browserPlan,
                                browserEvidence: browserResult.evidenceBundle,
                                relatedEvidence: persistedEvidence,
                            })
                            : null;
                        if (browserSummary) {
                            noteSnippets.push(browserSummary);
                        } else if (browserResult.notesSummary) {
                            noteSnippets.push(browserResult.notesSummary);
                        }

                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                            executionState: browserResult.executionState === 'completed' ? 'running' : browserResult.executionState,
                            notesSummary: browserResult.notesSummary,
                            errorMessage: browserResult.errorMessage ?? null,
                        });

                        if (browserResult.executionState === 'blocked') {
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', browserResult.errorMessage || browserResult.notesSummary || null);
                            await finalize('blocked', browserResult.notesSummary, browserResult.errorMessage ?? null);
                            return remainingScanRequestBudget;
                        }
                        if (browserResult.executionState === 'failed_to_execute') {
                            finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', browserResult.errorMessage || browserResult.notesSummary || null);
                            await finalize('failed_to_execute', browserResult.notesSummary, browserResult.errorMessage ?? null);
                            return remainingScanRequestBudget;
                        }
                        finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'completed');
                        await maybeQueueAdaptiveConfirmation(actionIndex, actionTraceIds);
                        break;
                    }
                    case 'capture_note': {
                        const note = action.note || action.summary;
                        noteSnippets.push(note);
                        const bundle = await this.persistExecutionNote(input.testCase, executionId, input.profile, action.type, note, persistedEvidence, action);
                        persistedEvidence.push(bundle);
                        actionEvidenceIds.push(bundle.id);
                        const noteTrace = recordTrace({
                            actionType: 'note_recorded',
                            actionSummary: bundle.summary,
                            targetSummary: this.buildTraceTargetSummary(input.testCase),
                            reasoningNote: note,
                            nextStepRationale: 'Keep the note with the bounded evidence set so the next step stays inspectable.',
                            rail: 'system',
                            toolSummary: 'System-owned execution note',
                            linkedEvidenceIds: [bundle.id],
                        });
                        actionTraceIds.push(noteTrace.id);
                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                            notesSummary: note,
                        });
                        finalizeAdaptiveConfirmationAction(
                            actionIndex,
                            action,
                            actionEvidenceIds,
                            actionTraceIds,
                            /could not|unavailable|missing/i.test(note) ? 'blocked' : 'completed',
                            /could not|unavailable|missing/i.test(note) ? note : null,
                        );
                        break;
                    }
                    case 'capture_screenshot_if_available': {
                        const screenshot = await this.captureScreenshotIfAvailable(browserSessionId, input.scan);
                        if (screenshot) {
                            const bundle: EvidenceBundle = {
                                id: this.deps.createId(),
                                scanId: input.testCase.scanId,
                                caseId: input.testCase.id,
                                executionId,
                                summary: action.summary,
                                source: 'screenshot',
                                capturedAt: this.deps.now(),
                                screenshotRef: screenshot,
                                provenance: this.buildProvenance(input.profile, action.type, action),
                            };
                            createEvidenceBundle(bundle);
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const screenshotTrace = recordTrace({
                                actionType: 'screenshot_captured',
                                actionSummary: action.summary,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'Captured the current bounded browser state for operator review.',
                                nextStepRationale: 'Use the screenshot as supporting evidence without widening the execution rails.',
                                rail: browserSessionId ? 'browser' : 'system',
                                toolSummary: browserSessionId ? `Browser session ${browserSessionId}` : 'System-owned screenshot capture',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(screenshotTrace.id);
                        } else {
                            const bundle = await this.persistExecutionNote(
                                input.testCase,
                                executionId,
                                input.profile,
                                action.type,
                                'No browser-backed screenshot was available in the focused execution path.',
                                persistedEvidence,
                                action,
                            );
                            persistedEvidence.push(bundle);
                            actionEvidenceIds.push(bundle.id);
                            const noteTrace = recordTrace({
                                actionType: 'note_recorded',
                                actionSummary: bundle.summary,
                                targetSummary: this.buildTraceTargetSummary(input.testCase),
                                reasoningNote: 'Screenshot capture was requested, but no browser-backed session was available.',
                                nextStepRationale: 'Keep the bounded execution moving without fabricating visual evidence.',
                                rail: 'system',
                                toolSummary: 'System-owned screenshot guard',
                                linkedEvidenceIds: [bundle.id],
                            });
                            actionTraceIds.push(noteTrace.id);
                        }
                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                        });
                        finalizeAdaptiveConfirmationAction(
                            actionIndex,
                            action,
                            actionEvidenceIds,
                            actionTraceIds,
                            screenshot ? 'completed' : 'blocked',
                            screenshot ? null : 'No browser-backed screenshot was available in the focused execution path.',
                        );
                        break;
                    }
                    case 'block_case': {
                        const reason = action.reason || action.summary;
                        noteSnippets.push(reason);
                        const bundle = await this.persistExecutionNote(input.testCase, executionId, input.profile, action.type, reason, persistedEvidence, action);
                        persistedEvidence.push(bundle);
                        actionEvidenceIds.push(bundle.id);
                        const blockedTrace = recordTrace({
                            actionType: 'blocked',
                            actionSummary: reason,
                            targetSummary: this.buildTraceTargetSummary(input.testCase),
                            reasoningNote: 'The bounded execution profile explicitly stopped the case before completion.',
                            stopReason: reason,
                            rail: 'system',
                            toolSummary: 'System-owned block decision',
                            linkedEvidenceIds: [bundle.id],
                        });
                        actionTraceIds.push(blockedTrace.id);
                        await recordIssues([{
                            issueType: 'blocked_flow',
                            issueTitle: 'Focused execution explicitly blocked the case before completion.',
                            issueDetails: reason,
                            issueStatus: 'open',
                            impact: 'blocking',
                            source: 'system',
                            linkedEvidenceIds: [bundle.id],
                            correlation: {
                                executionState: 'blocked',
                                requestActionType: action.type,
                            },
                        }]);
                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                            executionState: 'blocked',
                            notesSummary: reason,
                        });
                        finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'blocked', reason);
                        await finalize('blocked', reason);
                        return remainingScanRequestBudget;
                    }
                    case 'complete_case': {
                        const completionNote = action.note || action.summary;
                        noteSnippets.push(completionNote);
                        refreshFindingThread({
                            linkedTraceIds: actionTraceIds,
                            notesSummary: completionNote,
                        });
                        finalizeAdaptiveConfirmationAction(actionIndex, action, actionEvidenceIds, actionTraceIds, 'completed');
                        await finalize('completed', noteSnippets.join(' ').slice(0, 500) || completionNote);
                        return remainingScanRequestBudget;
                    }
                }
            }

            const finalSummary = noteSnippets.join(' ').slice(0, 500) || 'Focused execution completed with persisted evidence.';
            if (input.runReason === 'retry' && previousExecutions.some((execution) => execution.executionState === 'blocked' || execution.executionState === 'failed_to_execute')) {
                await recordIssues([{
                    issueType: 'retry_failure',
                    issueTitle: 'A retry was attempted after an earlier blocked or failed focused execution.',
                    issueDetails: 'This retry completed, but the scoped run should still be reviewed alongside the earlier blocked or failed attempt.',
                    issueStatus: 'resolved',
                    impact: 'informational',
                    source: 'system',
                    workaroundAttempts: [{
                        attemptedAt: this.deps.now(),
                        summary: 'Retried the focused case execution.',
                        outcome: 'resolved',
                        linkedEvidenceIds: persistedEvidence.map((entry) => entry.id),
                    }],
                    resolvedAt: this.deps.now(),
                    correlation: {
                        executionState: 'completed',
                    },
                }]);
            }
            await finalize('completed', finalSummary);
            return remainingScanRequestBudget;
        } catch (error: any) {
            const retryAttempt = input.runReason === 'retry' && previousExecutions.some((execution) => execution.executionState === 'blocked' || execution.executionState === 'failed_to_execute');
            await recordIssues([
                {
                    issueType: 'environment_instability',
                    issueTitle: 'Focused execution failed before the case completed.',
                    issueDetails: error.message,
                    issueStatus: 'open',
                    impact: 'degrading',
                    source: 'system',
                    linkedEvidenceIds: persistedEvidence.map((entry) => entry.id),
                    correlation: {
                        executionState: 'failed_to_execute',
                        evidenceSources: persistedEvidence.map((entry) => entry.source),
                    },
                },
                ...(retryAttempt ? [{
                    issueType: 'retry_failure' as const,
                    issueTitle: 'Focused retry did not resolve the earlier execution blocker.',
                    issueDetails: error.message,
                    issueStatus: 'open' as const,
                    impact: 'degrading' as const,
                    source: 'system' as const,
                    workaroundAttempts: [{
                        attemptedAt: this.deps.now(),
                        summary: 'Retried the focused case execution.',
                        outcome: 'no_change' as const,
                        linkedEvidenceIds: persistedEvidence.map((entry) => entry.id),
                    }],
                    linkedEvidenceIds: persistedEvidence.map((entry) => entry.id),
                    correlation: {
                        executionState: 'failed_to_execute' as const,
                    },
                }] : []),
            ]);
            await finalize('failed_to_execute', 'Focused execution failed before the case completed.', error.message);
            return remainingScanRequestBudget;
        }
    }

    private orderCandidateCases(scanId: string, cases: FocusedTestCase[]): FocusedTestCase[] {
        const latestThreads = listLatestFocusedFindingThreadsByScan(scanId);
        const threadByCaseId = new Map<string, FocusedFindingThread>();
        for (const thread of latestThreads) {
            if (!threadByCaseId.has(thread.caseId)) {
                threadByCaseId.set(thread.caseId, thread);
            }
        }

        const priorityRank: Record<FocusedTestCase['priority'], number> = {
            high: 0,
            medium: 1,
            low: 2,
        };

        return [...cases].sort((left, right) => {
            const leftThread = threadByCaseId.get(left.id);
            const rightThread = threadByCaseId.get(right.id);
            const leftSuspicion = leftThread?.suspicionScore || 0;
            const rightSuspicion = rightThread?.suspicionScore || 0;
            if (leftSuspicion !== rightSuspicion) {
                return rightSuspicion - leftSuspicion;
            }

            const leftConfirmation = leftThread?.confirmationProgress || 0;
            const rightConfirmation = rightThread?.confirmationProgress || 0;
            if (leftConfirmation !== rightConfirmation) {
                return rightConfirmation - leftConfirmation;
            }

            if (priorityRank[left.priority] !== priorityRank[right.priority]) {
                return priorityRank[left.priority] - priorityRank[right.priority];
            }

            return left.title.localeCompare(right.title);
        });
    }

    private traceRailForAction(actionType: FocusedExecutionAction['type']): FocusedExecutionRail {
        switch (actionType) {
            case 'baseline_replay':
            case 'mutated_replay':
            case 'compare_responses':
                return 'request';
            case 'browser_sequence':
            case 'browser_state_check':
            case 'capture_screenshot_if_available':
                return 'browser';
            default:
                return 'system';
        }
    }

    private traceRailFromCounts(requestActionsUsed: number, browserActionsUsed: number): FocusedExecutionRail {
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

    private buildToolSummaryForRail(rail: FocusedExecutionRail): string {
        switch (rail) {
            case 'request':
                return 'Burp/MCP request rail';
            case 'browser':
                return 'Browser-backed rail';
            case 'hybrid':
                return 'Hybrid request and browser rails';
            default:
                return 'System-owned runtime note';
        }
    }

    private buildTraceTargetSummary(testCase: FocusedTestCase): string {
        return [
            testCase.targetArtifact.kind,
            testCase.targetArtifact.method?.toUpperCase(),
            testCase.targetArtifact.path || testCase.targetArtifact.url || testCase.targetArtifact.label || testCase.title,
        ].filter(Boolean).join(' ');
    }

    private buildTraceRequestSummary(
        action: FocusedExecutionAction,
        resolvedRequest: {
            method: string;
            url: string;
        },
    ): FocusedExecutionTraceEntry['requestSummary'] {
        const path = this.normalizeRoutePath(resolvedRequest.url);
        const host = this.normalizeUrl(resolvedRequest.url)
            ? new URL(resolvedRequest.url).host
            : null;
        const mutations = [
            ...(action.queryMutations || []).map((entry) => `${entry.name}=${String(entry.value)}`),
            ...(action.bodyMutations || []).map((entry) => `${entry.name}=${String(entry.value)}`),
        ];
        return {
            method: resolvedRequest.method,
            url: resolvedRequest.url,
            path: path || null,
            host,
            mutationSummary: mutations.length > 0 ? mutations.join(', ').slice(0, 180) : null,
            targetInputs: (action.targetInputs || []).map((entry) => `${entry.location}:${entry.name}`).slice(0, 4),
            expectedSignals: (action.expectedSignals || []).slice(0, 4),
            selectionReason: action.selectionReason || null,
            executionPhase: action.phase || 'planned',
            confirmationKind: action.confirmationKind ?? null,
            confirmationOrdinal: action.confirmationOrdinal ?? null,
            generatedFromFindingThreadId: action.generatedFromFindingThreadId ?? null,
        };
    }

    private buildTraceResponseSummary(input: {
        statusCode?: number | null;
        body?: string | null;
        structureChanged?: boolean | null;
        bodyLengthDelta?: number | null;
        keywordSignals?: string[];
    }): FocusedExecutionTraceEntry['responseSummary'] {
        return {
            statusCode: input.statusCode ?? null,
            bodySummary: input.body ? String(input.body).slice(0, 180) : null,
            structureChanged: input.structureChanged ?? null,
            bodyLengthDelta: input.bodyLengthDelta ?? null,
            keywordSignals: input.keywordSignals || [],
        };
    }

    private buildReasoningEntryFromExecutionTrace(input: {
        objectiveId: string;
        caseFamily: FocusedCaseFamily;
        traceEntry: FocusedExecutionTraceEntry;
    }) {
        const { traceEntry } = input;
        return {
            scanId: traceEntry.scanId,
            objectiveId: input.objectiveId,
            caseId: traceEntry.caseId,
            executionId: traceEntry.executionId,
            timestamp: traceEntry.timestamp,
            stage: 'execution' as const,
            entryType: this.mapReasoningEntryType(traceEntry.actionType),
            rail: this.mapReasoningRail(traceEntry.rail),
            caseFamily: input.caseFamily,
            summary: traceEntry.actionSummary,
            observationSummary: traceEntry.responseSummary?.bodySummary
                || traceEntry.targetSummary
                || traceEntry.reasoningNote
                || null,
            hypothesisRationaleSummary: traceEntry.actionType === 'execution_started'
                ? traceEntry.reasoningNote
                : null,
            actionSelectionRationale: traceEntry.nextStepRationale || traceEntry.reasoningNote || null,
            requestResponseImpactSummary: this.buildReasoningRequestResponseImpact(traceEntry),
            browserStateImpactSummary: this.buildReasoningBrowserImpact(traceEntry),
            confidenceShiftSummary: this.buildReasoningConfidenceShift(traceEntry),
            stopRetryBlockRationale: traceEntry.stopReason || traceEntry.retryReason || null,
            linkedEvidenceIds: traceEntry.linkedEvidenceIds || [],
            linkedRequestContextKeys: [],
            contextInfluence: [],
        };
    }

    private mapReasoningEntryType(actionType: FocusedExecutionTraceActionType) {
        switch (actionType) {
            case 'execution_started':
            case 'retry_context':
                return 'decision' as const;
            case 'action_planned':
                return 'action' as const;
            case 'request_dispatch':
            case 'browser_sequence_started':
                return 'action' as const;
            case 'response_observed':
            case 'browser_sequence_result':
            case 'screenshot_captured':
                return 'observation' as const;
            case 'response_compared':
            case 'execution_completed':
                return 'result' as const;
            case 'execution_failed':
            case 'blocked':
            case 'skipped':
                return 'constraint' as const;
            default:
                return 'observation' as const;
        }
    }

    private mapReasoningRail(rail: FocusedExecutionRail) {
        switch (rail) {
            case 'request':
            case 'browser':
            case 'hybrid':
                return rail;
            default:
                return 'system_only' as const;
        }
    }

    private buildReasoningRequestResponseImpact(traceEntry: FocusedExecutionTraceEntry): string | null {
        if (!traceEntry.requestSummary && !traceEntry.responseSummary) {
            return null;
        }
        return [
            traceEntry.requestSummary
                ? [traceEntry.requestSummary.method, traceEntry.requestSummary.path || traceEntry.requestSummary.url, traceEntry.requestSummary.mutationSummary].filter(Boolean).join(' ')
                : null,
            traceEntry.responseSummary
                ? [
                    typeof traceEntry.responseSummary.statusCode === 'number' ? `HTTP ${traceEntry.responseSummary.statusCode}` : null,
                    traceEntry.responseSummary.structureChanged ? 'structure changed' : null,
                    typeof traceEntry.responseSummary.bodyLengthDelta === 'number' ? `body delta ${traceEntry.responseSummary.bodyLengthDelta}` : null,
                    traceEntry.responseSummary.keywordSignals?.length ? traceEntry.responseSummary.keywordSignals.join(', ') : null,
                ].filter(Boolean).join(' | ')
                : null,
        ].filter(Boolean).join(' => ') || null;
    }

    private buildReasoningBrowserImpact(traceEntry: FocusedExecutionTraceEntry): string | null {
        if (traceEntry.actionType !== 'browser_sequence_result' && traceEntry.actionType !== 'screenshot_captured') {
            return null;
        }
        return [
            traceEntry.targetSummary,
            traceEntry.responseSummary?.bodySummary,
            traceEntry.reasoningNote,
        ].filter(Boolean).join(' | ') || null;
    }

    private buildReasoningConfidenceShift(traceEntry: FocusedExecutionTraceEntry): string | null {
        if (traceEntry.actionType === 'response_compared') {
            return traceEntry.responseSummary?.bodySummary || traceEntry.reasoningNote || null;
        }
        if (traceEntry.actionType === 'blocked' || traceEntry.actionType === 'execution_failed') {
            return traceEntry.stopReason || traceEntry.reasoningNote || null;
        }
        if (traceEntry.actionType === 'execution_completed') {
            return traceEntry.reasoningNote || null;
        }
        return null;
    }

    private resolveRequestAnchor(
        targetUrl: string,
        testCase: FocusedTestCase,
        scopeEnvelope: any,
        initialRequest?: string | null,
    ): FocusedExecutionAnchor | null {
        const selectedEndpoint = this.findSelectedEndpoint(testCase, scopeEnvelope.selectedEndpoints || []);
        const discoveredRequestRef = this.findDiscoveredRequestRef(testCase, scopeEnvelope.discoveredRequestRefs || []);
        const baselineRef = scopeEnvelope.baselineRequestRefs?.[0] || null;
        const parsedBaseline = initialRequest?.trim() ? parseRawBurpRequest(initialRequest.trim()) : null;
        const artifactPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url);
        const artifactUrl = this.normalizeUrl(testCase.targetArtifact.url) || undefined;

        if (testCase.targetArtifact.kind === 'baseline_request') {
            const url = artifactUrl || baselineRef?.url || parsedBaseline?.url;
            if (!url) {
                return null;
            }
            return {
                defaultMethod: testCase.targetArtifact.method?.toUpperCase() || baselineRef?.method || parsedBaseline?.method || 'GET',
                defaultUrl: url,
                defaultPath: artifactPath || baselineRef?.path || parsedBaseline?.pathWithQuery,
                useInitialRequestBaseline: true,
                baselineAvailable: true,
                requestShape: this.buildObservedRequestShape(parsedBaseline, testCase.targetArtifact, url),
            };
        }

        if (testCase.targetArtifact.kind === 'endpoint') {
            const path = artifactPath
                || this.normalizeRoutePath(selectedEndpoint?.path || selectedEndpoint?.url)
                || this.normalizeRoutePath(discoveredRequestRef?.path || discoveredRequestRef?.url);
            if (!path) {
                return null;
            }
            return {
                defaultMethod: testCase.targetArtifact.method?.toUpperCase() || selectedEndpoint?.method || discoveredRequestRef?.method || 'GET',
                defaultUrl: artifactUrl || selectedEndpoint?.url || discoveredRequestRef?.url || this.buildAbsoluteUrl(targetUrl, path),
                defaultPath: path,
                useInitialRequestBaseline: false,
                baselineAvailable: !!baselineRef,
                requestShape: this.buildObservedRequestShape(parsedBaseline, testCase.targetArtifact, artifactUrl || selectedEndpoint?.url || discoveredRequestRef?.url || this.buildAbsoluteUrl(targetUrl, path)),
            };
        }

        const fallbackPath = artifactPath
            || this.normalizeRoutePath(selectedEndpoint?.path || selectedEndpoint?.url)
            || this.normalizeRoutePath(discoveredRequestRef?.path || discoveredRequestRef?.url)
            || baselineRef?.path
            || parsedBaseline?.pathWithQuery;
        const fallbackUrl = artifactUrl
            || selectedEndpoint?.url
            || discoveredRequestRef?.url
            || baselineRef?.url
            || (fallbackPath ? this.buildAbsoluteUrl(targetUrl, fallbackPath) : undefined);

        if (!fallbackUrl) {
            return null;
        }

        return {
            defaultMethod: testCase.targetArtifact.method?.toUpperCase() || selectedEndpoint?.method || discoveredRequestRef?.method || baselineRef?.method || parsedBaseline?.method || 'GET',
            defaultUrl: fallbackUrl,
            defaultPath: fallbackPath,
            useInitialRequestBaseline: !!baselineRef && !selectedEndpoint && !discoveredRequestRef,
            baselineAvailable: !!baselineRef,
            requestShape: this.buildObservedRequestShape(parsedBaseline, testCase.targetArtifact, fallbackUrl),
        };
    }

    private resolveBrowserAnchor(
        targetUrl: string,
        testCase: FocusedTestCase,
        scopeEnvelope: any,
        initialRequest?: string | null,
    ): FocusedBrowserAnchor | null {
        const selectedEndpoint = this.findSelectedEndpoint(testCase, scopeEnvelope.selectedEndpoints || []);
        const discoveredRequestRef = this.findDiscoveredRequestRef(testCase, scopeEnvelope.discoveredRequestRefs || []);
        const discoveredBrowserAnchor = this.findBrowserAnchor(testCase, scopeEnvelope.browserAnchors || []);
        const baselineRef = scopeEnvelope.baselineRequestRefs?.[0] || null;
        const parsedBaseline = initialRequest?.trim() ? parseRawBurpRequest(initialRequest.trim()) : null;
        const artifactPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url);
        const artifactUrl = this.normalizeUrl(testCase.targetArtifact.url) || undefined;

        if (artifactUrl || artifactPath) {
            return {
                startUrl: artifactUrl || this.buildAbsoluteUrl(targetUrl, artifactPath!),
                startPath: artifactPath || this.normalizeRoutePath(artifactUrl),
                source: 'target_artifact',
            };
        }

        if (testCase.targetArtifact.kind !== 'endpoint' && discoveredBrowserAnchor?.startUrl) {
            return {
                startUrl: discoveredBrowserAnchor.startUrl,
                startPath: this.normalizeRoutePath(discoveredBrowserAnchor.startPath || discoveredBrowserAnchor.startUrl),
                source: discoveredBrowserAnchor.source === 'request_url' ? 'request_url' : 'discovered_browser',
            };
        }

        if (selectedEndpoint?.url || selectedEndpoint?.path) {
            return {
                startUrl: selectedEndpoint.url || this.buildAbsoluteUrl(targetUrl, selectedEndpoint.path),
                startPath: this.normalizeRoutePath(selectedEndpoint.path || selectedEndpoint.url),
                source: 'selected_endpoint',
            };
        }

        if (discoveredBrowserAnchor?.startUrl) {
            return {
                startUrl: discoveredBrowserAnchor.startUrl,
                startPath: this.normalizeRoutePath(discoveredBrowserAnchor.startPath || discoveredBrowserAnchor.startUrl),
                source: discoveredBrowserAnchor.source === 'request_url' ? 'request_url' : 'discovered_browser',
            };
        }

        if (discoveredRequestRef?.url || discoveredRequestRef?.path) {
            const discoveredUrl = discoveredRequestRef.url || this.buildAbsoluteUrl(targetUrl, discoveredRequestRef.path);
            return {
                startUrl: discoveredUrl,
                startPath: this.normalizeRoutePath(discoveredRequestRef.path || discoveredUrl),
                source: discoveredRequestRef.source === 'request_url' ? 'request_url' : 'discovered_request',
            };
        }

        if (baselineRef?.url || baselineRef?.path || parsedBaseline?.url || parsedBaseline?.pathWithQuery) {
            const baselineUrl = baselineRef?.url || parsedBaseline?.url || this.buildAbsoluteUrl(targetUrl, baselineRef?.path || parsedBaseline?.pathWithQuery);
            return {
                startUrl: baselineUrl,
                startPath: this.normalizeRoutePath(baselineRef?.path || parsedBaseline?.pathWithQuery || baselineUrl),
                source: 'baseline_request',
            };
        }

        const allowedRoute = Array.isArray(scopeEnvelope.allowedRoutes) ? scopeEnvelope.allowedRoutes.find((entry: string) => !!this.normalizeRoutePath(entry)) : null;
        if (allowedRoute) {
            return {
                startUrl: this.buildAbsoluteUrl(targetUrl, allowedRoute),
                startPath: this.normalizeRoutePath(allowedRoute),
                source: 'allowed_route',
            };
        }

        return null;
    }

    private findSelectedEndpoint(testCase: FocusedTestCase, selectedEndpoints: Array<{ method?: string; path?: string; url?: string }>): { method?: string; path?: string; url?: string } | null {
        const targetPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url);
        const targetMethod = testCase.targetArtifact.method?.toUpperCase();
        if (!targetPath) {
            return selectedEndpoints[0] || null;
        }

        return selectedEndpoints.find((endpoint) => {
            const endpointPath = this.normalizeRoutePath(endpoint.path || endpoint.url);
            const endpointMethod = endpoint.method?.toUpperCase();
            return !!endpointPath
                && this.routeMatches(targetPath, endpointPath)
                && (!targetMethod || !endpointMethod || endpointMethod === targetMethod);
        }) || selectedEndpoints[0] || null;
    }

    private findDiscoveredRequestRef(
        testCase: FocusedTestCase,
        discoveredRequestRefs: Array<{ id?: string; method?: string; path?: string; url?: string; source?: string }>,
    ): { id?: string; method?: string; path?: string; url?: string; source?: string } | null {
        const targetPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url);
        const targetMethod = testCase.targetArtifact.method?.toUpperCase();
        if (!targetPath) {
            return discoveredRequestRefs[0] || null;
        }

        return discoveredRequestRefs.find((entry) => {
            const entryPath = this.normalizeRoutePath(entry.path || entry.url);
            const entryMethod = entry.method?.toUpperCase();
            return !!entryPath
                && this.routeMatches(targetPath, entryPath)
                && (!targetMethod || !entryMethod || entryMethod === targetMethod);
        }) || discoveredRequestRefs[0] || null;
    }

    private findBrowserAnchor(
        testCase: FocusedTestCase,
        browserAnchors: Array<{ startUrl?: string; startPath?: string; source?: string }>,
    ): { startUrl?: string; startPath?: string; source?: string } | null {
        const targetPath = this.normalizeRoutePath(testCase.targetArtifact.path || testCase.targetArtifact.url);
        if (!targetPath) {
            return browserAnchors[0] || null;
        }

        return browserAnchors.find((entry) => {
            const entryPath = this.normalizeRoutePath(entry.startPath || entry.startUrl);
            return !!entryPath && this.routeMatches(targetPath, entryPath);
        }) || browserAnchors[0] || null;
    }

    private resolveRequestAction(action: FocusedExecutionAction, anchor: FocusedExecutionAnchor): {
        method: string;
        url: string;
        preserveExplicitAuth: boolean;
        useInitialRequestBaseline: boolean;
    } {
        return {
            method: action.method || anchor.defaultMethod,
            url: action.url || anchor.defaultUrl,
            preserveExplicitAuth: action.preserveExplicitAuth ?? true,
            useInitialRequestBaseline: action.useInitialRequestBaseline ?? anchor.useInitialRequestBaseline,
        };
    }

    private buildObservedRequestShape(
        parsedBaseline: ReturnType<typeof parseRawBurpRequest> | null,
        targetArtifact: FocusedTestCase['targetArtifact'],
        url: string,
    ) {
        const pathParams = this.extractPathParams(url, targetArtifact);
        const queryParams = this.extractQueryParams(url);
        const bodyFields = parsedBaseline?.body ? this.extractBodyFields(parsedBaseline.body) : [];
        const headerFields = parsedBaseline
            ? Object.entries(parsedBaseline.headers || {}).map(([name, value]) => ({
                name,
                location: 'header' as const,
                valuePreview: String(value || '').slice(0, 80),
            }))
            : [];

        return {
            pathParams,
            queryParams,
            bodyFields,
            headerFields,
        };
    }

    private extractPathParams(url: string, targetArtifact: FocusedTestCase['targetArtifact']) {
        try {
            const parsed = new URL(url);
            const actualSegments = parsed.pathname.split('/').filter(Boolean);
            const templateSegments = this.normalizeRoutePath(targetArtifact.path || targetArtifact.url)?.split('/').filter(Boolean) || [];
            return actualSegments
                .map((segment, index) => {
                    const templateSegment = templateSegments[index];
                    if (templateSegment?.startsWith(':')) {
                        return {
                            name: templateSegment.slice(1),
                            location: 'path' as const,
                            valuePreview: segment.slice(0, 80),
                        };
                    }
                    if (/^\d+$/.test(segment) || /^[0-9a-f]{8,}$/i.test(segment)) {
                        return {
                            name: templateSegments[index - 1]?.replace(/[^A-Za-z0-9_]/g, '') || 'id',
                            location: 'path' as const,
                            valuePreview: segment.slice(0, 80),
                        };
                    }
                    return null;
                })
                .filter((entry): entry is { name: string; location: 'path'; valuePreview: string } => !!entry);
        } catch {
            return [];
        }
    }

    private extractQueryParams(url: string) {
        try {
            const parsed = new URL(url);
            return [...parsed.searchParams.entries()].map(([name, value]) => ({
                name,
                location: 'query' as const,
                valuePreview: value.slice(0, 80),
            }));
        } catch {
            return [];
        }
    }

    private extractBodyFields(body: string) {
        const trimmed = String(body || '').trim();
        if (!trimmed) {
            return [];
        }

        try {
            const parsed = JSON.parse(trimmed);
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                return Object.entries(parsed).map(([name, value]) => ({
                    name,
                    location: 'body' as const,
                    valuePreview: value == null ? null : String(value).slice(0, 80),
                }));
            }
        } catch {
            // Fall through to form parsing.
        }

        if (/=/.test(trimmed)) {
            return trimmed.split('&').map((entry) => entry.split('=')).map(([name, value]) => ({
                name: decodeURIComponent(String(name || '')),
                location: 'body' as const,
                valuePreview: value ? decodeURIComponent(value).slice(0, 80) : null,
            })).filter((entry) => entry.name);
        }

        return [];
    }

    private buildResponseSnapshot(response: ReturnType<typeof normalizeSendHttpResponse>): ResponseSnapshot {
        return {
            statusCode: response.statusCode,
            headers: this.normalizeHeaders(response.headers),
            body: response.body,
        };
    }

    private normalizeHeaders(headers: Record<string, any> | string[]): Record<string, string> {
        if (Array.isArray(headers)) {
            return Object.fromEntries(headers.map((line) => {
                const index = line.indexOf(':');
                return index > 0
                    ? [line.slice(0, index).trim(), line.slice(index + 1).trim()]
                    : [line.trim(), ''];
            }));
        }

        return Object.fromEntries(
            Object.entries(headers || {}).map(([key, value]) => [key, String(value)]),
        );
    }

    private async persistSkippedExecution(scanId: string, testCase: FocusedTestCase, profile: FocusedExecutionProfile, runReason: string): Promise<void> {
        const reason = !isFocusedTestCaseEnabled(testCase)
            ? 'Execution skipped because the case is disabled.'
            : !isFocusedTestCaseApproved(testCase)
                ? `Execution skipped because review state is ${testCase.reviewState}.`
                : 'Execution skipped.';
        const executionId = this.deps.createId();
        const objective = getFocusedTestObjective(scanId);

        createFocusedTestCaseExecution({
            id: executionId,
            scanId,
            caseId: testCase.id,
            objectiveId: testCase.objectiveId,
            executionState: 'skipped',
            executionProfileKey: profile.key,
            runReason,
            notesSummary: reason,
            requestActionsUsed: 0,
            browserActionsUsed: 0,
            browserSessionId: null,
            startedAt: this.deps.now(),
            completedAt: this.deps.now(),
        });
        createFocusedExecutionTraceEntry({
            id: this.deps.createId(),
            scanId,
            caseId: testCase.id,
            executionId,
            timestamp: this.deps.now(),
            actionType: 'skipped',
            actionSummary: reason,
            targetSummary: this.buildTraceTargetSummary(testCase),
            reasoningNote: 'The case did not enter bounded execution because it was not runnable under the current review or status state.',
            stopReason: reason,
            rail: 'system',
            toolSummary: 'System-owned review gate',
            linkedEvidenceIds: [],
        });
        if (objective) {
            focusedReasoningTraceService.record({
                scanId,
                objectiveId: objective.id,
                caseId: testCase.id,
                executionId,
                stage: 'execution',
                entryType: 'constraint',
                rail: 'system_only',
                caseFamily: resolveFocusedCaseFamily(objective, testCase),
                summary: reason,
                observationSummary: this.buildTraceTargetSummary(testCase),
                stopRetryBlockRationale: reason,
            });
        }
    }

    private async persistTerminalExecution(input: {
        testCase: FocusedTestCase;
        profile: FocusedExecutionProfile;
        runReason: string;
        userId?: number;
        executionState: FocusedExecutionState;
        notesSummary: string;
        errorMessage?: string | null;
        investigationObservations?: FocusedInvestigationObservation[];
    }): Promise<void> {
        const executionId = this.deps.createId();
        const objective = getFocusedTestObjective(input.testCase.scanId);
        createFocusedTestCaseExecution({
            id: executionId,
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            objectiveId: input.testCase.objectiveId,
            executionState: input.executionState,
            executionProfileKey: input.profile.key,
            runReason: input.runReason,
            notesSummary: input.notesSummary,
            errorMessage: input.errorMessage ?? null,
            requestActionsUsed: 0,
            browserActionsUsed: 0,
            browserSessionId: null,
            startedAt: this.deps.now(),
            completedAt: this.deps.now(),
        });
        createFocusedExecutionTraceEntry({
            id: this.deps.createId(),
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            executionId,
            timestamp: this.deps.now(),
            actionType: input.executionState === 'failed_to_execute' ? 'execution_failed' : 'blocked',
            actionSummary: input.notesSummary,
            targetSummary: this.buildTraceTargetSummary(input.testCase),
            reasoningNote: input.notesSummary,
            stopReason: input.errorMessage ?? input.notesSummary,
            rail: 'system',
            toolSummary: 'System-owned preflight gate',
            linkedEvidenceIds: [],
        });
        if (objective) {
            focusedReasoningTraceService.record({
                scanId: input.testCase.scanId,
                objectiveId: objective.id,
                caseId: input.testCase.id,
                executionId,
                stage: 'execution',
                entryType: 'constraint',
                rail: 'system_only',
                caseFamily: resolveFocusedCaseFamily(objective, input.testCase),
                summary: input.notesSummary,
                observationSummary: this.buildTraceTargetSummary(input.testCase),
                stopRetryBlockRationale: input.errorMessage ?? input.notesSummary,
            });
        }

        if (input.investigationObservations?.length) {
            await this.deps.investigationService.recordExecutionObservations({
                scanId: input.testCase.scanId,
                caseId: input.testCase.id,
                executionId,
                objectiveId: input.testCase.objectiveId,
                userId: input.userId,
                observations: input.investigationObservations,
            });
            await this.deps.investigationService.finalizeExecutionIssues(
                input.testCase.scanId,
                input.testCase.id,
                executionId,
                input.userId,
            );
        }
    }

    private async persistScopeViolation(testCase: FocusedTestCase, executionId: string, profile: FocusedExecutionProfile, violation: ScopeViolationRecord): Promise<EvidenceBundle> {
        const bundle: EvidenceBundle = {
            id: this.deps.createId(),
            scanId: testCase.scanId,
            caseId: testCase.id,
            executionId,
            summary: violation.reason,
            source: 'scope_guard',
            capturedAt: this.deps.now(),
            executionNotes: violation.reason,
            provenance: this.buildProvenance(profile, violation.attemptedAction as FocusedExecutionAction['type']),
            scopeViolation: violation,
        };
        createEvidenceBundle(bundle);
        return bundle;
    }

    private async persistBudgetEvidence(
        testCase: FocusedTestCase,
        executionId: string,
        profile: FocusedExecutionProfile,
        actionType: FocusedExecutionAction['type'],
        reason: string,
        action?: Partial<FocusedExecutionAction> | null,
    ): Promise<EvidenceBundle> {
        const bundle: EvidenceBundle = {
            id: this.deps.createId(),
            scanId: testCase.scanId,
            caseId: testCase.id,
            executionId,
            summary: reason,
            source: 'execution_note',
            capturedAt: this.deps.now(),
            executionNotes: reason,
            provenance: this.buildProvenance(profile, actionType, action),
            scopeViolation: {
                reason,
                attemptedAction: actionType,
                violationKind: 'budget',
                blockedAt: this.deps.now(),
            },
        };
        createEvidenceBundle(bundle);
        return bundle;
    }

    private async persistRequestEvidence(input: {
        testCase: FocusedTestCase;
        executionId: string;
        profile: FocusedExecutionProfile;
        action: FocusedExecutionAction;
        summary: string;
        requestRef?: EvidenceBundle['requestRef'];
        responseRef?: EvidenceBundle['responseRef'];
    }): Promise<EvidenceBundle> {
        const bundle: EvidenceBundle = {
            id: this.deps.createId(),
            scanId: input.testCase.scanId,
            caseId: input.testCase.id,
            executionId: input.executionId,
            summary: input.summary,
            source: input.action.type === 'baseline_replay' ? 'baseline_replay' : 'mutated_replay',
            capturedAt: this.deps.now(),
            requestRef: input.requestRef ?? null,
            responseRef: input.responseRef ?? null,
            provenance: this.buildProvenance(input.profile, input.action.type, input.action),
        };
        createEvidenceBundle(bundle);
        return bundle;
    }

    private async persistExecutionNote(
        testCase: FocusedTestCase,
        executionId: string,
        profile: FocusedExecutionProfile,
        actionType: FocusedExecutionAction['type'],
        note: string,
        relatedEvidence: EvidenceBundle[] = [],
        action?: Partial<FocusedExecutionAction> | null,
    ): Promise<EvidenceBundle> {
        const bundle: EvidenceBundle = {
            id: this.deps.createId(),
            scanId: testCase.scanId,
            caseId: testCase.id,
            executionId,
            summary: note.slice(0, 220),
            source: 'execution_note',
            capturedAt: this.deps.now(),
            executionNotes: note,
            relatedEvidenceIds: relatedEvidence.map((entry) => entry.id),
            provenance: this.buildProvenance(profile, actionType, action),
        };
        createEvidenceBundle(bundle);
        return bundle;
    }

    private buildScopeViolationObservations(
        violation: ScopeViolationRecord,
        linkedEvidenceIds: string[],
        correlation: FocusedInvestigationObservation['correlation'],
    ): FocusedInvestigationObservation[] {
        const observations: FocusedInvestigationObservation[] = [{
            issueType: violation.violationKind === 'budget' ? 'execution_budget_exhausted' : 'scope_violation',
            issueTitle: violation.violationKind === 'budget'
                ? 'Focused execution exhausted a scoped runtime budget.'
                : 'Focused execution attempted to leave the approved scoped boundary.',
            issueDetails: violation.reason,
            issueStatus: 'open',
            impact: violation.violationKind === 'budget' ? 'degrading' : 'blocking',
            source: 'system',
            linkedEvidenceIds,
            correlation: {
                ...correlation,
                scopeViolationKinds: [violation.violationKind],
            },
        }];

        if (violation.violationKind !== 'budget') {
            observations.push({
                issueType: 'request_replay_mismatch',
                issueTitle: 'Focused request execution drifted away from the approved anchor or route.',
                issueDetails: violation.reason,
                issueStatus: 'open',
                impact: 'degrading',
                source: 'system',
                linkedEvidenceIds,
                correlation,
            });
        }

        return observations;
    }

    private buildAuthSessionDriftObservation(input: {
        scopeEnvelope: any;
        actionType: FocusedExecutionAction['type'];
        statusCode?: number | null;
        path?: string;
        executionState: FocusedExecutionState;
        linkedEvidenceIds: string[];
    }): FocusedInvestigationObservation | null {
        const authContext = input.scopeEnvelope?.authContext;
        const looksAuthenticated = authContext?.hasSessionCookies || (authContext?.providedCredentialCount || 0) > 0;
        if (!looksAuthenticated) {
            return null;
        }
        if (input.actionType !== 'baseline_replay') {
            return null;
        }
        if (input.statusCode !== 401 && input.statusCode !== 403) {
            return null;
        }

        return {
            issueType: 'auth_session_drift',
            issueTitle: 'Focused request replay appears to have lost the expected authenticated session.',
            issueDetails: `Scoped request returned HTTP ${input.statusCode} despite persisted auth context.`,
            issueStatus: 'open',
            impact: 'degrading',
            source: 'system',
            linkedEvidenceIds: input.linkedEvidenceIds,
            correlation: {
                executionState: input.executionState,
                requestActionType: input.actionType,
                observedPath: input.path,
                observedStatusCode: input.statusCode,
            },
        };
    }

    private buildProvenance(
        profile: FocusedExecutionProfile,
        actionType: FocusedExecutionAction['type'],
        action?: Partial<FocusedExecutionAction> | null,
    ) {
        return {
            profileKey: profile.key,
            actionType,
            provider: profile.provider || undefined,
            model: profile.model || undefined,
            source: profile.provider || profile.model ? 'model' as const : 'system' as const,
            executionPhase: action?.phase || 'planned',
            confirmationKind: action?.confirmationKind ?? null,
            confirmationOrdinal: action?.confirmationOrdinal ?? null,
            generatedFromFindingThreadId: action?.generatedFromFindingThreadId ?? null,
        };
    }

    private async captureScreenshotIfAvailable(browserSessionId: string | null, scan: any): Promise<{ kind: string; value: string; mimeType?: string } | null> {
        const candidateSessionId = browserSessionId || scan?.browser_session_id || scan?.browserSessionId;
        if (!candidateSessionId) {
            return null;
        }

        try {
            const screenshot = await browserService.captureScreenshot(candidateSessionId);
            if (!screenshot?.base64) {
                return null;
            }
            return {
                kind: 'browser_session_base64',
                value: screenshot.base64,
                mimeType: screenshot.mimeType,
            };
        } catch {
            return null;
        }
    }

    private buildAbsoluteUrl(targetUrl: string, path?: string | null): string {
        if (!path) {
            return targetUrl;
        }
        try {
            return new URL(path, targetUrl).toString();
        } catch {
            return path;
        }
    }

    private normalizeUrl(value?: string | null): string | undefined {
        if (!value) {
            return undefined;
        }

        try {
            return new URL(value).toString();
        } catch {
            return undefined;
        }
    }

    private normalizeRoutePath(value?: string | null): string | undefined {
        if (!value) {
            return undefined;
        }

        try {
            return new URL(value).pathname || '/';
        } catch {
            const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
            if (!withoutQuery) {
                return undefined;
            }
            return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
        }
    }

    private routeMatches(left: string, right: string): boolean {
        const escaped = left
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\/:([A-Za-z0-9_]+)/g, '/[^/]+');
        return new RegExp(`^${escaped}$`).test(right);
    }
}

export const focusedExecutionRunner = new FocusedExecutionRunner();
