import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-execution-runner-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { FocusedExecutionRunner } = require('../src/services/runtime/FocusedExecutionRunner') as typeof import('../src/services/runtime/FocusedExecutionRunner');
const { AuthStateManager } = require('../src/services/auth/AuthStateManager') as typeof import('../src/services/auth/AuthStateManager');
const { OrchestratorRequestExecutor } = require('../src/agents/orchestrator/OrchestratorRequestExecutor') as typeof import('../src/agents/orchestrator/OrchestratorRequestExecutor');
const { focusedScopeGuard } = require('../src/services/runtime/FocusedScopeGuard') as typeof import('../src/services/runtime/FocusedScopeGuard');

async function resetDb() {
    await dbModule.initDatabase();
    dbModule.db.exec(`
        DELETE FROM focused_scan_historical_compare_summaries;
        DELETE FROM focused_test_case_historical_compares;
        DELETE FROM focused_scan_historical_compare_states;
        DELETE FROM focused_scan_blocker_summaries;
        DELETE FROM focused_test_case_investigation_issues;
        DELETE FROM focused_scan_verdict_summaries;
        DELETE FROM focused_test_case_verdicts;
        DELETE FROM focused_test_case_finding_threads;
        DELETE FROM focused_test_case_evidence_bundles;
        DELETE FROM focused_reasoning_trace_entries;
        DELETE FROM focused_test_case_execution_trace_entries;
        DELETE FROM focused_test_case_executions;
        DELETE FROM focused_test_cases;
        DELETE FROM focused_test_objectives;
        DELETE FROM scope_envelopes;
        DELETE FROM scans;
    `);
}

function seedScopedScan(scanId: string) {
    dbModule.createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });
    dbModule.createFocusedTestObjective({
        id: `objective-${scanId}`,
        scanId,
        title: 'Scoped execution objective',
        scopeType: 'endpoint_scoped',
        goal: 'Execute approved bounded request cases.',
        riskTags: ['idor'],
    });
}

test('focused execution runner executes approved cases, skips non-runnable cases, and persists diff evidence', async () => {
    await resetDb();
    seedScopedScan('scan-runner-1');

    dbModule.createScopeEnvelope({
        id: 'scope-runner-1',
        scanId: 'scan-runner-1',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/orders/:id'],
        selectedEndpoints: [{ method: 'GET', path: '/api/orders/:id', host: 'app.example.com' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: [],
        explorationBudget: { maxRequests: 4, maxRouteVariants: 1 },
    });

    const baseCase = {
        scanId: 'scan-runner-1',
        objectiveId: 'objective-scan-runner-1',
        title: 'Replay order detail',
        hypothesis: 'Order detail stays tenant-bound.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' } as const,
        preconditions: ['Reuse the scoped auth context.'],
        steps: [{ order: 1, action: 'Replay the bounded request.' }],
        assertions: [{ kind: 'authz', description: 'Unauthorized access is denied.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture a response diff.' }],
        priority: 'high' as const,
        plannerRationaleSummary: 'Keep the request bounded.',
    };

    dbModule.createFocusedTestCase({
        id: 'case-approved',
        ...baseCase,
        status: 'planned',
        reviewState: 'approved',
    });
    dbModule.createFocusedTestCase({
        id: 'case-disabled',
        ...baseCase,
        title: 'Disabled case',
        status: 'disabled',
        reviewState: 'approved',
    });
    dbModule.createFocusedTestCase({
        id: 'case-pending',
        ...baseCase,
        title: 'Pending case',
        status: 'planned',
        reviewState: 'pending_review',
    });

    const originalInitialize = AuthStateManager.prototype.initialize;
    const originalExecute = OrchestratorRequestExecutor.prototype.execute;
    const callOrder: string[] = [];
    const verdictLaunches: Array<{ scanId: string; userId?: number }> = [];
    let requestCount = 0;

    AuthStateManager.prototype.initialize = (async function initialize() {
        return;
    }) as any;
    OrchestratorRequestExecutor.prototype.execute = (async function execute(toolCall: any) {
        requestCount += 1;
        const tag = requestCount === 1 ? 'baseline' : 'mutated';
        callOrder.push(`${tag}:${toolCall.args.url}`);
        (this as any).lastExchange = {
            action: toolCall,
            result: {
                statusCode: requestCount === 1 ? 200 : 403,
                headers: { 'content-type': 'application/json' },
                body: requestCount === 1 ? '{"ok":true}' : '{"error":"forbidden"}',
            },
            rawRequest: `GET ${toolCall.args.url} HTTP/1.1`,
            rawResponse: requestCount === 1 ? 'HTTP/1.1 200 OK' : 'HTTP/1.1 403 Forbidden',
        };
        return {
            statusCode: requestCount === 1 ? 200 : 403,
            headers: { 'content-type': 'application/json' },
            body: requestCount === 1 ? '{"ok":true}' : '{"error":"forbidden"}',
        };
    }) as any;

    try {
        const runner = new FocusedExecutionRunner({
            database: dbModule.db,
            createBurpClient: () => ({
                isAvailable: async () => true,
                callTool: async (_name: string, _args: any) => ({ items: [] }),
                disconnect: () => undefined,
            }) as any,
            profileResolver: {
                resolve: () => ({
                    key: 'generic:test',
                    provider: null,
                    model: null,
                    planActions: async () => ([
                        { type: 'baseline_replay', summary: 'Capture baseline.', method: 'GET', url: 'https://app.example.com/api/orders/1' },
                        { type: 'mutated_replay', summary: 'Capture mutated response.', method: 'GET', url: 'https://app.example.com/api/orders/1?__penpard_scope_probe=1' },
                        { type: 'compare_responses', summary: 'Compare the two responses.' },
                        { type: 'complete_case', summary: 'Complete the case.' },
                    ]),
                    planConfirmationActions: async () => [],
                }),
            } as any,
            scopeGuard: focusedScopeGuard,
            verdictService: {
                generateNow: async (scanId: string, userId?: number) => {
                    verdictLaunches.push({ scanId, userId });
                    return {
                        scanId,
                        caseVerdicts: [],
                        focusedVerdictSummary: null as any,
                    };
                },
            },
            now: () => new Date().toISOString(),
            createId: (() => {
                let counter = 0;
                return () => `runner-id-${++counter}`;
            })(),
        });

        await runner.executeNow('scan-runner-1');

        const approvedExecution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-1', 'case-approved');
        const approvedEvidence = dbModule.listEvidenceBundlesByExecution('scan-runner-1', 'case-approved', approvedExecution.id);
        const disabledExecution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-1', 'case-disabled');
        const pendingExecution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-1', 'case-pending');
        const approvedTrace = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-1', 'case-approved', approvedExecution.id);
        const approvedReasoning = dbModule.listFocusedReasoningTraceEntriesByExecution('scan-runner-1', 'case-approved', approvedExecution.id);
        const approvedFindingThreads = dbModule.listFocusedFindingThreadsByExecution('scan-runner-1', 'case-approved', approvedExecution.id);
        const disabledTrace = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-1', 'case-disabled', disabledExecution.id);
        const pendingTrace = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-1', 'case-pending', pendingExecution.id);
        const caseRows = dbModule.listFocusedTestCasesWithExecutionSummary('scan-runner-1');
        const approvedCase = caseRows.find((entry: any) => entry.id === 'case-approved');
        const approvedIssues = dbModule.listFocusedInvestigationIssuesByCase('scan-runner-1', 'case-approved');
        const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-runner-1');
        const scan = dbModule.getScan('scan-runner-1');
        const baselineEvidence = approvedEvidence.find((bundle: any) => bundle.source === 'baseline_replay');
        const mutatedEvidence = approvedEvidence.find((bundle: any) => bundle.source === 'mutated_replay');
        const comparisonEvidence = approvedEvidence.find((bundle: any) => bundle.source === 'comparison');

        assert.deepEqual(callOrder, [
            'baseline:https://app.example.com/api/orders/1',
            'mutated:https://app.example.com/api/orders/1?__penpard_scope_probe=1',
        ]);
        assert.equal(approvedExecution.executionState, 'completed');
        assert.equal(approvedExecution.requestActionsUsed, 2);
        assert.equal(approvedEvidence.some((bundle: any) => bundle.source === 'comparison'), true);
        assert.ok(baselineEvidence);
        assert.ok(mutatedEvidence);
        assert.ok(comparisonEvidence);
        assert.equal(comparisonEvidence?.relatedEvidenceIds.includes(baselineEvidence?.id), true);
        assert.equal(comparisonEvidence?.relatedEvidenceIds.includes(mutatedEvidence?.id), true);
        const approvedTraceTypes = approvedTrace.map((entry: any) => entry.actionType);
        assert.equal(approvedTraceTypes[0], 'execution_started');
        assert.equal(approvedTraceTypes[approvedTraceTypes.length - 1], 'execution_completed');
        assert.equal(approvedTraceTypes.filter((entry: string) => entry === 'request_dispatch').length, 2);
        assert.equal(approvedTraceTypes.filter((entry: string) => entry === 'response_observed').length, 2);
        assert.equal(approvedTraceTypes.includes('response_compared'), true);
        assert.equal(approvedFindingThreads.length, 1);
        assert.equal(approvedFindingThreads[0]?.isPrimary, true);
        assert.equal((approvedFindingThreads[0]?.linkedTraceIds.length || 0) > 0, true);
        assert.equal((approvedFindingThreads[0]?.confirmationProgress || 0) > 0, true);
        assert.equal(approvedCase?.activeFindingThread?.id, approvedFindingThreads[0]?.id);
        assert.equal(approvedCase?.executionRailSummary?.rail, 'request');
        assert.equal(approvedCase?.executionRailSummary?.usedBurpMcp, true);
        assert.equal(approvedCase?.latestExecutionTracePreview?.some((entry: any) => entry.actionType === 'response_compared'), true);
        assert.equal(approvedReasoning.some((entry: any) => entry.stage === 'execution' && entry.entryType === 'action'), true);
        assert.equal(approvedReasoning.some((entry: any) => /HTTP 403/i.test(entry.requestResponseImpactSummary || '')), true);
        assert.equal(
            approvedReasoning.some((entry: any) => entry.linkedEvidenceIds.some((id: string) => approvedEvidence.some((bundle: any) => bundle.id === id))),
            true,
        );
        assert.equal(approvedReasoning.some((entry: any) => /compare/i.test(entry.summary) && /rejected|forbidden|403/i.test(entry.confidenceShiftSummary || '')), true);
        assert.equal(disabledExecution.executionState, 'skipped');
        assert.equal(disabledTrace[0]?.actionType, 'skipped');
        assert.equal(pendingExecution.executionState, 'skipped');
        assert.equal(pendingTrace[0]?.actionType, 'skipped');
        assert.equal(approvedIssues.length, 0);
        assert.equal(blockerSummary?.casesNeedingReview.length, 0);
        assert.equal(scan.status, 'scoped_executed');
        assert.deepEqual(verdictLaunches, [{ scanId: 'scan-runner-1', userId: 1 }]);
    } finally {
        AuthStateManager.prototype.initialize = originalInitialize;
        OrchestratorRequestExecutor.prototype.execute = originalExecute;
    }
});

test('focused execution runner injects one bounded adaptive confirmation step and persists stop reasons on the live finding thread', async () => {
    await resetDb();
    seedScopedScan('scan-runner-adaptive');

    dbModule.createScopeEnvelope({
        id: 'scope-runner-adaptive',
        scanId: 'scan-runner-adaptive',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/search'],
        selectedEndpoints: [{ method: 'GET', path: '/api/search', host: 'app.example.com' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: [],
        explorationBudget: { maxRequests: 6, maxRouteVariants: 2 },
    });

    dbModule.createFocusedTestCase({
        id: 'case-adaptive',
        scanId: 'scan-runner-adaptive',
        objectiveId: 'objective-scan-runner-adaptive',
        title: 'Probe for SQL-style backend errors',
        hypothesis: 'Scoped query manipulation may change backend behavior.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/search' },
        preconditions: ['Reuse the scoped auth context.'],
        steps: [{ order: 1, action: 'Replay the in-scope search request.' }],
        assertions: [{ kind: 'response_diff', description: 'Record backend error shifts.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture diff evidence.' }],
        priority: 'high',
        plannerRationaleSummary: 'SQL-style anomalies need one bounded confirmation replay.',
        caseFamily: 'sqli',
        maxAdaptiveFollowUps: 1,
        preferredRail: 'request',
        allowedConfirmationKinds: ['repeat_mutation', 'error_surface_compare'],
        status: 'planned',
        reviewState: 'approved',
    });

    const originalInitialize = AuthStateManager.prototype.initialize;
    const originalExecute = OrchestratorRequestExecutor.prototype.execute;
    let requestCount = 0;

    AuthStateManager.prototype.initialize = (async function initialize() {
        return;
    }) as any;
    OrchestratorRequestExecutor.prototype.execute = (async function execute(toolCall: any) {
        requestCount += 1;
        const body = requestCount === 1
            ? '{"rows":[]}'
            : requestCount === 2
                ? `{"error":"SQL syntax error near 'UNION'"}`
                : `{"error":"SQL syntax error near 'UNION ALL'"}`;
        const statusCode = requestCount === 1 ? 200 : 500;
        (this as any).lastExchange = {
            action: toolCall,
            result: {
                statusCode,
                headers: { 'content-type': 'application/json' },
                body,
            },
            rawRequest: `GET ${toolCall.args.url} HTTP/1.1`,
            rawResponse: `HTTP/1.1 ${statusCode} ${statusCode === 200 ? 'OK' : 'Internal Server Error'}`,
        };
        return {
            statusCode,
            headers: { 'content-type': 'application/json' },
            body,
        };
    }) as any;

    try {
        const runner = new FocusedExecutionRunner({
            database: dbModule.db,
            createBurpClient: () => ({
                isAvailable: async () => true,
                callTool: async (_name: string, _args: any) => ({ items: [] }),
                disconnect: () => undefined,
            }) as any,
            profileResolver: {
                resolve: () => ({
                    key: 'generic:test',
                    provider: null,
                    model: null,
                    planActions: async () => ([
                        {
                            type: 'baseline_replay',
                            summary: 'Capture baseline.',
                            method: 'GET',
                            url: 'https://app.example.com/api/search?q=test',
                            selectionReason: 'Baseline replay anchors the suspicious query behavior to the same scoped target.',
                            expectedSignals: ['Stable baseline search response'],
                            targetInputs: [{ name: 'q', location: 'query', reason: 'Observed search input.', mutationStrategy: 'type_contract_variation' }],
                        },
                        {
                            type: 'mutated_replay',
                            summary: 'Capture suspicious SQL-style mutation.',
                            method: 'GET',
                            url: 'https://app.example.com/api/search?q=test%27',
                            selectionReason: 'The observed search query is the tightest same-scope mutation target.',
                            expectedSignals: ['SQL-style parser or server-error change'],
                            targetInputs: [{ name: 'q', location: 'query', reason: 'Observed search input.', mutationStrategy: 'malformed_value' }],
                        },
                        { type: 'compare_responses', summary: 'Compare the SQL-style responses.', selectionReason: 'Only the baseline-vs-mutation comparison can strengthen the same hypothesis.' },
                        { type: 'complete_case', summary: 'Complete the case.' },
                    ]),
                    planConfirmationActions: async () => ([
                        {
                            type: 'mutated_replay',
                            summary: 'Adaptive confirmation: replay one additional bounded mutation.',
                            method: 'GET',
                            url: 'https://app.example.com/api/search?q=test%27%20order%20by%201',
                            phase: 'adaptive_confirmation',
                            confirmationKind: 'repeat_mutation',
                            confirmationOrdinal: 1,
                            selectionReason: 'The first suspicious replay raised enough suspicion to justify one more same-scope contrast.',
                            expectedSignals: ['SQL parser anomaly strengthens on the same route'],
                            targetInputs: [{ name: 'q', location: 'query', reason: 'Observed search input.', mutationStrategy: 'malformed_value' }],
                        },
                        {
                            type: 'compare_responses',
                            summary: 'Adaptive confirmation: compare the confirmation replay.',
                            phase: 'adaptive_confirmation',
                            confirmationKind: 'repeat_mutation',
                            confirmationOrdinal: 1,
                            selectionReason: 'The adaptive replay only matters if it strengthens or weakens the same bounded hypothesis.',
                        },
                    ]),
                }),
            } as any,
            scopeGuard: focusedScopeGuard,
            verdictService: {
                generateNow: async () => ({
                    scanId: 'scan-runner-adaptive',
                    caseVerdicts: [],
                    focusedVerdictSummary: null as any,
                }),
            },
            now: (() => {
                let counter = 0;
                return () => `2026-04-20T12:00:${String(counter++).padStart(2, '0')}.000Z`;
            })(),
            createId: (() => {
                let counter = 0;
                return () => `adaptive-id-${++counter}`;
            })(),
        });

        await runner.executeNow('scan-runner-adaptive');

        const execution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-adaptive', 'case-adaptive');
        const traceEntries = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-adaptive', 'case-adaptive', execution.id);
        const evidenceBundles = dbModule.listEvidenceBundlesByExecution('scan-runner-adaptive', 'case-adaptive', execution.id);
        const findingThreads = dbModule.listFocusedFindingThreadsByExecution('scan-runner-adaptive', 'case-adaptive', execution.id);
        const findingThread = findingThreads[0];
        const requestTrace = traceEntries.find((entry: any) => entry.actionType === 'request_dispatch' && /test%27/.test(entry.requestSummary?.url || ''));
        const queueTrace = traceEntries.find((entry: any) => entry.actionType === 'note_recorded' && /Queued adaptive follow-up/i.test(entry.actionSummary || ''));
        const adaptiveReplayEvidence = evidenceBundles.find((bundle: any) =>
            bundle.source === 'mutated_replay'
            && bundle.provenance?.executionPhase === 'adaptive_confirmation',
        );
        const adaptiveComparisonEvidence = evidenceBundles.find((bundle: any) =>
            bundle.source === 'comparison'
            && bundle.provenance?.executionPhase === 'adaptive_confirmation',
        );

        assert.equal(requestCount, 3);
        assert.equal(traceEntries.filter((entry: any) => entry.actionType === 'response_observed').length, 3);
        assert.equal(traceEntries.filter((entry: any) => entry.actionType === 'response_compared').length, 2);
        assert.ok(findingThread);
        assert.ok(requestTrace);
        assert.ok(adaptiveReplayEvidence);
        assert.ok(adaptiveComparisonEvidence);
        assert.deepEqual(requestTrace?.requestSummary?.targetInputs, ['query:q']);
        assert.equal((requestTrace?.requestSummary?.expectedSignals || []).includes('SQL-style parser or server-error change'), true);
        assert.match(requestTrace?.requestSummary?.selectionReason || '', /same-scope mutation target/i);
        assert.ok(queueTrace);
        assert.equal(adaptiveReplayEvidence?.provenance?.confirmationKind, 'repeat_mutation');
        assert.equal(adaptiveReplayEvidence?.provenance?.confirmationOrdinal, 1);
        assert.equal(adaptiveComparisonEvidence?.relatedEvidenceIds.includes(adaptiveReplayEvidence?.id), true);
        assert.equal(findingThread.confirmationState.usedAdaptiveFollowUps, 1);
        assert.equal(findingThread.confirmationState.steps.length, 1);
        assert.equal(findingThread.confirmationState.steps[0]?.status, 'completed');
        assert.equal(findingThread.confirmationState.exhausted, true);
        assert.match(findingThread.confirmationState.stopReason || '', /adaptive confirmation budget exhausted/i);
        assert.equal((findingThread.suspicionScore || 0) > 0, true);
        assert.equal((findingThread.confirmationProgress || 0) > 0, true);
        assert.equal(findingThread.supportProvenance?.rail, 'request');
        assert.equal(findingThread.supportProvenance?.requestBackedEvidence, true);
        assert.equal(findingThread.requestEvidenceStory?.confirmationRequestRefs.length, 1);
        assert.equal(findingThread.requestEvidenceStory?.strongestSuspiciousRequestRef?.evidenceId, adaptiveReplayEvidence?.id);
    } finally {
        AuthStateManager.prototype.initialize = originalInitialize;
        OrchestratorRequestExecutor.prototype.execute = originalExecute;
    }
});

test('focused execution runner keeps narrative-only flow/feature cases blocked when no concrete browser or request anchor exists', async () => {
    await resetDb();
    seedScopedScan('scan-runner-2');

    dbModule.createScopeEnvelope({
        id: 'scope-runner-2',
        scanId: 'scan-runner-2',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: [],
        selectedEndpoints: [],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: ['Do not widen beyond the checkout flow.'],
        boundaryHints: ['Keep testing inside the checkout flow only.'],
        explorationBudget: null,
    });

    dbModule.createFocusedTestCase({
        id: 'case-feature',
        scanId: 'scan-runner-2',
        objectiveId: 'objective-scan-runner-2',
        title: 'Narrative flow case',
        hypothesis: 'Checkout flow remains bounded.',
        targetArtifact: { kind: 'feature', label: 'Checkout flow' },
        preconditions: ['Stay inside the persisted boundary notes.'],
        steps: [{ order: 1, action: 'Exercise the narrative flow.' }],
        assertions: [{ kind: 'flow', description: 'Do not widen scope.' }],
        requiredEvidence: [{ kind: 'note', description: 'Capture why execution was blocked.' }],
        priority: 'medium',
        plannerRationaleSummary: 'Narrative flows need an anchor before Phase 1D.',
        status: 'planned',
        reviewState: 'approved',
    });

    const originalInitialize = AuthStateManager.prototype.initialize;
    const verdictLaunches: Array<{ scanId: string; userId?: number }> = [];
    AuthStateManager.prototype.initialize = (async function initialize() {
        return;
    }) as any;

    try {
        const runner = new FocusedExecutionRunner({
            database: dbModule.db,
            createBurpClient: () => ({
                isAvailable: async () => true,
                callTool: async (_name: string, _args: any) => ({ items: [] }),
                disconnect: () => undefined,
            }) as any,
            profileResolver: {
                resolve: () => ({
                    key: 'generic:test',
                    provider: null,
                    model: null,
                    planActions: async () => [],
                }),
            } as any,
            scopeGuard: focusedScopeGuard,
            verdictService: {
                generateNow: async (scanId: string, userId?: number) => {
                    verdictLaunches.push({ scanId, userId });
                    return {
                        scanId,
                        caseVerdicts: [],
                        focusedVerdictSummary: null as any,
                    };
                },
            },
            now: () => new Date().toISOString(),
            createId: (() => {
                let counter = 0;
                return () => `runner-anchor-${++counter}`;
            })(),
        });

        await runner.executeNow('scan-runner-2');

        const execution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-2', 'case-feature');
        const trace = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-2', 'case-feature', execution.id);
        const reasoningTrace = dbModule.listFocusedReasoningTraceEntriesByExecution('scan-runner-2', 'case-feature', execution.id);
        const issues = dbModule.listFocusedInvestigationIssuesByCase('scan-runner-2', 'case-feature');
        const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-runner-2');
        assert.equal(execution.executionState, 'blocked');
        assert.match(execution.notesSummary || '', /concrete request or browser anchor/i);
        assert.equal(trace[0]?.actionType, 'blocked');
        assert.equal(reasoningTrace[0]?.entryType, 'constraint');
        assert.match(reasoningTrace[0]?.stopRetryBlockRationale || '', /anchor/i);
        assert.equal(issues.length, 1);
        assert.equal(issues[0]?.issueType, 'missing_anchor');
        assert.equal(issues[0]?.issueStatus, 'unresolved');
        assert.equal(blockerSummary?.unresolvedByType.missing_anchor, 1);
        assert.deepEqual(blockerSummary?.casesNeedingReview, ['case-feature']);
        assert.deepEqual(verdictLaunches, [{ scanId: 'scan-runner-2', userId: 1 }]);
    } finally {
        AuthStateManager.prototype.initialize = originalInitialize;
    }
});

test('focused execution runner executes browser-anchored flow cases and links browser evidence', async () => {
    await resetDb();
    seedScopedScan('scan-runner-3');

    dbModule.createScopeEnvelope({
        id: 'scope-runner-3',
        scanId: 'scan-runner-3',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/account/profile'],
        selectedEndpoints: [],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: ['Stay inside the profile experience.'],
        explorationBudget: { maxBrowserActions: 4, maxNavigationDepth: 2, maxVerificationRetries: 1 },
    });

    dbModule.createFocusedTestCase({
        id: 'case-flow-browser',
        scanId: 'scan-runner-3',
        objectiveId: 'objective-scan-runner-3',
        title: 'Profile render flow',
        hypothesis: 'Profile update becomes visible in the UI.',
        targetArtifact: { kind: 'flow', url: 'https://app.example.com/account/profile', label: 'Profile flow' },
        preconditions: ['Stay inside the approved profile path.'],
        steps: [{ order: 1, action: 'Open the profile page and confirm the updated display name is visible.' }],
        assertions: [{ kind: 'state_change', description: 'The updated display name is rendered.' }],
        requiredEvidence: [{ kind: 'rendered_output', description: 'Confirm "Profile Saved" is visible.' }],
        priority: 'medium',
        plannerRationaleSummary: 'This case needs bounded browser verification.',
        status: 'planned',
        reviewState: 'approved',
    });

    const originalInitialize = AuthStateManager.prototype.initialize;
    const verdictLaunches: Array<{ scanId: string; userId?: number }> = [];
    AuthStateManager.prototype.initialize = (async function initialize() {
        return;
    }) as any;

    try {
        const runner = new FocusedExecutionRunner({
            database: dbModule.db,
            createBurpClient: () => ({
                isAvailable: async () => true,
                callTool: async (_name: string, _args: any) => ({ items: [] }),
                disconnect: () => undefined,
            }) as any,
            profileResolver: {
                resolve: () => ({
                    key: 'generic:test',
                    provider: null,
                    model: null,
                    planActions: async () => ([
                        { type: 'browser_sequence', summary: 'Open the approved profile flow.' },
                        { type: 'complete_case', summary: 'Complete the case.' },
                    ]),
                    planBrowserSequence: async () => ({
                        summary: 'Verify the approved profile path.',
                        steps: [{
                            action: 'waitForSelector',
                            summary: 'Wait for the page body to render.',
                            selector: 'body',
                        }],
                        expectations: [{
                            kind: 'rendered_output',
                            description: 'Profile saved banner is visible.',
                            matcher: 'text_contains',
                            value: 'Profile Saved',
                        }],
                    }),
                    summarizeStatefulExecution: async () => 'Browser verification stayed inside the approved profile flow.',
                }),
            } as any,
            browserFlowRunner: {
                execute: async ({ executionId, scanId, testCase }: any) => {
                    const bundle = {
                        id: 'browser-evidence-1',
                        scanId,
                        caseId: testCase.id,
                        executionId,
                        summary: 'Browser verified the approved profile page.',
                        source: 'browser_verification',
                        capturedAt: '2026-04-18T10:00:20.000Z',
                        screenshotRef: {
                            kind: 'browser_session_base64',
                            value: 'ZmFrZQ==',
                            mimeType: 'image/png',
                        },
                        browserState: {
                            sessionId: 'browser-session-1',
                            startUrl: 'https://app.example.com/account/profile',
                            finalUrl: 'https://app.example.com/account/profile',
                            finalPath: '/account/profile',
                            pageTitle: 'Profile',
                            actionCount: 1,
                            navigationDepth: 1,
                            verificationRetries: 0,
                            actionSummary: 'Browser verified the approved profile page.',
                            domSummary: 'Profile Saved',
                            stateNotes: ['Profile Saved banner visible'],
                            detectedChanges: [],
                            actions: [],
                            expectations: [{
                                kind: 'rendered_output',
                                description: 'Profile saved banner is visible.',
                                matcher: 'text_contains',
                                matched: true,
                                expected: 'Profile Saved',
                                observedSummary: 'Page text contains "Profile Saved".',
                            }],
                            screenshots: [{
                                kind: 'browser_session_base64',
                                value: 'ZmFrZQ==',
                                mimeType: 'image/png',
                            }],
                            relatedRequestEvidenceIds: [],
                        },
                        relatedEvidenceIds: [],
                        executionNotes: 'Browser verified the approved profile page.',
                        provenance: {
                            profileKey: 'generic:test',
                            actionType: 'browser_sequence',
                            source: 'system',
                        },
                    } as any;
                    dbModule.createEvidenceBundle(bundle);
                    return {
                        executionState: 'completed',
                        notesSummary: 'Browser verified the approved profile page.',
                        browserActionsUsed: 1,
                        browserSessionId: 'browser-session-1',
                        evidenceBundle: bundle,
                        evidenceIds: [bundle.id],
                        investigationObservations: [],
                    };
                },
            },
            scopeGuard: focusedScopeGuard,
            verdictService: {
                generateNow: async (scanId: string, userId?: number) => {
                    verdictLaunches.push({ scanId, userId });
                    return {
                        scanId,
                        caseVerdicts: [],
                        focusedVerdictSummary: null as any,
                    };
                },
            },
            now: () => new Date().toISOString(),
            createId: (() => {
                let counter = 0;
                return () => `runner-browser-${++counter}`;
            })(),
        });

        await runner.executeNow('scan-runner-3');

        const execution = dbModule.getLatestFocusedTestCaseExecution('scan-runner-3', 'case-flow-browser');
        const evidence = dbModule.listEvidenceBundlesByExecution('scan-runner-3', 'case-flow-browser', execution.id);
        const trace = dbModule.listFocusedExecutionTraceEntriesByExecution('scan-runner-3', 'case-flow-browser', execution.id);
        const reasoningTrace = dbModule.listFocusedReasoningTraceEntriesByExecution('scan-runner-3', 'case-flow-browser', execution.id);
        const caseRows = dbModule.listFocusedTestCasesWithExecutionSummary('scan-runner-3');
        const browserCase = caseRows.find((entry: any) => entry.id === 'case-flow-browser');
        const issues = dbModule.listFocusedInvestigationIssuesByCase('scan-runner-3', 'case-flow-browser');
        const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-runner-3');
        assert.equal(execution.executionState, 'completed');
        assert.equal(execution.browserActionsUsed, 1);
        assert.equal(execution.browserSessionId, 'browser-session-1');
        assert.equal(evidence.some((bundle: any) => bundle.source === 'browser_verification'), true);
        assert.equal(trace.some((entry: any) => entry.actionType === 'browser_sequence_started'), true);
        assert.equal(trace.some((entry: any) => entry.actionType === 'browser_sequence_result'), true);
        assert.equal(trace[trace.length - 1]?.actionType, 'execution_completed');
        assert.equal(reasoningTrace.some((entry: any) => entry.rail === 'browser'), true);
        assert.equal(reasoningTrace.some((entry: any) => entry.browserStateImpactSummary || entry.linkedEvidenceIds.length > 0), true);
        assert.equal(browserCase?.executionRailSummary?.rail, 'browser');
        assert.equal(issues.length, 0);
        assert.equal(blockerSummary?.casesNeedingReview.length, 0);
        assert.deepEqual(verdictLaunches, [{ scanId: 'scan-runner-3', userId: 1 }]);
    } finally {
        AuthStateManager.prototype.initialize = originalInitialize;
    }
});
