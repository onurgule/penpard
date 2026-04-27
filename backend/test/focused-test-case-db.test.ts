import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-test-case-db-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');

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
        DELETE FROM focused_test_case_executions;
        DELETE FROM focused_test_cases;
        DELETE FROM focused_test_objectives;
        DELETE FROM scope_envelopes;
        DELETE FROM scans;
    `);
}

function seedScopedScan(scanId: string, objectiveId: string) {
    dbModule.createScan({
        id: scanId,
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });

    dbModule.createFocusedTestObjective({
        id: objectiveId,
        scanId,
        title: 'Scoped objective',
        scopeType: 'endpoint_scoped',
        goal: 'Exercise bounded order tests.',
        riskTags: ['idor'],
    });
}

test('focused test case helpers persist, list, and update review metadata', async () => {
    await resetDb();
    seedScopedScan('scan-db-1', 'objective-db-1');

    dbModule.createFocusedTestCase({
        id: 'case-db-1',
        scanId: 'scan-db-1',
        objectiveId: 'objective-db-1',
        title: 'Authorization boundary on GET /api/orders',
        hypothesis: 'Orders may leak across tenants.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders' },
        preconditions: ['Reuse the persisted auth context.'],
        steps: [{ order: 1, action: 'Replay the in-scope request.' }],
        assertions: [{ kind: 'authz_enforced', description: 'Unauthorized data is denied.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture any leaked records.' }],
        priority: 'high',
        plannerRationaleSummary: 'Orders are authz sensitive.',
        status: 'planned',
        reviewState: 'pending_review',
    });

    const listedCases = dbModule.listFocusedTestCasesByScan('scan-db-1');
    assert.equal(listedCases.length, 1);
    assert.equal(listedCases[0]?.targetArtifact.path, '/api/orders');
    assert.equal(listedCases[0]?.steps[0]?.action, 'Replay the in-scope request.');

    const updatedCase = dbModule.updateFocusedTestCase('scan-db-1', 'case-db-1', {
        priority: 'medium',
        status: 'disabled',
        reviewState: 'approved',
    });

    assert.equal(updatedCase?.priority, 'medium');
    assert.equal(updatedCase?.status, 'disabled');
    assert.equal(updatedCase?.reviewState, 'approved');
    assert.ok(updatedCase?.updatedAt);
});

test('replaceFocusedTestCasesByScan swaps persisted cases without widening scan ownership', async () => {
    await resetDb();
    seedScopedScan('scan-db-2', 'objective-db-2');

    dbModule.createFocusedTestCase({
        id: 'case-db-2a',
        scanId: 'scan-db-2',
        objectiveId: 'objective-db-2',
        title: 'Legacy case',
        hypothesis: 'Legacy hypothesis',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/legacy' },
        preconditions: ['Existing scope'],
        steps: [{ order: 1, action: 'Replay legacy request.' }],
        assertions: [{ kind: 'authz_enforced', description: 'Legacy request stays bounded.' }],
        requiredEvidence: [{ kind: 'status_code', description: 'Capture status code.' }],
        priority: 'low',
        plannerRationaleSummary: 'Legacy rationale',
        status: 'planned',
        reviewState: 'pending_review',
    });

    dbModule.replaceFocusedTestCasesByScan('scan-db-2', [{
        id: 'case-db-2b',
        scanId: 'scan-db-2',
        objectiveId: 'objective-db-2',
        title: 'Replacement case',
        hypothesis: 'Replacement hypothesis',
        targetArtifact: { kind: 'endpoint', method: 'POST', path: '/api/orders' },
        preconditions: ['Replacement scope'],
        steps: [{ order: 1, action: 'Replay replacement request.' }],
        assertions: [{ kind: 'validation_enforced', description: 'Replacement request rejects bad input.' }],
        requiredEvidence: [{ kind: 'response_excerpt', description: 'Capture validation error.' }],
        priority: 'high',
        plannerRationaleSummary: 'Replacement rationale',
        status: 'planned',
        reviewState: 'pending_review',
    }]);

    const listedCases = dbModule.listFocusedTestCasesByScan('scan-db-2');
    assert.equal(listedCases.length, 1);
    assert.equal(listedCases[0]?.id, 'case-db-2b');
    assert.equal(dbModule.getFocusedTestCaseById('scan-db-2', 'case-db-2a'), null);
});

test('focused execution helpers persist latest execution summaries and evidence bundles', async () => {
    await resetDb();
    seedScopedScan('scan-db-3', 'objective-db-3');

    dbModule.createFocusedTestCase({
        id: 'case-db-3',
        scanId: 'scan-db-3',
        objectiveId: 'objective-db-3',
        title: 'Execution-backed case',
        hypothesis: 'Execution should persist evidence.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/1' },
        preconditions: ['Reuse the scoped auth context.'],
        steps: [{ order: 1, action: 'Replay the request.' }],
        assertions: [{ kind: 'authz', description: 'Only authorized data is returned.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture response diff.' }],
        priority: 'high',
        plannerRationaleSummary: 'Execution persistence should be inspectable.',
        status: 'planned',
        reviewState: 'approved',
    });

    dbModule.createFocusedTestCaseExecution({
        id: 'exec-db-3a',
        scanId: 'scan-db-3',
        caseId: 'case-db-3',
        objectiveId: 'objective-db-3',
        executionState: 'completed',
        executionProfileKey: 'generic:fallback',
        runReason: 'batch',
        notesSummary: 'Completed with baseline and diff evidence.',
        requestActionsUsed: 2,
        startedAt: '2026-04-18T10:00:00.000Z',
        completedAt: '2026-04-18T10:01:00.000Z',
    });

    dbModule.createEvidenceBundle({
        id: 'evidence-db-3a',
        scanId: 'scan-db-3',
        caseId: 'case-db-3',
        executionId: 'exec-db-3a',
        summary: 'Baseline replay captured.',
        source: 'baseline_replay',
        capturedAt: '2026-04-18T10:00:05.000Z',
        requestRef: { method: 'GET', url: 'https://app.example.com/api/orders/1' },
        responseRef: { statusCode: 200, raw: 'HTTP/1.1 200 OK' },
        provenance: {
            profileKey: 'generic:fallback',
            actionType: 'baseline_replay',
            source: 'system',
        },
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-db-3b',
        scanId: 'scan-db-3',
        caseId: 'case-db-3',
        executionId: 'exec-db-3a',
        summary: 'Scope violation was blocked.',
        source: 'scope_guard',
        capturedAt: '2026-04-18T10:00:20.000Z',
        scopeViolation: {
            reason: 'Attempted path /admin is outside the persisted allowed routes.',
            attemptedAction: 'mutated_replay',
            attemptedPath: '/admin',
            violationKind: 'route',
            blockedAt: '2026-04-18T10:00:20.000Z',
        },
        provenance: {
            profileKey: 'generic:fallback',
            actionType: 'mutated_replay',
            source: 'system',
        },
    });

    const latestExecution = dbModule.getLatestFocusedTestCaseExecution('scan-db-3', 'case-db-3');
    const summaries = dbModule.listFocusedExecutionSummariesByScan('scan-db-3');
    const enrichedCases = dbModule.listFocusedTestCasesWithExecutionSummary('scan-db-3');
    const evidence = dbModule.listEvidenceBundlesByExecution('scan-db-3', 'case-db-3', 'exec-db-3a');
    dbModule.upsertFocusedFindingThread({
        id: 'thread-db-3a',
        scanId: 'scan-db-3',
        caseId: 'case-db-3',
        executionId: 'exec-db-3a',
        objectiveId: 'objective-db-3',
        findingKey: 'family:generic:runtime',
        title: 'Potential scoped finding on GET /api/orders/1',
        family: 'generic',
        status: 'strengthening',
        suspicionScore: 41,
        confirmationProgress: 48,
        confidenceBand: 'medium',
        isPrimary: true,
        strongestSupportSummary: 'Response evidence is being collected live.',
        strongestSuspiciousSignal: 'Response evidence is being collected live.',
        strongestBlockerSummary: null,
        nextStepSummary: 'Compare the latest bounded response evidence.',
        stopReason: null,
        supportingSignals: ['Response evidence is being collected live.'],
        blockingConstraints: [],
        supportingEvidenceRefs: [],
        blockingEvidenceRefs: [],
        linkedTraceIds: ['trace-db-3a'],
        linkedVerdictIds: [],
        linkedInvestigationIds: [],
        confirmationState: {
            maxAdaptiveFollowUps: 1,
            usedAdaptiveFollowUps: 0,
            preferredRail: 'request',
            allowedConfirmationKinds: ['control_contrast'],
            recommendedConfirmationKinds: ['control_contrast'],
            nextKind: 'control_contrast',
            nextStepSummary: 'Compare the latest bounded response evidence.',
            readyForAdaptiveConfirmation: true,
            exhausted: false,
            stopReason: null,
            steps: [],
        },
        publishedFindingId: null,
        createdAt: '2026-04-18T10:00:30.000Z',
        updatedAt: '2026-04-18T10:00:30.000Z',
    });
    const latestThreadsByCase = dbModule.listLatestFocusedFindingThreadsByCase('scan-db-3', 'case-db-3');
    const latestPrimaryThread = dbModule.getLatestPrimaryFocusedFindingThreadByCase('scan-db-3', 'case-db-3');
    const enrichedCasesWithThreads = dbModule.listFocusedTestCasesWithExecutionSummary('scan-db-3');

    assert.equal(latestExecution?.id, 'exec-db-3a');
    assert.equal(summaries.length, 1);
    assert.equal(summaries[0]?.executionState, 'completed');
    assert.equal(summaries[0]?.evidenceCount, 2);
    assert.equal(summaries[0]?.scopeViolationCount, 1);
    assert.equal(enrichedCases[0]?.executionState, 'completed');
    assert.equal(enrichedCases[0]?.executionProfileKey, 'generic:fallback');
    assert.equal(evidence.length, 2);
    assert.equal(latestThreadsByCase.length, 1);
    assert.equal(latestPrimaryThread?.id, 'thread-db-3a');
    assert.equal(enrichedCasesWithThreads[0]?.activeFindingThread?.id, 'thread-db-3a');
    assert.equal(enrichedCasesWithThreads[0]?.confirmationState?.nextKind, 'control_contrast');
});

test('focused verdict helpers persist per-execution verdicts and scan summaries', async () => {
    await resetDb();
    seedScopedScan('scan-db-verdicts', 'objective-db-verdicts');

    dbModule.createFocusedTestCase({
        id: 'case-db-verdict',
        scanId: 'scan-db-verdicts',
        objectiveId: 'objective-db-verdicts',
        title: 'Verdict-backed case',
        hypothesis: 'Verdicts should project onto the latest execution only.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' },
        preconditions: ['Reuse the scoped auth context.'],
        steps: [{ order: 1, action: 'Replay the request.' }],
        assertions: [{ kind: 'validation_enforced', description: 'Bounded invalid input is rejected.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture response diff.' }],
        priority: 'high',
        plannerRationaleSummary: 'Verdict persistence should be inspectable.',
        status: 'planned',
        reviewState: 'approved',
    });

    dbModule.createFocusedTestCaseExecution({
        id: 'exec-db-verdict-old',
        scanId: 'scan-db-verdicts',
        caseId: 'case-db-verdict',
        objectiveId: 'objective-db-verdicts',
        executionState: 'completed',
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: 'Older execution.',
        requestActionsUsed: 1,
        startedAt: '2026-04-18T08:00:00.000Z',
        completedAt: '2026-04-18T08:01:00.000Z',
    });
    dbModule.createFocusedTestCaseExecution({
        id: 'exec-db-verdict-new',
        scanId: 'scan-db-verdicts',
        caseId: 'case-db-verdict',
        objectiveId: 'objective-db-verdicts',
        executionState: 'completed',
        executionProfileKey: 'generic:test',
        runReason: 'retry',
        notesSummary: 'Latest execution.',
        requestActionsUsed: 2,
        startedAt: '2026-04-18T09:00:00.000Z',
        completedAt: '2026-04-18T09:01:00.000Z',
    });

    dbModule.upsertFocusedCaseVerdict({
        id: 'verdict-db-old',
        scanId: 'scan-db-verdicts',
        caseId: 'case-db-verdict',
        executionId: 'exec-db-verdict-old',
        objectiveId: 'objective-db-verdicts',
        verdictState: 'inconclusive',
        verdictReason: 'Older verdict should not project once a newer execution exists.',
        evidenceSufficiency: {
            state: 'insufficient',
            summary: 'Older execution was missing evidence.',
            anchoredToTarget: true,
            anchoredMethod: 'GET',
            anchoredPath: '/api/orders/1',
            supportingEvidenceIds: [],
            missingRequirements: ['response_diff'],
            unsupportedRequirements: [],
            contradictorySignals: [],
            underminedByScopeViolation: false,
            requirementEvaluations: [],
        },
        supportingEvidenceRefs: [],
        scopeViolationImpact: {
            hasScopeViolation: false,
            severity: 'none',
            underminesConfidence: false,
            reasons: [],
        },
        executionSnapshot: {
            executionId: 'exec-db-verdict-old',
            executionState: 'completed',
            executionProfileKey: 'generic:test',
            requestActionsUsed: 1,
        },
        verdictAt: '2026-04-18T08:02:00.000Z',
    });
    dbModule.upsertFocusedCaseVerdict({
        id: 'verdict-db-new',
        scanId: 'scan-db-verdicts',
        caseId: 'case-db-verdict',
        executionId: 'exec-db-verdict-new',
        objectiveId: 'objective-db-verdicts',
        verdictState: 'pass',
        verdictReason: 'Latest execution has a persisted pass verdict.',
        evidenceSufficiency: {
            state: 'sufficient',
            summary: 'Latest execution captured required evidence.',
            anchoredToTarget: true,
            anchoredMethod: 'GET',
            anchoredPath: '/api/orders/1',
            supportingEvidenceIds: ['evidence-1'],
            missingRequirements: [],
            unsupportedRequirements: [],
            contradictorySignals: [],
            underminedByScopeViolation: false,
            requirementEvaluations: [],
        },
        supportingEvidenceRefs: [{
            evidenceId: 'evidence-1',
            source: 'comparison',
            role: 'comparison',
            summary: 'Status 200 to 403',
            capturedAt: '2026-04-18T09:00:30.000Z',
        }],
        scopeViolationImpact: {
            hasScopeViolation: false,
            severity: 'none',
            underminesConfidence: false,
            reasons: [],
        },
        executionSnapshot: {
            executionId: 'exec-db-verdict-new',
            executionState: 'completed',
            executionProfileKey: 'generic:test',
            requestActionsUsed: 2,
        },
        assistanceProfileKey: 'generic:test',
        assistanceNarrative: 'Operator-facing verdict narrative.',
        verdictAt: '2026-04-18T09:02:00.000Z',
    });

    dbModule.upsertFocusedScanVerdictSummary({
        scanId: 'scan-db-verdicts',
        objectiveId: 'objective-db-verdicts',
        overallVerdict: 'pass',
        totalCases: 1,
        countsByVerdict: {
            pass: 1,
            fail: 0,
            inconclusive: 0,
            needs_review: 0,
        },
        manualReviewRecommended: false,
        majorBlockers: [],
        latestVerdictAt: '2026-04-18T09:02:00.000Z',
    });

    const latestCaseVerdict = dbModule.getLatestFocusedCaseVerdictByCase('scan-db-verdicts', 'case-db-verdict');
    const latestExecutionVerdict = dbModule.getFocusedCaseVerdictByExecution('scan-db-verdicts', 'case-db-verdict', 'exec-db-verdict-new');
    const verdictsByCase = dbModule.listFocusedCaseVerdictsByCase('scan-db-verdicts', 'case-db-verdict');
    const projectedCases = dbModule.listFocusedTestCasesWithExecutionSummary('scan-db-verdicts');
    const summary = dbModule.getFocusedScanVerdictSummary('scan-db-verdicts');

    assert.equal(verdictsByCase.length, 2);
    assert.equal(latestCaseVerdict?.executionId, 'exec-db-verdict-new');
    assert.equal(latestExecutionVerdict?.verdictState, 'pass');
    assert.equal(projectedCases[0]?.latestVerdict?.executionId, 'exec-db-verdict-new');
    assert.equal(projectedCases[0]?.latestVerdict?.assistanceNarrative, 'Operator-facing verdict narrative.');
    assert.equal(summary?.overallVerdict, 'pass');
    assert.equal(summary?.countsByVerdict.pass, 1);
});

test('focused investigation helpers persist issue history, case summaries, and blocker summaries', async () => {
    await resetDb();
    seedScopedScan('scan-db-investigation', 'objective-db-investigation');

    dbModule.createFocusedTestCase({
        id: 'case-db-investigation',
        scanId: 'scan-db-investigation',
        objectiveId: 'objective-db-investigation',
        title: 'Investigation-backed case',
        hypothesis: 'Troubleshooting should persist as product data.',
        targetArtifact: { kind: 'flow', label: 'Checkout flow', url: 'https://app.example.com/checkout' },
        preconditions: ['Stay inside the scoped checkout boundary.'],
        steps: [{ order: 1, action: 'Attempt the bounded checkout verification flow.' }],
        assertions: [{ kind: 'flow', description: 'The flow should remain inspectable.' }],
        requiredEvidence: [{ kind: 'rendered_output', description: 'Capture a rendered confirmation.' }],
        priority: 'medium',
        plannerRationaleSummary: 'Operators need structured troubleshooting history.',
        status: 'planned',
        reviewState: 'approved',
    });

    dbModule.createFocusedTestCaseExecution({
        id: 'exec-db-investigation',
        scanId: 'scan-db-investigation',
        caseId: 'case-db-investigation',
        objectiveId: 'objective-db-investigation',
        executionState: 'blocked',
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: 'Blocked by missing anchor.',
        startedAt: '2026-04-18T10:00:00.000Z',
        completedAt: '2026-04-18T10:00:20.000Z',
    });

    dbModule.createFocusedInvestigationIssue({
        id: 'issue-db-investigation',
        scanId: 'scan-db-investigation',
        caseId: 'case-db-investigation',
        executionId: 'exec-db-investigation',
        objectiveId: 'objective-db-investigation',
        issueType: 'missing_anchor',
        issueTitle: 'The scoped case could not resolve a concrete browser anchor.',
        issueDetails: 'The flow artifact remained narrative-only, so execution could not collect bounded proof.',
        issueStatus: 'unresolved',
        impact: 'blocking',
        source: 'system',
        correlation: {
            executionState: 'blocked',
            evidenceSources: ['note'],
        },
        linkedEvidenceIds: ['evidence-db-investigation'],
        linkedVerdictIds: ['verdict-db-investigation'],
        workaroundAttempts: [{
            attemptedAt: '2026-04-18T10:00:10.000Z',
            summary: 'Attempted bounded browser fallback.',
            outcome: 'no_change',
            notes: 'A concrete approved anchor was still unavailable.',
        }],
        expertFollowupHint: 'Confirm that the selected flow is paired with an approved browser or request anchor.',
        assistanceSummary: 'Execution stayed blocked because the scoped flow could not be grounded to a concrete approved anchor.',
        assistanceProfileKey: 'generic:test',
        assistanceProvider: null,
        assistanceModel: null,
        detectedAt: '2026-04-18T10:00:05.000Z',
        resolvedAt: null,
        createdAt: '2026-04-18T10:00:05.000Z',
        updatedAt: '2026-04-18T10:00:10.000Z',
    });

    const updatedIssue = dbModule.updateFocusedInvestigationIssue('scan-db-investigation', 'case-db-investigation', 'issue-db-investigation', {
        issueStatus: 'partially_resolved',
        updatedAt: '2026-04-18T10:00:15.000Z',
    });

    dbModule.upsertFocusedScanBlockerSummary({
        scanId: 'scan-db-investigation',
        objectiveId: 'objective-db-investigation',
        countsByStatus: {
            open: 0,
            resolved: 0,
            partially_resolved: 1,
            unresolved: 0,
            not_applicable: 0,
        },
        countsByImpact: {
            informational: 0,
            degrading: 0,
            blocking: 1,
        },
        unresolvedByType: {
            scope_violation: 0,
            auth_session_drift: 0,
            missing_anchor: 1,
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
        },
        repeatedBlockers: ['missing_anchor x1'],
        casesNeedingReview: ['case-db-investigation'],
        latestMajorBlockerSummary: 'Checkout flow validation still needs a concrete approved anchor.',
        createdAt: '2026-04-18T10:00:05.000Z',
        updatedAt: '2026-04-18T10:00:15.000Z',
    });

    const issuesByCase = dbModule.listFocusedInvestigationIssuesByCase('scan-db-investigation', 'case-db-investigation');
    const issuesByExecution = dbModule.listFocusedInvestigationIssuesByExecution('scan-db-investigation', 'case-db-investigation', 'exec-db-investigation');
    const caseSummary = dbModule.getFocusedCaseInvestigationSummaryByCase('scan-db-investigation', 'case-db-investigation');
    const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-db-investigation');
    const enrichedCases = dbModule.listFocusedTestCasesWithExecutionSummary('scan-db-investigation');

    assert.equal(updatedIssue?.issueStatus, 'partially_resolved');
    assert.equal(issuesByCase.length, 1);
    assert.equal(issuesByExecution[0]?.workaroundAttempts[0]?.outcome, 'no_change');
    assert.equal(caseSummary?.latestIssueType, 'missing_anchor');
    assert.equal(caseSummary?.blockingCount, 1);
    assert.equal(blockerSummary?.latestMajorBlockerSummary, 'Checkout flow validation still needs a concrete approved anchor.');
    assert.equal(enrichedCases[0]?.investigationSummary?.latestIssueStatus, 'partially_resolved');
});

test('scoped execution terminal status is persisted while scoped_executing is recoverable', async () => {
    await resetDb();
    seedScopedScan('scan-db-4', 'objective-db-4');

    dbModule.updateScanStatus('scan-db-4', 'scoped_executing');
    let scan = dbModule.getScan('scan-db-4');
    assert.equal(scan.status, 'scoped_executing');
    assert.equal(scan.completed_at, null);

    const recovered = dbModule.recoverOrphanedScans();
    assert.equal(recovered >= 1, true);
    scan = dbModule.getScan('scan-db-4');
    assert.equal(scan.status, 'interrupted');

    dbModule.updateScanStatus('scan-db-4', 'scoped_executed');
    scan = dbModule.getScan('scan-db-4');
    assert.equal(scan.status, 'scoped_executed');
    assert.ok(scan.completed_at);
});
