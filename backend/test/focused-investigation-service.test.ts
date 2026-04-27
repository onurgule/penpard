import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-investigation-service-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { FocusedInvestigationService } = require('../src/services/runtime/FocusedInvestigationService') as typeof import('../src/services/runtime/FocusedInvestigationService');

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
        DELETE FROM focused_test_case_evidence_bundles;
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
        title: 'Investigation service objective',
        scopeType: 'flow_scoped',
        goal: 'Persist focused troubleshooting as structured product data.',
        riskTags: ['authz'],
    });
    dbModule.createScopeEnvelope({
        id: `scope-${scanId}`,
        scanId,
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/checkout', '/account/profile'],
        selectedEndpoints: [],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: ['Stay inside the persisted scoped routes.'],
        explorationBudget: null,
    });
}

function createCase(scanId: string, caseId: string, title: string) {
    dbModule.createFocusedTestCase({
        id: caseId,
        scanId,
        objectiveId: `objective-${scanId}`,
        title,
        hypothesis: 'Structured troubleshooting should remain inspectable.',
        targetArtifact: { kind: 'flow', label: title, url: 'https://app.example.com/checkout' },
        preconditions: ['Stay inside the persisted scope.'],
        steps: [{ order: 1, action: 'Attempt the bounded flow verification.' }],
        assertions: [{ kind: 'flow', description: 'Flow evidence should stay bounded.' }],
        requiredEvidence: [{ kind: 'rendered_output', description: 'Capture rendered proof when possible.' }],
        priority: 'medium',
        plannerRationaleSummary: 'Troubleshooting state should survive execution and review.',
        status: 'planned',
        reviewState: 'approved',
    });
}

function createExecution(scanId: string, caseId: string, executionId: string, executionState: import('../src/services/runtime/ScopedScanTypes').FocusedTestCaseExecution['executionState']) {
    dbModule.createFocusedTestCaseExecution({
        id: executionId,
        scanId,
        caseId,
        objectiveId: `objective-${scanId}`,
        executionState,
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: `${executionState} execution for ${caseId}`,
        startedAt: '2026-04-18T10:00:00.000Z',
        completedAt: '2026-04-18T10:00:20.000Z',
    });
}

test('FocusedInvestigationService persists lifecycle updates and aggregates unresolved blockers per scan', async () => {
    await resetDb();
    seedScopedScan('scan-investigation-service');
    createCase('scan-investigation-service', 'case-investigation-open', 'Checkout flow anchor');
    createCase('scan-investigation-service', 'case-investigation-resolved', 'Profile flow retry');
    createExecution('scan-investigation-service', 'case-investigation-open', 'exec-investigation-open', 'blocked');
    createExecution('scan-investigation-service', 'case-investigation-resolved', 'exec-investigation-resolved', 'completed');

    const service = new FocusedInvestigationService({
        profileResolver: {
            resolve: () => ({
                key: 'generic:test',
                provider: null,
                model: null,
                enhanceIssue: async () => ({
                    assistanceSummary: null,
                    expertFollowupHint: null,
                }),
                summarizeBlockers: async () => null,
            }),
        } as any,
        now: (() => {
            let tick = 0;
            return () => `2026-04-18T10:00:${String(tick++).padStart(2, '0')}.000Z`;
        })(),
        createId: (() => {
            let tick = 0;
            return () => `investigation-id-${++tick}`;
        })(),
    });

    await service.recordExecutionObservations({
        scanId: 'scan-investigation-service',
        caseId: 'case-investigation-open',
        executionId: 'exec-investigation-open',
        objectiveId: 'objective-scan-investigation-service',
        observations: [{
            issueType: 'blocked_flow',
            issueTitle: 'Checkout verification could not start without an approved anchor.',
            issueDetails: 'No approved request or browser anchor was available for this flow case.',
            issueStatus: 'open',
            impact: 'blocking',
            source: 'system',
            workaroundAttempts: [{
                attemptedAt: '2026-04-18T10:00:01.000Z',
                summary: 'Attempted bounded browser fallback.',
                outcome: 'no_change',
            }],
        }],
        applyAssistance: false,
    });
    await service.finalizeExecutionIssues('scan-investigation-service', 'case-investigation-open', 'exec-investigation-open');

    await service.recordExecutionObservations({
        scanId: 'scan-investigation-service',
        caseId: 'case-investigation-resolved',
        executionId: 'exec-investigation-resolved',
        objectiveId: 'objective-scan-investigation-service',
        observations: [{
            issueType: 'retry_failure',
            issueTitle: 'Initial bounded retry did not resolve the profile verification path.',
            issueDetails: 'The first bounded retry still missed the expected rendered state.',
            issueStatus: 'open',
            impact: 'degrading',
            source: 'system',
        }],
        applyAssistance: false,
    });
    await service.recordExecutionObservations({
        scanId: 'scan-investigation-service',
        caseId: 'case-investigation-resolved',
        executionId: 'exec-investigation-resolved',
        objectiveId: 'objective-scan-investigation-service',
        observations: [{
            issueType: 'retry_failure',
            issueTitle: 'Initial bounded retry did not resolve the profile verification path.',
            issueDetails: 'A later bounded retry succeeded after the flow was re-anchored.',
            issueStatus: 'resolved',
            impact: 'informational',
            source: 'system',
            resolvedAt: '2026-04-18T10:00:10.000Z',
            workaroundAttempts: [{
                attemptedAt: '2026-04-18T10:00:10.000Z',
                summary: 'Retried after re-anchoring the bounded profile flow.',
                outcome: 'resolved',
            }],
        }],
        applyAssistance: false,
    });
    await service.finalizeExecutionIssues('scan-investigation-service', 'case-investigation-resolved', 'exec-investigation-resolved');

    const openIssues = dbModule.listFocusedInvestigationIssuesByCase('scan-investigation-service', 'case-investigation-open');
    const resolvedIssues = dbModule.listFocusedInvestigationIssuesByCase('scan-investigation-service', 'case-investigation-resolved');
    const openSummary = service.buildCaseInvestigationSummary('scan-investigation-service', 'case-investigation-open');
    const resolvedSummary = service.buildCaseInvestigationSummary('scan-investigation-service', 'case-investigation-resolved');
    const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-investigation-service');

    assert.equal(openIssues[0]?.issueStatus, 'unresolved');
    assert.equal(openIssues[0]?.workaroundAttempts[0]?.outcome, 'no_change');
    assert.equal(resolvedIssues[0]?.issueStatus, 'resolved');
    assert.equal(resolvedIssues[0]?.workaroundAttempts.slice(-1)[0]?.outcome, 'resolved');
    assert.equal(openSummary?.unresolvedCount, 1);
    assert.equal(resolvedSummary?.unresolvedCount, 0);
    assert.equal(blockerSummary?.unresolvedByType.blocked_flow, 1);
    assert.equal(blockerSummary?.unresolvedByType.retry_failure, 0);
    assert.deepEqual(blockerSummary?.casesNeedingReview, ['case-investigation-open']);
});
