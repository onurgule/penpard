import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-verdict-service-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { FocusedVerdictService } = require('../src/services/runtime/FocusedVerdictService') as typeof import('../src/services/runtime/FocusedVerdictService');

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
        DELETE FROM focused_test_case_findings;
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

function createVerdictService() {
    let counter = 0;
    return new FocusedVerdictService({
        database: dbModule.db,
        profileResolver: {
            resolve: () => ({
                key: 'generic:test',
                provider: null,
                model: null,
                explainVerdict: async () => 'Draft operator-facing verdict narrative.',
            }),
        } as any,
        now: () => `2026-04-18T10:${String(counter++).padStart(2, '0')}:00.000Z`,
        createId: () => `verdict-id-${++counter}`,
    });
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
        title: 'Scoped verdict objective',
        scopeType: 'endpoint_scoped',
        goal: 'Turn focused execution evidence into final verdicts.',
        riskTags: ['validation'],
    });
    dbModule.createScopeEnvelope({
        id: `scope-${scanId}`,
        scanId,
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/orders/:id'],
        selectedEndpoints: [{ method: 'GET', path: '/api/orders/:id', host: 'app.example.com' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: ['Stay inside the selected order detail endpoint.'],
        explorationBudget: { maxRequests: 4, maxRouteVariants: 1 },
    });
}

function createCase(scanId: string, caseId: string, overrides: Partial<import('../src/services/runtime/ScopedScanTypes').FocusedTestCase> = {}) {
    dbModule.createFocusedTestCase({
        id: caseId,
        scanId,
        objectiveId: `objective-${scanId}`,
        title: `Case ${caseId}`,
        hypothesis: 'Scoped evidence should be verdictable.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' },
        preconditions: ['Reuse the persisted auth context.'],
        steps: [{ order: 1, action: 'Replay the bounded request.' }],
        assertions: [{ kind: 'validation_enforced', description: 'Unexpected input is rejected.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture a response diff.' },
            { kind: 'status_code', description: 'Capture the status code transition.' },
        ],
        priority: 'high',
        plannerRationaleSummary: 'Verdict evaluation needs deterministic evidence.',
        status: 'planned',
        reviewState: 'approved',
        ...overrides,
    });
}

function createExecution(
    scanId: string,
    caseId: string,
    executionId: string,
    executionState: import('../src/services/runtime/ScopedScanTypes').FocusedTestCaseExecution['executionState'],
    overrides: Partial<import('../src/services/runtime/ScopedScanTypes').FocusedTestCaseExecution> = {},
) {
    dbModule.createFocusedTestCaseExecution({
        id: executionId,
        scanId,
        caseId,
        objectiveId: `objective-${scanId}`,
        executionState,
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: `${executionState} execution for ${caseId}`,
        requestActionsUsed: executionState === 'completed' ? 2 : 0,
        startedAt: '2026-04-18T09:00:00.000Z',
        completedAt: executionState === 'running' || executionState === 'ready' ? null : '2026-04-18T09:01:00.000Z',
        ...overrides,
    });
}

function createRequestEvidence(
    scanId: string,
    caseId: string,
    executionId: string,
    evidenceId: string,
    source: import('../src/services/runtime/ScopedScanTypes').EvidenceBundle['source'],
) {
    dbModule.createEvidenceBundle({
        id: evidenceId,
        scanId,
        caseId,
        executionId,
        summary: `${source} evidence`,
        source,
        capturedAt: '2026-04-18T09:00:30.000Z',
        requestRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            path: '/api/orders/1',
            host: 'app.example.com',
            raw: 'GET /api/orders/1 HTTP/1.1',
        },
        responseRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders/1',
            path: '/api/orders/1',
            host: 'app.example.com',
            statusCode: 200,
            raw: 'HTTP/1.1 200 OK',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: source === 'baseline_replay' ? 'baseline_replay' : 'mutated_replay',
            source: 'system',
        },
    });
}

function createComparisonEvidence(
    scanId: string,
    caseId: string,
    executionId: string,
    evidenceId: string,
    diff: {
        summary: string;
        originalStatus: number;
        mutatedStatus: number;
        significant: boolean;
        keywordSignals?: string[];
    },
) {
    dbModule.createEvidenceBundle({
        id: evidenceId,
        scanId,
        caseId,
        executionId,
        summary: diff.summary,
        source: 'comparison',
        capturedAt: '2026-04-18T09:00:45.000Z',
        responseDiffSummary: {
            summary: diff.summary,
            significant: diff.significant,
            originalStatus: diff.originalStatus,
            mutatedStatus: diff.mutatedStatus,
            keywordSignals: diff.keywordSignals || [],
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'compare_responses',
            source: 'system',
        },
    });
}

test('focused verdict service persists strict pass/fail verdicts and aggregate precedence', async () => {
    await resetDb();
    seedScopedScan('scan-verdict-pass-fail');

    createCase('scan-verdict-pass-fail', 'case-pass');
    createExecution('scan-verdict-pass-fail', 'case-pass', 'exec-pass', 'completed');
    createRequestEvidence('scan-verdict-pass-fail', 'case-pass', 'exec-pass', 'evidence-pass-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-pass-fail', 'case-pass', 'exec-pass', 'evidence-pass-diff', {
        summary: 'Status 200 to 403 after bounded mutation',
        originalStatus: 200,
        mutatedStatus: 403,
        significant: true,
    });

    createCase('scan-verdict-pass-fail', 'case-fail', {
        assertions: [{ kind: 'authz_enforced', description: 'Unauthorized access stays blocked.' }],
    });
    createExecution('scan-verdict-pass-fail', 'case-fail', 'exec-fail', 'completed');
    createRequestEvidence('scan-verdict-pass-fail', 'case-fail', 'exec-fail', 'evidence-fail-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-pass-fail', 'case-fail', 'exec-fail', 'evidence-fail-diff', {
        summary: 'Status 403 to 200 after bounded mutation',
        originalStatus: 403,
        mutatedStatus: 200,
        significant: true,
        keywordSignals: ['FORBIDDEN_BYPASSED'],
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-verdict-pass-fail', 1);

    const passVerdict = result.caseVerdicts.find((entry) => entry.caseId === 'case-pass');
    const failVerdict = result.caseVerdicts.find((entry) => entry.caseId === 'case-fail');
    const summary = dbModule.getFocusedScanVerdictSummary('scan-verdict-pass-fail');
    const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-verdict-pass-fail');

    assert.equal(passVerdict?.verdictState, 'pass');
    assert.equal(passVerdict?.evidenceSufficiency.state, 'sufficient');
    assert.equal(passVerdict?.assistanceNarrative, 'Draft operator-facing verdict narrative.');
    assert.equal(passVerdict?.interpretationSummary.caseFamily, 'input_validation');
    assert.equal((passVerdict?.interpretationSummary.controlSignals.length || 0) > 0, true);
    assert.match(passVerdict?.interpretationSummary.followUpDecisionSummary || '', /control-held result/i);
    assert.equal(passVerdict?.supportProvenance?.rail, 'request');
    assert.equal(passVerdict?.supportProvenance?.requestBackedEvidence, true);
    assert.equal(passVerdict?.requestEvidenceStory?.baselineRequestRef?.source, 'baseline_replay');
    assert.equal(passVerdict?.requestEvidenceStory?.hasRequestBackedEvidence, true);
    assert.equal(failVerdict?.verdictState, 'fail');
    assert.equal(failVerdict?.evidenceSufficiency.state, 'sufficient');
    assert.equal(failVerdict?.interpretationSummary.caseFamily, 'access_control');
    assert.equal((failVerdict?.interpretationSummary.failSignals.length || 0) > 0, true);
    assert.match(failVerdict?.interpretationSummary.followUpDecisionSummary || '', /queue one bounded/i);
    assert.equal(failVerdict?.supportProvenance?.rail, 'request');
    assert.equal(failVerdict?.requestEvidenceStory?.hasRequestBackedEvidence, true);
    assert.equal(summary?.overallVerdict, 'fail');
    assert.equal(summary?.countsByVerdict.pass, 1);
    assert.equal(summary?.countsByVerdict.fail, 1);
    assert.equal(summary?.manualReviewRecommended, false);
    assert.equal(blockerSummary?.casesNeedingReview.length, 0);
    assert.equal(summary?.majorBlockers.length, 0);
});

test('focused verdict service creates a baseline on the first comparable run and compares later runs against it', async () => {
    await resetDb();

    seedScopedScan('scan-compare-baseline');
    createCase('scan-compare-baseline', 'case-orders-baseline');
    createExecution('scan-compare-baseline', 'case-orders-baseline', 'exec-orders-baseline', 'completed');
    createRequestEvidence('scan-compare-baseline', 'case-orders-baseline', 'exec-orders-baseline', 'evidence-orders-request-baseline', 'baseline_replay');
    createComparisonEvidence('scan-compare-baseline', 'case-orders-baseline', 'exec-orders-baseline', 'evidence-orders-diff-baseline', {
        summary: 'Status 200 to 403 after bounded mutation',
        originalStatus: 200,
        mutatedStatus: 403,
        significant: true,
    });

    const service = createVerdictService();
    await service.generateNow('scan-compare-baseline', 1);

    const baselineState = dbModule.getFocusedHistoricalCompareState('scan-compare-baseline');
    const baselineSummary = dbModule.getFocusedHistoricalCompareSummary('scan-compare-baseline');
    const baselineCaseCompare = dbModule.getFocusedCaseHistoricalCompareByCase('scan-compare-baseline', 'case-orders-baseline');

    assert.equal(baselineState?.comparisonStatus, 'baseline_created');
    assert.equal(baselineState?.baselineScanId, 'scan-compare-baseline');
    assert.equal(baselineState?.comparedAgainstScanId, null);
    assert.equal(baselineSummary?.comparisonStatus, 'baseline_created');
    assert.equal(baselineSummary?.overallChangeClassification, 'baseline_only');
    assert.equal(baselineCaseCompare?.compareStatus, 'baseline_only');

    seedScopedScan('scan-compare-followup');
    createCase('scan-compare-followup', 'case-orders-followup');
    createExecution('scan-compare-followup', 'case-orders-followup', 'exec-orders-followup', 'completed');
    createRequestEvidence('scan-compare-followup', 'case-orders-followup', 'exec-orders-followup', 'evidence-orders-request-followup', 'baseline_replay');
    createComparisonEvidence('scan-compare-followup', 'case-orders-followup', 'exec-orders-followup', 'evidence-orders-diff-followup', {
        summary: 'Status 403 to 200 after bounded mutation',
        originalStatus: 403,
        mutatedStatus: 200,
        significant: true,
        keywordSignals: ['FORBIDDEN_BYPASSED'],
    });

    await service.generateNow('scan-compare-followup', 1);

    const compareState = dbModule.getFocusedHistoricalCompareState('scan-compare-followup');
    const compareSummary = dbModule.getFocusedHistoricalCompareSummary('scan-compare-followup');
    const compareCase = dbModule.getFocusedCaseHistoricalCompareByCase('scan-compare-followup', 'case-orders-followup');

    assert.equal(compareState?.comparisonStatus, 'compared');
    assert.equal(compareState?.baselineScanId, 'scan-compare-baseline');
    assert.equal(compareState?.comparedAgainstScanId, 'scan-compare-baseline');
    assert.equal(compareSummary?.comparisonStatus, 'compared');
    assert.equal(compareSummary?.overallChangeClassification, 'regression');
    assert.equal(compareSummary?.regressedCount, 1);
    assert.equal(compareSummary?.manualReviewRecommended, true);
    assert.equal(compareCase?.compareStatus, 'exact_match');
    assert.equal(compareCase?.priorVerdict, 'pass');
    assert.equal(compareCase?.currentVerdict, 'fail');
    assert.equal(compareCase?.verdictTransition, 'pass_to_fail');
    assert.equal(compareCase?.historicalOutcome, 'regressed');
});

test('focused verdict service keeps SQLi-style internal errors review-weighted instead of forcing a fail verdict', async () => {
    await resetDb();
    seedScopedScan('scan-verdict-sqli');

    createCase('scan-verdict-sqli', 'case-sqli-review', {
        title: 'SQL injection probe on order lookup',
        hypothesis: 'SQL-style payloads may trigger backend query handling failures.',
        assertions: [{ kind: 'sqli', description: 'Identify suspicious backend query manipulation signals.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the response delta.' },
            { kind: 'status_code', description: 'Capture the status transition.' },
        ],
    });
    createExecution('scan-verdict-sqli', 'case-sqli-review', 'exec-sqli-review', 'completed');
    createRequestEvidence('scan-verdict-sqli', 'case-sqli-review', 'exec-sqli-review', 'evidence-sqli-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-sqli', 'case-sqli-review', 'exec-sqli-review', 'evidence-sqli-diff', {
        summary: 'Status 200 to 500 with INTERNAL_ERROR after bounded SQL-style payload',
        originalStatus: 200,
        mutatedStatus: 500,
        significant: true,
        keywordSignals: ['INTERNAL_ERROR', 'SQL_ERROR'],
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-verdict-sqli', 1);

    const verdict = result.caseVerdicts.find((entry) => entry.caseId === 'case-sqli-review');
    const issues = dbModule.listFocusedInvestigationIssuesByCase('scan-verdict-sqli', 'case-sqli-review');

    assert.equal(verdict?.interpretationSummary.caseFamily, 'sqli');
    assert.equal(verdict?.interpretationSummary.suspiciousness, 'high');
    assert.equal((verdict?.interpretationSummary.reviewSignals.length || 0) > 0, true);
    assert.equal(verdict?.verdictState, 'needs_review');
    assert.equal(verdict?.evidenceSufficiency.state, 'sufficient');
    assert.match(verdict?.verdictReason || '', /internal|review|sql/i);
    assert.equal(verdict?.supportProvenance?.rail, 'request');
    assert.equal(verdict?.requestEvidenceStory?.hasRequestBackedEvidence, true);
    assert.equal(issues.some((issue: any) => issue.issueType === 'environment_instability'), true);
});

test('focused verdict service keeps request-heavy browser-only evidence bounded and low confidence', async () => {
    await resetDb();
    seedScopedScan('scan-verdict-request-only');

    createCase('scan-verdict-request-only', 'case-request-heavy-browser-only', {
        title: 'Request-heavy order detail case without Burp replay evidence',
        hypothesis: 'The order detail request should stay grounded in visible request evidence.',
        assertions: [{ kind: 'authz_enforced', description: 'Unauthorized access stays blocked.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the response delta.' },
            { kind: 'status_code', description: 'Capture the status transition.' },
        ],
    });
    createExecution('scan-verdict-request-only', 'case-request-heavy-browser-only', 'exec-request-heavy-browser-only', 'completed', {
        notesSummary: 'Completed with browser-only supporting evidence.',
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-request-heavy-browser-only',
        scanId: 'scan-verdict-request-only',
        caseId: 'case-request-heavy-browser-only',
        executionId: 'exec-request-heavy-browser-only',
        summary: 'Browser observed suspicious state, but no Burp-visible replay was captured.',
        source: 'browser_verification',
        capturedAt: '2026-04-18T09:00:20.000Z',
        browserState: {
            sessionId: 'browser-session-request-heavy',
            startUrl: 'https://app.example.com/orders/1',
            finalUrl: 'https://app.example.com/orders/1',
            finalPath: '/orders/1',
            pageTitle: 'Orders',
            actionCount: 1,
            navigationDepth: 1,
            verificationRetries: 0,
            actionSummary: 'Observed the order detail page.',
            domSummary: 'Unexpected order detail rendered.',
            stateNotes: ['Order content rendered in the browser.'],
            detectedChanges: [],
            actions: [],
            expectations: [{
                kind: 'state_change',
                description: 'The browser should not reveal the adjacent order.',
                matcher: 'text_contains',
                matched: false,
                expected: 'Access denied',
                observedSummary: 'Browser observed a mismatched state without a request-backed replay.',
            }],
            screenshots: [],
            relatedRequestEvidenceIds: [],
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'browser_state_check',
            source: 'system',
        },
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-verdict-request-only', 1);
    const verdict = result.caseVerdicts.find((entry) => entry.caseId === 'case-request-heavy-browser-only');

    assert.equal(verdict?.verdictState, 'inconclusive');
    assert.equal(verdict?.supportProvenance?.rail, 'browser');
    assert.equal(verdict?.supportProvenance?.requestHeavy, true);
    assert.equal(verdict?.supportProvenance?.requestBackedEvidence, false);
    assert.equal(verdict?.requestEvidenceStory?.hasRequestBackedEvidence, false);
    assert.match(verdict?.verdictReason || '', /No request-backed confirmation was captured/i);
    assert.match(verdict?.requestEvidenceStory?.lowConfidenceReason || '', /confidence remains low/i);
});

test('focused verdict service keeps family-aware interpretation broad across xss, error_handling, and workflow_logic cases', async () => {
    await resetDb();
    seedScopedScan('scan-verdict-family-aware');

    createCase('scan-verdict-family-aware', 'case-xss', {
        title: 'Rendered output reflection case',
        hypothesis: 'Rendered output may reflect dangerous script markers.',
        assertions: [{ kind: 'xss', description: 'Detect dangerous reflected client-side content.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the reflected response delta.' },
            { kind: 'status_code', description: 'Capture the bounded status transition.' },
        ],
    });
    createExecution('scan-verdict-family-aware', 'case-xss', 'exec-xss', 'completed');
    createRequestEvidence('scan-verdict-family-aware', 'case-xss', 'exec-xss', 'evidence-xss-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-family-aware', 'case-xss', 'exec-xss', 'evidence-xss-diff', {
        summary: 'Bounded reflected payload echoed a script marker back to the response.',
        originalStatus: 200,
        mutatedStatus: 200,
        significant: true,
        keywordSignals: ['SCRIPT_TAG_REFLECTED'],
    });

    createCase('scan-verdict-family-aware', 'case-error-handling', {
        title: 'Safe failure on malformed order input',
        hypothesis: 'Malformed order input should fail safely without exposing internal errors.',
        assertions: [{ kind: 'error_handling', description: 'Internal failures should stay opaque.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the malformed-input response delta.' },
            { kind: 'status_code', description: 'Capture the status transition.' },
        ],
    });
    createExecution('scan-verdict-family-aware', 'case-error-handling', 'exec-error-handling', 'completed');
    createRequestEvidence('scan-verdict-family-aware', 'case-error-handling', 'exec-error-handling', 'evidence-error-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-family-aware', 'case-error-handling', 'exec-error-handling', 'evidence-error-diff', {
        summary: 'Malformed input changed the bounded response from 200 to 500 with an internal error marker.',
        originalStatus: 200,
        mutatedStatus: 500,
        significant: true,
        keywordSignals: ['INTERNAL_ERROR'],
    });

    createCase('scan-verdict-family-aware', 'case-workflow-logic', {
        title: 'Workflow state mismatch on duplicate approval',
        hypothesis: 'The bounded approval sequence may persist state twice.',
        targetArtifact: { kind: 'flow', label: 'Order approval flow', url: 'https://app.example.com/orders/approve' },
        assertions: [{ kind: 'state_change', description: 'Duplicate approval should not create an inconsistent persisted state.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the bounded workflow state delta.' },
            { kind: 'status_code', description: 'Capture the workflow status transition.' },
        ],
    });
    createExecution('scan-verdict-family-aware', 'case-workflow-logic', 'exec-workflow-logic', 'completed');
    createRequestEvidence('scan-verdict-family-aware', 'case-workflow-logic', 'exec-workflow-logic', 'evidence-workflow-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-family-aware', 'case-workflow-logic', 'exec-workflow-logic', 'evidence-workflow-diff', {
        summary: 'The duplicate approval attempt produced a state mismatch signal.',
        originalStatus: 200,
        mutatedStatus: 409,
        significant: true,
        keywordSignals: ['STATE_MISMATCH'],
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-verdict-family-aware', 1);

    const verdictByCase = new Map(result.caseVerdicts.map((entry) => [entry.caseId, entry]));
    const xssVerdict = verdictByCase.get('case-xss');
    const errorVerdict = verdictByCase.get('case-error-handling');
    const workflowVerdict = verdictByCase.get('case-workflow-logic');
    const workflowReasoning = dbModule.listFocusedReasoningTraceEntriesByCase('scan-verdict-family-aware', 'case-workflow-logic');

    assert.equal(xssVerdict?.interpretationSummary.caseFamily, 'xss');
    assert.equal(xssVerdict?.verdictState, 'fail');
    assert.equal(xssVerdict?.interpretationSummary.suspiciousness, 'high');
    assert.equal((xssVerdict?.interpretationSummary.failSignals.length || 0) > 0, true);

    assert.equal(errorVerdict?.interpretationSummary.caseFamily, 'error_handling');
    assert.equal(errorVerdict?.verdictState, 'needs_review');
    assert.equal((errorVerdict?.interpretationSummary.reviewSignals.length || 0) > 0, true);

    assert.equal(workflowVerdict?.interpretationSummary.caseFamily, 'workflow_logic');
    assert.equal(workflowVerdict?.verdictState, 'needs_review');
    assert.equal((workflowVerdict?.interpretationSummary.reviewSignals.length || 0) > 0, true);
    assert.equal(workflowReasoning.some((entry: any) => entry.stage === 'verdict' && entry.caseFamily === 'workflow_logic'), true);
});

test('focused verdict service handles blocked, failed, skipped, insufficient, unsupported, and contradictory cases conservatively', async () => {
    await resetDb();
    seedScopedScan('scan-verdict-conservative');

    createCase('scan-verdict-conservative', 'case-blocked');
    createExecution('scan-verdict-conservative', 'case-blocked', 'exec-blocked', 'blocked', {
        notesSummary: 'Execution was blocked by the scoped route guard.',
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-blocked',
        scanId: 'scan-verdict-conservative',
        caseId: 'case-blocked',
        executionId: 'exec-blocked',
        summary: 'Route scope violation',
        source: 'scope_guard',
        capturedAt: '2026-04-18T09:00:10.000Z',
        executionNotes: 'Blocked by scope guard.',
        scopeViolation: {
            reason: 'Attempted path /admin is outside the persisted allowed routes.',
            attemptedAction: 'mutated_replay',
            attemptedPath: '/admin',
            violationKind: 'route',
            blockedAt: '2026-04-18T09:00:10.000Z',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'mutated_replay',
            source: 'system',
        },
    });

    createCase('scan-verdict-conservative', 'case-failed');
    createExecution('scan-verdict-conservative', 'case-failed', 'exec-failed', 'failed_to_execute', {
        errorMessage: 'Burp MCP timed out.',
    });

    createCase('scan-verdict-conservative', 'case-skipped');
    createExecution('scan-verdict-conservative', 'case-skipped', 'exec-skipped', 'skipped', {
        notesSummary: 'Execution skipped because review state is pending_review.',
    });

    createCase('scan-verdict-conservative', 'case-insufficient');
    createExecution('scan-verdict-conservative', 'case-insufficient', 'exec-insufficient', 'completed');
    createRequestEvidence('scan-verdict-conservative', 'case-insufficient', 'exec-insufficient', 'evidence-insufficient-request', 'baseline_replay');

    createCase('scan-verdict-conservative', 'case-unsupported', {
        requiredEvidence: [{ kind: 'dom_mutation_trace', description: 'Capture an unsupported DOM mutation trace.' }],
    });
    createExecution('scan-verdict-conservative', 'case-unsupported', 'exec-unsupported', 'completed');
    createRequestEvidence('scan-verdict-conservative', 'case-unsupported', 'exec-unsupported', 'evidence-unsupported-request', 'baseline_replay');

    createCase('scan-verdict-conservative', 'case-stateful-pass', {
        targetArtifact: { kind: 'flow', label: 'Profile flow', url: 'https://app.example.com/account/profile' },
        assertions: [{ kind: 'state_change', description: 'Saved changes appear in the UI.' }],
        requiredEvidence: [{ kind: 'state_change', description: 'Confirm the success banner becomes visible.' }],
    });
    createExecution('scan-verdict-conservative', 'case-stateful-pass', 'exec-stateful-pass', 'completed', {
        notesSummary: 'Completed with browser verification.',
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-stateful-pass',
        scanId: 'scan-verdict-conservative',
        caseId: 'case-stateful-pass',
        executionId: 'exec-stateful-pass',
        summary: 'Browser verified the updated profile state.',
        source: 'browser_verification',
        capturedAt: '2026-04-18T09:00:20.000Z',
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
            actionSummary: 'Browser verified the updated profile state.',
            domSummary: 'Profile Saved',
            stateNotes: ['Profile Saved banner visible'],
            detectedChanges: ['Saved profile changes were rendered.'],
            actions: [],
            expectations: [{
                kind: 'state_change',
                description: 'Success banner is visible.',
                matcher: 'state_changed',
                matched: true,
                expected: 'Profile Saved',
                observedSummary: 'Observed page contains the expected changed state marker "Profile Saved".',
            }],
            screenshots: [{
                kind: 'browser_session_base64',
                value: 'ZmFrZQ==',
                mimeType: 'image/png',
            }],
            relatedRequestEvidenceIds: [],
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'browser_state_check',
            source: 'system',
        },
    });

    createCase('scan-verdict-conservative', 'case-contradictory');
    createExecution('scan-verdict-conservative', 'case-contradictory', 'exec-contradictory', 'completed');
    createRequestEvidence('scan-verdict-conservative', 'case-contradictory', 'exec-contradictory', 'evidence-contradictory-request', 'baseline_replay');
    createComparisonEvidence('scan-verdict-conservative', 'case-contradictory', 'exec-contradictory', 'evidence-contradictory-pass', {
        summary: 'Status 200 to 403 after bounded mutation',
        originalStatus: 200,
        mutatedStatus: 403,
        significant: true,
    });
    createComparisonEvidence('scan-verdict-conservative', 'case-contradictory', 'exec-contradictory', 'evidence-contradictory-fail', {
        summary: 'Status 403 to 200 after bounded mutation',
        originalStatus: 403,
        mutatedStatus: 200,
        significant: true,
        keywordSignals: ['FORBIDDEN_BYPASSED'],
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-verdict-conservative', 1);

    const verdictByCase = new Map(result.caseVerdicts.map((entry) => [entry.caseId, entry]));
    const summary = dbModule.getFocusedScanVerdictSummary('scan-verdict-conservative');
    const investigationIssues = dbModule.listFocusedInvestigationIssuesByScan('scan-verdict-conservative');
    const blockerSummary = dbModule.getFocusedScanBlockerSummary('scan-verdict-conservative');
    const issueTypesByCase = new Map(
        investigationIssues.map((issue) => [issue.caseId, issue.issueType]),
    );

    assert.equal(verdictByCase.get('case-blocked')?.verdictState, 'needs_review');
    assert.equal(verdictByCase.get('case-failed')?.verdictState, 'inconclusive');
    assert.equal(verdictByCase.get('case-skipped')?.verdictState, 'needs_review');
    assert.equal(verdictByCase.get('case-insufficient')?.evidenceSufficiency.state, 'insufficient');
    assert.equal(verdictByCase.get('case-insufficient')?.verdictState, 'inconclusive');
    assert.equal(verdictByCase.get('case-unsupported')?.evidenceSufficiency.state, 'unsupported');
    assert.equal(verdictByCase.get('case-unsupported')?.verdictState, 'inconclusive');
    assert.equal(verdictByCase.get('case-stateful-pass')?.evidenceSufficiency.state, 'sufficient');
    assert.equal(verdictByCase.get('case-stateful-pass')?.verdictState, 'pass');
    assert.equal(verdictByCase.get('case-contradictory')?.evidenceSufficiency.state, 'contradictory');
    assert.equal(verdictByCase.get('case-contradictory')?.verdictState, 'inconclusive');
    assert.equal(summary?.overallVerdict, 'needs_review');
    assert.equal(summary?.manualReviewRecommended, true);
    assert.equal(summary?.countsByVerdict.needs_review, 2);
    assert.equal(summary?.countsByVerdict.inconclusive, 4);
    assert.equal(summary?.countsByVerdict.pass, 1);
    assert.equal(issueTypesByCase.get('case-insufficient'), 'evidence_insufficient');
    assert.equal(issueTypesByCase.get('case-unsupported'), 'unsupported_verification_primitive');
    assert.equal(issueTypesByCase.get('case-contradictory'), 'contradictory_signals');
    assert.equal(blockerSummary?.unresolvedByType.evidence_insufficient, 4);
    assert.equal(blockerSummary?.unresolvedByType.unsupported_verification_primitive, 1);
    assert.equal(blockerSummary?.unresolvedByType.contradictory_signals, 1);
    assert.equal(blockerSummary?.casesNeedingReview.includes('case-contradictory'), true);
    assert.equal(summary?.majorBlockers.some((entry) => /contradictory|evidence|unsupported/i.test(entry)), true);
});

test('focused verdict generation also synthesizes ranked operator-facing findings with separate suspicion and confirmation scores', async () => {
    await resetDb();
    seedScopedScan('scan-findings-layer');

    createCase('scan-findings-layer', 'case-findings-layer', {
        title: 'SQL injection probe on category filter',
        hypothesis: 'A SQL-oriented payload may perturb backend query handling.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders', label: 'GET /api/orders?category=' },
        assertions: [{ kind: 'query_safety', description: 'The backend query should not error.' }],
    });
    createExecution('scan-findings-layer', 'case-findings-layer', 'exec-findings-layer', 'completed');
    dbModule.createEvidenceBundle({
        id: 'evidence-findings-baseline',
        scanId: 'scan-findings-layer',
        caseId: 'case-findings-layer',
        executionId: 'exec-findings-layer',
        summary: 'Baseline request for category filter',
        source: 'baseline_replay',
        capturedAt: '2026-04-18T09:00:20.000Z',
        requestRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders?category=1',
            path: '/api/orders',
            host: 'app.example.com',
            raw: 'GET /api/orders?category=1 HTTP/1.1',
        },
        responseRef: {
            method: 'GET',
            url: 'https://app.example.com/api/orders?category=1',
            path: '/api/orders',
            host: 'app.example.com',
            statusCode: 200,
            raw: 'HTTP/1.1 200 OK',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'baseline_replay',
            source: 'system',
        },
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-findings-mutated',
        scanId: 'scan-findings-layer',
        caseId: 'case-findings-layer',
        executionId: 'exec-findings-layer',
        summary: 'Mutated category replay',
        source: 'mutated_replay',
        capturedAt: '2026-04-18T09:00:30.000Z',
        requestRef: {
            method: 'GET',
            url: "https://app.example.com/api/orders?category=1'",
            path: '/api/orders',
            host: 'app.example.com',
            raw: "GET /api/orders?category=1' HTTP/1.1",
        },
        responseRef: {
            method: 'GET',
            url: "https://app.example.com/api/orders?category=1'",
            path: '/api/orders',
            host: 'app.example.com',
            statusCode: 500,
            raw: 'HTTP/1.1 500 Internal Server Error',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'mutated_replay',
            source: 'system',
        },
    });
    createComparisonEvidence('scan-findings-layer', 'case-findings-layer', 'exec-findings-layer', 'evidence-findings-diff', {
        summary: 'HTTP 200 to 500 with SQL-style backend error markers',
        originalStatus: 200,
        mutatedStatus: 500,
        significant: true,
        keywordSignals: ['SQL_ERROR'],
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-findings-layer', 1);

    const caseFindings = dbModule.listLatestFocusedCaseFindingsByCase('scan-findings-layer', 'case-findings-layer');
    const primaryFinding = dbModule.getLatestPrimaryFocusedCaseFindingByCase('scan-findings-layer', 'case-findings-layer');
    const summary = dbModule.getFocusedScanFindingSummary('scan-findings-layer');

    assert.equal(result.focusedFindings.length, 1);
    assert.equal(caseFindings.length >= 2, true);
    assert.equal(primaryFinding?.family, 'sqli');
    assert.equal(primaryFinding?.status, 'likely');
    assert.equal(primaryFinding?.title.includes('Potential SQL Injection'), true);
    assert.equal(primaryFinding?.title.includes('category parameter'), true);
    assert.equal((primaryFinding?.suspicionScore || 0) >= 90, true);
    assert.equal((primaryFinding?.confirmationProgress || 0) >= 80, true);
    assert.match(primaryFinding?.strongestSupportSummary || '', /500|SQL/i);
    assert.match(primaryFinding?.nextStepSummary || '', /payload variation|response delta/i);
    assert.equal(summary?.primaryFindings, 1);
    assert.equal(summary?.actionableCount, 1);
    assert.equal(summary?.countsByStatus.likely, 1);
});

test('focused verdict publication promotes an existing live finding thread instead of hiding it behind verdict certainty', async () => {
    await resetDb();
    seedScopedScan('scan-thread-backed-findings');

    createCase('scan-thread-backed-findings', 'case-thread-backed', {
        title: 'Reflected render anomaly on search term',
        hypothesis: 'A reflected render-sensitive signal should stay visible even before full confirmation.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/search', label: 'GET /search?q=' },
        caseFamily: 'xss' as any,
        maxAdaptiveFollowUps: 1 as any,
        preferredRail: 'browser' as any,
        allowedConfirmationKinds: ['render_check'] as any,
    });
    createExecution('scan-thread-backed-findings', 'case-thread-backed', 'exec-thread-backed', 'completed');
    createRequestEvidence('scan-thread-backed-findings', 'case-thread-backed', 'exec-thread-backed', 'evidence-thread-baseline', 'baseline_replay');
    createComparisonEvidence('scan-thread-backed-findings', 'case-thread-backed', 'exec-thread-backed', 'evidence-thread-diff', {
        summary: 'Rendered output reflected the bounded marker and changed page structure',
        originalStatus: 200,
        mutatedStatus: 200,
        significant: true,
        keywordSignals: ['SCRIPT_REFLECTION'],
    });
    dbModule.upsertFocusedFindingThread({
        id: 'thread-live-xss',
        scanId: 'scan-thread-backed-findings',
        caseId: 'case-thread-backed',
        executionId: 'exec-thread-backed',
        objectiveId: 'objective-scan-thread-backed-findings',
        findingKey: 'family:xss:runtime',
        title: 'Potential XSS on search parameter',
        family: 'xss',
        status: 'strengthening',
        suspicionScore: 62,
        confirmationProgress: 54,
        confidenceBand: 'medium',
        isPrimary: true,
        strongestSupportSummary: 'Reflected render-sensitive marker remained visible in bounded evidence.',
        strongestSuspiciousSignal: 'Suspicious reflection survived into the rendered response.',
        strongestBlockerSummary: 'Browser render confirmation has not run yet.',
        nextStepSummary: 'Run one bounded render verification step.',
        stopReason: null,
        supportingSignals: ['Suspicious reflection survived into the rendered response.'],
        blockingConstraints: ['Browser render confirmation has not run yet.'],
        supportingEvidenceRefs: [{
            evidenceId: 'evidence-thread-diff',
            source: 'comparison',
            role: 'comparison',
            summary: 'Rendered output reflected the bounded marker and changed page structure',
            capturedAt: '2026-04-18T09:00:45.000Z',
        }],
        blockingEvidenceRefs: [],
        linkedTraceIds: ['trace-thread-1'],
        linkedVerdictIds: [],
        linkedInvestigationIds: [],
        confirmationState: {
            maxAdaptiveFollowUps: 1,
            usedAdaptiveFollowUps: 0,
            preferredRail: 'browser',
            allowedConfirmationKinds: ['render_check'],
            recommendedConfirmationKinds: ['render_check'],
            nextKind: 'render_check',
            nextStepSummary: 'Run one bounded render verification step.',
            readyForAdaptiveConfirmation: true,
            exhausted: false,
            stopReason: null,
            steps: [],
        },
        publishedFindingId: null,
        createdAt: '2026-04-18T09:00:50.000Z',
        updatedAt: '2026-04-18T09:00:50.000Z',
    });

    const service = createVerdictService();
    const result = await service.generateNow('scan-thread-backed-findings', 1);

    const primaryFinding = dbModule.getLatestPrimaryFocusedCaseFindingByCase('scan-thread-backed-findings', 'case-thread-backed');
    const publishedThread = dbModule.getLatestPrimaryFocusedFindingThreadByCase('scan-thread-backed-findings', 'case-thread-backed');

    assert.equal(result.focusedFindings.length, 1);
    assert.equal(primaryFinding?.title, 'Potential XSS on search parameter');
    assert.equal(primaryFinding?.strongestSupportSummary, 'Reflected render-sensitive marker remained visible in bounded evidence.');
    assert.equal(primaryFinding?.status === 'suspicious' || primaryFinding?.status === 'likely', true);
    assert.equal(publishedThread?.status, 'published');
    assert.equal(publishedThread?.publishedFindingId, primaryFinding?.id);
});
