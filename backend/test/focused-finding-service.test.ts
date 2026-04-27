import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-focused-finding-service-'));
process.env.DATABASE_PATH = path.join(tempDir, 'penpard.db');

const dbModule = require('../src/db/init') as typeof import('../src/db/init');
const { FocusedFindingService } = require('../src/services/runtime/FocusedFindingService') as typeof import('../src/services/runtime/FocusedFindingService');

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

test('focused finding service carries request evidence stories and support provenance onto runtime threads and published findings', async () => {
    await resetDb();

    dbModule.createScan({
        id: 'scan-finding-service',
        userId: 1,
        type: 'web',
        target: 'https://app.example.com',
        scanMode: 'scoped',
    });
    dbModule.createFocusedTestObjective({
        id: 'objective-finding-service',
        scanId: 'scan-finding-service',
        title: 'Scoped finding objective',
        scopeType: 'endpoint_scoped',
        goal: 'Keep findings traceable to Burp-visible request evidence.',
        riskTags: ['sqli'],
    });
    dbModule.createScopeEnvelope({
        id: 'scope-finding-service',
        scanId: 'scan-finding-service',
        version: 1,
        allowedHosts: ['app.example.com'],
        allowedRoutes: ['/api/search'],
        selectedEndpoints: [{ method: 'GET', path: '/api/search', host: 'app.example.com' }],
        baselineRequestRefs: [],
        requestBundleRefs: [],
        authContext: null,
        outOfScopeNotes: [],
        boundaryHints: ['Stay on the approved search endpoint only.'],
        explorationBudget: { maxRequests: 4, maxRouteVariants: 1 },
    });

    const testCase: import('../src/services/runtime/ScopedScanTypes').FocusedTestCase = {
        id: 'case-finding-service',
        scanId: 'scan-finding-service',
        objectiveId: 'objective-finding-service',
        title: 'SQL-style query probe',
        hypothesis: 'A bounded query mutation may perturb backend parsing.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/search', label: 'GET /api/search?q=' },
        preconditions: ['Reuse the persisted auth context.'],
        steps: [{ order: 1, action: 'Replay the bounded search request and mutate the observed query parameter.' }],
        assertions: [{ kind: 'query_safety', description: 'The backend should not surface parser errors.' }],
        requiredEvidence: [
            { kind: 'response_diff', description: 'Capture the response delta.' },
            { kind: 'status_code', description: 'Capture the status transition.' },
        ],
        priority: 'high',
        plannerRationaleSummary: 'Findings should stay tied to real request evidence.',
        caseFamily: 'sqli',
        status: 'planned',
        reviewState: 'approved',
    };
    dbModule.createFocusedTestCase(testCase);

    const execution: import('../src/services/runtime/ScopedScanTypes').FocusedTestCaseExecution = {
        id: 'exec-finding-service',
        scanId: 'scan-finding-service',
        caseId: 'case-finding-service',
        objectiveId: 'objective-finding-service',
        executionState: 'completed',
        executionProfileKey: 'generic:test',
        runReason: 'batch',
        notesSummary: 'Completed with request-backed suspicious evidence.',
        requestActionsUsed: 2,
        browserActionsUsed: 0,
        startedAt: '2026-04-20T12:00:00.000Z',
        completedAt: '2026-04-20T12:01:00.000Z',
    };
    dbModule.createFocusedTestCaseExecution(execution);

    dbModule.createEvidenceBundle({
        id: 'evidence-finding-baseline',
        scanId: execution.scanId,
        caseId: execution.caseId,
        executionId: execution.id,
        summary: 'Baseline search replay',
        source: 'baseline_replay',
        capturedAt: '2026-04-20T12:00:10.000Z',
        requestRef: {
            method: 'GET',
            url: 'https://app.example.com/api/search?q=test',
            path: '/api/search',
            host: 'app.example.com',
            raw: 'GET /api/search?q=test HTTP/1.1',
        },
        responseRef: {
            method: 'GET',
            url: 'https://app.example.com/api/search?q=test',
            path: '/api/search',
            host: 'app.example.com',
            statusCode: 200,
            raw: 'HTTP/1.1 200 OK',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'baseline_replay',
            source: 'system',
            executionPhase: 'primary_execution',
        },
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-finding-mutated',
        scanId: execution.scanId,
        caseId: execution.caseId,
        executionId: execution.id,
        summary: 'Bounded suspicious query mutation',
        source: 'mutated_replay',
        capturedAt: '2026-04-20T12:00:20.000Z',
        requestRef: {
            method: 'GET',
            url: "https://app.example.com/api/search?q=test'",
            path: '/api/search',
            host: 'app.example.com',
            raw: "GET /api/search?q=test' HTTP/1.1",
        },
        responseRef: {
            method: 'GET',
            url: "https://app.example.com/api/search?q=test'",
            path: '/api/search',
            host: 'app.example.com',
            statusCode: 500,
            raw: 'HTTP/1.1 500 Internal Server Error',
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'mutated_replay',
            source: 'system',
            executionPhase: 'primary_execution',
        },
    });
    dbModule.createEvidenceBundle({
        id: 'evidence-finding-comparison',
        scanId: execution.scanId,
        caseId: execution.caseId,
        executionId: execution.id,
        summary: 'HTTP 200 to 500 with SQL parser error markers',
        source: 'comparison',
        capturedAt: '2026-04-20T12:00:30.000Z',
        responseDiffSummary: {
            summary: 'HTTP 200 to 500 with SQL parser error markers',
            significant: true,
            originalStatus: 200,
            mutatedStatus: 500,
            keywordSignals: ['SQL_ERROR'],
        },
        relatedEvidenceIds: ['evidence-finding-baseline', 'evidence-finding-mutated'],
        provenance: {
            profileKey: 'generic:test',
            actionType: 'compare_responses',
            source: 'system',
            executionPhase: 'primary_execution',
        },
    });

    dbModule.upsertFocusedCaseVerdict({
        id: 'verdict-finding-service',
        scanId: execution.scanId,
        caseId: execution.caseId,
        executionId: execution.id,
        objectiveId: execution.objectiveId,
        verdictState: 'needs_review',
        verdictReason: 'Request-backed suspicious signal observed and needs review.',
        evidenceSufficiency: {
            state: 'sufficient',
            summary: 'Required supported evidence was captured and anchored to the intended scoped target.',
            anchoredToTarget: true,
            anchoredMethod: 'GET',
            anchoredPath: '/api/search',
            supportingEvidenceIds: ['evidence-finding-baseline', 'evidence-finding-mutated', 'evidence-finding-comparison'],
            missingRequirements: [],
            unsupportedRequirements: [],
            contradictorySignals: [],
            underminedByScopeViolation: false,
            requirementEvaluations: [],
        },
        interpretationSummary: {
            caseFamily: 'sqli',
            suspiciousness: 'high',
            summary: 'SQL-style parser signals remain suspicious but still review-weighted.',
            suspiciousSignals: ['HTTP 200 to 500 with SQL parser error markers'],
            passSignals: [],
            failSignals: [],
            reviewSignals: ['HTTP 200 to 500 with SQL parser error markers'],
            contradictorySignals: [],
            controlSignals: [],
            keywordSignals: ['SQL_ERROR'],
            signalMarkers: ['sql_error_marker'],
            parameterHints: ['q'],
            scoreDelta: 22,
            strongestSupport: 'HTTP 200 to 500 with SQL parser error markers',
            strongestBlocker: null,
            missingEvidence: [],
            uncertaintyReasons: ['Suspicious same-scope evidence exists, but it still needs a stronger confirmation contrast.'],
            nextStepSummary: 'Run one additional bounded error-surface comparison on the same target.',
            followUpDecisionSummary: 'Queue one bounded repeat mutation follow-up because suspicion materially increased inside scope.',
            confirmationReadiness: 'ready',
            recommendedConfirmationKinds: ['repeat_mutation', 'error_surface_compare'],
        },
        supportingEvidenceRefs: [{
            evidenceId: 'evidence-finding-comparison',
            source: 'comparison',
            role: 'comparison',
            summary: 'HTTP 200 to 500 with SQL parser error markers',
            capturedAt: '2026-04-20T12:00:30.000Z',
            relatedEvidenceIds: ['evidence-finding-baseline', 'evidence-finding-mutated'],
            supportRail: 'request',
        }],
        supportProvenance: {
            rail: 'request',
            requestHeavy: true,
            requestBackedEvidence: true,
            browserBackedEvidence: false,
            requestEvidenceIds: ['evidence-finding-baseline', 'evidence-finding-mutated', 'evidence-finding-comparison'],
            browserEvidenceIds: [],
            systemEvidenceIds: [],
            summary: 'Request-backed support: Burp-visible request evidence is anchoring the current conclusion.',
            lowConfidenceReason: null,
        },
        requestEvidenceStory: {
            requestHeavy: true,
            hasRequestBackedEvidence: true,
            baselineRequestRef: {
                evidenceId: 'evidence-finding-baseline',
                source: 'baseline_replay',
                summary: 'Baseline search replay',
                capturedAt: '2026-04-20T12:00:10.000Z',
                method: 'GET',
                url: 'https://app.example.com/api/search?q=test',
                path: '/api/search',
                host: 'app.example.com',
                statusCode: 200,
                executionPhase: 'primary_execution',
                relatedEvidenceIds: [],
            },
            strongestSuspiciousRequestRef: {
                evidenceId: 'evidence-finding-mutated',
                source: 'mutated_replay',
                summary: 'Bounded suspicious query mutation',
                capturedAt: '2026-04-20T12:00:20.000Z',
                method: 'GET',
                url: "https://app.example.com/api/search?q=test'",
                path: '/api/search',
                host: 'app.example.com',
                statusCode: 500,
                executionPhase: 'primary_execution',
                relatedEvidenceIds: ['evidence-finding-baseline'],
            },
            supportingRequestRefs: [{
                evidenceId: 'evidence-finding-mutated',
                source: 'mutated_replay',
                summary: 'Bounded suspicious query mutation',
                capturedAt: '2026-04-20T12:00:20.000Z',
                method: 'GET',
                url: "https://app.example.com/api/search?q=test'",
                path: '/api/search',
                host: 'app.example.com',
                statusCode: 500,
                executionPhase: 'primary_execution',
                relatedEvidenceIds: ['evidence-finding-baseline'],
            }],
            contradictingRequestRefs: [],
            confirmationRequestRefs: [],
            summary: 'Request-backed suspicious signal observed.',
            lowConfidenceReason: null,
        },
        scopeViolationImpact: {
            hasScopeViolation: false,
            severity: 'none',
            underminesConfidence: false,
            reasons: [],
        },
        executionSnapshot: {
            executionId: execution.id,
            executionState: execution.executionState,
            executionProfileKey: execution.executionProfileKey,
            requestActionsUsed: execution.requestActionsUsed,
            browserActionsUsed: execution.browserActionsUsed,
        },
        verdictAt: '2026-04-20T12:01:00.000Z',
    });

    const service = new FocusedFindingService({
        now: (() => {
            let counter = 0;
            return () => `2026-04-20T12:02:${String(counter++).padStart(2, '0')}.000Z`;
        })(),
        createId: (() => {
            let counter = 0;
            return () => `finding-service-id-${++counter}`;
        })(),
    });

    const objective = dbModule.getFocusedTestObjective('scan-finding-service');
    const evidenceBundles = dbModule.listEvidenceBundlesByExecution('scan-finding-service', 'case-finding-service', 'exec-finding-service');
    const verdict = dbModule.getFocusedCaseVerdictByExecution('scan-finding-service', 'case-finding-service', 'exec-finding-service');
    const runtimeThread = service.updateRuntimeThread({
        objective,
        testCase,
        execution,
        evidenceBundles,
        investigationIssues: [],
        linkedTraceIds: [],
        linkedVerdictIds: ['verdict-finding-service'],
        linkedInvestigationIds: [],
        verdict,
    });

    assert.equal(runtimeThread.supportProvenance?.rail, 'request');
    assert.equal(runtimeThread.supportProvenance?.requestBackedEvidence, true);
    assert.equal(runtimeThread.requestEvidenceStory?.hasRequestBackedEvidence, true);
    assert.equal(runtimeThread.requestEvidenceStory?.strongestSuspiciousRequestRef?.evidenceId, 'evidence-finding-mutated');

    const result = await service.generateNow('scan-finding-service');
    const persistedFindings = dbModule.listFocusedCaseFindingsByExecution('scan-finding-service', 'case-finding-service', 'exec-finding-service');
    const persistedThreads = dbModule.listFocusedFindingThreadsByExecution('scan-finding-service', 'case-finding-service', 'exec-finding-service');
    const primaryFinding = persistedFindings.find((entry) => entry.isPrimary) || persistedFindings[0];
    const publishedThread = persistedThreads.find((entry) => entry.isPrimary) || persistedThreads[0];

    assert.equal(result.focusedFindings.length, 1);
    assert.ok(primaryFinding);
    assert.ok(publishedThread);
    assert.equal(primaryFinding?.supportProvenance?.rail, 'request');
    assert.equal(primaryFinding?.requestEvidenceStory?.baselineRequestRef?.evidenceId, 'evidence-finding-baseline');
    assert.equal(primaryFinding?.requestEvidenceStory?.strongestSuspiciousRequestRef?.evidenceId, 'evidence-finding-mutated');
    assert.equal(publishedThread?.status, 'published');
    assert.equal(publishedThread?.supportProvenance?.rail, 'request');
    assert.equal(publishedThread?.requestEvidenceStory?.hasRequestBackedEvidence, true);
});
