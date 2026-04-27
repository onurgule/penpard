import test from 'node:test';
import assert from 'node:assert/strict';

const { interpretFocusedSignals } = require('../src/services/runtime/FocusedSignalInterpreter') as typeof import('../src/services/runtime/FocusedSignalInterpreter');

type EvidenceBundle = import('../src/services/runtime/ScopedScanTypes').EvidenceBundle;
type FocusedTestCase = import('../src/services/runtime/ScopedScanTypes').FocusedTestCase;

function buildCase(overrides: Partial<FocusedTestCase>): FocusedTestCase {
    return {
        id: 'case-signal',
        scanId: 'scan-signal',
        objectiveId: 'objective-signal',
        title: 'Signal interpretation case',
        hypothesis: 'Signal interpretation should remain bounded and explainable.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/:id' },
        preconditions: ['Reuse the persisted auth context.'],
        steps: [{ order: 1, action: 'Replay the scoped target.' }],
        assertions: [{ kind: 'authz_enforced', description: 'Unauthorized access remains blocked.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture a bounded diff.' }],
        priority: 'high',
        plannerRationaleSummary: 'Signal interpreter coverage.',
        status: 'planned',
        reviewState: 'approved',
        ...overrides,
    };
}

function buildComparisonEvidence(input: {
    id: string;
    summary: string;
    originalStatus: number;
    mutatedStatus: number;
    significant?: boolean;
    keywordSignals?: string[];
}): EvidenceBundle {
    return {
        id: input.id,
        scanId: 'scan-signal',
        caseId: 'case-signal',
        executionId: 'exec-signal',
        summary: input.summary,
        source: 'comparison',
        capturedAt: '2026-04-20T12:00:00.000Z',
        responseDiffSummary: {
            summary: input.summary,
            significant: input.significant ?? true,
            originalStatus: input.originalStatus,
            mutatedStatus: input.mutatedStatus,
            keywordSignals: input.keywordSignals || [],
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: 'compare_responses',
            source: 'system',
        },
    };
}

function buildRequestEvidence(input: {
    id: string;
    source: 'baseline_replay' | 'mutated_replay';
    url: string;
    statusCode: number;
}): EvidenceBundle {
    return {
        id: input.id,
        scanId: 'scan-signal',
        caseId: 'case-signal',
        executionId: 'exec-signal',
        summary: `${input.source} evidence`,
        source: input.source,
        capturedAt: '2026-04-20T11:59:50.000Z',
        requestRef: {
            method: 'GET',
            url: input.url,
            path: '/api/orders/1',
            host: 'app.example.com',
            raw: `GET ${input.url} HTTP/1.1`,
        },
        responseRef: {
            method: 'GET',
            url: input.url,
            path: '/api/orders/1',
            host: 'app.example.com',
            statusCode: input.statusCode,
            raw: `HTTP/1.1 ${input.statusCode}`,
        },
        provenance: {
            profileKey: 'generic:test',
            actionType: input.source,
            source: 'system',
        },
    };
}

test('interpretFocusedSignals separates control-held and contradictory evidence for access-control cases', () => {
    const interpretation = interpretFocusedSignals({
        objective: {
            id: 'objective-signal',
            scanId: 'scan-signal',
            title: 'Access control review',
            scopeType: 'endpoint_scoped',
            goal: 'Validate adjacent order access.',
            riskTags: ['idor', 'authz'],
        } as any,
        testCase: buildCase({ caseFamily: 'access_control' }),
        execution: null,
        evidenceBundles: [
            buildRequestEvidence({
                id: 'evidence-pass-baseline',
                source: 'baseline_replay',
                url: 'https://app.example.com/api/orders/1',
                statusCode: 200,
            }),
            buildRequestEvidence({
                id: 'evidence-pass-mutated',
                source: 'mutated_replay',
                url: 'https://app.example.com/api/orders/2',
                statusCode: 403,
            }),
            buildComparisonEvidence({
                id: 'evidence-pass',
                summary: 'Status 200 to 403 after bounded alternate-id replay',
                originalStatus: 200,
                mutatedStatus: 403,
            }),
            buildComparisonEvidence({
                id: 'evidence-fail',
                summary: 'Status 403 to 200 after adjacent identifier replay',
                originalStatus: 403,
                mutatedStatus: 200,
                keywordSignals: ['FORBIDDEN_BYPASSED'],
            }),
        ],
    });

    assert.equal(interpretation.suspiciousness, 'high');
    assert.equal(interpretation.controlSignals.length > 0, true);
    assert.equal(interpretation.contradictorySignals.length, 1);
    assert.equal(interpretation.uncertaintyReasons.some((entry) => /control-holding and suspicious/i.test(entry)), true);
    assert.equal(interpretation.followUpDecisionSummary?.includes('alternate id compare'), true);
});

test('interpretFocusedSignals keeps suspicious but not confirmed SQL-style evidence visible', () => {
    const interpretation = interpretFocusedSignals({
        objective: {
            id: 'objective-signal',
            scanId: 'scan-signal',
            title: 'Query handling review',
            scopeType: 'endpoint_scoped',
            goal: 'Review one bounded backend parser anomaly.',
            riskTags: ['sqli'],
        } as any,
        testCase: buildCase({
            caseFamily: 'sqli',
            assertions: [{ kind: 'response_diff', description: 'Capture SQL-style backend errors.' }],
        }),
        execution: null,
        evidenceBundles: [
            buildRequestEvidence({
                id: 'evidence-sqli-baseline',
                source: 'baseline_replay',
                url: 'https://app.example.com/api/orders/1',
                statusCode: 200,
            }),
            buildRequestEvidence({
                id: 'evidence-sqli-mutated',
                source: 'mutated_replay',
                url: "https://app.example.com/api/orders/1?id=1'",
                statusCode: 500,
            }),
            buildComparisonEvidence({
                id: 'evidence-sqli',
                summary: 'Status 200 to 500 with SQL parser keywords',
                originalStatus: 200,
                mutatedStatus: 500,
                keywordSignals: ['SQL_ERROR'],
            }),
        ],
    });

    assert.equal(interpretation.suspiciousness, 'high');
    assert.equal(interpretation.failSignals.length, 0);
    assert.equal(interpretation.reviewSignals.length > 0 || interpretation.suspiciousSignals.length > 0, true);
    assert.equal(interpretation.uncertaintyReasons.some((entry) => /needs a stronger confirmation contrast/i.test(entry)), true);
    assert.equal(interpretation.recommendedConfirmationKinds[0], 'repeat_mutation');
});

test('interpretFocusedSignals keeps request-heavy browser-only observations low confidence until a Burp-visible replay exists', () => {
    const interpretation = interpretFocusedSignals({
        objective: {
            id: 'objective-signal',
            scanId: 'scan-signal',
            title: 'Order detail review',
            scopeType: 'endpoint_scoped',
            goal: 'Keep request-heavy confidence grounded in visible request evidence.',
            riskTags: ['idor'],
        } as any,
        testCase: buildCase({
            caseFamily: 'access_control',
            assertions: [{ kind: 'authz_enforced', description: 'Unauthorized access stays blocked.' }],
        }),
        execution: null,
        evidenceBundles: [{
            id: 'evidence-browser-only',
            scanId: 'scan-signal',
            caseId: 'case-signal',
            executionId: 'exec-signal',
            summary: 'Browser noticed a state mismatch, but no request replay was captured.',
            source: 'browser_verification',
            capturedAt: '2026-04-20T12:01:00.000Z',
            browserState: {
                sessionId: 'browser-only-session',
                startUrl: 'https://app.example.com/orders/1',
                finalUrl: 'https://app.example.com/orders/1',
                finalPath: '/orders/1',
                pageTitle: 'Orders',
                actionCount: 1,
                navigationDepth: 1,
                verificationRetries: 0,
                actionSummary: 'Observed the order detail page.',
                domSummary: 'Unexpected order details were visible.',
                stateNotes: ['Order content rendered in the browser.'],
                detectedChanges: [],
                actions: [],
                expectations: [{
                    kind: 'state_change',
                    description: 'Unexpected order details appear.',
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
        }],
    });

    assert.equal(interpretation.suspiciousness, 'low');
    assert.equal(interpretation.confirmationReadiness, 'watch');
    assert.match(interpretation.summary, /No Burp-visible request confirmation was captured/i);
    assert.match(interpretation.followUpDecisionSummary || '', /No request-backed confirmation was captured/i);
});
