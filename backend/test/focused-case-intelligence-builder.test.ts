import test from 'node:test';
import assert from 'node:assert/strict';

const { focusedCaseIntelligenceBuilder } = require('../src/services/runtime/FocusedCaseIntelligenceBuilder') as typeof import('../src/services/runtime/FocusedCaseIntelligenceBuilder');

type ContextPack = import('../src/services/runtime/ScopedScanTypes').ContextPack;
type FocusedTestCaseDraft = import('../src/services/runtime/ScopedScanTypes').FocusedTestCaseDraft;
type FocusedCaseFamily = import('../src/services/runtime/ScopedScanTypes').FocusedCaseFamily;

function buildContextPack(input: {
    goal: string;
    riskTags?: string[];
    targetUrl: string;
    description: string;
    observedInputHints?: string[];
    endpointRecord?: {
        path: string;
        classification: string;
        likelyAuthRelevant?: boolean;
        exercisedInBrowser?: boolean;
        notes?: string[];
        evidence?: string[];
    } | null;
}): ContextPack {
    return {
        scanId: 'scan-intelligence-1',
        objective: {
            id: 'objective-intelligence-1',
            title: 'Scoped request review',
            scopeType: 'request_scoped',
            goal: input.goal,
            operatorNotes: 'Keep the run bounded to the persisted anchors.',
            riskTags: input.riskTags || [],
            featureDescription: input.description,
        },
        scope: {
            allowedHosts: ['app.example.com'],
            allowedRoutes: ['/api/orders/:id', '/comments/preview', '/workflow/publish'],
            selectedEndpoints: [],
            baselineRequestRefs: [],
            requestBundleRefs: [],
            boundaryHints: ['Use only persisted routes and observed inputs.'],
            outOfScopeNotes: ['Do not widen into unrelated admin routes.'],
            explorationBudget: null,
        },
        authSummary: {
            continuityStrategy: 'burp_baseline',
            summary: 'Baseline request continuity is available.',
            authContext: {
                authStartupMode: 'no_credentials',
                providedCredentialCount: 0,
                hasSessionCookies: true,
                hasInitialRequestBaseline: true,
                continuityStrategy: 'burp_baseline',
                summary: 'Persisted baseline request available.',
            },
        },
        selectedTargets: [{
            kind: 'baseline_request',
            method: 'POST',
            path: '/api/orders/41',
            label: 'POST /api/orders/41',
            referenceKind: 'scan_initial_request',
            referenceId: 'initial_request',
        }],
        supportingContext: {
            operatorInstructions: 'Keep this compact and case-driven.',
            requestBundles: [],
            observedInputHints: input.observedInputHints || [],
            securityTestRequest: {
                id: 'request-1',
                scanId: 'scan-intelligence-1',
                targetUrl: input.targetUrl,
                description: input.description,
                testData: [],
                testUsers: [],
                authMechanismHints: [],
                attachmentMetadata: [],
                operatorNotes: null,
            },
            endpointIntelligence: input.endpointRecord
                ? {
                    summary: 'Endpoint intelligence available.',
                    authRelevantCount: input.endpointRecord.likelyAuthRelevant ? 1 : 0,
                    observedInBurpCount: 1,
                    exercisedInBrowserCount: input.endpointRecord.exercisedInBrowser ? 1 : 0,
                    records: [{
                        endpoint: input.endpointRecord.path,
                        path: input.endpointRecord.path,
                        methods: ['GET', 'POST'],
                        classification: input.endpointRecord.classification,
                        likelyAuthRelevant: input.endpointRecord.likelyAuthRelevant ?? false,
                        observedInBurp: true,
                        exercisedInBrowser: input.endpointRecord.exercisedInBrowser ?? false,
                        confidence: 0.84,
                        notes: input.endpointRecord.notes || [],
                        evidence: input.endpointRecord.evidence || [],
                    }],
                }
                : undefined,
        },
        plannerConstraints: {
            schemaVersion: 1,
            noScopeExpansion: true,
            maxCases: 5,
        },
    };
}

function buildDraftCase(input: {
    title: string;
    hypothesis: string;
    family: FocusedCaseFamily;
    path: string;
    url?: string;
    step: string;
    assertionDescription: string;
}): FocusedTestCaseDraft {
    return {
        title: input.title,
        hypothesis: input.hypothesis,
        targetArtifact: {
            kind: 'endpoint',
            method: 'GET',
            path: input.path,
            url: input.url,
        },
        preconditions: ['Reuse the persisted bounded request context.'],
        steps: [{ order: 1, action: input.step }],
        assertions: [{ kind: 'response_diff', description: input.assertionDescription }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Capture the bounded diff.' }],
        priority: 'high',
        plannerRationaleSummary: 'Focused case seeded for deterministic intelligence.',
        caseFamily: input.family,
    };
}

test('FocusedCaseIntelligenceBuilder derives family-aware candidate inputs and bounded follow-up policy', () => {
    const scenarios: Array<{
        family: FocusedCaseFamily;
        contextPack: ContextPack;
        draftCase: FocusedTestCaseDraft;
        expectedStrategies: import('../src/services/runtime/ScopedScanTypes').FocusedCaseMutationStrategy[];
        expectedConfirmation: import('../src/services/runtime/ScopedScanTypes').FocusedConfirmationKind;
    }> = [
        {
            family: 'access_control',
            contextPack: buildContextPack({
                goal: 'Validate order-detail access control.',
                riskTags: ['idor', 'authz'],
                targetUrl: 'https://app.example.com/api/orders/41?view=full',
                description: 'Replay the seeded order detail request and confirm adjacent order access stays tenant-bound.',
                observedInputHints: ['orderId', 'tenantId'],
                endpointRecord: {
                    path: '/api/orders/:id',
                    classification: 'object_detail',
                    likelyAuthRelevant: true,
                    notes: ['Path includes tenant-bound order identifiers.'],
                    evidence: ['Observed orderId in the captured route.'],
                },
            }),
            draftCase: buildDraftCase({
                title: 'Authorization boundary on GET /api/orders/41',
                hypothesis: 'Adjacent order identifiers may cross tenant boundaries.',
                family: 'access_control',
                path: '/api/orders/41',
                url: 'https://app.example.com/api/orders/41?view=full',
                step: 'Replay the same order detail request with one adjacent identifier.',
                assertionDescription: 'Alternate order identifiers remain unauthorized.',
            }),
            expectedStrategies: ['adjacent_identifier'],
            expectedConfirmation: 'alternate_id_compare',
        },
        {
            family: 'xss',
            contextPack: buildContextPack({
                goal: 'Validate comment preview rendering.',
                riskTags: ['xss', 'rendering'],
                targetUrl: 'https://app.example.com/comments/preview',
                description: 'Comment preview accepts user-controlled rich text before it is rendered back to the operator.',
                observedInputHints: ['content', 'comment_body', 'preview_html'],
                endpointRecord: {
                    path: '/comments/preview',
                    classification: 'content_preview',
                    notes: ['Preview endpoint renders comment body content.'],
                    evidence: ['Observed content field in the feature description.'],
                },
            }),
            draftCase: buildDraftCase({
                title: 'Rendered content handling on comment preview',
                hypothesis: 'A benign render marker may reappear unsafely in the preview path.',
                family: 'xss',
                path: '/comments/preview',
                url: 'https://app.example.com/comments/preview',
                step: 'Replay the same preview request with a benign marker in the comment body.',
                assertionDescription: 'Rendered preview safely encodes the marker.',
            }),
            expectedStrategies: ['benign_render_marker'],
            expectedConfirmation: 'render_check',
        },
        {
            family: 'workflow_logic',
            contextPack: buildContextPack({
                goal: 'Validate publish workflow integrity.',
                riskTags: ['workflow', 'state'],
                targetUrl: 'https://app.example.com/workflow/publish',
                description: 'Publish flow changes article status from draft to published inside a browser-driven approval step.',
                observedInputHints: ['status', 'publishState'],
                endpointRecord: {
                    path: '/workflow/publish',
                    classification: 'workflow_transition',
                    exercisedInBrowser: true,
                    notes: ['Feature is already exercised through browser state transitions.'],
                    evidence: ['Observed publish state toggle in the scoped notes.'],
                },
            }),
            draftCase: buildDraftCase({
                title: 'Publish workflow replay',
                hypothesis: 'Duplicate publish replays may shift state unexpectedly.',
                family: 'workflow_logic',
                path: '/workflow/publish',
                url: 'https://app.example.com/workflow/publish',
                step: 'Replay the same publish step and compare state outcomes.',
                assertionDescription: 'Duplicate publish remains idempotent.',
            }),
            expectedStrategies: ['state_toggle', 'duplicate_replay'],
            expectedConfirmation: 'state_replay',
        },
    ];

    for (const scenario of scenarios) {
        const intelligence = focusedCaseIntelligenceBuilder.build(scenario.contextPack, scenario.draftCase);

        assert.match(intelligence.selectionSummary, /persisted scoped anchors/i);
        assert.ok(intelligence.anchorSummary.length > 0);
        assert.equal(intelligence.securityConcerns[0]?.family, scenario.family);
        assert.equal(
            intelligence.candidateInputs.some((entry) => scenario.expectedStrategies.includes(entry.mutationStrategy)),
            true,
        );
        assert.equal(
            intelligence.followUpPolicy.allowedConfirmationKinds.includes(scenario.expectedConfirmation),
            true,
        );
        assert.equal(intelligence.followUpPolicy.queueThresholdScore, 40);
    }
});
