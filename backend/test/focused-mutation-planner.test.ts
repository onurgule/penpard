import test from 'node:test';
import assert from 'node:assert/strict';

const { focusedMutationPlanner } = require('../src/services/runtime/FocusedMutationPlanner') as typeof import('../src/services/runtime/FocusedMutationPlanner');

type FocusedTestCase = import('../src/services/runtime/ScopedScanTypes').FocusedTestCase;

function buildCase(overrides: Partial<FocusedTestCase>): FocusedTestCase {
    return {
        id: 'case-mutation',
        scanId: 'scan-mutation',
        objectiveId: 'objective-mutation',
        title: 'Mutation test case',
        hypothesis: 'Bounded mutation planning should stay concrete.',
        targetArtifact: { kind: 'endpoint', method: 'GET', path: '/api/orders/41' },
        preconditions: ['Reuse the persisted auth context.'],
        steps: [{ order: 1, action: 'Replay the same scoped target.' }],
        assertions: [{ kind: 'response_diff', description: 'Capture a bounded diff.' }],
        requiredEvidence: [{ kind: 'response_diff', description: 'Persist the comparison.' }],
        priority: 'high',
        plannerRationaleSummary: 'Mutation planner coverage.',
        caseFamily: 'generic',
        caseIntelligence: {
            selectionSummary: 'Selected because it stays inside the persisted anchors.',
            anchorSummary: 'Stay on the existing route only.',
            candidateInputs: [],
            securityConcerns: [],
            followUpPolicy: {
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['control_contrast'],
                queueThresholdScore: 40,
                strongSignalMarkers: [],
                boundedBy: ['Persisted inputs only'],
                stopConditions: ['No same-scope input remains'],
            },
        },
        maxAdaptiveFollowUps: 1,
        preferredRail: 'request',
        allowedConfirmationKinds: ['control_contrast'],
        status: 'planned',
        reviewState: 'approved',
        ...overrides,
    };
}

test('FocusedMutationPlanner mutates observed path identifiers without placeholder probe parameters', () => {
    const testCase = buildCase({
        caseFamily: 'access_control',
        caseIntelligence: {
            selectionSummary: 'Selected for an adjacent order-id contrast.',
            anchorSummary: 'Stay on the captured order-detail path.',
            candidateInputs: [{
                name: 'orderId',
                location: 'path',
                reason: 'Observed object reference in the captured route.',
                mutationStrategy: 'adjacent_identifier',
                observedValuePreview: '41',
            }],
            securityConcerns: [],
            followUpPolicy: {
                maxAdaptiveFollowUps: 2,
                allowedConfirmationKinds: ['alternate_id_compare'],
                queueThresholdScore: 40,
                strongSignalMarkers: ['authz_bypass'],
                boundedBy: ['Persisted route only'],
                stopConditions: ['No further adjacent identifier remains'],
            },
        },
    });

    const action = focusedMutationPlanner.buildPrimaryMutationAction({
        testCase,
        anchor: {
            defaultMethod: 'GET',
            defaultUrl: 'https://app.example.com/api/orders/41?view=full',
            useInitialRequestBaseline: false,
            requestShape: {
                pathParams: [{ name: 'orderId', location: 'path', valuePreview: '41' }],
                queryParams: [{ name: 'view', location: 'query', valuePreview: 'full' }],
                bodyFields: [],
                headerFields: [],
            },
        },
    });

    assert.ok(action);
    assert.equal(action?.type, 'mutated_replay');
    assert.equal(action?.url?.includes('/api/orders/42'), true);
    assert.equal(action?.url?.includes('__penpard'), false);
    assert.equal(action?.queryMutations, undefined);
    assert.equal(action?.bodyMutations, undefined);
    assert.equal(action?.targetInputs?.[0]?.name, 'orderId');
    assert.equal((action?.expectedSignals?.length || 0) > 0, true);
});

test('FocusedMutationPlanner emits same-scope body mutations for validation cases', () => {
    const testCase = buildCase({
        caseFamily: 'input_validation',
        targetArtifact: { kind: 'baseline_request', method: 'POST', path: '/api/orders' },
        caseIntelligence: {
            selectionSummary: 'Selected for one bounded quantity variation.',
            anchorSummary: 'Stay on the captured order creation request.',
            candidateInputs: [{
                name: 'quantity',
                location: 'body',
                reason: 'Observed body field in the persisted baseline request.',
                mutationStrategy: 'boundary_value',
                observedValuePreview: '5',
            }],
            securityConcerns: [],
            followUpPolicy: {
                maxAdaptiveFollowUps: 1,
                allowedConfirmationKinds: ['control_contrast'],
                queueThresholdScore: 40,
                strongSignalMarkers: ['validation_rejected'],
                boundedBy: ['Existing body field only'],
                stopConditions: ['Safe-failure comparison completed'],
            },
        },
    });

    const action = focusedMutationPlanner.buildPrimaryMutationAction({
        testCase,
        anchor: {
            defaultMethod: 'POST',
            defaultUrl: 'https://app.example.com/api/orders',
            useInitialRequestBaseline: true,
            requestShape: {
                pathParams: [],
                queryParams: [],
                bodyFields: [{ name: 'quantity', location: 'body', valuePreview: '5' }],
                headerFields: [],
            },
        },
    });

    assert.ok(action);
    assert.equal(action?.type, 'mutated_replay');
    assert.equal(action?.url, 'https://app.example.com/api/orders');
    assert.equal(action?.queryMutations, undefined);
    assert.equal(action?.bodyMutations?.[0]?.name, 'quantity');
    assert.equal(action?.bodyMutations?.[0]?.value, 6);
    assert.equal(action?.selectionReason?.includes('quantity'), true);
});
