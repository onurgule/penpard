import test from 'node:test';
import assert from 'node:assert/strict';

import {
    ensureFindingIdentity,
    estimateCvss,
    isDuplicateFindingName,
} from '../src/agents/orchestrator/OrchestratorFindingIdentityPolicy';

test('finding identity policy derives a stable finding name from generic findings and request context', () => {
    const finding: any = {
        name: 'Security Issue',
        cwe: 'CWE-79',
        parameter: 'q',
        description: 'Payload reflects in the response body.',
    };

    const name = ensureFindingIdentity(finding, {
        action: {
            tool: 'send_http_request',
            args: {
                url: 'https://app.example.com/search?q=test',
            },
        },
    } as any);

    assert.equal(name, 'Cross-Site Scripting (XSS) - /search?q=test (q)');
    assert.equal(finding.name, name);
});

test('finding identity policy detects duplicate finding names by vulnerability family and endpoint overlap', () => {
    assert.equal(isDuplicateFindingName(
        ['Cross-Site Scripting (XSS) - /search (q)'],
        'Cross Site Scripting XSS - /search?q=test (term)',
    ), true);

    assert.equal(isDuplicateFindingName(
        ['SQL Injection - /api/users'],
        'Cross-Site Scripting (XSS) - /search (q)',
    ), false);
});

test('finding identity policy keeps severity-to-cvss scoring stable', () => {
    assert.equal(estimateCvss('critical'), 9.5);
    assert.equal(estimateCvss('medium'), 5.5);
    assert.equal(estimateCvss('unknown'), 5.0);
});
