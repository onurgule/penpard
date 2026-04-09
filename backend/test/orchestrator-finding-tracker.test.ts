import test from 'node:test';
import assert from 'node:assert/strict';

import { OrchestratorFindingTracker } from '../src/agents/orchestrator/OrchestratorFindingTracker';
import { ToolCall } from '../src/agents/orchestrator/types';

class FakeBurp {
    public readonly repeaterCalls: Array<Record<string, any>> = [];

    async callTool(tool: string, args: Record<string, any>): Promise<any> {
        if (tool === 'send_to_repeater') {
            this.repeaterCalls.push(args);
        }
        return {};
    }
}

function createAction(url: string): ToolCall {
    return {
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url,
            headers: {
                Cookie: 'session=abc123',
            },
        },
    };
}

test('finding tracker normalizes generic findings, persists once, and forwards repeater evidence', () => {
    const burp = new FakeBurp();
    const persisted: Array<Record<string, any>> = [];
    const savedNames: string[] = [];
    const savedFindings: any[] = [];
    const lastExchange = {
        action: createAction('https://app.example.com/search?q=penpard'),
        result: {
            statusCode: 200,
            headers: ['content-type: text/html'],
            body: '<html>ok</html>',
        },
        rawRequest: 'GET /search?q=penpard HTTP/1.1\r\nHost: app.example.com\r\nCookie: session=abc123\r\n\r\n',
        rawResponse: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>',
    };

    const tracker = new OrchestratorFindingTracker({
        scanId: 'scan-finding-test',
        burp: burp as any,
        log: () => {},
        getLastExchange: () => lastExchange,
        onFindingSaved: (finding) => {
            savedFindings.push({ ...finding });
            savedNames.push(String(finding.name));
        },
        persistVulnerability: (payload) => {
            persisted.push(payload);
        },
        loadExistingFindingNames: () => [...savedNames],
    });

    const firstSaved = tracker.saveFinding({
        name: 'Security Issue',
        severity: 'high',
        description: 'User input is reflected in HTML output.',
        cwe: 'CWE-79',
        endpoint: '/search',
        parameter: 'q',
        evidence: 'Reflected payload observed in the response body.',
    });
    const secondSaved = tracker.saveFinding({
        name: 'Cross-Site Scripting (XSS) - /search (q)',
        severity: 'high',
        description: 'Duplicate persistence attempt',
        cwe: 'CWE-79',
    });

    assert.equal(firstSaved, true);
    assert.equal(secondSaved, false);
    assert.equal(persisted.length, 1);
    assert.equal(savedFindings.length, 1);
    assert.equal(savedFindings[0].name, 'Cross-Site Scripting (XSS) - /search (q)');
    assert.match(String(persisted[0].request || ''), /GET \/search\?q=penpard HTTP\/1\.1/);
    assert.match(String(persisted[0].response || ''), /HTTP\/1\.1 200 OK/);
    assert.equal(burp.repeaterCalls.length, 1);
    assert.equal(burp.repeaterCalls[0].host, 'app.example.com');
});

test('finding tracker auto-detects reflected XSS from the latest request/response evidence', () => {
    const burp = new FakeBurp();
    const persisted: Array<Record<string, any>> = [];
    const action = createAction('https://app.example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
    const tracker = new OrchestratorFindingTracker({
        scanId: 'scan-auto-finding-test',
        burp: burp as any,
        log: () => {},
        getLastExchange: () => ({
            action,
            result: {
                statusCode: 200,
                headers: ['content-type: text/html'],
            },
            rawRequest: 'GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: app.example.com\r\n\r\n',
            rawResponse: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script>alert(1)</script></html>',
        }),
        persistVulnerability: (payload) => {
            persisted.push(payload);
        },
        loadExistingFindingNames: () => [],
    });

    tracker.analyzeResponseForVulns(action, {
        statusCode: 200,
        headers: ['content-type: text/html'],
        body: '<html><script>alert(1)</script></html>',
    });

    assert.equal(persisted.length, 1);
    assert.match(String(persisted[0].name || ''), /Reflected XSS - https:\/\/app\.example\.com\/search/);
    assert.equal(persisted[0].cwe, 'CWE-79');
    assert.match(String(persisted[0].request || ''), /GET \/search\?q=/);
    assert.equal(burp.repeaterCalls.length, 1);
});
