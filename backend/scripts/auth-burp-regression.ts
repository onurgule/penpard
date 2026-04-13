import path from 'path';
import { serializeStructuredBurpRequest } from '../src/services/burp-request';

process.env.DATABASE_PATH = process.env.DATABASE_PATH || path.join(process.cwd(), 'tmp', 'penpard-script.db');
const { OrchestratorAgent } = require('../src/agents/OrchestratorAgent') as typeof import('../src/agents/OrchestratorAgent');

function makeJwt(exp: number): string {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({ sub: 'script-user', exp })}.signature`;
}

function buildRawRequest(authHeader: string, cookieHeader: string = 'session=primary'): string {
    return [
        'GET /api/me HTTP/1.1',
        'Host: app.example.com',
        `Authorization: ${authHeader}`,
        `Cookie: ${cookieHeader}`,
        'Accept: application/json',
        '',
        '',
    ].join('\r\n');
}

class ScriptFakeBurp {
    public sent: Array<Record<string, any>> = [];
    private responses: Array<Record<string, any>> = [];

    setResponses(responses: Array<Record<string, any>>) {
        this.responses = [...responses];
    }

    async callTool(tool: string, args: Record<string, any>): Promise<any> {
        switch (tool) {
            case 'get_cookies_and_auth_for_host':
                return { entries: [] };
            case 'get_session_cookies':
                return { cookieHeader: '' };
            case 'get_proxy_history':
                return { items: [] };
            case 'send_http_request':
                this.sent.push(args);
                return this.responses.shift() || {
                    statusCode: 200,
                    headers: ['content-type: application/json'],
                    body: '{"ok":true}',
                };
            default:
                return {};
        }
    }
}

function printScenarioHeader(title: string): void {
    console.log(`\n=== ${title} ===`);
}

function printSentRequest(label: string, request: Record<string, any>): void {
    console.log(`\n${label}`);
    console.log(`Method: ${request.method}`);
    console.log(`URL: ${request.url}`);
    console.log('Headers:');
    for (const [name, value] of Object.entries(request.headers || {})) {
        console.log(`  ${name}: ${value}`);
    }
    console.log('\nSerialized raw request preview:');
    console.log(serializeStructuredBurpRequest({
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: request.body,
    }));
}

async function main(): Promise<void> {
    const jwt = makeJwt(Math.floor(Date.now() / 1000) + 3600);
    const initialRequest = buildRawRequest(`Bearer ${jwt}`);
    const burp = new ScriptFakeBurp();
    const agent = new OrchestratorAgent(
        'scan-script',
        'https://app.example.com',
        {
            rateLimit: 5,
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            initialRequest,
        },
        burp as any,
    );

    await agent.authManager.initialize({
        idorUsers: [],
        initialRequest,
    }, burp as any);

    const executeSendHttpRequest = (toolCall: any) => (agent as any).requestExecutor.execute(toolCall);

    let failures = 0;

    printScenarioHeader('Scenario 1: Managed injection from Burp-seeded auth state');
    burp.sent = [];
    burp.setResponses([{
        statusCode: 200,
        headers: ['content-type: application/json'],
        body: '{"ok":true}',
    }]);

    const baselineResult = await executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
        },
    });

    printSentRequest('Outgoing request', burp.sent[0]);

    if (burp.sent[0]?.headers?.Authorization === `Bearer ${jwt}`) {
        console.log('PASS: Authorization was injected from stored Burp auth state.');
    } else {
        console.log('FAIL: Authorization was not injected.');
        failures++;
    }

    console.log(`Result status: ${baselineResult.statusCode || baselineResult.status}`);

    printScenarioHeader('Scenario 2: 401 recovery when a Burp-originated request was sent without auth');
    burp.sent = [];
    burp.setResponses([
        {
            statusCode: 401,
            headers: ['content-type: application/json'],
            body: '{"error":"missing auth"}',
        },
        {
            statusCode: 200,
            headers: ['content-type: application/json'],
            body: '{"ok":true}',
        },
    ]);

    const recoveryResult = await executeSendHttpRequest({
        tool: 'send_http_request',
        args: {
            method: 'GET',
            url: 'https://app.example.com/api/me',
            headers: {},
            preserveExplicitAuth: true,
        },
    });

    printSentRequest('First outgoing request', burp.sent[0]);
    printSentRequest('Retry request', burp.sent[1]);

    const firstHadAuth = !!burp.sent[0]?.headers?.Authorization;
    const secondHadAuth = burp.sent[1]?.headers?.Authorization === `Bearer ${jwt}`;

    if (!firstHadAuth && secondHadAuth && recoveryResult.retriedAfterAuthInjection === true) {
        console.log('PASS: 401 recovery retried once with stored Authorization.');
    } else {
        console.log('FAIL: 401 recovery did not behave as expected.');
        failures++;
    }

    console.log(`Final status: ${recoveryResult.statusCode || recoveryResult.status}`);
    if (recoveryResult.authWarning) {
        console.log(`Auth warning: ${recoveryResult.authWarning}`);
    }

    if (failures > 0) {
        console.error(`\nRegression script finished with ${failures} failure(s).`);
        process.exitCode = 1;
        return;
    }

    console.log('\nAll Burp auth regression checks passed.');
}

main().catch(error => {
    console.error('Regression script failed to run:', error);
    process.exitCode = 1;
});
