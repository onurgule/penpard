import { ParsedBurpRequest, parseRawBurpRequest } from '../../services/burp-request';
import { ConversationMessage } from './types';

export interface OrchestratorInitialRequestContext {
    parsed: ParsedBurpRequest | null;
    systemPromptAppendix: string;
    initialMessages: ConversationMessage[];
    continuationMessages: ConversationMessage[];
    logSummary: string;
}

function buildHeaderLines(parsed: ParsedBurpRequest): string {
    return Object.entries(parsed.headers)
        .filter(([name]) => !name.toLowerCase().startsWith('x-penpard'))
        .map(([name, value]) => `    "${name}": "${value}"`)
        .join(',\n');
}

function buildHeadersJson(parsed: ParsedBurpRequest): string {
    return JSON.stringify(
        Object.fromEntries(
            Object.entries(parsed.headers).filter(([name]) => !name.toLowerCase().startsWith('x-penpard')),
        ),
        null,
        2,
    );
}

export function buildInitialRequestContext(rawRequest: string): OrchestratorInitialRequestContext {
    const parsed = parseRawBurpRequest(rawRequest.trim());
    if (!parsed) {
        return {
            parsed: null,
            systemPromptAppendix: '',
            initialMessages: [{
                role: 'user',
                content: `Request from Burp (Send to PenPard). Test this request. Raw:\n\n${rawRequest.trim()}`,
            }],
            continuationMessages: [{
                role: 'user',
                content: `Reminder: the original Burp request is still active. Raw request:\n\n${rawRequest.trim()}`,
            }],
            logSummary: 'Could not parse Burp request; raw request was injected instead',
        };
    }

    const headerLines = buildHeaderLines(parsed);
    const headersJson = buildHeadersJson(parsed);
    const headerCount = Object.keys(parsed.headers).length;

    return {
        parsed,
        systemPromptAppendix: `\n\n================================================================\n  SEND TO PENPARD - REQUEST FROM BURP (CRITICAL)\n================================================================\n\nYou received a complete HTTP request from the user via Burp. STRICT RULES:\n\n1. Every send_http_request MUST include ALL headers listed below. Do NOT omit any. Do NOT add new headers. Copy them exactly.\n2. Set preserveExplicitAuth=true so PenPard preserves the explicit Cookie/Authorization headers exactly as supplied.\n3. Only PARAMETRIC testing: change parameter values in the URL query string or body. Do NOT touch headers unless the user explicitly asks.\n4. The request has cookies and auth tokens - these are essential for authenticated testing.\n\nBASE REQUEST:\n  Method: ${parsed.method}\n  URL: ${parsed.url}\n  Headers (INCLUDE ALL OF THESE IN EVERY REQUEST):\n${headerLines}\n  Body: ${parsed.body || '(none)'}\n\nWhen calling send_http_request, use:\n  { "method": "${parsed.method}", "url": "<url with modified params>", "headers": { ALL HEADERS ABOVE }, "body": "${parsed.body || ''}", "preserveExplicitAuth": true }\n`,
        initialMessages: [
            {
                role: 'user',
                content: `CRITICAL - Request from Burp (Send to PenPard).\n\nPLANNING PHASE: Before testing, analyze this request:\n- Look at the cookies and auth tokens - note which ones are session tokens\n- Identify all parameters in the URL query string and body\n- Plan which parameters to test for which vulnerability types (SQLi, XSS, IDOR, etc.)\n\nRULES:\n1. Include ALL headers below in EVERY send_http_request call. Copy them exactly - do not omit Cookie, User-Agent, Authorization, or any other header. The user's session depends on these.\n2. Only modify PARAMETER VALUES (query string, body fields). Headers stay unchanged.\n3. If the user later says "test the Host header" or similar, only then may you modify that specific header.\n\nBASE REQUEST:\nMethod: ${parsed.method}\nURL: ${parsed.url}\nHeaders (JSON - pass this entire object in every send_http_request):\n${headersJson}\nBody: ${parsed.body || '(none)'}\n\nExample call:\n{\n  "tool": "send_http_request",\n  "args": {\n    "method": "${parsed.method}",\n    "url": "${parsed.url}",\n    "headers": ${headersJson},\n    "body": "${parsed.body || ''}",\n    "preserveExplicitAuth": true\n  }\n}\n\nStart by sending the original request as-is to get a baseline response, then begin parametric testing.`,
            },
            {
                role: 'assistant',
                content: `Understood. I will:\n1. Include ALL ${headerCount} headers in every request (Cookie, User-Agent, auth tokens, etc.)\n2. Set preserveExplicitAuth=true when replaying the Burp-derived request so PenPard preserves the supplied auth exactly\n3. Only modify parameter values for testing - headers stay exactly as provided\n4. Start with a baseline request, then test each parameter for vulnerabilities\n\nLet me begin by analyzing the request and planning my tests.`,
            },
        ],
        continuationMessages: [
            {
                role: 'user',
                content: `REMINDER - The original request from Burp (Send to PenPard) is still active. You MUST include ALL these headers in every send_http_request and set preserveExplicitAuth=true.\n\nMethod: ${parsed.method}\nURL: ${parsed.url}\nHeaders (JSON - pass this entire object):\n${headersJson}\nBody: ${parsed.body || '(none)'}\n\nDo NOT send requests without these headers. The user's session cookies and auth tokens are required.`,
            },
            {
                role: 'assistant',
                content: `Understood. I will continue including all ${headerCount} headers (Cookie, auth tokens, User-Agent, etc.) in every request and I will set preserveExplicitAuth=true so PenPard does not replace them.`,
            },
        ],
        logSummary: `Burp request parsed - ${parsed.method} ${parsed.url.substring(0, 80)} - ${headerCount} headers preserved`,
    };
}
