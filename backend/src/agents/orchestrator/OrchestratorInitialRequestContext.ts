import { ConversationMessage } from './types';
import {
    buildInitialRequestLogSummary,
    buildInitialRequestPromptSummary,
    parseInitialRequestProfile,
} from './OrchestratorInitialRequestProfile';

export interface OrchestratorInitialRequestContext {
    parsed: ReturnType<typeof parseInitialRequestProfile>;
    systemPromptAppendix: string;
    initialMessages: ConversationMessage[];
    continuationMessages: ConversationMessage[];
    logSummary: string;
}

export function buildInitialRequestContext(rawRequest: string): OrchestratorInitialRequestContext {
    const parsed = parseInitialRequestProfile(rawRequest.trim());
    if (!parsed) {
        return {
            parsed: null,
            systemPromptAppendix: `\n\n================================================================\n  SEND TO PENPARD - REQUEST FROM BURP (SANITIZED)\n================================================================\n\nA Burp-originated HTTP request is stored server-side for replay. The request could not be safely summarized, so PenPard will keep the raw request entirely on the backend.\n\nRules for Burp-derived replay:\n1. Treat the stored request as a backend-only baseline request.\n2. When replaying it, set useInitialRequestBaseline=true so PenPard reuses the stored request server-side.\n3. Pair baseline replay with preserveExplicitAuth=true so PenPard preserves the stored explicit auth material server-side.\n4. Do NOT ask for or reconstruct raw Cookie, Authorization, CSRF, API-key, or other secret header values.\n5. Only provide the modified URL/body/header pieces you intentionally want PenPard to change.\n`,
            initialMessages: [{
                role: 'user',
                content: `A Burp-originated HTTP request is stored server-side for replay. The raw request was intentionally not copied into the conversation.\n\nStart with a baseline replay of the stored request using useInitialRequestBaseline=true and preserveExplicitAuth=true, then continue with targeted testing while keeping all raw auth material on the backend.`,
            }],
            continuationMessages: [{
                role: 'user',
                content: `Reminder: the Burp-originated request is still stored server-side. Continue using useInitialRequestBaseline=true with preserveExplicitAuth=true for baseline replay and do not reconstruct raw auth headers or cookies in the conversation.`,
            }],
            logSummary: 'Burp request profile stored server-side without prompt serialization',
        };
    }

    const promptSummary = buildInitialRequestPromptSummary(parsed);
    const logSummary = buildInitialRequestLogSummary(parsed);

    return {
        parsed,
        systemPromptAppendix: `\n\n================================================================\n  SEND TO PENPARD - REQUEST FROM BURP (SANITIZED)\n================================================================\n\nA Burp-originated HTTP request is stored server-side for replay.\n\n${promptSummary}\n\nStrict rules:\n1. For Burp-derived replay, set useInitialRequestBaseline=true so PenPard reuses the stored baseline request server-side.\n2. Pair baseline replay with preserveExplicitAuth=true so PenPard preserves the stored explicit auth material server-side.\n3. Do NOT include raw Cookie, Authorization, CSRF, API-key, or other secret header values in prompts or tool calls unless you intentionally need to override a specific header.\n4. Do NOT copy literal <preserved> placeholders into tool calls. Use useInitialRequestBaseline=true and mutations instead.\n5. You may omit unchanged headers and unchanged body content. PenPard will replay the stored baseline request server-side and merge only your explicit changes.\n6. Prefer parametric testing. Use queryMutations for URL parameters. For JSON or form bodies, use bodyMutations when you only need to change specific stored fields.\n7. Only change headers when the operator explicitly asks for header-focused testing.\n\nPreferred Burp-derived replay shapes:\n  { "method": "${parsed.method}", "useInitialRequestBaseline": true, "preserveExplicitAuth": true }\n  { "method": "${parsed.method}", "useInitialRequestBaseline": true, "preserveExplicitAuth": true, "queryMutations": [{ "name": "<param>", "value": "<mutated-value>" }], "bodyMutations": [{ "name": "<field>", "value": "<mutated-value>" }] }\n`,
        initialMessages: [
            {
                role: 'user',
                content: `CRITICAL - Request from Burp (Send to PenPard).\n\nA full baseline request is stored server-side and has been summarized safely below:\n${promptSummary}\n\nPlanning rules:\n1. Start with a baseline replay of the stored request using useInitialRequestBaseline=true and preserveExplicitAuth=true.\n2. Do NOT reconstruct or quote raw cookies, bearer tokens, CSRF values, or other secret header values.\n3. Modify parameter values, not unrelated internal state.\n4. Do NOT copy literal <preserved> placeholders into tool calls. Use queryMutations or bodyMutations while keeping useInitialRequestBaseline=true.\n5. If you need to change only stored JSON or form body fields, use bodyMutations so PenPard preserves the rest of the baseline body server-side.\n6. If the operator later asks to test a specific header, send only that explicit override instead of serializing the entire stored header set.\n\nExample calls:\n{\n  "tool": "send_http_request",\n  "args": {\n    "method": "${parsed.method}",\n    "useInitialRequestBaseline": true,\n    "preserveExplicitAuth": true\n  }\n}\n\n{\n  "tool": "send_http_request",\n  "args": {\n    "method": "${parsed.method}",\n    "useInitialRequestBaseline": true,\n    "preserveExplicitAuth": true,\n    "queryMutations": [{ "name": "<param>", "value": "<mutated-value>" }],\n    "bodyMutations": [{ "name": "<field>", "value": "<mutated-value>" }]\n  }\n}\n\nStart with the baseline replay, then continue with targeted parametric testing.`,
            },
            {
                role: 'assistant',
                content: `Understood. I will:\n1. Replay the stored Burp request via PenPard with useInitialRequestBaseline=true and preserveExplicitAuth=true so raw auth material stays on the backend\n2. Use the sanitized request summary to choose target parameters without serializing secret headers or body values\n3. Prefer queryMutations and bodyMutations over reconstructing the entire stored request\n4. Start with a baseline replay, then test each relevant parameter for vulnerabilities\n\nLet me begin by analyzing the request summary and planning my tests.`,
            },
        ],
        continuationMessages: [
            {
                role: 'user',
                content: `REMINDER - The Burp-originated request is still stored server-side. Continue using useInitialRequestBaseline=true with preserveExplicitAuth=true for Burp-derived replay.\n\nSanitized request summary:\n${promptSummary}\n\nDo NOT reconstruct raw cookies, bearer tokens, or other secret header values in the conversation. Send only the URL/body/header changes you intentionally want PenPard to apply.`,
            },
            {
                role: 'assistant',
                content: `Understood. I will continue replaying the stored Burp baseline through PenPard with useInitialRequestBaseline=true and preserveExplicitAuth=true, and I will avoid serializing raw auth material into the conversation.`,
            },
        ],
        logSummary,
    };
}
