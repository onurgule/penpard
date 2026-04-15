import test from 'node:test';
import assert from 'node:assert/strict';

import {
    buildLocalOpenAiRequestBody,
    callOpenAiCompatibleLocalModel,
    extractVisibleContent,
    normalizeOpenAiCompatibleChatResponse,
    normalizeToolCalls,
    normalizeUsage,
} from '../src/services/llm/OpenAiCompatibleLocalAdapter';

function mockFetchSequence(handlers: Array<() => Promise<Response> | Response>) {
    const originalFetch = globalThis.fetch;
    let index = 0;

    (globalThis as any).fetch = async () => {
        const handler = handlers[Math.min(index, handlers.length - 1)];
        index += 1;
        return handler();
    };

    return {
        calls: () => index,
        restore: () => {
            (globalThis as any).fetch = originalFetch;
        },
    };
}

function jsonResponse(body: any, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    });
}

function sseResponse(chunks: string[]) {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
        start(controller) {
            for (const chunk of chunks) {
                controller.enqueue(encoder.encode(chunk));
            }
            controller.close();
        },
    });

    return new Response(stream, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
    });
}

test('request builder disables Qwen thinking for structured output and tool calls', () => {
    const jsonBody = buildLocalOpenAiRequestBody({
        systemPrompt: 'system',
        userPrompt: 'user',
        responseFormat: { type: 'json_object' },
        reasoningMode: 'capture',
    }, {
        configuredModel: 'qwen3.5',
        defaultMaxTokens: 1024,
        temperature: 0.1,
    }, { stream: false });

    assert.equal(jsonBody.model, 'qwen3.5');
    assert.deepEqual(jsonBody.response_format, { type: 'json_object' });
    assert.deepEqual(jsonBody.chat_template_kwargs, { enable_thinking: false });

    const toolBody = buildLocalOpenAiRequestBody({
        systemPrompt: 'system',
        userPrompt: 'user',
        tools: [{
            type: 'function',
            function: {
                name: 'lookup_asset',
                description: 'Lookup an asset',
                parameters: { type: 'object' },
            },
        }],
        toolChoice: 'auto',
    }, {
        configuredModel: 'qwen3.5',
        defaultMaxTokens: 1024,
        temperature: 0.1,
    }, { stream: true });

    assert.equal(toolBody.stream, true);
    assert.equal(Array.isArray(toolBody.tools), true);
    assert.equal(toolBody.tool_choice, 'auto');
    assert.deepEqual(toolBody.chat_template_kwargs, { enable_thinking: false });
});

test('extractVisibleContent keeps visible blocks and excludes reasoning blocks', () => {
    assert.equal(extractVisibleContent('plain text'), 'plain text');
    assert.equal(extractVisibleContent([
        { type: 'text', text: 'First ' },
        { type: 'reasoning', text: 'private' },
        { type: 'text', text: 'Second' },
    ]), 'First Second');
});

test('response normalization captures reasoning separately without leaking it into text', () => {
    const normalized = normalizeOpenAiCompatibleChatResponse({
        model: 'qwen3.5',
        choices: [{
            message: {
                role: 'assistant',
                content: 'Visible answer',
                reasoning: 'Hidden reasoning',
                tool_calls: [{
                    id: 'call_1',
                    type: 'function',
                    function: {
                        name: 'lookup_asset',
                        arguments: '{"asset":"token"}',
                    },
                }],
            },
            finish_reason: 'tool_calls',
        }],
        usage: {
            prompt_tokens: 12,
            completion_tokens: 4,
            total_tokens: 16,
            completion_tokens_details: { reasoning_tokens: 0 },
        },
    });

    assert.equal(normalized.text, 'Visible answer');
    assert.equal(normalized.reasoning, 'Hidden reasoning');
    assert.equal(normalized.finishReason, 'tool_calls');
    assert.equal(normalized.toolCalls.length, 1);
    assert.deepEqual(normalized.toolCalls[0].function.parsedArguments, { asset: 'token' });
    assert.equal(normalized.usage?.total_tokens, 16);
    assert.equal(normalized.usage?.reasoning_tokens, 0);
});

test('tool-call normalization preserves malformed argument strings without crashing', () => {
    const toolCalls = normalizeToolCalls([{
        id: 'call_1',
        type: 'function',
        function: {
            name: 'lookup_asset',
            arguments: '{"asset":',
        },
    }]);

    assert.equal(toolCalls.length, 1);
    assert.equal(toolCalls[0].function.arguments, '{"asset":');
    assert.equal(toolCalls[0].function.parsedArguments, undefined);
});

test('usage normalization captures total and reasoning token fields', () => {
    const usage = normalizeUsage({
        prompt_tokens: 20,
        completion_tokens: 7,
        total_tokens: 27,
        completion_tokens_details: { reasoning_tokens: 3 },
    });

    assert.deepEqual(usage, {
        input_tokens: 20,
        output_tokens: 7,
        total_tokens: 27,
        reasoning_tokens: 3,
    });
});

test('streamed local adapter aggregates reasoning, content, and incremental tool-call arguments', async () => {
    const fetchMock = mockFetchSequence([
        () => sseResponse([
            'data: {"id":"chatcmpl-1","model":"qwen3.5","choices":[{"index":0,"delta":{"role":"assistant","reasoning":"Thinking... "}}]}\n\n',
            'data: {"id":"chatcmpl-1","model":"qwen3.5","choices":[{"index":0,"delta":{"content":"Visible "}}]}\n\n',
            'data: {"id":"chatcmpl-1","model":"qwen3.5","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup_asset","arguments":"{\\"asset\\":"}}]}}]}\n\n',
            'data: {"id":"chatcmpl-1","model":"qwen3.5","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"token\\"}"}}]}}]}\n\n',
            'data: {"id":"chatcmpl-1","model":"qwen3.5","choices":[{"index":0,"delta":{"content":"answer"},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}}\n\n',
            'data: [DONE]\n\n',
        ]),
    ]);

    try {
        const result = await callOpenAiCompatibleLocalModel({
            baseUrl: 'http://127.0.0.1:8080',
            configuredModel: 'qwen3.5',
            defaultMaxTokens: 1024,
            temperature: 0.2,
            request: {
                systemPrompt: 'system',
                userPrompt: 'user',
            },
        });

        assert.equal(result.text, 'Visible answer');
        assert.equal(result.reasoning, 'Thinking... ');
        assert.equal(result.finishReason, 'tool_calls');
        assert.equal(result.toolCalls?.length, 1);
        assert.equal(result.toolCalls?.[0]?.function.arguments, '{"asset":"token"}');
        assert.deepEqual(result.toolCalls?.[0]?.function.parsedArguments, { asset: 'token' });
        assert.equal(result.diagnostics?.streamingStarted, true);
        assert.equal(result.responseSummary.streamed, true);
    } finally {
        fetchMock.restore();
    }
});

test('local adapter falls back to non-stream mode when the server rejects SSE', async () => {
    const fetchMock = mockFetchSequence([
        () => jsonResponse({ error: { message: 'stream unsupported' } }, 400),
        () => jsonResponse({
            model: 'qwen3.5',
            choices: [{
                message: { role: 'assistant', content: 'Fallback JSON response' },
                finish_reason: 'stop',
            }],
            usage: { prompt_tokens: 6, completion_tokens: 3, total_tokens: 9 },
        }),
    ]);

    try {
        const result = await callOpenAiCompatibleLocalModel({
            baseUrl: 'http://127.0.0.1:8080',
            configuredModel: 'qwen3.5',
            defaultMaxTokens: 1024,
            temperature: 0.2,
            request: {
                systemPrompt: 'system',
                userPrompt: 'user',
            },
        });

        assert.equal(fetchMock.calls(), 2);
        assert.equal(result.text, 'Fallback JSON response');
        assert.equal(result.responseSummary.streamed, false);
    } finally {
        fetchMock.restore();
    }
});
