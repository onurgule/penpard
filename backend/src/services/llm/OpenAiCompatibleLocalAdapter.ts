import type {
    GenerationMessage,
    GenerationRequest,
    GenerationResponse,
    GenerationResponseFormat,
    GenerationToolCall,
    GenerationToolChoice,
    NormalizedUsage,
} from './LlmProviderTypes';
import type { ProviderAttemptDiagnostics, ProviderExecutionOptions } from './LlmRuntimeTypes';
import { extractStructuredJsonValue } from './LlmStructuredOutput';

interface LocalOpenAiAdapterOptions {
    baseUrl: string;
    configuredModel: string;
    defaultMaxTokens: number;
    temperature: number;
    timeoutMs?: number | null;
    request: GenerationRequest;
    executionOptions?: ProviderExecutionOptions;
}

export interface LocalOpenAiResponseSummary {
    streamed: boolean;
    resolvedModel: string | null;
    finishReason: string | null;
    hasContent: boolean;
    contentLength: number;
    hasReasoning: boolean;
    reasoningLength: number;
    toolCallCount: number;
    usageFields: string[];
}

export interface LocalOpenAiAdapterResult extends GenerationResponse {
    resolvedModel?: string | null;
    diagnostics?: Partial<ProviderAttemptDiagnostics>;
    responseSummary: LocalOpenAiResponseSummary;
}

interface MutableToolCall {
    id?: string;
    type: 'function';
    function: {
        name: string;
        arguments: string;
    };
}

interface NormalizedLocalResponse {
    text: string;
    reasoning: string | null;
    toolCalls: GenerationToolCall[];
    finishReason: string | null;
    usage?: NormalizedUsage;
    resolvedModel: string | null;
}

interface StreamParseState {
    content: string;
    reasoning: string;
    toolCalls: Map<number, MutableToolCall>;
    usage?: NormalizedUsage;
    resolvedModel: string | null;
    finishReason: string | null;
    anyEventReceived: boolean;
    assistantMessageReceived: boolean;
    progressEventCount: number;
    sawDone: boolean;
    firstEventAtMs: number | null;
    firstProgressAtMs: number | null;
    partialOutputAtMs: number | null;
    lastEventAtMs: number | null;
    lastProgressAtMs: number | null;
    idleAtMs: number | null;
    finalizationAtMs: number | null;
}

function nowMs(startedAtMs: number): number {
    return Date.now() - startedAtMs;
}

function combineAbortSignals(signals: Array<AbortSignal | undefined>): { signal?: AbortSignal; cleanup: () => void } {
    const activeSignals = signals.filter((signal): signal is AbortSignal => !!signal);
    if (activeSignals.length === 0) {
        return { signal: undefined, cleanup: () => undefined };
    }

    const controller = new AbortController();
    const cleanups: Array<() => void> = [];

    for (const signal of activeSignals) {
        if (signal.aborted) {
            controller.abort(signal.reason);
            break;
        }

        const handler = () => controller.abort(signal.reason);
        signal.addEventListener('abort', handler, { once: true });
        cleanups.push(() => signal.removeEventListener('abort', handler));
    }

    return {
        signal: controller.signal,
        cleanup: () => {
            for (const cleanup of cleanups) {
                cleanup();
            }
        },
    };
}

function isQwenModel(model: string): boolean {
    const normalized = model.trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

function shouldDisableQwenThinking(request: GenerationRequest, model: string): boolean {
    if (!isQwenModel(model)) {
        return false;
    }

    if (request.reasoningMode === 'disabled') {
        return true;
    }

    if (request.responseFormat || (request.tools && request.tools.length > 0)) {
        return true;
    }

    return !!request.messages?.some((message) =>
        message.role === 'tool'
        || (message.role === 'assistant' && Array.isArray(message.tool_calls) && message.tool_calls.length > 0),
    );
}

function buildRequestMessages(request: GenerationRequest): GenerationMessage[] {
    if (request.messages && request.messages.length > 0) {
        return request.messages;
    }

    const messages: GenerationMessage[] = [];
    if (request.systemPrompt) {
        messages.push({ role: 'system', content: request.systemPrompt });
    }

    if (request.images && request.images.length > 0) {
        messages.push({
            role: 'user',
            content: [
                { type: 'text', text: request.userPrompt || '' },
                ...request.images.map((image) => ({
                    type: 'image_url',
                    image_url: {
                        url: `data:${image.mimeType};base64,${image.data}`,
                        detail: 'high',
                    },
                })),
            ],
        });
    } else {
        messages.push({ role: 'user', content: request.userPrompt || '' });
    }

    return messages;
}

function buildResponseFormat(responseFormat: GenerationResponseFormat | undefined): Record<string, unknown> | undefined {
    if (!responseFormat) {
        return undefined;
    }

    if (responseFormat.type === 'json_object') {
        return { type: 'json_object' };
    }

    return {
        type: 'json_schema',
        json_schema: {
            name: responseFormat.json_schema.name,
            schema: responseFormat.json_schema.schema,
        },
    };
}

export function buildLocalOpenAiRequestBody(
    request: GenerationRequest,
    options: Pick<LocalOpenAiAdapterOptions, 'configuredModel' | 'defaultMaxTokens' | 'temperature'>,
    extra: { stream: boolean },
): Record<string, unknown> {
    const body: Record<string, unknown> = {
        model: options.configuredModel,
        messages: buildRequestMessages(request),
        max_tokens: request.maxTokens ?? options.defaultMaxTokens,
        temperature: request.temperature ?? options.temperature,
        stream: extra.stream,
    };

    const responseFormat = buildResponseFormat(request.responseFormat);
    if (responseFormat) {
        body.response_format = responseFormat;
    }
    if (request.tools?.length) {
        body.tools = request.tools;
    }
    if (request.toolChoice) {
        body.tool_choice = request.toolChoice as GenerationToolChoice;
    }
    if (shouldDisableQwenThinking(request, options.configuredModel)) {
        body.chat_template_kwargs = { enable_thinking: false };
    }

    return body;
}

export function extractVisibleContent(content: unknown): string {
    if (typeof content === 'string') {
        return content;
    }

    if (!Array.isArray(content)) {
        return '';
    }

    const parts: string[] = [];
    for (const block of content) {
        if (typeof block === 'string') {
            parts.push(block);
            continue;
        }
        if (!block || typeof block !== 'object') {
            continue;
        }
        const blockType = typeof block.type === 'string' ? block.type.toLowerCase() : '';
        if (blockType.includes('reasoning')) {
            continue;
        }
        if (typeof block.text === 'string') {
            parts.push(block.text);
        }
    }

    return parts.join('');
}

export function extractReasoningText(choice: any): string | null {
    const message = choice?.message;
    const candidates: unknown[] = [
        message?.reasoning,
        message?.reasoning_content,
        choice?.reasoning,
        choice?.reasoning_content,
    ];

    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.length > 0) {
            return candidate;
        }
        if (!Array.isArray(candidate)) {
            continue;
        }
        const parts = candidate
            .filter((block) => block && typeof block === 'object' && typeof block.text === 'string')
            .map((block) => String(block.text));
        if (parts.length > 0) {
            return parts.join('');
        }
    }

    const content = Array.isArray(message?.content) ? message.content : [];
    const reasoningParts = content
        .filter((block: any) => block && typeof block === 'object' && /reasoning/i.test(String(block.type || '')))
        .map((block: any) => String(block.text || ''))
        .filter(Boolean);
    return reasoningParts.length > 0 ? reasoningParts.join('') : null;
}

function normalizeToolArguments(argumentsText: string): unknown {
    const parsed = extractStructuredJsonValue(argumentsText);
    return parsed === null ? undefined : parsed;
}

export function normalizeToolCalls(rawToolCalls: unknown): GenerationToolCall[] {
    if (!Array.isArray(rawToolCalls)) {
        return [];
    }

    const normalized: GenerationToolCall[] = [];
    for (const rawCall of rawToolCalls) {
        if (!rawCall || typeof rawCall !== 'object') {
            continue;
        }
        const call = rawCall as Record<string, any>;
        const functionName = typeof call.function?.name === 'string' ? call.function.name : '';
        if (!functionName) {
            continue;
        }

        const rawArguments = call.function?.arguments;
        const argumentsText = typeof rawArguments === 'string'
            ? rawArguments
            : (rawArguments ? JSON.stringify(rawArguments) : '');

        normalized.push({
            id: typeof call.id === 'string' ? call.id : undefined,
            type: 'function',
            function: {
                name: functionName,
                arguments: argumentsText,
                parsedArguments: argumentsText ? normalizeToolArguments(argumentsText) : undefined,
            },
        });
    }

    return normalized;
}

function toNonNegativeNumber(value: unknown): number | undefined {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        return undefined;
    }
    return value;
}

export function normalizeUsage(rawUsage: any): NormalizedUsage | undefined {
    if (!rawUsage || typeof rawUsage !== 'object') {
        return undefined;
    }

    const inputTokens = toNonNegativeNumber(rawUsage.prompt_tokens ?? rawUsage.input_tokens);
    const outputTokens = toNonNegativeNumber(rawUsage.completion_tokens ?? rawUsage.output_tokens);
    const totalTokens = toNonNegativeNumber(rawUsage.total_tokens);
    const reasoningTokens = toNonNegativeNumber(
        rawUsage.reasoning_tokens
        ?? rawUsage.completion_tokens_details?.reasoning_tokens
        ?? rawUsage.output_tokens_details?.reasoning_tokens,
    );

    if (inputTokens === undefined && outputTokens === undefined && totalTokens === undefined && reasoningTokens === undefined) {
        return undefined;
    }

    return {
        input_tokens: inputTokens ?? 0,
        output_tokens: outputTokens ?? 0,
        total_tokens: totalTokens ?? ((inputTokens ?? 0) + (outputTokens ?? 0)),
        reasoning_tokens: reasoningTokens,
    };
}

function normalizeFinishReason(value: unknown): string | null {
    return typeof value === 'string' && value.trim() ? value : null;
}

export function normalizeOpenAiCompatibleChatResponse(data: any): NormalizedLocalResponse {
    if (!data || !Array.isArray(data.choices) || data.choices.length === 0) {
        throw new Error('Local LLM returned an invalid response format. Expected an OpenAI-compatible choices array.');
    }

    const choice = data.choices[0];
    const message = choice?.message || {};
    const text = extractVisibleContent(message.content);
    const reasoning = extractReasoningText(choice);
    const toolCalls = normalizeToolCalls(message.tool_calls ?? choice?.tool_calls);

    return {
        text,
        reasoning,
        toolCalls,
        finishReason: normalizeFinishReason(choice?.finish_reason),
        usage: normalizeUsage(data.usage),
        resolvedModel: typeof data.model === 'string' ? data.model : null,
    };
}

function buildResponseSummary(
    response: NormalizedLocalResponse,
    streamed: boolean,
): LocalOpenAiResponseSummary {
    return {
        streamed,
        resolvedModel: response.resolvedModel,
        finishReason: response.finishReason,
        hasContent: response.text.trim().length > 0,
        contentLength: response.text.length,
        hasReasoning: !!response.reasoning,
        reasoningLength: response.reasoning?.length || 0,
        toolCallCount: response.toolCalls.length,
        usageFields: response.usage
            ? Object.entries(response.usage)
                .filter(([, value]) => typeof value === 'number')
                .map(([key]) => key)
            : [],
    };
}

function buildCompletedDiagnostics(
    response: NormalizedLocalResponse,
    streamed: boolean,
    startedAtMs: number,
    base?: Partial<ProviderAttemptDiagnostics>,
): Partial<ProviderAttemptDiagnostics> {
    const completedAtMs = nowMs(startedAtMs);
    return {
        streamingStarted: streamed,
        anyEventReceived: streamed ? !!base?.anyEventReceived : true,
        partialOutputReceived: response.text.length > 0,
        assistantMessageReceived: streamed ? !!base?.assistantMessageReceived : response.text.length > 0 || response.toolCalls.length > 0 || !!response.reasoning,
        idleReceived: streamed ? !!base?.idleReceived : false,
        finalizationReceived: streamed ? !!base?.finalizationReceived : true,
        firstEventAtMs: base?.firstEventAtMs ?? completedAtMs,
        firstProgressAtMs: base?.firstProgressAtMs ?? completedAtMs,
        partialOutputAtMs: base?.partialOutputAtMs ?? (response.text.length > 0 ? completedAtMs : null),
        lastEventAtMs: base?.lastEventAtMs ?? completedAtMs,
        lastProgressAtMs: base?.lastProgressAtMs ?? completedAtMs,
        idleAtMs: base?.idleAtMs ?? null,
        finalizationAtMs: base?.finalizationAtMs ?? completedAtMs,
        finalContentLength: response.text.length,
        progressEventCount: base?.progressEventCount ?? (response.text.length > 0 || response.toolCalls.length > 0 || !!response.reasoning ? 1 : 0),
        attemptPhase: 'completed',
        completionSignal: base?.completionSignal ?? 'provider_response',
        livenessCategory: null,
        warningCategory: null,
        rawProviderError: null,
        finishReason: response.finishReason,
        toolCallCount: response.toolCalls.length,
        reasoningContentLength: response.reasoning?.length || 0,
        visibleContentLength: response.text.length,
    };
}

async function readResponseText(response: Response): Promise<string> {
    return response.text();
}

function buildHttpErrorMessage(status: number, rawBody: string, model: string): string {
    let parsed: any = null;
    try {
        parsed = JSON.parse(rawBody);
    } catch {
        parsed = null;
    }

    const errorMessage = parsed?.error?.message
        || parsed?.error
        || parsed?.message
        || rawBody
        || `HTTP ${status}`;

    if (status === 404) {
        return `Local LLM model '${model}' was not found on the server.`;
    }

    return `Local LLM returned HTTP ${status}: ${String(errorMessage).slice(0, 240)}`;
}

async function executeJsonRequest(
    url: string,
    body: Record<string, unknown>,
    signal: AbortSignal | undefined,
    startedAtMs: number,
): Promise<LocalOpenAiAdapterResult> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal,
    });

    const rawText = await readResponseText(response);
    if (!response.ok) {
        throw new Error(buildHttpErrorMessage(response.status, rawText, String(body.model || 'unknown')));
    }

    let parsed: any;
    try {
        parsed = JSON.parse(rawText);
    } catch {
        throw new Error('Local LLM returned an invalid JSON response.');
    }

    const normalized = normalizeOpenAiCompatibleChatResponse(parsed);
    return {
        text: normalized.text,
        reasoning: normalized.reasoning,
        toolCalls: normalized.toolCalls,
        finishReason: normalized.finishReason,
        usage: normalized.usage,
        resolvedModel: normalized.resolvedModel,
        diagnostics: buildCompletedDiagnostics(normalized, false, startedAtMs),
        responseSummary: buildResponseSummary(normalized, false),
    };
}

function updateToolCallsFromDelta(rawToolCalls: unknown, state: StreamParseState) {
    if (!Array.isArray(rawToolCalls)) {
        return false;
    }

    let sawProgress = false;
    for (const rawCall of rawToolCalls) {
        if (!rawCall || typeof rawCall !== 'object') {
            continue;
        }
        const call = rawCall as Record<string, any>;
        const index = typeof call.index === 'number' ? call.index : state.toolCalls.size;
        const existing = state.toolCalls.get(index) || {
            type: 'function' as const,
            function: {
                name: '',
                arguments: '',
            },
        };

        if (typeof call.id === 'string' && call.id) {
            existing.id = call.id;
        }
        if (typeof call.type === 'string' && call.type === 'function') {
            existing.type = 'function';
        }
        if (typeof call.function?.name === 'string' && call.function.name) {
            existing.function.name = call.function.name;
            sawProgress = true;
        }
        if (typeof call.function?.arguments === 'string') {
            existing.function.arguments += call.function.arguments;
            if (call.function.arguments.length > 0) {
                sawProgress = true;
            }
        }

        state.toolCalls.set(index, existing);
    }

    return sawProgress;
}

function parseStreamToolCalls(toolCalls: Map<number, MutableToolCall>): GenerationToolCall[] {
    return normalizeToolCalls(Array.from(toolCalls.values()).map((toolCall) => ({
        ...toolCall,
        function: {
            ...toolCall.function,
            arguments: toolCall.function.arguments,
        },
    })));
}

async function executeStreamRequest(
    url: string,
    body: Record<string, unknown>,
    signal: AbortSignal | undefined,
    startedAtMs: number,
): Promise<LocalOpenAiAdapterResult | null> {
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal,
    });

    if (!response.ok) {
        if (response.status === 400) {
            return null;
        }
        const rawText = await readResponseText(response);
        throw new Error(buildHttpErrorMessage(response.status, rawText, String(body.model || 'unknown')));
    }

    if (!response.body) {
        return null;
    }

    const state: StreamParseState = {
        content: '',
        reasoning: '',
        toolCalls: new Map<number, MutableToolCall>(),
        resolvedModel: null,
        finishReason: null,
        anyEventReceived: false,
        assistantMessageReceived: false,
        progressEventCount: 0,
        sawDone: false,
        firstEventAtMs: null,
        firstProgressAtMs: null,
        partialOutputAtMs: null,
        lastEventAtMs: null,
        lastProgressAtMs: null,
        idleAtMs: null,
        finalizationAtMs: null,
    };

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let rawAggregate = '';

    const noteEvent = () => {
        const current = nowMs(startedAtMs);
        state.anyEventReceived = true;
        state.lastEventAtMs = current;
        if (state.firstEventAtMs === null) {
            state.firstEventAtMs = current;
        }
    };

    const noteProgress = (partialOutput = false) => {
        const current = nowMs(startedAtMs);
        state.progressEventCount += 1;
        state.lastProgressAtMs = current;
        if (state.firstProgressAtMs === null) {
            state.firstProgressAtMs = current;
        }
        if (partialOutput && state.partialOutputAtMs === null) {
            state.partialOutputAtMs = current;
        }
    };

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                break;
            }

            const chunk = decoder.decode(value, { stream: true });
            rawAggregate += chunk;
            buffer += chunk;

            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop() || '';

            for (const eventBlock of events) {
                const dataLines = eventBlock
                    .split(/\r?\n/)
                    .filter((line) => line.startsWith('data:'))
                    .map((line) => line.slice(5).trimStart());
                if (dataLines.length === 0) {
                    continue;
                }

                const payload = dataLines.join('\n').trim();
                if (!payload) {
                    continue;
                }
                if (payload === '[DONE]') {
                    state.sawDone = true;
                    state.idleAtMs = nowMs(startedAtMs);
                    if (state.finalizationAtMs === null) {
                        state.finalizationAtMs = state.idleAtMs;
                    }
                    continue;
                }

                let parsed: any;
                try {
                    parsed = JSON.parse(payload);
                } catch {
                    continue;
                }

                noteEvent();
                if (typeof parsed.model === 'string') {
                    state.resolvedModel = parsed.model;
                }
                if (parsed.usage) {
                    state.usage = normalizeUsage(parsed.usage);
                }

                const choice = parsed.choices?.[0];
                const delta = choice?.delta || {};

                if (delta.role === 'assistant') {
                    state.assistantMessageReceived = true;
                }

                let sawProgress = false;

                const reasoningDelta = typeof delta.reasoning === 'string'
                    ? delta.reasoning
                    : (typeof delta.reasoning_content === 'string' ? delta.reasoning_content : '');
                if (reasoningDelta) {
                    state.reasoning += reasoningDelta;
                    sawProgress = true;
                }

                const contentDelta = extractVisibleContent(delta.content);
                if (contentDelta) {
                    state.content += contentDelta;
                    sawProgress = true;
                }

                if (updateToolCallsFromDelta(delta.tool_calls, state)) {
                    sawProgress = true;
                }

                const finishReason = normalizeFinishReason(choice?.finish_reason);
                if (finishReason) {
                    state.finishReason = finishReason;
                    state.finalizationAtMs = nowMs(startedAtMs);
                }

                if (sawProgress) {
                    noteProgress(contentDelta.length > 0);
                    state.assistantMessageReceived = true;
                }
            }
        }
    } finally {
        await reader.cancel().catch(() => undefined);
    }

    if (!state.anyEventReceived) {
        const trimmed = rawAggregate.trim();
        if (!trimmed) {
            return null;
        }

        let parsed: any;
        try {
            parsed = JSON.parse(trimmed);
        } catch {
            return null;
        }

        const normalized = normalizeOpenAiCompatibleChatResponse(parsed);
        return {
            text: normalized.text,
            reasoning: normalized.reasoning,
            toolCalls: normalized.toolCalls,
            finishReason: normalized.finishReason,
            usage: normalized.usage,
            resolvedModel: normalized.resolvedModel,
            diagnostics: buildCompletedDiagnostics(normalized, false, startedAtMs),
            responseSummary: buildResponseSummary(normalized, false),
        };
    }

    const normalized: NormalizedLocalResponse = {
        text: state.content,
        reasoning: state.reasoning || null,
        toolCalls: parseStreamToolCalls(state.toolCalls),
        finishReason: state.finishReason,
        usage: state.usage,
        resolvedModel: state.resolvedModel,
    };

    return {
        text: normalized.text,
        reasoning: normalized.reasoning,
        toolCalls: normalized.toolCalls,
        finishReason: normalized.finishReason,
        usage: normalized.usage,
        resolvedModel: normalized.resolvedModel,
        diagnostics: buildCompletedDiagnostics(normalized, true, startedAtMs, {
            streamingStarted: true,
            anyEventReceived: state.anyEventReceived,
            partialOutputReceived: state.content.length > 0,
            assistantMessageReceived: state.assistantMessageReceived,
            idleReceived: state.sawDone,
            finalizationReceived: !!(state.finishReason || state.sawDone),
            firstEventAtMs: state.firstEventAtMs,
            firstProgressAtMs: state.firstProgressAtMs,
            partialOutputAtMs: state.partialOutputAtMs,
            lastEventAtMs: state.lastEventAtMs,
            lastProgressAtMs: state.lastProgressAtMs,
            idleAtMs: state.idleAtMs,
            finalizationAtMs: state.finalizationAtMs,
            progressEventCount: state.progressEventCount,
            completionSignal: state.finishReason ? 'provider_response' : (state.sawDone ? 'session_idle' : null),
        }),
        responseSummary: buildResponseSummary(normalized, true),
    };
}

export async function callOpenAiCompatibleLocalModel(options: LocalOpenAiAdapterOptions): Promise<LocalOpenAiAdapterResult> {
    const url = `${options.baseUrl.replace(/\/$/, '')}/v1/chat/completions`;
    const timeoutSignal = options.timeoutMs && options.timeoutMs > 0
        ? AbortSignal.timeout(options.timeoutMs)
        : undefined;
    const signalBundle = combineAbortSignals([options.executionOptions?.signal, timeoutSignal]);
    const startedAtMs = Date.now();

    try {
        const streamBody = buildLocalOpenAiRequestBody(options.request, {
            configuredModel: options.configuredModel,
            defaultMaxTokens: options.defaultMaxTokens,
            temperature: options.temperature,
        }, { stream: true });

        const streamed = await executeStreamRequest(url, streamBody, signalBundle.signal, startedAtMs);
        if (streamed) {
            return streamed;
        }

        const jsonBody = buildLocalOpenAiRequestBody(options.request, {
            configuredModel: options.configuredModel,
            defaultMaxTokens: options.defaultMaxTokens,
            temperature: options.temperature,
        }, { stream: false });
        return executeJsonRequest(url, jsonBody, signalBundle.signal, startedAtMs);
    } catch (error: any) {
        if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
            throw new Error(`Local LLM request timed out connecting to ${options.baseUrl}. The server may be overloaded or unresponsive.`);
        }
        if (error?.cause?.code === 'ECONNREFUSED' || error?.code === 'ECONNREFUSED' || error?.code === 'ENOTFOUND') {
            throw new Error(`Local LLM endpoint unreachable at ${options.baseUrl}. Ensure the server is running and the host/port are correct.`);
        }
        throw error;
    } finally {
        signalBundle.cleanup();
    }
}
