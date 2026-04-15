export interface GenerationImage {
    data: string;
    mimeType: string;
}

export interface GenerationToolDefinition {
    type: 'function';
    function: {
        name: string;
        description?: string;
        parameters?: unknown;
    };
}

export type GenerationToolChoice =
    | 'auto'
    | 'none'
    | {
        type: 'function';
        function: {
            name: string;
        };
    };

export type GenerationReasoningMode = 'provider_default' | 'disabled' | 'capture';

export type GenerationResponseFormat =
    | {
        type: 'json_object';
    }
    | {
        type: 'json_schema';
        json_schema: {
            name: string;
            schema: unknown;
        };
    };

export interface GenerationToolCall {
    id?: string;
    type: 'function';
    function: {
        name: string;
        arguments: string;
        parsedArguments?: unknown;
    };
}

export type GenerationMessageContent =
    | string
    | Array<
        | string
        | {
            type?: string;
            text?: string;
            [key: string]: unknown;
        }
    >
    | null;

export interface GenerationMessage {
    role: 'system' | 'user' | 'assistant' | 'tool';
    content?: GenerationMessageContent;
    name?: string;
    tool_calls?: GenerationToolCall[];
    tool_call_id?: string;
}

export interface NormalizedUsage {
    input_tokens: number;
    output_tokens: number;
    total_tokens?: number;
    reasoning_tokens?: number;
}

export interface GenerationRequest {
    systemPrompt?: string;
    userPrompt?: string;
    messages?: GenerationMessage[];
    images?: GenerationImage[];
    temperature?: number;
    maxTokens?: number;
    responseFormat?: GenerationResponseFormat;
    tools?: GenerationToolDefinition[];
    toolChoice?: GenerationToolChoice;
    reasoningMode?: GenerationReasoningMode;
}

export interface GenerationResponse {
    text: string;
    reasoning?: string | null;
    toolCalls?: GenerationToolCall[];
    finishReason?: string | null;
    usage?: NormalizedUsage;
}
