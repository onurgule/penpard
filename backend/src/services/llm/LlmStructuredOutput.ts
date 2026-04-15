import type { ZodType } from 'zod';
import type { GenerationResponse, GenerationResponseFormat } from './LlmProviderTypes';

function stripMarkdownCodeFences(text: string): string {
    const match = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/i);
    return match ? match[1].trim() : text;
}

function parseJsonCandidate(candidate: string): any | null {
    const trimmed = candidate.trim();
    if (!trimmed) {
        return null;
    }

    const attempts = [trimmed];
    if (
        (trimmed.startsWith('"') && trimmed.endsWith('"'))
        || (trimmed.startsWith('\'') && trimmed.endsWith('\''))
    ) {
        attempts.push(trimmed.slice(1, -1));
    }

    for (const attempt of attempts) {
        try {
            return unwrapJsonEnvelope(JSON.parse(attempt));
        } catch {
            const repaired = attempt
                .replace(/,\s*([}\]])/g, '$1')
                .replace(/([{,]\s*)'([^']+?)'\s*:/g, '$1"$2":')
                .replace(/:\s*'([^']*?)'(?=\s*[,}])/g, ': "$1"');
            if (repaired === attempt) {
                continue;
            }
            try {
                return unwrapJsonEnvelope(JSON.parse(repaired));
            } catch {
                // Continue searching other candidates.
            }
        }
    }

    return null;
}

export function unwrapJsonEnvelope(value: any, depth = 0): any {
    if (depth > 5 || value === null || value === undefined) {
        return value;
    }

    if (typeof value === 'string') {
        const parsed = parseJsonCandidate(value);
        return parsed !== null ? unwrapJsonEnvelope(parsed, depth + 1) : value.trim();
    }

    if (Array.isArray(value)) {
        return value.map((entry) => unwrapJsonEnvelope(entry, depth + 1));
    }

    if (typeof value !== 'object') {
        return value;
    }

    const obj = value as Record<string, any>;

    if (Array.isArray(obj.choices) && obj.choices[0]?.message) {
        return unwrapJsonEnvelope(obj.choices[0].message, depth + 1);
    }

    if (obj.message) {
        return unwrapJsonEnvelope(obj.message, depth + 1);
    }

    if (Array.isArray(obj.tool_calls) && obj.tool_calls[0]?.function) {
        return unwrapJsonEnvelope(obj.tool_calls[0].function, depth + 1);
    }

    if (obj.name === 'AgentOutput' && obj.arguments !== undefined) {
        return unwrapJsonEnvelope(obj.arguments, depth + 1);
    }

    if (obj.type === 'function' && obj.function) {
        return unwrapJsonEnvelope(obj.function, depth + 1);
    }

    if (obj.arguments !== undefined && !obj.action && !obj.actions) {
        const parsedArgs = unwrapJsonEnvelope(obj.arguments, depth + 1);
        if (parsedArgs && typeof parsedArgs === 'object' && !Array.isArray(parsedArgs)) {
            return { ...obj, ...parsedArgs };
        }
    }

    if (
        typeof obj.content === 'string'
        && !obj.action
        && !obj.actions
        && !obj.tool
        && !obj.name
    ) {
        const parsedContent = extractStructuredJsonValue(obj.content);
        if (parsedContent !== null) {
            return unwrapJsonEnvelope(parsedContent, depth + 1);
        }
    }

    return obj;
}

export function extractStructuredJsonValue(text: string): any | null {
    const cleaned = stripMarkdownCodeFences(text).trim();
    if (!cleaned) {
        return null;
    }

    const direct = parseJsonCandidate(cleaned);
    if (direct !== null) {
        return direct;
    }

    for (let start = 0; start < cleaned.length; start += 1) {
        const opener = cleaned[start];
        if (opener !== '{' && opener !== '[') {
            continue;
        }

        const stack: string[] = [];
        let inString = false;
        let escaped = false;

        for (let end = start; end < cleaned.length; end += 1) {
            const char = cleaned[end];

            if (escaped) {
                escaped = false;
                continue;
            }
            if (char === '\\') {
                escaped = true;
                continue;
            }
            if (char === '"' && !escaped) {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }

            if (char === '{' || char === '[') {
                stack.push(char);
                continue;
            }

            if (char === '}' || char === ']') {
                const expected = char === '}' ? '{' : '[';
                if (stack[stack.length - 1] !== expected) {
                    break;
                }
                stack.pop();
                if (stack.length === 0) {
                    const candidate = parseJsonCandidate(cleaned.slice(start, end + 1));
                    if (candidate !== null) {
                        return candidate;
                    }
                    break;
                }
            }
        }
    }

    return null;
}

export class StructuredOutputError extends Error {
    public readonly finishReason: string | null;

    constructor(message: string, finishReason: string | null = null) {
        super(message);
        this.name = 'StructuredOutputError';
        this.finishReason = finishReason;
    }
}

interface ParseStructuredJsonOptions<T> {
    label?: string;
    schema?: ZodType<T>;
}

export function parseStructuredJsonResponse<T>(
    response: Pick<GenerationResponse, 'text' | 'finishReason'>,
    options: ParseStructuredJsonOptions<T> = {},
): T {
    const label = options.label || 'Structured output';
    const trimmed = response.text.trim();

    if (!trimmed) {
        if (response.finishReason === 'length') {
            throw new StructuredOutputError(
                `${label} was truncated before any visible JSON was emitted.`,
                response.finishReason,
            );
        }
        throw new StructuredOutputError(`${label} was empty.`, response.finishReason || null);
    }

    const extracted = extractStructuredJsonValue(trimmed);
    if (extracted === null) {
        if (response.finishReason === 'length') {
            throw new StructuredOutputError(
                `${label} was truncated before a valid JSON payload could be parsed.`,
                response.finishReason,
            );
        }
        throw new StructuredOutputError(`${label} did not contain valid JSON.`, response.finishReason || null);
    }

    if (options.schema) {
        return options.schema.parse(extracted);
    }

    return extracted as T;
}

export function buildJsonObjectResponseFormat(): GenerationResponseFormat {
    return { type: 'json_object' };
}

export function buildJsonSchemaResponseFormat(name: string, schema: unknown): GenerationResponseFormat {
    return {
        type: 'json_schema',
        json_schema: {
            name,
            schema,
        },
    };
}
