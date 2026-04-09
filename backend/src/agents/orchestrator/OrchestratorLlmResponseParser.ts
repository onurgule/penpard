import { AgentReflection, LLMResponse, ToolCall } from './types';
import type { OrchestratorToolRegistry } from './OrchestratorToolRegistry';

type LogFn = (channel: 'debug' | 'error', message: string) => void;

export class OrchestratorLlmResponseParser {
    constructor(
        private readonly targetUrl: string,
        private readonly isFocusedScope: () => boolean,
        private readonly toolRegistry: Pick<OrchestratorToolRegistry, 'isKnown' | 'normalizeToolCall'>,
        private readonly log?: LogFn,
    ) {}

    public parseAgentResponse(text: string): LLMResponse | null {
        this.log?.('debug', `LLM Response: ${text.substring(0, 300)}...`);

        try {
            const jsonObj = this.extractJsonObject(text);
            if (jsonObj) {
                const normalized = this.normalizeResponse(jsonObj);
                if (normalized) return normalized;
            }

            const urlMatch = text.match(/https?:\/\/[^\s"'<>]+/);
            if (urlMatch) {
                const methodMatch = text.match(/\b(GET|POST|PUT|DELETE|PATCH)\b/i);
                return {
                    thought: text.substring(0, 150),
                    action: {
                        tool: 'send_http_request',
                        args: {
                            url: urlMatch[0],
                            method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
                        },
                    },
                };
            }

            if (!this.isFocusedScope()) {
                const lower = text.toLowerCase();
                if (lower.includes('proxy history') || lower.includes('get_proxy_history')) {
                    return {
                        thought: text.substring(0, 150),
                        action: { tool: 'get_proxy_history', args: { count: 20, excludePenPard: true } },
                    };
                }

                if (lower.includes('sitemap') || lower.includes('get_sitemap')) {
                    return { thought: text.substring(0, 150), action: { tool: 'get_sitemap', args: {} } };
                }

                if (lower.includes('spider') || lower.includes('crawl')) {
                    return {
                        thought: text.substring(0, 150),
                        action: { tool: 'spider_url', args: { url: this.targetUrl } },
                    };
                }
            }

            return { thought: text.substring(0, 500) };
        } catch (error: any) {
            this.log?.('error', `Parse error: ${error.message}`);
            return { thought: text.substring(0, 500) };
        }
    }

    public extractJsonObject(text: string): any | null {
        const cleaned = this.stripMarkdownCodeFences(text).trim();
        if (!cleaned) return null;

        const direct = this.parseJsonCandidate(cleaned);
        if (direct !== null) {
            return direct;
        }

        for (let start = 0; start < cleaned.length; start++) {
            const opener = cleaned[start];
            if (opener !== '{' && opener !== '[') continue;

            const stack: string[] = [];
            let inString = false;
            let escaped = false;

            for (let end = start; end < cleaned.length; end++) {
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
                if (inString) continue;

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
                        const candidate = this.parseJsonCandidate(cleaned.substring(start, end + 1));
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

    private stripMarkdownCodeFences(text: string): string {
        const match = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/i);
        return match ? match[1].trim() : text;
    }

    private parseJsonCandidate(candidate: string): any | null {
        const trimmed = candidate.trim();
        if (!trimmed) return null;

        const attempts = [trimmed];
        if (
            (trimmed.startsWith('"') && trimmed.endsWith('"'))
            || (trimmed.startsWith('\'') && trimmed.endsWith('\''))
        ) {
            attempts.push(trimmed.substring(1, trimmed.length - 1));
        }

        for (const attempt of attempts) {
            try {
                return this.unwrapJsonValue(JSON.parse(attempt));
            } catch {
                const repaired = attempt
                    .replace(/,\s*([}\]])/g, '$1')
                    .replace(/([{,]\s*)'([^']+?)'\s*:/g, '$1"$2":')
                    .replace(/:\s*'([^']*?)'(?=\s*[,}])/g, ': "$1"');
                if (repaired !== attempt) {
                    try {
                        return this.unwrapJsonValue(JSON.parse(repaired));
                    } catch {
                        // Ignore and keep searching.
                    }
                }
            }
        }

        return null;
    }

    private unwrapJsonValue(value: any, depth: number = 0): any {
        if (depth > 5 || value === null || value === undefined) {
            return value;
        }

        if (typeof value === 'string') {
            const parsed = this.parseJsonCandidate(value);
            return parsed !== null ? this.unwrapJsonValue(parsed, depth + 1) : value.trim();
        }

        if (Array.isArray(value)) {
            return value.map((entry) => this.unwrapJsonValue(entry, depth + 1));
        }

        if (typeof value !== 'object') {
            return value;
        }

        const obj = value as Record<string, any>;

        if (Array.isArray(obj.choices) && obj.choices[0]?.message) {
            return this.unwrapJsonValue(obj.choices[0].message, depth + 1);
        }

        if (obj.message) {
            return this.unwrapJsonValue(obj.message, depth + 1);
        }

        if (Array.isArray(obj.tool_calls) && obj.tool_calls[0]?.function) {
            return this.unwrapJsonValue(obj.tool_calls[0].function, depth + 1);
        }

        if (obj.name === 'AgentOutput' && obj.arguments !== undefined) {
            return this.unwrapJsonValue(obj.arguments, depth + 1);
        }

        if (obj.type === 'function' && obj.function) {
            return this.unwrapJsonValue(obj.function, depth + 1);
        }

        if (obj.function?.name && obj.function?.arguments !== undefined) {
            const functionName = String(obj.function.name);
            const args = this.unwrapJsonValue(obj.function.arguments, depth + 1);
            if (this.toolRegistry.isKnown(functionName)) {
                return { ...obj, action: { tool: functionName, args } };
            }
            if (functionName === 'AgentOutput') {
                return this.unwrapJsonValue(args, depth + 1);
            }
        }

        if (
            typeof obj.content === 'string'
            && !obj.action
            && !obj.actions
            && !obj.tool
            && !obj.name
        ) {
            const parsedContent = this.extractJsonObject(obj.content);
            if (parsedContent !== null) {
                return this.unwrapJsonValue(parsedContent, depth + 1);
            }
        }

        if (obj.name && obj.arguments !== undefined && this.toolRegistry.isKnown(String(obj.name))) {
            return {
                ...obj,
                action: {
                    tool: String(obj.name),
                    args: this.unwrapJsonValue(obj.arguments, depth + 1),
                },
            };
        }

        if (obj.arguments !== undefined && !obj.action && !obj.actions) {
            const parsedArgs = this.unwrapJsonValue(obj.arguments, depth + 1);
            if (parsedArgs && typeof parsedArgs === 'object' && !Array.isArray(parsedArgs)) {
                return { ...obj, ...parsedArgs };
            }
        }

        return obj;
    }

    private normalizeResponse(obj: any): LLMResponse | null {
        const resolved = this.unwrapJsonValue(obj);
        if (!resolved) return null;

        const result: LLMResponse = { thought: '' };

        const addAction = (action: ToolCall | null) => {
            if (!action) return;
            if (!result.action) {
                result.action = action;
                return;
            }
            result.actions = result.actions || [result.action];
            result.actions.push(action);
            delete result.action;
        };

        if (Array.isArray(resolved)) {
            for (const entry of resolved) {
                addAction(this.toolRegistry.normalizeToolCall(entry, (value) => this.unwrapJsonValue(value)));
            }
            return result.action || result.actions?.length ? result : null;
        }

        if (typeof resolved !== 'object') {
            return null;
        }

        const source = resolved as Record<string, any>;
        const reflection = this.extractReflection(source);

        result.thought = this.firstString(
            source.thought,
            source.thinking,
            source.purpose,
            source.reasoning,
            source.analysis,
            source.rationale,
        ) || '';

        if (reflection) {
            result.reflection = reflection;
        }

        if (source.finding) result.finding = source.finding;
        if (Array.isArray(source.findings)) result.findings = source.findings;
        else if (source.findings && typeof source.findings === 'object') result.findings = [source.findings];

        result.answer = this.firstString(source.answer, source.final_answer, source.summary, source.result);

        if (source.action !== undefined) {
            addAction(this.toolRegistry.normalizeToolCall(source.action, (value) => this.unwrapJsonValue(value), source));
        }

        if (Array.isArray(source.actions)) {
            for (const action of source.actions) {
                addAction(this.toolRegistry.normalizeToolCall(action, (value) => this.unwrapJsonValue(value), source));
            }
        }

        if (!result.action && !result.actions?.length) {
            addAction(this.toolRegistry.normalizeToolCall(source, (value) => this.unwrapJsonValue(value)));
        }

        if (result.actions?.length === 1) {
            result.action = result.actions[0];
            delete result.actions;
        }

        if (
            result.thought
            || result.reflection
            || result.action
            || result.actions?.length
            || result.answer
            || result.finding
            || result.findings?.length
        ) {
            return result;
        }

        return null;
    }

    private extractReflection(obj: Record<string, any>): AgentReflection | undefined {
        const reflectionSource = (obj.reflection && typeof obj.reflection === 'object')
            ? obj.reflection as Record<string, any>
            : obj;

        const reflection: AgentReflection = {
            evaluationPreviousGoal: this.firstString(
                reflectionSource.evaluation_previous_goal,
                reflectionSource.evaluationPreviousGoal,
                reflectionSource.evaluation,
                reflectionSource.previous_goal,
            ),
            memory: this.firstString(
                reflectionSource.memory,
                reflectionSource.remember,
                reflectionSource.notes,
            ),
            nextGoal: this.firstString(
                reflectionSource.next_goal,
                reflectionSource.nextGoal,
                reflectionSource.goal,
                reflectionSource.plan,
            ),
        };

        return reflection.evaluationPreviousGoal || reflection.memory || reflection.nextGoal
            ? reflection
            : undefined;
    }

    private firstString(...values: unknown[]): string | undefined {
        for (const value of values) {
            if (typeof value === 'string' && value.trim()) {
                return value.trim();
            }
        }
        return undefined;
    }
}
