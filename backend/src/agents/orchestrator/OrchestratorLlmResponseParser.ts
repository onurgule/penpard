import { AgentReflection, LLMResponse, ToolCall } from './types';

type LogFn = (channel: 'debug' | 'error', message: string) => void;

const KNOWN_TOOL_NAMES = new Set([
    'send_http_request',
    'send_to_scanner',
    'get_proxy_history',
    'get_session_cookies',
    'get_cookies_and_auth_for_host',
    'get_sitemap',
    'spider_url',
    'check_authorization',
    'generate_payloads',
    'extract_links',
    'analyze_response',
    'browser_navigate',
    'browser_get_page_state',
    'browser_get_frontend_analysis',
    'browser_fill_and_submit',
    'browser_evaluate_js',
    'browser_screenshot',
    'browser_correlate_burp',
    'harvest_traffic',
    'get_hypotheses',
    'get_coverage',
    'repeater_test',
]);

export class OrchestratorLlmResponseParser {
    constructor(
        private readonly targetUrl: string,
        private readonly isFocusedScope: () => boolean,
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
            if (this.isKnownToolName(functionName)) {
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

        if (obj.name && obj.arguments !== undefined && this.isKnownToolName(String(obj.name))) {
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
                addAction(this.normalizeToolCall(entry));
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
            addAction(this.normalizeToolCall(source.action, source));
        }

        if (Array.isArray(source.actions)) {
            for (const action of source.actions) {
                addAction(this.normalizeToolCall(action, source));
            }
        }

        if (!result.action && !result.actions?.length) {
            addAction(this.normalizeToolCall(source));
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

    private normalizeToolCall(rawAction: any, context?: Record<string, any>): ToolCall | null {
        const action = this.unwrapJsonValue(rawAction);

        if (typeof action === 'string') {
            const tool = this.canonicalizeToolName(action);
            if (!this.isKnownToolName(tool)) return null;
            return {
                tool,
                args: this.coerceToolArgs(
                    tool,
                    context?.args ?? context?.parameters ?? context?.params ?? context?.input ?? context?.arguments ?? context ?? {},
                ),
            };
        }

        if (action === null || action === undefined) {
            return null;
        }

        if (typeof action !== 'object') {
            return null;
        }

        const actionObj = action as Record<string, any>;
        const explicitToolName = this.firstString(actionObj.tool, actionObj.name);
        if (explicitToolName) {
            const tool = this.canonicalizeToolName(explicitToolName);
            if (!this.isKnownToolName(tool)) return null;
            return {
                tool,
                args: this.coerceToolArgs(
                    tool,
                    actionObj.args ?? actionObj.arguments ?? actionObj.parameters ?? actionObj.params ?? actionObj.input ?? actionObj.tool_input ?? actionObj,
                    context,
                ),
            };
        }

        const entries = Object.entries(actionObj);
        if (entries.length === 1) {
            const [toolName, toolArgs] = entries[0];
            const tool = this.canonicalizeToolName(toolName);
            if (this.isKnownToolName(tool)) {
                return { tool, args: this.coerceToolArgs(tool, toolArgs, context) };
            }
        }

        if (actionObj.url || actionObj.target || actionObj.endpoint || actionObj.href) {
            return {
                tool: 'send_http_request',
                args: this.coerceToolArgs('send_http_request', actionObj, context),
            };
        }

        return null;
    }

    private coerceToolArgs(tool: string, rawArgs: any, context?: Record<string, any>): Record<string, any> {
        const args = this.unwrapJsonValue(
            rawArgs !== undefined
                ? rawArgs
                : context?.args ?? context?.arguments ?? context?.parameters ?? context?.params ?? context?.input ?? context?.tool_input,
        );

        if (args === null || args === undefined || args === '') {
            return tool === 'get_proxy_history' ? { count: 20, excludePenPard: true } : {};
        }

        if (typeof args === 'string') {
            const trimmed = args.trim();
            switch (tool) {
                case 'send_http_request':
                case 'send_to_scanner':
                case 'spider_url':
                case 'extract_links':
                case 'browser_navigate':
                    return { url: trimmed, method: tool === 'send_http_request' ? 'GET' : undefined };
                case 'browser_evaluate_js':
                    return { script: trimmed };
                case 'get_session_cookies':
                case 'get_cookies_and_auth_for_host':
                    return { host: trimmed };
                case 'get_proxy_history': {
                    const parsedCount = Number(trimmed);
                    return {
                        count: Number.isFinite(parsedCount) && parsedCount > 0 ? parsedCount : 20,
                        excludePenPard: true,
                    };
                }
                case 'repeater_test':
                    return { requestId: trimmed };
                default:
                    return {};
            }
        }

        if (typeof args === 'number') {
            if (tool === 'get_proxy_history') {
                return { count: args, excludePenPard: true };
            }
            return {};
        }

        if (Array.isArray(args)) {
            if (tool === 'browser_fill_and_submit') {
                return { fields: args };
            }
            return {};
        }

        if (typeof args !== 'object') {
            return {};
        }

        const normalized = { ...(args as Record<string, any>) };

        if (tool === 'send_http_request') {
            normalized.url = normalized.url || normalized.target || normalized.endpoint || normalized.href;
            normalized.method = String(normalized.method || 'GET').toUpperCase();
            normalized.headers = normalized.headers && typeof normalized.headers === 'object' ? normalized.headers : {};
            if (normalized.body === undefined && normalized.data !== undefined) {
                normalized.body = normalized.data;
            }
            if (normalized.body === undefined) {
                normalized.body = '';
            }
            return normalized;
        }

        if (tool === 'get_proxy_history') {
            return {
                ...normalized,
                count: normalized.count || 20,
                excludePenPard: normalized.excludePenPard ?? true,
            };
        }

        if (tool === 'browser_fill_and_submit' && normalized.submitSelector && normalized.submit_selector === undefined) {
            normalized.submit_selector = normalized.submitSelector;
        }

        if (tool === 'send_to_scanner' || tool === 'spider_url' || tool === 'extract_links' || tool === 'browser_navigate') {
            normalized.url = normalized.url || normalized.target || normalized.endpoint || normalized.href;
        }

        if (tool === 'browser_evaluate_js' && normalized.script === undefined && typeof normalized.code === 'string') {
            normalized.script = normalized.code;
        }

        if ((tool === 'get_session_cookies' || tool === 'get_cookies_and_auth_for_host') && normalized.host === undefined && typeof normalized.url === 'string') {
            try {
                normalized.host = new URL(normalized.url).hostname;
            } catch {
                normalized.host = normalized.url;
            }
        }

        return normalized;
    }

    private canonicalizeToolName(toolName: string): string {
        const normalized = toolName
            .trim()
            .replace(/^tools?\./i, '')
            .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
            .replace(/[\s-]+/g, '_')
            .toLowerCase();

        const aliases: Record<string, string> = {
            sendhttprequest: 'send_http_request',
            send_http_request: 'send_http_request',
            send_to_scanner: 'send_to_scanner',
            sendtoscanner: 'send_to_scanner',
            getproxyhistory: 'get_proxy_history',
            get_proxy_history: 'get_proxy_history',
            getsessioncookies: 'get_session_cookies',
            get_session_cookie: 'get_session_cookies',
            get_session_cookies: 'get_session_cookies',
            getcookiesandauthforhost: 'get_cookies_and_auth_for_host',
            get_cookies_and_auth_for_host: 'get_cookies_and_auth_for_host',
            getsitemap: 'get_sitemap',
            get_sitemap: 'get_sitemap',
            spiderurl: 'spider_url',
            spider_url: 'spider_url',
            checkauthorization: 'check_authorization',
            check_authorization: 'check_authorization',
            generatepayloads: 'generate_payloads',
            generate_payloads: 'generate_payloads',
            extractlinks: 'extract_links',
            extract_links: 'extract_links',
            browsernavigate: 'browser_navigate',
            browser_navigate: 'browser_navigate',
            browsergetpagestate: 'browser_get_page_state',
            browser_get_page_state: 'browser_get_page_state',
            browser_page_state: 'browser_get_page_state',
            browser_get_state: 'browser_get_page_state',
            browsergetfrontendanalysis: 'browser_get_frontend_analysis',
            browser_get_frontend_analysis: 'browser_get_frontend_analysis',
            browser_frontend_analysis: 'browser_get_frontend_analysis',
            browserfillandsubmit: 'browser_fill_and_submit',
            browser_fill_and_submit: 'browser_fill_and_submit',
            browser_fill_submit: 'browser_fill_and_submit',
            browserevaluatejs: 'browser_evaluate_js',
            browser_evaluate_js: 'browser_evaluate_js',
            browserscreenshot: 'browser_screenshot',
            browser_screenshot: 'browser_screenshot',
            browsercorrelateburp: 'browser_correlate_burp',
            browser_correlate_burp: 'browser_correlate_burp',
            harvesttraffic: 'harvest_traffic',
            harvest_traffic: 'harvest_traffic',
            gethypotheses: 'get_hypotheses',
            get_hypotheses: 'get_hypotheses',
            getcoverage: 'get_coverage',
            get_coverage: 'get_coverage',
            repeatertest: 'repeater_test',
            repeater_test: 'repeater_test',
        };

        return aliases[normalized] || aliases[normalized.replace(/_/g, '')] || normalized;
    }

    private isKnownToolName(toolName: string): boolean {
        return KNOWN_TOOL_NAMES.has(this.canonicalizeToolName(toolName));
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
