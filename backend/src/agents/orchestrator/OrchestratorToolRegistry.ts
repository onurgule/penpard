import { KnownToolName, ToolCall } from './types';

type ToolHandler = (toolCall: ToolCall) => Promise<any>;
type JsonUnwrapper = (value: any) => any;

interface ToolSpec {
    name: string;
    aliases: string[];
    normalizeArgs: (tool: string, args: any, unwrapJsonValue: JsonUnwrapper, context?: Record<string, any>) => Record<string, any>;
}

interface OrchestratorToolRegistryOptions {
    handlers: Record<string, ToolHandler>;
}

function unwrapArgsSource(rawArgs: any, context?: Record<string, any>): any {
    if (rawArgs !== undefined) {
        return rawArgs;
    }
    return context?.args
        ?? context?.arguments
        ?? context?.parameters
        ?? context?.params
        ?? context?.input
        ?? context?.tool_input;
}

function normalizeUrlLikeArgs(tool: string, value: string): Record<string, any> {
    if (tool === 'send_http_request') {
        return {
            url: value,
            method: 'GET',
        };
    }

    return { url: value };
}

function normalizeDefaultArgs(tool: string, rawArgs: any, unwrapJsonValue: JsonUnwrapper, context?: Record<string, any>): Record<string, any> {
    const args = unwrapJsonValue(unwrapArgsSource(rawArgs, context));

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
                return normalizeUrlLikeArgs(tool, trimmed);
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

const TOOL_SPECS: ToolSpec[] = [
    { name: 'send_http_request', aliases: ['sendhttprequest'], normalizeArgs: normalizeDefaultArgs },
    { name: 'send_to_scanner', aliases: ['sendtoscanner'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_proxy_history', aliases: ['getproxyhistory'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_session_cookies', aliases: ['getsessioncookies', 'get_session_cookie'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_cookies_and_auth_for_host', aliases: ['getcookiesandauthforhost'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_sitemap', aliases: ['getsitemap'], normalizeArgs: normalizeDefaultArgs },
    { name: 'spider_url', aliases: ['spiderurl'], normalizeArgs: normalizeDefaultArgs },
    { name: 'check_authorization', aliases: ['checkauthorization'], normalizeArgs: normalizeDefaultArgs },
    { name: 'generate_payloads', aliases: ['generatepayloads'], normalizeArgs: normalizeDefaultArgs },
    { name: 'extract_links', aliases: ['extractlinks'], normalizeArgs: normalizeDefaultArgs },
    { name: 'analyze_response', aliases: ['analyzeresponse'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_navigate', aliases: ['browsernavigate'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_get_page_state', aliases: ['browsergetpagestate', 'browser_page_state', 'browser_get_state'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_get_frontend_analysis', aliases: ['browsergetfrontendanalysis', 'browser_frontend_analysis'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_fill_and_submit', aliases: ['browserfillandsubmit', 'browser_fill_submit'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_evaluate_js', aliases: ['browserevaluatejs'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_screenshot', aliases: ['browserscreenshot'], normalizeArgs: normalizeDefaultArgs },
    { name: 'browser_correlate_burp', aliases: ['browsercorrelateburp'], normalizeArgs: normalizeDefaultArgs },
    { name: 'harvest_traffic', aliases: ['harvesttraffic'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_hypotheses', aliases: ['gethypotheses'], normalizeArgs: normalizeDefaultArgs },
    { name: 'get_coverage', aliases: ['getcoverage'], normalizeArgs: normalizeDefaultArgs },
    { name: 'repeater_test', aliases: ['repeatertest'], normalizeArgs: normalizeDefaultArgs },
    { name: 'none', aliases: [], normalizeArgs: normalizeDefaultArgs },
];

export class OrchestratorToolRegistry {
    private readonly specsByName = new Map<string, ToolSpec>();
    private readonly aliases = new Map<string, string>();

    constructor(private readonly options: OrchestratorToolRegistryOptions) {
        for (const spec of TOOL_SPECS) {
            this.specsByName.set(spec.name, spec);
            this.aliases.set(spec.name, spec.name);
            this.aliases.set(spec.name.replace(/_/g, ''), spec.name);
            for (const alias of spec.aliases) {
                this.aliases.set(alias, spec.name);
                this.aliases.set(alias.replace(/_/g, ''), spec.name);
            }
        }
    }

    public getHandlers(): Record<string, ToolHandler> {
        return this.options.handlers;
    }

    public listToolNames(): string[] {
        return Array.from(this.specsByName.keys());
    }

    public canonicalize(toolName: string): string {
        const normalized = String(toolName || '')
            .trim()
            .replace(/^tools?\./i, '')
            .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
            .replace(/[\s-]+/g, '_')
            .toLowerCase();

        return this.aliases.get(normalized) || this.aliases.get(normalized.replace(/_/g, '')) || normalized;
    }

    public isKnown(toolName: string): boolean {
        return this.specsByName.has(this.canonicalize(toolName));
    }

    public coerceArgs(
        toolName: string,
        rawArgs: any,
        unwrapJsonValue: JsonUnwrapper,
        context?: Record<string, any>,
    ): Record<string, any> {
        const canonical = this.canonicalize(toolName);
        const spec = this.specsByName.get(canonical);
        if (!spec) {
            return {};
        }
        return spec.normalizeArgs(canonical, rawArgs, unwrapJsonValue, context);
    }

    public normalizeToolCall(
        rawAction: any,
        unwrapJsonValue: JsonUnwrapper,
        context?: Record<string, any>,
    ): ToolCall | null {
        const action = unwrapJsonValue(rawAction);

        if (typeof action === 'string') {
            const tool = this.canonicalize(action) as KnownToolName;
            if (!this.isKnown(tool)) return null;
            return {
                tool,
                args: this.coerceArgs(tool, context?.args ?? context?.parameters ?? context?.params ?? context?.input ?? context?.arguments ?? context ?? {}, unwrapJsonValue),
            };
        }

        if (action === null || action === undefined || typeof action !== 'object') {
            return null;
        }

        const actionObj = action as Record<string, any>;
        const explicitToolName = firstString(actionObj.tool, actionObj.name);
        if (explicitToolName) {
            const tool = this.canonicalize(explicitToolName) as KnownToolName;
            if (!this.isKnown(tool)) return null;
            return {
                tool,
                args: this.coerceArgs(
                    tool,
                    actionObj.args ?? actionObj.arguments ?? actionObj.parameters ?? actionObj.params ?? actionObj.input ?? actionObj.tool_input ?? actionObj,
                    unwrapJsonValue,
                    context,
                ),
            };
        }

        const entries = Object.entries(actionObj);
        if (entries.length === 1) {
            const [toolName, toolArgs] = entries[0];
            const tool = this.canonicalize(toolName) as KnownToolName;
            if (this.isKnown(tool)) {
                return {
                    tool,
                    args: this.coerceArgs(tool, toolArgs, unwrapJsonValue, context),
                };
            }
        }

        if (actionObj.url || actionObj.target || actionObj.endpoint || actionObj.href) {
            return {
                tool: 'send_http_request',
                args: this.coerceArgs('send_http_request', actionObj, unwrapJsonValue, context),
            };
        }

        return null;
    }
}

function firstString(...values: unknown[]): string | undefined {
    for (const value of values) {
        if (typeof value === 'string' && value.trim()) {
            return value.trim();
        }
    }
    return undefined;
}
