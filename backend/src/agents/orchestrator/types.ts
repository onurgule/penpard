export type SendHttpRequestArgs = Record<string, any> & {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    body?: unknown;
    useInitialRequestBaseline?: boolean;
    queryMutations?: Array<{ name?: string; value?: string | number | boolean | null }>;
    bodyMutations?: Array<{ name?: string; value?: string | number | boolean | null }>;
};

export type UrlToolArgs = Record<string, any> & {
    url: string;
};

export type ProxyHistoryArgs = Record<string, any> & {
    count?: number;
    excludePenPard?: boolean;
};

export type SessionCookieArgs = Record<string, any> & {
    host?: string;
    url?: string;
};

export type BrowserFillField = {
    selector?: string;
    value?: string;
};

export type BrowserFillAndSubmitArgs = Record<string, any> & {
    fields?: BrowserFillField[];
    submit_selector?: string;
};

export type BrowserEvaluateArgs = Record<string, any> & {
    script?: string;
};

export type GetHypothesesArgs = Record<string, any> & {
    status?: string;
};

export type RepeaterTestArgs = Record<string, any> & {
    requestId?: string;
    mutations?: any[];
};

export interface ToolArgsByName {
    send_http_request: SendHttpRequestArgs;
    send_to_scanner: UrlToolArgs;
    get_proxy_history: ProxyHistoryArgs;
    get_session_cookies: SessionCookieArgs;
    get_cookies_and_auth_for_host: SessionCookieArgs;
    get_sitemap: Record<string, any>;
    spider_url: UrlToolArgs;
    check_authorization: Record<string, any>;
    generate_payloads: Record<string, any>;
    extract_links: UrlToolArgs;
    analyze_response: Record<string, any>;
    browser_navigate: UrlToolArgs;
    browser_get_page_state: Record<string, any>;
    browser_get_frontend_analysis: Record<string, any>;
    browser_fill_and_submit: BrowserFillAndSubmitArgs;
    browser_evaluate_js: BrowserEvaluateArgs;
    browser_screenshot: Record<string, any>;
    browser_correlate_burp: Record<string, any>;
    harvest_traffic: Record<string, any>;
    get_hypotheses: GetHypothesesArgs;
    get_coverage: Record<string, any>;
    repeater_test: RepeaterTestArgs;
    none: Record<string, any>;
}

export type KnownToolName = keyof ToolArgsByName;

export interface ToolCall<TTool extends KnownToolName = KnownToolName> {
    tool: TTool;
    args: ToolArgsByName[TTool];
}

export interface RequestExecutionExchange {
    action?: ToolCall;
    result?: any;
    rawRequest?: string;
    rawResponse?: string;
}

export type AgentPhase =
    | 'planning'
    | 'executing'
    | 'replanning'
    | 'reporting'
    | 'completed'
    | 'failed'
    | 'stopped';

export interface ConversationMessage {
    role: string;
    content: string;
}

export interface PlanStep {
    step: number;
    objective: string;
    approach: string;
    tools: string[];
    status: 'pending' | 'executing' | 'completed' | 'skipped';
    result?: string;
}

export interface AttackPlan {
    round: number;
    analysis: string;
    steps: PlanStep[];
}

export interface AgentReflection {
    evaluationPreviousGoal?: string;
    memory?: string;
    nextGoal?: string;
}

export interface LLMResponse {
    thought: string;
    reflection?: AgentReflection;
    action?: ToolCall;
    actions?: ToolCall[];
    answer?: string;
    finding?: any;
    findings?: any[];
}

export interface InstructionAnalysis {
    is_focused: boolean;
    focused_endpoints: string[];
    focused_vulns: string[];
    skip_recon: boolean;
    auto_finish: boolean;
    summary: string;
}

export interface StepExecutionResult {
    step: PlanStep;
    findings: any[];
    toolResults: string[];
}
