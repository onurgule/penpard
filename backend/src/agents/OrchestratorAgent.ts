/**
 * PenPard Orchestrator Agent - Iterative Planning & Execution
 * 
 * This agent uses a Plan→Execute→Replan cycle:
 * 1. RECON: Gather intel about the target
 * 2. PLAN: LLM creates a 5-step attack plan
 * 3. EXECUTE: Run each step, collect results
 * 4. REPLAN: Analyze results, create next 5-step plan
 * 5. REPEAT until testing is thorough or max iterations reached
 */

import { BurpMCPClient } from '../services/burp-mcp';
import { llmProvider } from '../services/LLMProviderService';
import { llmQueue } from '../services/LLMQueue';
import { db, saveScanAuthInventory, saveScanEndpointInventory } from '../db/init';
import { logger } from '../utils/logger';
import path from 'path';
import { mindsetService, MindsetTTP } from '../services/mindset-service';
import { analyzeSource, buildAgentContextBlock } from '../services/source-analysis/SourceAnalysisService';
import { SourceAnalysisMode } from '../services/source-analysis/SourceAnalysisMode';
import { RequestHarvester } from '../services/RequestHarvester';
import { HypothesisEngine } from '../services/HypothesisEngine';
import { CoverageTracker } from '../services/CoverageTracker';
import { diffResponses, ResponseSnapshot } from '../services/ResponseDiffer';
import { browserService } from '../services/BrowserService';
import { AuthStateManager, AuthStartupConfig, AuthStartupInventory } from '../services/auth';
import { parseRawBurpRequest, type ParsedBurpRequest } from '../services/burp-request';
import { normalizeCookiesAndAuthEntries, normalizeProxyHistoryItems, normalizeSendHttpResponse, normalizeSessionCookieResult } from '../services/burp-tool-result';
import { WebAuthStartupService } from '../services/WebAuthStartupService';
import { EndpointIntelligenceService, EndpointInventorySnapshot } from '../services/EndpointIntelligenceService';
import {
    DEFAULT_WEB_PROMPT,
    buildContinuationScopeMessage,
    buildOperatorInstructionMessages,
} from '../prompts/orchestratorPrompts';
import { OrchestratorBrowserSession } from './orchestrator/OrchestratorBrowserSession';
import { OrchestratorContextSignals } from './orchestrator/OrchestratorContextSignals';
import { OrchestratorFallbackPlanner } from './orchestrator/OrchestratorFallbackPlanner';
import { OrchestratorFindingTracker } from './orchestrator/OrchestratorFindingTracker';
import { OrchestratorInstructionAnalyzer } from './orchestrator/OrchestratorInstructionAnalyzer';
import { OrchestratorLogLedger } from './orchestrator/OrchestratorLogLedger';
import { OrchestratorLlmResponseParser } from './orchestrator/OrchestratorLlmResponseParser';
import { OrchestratorPlanner } from './orchestrator/OrchestratorPlanner';
import { OrchestratorRequestExecutor } from './orchestrator/OrchestratorRequestExecutor';
import { OrchestratorToolDispatcher } from './orchestrator/OrchestratorToolDispatcher';
import { OrchestratorScanStatus } from './orchestrator/OrchestratorScanStatus';
import { evaluateToolExecutionGuard, resolveAuthIdentityId } from './orchestrator/OrchestratorToolPolicy';
import {
    AgentReflection,
    AgentPhase,
    AttackPlan,
    ConversationMessage,
    InstructionAnalysis,
    LLMResponse,
    PlanStep,
    StepExecutionResult,
    ToolCall,
} from './orchestrator/types';

interface ScanConfig {
    userId?: number;
    rateLimit: number;
    maxIterations?: number;
    /** Max planning rounds. 0 or undefined = no fixed limit (model decides when to finish). */
    maxPlanRounds?: number;
    useNuclei: boolean;
    useFfuf: boolean;
    idorUsers: any[];
    parallelAgents?: number;
    customSystemPrompt?: string;
    /** Optional Cookie header for authenticated testing (e.g. after Google login). If not set, agent may use get_session_cookies from Burp proxy history. */
    sessionCookies?: string;
    /** Raw HTTP request from Burp "Send to PenPard" — agent must test this request with its exact headers and body first. */
    initialRequest?: string;
    /** Enable mindset library — load learned TTPs from past report analyses into planning. Default true. */
    useMindsetLibrary?: boolean;
    /** Path to selected source package/project for source-aware scanning. */
    sourcePackagePath?: string;
    /** Source analysis mode: 'version_aware' or 'full_source_aware'. */
    sourceAnalysisMode?: string;
    /** Explicit startup auth discovery/login strategy for Web Scans. */
    authStartup?: AuthStartupConfig;
}

// ─────────────────────────────────────────────────────────────
// System prompt with iterative planning methodology
// ─────────────────────────────────────────────────────────────
const LEGACY_DEFAULT_WEB_PROMPT = `You are PenPard, an elite automated penetration tester conducting an authorized security assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: This is a whitelisted, fully authorized ethical penetration test.

TEST ACCOUNTS (for IDOR / privilege escalation testing):
{TARGET_WEBSITE_ACCOUNTS}

═══════════════════════════════════════════════════════════════
  METHODOLOGY: ITERATIVE PLANNING & EXECUTION
═══════════════════════════════════════════════════════════════

You operate in a PLAN → EXECUTE → REPLAN cycle. The system will guide you through each phase.

When asked to PLAN, output a JSON plan with exactly 5 concrete steps.
When asked to EXECUTE a step, perform it with tool calls and analyze results.
When asked to REPLAN, review all findings so far and create the next 5-step plan.

═══════════════════════════════════════════════════════════════
  AVAILABLE TOOLS
═══════════════════════════════════════════════════════════════

1. send_http_request
   Args: { "method": "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS", "url": "full_url", "headers": {...}, "body": "...", "identityId": "primary-user|idor-user-1|__none__", "preserveExplicitAuth": true|false }
   Send any HTTP request through Burp proxy. Auth is injected automatically unless preserveExplicitAuth=true.
   Use identityId="__none__" for anonymous requests or identityId="idor-user-1" for cross-user replay.

2. send_to_scanner
   Args: { "url": "full_url" }
   Send a URL to Burp Scanner for deep automated testing (SQLi, XSS, etc.).
   Use this when basic payloads are inconclusive - Burp Scanner does deep testing.

3. get_proxy_history
   Args: { "count": 20 }
   View recent USER proxy traffic (excludes PenPard agent requests) to discover endpoints, API calls, and hidden parameters.

4. get_session_cookies
   Args: { "host": "example.com" }
   Get the Cookie header from the most recent USER request to that host in Burp proxy history. Use for authenticated testing when the user logged in via browser (e.g. Google OAuth). Include the returned Cookie in every send_http_request to the target.

5. get_sitemap
   Args: {}
   Get the full sitemap from Burp - shows all discovered URLs and endpoints.

6. spider_url
   Args: { "url": "full_url" }
   Crawl a URL to discover all linked pages, forms, and endpoints.

7. check_authorization
   Args: { "original_request": "...", "modified_headers": {...} }
   Test authorization bypass by replaying a request with different auth tokens.

8. generate_payloads
   Args: { "type": "xss|sqli|lfi|cmdi|ssrf|idor", "context": "html|attribute|js|url|header" }
   Generate context-aware payloads for a specific vulnerability type.

9. extract_links
   Args: { "url": "full_url" }
   Extract all links, forms, and resources from a page.

10. browser_navigate
    Args: { "url": "full_url" }
    Navigate to URL in PenPard Browser (renders JavaScript, executes client-side code).
    Use instead of send_http_request when you need to see JS-rendered content, SPAs, or
    interact with the page. ALL browser traffic routes through Burp proxy automatically.

11. browser_get_page_state
    Args: {}
    Get current page DOM state: forms, links, hidden inputs, meta tags, cookies,
    localStorage, sessionStorage. More complete than HTTP response body for JS-heavy apps.

12. browser_get_frontend_analysis
    Args: {}
    Extract from current page JavaScript: API endpoints, GraphQL URLs, WebSocket URLs,
    JWT tokens, CSRF tokens, frontend routes, hidden parameters.
    Reveals attack surface invisible to HTTP-only testing.

13. browser_fill_and_submit
    Args: { "fields": [{"selector": "input[name=user]", "value": "admin"}, {"selector": "input[name=pass]", "value": "' OR 1=1--"}], "submit_selector": "button[type=submit]" }
    Fill form fields and submit. For testing login, search, registration with payloads.
    All submission traffic is captured by Burp proxy.

14. browser_evaluate_js
    Args: { "script": "document.cookie" }
    Run JavaScript in the page context. Access DOM, cookies, localStorage, sessionStorage.
    Returns the evaluation result.

15. browser_screenshot
    Args: {}
    Capture screenshot of current page state. Use as evidence when reporting findings.

16. browser_correlate_burp
    Args: {}
    Compare frontend-discovered API endpoints with Burp proxy traffic history.
    Returns endpoints found in JS but never seen in Burp = untested attack surface.
    ALWAYS use after browser_get_frontend_analysis to find hidden endpoints.

17. harvest_traffic
    Args: {}
    Harvest recent Burp proxy traffic, classify requests by purpose (authentication,
    state-changing, object-reference, admin, etc.), and score them for testing interest.
    Returns newly-harvested high-value requests ready for active testing.

18. get_hypotheses
    Args: { "status": "new|testing|escalated|confirmed|discarded|all" }
    Get current vulnerability hypotheses and their validation evidence.
    Each hypothesis tracks: type, target endpoint, parameter, confidence, status, next action.

19. get_coverage
    Args: {}
    Get coverage summary: tested vs untested endpoints, explored vs unexplored workflows,
    frontend-only routes, weakly-tested areas. Use to identify gaps in testing.

20. repeater_test
    Args: { "requestId": "req-...", "identityId": "primary-user|idor-user-1|__none__", "preserveExplicitAuth": true|false, "mutations": [{ "parameter": "id", "originalValue": "1", "newValue": "2", "description": "IDOR swap", "identityId": "idor-user-1" }] }
    Send a harvested request through Burp with controlled mutations.
    Returns response diff analysis: status change, body change, keyword signals, significance.
    Use for hypothesis validation — testing specific vulnerability theories with evidence.


═══════════════════════════════════════════════════════════════
  OPERATOR SCAN INSTRUCTIONS (HIGHEST PRIORITY — OVERRIDES PHASES)
═══════════════════════════════════════════════════════════════

⚠️ If OPERATOR SCAN INSTRUCTIONS are provided at the top of this prompt:
  • They are ABSOLUTE LAW. They completely override the default phases below.
  • If the operator specifies exact endpoints → ONLY test those endpoints. Do NOT spider, do NOT check robots.txt, do NOT discover other endpoints.
  • If the operator specifies exact vulnerability types → ONLY test for those types. Skip all other vulnerability categories.
  • If the operator says "then finish" → Complete the test after thorough testing of the specified scope. Do NOT expand scope.
  • Skip PHASE 1 (RECON) entirely if the operator has already told you exactly where and what to test.
  • Go DIRECTLY to testing the specified endpoint(s) with the specified attack(s) in Round 1.

═══════════════════════════════════════════════════════════════
  DEFAULT ATTACK PHASES (only if NO operator instructions are given)
═══════════════════════════════════════════════════════════════

The following phases apply ONLY when the operator has NOT provided specific instructions.
If operator instructions exist, skip directly to the relevant testing phase for the specified scope.

PHASE 1 - RECON & DISCOVERY (Rounds 1-2)
  • Spider the target, check robots.txt, sitemap.xml
  • Map all endpoints, parameters, forms, and API routes
  • Identify technologies (frameworks, headers, cookies, error pages)
  • Check for common paths: /admin, /api, /swagger, /graphql, /.env, /debug

PHASE 2 - MAPPING & ANALYSIS (Rounds 2-3)
  • Classify endpoints by input type (query params, POST body, headers, cookies)
  • Identify authentication mechanisms and session management
  • Note any file upload, redirect, or dynamic content features
  • Map parameter types (numeric IDs, filenames, search terms, JSON fields)

PHASE 3 - VULNERABILITY TESTING (Rounds 3-6)
  • Test each unique parameter for injection flaws (SQLi, XSS, LFI, CMDI, SSRF)
  • Test IDOR with different user accounts (swap IDs, tokens)
  • Check for broken access control (access admin endpoints as regular user)
  • Test authentication bypass, password reset flaws, session fixation
  • Use send_to_scanner for thorough testing of complex parameters

PHASE 4 - DEEP EXPLOITATION (Rounds 5-8)
  • Chain vulnerabilities if possible (e.g., XSS + CSRF, IDOR + info leak)
  • Test for second-order injection (stored XSS, blind SQLi)
  • Check for SSRF, XXE, deserialization if applicable
  • Test API-specific issues: mass assignment, rate limiting, JWT flaws

═══════════════════════════════════════════════════════════════
  RESPONSE FORMATS
═══════════════════════════════════════════════════════════════

── PLANNING RESPONSE (when asked to create a plan) ──
{
  "analysis": "Current state: discovered 12 endpoints, tested 3 for SQLi. The /api/users endpoint accepts ID parameter that needs IDOR testing...",
  "plan": [
    { "step": 1, "objective": "Test IDOR on /api/users/{id}", "approach": "Access user 2's data with user 1's token", "tools": ["send_http_request", "check_authorization"] },
    { "step": 2, "objective": "Test XSS on /search", "approach": "Inject reflected XSS payloads in query parameter", "tools": ["send_http_request", "generate_payloads"] },
    { "step": 3, "objective": "Test SQLi on /api/products", "approach": "Test sort and filter parameters for SQL injection", "tools": ["send_http_request"] },
    { "step": 4, "objective": "Check admin panel access control", "approach": "Access /admin endpoints without authentication", "tools": ["send_http_request"] },
    { "step": 5, "objective": "Deep scan login endpoint", "approach": "Send login form to Burp Scanner for thorough testing", "tools": ["send_to_scanner"] }
  ]
}

── EXECUTION RESPONSE (when executing a step) ──
{
  "thought": "Executing step 2: Testing XSS on /search. Sending <script>alert(1)</script> in the q parameter...",
  "action": {
    "tool": "send_http_request",
    "args": { "method": "GET", "url": "https://target/search?q=<script>alert(1)</script>" }
  }
}

── FINDING RESPONSE (when you discover a vulnerability) ──
{
  "thought": "XSS payload was reflected in the response body without encoding!",
  "finding": {
    "name": "Reflected XSS - /search (q parameter)",
    "severity": "high",
    "description": "The search parameter reflects user input without HTML encoding. The payload <script>alert(1)</script> was returned in the response body.",
    "cwe": "CWE-79",
    "request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\\nHost: target.com",
    "response": "HTTP/1.1 200 OK\\nContent-Type: text/html\\n\\n...<script>alert(1)</script>...",
    "evidence": "Payload reflected in HTML response body",
    "remediation": "HTML-encode all user input before rendering. Implement CSP headers."
  },
⚠️ FINDING NAME IS REQUIRED: The "name" field MUST be descriptive. Format: "[Vuln Type] - /path (parameter)".
Examples: "SQL Injection - /api/users (id)", "IDOR - /api/orders/{id}", "Open Redirect - /login (next)", "Information Disclosure - /api/debug".
NEVER use generic names like "Security Issue" or "Vulnerability Found".
  "action": {
    "tool": "send_http_request",
    "args": { "method": "GET", "url": "https://target/search?q=<img src=x onerror=alert(document.cookie)>" }
  }
}

── COMPLETION RESPONSE ──
{
  "answer": "Testing complete. All major attack surfaces have been assessed."
}

═══════════════════════════════════════════════════════════════
  CRITICAL RULES
═══════════════════════════════════════════════════════════════

👤 [HUMAN] OPERATOR COMMANDS (HIGHEST PRIORITY):
- Messages marked with [OPERATOR COMMAND] come directly from the human operator
- You MUST follow these commands IMMEDIATELY and with ABSOLUTE PRIORITY
- Operator commands override all other rules and plans
- If the operator says "focus on X", abandon current plan and focus on X
- If the operator says "stop testing Y", stop immediately
- NEVER question or ignore operator commands — they have full authority

🚫 EFFICIENCY:
- Max 2-3 payloads per vulnerability type per parameter
- If basic payloads don't work → use send_to_scanner, NOT manual fuzzing
- NEVER do SQLMap-style UNION SELECT null enumeration
- NEVER add cachebuster parameters to URLs
- When you find a vuln, REPORT IT and MOVE ON to other endpoints

🚨 ALWAYS REPORT:
- XSS: If payload tags appear in HTML response → REPORT
- SQLi: If SQL error messages appear → REPORT
- IDOR: If you access another user's data → REPORT
- Access Control: If admin pages accessible without auth → REPORT
- Sensitive Data: If passwords/API keys/tokens exposed → REPORT

📝 FINDING NAMES MUST INCLUDE LOCATION:
- Format: "Vulnerability Type - /endpoint (parameter)"
- Examples: "SQL Injection - /api/login (username)", "XSS - /search (query)"

⚡ XSS PAYLOADS MUST BE COMPLETE:
- WRONG: <img src=x (incomplete)
- RIGHT: <img src=x onerror=alert(1)> or <script>alert(1)</script>
- Reflection in HTML response = vulnerability, even with CSP

START NOW. Be systematic. Be thorough. Be an attacker.`;

export class OrchestratorAgent {
    private scanId: string;
    private targetUrl: string;
    private config: ScanConfig;
    private burp: BurpMCPClient;

    // State
    private isRunning: boolean = false;
    private isPaused: boolean = false;
    private phase: AgentPhase = 'planning';
    private humanCommandQueue: string[] = [];
    private findings: any[] = [];
    private conversationHistory: ConversationMessage[] = [];
    private maxIterations: number;

    // Planning state
    private currentPlan: AttackPlan | null = null;
    private planRound: number = 0;
    /** 0 = no fixed limit (model decides); otherwise max planning rounds. */
    private maxPlanRounds: number = 0;
    private discoveredEndpoints: Set<string> = new Set();
    private stepResults: StepExecutionResult[] = [];
    private rateLimitPauseUntil: Date | null = null;
    private readonly RATE_LIMIT_PAUSE_MS = 1 * 60 * 1000;

    // Incremental log persistence — flush to DB periodically to survive crashes
    private readonly logLedger: OrchestratorLogLedger;

    // Cached system prompt (always index 0 in conversationHistory)
    private systemPromptContent: string = '';

    // Instruction analysis — LLM-parsed understanding of operator's scan instructions
    private isFocusedScope: boolean = false;
    private instructionAnalysis: InstructionAnalysis | null = null;

    // Mindset library — loaded TTPs from past report analyses
    private mindsetTTPs: MindsetTTP[] = [];

    private startupAuthInventory: AuthStartupInventory | null = null;
    private endpointInventory: EndpointInventorySnapshot | null = null;

    // ── Pentester Loop Services (v2) ──
    private harvester: RequestHarvester;
    private hypothesisEngine: HypothesisEngine;
    private coverageTracker: CoverageTracker;

    // ── Auth State Engine ──
    public authManager: AuthStateManager;
    private readonly llmResponseParser: OrchestratorLlmResponseParser;
    private readonly instructionAnalyzer: OrchestratorInstructionAnalyzer;
    private readonly contextSignals: OrchestratorContextSignals;
    private readonly planner: OrchestratorPlanner;
    private readonly fallbackPlanner: OrchestratorFallbackPlanner;
    private readonly browserSession: OrchestratorBrowserSession;
    private readonly requestExecutor: OrchestratorRequestExecutor;
    private readonly findingTracker: OrchestratorFindingTracker;
    private readonly scanStatus: OrchestratorScanStatus;
    private readonly toolDispatcher: OrchestratorToolDispatcher;

    constructor(scanId: string, targetUrl: string, config: ScanConfig, burp: BurpMCPClient) {
        this.scanId = scanId;
        this.targetUrl = targetUrl;
        this.config = config;
        this.burp = burp;
        this.maxIterations = config.maxIterations ?? 50;
        // maxPlanRounds: 0 or undefined = no fixed limit (model decides)
        const requested = config.maxPlanRounds ?? 0;
        this.maxPlanRounds = requested > 0 ? requested : 0;
        this.logLedger = new OrchestratorLogLedger({ scanId });

        // Initialize pentester loop services
        this.harvester = new RequestHarvester();
        this.hypothesisEngine = new HypothesisEngine();
        this.coverageTracker = new CoverageTracker();

        // Initialize auth state engine
        this.authManager = new AuthStateManager(scanId, targetUrl);
        this.llmResponseParser = new OrchestratorLlmResponseParser(
            targetUrl,
            () => this.isFocusedScope,
            (channel, message) => this.log(channel, message),
        );
        this.instructionAnalyzer = new OrchestratorInstructionAnalyzer(
            this.llmResponseParser,
            (channel, message) => this.log(channel, message),
        );
        this.contextSignals = new OrchestratorContextSignals((channel, message) => this.log(channel, message));
        this.planner = new OrchestratorPlanner({
            parser: this.llmResponseParser,
            log: (channel, message) => this.log(channel, message),
            delay: (ms) => this.delay(ms),
            handleRateLimitError: (error) => this.handleRateLimitError(error),
        });
        this.fallbackPlanner = new OrchestratorFallbackPlanner((channel, message) => this.log(channel, message));
        this.browserSession = new OrchestratorBrowserSession({
            userId: config.userId,
            targetUrl,
            scanId,
            authManager: this.authManager,
            log: (channel, message) => this.log(channel, message),
        });
        this.requestExecutor = new OrchestratorRequestExecutor({
            scanId,
            burp,
            authManager: this.authManager,
            initialRequest: config.initialRequest,
            log: (channel, message) => this.log(channel as any, message),
            delay: (ms) => this.delay(ms),
            maxSameRequest: 2,
            rateLimitPauseMs: this.RATE_LIMIT_PAUSE_MS,
            setRateLimitPauseUntil: (until) => {
                this.rateLimitPauseUntil = until;
            },
            onEndpointDiscovered: (url) => {
                try {
                    const parsed = new URL(url);
                    this.discoveredEndpoints.add(parsed.pathname);
                } catch {
                    /* ignore */
                }
            },
            onManagedAuthRefreshed: (identityId) => this.browserSession.seedBrowserFromAuthManager(identityId),
        });
        this.findingTracker = new OrchestratorFindingTracker({
            scanId,
            burp,
            log: (channel, message) => this.log(channel as any, message),
            getLastExchange: () => this.requestExecutor.getLastExchange(),
            onFindingSaved: (finding) => {
                this.findings.push(finding);
            },
        });
        this.scanStatus = new OrchestratorScanStatus(scanId);
        this.toolDispatcher = new OrchestratorToolDispatcher({
            log: (channel, message) => this.log(channel as any, message),
            guard: (toolCall) => {
                const guardResult = evaluateToolExecutionGuard({
                    toolName: toolCall.tool,
                    isFocusedScope: this.isFocusedScope,
                    rateLimitPauseUntil: this.rateLimitPauseUntil,
                });

                if (!guardResult.allowed && guardResult.logMessage) {
                    this.log('tool', guardResult.logMessage);
                }

                return guardResult.allowed ? null : guardResult.response;
            },
            handlers: {
                send_http_request: (toolCall) => this.executeSendHttpRequest(toolCall),
                get_proxy_history: async (toolCall) => ({
                    items: normalizeProxyHistoryItems(
                        await this.burp.callTool('get_proxy_history', { ...toolCall.args, excludePenPard: true }),
                    ),
                }),
                get_session_cookies: async (toolCall) => normalizeSessionCookieResult(
                    await this.burp.callTool('get_session_cookies', { host: toolCall.args?.host || new URL(this.targetUrl).hostname }),
                ),
                get_cookies_and_auth_for_host: async (toolCall) => ({
                    entries: normalizeCookiesAndAuthEntries(await this.burp.callTool('get_cookies_and_auth_for_host', {
                        host: toolCall.args?.host || new URL(this.targetUrl).hostname,
                        maxItems: toolCall.args?.maxItems ?? 50,
                    })),
                }),
                send_to_scanner: (toolCall) => this.burp.callTool('send_to_scanner', toolCall.args),
                get_sitemap: (toolCall) => this.burp.callTool('get_sitemap', toolCall.args || {}),
                spider_url: (toolCall) => this.burp.callTool('spider_url', toolCall.args),
                check_authorization: (toolCall) => this.burp.callTool('check_authorization', toolCall.args),
                generate_payloads: (toolCall) => this.burp.callTool('generate_payloads', toolCall.args),
                extract_links: (toolCall) => this.burp.callTool('extract_links', toolCall.args),
                analyze_response: async () => ({ status: 'Analysis requested - handled by LLM' }),
                browser_navigate: (toolCall) => this.executeBrowserNavigate(toolCall),
                browser_get_page_state: () => this.executeBrowserPageState(),
                browser_get_frontend_analysis: () => this.executeBrowserFrontendAnalysis(),
                browser_fill_and_submit: (toolCall) => this.executeBrowserFillSubmit(toolCall),
                browser_evaluate_js: (toolCall) => this.executeBrowserEvaluateJs(toolCall),
                browser_screenshot: () => this.executeBrowserScreenshot(),
                browser_correlate_burp: () => this.executeBrowserCorrelateBurp(),
                harvest_traffic: () => this.executeHarvestTraffic(),
                get_hypotheses: (toolCall) => this.executeGetHypotheses(toolCall),
                get_coverage: () => this.executeGetCoverage(),
                repeater_test: (toolCall) => this.executeRepeaterTest(toolCall),
                none: async () => ({ status: 'No tool call (step complete)' }),
            },
        });
    }

    /**
     * Analyze operator instructions with LLM to determine scan scope.
     * Returns structured JSON: is_focused, focused_endpoints, focused_vulns, etc.
     */
    private async analyzeOperatorInstructions(instructions: string): Promise<void> {
        const analysis = await this.instructionAnalyzer.analyze(instructions, this.targetUrl);
        if (!analysis) {
            this.log('error', 'Failed to parse instruction analysis — treating as full scan');
            this.instructionAnalysis = null;
            this.isFocusedScope = false;
            return;
        }

        this.instructionAnalysis = analysis;
        this.isFocusedScope = analysis.is_focused;

        this.log('system', '✅ Instruction analysis complete:');
        this.log('system', `   Focused: ${this.isFocusedScope}`);
        if (analysis.focused_endpoints.length > 0) {
            this.log('system', `   Endpoints: ${analysis.focused_endpoints.join(', ')}`);
        }
        if (analysis.focused_vulns.length > 0) {
            this.log('system', `   Vuln types: ${analysis.focused_vulns.join(', ')}`);
        }
        this.log('system', `   Skip recon: ${analysis.skip_recon}`);
        this.log('system', `   Auto-finish: ${analysis.auto_finish}`);
        this.log('system', `   Summary: ${analysis.summary}`);

        if (this.isFocusedScope) {
            this.log('system', '🎯 FOCUSED SCOPE ACTIVE — Enumeration tools (spider, sitemap, extract_links) are BLOCKED.');
        }
    }

    /**
     * Build the operator instructions reminder block.
     * Injected into every planning/execution/replanning prompt.
     */
    private getOperatorInstructionsReminder(): string {
        return this.contextSignals.buildOperatorInstructionsReminder(this.config.customSystemPrompt, this.instructionAnalysis);
    }

    private isStoppedPhase(): boolean {
        return this.phase === 'stopped';
    }

    public async start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.contextSignals.resetBudgetSignals();
        this.log('system', `Orchestrator Agent started for target: ${this.targetUrl}`);

        try {
            this.scanStatus.initializing();

            if (!this.targetUrl) {
                throw new Error('Target URL is required');
            }

            // Phase 1: Initialize
            await this.phaseInit();
            if (!this.isRunning || this.isStoppedPhase()) {
                return;
            }

            // Phase 2: Iterative Plan → Execute → Replan
            await this.phaseIterativeTesting();
            if (!this.isRunning || this.isStoppedPhase()) {
                return;
            }

            // Phase 3: Reporting
            await this.phaseReporting();

        } catch (error: any) {
            if (this.isStoppedPhase()) {
                return;
            }
            this.phase = 'failed';
            this.log('error', `Critical Failure: ${error.message}`);
            this.scanStatus.failed(error.message);
        } finally {
            this.isRunning = false;
            this.saveLogs();
            this.browserSession.cleanup();
        }
    }

    /**
     * Continue a completed scan with a new instruction.
     * Re-initializes the agent with existing findings context and runs for X more planning rounds.
     */
    public async continueScan(opts: {
        instruction: string;
        iterations: number;
        planningEnabled: boolean;
        existingFindings?: any[];
        existingEndpoints?: string[];
        existingLogs?: string[];
    }) {
        if (this.isRunning) {
            this.log('error', 'Agent is already running. Cannot continue.');
            return;
        }

        this.isRunning = true;
        this.phase = 'planning';
        this.contextSignals.resetBudgetSignals();
        const extraRounds = Math.min(Math.max(opts.iterations, 1), 20); // clamp 1-20

        this.log('system', `═══ CONTINUING SCAN ═══`);
        this.log('system', `Instruction: ${opts.instruction}`);
        this.log('system', `Additional rounds: ${extraRounds}, Planning: ${opts.planningEnabled ? 'ON' : 'OFF'}`);

        try {
            this.scanStatus.testing();

            // Restore existing state from DB
            if (opts.existingFindings) {
                this.findings = opts.existingFindings;
                this.log('system', `Restored ${this.findings.length} existing findings`);
            }
            if (opts.existingEndpoints) {
                opts.existingEndpoints.forEach(ep => this.discoveredEndpoints.add(ep));
                this.log('system', `Restored ${this.discoveredEndpoints.size} discovered endpoints`);
            }

            // Check connections
            const burpOk = await this.burp.isAvailable();
            if (!burpOk) {
                this.log('error', 'Burp MCP not available! Attempting to continue anyway...');
            } else {
                this.log('system', '✓ Burp MCP: Connected');
            }

            const llmOk = await this.checkLLM();
            if (!llmOk) {
                throw new Error('No active LLM configured.');
            }
            this.log('system', '✓ LLM: Connected');

            // Build system prompt if not already set (includes initialRequest headers)
            if (this.conversationHistory.length === 0) {
                const promptTemplate = await this.loadPromptTemplate();
                const accountsJson = JSON.stringify(this.buildAccountPromptContext(), null, 2);
                let sysPrompt = promptTemplate
                    .replace('{TARGET_WEBSITE}', this.targetUrl)
                    .replace('{TARGET_WEBSITE_ACCOUNTS}', accountsJson);

                // Inject initialRequest structured data into system prompt (same as phaseInit)
                if (this.config.initialRequest?.trim()) {
                    const parsed = this.parseRawHttpRequest(this.config.initialRequest.trim());
                    if (parsed) {
                        const headersBlock = Object.entries(parsed.headers)
                            .filter(([k]) => !k.toLowerCase().startsWith('x-penpard'))
                            .map(([k, v]) => `    "${k}": "${v}"`)
                            .join(',\n');
                        sysPrompt += `\n\n═══════════════════════════════════════════════════════════════\n  SEND TO PENPARD — REQUEST FROM BURP (CRITICAL)\n═══════════════════════════════════════════════════════════════\n\nYou received a complete HTTP request from the user via Burp. STRICT RULES:\n\n1. Every send_http_request MUST include ALL headers listed below. Do NOT omit any. Do NOT add new headers. Copy them exactly.\n2. Set preserveExplicitAuth=true so PenPard preserves the explicit Cookie/Authorization headers exactly as supplied.\n3. Only PARAMETRIC testing: change parameter values in the URL query string or body. Do NOT touch headers unless the user explicitly asks.\n4. The request has cookies and auth tokens — these are essential for authenticated testing.\n\nBASE REQUEST:\n  Method: ${parsed.method}\n  URL: ${parsed.url}\n  Headers (INCLUDE ALL OF THESE IN EVERY REQUEST):\n${headersBlock}\n  Body: ${parsed.body || '(none)'}\n\nWhen calling send_http_request, use:\n  { "method": "${parsed.method}", "url": "<url with modified params>", "headers": { ALL HEADERS ABOVE }, "body": "${parsed.body || ''}", "preserveExplicitAuth": true }\n`;
                    }
                }

                this.systemPromptContent = sysPrompt;
                this.conversationHistory.push({ role: 'system', content: sysPrompt });
            }

            // Also inject initialRequest as structured user message for continuation context
            if (this.config.initialRequest?.trim()) {
                const parsed = this.parseRawHttpRequest(this.config.initialRequest.trim());
                if (parsed) {
                    const headersJson = JSON.stringify(
                        Object.fromEntries(
                            Object.entries(parsed.headers).filter(([k]) => !k.toLowerCase().startsWith('x-penpard'))
                        ),
                        null, 2
                    );
                    this.conversationHistory.push({
                        role: 'user',
                        content: `REMINDER — The original request from Burp (Send to PenPard) is still active. You MUST include ALL these headers in every send_http_request and set preserveExplicitAuth=true.\n\nMethod: ${parsed.method}\nURL: ${parsed.url}\nHeaders (JSON — pass this entire object):\n${headersJson}\nBody: ${parsed.body || '(none)'}\n\nDo NOT send requests without these headers. The user's session cookies and auth tokens are required.`
                    });
                    this.conversationHistory.push({
                        role: 'assistant',
                        content: `Understood. I will continue including all ${Object.keys(parsed.headers).length} headers (Cookie, auth tokens, User-Agent, etc.) in every request and I will set preserveExplicitAuth=true so PenPard does not replace them.`
                    });
                    this.log('system', `✓ Burp request headers re-injected for continuation (${Object.keys(parsed.headers).length} headers)`);
                }
            }

            // Inject continuation instruction as operator command
            const findingsSummary = this.findings.length > 0
                ? this.findings.map(f => `- [${f.severity?.toUpperCase()}] ${f.name}`).join('\n')
                : 'No findings yet.';

            this.conversationHistory.push({
                role: 'user',
                content: `⚠️ [OPERATOR COMMAND — SCAN CONTINUATION] The operator has resumed this completed scan with new instructions:

INSTRUCTION: ${opts.instruction}

PREVIOUS FINDINGS (${this.findings.length} total):
${findingsSummary}

DISCOVERED ENDPOINTS:
${[...this.discoveredEndpoints].join('\n') || 'None recorded'}

You have ${extraRounds} planning round(s) to execute this instruction. ${opts.planningEnabled ? 'Use the PLAN → EXECUTE → REPLAN cycle.' : 'Skip planning — execute the instruction directly with tool calls.'} Be thorough within the given rounds.`
            });

            // Analyze instruction scope
            await this.analyzeOperatorInstructions(opts.instruction);

            // Inject scope directives
            if (this.instructionAnalysis?.is_focused) {
                this.isFocusedScope = true;
                this.conversationHistory.push(buildContinuationScopeMessage(this.instructionAnalysis));
            }

            // Reset round counter for the continuation
            const savedRound = this.planRound;
            const savedMaxPlanRounds = this.maxPlanRounds;
            const savedMaxIterations = this.maxIterations;
            this.planRound = 0;
            this.maxPlanRounds = extraRounds;
            this.maxIterations = extraRounds * 10; // generous action budget

            if (opts.planningEnabled) {
                // Full Plan → Execute → Replan cycle
                await this.phaseIterativeTesting();
            } else {
                // Direct execution — send instruction and let LLM execute freely
                await this.phaseDirectExecution(opts.instruction, extraRounds);
            }

            const completedContinuationRounds = opts.planningEnabled ? this.planRound : 0;
            this.planRound = savedRound + completedContinuationRounds;
            this.maxPlanRounds = savedMaxPlanRounds;
            this.maxIterations = savedMaxIterations;

            if (!this.isStoppedPhase()) {
                this.log('system', '═══ CONTINUATION COMPLETE ═══');
                this.log('system', `Total findings after continuation: ${this.findings.length}`);
            }

        } catch (error: any) {
            this.log('error', `Continuation failed: ${error.message}`);
            this.scanStatus.failed(error.message);
        } finally {
            this.isRunning = false;
            this.saveLogs();
            this.browserSession.cleanup();
        }
    }

    /**
     * Direct execution mode — no planning, just let LLM execute instructions with tools.
     */
    private async phaseDirectExecution(_instruction: string, maxRounds: number) {
        this.phase = 'executing';
        this.scanStatus.testing();
        this.log('system', '═══ DIRECT EXECUTION MODE (No Planning) ═══');

        let totalActions = 0;
        const maxActions = maxRounds * 10;

        for (let round = 0; round < maxRounds && this.isRunning && totalActions < maxActions; round++) {
            // Process any human commands
            while (this.humanCommandQueue.length > 0) {
                const cmd = this.humanCommandQueue.shift()!;
                await this.processHumanCommand(cmd);
            }

            // Handle pause
            while (this.isPaused && this.isRunning) {
                await this.delay(1000);
            }

            if (!this.isRunning) break;

            this.log('system', `Direct execution round ${round + 1}/${maxRounds}`);

            // Rate limit protection
            if (this.rateLimitPauseUntil && new Date() < this.rateLimitPauseUntil) {
                const waitMs = this.rateLimitPauseUntil.getTime() - Date.now();
                this.log('system', `Rate limited. Waiting ${Math.ceil(waitMs / 1000)}s...`);
                await this.delay(waitMs);
                this.rateLimitPauseUntil = null;
            }

            try {
                const parsed = await this.planner.executeDirectInstructionTurn({
                    systemPrompt: this.systemPromptContent,
                    conversationHistory: this.conversationHistory,
                    rateLimitPauseUntil: this.rateLimitPauseUntil,
                    round: round + 1,
                    maxRounds,
                });
                if (!parsed) {
                    this.log('agent', 'No valid response from the planner during direct execution.');
                    continue;
                }

                this.logReflection(parsed.reflection);

                // Process findings
                if (parsed.finding) {
                    this.saveFinding(parsed.finding);
                }
                if (parsed.findings) {
                    for (const f of parsed.findings) {
                        this.saveFinding(f);
                    }
                }

                // Process tool actions
                if (parsed.action) {
                    const result = await this.executeToolCall(parsed.action);
                    totalActions++;
                    this.conversationHistory.push({
                        role: 'user',
                        content: `Tool result for ${parsed.action.tool}: ${JSON.stringify(result).slice(0, 3000)}`
                    });
                } else if (parsed.actions) {
                    for (const action of parsed.actions) {
                        const result = await this.executeToolCall(action);
                        totalActions++;
                        this.conversationHistory.push({
                            role: 'user',
                            content: `Tool result for ${action.tool}: ${JSON.stringify(result).slice(0, 3000)}`
                        });
                    }
                }

                // Check for completion
                if (parsed.answer) {
                    this.log('agent', `Conclusion: ${parsed.answer}`);
                    break;
                }
            } catch (e: any) {
                this.handleRateLimitError(e);
                this.log('error', `Execution error: ${e.message}`);
            }
        }

        this.log('system', `Direct execution finished. ${totalActions} actions taken.`);
    }

    public stop() {
        this.isRunning = false;
        this.isPaused = false;
        this.phase = 'stopped';
        this.log('system', 'Stop command received. Terminating agent...');
        this.scanStatus.stopped('Scan stopped by user');
        // Cleanup browser session
        this.cleanupBrowserSession();
    }

    public pause() {
        if (!this.isRunning || this.isPaused) return;
        this.isPaused = true;
        this.log('system', '⏸ Scan paused by user.');
    }

    public resume() {
        if (!this.isPaused) return;
        this.isPaused = false;
        this.log('system', '▶ Scan resumed by user.');
    }

    public handleUserCommand(command: string) {
        this.log('human', `User Command: ${command}`);
        this.humanCommandQueue.push(command);
    }

    public getState() {
        const loopState = this.getPentesterLoopState();
        return {
            phase: this.phase,
            isRunning: this.isRunning,
            isPaused: this.isPaused,
            logsCount: this.logLedger.count,
            findingsCount: this.findings.length,
            planRound: this.planRound,
            currentPlan: this.currentPlan,
            ...loopState,
        };
    }

    public getLogs(since: number = 0): string[] {
        return this.logLedger.getLogs(since);
    }

    public async checkBurpConnection(): Promise<boolean> {
        try {
            return await this.burp.isAvailable();
        } catch {
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE: INITIALIZATION
    // ═══════════════════════════════════════════════════════════

    private async phaseInit() {
        this.phase = 'planning';
        this.scanStatus.planning();
        this.log('system', '═══ PHASE: INITIALIZATION ═══');

        // Check Burp connection
        const burpOk = await this.burp.isAvailable();
        if (!burpOk) {
            this.log('error', 'Burp MCP not available! HTTP requests will fail.');
        } else {
            this.log('system', '✓ Burp MCP: Connected');
            try {
                await this.burp.callTool('add_to_scope', { url: this.targetUrl });
                this.log('burp', `Added ${this.targetUrl} to Burp scope`);
            } catch (e: any) {
                this.log('error', `Scope error: ${e.message}`);
            }
        }

        // Check LLM
        const llmOk = await this.checkLLM();
        if (!llmOk) {
            throw new Error('No active LLM configured. Please configure an LLM provider in Settings.');
        }
        this.log('system', '✓ LLM: Connected');

        // Load mindset library TTPs from past report analyses
        if (this.config.useMindsetLibrary !== false) {
            try {
                this.mindsetTTPs = mindsetService.getRelevantTTPs(this.targetUrl);
                if (this.mindsetTTPs.length > 0) {
                    this.log('system', `📚 Mindset Library: Loaded ${this.mindsetTTPs.length} TTPs from past reports`);
                } else {
                    this.log('system', '📚 Mindset Library: No TTPs available (upload red team reports to build library)');
                }
            } catch (e: any) {
                this.log('error', `Failed to load mindset library: ${e.message}`);
                this.mindsetTTPs = [];
            }
        }

        // ── Auth State Engine: Initialize and capture from all sources ──
        this.log('system', '🔐 Initializing Auth State Engine...');
        const authStartup = this.config.authStartup || {
            mode: 'no_credentials' as const,
            credentials: [],
            allowAccountCreation: false,
            preferSharedPassword: true,
        };
        await this.authManager.initialize(
            {
                sessionCookies: this.config.sessionCookies,
                idorUsers: this.config.idorUsers,
                initialRequest: this.config.initialRequest,
                authStartup,
            },
            this.burp,
            this.browserSession.getSessionId(),
        );
        this.log('system', `✓ Auth State Engine: ${this.authManager.identityRegistry.size} identities, ${this.authManager.getTotalCookies()} cookies, ${this.authManager.getTotalTokens()} tokens`);

        // ── Browser-first auth discovery and session acquisition must complete before normal planning ──
        await this.runAuthFirstStartup(authStartup);

        // Run source analysis after startup auth inventory is complete so planning always sees auth intelligence first
        let sourceContextBlock = '';
        if (this.config.sourcePackagePath && this.config.sourceAnalysisMode) {
            try {
                const mode = this.config.sourceAnalysisMode as SourceAnalysisMode;
                this.log('system', `🔬 Source Analysis: Running ${mode} analysis on ${this.config.sourcePackagePath}...`);
                const sourceResult = await analyzeSource(this.scanId, this.config.sourcePackagePath, mode);
                sourceContextBlock = buildAgentContextBlock(sourceResult);
                this.log('system', `✓ Source Analysis complete: ${sourceResult.framework}, ${sourceResult.dependencies.length} deps, ${sourceResult.cves.length} CVEs`);
                if (mode === SourceAnalysisMode.FULL_SOURCE_AWARE) {
                    const full = sourceResult as any;
                    this.log('system', `  Modules: ${full.modules?.length || 0}, Functions: ${full.functions?.length || 0}, Endpoints: ${full.endpoints?.length || 0}, Security Flows: ${full.securityFlows?.length || 0}`);
                }
            } catch (e: any) {
                this.log('error', `Source analysis failed: ${e.message} — continuing without source context`);
            }
        }

        // Generate the auth block for the system prompt (tells LLM auth is automatic)
        const sessionCookiesBlock = this.authManager.getSystemPromptBlock();
        const startupAuthBlock = this.buildStartupAuthPromptBlock();
        const endpointInventoryBlock = this.buildEndpointInventoryPromptBlock();

        // Build system prompt
        const promptTemplate = await this.loadPromptTemplate();
        const accountsJson = JSON.stringify(this.buildAccountPromptContext(), null, 2);
        let systemPrompt: string;

        const basePrompt = promptTemplate
            .replace('{TARGET_WEBSITE}', this.targetUrl)
            .replace('{TARGET_WEBSITE_ACCOUNTS}', accountsJson);

        if (this.config.customSystemPrompt) {
            systemPrompt = `⚠️ THIS IS THE MOST IMPORTANT — OPERATOR SCAN INSTRUCTIONS (follow these above all else):\n${this.config.customSystemPrompt}\n\n---\n\n${basePrompt}`;
        } else {
            systemPrompt = basePrompt;
        }
        systemPrompt += sessionCookiesBlock;
        systemPrompt += startupAuthBlock;
        systemPrompt += endpointInventoryBlock;

        if (sourceContextBlock) {
            systemPrompt += sourceContextBlock;
        }

        if (this.config.initialRequest?.trim()) {
            const parsed = this.parseRawHttpRequest(this.config.initialRequest.trim());
            if (parsed) {
                const headersBlock = Object.entries(parsed.headers)
                    .filter(([k]) => !k.toLowerCase().startsWith('x-penpard'))
                    .map(([k, v]) => `    "${k}": "${v}"`)
                    .join(',\n');
                systemPrompt += `\n\n═══════════════════════════════════════════════════════════════\n  SEND TO PENPARD — REQUEST FROM BURP (CRITICAL)\n═══════════════════════════════════════════════════════════════\n\nYou received a complete HTTP request from the user via Burp. STRICT RULES:\n\n1. Every send_http_request MUST include ALL headers listed below. Do NOT omit any. Do NOT add new headers. Copy them exactly.\n2. Set preserveExplicitAuth=true so PenPard preserves the explicit Cookie/Authorization headers exactly as supplied.\n3. Only PARAMETRIC testing: change parameter values in the URL query string or body. Do NOT touch headers unless the user explicitly asks.\n4. The request has cookies and auth tokens — these are essential for authenticated testing.\n\nBASE REQUEST:\n  Method: ${parsed.method}\n  URL: ${parsed.url}\n  Headers (INCLUDE ALL OF THESE IN EVERY REQUEST):\n${headersBlock}\n  Body: ${parsed.body || '(none)'}\n\nWhen calling send_http_request, use:\n  { "method": "${parsed.method}", "url": "<url with modified params>", "headers": { ALL HEADERS ABOVE }, "body": "${parsed.body || ''}", "preserveExplicitAuth": true }\n`;
            }
        }

        this.systemPromptContent = systemPrompt;
        this.conversationHistory.push({
            role: 'system',
            content: systemPrompt
        });

        if (this.startupAuthInventory) {
            this.conversationHistory.push({
                role: 'user',
                content: `[SYSTEM] Web Scan auth startup completed before planning.\n${this.buildStartupAuthSummary(this.startupAuthInventory)}\nTreat this inventory as established evidence and keep planning auth-surface-first in round 1 before generic crawling or fuzzing.`,
            });
        }
        if (this.endpointInventory) {
            this.conversationHistory.push({
                role: 'user',
                content: `[SYSTEM] Endpoint intelligence captured before planning.\n${this.buildEndpointInventorySummary(this.endpointInventory)}\nUse this for round 1 auth-surface-first planning and avoid already-filtered noise.`,
            });
        }

        this.log('system', '✓ System prompt loaded');
        await this.delay(500);

        // Analyze operator instructions with LLM to determine scope
        if (this.config.customSystemPrompt) {
            await this.analyzeOperatorInstructions(this.config.customSystemPrompt);
        }

        // Inject operator instructions into conversation based on analysis
        if (this.config.customSystemPrompt) {
            const instr = this.config.customSystemPrompt;
            this.conversationHistory.push(...buildOperatorInstructionMessages(instr, this.instructionAnalysis));

            this.log('system', `✓ Operator instructions processed: "${instr.substring(0, 100)}${instr.length > 100 ? '...' : ''}"`);
        }

        // Request sent from Burp "Send to PenPard" — parse and inject structured data
        if (this.config.initialRequest?.trim()) {
            const parsed = this.parseRawHttpRequest(this.config.initialRequest.trim());
            if (parsed) {
                const headersJson = JSON.stringify(
                    Object.fromEntries(
                        Object.entries(parsed.headers).filter(([k]) => !k.toLowerCase().startsWith('x-penpard'))
                    ),
                    null, 2
                );
                this.conversationHistory.push({
                    role: 'user',
                    content: `CRITICAL — Request from Burp (Send to PenPard).

PLANNING PHASE: Before testing, analyze this request:
- Look at the cookies and auth tokens — note which ones are session tokens
- Identify all parameters in the URL query string and body
- Plan which parameters to test for which vulnerability types (SQLi, XSS, IDOR, etc.)

RULES:
1. Include ALL headers below in EVERY send_http_request call. Copy them exactly — do not omit Cookie, User-Agent, Authorization, or any other header. The user's session depends on these.
2. Only modify PARAMETER VALUES (query string, body fields). Headers stay unchanged.
3. If the user later says "test the Host header" or similar, only then may you modify that specific header.

BASE REQUEST:
Method: ${parsed.method}
URL: ${parsed.url}
Headers (JSON — pass this entire object in every send_http_request):
${headersJson}
Body: ${parsed.body || '(none)'}

Example call:
{
  "tool": "send_http_request",
  "args": {
    "method": "${parsed.method}",
    "url": "${parsed.url}",
    "headers": ${headersJson},
    "body": "${parsed.body || ''}",
    "preserveExplicitAuth": true
  }
}

Start by sending the original request as-is to get a baseline response, then begin parametric testing.`
                });
                this.conversationHistory.push({
                    role: 'assistant',
                    content: `Understood. I will:\n1. Include ALL ${Object.keys(parsed.headers).length} headers in every request (Cookie, User-Agent, auth tokens, etc.)\n2. Set preserveExplicitAuth=true when replaying the Burp-derived request so PenPard preserves the supplied auth exactly\n3. Only modify parameter values for testing — headers stay exactly as provided\n4. Start with a baseline request, then test each parameter for vulnerabilities\n\nLet me begin by analyzing the request and planning my tests.`
                });
                this.log('system', `✓ Burp request parsed — ${parsed.method} ${parsed.url.substring(0, 80)} — ${Object.keys(parsed.headers).length} headers preserved`);
            } else {
                // Fallback: could not parse, inject raw
                this.conversationHistory.push({
                    role: 'user',
                    content: `Request from Burp (Send to PenPard). Test this request. Raw:\n\n${this.config.initialRequest.trim()}`
                });
                this.log('system', '⚠ Could not parse Burp request — injected raw');
            }
        }
    }

    private buildAccountPromptContext(): any[] {
        const startupAccounts = (this.config.authStartup?.credentials || []).map((credential, index) => ({
            identityId: index === 0 ? 'primary-user' : `provided-user-${index}`,
            username: credential.username,
            email: credential.email,
            label: credential.label,
            role: credential.role,
            privilege: credential.privilege || 'unknown',
            source: 'scan_start',
        }));

        const legacyAccounts = (this.config.idorUsers || []).map((account: any, index: number) => ({
            identityId: account.identityId || `idor-user-${index + 1}`,
            username: account.username,
            email: account.email,
            label: account.label,
            role: account.role,
            privilege: account.privilege || 'unknown',
            source: 'idor_pool',
        }));

        const seen = new Set<string>();
        return [...startupAccounts, ...legacyAccounts].filter((account) => {
            const key = JSON.stringify([account.identityId, account.username, account.email, account.role, account.label]);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    private async runAuthFirstStartup(authStartup: AuthStartupConfig): Promise<void> {
        this.log('system', '🔍 Starting browser-first auth discovery before normal planning...');
        const service = new WebAuthStartupService(
            this.scanId,
            this.config.userId || 1,
            this.targetUrl,
            this.burp,
            this.authManager,
            (kind, message) => this.log(kind === 'debug' ? 'debug' : kind, message),
        );
        const { browserSessionId, inventory } = await service.run(authStartup);
        this.browserSession.setSessionId(browserSessionId);
        this.startupAuthInventory = inventory;

        try {
            saveScanAuthInventory(this.scanId, JSON.stringify(inventory));
        } catch (error: any) {
            this.log('error', `Failed to persist auth startup inventory: ${error.message}`);
        }

        inventory.authRoutes.forEach((route) => {
            if (typeof route !== 'string' || !route.trim()) return;
            try {
                const absolute = route.startsWith('http') ? route : new URL(route, this.targetUrl).toString();
                this.discoveredEndpoints.add(absolute);
                this.coverageTracker.addRoute(new URL(absolute).pathname, 'GET', 'browser-navigation');
            } catch {
                this.discoveredEndpoints.add(route);
            }
        });

        inventory.traffic.forEach((entry) => {
            if (!entry?.url) return;
            this.discoveredEndpoints.add(entry.url);
            try {
                const parsed = new URL(entry.url);
                this.coverageTracker.addRoute(parsed.pathname, entry.method || 'GET', entry.source === 'browser' ? 'browser-navigation' : 'burp');
            } catch {
                /* ignore malformed URLs */
            }
        });

        this.log('system', `✓ Auth startup inventory captured: ${inventory.summary}`);
        await this.refreshEndpointInventory('startup', true);
    }

    private async refreshEndpointInventory(trigger: string, allowAiClassification: boolean = false): Promise<void> {
        const browserSessionId = this.browserSession.getSessionId();
        if (!browserSessionId) return;

        try {
            const service = new EndpointIntelligenceService(
                this.scanId,
                this.targetUrl,
                this.burp,
                (level, message) => this.log(level === 'error' ? 'error' : level === 'system' ? 'system' : 'debug', message),
            );
            const inventory = await service.buildInventory({
                browserSessionId,
                authInventory: this.startupAuthInventory,
                allowAiClassification,
            });
            this.endpointInventory = inventory;
            saveScanEndpointInventory(this.scanId, JSON.stringify(inventory));
            this.log('system', `✓ Endpoint intelligence refreshed (${trigger}): ${inventory.summary}`);
        } catch (error: any) {
            this.log('error', `Endpoint intelligence refresh failed (${trigger}): ${error.message}`);
        }
    }

    private buildStartupAuthPromptBlock(): string {
        if (!this.startupAuthInventory) return '';
        return `\n\n═══════════════════════════════════════════════════════════════
  WEB AUTH STARTUP INVENTORY (captured before planning)
═══════════════════════════════════════════════════════════════

${this.buildStartupAuthSummary(this.startupAuthInventory)}

Rules for subsequent work:
- Browser-driven auth discovery already ran before the first plan.
- Use this inventory as evidence, not as a guess.
- Reuse captured cookies, tokens, CSRF values, and identity state instead of rebuilding auth assumptions.
- Keep round 1 auth-surface-first unless operator instructions explicitly narrow scope elsewhere.
`;
    }

    private buildEndpointInventoryPromptBlock(): string {
        if (!this.endpointInventory) return '';
        return `\n\n═══════════════════════════════════════════════════════════════
  ENDPOINT INTELLIGENCE (browser + JS + Burp)
═══════════════════════════════════════════════════════════════

${this.buildEndpointInventorySummary(this.endpointInventory)}

Rules for subsequent work:
- Treat these endpoints and classifications as structured evidence gathered from rendered DOM, loaded JavaScript, browser execution, and Burp traffic.
- Prioritize auth-relevant endpoints early, especially login/register/reset/session-bootstrap/auth-refresh/admin routes.
- Do not waste time on socket polling, HMR, or other noise already filtered from this inventory.
`;
    }

    private buildEndpointInventorySummary(inventory: EndpointInventorySnapshot): string {
        const endpointLines = inventory.records.slice(0, 20).map((record) => {
            const method = record.methods.join(', ') || 'GET';
            const observed = `${record.observedInBurp ? 'burp' : 'no-burp'} / ${record.exercisedInBrowser ? 'browser' : 'not-browser'}`;
            return `- [${record.classification}] ${method} ${record.path} source=${record.primarySource} confidence=${record.confidence} observed=${observed} inferredOnly=${record.inferredOnly ? 'yes' : 'no'}`;
        }).join('\n') || '- none';

        const authLines = inventory.records
            .filter((record) => record.likelyAuthRelevant)
            .slice(0, 12)
            .map((record) => `- ${record.path} (${record.classification})`)
            .join('\n') || '- none';

        return [
            `Summary: ${inventory.summary}`,
            `JS artifacts: ${inventory.jsArtifacts.count} captured, ${inventory.jsArtifacts.totalBytes} bytes analyzed`,
            `Auth-relevant endpoints:\n${authLines}`,
            `Top records:\n${endpointLines}`,
        ].join('\n');
    }

    private buildStartupAuthSummary(inventory: AuthStartupInventory): string {
        const formLines = inventory.forms.slice(0, 8).map((form) => {
            const visibleFields = form.fields
                .slice(0, 8)
                .map((field) => `${field.name || field.id || 'unnamed'}:${field.type}`)
                .join(', ') || 'no fields';
            const hidden = form.hiddenInputs
                .slice(0, 5)
                .map((field) => field.name || field.id || 'hidden')
                .join(', ') || 'none';
            return `- [${form.type}] ${form.method} ${form.action || '(same page)'} fields=${visibleFields} hidden=${hidden}`;
        }).join('\n') || '- none';

        const elementLines = inventory.domElements.slice(0, 10).map((element) =>
            `- [${element.type}] ${element.tagName} text="${element.text}" selector=${element.selector || 'n/a'} href=${element.href || element.action || ''}`
        ).join('\n') || '- none';

        const credentialLines = inventory.discoveredCredentials.slice(0, 10).map((credential) =>
            `- ${credential.identityId || 'unknown'} ${credential.label || credential.username || credential.email || 'credential'} created=${credential.created ? 'yes' : 'no'} success=${credential.success ? 'yes' : 'no'} role=${credential.role || 'unknown'} privilege=${credential.privilege || 'unknown'}`
        ).join('\n') || '- none';

        const blockerLines = inventory.blockers.slice(0, 8).map((blocker) => `- ${blocker}`).join('\n') || '- none';

        return [
            `Startup mode: ${inventory.mode}`,
            `Summary: ${inventory.summary}`,
            `Browser session: ${inventory.browserSessionId || 'not available'}`,
            `Registration available: ${inventory.registrationAvailable ? 'yes' : 'no'}`,
            `Password reset available: ${inventory.passwordResetAvailable ? 'yes' : 'no'}`,
            `Activation gate observed: ${inventory.activationRequired ? 'yes' : 'no'}`,
            `SSO providers: ${inventory.ssoProviders.join(', ') || 'none'}`,
            `Transport: authorization=${inventory.transport.authorizationSchemes.join(', ') || 'none'} | cookies=${inventory.transport.cookieNames.join(', ') || 'none'} | localStorage=${inventory.transport.localStorageKeys.join(', ') || 'none'} | sessionStorage=${inventory.transport.sessionStorageKeys.join(', ') || 'none'} | indexedDB=${inventory.transport.indexedDbNames.join(', ') || 'none'} | csrfHeaders=${inventory.transport.csrfHeaders.join(', ') || 'none'} | csrfFields=${inventory.transport.csrfFormFields.join(', ') || 'none'} | csrfMeta=${inventory.transport.csrfMetaNames.join(', ') || 'none'} | csrfCookies=${inventory.transport.csrfCookieNames.join(', ') || 'none'}`,
            `Auth routes:\n${inventory.authRoutes.slice(0, 20).map((route) => `- ${route}`).join('\n') || '- none'}`,
            `Forms:\n${formLines}`,
            `Auth controls:\n${elementLines}`,
            `Credentials:\n${credentialLines}`,
            `Traffic samples captured: ${inventory.traffic.length}`,
            `Blockers:\n${blockerLines}`,
        ].join('\n');
    }

    private buildAuthStartupDirective(): string {
        return this.contextSignals.buildAuthStartupDirective(
            this.planRound,
            this.config.authStartup?.mode || 'no_credentials',
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE: ITERATIVE PLAN → EXECUTE → REPLAN
    // ═══════════════════════════════════════════════════════════

    private async phaseIterativeTesting() {
        this.phase = 'planning';
        this.scanStatus.testing();
        this.log('system', '═══ PHASE: ITERATIVE TESTING ═══');

        let totalActions = 0;

        while (this.isRunning && (this.maxPlanRounds === 0 || this.planRound < this.maxPlanRounds) && totalActions < this.maxIterations) {
            // Handle pause
            while (this.isPaused && this.isRunning) {
                if (this.humanCommandQueue.length > 0) {
                    const cmd = this.humanCommandQueue.shift()!;
                    await this.processHumanCommand(cmd);
                }
                await this.delay(1000);
            }
            if (!this.isRunning) break;

            // ── PLAN ──
            this.planRound++;
            this.phase = 'planning';
            this.log('system', `\n╔══════════════════════════════════════╗`);
            this.log('system', this.maxPlanRounds > 0
                ? `║  PLANNING ROUND ${this.planRound}/${this.maxPlanRounds}              ║`
                : `║  PLANNING ROUND ${this.planRound} (model decides)     ║`);
            this.log('system', `╚══════════════════════════════════════╝`);

            const plan = await this.createPlan();
            if (!plan) {
                this.log('system', 'LLM indicates testing is complete or failed to create plan.');
                break;
            }

            this.currentPlan = plan;
            this.log('agent', `Plan analysis: ${plan.analysis.substring(0, 200)}...`);

            for (const step of plan.steps) {
                this.log('plan', `Step ${step.step}: ${step.objective} [${step.tools.join(', ')}]`);
            }

            // ── EXECUTE ──
            this.phase = 'executing';
            const roundResults: StepExecutionResult[] = [];

            for (let i = 0; i < plan.steps.length; i++) {
                if (!this.isRunning || totalActions >= this.maxIterations) break;

                // Handle pause between steps
                while (this.isPaused && this.isRunning) {
                    await this.delay(1000);
                }
                if (!this.isRunning) break;

                // Handle human commands
                if (this.humanCommandQueue.length > 0) {
                    const cmd = this.humanCommandQueue.shift()!;
                    await this.processHumanCommand(cmd);
                }

                const step = plan.steps[i];
                step.status = 'executing';

                this.log('system', `\n── Executing Step ${step.step}: ${step.objective} ──`);

                const stepFindings: any[] = [];
                const stepToolResults: string[] = [];

                // Each step can do up to 5 tool calls (multi-step execution)
                const maxActionsPerStep = 5;
                let stepActions = 0;

                while (stepActions < maxActionsPerStep && this.isRunning && totalActions < this.maxIterations) {
                    await this.delay(2000); // Rate limiting between LLM calls

                    try {
                        const response = await this.askLLMForStepExecution(step, stepToolResults, totalActions);
                        totalActions++;
                        stepActions++;

                        if (!response) {
                            this.log('error', 'No valid response from LLM for step execution');
                            break;
                        }

                        // Log thought
                        if (response.thought) {
                            this.log('agent', `Thought: ${response.thought.substring(0, 200)}...`);
                        }
                        this.logReflection(response.reflection);

                        // Process findings
                        if (response.finding) {
                            this.saveFinding(response.finding);
                            stepFindings.push(response.finding);
                        }
                        if (response.findings && response.findings.length > 0) {
                            for (const finding of response.findings) {
                                this.saveFinding(finding);
                                stepFindings.push(finding);
                            }
                        }

                        // Execute action
                        if (response.action && response.action.tool) {
                            this.log('tool', `→ ${response.action.tool}: ${JSON.stringify(response.action.args).substring(0, 150)}`);
                            const result = await this.executeToolCall(response.action);

                            // Analyze for auto-detected vulns
                            if (result && !result.error && !result.skipped) {
                                this.analyzeResponseForVulns(response.action, result);
                            }

                            const resultSummary = JSON.stringify(result).substring(0, 1500);
                            stepToolResults.push(`[${response.action.tool}] ${resultSummary}`);

                            // Feed result back to conversation
                            this.conversationHistory.push({
                                role: 'user',
                                content: `Tool result for step "${step.objective}": ${resultSummary}`
                            });
                        } else if (response.answer) {
                            // Step is done
                            this.log('agent', `Step complete: ${response.answer.substring(0, 100)}`);
                            break;
                        } else {
                            // No action, no answer - LLM is done with this step
                            break;
                        }

                    } catch (e: any) {
                        this.log('error', `Step execution error: ${e.message}`);
                        stepToolResults.push(`[ERROR] ${e.message}`);
                        break;
                    }
                }

                step.status = 'completed';
                step.result = stepFindings.length > 0
                    ? `Found ${stepFindings.length} vulnerabilities`
                    : `Completed - ${stepToolResults.length} tool calls`;

                roundResults.push({ step, findings: stepFindings, toolResults: stepToolResults });
            }

            this.stepResults = [...this.stepResults, ...roundResults];

            // ── HARVEST: Pull and classify Burp traffic after round ──
            try {
                await this.runHarvestCycle();
            } catch (e: any) {
                this.log('error', `Harvest cycle failed (non-fatal): ${e.message}`);
            }

            // ── DELTA FRONTEND ANALYSIS: Check for new state after round ──
            try {
                await this.deltaFrontendAnalysis('round-end');
            } catch (e: any) {
                this.log('error', `Delta analysis failed (non-fatal): ${e.message}`);
            }

            // ── REPLAN ──
            this.phase = 'replanning';
            this.log('system', `\nRound ${this.planRound} complete. Findings this round: ${roundResults.reduce((sum, r) => sum + r.findings.length, 0)}`);
            this.log('system', `Total findings: ${this.findings.length} | Total actions: ${totalActions}/${this.maxIterations}`);

            // Check if LLM wants to continue
            if (totalActions >= this.maxIterations) {
                this.log('system', `Reached max iterations (${this.maxIterations}). Moving to reporting.`);
                break;
            }

            const shouldContinue = await this.shouldContinueTesting(roundResults);
            if (!shouldContinue) {
                this.log('system', 'LLM determined testing is thorough enough.');
                break;
            }
        }

        if (this.maxPlanRounds > 0 && this.planRound >= this.maxPlanRounds) {
            this.log('system', `Reached max plan rounds (${this.maxPlanRounds}).`);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE: REPORTING
    // ═══════════════════════════════════════════════════════════

    private async phaseReporting() {
        if (!this.isRunning || this.isStoppedPhase()) {
            return;
        }

        this.phase = 'reporting';
        this.scanStatus.reporting();
        this.log('system', '═══ PHASE: REPORTING ═══');

        const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(this.scanId) as any[];
        this.log('agent', `Total findings: ${vulns.length}`);

        if (vulns.length > 0) {
            try {
                const vulnList = vulns.map((v: any) => `[${v.severity.toUpperCase()}] ${v.name}`).join('\n');
                const summary = await llmQueue.enqueue({
                    systemPrompt: 'You are a security report writer. Provide a concise executive summary of the penetration test findings. Include: total vulns by severity, most critical issues, and key recommendations.',
                    userPrompt: `Target: ${this.targetUrl}\nPlanning rounds completed: ${this.planRound}\nEndpoints tested: ${this.discoveredEndpoints.size}\n\nFindings:\n${vulnList}`
                });
                this.log('agent', `Executive Summary:\n${summary.text.substring(0, 500)}`);
            } catch (e: any) {
                this.log('error', `Summary generation failed: ${e.message}`);
            }
        }

        await this.delay(1000);
        this.phase = 'completed';
        this.scanStatus.completed();
        this.log('system', `\n═══ SCAN COMPLETED ═══`);
        this.log('system', `Rounds: ${this.planRound} | Endpoints: ${this.discoveredEndpoints.size} | Findings: ${vulns.length}`);

        // Cleanup browser session when scan completes
        this.cleanupBrowserSession();
    }

    // ═══════════════════════════════════════════════════════════
    //  LLM INTERACTION: PLAN / EXECUTE / REPLAN
    // ═══════════════════════════════════════════════════════════

    private async createPlan(): Promise<AttackPlan | null> {
        const decision = await this.planner.createPlan({
            systemPrompt: this.systemPromptContent,
            conversationHistory: this.conversationHistory,
            rateLimitPauseUntil: this.rateLimitPauseUntil,
            planRound: this.planRound,
            findingsCount: this.findings.length,
            endpointsSummary: this.discoveredEndpoints.size > 0
                ? Array.from(this.discoveredEndpoints).slice(0, 30).join(', ')
                : 'None yet - initial discovery needed',
            previousResults: this.stepResults.length > 0
                ? this.stepResults.slice(-10).map((result) =>
                    `Step "${result.step.objective}": ${result.step.result || 'completed'} (${result.toolResults.length} tool calls)`,
                ).join('\n')
                : 'This is the first round - no previous results.',
            authStartupSummary: this.startupAuthInventory
                ? this.buildStartupAuthSummary(this.startupAuthInventory)
                : 'No startup auth inventory was captured.',
            authStartupDirective: this.buildAuthStartupDirective(),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
            mindsetTtps: this.mindsetTTPs.length > 0
                ? mindsetService.formatTTPsForPlanning(this.mindsetTTPs)
                : 'None loaded — no past reports analyzed yet.',
        });

        if (!decision) {
            return this.createFallbackPlan();
        }

        if (decision.kind === 'complete') {
            return null;
        }

        return decision.plan;
    }

    private createFallbackPlan(): AttackPlan {
        return this.fallbackPlanner.createPlan({
            targetUrl: this.targetUrl,
            planRound: this.planRound,
            instructionAnalysis: this.instructionAnalysis,
            startupAuthInventory: this.startupAuthInventory,
            authStartupMode: this.config.authStartup?.mode || 'no_credentials',
            discoveredEndpoints: this.discoveredEndpoints,
        });
    }

    private async askLLMForStepExecution(step: PlanStep, previousResults: string[], totalActions: number): Promise<LLMResponse | null> {
        return this.planner.askForStepExecution({
            systemPrompt: this.systemPromptContent,
            conversationHistory: this.conversationHistory,
            rateLimitPauseUntil: this.rateLimitPauseUntil,
            step,
            previousResults,
            totalActions,
            budgetPressureReminder: this.getBudgetPressureReminder(totalActions),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
        });
    }

    private async shouldContinueTesting(roundResults: StepExecutionResult[]): Promise<boolean> {
        return this.planner.shouldContinueTesting({
            systemPrompt: this.systemPromptContent,
            conversationHistory: this.conversationHistory,
            rateLimitPauseUntil: this.rateLimitPauseUntil,
            roundResults,
            findings: this.findings,
            discoveredEndpoints: Array.from(this.discoveredEndpoints),
            hypothesisStatus: this.hypothesisEngine.getSummaryForPrompt(),
            coverageStatus: this.coverageTracker.getSummaryForPrompt(),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
            planRound: this.planRound,
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  TOOL EXECUTION
    // ═══════════════════════════════════════════════════════════

    private getBudgetPressureReminder(totalActions: number): string {
        return this.contextSignals.buildBudgetPressureReminder(totalActions, this.maxIterations);
    }

    private logReflection(reflection?: AgentReflection) {
        if (!reflection) return;

        const parts: string[] = [];
        if (reflection.evaluationPreviousGoal) {
            parts.push(`prev=${reflection.evaluationPreviousGoal.substring(0, 120)}`);
        }
        if (reflection.memory) {
            parts.push(`memory=${reflection.memory.substring(0, 120)}`);
        }
        if (reflection.nextGoal) {
            parts.push(`next=${reflection.nextGoal.substring(0, 120)}`);
        }

        if (parts.length > 0) {
            this.log('agent', `Reflection: ${parts.join(' | ')}`);
        }
    }

    private async executeToolCall(toolCall: ToolCall): Promise<any> {
        return this.toolDispatcher.execute(toolCall);
    }

    private async syncAuthFromBrowser(identityId: string = 'primary-user'): Promise<void> {
        await this.browserSession.syncAuthFromBrowser(identityId);
    }

    private async seedBrowserFromAuthManager(identityId: string = 'primary-user'): Promise<void> {
        await this.browserSession.seedBrowserFromAuthManager(identityId);
    }

    private async executeSendHttpRequest(toolCall: ToolCall): Promise<any> {
        return this.requestExecutor.execute(toolCall);
    }

    //  RAW HTTP REQUEST PARSER
    // ═══════════════════════════════════════════════════════════

    /**
     * Parse a raw HTTP request string (from Burp "Send to PenPard") into structured components.
     * Returns { method, url, headers, body } or null if parsing fails.
     */
    private parseRawHttpRequest(raw: string): ParsedBurpRequest | null {
        return parseRawBurpRequest(raw);
    }

    // ═══════════════════════════════════════════════════════════
    //  RESPONSE PARSING
    // ═══════════════════════════════════════════════════════════

    private parseAgentResponse(text: string): LLMResponse | null {
        return this.llmResponseParser.parseAgentResponse(text);
    }

    private extractJsonObject(text: string): any | null {
        return this.llmResponseParser.extractJsonObject(text);
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

        const result: LLMResponse = {
            thought: '',
        };

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
                args: this.coerceToolArgs(tool, context?.args ?? context?.parameters ?? context?.params ?? context?.input ?? context?.arguments ?? context ?? {}),
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
                return {
                    tool,
                    args: this.coerceToolArgs(tool, toolArgs, context),
                };
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
        return new Set([
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
        ]).has(this.canonicalizeToolName(toolName));
    }

    private firstString(...values: unknown[]): string | undefined {
        for (const value of values) {
            if (typeof value === 'string' && value.trim()) {
                return value.trim();
            }
        }
        return undefined;
    }

    // ═══════════════════════════════════════════════════════════
    //  VULNERABILITY DETECTION & SAVING
    // ═══════════════════════════════════════════════════════════

    private saveFinding(finding: any) {
        this.findingTracker.saveFinding(finding);
    }

    private analyzeResponseForVulns(action: ToolCall, response: any): void {
        this.findingTracker.analyzeResponseForVulns(action, response);
    }

    //  BROWSER TOOLS — AI-driven browser testing
    // ═══════════════════════════════════════════════════════════

    /**
     * Ensure a browser session exists and is alive.
     * If the session is dead or missing, attempt a relaunch.
     */
    private async ensureBrowserSession(): Promise<string> {
        return this.browserSession.ensureSession();
    }

    /**
     * Cleanup browser session. Safe to call multiple times.
     */
    private cleanupBrowserSession(): void {
        this.browserSession.cleanup();
    }

    /**
     * Get the current browser session ID. Exposed for show/hide API.
     */
    public getBrowserSessionId(): string | null {
        return this.browserSession.getSessionId();
    }

    // ── Browser Tool Implementations ──

    private async executeBrowserNavigate(toolCall: ToolCall): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        const url = toolCall.args?.url;
        if (!url) return { error: 'Missing required arg: url' };

        this.log('tool', `🌐 browser_navigate → ${url}`);
        const result = await browserService.executeAction(sessionId, {
            type: 'goto',
            url,
        });

        // Track the discovered endpoint + update coverage
        try {
            const pathname = new URL(url).pathname;
            this.discoveredEndpoints.add(pathname);
            this.coverageTracker.markExercisedInBrowser(pathname, 'GET');
            this.coverageTracker.inferWorkflowFromRoute(pathname);
        } catch { /* malformed URL */ }

        // Delta analysis after navigation
        this.deltaFrontendAnalysis('navigation').catch(() => { /* non-fatal */ });
        await this.syncAuthFromBrowser();

        return result;
    }

    private async executeBrowserPageState(): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        this.log('tool', '🌐 browser_get_page_state');
        const state = await browserService.getFullPageState(sessionId);

        this.browserSession.syncAuthFromPageState(state, 'primary-user');

        return {
            ...state,
            cookies: state.contextCookies || [],
            localStorage: state.localStorageData || {},
            sessionStorage: state.sessionStorageData || {},
        };
    }

    private async executeBrowserFrontendAnalysis(): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        this.log('tool', '🌐 browser_get_frontend_analysis');
        const analysis = await browserService.getFrontendAnalysis(sessionId);

        // Feed discovered endpoints into the orchestrator's tracking
        if (analysis.apiEndpoints?.length > 0) {
            analysis.apiEndpoints.forEach((ep: string) => this.discoveredEndpoints.add(ep));
        }
        await this.refreshEndpointInventory('browser-tool', false);

        return analysis;
    }

    private async executeBrowserFillSubmit(toolCall: ToolCall): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        const { fields, submit_selector } = toolCall.args || {};
        if (!fields || !Array.isArray(fields)) {
            return { error: 'Missing required arg: fields (array of {selector, value})' };
        }

        this.log('tool', `🌐 browser_fill_and_submit (${fields.length} fields)`);

        // Fill each field sequentially
        for (const field of fields) {
            if (!field.selector || field.value === undefined) continue;
            await browserService.executeAction(sessionId, {
                type: 'fill',
                selector: field.selector,
                value: String(field.value),
            });
        }

        // Submit if a selector is provided
        if (submit_selector) {
            await browserService.executeAction(sessionId, {
                type: 'click',
                selector: submit_selector,
            });
            // Wait for navigation after submit
            try {
                await browserService.executeAction(sessionId, {
                    type: 'waitForNavigation',
                    timeout: 5000,
                });
            } catch { /* navigation may not happen for AJAX forms */ }
        }

        // Return new page state after submission
        const newState = await browserService.getPageState(sessionId);

        // Delta analysis after form submission
        this.deltaFrontendAnalysis('form-submission').catch(() => { /* non-fatal */ });
        await this.syncAuthFromBrowser();

        return {
            submitted: true,
            newUrl: newState?.url || 'unknown',
            newTitle: newState?.title || '',
            forms: newState?.forms?.length || 0,
        };
    }

    private async executeBrowserEvaluateJs(toolCall: ToolCall): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        const script = toolCall.args?.script;
        if (!script) return { error: 'Missing required arg: script' };

        this.log('tool', `🌐 browser_evaluate_js (${script.substring(0, 80)}...)`);
        const result = await browserService.executeAction(sessionId, {
            type: 'evaluate',
            script,
        });
        return result;
    }

    private async executeBrowserScreenshot(): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        this.log('tool', '🌐 browser_screenshot');

        const result = await browserService.executeAction(sessionId, {
            type: 'screenshot',
        });

        return {
            captured: true,
            mimeType: result?.mimeType || 'image/png',
            sizeBytes: result?.base64?.length || 0,
            note: 'Screenshot captured and stored. Can be used as finding evidence.',
        };
    }

    private async executeBrowserCorrelateBurp(): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        this.log('tool', '🌐 browser_correlate_burp');
        const correlation = await browserService.correlateBrowserWithBurp(sessionId);

        // Track newly discovered untested endpoints
        if (correlation?.frontendOnlyEndpoints?.length > 0) {
            correlation.frontendOnlyEndpoints.forEach((ep: string) => this.discoveredEndpoints.add(ep));
            this.log('system', `Browser⇔Burp correlation: ${correlation.frontendOnlyEndpoints.length} untested endpoints found`);
        }

        return correlation;
    }

    // ═══════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════

    private async processHumanCommand(cmd: string) {
        this.log('system', `Processing operator command: ${cmd}`);
        this.conversationHistory.push({
            role: 'user',
            content: `⚠️ [OPERATOR COMMAND — HIGHEST PRIORITY] The human operator has issued the following directive. You MUST follow this immediately and override any current plan:\n\n${cmd}\n\nACKNOWLEDGE this command and adjust your next actions accordingly.`
        });
    }

    private async loadPromptTemplate(): Promise<string> {
        // Priority 1: Check if user has selected a prompt from the Prompt Library
        try {
            const { promptLibrary } = await import('../services/PromptLibraryService');
            const activePrompt = promptLibrary.getActivePromptTemplate();
            if (activePrompt && activePrompt.template) {
                logger.info(`Using Prompt Library prompt: ${activePrompt.id}`);
                return activePrompt.template;
            }
        } catch (e) {
            logger.warn('Could not load from Prompt Library, trying legacy prompts');
        }

        // Priority 2: Check legacy custom prompts (from Settings > Prompt Templates)
        try {
            const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('prompts') as any;
            if (row) {
                const prompts = JSON.parse(row.value);
                const webPrompt = prompts.find((p: any) => p.key === 'web_prompt');
                if (webPrompt?.template) return webPrompt.template;
            }
        } catch (e) {
            logger.warn('Could not load custom prompts, using default');
        }

        // Priority 3: Built-in default
        return DEFAULT_WEB_PROMPT;
    }

    private async checkLLM(): Promise<boolean> {
        try {
            const configs = llmProvider.getAllConfigs();
            const active = configs.find(c => c.is_active);
            return !!active;
        } catch { return false; }
    }

    private handleRateLimitError(e: any) {
        const errorMsg = e.message || String(e);
        if (errorMsg.includes('429') || errorMsg.includes('Too Many Requests') || errorMsg.includes('Resource exhausted')) {
            this.rateLimitPauseUntil = new Date(Date.now() + this.RATE_LIMIT_PAUSE_MS);
            this.log('error', `🚫 LLM Rate Limited! Pausing for 1 minute...`);
        }
    }

    private estimateCvss(severity: string): number {
        const scores: Record<string, number> = { 'critical': 9.5, 'high': 8.0, 'medium': 5.5, 'low': 3.0, 'info': 0.0 };
        return scores[severity?.toLowerCase()] || 5.0;
    }

    private async delay(ms: number) {
        await new Promise(r => setTimeout(r, ms));
    }
    private log(type: string, message: string) {
        this.logLedger.append(type, message);
    }

    /**
     * Flush unflushed logs to the database incrementally.
     * Safe to call multiple times - only writes entries that have not yet been persisted.
     * Returns the number of logs flushed.
     */
    public flushLogsToDB(): number {
        return this.logLedger.flushToDB();
    }

    /** Number of logs that have NOT yet been persisted to the database. */
    public get unflushedLogCount(): number {
        return this.logLedger.unflushedCount;
    }

    private saveLogs() {
        this.logLedger.persistToFile(path.join(__dirname, '../../logs', `${this.scanId}.log`));
    }

    //  PENTESTER LOOP v2: Harvest → Classify → Hypothesize → Validate
    // ═══════════════════════════════════════════════════════════

    private async deltaFrontendAnalysis(trigger: string): Promise<void> {
        const browserSessionId = this.browserSession.getSessionId();
        if (!browserSessionId) return;

        this.log('system', `🔍 Delta frontend analysis (trigger: ${trigger})`);
        try {
            const isAlive = await browserService.isSessionAlive(browserSessionId);
            if (!isAlive) return;

            const newAnalysis = await browserService.getFrontendAnalysis(browserSessionId);
            const newEndpoints = (newAnalysis.apiEndpoints || []).filter(
                (ep: string) => !this.discoveredEndpoints.has(ep)
            );

            if (newEndpoints.length > 0) {
                newEndpoints.forEach((ep: string) => {
                    this.discoveredEndpoints.add(ep);
                    this.coverageTracker.addRoute(ep, 'GET', 'frontend-js');
                });
                this.log('system', `✓ Delta analysis: ${newEndpoints.length} new endpoint(s) discovered`);
                this.conversationHistory.push({
                    role: 'user',
                    content: `[SYSTEM] Frontend analysis update (after ${trigger}): New endpoints: ${newEndpoints.join(', ')}` 
                });
            }

            // Track new frontend routes
            if (newAnalysis.frontendRoutes?.length > 0) {
                newAnalysis.frontendRoutes.forEach((r: string) => this.coverageTracker.addRoute(r, 'GET', 'frontend-js'));
            }

            if (newEndpoints.length > 0) {
                await this.refreshEndpointInventory(`delta-${trigger}`, false);
            }
        } catch (e: any) {
            this.log('error', `Delta frontend analysis failed (non-fatal): ${e.message}`);
        }
    }

    /**
     * Run a full harvest → classify → promote → hypothesize cycle.
     * Called at harvest checkpoints in the main loop.
     */
    private async runHarvestCycle(): Promise<void> {
        let targetHost = '';
        try { targetHost = new URL(this.targetUrl).hostname; } catch { return; }

        this.log('system', '═══ HARVEST CYCLE ═══');

        // 1. Harvest new requests from Burp
        const newRequests = await this.harvester.harvest(this.burp, targetHost);
        if (newRequests.length === 0) {
            this.log('system', '  No new requests harvested');
            return;
        }

        this.log('system', `  Harvested ${newRequests.length} new request(s)`);

        // 2. Update coverage from harvested requests
        for (const req of newRequests) {
            this.coverageTracker.addRoute(req.path, req.method, 'burp');
            this.coverageTracker.inferWorkflowFromRoute(req.path);
        }
        await this.refreshEndpointInventory('harvest', false);

        // 3. Promote top candidates
        const promoted = this.harvester.getPromotionCandidates(5);
        if (promoted.length > 0) {
            this.log('system', `  Promoted ${promoted.length} request(s) for active testing:`);
            for (const p of promoted) {
                this.log('system', `    → ${p.reason}`);
                this.coverageTracker.markPromoted(p.request.path, p.request.method);

                // 4. Generate hypotheses for promoted requests
                const hypotheses = this.hypothesisEngine.generateFromRequest(p.request);
                for (const h of hypotheses) {
                    this.log('system', `    ⚡ Hypothesis ${h.id}: ${h.type} on ${h.parameter || h.targetEndpoint} (confidence: ${h.confidence}%)`);
                }
            }
        } else {
            this.log('system', `  No requests scored high enough for promotion`);
        }

        // 5. Inject harvest summary into conversation
        const harvesterSummary = this.harvester.getSummary();
        const hypSummary = this.hypothesisEngine.getSummaryForPrompt();
        const covSummary = this.coverageTracker.getSummaryForPrompt();

        this.conversationHistory.push({
            role: 'user',
            content: `[SYSTEM] Harvest cycle complete:\n  Requests: ${harvesterSummary.total} total, ${harvesterSummary.promoted} promoted\n  ${hypSummary}\n  ${covSummary}`
        });
    }

    // ── Pentester Loop Tool Implementations ──

    private async executeHarvestTraffic(): Promise<any> {
        this.log('tool', '📡 harvest_traffic');
        let targetHost = '';
        try { targetHost = new URL(this.targetUrl).hostname; } catch { /* skip */ }

        const newRequests = await this.harvester.harvest(this.burp, targetHost);

        // Update coverage
        for (const req of newRequests) {
            this.coverageTracker.addRoute(req.path, req.method, 'burp');
            this.coverageTracker.inferWorkflowFromRoute(req.path);
        }

        // Auto-promote
        const promoted = this.harvester.getPromotionCandidates(5);
        for (const p of promoted) {
            this.coverageTracker.markPromoted(p.request.path, p.request.method);
            this.hypothesisEngine.generateFromRequest(p.request);
        }

        return {
            newRequests: newRequests.length,
            promoted: promoted.map(p => ({
                id: p.request.id,
                method: p.request.method,
                path: p.request.path,
                score: p.request.interestScore,
                classification: p.request.classification,
                reason: p.reason,
            })),
            summary: this.harvester.getSummary(),
        };
    }

    private async executeGetHypotheses(toolCall: ToolCall): Promise<any> {
        const status = toolCall.args?.status || 'all';
        this.log('tool', `📋 get_hypotheses (status: ${status})`);

        const hypotheses = this.hypothesisEngine.getAll(status as any);
        return {
            count: hypotheses.length,
            statusCounts: this.hypothesisEngine.getStatusCounts(),
            hypotheses: hypotheses.map(h => ({
                id: h.id,
                type: h.type,
                target: `${h.targetMethod} ${h.targetEndpoint}`,
                parameter: h.parameter,
                confidence: h.confidence,
                status: h.status,
                rationale: h.rationale.substring(0, 150),
                nextAction: h.nextAction,
                evidenceCount: h.evidence.length,
            })),
        };
    }

    private async executeGetCoverage(): Promise<any> {
        this.log('tool', '📊 get_coverage');
        return this.coverageTracker.getSummary();
    }

    private async executeRepeaterTest(toolCall: ToolCall): Promise<any> {
        const { requestId, mutations } = toolCall.args || {};
        if (!requestId) return { error: 'Missing required arg: requestId' };
        if (!mutations || !Array.isArray(mutations)) return { error: 'Missing required arg: mutations (array)' };

        const request = this.harvester.getById(requestId);
        if (!request) return { error: `Request ${requestId} not found in harvest pool. Use harvest_traffic first.` };

        this.log('tool', `🔬 repeater_test: ${request.method} ${request.path} (${mutations.length} mutation(s))`);

        const results: any[] = [];
        const defaultIdentityId = resolveAuthIdentityId(toolCall.args);
        const defaultPreserveExplicitAuth = toolCall.args?.preserveExplicitAuth === true;

        for (const mutation of mutations) {
            try {
                // Build mutated request
                const mutatedUrl = this.applyUrlMutation(request.url, mutation.parameter, mutation.newValue);
                const mutatedBody = this.applyBodyMutation(request.requestBody, mutation.parameter, mutation.newValue);
                const mutatedHeaders = { ...request.requestHeaders };
                const mutationIdentityId = typeof mutation.identityId === 'string' && mutation.identityId.trim()
                    ? mutation.identityId.trim()
                    : defaultIdentityId;

                // Apply header mutations (for auth bypass tests)
                if (mutation.parameter === 'Authorization') {
                    if (mutation.newValue) mutatedHeaders['authorization'] = mutation.newValue;
                    else delete mutatedHeaders['authorization'];
                }
                if (mutation.parameter === 'Cookie') {
                    if (mutation.newValue) mutatedHeaders['cookie'] = mutation.newValue;
                    else delete mutatedHeaders['cookie'];
                }

                const preserveExplicitAuth = defaultPreserveExplicitAuth ||
                    mutation.parameter === 'Authorization' ||
                    mutation.parameter === 'Cookie';

                const preparedRequest = this.authManager.prepareRequest(
                    mutatedHeaders,
                    mutatedBody || '',
                    mutatedUrl,
                    request.method,
                    mutationIdentityId,
                    preserveExplicitAuth,
                );

                // Send through Burp
                const response = await this.burp.callTool('send_http_request', {
                    method: request.method,
                    url: mutatedUrl,
                    headers: preparedRequest.headers,
                    body: preparedRequest.body || '',
                });

                // Build response snapshots for diffing
                const originalSnapshot: ResponseSnapshot = {
                    statusCode: request.statusCode,
                    headers: request.responseHeaders,
                    body: request.responseBody,
                    mimeType: request.mimeType,
                };

                // Parse response from Burp MCP
                const normalizedResponse = normalizeSendHttpResponse(response);
                const mutatedSnapshot: ResponseSnapshot = {
                    statusCode: normalizedResponse.statusCode,
                    headers: normalizedResponse.headers as Record<string, string>,
                    body: normalizedResponse.body.substring(0, 5000),
                };

                // Diff
                const diff = diffResponses(originalSnapshot, mutatedSnapshot);

                // Update hypothesis if linked
                if (mutation.hypothesisId) {
                    this.hypothesisEngine.updateFromDiff(mutation.hypothesisId, mutation.description, diff);
                    this.harvester.linkHypothesis(requestId, mutation.hypothesisId);
                    this.coverageTracker.markVulnTested(request.path, request.method, mutation.vulnType || 'unknown', mutation.hypothesisId);

                    // If hypothesis confirmed, save as finding
                    const hyp = this.hypothesisEngine.getById(mutation.hypothesisId);
                    if (hyp && hyp.status === 'confirmed') {
                        this.saveFinding({
                            name: `${hyp.type} - ${hyp.targetEndpoint}${hyp.parameter ? ` (${hyp.parameter})` : ''}`,
                            severity: this.hypothesisTypeToSeverity(hyp.type),
                            description: hyp.rationale,
                            evidence: hyp.evidence.map(e => `${e.action}: ${e.result}`).join('\n'),
                            endpoint: request.url,
                            method: request.method,
                            cwe: this.hypothesisTypeToCWE(hyp.type),
                        });
                    }
                }

                results.push({
                    mutation: mutation.description,
                    parameter: mutation.parameter,
                    originalValue: mutation.originalValue,
                    newValue: mutation.newValue,
                    diff: {
                        significant: diff.significant,
                        summary: diff.summary,
                        statusChange: diff.statusCodeChanged ? `${diff.originalStatus} → ${diff.mutatedStatus}` : null,
                        keywordSignals: diff.keywordSignals,
                    },
                });

            } catch (e: any) {
                results.push({
                    mutation: mutation.description,
                    error: e.message,
                });
            }
        }

        return { requestId, path: request.path, method: request.method, results };
    }

    // ── Helpers for Repeater mutations ──

    private applyUrlMutation(url: string, param: string, newValue: string): string {
        try {
            const u = new URL(url);
            if (u.searchParams.has(param)) {
                u.searchParams.set(param, newValue);
                return u.toString();
            }
            // Check path segments — replace numeric/UUID segments
            const segments = u.pathname.split('/');
            for (let i = 0; i < segments.length; i++) {
                if (param === `path_segment_${i}` || segments[i] === param) {
                    segments[i] = newValue;
                }
            }
            u.pathname = segments.join('/');
            return u.toString();
        } catch {
            return url;
        }
    }

    private applyBodyMutation(body: string, param: string, newValue: string): string {
        if (!body) return body;
        try {
            const obj = JSON.parse(body);
            if (typeof obj === 'object' && obj !== null) {
                obj[param] = newValue;
                return JSON.stringify(obj);
            }
        } catch {
            // Form-encoded
            try {
                const params = new URLSearchParams(body);
                if (params.has(param)) {
                    params.set(param, newValue);
                    return params.toString();
                }
            } catch { /* return original */ }
        }
        return body;
    }

    private hypothesisTypeToSeverity(type: string): string {
        const map: Record<string, string> = {
            'idor': 'high', 'sqli': 'critical', 'xss-reflected': 'medium', 'xss-stored': 'high',
            'auth-bypass': 'critical', 'csrf-bypass': 'medium', 'ssrf': 'high',
            'privilege-escalation': 'critical', 'mass-assignment': 'high', 'path-traversal': 'high',
            'info-disclosure': 'low', 'workflow-bypass': 'medium', 'graphql-overreach': 'medium',
            'hidden-admin': 'high', 'tenant-crossover': 'critical', 'rate-limit-bypass': 'low',
        };
        return map[type] || 'medium';
    }

    private hypothesisTypeToCWE(type: string): string {
        const map: Record<string, string> = {
            'idor': 'CWE-639', 'sqli': 'CWE-89', 'xss-reflected': 'CWE-79', 'xss-stored': 'CWE-79',
            'auth-bypass': 'CWE-287', 'csrf-bypass': 'CWE-352', 'ssrf': 'CWE-918',
            'privilege-escalation': 'CWE-269', 'mass-assignment': 'CWE-915', 'path-traversal': 'CWE-22',
            'info-disclosure': 'CWE-200', 'graphql-overreach': 'CWE-200', 'hidden-admin': 'CWE-862',
        };
        return map[type] || '';
    }

    /**
     * Get v2 pentester loop state — exposed via getState for /live endpoint.
     */
    public getPentesterLoopState(): {
        harvestedRequestCount: number;
        promotedRequestCount: number;
        hypothesisCount: Record<string, number>;
        coverageSummary: { routesSeen: number; exercised: number; promoted: number; untested: number; coveragePercentage: number };
        endpointInventory: EndpointInventorySnapshot | null;
    } {
        const harvSummary = this.harvester.getSummary();
        const covSummary = this.coverageTracker.getSummary();
        return {
            harvestedRequestCount: harvSummary.total,
            promotedRequestCount: harvSummary.promoted,
            hypothesisCount: this.hypothesisEngine.getStatusCounts(),
            coverageSummary: {
                routesSeen: covSummary.routesSeen,
                exercised: covSummary.routesExercisedInBrowser,
                promoted: covSummary.requestsPromoted,
                untested: covSummary.untestedRoutes.length,
                coveragePercentage: covSummary.coveragePercentage,
            },
            endpointInventory: this.endpointInventory,
        };
    }
}
