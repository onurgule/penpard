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
import { updateScanStatus, addVulnerability, db } from '../db/init';
import { logger, formatLogTimestamp } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { mindsetService, MindsetTTP } from '../services/mindset-service';
import { analyzeSource, buildAgentContextBlock } from '../services/source-analysis/SourceAnalysisService';
import { SourceAnalysisMode } from '../services/source-analysis/SourceAnalysisMode';
import { RequestHarvester, HarvestedRequest, PromotedRequest } from '../services/RequestHarvester';
import { HypothesisEngine, VulnHypothesis, MutationTemplate } from '../services/HypothesisEngine';
import { CoverageTracker } from '../services/CoverageTracker';
import { diffResponses, ResponseSnapshot } from '../services/ResponseDiffer';
import { browserService } from '../services/BrowserService';

type AgentPhase = 'planning' | 'executing' | 'replanning' | 'reporting' | 'completed' | 'failed' | 'stopped';

interface ScanConfig {
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
}

interface ToolCall {
    tool: string;
    args: Record<string, any>;
}

interface PlanStep {
    step: number;
    objective: string;
    approach: string;
    tools: string[];
    status: 'pending' | 'executing' | 'completed' | 'skipped';
    result?: string;
}

interface AttackPlan {
    round: number;
    analysis: string;
    steps: PlanStep[];
}

interface LLMResponse {
    thought: string;
    action?: ToolCall;
    actions?: ToolCall[];
    answer?: string;
    finding?: any;
    findings?: any[];
}

// ─────────────────────────────────────────────────────────────
// System prompt with iterative planning methodology
// ─────────────────────────────────────────────────────────────
const DEFAULT_WEB_PROMPT = `You are PenPard, an elite automated penetration tester conducting an authorized security assessment.

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
   Args: { "method": "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS", "url": "full_url", "headers": {...}, "body": "..." }
   Send any HTTP request through Burp proxy. Max 2-3 payloads per vuln type per parameter.

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
    Args: { "requestId": "req-...", "mutations": [{ "parameter": "id", "originalValue": "1", "newValue": "2", "description": "IDOR swap" }] }
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

// ─────────────────────────────────────────────────────────────
// Planning prompt templates
// ─────────────────────────────────────────────────────────────
const PLAN_PROMPT = `Based on everything you know about the target so far, create your next 5-step attack plan.
{OPERATOR_INSTRUCTIONS_REMINDER}
CURRENT STATE:
- Planning round: {ROUND}
- Total findings so far: {FINDINGS_COUNT}
- Endpoints discovered: {ENDPOINTS_SUMMARY}
- Previous plan results: {PREVIOUS_RESULTS}

LEARNED ATTACK PATTERNS (from past Red Team reports):
{MINDSET_TTPS}
If any learned patterns match discovered endpoints or parameters, PRIORITIZE testing them.
Include the TTP id in your thought when a step is derived from a learned pattern.

RULES:
1. **OPERATOR INSTRUCTIONS ARE LAW.** If operator instructions specify endpoints, vulnerability types, or scope — your ENTIRE plan MUST stay within those boundaries. Do NOT test anything outside the operator's scope. Do NOT do general recon if the operator told you exactly what to test.
2. If operator instructions specify exact endpoints and vuln types → Skip discovery. Go DIRECTLY to testing those endpoints for those vulns in Round 1. Every step should be an attack on the specified scope.
3. Each step must be concrete and actionable (specific endpoint + specific test)
4. Don't repeat tests that were already done
5. Only do discovery/mapping if NO operator instructions are present
6. If the operator says to finish after testing → respond with completion after thorough testing of the defined scope

Respond with ONLY a JSON object in this exact format:
{
  "analysis": "Brief analysis of current state and what to focus on next...",
  "plan": [
    { "step": 1, "objective": "...", "approach": "...", "tools": ["tool1", "tool2"] },
    { "step": 2, "objective": "...", "approach": "...", "tools": ["tool1"] },
    { "step": 3, "objective": "...", "approach": "...", "tools": ["tool1"] },
    { "step": 4, "objective": "...", "approach": "...", "tools": ["tool1"] },
    { "step": 5, "objective": "...", "approach": "...", "tools": ["tool1"] }
  ]
}`;

const EXECUTE_STEP_PROMPT = `You are now executing step {STEP_NUM} of the current attack plan.
{OPERATOR_INSTRUCTIONS_REMINDER}
STEP OBJECTIVE: {OBJECTIVE}
APPROACH: {APPROACH}
SUGGESTED TOOLS: {TOOLS}

Execute this step by choosing the right tool and arguments. Be precise and targeted.
IMPORTANT: If operator instructions restrict scope (specific endpoints or vuln types), ONLY test within that scope. Skip anything outside it.
If you discover a vulnerability, include a "finding" object with a DESCRIPTIVE "name" field.
The name MUST follow the pattern: "Vulnerability Type - /endpoint/path (parameter)" e.g. "Reflected XSS - /search (q parameter)" or "SQL Injection - /api/login (username)".
NEVER leave the "name" field empty or generic. Always include the specific vulnerability type AND the affected endpoint.
If you need multiple requests for this step, you'll get to continue.

Respond in JSON format with your action.`;

const REPLAN_PROMPT = `The previous plan round is complete. Review the results and create the next plan.
{OPERATOR_INSTRUCTIONS_REMINDER}
COMPLETED STEPS AND RESULTS:
{STEP_RESULTS}

ALL FINDINGS SO FAR:
{ALL_FINDINGS}

DISCOVERED ENDPOINTS:
{ENDPOINTS}

{HYPOTHESIS_STATUS}

{COVERAGE_STATUS}

Now decide: is more testing needed within the allowed scope?
- PRIORITIZE untested surface and escalated hypotheses before testing already-covered endpoints.
- Use harvest_traffic to discover new Burp-observed requests, then repeater_test for hypothesis validation.
- If operator instructions defined a specific scope and you have tested it thoroughly → FINISH. Respond with the completion JSON.
- Do NOT expand beyond operator-defined scope. Do NOT add new endpoints or vuln types that were not requested.
- If more testing is needed within scope: test different payloads, techniques, or parameters on the SAME endpoint(s).

If testing is complete, respond with:
{ "answer": "Testing complete. All major attack surfaces have been assessed." }

Otherwise, respond with a new plan JSON focused strictly on the allowed scope.`;

// ─────────────────────────────────────────────────────────────

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
    private logs: string[] = [];
    private findings: any[] = [];
    private conversationHistory: { role: string; content: string }[] = [];
    private maxIterations: number;

    // Planning state
    private currentPlan: AttackPlan | null = null;
    private planRound: number = 0;
    /** 0 = no fixed limit (model decides); otherwise max planning rounds. */
    private maxPlanRounds: number = 0;
    private discoveredEndpoints: Set<string> = new Set();
    private testedParameters: Map<string, Set<string>> = new Map(); // endpoint → set of tested vuln types
    private stepResults: { step: PlanStep; findings: any[]; toolResults: string[] }[] = [];

    // Request tracking
    private requestHistory: Map<string, { count: number; lastResponse: any; timestamp: Date }> = new Map();
    private rateLimitPauseUntil: Date | null = null;
    private readonly MAX_SAME_REQUEST = 2;
    private readonly RATE_LIMIT_PAUSE_MS = 1 * 60 * 1000;

    // Store last request/response for findings (includes raw Burp data when available)
    private lastRequestResponse: { action?: ToolCall; result?: any; rawRequest?: string; rawResponse?: string } | null = null;

    // Cached system prompt (always index 0 in conversationHistory)
    private systemPromptContent: string = '';

    // Instruction analysis — LLM-parsed understanding of operator's scan instructions
    private isFocusedScope: boolean = false;
    private instructionAnalysis: {
        is_focused: boolean;
        focused_endpoints: string[];
        focused_vulns: string[];
        skip_recon: boolean;
        auto_finish: boolean;
        summary: string;
    } | null = null;

    // Mindset library — loaded TTPs from past report analyses
    private mindsetTTPs: MindsetTTP[] = [];

    // Browser session for AI-driven browser testing
    private browserSessionId: string | null = null;
    private browserLock: boolean = false;

    // ── Pentester Loop Services (v2) ──
    private harvester: RequestHarvester;
    private hypothesisEngine: HypothesisEngine;
    private coverageTracker: CoverageTracker;
    private lastFrontendAnalysis: any = null;
    private frontendAnalysisVersion: number = 0;

    constructor(scanId: string, targetUrl: string, config: ScanConfig, burp: BurpMCPClient) {
        this.scanId = scanId;
        this.targetUrl = targetUrl;
        this.config = config;
        this.burp = burp;
        this.maxIterations = config.maxIterations ?? 50;
        // maxPlanRounds: 0 or undefined = no fixed limit (model decides)
        const requested = config.maxPlanRounds ?? 0;
        this.maxPlanRounds = requested > 0 ? requested : 0;

        // Initialize pentester loop services
        this.harvester = new RequestHarvester();
        this.hypothesisEngine = new HypothesisEngine();
        this.coverageTracker = new CoverageTracker();
    }

    /**
     * Analyze operator instructions with LLM to determine scan scope.
     * Returns structured JSON: is_focused, focused_endpoints, focused_vulns, etc.
     */
    private async analyzeOperatorInstructions(instructions: string): Promise<void> {
        this.log('system', '🔍 Analyzing operator instructions with LLM...');

        try {
            const response = await llmQueue.enqueue({
                systemPrompt: `You are an instruction parser for a penetration testing tool. Analyze the operator's scan instructions and return a JSON object. Be precise — extract exactly what the operator wants.`,
                userPrompt: `Analyze this scan instruction and return ONLY a JSON object (no markdown, no explanation):

INSTRUCTION: "${instructions}"
TARGET WEBSITE: ${this.targetUrl}

Return this exact JSON structure:
{
  "is_focused": true/false,       // true if the operator wants to test specific endpoints or specific vuln types only (not a full scan)
  "focused_endpoints": [],         // array of endpoint paths mentioned (e.g., ["/login", "/api/users"]). Empty if no specific endpoints. Include the full URL with the target domain.
  "focused_vulns": [],             // array of vulnerability types to test (e.g., ["SQL Injection", "XSS"]). Empty if no restriction.
  "skip_recon": true/false,        // true if operator specified exact endpoints (no need to discover/enumerate)
  "auto_finish": true/false,       // true if operator wants to finish after testing the specified scope (words like "then finish", "only", "just", "don't test other")
  "summary": "..."                 // one-line summary of what the operator wants
}

Examples:
- "only focus on /login endpoint and test for sql injection only, then finish" →
  {"is_focused":true,"focused_endpoints":["${this.targetUrl}/login"],"focused_vulns":["SQL Injection"],"skip_recon":true,"auto_finish":true,"summary":"Test only /login for SQL Injection, then finish"}

- "pay special attention to authentication endpoints" →
  {"is_focused":false,"focused_endpoints":[],"focused_vulns":[],"skip_recon":false,"auto_finish":false,"summary":"Full scan with extra focus on auth endpoints"}

- "test the /api/v2/users and /api/v2/orders endpoints for IDOR and access control issues" →
  {"is_focused":true,"focused_endpoints":["${this.targetUrl}/api/v2/users","${this.targetUrl}/api/v2/orders"],"focused_vulns":["IDOR","Broken Access Control"],"skip_recon":true,"auto_finish":true,"summary":"Test two API endpoints for IDOR and access control only"}

Return ONLY the JSON object.`
            });

            const parsed = this.extractJsonObject(response.text);

            if (parsed && typeof parsed.is_focused === 'boolean') {
                this.instructionAnalysis = {
                    is_focused: parsed.is_focused,
                    focused_endpoints: Array.isArray(parsed.focused_endpoints) ? parsed.focused_endpoints : [],
                    focused_vulns: Array.isArray(parsed.focused_vulns) ? parsed.focused_vulns : [],
                    skip_recon: !!parsed.skip_recon,
                    auto_finish: !!parsed.auto_finish,
                    summary: parsed.summary || '',
                };
                this.isFocusedScope = parsed.is_focused;

                this.log('system', `✅ Instruction analysis complete:`);
                this.log('system', `   Focused: ${this.isFocusedScope}`);
                if (this.instructionAnalysis.focused_endpoints.length > 0) {
                    this.log('system', `   Endpoints: ${this.instructionAnalysis.focused_endpoints.join(', ')}`);
                }
                if (this.instructionAnalysis.focused_vulns.length > 0) {
                    this.log('system', `   Vuln types: ${this.instructionAnalysis.focused_vulns.join(', ')}`);
                }
                this.log('system', `   Skip recon: ${this.instructionAnalysis.skip_recon}`);
                this.log('system', `   Auto-finish: ${this.instructionAnalysis.auto_finish}`);
                this.log('system', `   Summary: ${this.instructionAnalysis.summary}`);

                if (this.isFocusedScope) {
                    this.log('system', `🎯 FOCUSED SCOPE ACTIVE — Enumeration tools (spider, sitemap, extract_links) are BLOCKED.`);
                }
            } else {
                this.log('error', 'Failed to parse instruction analysis — treating as full scan');
                this.instructionAnalysis = null;
                this.isFocusedScope = false;
            }
        } catch (e: any) {
            this.log('error', `Instruction analysis failed: ${e.message} — treating as full scan`);
            this.instructionAnalysis = null;
            this.isFocusedScope = false;
        }
    }

    /**
     * Build the operator instructions reminder block.
     * Injected into every planning/execution/replanning prompt.
     */
    private getOperatorInstructionsReminder(): string {
        if (!this.config.customSystemPrompt) return '';

        const analysis = this.instructionAnalysis;
        if (analysis?.is_focused) {
            const endpoints = analysis.focused_endpoints.length > 0
                ? `Endpoints: ${analysis.focused_endpoints.join(', ')}`
                : '';
            const vulns = analysis.focused_vulns.length > 0
                ? `Vuln types: ${analysis.focused_vulns.join(', ')}`
                : '';
            return `
🚨 OPERATOR SCOPE LOCK (violating this = scan failure):
"${this.config.customSystemPrompt}"
${endpoints}
${vulns}
→ Do NOT test outside this scope. No recon. No enumeration. No other endpoints or vuln types.
`;
        }

        return `
📋 Operator instructions: "${this.config.customSystemPrompt}"
`;
    }

    public async start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.log('system', `Orchestrator Agent started for target: ${this.targetUrl}`);

        try {
            updateScanStatus(this.scanId, 'initializing');

            if (!this.targetUrl) {
                throw new Error('Target URL is required');
            }

            // Phase 1: Initialize
            await this.phaseInit();

            // Phase 2: Iterative Plan → Execute → Replan
            await this.phaseIterativeTesting();

            // Phase 3: Reporting
            await this.phaseReporting();

        } catch (error: any) {
            this.phase = 'failed';
            this.log('error', `Critical Failure: ${error.message}`);
            updateScanStatus(this.scanId, 'failed', error.message);
        } finally {
            this.isRunning = false;
            this.saveLogs();
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
        const extraRounds = Math.min(Math.max(opts.iterations, 1), 20); // clamp 1-20

        this.log('system', `═══ CONTINUING SCAN ═══`);
        this.log('system', `Instruction: ${opts.instruction}`);
        this.log('system', `Additional rounds: ${extraRounds}, Planning: ${opts.planningEnabled ? 'ON' : 'OFF'}`);

        try {
            updateScanStatus(this.scanId, 'testing');

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
                const accountsJson = JSON.stringify(this.config.idorUsers || [], null, 2);
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
                        sysPrompt += `\n\n═══════════════════════════════════════════════════════════════\n  SEND TO PENPARD — REQUEST FROM BURP (CRITICAL)\n═══════════════════════════════════════════════════════════════\n\nYou received a complete HTTP request from the user via Burp. STRICT RULES:\n\n1. Every send_http_request MUST include ALL headers listed below. Do NOT omit any. Do NOT add new headers. Copy them exactly.\n2. Only PARAMETRIC testing: change parameter values in the URL query string or body. Do NOT touch headers unless the user explicitly asks.\n3. The request has cookies and auth tokens — these are essential for authenticated testing.\n\nBASE REQUEST:\n  Method: ${parsed.method}\n  URL: ${parsed.url}\n  Headers (INCLUDE ALL OF THESE IN EVERY REQUEST):\n${headersBlock}\n  Body: ${parsed.body || '(none)'}\n\nWhen calling send_http_request, use:\n  { "method": "${parsed.method}", "url": "<url with modified params>", "headers": { ALL HEADERS ABOVE }, "body": "${parsed.body || ''}" }\n`;
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
                        content: `REMINDER — The original request from Burp (Send to PenPard) is still active. You MUST include ALL these headers in every send_http_request:\n\nMethod: ${parsed.method}\nURL: ${parsed.url}\nHeaders (JSON — pass this entire object):\n${headersJson}\nBody: ${parsed.body || '(none)'}\n\nDo NOT send requests without these headers. The user's session cookies and auth tokens are required.`
                    });
                    this.conversationHistory.push({
                        role: 'assistant',
                        content: `Understood. I will continue including all ${Object.keys(parsed.headers).length} headers (Cookie, auth tokens, User-Agent, etc.) in every request.`
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
                const endpointsList = this.instructionAnalysis.focused_endpoints.length > 0
                    ? `Target endpoints: ${this.instructionAnalysis.focused_endpoints.join(', ')}`
                    : 'No specific endpoints';
                const vulnsList = this.instructionAnalysis.focused_vulns.length > 0
                    ? `Vulnerability types: ${this.instructionAnalysis.focused_vulns.join(', ')}`
                    : 'All vulnerability types';
                this.isFocusedScope = true;

                this.conversationHistory.push({
                    role: 'user',
                    content: `🎯 FOCUSED SCOPE for continuation:
- ${endpointsList}
- ${vulnsList}
- Skip recon: ${this.instructionAnalysis.skip_recon ? 'YES' : 'No'}
Proceed with testing.`
                });
            }

            // Reset round counter for the continuation
            const savedRound = this.planRound;
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

            // Restore round counter
            this.planRound = savedRound + extraRounds;

            this.log('system', `═══ CONTINUATION COMPLETE ═══`);
            this.log('system', `Total findings after continuation: ${this.findings.length}`);

        } catch (error: any) {
            this.log('error', `Continuation failed: ${error.message}`);
            updateScanStatus(this.scanId, 'failed', error.message);
        } finally {
            this.isRunning = false;
            this.saveLogs();
        }
    }

    /**
     * Direct execution mode — no planning, just let LLM execute instructions with tools.
     */
    private async phaseDirectExecution(instruction: string, maxRounds: number) {
        this.phase = 'executing';
        updateScanStatus(this.scanId, 'testing');
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
                // Build context from conversation history (same pattern as createPlan/executeStep)
                const recentMessages = this.conversationHistory.slice(-12);
                const contextBlock = recentMessages.length > 0
                    ? `CONVERSATION CONTEXT:\n${recentMessages.map(m => `[${m.role.toUpperCase()}]: ${m.content}`).join('\n---\n')}\n\n---\n\n`
                    : '';

                const response = await llmQueue.enqueue({
                    systemPrompt: this.systemPromptContent,
                    userPrompt: `${contextBlock}Execute the operator's instruction. You are in round ${round + 1} of ${maxRounds}. Use tools to test and report findings.\n\nRespond with ONLY a valid JSON object containing "action" or "finding" or "answer".`,
                });

                this.conversationHistory.push({ role: 'assistant', content: response.text });

                const parsed = this.extractJsonObject(response.text);
                if (!parsed) {
                    this.log('agent', `Response: ${response.text.slice(0, 200)}`);
                    continue;
                }

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
        this.phase = 'stopped';
        this.log('system', 'Stop command received. Terminating agent...');
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
            logsCount: this.logs.length,
            findingsCount: this.findings.length,
            planRound: this.planRound,
            currentPlan: this.currentPlan,
            ...loopState,
        };
    }

    public getLogs(since: number = 0): string[] {
        return this.logs.slice(since);
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
        updateScanStatus(this.scanId, 'planning');
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

        // Run source analysis if configured
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

        // Resolve session cookies and auth for authenticated testing (from operator input or proxy history, newest to oldest)
        let sessionCookieHeader = '';
        let sessionAuthHeader = '';
        if (this.config.sessionCookies?.trim()) {
            const raw = this.config.sessionCookies.trim();
            sessionCookieHeader = raw.replace(/^Cookie:\s*/i, '').trim();
            this.log('system', '✓ Using operator-provided session cookies for authenticated requests');
        } else {
            try {
                const host = new URL(this.targetUrl).hostname;
                // First try get_cookies_and_auth_for_host (newest to oldest) for planning-phase discovery
                const historyResult = await this.burp.callTool('get_cookies_and_auth_for_host', { host, maxItems: 50 });
                const entries = Array.isArray(historyResult?.entries) ? historyResult.entries : [];
                const firstWithSession = entries.find((e: any) => (e?.cookie && e.cookie.trim()) || (e?.authorization && e.authorization.trim()));
                if (firstWithSession) {
                    if (firstWithSession.cookie && String(firstWithSession.cookie).trim()) {
                        sessionCookieHeader = String(firstWithSession.cookie).trim();
                    }
                    if (firstWithSession.authorization && String(firstWithSession.authorization).trim()) {
                        sessionAuthHeader = String(firstWithSession.authorization).trim();
                    }
                    if (sessionCookieHeader || sessionAuthHeader) {
                        this.log('system', `✓ Using cookie/auth from Burp proxy history (newest→oldest) for ${host}`);
                    }
                }
                // Fallback: single most recent request
                if (!sessionCookieHeader && !sessionAuthHeader) {
                    const result = await this.burp.callTool('get_session_cookies', { host });
                    const cookie = result?.cookieHeader;
                    if (cookie && typeof cookie === 'string' && cookie.trim()) {
                        sessionCookieHeader = cookie.trim();
                        this.log('system', `✓ Using session cookies from Burp proxy history (last user request to ${host})`);
                    }
                }
            } catch (e) {
                // Burp may be unavailable or tool not supported; continue without cookies
            }
        }
        const hasSession = !!(sessionCookieHeader || sessionAuthHeader);
        const sessionCookiesBlock = hasSession
            ? `\n\n═══════════════════════════════════════════════════════════════\n  SESSION COOKIES / AUTH FROM PROXY HISTORY (authenticated testing)\n═══════════════════════════════════════════════════════════════\n\nYou MUST send requests to the target domain WITH these headers so tests run in the user's session. Include them in EVERY send_http_request to the target host.\n\n${sessionCookieHeader ? `Cookie: ${sessionCookieHeader}\n\n` : ''}${sessionAuthHeader ? `Authorization: ${sessionAuthHeader}\n\n` : ''}In send_http_request always set headers to include the Cookie and/or Authorization above. Do not omit them. Test with the user's authenticated session.\n`
            : `\n\n═══════════════════════════════════════════════════════════════\n  SESSION COOKIES\n═══════════════════════════════════════════════════════════════\n\nNone found for target. For authenticated testing: have the user browse the site (through Burp) and log in first; PenPard will use get_session_cookies or get_cookies_and_auth_for_host. Then include that Cookie/Authorization in every send_http_request.\n`;

        // Build system prompt
        const promptTemplate = await this.loadPromptTemplate();
        const accountsJson = JSON.stringify(this.config.idorUsers || [], null, 2);
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
                systemPrompt += `\n\n═══════════════════════════════════════════════════════════════\n  SEND TO PENPARD — REQUEST FROM BURP (CRITICAL)\n═══════════════════════════════════════════════════════════════\n\nYou received a complete HTTP request from the user via Burp. STRICT RULES:\n\n1. Every send_http_request MUST include ALL headers listed below. Do NOT omit any. Do NOT add new headers. Copy them exactly.\n2. Only PARAMETRIC testing: change parameter values in the URL query string or body. Do NOT touch headers unless the user explicitly asks.\n3. The request has cookies and auth tokens — these are essential for authenticated testing.\n\nBASE REQUEST:\n  Method: ${parsed.method}\n  URL: ${parsed.url}\n  Headers (INCLUDE ALL OF THESE IN EVERY REQUEST):\n${headersBlock}\n  Body: ${parsed.body || '(none)'}\n\nWhen calling send_http_request, use:\n  { "method": "${parsed.method}", "url": "<url with modified params>", "headers": { ALL HEADERS ABOVE }, "body": "${parsed.body || ''}" }\n`;
            }
        }

        this.systemPromptContent = systemPrompt;
        this.conversationHistory.push({
            role: 'system',
            content: systemPrompt
        });

        this.log('system', '✓ System prompt loaded');
        await this.delay(500);

        // ── Auto-launch headless browser + frontend analysis ──
        await this.initBrowserAndAnalyze();

        // Analyze operator instructions with LLM to determine scope
        if (this.config.customSystemPrompt) {
            await this.analyzeOperatorInstructions(this.config.customSystemPrompt);
        }

        // Inject operator instructions into conversation based on analysis
        if (this.config.customSystemPrompt) {
            const instr = this.config.customSystemPrompt;
            const analysis = this.instructionAnalysis;

            if (analysis?.is_focused) {
                // Focused scope — inject strict directives
                const endpointsList = analysis.focused_endpoints.length > 0
                    ? `Target endpoints: ${analysis.focused_endpoints.join(', ')}`
                    : 'No specific endpoints — test the entire target but only for specified vuln types';
                const vulnsList = analysis.focused_vulns.length > 0
                    ? `Vulnerability types: ${analysis.focused_vulns.join(', ')}`
                    : 'All vulnerability types on the specified endpoints';

                this.conversationHistory.push({
                    role: 'user',
                    content: `🚨 MANDATORY OPERATOR INSTRUCTIONS — ABSOLUTE LAW FOR THIS SCAN 🚨

Operator's original instruction: "${instr}"

PARSED SCOPE (you MUST follow this exactly):
- ${endpointsList}
- ${vulnsList}
- Skip reconnaissance: ${analysis.skip_recon ? 'YES — go directly to testing' : 'No — do basic recon first'}
- Auto-finish when scope is tested: ${analysis.auto_finish ? 'YES' : 'No'}

ENFORCED RULES:
1. Do NOT use spider_url, get_sitemap, or extract_links — these are BLOCKED by the system.
2. Do NOT test endpoints outside the list above.
3. Do NOT test vulnerability types outside the list above.
4. Round 1 plan must DIRECTLY attack the specified targets with the specified vuln types.
5. When the specified scope is thoroughly tested, respond with completion.

Acknowledge and begin.`
                });
                this.conversationHistory.push({
                    role: 'assistant',
                    content: `Understood. Operator scope is locked:

${endpointsList}
${vulnsList}
Recon: SKIPPED — going directly to attack.
Auto-finish: ${analysis.auto_finish ? 'Yes, will complete after testing specified scope' : 'No'}

I will create a focused attack plan targeting ONLY the specified scope. Starting now.`
                });
            } else {
                // Full scan — standard injection
                this.conversationHistory.push({
                    role: 'user',
                    content: `The operator provided these general instructions for this scan:\n\n"${instr}"\n\nKeep these in mind throughout the scan. Acknowledge.`
                });
                this.conversationHistory.push({
                    role: 'assistant',
                    content: `Understood. I will keep the operator's instructions in mind: "${instr}". Proceeding with the full scan methodology.`
                });
            }

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
    "body": "${parsed.body || ''}"
  }
}

Start by sending the original request as-is to get a baseline response, then begin parametric testing.`
                });
                this.conversationHistory.push({
                    role: 'assistant',
                    content: `Understood. I will:\n1. Include ALL ${Object.keys(parsed.headers).length} headers in every request (Cookie, User-Agent, auth tokens, etc.)\n2. Only modify parameter values for testing — headers stay exactly as provided\n3. Start with a baseline request, then test each parameter for vulnerabilities\n\nLet me begin by analyzing the request and planning my tests.`
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

    // ═══════════════════════════════════════════════════════════
    //  PHASE: ITERATIVE PLAN → EXECUTE → REPLAN
    // ═══════════════════════════════════════════════════════════

    private async phaseIterativeTesting() {
        this.phase = 'planning';
        updateScanStatus(this.scanId, 'testing');
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
            const roundResults: { step: PlanStep; findings: any[]; toolResults: string[] }[] = [];

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
                        const response = await this.askLLMForStepExecution(step, stepToolResults);
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

                            // Track discovered endpoints
                            if (response.action.tool === 'send_http_request' && response.action.args?.url) {
                                try {
                                    const url = new URL(response.action.args.url);
                                    this.discoveredEndpoints.add(url.pathname);
                                } catch { /* ignore */ }
                            }

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
        this.phase = 'reporting';
        updateScanStatus(this.scanId, 'reporting');
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
        updateScanStatus(this.scanId, 'completed');
        this.log('system', `\n═══ SCAN COMPLETED ═══`);
        this.log('system', `Rounds: ${this.planRound} | Endpoints: ${this.discoveredEndpoints.size} | Findings: ${vulns.length}`);

        // Cleanup browser session when scan completes
        this.cleanupBrowserSession();
    }

    // ═══════════════════════════════════════════════════════════
    //  LLM INTERACTION: PLAN / EXECUTE / REPLAN
    // ═══════════════════════════════════════════════════════════

    private async createPlan(): Promise<AttackPlan | null> {
        try {
            if (this.rateLimitPauseUntil && new Date() < this.rateLimitPauseUntil) {
                await this.delay(30000);
                return null;
            }

            // Build context for planning
            const endpointsSummary = this.discoveredEndpoints.size > 0
                ? Array.from(this.discoveredEndpoints).slice(0, 30).join(', ')
                : 'None yet - initial discovery needed';

            const previousResults = this.stepResults.length > 0
                ? this.stepResults.slice(-10).map(r =>
                    `Step "${r.step.objective}": ${r.step.result || 'completed'} (${r.toolResults.length} tool calls)`
                ).join('\n')
                : 'This is the first round - no previous results.';

            const planPrompt = PLAN_PROMPT
                .replace('{ROUND}', String(this.planRound))
                .replace('{FINDINGS_COUNT}', String(this.findings.length))
                .replace('{ENDPOINTS_SUMMARY}', endpointsSummary)
                .replace('{PREVIOUS_RESULTS}', previousResults)
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', this.getOperatorInstructionsReminder())
                .replace('{MINDSET_TTPS}', this.mindsetTTPs.length > 0
                    ? mindsetService.formatTTPsForPlanning(this.mindsetTTPs)
                    : 'None loaded — no past reports analyzed yet.');

            this.conversationHistory.push({ role: 'user', content: planPrompt });

            // Always use the original system prompt — never let it get sliced away
            // Build context from recent conversation history, then place the plan prompt last and prominent
            const recentMessages = this.conversationHistory.slice(-14);
            const contextMessages = recentMessages.slice(0, -1); // everything except the current plan prompt
            const contextBlock = contextMessages.length > 0
                ? `CONVERSATION CONTEXT:\n${contextMessages.map(m => `[${m.role.toUpperCase()}]: ${m.content}`).join('\n---\n')}\n\n---\n\n`
                : '';

            const response = await llmQueue.enqueue({
                systemPrompt: this.systemPromptContent,
                userPrompt: `${contextBlock}${planPrompt}\n\nIMPORTANT: Respond with ONLY a valid JSON object. No markdown code fences, no explanation, no text before or after the JSON.`
            });

            this.conversationHistory.push({ role: 'assistant', content: response.text });

            // Check for completion
            let parsed = this.extractJsonObject(response.text);
            if (!parsed) {
                // Log truncated response for debugging
                this.log('warn', `Plan JSON parse failed. LLM response (first 300 chars): ${response.text.substring(0, 300)}`);

                // Retry once: ask LLM to fix its own response into valid JSON
                try {
                    this.log('system', '🔄 Retrying plan creation — asking LLM to return valid JSON...');
                    const retryResponse = await llmQueue.enqueue({
                        systemPrompt: 'You are a JSON repair assistant. The user will give you text that should be JSON. Extract or fix the JSON and return ONLY a valid JSON object. No markdown, no explanation, no code fences.',
                        userPrompt: `Fix or extract the JSON from this text. Return ONLY valid JSON:\n\n${response.text.substring(0, 2000)}`
                    });
                    parsed = this.extractJsonObject(retryResponse.text);
                } catch { /* ignore retry error */ }

                if (!parsed) {
                    this.log('error', 'Failed to parse plan JSON from LLM (even after retry)');
                    return this.createFallbackPlan();
                }
                this.log('system', '✅ JSON repair successful');
            }

            if (parsed.answer && parsed.answer.toLowerCase().includes('complete')) {
                return null; // Testing complete
            }

            if (!parsed.plan || !Array.isArray(parsed.plan) || parsed.plan.length === 0) {
                this.log('error', 'Invalid plan format from LLM');
                return this.createFallbackPlan();
            }

            const steps: PlanStep[] = parsed.plan.slice(0, 5).map((s: any, i: number) => ({
                step: i + 1,
                objective: s.objective || `Step ${i + 1}`,
                approach: s.approach || '',
                tools: Array.isArray(s.tools) ? s.tools : ['send_http_request'],
                status: 'pending' as const,
            }));

            return {
                round: this.planRound,
                analysis: parsed.analysis || '',
                steps,
            };

        } catch (e: any) {
            this.log('error', `Plan creation failed: ${e.message}`);
            this.handleRateLimitError(e);
            return this.createFallbackPlan();
        }
    }

    private createFallbackPlan(): AttackPlan {
        const baseUrl = this.targetUrl.replace(/\/$/, '');

        // Use LLM-analyzed instruction data if available
        if (this.instructionAnalysis?.is_focused) {
            const analysis = this.instructionAnalysis;
            const endpoints = analysis.focused_endpoints.length > 0
                ? analysis.focused_endpoints
                : [baseUrl];
            const vulnLabel = analysis.focused_vulns.length > 0
                ? analysis.focused_vulns.join(', ')
                : 'common vulnerabilities';

            this.log('system', `Generating focused fallback plan: ${endpoints.join(', ')} → ${vulnLabel}`);

            return {
                round: this.planRound,
                analysis: `Focused fallback: Testing ${endpoints.join(', ')} for ${vulnLabel}`,
                steps: endpoints.slice(0, 3).flatMap((ep, i) => [
                    {
                        step: i * 2 + 1,
                        objective: `Test ${ep} for ${vulnLabel}`,
                        approach: `Send targeted ${vulnLabel} payloads to ${ep}`,
                        tools: ['send_http_request', 'generate_payloads'],
                        status: 'pending' as const,
                    },
                    {
                        step: i * 2 + 2,
                        objective: `Deep scan ${ep} with Burp Scanner for ${vulnLabel}`,
                        approach: `Send ${ep} to Burp Scanner for thorough automated testing`,
                        tools: ['send_to_scanner'],
                        status: 'pending' as const,
                    },
                ]).slice(0, 5),
            };
        }

        // No operator instructions — use generic recon plan
        if (this.planRound <= 1) {
            return {
                round: this.planRound,
                analysis: 'Fallback: Initial reconnaissance plan',
                steps: [
                    { step: 1, objective: 'Check robots.txt', approach: `GET ${baseUrl}/robots.txt`, tools: ['send_http_request'], status: 'pending' },
                    { step: 2, objective: 'Check sitemap', approach: `GET ${baseUrl}/sitemap.xml`, tools: ['send_http_request'], status: 'pending' },
                    { step: 3, objective: 'Spider target', approach: 'Crawl main page for links', tools: ['spider_url'], status: 'pending' },
                    { step: 4, objective: 'Check common paths', approach: 'Test /admin, /api, /login, /.env', tools: ['send_http_request'], status: 'pending' },
                    { step: 5, objective: 'Get proxy history', approach: 'Review discovered endpoints', tools: ['get_proxy_history'], status: 'pending' },
                ],
            };
        }

        return {
            round: this.planRound,
            analysis: 'Fallback: Testing discovered endpoints',
            steps: Array.from(this.discoveredEndpoints).slice(0, 5).map((endpoint, i) => ({
                step: i + 1,
                objective: `Test ${endpoint} for common vulns`,
                approach: `Send test payloads to ${endpoint}`,
                tools: ['send_http_request', 'send_to_scanner'],
                status: 'pending' as const,
            })),
        };
    }

    private async askLLMForStepExecution(step: PlanStep, previousResults: string[]): Promise<LLMResponse | null> {
        try {
            if (this.rateLimitPauseUntil && new Date() < this.rateLimitPauseUntil) {
                await this.delay(30000);
                return null;
            }

            const contextFromPrevious = previousResults.length > 0
                ? `\n\nPREVIOUS RESULTS FOR THIS STEP:\n${previousResults.slice(-3).join('\n')}\n\nContinue testing or move to next action for this step.`
                : '';

            const stepPrompt = EXECUTE_STEP_PROMPT
                .replace('{STEP_NUM}', String(step.step))
                .replace('{OBJECTIVE}', step.objective)
                .replace('{APPROACH}', step.approach)
                .replace('{TOOLS}', step.tools.join(', '))
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', this.getOperatorInstructionsReminder())
                + contextFromPrevious;

            this.conversationHistory.push({ role: 'user', content: stepPrompt });

            // Always use the original system prompt — never let it get sliced away
            const recentMessages = this.conversationHistory.slice(-11);
            const contextMessages = recentMessages.slice(0, -1);
            const contextBlock = contextMessages.length > 0
                ? `CONVERSATION CONTEXT:\n${contextMessages.map(m => `[${m.role.toUpperCase()}]: ${m.content}`).join('\n---\n')}\n\n---\n\n`
                : '';

            const response = await llmQueue.enqueue({
                systemPrompt: this.systemPromptContent,
                userPrompt: `${contextBlock}${stepPrompt}\n\nRespond with ONLY a valid JSON object.`
            });

            this.conversationHistory.push({ role: 'assistant', content: response.text });
            return this.parseAgentResponse(response.text);

        } catch (e: any) {
            this.log('error', `Step execution LLM call failed: ${e.message}`);
            this.handleRateLimitError(e);
            return null;
        }
    }

    private async shouldContinueTesting(roundResults: { step: PlanStep; findings: any[]; toolResults: string[] }[]): Promise<boolean> {
        try {
            const stepSummary = roundResults.map(r =>
                `Step "${r.step.objective}": ${r.step.result} | Tool calls: ${r.toolResults.length} | Findings: ${r.findings.length}`
            ).join('\n');

            const allFindings = this.findings.map(f => `[${f.severity || 'MEDIUM'}] ${f.name}`).join('\n');
            const endpoints = Array.from(this.discoveredEndpoints).join(', ');

            const replanPrompt = REPLAN_PROMPT
                .replace('{STEP_RESULTS}', stepSummary)
                .replace('{ALL_FINDINGS}', allFindings || 'None yet')
                .replace('{ENDPOINTS}', endpoints || 'None discovered')
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', this.getOperatorInstructionsReminder())
                .replace('{HYPOTHESIS_STATUS}', this.hypothesisEngine.getSummaryForPrompt())
                .replace('{COVERAGE_STATUS}', this.coverageTracker.getSummaryForPrompt());

            this.conversationHistory.push({ role: 'user', content: replanPrompt });

            // Always use the original system prompt — never let it get sliced away
            const recentMessages = this.conversationHistory.slice(-11);
            const contextMessages = recentMessages.slice(0, -1);
            const contextBlock = contextMessages.length > 0
                ? `CONVERSATION CONTEXT:\n${contextMessages.map(m => `[${m.role.toUpperCase()}]: ${m.content}`).join('\n---\n')}\n\n---\n\n`
                : '';

            const response = await llmQueue.enqueue({
                systemPrompt: this.systemPromptContent,
                userPrompt: `${contextBlock}${replanPrompt}\n\nRespond with ONLY a valid JSON object.`
            });

            this.conversationHistory.push({ role: 'assistant', content: response.text });

            const parsed = this.extractJsonObject(response.text);
            if (parsed?.answer && parsed.answer.toLowerCase().includes('complete')) {
                return false;
            }

            return true; // Continue testing
        } catch (e: any) {
            this.log('error', `Replan check failed: ${e.message}`);
            // On error, continue if we haven't done much
            return this.planRound < 3;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  TOOL EXECUTION
    // ═══════════════════════════════════════════════════════════

    private async executeToolCall(toolCall: ToolCall): Promise<any> {
        this.log('tool', `Executing: ${toolCall.tool}`);

        try {
            if (this.rateLimitPauseUntil && new Date() < this.rateLimitPauseUntil) {
                const remainingMs = this.rateLimitPauseUntil.getTime() - Date.now();
                const remainingMin = Math.ceil(remainingMs / 60000);
                this.log('tool', `⏳ Rate limited - waiting ${remainingMin} more minutes`);
                return { error: `Rate limited. Waiting ${remainingMin} minutes.`, skipped: true };
            }

            // FOCUSED SCOPE GUARD: Block enumeration tools when operator specified exact targets
            if (this.isFocusedScope) {
                const blockedTools = ['spider_url', 'get_sitemap', 'extract_links'];
                if (blockedTools.includes(toolCall.tool)) {
                    this.log('tool', `🚫 BLOCKED: "${toolCall.tool}" — Operator instructions define a focused scope. Enumeration is not allowed. Go directly to the specified endpoint(s).`);
                    return {
                        error: `Tool "${toolCall.tool}" is blocked because operator instructions define a specific scope. Do NOT enumerate. Go directly to the target endpoint and test for the specified vulnerability type.`,
                        blocked: true,
                    };
                }
            }

            switch (toolCall.tool) {
                case 'send_http_request':
                    return await this.executeSendHttpRequest(toolCall);

                case 'get_proxy_history':
                    // Always exclude PenPard agent requests — only show user's real traffic
                    return await this.burp.callTool('get_proxy_history', { ...toolCall.args, excludePenPard: true });

                case 'get_session_cookies':
                    return await this.burp.callTool('get_session_cookies', { host: toolCall.args?.host || new URL(this.targetUrl).hostname });

                case 'get_cookies_and_auth_for_host':
                    return await this.burp.callTool('get_cookies_and_auth_for_host', {
                        host: toolCall.args?.host || new URL(this.targetUrl).hostname,
                        maxItems: toolCall.args?.maxItems ?? 50
                    });

                case 'send_to_scanner':
                    return await this.burp.callTool('send_to_scanner', toolCall.args);

                case 'get_sitemap':
                    return await this.burp.callTool('get_sitemap', toolCall.args || {});

                case 'spider_url':
                    return await this.burp.callTool('spider_url', toolCall.args);

                case 'check_authorization':
                    return await this.burp.callTool('check_authorization', toolCall.args);

                case 'generate_payloads':
                    return await this.burp.callTool('generate_payloads', toolCall.args);

                case 'extract_links':
                    return await this.burp.callTool('extract_links', toolCall.args);

                case 'analyze_response':
                    return { status: 'Analysis requested - handled by LLM' };

                // ── Browser Tools ──
                case 'browser_navigate':
                    return await this.executeBrowserNavigate(toolCall);

                case 'browser_get_page_state':
                    return await this.executeBrowserPageState();

                case 'browser_get_frontend_analysis':
                    return await this.executeBrowserFrontendAnalysis();

                case 'browser_fill_and_submit':
                    return await this.executeBrowserFillSubmit(toolCall);

                case 'browser_evaluate_js':
                    return await this.executeBrowserEvaluateJs(toolCall);

                case 'browser_screenshot':
                    return await this.executeBrowserScreenshot();

                case 'browser_correlate_burp':
                    return await this.executeBrowserCorrelateBurp();

                // ── Pentester Loop Tools (v2) ──
                case 'harvest_traffic':
                    return await this.executeHarvestTraffic();

                case 'get_hypotheses':
                    return await this.executeGetHypotheses(toolCall);

                case 'get_coverage':
                    return await this.executeGetCoverage();

                case 'repeater_test':
                    return await this.executeRepeaterTest(toolCall);

                case 'none':
                    return { status: 'No tool call (step complete)' };

                default:
                    this.log('error', `Unknown tool: ${toolCall.tool}`);
                    return { error: `Unknown tool: ${toolCall.tool}. Available: send_http_request, get_proxy_history, get_session_cookies, send_to_scanner, get_sitemap, spider_url, check_authorization, generate_payloads, extract_links, browser_navigate, browser_get_page_state, browser_get_frontend_analysis, browser_fill_and_submit, browser_evaluate_js, browser_screenshot, browser_correlate_burp, harvest_traffic, get_hypotheses, get_coverage, repeater_test` };
            }
        } catch (e: any) {
            this.log('error', `Tool error: ${e.message}`);
            return { error: e.message };
        }
    }

    private async executeSendHttpRequest(toolCall: ToolCall): Promise<any> {
        const url = toolCall.args.url;
        const method = toolCall.args.method || 'GET';

        // Block SQLMap-style UNION SELECT null enumeration
        const decodedUrl = (() => { try { return decodeURIComponent(url); } catch { return url; } })();
        const unionNullMatch = decodedUrl.match(/union\s+select\s+null(?:,\s*null)*/gi);
        if (unionNullMatch) {
            const nullCount = (unionNullMatch[0].match(/null/gi) || []).length;
            if (nullCount >= 5) {
                this.log('tool', `⚠️ Blocked SQLMap-style payload (${nullCount} nulls). Use send_to_scanner.`);
                const baseUrl = url.split('?')[0];
                return {
                    error: `SQLMap-style fuzzing blocked. Use send_to_scanner with ${baseUrl} instead.`,
                    blocked: true,
                    suggestion: { tool: 'send_to_scanner', args: { url: baseUrl } }
                };
            }
        }

        // Build a key from the full request signature: method + url + body + headers
        // Only skip truly identical requests (same URL, same params, same body)
        const body = toolCall.args.body || toolCall.args.data || '';
        const headers = toolCall.args.headers ? JSON.stringify(toolCall.args.headers, Object.keys(toolCall.args.headers).sort()) : '';
        const requestKey = `${method}:${url}:${typeof body === 'string' ? body : JSON.stringify(body)}:${headers}`;

        // Check for duplicate requests - only exact same request
        const existing = this.requestHistory.get(requestKey);
        if (existing && existing.count >= this.MAX_SAME_REQUEST) {
            this.log('tool', `⚠️ Skipping exact duplicate request (${existing.count}x): ${method} ${url.substring(0, 80)}`);
            return {
                ...existing.lastResponse,
                cached: true,
                message: `Cached response. This exact request was sent ${existing.count} times already. Try different parameters or payloads.`
            };
        }

        const result = await this.burp.callTool('send_http_request', {
            ...toolCall.args,
            use_proxy: true,
            penpard_source: `Orchestrator/${this.scanId}`
        });

        // Track request
        this.requestHistory.set(requestKey, {
            count: (existing?.count || 0) + 1,
            lastResponse: result,
            timestamp: new Date()
        });

        // Fetch the actual raw request/response from Burp proxy history
        // This captures ALL headers (Host, Cookie, User-Agent, etc.) as Burp sees them
        let rawRequest: string | undefined;
        let rawResponse: string | undefined;
        try {
            // Small delay to ensure Burp has logged the request
            await this.delay(200);
            const proxyHistory = await this.burp.callTool('get_proxy_history', {
                count: 1,
                includeDetails: true,
                urlRegex: url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\?.*/, ''), // match base URL
            });

            if (proxyHistory && Array.isArray(proxyHistory) && proxyHistory.length > 0) {
                const entry = proxyHistory[0];
                if (entry.request) rawRequest = entry.request;
                if (entry.response) rawResponse = entry.response;
            } else if (proxyHistory?.items && Array.isArray(proxyHistory.items) && proxyHistory.items.length > 0) {
                const entry = proxyHistory.items[0];
                if (entry.request) rawRequest = entry.request;
                if (entry.response) rawResponse = entry.response;
            }
        } catch (e: any) {
            // Non-critical — fall back to reconstructed request
            this.log('debug', `Could not fetch raw proxy data: ${e.message}`);
        }

        // Store for findings — includes raw Burp data when available
        this.lastRequestResponse = { action: toolCall, result, rawRequest, rawResponse };

        // Track endpoint
        try {
            const parsedUrl = new URL(url);
            this.discoveredEndpoints.add(parsedUrl.pathname);
        } catch { /* ignore */ }

        // Check for 429
        if (result?.status === 429 || result?.statusCode === 429) {
            this.rateLimitPauseUntil = new Date(Date.now() + this.RATE_LIMIT_PAUSE_MS);
            this.log('tool', `🚫 429 Rate Limited! Pausing for 1 minute...`);
            return { ...result, rateLimited: true, message: 'Rate limited. Pausing 1 minute.' };
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════
    //  RAW HTTP REQUEST PARSER
    // ═══════════════════════════════════════════════════════════

    /**
     * Parse a raw HTTP request string (from Burp "Send to PenPard") into structured components.
     * Returns { method, url, headers, body } or null if parsing fails.
     */
    private parseRawHttpRequest(raw: string): { method: string; url: string; headers: Record<string, string>; body: string } | null {
        try {
            // Normalize line endings
            const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            const headerBodySplit = normalized.indexOf('\n\n');
            const headerSection = headerBodySplit >= 0 ? normalized.substring(0, headerBodySplit) : normalized;
            const body = headerBodySplit >= 0 ? normalized.substring(headerBodySplit + 2).trim() : '';

            const lines = headerSection.split('\n');
            if (lines.length < 1) return null;

            // Parse request line: GET /path?query HTTP/1.1
            const requestLine = lines[0].trim();
            const parts = requestLine.split(/\s+/);
            if (parts.length < 2) return null;
            const method = parts[0].toUpperCase();
            const pathAndQuery = parts[1]; // e.g. /hafifmuzik/mobile/video/likestatus?idlist=...

            // Parse headers
            const headers: Record<string, string> = {};
            let host = '';
            for (let i = 1; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                const colonIdx = line.indexOf(':');
                if (colonIdx <= 0) continue;
                const name = line.substring(0, colonIdx).trim();
                const value = line.substring(colonIdx + 1).trim();
                headers[name] = value;
                if (name.toLowerCase() === 'host') {
                    host = value;
                }
            }

            if (!host) return null;

            // Determine scheme (assume https unless port is 80 or explicit http)
            const isHttp = host.endsWith(':80') || host.startsWith('http://');
            const scheme = isHttp ? 'http' : 'https';
            const cleanHost = host.replace(/^https?:\/\//, '');
            const url = `${scheme}://${cleanHost}${pathAndQuery}`;

            return { method, url, headers, body };
        } catch (e) {
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  RESPONSE PARSING
    // ═══════════════════════════════════════════════════════════

    private parseAgentResponse(text: string): LLMResponse | null {
        this.log('debug', `LLM Response: ${text.substring(0, 300)}...`);

        try {
            const jsonObj = this.extractJsonObject(text);
            if (jsonObj) {
                const normalized = this.normalizeResponse(jsonObj);
                if (normalized) return normalized;
            }

            // Fallback: extract URL from text
            const urlMatch = text.match(/https?:\/\/[^\s"'<>]+/);
            if (urlMatch) {
                const methodMatch = text.match(/\b(GET|POST|PUT|DELETE|PATCH)\b/i);
                return {
                    thought: text.substring(0, 150),
                    action: {
                        tool: 'send_http_request',
                        args: { url: urlMatch[0], method: methodMatch ? methodMatch[1].toUpperCase() : 'GET' }
                    }
                };
            }

            // Fallback tool detection from plain text — skip enumeration tools in focused scope
            if (!this.isFocusedScope) {
                if (text.toLowerCase().includes('proxy history') || text.toLowerCase().includes('get_proxy_history')) {
                    return { thought: text.substring(0, 150), action: { tool: 'get_proxy_history', args: { count: 20, excludePenPard: true } } };
                }

                if (text.toLowerCase().includes('sitemap') || text.toLowerCase().includes('get_sitemap')) {
                    return { thought: text.substring(0, 150), action: { tool: 'get_sitemap', args: {} } };
                }

                if (text.toLowerCase().includes('spider') || text.toLowerCase().includes('crawl')) {
                    return { thought: text.substring(0, 150), action: { tool: 'spider_url', args: { url: this.targetUrl } } };
                }
            }

            return { thought: text.substring(0, 500) };
        } catch (e) {
            this.log('error', `Parse error: ${(e as any).message}`);
            return { thought: text.substring(0, 500) };
        }
    }

    private extractJsonObject(text: string): any | null {
        // Step 1: Strip markdown code fences (```json ... ``` or ``` ... ```)
        let cleaned = text;
        const codeBlockMatch = cleaned.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
        if (codeBlockMatch) {
            cleaned = codeBlockMatch[1].trim();
        }

        // Step 2: Try direct JSON.parse first (works when LLM returns clean JSON)
        try {
            const trimmed = cleaned.trim();
            if (trimmed.startsWith('{')) {
                return JSON.parse(trimmed);
            }
        } catch { /* fall through to bracket-matching */ }

        // Step 3: Bracket-matching extraction (handles text before/after JSON)
        const startIdx = cleaned.indexOf('{');
        if (startIdx === -1) return null;

        let depth = 0;
        let inString = false;
        let escaped = false;

        for (let i = startIdx; i < cleaned.length; i++) {
            const char = cleaned[i];

            if (escaped) { escaped = false; continue; }
            if (char === '\\') { escaped = true; continue; }
            if (char === '"' && !escaped) { inString = !inString; continue; }
            if (inString) continue;

            if (char === '{') depth++;
            if (char === '}') {
                depth--;
                if (depth === 0) {
                    const jsonStr = cleaned.substring(startIdx, i + 1);
                    try {
                        return JSON.parse(jsonStr);
                    } catch {
                        // Try next JSON object in the text
                        const remaining = cleaned.substring(i + 1);
                        return this.extractJsonObject(remaining);
                    }
                }
            }
        }

        // Step 4: Last resort — try to fix common LLM JSON issues (trailing commas, single quotes)
        try {
            const fixable = cleaned.substring(startIdx)
                .replace(/,\s*}/g, '}')
                .replace(/,\s*]/g, ']')
                .replace(/'/g, '"');
            const lastBrace = fixable.lastIndexOf('}');
            if (lastBrace !== -1) {
                return JSON.parse(fixable.substring(0, lastBrace + 1));
            }
        } catch { /* give up */ }

        return null;
    }

    private normalizeResponse(obj: any): LLMResponse | null {
        if (!obj) return null;

        const result: LLMResponse = {
            thought: obj.thought || obj.purpose || obj.reasoning || obj.analysis || ''
        };

        if (obj.finding) result.finding = obj.finding;
        if (obj.findings) result.findings = obj.findings;
        if (obj.answer) result.answer = obj.answer;

        // Handle action formats
        if (obj.action) {
            if (typeof obj.action === 'string') {
                const toolName = obj.action.toLowerCase();
                const args = obj.parameters || obj.params || obj.args || {};
                if (args.url || args.target || args.endpoint) {
                    result.action = {
                        tool: toolName,
                        args: {
                            url: args.url || args.target || args.endpoint,
                            method: (args.method || 'GET').toUpperCase(),
                            headers: args.headers || {},
                            body: args.body || args.data || ''
                        }
                    };
                } else if (toolName === 'get_proxy_history') {
                    result.action = { tool: 'get_proxy_history', args: { count: args.count || 20, excludePenPard: true } };
                } else {
                    result.action = { tool: toolName, args };
                }
            } else if (typeof obj.action === 'object' && obj.action.tool) {
                result.action = obj.action;
            }
        }

        if (!result.action && obj.tool) {
            result.action = { tool: obj.tool, args: obj.args || obj.parameters || {} };
        }

        if (result.thought || result.action || result.answer || result.finding || result.findings) {
            return result;
        }
        return null;
    }

    // ═══════════════════════════════════════════════════════════
    //  VULNERABILITY DETECTION & SAVING
    // ═══════════════════════════════════════════════════════════

    private saveFinding(finding: any) {
        if (!finding || typeof finding !== 'object') {
            this.log('debug', 'Skipping invalid finding (not an object)');
            return;
        }

        // Build a name if missing or generic
        if (!finding.name || finding.name === 'Security Issue' || finding.name === 'Vulnerability Found') {
            // Determine vulnerability type from all available fields
            const typeFromFields = finding.type || finding.vulnerability || finding.title || '';
            const cweToType: Record<string, string> = {
                'CWE-79': 'Cross-Site Scripting (XSS)', 'CWE-89': 'SQL Injection', 'CWE-22': 'Path Traversal',
                'CWE-78': 'Command Injection', 'CWE-918': 'SSRF', 'CWE-352': 'CSRF', 'CWE-287': 'Authentication Bypass',
                'CWE-639': 'IDOR', 'CWE-601': 'Open Redirect', 'CWE-200': 'Information Disclosure',
                'CWE-311': 'Missing Encryption', 'CWE-434': 'Unrestricted File Upload', 'CWE-502': 'Deserialization',
                'CWE-611': 'XXE', 'CWE-94': 'Code Injection', 'CWE-862': 'Missing Authorization',
            };
            const typeFromCwe = finding.cwe ? cweToType[finding.cwe] || '' : '';

            // Extract type from description/evidence keywords
            let typeFromDesc = '';
            const descText = ((finding.description || '') + ' ' + (finding.evidence || '')).toLowerCase();
            const descPatterns: [string, RegExp][] = [
                ['SQL Injection', /sql\s*inject|sqli|sql\s*error|database\s*error/i],
                ['Cross-Site Scripting (XSS)', /xss|cross.site.script|script.*alert|reflected.*payload/i],
                ['Path Traversal', /path\s*traversal|directory\s*traversal|lfi|local\s*file/i],
                ['Command Injection', /command\s*inject|os\s*command|cmdi|shell/i],
                ['SSRF', /ssrf|server.side\s*request/i],
                ['CSRF', /csrf|cross.site\s*request\s*forgery/i],
                ['IDOR', /idor|insecure\s*direct\s*object/i],
                ['Open Redirect', /open\s*redirect/i],
                ['Information Disclosure', /information\s*disclos|sensitive\s*data|stack\s*trace|debug|error\s*message/i],
                ['Authentication Bypass', /auth.*bypass|broken\s*auth/i],
                ['Missing Security Headers', /security\s*header|x-frame|hsts|csp|x-content/i],
                ['Insecure Cookie', /cookie.*secure|httponly|samesite/i],
            ];
            for (const [label, regex] of descPatterns) {
                if (regex.test(descText)) { typeFromDesc = label; break; }
            }

            const vulnType = typeFromFields || typeFromCwe || typeFromDesc || 'Security Issue';

            // Determine endpoint from all available fields
            let endpoint = finding.endpoint || finding.url || finding.path || finding.location || '';
            if (!endpoint && finding.request) {
                // Extract URL path from request string like "GET /api/foo HTTP/1.1"
                const reqMatch = String(finding.request).match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
                if (reqMatch) endpoint = reqMatch[1];
            }
            if (!endpoint && this.lastRequestResponse?.action?.args?.url) {
                endpoint = this.lastRequestResponse.action.args.url;
            }
            // Trim to path only (remove host/query for readability)
            if (endpoint) {
                try {
                    const u = new URL(endpoint.startsWith('http') ? endpoint : `https://x${endpoint}`);
                    endpoint = u.pathname + (u.search ? u.search.substring(0, 40) : '');
                } catch { /* keep as-is */ }
            }

            const param = finding.parameter || finding.param || '';

            finding.name = endpoint
                ? `${vulnType} - ${endpoint}${param ? ` (${param})` : ''}`
                : `${vulnType}`;

            this.log('debug', `Finding had no/generic name, generated: ${finding.name}`);
        }

        // Deduplicate
        const name = String(finding.name);
        const vulnType = name.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
        const endpoint = name.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';
        const existingNames = db.prepare('SELECT name FROM vulnerabilities WHERE scan_id = ?').all(this.scanId) as { name: string }[];
        const isDuplicate = existingNames.some((row) => {
            const rName = row.name || '';
            const rType = rName.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
            const rPath = rName.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';
            const typeMatch = vulnType && rType && (vulnType.includes(rType) || rType.includes(vulnType));
            const pathMatch = !endpoint || !rPath || endpoint === rPath || rPath.includes(endpoint) || endpoint.includes(rPath);
            return typeMatch && pathMatch;
        });
        if (isDuplicate) {
            this.log('debug', `Skipping duplicate finding: ${name}`);
            return;
        }

        this.log('vuln', `🚨 [${(finding.severity || 'MEDIUM').toUpperCase()}] ${name}`);

        // Fill request/response from last tool call if not provided
        let requestStr = finding.request || '';
        let responseStr = finding.response || '';

        if ((!requestStr || !responseStr) && this.lastRequestResponse) {
            const action = this.lastRequestResponse.action;
            const result = this.lastRequestResponse.result;
            const rawReq = this.lastRequestResponse.rawRequest;
            const rawRes = this.lastRequestResponse.rawResponse;

            // Priority 1: Use raw request from Burp proxy history (has ALL headers: Host, Cookie, User-Agent, etc.)
            if (!requestStr && rawReq) {
                requestStr = rawReq;
            }
            // Priority 2: Reconstruct from agent's tool call args (fallback)
            if (!requestStr && action?.args) {
                const method = action.args.method || 'GET';
                const url = action.args.url || '';
                // Build a more complete request string
                let reconstructed = `${method} ${url} HTTP/1.1\n`;
                // Add Host header from URL
                try {
                    const parsedUrl = new URL(url);
                    reconstructed += `Host: ${parsedUrl.host}\n`;
                } catch { /* ignore */ }
                // Add all headers from the tool call
                if (action.args.headers) {
                    Object.entries(action.args.headers).forEach(([key, value]) => {
                        // Don't duplicate Host header
                        if (key.toLowerCase() !== 'host') {
                            reconstructed += `${key}: ${value}\n`;
                        }
                    });
                }
                if (action.args.body) {
                    reconstructed += `\n${action.args.body}`;
                }
                requestStr = reconstructed;
            }

            // Priority 1: Use raw response from Burp proxy history (has ALL headers)
            if (!responseStr && rawRes) {
                responseStr = rawRes;
            }
            // Priority 2: Reconstruct from tool result (fallback)
            if (!responseStr && result) {
                const statusCode = result.statusCode || result.status || 200;
                responseStr = `HTTP/1.1 ${statusCode}\n`;
                if (result.headers) {
                    if (Array.isArray(result.headers)) {
                        result.headers.forEach((header: string) => { responseStr += `${header}\n`; });
                    } else if (typeof result.headers === 'object') {
                        Object.entries(result.headers).forEach(([key, value]) => { responseStr += `${key}: ${value}\n`; });
                    }
                }
                const body = result.body_preview || result.body || '';
                if (body) { responseStr += `\n${body}`; }
            }
        }

        try {
            addVulnerability({
                scanId: this.scanId,
                name: name,
                description: String(finding.description || finding.evidence || ''),
                severity: String((finding.severity || 'medium')).toLowerCase(),
                cvssScore: this.estimateCvss(finding.severity),
                remediation: String(finding.remediation || ''),
                cwe: String(finding.cwe || ''),
                cve: String(finding.cve || ''),
                request: String(requestStr || ''),
                response: String(responseStr || ''),
                evidence: String(finding.evidence || '')
            });
            this.log('system', `✓ Finding saved to DB: ${name}`);
        } catch (dbErr: any) {
            this.log('error', `Failed to save finding to DB: ${dbErr.message}. Finding: ${JSON.stringify({ name, severity: finding.severity, cwe: finding.cwe }).substring(0, 200)}`);
        }

        // Send to Repeater
        try {
            if (this.lastRequestResponse?.action) {
                this.sendToRepeater(requestStr, name, this.lastRequestResponse.action).catch(() => { });
            }
        } catch { /* ignore repeater errors */ }

        finding.name = name;
        this.findings.push(finding);
    }

    private analyzeResponseForVulns(action: ToolCall, response: any): void {
        if (!response) return;

        const body = response.body_preview || response.body || '';
        if (!body || body.length === 0) return;

        const url = action.args?.url || '';
        const method = action.args?.method || 'GET';
        const statusCode = response.statusCode || response.status || 200;

        // Check for reflected XSS
        if (url.includes('?')) {
            const queryString = url.split('?')[1];
            const params = new URLSearchParams(queryString);

            for (const [paramName, rawPayload] of params.entries()) {
                if (!rawPayload || rawPayload.length < 3) continue;

                try {
                    const decodedPayload = decodeURIComponent(rawPayload);
                    const xssIndicators = [
                        '<script', '</script>', 'onerror=', 'onload=', 'onclick=', 'onmouseover=',
                        '<img', '<svg', '<iframe', '<body', '<input', 'javascript:', 'alert(',
                        'eval(', 'document.cookie', 'document.write'
                    ];

                    const hasXssIndicator = xssIndicators.some(ind => decodedPayload.toLowerCase().includes(ind.toLowerCase()));
                    if (!hasXssIndicator) continue;

                    const isReflected =
                        body.includes(decodedPayload) ||
                        body.includes(rawPayload) ||
                        (decodedPayload.includes('<') && body.includes('<') &&
                            decodedPayload.includes('>') && body.includes('>') &&
                            decodedPayload.length > 10 && body.includes(decodedPayload.substring(0, Math.min(20, decodedPayload.length))));

                    if (isReflected) {
                        this.log('vuln', `🚨 XSS DETECTED: Payload reflected! Parameter: ${paramName}`);

                        // Prefer raw Burp proxy data (has ALL headers: Cookie, User-Agent, etc.)
                        let reqStr = this.lastRequestResponse?.rawRequest || '';
                        if (!reqStr) {
                            reqStr = `${method} ${url} HTTP/1.1\n`;
                            try { const pu = new URL(url); reqStr += `Host: ${pu.host}\n`; } catch { }
                            if (action.args?.headers) Object.entries(action.args.headers).forEach(([k, v]) => { if (k.toLowerCase() !== 'host') reqStr += `${k}: ${v}\n`; });
                            if (action.args?.body) reqStr += `\n${action.args.body}`;
                        }

                        let resStr = this.lastRequestResponse?.rawResponse || '';
                        if (!resStr) {
                            resStr = `HTTP/1.1 ${statusCode}\n`;
                            if (response.headers && Array.isArray(response.headers)) response.headers.forEach((h: string) => { resStr += `${h}\n`; });
                            resStr += `\n${body.substring(0, 5000)}`;
                        }

                        this.saveFinding({
                            name: `Reflected XSS - ${url.split('?')[0]} (${paramName} parameter)`,
                            severity: 'high',
                            description: `XSS payload reflected without encoding in HTML response.`,
                            evidence: `Payload "${decodedPayload.substring(0, 100)}" reflected in response. Status: ${statusCode}`,
                            cwe: 'CWE-79',
                            request: reqStr,
                            response: resStr,
                            remediation: 'HTML-encode all user input. Implement Content Security Policy (CSP).'
                        });
                        return;
                    }
                } catch { continue; }
            }
        }

        // Check for SQL injection errors
        const sqlErrors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite', 'sql error', 'database error'];
        if (sqlErrors.some(err => body.toLowerCase().includes(err))) {
            const payload = action.args?.body || action.args?.url?.match(/[?&][^=]+=([^&]+)/)?.[1] || '';
            if (payload && (payload.includes("'") || payload.includes('"') || payload.includes('--'))) {
                // Prefer raw Burp proxy data (has ALL headers: Cookie, User-Agent, etc.)
                let reqStr = this.lastRequestResponse?.rawRequest || '';
                if (!reqStr) {
                    reqStr = `${method} ${url} HTTP/1.1\n`;
                    try { const pu = new URL(url); reqStr += `Host: ${pu.host}\n`; } catch { }
                    if (action.args?.headers) Object.entries(action.args.headers).forEach(([k, v]) => { if (k.toLowerCase() !== 'host') reqStr += `${k}: ${v}\n`; });
                    if (action.args?.body) reqStr += `\n${action.args.body}`;
                }

                let resStr = this.lastRequestResponse?.rawResponse || '';
                if (!resStr) {
                    resStr = `HTTP/1.1 ${statusCode}\n`;
                    if (response.headers && Array.isArray(response.headers)) response.headers.forEach((h: string) => { resStr += `${h}\n`; });
                    resStr += `\n${body.substring(0, 5000)}`;
                }

                this.saveFinding({
                    name: `SQL Injection - ${url.split('?')[0]}`,
                    severity: 'critical',
                    description: `SQL error message detected in response, indicating SQL injection vulnerability.`,
                    evidence: `SQL error: ${body.match(new RegExp(sqlErrors.find(e => body.toLowerCase().includes(e)) || '', 'i'))?.[0] || 'DB error'}`,
                    cwe: 'CWE-89',
                    request: reqStr,
                    response: resStr,
                    remediation: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.'
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  BROWSER TOOLS — AI-driven browser testing
    // ═══════════════════════════════════════════════════════════

    /**
     * Initialize headless browser and run automatic frontend analysis.
     * Called early in phaseInit() so browser intelligence informs the first planning round.
     * Non-fatal: if browser launch fails the scan continues in HTTP-only mode.
     */
    private async initBrowserAndAnalyze(): Promise<void> {
        this.log('system', '🌐 Launching headless PenPard Browser...');
        try {
            this.browserSessionId = await browserService.launchSession(1, {
                targetUrl: this.targetUrl,
                scanId: this.scanId,
                headless: true,
            });
            this.log('system', '✓ PenPard Browser: Running (headless)');
        } catch (err: any) {
            this.log('error', `Browser launch failed (non-fatal): ${err.message}`);
            this.log('system', 'Continuing without browser tools — HTTP-only mode.');
            this.browserSessionId = null;
            return;
        }

        // ── Automatic Frontend Analysis ──
        this.log('system', '🔍 Running automatic frontend analysis...');
        try {
            let browserIntelBlock = '\n\n═══════════════════════════════════════════════════════════════\n';
            browserIntelBlock += '  BROWSER INTELLIGENCE (auto-collected at scan start)\n';
            browserIntelBlock += '═══════════════════════════════════════════════════════════════\n\n';

            let hasIntel = false;

            // Frontend analysis — extract JS-embedded endpoints, tokens, routes
            try {
                const frontendAnalysis = await browserService.getFrontendAnalysis(this.browserSessionId);
                if (frontendAnalysis.apiEndpoints?.length > 0) {
                    browserIntelBlock += `API Endpoints (from JavaScript): ${frontendAnalysis.apiEndpoints.join(', ')}\n`;
                    frontendAnalysis.apiEndpoints.forEach((ep: string) => this.discoveredEndpoints.add(ep));
                    hasIntel = true;
                }
                if (frontendAnalysis.graphqlIndicators?.length > 0) {
                    browserIntelBlock += `GraphQL Indicators: ${frontendAnalysis.graphqlIndicators.join(', ')}\n`;
                    hasIntel = true;
                }
                if (frontendAnalysis.websocketUrls?.length > 0) {
                    browserIntelBlock += `WebSocket URLs: ${frontendAnalysis.websocketUrls.join(', ')}\n`;
                    hasIntel = true;
                }
                if (frontendAnalysis.csrfTokens?.length > 0) {
                    browserIntelBlock += `CSRF Tokens: ${JSON.stringify(frontendAnalysis.csrfTokens)}\n`;
                    hasIntel = true;
                }
                if (frontendAnalysis.tokenPatterns?.length > 0) {
                    browserIntelBlock += `Token Patterns: ${frontendAnalysis.tokenPatterns.join(', ')}\n`;
                    hasIntel = true;
                }
                this.log('system', `✓ Frontend analysis: ${frontendAnalysis.apiEndpoints?.length || 0} API endpoints found`);
            } catch (e: any) {
                this.log('error', `Frontend analysis failed (non-fatal): ${e.message}`);
            }

            // Page state — extract forms, links, hidden inputs
            try {
                const pageState = await browserService.getPageState(this.browserSessionId);
                if (pageState?.forms?.length > 0) {
                    browserIntelBlock += `\nForms (${pageState.forms.length} found):\n`;
                    pageState.forms.forEach((f: any) => {
                        const fields = f.fields?.map((fd: any) => `${fd.name || fd.id}(${fd.type})`).join(', ') || 'no fields';
                        browserIntelBlock += `  - ${f.method || 'GET'} ${f.action || '/'} [${fields}]\n`;
                    });
                    hasIntel = true;
                }
                this.log('system', `✓ Page state: ${pageState?.forms?.length || 0} forms, ${pageState?.links?.length || 0} links`);
            } catch (e: any) {
                this.log('error', `Page state extraction failed (non-fatal): ${e.message}`);
            }

            // Burp correlation — find untested endpoints
            try {
                const correlation = await browserService.correlateBrowserWithBurp(this.browserSessionId);
                if (correlation?.frontendOnlyEndpoints?.length > 0) {
                    browserIntelBlock += `\n⚠️ UNTESTED ENDPOINTS (found in JavaScript but NOT in Burp proxy traffic):\n`;
                    correlation.frontendOnlyEndpoints.forEach((ep: string) => {
                        browserIntelBlock += `  → ${ep}\n`;
                    });
                    browserIntelBlock += `  These are HIGH PRIORITY targets — test them!\n`;
                    hasIntel = true;
                    this.log('system', `✓ Burp correlation: ${correlation.frontendOnlyEndpoints.length} untested endpoints found`);
                } else {
                    this.log('system', '✓ Burp correlation: No untested endpoints found');
                }
            } catch (e: any) {
                this.log('error', `Burp correlation failed (non-fatal): ${e.message}`);
            }

            // Inject browser intelligence into system prompt
            if (hasIntel) {
                this.systemPromptContent += browserIntelBlock;
                // Update the already-pushed system message
                if (this.conversationHistory.length > 0 && this.conversationHistory[0].role === 'system') {
                    this.conversationHistory[0].content = this.systemPromptContent;
                }
                this.log('system', '✓ Browser intelligence injected into agent context');
            } else {
                this.log('system', 'No browser intelligence discovered at startup');
            }
        } catch (e: any) {
            this.log('error', `Automatic frontend analysis failed (non-fatal): ${e.message}`);
        }
    }

    /**
     * Ensure a browser session exists and is alive.
     * If the session is dead or missing, attempt a relaunch.
     */
    private async ensureBrowserSession(): Promise<string> {
        if (this.browserSessionId && browserService.isSessionAlive(this.browserSessionId)) {
            return this.browserSessionId;
        }

        // Session is dead or was never created — attempt relaunch
        this.log('system', '🌐 Browser session not found. Re-launching headless browser...');
        try {
            this.browserSessionId = await browserService.launchSession(1, {
                targetUrl: this.targetUrl,
                scanId: this.scanId,
                headless: true,
            });
            this.log('system', '✓ Browser re-launched successfully');
            return this.browserSessionId;
        } catch (err: any) {
            this.log('error', `Browser re-launch failed: ${err.message}`);
            throw new Error(`Browser session unavailable: ${err.message}`);
        }
    }

    /**
     * Cleanup browser session. Safe to call multiple times.
     */
    private cleanupBrowserSession(): void {
        if (this.browserSessionId) {
            const sid = this.browserSessionId;
            this.browserSessionId = null;
            browserService.closeSession(sid).catch((err: any) => {
                this.log('error', `Browser session cleanup failed (non-fatal): ${err.message}`);
            });
            this.log('system', '🌐 Browser session closed');
        }
    }

    /**
     * Get the current browser session ID. Exposed for show/hide API.
     */
    public getBrowserSessionId(): string | null {
        return this.browserSessionId;
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

        return result;
    }

    private async executeBrowserPageState(): Promise<any> {
        const sessionId = await this.ensureBrowserSession();
        this.log('tool', '🌐 browser_get_page_state');
        const state = await browserService.getPageState(sessionId);

        // Also get storage data for a complete picture
        let storageData: any = {};
        try {
            storageData = await browserService.getSessionStorageData(sessionId);
        } catch { /* non-fatal */ }

        return {
            ...state,
            cookies: storageData.contextCookies || [],
            localStorage: storageData.localStorageData || {},
            sessionStorage: storageData.sessionStorageData || {},
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
        const timestamp = formatLogTimestamp();
        const line = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
        this.logs.push(line);
        logger.info(message, { scanId: this.scanId, type });
    }

    private saveLogs() {
        try {
            const logsDir = path.join(__dirname, '../../logs');
            if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
            fs.writeFileSync(path.join(logsDir, `${this.scanId}.log`), this.logs.join('\n'));
        } catch (e) {
            logger.error('Failed to save logs', { error: (e as any).message });
        }
    }

    /** Normalize request for Repeater */
    private normalizeRequestForRepeater(raw: string): string {
        const lines = raw.split(/\r?\n/);
        const result: string[] = [];
        let bodyStart = -1;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (i === 0) { result.push(line.replace(/\s+/g, ' ').trim()); continue; }
            if (line.trim() === '') { bodyStart = i; break; }
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                const name = line.substring(0, colonIdx).trim();
                const value = line.substring(colonIdx + 1).trim().replace(/[\r\n]/g, ' ');
                const nameNormalized = name.split('-').map(p => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()).join('-');
                result.push(`${nameNormalized}: ${value}`);
            }
        }
        result.push('');
        if (bodyStart >= 0 && bodyStart < lines.length - 1) {
            result.push(lines.slice(bodyStart + 1).join('\n'));
        }
        return result.join('\r\n');
    }

    private async sendToRepeater(requestStr: string, vulnName: string, action?: ToolCall): Promise<void> {
        try {
            let host = '';
            let port = 80;
            let useHttps = false;
            let finalRequest = requestStr;

            // Priority 1: Use raw request from Burp proxy (has ALL headers: Cookie, User-Agent, etc.)
            const rawReq = this.lastRequestResponse?.rawRequest;
            if (rawReq && action?.args?.url) {
                try {
                    const url = new URL(action.args.url);
                    host = url.hostname;
                    port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                    useHttps = url.protocol === 'https:';

                    // Raw request from Burp already has the correct format with all headers
                    // Just ensure it uses relative path (not full URL) for Repeater
                    finalRequest = rawReq;
                    // If the raw request has a full URL in the request line, convert to relative path
                    const firstLine = finalRequest.split(/\r?\n/)[0];
                    const fullUrlMatch = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+https?:\/\/[^\/]+(\/[^\s]*)\s+(HTTP\/\S+)/i);
                    if (fullUrlMatch) {
                        finalRequest = `${fullUrlMatch[1]} ${fullUrlMatch[2]} ${fullUrlMatch[3]}` + finalRequest.substring(firstLine.length);
                    }
                } catch { /* fallback below */ }
            }
            // Priority 2: Reconstruct from action args (fallback)
            else if (action?.args?.url) {
                try {
                    const url = new URL(action.args.url);
                    host = url.hostname;
                    port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                    useHttps = url.protocol === 'https:';

                    const method = action.args.method || 'GET';
                    const urlPath = url.pathname + url.search;
                    const headerLines: string[] = [];
                    headerLines.push(`Host: ${host}${port !== (useHttps ? 443 : 80) ? `:${port}` : ''}`);
                    if (action.args.headers) {
                        Object.entries(action.args.headers).forEach(([key, value]) => {
                            if (key.toLowerCase() !== 'host') {
                                const v = String(value).replace(/[\r\n]/g, ' ');
                                const k = key.split('-').map(p => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()).join('-');
                                headerLines.push(`${k}: ${v}`);
                            }
                        });
                    }
                    finalRequest = `${method} ${urlPath} HTTP/1.1\r\n` + headerLines.join('\r\n') + '\r\n\r\n';
                    if (action.args.body) finalRequest += String(action.args.body).replace(/\r\n/g, '\n');
                } catch { /* fallback below */ }
            }

            if (!host) {
                const requestLines = requestStr.split('\n');
                const requestLine = requestLines[0];
                const urlMatch = requestLine.match(/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(https?:\/\/[^\s]+)/i);
                if (urlMatch) {
                    const url = new URL(urlMatch[2]);
                    host = url.hostname;
                    port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                    useHttps = url.protocol === 'https:';
                    finalRequest = requestStr.replace(urlMatch[2], url.pathname + url.search);
                } else {
                    const hostHeader = requestLines.find(line => line.toLowerCase().startsWith('host:'));
                    if (hostHeader) {
                        const hostValue = hostHeader.split(':').slice(1).join(':').trim();
                        const [hostName, portStr] = hostValue.split(':');
                        host = hostName;
                        port = portStr ? parseInt(portStr) : 80;
                        useHttps = port === 443;
                    }
                }
            }

            if (host) {
                const normalizedRequest = this.normalizeRequestForRepeater(finalRequest);
                await this.burp.callTool('send_to_repeater', {
                    host, port, useHttps,
                    request: normalizedRequest,
                    name: `${vulnName} - ${this.scanId.substring(0, 8)}`
                });
                this.log('debug', `✅ Sent to Repeater: ${vulnName}`);
            }
        } catch (error: any) {
            this.log('debug', `Repeater send failed: ${error.message}`);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  PENTESTER LOOP v2: Harvest → Classify → Hypothesize → Validate
    // ═══════════════════════════════════════════════════════════

    /**
     * Browser lock — ensures only one browser operation runs at a time.
     * Prevents race conditions during show/hide transitions.
     */
    private async withBrowserLock<T>(fn: () => Promise<T>): Promise<T> {
        if (this.browserLock) {
            throw new Error('Browser operation in progress — retry later');
        }
        this.browserLock = true;
        try {
            return await fn();
        } finally {
            this.browserLock = false;
        }
    }

    /**
     * Delta frontend analysis — re-runs analysis after state changes.
     * Captures new endpoints, tokens, and routes that appeared after navigation/form submission.
     */
    private async deltaFrontendAnalysis(trigger: string): Promise<void> {
        if (!this.browserSessionId) return;

        this.log('system', `🔍 Delta frontend analysis (trigger: ${trigger})`);
        try {
            const isAlive = await browserService.isSessionAlive(this.browserSessionId);
            if (!isAlive) return;

            const newAnalysis = await browserService.getFrontendAnalysis(this.browserSessionId);
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

            this.lastFrontendAnalysis = newAnalysis;
            this.frontendAnalysisVersion++;
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

        for (const mutation of mutations) {
            try {
                // Build mutated request
                const mutatedUrl = this.applyUrlMutation(request.url, mutation.parameter, mutation.newValue);
                const mutatedBody = this.applyBodyMutation(request.requestBody, mutation.parameter, mutation.newValue);
                const mutatedHeaders = { ...request.requestHeaders };

                // Apply header mutations (for auth bypass tests)
                if (mutation.parameter === 'Authorization') {
                    if (mutation.newValue) mutatedHeaders['authorization'] = mutation.newValue;
                    else delete mutatedHeaders['authorization'];
                }
                if (mutation.parameter === 'Cookie') {
                    if (mutation.newValue) mutatedHeaders['cookie'] = mutation.newValue;
                    else delete mutatedHeaders['cookie'];
                }

                // Send through Burp
                const response = await this.burp.callTool('send_http_request', {
                    method: request.method,
                    url: mutatedUrl,
                    headers: mutatedHeaders,
                    body: mutatedBody || '',
                });

                // Build response snapshots for diffing
                const originalSnapshot: ResponseSnapshot = {
                    statusCode: request.statusCode,
                    headers: request.responseHeaders,
                    body: request.responseBody,
                    mimeType: request.mimeType,
                };

                // Parse response from Burp MCP
                let mutatedSnapshot: ResponseSnapshot;
                try {
                    const respText = response?.content?.[0]?.text || JSON.stringify(response);
                    const respParsed = JSON.parse(respText);
                    mutatedSnapshot = {
                        statusCode: respParsed.statusCode || respParsed.status || 0,
                        headers: respParsed.headers || {},
                        body: respParsed.body || respText.substring(0, 5000),
                    };
                } catch {
                    mutatedSnapshot = {
                        statusCode: 0,
                        headers: {},
                        body: JSON.stringify(response).substring(0, 5000),
                    };
                }

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
        };
    }
}
