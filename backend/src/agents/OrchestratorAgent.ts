/**
 * PenPard Orchestrator Agent - Iterative Planning & Execution
 * 
 * This agent uses a Plan→Execute→Replan cycle:
 * 1. RECON: Gather intel about the target
 * 2. PLAN: LLM creates a 5-step attack plan
 * 3. EXECUTE: Run each step, collect results
 * 4. REPLAN: Analyze results, create next 5-step plan
 * 5. REPEAT until testing is thorough or max iterations reached
 *
 * Ownership split (post-refactor):
 *   - OrchestratorScanState: owns all mutable per-scan execution state
 *   - OrchestratorSingleAgentHarness: owns the execution loop, phase machine,
 *     pause polling, iteration counting, checkpoint scheduling
 *   - OrchestratorAgent: owns reasoning — prompt building, LLM interaction,
 *     plan creation, tool selection, finding detection, instruction analysis
 */

import { llmProvider } from '../services/LLMProviderService';
import { llmRuntime } from '../services/llm/LlmRuntime';
import { browserService } from '../services/BrowserService';
import { logger } from '../utils/logger';
import path from 'path';
import { mindsetService, MindsetTTP } from '../services/mindset-service';
import { analyzeSource, buildAgentContextBlock } from '../services/source-analysis/SourceAnalysisService';
import { SourceAnalysisMode } from '../services/source-analysis/SourceAnalysisMode';
import { AuthStateManager, AuthStartupConfig, AuthStartupInventory } from '../services/auth';
import { EndpointInventorySnapshot } from '../services/EndpointIntelligenceService';
import { ScanRuntimeCheckpoint } from '../services/runtime/ScanRuntimeCheckpointService';
import {
    buildContinuationScopeMessage,
    buildOperatorInstructionMessages,
} from '../prompts/orchestratorPrompts';
import { createBurpToolHandlers, BurpToolClient } from './orchestrator/OrchestratorBurpToolHandlers';
import { OrchestratorContinuationCoordinator, ContinuationPrepareResult } from './orchestrator/OrchestratorContinuationCoordinator';
import { OrchestratorBrowserSession } from './orchestrator/OrchestratorBrowserSession';
import { OrchestratorBrowserTools } from './orchestrator/OrchestratorBrowserTools';
import { OrchestratorContextSignals } from './orchestrator/OrchestratorContextSignals';
import { OrchestratorDomainCoordinator } from './orchestrator/OrchestratorDomainCoordinator';
import { OrchestratorFallbackPlanner } from './orchestrator/OrchestratorFallbackPlanner';
import { OrchestratorFindingTracker } from './orchestrator/OrchestratorFindingTracker';
import { OrchestratorInstructionAnalyzer } from './orchestrator/OrchestratorInstructionAnalyzer';
import { OrchestratorLogLedger } from './orchestrator/OrchestratorLogLedger';
import { OrchestratorLlmResponseParser } from './orchestrator/OrchestratorLlmResponseParser';
import { OrchestratorPlanner } from './orchestrator/OrchestratorPlanner';
import { OrchestratorRequestExecutor } from './orchestrator/OrchestratorRequestExecutor';
import { OrchestratorScanSurface } from './orchestrator/OrchestratorScanSurface';
import { buildInitialRequestContext, type OrchestratorInitialRequestContext } from './orchestrator/OrchestratorInitialRequestContext';
import { OrchestratorSingleAgentHarness, HarnessAgentContract } from './orchestrator/OrchestratorSingleAgentHarness';
import { OrchestratorScanState } from './orchestrator/OrchestratorScanState';
import { OrchestratorPersistenceSeam } from './orchestrator/OrchestratorPersistenceSeam';
import { OrchestratorSystemPromptBuilder } from './orchestrator/OrchestratorSystemPromptBuilder';
import { OrchestratorToolDispatcher } from './orchestrator/OrchestratorToolDispatcher';
import { OrchestratorToolRegistry } from './orchestrator/OrchestratorToolRegistry';
import { OrchestratorScanStatus } from './orchestrator/OrchestratorScanStatus';
import type { OrchestratorScanStatusOverrides } from './orchestrator/OrchestratorScanStatus';
import { safeSnippetForLog, summarizeToolCallForLog } from './orchestrator/OrchestratorSafeLogging';
import { evaluateToolExecutionGuard, resolveAuthIdentityId } from './orchestrator/OrchestratorToolPolicy';
import { buildPromptIdentityContext } from '../services/prompt-data-minimization';
import { ScopedMissionPolicy } from '../services/runtime/ScopedMissionPolicy';
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
    /** Optional scoped mission runtime policy for bounded exploratory launches. */
    scopedMissionPolicy?: ScopedMissionPolicy;
    /** Optional status remapping for runtimes that reuse the exploratory agent under a different lifecycle. */
    statusOverrides?: OrchestratorScanStatusOverrides;
}

interface ContinueScanOptions {
    instruction: string;
    iterations: number;
    planningEnabled: boolean;
    existingFindings?: any[];
    existingEndpoints?: string[];
    existingLogs?: string[];
}

interface OrchestratorAgentHooks {
    checkpoint?: (checkpoint: ScanRuntimeCheckpoint) => void | Promise<void>;
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
   Args: { "method": "GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS", "url": "full_url", "headers": {...}, "body": "...", "identityId": "primary-user|idor-user-1|__none__", "preserveExplicitAuth": true|false, "useInitialRequestBaseline": true|false, "queryMutations": [...], "bodyMutations": [...] }
   Send any HTTP request through Burp proxy. Auth is injected automatically unless preserveExplicitAuth=true. When replaying a Burp-originated baseline request, set useInitialRequestBaseline=true and prefer queryMutations/bodyMutations over reconstructing the raw request.
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
    private burp: BurpToolClient;

    // ── State container — owns all mutable per-scan state ──
    public readonly state: OrchestratorScanState;

    // Incremental log persistence — flush to DB periodically to survive crashes
    private readonly logLedger: OrchestratorLogLedger;

    // Instruction analysis — LLM-parsed understanding of operator's scan instructions
    private isFocusedScope: boolean = false;
    private instructionAnalysis: InstructionAnalysis | null = null;

    // Mindset library — loaded TTPs from past report analyses
    private mindsetTTPs: MindsetTTP[] = [];

    // ── Auth State Engine ──
    public authManager: AuthStateManager;

    // ── Extracted collaborators ──
    private readonly llmResponseParser: OrchestratorLlmResponseParser;
    private readonly instructionAnalyzer: OrchestratorInstructionAnalyzer;
    private readonly contextSignals: OrchestratorContextSignals;
    private readonly planner: OrchestratorPlanner;
    private readonly fallbackPlanner: OrchestratorFallbackPlanner;
    private readonly browserSession: OrchestratorBrowserSession;
    private readonly browserTools: OrchestratorBrowserTools;
    private readonly scanSurface: OrchestratorScanSurface;
    private readonly requestExecutor: OrchestratorRequestExecutor;
    private readonly findingTracker: OrchestratorFindingTracker;
    private readonly scanStatus: OrchestratorScanStatus;
    private readonly toolDispatcher: OrchestratorToolDispatcher;
    private readonly toolRegistry: OrchestratorToolRegistry;
    private readonly harness: OrchestratorSingleAgentHarness<ContinueScanOptions>;
    private readonly initialRequestContext: OrchestratorInitialRequestContext | null;
    private readonly domainCoordinator: OrchestratorDomainCoordinator;
    private readonly persistence: OrchestratorPersistenceSeam;
    private readonly systemPromptBuilder: OrchestratorSystemPromptBuilder;
    private readonly continuationCoordinator: OrchestratorContinuationCoordinator;
    private lastContinuationResult: ContinuationPrepareResult | null = null;

    private readonly RATE_LIMIT_PAUSE_MS = 1 * 60 * 1000;

    constructor(
        scanId: string,
        targetUrl: string,
        config: ScanConfig,
        burp: BurpToolClient,
        private readonly hooks: OrchestratorAgentHooks = {},
    ) {
        this.scanId = scanId;
        this.targetUrl = targetUrl;
        this.config = config;
        this.burp = burp;

        // ── Initialize state container ──
        const maxIterations = config.maxIterations ?? 50;
        const requested = config.maxPlanRounds ?? 0;
        const maxPlanRounds = requested > 0 ? requested : 0;
        this.state = new OrchestratorScanState({ maxIterations, maxPlanRounds });

        this.logLedger = new OrchestratorLogLedger({ scanId });
        this.persistence = new OrchestratorPersistenceSeam();
        this.systemPromptBuilder = new OrchestratorSystemPromptBuilder(this.persistence);
        this.initialRequestContext = config.initialRequest?.trim()
            ? buildInitialRequestContext(config.initialRequest.trim())
            : null;

        // Initialize auth state engine
        this.authManager = new AuthStateManager(scanId, targetUrl);

        // Initialize domain coordinator (owns harvester, hypothesis engine, coverage tracker)
        this.domainCoordinator = new OrchestratorDomainCoordinator({
            targetUrl,
            burp,
            authManager: this.authManager,
            log: (channel, message) => this.log(channel, message),
            scopePolicy: config.scopedMissionPolicy,
            onEndpointDiscovered: (_path, _method, source) => {
                if (source === 'harvest-refresh') {
                    void this.scanSurface.refreshEndpointInventory('harvest', false);
                }
            },
            onCheckpoint: (reason) => this.persistRuntimeCheckpoint(reason),
            onHypothesisConfirmed: (finding) => this.saveFinding(finding),
        });

        this.browserSession = new OrchestratorBrowserSession({
            userId: config.userId,
            targetUrl,
            scanId,
            authManager: this.authManager,
            browser: browserService,
            log: (channel, message) => this.log(channel, message),
        });
        this.scanSurface = new OrchestratorScanSurface({
            scanId,
            userId: config.userId,
            targetUrl,
            burp,
            authManager: this.authManager,
            browserSession: this.browserSession,
            coverageTracker: this.domainCoordinator.coverageTracker,
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
                this.state.setRateLimitPauseUntil(until);
            },
            onRequestAftermath: (aftermath) => {
                this.scanSurface.recordRequestExecution({
                    url: aftermath.url,
                    method: aftermath.method,
                    statusCode: aftermath.statusCode,
                });
                this.config.scopedMissionPolicy?.recordExecutedRequest(aftermath);
            },
            onManagedAuthRefreshed: (identityId) => this.browserSession.seedBrowserFromAuthManager(identityId),
        });
        this.findingTracker = new OrchestratorFindingTracker({
            scanId,
            burp,
            log: (channel, message) => this.log(channel as any, message),
            getLastExchange: () => this.requestExecutor.getLastExchange(),
            onFindingSaved: (finding) => {
                this.state.pushFinding(finding);
                this.config.scopedMissionPolicy?.recordFinding(finding);
            },
        });
        this.scanStatus = new OrchestratorScanStatus(scanId, undefined, config.statusOverrides);
        this.browserTools = new OrchestratorBrowserTools({
            browserSession: this.browserSession,
            scanSurface: this.scanSurface,
            browser: browserService,
            log: (channel, message) => this.log(channel, message),
            onFrontendDelta: (trigger, newEndpoints) => {
                this.state.pushMessage({
                    role: 'user',
                    content: `[SYSTEM] Frontend analysis update (after ${trigger}): New endpoints: ${newEndpoints.join(', ')}`,
                });
            },
        });
        // Burp passthrough handlers are created by the extracted factory
        const burpHandlers = createBurpToolHandlers({ burp, targetUrl });
        this.toolRegistry = new OrchestratorToolRegistry({
            handlers: {
                // Burp passthrough tools (owned by OrchestratorBurpToolHandlers)
                ...burpHandlers,
                // Request executor (owns auth-aware HTTP dispatch)
                send_http_request: (toolCall) => this.requestExecutor.execute(toolCall as ToolCall<'send_http_request'>),
                // Browser tools (owned by OrchestratorBrowserTools)
                browser_navigate: (toolCall) => this.browserTools.navigate(toolCall as ToolCall<'browser_navigate'>),
                browser_get_page_state: () => this.browserTools.getPageState(),
                browser_get_frontend_analysis: () => this.browserTools.getFrontendAnalysis(),
                browser_fill_and_submit: (toolCall) => this.browserTools.fillAndSubmit(toolCall as ToolCall<'browser_fill_and_submit'>),
                browser_evaluate_js: (toolCall) => this.browserTools.evaluateJs(toolCall as ToolCall<'browser_evaluate_js'>),
                browser_screenshot: () => this.browserTools.screenshot(),
                browser_correlate_burp: () => this.browserTools.correlateBurp(),
                // Domain engines (owned by OrchestratorDomainCoordinator)
                harvest_traffic: () => this.domainCoordinator.executeHarvestTraffic(),
                get_hypotheses: (toolCall) => this.domainCoordinator.executeGetHypotheses(toolCall as ToolCall<'get_hypotheses'>),
                get_coverage: () => this.domainCoordinator.executeGetCoverage(),
                repeater_test: (toolCall) => this.domainCoordinator.executeRepeaterTest(toolCall as ToolCall<'repeater_test'>),
            },
        });
        this.llmResponseParser = new OrchestratorLlmResponseParser(
            targetUrl,
            () => this.isFocusedScope,
            this.toolRegistry,
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
        this.toolDispatcher = new OrchestratorToolDispatcher({
            log: (channel, message) => this.log(channel as any, message),
            guard: (toolCall) => {
                const guardResult = evaluateToolExecutionGuard({
                    toolName: toolCall.tool,
                    toolArgs: toolCall.args,
                    isFocusedScope: this.isFocusedScope,
                    scopePolicy: this.config.scopedMissionPolicy,
                    rateLimitPauseUntil: this.state.rateLimitPauseUntil,
                });

                if (!guardResult.allowed && guardResult.logMessage) {
                    this.log('tool', guardResult.logMessage);
                }

                return guardResult.allowed ? null : guardResult.response;
            },
            handlers: this.toolRegistry.getHandlers(),
        });

        // ── Build the continuation coordinator ──
        this.continuationCoordinator = new OrchestratorContinuationCoordinator({
            targetUrl,
            burp,
            llm: { hasActiveConfig: () => { try { return !!llmProvider.getAllConfigs(this.config.userId).find(c => c.is_active); } catch { return false; } } },
            state: this.state,
            scanSurface: this.scanSurface,
            scanStatus: this.scanStatus,
            lifecycle: {
                persistRuntimeCheckpoint: (reason: string) =>
                    this.persistRuntimeCheckpoint(reason),
            },
            initialRequestContext: this.initialRequestContext,
            systemPromptBuilder: this.systemPromptBuilder,
            buildAccountPromptContext: () => this.buildAccountPromptContext(),
            buildContinuationScopeMessage: (analysis) => buildContinuationScopeMessage(analysis),
            analyzeOperatorInstructions: async (instruction: string) => {
                await this.analyzeOperatorInstructions(instruction);
                return {
                    analysis: this.instructionAnalysis,
                    isFocusedScope: this.isFocusedScope,
                };
            },
            log: (channel, message) => this.log(channel as any, message),
        });

        // ── Build the harness agent contract ──
        const agentContract: HarnessAgentContract<ContinueScanOptions> = {
            beforeRun: (kind) => this.prepareRun(kind),
            finalizeRun: () => this.finalizeRun(),
            handleFailure: (kind, error) => this.handleRunFailure(kind, error),
            runInit: () => this.phaseInit(),
            prepareContinuation: (opts) => this.prepareContinuationViaCoordinator(opts),
            createPlan: () => this.createPlanForHarness(),
            executeStep: (step, stepToolResults, totalActions) => this.executeStepForHarness(step, stepToolResults, totalActions),
            shouldContinueTesting: (roundResults) => this.shouldContinueTesting(roundResults),
            processHumanCommand: (cmd) => this.processHumanCommand(cmd),
            runPostRoundWork: () => this.runPostRoundWork(),
            runReporting: () => this.phaseReporting(),
            runDirectExecution: (instruction, maxRounds) => this.phaseDirectExecution(instruction, maxRounds),
            log: (channel, message) => this.log(channel, message),
            persistCheckpoint: (reason) => this.persistRuntimeCheckpoint(reason),
            delay: (ms) => this.delay(ms),
        };

        this.harness = new OrchestratorSingleAgentHarness<ContinueScanOptions>({
            state: this.state,
            agent: agentContract,
        });
    }

    /**
     * Analyze operator instructions with LLM to determine scan scope.
     * Returns structured JSON: is_focused, focused_endpoints, focused_vulns, etc.
     */
    private async analyzeOperatorInstructions(instructions: string): Promise<void> {
        const analysis = await this.instructionAnalyzer.analyze(instructions, this.targetUrl, this.scanId, this.config.userId);
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

    private async finalizeRun(): Promise<void> {
        this.state.setRunning(false);
        await this.persistRuntimeCheckpoint('run-finalizing');
        try {
            await this.browserSession.cleanup();
        } finally {
            this.saveLogs();
        }

        await this.persistRuntimeCheckpoint('run-finalized');
    }

    public async waitForCompletion(): Promise<void> {
        await this.harness.waitForCompletion();
    }

    private prepareRun(kind: 'initial' | 'continuation'): void {
        this.state.setRunning(true);
        this.contextSignals.resetBudgetSignals();
        if (kind === 'initial') {
            this.log('system', `Orchestrator Agent started for target: ${this.targetUrl}`);
            return;
        }
        this.state.setPhase('planning');
    }

    public async start() {
        await this.harness.start();
    }

    /**
     * Continue a completed scan with a new instruction.
     * Re-initializes the agent with existing findings context and runs for X more planning rounds.
     */
    public async continueScan(opts: ContinueScanOptions) {
        await this.harness.continueScan(opts);
    }

    private handleRunFailure(kind: 'initial' | 'continuation', error: any): void {
        if (this.state.isStoppedPhase()) {
            return;
        }

        this.state.transitionToFailed();
        const message = error?.message || String(error);
        this.log('error', kind === 'continuation' ? `Continuation failed: ${message}` : `Critical Failure: ${message}`);
        this.scanStatus.failed(message);
    }

    // ═════════════════════════════════════════════════════════════
    //  Agent contract: harness calls these at loop boundaries
    // ═════════════════════════════════════════════════════════════

    /**
     * Create a plan for the harness. Returns structured decision:
     * - { kind: 'plan', plan } — created a new plan
     * - { kind: 'complete' } — LLM says testing is done
     * - null — fallback plan created
     */
    private async createPlanForHarness(): Promise<{ kind: 'plan'; plan: AttackPlan } | { kind: 'complete' } | null> {
        const decision = await this.planner.createPlan({
            scanId: this.scanId,
            userId: this.config.userId,
            systemPrompt: this.state.systemPromptContent,
            conversationHistory: this.state.conversationHistory,
            rateLimitPauseUntil: this.state.rateLimitPauseUntil,
            planRound: this.state.planRound,
            findingsCount: this.state.findingsCount,
            endpointsSummary: this.scanSurface.getDiscoveredEndpointCount() > 0
                ? this.scanSurface.getDiscoveredEndpoints().slice(0, 30).join(', ')
                : 'None yet - initial discovery needed',
            previousResults: this.state.stepResults.length > 0
                ? this.state.stepResults.slice(-10).map((result) =>
                    `Step "${result.step.objective}": ${result.step.result || 'completed'} (${result.toolResults.length} tool calls)`,
                ).join('\n')
                : 'This is the first round - no previous results.',
            authStartupSummary: this.scanSurface.getStartupAuthInventory()
                ? this.scanSurface.buildStartupAuthSummary()
                : 'No startup auth inventory was captured.',
            authStartupDirective: this.buildAuthStartupDirective(),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
            mindsetTtps: this.mindsetTTPs.length > 0
                ? mindsetService.formatTTPsForPlanning(this.mindsetTTPs)
                : 'None loaded — no past reports analyzed yet.',
        });

        if (!decision) {
            return { kind: 'plan', plan: this.createFallbackPlan() };
        }

        if (decision.kind === 'complete') {
            return { kind: 'complete' };
        }

        return { kind: 'plan', plan: decision.plan };
    }

    /**
     * Execute a single step within a plan round. Called by the harness per-action.
     * Returns a normalized result that the harness can interpret:
     *   - stepFindings: findings discovered
     *   - toolResultSummary: string summary of tool result
     *   - stepComplete: whether the step is done
     */
    private async executeStepForHarness(
        step: PlanStep,
        previousResults: string[],
        totalActions: number,
    ): Promise<{ stepFindings: any[]; toolResultSummary: string | null; stepComplete: boolean }> {
        const response = await this.askLLMForStepExecution(step, previousResults, totalActions);

        if (!response) {
            return { stepFindings: [], toolResultSummary: null, stepComplete: true };
        }

        // Log thought
        if (response.thought) {
            this.log('agent', `Thought: ${safeSnippetForLog(response.thought, 200) || 'captured'}`);
        }
        this.logReflection(response.reflection);

        // Process findings
        const stepFindings: any[] = [];
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
            this.log('tool', `-> ${summarizeToolCallForLog(response.action.tool, response.action.args)}`);
            const result = await this.executeToolCall(response.action);

            // Analyze for auto-detected vulns
            if (result && !result.error && !result.skipped) {
                this.findingTracker.analyzeResponseForVulns(response.action, result);
            }

            const resultSummary = JSON.stringify(result).substring(0, 1500);
            const toolResultSummary = `[${response.action.tool}] ${resultSummary}`;

            // Feed result back to conversation
            this.state.pushMessage({
                role: 'user',
                content: `Tool result for step "${step.objective}": ${resultSummary}`
            });

            return { stepFindings, toolResultSummary, stepComplete: false };
        } else if (response.answer) {
            // Step is done
            this.log('agent', `Step complete: ${safeSnippetForLog(response.answer, 120) || 'completed'}`);
            return { stepFindings, toolResultSummary: null, stepComplete: true };
        } else {
            // No action, no answer - LLM is done with this step
            return { stepFindings, toolResultSummary: null, stepComplete: true };
        }
    }

    /**
     * Post-round work: harvest cycle and delta frontend analysis.
     * Called by the harness after each round's steps complete.
     */
    private async runPostRoundWork(): Promise<void> {
        // ── HARVEST: Pull and classify Burp traffic after round ──
        try {
            await this.domainCoordinator.runHarvestCycle();
            const harvestSummary = this.domainCoordinator.getHarvestConversationSummary();
            this.state.pushMessage({ role: 'user', content: harvestSummary });
        } catch (e: any) {
            this.log('error', `Harvest cycle failed (non-fatal): ${e.message}`);
        }

        // ── DELTA FRONTEND ANALYSIS: Check for new state after round ──
        try {
            await this.browserTools.runDeltaFrontendAnalysis('round-end');
        } catch (e: any) {
            this.log('error', `Delta analysis failed (non-fatal): ${e.message}`);
        }
    }

    /**
     * Prepare the agent state for a continuation run via the ContinuationCoordinator.
     *
     * IMPORTANT: This is NOT a resume. Continuation creates a new runtime seeded
     * from persisted state (findings + endpoints). See OrchestratorContinuationCoordinator
     * for the full continuation truth contract.
     *
     * Called by the harness before the continuation loop begins.
     */
    private async prepareContinuationViaCoordinator(opts: ContinueScanOptions): Promise<void> {
        const result = await this.continuationCoordinator.prepare({
            instruction: opts.instruction,
            iterations: opts.iterations,
            planningEnabled: opts.planningEnabled,
            existingFindings: opts.existingFindings,
            existingEndpoints: opts.existingEndpoints,
        });

        // Store the result so the harness can access continuation-specific decisions
        this.lastContinuationResult = result;
    }

    /**
     * Direct execution mode — no planning, just let LLM execute instructions with tools.
     */
    private async phaseDirectExecution(_instruction: string, maxRounds: number) {
        this.state.setPhase('executing');
        this.scanStatus.testing();
        this.log('system', '═══ DIRECT EXECUTION MODE (No Planning) ═══');

        let totalActions = 0;
        const maxActions = maxRounds * 10;

        for (let round = 0; round < maxRounds && this.state.isRunning && totalActions < maxActions; round++) {
            // Process any human commands
            while (this.state.hasHumanCommands()) {
                const cmd = this.state.shiftHumanCommand()!;
                await this.processHumanCommand(cmd);
            }

            // Handle pause
            while (this.state.isPaused && this.state.isRunning) {
                await this.delay(1000);
            }

            if (!this.state.isRunning) break;

            this.log('system', `Direct execution round ${round + 1}/${maxRounds}`);

            // Rate limit protection
            if (this.state.isRateLimited()) {
                const waitMs = this.state.getRateLimitWaitMs();
                this.log('system', `Rate limited. Waiting ${Math.ceil(waitMs / 1000)}s...`);
                await this.delay(waitMs);
                this.state.clearRateLimitPause();
            }

            try {
                const parsed = await this.planner.executeDirectInstructionTurn({
                    scanId: this.scanId,
                    userId: this.config.userId,
                    systemPrompt: this.state.systemPromptContent,
                    conversationHistory: this.state.conversationHistory,
                    rateLimitPauseUntil: this.state.rateLimitPauseUntil,
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
                    this.state.pushMessage({
                        role: 'user',
                        content: `Tool result for ${parsed.action.tool}: ${JSON.stringify(result).slice(0, 3000)}`
                    });
                } else if (parsed.actions) {
                    for (const action of parsed.actions) {
                        const result = await this.executeToolCall(action);
                        totalActions++;
                        this.state.pushMessage({
                            role: 'user',
                            content: `Tool result for ${action.tool}: ${JSON.stringify(result).slice(0, 3000)}`
                        });
                    }
                }

                // Check for completion
                if (parsed.answer) {
                    this.log('agent', `Conclusion: ${safeSnippetForLog(parsed.answer, 160) || 'recorded'}`);
                    break;
                }
            } catch (e: any) {
                this.handleRateLimitError(e);
                this.log('error', `Execution error: ${e.message}`);
            }

            await this.persistRuntimeCheckpoint(`direct-execution-round-${round + 1}`);
        }

        this.log('system', `Direct execution finished. ${totalActions} actions taken.`);
    }

    public stop() {
        this.state.transitionToStopped();
        this.log('system', 'Stop command received. Terminating agent...');
        this.scanStatus.stopped('Scan stopped by user');
        // Cleanup browser session
        void this.browserSession.cleanup();
    }

    public pause() {
        if (!this.state.isRunning || this.state.isPaused) return;
        this.state.setPaused(true);
        this.log('system', '⏸ Scan paused by user.');
    }

    public resume() {
        if (!this.state.isPaused) return;
        this.state.setPaused(false);
        this.log('system', '▶ Scan resumed by user.');
    }

    public handleUserCommand(command: string) {
        this.log('human', `User Command: ${safeSnippetForLog(command, 160) || 'received'}`);
        this.state.pushHumanCommand(command);
    }

    public getState() {
        const loopState = this.getPentesterLoopState();
        const stateSnapshot = this.state.getStateSnapshot();
        return {
            phase: stateSnapshot.phase,
            isRunning: stateSnapshot.isRunning,
            isPaused: stateSnapshot.isPaused,
            logsCount: this.logLedger.count,
            findingsCount: stateSnapshot.findingsCount,
            planRound: stateSnapshot.planRound,
            currentPlan: stateSnapshot.currentPlan,
            ...loopState,
        };
    }

    public getRuntimeSummary(): any | null {
        return this.config.scopedMissionPolicy?.buildRuntimeSummary({
            missionState: this.getState().phase,
            targetUrl: this.targetUrl,
        }) || null;
    }

    public getLogs(since: number = 0): string[] {
        return this.logLedger.getLogs(since);
    }

    public getRuntimeCheckpointSnapshot(reason: string): ScanRuntimeCheckpoint {
        const domainCheckpoint = this.domainCoordinator.getCheckpointSummary();
        const stateCheckpoint = this.state.getCheckpointSnapshot();

        return {
            version: 1,
            executionMode: 'single-agent',
            reason,
            updatedAt: new Date().toISOString(),
            phase: stateCheckpoint.phase,
            isRunning: stateCheckpoint.isRunning,
            isPaused: stateCheckpoint.isPaused,
            planRound: stateCheckpoint.planRound,
            maxPlanRounds: stateCheckpoint.maxPlanRounds,
            maxIterations: stateCheckpoint.maxIterations,
            findingsCount: stateCheckpoint.findingsCount,
            discoveredEndpointsCount: this.scanSurface.getDiscoveredEndpointCount(),
            discoveredEndpointsPreview: this.scanSurface.getDiscoveredEndpointPreview(25),
            currentPlan: stateCheckpoint.currentPlan,
            harvested: domainCheckpoint.harvested,
            hypotheses: domainCheckpoint.hypotheses,
            coverage: domainCheckpoint.coverage,
            endpointInventory: this.scanSurface.getEndpointInventory() ? {
                summary: this.scanSurface.getEndpointInventory()!.summary,
                authSurfaceCount: this.scanSurface.getEndpointInventory()!.authRelevantCount,
                endpointCount: this.scanSurface.getEndpointInventory()!.records.length,
            } : null,
        };
    }

    private async persistRuntimeCheckpoint(reason: string): Promise<void> {
        try {
            await this.hooks.checkpoint?.(this.getRuntimeCheckpointSnapshot(reason));
        } catch (error: any) {
            this.log('error', `Failed to persist runtime checkpoint (${reason}): ${error.message}`);
        }
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
        this.state.setPhase('planning');
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
        await this.scanSurface.runAuthStartup(authStartup);

        // Run source analysis after startup auth inventory is complete so planning always sees auth intelligence first
        let sourceContextBlock = '';
        if (this.config.sourcePackagePath && this.config.sourceAnalysisMode) {
            try {
                const mode = this.config.sourceAnalysisMode as SourceAnalysisMode;
                this.log('system', `🔬 Source Analysis: Running ${mode} analysis on ${this.config.sourcePackagePath}...`);
                const sourceResult = await analyzeSource(this.scanId, this.config.sourcePackagePath, mode, this.config.userId);
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
        const startupAuthBlock = this.scanSurface.buildStartupAuthPromptBlock();
        const endpointInventoryBlock = this.scanSurface.buildEndpointInventoryPromptBlock();

        // Build system prompt
        let systemPrompt = await this.systemPromptBuilder.build({
            targetUrl: this.targetUrl,
            accounts: this.buildAccountPromptContext(),
            customSystemPrompt: this.config.customSystemPrompt,
            sessionCookiesBlock,
            startupAuthBlock,
            endpointInventoryBlock,
            sourceContextBlock,
            initialRequestAppendix: this.initialRequestContext?.systemPromptAppendix,
        });
        const basePrompt = systemPrompt;

        if (false && this.config.customSystemPrompt) {
            systemPrompt = `⚠️ THIS IS THE MOST IMPORTANT — OPERATOR SCAN INSTRUCTIONS (follow these above all else):\n${this.config.customSystemPrompt}\n\n---\n\n${basePrompt}`;
        } else {
            systemPrompt = basePrompt;
        }
        systemPrompt += '';
        systemPrompt += '';
        systemPrompt += '';

        if (false && sourceContextBlock) {
            systemPrompt += sourceContextBlock;
        }

        if (false && this.initialRequestContext) {
            systemPrompt += this.initialRequestContext?.systemPromptAppendix || '';
        }

        this.state.setSystemPromptContent(systemPrompt);
        this.state.pushMessage({
            role: 'system',
            content: systemPrompt
        });

        if (this.scanSurface.getStartupAuthInventory()) {
            this.state.pushMessage({
                role: 'user',
                content: `[SYSTEM] Web Scan auth startup completed before planning.\n${this.scanSurface.buildStartupAuthSummary()}\nTreat this inventory as established evidence and keep planning auth-surface-first in round 1 before generic crawling or fuzzing.`,
            });
        }
        if (this.scanSurface.getEndpointInventory()) {
            this.state.pushMessage({
                role: 'user',
                content: `[SYSTEM] Endpoint intelligence captured before planning.\n${this.scanSurface.buildEndpointInventorySummary()}\nUse this for round 1 auth-surface-first planning and avoid already-filtered noise.`,
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
            this.state.pushMessages(buildOperatorInstructionMessages(instr, this.instructionAnalysis));

            this.log('system', '✓ Operator instructions processed and injected into the conversation');
        }

        // Request sent from Burp "Send to PenPard" — parse and inject structured data
        if (this.initialRequestContext) {
            this.state.pushMessages(this.initialRequestContext.initialMessages);
            this.log('system', `✓ ${this.initialRequestContext.logSummary}`);
        }

        // Set scan status to testing — harness loop will start after this
        this.scanStatus.testing();

        await this.persistRuntimeCheckpoint('initialization-complete');
    }

    private buildAccountPromptContext(): any[] {
        const startupAccounts = (this.config.authStartup?.credentials || []).map((credential, index) =>
            buildPromptIdentityContext({
                identityId: index === 0 ? 'primary-user' : `provided-user-${index}`,
                username: credential.username,
                email: credential.email,
                label: credential.label,
                role: credential.role,
                privilege: credential.privilege || 'unknown',
                source: 'scan_start',
            }),
        );

        const legacyAccounts = (this.config.idorUsers || []).map((account: any, index: number) =>
            buildPromptIdentityContext({
                identityId: account.identityId || `idor-user-${index + 1}`,
                username: account.username,
                email: account.email,
                label: account.label,
                role: account.role,
                privilege: account.privilege || 'unknown',
                source: 'idor_pool',
            }),
        );

        const seen = new Set<string>();
        return [...startupAccounts, ...legacyAccounts].filter((account) => {
            const key = JSON.stringify([account.identityId, account.label, account.role, account.privilege, account.source]);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    private buildAuthStartupDirective(): string {
        return this.contextSignals.buildAuthStartupDirective(
            this.state.planRound,
            this.config.authStartup?.mode || 'no_credentials',
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  PHASE: REPORTING
    // ═══════════════════════════════════════════════════════════

    private async phaseReporting() {
        if (!this.state.isRunning || this.state.isStoppedPhase()) {
            return;
        }

        this.state.setPhase('reporting');
        this.scanStatus.reporting();
        this.log('system', '═══ PHASE: REPORTING ═══');

        const vulns = this.persistence.loadVulnerabilitiesForReporting(this.scanId);
        this.log('agent', `Total findings: ${vulns.length}`);

        if (vulns.length > 0) {
            try {
                const vulnList = vulns.map((v: any) => `[${v.severity.toUpperCase()}] ${v.name}`).join('\n');
                const summary = await llmRuntime.generate({
                    systemPrompt: 'You are a security report writer. Provide a concise executive summary of the penetration test findings. Include: total vulns by severity, most critical issues, and key recommendations.',
                    userPrompt: `Target: ${this.targetUrl}\nPlanning rounds completed: ${this.state.planRound}\nEndpoints tested: ${this.scanSurface.getDiscoveredEndpointCount()}\n\nFindings:\n${vulnList}`
                }, {
                    scanId: this.scanId,
                    userId: this.config.userId,
                    callSite: 'executive_summary',
                    context: 'orchestrator-executive-summary-legacy',
                });
                this.log('agent', `Executive Summary: ${safeSnippetForLog(summary.text, 240) || 'generated'}`);
            } catch (e: any) {
                this.log('error', `Summary generation failed: ${e.message}`);
            }
        }

        await this.delay(1000);
        this.state.setPhase('completed');
        this.scanStatus.completed();
        this.log('system', `\n═══ SCAN COMPLETED ═══`);
        this.log('system', `Rounds: ${this.state.planRound} | Endpoints: ${this.scanSurface.getDiscoveredEndpointCount()} | Findings: ${vulns.length}`);

        // Cleanup browser session when scan completes
        await this.browserSession.cleanup();
    }

    // ═══════════════════════════════════════════════════════════
    //  LLM INTERACTION: PLAN / EXECUTE / REPLAN
    // ═══════════════════════════════════════════════════════════

    private createFallbackPlan(): AttackPlan {
        return this.fallbackPlanner.createPlan({
            targetUrl: this.targetUrl,
            planRound: this.state.planRound,
            instructionAnalysis: this.instructionAnalysis,
            startupAuthInventory: this.scanSurface.getStartupAuthInventory(),
            authStartupMode: this.config.authStartup?.mode || 'no_credentials',
            discoveredEndpoints: this.scanSurface.getDiscoveredEndpoints(),
        });
    }

    private async askLLMForStepExecution(step: PlanStep, previousResults: string[], totalActions: number): Promise<LLMResponse | null> {
        return this.planner.askForStepExecution({
            scanId: this.scanId,
            userId: this.config.userId,
            systemPrompt: this.state.systemPromptContent,
            conversationHistory: this.state.conversationHistory,
            rateLimitPauseUntil: this.state.rateLimitPauseUntil,
            step,
            previousResults,
            totalActions,
            budgetPressureReminder: this.getBudgetPressureReminder(totalActions),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
        });
    }

    private async shouldContinueTesting(roundResults: StepExecutionResult[]): Promise<boolean> {
        return this.planner.shouldContinueTesting({
            scanId: this.scanId,
            userId: this.config.userId,
            systemPrompt: this.state.systemPromptContent,
            conversationHistory: this.state.conversationHistory,
            rateLimitPauseUntil: this.state.rateLimitPauseUntil,
            roundResults,
            findings: this.state.findings,
            discoveredEndpoints: this.scanSurface.getDiscoveredEndpoints(),
            hypothesisStatus: this.domainCoordinator.hypothesisEngine.getSummaryForPrompt(),
            coverageStatus: this.domainCoordinator.coverageTracker.getSummaryForPrompt(),
            operatorInstructionsReminder: this.getOperatorInstructionsReminder(),
            planRound: this.state.planRound,
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  TOOL EXECUTION
    // ═══════════════════════════════════════════════════════════

    private getBudgetPressureReminder(totalActions: number): string {
        return this.contextSignals.buildBudgetPressureReminder(totalActions, this.state.maxIterations);
    }

    private logReflection(reflection?: AgentReflection) {
        if (!reflection) return;

        const parts: string[] = [];
        if (reflection.evaluationPreviousGoal) {
            parts.push(`prev=${safeSnippetForLog(reflection.evaluationPreviousGoal, 120)}`);
        }
        if (reflection.memory) {
            parts.push(`memory=${safeSnippetForLog(reflection.memory, 120)}`);
        }
        if (reflection.nextGoal) {
            parts.push(`next=${safeSnippetForLog(reflection.nextGoal, 120)}`);
        }

        if (parts.length > 0) {
            this.log('agent', `Reflection: ${parts.join(' | ')}`);
        }
    }

    private async executeToolCall(toolCall: ToolCall): Promise<any> {
        return this.toolDispatcher.execute(toolCall);
    }

    // ═══════════════════════════════════════════════════════════
    //  VULNERABILITY DETECTION & SAVING
    // ═══════════════════════════════════════════════════════════

    private saveFinding(finding: any) {
        this.findingTracker.saveFinding(finding);
    }

    // ═══════════════════════════════════════════════════════════
    //  BROWSER SESSION (public accessors for routes)
    // ═══════════════════════════════════════════════════════════

    /**
     * Get the current browser session ID. Exposed for show/hide API.
     */
    public getBrowserSessionId(): string | null {
        return this.browserSession.getSessionId();
    }

    // ═══════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════

    private async processHumanCommand(cmd: string) {
        this.log('system', 'Processing operator command');
        this.state.pushMessage({
            role: 'user',
            content: `⚠️ [OPERATOR COMMAND — HIGHEST PRIORITY] The human operator has issued the following directive. You MUST follow this immediately and override any current plan:\n\n${cmd}\n\nACKNOWLEDGE this command and adjust your next actions accordingly.`
        });
    }

    private async checkLLM(): Promise<boolean> {
        try {
            const configs = llmProvider.getAllConfigs(this.config.userId);
            const active = configs.find(c => c.is_active);
            return !!active;
        } catch { return false; }
    }

    private handleRateLimitError(e: any) {
        const errorMsg = e.message || String(e);
        if (errorMsg.includes('429') || errorMsg.includes('Too Many Requests') || errorMsg.includes('Resource exhausted')) {
            this.state.applyRateLimitPause();
            this.log('error', `🚫 LLM Rate Limited! Pausing for 1 minute...`);
        }
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
        const loopState = this.domainCoordinator.getPentesterLoopState();
        return {
            ...loopState,
            endpointInventory: this.scanSurface.getEndpointInventory(),
        };
    }
}
