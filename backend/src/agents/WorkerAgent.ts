/**
 * Worker Agent - Parallel execution agent
 * Each worker focuses on a specific task
 */

import { BurpMCPClient } from '../services/burp-mcp';
import { llmQueue } from '../services/LLMQueue';
import { SharedContext, DiscoveredEndpoint, SharedVulnerability, AgentMessage } from './SharedContext';
import { logger, formatLogTimestamp } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

export type WorkerRole = 'crawler' | 'scanner' | 'fuzzer' | 'analyzer';

interface WorkerConfig {
    role: WorkerRole;
    maxIterations: number;
    rateLimit: number; // requests per second
}

const ROLE_PROMPTS: Record<WorkerRole, string> = {
    crawler: `You are a web crawler agent. Your job is to DISCOVER endpoints.
- Analyze HTML/JS for links, forms, API endpoints
- Look for hidden paths in robots.txt, sitemap.xml, JS files
- Report each discovered endpoint with method and URL
- Focus on finding MORE endpoints, not testing them

OUTPUT FORMAT:
{
  "discovered": [
    { "url": "https://...", "method": "GET", "priority": 8 },
    { "url": "https://...", "method": "POST", "priority": 7 }
  ],
  "nextAction": { "tool": "send_http_request", "args": {...} }
}`,

    scanner: `You are a vulnerability scanner agent. Your job is to TEST endpoints for vulnerabilities.
- Test for SQL Injection, XSS, Command Injection
- Modify parameters with payloads
- Analyze responses for error messages, behavior changes
- Report any vulnerabilities found

OUTPUT FORMAT:
{
  "tested": { "url": "...", "result": "vulnerable|safe|error" },
  "finding": { "name": "SQL Injection", "severity": "high", "evidence": "..." },
  "nextAction": { "tool": "send_http_request", "args": {...} }
}`,

    fuzzer: `You are a parameter fuzzer agent. Your job is to FUZZ parameters with various payloads.
- Try SQL payloads: ', ", --, OR 1=1, UNION SELECT
- Try XSS payloads: <script>, onerror=, javascript:
- Try path traversal: ../, ....//
- Try command injection: |, ;, &&, $()
- Vary the intensity based on response patterns

OUTPUT FORMAT:
{
  "fuzzed": { "url": "...", "param": "id", "payload": "1'", "response": "error" },
  "finding": { "name": "...", "severity": "...", "evidence": "..." },
  "nextAction": { "tool": "send_http_request", "args": {...} }
}`,

    analyzer: `You are a response analyzer agent. Your job is to ANALYZE responses for security issues.
- Look for sensitive data exposure (API keys, passwords, tokens)
- Check for security headers (CSP, X-Frame-Options, etc.)
- Identify technology stack from responses
- Find hidden endpoints in JavaScript code
- Report information disclosure vulnerabilities

OUTPUT FORMAT:
{
  "analysis": { "tech": ["Node.js", "Express"], "issues": [...] },
  "discovered": [{ "url": "...", "method": "GET", "source": "js-analysis" }],
  "finding": { "name": "Information Disclosure", "severity": "low", "evidence": "..." }
}`
};

export class WorkerAgent {
    public readonly id: string;
    public readonly role: WorkerRole;

    private config: WorkerConfig;
    private context: SharedContext;
    private burp: BurpMCPClient;

    private isRunning: boolean = false;
    private isPaused: boolean = false;
    private iteration: number = 0;
    private logs: string[] = [];
    private lastRequestResponse: { request?: any; response?: any } | null = null;

    constructor(
        role: WorkerRole,
        context: SharedContext,
        burp: BurpMCPClient,
        config?: Partial<WorkerConfig>
    ) {
        this.id = `${role}-${uuidv4().substring(0, 8)}`;
        this.role = role;
        this.context = context;
        this.burp = burp;
        this.config = {
            role,
            maxIterations: config?.maxIterations || 20,
            rateLimit: config?.rateLimit || 5
        };

        // Listen for messages to this worker
        this.context.on(`message:${this.id}`, this.handleMessage.bind(this));
        this.context.on('broadcast', this.handleMessage.bind(this));
    }

    public async start(): Promise<void> {
        if (this.isRunning) return;

        this.isRunning = true;
        this.log(`Worker started: ${this.role}`);

        try {
            await this.runLoop();
        } catch (error: any) {
            this.log(`Worker error: ${error.message}`);
        } finally {
            this.isRunning = false;
            this.log(`Worker stopped: ${this.role}`);
        }
    }

    public stop(): void {
        this.isRunning = false;
    }

    public pause(): void {
        this.isPaused = true;
    }

    public resume(): void {
        this.isPaused = false;
    }

    public getStatus() {
        return {
            id: this.id,
            role: this.role,
            isRunning: this.isRunning,
            isPaused: this.isPaused,
            iteration: this.iteration,
            logsCount: this.logs.length
        };
    }

    public getLogs(since: number = 0): string[] {
        return this.logs.slice(since);
    }

    // ============ MAIN LOOP ============

    private async runLoop(): Promise<void> {
        while (this.isRunning && this.iteration < this.config.maxIterations) {
            this.iteration++;

            // Pause handling
            while (this.isPaused && this.isRunning) {
                await this.delay(500);
            }

            if (!this.isRunning) break;

            // Rate limiting
            await this.delay(1000 / this.config.rateLimit);

            try {
                await this.executeIteration();
            } catch (error: any) {
                this.log(`Iteration ${this.iteration} error: ${error.message}`);
            }
        }
    }

    private async executeIteration(): Promise<void> {
        // Get work based on role
        const workData = this.getWorkForRole();

        if (!workData) {
            this.log(`No work available, waiting...`);
            await this.delay(2000);
            return;
        }

        // Build prompt for LLM
        const prompt = this.buildPrompt(workData);

        // Ask LLM
        const response = await this.askLLM(prompt);

        if (!response) {
            this.log(`No response from LLM`);
            return;
        }

        // Process response based on role
        await this.processResponse(response, workData);
    }

    private getWorkForRole(): any {
        switch (this.role) {
            case 'crawler':
                // Crawler starts from target URL or continues from discovered endpoints
                const unexPlored = this.context.getUntestedEndpoints(1);
                return unexPlored[0] || { url: this.context.targetUrl, method: 'GET', isInitial: true };

            case 'scanner':
                // Scanner gets untested endpoints to scan
                return this.context.getUntestedEndpoints(5);

            case 'fuzzer':
                // Fuzzer gets endpoints with parameters
                const endpoints = this.context.getAllEndpoints()
                    .filter(e => e.url.includes('?') || e.method === 'POST');
                return endpoints.slice(0, 3);

            case 'analyzer':
                // Analyzer gets recent responses to analyze
                const recent = this.context.getUntestedEndpoints(3);
                return recent;

            default:
                return null;
        }
    }

    private buildPrompt(workData: any): string {
        const basePrompt = ROLE_PROMPTS[this.role];
        const contextInfo = `
TARGET: ${this.context.targetUrl}
SCAN ID: ${this.context.scanId}

CURRENT STATS:
- Total Endpoints: ${this.context.getStats().totalEndpoints}
- Tested: ${this.context.getStats().testedEndpoints}
- Vulnerabilities: ${this.context.getStats().vulnerabilitiesFound}

WORK DATA:
${JSON.stringify(workData, null, 2)}

${basePrompt}

Now execute your task and respond in the specified JSON format.`;

        return contextInfo;
    }

    private async askLLM(prompt: string): Promise<any> {
        try {
            const response = await llmQueue.enqueue({
                systemPrompt: `You are a specialized ${this.role} agent in a security testing team. Be precise and output valid JSON.`,
                userPrompt: prompt
            });

            // Parse JSON from response
            return this.parseResponse(response.text);
        } catch (error: any) {
            this.log(`LLM error: ${error.message}`);
            return null;
        }
    }

    private parseResponse(text: string): any {
        try {
            // Find JSON in response
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
        } catch {
            // Try to extract data from text
        }
        return null;
    }

    private async processResponse(response: any, workData: any): Promise<void> {
        // Handle discovered endpoints
        if (response.discovered && Array.isArray(response.discovered)) {
            for (const endpoint of response.discovered) {
                const added = this.context.addEndpoint({
                    url: endpoint.url,
                    method: endpoint.method || 'GET',
                    priority: endpoint.priority || 5,
                    source: this.id,
                    tested: false
                });
                if (added) {
                    this.log(`Discovered: ${endpoint.method || 'GET'} ${endpoint.url}`);
                }
            }
        }

        // Handle findings - send to recheck agent for verification
        if (response.finding) {
            const suspectedVuln: any = {
                id: uuidv4(),
                type: this.detectVulnType(response.finding.name),
                endpoint: response.finding.url || workData?.url || '',
                method: workData?.method || 'GET',
                parameter: response.finding.parameter,
                payload: response.finding.payload,
                evidence: response.finding.evidence || response.finding.description || '',
                foundBy: this.id
            };

            // Add request/response if available from last HTTP call
            if (this.lastRequestResponse) {
                if (this.lastRequestResponse.request) {
                    suspectedVuln.request = this.lastRequestResponse.request;
                }
                if (this.lastRequestResponse.response) {
                    suspectedVuln.response = this.lastRequestResponse.response;
                }
            }

            // Emit suspected vulnerability for recheck agent to verify
            this.context.emit('vulnerability:suspected', suspectedVuln);
            this.log(`SUSPECTED VULN: [${response.finding.severity}] ${response.finding.name} - sent to recheck agent`);
        }

        // Handle next action (tool call)
        if (response.nextAction || response.action) {
            const action = response.nextAction || response.action;
            await this.executeAction(action);
        }

        // Mark work as tested if scanner/fuzzer
        if ((this.role === 'scanner' || this.role === 'fuzzer') && workData?.url) {
            if (Array.isArray(workData)) {
                for (const w of workData) {
                    this.context.markEndpointTested(w.url, w.method || 'GET', response);
                }
            } else {
                this.context.markEndpointTested(workData.url, workData.method || 'GET', response);
            }
        }

        // Broadcast status to other workers
        this.context.sendMessage({
            from: this.id,
            to: 'all',
            type: 'status',
            payload: {
                role: this.role,
                iteration: this.iteration,
                lastWork: workData?.url || 'unknown'
            }
        });
    }

    private async executeAction(action: any): Promise<any> {
        if (!action) return null;

        const tool = action.tool || (typeof action === 'string' ? action : null);
        const args = action.args || action.parameters || {};

        if (!tool) return null;

        this.log(`Executing: ${tool}`);
        this.context.incrementRequests();

        try {
            switch (tool) {
                case 'send_http_request':
                    const requestData = {
                        method: args.method || 'GET',
                        url: args.url,
                        headers: args.headers || {},
                        body: args.body || ''
                    };
                    
                    const result = await this.burp.callTool('send_http_request', {
                        ...requestData,
                        use_proxy: true,
                        penpard_source: `Worker/${this.id}`
                    });
                    
                    // Store request/response for potential vulnerability reporting
                    this.lastRequestResponse = {
                        request: {
                            url: args.url,
                            method: requestData.method,
                            headers: requestData.headers,
                            body: requestData.body
                        },
                        response: result ? {
                            status: result.status || 200,
                            headers: result.headers || {},
                            body: result.body || ''
                        } : undefined
                    };
                    
                    return result;

                case 'get_proxy_history':
                    return await this.burp.callTool('get_proxy_history', { count: args.count || 10, excludePenPard: true });

                default:
                    this.log(`Unknown tool: ${tool}`);
                    return null;
            }
        } catch (error: any) {
            this.log(`Tool error: ${error.message}`);
            return null;
        }
    }

    private handleMessage(message: AgentMessage): void {
        if (message.from === this.id) return; // Ignore own messages

        // Handle incoming messages
        if (message.type === 'task') {
            this.log(`Received task from ${message.from}: ${message.payload.task}`);
            // Process assigned task
        }
    }

    private log(message: string): void {
        const timestamp = formatLogTimestamp();
        const line = `[${timestamp}] [${this.id}] ${message}`;
        this.logs.push(line);
        logger.info(message, { workerId: this.id, role: this.role });

        // Emit to context for aggregation
        this.context.emit('worker:log', { workerId: this.id, message: line });
    }

    private async delay(ms: number): Promise<void> {
        await new Promise(resolve => setTimeout(resolve, ms));
    }

    private detectVulnType(name: string): string {
        const lower = name.toLowerCase();

        if (lower.includes('sql') || lower.includes('injection')) return 'sqli';
        if (lower.includes('xss') || lower.includes('cross-site') || lower.includes('script')) return 'xss';
        if (lower.includes('idor') || lower.includes('insecure direct')) return 'idor';
        if (lower.includes('lfi') || lower.includes('local file')) return 'lfi';
        if (lower.includes('rfi') || lower.includes('remote file')) return 'rfi';
        if (lower.includes('rce') || lower.includes('command') || lower.includes('execution')) return 'rce';
        if (lower.includes('ssrf') || lower.includes('server-side request')) return 'ssrf';
        if (lower.includes('xxe') || lower.includes('xml external')) return 'xxe';
        if (lower.includes('traversal') || lower.includes('path')) return 'lfi';

        return 'default';
    }
}
