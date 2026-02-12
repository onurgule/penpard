/**
 * Recheck Agent - Vulnerability verification agent
 * Re-tests suspected findings with different payloads
 * Confirms real vulnerabilities and discards false positives
 */

import { BurpMCPClient } from '../services/burp-mcp';
import { llmQueue } from '../services/LLMQueue';
import { SharedContext, SharedVulnerability } from './SharedContext';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

interface SuspectedVulnerability {
    id: string;
    type: string;  // sqli, xss, idor, etc.
    endpoint: string;
    method: string;
    parameter?: string;
    payload?: string;
    evidence: string;
    originalResponse?: string;
    foundBy: string;
    request?: {
        url: string;
        method: string;
        headers: Record<string, string>;
        body?: string;
    };
    response?: {
        status: number;
        headers: Record<string, string>;
        body: string;
    };
}

const RECHECK_PROMPTS: Record<string, string> = {
    sqli: `You are verifying a potential SQL Injection vulnerability.
Original finding: {evidence}

To confirm this is a real SQLi, try these additional payloads:
1. Time-based: ' AND SLEEP(5)-- or ' WAITFOR DELAY '0:0:5'--
2. Error-based: ' AND 1=CONVERT(int,(SELECT @@version))--
3. Boolean-based: ' AND '1'='1 vs ' AND '1'='2

If ANY of these show different behavior (time delay, SQL errors, different content), it's CONFIRMED.
If all behave the same as normal request, it's likely a FALSE POSITIVE.

Respond with:
{
  "confirmed": true/false,
  "confidence": 1-100,
  "evidence": "explanation of why",
  "severity": "critical/high/medium/low",
  "additionalPayloads": ["payload1", "payload2"]
}`,

    xss: `You are verifying a potential Cross-Site Scripting (XSS) vulnerability.
Original finding: {evidence}

To confirm this is a real XSS:
1. Check if the payload is reflected in the response
2. Try alternative payloads: <img src=x onerror=alert(1)>, <svg onload=alert(1)>
3. Check if encoding is bypassed

If the payload is reflected WITHOUT proper encoding, it's CONFIRMED.

Respond with:
{
  "confirmed": true/false,
  "confidence": 1-100,
  "evidence": "explanation of why",
  "severity": "critical/high/medium/low"
}`,

    idor: `You are verifying a potential Insecure Direct Object Reference (IDOR).
Original finding: {evidence}

To confirm this is a real IDOR:
1. Try accessing another user's resource with current session
2. Check if resource IDs are predictable
3. Verify authorization checks are missing

If you can access resources belonging to other users, it's CONFIRMED.

Respond with:
{
  "confirmed": true/false,
  "confidence": 1-100,
  "evidence": "explanation of why",
  "severity": "critical/high/medium/low"
}`,

    default: `You are verifying a potential security vulnerability.
Original finding: {evidence}

Analyze the evidence and determine if this is a real vulnerability or a false positive.

Consider:
1. Is the behavior actually exploitable?
2. Are there mitigating controls?
3. What's the real impact?

Respond with:
{
  "confirmed": true/false,
  "confidence": 1-100,
  "evidence": "explanation of why",
  "severity": "critical/high/medium/low"
}`
};

export class RecheckAgent {
    public readonly id: string;

    private context: SharedContext;
    private burp: BurpMCPClient;
    private scanId: string;

    private isRunning: boolean = false;
    private queue: SuspectedVulnerability[] = [];
    private confirmed: SharedVulnerability[] = [];
    private rejected: SuspectedVulnerability[] = [];
    private logs: string[] = [];

    constructor(scanId: string, context: SharedContext, burp: BurpMCPClient) {
        this.id = `recheck-${uuidv4().substring(0, 8)}`;
        this.scanId = scanId;
        this.context = context;
        this.burp = burp;

        // Listen for suspected vulnerabilities
        this.context.on('vulnerability:suspected', this.handleSuspectedVuln.bind(this));
    }

    public async start(): Promise<void> {
        if (this.isRunning) return;

        this.isRunning = true;
        this.log('Recheck Agent started - waiting for suspected vulnerabilities');

        while (this.isRunning) {
            if (this.queue.length > 0) {
                const suspected = this.queue.shift()!;
                await this.recheckVulnerability(suspected);
            } else {
                await this.delay(1000);
            }
        }

        this.log(`Recheck complete. Confirmed: ${this.confirmed.length}, Rejected: ${this.rejected.length}`);
    }

    public stop(): void {
        this.isRunning = false;
    }

    public addSuspectedVulnerability(vuln: SuspectedVulnerability): void {
        this.log(`Queued for recheck: ${vuln.type} at ${vuln.endpoint}`);
        this.queue.push(vuln);
    }

    public getStatus() {
        return {
            id: this.id,
            isRunning: this.isRunning,
            queueLength: this.queue.length,
            confirmed: this.confirmed.length,
            rejected: this.rejected.length
        };
    }

    public getLogs(): string[] {
        return this.logs;
    }

    // ============ PRIVATE METHODS ============

    private handleSuspectedVuln(vuln: SuspectedVulnerability): void {
        this.addSuspectedVulnerability(vuln);
    }

    private async recheckVulnerability(suspected: SuspectedVulnerability): Promise<void> {
        this.log(`Rechecking: ${suspected.type} at ${suspected.endpoint}`);

        try {
            // Get appropriate prompt
            const promptTemplate = RECHECK_PROMPTS[suspected.type] || RECHECK_PROMPTS.default;
            const prompt = promptTemplate.replace('{evidence}', suspected.evidence);

            // If we have the original endpoint, try additional payloads
            const additionalTests = await this.runAdditionalTests(suspected);

            // Ask LLM to analyze (use queue for rate limiting)
            const response = await llmQueue.enqueue({
                systemPrompt: `You are a security expert verifying vulnerability reports. Be thorough but avoid false positives. Only confirm if you have strong evidence.`,
                userPrompt: `${prompt}\n\nAdditional test results:\n${JSON.stringify(additionalTests, null, 2)}`
            });

            // Parse response
            const result = this.parseRecheckResult(response.text);

            if (result.confirmed && result.confidence >= 70) {
                // Get vulnerability details
                const vulnInfo = this.getVulnDetails(suspected.type);

                // Build PoC steps
                const pocSteps = this.generatePoC(suspected);

                // Confirmed! Add as real vulnerability
                const confirmedVuln: SharedVulnerability = {
                    id: uuidv4(),
                    name: this.getVulnName(suspected.type, suspected.endpoint),
                    severity: (result.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low' | 'info',

                    // CVSS 4.0
                    cvssVector: vulnInfo.cvssVector,
                    cvssScore: vulnInfo.cvssScore,

                    // CWE
                    cwe: vulnInfo.cwe,
                    cweName: vulnInfo.cweName,

                    // Description, Impact, Remediation
                    description: vulnInfo.description,
                    impact: vulnInfo.impact,
                    remediation: vulnInfo.remediation,

                    // PoC
                    poc: pocSteps,

                    // Request/Response
                    endpoint: suspected.endpoint,
                    method: suspected.method || 'GET',
                    request: suspected.request,
                    response: suspected.response,

                    evidence: suspected.evidence + '\n\nRecheck Result: ' + result.evidence,
                    foundBy: suspected.foundBy,
                    timestamp: new Date(),
                    verified: true
                };

                this.confirmed.push(confirmedVuln);
                this.context.addVulnerability(confirmedVuln);
                this.log(`✅ CONFIRMED [${result.severity}]: ${confirmedVuln.name} (confidence: ${result.confidence}%)`);
            } else {
                // Rejected as false positive
                this.rejected.push(suspected);
                this.log(`❌ REJECTED: ${suspected.type} at ${suspected.endpoint} (confidence: ${result.confidence}%)`);
            }

        } catch (error: any) {
            this.log(`Recheck error: ${error.message}`);
            // On error, add to confirmed with lower confidence (better safe than sorry)
            const vulnInfo = this.getVulnDetails(suspected.type);
            const fallbackVuln: SharedVulnerability = {
                id: uuidv4(),
                name: this.getVulnName(suspected.type, suspected.endpoint) + ' (Unverified)',
                severity: 'low',

                cvssVector: vulnInfo.cvssVector,
                cvssScore: 3.0,
                cwe: vulnInfo.cwe,
                cweName: vulnInfo.cweName,

                description: vulnInfo.description,
                impact: vulnInfo.impact + '\n\n⚠️ This finding requires manual verification.',
                remediation: vulnInfo.remediation,

                poc: ['Manual verification required - automated recheck failed'],

                endpoint: suspected.endpoint,
                method: suspected.method || 'GET',
                evidence: suspected.evidence,
                foundBy: suspected.foundBy,
                timestamp: new Date(),
                verified: false
            };
            this.context.addVulnerability(fallbackVuln);
        }
    }

    private async runAdditionalTests(suspected: SuspectedVulnerability): Promise<any[]> {
        const results: any[] = [];

        // Skip if no valid endpoint
        if (!suspected.endpoint || !suspected.endpoint.trim()) {
            this.log('Skipping additional tests - no valid endpoint');
            return results;
        }

        try {
            // Get additional payloads based on vulnerability type
            const payloads = this.getAdditionalPayloads(suspected.type);

            for (const payload of payloads.slice(0, 3)) { // Max 3 additional tests
                try {
                    // Build test URL
                    let testUrl = suspected.endpoint;
                    if (suspected.parameter) {
                        testUrl = suspected.endpoint.includes('?')
                            ? `${suspected.endpoint}&${suspected.parameter}=${encodeURIComponent(payload)}`
                            : `${suspected.endpoint}?${suspected.parameter}=${encodeURIComponent(payload)}`;
                    }

                    const startTime = Date.now();
                    const response = await this.burp.callTool('send_http_request', {
                        method: suspected.method || 'GET',
                        url: testUrl,
                        use_proxy: true,
                        penpard_source: `Recheck/${this.id}`
                    });
                    const duration = Date.now() - startTime;

                    results.push({
                        payload,
                        duration,
                        statusCode: response?.status,
                        responseLength: response?.body?.length || 0,
                        containsPayload: response?.body?.includes(payload) || false,
                        containsError: this.containsSQLError(response?.body || '')
                    });

                } catch (e) {
                    results.push({ payload, error: (e as any).message });
                }

                // Rate limiting
                await this.delay(500);
            }
        } catch (e) {
            this.log(`Additional tests failed: ${(e as any).message}`);
        }

        return results;
    }

    private getAdditionalPayloads(vulnType: string): string[] {
        const payloads: Record<string, string[]> = {
            sqli: [
                "' OR '1'='1",
                "' AND SLEEP(3)--",
                "1; SELECT * FROM users--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND '1'='2"
            ],
            xss: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "'\"><script>alert(1)</script>"
            ],
            idor: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "1",
                "admin",
                "0"
            ],
            lfi: [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php"
            ],
            rce: [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "& whoami"
            ]
        };

        return payloads[vulnType] || ["test", "1", "'", "\"", "<>"];
    }

    private containsSQLError(body: string): boolean {
        const sqlErrors = [
            'sql syntax',
            'mysql_fetch',
            'ORA-',
            'SQLite3::',
            'PostgreSQL',
            'SQLSTATE',
            'syntax error',
            'unclosed quotation',
            'unterminated string'
        ];
        const lower = body.toLowerCase();
        return sqlErrors.some(err => lower.includes(err.toLowerCase()));
    }

    private parseRecheckResult(text: string): { confirmed: boolean; confidence: number; evidence: string; severity: string } {
        try {
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return {
                    confirmed: !!parsed.confirmed,
                    confidence: parsed.confidence || 50,
                    evidence: parsed.evidence || '',
                    severity: parsed.severity || 'medium'
                };
            }
        } catch {
            // Parse from text
        }

        // Default: uncertain
        return {
            confirmed: text.toLowerCase().includes('confirmed'),
            confidence: 50,
            evidence: text.substring(0, 500),
            severity: 'medium'
        };
    }

    private getVulnName(type: string, endpoint: string): string {
        const names: Record<string, string> = {
            sqli: 'SQL Injection',
            xss: 'Cross-Site Scripting (XSS)',
            idor: 'Insecure Direct Object Reference',
            lfi: 'Local File Inclusion',
            rfi: 'Remote File Inclusion',
            rce: 'Remote Code Execution',
            ssrf: 'Server-Side Request Forgery',
            xxe: 'XML External Entity',
            default: 'Security Issue'
        };

        let path = '/unknown';
        if (endpoint && endpoint.trim()) {
            try {
                path = new URL(endpoint).pathname;
            } catch {
                // If URL parsing fails, try to extract path manually
                path = endpoint.includes('/') ? endpoint.split('/').slice(3).join('/') || endpoint : endpoint;
            }
        }

        return `${names[type] || type.toUpperCase()} - ${path}`;
    }

    private log(message: string): void {
        const line = `[${new Date().toISOString()}] [RECHECK] ${message}`;
        this.logs.push(line);
        logger.info(message, { agentId: this.id, scanId: this.scanId });
        this.context.emit('worker:log', { workerId: this.id, message: line });
    }

    private async delay(ms: number): Promise<void> {
        await new Promise(resolve => setTimeout(resolve, ms));
    }

    private getVulnDetails(type: string): {
        cwe: string;
        cweName: string;
        cvssVector: string;
        cvssScore: number;
        description: string;
        impact: string;
        remediation: string;
    } {
        const vulnDatabase: Record<string, any> = {
            sqli: {
                cwe: 'CWE-89',
                cweName: 'SQL Injection',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
                cvssScore: 9.3,
                description: 'SQL Injection vulnerability allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view, modify, or delete data they are not authorized to access.',
                impact: 'An attacker could extract sensitive data from the database, modify or delete data, execute administrative operations, and in some cases, issue commands to the operating system.',
                remediation: 'Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use ORM frameworks. Apply the principle of least privilege to database accounts.'
            },
            xss: {
                cwe: 'CWE-79',
                cweName: 'Cross-Site Scripting',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N',
                cvssScore: 6.1,
                description: 'Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts into web pages viewed by other users.',
                impact: 'An attacker could steal session cookies, redirect users to malicious sites, deface the website, or perform actions on behalf of the victim user.',
                remediation: 'Implement proper output encoding for all user-supplied data. Use Content Security Policy (CSP) headers. Sanitize HTML input using a whitelist approach.'
            },
            idor: {
                cwe: 'CWE-639',
                cweName: 'Authorization Bypass Through User-Controlled Key',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
                cvssScore: 8.1,
                description: 'Insecure Direct Object Reference (IDOR) occurs when an application exposes a reference to an internal object without proper authorization checks.',
                impact: 'An attacker could access, modify, or delete other users\' data by manipulating object references (IDs, filenames, etc.).',
                remediation: 'Implement proper access control checks for every object access. Use indirect references (mapping) instead of direct database IDs. Validate user authorization for each request.'
            },
            lfi: {
                cwe: 'CWE-98',
                cweName: 'Improper Control of Filename for Include/Require Statement',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
                cvssScore: 7.5,
                description: 'Local File Inclusion vulnerability allows an attacker to read arbitrary files from the server by manipulating file path parameters.',
                impact: 'An attacker could read sensitive configuration files, source code, password files, and other confidential data from the server.',
                remediation: 'Avoid passing user input to file system functions. Use a whitelist of allowed files. Implement proper input validation and canonicalization.'
            },
            rce: {
                cwe: 'CWE-78',
                cweName: 'OS Command Injection',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
                cvssScore: 10.0,
                description: 'Remote Code Execution vulnerability allows an attacker to execute arbitrary commands or code on the target system.',
                impact: 'An attacker could gain complete control of the server, install malware, steal data, pivot to other systems, or cause a complete system compromise.',
                remediation: 'Never pass user input directly to system commands. Use parameterized APIs instead of shell commands. Implement strict input validation and sandboxing.'
            },
            ssrf: {
                cwe: 'CWE-918',
                cweName: 'Server-Side Request Forgery',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:H/SI:N/SA:N',
                cvssScore: 6.5,
                description: 'Server-Side Request Forgery vulnerability allows an attacker to make the server perform requests to arbitrary destinations.',
                impact: 'An attacker could scan internal networks, access internal services, bypass firewalls, or access cloud metadata endpoints to steal credentials.',
                remediation: 'Implement a whitelist of allowed domains. Disable unnecessary URL schemes. Use network segmentation and firewall rules to restrict outbound connections.'
            },
            default: {
                cwe: 'CWE-693',
                cweName: 'Protection Mechanism Failure',
                cvssVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
                cvssScore: 5.3,
                description: 'A security vulnerability was detected that could allow unauthorized access or data manipulation.',
                impact: 'The exact impact depends on the nature of the vulnerability and the context in which it exists.',
                remediation: 'Review the application code and implement appropriate security controls based on the specific vulnerability type.'
            }
        };

        return vulnDatabase[type] || vulnDatabase.default;
    }

    private generatePoC(suspected: SuspectedVulnerability): string[] {
        const endpoint = suspected.endpoint || 'the target endpoint';
        const method = suspected.method || 'GET';
        const payload = suspected.payload || 'the malicious payload';

        const baseSteps = [
            `1. Navigate to ${endpoint}`,
            `2. Open browser developer tools (F12) and go to the Network tab`,
        ];

        switch (suspected.type) {
            case 'sqli':
                return [
                    ...baseSteps,
                    `3. Locate the vulnerable parameter and inject: ${payload}`,
                    `4. Send the ${method} request and observe the response`,
                    `5. If the response contains SQL error messages or different behavior, the injection is successful`,
                    `6. Try extracting data using UNION-based or time-based techniques`
                ];
            case 'xss':
                return [
                    ...baseSteps,
                    `3. Enter the following payload in the input field: ${payload}`,
                    `4. Submit the form or trigger the vulnerable action`,
                    `5. Observe if the payload is executed (alert box or DOM changes)`,
                    `6. Check if the payload is reflected without proper encoding`
                ];
            case 'idor':
                return [
                    `1. Log in as User A and navigate to ${endpoint}`,
                    `2. Note the resource ID in the URL or request body`,
                    `3. Log in as User B (or log out)`,
                    `4. Change the resource ID to User A's resource ID`,
                    `5. Send the request and verify if you can access User A's data`
                ];
            case 'lfi':
                return [
                    ...baseSteps,
                    `3. Modify the file parameter to: ../../../etc/passwd`,
                    `4. Send the request and check if file contents are returned`,
                    `5. Try different traversal sequences: ....//....//....//etc/passwd`
                ];
            case 'rce':
                return [
                    ...baseSteps,
                    `3. Inject a command separator followed by a command: ${payload}`,
                    `4. Use a benign command like 'id' or 'whoami' to confirm execution`,
                    `5. Check the response for command output`,
                    `6. ⚠️ CAUTION: Do not execute destructive commands`
                ];
            default:
                return [
                    `1. Access the vulnerable endpoint: ${endpoint}`,
                    `2. Reproduce the vulnerability using method: ${method}`,
                    `3. Inject the payload: ${payload}`,
                    `4. Analyze the response for indicators of vulnerability`,
                    `5. Document the exact steps and evidence`
                ];
        }
    }
}
