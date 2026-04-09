import { addVulnerability, db } from '../../db/init';
import { ToolCall, RequestExecutionExchange } from './types';

interface BurpToolClient {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

interface VulnerabilityInsert {
    scanId: string;
    name: string;
    description?: string;
    severity: string;
    cvssScore?: number;
    cwe?: string;
    cve?: string;
    request?: string;
    response?: string;
    evidence?: string;
    remediation?: string;
}

export interface OrchestratorFindingTrackerOptions {
    scanId: string;
    burp: BurpToolClient;
    log: (channel: string, message: string) => void;
    getLastExchange: () => RequestExecutionExchange | null;
    onFindingSaved?: (finding: any) => void;
    persistVulnerability?: (payload: VulnerabilityInsert) => void;
    loadExistingFindingNames?: (scanId: string) => string[];
}

export class OrchestratorFindingTracker {
    constructor(private readonly options: OrchestratorFindingTrackerOptions) {}

    public saveFinding(finding: any): boolean {
        if (!finding || typeof finding !== 'object') {
            this.options.log('debug', 'Skipping invalid finding (not an object)');
            return false;
        }

        this.ensureFindingName(finding);

        const name = String(finding.name);
        const existingNames = (this.options.loadExistingFindingNames || defaultLoadExistingFindingNames)(this.options.scanId);
        if (isDuplicateFindingName(existingNames, name)) {
            this.options.log('debug', `Skipping duplicate finding: ${name}`);
            return false;
        }

        this.options.log('vuln', `[${(finding.severity || 'MEDIUM').toUpperCase()}] ${name}`);

        const evidence = this.buildStoredEvidence(finding);

        try {
            (this.options.persistVulnerability || addVulnerability)({
                scanId: this.options.scanId,
                name,
                description: String(finding.description || finding.evidence || ''),
                severity: String((finding.severity || 'medium')).toLowerCase(),
                cvssScore: estimateCvss(finding.severity),
                remediation: String(finding.remediation || ''),
                cwe: String(finding.cwe || ''),
                cve: String(finding.cve || ''),
                request: evidence.request,
                response: evidence.response,
                evidence: String(finding.evidence || ''),
            });
            this.options.log('system', `Finding saved to DB: ${name}`);
        } catch (error: any) {
            this.options.log('error', `Failed to save finding to DB: ${error.message}. Finding: ${JSON.stringify({ name, severity: finding.severity, cwe: finding.cwe }).substring(0, 200)}`);
            return false;
        }

        const lastExchange = this.options.getLastExchange();
        if (lastExchange?.action) {
            void this.sendToRepeater(evidence.request, name, lastExchange.action);
        }

        finding.name = name;
        this.options.onFindingSaved?.(finding);
        return true;
    }

    public analyzeResponseForVulns(action: ToolCall, response: any): void {
        if (!response) return;

        const body = response.body_preview || response.body || '';
        if (!body || body.length === 0) return;

        const url = action.args?.url || '';
        const method = action.args?.method || 'GET';
        const statusCode = response.statusCode || response.status || 200;

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
                        'eval(', 'document.cookie', 'document.write',
                    ];

                    const hasXssIndicator = xssIndicators.some((indicator) => decodedPayload.toLowerCase().includes(indicator.toLowerCase()));
                    if (!hasXssIndicator) continue;

                    const isReflected =
                        body.includes(decodedPayload) ||
                        body.includes(rawPayload) ||
                        (
                            decodedPayload.includes('<') &&
                            body.includes('<') &&
                            decodedPayload.includes('>') &&
                            body.includes('>') &&
                            decodedPayload.length > 10 &&
                            body.includes(decodedPayload.substring(0, Math.min(20, decodedPayload.length)))
                        );

                    if (isReflected) {
                        this.options.log('vuln', `XSS DETECTED: Payload reflected! Parameter: ${paramName}`);
                        const evidence = this.buildActionEvidence(action, response, method, url, statusCode, body);
                        this.saveFinding({
                            name: `Reflected XSS - ${url.split('?')[0]} (${paramName} parameter)`,
                            severity: 'high',
                            description: 'XSS payload reflected without encoding in HTML response.',
                            evidence: `Payload "${decodedPayload.substring(0, 100)}" reflected in response. Status: ${statusCode}`,
                            cwe: 'CWE-79',
                            request: evidence.request,
                            response: evidence.response,
                            remediation: 'HTML-encode all user input. Implement Content Security Policy (CSP).',
                        });
                        return;
                    }
                } catch {
                    continue;
                }
            }
        }

        const sqlErrors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite', 'sql error', 'database error'];
        if (sqlErrors.some((error) => body.toLowerCase().includes(error))) {
            const payload = action.args?.body || action.args?.url?.match(/[?&][^=]+=([^&]+)/)?.[1] || '';
            if (payload && (payload.includes('\'') || payload.includes('"') || payload.includes('--'))) {
                const evidence = this.buildActionEvidence(action, response, method, url, statusCode, body);
                this.saveFinding({
                    name: `SQL Injection - ${url.split('?')[0]}`,
                    severity: 'critical',
                    description: 'SQL error message detected in response, indicating SQL injection vulnerability.',
                    evidence: `SQL error: ${body.match(new RegExp(sqlErrors.find((entry) => body.toLowerCase().includes(entry)) || '', 'i'))?.[0] || 'DB error'}`,
                    cwe: 'CWE-89',
                    request: evidence.request,
                    response: evidence.response,
                    remediation: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
                });
            }
        }
    }

    private ensureFindingName(finding: any): void {
        if (finding.name && finding.name !== 'Security Issue' && finding.name !== 'Vulnerability Found') {
            return;
        }

        const typeFromFields = finding.type || finding.vulnerability || finding.title || '';
        const cweToType: Record<string, string> = {
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-89': 'SQL Injection',
            'CWE-22': 'Path Traversal',
            'CWE-78': 'Command Injection',
            'CWE-918': 'SSRF',
            'CWE-352': 'CSRF',
            'CWE-287': 'Authentication Bypass',
            'CWE-639': 'IDOR',
            'CWE-601': 'Open Redirect',
            'CWE-200': 'Information Disclosure',
            'CWE-311': 'Missing Encryption',
            'CWE-434': 'Unrestricted File Upload',
            'CWE-502': 'Deserialization',
            'CWE-611': 'XXE',
            'CWE-94': 'Code Injection',
            'CWE-862': 'Missing Authorization',
        };
        const typeFromCwe = finding.cwe ? cweToType[finding.cwe] || '' : '';

        let typeFromDesc = '';
        const descText = ((finding.description || '') + ' ' + (finding.evidence || '')).toLowerCase();
        const descPatterns: Array<[string, RegExp]> = [
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
            if (regex.test(descText)) {
                typeFromDesc = label;
                break;
            }
        }

        const vulnType = typeFromFields || typeFromCwe || typeFromDesc || 'Security Issue';

        let endpoint = finding.endpoint || finding.url || finding.path || finding.location || '';
        if (!endpoint && finding.request) {
            const requestMatch = String(finding.request).match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
            if (requestMatch) endpoint = requestMatch[1];
        }
        if (!endpoint) {
            const lastExchange = this.options.getLastExchange();
            endpoint = lastExchange?.action?.args?.url || '';
        }
        if (endpoint) {
            try {
                const parsed = new URL(endpoint.startsWith('http') ? endpoint : `https://x${endpoint}`);
                endpoint = parsed.pathname + (parsed.search ? parsed.search.substring(0, 40) : '');
            } catch {
                /* keep as-is */
            }
        }

        const param = finding.parameter || finding.param || '';
        finding.name = endpoint
            ? `${vulnType} - ${endpoint}${param ? ` (${param})` : ''}`
            : `${vulnType}`;

        this.options.log('debug', `Finding had no/generic name, generated: ${finding.name}`);
    }

    private buildStoredEvidence(finding: any): { request: string; response: string } {
        let request = String(finding.request || '');
        let response = String(finding.response || '');

        if (request && response) {
            return { request, response };
        }

        const lastExchange = this.options.getLastExchange();
        if (!lastExchange) {
            return { request, response };
        }

        const action = lastExchange.action;
        const result = lastExchange.result;

        if (!request && lastExchange.rawRequest) {
            request = lastExchange.rawRequest;
        }
        if (!request && action?.args) {
            request = buildRequestFromAction(action);
        }

        if (!response && lastExchange.rawResponse) {
            response = lastExchange.rawResponse;
        }
        if (!response && result) {
            response = buildResponseFromResult(result);
        }

        return { request, response };
    }

    private buildActionEvidence(
        action: ToolCall,
        response: any,
        method: string,
        url: string,
        statusCode: number,
        body: string,
    ): { request: string; response: string } {
        const lastExchange = this.options.getLastExchange();

        let request = lastExchange?.rawRequest || '';
        if (!request) {
            request = buildRequestFromAction(action, method, url);
        }

        let responseText = lastExchange?.rawResponse || '';
        if (!responseText) {
            responseText = buildResponseFromResult(response, statusCode, body);
        }

        return { request, response: responseText };
    }

    private async sendToRepeater(requestStr: string, vulnName: string, action?: ToolCall): Promise<void> {
        try {
            let host = '';
            let port = 80;
            let useHttps = false;
            let finalRequest = requestStr;

            const lastExchange = this.options.getLastExchange();
            const rawRequest = lastExchange?.rawRequest;
            if (rawRequest && action?.args?.url) {
                try {
                    const url = new URL(action.args.url);
                    host = url.hostname;
                    port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                    useHttps = url.protocol === 'https:';

                    finalRequest = rawRequest;
                    const firstLine = finalRequest.split(/\r?\n/)[0];
                    const fullUrlMatch = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+https?:\/\/[^\/]+(\/[^\s]*)\s+(HTTP\/\S+)/i);
                    if (fullUrlMatch) {
                        finalRequest = `${fullUrlMatch[1]} ${fullUrlMatch[2]} ${fullUrlMatch[3]}` + finalRequest.substring(firstLine.length);
                    }
                } catch {
                    /* fall through */
                }
            } else if (action?.args?.url) {
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
                                const sanitizedValue = String(value).replace(/[\r\n]/g, ' ');
                                const normalizedName = key.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join('-');
                                headerLines.push(`${normalizedName}: ${sanitizedValue}`);
                            }
                        });
                    }
                    finalRequest = `${method} ${urlPath} HTTP/1.1\r\n${headerLines.join('\r\n')}\r\n\r\n`;
                    if (action.args.body) {
                        finalRequest += String(action.args.body).replace(/\r\n/g, '\n');
                    }
                } catch {
                    /* fall through */
                }
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
                    const hostHeader = requestLines.find((line) => line.toLowerCase().startsWith('host:'));
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
                await this.options.burp.callTool('send_to_repeater', {
                    host,
                    port,
                    useHttps,
                    request: normalizeRequestForRepeater(finalRequest),
                    name: `${vulnName} - ${this.options.scanId.substring(0, 8)}`,
                });
                this.options.log('debug', `Sent to Repeater: ${vulnName}`);
            }
        } catch (error: any) {
            this.options.log('debug', `Repeater send failed: ${error.message}`);
        }
    }
}

function defaultLoadExistingFindingNames(scanId: string): string[] {
    return (db.prepare('SELECT name FROM vulnerabilities WHERE scan_id = ?').all(scanId) as Array<{ name: string }>)
        .map((row) => row.name || '');
}

function isDuplicateFindingName(existingNames: string[], name: string): boolean {
    const vulnType = name.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
    const endpoint = name.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';

    return existingNames.some((existingName) => {
        const existingType = existingName.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
        const existingPath = existingName.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';
        const typeMatch = vulnType && existingType && (vulnType.includes(existingType) || existingType.includes(vulnType));
        const pathMatch = !endpoint || !existingPath || endpoint === existingPath || existingPath.includes(endpoint) || endpoint.includes(existingPath);
        return typeMatch && pathMatch;
    });
}

function estimateCvss(severity: string): number {
    const scores: Record<string, number> = {
        critical: 9.5,
        high: 8.0,
        medium: 5.5,
        low: 3.0,
        info: 0.0,
    };
    return scores[severity?.toLowerCase()] || 5.0;
}

function buildRequestFromAction(action: ToolCall, fallbackMethod?: string, fallbackUrl?: string): string {
    const method = action.args.method || fallbackMethod || 'GET';
    const url = action.args.url || fallbackUrl || '';
    let reconstructed = `${method} ${url} HTTP/1.1\n`;
    try {
        const parsedUrl = new URL(url);
        reconstructed += `Host: ${parsedUrl.host}\n`;
    } catch {
        /* ignore */
    }
    if (action.args.headers) {
        Object.entries(action.args.headers).forEach(([key, value]) => {
            if (key.toLowerCase() !== 'host') {
                reconstructed += `${key}: ${value}\n`;
            }
        });
    }
    if (action.args.body) {
        reconstructed += `\n${action.args.body}`;
    }
    return reconstructed;
}

function buildResponseFromResult(result: any, fallbackStatusCode?: number, fallbackBody?: string): string {
    const statusCode = result.statusCode || result.status || fallbackStatusCode || 200;
    let response = `HTTP/1.1 ${statusCode}\n`;
    if (result.headers) {
        if (Array.isArray(result.headers)) {
            result.headers.forEach((header: string) => {
                response += `${header}\n`;
            });
        } else if (typeof result.headers === 'object') {
            Object.entries(result.headers).forEach(([key, value]) => {
                response += `${key}: ${value}\n`;
            });
        }
    }
    const body = result.body_preview || result.body || fallbackBody || '';
    if (body) {
        response += `\n${body}`;
    }
    return response;
}

function normalizeRequestForRepeater(raw: string): string {
    const lines = raw.split(/\r?\n/);
    const result: string[] = [];
    let bodyStart = -1;
    for (let index = 0; index < lines.length; index++) {
        const line = lines[index];
        if (index === 0) {
            result.push(line.replace(/\s+/g, ' ').trim());
            continue;
        }
        if (line.trim() === '') {
            bodyStart = index;
            break;
        }
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const name = line.substring(0, colonIndex).trim();
            const value = line.substring(colonIndex + 1).trim().replace(/[\r\n]/g, ' ');
            const normalizedName = name.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()).join('-');
            result.push(`${normalizedName}: ${value}`);
        }
    }
    result.push('');
    if (bodyStart >= 0 && bodyStart < lines.length - 1) {
        result.push(lines.slice(bodyStart + 1).join('\n'));
    }
    return result.join('\r\n');
}
