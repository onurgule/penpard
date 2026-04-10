import { addVulnerability, db } from '../../db/init';
import { prepareBurpDispatchRequest } from '../../services/burp-request';
import { ensureFindingIdentity, estimateCvss, isDuplicateFindingName } from './OrchestratorFindingIdentityPolicy';
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

        const originalName = typeof finding.name === 'string' ? finding.name : '';
        const name = ensureFindingIdentity(finding, this.options.getLastExchange());
        if (name !== originalName) {
            this.options.log('debug', `Finding had no/generic name, generated: ${name}`);
        }

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
            const lastExchange = this.options.getLastExchange();
            const prepared = prepareBurpDispatchRequest({
                rawRequest: lastExchange?.rawRequest || requestStr,
                url: typeof action?.args?.url === 'string' ? action.args.url : undefined,
                method: typeof action?.args?.method === 'string' ? action.args.method : undefined,
                headers: action?.args?.headers,
                body: typeof action?.args?.body === 'string' ? action.args.body : undefined,
            });

            if (prepared) {
                await this.options.burp.callTool('send_to_repeater', {
                    host: prepared.host,
                    port: prepared.port,
                    useHttps: prepared.useHttps,
                    request: prepared.request,
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

