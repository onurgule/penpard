import type { RequestExecutionExchange } from './types';

export function ensureFindingIdentity(finding: any, lastExchange: RequestExecutionExchange | null): string {
    if (finding.name && finding.name !== 'Security Issue' && finding.name !== 'Vulnerability Found') {
        return String(finding.name);
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

    const vulnerabilityType = typeFromFields || typeFromCwe || typeFromDesc || 'Security Issue';
    const endpoint = resolveFindingEndpoint(finding, lastExchange);
    const parameter = finding.parameter || finding.param || '';

    const name = endpoint
        ? `${vulnerabilityType} - ${endpoint}${parameter ? ` (${parameter})` : ''}`
        : `${vulnerabilityType}`;

    finding.name = name;
    return name;
}

export function isDuplicateFindingName(existingNames: string[], name: string): boolean {
    const vulnerabilityType = name.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
    const endpoint = name.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';

    return existingNames.some((existingName) => {
        const existingType = existingName.split(' - ')[0]?.toLowerCase().replace(/[^a-z]/g, '') || '';
        const existingPath = existingName.split(' - ')[1]?.split(' ')[0]?.split('(')[0]?.trim() || '';
        const typeMatch = vulnerabilityType
            && existingType
            && (vulnerabilityType.includes(existingType) || existingType.includes(vulnerabilityType));
        const pathMatch = !endpoint
            || !existingPath
            || endpoint === existingPath
            || existingPath.includes(endpoint)
            || endpoint.includes(existingPath);
        return typeMatch && pathMatch;
    });
}

export function estimateCvss(severity: string): number {
    const scores: Record<string, number> = {
        critical: 9.5,
        high: 8.0,
        medium: 5.5,
        low: 3.0,
        info: 0.0,
    };
    return scores[severity?.toLowerCase()] || 5.0;
}

function resolveFindingEndpoint(finding: any, lastExchange: RequestExecutionExchange | null): string {
    let endpoint = finding.endpoint || finding.url || finding.path || finding.location || '';

    if (!endpoint && finding.request) {
        const requestMatch = String(finding.request).match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/i);
        if (requestMatch) {
            endpoint = requestMatch[1];
        }
    }

    if (!endpoint) {
        endpoint = lastExchange?.action?.args?.url || '';
    }

    if (!endpoint) {
        return '';
    }

    try {
        const parsed = new URL(endpoint.startsWith('http') ? endpoint : `https://x${endpoint}`);
        return parsed.pathname + (parsed.search ? parsed.search.substring(0, 40) : '');
    } catch {
        return endpoint;
    }
}
