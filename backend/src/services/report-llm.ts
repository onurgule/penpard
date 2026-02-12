/**
 * LLM-Driven Report Enhancement for PenPard
 * Uses the active LLM to rewrite/enhance vulnerability descriptions,
 * add context, generate executive summaries, and improve overall report quality.
 */

import { llmProvider } from './LLMProviderService';
import { logger } from '../utils/logger';

interface Vulnerability {
    id: number;
    name: string;
    description?: string;
    severity: string;
    cvss_score?: number;
    cvss_vector?: string;
    cwe?: string;
    cve?: string;
    request?: string;
    response?: string;
    evidence?: string;
    remediation?: string;
}

interface Scan {
    id: string;
    type: string;
    target: string;
    status: string;
    created_at: string;
    completed_at: string;
}

/**
 * Enhance all vulnerability descriptions using the LLM.
 * Returns a Map<vulnId, enhancedDescription>.
 */
export async function enhanceVulnerabilityDescriptions(
    vulns: Vulnerability[]
): Promise<Map<number, string>> {
    const enhanced = new Map<number, string>();

    for (const vuln of vulns) {
        try {
            const result = await enhanceSingleDescription(vuln);
            if (result) {
                enhanced.set(vuln.id, result);
            }
        } catch (err: any) {
            logger.warn(`Failed to enhance description for vuln ${vuln.id}`, { error: err.message });
        }
    }

    return enhanced;
}

async function enhanceSingleDescription(vuln: Vulnerability): Promise<string | null> {
    const requestSnippet = vuln.request ? vuln.request.slice(0, 1500) : '';
    const responseSnippet = vuln.response ? vuln.response.slice(0, 1000) : '';

    const prompt = `You are a senior penetration tester writing a professional security assessment report. Rewrite and enhance the following vulnerability description to be clear, comprehensive, and suitable for both technical and executive audiences.

VULNERABILITY:
- Name: ${vuln.name}
- Severity: ${vuln.severity}
- CVSS Score: ${vuln.cvss_score || 'N/A'}
- CWE: ${vuln.cwe || 'N/A'}
- CVE: ${vuln.cve || 'N/A'}

ORIGINAL DESCRIPTION:
${vuln.description || 'No description provided.'}

${requestSnippet ? `HTTP REQUEST EVIDENCE:\n${requestSnippet}\n` : ''}
${responseSnippet ? `HTTP RESPONSE EVIDENCE:\n${responseSnippet}\n` : ''}
${vuln.evidence ? `ADDITIONAL EVIDENCE:\n${String(vuln.evidence).slice(0, 500)}\n` : ''}

REQUIREMENTS:
1. Start with a clear 1-2 sentence summary of what the vulnerability is
2. Explain the technical details of how it was discovered (reference the actual request/response if available)
3. Describe the potential impact on the business (data breach, unauthorized access, etc.)
4. Be specific — reference actual endpoints, parameters, and payloads from the evidence
5. Keep it professional and suitable for a formal security report
6. Maximum 300 words
7. Do NOT include remediation advice (that's in a separate section)

Write the enhanced description as plain text (no markdown, no headers, no bullet points).`;

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a senior penetration tester writing formal security assessment reports. Write clear, professional vulnerability descriptions.',
            userPrompt: prompt,
        }, 'report-description-enhancement');

        const text = response.text.trim();
        // Sanity check — must be a reasonable description
        if (text.length > 50 && text.length < 3000 && !text.startsWith('{') && !text.startsWith('[')) {
            return text;
        }
        return null;
    } catch (err: any) {
        logger.warn('LLM description enhancement failed', { error: err.message });
        return null;
    }
}

/**
 * Generate an enhanced executive summary using the LLM.
 */
export async function generateExecutiveSummary(
    scan: Scan,
    vulns: Vulnerability[]
): Promise<string | null> {
    const counts: Record<string, number> = {};
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
        counts[sev] = vulns.filter(v => v.severity === sev).length;
    }

    const topFindings = vulns
        .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
        .slice(0, 5)
        .map(v => `- [${v.severity.toUpperCase()}] ${v.name} (CVSS: ${v.cvss_score || 'N/A'})`)
        .join('\n');

    const prompt = `You are a cybersecurity consultant writing an executive summary for a penetration test report. Write a concise, professional executive summary.

TEST DETAILS:
- Target: ${scan.target}
- Test Type: ${scan.type} application penetration test
- Date: ${scan.created_at}
- Total Findings: ${vulns.length}
  - Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}, Info: ${counts.info}

TOP FINDINGS:
${topFindings || 'No findings.'}

REQUIREMENTS:
1. 2-3 paragraphs maximum
2. Start with the overall risk assessment
3. Highlight the most critical issues and their potential business impact
4. End with a brief recommendation
5. Professional tone suitable for C-level executives
6. Do NOT use bullet points or headers — write flowing prose
7. Maximum 200 words

Write the executive summary as plain text.`;

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a cybersecurity consultant writing executive summaries for penetration test reports. Be concise and professional.',
            userPrompt: prompt,
        }, 'report-executive-summary');

        const text = response.text.trim();
        if (text.length > 50 && text.length < 2000) {
            return text;
        }
        return null;
    } catch (err: any) {
        logger.warn('LLM executive summary generation failed', { error: err.message });
        return null;
    }
}

/**
 * Generate enhanced remediation advice using the LLM.
 */
export async function enhanceRemediations(
    vulns: Vulnerability[]
): Promise<Map<number, string>> {
    const enhanced = new Map<number, string>();

    for (const vuln of vulns) {
        try {
            const result = await enhanceSingleRemediation(vuln);
            if (result) {
                enhanced.set(vuln.id, result);
            }
        } catch (err: any) {
            logger.warn(`Failed to enhance remediation for vuln ${vuln.id}`, { error: err.message });
        }
    }

    return enhanced;
}

async function enhanceSingleRemediation(vuln: Vulnerability): Promise<string | null> {
    if (!vuln.remediation) return null;

    const prompt = `You are a senior application security engineer. Enhance the following remediation advice to be more specific, actionable, and include code examples where appropriate.

VULNERABILITY:
- Name: ${vuln.name}
- Severity: ${vuln.severity}
- CWE: ${vuln.cwe || 'N/A'}

ORIGINAL REMEDIATION:
${vuln.remediation}

REQUIREMENTS:
1. Make it specific and actionable
2. Include a brief code example if relevant (e.g., parameterized queries for SQLi, output encoding for XSS)
3. Reference industry standards (OWASP, CIS, etc.) where applicable
4. Keep it under 200 words
5. Write as plain text

Write the enhanced remediation as plain text.`;

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a senior application security engineer providing specific, actionable remediation advice.',
            userPrompt: prompt,
        }, 'report-remediation-enhancement');

        const text = response.text.trim();
        if (text.length > 30 && text.length < 2000) {
            return text;
        }
        return null;
    } catch (err: any) {
        return null;
    }
}
