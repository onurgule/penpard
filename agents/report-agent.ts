/**
 * Report Agent - Compiles vulnerability data into reports
 * 
 * This agent takes confirmed findings and generates comprehensive
 * PDF reports with CVSS scores, remediation advice, and evidence.
 */

import { logger } from '../backend/src/utils/logger';
import { generatePdfReport } from '../backend/src/services/report';
import { getVulnerabilitiesByScan, getScan } from '../backend/src/db/init';

export interface ReportInput {
    scanId: string;
    format?: 'pdf' | 'json' | 'html';
    includeEvidence?: boolean;
    includeRemediation?: boolean;
}

export interface ReportOutput {
    success: boolean;
    scanId: string;
    reportPath?: string;
    summary: ReportSummary;
    error?: string;
}

export interface ReportSummary {
    totalVulnerabilities: number;
    bySeverity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    riskScore: number;
    topVulnerabilities: string[];
}

export class ReportAgent {
    // CVSS 4.0 calculation weights
    private cvssWeights = {
        attackVector: { network: 0.85, adjacent: 0.62, local: 0.55, physical: 0.2 },
        attackComplexity: { low: 0.77, high: 0.44 },
        privilegesRequired: { none: 0.85, low: 0.62, high: 0.27 },
        userInteraction: { none: 0.85, required: 0.62 },
        scope: { unchanged: 1.0, changed: 1.08 },
        impact: { high: 0.56, low: 0.22, none: 0 },
    };

    async execute(input: ReportInput): Promise<ReportOutput> {
        logger.info('ReportAgent starting', { scanId: input.scanId });

        try {
            const scan = getScan(input.scanId);
            if (!scan) {
                throw new Error('Scan not found');
            }

            const vulnerabilities = getVulnerabilitiesByScan(input.scanId);

            // Calculate summary
            const summary = this.generateSummary(vulnerabilities);

            // Calculate CVSS scores if missing
            for (const vuln of vulnerabilities) {
                if (!vuln.cvss_score) {
                    vuln.cvss_score = this.estimateCvss(vuln);
                }
            }

            // Generate report based on format
            let reportPath: string | undefined;

            if (input.format === 'pdf' || !input.format) {
                reportPath = await generatePdfReport(scan, vulnerabilities);
            }

            logger.info('ReportAgent completed', {
                scanId: input.scanId,
                reportPath,
                summary
            });

            return {
                success: true,
                scanId: input.scanId,
                reportPath,
                summary,
            };
        } catch (error: any) {
            logger.error('ReportAgent failed', { scanId: input.scanId, error: error.message });
            return {
                success: false,
                scanId: input.scanId,
                summary: {
                    totalVulnerabilities: 0,
                    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    riskScore: 0,
                    topVulnerabilities: [],
                },
                error: error.message,
            };
        }
    }

    private generateSummary(vulnerabilities: any[]): ReportSummary {
        const bySeverity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };

        for (const vuln of vulnerabilities) {
            const severity = vuln.severity?.toLowerCase() as keyof typeof bySeverity;
            if (severity in bySeverity) {
                bySeverity[severity]++;
            }
        }

        // Calculate overall risk score (0-100)
        const riskScore = this.calculateRiskScore(bySeverity);

        // Get top vulnerabilities (highest severity first)
        const sortedVulns = [...vulnerabilities].sort((a, b) => {
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            const aSev = severityOrder[a.severity?.toLowerCase() as keyof typeof severityOrder] ?? 5;
            const bSev = severityOrder[b.severity?.toLowerCase() as keyof typeof severityOrder] ?? 5;
            return aSev - bSev;
        });

        const topVulnerabilities = sortedVulns.slice(0, 5).map(v => v.name);

        return {
            totalVulnerabilities: vulnerabilities.length,
            bySeverity,
            riskScore,
            topVulnerabilities,
        };
    }

    private calculateRiskScore(bySeverity: ReportSummary['bySeverity']): number {
        const weights = {
            critical: 40,
            high: 25,
            medium: 15,
            low: 5,
            info: 0,
        };

        let score = 0;
        for (const [severity, count] of Object.entries(bySeverity)) {
            score += (weights[severity as keyof typeof weights] || 0) * Math.min(count, 5);
        }

        return Math.min(score, 100);
    }

    private estimateCvss(vulnerability: any): number {
        // Simplified CVSS estimation based on severity
        const severityScores: Record<string, number> = {
            critical: 9.5,
            high: 7.5,
            medium: 5.5,
            low: 3.0,
            info: 0.0,
        };

        const baseSeverity = vulnerability.severity?.toLowerCase() || 'medium';
        let score = severityScores[baseSeverity] ?? 5.0;

        // Adjust based on vulnerability type
        const vulnName = vulnerability.name?.toLowerCase() || '';

        if (vulnName.includes('injection') || vulnName.includes('rce')) {
            score = Math.min(score + 1.0, 10.0);
        }

        if (vulnName.includes('authentication') || vulnName.includes('bypass')) {
            score = Math.min(score + 0.5, 10.0);
        }

        return Math.round(score * 10) / 10;
    }

    async generateRemediationPlan(vulnerabilities: any[]): Promise<string> {
        // Group vulnerabilities by type for consolidated remediation
        const grouped = new Map<string, any[]>();

        for (const vuln of vulnerabilities) {
            const type = this.categorizeVulnerability(vuln.name);
            if (!grouped.has(type)) {
                grouped.set(type, []);
            }
            grouped.get(type)!.push(vuln);
        }

        let plan = '# Remediation Plan\n\n';

        for (const [type, vulns] of grouped) {
            plan += `## ${type}\n\n`;
            plan += `**Affected Areas:** ${vulns.length} instances\n\n`;
            plan += this.getRemediationAdvice(type);
            plan += '\n\n';
        }

        return plan;
    }

    private categorizeVulnerability(name: string): string {
        const categories: Record<string, string[]> = {
            'Injection Vulnerabilities': ['sql', 'injection', 'command', 'ldap', 'xpath'],
            'Cross-Site Scripting': ['xss', 'cross-site scripting', 'script'],
            'Authentication Issues': ['auth', 'password', 'session', 'token', 'login'],
            'Access Control': ['idor', 'access', 'authorization', 'privilege'],
            'Cryptographic Issues': ['crypto', 'ssl', 'tls', 'certificate', 'encrypt'],
            'Configuration Issues': ['config', 'header', 'disclosure', 'debug'],
        };

        const lowerName = name.toLowerCase();

        for (const [category, keywords] of Object.entries(categories)) {
            if (keywords.some(kw => lowerName.includes(kw))) {
                return category;
            }
        }

        return 'Other Security Issues';
    }

    private getRemediationAdvice(category: string): string {
        const advice: Record<string, string> = {
            'Injection Vulnerabilities': `
- Use parameterized queries or prepared statements
- Implement input validation with allowlists
- Apply least privilege principle to database accounts
- Use ORM frameworks that handle escaping automatically`,
            'Cross-Site Scripting': `
- Implement context-aware output encoding
- Use Content Security Policy (CSP) headers
- Validate and sanitize all user inputs
- Use HttpOnly and Secure flags for cookies`,
            'Authentication Issues': `
- Implement strong password policies
- Use secure session management
- Enable multi-factor authentication
- Hash passwords with bcrypt/argon2`,
            'Access Control': `
- Implement server-side access control checks
- Use indirect object references
- Apply principle of least privilege
- Log all access control failures`,
            'Cryptographic Issues': `
- Use TLS 1.2+ with strong cipher suites
- Implement certificate pinning for mobile
- Use strong, modern encryption algorithms
- Never store sensitive data in plaintext`,
            'Configuration Issues': `
- Remove debug/development features in production
- Implement security headers (HSTS, CSP, X-Frame-Options)
- Disable directory listing
- Remove server version disclosure`,
        };

        return advice[category] || '- Review and implement security best practices\n- Consult OWASP guidelines';
    }
}

// CLI execution
if (require.main === module) {
    const agent = new ReportAgent();

    const input: ReportInput = {
        scanId: process.argv[2] || 'test-scan',
        format: 'pdf',
        includeEvidence: true,
        includeRemediation: true,
    };

    agent.execute(input).then((result) => {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.success ? 0 : 1);
    });
}
