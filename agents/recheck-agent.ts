/**
 * Recheck Agent - Validates findings from initial scan
 * 
 * This agent takes findings from the Scan Agent and validates
 * them to filter out false positives and confirm true positives.
 */

import { logger } from '../backend/src/utils/logger';

export interface RecheckInput {
    scanId: string;
    target: string;
    findings: Finding[];
}

export interface Finding {
    id?: number;
    name: string;
    severity: string;
    description: string;
    location?: string;
    request?: string;
    response?: string;
}

export interface RecheckResult {
    scanId: string;
    confirmedFindings: Finding[];
    falsePositives: Finding[];
    unverifiable: Finding[];
    duration: number;
}

export class RecheckAgent {
    private verificationPatterns: Map<string, RegExp[]>;

    constructor() {
        this.verificationPatterns = new Map([
            ['SQL Injection', [
                /SQL syntax.*error/i,
                /mysql_/i,
                /PostgreSQL.*ERROR/i,
                /ORA-\d{5}/i,
                /Microsoft SQL.*Driver/i,
                /ODBC.*Driver/i,
                /SQLite.*error/i,
            ]],
            ['Cross-Site Scripting', [
                /<script[^>]*>/i,
                /javascript:/i,
                /onerror\s*=/i,
                /onload\s*=/i,
            ]],
            ['Path Traversal', [
                /root:.*:0:0/,
                /\[boot loader\]/i,
                /\[operating systems\]/i,
            ]],
            ['Command Injection', [
                /uid=\d+.*gid=\d+/,
                /Volume Serial Number/i,
                /Directory of/i,
            ]],
        ]);
    }

    async execute(input: RecheckInput): Promise<RecheckResult> {
        const startTime = Date.now();

        logger.info('RecheckAgent starting', {
            scanId: input.scanId,
            findingsCount: input.findings.length
        });

        const confirmedFindings: Finding[] = [];
        const falsePositives: Finding[] = [];
        const unverifiable: Finding[] = [];

        for (const finding of input.findings) {
            const status = await this.verifyFinding(input.target, finding);

            switch (status) {
                case 'confirmed':
                    confirmedFindings.push(finding);
                    break;
                case 'false_positive':
                    falsePositives.push(finding);
                    break;
                default:
                    unverifiable.push(finding);
            }
        }

        const duration = Date.now() - startTime;

        logger.info('RecheckAgent completed', {
            scanId: input.scanId,
            confirmed: confirmedFindings.length,
            falsePositives: falsePositives.length,
            unverifiable: unverifiable.length,
            duration,
        });

        return {
            scanId: input.scanId,
            confirmedFindings,
            falsePositives,
            unverifiable,
            duration,
        };
    }

    private async verifyFinding(
        target: string,
        finding: Finding
    ): Promise<'confirmed' | 'false_positive' | 'unverifiable'> {
        // Check if we have verification patterns for this type
        for (const [vulnType, patterns] of this.verificationPatterns) {
            if (finding.name.toLowerCase().includes(vulnType.toLowerCase())) {
                return this.verifyWithPatterns(finding, patterns);
            }
        }

        // For findings without specific verification, check response content
        if (finding.response) {
            return this.analyzeResponse(finding);
        }

        return 'unverifiable';
    }

    private verifyWithPatterns(finding: Finding, patterns: RegExp[]): 'confirmed' | 'false_positive' | 'unverifiable' {
        const response = finding.response || '';

        for (const pattern of patterns) {
            if (pattern.test(response)) {
                return 'confirmed';
            }
        }

        // If we have patterns but none matched, might be false positive
        if (finding.response) {
            return 'false_positive';
        }

        return 'unverifiable';
    }

    private analyzeResponse(finding: Finding): 'confirmed' | 'false_positive' | 'unverifiable' {
        const response = finding.response || '';

        // Check for common error indicators
        const errorIndicators = [
            /error/i,
            /exception/i,
            /warning/i,
            /failed/i,
            /denied/i,
            /invalid/i,
        ];

        // Check for sensitive data exposure
        const sensitivePatterns = [
            /password/i,
            /api[_-]?key/i,
            /secret/i,
            /token/i,
            /private[_-]?key/i,
        ];

        for (const pattern of sensitivePatterns) {
            if (pattern.test(response)) {
                return 'confirmed';
            }
        }

        // Default to unverifiable if no clear indicators
        return 'unverifiable';
    }

    async generateExploit(finding: Finding): Promise<string | null> {
        // Generate proof-of-concept exploit code
        // This is a simplified version - would be enhanced with AI

        if (finding.name.toLowerCase().includes('sql injection')) {
            return `# SQL Injection PoC
import requests

target = "${finding.location || 'TARGET_URL'}"
payload = "' OR '1'='1"
response = requests.get(target, params={"id": payload})
print(f"Status: {response.status_code}")
print(f"Response: {response.text[:500]}")
`;
        }

        if (finding.name.toLowerCase().includes('xss')) {
            return `# XSS PoC
const payload = "<script>alert('XSS')</script>";
fetch("${finding.location || 'TARGET_URL'}", {
  method: "POST",
  body: JSON.stringify({ input: payload }),
  headers: { "Content-Type": "application/json" }
});
`;
        }

        return null;
    }
}

// CLI execution
if (require.main === module) {
    const agent = new RecheckAgent();

    const input: RecheckInput = {
        scanId: process.argv[2] || 'test-scan',
        target: process.argv[3] || 'http://localhost:5000',
        findings: JSON.parse(process.argv[4] || '[]'),
    };

    agent.execute(input).then((result) => {
        console.log(JSON.stringify(result, null, 2));
    });
}
