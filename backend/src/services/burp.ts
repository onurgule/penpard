import axios from 'axios';
import { logger } from '../utils/logger';
import { addVulnerability, updateScanStatus } from '../db/init';

// Use localhost for npm, host.docker.internal for Docker
const BURP_API_URL = process.env.BURP_API_URL || 'http://localhost:8082';

interface BurpIssue {
    name: string;
    severity: string;
    confidence: string;
    host: string;
    path: string;
    issueDetail?: string;
    issueBackground?: string;
    remediationDetail?: string;
    remediationBackground?: string;
    request?: string;
    response?: string;
    serialNumber?: string;
}

export class BurpService {
    private baseUrl: string;

    constructor() {
        this.baseUrl = BURP_API_URL;
    }

    async isAvailable(): Promise<boolean> {
        try {
            const response = await axios.get(`${this.baseUrl}/v0.1/`, { timeout: 5000 });
            return response.status === 200;
        } catch (error) {
            logger.warn('Burp Suite API not available', { url: this.baseUrl });
            return false;
        }
    }

    async scan(scanId: string, targetUrl: string): Promise<void> {
        logger.info('Starting Burp scan', { scanId, targetUrl });

        try {
            // Start the scan
            const startResponse = await axios.post(`${this.baseUrl}/v0.1/scan`, {
                urls: [targetUrl],
                scope: {
                    include: [{ rule: targetUrl }],
                    type: 'SimpleScope',
                },
                scanConfigurations: [
                    { type: 'NamedConfiguration', name: 'Crawl and Audit - Balanced' },
                ],
            });

            const burpTaskId = startResponse.data.task_id;
            logger.info('Burp scan initiated', { scanId, burpTaskId });

            // Update scan status
            updateScanStatus(scanId, 'crawling');

            // Poll for completion
            let completed = false;
            let attempts = 0;
            const maxAttempts = 120; // 10 minutes max

            while (!completed && attempts < maxAttempts) {
                await new Promise((r) => setTimeout(r, 5000));
                attempts++;

                const statusResponse = await axios.get(
                    `${this.baseUrl}/v0.1/scan/${burpTaskId}`
                );

                const status = statusResponse.data.scan_status;
                logger.info('Burp scan status', { scanId, status, attempts });

                if (status === 'succeeded' || status === 'paused' || status === 'failed') {
                    completed = true;

                    if (status === 'failed') {
                        throw new Error('Burp scan failed');
                    }

                    // Fetch issues
                    await this.fetchIssues(scanId, burpTaskId);
                } else if (status === 'crawling') {
                    updateScanStatus(scanId, 'crawling');
                } else if (status === 'auditing') {
                    updateScanStatus(scanId, 'auditing');
                }
            }

            if (!completed) {
                throw new Error('Burp scan timed out');
            }

            updateScanStatus(scanId, 'analyzing');
        } catch (error: any) {
            logger.error('Burp scan error', { scanId, error: error.message });
            throw error;
        }
    }

    private async fetchIssues(scanId: string, burpTaskId: string): Promise<void> {
        try {
            const issuesResponse = await axios.get(
                `${this.baseUrl}/v0.1/scan/${burpTaskId}/issues`
            );

            const issues: BurpIssue[] = issuesResponse.data.issues || [];
            logger.info('Fetched Burp issues', { scanId, count: issues.length });

            for (const issue of issues) {
                const severity = this.mapSeverity(issue.severity);
                const cvssScore = this.estimateCvss(issue.severity, issue.confidence);

                addVulnerability({
                    scanId,
                    name: issue.name,
                    description: issue.issueDetail || issue.issueBackground || '',
                    severity,
                    cvssScore,
                    cwe: this.extractCwe(issue.name),
                    request: issue.request,
                    response: issue.response,
                    remediation: issue.remediationDetail || issue.remediationBackground,
                });
            }
        } catch (error: any) {
            logger.error('Failed to fetch Burp issues', { scanId, error: error.message });
        }
    }

    private mapSeverity(burpSeverity: string): string {
        const map: Record<string, string> = {
            high: 'high',
            medium: 'medium',
            low: 'low',
            information: 'info',
        };
        return map[burpSeverity.toLowerCase()] || 'info';
    }

    private estimateCvss(severity: string, confidence: string): number {
        const severityScores: Record<string, number> = {
            high: 8.0,
            medium: 5.5,
            low: 3.0,
            information: 0.0,
        };

        const confidenceMultiplier: Record<string, number> = {
            certain: 1.0,
            firm: 0.9,
            tentative: 0.7,
        };

        const base = severityScores[severity.toLowerCase()] || 0;
        const multiplier = confidenceMultiplier[confidence.toLowerCase()] || 0.8;

        return Math.round(base * multiplier * 10) / 10;
    }

    private extractCwe(issueName: string): string | undefined {
        // Map common Burp issue names to CWE IDs
        const cweMap: Record<string, string> = {
            'SQL injection': '89',
            'Cross-site scripting': '79',
            'Cross-site request forgery': '352',
            'Path traversal': '22',
            'Command injection': '78',
            'XML external entity injection': '611',
            'Server-side request forgery': '918',
            'Open redirection': '601',
            'HTTP response splitting': '113',
            'LDAP injection': '90',
            'XPath injection': '643',
        };

        for (const [name, cwe] of Object.entries(cweMap)) {
            if (issueName.toLowerCase().includes(name.toLowerCase())) {
                return cwe;
            }
        }

        return undefined;
    }

    async getScreenshot(scanId: string, issueIndex: number): Promise<Buffer | null> {
        // Burp REST API doesn't directly provide screenshots
        // This would require Burp Enterprise or custom implementation
        return null;
    }
}
