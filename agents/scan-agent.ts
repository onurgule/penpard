/**
 * Scan Agent - Orchestrates vulnerability scanning using Burp/MobSF
 * 
 * This agent initiates scans, configures OWASP testing, and collects
 * initial findings. It integrates with LLM providers for enhanced testing.
 */

import { logger } from '../backend/src/utils/logger';
import { BurpService } from '../backend/src/services/burp';
import { MobSFService } from '../backend/src/services/mobsf';

export interface ScanConfig {
    scanId: string;
    type: 'web' | 'mobile';
    target: string;
    options?: {
        depth?: 'quick' | 'balanced' | 'deep';
        owaspTests?: string[];
        aiEnhanced?: boolean;
    };
}

export interface ScanResult {
    success: boolean;
    scanId: string;
    findings: Finding[];
    duration: number;
    errors?: string[];
}

export interface Finding {
    name: string;
    severity: string;
    description: string;
    location?: string;
    evidence?: string;
}

export class ScanAgent {
    private burpService: BurpService;
    private mobsfService: MobSFService;

    constructor() {
        this.burpService = new BurpService();
        this.mobsfService = new MobSFService();
    }

    async execute(config: ScanConfig): Promise<ScanResult> {
        const startTime = Date.now();
        const errors: string[] = [];
        const findings: Finding[] = [];

        logger.info('ScanAgent starting', { scanId: config.scanId, type: config.type });

        try {
            if (config.type === 'web') {
                await this.executeWebScan(config, findings, errors);
            } else {
                await this.executeMobileScan(config, findings, errors);
            }

            // If AI enhancement is enabled, enrich findings
            if (config.options?.aiEnhanced) {
                await this.enhanceWithAI(findings);
            }

            const duration = Date.now() - startTime;
            logger.info('ScanAgent completed', {
                scanId: config.scanId,
                findingsCount: findings.length,
                duration
            });

            return {
                success: errors.length === 0,
                scanId: config.scanId,
                findings,
                duration,
                errors: errors.length > 0 ? errors : undefined,
            };
        } catch (error: any) {
            logger.error('ScanAgent failed', { scanId: config.scanId, error: error.message });
            return {
                success: false,
                scanId: config.scanId,
                findings,
                duration: Date.now() - startTime,
                errors: [error.message],
            };
        }
    }

    private async executeWebScan(
        config: ScanConfig,
        findings: Finding[],
        errors: string[]
    ): Promise<void> {
        // Check Burp availability
        const burpAvailable = await this.burpService.isAvailable();

        if (burpAvailable) {
            logger.info('Using Burp Suite for web scan', { scanId: config.scanId });
            await this.burpService.scan(config.scanId, config.target);
        } else {
            logger.warn('Burp Suite not available, using fallback scan');
            // Perform basic checks using fetch
            await this.basicWebChecks(config.target, findings);
        }

        // OWASP specific tests
        if (config.options?.owaspTests) {
            for (const test of config.options.owaspTests) {
                await this.runOwaspTest(config.target, test, findings, errors);
            }
        }
    }

    private async executeMobileScan(
        config: ScanConfig,
        findings: Finding[],
        errors: string[]
    ): Promise<void> {
        const mobsfAvailable = await this.mobsfService.isAvailable();

        if (mobsfAvailable) {
            logger.info('Using MobSF for mobile scan', { scanId: config.scanId });
            await this.mobsfService.analyze(config.scanId, config.target);
        } else {
            logger.warn('MobSF not available, using fallback analysis');
            findings.push({
                name: 'MobSF Not Available',
                severity: 'info',
                description: 'Mobile Security Framework is not running. Install and configure MobSF for full analysis.',
            });
        }
    }

    private async basicWebChecks(target: string, findings: Finding[]): Promise<void> {
        try {
            const response = await fetch(target, { method: 'GET' });
            const headers = response.headers;

            // Check security headers
            const securityHeaders = [
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection',
                'strict-transport-security',
                'content-security-policy',
            ];

            for (const header of securityHeaders) {
                if (!headers.get(header)) {
                    findings.push({
                        name: `Missing Security Header: ${header}`,
                        severity: 'medium',
                        description: `The application does not set the ${header} header.`,
                        location: target,
                    });
                }
            }

            // Check for server information disclosure
            const server = headers.get('server');
            if (server) {
                findings.push({
                    name: 'Server Information Disclosure',
                    severity: 'low',
                    description: `Server header reveals: ${server}`,
                    location: target,
                });
            }
        } catch (error: any) {
            logger.warn('Basic web checks failed', { target, error: error.message });
        }
    }

    private async runOwaspTest(
        target: string,
        testId: string,
        findings: Finding[],
        errors: string[]
    ): Promise<void> {
        // This would contain specific OWASP test implementations
        // For MVP, we log the test and add placeholder
        logger.info('Running OWASP test', { target, testId });

        // Test implementations would go here
        // Examples: A01 Broken Access Control, A02 Cryptographic Failures, etc.
    }

    private async enhanceWithAI(findings: Finding[]): Promise<void> {
        // This would integrate with LLM provider for enhanced analysis
        // For MVP, we add remediation suggestions based on finding type
        logger.info('Enhancing findings with AI');

        const remediations: Record<string, string> = {
            'SQL Injection': 'Use parameterized queries and input validation.',
            'Cross-Site Scripting': 'Implement output encoding and CSP.',
            'Missing Security Header': 'Add appropriate security headers to server configuration.',
        };

        for (const finding of findings) {
            for (const [pattern, remediation] of Object.entries(remediations)) {
                if (finding.name.includes(pattern)) {
                    (finding as any).remediation = remediation;
                    break;
                }
            }
        }
    }
}

// CLI execution
if (require.main === module) {
    const agent = new ScanAgent();

    const config: ScanConfig = {
        scanId: process.argv[2] || 'test-scan',
        type: (process.argv[3] as 'web' | 'mobile') || 'web',
        target: process.argv[4] || 'http://localhost:5000',
        options: {
            aiEnhanced: true,
        },
    };

    agent.execute(config).then((result) => {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.success ? 0 : 1);
    });
}
