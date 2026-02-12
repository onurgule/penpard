/**
 * Oversight Agent - Orchestrates the full scanning pipeline
 * 
 * This agent chains together Scan, Recheck, and Report agents,
 * handling errors, retries, and status updates.
 */

import { logger } from '../backend/src/utils/logger';
import { ScanAgent, ScanConfig, ScanResult } from './scan-agent';
import { RecheckAgent, RecheckInput, RecheckResult } from './recheck-agent';
import { ReportAgent, ReportInput, ReportOutput } from './report-agent';
import { updateScanStatus, addVulnerability } from '../backend/src/db/init';

export interface OversightConfig {
    scanId: string;
    type: 'web' | 'mobile';
    target: string;
    options?: {
        skipRecheck?: boolean;
        skipReport?: boolean;
        retryCount?: number;
    };
}

export interface OversightResult {
    success: boolean;
    scanId: string;
    stages: {
        scan: { success: boolean; duration: number; findingsCount: number };
        recheck?: { success: boolean; duration: number; confirmedCount: number };
        report?: { success: boolean; reportPath?: string };
    };
    totalDuration: number;
    errors: string[];
}

export class OversightAgent {
    private scanAgent: ScanAgent;
    private recheckAgent: RecheckAgent;
    private reportAgent: ReportAgent;

    constructor() {
        this.scanAgent = new ScanAgent();
        this.recheckAgent = new RecheckAgent();
        this.reportAgent = new ReportAgent();
    }

    async execute(config: OversightConfig): Promise<OversightResult> {
        const startTime = Date.now();
        const errors: string[] = [];
        const retryCount = config.options?.retryCount ?? 3;

        logger.info('OversightAgent starting pipeline', {
            scanId: config.scanId,
            type: config.type
        });

        const result: OversightResult = {
            success: false,
            scanId: config.scanId,
            stages: {
                scan: { success: false, duration: 0, findingsCount: 0 },
            },
            totalDuration: 0,
            errors: [],
        };

        try {
            // Stage 1: Scan
            logger.info('Stage 1: Running scan', { scanId: config.scanId });
            updateScanStatus(config.scanId, 'scanning');

            let scanResult: ScanResult | null = null;
            for (let attempt = 1; attempt <= retryCount; attempt++) {
                try {
                    scanResult = await this.scanAgent.execute({
                        scanId: config.scanId,
                        type: config.type,
                        target: config.target,
                        options: { aiEnhanced: true },
                    });

                    if (scanResult.success) break;

                    logger.warn(`Scan attempt ${attempt} failed, retrying...`);
                } catch (error: any) {
                    logger.error(`Scan attempt ${attempt} error`, { error: error.message });
                    if (attempt === retryCount) throw error;
                }
            }

            if (!scanResult || !scanResult.success) {
                throw new Error('Scan failed after retries');
            }

            result.stages.scan = {
                success: true,
                duration: scanResult.duration,
                findingsCount: scanResult.findings.length,
            };

            // Store findings
            for (const finding of scanResult.findings) {
                addVulnerability({
                    scanId: config.scanId,
                    name: finding.name,
                    description: finding.description,
                    severity: finding.severity,
                });
            }

            // Stage 2: Recheck (optional)
            if (!config.options?.skipRecheck && scanResult.findings.length > 0) {
                logger.info('Stage 2: Running recheck', { scanId: config.scanId });
                updateScanStatus(config.scanId, 'rechecking');

                const recheckResult = await this.recheckAgent.execute({
                    scanId: config.scanId,
                    target: config.target,
                    findings: scanResult.findings,
                });

                result.stages.recheck = {
                    success: true,
                    duration: recheckResult.duration,
                    confirmedCount: recheckResult.confirmedFindings.length,
                };

                logger.info('Recheck complete', {
                    confirmed: recheckResult.confirmedFindings.length,
                    falsePositives: recheckResult.falsePositives.length,
                });
            }

            // Stage 3: Report (optional)
            if (!config.options?.skipReport) {
                logger.info('Stage 3: Generating report', { scanId: config.scanId });
                updateScanStatus(config.scanId, 'reporting');

                const reportResult = await this.reportAgent.execute({
                    scanId: config.scanId,
                    format: 'pdf',
                    includeEvidence: true,
                    includeRemediation: true,
                });

                result.stages.report = {
                    success: reportResult.success,
                    reportPath: reportResult.reportPath,
                };
            }

            // Complete
            result.success = true;
            updateScanStatus(config.scanId, 'completed');

        } catch (error: any) {
            logger.error('OversightAgent pipeline failed', {
                scanId: config.scanId,
                error: error.message
            });
            errors.push(error.message);
            updateScanStatus(config.scanId, 'failed', error.message);
        }

        result.totalDuration = Date.now() - startTime;
        result.errors = errors;

        logger.info('OversightAgent completed', {
            scanId: config.scanId,
            success: result.success,
            totalDuration: result.totalDuration,
        });

        return result;
    }

    async runFullPipeline(config: OversightConfig): Promise<void> {
        // This is used for background execution from the API
        try {
            await this.execute(config);
        } catch (error: any) {
            logger.error('Full pipeline failed', { scanId: config.scanId, error: error.message });
            updateScanStatus(config.scanId, 'failed', error.message);
        }
    }
}

// CLI execution
if (require.main === module) {
    const agent = new OversightAgent();

    const config: OversightConfig = {
        scanId: process.argv[2] || 'test-scan',
        type: (process.argv[3] as 'web' | 'mobile') || 'web',
        target: process.argv[4] || 'http://localhost:5000',
    };

    agent.execute(config).then((result) => {
        console.log(JSON.stringify(result, null, 2));
        process.exit(result.success ? 0 : 1);
    });
}
