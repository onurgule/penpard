import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';
import { logger } from '../utils/logger';
import { addVulnerability, updateScanStatus } from '../db/init';

const MOBSF_API_URL = process.env.MOBSF_API_URL || 'http://host.docker.internal:8000';
const MOBSF_API_KEY = process.env.MOBSF_API_KEY || '';

interface MobSFFinding {
    title: string;
    description: string;
    severity: string;
    section?: string;
}

export class MobSFService {
    private baseUrl: string;
    private apiKey: string;

    constructor() {
        this.baseUrl = MOBSF_API_URL;
        this.apiKey = MOBSF_API_KEY;
    }

    async isAvailable(): Promise<boolean> {
        try {
            const response = await axios.get(`${this.baseUrl}/api/v1/scans`, {
                headers: { Authorization: this.apiKey },
                timeout: 5000,
            });
            return response.status === 200;
        } catch (error) {
            logger.warn('MobSF API not available', { url: this.baseUrl });
            return false;
        }
    }

    async analyze(scanId: string, apkPath: string): Promise<void> {
        logger.info('Starting MobSF analysis', { scanId, apkPath });

        try {
            // Upload the APK
            updateScanStatus(scanId, 'uploading');

            const formData = new FormData();
            formData.append('file', fs.createReadStream(apkPath));

            const uploadResponse = await axios.post(
                `${this.baseUrl}/api/v1/upload`,
                formData,
                {
                    headers: {
                        Authorization: this.apiKey,
                        ...formData.getHeaders(),
                    },
                    maxContentLength: Infinity,
                    maxBodyLength: Infinity,
                }
            );

            const { hash, file_name, scan_type } = uploadResponse.data;
            logger.info('APK uploaded to MobSF', { scanId, hash, file_name });

            // Start scan
            updateScanStatus(scanId, 'analyzing');

            await axios.post(
                `${this.baseUrl}/api/v1/scan`,
                { hash, scan_type, file_name },
                {
                    headers: { Authorization: this.apiKey },
                }
            );

            // Poll for completion (MobSF scan is usually fast)
            await new Promise((r) => setTimeout(r, 5000));
            updateScanStatus(scanId, 'code_analysis');
            await new Promise((r) => setTimeout(r, 10000));

            // Get the report
            const reportResponse = await axios.post(
                `${this.baseUrl}/api/v1/report_json`,
                { hash },
                {
                    headers: { Authorization: this.apiKey },
                }
            );

            const report = reportResponse.data;
            await this.processReport(scanId, report);

            updateScanStatus(scanId, 'reporting');
        } catch (error: any) {
            logger.error('MobSF analysis error', { scanId, error: error.message });
            throw error;
        }
    }

    private async processReport(scanId: string, report: any): Promise<void> {
        logger.info('Processing MobSF report', { scanId });

        // Process manifest findings
        if (report.manifest_analysis) {
            for (const finding of report.manifest_analysis) {
                if (finding.severity !== 'info') {
                    addVulnerability({
                        scanId,
                        name: finding.title || 'Manifest Issue',
                        description: finding.description,
                        severity: this.mapSeverity(finding.severity),
                        cvssScore: this.estimateCvss(finding.severity),
                        cwe: finding.cwe,
                    });
                }
            }
        }

        // Process code analysis findings
        if (report.code_analysis) {
            for (const [category, findings] of Object.entries(report.code_analysis)) {
                if (Array.isArray(findings)) {
                    for (const finding of findings as MobSFFinding[]) {
                        addVulnerability({
                            scanId,
                            name: finding.title || category,
                            description: finding.description,
                            severity: this.mapSeverity(finding.severity || 'medium'),
                            cvssScore: this.estimateCvss(finding.severity || 'medium'),
                        });
                    }
                }
            }
        }

        // Process binary analysis
        if (report.binary_analysis) {
            for (const finding of report.binary_analysis) {
                addVulnerability({
                    scanId,
                    name: finding.title || 'Binary Issue',
                    description: finding.description,
                    severity: this.mapSeverity(finding.severity || 'low'),
                    cvssScore: this.estimateCvss(finding.severity || 'low'),
                });
            }
        }

        // Check for hardcoded secrets
        if (report.secrets) {
            for (const secret of report.secrets) {
                addVulnerability({
                    scanId,
                    name: 'Hardcoded Secret',
                    description: `Found hardcoded secret: ${secret.type}`,
                    severity: 'high',
                    cvssScore: 7.5,
                    cwe: '798',
                });
            }
        }

        logger.info('MobSF report processed', { scanId });
    }

    private mapSeverity(mobsfSeverity: string): string {
        const map: Record<string, string> = {
            high: 'high',
            warning: 'medium',
            medium: 'medium',
            info: 'low',
            good: 'info',
            secure: 'info',
        };
        return map[mobsfSeverity.toLowerCase()] || 'medium';
    }

    private estimateCvss(severity: string): number {
        const scores: Record<string, number> = {
            high: 7.5,
            warning: 5.5,
            medium: 5.0,
            info: 2.0,
            good: 0.0,
        };
        return scores[severity.toLowerCase()] || 5.0;
    }
}
