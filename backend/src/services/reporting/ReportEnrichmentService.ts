import { llmQueue } from '../LLMQueue';
import { llmProvider } from '../LLMProviderService';
import { logger } from '../../utils/logger';
import { applyNarrativePatch } from './reporting-model';
import { reportNarrativePatchSchema } from './types';
import type { CanonicalReportModel, ReportLlmStatus } from './types';

interface EnrichmentOptions {
    scanId: string;
    reportExportId: string;
}

interface EnrichmentResult {
    report: CanonicalReportModel;
    llmStatus: ReportLlmStatus;
    errorMessage: string | null;
}

export class ReportEnrichmentService {
    public async enrichReport(baseReport: CanonicalReportModel, options: EnrichmentOptions): Promise<EnrichmentResult> {
        try {
            llmProvider.getActiveConfig();
        } catch (error: any) {
            logger.warn('Skipping report enrichment because no active LLM is configured', {
                scanId: options.scanId,
                reportExportId: options.reportExportId,
                error: error.message,
            });

            return {
                report: {
                    ...baseReport,
                    narrativeMeta: {
                        enrichmentMode: 'llm',
                        llmEnriched: false,
                        llmFailed: true,
                        llmFailureReason: 'No active LLM provider configured.',
                    },
                },
                llmStatus: 'skipped',
                errorMessage: 'No active LLM provider configured.',
            };
        }

        const promptPayload = {
            target: baseReport.scan.target,
            scanType: baseReport.scan.type,
            riskRating: baseReport.summary.riskRating,
            countsBySeverity: baseReport.summary.countsBySeverity,
            currentExecutiveSummary: baseReport.summary.executiveSummary,
            currentRemediationOverview: baseReport.summary.remediationOverview,
            findings: baseReport.findings.map((finding) => ({
                findingId: finding.id,
                title: finding.title,
                severity: finding.severity,
                endpoint: finding.endpoint,
                cvssScore: finding.cvssScore,
                cwe: finding.cwe,
                cve: finding.cve,
                description: finding.description,
                impact: finding.impact,
                remediation: finding.remediation,
            })),
        };

        const response = await llmQueue.enqueue({
            systemPrompt: 'You improve penetration test report narratives. Return ONLY valid JSON that matches the requested schema. Do not wrap the JSON in markdown.',
            userPrompt: [
                'Improve the following report narratives while staying evidence-bound and professional.',
                'Requirements:',
                '- Do not invent findings, endpoints, evidence, or remediation steps.',
                '- Keep language concise and suitable for a formal security report.',
                '- Only reference finding IDs that already exist in the input.',
                '- Omit any field you do not want to change.',
                '- Return JSON with this shape:',
                '{"executiveSummary?: string, "remediationOverview"?: string, "findings": [{"findingId": number, "description"?: string, "impact"?: string, "remediation"?: string}]}',
                '',
                stableJson(promptPayload),
            ].join('\n'),
            temperature: 0,
        }, {
            scanId: options.scanId,
            reportExportId: options.reportExportId,
            context: 'report-export-enrichment',
        });

        try {
            const parsed = parsePatch(response.text);
            return {
                report: applyNarrativePatch(baseReport, parsed, 'llm'),
                llmStatus: 'completed',
                errorMessage: null,
            };
        } catch (error: any) {
            logger.warn('Report enrichment returned invalid structured output', {
                scanId: options.scanId,
                reportExportId: options.reportExportId,
                error: error.message,
            });

            return {
                report: {
                    ...baseReport,
                    narrativeMeta: {
                        enrichmentMode: 'llm',
                        llmEnriched: false,
                        llmFailed: true,
                        llmFailureReason: error.message,
                    },
                },
                llmStatus: 'failed',
                errorMessage: error.message,
            };
        }
    }
}

function parsePatch(rawText: string) {
    const trimmed = rawText.trim();
    const objectMatch = trimmed.match(/\{[\s\S]*\}/);
    const candidate = objectMatch ? objectMatch[0] : trimmed;
    const parsed = JSON.parse(candidate);
    return reportNarrativePatchSchema.parse(parsed);
}

function stableJson(value: unknown): string {
    return JSON.stringify(value, null, 2);
}

export const reportEnrichmentService = new ReportEnrichmentService();
