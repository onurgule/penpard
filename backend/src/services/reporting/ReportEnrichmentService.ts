import { llmRuntime } from '../llm/LlmRuntime';
import { llmProvider } from '../LLMProviderService';
import { buildJsonSchemaResponseFormat, parseStructuredJsonResponse } from '../llm/LlmStructuredOutput';
import { logger } from '../../utils/logger';
import { applyNarrativePatch } from './reporting-model';
import { reportNarrativePatchSchema } from './types';
import type { CanonicalReportModel, ReportLlmStatus } from './types';

interface EnrichmentOptions {
    scanId: string;
    userId?: number;
    reportExportId: string;
    signal?: AbortSignal;
}

interface EnrichmentResult {
    report: CanonicalReportModel;
    llmStatus: ReportLlmStatus;
    errorMessage: string | null;
}

const REPORT_NARRATIVE_PATCH_JSON_SCHEMA = {
    type: 'object',
    additionalProperties: false,
    properties: {
        executiveSummary: { type: 'string', minLength: 1, maxLength: 2500 },
        remediationOverview: { type: 'string', minLength: 1, maxLength: 2500 },
        findings: {
            type: 'array',
            maxItems: 250,
            items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    findingId: { type: 'integer', minimum: 1 },
                    description: { type: 'string', minLength: 1, maxLength: 3000 },
                    impact: { type: 'string', minLength: 1, maxLength: 2000 },
                    remediation: { type: 'string', minLength: 1, maxLength: 2500 },
                },
                required: ['findingId'],
            },
        },
    },
};

export class ReportEnrichmentService {
    public async enrichReport(baseReport: CanonicalReportModel, options: EnrichmentOptions): Promise<EnrichmentResult> {
        try {
            llmProvider.getActiveConfig(options.userId);
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

        const response = await llmRuntime.generate({
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
            responseFormat: buildJsonSchemaResponseFormat('report_narrative_patch', REPORT_NARRATIVE_PATCH_JSON_SCHEMA),
            reasoningMode: 'disabled',
        }, {
            scanId: options.scanId,
            userId: options.userId,
            reportExportId: options.reportExportId,
            callSite: 'report_enrichment',
            context: 'report-export-enrichment',
            maxAttempts: 1,
            retryBudgetMs: null,
            slowFirstProgressWarningMs: null,
            finalizationGraceMs: null,
            queueWaitTimeoutMs: null,
            executionWatchdogMs: null,
            signal: options.signal,
        });

        try {
            const parsed = parseStructuredJsonResponse(response, {
                label: 'Report narrative patch',
                schema: reportNarrativePatchSchema,
            });
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

function stableJson(value: unknown): string {
    return JSON.stringify(value, null, 2);
}

export const reportEnrichmentService = new ReportEnrichmentService();
