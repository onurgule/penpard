import { z } from 'zod';
import type { ReportSection } from '../source-analysis/SourceReportEnricher';

export const reportExportFormatValues = ['pdf', 'docx', 'pptx'] as const;
export type ReportExportFormat = (typeof reportExportFormatValues)[number];

export const reportEnrichmentModeValues = ['deterministic', 'llm'] as const;
export type ReportEnrichmentMode = (typeof reportEnrichmentModeValues)[number];

export const reportExportStageValues = [
    'idle',
    'queued',
    'collecting_data',
    'composing_report',
    'enriching_with_llm',
    'rendering_export',
    'completed',
    'failed',
    'canceled',
] as const;
export type ReportExportStage = (typeof reportExportStageValues)[number];

export const reportExportStatusValues = ['pending', 'running', 'completed', 'failed', 'canceled'] as const;
export type ReportExportStatus = (typeof reportExportStatusValues)[number];

export const reportLlmStatusValues = ['not_requested', 'queued', 'running', 'completed', 'failed', 'skipped'] as const;
export type ReportLlmStatus = (typeof reportLlmStatusValues)[number];

export const reportSeverityValues = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type ReportSeverity = (typeof reportSeverityValues)[number];

export type CountsBySeverity = Record<ReportSeverity, number>;

export interface CanonicalReportFinding {
    id: number;
    title: string;
    severity: ReportSeverity;
    sortOrder: number;
    cvssScore: number | null;
    cvssVector: string | null;
    cwe: string | null;
    cve: string | null;
    endpoint: string | null;
    description: string;
    impact: string;
    remediation: string;
    evidence: {
        request: string | null;
        response: string | null;
        additional: string | null;
        screenshotPath: string | null;
    };
}

export interface CanonicalReportModel {
    schemaVersion: 1;
    fingerprint: string;
    generatedAt: string;
    scan: {
        id: string;
        target: string;
        type: string;
        status: string;
        createdAt: string;
        completedAt: string | null;
        duration: string | null;
    };
    summary: {
        riskRating: string;
        totalFindings: number;
        countsBySeverity: CountsBySeverity;
        executiveSummary: string;
        methodology: string;
        scopeSummary: string;
        remediationOverview: string;
    };
    findingsSummary: Array<{
        id: number;
        title: string;
        severity: ReportSeverity;
        cvssScore: number | null;
        cwe: string | null;
    }>;
    findings: CanonicalReportFinding[];
    remediationPriorities: Array<{
        label: string;
        description: string;
        severityLevels: ReportSeverity[];
        findingIds: number[];
    }>;
    sourceIntelligence: ReportSection | null;
    narrativeMeta: {
        enrichmentMode: ReportEnrichmentMode;
        llmEnriched: boolean;
        llmFailed: boolean;
        llmFailureReason: string | null;
    };
}

export interface ReportSnapshotRecord {
    id: string;
    scan_id: string;
    fingerprint: string;
    report_json: string;
    created_at: string;
    updated_at: string;
}

export interface ReportExportRecord {
    id: string;
    scan_id: string;
    snapshot_id: string;
    snapshot_fingerprint: string;
    format: ReportExportFormat;
    enrichment_mode: ReportEnrichmentMode;
    status: ReportExportStatus;
    stage: ReportExportStage;
    llm_status: ReportLlmStatus;
    artifact_path: string | null;
    resolved_report_json: string | null;
    error_message: string | null;
    llm_error_message: string | null;
    attempt_count: number;
    created_at: string;
    updated_at: string;
    started_at: string | null;
    completed_at: string | null;
    canceled_at: string | null;
}

export const reportNarrativeFindingPatchSchema = z.object({
    findingId: z.number().int().positive(),
    description: z.string().min(1).max(3000).optional(),
    impact: z.string().min(1).max(2000).optional(),
    remediation: z.string().min(1).max(2500).optional(),
});

export const reportNarrativePatchSchema = z.object({
    executiveSummary: z.string().min(1).max(2500).optional(),
    remediationOverview: z.string().min(1).max(2500).optional(),
    findings: z.array(reportNarrativeFindingPatchSchema).max(250).default([]),
}).strict();

export type ReportNarrativePatch = z.infer<typeof reportNarrativePatchSchema>;
