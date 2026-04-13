export type ReportExportFormat = 'pdf' | 'docx' | 'pptx';
export type ReportEnrichmentMode = 'deterministic' | 'llm';
export type ReportExportStage =
    | 'idle'
    | 'queued'
    | 'collecting_data'
    | 'composing_report'
    | 'enriching_with_llm'
    | 'rendering_export'
    | 'completed'
    | 'failed'
    | 'canceled';
export type ReportExportStatus = 'pending' | 'running' | 'completed' | 'failed' | 'canceled';
export type ReportLlmStatus = 'not_requested' | 'queued' | 'running' | 'completed' | 'failed' | 'skipped';

export interface ReportExportJob {
    id: string;
    scanId: string;
    snapshotId: string;
    format: ReportExportFormat;
    enrichmentMode: ReportEnrichmentMode;
    status: ReportExportStatus;
    stage: ReportExportStage;
    stageLabel: string;
    llmStatus: ReportLlmStatus;
    artifactReady: boolean;
    errorMessage: string | null;
    llmErrorMessage: string | null;
    attemptCount: number;
    createdAt: string;
    updatedAt: string;
    startedAt: string | null;
    completedAt: string | null;
    canceledAt: string | null;
    downloadUrl: string;
}

export function isTerminalReportExport(job: ReportExportJob | null | undefined): boolean {
    return !!job && ['completed', 'failed', 'canceled'].includes(job.status);
}

export function shouldPollReportExport(job: ReportExportJob | null | undefined): boolean {
    return !!job && ['pending', 'running'].includes(job.status);
}

export function pickPreferredReportExportJob(
    jobs: ReportExportJob[],
    format: ReportExportFormat,
    enrichmentMode: ReportEnrichmentMode,
): ReportExportJob | null {
    const candidates = jobs.filter((job) => job.format === format && job.enrichmentMode === enrichmentMode);
    if (candidates.length === 0) return null;

    return [...candidates].sort(compareJobs)[0];
}

export function compareJobs(left: ReportExportJob, right: ReportExportJob): number {
    return jobPriority(left) - jobPriority(right)
        || dateValue(right.updatedAt) - dateValue(left.updatedAt)
        || dateValue(right.createdAt) - dateValue(left.createdAt);
}

export function getReportExportStageDisplay(job: ReportExportJob | null | undefined): string {
    if (!job) return 'Ready to export';
    if (job.stageLabel) return job.stageLabel;

    switch (job.stage) {
        case 'queued':
            return 'Queued';
        case 'collecting_data':
            return 'Collecting findings';
        case 'composing_report':
            return 'Composing report';
        case 'enriching_with_llm':
            return 'Enriching with LLM';
        case 'rendering_export':
            return `Rendering ${job.format.toUpperCase()}`;
        case 'completed':
            return 'Completed';
        case 'failed':
            return 'Failed';
        case 'canceled':
            return 'Canceled';
        default:
            return 'Ready to export';
    }
}

export function getReportLlmStatusDisplay(job: ReportExportJob | null | undefined): string | null {
    if (!job || job.enrichmentMode !== 'llm') return null;

    switch (job.llmStatus) {
        case 'queued':
            return 'LLM enrichment queued';
        case 'running':
            return 'LLM enrichment running';
        case 'completed':
            return 'LLM enrichment completed';
        case 'failed':
            return job.llmErrorMessage
                ? `LLM enrichment failed: ${job.llmErrorMessage}`
                : 'LLM enrichment failed and the deterministic report was kept';
        case 'skipped':
            return job.llmErrorMessage
                ? `LLM enrichment skipped: ${job.llmErrorMessage}`
                : 'LLM enrichment skipped';
        default:
            return null;
    }
}

function jobPriority(job: ReportExportJob): number {
    switch (job.status) {
        case 'running':
            return 0;
        case 'pending':
            return 1;
        case 'completed':
            return 2;
        case 'failed':
            return 3;
        case 'canceled':
            return 4;
        default:
            return 5;
    }
}

function dateValue(value: string | null | undefined): number {
    if (!value) return 0;
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? 0 : parsed;
}
