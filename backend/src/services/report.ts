import path from 'path';
import type { SourceAnalysisResult } from './source-analysis/SourceAnalysisMode';
import { createDeterministicReportModel, createSnapshotFingerprint } from './reporting/reporting-model';
import { renderPdfReport } from './reporting/renderers/pdfRenderer';
import { REPORTS_DIR, ensureReportsDir } from './reporting/renderers/shared';

interface Scan {
    id: string;
    type: string;
    target: string;
    status: string;
    created_at: string;
    completed_at?: string | null;
}

interface Vulnerability {
    id: number;
    name: string;
    description?: string | null;
    severity: string;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe?: string | null;
    cve?: string | null;
    request?: string | null;
    response?: string | null;
    evidence?: string | null;
    remediation?: string | null;
    screenshot_path?: string | null;
}

export async function generatePdfReport(
    scan: Scan,
    vulnerabilities: Vulnerability[],
    sourceAnalysis?: SourceAnalysisResult | null,
): Promise<string> {
    ensureReportsDir();
    const fingerprint = createSnapshotFingerprint(scan as any, vulnerabilities as any[], sourceAnalysis);
    const report = createDeterministicReportModel(scan as any, vulnerabilities as any[], sourceAnalysis, fingerprint);
    const outputPath = path.join(REPORTS_DIR, `report-${scan.id}.pdf`);
    await renderPdfReport(report, outputPath);
    return outputPath;
}
