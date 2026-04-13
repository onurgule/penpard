import path from 'path';
import type { SourceAnalysisResult } from './source-analysis/SourceAnalysisMode';
import { createDeterministicReportModel, createSnapshotFingerprint } from './reporting/reporting-model';
import { renderDocxReport } from './reporting/renderers/docxRenderer';
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

interface DocxOptions {
    llmEnhanced?: boolean;
    enhancedDescriptions?: Map<number, string>;
    sourceAnalysis?: SourceAnalysisResult | null;
}

export async function generateDocxReport(
    scan: Scan,
    vulnerabilities: Vulnerability[],
    options: DocxOptions = {},
): Promise<string> {
    ensureReportsDir();
    const fingerprint = createSnapshotFingerprint(scan as any, vulnerabilities as any[], options.sourceAnalysis);
    const report = createDeterministicReportModel(scan as any, vulnerabilities as any[], options.sourceAnalysis, fingerprint);

    if (options.enhancedDescriptions) {
        report.findings = report.findings.map((finding) => ({
            ...finding,
            description: options.enhancedDescriptions?.get(finding.id) || finding.description,
        }));
        report.narrativeMeta = {
            enrichmentMode: options.llmEnhanced ? 'llm' : 'deterministic',
            llmEnriched: Boolean(options.llmEnhanced),
            llmFailed: false,
            llmFailureReason: null,
        };
    }

    const outputPath = path.join(REPORTS_DIR, `report-${scan.id}.docx`);
    await renderDocxReport(report, outputPath);
    return outputPath;
}
