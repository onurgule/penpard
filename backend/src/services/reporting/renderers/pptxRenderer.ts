import PptxGenJS from 'pptxgenjs';
import { writeFileAtomically, formatDisplayDate, severityHex } from './shared';
import type { CanonicalReportModel } from '../types';

export async function renderPptxReport(report: CanonicalReportModel, outputPath: string): Promise<void> {
    const pptx = new PptxGenJS();
    pptx.layout = 'LAYOUT_16x9';
    pptx.author = 'PenPard';
    pptx.company = 'PenPard';
    pptx.subject = `Security assessment for ${report.scan.target}`;
    pptx.title = `PenPard Security Assessment - ${report.scan.target}`;

    addTitleSlide(pptx, report);
    addSummarySlide(pptx, report);
    addFindingsOverviewSlide(pptx, report);
    addFindingSlides(pptx, report);
    addRemediationSlide(pptx, report);
    addNotesSlide(pptx, report);

    const buffer = await pptx.write({ outputType: 'nodebuffer' }) as Buffer;
    await writeFileAtomically(outputPath, buffer);
}

function addTitleSlide(pptx: PptxGenJS, report: CanonicalReportModel): void {
    const slide = pptx.addSlide();
    slide.background = { color: '0F172A' };
    slide.addText('PENPARD', { x: 0.5, y: 0.5, w: 4, h: 0.5, fontFace: 'Calibri', fontSize: 28, bold: true, color: '22D3EE' });
    slide.addText('Security Assessment Report', { x: 0.5, y: 1.2, w: 7, h: 0.5, fontFace: 'Calibri', fontSize: 24, bold: true, color: 'FFFFFF' });
    slide.addText(`Target: ${report.scan.target}`, { x: 0.5, y: 2.1, w: 10, h: 0.3, fontFace: 'Calibri', fontSize: 16, color: 'E2E8F0' });
    slide.addText(`Scan ID: ${report.scan.id}`, { x: 0.5, y: 2.5, w: 10, h: 0.3, fontFace: 'Calibri', fontSize: 12, color: '94A3B8' });
    slide.addText(`Created: ${formatDisplayDate(report.scan.createdAt)}`, { x: 0.5, y: 2.85, w: 10, h: 0.3, fontFace: 'Calibri', fontSize: 12, color: '94A3B8' });
    slide.addText(`Completed: ${formatDisplayDate(report.scan.completedAt)}`, { x: 0.5, y: 3.2, w: 10, h: 0.3, fontFace: 'Calibri', fontSize: 12, color: '94A3B8' });
    slide.addText(`Overall risk: ${report.summary.riskRating}`, { x: 0.5, y: 4.0, w: 10, h: 0.35, fontFace: 'Calibri', fontSize: 18, bold: true, color: 'F87171' });
    slide.addText(`Total findings: ${report.summary.totalFindings}`, { x: 0.5, y: 4.45, w: 10, h: 0.35, fontFace: 'Calibri', fontSize: 18, bold: true, color: 'FFFFFF' });
}

function addSummarySlide(pptx: PptxGenJS, report: CanonicalReportModel): void {
    const slide = createStandardSlide(pptx, 'Executive Summary');
    slide.addText(report.summary.executiveSummary, { x: 0.5, y: 1.2, w: 6.2, h: 1.8, fontFace: 'Calibri', fontSize: 18, color: 'E2E8F0', valign: 'top' });
    slide.addText(report.summary.methodology, { x: 0.5, y: 3.2, w: 6.2, h: 1.0, fontFace: 'Calibri', fontSize: 12, color: 'CBD5E1' });
    slide.addText(report.summary.remediationOverview, { x: 0.5, y: 4.4, w: 6.2, h: 1.1, fontFace: 'Calibri', fontSize: 12, color: 'CBD5E1' });

    let y = 1.3;
    Object.entries(report.summary.countsBySeverity).forEach(([severity, count]) => {
        slide.addShape('rect', { x: 7.4, y, w: 2.1, h: 0.4, fill: { color: severityHex(severity as any) }, line: { color: severityHex(severity as any) } });
        slide.addText(`${severity.toUpperCase()}: ${count}`, { x: 7.55, y: y + 0.07, w: 1.8, h: 0.2, fontFace: 'Calibri', fontSize: 11, bold: true, color: 'FFFFFF', align: 'center' });
        y += 0.55;
    });
}

function addFindingsOverviewSlide(pptx: PptxGenJS, report: CanonicalReportModel): void {
    const slide = createStandardSlide(pptx, 'Findings Overview');
    if (report.findingsSummary.length === 0) {
        slide.addText('No vulnerabilities were recorded in this snapshot.', { x: 0.5, y: 1.3, w: 12, h: 0.5, fontFace: 'Calibri', fontSize: 20, color: 'CBD5E1' });
        return;
    }

    const rows = [
        [
            { text: '#', options: { bold: true, color: 'FFFFFF', fill: { color: '1E293B' } } },
            { text: 'Finding', options: { bold: true, color: 'FFFFFF', fill: { color: '1E293B' } } },
            { text: 'Severity', options: { bold: true, color: 'FFFFFF', fill: { color: '1E293B' } } },
            { text: 'CVSS', options: { bold: true, color: 'FFFFFF', fill: { color: '1E293B' } } },
        ],
        ...report.findingsSummary.slice(0, 15).map((finding, index) => ([
            { text: String(index + 1), options: { color: 'E2E8F0' } },
            { text: finding.title, options: { color: 'E2E8F0' } },
            { text: finding.severity.toUpperCase(), options: { color: 'FFFFFF', bold: true, fill: { color: severityHex(finding.severity) } } },
            { text: finding.cvssScore ? String(finding.cvssScore) : '-', options: { color: 'E2E8F0' } },
        ])),
    ];

    slide.addTable(rows as any, {
        x: 0.4,
        y: 1.2,
        w: 12.4,
        border: { type: 'solid', pt: 0.5, color: '334155' },
        colW: [0.6, 7.4, 2.2, 1.8],
    });
}

function addFindingSlides(pptx: PptxGenJS, report: CanonicalReportModel): void {
    for (const [index, finding] of report.findings.entries()) {
        const slide = createStandardSlide(pptx, `Finding ${index + 1}`);
    slide.addShape('rect', { x: 0.4, y: 1.0, w: 2.2, h: 0.35, fill: { color: severityHex(finding.severity) }, line: { color: severityHex(finding.severity) } });
        slide.addText(finding.severity.toUpperCase(), { x: 0.4, y: 1.06, w: 2.2, h: 0.2, fontFace: 'Calibri', fontSize: 12, bold: true, color: 'FFFFFF', align: 'center' });
        slide.addText(finding.title, { x: 0.4, y: 1.55, w: 12, h: 0.35, fontFace: 'Calibri', fontSize: 20, bold: true, color: 'FFFFFF' });

        const metadata = [
            finding.endpoint ? `Endpoint: ${finding.endpoint}` : null,
            finding.cvssScore ? `CVSS ${finding.cvssScore}` : null,
            finding.cwe ? `CWE-${finding.cwe}` : null,
            finding.cve ? finding.cve : null,
        ].filter(Boolean).join(' | ');
        if (metadata) {
            slide.addText(metadata, { x: 0.4, y: 1.95, w: 12.2, h: 0.25, fontFace: 'Courier New', fontSize: 9, color: '94A3B8' });
        }

        slide.addText('Description', { x: 0.4, y: 2.4, w: 2, h: 0.2, fontFace: 'Calibri', fontSize: 12, bold: true, color: '22D3EE' });
        slide.addText(finding.description.slice(0, 650), { x: 0.4, y: 2.65, w: 6.0, h: 1.6, fontFace: 'Calibri', fontSize: 11, color: 'E2E8F0', valign: 'top' });

        slide.addText('Impact', { x: 0.4, y: 4.35, w: 2, h: 0.2, fontFace: 'Calibri', fontSize: 12, bold: true, color: '22D3EE' });
        slide.addText(finding.impact.slice(0, 360), { x: 0.4, y: 4.6, w: 6.0, h: 1.0, fontFace: 'Calibri', fontSize: 11, color: 'E2E8F0', valign: 'top' });

        slide.addText('Remediation', { x: 6.8, y: 2.4, w: 2, h: 0.2, fontFace: 'Calibri', fontSize: 12, bold: true, color: '4ADE80' });
        slide.addText(finding.remediation.slice(0, 520), { x: 6.8, y: 2.65, w: 5.8, h: 1.6, fontFace: 'Calibri', fontSize: 11, color: 'E2E8F0', valign: 'top' });

        const evidenceText = finding.evidence.request || finding.evidence.additional || finding.evidence.response || 'No textual evidence stored.';
        slide.addText('Evidence', { x: 6.8, y: 4.45, w: 2, h: 0.2, fontFace: 'Calibri', fontSize: 12, bold: true, color: 'FBBF24' });
        slide.addText(evidenceText.slice(0, 700), { x: 6.8, y: 4.7, w: 5.8, h: 1.7, fontFace: 'Courier New', fontSize: 8, color: 'CBD5E1', valign: 'top' });
    }
}

function addRemediationSlide(pptx: PptxGenJS, report: CanonicalReportModel): void {
    const slide = createStandardSlide(pptx, 'Remediation Priority');
    let y = 1.2;
    report.remediationPriorities.forEach((priority) => {
        slide.addText(priority.label, { x: 0.5, y, w: 4, h: 0.25, fontFace: 'Calibri', fontSize: 16, bold: true, color: 'FFFFFF' });
        y += 0.3;
        slide.addText(priority.description, { x: 0.7, y, w: 11.8, h: 0.35, fontFace: 'Calibri', fontSize: 11, color: 'CBD5E1' });
        y += 0.4;
        priority.findingIds.slice(0, 6).forEach((findingId) => {
            const finding = report.findings.find((entry) => entry.id === findingId);
            if (!finding) return;
            slide.addText(`- ${finding.title} [${finding.severity.toUpperCase()}]`, { x: 1.0, y, w: 11.2, h: 0.25, fontFace: 'Calibri', fontSize: 10, color: 'E2E8F0' });
            y += 0.22;
        });
        y += 0.18;
    });
}

function addNotesSlide(pptx: PptxGenJS, report: CanonicalReportModel): void {
    const slide = createStandardSlide(pptx, 'Export Notes');
    slide.addText('This report was rendered from a persisted canonical snapshot. Export state and optional LLM enrichment are tracked separately from scan execution.', {
        x: 0.5,
        y: 1.3,
        w: 11.8,
        h: 0.8,
        fontFace: 'Calibri',
        fontSize: 16,
        color: 'E2E8F0',
    });
    slide.addText(`Enrichment mode: ${report.narrativeMeta.enrichmentMode}`, { x: 0.5, y: 2.5, w: 6, h: 0.25, fontFace: 'Calibri', fontSize: 13, color: 'CBD5E1' });
    slide.addText(`LLM enriched: ${report.narrativeMeta.llmEnriched ? 'yes' : 'no'}`, { x: 0.5, y: 2.9, w: 6, h: 0.25, fontFace: 'Calibri', fontSize: 13, color: 'CBD5E1' });
    if (report.narrativeMeta.llmFailureReason) {
        slide.addText(`LLM note: ${report.narrativeMeta.llmFailureReason}`, { x: 0.5, y: 3.3, w: 12, h: 0.5, fontFace: 'Calibri', fontSize: 12, color: 'FBBF24' });
    }
}

function createStandardSlide(pptx: PptxGenJS, title: string) {
    const slide = pptx.addSlide();
    slide.background = { color: '0F172A' };
    slide.addShape('rect', { x: 0, y: 0, w: 13.33, h: 0.12, fill: { color: '22D3EE' }, line: { color: '22D3EE' } });
    slide.addText('PENPARD', { x: 0.4, y: 0.25, w: 2.0, h: 0.25, fontFace: 'Calibri', fontSize: 12, bold: true, color: '22D3EE' });
    slide.addText(title, { x: 0.4, y: 0.65, w: 10, h: 0.35, fontFace: 'Calibri', fontSize: 22, bold: true, color: 'FFFFFF' });
    return slide;
}
