import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from 'pdf-lib';
import { writeFileAtomically, formatDisplayDate, safePdfText, severityRgb } from './shared';
import type { CanonicalReportModel } from '../types';

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN = 48;
const CONTENT_WIDTH = PAGE_WIDTH - (MARGIN * 2);

export async function renderPdfReport(report: CanonicalReportModel, outputPath: string): Promise<void> {
    const document = await PDFDocument.create();
    const regularFont = await document.embedFont(StandardFonts.Helvetica);
    const boldFont = await document.embedFont(StandardFonts.HelveticaBold);
    const monoFont = await document.embedFont(StandardFonts.Courier);

    if (typeof (document as any).setCreationDate === 'function') {
        (document as any).setCreationDate(new Date(report.generatedAt));
    }
    if (typeof (document as any).setModificationDate === 'function') {
        (document as any).setModificationDate(new Date(report.generatedAt));
    }

    document.setTitle(`PenPard Security Assessment - ${report.scan.target}`);
    document.setAuthor('PenPard');
    document.setSubject(`Security assessment report for ${report.scan.target}`);
    document.setCreator('PenPard deterministic report pipeline');
    document.setProducer('PenPard deterministic report pipeline');

    const writer = new PdfWriter(document, regularFont, boldFont, monoFont);
    writer.addTitlePage(report);
    writer.addSummarySection(report);
    writer.addFindingsSummary(report);
    writer.addDetailedFindings(report);
    writer.addRemediationSection(report);
    writer.addSourceIntelligence(report);
    writer.addFooterPage(report);

    const bytes = await document.save();
    await writeFileAtomically(outputPath, bytes);
}

class PdfWriter {
    private page!: PDFPage;
    private y = 0;

    constructor(
        private readonly document: PDFDocument,
        private readonly regularFont: PDFFont,
        private readonly boldFont: PDFFont,
        private readonly monoFont: PDFFont,
    ) {}

    public addTitlePage(report: CanonicalReportModel): void {
        this.newPage();
        this.drawHeaderBar(rgb(0.04, 0.52, 0.78));
        this.drawText('PENPARD', {
            x: MARGIN,
            y: PAGE_HEIGHT - 130,
            size: 30,
            font: this.boldFont,
            color: rgb(0.06, 0.52, 0.84),
        });
        this.drawText('Security Assessment Report', {
            x: MARGIN,
            y: PAGE_HEIGHT - 165,
            size: 20,
            font: this.boldFont,
            color: rgb(0.1, 0.1, 0.1),
        });
        this.drawText(`Target: ${report.scan.target}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 235,
            size: 14,
            font: this.boldFont,
            color: rgb(0.1, 0.1, 0.1),
        });
        this.drawText(`Scan ID: ${report.scan.id}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 260,
            size: 12,
            font: this.regularFont,
            color: rgb(0.3, 0.3, 0.3),
        });
        this.drawText(`Started: ${formatDisplayDate(report.scan.createdAt)}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 290,
            size: 12,
            font: this.regularFont,
            color: rgb(0.2, 0.2, 0.2),
        });
        this.drawText(`Completed: ${formatDisplayDate(report.scan.completedAt)}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 310,
            size: 12,
            font: this.regularFont,
            color: rgb(0.2, 0.2, 0.2),
        });
        this.drawText(`Duration: ${report.scan.duration || 'N/A'}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 330,
            size: 12,
            font: this.regularFont,
            color: rgb(0.2, 0.2, 0.2),
        });
        this.drawText(`Overall risk: ${report.summary.riskRating}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 360,
            size: 13,
            font: this.boldFont,
            color: rgb(0.78, 0.15, 0.15),
        });
        this.drawText(`Total findings: ${report.summary.totalFindings}`, {
            x: MARGIN,
            y: PAGE_HEIGHT - 380,
            size: 13,
            font: this.boldFont,
            color: rgb(0.1, 0.1, 0.1),
        });

        this.y = PAGE_HEIGHT - 430;
        this.writeParagraph('Deterministic report composition was used to build this snapshot. Optional narrative enrichment, when enabled, is applied as a separate validated step and never changes the captured findings data.', 11, 16);
    }

    public addSummarySection(report: CanonicalReportModel): void {
        this.newPage();
        this.writeSectionTitle('1. Executive Summary');
        this.writeParagraph(report.summary.executiveSummary, 11, 16);
        this.gap(10);
        this.writeParagraph(report.summary.methodology, 10, 15);
        this.gap(10);
        this.writeParagraph(report.summary.scopeSummary, 10, 15);
        this.gap(12);
        this.writeParagraph(report.summary.remediationOverview, 10, 15);
        this.gap(16);

        for (const [severity, count] of Object.entries(report.summary.countsBySeverity)) {
            const [r, g, b] = severityRgb(severity as any);
            this.ensureSpace(18);
            this.page.drawRectangle({ x: MARGIN, y: this.y - 4, width: 10, height: 10, color: rgb(r, g, b) });
            this.drawText(`${severity.toUpperCase()}: ${count}`, {
                x: MARGIN + 18,
                y: this.y - 1,
                size: 10,
                font: this.boldFont,
                color: rgb(0.18, 0.18, 0.2),
            });
            this.y -= 18;
        }
    }

    public addFindingsSummary(report: CanonicalReportModel): void {
        this.newPage();
        this.writeSectionTitle('2. Findings Summary');
        if (report.findingsSummary.length === 0) {
            this.writeParagraph('No vulnerabilities were recorded in this snapshot.', 11, 16);
            return;
        }

        report.findingsSummary.forEach((finding, index) => {
            this.ensureSpace(20);
            const [r, g, b] = severityRgb(finding.severity);
            this.drawText(`${index + 1}.`, {
                x: MARGIN,
                y: this.y,
                size: 10,
                font: this.boldFont,
                color: rgb(0.05, 0.45, 0.67),
            });
            this.drawText(`${finding.title} [${finding.severity.toUpperCase()}]`, {
                x: MARGIN + 20,
                y: this.y,
                size: 10,
                font: this.boldFont,
                color: rgb(r, g, b),
            });
            const metadata = [
                finding.cvssScore ? `CVSS ${finding.cvssScore}` : null,
                finding.cwe ? `CWE-${finding.cwe}` : null,
            ].filter(Boolean).join(' | ');
            if (metadata) {
                this.drawText(metadata, {
                    x: MARGIN + 20,
                    y: this.y - 11,
                    size: 8,
                    font: this.regularFont,
                    color: rgb(0.35, 0.35, 0.38),
                });
                this.y -= 26;
            } else {
                this.y -= 18;
            }
        });
    }

    public addDetailedFindings(report: CanonicalReportModel): void {
        this.newPage();
        this.writeSectionTitle('3. Detailed Findings');
        if (report.findings.length === 0) {
            this.writeParagraph('No detailed findings are available because the scan produced no vulnerabilities.', 11, 16);
            return;
        }

        report.findings.forEach((finding, index) => {
            this.ensureSpace(120);
            const [r, g, b] = severityRgb(finding.severity);
            this.page.drawRectangle({
                x: MARGIN,
                y: this.y - 6,
                width: CONTENT_WIDTH,
                height: 18,
                color: rgb(r, g, b),
            });
            this.drawText(`${index + 1}. ${finding.title}`, {
                x: MARGIN + 8,
                y: this.y - 1,
                size: 11,
                font: this.boldFont,
                color: rgb(1, 1, 1),
            });
            this.y -= 28;

            const metadata = [
                finding.endpoint ? `Endpoint: ${finding.endpoint}` : null,
                finding.cvssScore ? `CVSS: ${finding.cvssScore}` : null,
                finding.cvssVector ? finding.cvssVector : null,
                finding.cwe ? `CWE-${finding.cwe}` : null,
                finding.cve ? finding.cve : null,
            ].filter(Boolean).join(' | ');
            if (metadata) {
                this.writeParagraph(metadata, 8.5, 12, this.monoFont);
                this.gap(6);
            }

            this.writeLabel('Description');
            this.writeParagraph(finding.description, 10, 14);
            this.gap(6);

            this.writeLabel('Impact');
            this.writeParagraph(finding.impact, 10, 14);
            this.gap(6);

            this.writeLabel('Remediation');
            this.writeParagraph(finding.remediation, 10, 14);
            this.gap(8);

            if (finding.evidence.request) {
                this.writeLabel('HTTP Request');
                this.writeCodeBlock(finding.evidence.request);
            }
            if (finding.evidence.response) {
                this.writeLabel('HTTP Response');
                this.writeCodeBlock(finding.evidence.response);
            }
            if (finding.evidence.additional) {
                this.writeLabel('Additional Evidence');
                this.writeCodeBlock(finding.evidence.additional);
            }

            this.gap(12);
        });
    }

    public addRemediationSection(report: CanonicalReportModel): void {
        this.newPage();
        this.writeSectionTitle('4. Remediation Priority');
        report.remediationPriorities.forEach((priority) => {
            this.ensureSpace(50);
            this.writeLabel(priority.label);
            this.writeParagraph(priority.description, 10, 14);
            const labels = priority.findingIds
                .map((findingId) => report.findings.find((finding) => finding.id === findingId)?.title)
                .filter(Boolean)
                .join(', ');
            if (labels) {
                this.writeParagraph(labels, 9, 13);
            }
            this.gap(12);
        });
    }

    public addSourceIntelligence(report: CanonicalReportModel): void {
        if (!report.sourceIntelligence) {
            return;
        }

        this.newPage();
        this.writeSectionTitle(`5. ${report.sourceIntelligence.title}`);
        report.sourceIntelligence.subsections.forEach((subsection) => {
            this.ensureSpace(44);
            this.writeLabel(subsection.heading);
            subsection.paragraphs?.forEach((paragraph) => this.writeParagraph(paragraph, 9.5, 13.5));
            if (subsection.table) {
                this.gap(4);
                this.writeParagraph(subsection.table.headers.join(' | '), 8.5, 11, this.boldFont);
                subsection.table.rows.slice(0, 20).forEach((row) => this.writeParagraph(row.join(' | '), 8, 10.5));
                if (subsection.table.rows.length > 20) {
                    this.writeParagraph(`... and ${subsection.table.rows.length - 20} more rows`, 8, 11);
                }
            }
            this.gap(10);
        });
    }

    public addFooterPage(report: CanonicalReportModel): void {
        this.newPage();
        this.writeSectionTitle('6. Notes');
        this.writeParagraph('This artifact was generated from the persisted PenPard report snapshot. Export progress, enrichment status, and artifact metadata are tracked separately from the scan lifecycle.', 10, 14);
        this.gap(8);
        this.writeParagraph(`Enrichment mode: ${report.narrativeMeta.enrichmentMode}`, 10, 14);
        this.writeParagraph(`LLM enriched: ${report.narrativeMeta.llmEnriched ? 'yes' : 'no'}`, 10, 14);
        if (report.narrativeMeta.llmFailureReason) {
            this.writeParagraph(`LLM note: ${report.narrativeMeta.llmFailureReason}`, 10, 14);
        }
    }

    private newPage(): void {
        this.page = this.document.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
        this.y = PAGE_HEIGHT - MARGIN;
    }

    private drawHeaderBar(color: ReturnType<typeof rgb>): void {
        this.page.drawRectangle({ x: 0, y: PAGE_HEIGHT - 14, width: PAGE_WIDTH, height: 14, color });
    }

    private writeSectionTitle(title: string): void {
        this.ensureSpace(30);
        this.drawText(title, {
            x: MARGIN,
            y: this.y,
            size: 18,
            font: this.boldFont,
            color: rgb(0.08, 0.34, 0.56),
        });
        this.y -= 24;
    }

    private writeLabel(label: string): void {
        this.ensureSpace(18);
        this.drawText(label, {
            x: MARGIN,
            y: this.y,
            size: 11,
            font: this.boldFont,
            color: rgb(0.2, 0.2, 0.22),
        });
        this.y -= 16;
    }

    private writeParagraph(text: string, size: number, lineHeight: number, font: PDFFont = this.regularFont): void {
        const lines = wrapText(safePdfText(text, font), font, size, CONTENT_WIDTH);
        for (const line of lines) {
            this.ensureSpace(lineHeight + 2);
            this.drawText(line, {
                x: MARGIN,
                y: this.y,
                size,
                font,
                color: rgb(0.12, 0.12, 0.14),
            });
            this.y -= lineHeight;
        }
    }

    private writeCodeBlock(text: string): void {
        const lines = wrapText(safePdfText(text, this.monoFont), this.monoFont, 8, CONTENT_WIDTH - 16);
        const visibleLines = lines.slice(0, 28);
        const height = Math.max(visibleLines.length * 10 + 10, 20);
        this.ensureSpace(height + 8);
        this.page.drawRectangle({
            x: MARGIN,
            y: this.y - height + 4,
            width: CONTENT_WIDTH,
            height,
            color: rgb(0.95, 0.96, 0.98),
        });
        let currentY = this.y - 8;
        visibleLines.forEach((line) => {
            this.drawText(line, {
                x: MARGIN + 8,
                y: currentY,
                size: 8,
                font: this.monoFont,
                color: rgb(0.16, 0.17, 0.22),
            });
            currentY -= 10;
        });
        this.y -= height + 8;
    }

    private ensureSpace(spaceNeeded: number): void {
        if (this.y - spaceNeeded < MARGIN) {
            this.newPage();
        }
    }

    private gap(amount: number): void {
        this.y -= amount;
    }

    private drawText(
        text: string,
        options: {
            x: number;
            y: number;
            size: number;
            font: PDFFont;
            color: ReturnType<typeof rgb>;
        },
    ): void {
        this.page.drawText(safePdfText(text, options.font), options);
    }
}

function wrapText(text: string, font: PDFFont, size: number, width: number): string[] {
    if (!text) return [''];

    const lines: string[] = [];
    for (const paragraph of text.split('\n')) {
        const words = paragraph.split(/\s+/).filter(Boolean);
        if (words.length === 0) {
            lines.push('');
            continue;
        }

        let current = '';
        for (const word of words) {
            const candidate = current ? `${current} ${word}` : word;
            if (font.widthOfTextAtSize(candidate, size) <= width) {
                current = candidate;
                continue;
            }
            if (current) {
                lines.push(current);
                current = word;
                continue;
            }
            lines.push(word);
        }
        if (current) {
            lines.push(current);
        }
    }
    return lines;
}
