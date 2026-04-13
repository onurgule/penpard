import {
    AlignmentType,
    Document,
    Footer,
    HeadingLevel,
    Packer,
    PageNumber,
    Paragraph,
    Table,
    TableCell,
    TableRow,
    TextRun,
    WidthType,
} from 'docx';
import { writeFileAtomically, formatDisplayDate } from './shared';
import type { CanonicalReportModel } from '../types';

export async function renderDocxReport(report: CanonicalReportModel, outputPath: string): Promise<void> {
    const document = new Document({
        creator: 'PenPard',
        title: `PenPard Security Assessment - ${report.scan.target}`,
        subject: `Security assessment report for ${report.scan.target}`,
        description: 'Deterministic PenPard report export',
        sections: [{
            properties: {},
            footers: {
                default: new Footer({
                    children: [
                        new Paragraph({
                            alignment: AlignmentType.CENTER,
                            children: [
                                new TextRun('PenPard report export - Page '),
                                new TextRun({ children: [PageNumber.CURRENT] }),
                                new TextRun(' of '),
                                new TextRun({ children: [PageNumber.TOTAL_PAGES] }),
                            ],
                        }),
                    ],
                }),
            },
            children: buildDocxChildren(report),
        }],
    });

    const buffer = await Packer.toBuffer(document);
    await writeFileAtomically(outputPath, buffer);
}

function buildDocxChildren(report: CanonicalReportModel) {
    const children: Array<Paragraph | Table> = [];

    children.push(new Paragraph({
        heading: HeadingLevel.TITLE,
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'PENPARD', bold: true, size: 40, color: '0EA5E9' })],
    }));
    children.push(new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'Security Assessment Report', size: 28 })],
    }));
    children.push(new Paragraph({ children: [new TextRun(`Target: ${report.scan.target}`)] }));
    children.push(new Paragraph({ children: [new TextRun(`Scan ID: ${report.scan.id}`)] }));
    children.push(new Paragraph({ children: [new TextRun(`Created: ${formatDisplayDate(report.scan.createdAt)}`)] }));
    children.push(new Paragraph({ children: [new TextRun(`Completed: ${formatDisplayDate(report.scan.completedAt)}`)] }));
    children.push(new Paragraph({ children: [new TextRun(`Duration: ${report.scan.duration || 'N/A'}`)] }));
    children.push(new Paragraph({ text: '' }));

    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('1. Executive Summary')] }));
    children.push(new Paragraph(report.summary.executiveSummary));
    children.push(new Paragraph(report.summary.methodology));
    children.push(new Paragraph(report.summary.scopeSummary));
    children.push(new Paragraph(report.summary.remediationOverview));

    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('2. Severity Breakdown')] }));
    children.push(createSeverityTable(report));

    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('3. Detailed Findings')] }));
    if (report.findings.length === 0) {
        children.push(new Paragraph('No findings were recorded in this snapshot.'));
    } else {
        for (const [index, finding] of report.findings.entries()) {
            children.push(new Paragraph({
                heading: HeadingLevel.HEADING_2,
                children: [new TextRun({ text: `${index + 1}. ${finding.title} [${finding.severity.toUpperCase()}]`, bold: true })],
            }));
            const metadata = [
                finding.endpoint ? `Endpoint: ${finding.endpoint}` : null,
                finding.cvssScore ? `CVSS ${finding.cvssScore}` : null,
                finding.cwe ? `CWE-${finding.cwe}` : null,
                finding.cve ? finding.cve : null,
            ].filter(Boolean).join(' | ');
            if (metadata) {
                children.push(new Paragraph({ children: [new TextRun({ text: metadata, italics: true, size: 18 })] }));
            }
            children.push(new Paragraph({ children: [new TextRun({ text: 'Description', bold: true })] }));
            children.push(new Paragraph(finding.description));
            children.push(new Paragraph({ children: [new TextRun({ text: 'Impact', bold: true })] }));
            children.push(new Paragraph(finding.impact));
            children.push(new Paragraph({ children: [new TextRun({ text: 'Remediation', bold: true })] }));
            children.push(new Paragraph(finding.remediation));
            if (finding.evidence.request) {
                children.push(new Paragraph({ children: [new TextRun({ text: 'HTTP Request', bold: true })] }));
                children.push(codeParagraph(finding.evidence.request));
            }
            if (finding.evidence.response) {
                children.push(new Paragraph({ children: [new TextRun({ text: 'HTTP Response', bold: true })] }));
                children.push(codeParagraph(finding.evidence.response));
            }
            if (finding.evidence.additional) {
                children.push(new Paragraph({ children: [new TextRun({ text: 'Additional Evidence', bold: true })] }));
                children.push(codeParagraph(finding.evidence.additional));
            }
        }
    }

    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('4. Remediation Priority')] }));
    for (const priority of report.remediationPriorities) {
        children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(priority.label)] }));
        children.push(new Paragraph(priority.description));
        for (const findingId of priority.findingIds) {
            const finding = report.findings.find((entry) => entry.id === findingId);
            if (finding) {
                children.push(new Paragraph({
                    bullet: { level: 0 },
                    children: [new TextRun(`${finding.title} [${finding.severity.toUpperCase()}]`)],
                }));
            }
        }
    }

    if (report.sourceIntelligence) {
        children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(`5. ${report.sourceIntelligence.title}`)] }));
        for (const subsection of report.sourceIntelligence.subsections) {
            children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(subsection.heading)] }));
            subsection.paragraphs?.forEach((paragraph) => children.push(new Paragraph(paragraph)));
            if (subsection.table) {
                const rows = [
                    new TableRow({
                        children: subsection.table.headers.map((header) => new TableCell({
                            children: [new Paragraph({ children: [new TextRun({ text: header, bold: true })] })],
                        })),
                    }),
                    ...subsection.table.rows.slice(0, 20).map((row) => new TableRow({
                        children: row.map((cell) => new TableCell({
                            children: [new Paragraph(cell || '-')],
                        })),
                    })),
                ];
                children.push(new Table({
                    width: { size: 100, type: WidthType.PERCENTAGE },
                    rows,
                }));
            }
        }
    }

    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('6. Notes')] }));
    children.push(new Paragraph(`Enrichment mode: ${report.narrativeMeta.enrichmentMode}`));
    children.push(new Paragraph(`LLM enriched: ${report.narrativeMeta.llmEnriched ? 'yes' : 'no'}`));
    if (report.narrativeMeta.llmFailureReason) {
        children.push(new Paragraph(`LLM note: ${report.narrativeMeta.llmFailureReason}`));
    }

    return children;
}

function createSeverityTable(report: CanonicalReportModel): Table {
    const rows = [
        new TableRow({
            children: [
                new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Severity', bold: true })] })] }),
                new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: 'Count', bold: true })] })] }),
            ],
        }),
        ...Object.entries(report.summary.countsBySeverity).map(([severity, count]) => new TableRow({
            children: [
                new TableCell({ children: [new Paragraph(severity.toUpperCase())] }),
                new TableCell({ children: [new Paragraph(String(count))] }),
            ],
        })),
    ];

    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows,
    });
}

function codeParagraph(text: string): Paragraph {
    return new Paragraph({
        children: [new TextRun({ text: text.slice(0, 6000), font: 'Courier New', size: 16 })],
    });
}
