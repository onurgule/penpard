/**
 * DOCX Report Generator for PenPard
 * Generates an editable Word document with the same content as the PDF report.
 * Metadata includes github.com/onurgule/penpard attribution.
 */

import {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
    HeadingLevel, AlignmentType, BorderStyle, WidthType,
    TableOfContents, Footer, PageNumber, NumberFormat,
    ShadingType, ImageRun, ExternalHyperlink
} from 'docx';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';
import { SourceAnalysisResult } from './source-analysis/SourceAnalysisMode';
import { buildSourceReportSections } from './source-analysis/SourceReportEnricher';

const REPORTS_DIR = path.join(__dirname, '../../reports');

interface Scan {
    id: string;
    type: string;
    target: string;
    status: string;
    created_at: string;
    completed_at: string;
}

interface Vulnerability {
    id: number;
    name: string;
    description?: string;
    severity: string;
    cvss_score?: number;
    cvss_vector?: string;
    cwe?: string;
    cve?: string;
    request?: string;
    response?: string;
    evidence?: string;
    remediation?: string;
    screenshot_path?: string;
    created_at?: string;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function severityColorHex(sev: string): string {
    const map: Record<string, string> = {
        critical: 'DC2439', high: 'ED5922', medium: 'EBA10D',
        low: '2E80DE', info: '808088'
    };
    return map[sev] || '808088';
}

function formatDate(dateStr: string): string {
    try {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch { return dateStr; }
}

function calcDuration(start: string, end: string): string {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 60) return `${mins} minutes`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

interface DocxOptions {
    llmEnhanced?: boolean;
    enhancedDescriptions?: Map<number, string>;
    sourceAnalysis?: SourceAnalysisResult | null;
}

export async function generateDocxReport(
    scan: Scan,
    vulnerabilities: Vulnerability[],
    options: DocxOptions = {}
): Promise<string> {
    logger.info('Generating DOCX report', { scanId: scan.id });

    const sorted = [...vulnerabilities].sort((a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );

    const counts: Record<string, number> = {};
    for (const sev of SEVERITY_ORDER) {
        counts[sev] = vulnerabilities.filter(v => v.severity === sev).length;
    }

    const doc = new Document({
        creator: 'PenPard — AI-Powered Penetration Testing',
        title: `PenPard Security Assessment — ${scan.target}`,
        description: `Penetration Test Report for ${scan.target}`,
        subject: 'Security Assessment Report',
        keywords: 'penetration test, security, vulnerability, PenPard',
        lastModifiedBy: 'PenPard Report Engine',
        revision: 1,
        customProperties: [
            { name: 'Generator', value: 'PenPard (github.com/onurgule/penpard)' },
            { name: 'ReportType', value: options.llmEnhanced ? 'LLM-Enhanced' : 'Static' },
        ],
        sections: [
            // ── Cover Page ──
            {
                properties: {
                    page: {
                        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 },
                    },
                },
                children: [
                    new Paragraph({ spacing: { before: 4000 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: 'CONFIDENTIAL', bold: true, size: 20, color: 'DC2439', font: 'Calibri' }),
                        ],
                    }),
                    new Paragraph({ spacing: { before: 600 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: 'PENPARD', bold: true, size: 56, color: '00B5D4', font: 'Calibri' }),
                        ],
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: 'Security Assessment Report', size: 32, color: '666666', font: 'Calibri' }),
                        ],
                    }),
                    new Paragraph({ spacing: { before: 800 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: `Target: ${scan.target}`, bold: true, size: 24, font: 'Calibri' }),
                        ],
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: `Date: ${formatDate(scan.created_at)}`, size: 20, color: '888888', font: 'Calibri' }),
                        ],
                    }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({
                                text: scan.completed_at
                                    ? `Duration: ${calcDuration(scan.created_at, scan.completed_at)}`
                                    : 'Status: In Progress',
                                size: 20, color: '888888', font: 'Calibri'
                            }),
                        ],
                    }),
                    new Paragraph({ spacing: { before: 400 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({
                                text: `${vulnerabilities.length} Vulnerabilities Found`,
                                bold: true, size: 28, color: vulnerabilities.length > 0 ? 'DC2439' : '2EAD26', font: 'Calibri'
                            }),
                        ],
                    }),
                    new Paragraph({ spacing: { before: 2000 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        children: [
                            new TextRun({ text: `Report ID: ${scan.id}`, size: 16, color: 'AAAAAA', font: 'Courier New' }),
                        ],
                    }),
                ],
            },

            // ── Main Content ──
            {
                properties: {
                    page: {
                        margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 },
                    },
                },
                footers: {
                    default: new Footer({
                        children: [
                            new Paragraph({
                                alignment: AlignmentType.CENTER,
                                children: [
                                    new TextRun({ text: 'Generated by PenPard (github.com/onurgule/penpard) — ', size: 14, color: 'AAAAAA' }),
                                    new TextRun({ text: 'Page ', size: 14, color: 'AAAAAA' }),
                                    new TextRun({ children: [PageNumber.CURRENT], size: 14, color: 'AAAAAA' }),
                                    new TextRun({ text: ' of ', size: 14, color: 'AAAAAA' }),
                                    new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 14, color: 'AAAAAA' }),
                                ],
                            }),
                        ],
                    }),
                },
                children: [
                    // ── Executive Summary ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '1. Executive Summary', bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),

                    new Paragraph({
                        children: [
                            new TextRun({
                                text: `A penetration test was conducted against ${scan.target} on ${formatDate(scan.created_at)}. ` +
                                    `The assessment identified ${vulnerabilities.length} vulnerabilities: ` +
                                    SEVERITY_ORDER.map(s => `${counts[s]} ${s}`).join(', ') + '.',
                            }),
                        ],
                    }),
                    new Paragraph({ spacing: { after: 200 } }),

                    // Severity breakdown table
                    createSeverityTable(counts),
                    new Paragraph({ spacing: { after: 400 } }),

                    // ── Scope & Methodology ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '2. Scope & Methodology', bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),
                    new Paragraph({
                        children: [
                            new TextRun({ text: 'Target: ', bold: true }), new TextRun({ text: scan.target }),
                        ],
                    }),
                    new Paragraph({
                        children: [
                            new TextRun({ text: 'Scan Type: ', bold: true }), new TextRun({ text: scan.type.toUpperCase() }),
                        ],
                    }),
                    new Paragraph({
                        children: [
                            new TextRun({ text: 'Methodology: ', bold: true }),
                            new TextRun({ text: 'AI-powered autonomous testing using OWASP Top 10 methodology with Burp Suite Professional integration.' }),
                        ],
                    }),
                    new Paragraph({ spacing: { after: 400 } }),

                    // ── Findings Summary ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '3. Findings Summary', bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),
                    ...(sorted.length > 0 ? [createFindingsSummaryTable(sorted)] : [
                        new Paragraph({ children: [new TextRun({ text: 'No vulnerabilities were identified during this assessment.', italics: true, color: '888888' })] }),
                    ]),
                    new Paragraph({ spacing: { after: 400 } }),

                    // ── Detailed Findings ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '4. Detailed Findings', bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),
                    ...sorted.flatMap((v, i) => createFindingSection(v, i, options)),

                    // ── Remediation Priority ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: '5. Remediation Priority', bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),
                    ...createRemediationPriority(sorted),

                    // ── Source Intelligence (conditional) ──
                    ...createSourceIntelligenceSection(options.sourceAnalysis),

                    // ── Disclaimer ──
                    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: `${options.sourceAnalysis ? '7' : '6'}. Disclaimer`, bold: true })] }),
                    new Paragraph({ spacing: { after: 200 } }),
                    new Paragraph({
                        children: [new TextRun({
                            text: 'This report was generated with the autonomous assistance of PenPard, an open-source AI-powered penetration testing tool available at github.com/onurgule/penpard. PenPard uses Large Language Models integrated with Burp Suite Professional to plan, execute, and report security assessments.',
                            size: 20, color: '666666',
                        })],
                    }),
                    new Paragraph({ spacing: { after: 100 } }),
                    new Paragraph({
                        children: [new TextRun({
                            text: 'This report is provided "as is" for informational purposes only. AI-assisted automated testing may not identify all vulnerabilities. It is recommended that findings be validated by qualified security professionals.',
                            size: 20, color: '666666',
                        })],
                    }),
                    new Paragraph({ spacing: { before: 400, after: 200 } }),
                    new Paragraph({
                        alignment: AlignmentType.CENTER,
                        shading: { type: ShadingType.SOLID, color: 'F0F8FF' },
                        children: [
                            new TextRun({ text: '🔒 Run your own AI-powered security scan at ', size: 20 }),
                            new ExternalHyperlink({
                                link: 'https://github.com/onurgule/penpard',
                                children: [new TextRun({ text: 'github.com/onurgule/penpard', bold: true, color: '00B5D4', size: 20 })],
                            }),
                        ],
                    }),
                ],
            },
        ],
    });

    const buffer = await Packer.toBuffer(doc);
    const reportPath = path.join(REPORTS_DIR, `report-${scan.id}.docx`);
    fs.writeFileSync(reportPath, buffer);

    logger.info('DOCX report generated', { scanId: scan.id, path: reportPath });
    return reportPath;
}

// ── Helper Functions ──

function createSeverityTable(counts: Record<string, number>): Table {
    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
            new TableRow({
                tableHeader: true,
                children: ['Severity', 'Count'].map(h =>
                    new TableCell({
                        shading: { type: ShadingType.SOLID, color: '1A1A2E' },
                        children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: 'FFFFFF', size: 20 })] })],
                    })
                ),
            }),
            ...SEVERITY_ORDER.map(sev =>
                new TableRow({
                    children: [
                        new TableCell({
                            shading: { type: ShadingType.SOLID, color: severityColorHex(sev) },
                            children: [new Paragraph({ children: [new TextRun({ text: sev.toUpperCase(), bold: true, color: 'FFFFFF', size: 20 })] })],
                        }),
                        new TableCell({
                            children: [new Paragraph({ children: [new TextRun({ text: String(counts[sev] || 0), size: 20 })] })],
                        }),
                    ],
                })
            ),
        ],
    });
}

function createFindingsSummaryTable(vulns: Vulnerability[]): Table {
    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
            new TableRow({
                tableHeader: true,
                children: ['#', 'Vulnerability', 'Severity', 'CVSS', 'CWE'].map(h =>
                    new TableCell({
                        shading: { type: ShadingType.SOLID, color: '1A1A2E' },
                        children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: 'FFFFFF', size: 18 })] })],
                    })
                ),
            }),
            ...vulns.map((v, i) =>
                new TableRow({
                    children: [
                        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: String(i + 1), size: 18 })] })] }),
                        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: v.name.slice(0, 60), size: 18 })] })] }),
                        new TableCell({
                            shading: { type: ShadingType.SOLID, color: severityColorHex(v.severity) },
                            children: [new Paragraph({ children: [new TextRun({ text: v.severity.toUpperCase(), bold: true, color: 'FFFFFF', size: 18 })] })],
                        }),
                        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: v.cvss_score ? String(v.cvss_score) : '-', size: 18 })] })] }),
                        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: v.cwe || '-', size: 18 })] })] }),
                    ],
                })
            ),
        ],
    });
}

function createFindingSection(v: Vulnerability, index: number, options: DocxOptions): Paragraph[] {
    const parts: Paragraph[] = [];

    // Heading
    parts.push(new Paragraph({
        heading: HeadingLevel.HEADING_2,
        shading: { type: ShadingType.SOLID, color: severityColorHex(v.severity) },
        children: [
            new TextRun({ text: `${index + 1}. [${v.severity.toUpperCase()}] ${v.name}`, bold: true, color: 'FFFFFF' }),
        ],
    }));

    // Metadata
    const metaParts: string[] = [];
    if (v.cvss_score) metaParts.push(`CVSS: ${v.cvss_score}`);
    if (v.cvss_vector) metaParts.push(`Vector: ${v.cvss_vector}`);
    if (v.cwe) metaParts.push(`CWE-${v.cwe}`);
    if (v.cve) metaParts.push(v.cve);
    if (metaParts.length > 0) {
        parts.push(new Paragraph({
            children: [new TextRun({ text: metaParts.join('  |  '), size: 16, color: '888888', font: 'Courier New' })],
        }));
    }
    parts.push(new Paragraph({ spacing: { after: 100 } }));

    // Description
    if (v.description) {
        const desc = options.enhancedDescriptions?.get(v.id) || v.description;
        parts.push(new Paragraph({
            children: [new TextRun({ text: 'Description & Impact', bold: true, size: 22, color: '00B5D4' })],
        }));
        parts.push(new Paragraph({ children: [new TextRun({ text: desc, size: 20 })] }));
        parts.push(new Paragraph({ spacing: { after: 100 } }));
    }

    // Request
    if (v.request) {
        parts.push(new Paragraph({
            children: [new TextRun({ text: 'HTTP Request (Evidence)', bold: true, size: 22, color: '00B5D4' })],
        }));
        parts.push(new Paragraph({
            shading: { type: ShadingType.SOLID, color: 'F0F0F4' },
            children: [new TextRun({ text: v.request.slice(0, 3000), size: 16, font: 'Courier New' })],
        }));
        parts.push(new Paragraph({ spacing: { after: 100 } }));
    }

    // Response
    if (v.response) {
        parts.push(new Paragraph({
            children: [new TextRun({ text: 'HTTP Response', bold: true, size: 22, color: '00B5D4' })],
        }));
        parts.push(new Paragraph({
            shading: { type: ShadingType.SOLID, color: 'F0F0F4' },
            children: [new TextRun({ text: v.response.slice(0, 3000), size: 16, font: 'Courier New' })],
        }));
        parts.push(new Paragraph({ spacing: { after: 100 } }));
    }

    // Evidence
    if (v.evidence && v.evidence !== '{}' && v.evidence !== 'null') {
        let evidenceText: string;
        try {
            const parsed = JSON.parse(v.evidence);
            evidenceText = typeof parsed === 'object' ? JSON.stringify(parsed, null, 2) : String(parsed);
        } catch { evidenceText = v.evidence; }

        if (evidenceText) {
            parts.push(new Paragraph({
                children: [new TextRun({ text: 'Additional Evidence', bold: true, size: 22, color: '00B5D4' })],
            }));
            parts.push(new Paragraph({
                shading: { type: ShadingType.SOLID, color: 'F0F0F4' },
                children: [new TextRun({ text: evidenceText.slice(0, 2000), size: 16, font: 'Courier New' })],
            }));
            parts.push(new Paragraph({ spacing: { after: 100 } }));
        }
    }

    // Remediation
    if (v.remediation) {
        parts.push(new Paragraph({
            children: [new TextRun({ text: 'Remediation', bold: true, size: 22, color: '26AD62' })],
        }));
        parts.push(new Paragraph({
            border: { left: { style: BorderStyle.SINGLE, size: 6, color: '26AD62' } },
            children: [new TextRun({ text: v.remediation, size: 20 })],
        }));
    }

    parts.push(new Paragraph({ spacing: { after: 400 } }));
    return parts;
}

function createRemediationPriority(vulns: Vulnerability[]): Paragraph[] {
    const parts: Paragraph[] = [];
    const priorities = [
        { label: 'Immediate (0–48 hours)', sevs: ['critical'] },
        { label: 'Short-term (1–2 weeks)', sevs: ['high'] },
        { label: 'Medium-term (1–3 months)', sevs: ['medium'] },
        { label: 'Long-term (Next release)', sevs: ['low', 'info'] },
    ];

    for (const p of priorities) {
        const matching = vulns.filter(v => p.sevs.includes(v.severity));
        if (matching.length === 0) continue;

        parts.push(new Paragraph({
            children: [new TextRun({ text: p.label, bold: true, size: 22 })],
        }));
        for (const v of matching) {
            parts.push(new Paragraph({
                bullet: { level: 0 },
                children: [
                    new TextRun({ text: `[${v.severity.toUpperCase()}] `, bold: true, color: severityColorHex(v.severity) }),
                    new TextRun({ text: v.name, size: 20 }),
                ],
            }));
        }
        parts.push(new Paragraph({ spacing: { after: 200 } }));
    }

    return parts;
}

function createSourceIntelligenceSection(sourceAnalysis?: SourceAnalysisResult | null): (Paragraph | Table)[] {
    if (!sourceAnalysis) return [];

    const sections = buildSourceReportSections(sourceAnalysis);
    const parts: (Paragraph | Table)[] = [];
    const sectionNum = '6';

    parts.push(new Paragraph({
        heading: HeadingLevel.HEADING_1,
        children: [new TextRun({ text: `${sectionNum}. ${sections.title}`, bold: true })],
    }));
    parts.push(new Paragraph({ spacing: { after: 200 } }));

    for (const sub of sections.subsections) {
        parts.push(new Paragraph({
            heading: HeadingLevel.HEADING_2,
            children: [new TextRun({ text: sub.heading, bold: true, color: '00B5D4' })],
        }));

        if (sub.paragraphs) {
            for (const para of sub.paragraphs) {
                parts.push(new Paragraph({
                    children: [new TextRun({ text: para, size: 20 })],
                }));
            }
        }

        if (sub.table) {
            const tableRows: TableRow[] = [
                new TableRow({
                    tableHeader: true,
                    children: sub.table.headers.map(h =>
                        new TableCell({
                            shading: { type: ShadingType.SOLID, color: '00B5D4' },
                            children: [new Paragraph({
                                children: [new TextRun({ text: h, bold: true, color: 'FFFFFF', size: 18, font: 'Calibri' })],
                            })],
                        })
                    ),
                }),
                ...sub.table.rows.slice(0, 40).map((row, ri) =>
                    new TableRow({
                        children: row.map(cell =>
                            new TableCell({
                                shading: ri % 2 === 0 ? { type: ShadingType.SOLID, color: 'F8F8FA' } : undefined,
                                children: [new Paragraph({
                                    children: [new TextRun({ text: (cell || '-').slice(0, 80), size: 16, font: 'Calibri' })],
                                })],
                            })
                        ),
                    })
                ),
            ];

            parts.push(new Table({
                width: { size: 100, type: WidthType.PERCENTAGE },
                rows: tableRows,
            }));

            if (sub.table.rows.length > 40) {
                parts.push(new Paragraph({
                    children: [new TextRun({ text: `... and ${sub.table.rows.length - 40} more rows`, size: 18, color: '888888', italics: true })],
                }));
            }
        }

        parts.push(new Paragraph({ spacing: { after: 200 } }));
    }

    return parts;
}
