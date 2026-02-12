/**
 * PPTX Presentation Generator for PenPard
 * Generates a professional vulnerability presentation for cybersecurity team briefings.
 * Designed for executive and technical audiences.
 */

import PptxGenJS from 'pptxgenjs';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';

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

const COLORS = {
    bg: '0D0D14',
    bgAlt: '14141F',
    primary: '00B5D4',
    white: 'FFFFFF',
    textLight: '999999',
    textMuted: '666666',
    critical: 'DC2439',
    high: 'ED5922',
    medium: 'EBA10D',
    low: '2E80DE',
    info: '808088',
    green: '26AD62',
};

function severityColor(sev: string): string {
    return (COLORS as any)[sev] || COLORS.info;
}

function formatDate(dateStr: string): string {
    try {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric'
        });
    } catch { return dateStr; }
}

function calcDuration(start: string, end: string): string {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 60) return `${mins} minutes`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

interface PptxOptions {
    llmEnhanced?: boolean;
    enhancedDescriptions?: Map<number, string>;
}

export async function generatePptxReport(
    scan: Scan,
    vulnerabilities: Vulnerability[],
    options: PptxOptions = {}
): Promise<string> {
    logger.info('Generating PPTX report', { scanId: scan.id });

    const pptx = new PptxGenJS();

    // Metadata
    pptx.author = 'PenPard — AI-Powered Penetration Testing';
    pptx.title = `Security Assessment — ${scan.target}`;
    pptx.subject = `Penetration Test Report for ${scan.target}`;
    pptx.company = 'PenPard (github.com/onurgule/penpard)';
    pptx.revision = '1';

    // Layout
    pptx.layout = 'LAYOUT_16x9';
    pptx.defineLayout({ name: 'PENPARD', width: 13.33, height: 7.5 });

    const sorted = [...vulnerabilities].sort((a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );

    const counts: Record<string, number> = {};
    for (const sev of SEVERITY_ORDER) {
        counts[sev] = vulnerabilities.filter(v => v.severity === sev).length;
    }

    // ═══════════════════════════════════════════════════════
    //  SLIDE 1: Title
    // ═══════════════════════════════════════════════════════
    const slide1 = pptx.addSlide();
    slide1.background = { color: COLORS.bg };

    // Top bar
    slide1.addShape('rect', { x: 0, y: 0, w: '100%', h: 0.08, fill: { color: COLORS.primary } });

    // CONFIDENTIAL
    slide1.addText('CONFIDENTIAL', {
        x: 0.5, y: 0.4, w: 4, h: 0.35,
        fontSize: 12, bold: true, color: COLORS.critical,
        fontFace: 'Calibri'
    });

    // Title
    slide1.addText('PENPARD', {
        x: 0.5, y: 1.5, w: 12, h: 0.9,
        fontSize: 48, bold: true, color: COLORS.primary,
        fontFace: 'Calibri'
    });

    slide1.addText('Security Assessment Report', {
        x: 0.5, y: 2.4, w: 12, h: 0.6,
        fontSize: 24, color: COLORS.textLight,
        fontFace: 'Calibri'
    });

    // Target info
    slide1.addShape('rect', { x: 0.5, y: 3.5, w: 12, h: 2.2, fill: { color: COLORS.bgAlt }, rectRadius: 0.1 });

    const infoItems = [
        ['TARGET', scan.target],
        ['DATE', formatDate(scan.created_at)],
        ['DURATION', scan.completed_at ? calcDuration(scan.created_at, scan.completed_at) : 'In Progress'],
        ['FINDINGS', `${vulnerabilities.length} Vulnerabilities`],
    ];

    infoItems.forEach(([label, value], i) => {
        slide1.addText(label, {
            x: 0.8, y: 3.7 + i * 0.45, w: 2, h: 0.35,
            fontSize: 10, bold: true, color: COLORS.primary,
            fontFace: 'Calibri'
        });
        slide1.addText(value, {
            x: 3.0, y: 3.7 + i * 0.45, w: 9, h: 0.35,
            fontSize: 12, color: COLORS.white,
            fontFace: 'Calibri'
        });
    });

    // Footer
    slide1.addText('github.com/onurgule/penpard', {
        x: 0.5, y: 6.8, w: 5, h: 0.3,
        fontSize: 8, color: COLORS.textMuted,
        fontFace: 'Courier New'
    });

    // ═══════════════════════════════════════════════════════
    //  SLIDE 2: Executive Summary
    // ═══════════════════════════════════════════════════════
    const slide2 = pptx.addSlide();
    slide2.background = { color: COLORS.bg };
    addSlideHeader(slide2, 'Executive Summary');

    // Risk score bar chart
    const chartData = SEVERITY_ORDER.map(sev => ({
        name: sev.toUpperCase(),
        labels: [sev.toUpperCase()],
        values: [counts[sev] || 0],
    }));

    if (vulnerabilities.length > 0) {
        slide2.addChart(pptx.ChartType.bar, chartData, {
            x: 0.5, y: 1.5, w: 6, h: 4,
            showTitle: false,
            showValue: true,
            catAxisLabelColor: COLORS.white,
            valAxisLabelColor: COLORS.white,
            chartColors: SEVERITY_ORDER.map(s => severityColor(s)),
        });
    }

    // Stats panel
    slide2.addShape('rect', { x: 7.5, y: 1.5, w: 5, h: 4, fill: { color: COLORS.bgAlt }, rectRadius: 0.1 });

    slide2.addText('Key Statistics', {
        x: 7.8, y: 1.6, w: 4.5, h: 0.4,
        fontSize: 16, bold: true, color: COLORS.primary,
        fontFace: 'Calibri'
    });

    SEVERITY_ORDER.forEach((sev, i) => {
        // Severity badge
        slide2.addShape('rect', { x: 7.8, y: 2.2 + i * 0.6, w: 1.2, h: 0.35, fill: { color: severityColor(sev) }, rectRadius: 0.05 });
        slide2.addText(sev.toUpperCase(), {
            x: 7.8, y: 2.2 + i * 0.6, w: 1.2, h: 0.35,
            fontSize: 9, bold: true, color: COLORS.white, align: 'center',
            fontFace: 'Calibri'
        });
        slide2.addText(String(counts[sev] || 0), {
            x: 9.2, y: 2.2 + i * 0.6, w: 1, h: 0.35,
            fontSize: 14, bold: true, color: COLORS.white,
            fontFace: 'Calibri'
        });
    });

    slide2.addText(`Total: ${vulnerabilities.length}`, {
        x: 7.8, y: 5.0, w: 4, h: 0.3,
        fontSize: 14, bold: true, color: COLORS.primary,
        fontFace: 'Calibri'
    });

    // ═══════════════════════════════════════════════════════
    //  SLIDE 3: Findings Overview Table
    // ═══════════════════════════════════════════════════════
    if (sorted.length > 0) {
        const slide3 = pptx.addSlide();
        slide3.background = { color: COLORS.bg };
        addSlideHeader(slide3, 'Findings Overview');

        const rows: any[][] = [
            [
                { text: '#', options: { bold: true, color: COLORS.white, fill: { color: '1A1A2E' }, fontSize: 10 } },
                { text: 'Vulnerability', options: { bold: true, color: COLORS.white, fill: { color: '1A1A2E' }, fontSize: 10 } },
                { text: 'Severity', options: { bold: true, color: COLORS.white, fill: { color: '1A1A2E' }, fontSize: 10 } },
                { text: 'CVSS', options: { bold: true, color: COLORS.white, fill: { color: '1A1A2E' }, fontSize: 10 } },
            ],
        ];

        // Show max 15 findings in overview
        sorted.slice(0, 15).forEach((v, i) => {
            rows.push([
                { text: String(i + 1), options: { fontSize: 9, color: COLORS.white } },
                { text: v.name.slice(0, 50), options: { fontSize: 9, color: COLORS.white } },
                { text: v.severity.toUpperCase(), options: { fontSize: 9, bold: true, color: COLORS.white, fill: { color: severityColor(v.severity) } } },
                { text: v.cvss_score ? String(v.cvss_score) : '-', options: { fontSize: 9, color: COLORS.white } },
            ]);
        });

        slide3.addTable(rows, {
            x: 0.5, y: 1.5, w: 12,
            border: { type: 'solid', pt: 0.5, color: '333344' },
            colW: [0.5, 7.5, 2, 2],
            autoPage: true,
            autoPageRepeatHeader: true,
        });
    }

    // ═══════════════════════════════════════════════════════
    //  INDIVIDUAL FINDING SLIDES
    // ═══════════════════════════════════════════════════════
    for (let i = 0; i < sorted.length; i++) {
        const v = sorted[i];
        const findingSlide = pptx.addSlide();
        findingSlide.background = { color: COLORS.bg };

        // Severity bar at top
        findingSlide.addShape('rect', { x: 0, y: 0, w: '100%', h: 0.08, fill: { color: severityColor(v.severity) } });

        // Finding number + severity badge
        findingSlide.addShape('rect', { x: 0.3, y: 0.3, w: 1.2, h: 0.4, fill: { color: severityColor(v.severity) }, rectRadius: 0.05 });
        findingSlide.addText(`${v.severity.toUpperCase()}`, {
            x: 0.3, y: 0.3, w: 1.2, h: 0.4,
            fontSize: 12, bold: true, color: COLORS.white, align: 'center',
            fontFace: 'Calibri'
        });

        // CVSS badge
        if (v.cvss_score) {
            findingSlide.addShape('rect', { x: 1.7, y: 0.3, w: 1, h: 0.4, fill: { color: COLORS.bgAlt }, rectRadius: 0.05 });
            findingSlide.addText(`CVSS ${v.cvss_score}`, {
                x: 1.7, y: 0.3, w: 1, h: 0.4,
                fontSize: 10, bold: true, color: severityColor(v.severity), align: 'center',
                fontFace: 'Calibri'
            });
        }

        // Title
        findingSlide.addText(`Finding ${i + 1}: ${v.name}`, {
            x: 0.3, y: 0.85, w: 12.5, h: 0.5,
            fontSize: 18, bold: true, color: COLORS.white,
            fontFace: 'Calibri'
        });

        // CWE/CVE line
        const metaParts: string[] = [];
        if (v.cwe) metaParts.push(`CWE-${v.cwe}`);
        if (v.cve) metaParts.push(v.cve);
        if (v.cvss_vector) metaParts.push(v.cvss_vector);
        if (metaParts.length > 0) {
            findingSlide.addText(metaParts.join('  |  '), {
                x: 0.3, y: 1.35, w: 12, h: 0.3,
                fontSize: 8, color: COLORS.textMuted,
                fontFace: 'Courier New'
            });
        }

        // Two-column layout: Description (left) + Evidence (right)
        const descY = 1.8;

        // Description
        if (v.description) {
            const desc = options.enhancedDescriptions?.get(v.id) || v.description;
            findingSlide.addText('Description & Impact', {
                x: 0.3, y: descY, w: 6, h: 0.3,
                fontSize: 11, bold: true, color: COLORS.primary,
                fontFace: 'Calibri'
            });
            findingSlide.addText(desc.slice(0, 600), {
                x: 0.3, y: descY + 0.35, w: 6, h: 2.5,
                fontSize: 9, color: COLORS.white, valign: 'top',
                fontFace: 'Calibri', paraSpaceBefore: 4
            });
        }

        // Evidence (right panel)
        findingSlide.addShape('rect', { x: 6.8, y: descY, w: 6, h: 3.2, fill: { color: COLORS.bgAlt }, rectRadius: 0.1 });

        findingSlide.addText('Evidence', {
            x: 7.0, y: descY + 0.1, w: 5.5, h: 0.3,
            fontSize: 11, bold: true, color: COLORS.primary,
            fontFace: 'Calibri'
        });

        // Show request snippet as evidence
        let evidenceText = '';
        if (v.request) {
            evidenceText = v.request.slice(0, 400);
        } else if (v.evidence) {
            evidenceText = v.evidence.slice(0, 400);
        }

        if (evidenceText) {
            findingSlide.addText(evidenceText, {
                x: 7.0, y: descY + 0.5, w: 5.5, h: 2.5,
                fontSize: 7, color: COLORS.textLight, valign: 'top',
                fontFace: 'Courier New', paraSpaceBefore: 2
            });
        }

        // Remediation bar at bottom
        if (v.remediation) {
            findingSlide.addShape('rect', { x: 0.3, y: 5.3, w: 12.5, h: 1.6, fill: { color: '0A1E12' }, rectRadius: 0.1 });
            findingSlide.addShape('rect', { x: 0.3, y: 5.3, w: 0.06, h: 1.6, fill: { color: COLORS.green } });

            findingSlide.addText('Remediation', {
                x: 0.6, y: 5.4, w: 12, h: 0.3,
                fontSize: 11, bold: true, color: COLORS.green,
                fontFace: 'Calibri'
            });
            findingSlide.addText(v.remediation.slice(0, 500), {
                x: 0.6, y: 5.75, w: 12, h: 1.0,
                fontSize: 9, color: COLORS.white, valign: 'top',
                fontFace: 'Calibri', paraSpaceBefore: 3
            });
        }

        // Page indicator
        findingSlide.addText(`Finding ${i + 1} of ${sorted.length}`, {
            x: 10, y: 7.0, w: 3, h: 0.3,
            fontSize: 8, color: COLORS.textMuted, align: 'right',
            fontFace: 'Calibri'
        });
    }

    // ═══════════════════════════════════════════════════════
    //  REMEDIATION PRIORITY SLIDE
    // ═══════════════════════════════════════════════════════
    const remSlide = pptx.addSlide();
    remSlide.background = { color: COLORS.bg };
    addSlideHeader(remSlide, 'Remediation Priority');

    const priorities = [
        { label: 'Immediate (0–48h)', sevs: ['critical'], color: COLORS.critical },
        { label: 'Short-term (1–2 weeks)', sevs: ['high'], color: COLORS.high },
        { label: 'Medium-term (1–3 months)', sevs: ['medium'], color: COLORS.medium },
        { label: 'Long-term (Next release)', sevs: ['low', 'info'], color: COLORS.low },
    ];

    let py = 1.5;
    for (const p of priorities) {
        const matching = sorted.filter(v => p.sevs.includes(v.severity));
        if (matching.length === 0) continue;

        remSlide.addShape('rect', { x: 0.5, y: py, w: 0.08, h: 0.35, fill: { color: p.color } });
        remSlide.addText(p.label, {
            x: 0.8, y: py, w: 4, h: 0.35,
            fontSize: 12, bold: true, color: COLORS.white,
            fontFace: 'Calibri'
        });

        py += 0.4;
        for (const v of matching.slice(0, 5)) {
            remSlide.addText(`• ${v.name.slice(0, 60)}`, {
                x: 1.0, y: py, w: 11, h: 0.3,
                fontSize: 9, color: COLORS.textLight,
                fontFace: 'Calibri'
            });
            py += 0.3;
        }
        if (matching.length > 5) {
            remSlide.addText(`  ... and ${matching.length - 5} more`, {
                x: 1.0, y: py, w: 11, h: 0.3,
                fontSize: 9, color: COLORS.textMuted, italic: true,
                fontFace: 'Calibri'
            });
            py += 0.3;
        }
        py += 0.15;
    }

    // ═══════════════════════════════════════════════════════
    //  CLOSING SLIDE
    // ═══════════════════════════════════════════════════════
    const closeSlide = pptx.addSlide();
    closeSlide.background = { color: COLORS.bg };
    closeSlide.addShape('rect', { x: 0, y: 0, w: '100%', h: 0.08, fill: { color: COLORS.primary } });

    closeSlide.addText('Thank You', {
        x: 0.5, y: 2.0, w: 12, h: 0.8,
        fontSize: 36, bold: true, color: COLORS.primary, align: 'center',
        fontFace: 'Calibri'
    });

    closeSlide.addText('Questions & Discussion', {
        x: 0.5, y: 3.0, w: 12, h: 0.5,
        fontSize: 18, color: COLORS.textLight, align: 'center',
        fontFace: 'Calibri'
    });

    closeSlide.addShape('rect', { x: 3.5, y: 4.2, w: 6.3, h: 1.4, fill: { color: COLORS.bgAlt }, rectRadius: 0.1 });
    closeSlide.addText([
        { text: 'This report was generated by ', options: { fontSize: 10, color: COLORS.textLight } },
        { text: 'PenPard', options: { fontSize: 10, bold: true, color: COLORS.primary } },
        { text: '\nAI-Powered Penetration Testing Platform', options: { fontSize: 9, color: COLORS.textMuted } },
        { text: '\n\ngithub.com/onurgule/penpard', options: { fontSize: 10, bold: true, color: COLORS.primary } },
        { text: '\nRun your own AI-powered security scan — 100% free & open source', options: { fontSize: 8, color: COLORS.textMuted } },
    ], {
        x: 3.5, y: 4.2, w: 6.3, h: 1.4, align: 'center', valign: 'middle',
    });

    closeSlide.addText('CONFIDENTIAL — Do not distribute without authorization', {
        x: 0.5, y: 6.8, w: 12, h: 0.3,
        fontSize: 8, color: COLORS.critical, align: 'center',
        fontFace: 'Calibri'
    });

    // Save
    const reportPath = path.join(REPORTS_DIR, `report-${scan.id}.pptx`);
    await pptx.writeFile({ fileName: reportPath });

    logger.info('PPTX report generated', { scanId: scan.id, path: reportPath });
    return reportPath;
}

// ── Helper ──

function addSlideHeader(slide: any, title: string) {
    slide.addShape('rect', { x: 0, y: 0, w: '100%', h: 0.08, fill: { color: COLORS.primary } });
    slide.addText('PENPARD', {
        x: 0.3, y: 0.3, w: 2, h: 0.35,
        fontSize: 10, bold: true, color: COLORS.primary,
        fontFace: 'Calibri'
    });
    slide.addText(title, {
        x: 0.3, y: 0.7, w: 12, h: 0.5,
        fontSize: 22, bold: true, color: COLORS.white,
        fontFace: 'Calibri'
    });
    slide.addText('github.com/onurgule/penpard', {
        x: 8, y: 7.0, w: 5, h: 0.3,
        fontSize: 7, color: COLORS.textMuted, align: 'right',
        fontFace: 'Courier New'
    });
}
