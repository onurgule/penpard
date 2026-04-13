import fs from 'fs';
import path from 'path';
import type { PDFFont } from 'pdf-lib';
import type { ReportSeverity } from '../types';

export const REPORTS_DIR = path.join(__dirname, '../../../../reports');

export function ensureReportsDir(): void {
    if (!fs.existsSync(REPORTS_DIR)) {
        fs.mkdirSync(REPORTS_DIR, { recursive: true });
    }
}

export async function writeFileAtomically(targetPath: string, content: Uint8Array | Buffer): Promise<void> {
    ensureReportsDir();
    const tempPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
    await fs.promises.writeFile(tempPath, content);
    await fs.promises.rename(tempPath, targetPath);
}

export function severityHex(severity: ReportSeverity): string {
    switch (severity) {
        case 'critical':
            return 'DC2626';
        case 'high':
            return 'EA580C';
        case 'medium':
            return 'D97706';
        case 'low':
            return '2563EB';
        default:
            return '64748B';
    }
}

export function severityRgb(severity: ReportSeverity): [number, number, number] {
    const hex = severityHex(severity);
    return [
        parseInt(hex.slice(0, 2), 16) / 255,
        parseInt(hex.slice(2, 4), 16) / 255,
        parseInt(hex.slice(4, 6), 16) / 255,
    ];
}

export function formatDisplayDate(value: string | null | undefined): string {
    if (!value) return 'N/A';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

export function safeText(value: string | null | undefined): string {
    return String(value || '').replace(/\r\n/g, '\n').trim();
}

const PDF_CHAR_REPLACEMENTS: Record<string, string> = {
    '\u00a0': ' ',
    '\u00ad': '-',
    '\u200b': '',
    '\u200c': '',
    '\u200d': '',
    '\u2010': '-',
    '\u2011': '-',
    '\u2012': '-',
    '\u2013': '-',
    '\u2014': '-',
    '\u2015': '-',
    '\u2018': '\'',
    '\u2019': '\'',
    '\u201a': '\'',
    '\u201b': '\'',
    '\u201c': '"',
    '\u201d': '"',
    '\u201e': '"',
    '\u2022': '*',
    '\u2023': '*',
    '\u2026': '...',
    '\u2043': '-',
    '\u2060': '',
    '\u2190': '<-',
    '\u2192': '->',
    '\u2194': '<->',
    '\u21d0': '<=',
    '\u21d2': '=>',
    '\u21d4': '<=>',
    '\u2212': '-',
    '\u2260': '!=',
    '\u2264': '<=',
    '\u2265': '>=',
    '\u25e6': '*',
    '\ufeff': '',
    '\ufe0f': '',
};

export function safePdfText(value: string | null | undefined, font: PDFFont): string {
    const normalized = safeText(value).replace(/\t/g, '    ');
    let result = '';

    for (const char of normalized) {
        if (char === '\n') {
            result += '\n';
            continue;
        }

        const replacement = PDF_CHAR_REPLACEMENTS[char] ?? char;
        for (const candidateChar of replacement) {
            if (!candidateChar) {
                continue;
            }

            try {
                font.encodeText(candidateChar);
                result += candidateChar;
            } catch {
                result += '?';
            }
        }
    }

    return result;
}
