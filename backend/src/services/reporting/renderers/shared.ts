import fs from 'fs';
import path from 'path';
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
