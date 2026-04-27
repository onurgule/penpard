import fs from 'fs';
import path from 'path';
import { saveScanLogs } from '../../db/init';
import { formatLogTimestamp } from '../../utils/logger';
import { sanitizeOrchestratorLogText } from '../../agents/orchestrator/OrchestratorSafeLogging';

type TimestampFn = () => string;

export interface RuntimeLogLedgerOptions {
    timestamp?: TimestampFn;
    scanId?: string;
}

export interface RuntimeLogEntry {
    type: string;
    message: string;
    line: string;
}

const MOJIBAKE_REPAIRS: Array<[RegExp, string]> = [
    [/Ã¢Å“â€¦|Ã¢Å“â€œ|âœ“|âœ…/g, '[ok]'],
    [/Ã¢Å¡Â Ã¯Â¸Â|Ã¢Å¡Â |âš ï¸|âš /g, '[warn]'],
    [/ÄŸÅ¸ÂÂ¯|ğŸ¯/g, '[scope]'],
    [/ÄŸÅ¸â€œÅ¡|ğŸ“š/g, '[mindset]'],
    [/ÄŸÅ¸â€Â|ğŸ”/g, '[auth]'],
    [/ÄŸÅ¸â€Â|ğŸ”/g, '[analysis]'],
    [/ÄŸÅ¸â€Â¬|ğŸ”¬/g, '[source]'],
    [/ÄŸÅ¸Å’Â|ğŸŒ/g, '[browser]'],
    [/ÄŸÅ¸Å¡Â«|Ã„Å¸Ã…Â¸Ã…Â¡Ã‚Â«|ğŸš«/g, '[rate-limit]'],
    [/ÄŸÅ¸â€œÂ¡|ğŸ“¡/g, '[harvest]'],
    [/ÄŸÅ¸â€œâ€¹|ğŸ“‹/g, '[hypotheses]'],
    [/ÄŸÅ¸â€œÅ |ğŸ“Š/g, '[coverage]'],
    [/Ã¢ÂÂ¸|â¸/g, '[paused]'],
    [/Ã¢â€“Â¶|â–¶/g, '[resumed]'],
    [/Ã¢Å¡Â¡|âš¡/g, '[hypothesis]'],
    [/Ã¢â€¡â€|â‡”/g, '<->'],
    [/Ã¢â€ â€™|â†’/g, '->'],
    [/Ã¢â‚¬â€|â€”/g, '-'],
    [/Ã¢â€¢Â|â•/g, '='],
    [/Ã¢â€â‚¬|â”€/g, '-'],
    [/Ã¢â€¢â€|â•”/g, '='],
    [/Ã¢â€¢Å¡|â•š/g, '='],
    [/Ã¢â‚¬Â¢Ã¢â‚¬Â|Ã¢â‚¬Â¢Ã…Â¡|Ã¢â‚¬Â¢Ã¢â‚¬Ëœ|Ã¢â‚¬Â¢Ã‚Â|â•‘|â•£|â• |â•|â•—/g, '='],
];

const CLEAN_MARKER_REPAIRS: Array<[RegExp, string]> = [
    [/^[\u2713\u2714]\s+/gm, '[ok] '],
    [/^⚠️?\s+/gm, '[warn] '],
    [/^\u{1F3AF}\s+/gmu, '[scope] '],
    [/^\u{1F9E0}\s+/gmu, '[mindset] '],
    [/^\u{1F510}\s+/gmu, '[auth] '],
    [/^\u{1F50D}\s+/gmu, '[analysis] '],
    [/^\u{1F4EC}\s+/gmu, '[source] '],
    [/^(?:\u{1F310}|\u{1F30D}|\u{1F30E}|\u{1F30F})\s+/gmu, '[browser] '],
    [/^\u{1F6A6}\s+/gmu, '[rate-limit] '],
    [/^\u{1F321}\u{FE0F}?\s+/gmu, '[harvest] '],
    [/^\u{1F4A1}\s+/gmu, '[hypotheses] '],
    [/^\u{1F4CA}\s+/gmu, '[coverage] '],
    [/^⏸\s+/gm, '[paused] '],
    [/^▶️?\s+/gm, '[resumed] '],
    [/^⚡\s+/gm, '[hypothesis] '],
];

export function normalizeVisibleRuntimeLogMessage(message: string): string {
    let normalized = String(message || '').normalize('NFC');

    for (const [pattern, replacement] of MOJIBAKE_REPAIRS) {
        normalized = normalized.replace(pattern, replacement);
    }

    for (const [pattern, replacement] of CLEAN_MARKER_REPAIRS) {
        normalized = normalized.replace(pattern, replacement);
    }

    normalized = normalized
        .replace(/↔/g, ' <-> ')
        .replace(/→/g, ' -> ')
        .replace(/[═]{3,}/g, ' === ')
        .replace(/\s+=+\s+/g, ' === ')
        .replace(/= {2,}/g, '= ')
        .replace(/ {2,}=/g, ' =')
        .replace(/^=+\s*/gm, '=== ')
        .replace(/\s*=+$/gm, ' ===')
        .replace(/===\s*===/g, '===')
        .replace(/\s+-\s+/g, ' - ')
        .replace(/\s+<->\s+/g, ' <-> ')
        .replace(/\s+->\s+/g, ' -> ')
        .replace(/[ \t]+/g, ' ')
        .replace(/ \n/g, '\n')
        .trim();

    return normalized;
}

export class RuntimeLogLedger {
    private readonly logs: string[] = [];
    private readonly timestamp: TimestampFn;
    private readonly scanId: string | null;
    private flushedCount = 0;

    constructor(options: RuntimeLogLedgerOptions = {}) {
        this.timestamp = options.timestamp ?? formatLogTimestamp;
        this.scanId = options.scanId || null;
    }

    public append(type: string, message: string): RuntimeLogEntry {
        const normalizedMessage = normalizeVisibleRuntimeLogMessage(sanitizeOrchestratorLogText(message));
        const line = `[${this.timestamp()}] [${type.toUpperCase()}] ${normalizedMessage}`;
        this.logs.push(line);
        return {
            type,
            message: normalizedMessage,
            line,
        };
    }

    public getLogs(since: number = 0): string[] {
        return this.logs.slice(since);
    }

    public get count(): number {
        return this.logs.length;
    }

    public flushToDB(): number {
        if (!this.scanId) return 0;
        const pending = this.logs.slice(this.flushedCount);
        if (pending.length === 0) return 0;
        saveScanLogs(this.scanId, pending);
        this.flushedCount = this.logs.length;
        return pending.length;
    }

    public get unflushedCount(): number {
        return Math.max(this.logs.length - this.flushedCount, 0);
    }

    public persistToFile(targetPath: string): void {
        const directory = path.dirname(targetPath);
        fs.mkdirSync(directory, { recursive: true });
        fs.writeFileSync(targetPath, this.logs.join('\n'));
    }
}
