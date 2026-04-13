import fs from 'fs';
import path from 'path';
import { saveScanLogs } from '../../db/init';
import { formatLogTimestamp } from '../../utils/logger';
import { sanitizeOrchestratorLogText } from './OrchestratorSafeLogging';

type TimestampFn = () => string;

export interface OrchestratorLogLedgerOptions {
    timestamp?: TimestampFn;
    scanId?: string;
}

export interface OrchestratorLogEntry {
    type: string;
    message: string;
    line: string;
}

const MOJIBAKE_REPAIRS: Array<[RegExp, string]> = [
    [/âœ…|âœ“|✓|✅/g, '[ok]'],
    [/âš ï¸|âš |⚠️|⚠/g, '[warn]'],
    [/ğŸ¯|🎯/g, '[scope]'],
    [/ğŸ“š|📚/g, '[mindset]'],
    [/ğŸ”|🔐/g, '[auth]'],
    [/ğŸ”|🔍/g, '[analysis]'],
    [/ğŸ”¬|🔬/g, '[source]'],
    [/ğŸŒ|🌐/g, '[browser]'],
    [/ğŸš«|ÄŸÅ¸Å¡Â«|🚫/g, '[rate-limit]'],
    [/ğŸ“¡|📡/g, '[harvest]'],
    [/ğŸ“‹|📋/g, '[hypotheses]'],
    [/ğŸ“Š|📊/g, '[coverage]'],
    [/â¸|⏸/g, '[paused]'],
    [/â–¶|▶/g, '[resumed]'],
    [/âš¡|⚡/g, '[hypothesis]'],
    [/â‡”|⇔/g, '<->'],
    [/â†’|→/g, '->'],
    [/â€”|—/g, '-'],
    [/â•|═/g, '='],
    [/â”€|─/g, '-'],
    [/â•”|╔/g, '='],
    [/â•š|╚/g, '='],
    [/â€¢â€|â€¢Å¡|â€¢â€˜|â€¢Â|║|╣|╠|╝|╗/g, '='],
];

export function normalizeVisibleLogMessage(message: string): string {
    let normalized = String(message || '').normalize('NFC');

    for (const [pattern, replacement] of MOJIBAKE_REPAIRS) {
        normalized = normalized.replace(pattern, replacement);
    }

    normalized = normalized
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

export class OrchestratorLogLedger {
    private readonly logs: string[] = [];
    private readonly timestamp: TimestampFn;
    private readonly scanId: string | null;
    private flushedCount = 0;

    constructor(options: OrchestratorLogLedgerOptions = {}) {
        this.timestamp = options.timestamp ?? formatLogTimestamp;
        this.scanId = options.scanId || null;
    }

    public append(type: string, message: string): OrchestratorLogEntry {
        const normalizedMessage = normalizeVisibleLogMessage(sanitizeOrchestratorLogText(message));
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
