import { formatLogTimestamp } from '../../utils/logger';

type TimestampFn = () => string;

export interface OrchestratorLogLedgerOptions {
    timestamp?: TimestampFn;
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

    constructor(options: OrchestratorLogLedgerOptions = {}) {
        this.timestamp = options.timestamp ?? formatLogTimestamp;
    }

    public append(type: string, message: string): OrchestratorLogEntry {
        const normalizedMessage = normalizeVisibleLogMessage(message);
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
}
