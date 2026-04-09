import fs from 'fs';
import path from 'path';
import { saveScanLogs } from '../../db/init';
import { formatLogTimestamp, logger } from '../../utils/logger';

type PersistLogsFn = (scanId: string, logs: string[]) => void;
type TimestampFn = () => string;
type LoggerFn = (message: string, meta: Record<string, any>) => void;

export interface OrchestratorLogLedgerOptions {
    scanId: string;
    persistLogs?: PersistLogsFn;
    timestamp?: TimestampFn;
    writeInfoLog?: LoggerFn;
    flushIntervalMs?: number;
    flushBatchSize?: number;
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
    private lastFlushedLogIndex = 0;
    private lastFlushTime = Date.now();
    private readonly flushIntervalMs: number;
    private readonly flushBatchSize: number;
    private readonly persistLogs: PersistLogsFn;
    private readonly timestamp: TimestampFn;
    private readonly writeInfoLog: LoggerFn;

    constructor(private readonly options: OrchestratorLogLedgerOptions) {
        this.flushIntervalMs = options.flushIntervalMs ?? 60_000;
        this.flushBatchSize = options.flushBatchSize ?? 50;
        this.persistLogs = options.persistLogs ?? saveScanLogs;
        this.timestamp = options.timestamp ?? formatLogTimestamp;
        this.writeInfoLog = options.writeInfoLog ?? ((message, meta) => logger.info(message, meta));
    }

    public append(type: string, message: string): string {
        const normalizedMessage = normalizeVisibleLogMessage(message);
        const line = `[${this.timestamp()}] [${type.toUpperCase()}] ${normalizedMessage}`;
        this.logs.push(line);
        this.writeInfoLog(normalizedMessage, { scanId: this.options.scanId, type });
        this.maybeFlush();
        return line;
    }

    public getLogs(since: number = 0): string[] {
        return this.logs.slice(since);
    }

    public get count(): number {
        return this.logs.length;
    }

    public get unflushedCount(): number {
        return this.logs.length - this.lastFlushedLogIndex;
    }

    public flushToDB(): number {
        const newLogs = this.logs.slice(this.lastFlushedLogIndex);
        if (newLogs.length === 0) {
            return 0;
        }

        try {
            this.persistLogs(this.options.scanId, newLogs);
            this.lastFlushedLogIndex = this.logs.length;
            this.lastFlushTime = Date.now();
            return newLogs.length;
        } catch (error: any) {
            logger.error('Failed to flush logs to DB', {
                scanId: this.options.scanId,
                error: error.message,
            });
            return 0;
        }
    }

    public persistToFile(filePath: string): void {
        try {
            const logsDir = path.dirname(filePath);
            if (!fs.existsSync(logsDir)) {
                fs.mkdirSync(logsDir, { recursive: true });
            }
            fs.writeFileSync(filePath, this.logs.join('\n'), 'utf8');
        } catch (error: any) {
            logger.error('Failed to save logs', { error: error.message });
        }

        this.flushToDB();
    }

    private maybeFlush(): void {
        const newLogCount = this.logs.length - this.lastFlushedLogIndex;
        const timeSinceFlush = Date.now() - this.lastFlushTime;

        if (newLogCount >= this.flushBatchSize || (newLogCount > 0 && timeSinceFlush >= this.flushIntervalMs)) {
            this.flushToDB();
        }
    }
}
