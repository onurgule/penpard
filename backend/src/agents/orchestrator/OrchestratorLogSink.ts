import fs from 'fs';
import path from 'path';
import { saveScanLogs } from '../../db/init';
import { logger } from '../../utils/logger';
import { OrchestratorLogEntry, OrchestratorLogLedger } from './OrchestratorLogLedger';

type PersistLogsFn = (scanId: string, logs: string[]) => void;
type LoggerFn = (message: string, meta: Record<string, any>) => void;
type NowFn = () => number;

export interface OrchestratorLogSinkOptions {
    scanId: string;
    persistLogs?: PersistLogsFn;
    writeInfoLog?: LoggerFn;
    now?: NowFn;
    flushIntervalMs?: number;
    flushBatchSize?: number;
}

export class OrchestratorLogSink {
    private lastFlushedLogIndex = 0;
    private lastFlushTime: number;
    private readonly flushIntervalMs: number;
    private readonly flushBatchSize: number;
    private readonly persistLogs: PersistLogsFn;
    private readonly writeInfoLog: LoggerFn;
    private readonly now: NowFn;

    constructor(private readonly options: OrchestratorLogSinkOptions) {
        this.flushIntervalMs = options.flushIntervalMs ?? 60_000;
        this.flushBatchSize = options.flushBatchSize ?? 50;
        this.persistLogs = options.persistLogs ?? saveScanLogs;
        this.writeInfoLog = options.writeInfoLog ?? ((message, meta) => logger.info(message, meta));
        this.now = options.now ?? (() => Date.now());
        this.lastFlushTime = this.now();
    }

    public record(entry: OrchestratorLogEntry, ledger: OrchestratorLogLedger): void {
        this.writeInfoLog(entry.message, { scanId: this.options.scanId, type: entry.type });
        this.maybeFlush(ledger);
    }

    public getUnflushedCount(ledger: OrchestratorLogLedger): number {
        return ledger.count - this.lastFlushedLogIndex;
    }

    public flushToDB(ledger: OrchestratorLogLedger): number {
        const newLogs = ledger.getLogs(this.lastFlushedLogIndex);
        if (newLogs.length === 0) {
            return 0;
        }

        try {
            this.persistLogs(this.options.scanId, newLogs);
            this.lastFlushedLogIndex = ledger.count;
            this.lastFlushTime = this.now();
            return newLogs.length;
        } catch (error: any) {
            logger.error('Failed to flush logs to DB', {
                scanId: this.options.scanId,
                error: error.message,
            });
            return 0;
        }
    }

    public persistToFile(ledger: OrchestratorLogLedger, filePath: string): void {
        try {
            const logsDir = path.dirname(filePath);
            if (!fs.existsSync(logsDir)) {
                fs.mkdirSync(logsDir, { recursive: true });
            }
            fs.writeFileSync(filePath, ledger.getLogs(0).join('\n'), 'utf8');
        } catch (error: any) {
            logger.error('Failed to save logs', { error: error.message });
        }

        this.flushToDB(ledger);
    }

    private maybeFlush(ledger: OrchestratorLogLedger): void {
        const newLogCount = this.getUnflushedCount(ledger);
        const timeSinceFlush = this.now() - this.lastFlushTime;

        if (newLogCount >= this.flushBatchSize || (newLogCount > 0 && timeSinceFlush >= this.flushIntervalMs)) {
            this.flushToDB(ledger);
        }
    }
}
