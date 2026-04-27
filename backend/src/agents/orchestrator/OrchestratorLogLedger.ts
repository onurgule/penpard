import {
    RuntimeLogLedger,
    type RuntimeLogEntry,
    type RuntimeLogLedgerOptions,
    normalizeVisibleRuntimeLogMessage,
} from '../../services/runtime/RuntimeLogLedger';

export type OrchestratorLogLedgerOptions = RuntimeLogLedgerOptions;
export type OrchestratorLogEntry = RuntimeLogEntry;

export function normalizeVisibleLogMessage(message: string): string {
    return normalizeVisibleRuntimeLogMessage(message);
}

export class OrchestratorLogLedger extends RuntimeLogLedger {}
