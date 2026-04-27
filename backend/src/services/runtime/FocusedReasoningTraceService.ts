import { v4 as uuidv4 } from 'uuid';
import {
    createFocusedReasoningTraceEntry,
    listFocusedReasoningTraceEntriesByCase,
    listFocusedReasoningTraceEntriesByExecution,
    listFocusedReasoningTraceEntriesByScan,
} from '../../db/init';
import type {
    FocusedReasoningContextEffect,
    FocusedReasoningContextInfluence,
    FocusedReasoningTraceEntry,
    FocusedRequestContextField,
} from './ScopedScanTypes';

interface FocusedReasoningTraceDependencies {
    now: () => string;
    createId: () => string;
}

export interface RecordFocusedReasoningTraceInput extends Omit<FocusedReasoningTraceEntry, 'id' | 'timestamp' | 'linkedEvidenceIds' | 'linkedRequestContextKeys' | 'contextInfluence'> {
    timestamp?: string | null;
    linkedEvidenceIds?: string[];
    linkedRequestContextKeys?: FocusedRequestContextField[];
    contextInfluence?: FocusedReasoningContextInfluence[];
}

export class FocusedReasoningTraceService {
    private readonly deps: FocusedReasoningTraceDependencies;

    constructor(
        deps: Partial<FocusedReasoningTraceDependencies> = {},
    ) {
        this.deps = {
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
            ...deps,
        };
    }

    public record(input: RecordFocusedReasoningTraceInput): FocusedReasoningTraceEntry {
        const entry: FocusedReasoningTraceEntry = {
            id: this.deps.createId(),
            scanId: input.scanId,
            objectiveId: input.objectiveId,
            caseId: input.caseId ?? null,
            executionId: input.executionId ?? null,
            timestamp: input.timestamp || this.deps.now(),
            stage: input.stage,
            entryType: input.entryType,
            rail: input.rail,
            caseFamily: input.caseFamily ?? null,
            summary: input.summary,
            observationSummary: input.observationSummary ?? null,
            hypothesisRationaleSummary: input.hypothesisRationaleSummary ?? null,
            actionSelectionRationale: input.actionSelectionRationale ?? null,
            requestResponseImpactSummary: input.requestResponseImpactSummary ?? null,
            browserStateImpactSummary: input.browserStateImpactSummary ?? null,
            confidenceShiftSummary: input.confidenceShiftSummary ?? null,
            stopRetryBlockRationale: input.stopRetryBlockRationale ?? null,
            linkedEvidenceIds: dedupeStrings(input.linkedEvidenceIds || []),
            linkedRequestContextKeys: dedupeContextFields(input.linkedRequestContextKeys || []),
            contextInfluence: dedupeContextInfluence(input.contextInfluence || []),
        };

        createFocusedReasoningTraceEntry(entry);
        return entry;
    }

    public listByScan(scanId: string, limit = 200): FocusedReasoningTraceEntry[] {
        return listFocusedReasoningTraceEntriesByScan(scanId, limit);
    }

    public listByCase(scanId: string, caseId: string): FocusedReasoningTraceEntry[] {
        return listFocusedReasoningTraceEntriesByCase(scanId, caseId);
    }

    public listByExecution(scanId: string, caseId: string, executionId: string): FocusedReasoningTraceEntry[] {
        return listFocusedReasoningTraceEntriesByExecution(scanId, caseId, executionId);
    }
}

export function buildFocusedContextInfluence(
    field: FocusedRequestContextField,
    effect: FocusedReasoningContextEffect,
    summary: string,
): FocusedReasoningContextInfluence {
    return {
        field,
        effect,
        summary: summary.trim(),
    };
}

function dedupeStrings(values: string[]): string[] {
    return [...new Set(values.filter((entry) => typeof entry === 'string' && entry.trim().length > 0))];
}

function dedupeContextFields(values: FocusedRequestContextField[]): FocusedRequestContextField[] {
    return [...new Set(values)];
}

function dedupeContextInfluence(values: FocusedReasoningContextInfluence[]): FocusedReasoningContextInfluence[] {
    const deduped = new Map<string, FocusedReasoningContextInfluence>();
    for (const influence of values) {
        if (!influence.summary?.trim()) {
            continue;
        }
        const key = `${influence.field}:${influence.effect}:${influence.summary.trim()}`;
        if (!deduped.has(key)) {
            deduped.set(key, {
                field: influence.field,
                effect: influence.effect,
                summary: influence.summary.trim(),
            });
        }
    }
    return [...deduped.values()];
}

export const focusedReasoningTraceService = new FocusedReasoningTraceService();
