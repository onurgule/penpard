import { getScanRuntimeCheckpoint, saveScanRuntimeCheckpoint } from '../../db/init';
import { logger } from '../../utils/logger';

export interface ScanRuntimeCheckpointPlanStep {
    step: number;
    objective: string;
    status: string;
    tools: string[];
}

export interface ScanRuntimeCheckpoint {
    version: 1;
    executionMode: 'single-agent';
    reason: string;
    updatedAt: string;
    phase: string;
    isRunning: boolean;
    isPaused: boolean;
    planRound: number;
    maxPlanRounds: number;
    maxIterations: number;
    findingsCount: number;
    discoveredEndpointsCount: number;
    discoveredEndpointsPreview: string[];
    currentPlan: {
        round: number;
        steps: ScanRuntimeCheckpointPlanStep[];
    } | null;
    harvested: {
        total: number;
        promoted: number;
        byClassification: Record<string, number>;
        promotedRequests: Array<{
            id: string;
            method: string;
            path: string;
            classification: string;
            interestScore: number;
            testedHypotheses: string[];
        }>;
        topScoring: Array<{
            id: string;
            score: number;
            method: string;
            path: string;
            classification: string;
        }>;
    };
    hypotheses: {
        total: number;
        counts: Record<string, number>;
        activeHypotheses: Array<{
            id: string;
            type: string;
            targetEndpoint: string;
            targetMethod: string;
            parameter: string;
            confidence: number;
            status: string;
            nextAction: string;
            evidenceCount: number;
        }>;
    };
    coverage: {
        routesSeen: number;
        routesFromFrontend: number;
        routesExercisedInBrowser: number;
        requestsObservedInBurp: number;
        requestsPromoted: number;
        hypothesesActive: number;
        untestedRoutes: string[];
        weaklyTestedRoutes: string[];
        workflowStatus: Record<string, { explored: boolean; completeness: string }>;
        coveragePercentage: number;
    };
    endpointInventory: {
        summary: string;
        authSurfaceCount?: number;
        endpointCount?: number;
        highValueCount?: number;
    } | null;
}

export class ScanRuntimeCheckpointService {
    public saveCheckpoint(scanId: string, checkpoint: ScanRuntimeCheckpoint): void {
        try {
            saveScanRuntimeCheckpoint(scanId, JSON.stringify(checkpoint));
        } catch (error: any) {
            logger.error('Failed to persist scan runtime checkpoint', {
                scanId,
                reason: checkpoint.reason,
                error: error.message,
            });
        }
    }

    public getCheckpoint(scanId: string): ScanRuntimeCheckpoint | null {
        return getScanRuntimeCheckpoint(scanId) as ScanRuntimeCheckpoint | null;
    }
}

export const scanRuntimeCheckpointService = new ScanRuntimeCheckpointService();
