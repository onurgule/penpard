import { Database as DatabaseType } from 'better-sqlite3';
import {
    createScopedFeatureDiscoveryState,
    createScopedTestRequest,
    createFocusedTestObjective,
    createScan,
    createScopeEnvelope,
    db,
    saveScanConfig,
    setScanInitialRequest,
    updateScanStatus,
} from '../../db/init';
import { logger } from '../../utils/logger';
import { ScopeEnvelopeService, ScopedScanValidationError, scopeEnvelopeService } from './ScopeEnvelopeService';
import { FocusedTestObjective, ScopeEnvelope, normalizeScanMode } from './ScopedScanTypes';
import { WebScanRuntimeConfig } from './ScanRuntimeFactory';
import { ScopedRequestIntakeService, scopedRequestIntakeService } from './ScopedRequestIntakeService';

function normalizeAutoAcceptPlans(value: unknown): boolean {
    if (value === undefined || value === null) {
        return true;
    }
    if (typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        return value !== 0;
    }
    if (typeof value === 'string') {
        return !['false', '0', 'no', 'off'].includes(value.trim().toLowerCase());
    }
    return Boolean(value);
}

export interface ScopedScanLaunchInput {
    scanId: string;
    userId: number;
    targetUrl: string;
    requestBody: Record<string, any>;
    scanMetadata: {
        sourcePackagePath?: string;
        sourceAnalysisMode?: string;
        scanMode?: string;
    };
    persistedConfig: Record<string, any>;
    runtimeConfig: WebScanRuntimeConfig;
    initialRequest?: string;
}

interface ScopedMissionLauncher {
    launchScopedMission(scanId: string, targetUrl: string, config?: WebScanRuntimeConfig): void;
}

export interface ScopedScanLaunchResult {
    objective: FocusedTestObjective;
    envelope: ScopeEnvelope;
}

export class ScopedScanLaunchService {
    private readonly requestIntakeService: ScopedRequestIntakeService;

    constructor(
        private readonly database: DatabaseType = db,
        private readonly scopeService: ScopeEnvelopeService = scopeEnvelopeService,
        private readonly missionLauncher: ScopedMissionLauncher = {
            launchScopedMission: () => {
                throw new Error('Scoped mission launcher not configured');
            },
        },
        requestIntakeService: ScopedRequestIntakeService = scopedRequestIntakeService,
    ) {
        this.requestIntakeService = requestIntakeService;
    }

    public launch(input: ScopedScanLaunchInput): ScopedScanLaunchResult {
        const scanMode = normalizeScanMode(input.scanMetadata.scanMode ?? input.runtimeConfig.scanMode ?? input.requestBody.scanMode);
        if (scanMode !== 'scoped') {
            throw new ScopedScanValidationError('ScopedScanLaunchService only accepts scanMode="scoped".');
        }

        const prepared = this.requestIntakeService.prepare({
            scanId: input.scanId,
            targetUrl: input.targetUrl,
            requestBody: input.requestBody,
            initialRequest: input.initialRequest,
        });
        const { objective, envelope } = prepared;
        const requestRecordId = input.scanId;
        const discoveryStateId = `${input.scanId}:feature-discovery`;

        const persistedConfig = {
            ...input.persistedConfig,
            scanMode: 'scoped',
            autoAcceptPlans: normalizeAutoAcceptPlans(input.requestBody.autoAcceptPlans),
            focusedTestObjectiveId: objective.id,
            scopeEnvelopeId: envelope.id,
            structuredSecurityTestRequestId: requestRecordId,
            scopedFeatureDiscoveryStateId: discoveryStateId,
        };

        const persistScan = this.database.transaction(() => {
            createScan({
                id: input.scanId,
                userId: input.userId,
                type: 'web',
                scanMode: 'scoped',
                target: input.targetUrl,
                sourcePackagePath: input.scanMetadata.sourcePackagePath,
                sourceAnalysisMode: input.scanMetadata.sourceAnalysisMode,
            });
            if (input.initialRequest?.trim()) {
                setScanInitialRequest(input.scanId, input.initialRequest.trim());
            }
            saveScanConfig(input.scanId, JSON.stringify(persistedConfig));
            createFocusedTestObjective(objective);
            createScopeEnvelope(envelope);
            createScopedTestRequest({
                id: requestRecordId,
                scanId: input.scanId,
                ...prepared.securityTestRequest,
            });
            createScopedFeatureDiscoveryState({
                id: discoveryStateId,
                scanId: input.scanId,
                phase: 'not_started',
                outcome: null,
                summary: 'Structured security test request accepted. Feature discovery is queued.',
                errorMessage: null,
                requestAnchorCount: envelope.baselineRequestRefs.length + envelope.discoveredRequestRefs.length,
                browserAnchorCount: envelope.browserAnchors.length,
                selectedEndpointCount: envelope.selectedEndpoints.length,
                allowedRouteCount: envelope.allowedRoutes.length,
                startedAt: null,
                completedAt: null,
            });
            updateScanStatus(input.scanId, 'scoped_discovering');
        });

        persistScan();

        logger.info('Launching scoped scan', {
            scanId: input.scanId,
            targetUrl: input.targetUrl,
            scopeType: objective.scopeType,
            selectedEndpoints: envelope.selectedEndpoints.length,
            baselineRequestRefs: envelope.baselineRequestRefs.length,
            requestDescription: prepared.securityTestRequest.description,
        });

        this.missionLauncher.launchScopedMission(input.scanId, input.targetUrl, {
            ...input.runtimeConfig,
            scanMode: 'scoped',
        });

        return {
            objective,
            envelope,
        };
    }
}
