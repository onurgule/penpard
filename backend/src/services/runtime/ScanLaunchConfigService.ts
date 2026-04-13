import { logger } from '../../utils/logger';
import { defaultAuthStartupConfig, redactAuthStartupConfig, resolveAuthStartupConfig, toLegacyIdorUsers } from '../web-auth-startup-config';
import type { WebScanRuntimeConfig } from './ScanRuntimeFactory';

type WarnFn = (message: string, meta?: Record<string, any>) => void;
type MaybeBoolean = boolean | string | number | null | undefined;

const VALID_SOURCE_ANALYSIS_MODES = new Set(['version_aware', 'full_source_aware']);

export interface PreparedScanLaunch {
    scanMetadata: {
        sourcePackagePath?: string;
        sourceAnalysisMode?: string;
    };
    runtimeConfig: WebScanRuntimeConfig;
    persistedConfig: Record<string, any>;
}

export interface PrepareWebScanLaunchInput {
    userId: number;
    rateLimit?: unknown;
    useNuclei?: unknown;
    useFfuf?: unknown;
    idorUsers?: unknown;
    parallelAgents?: unknown;
    scanInstructions?: unknown;
    sessionCookies?: unknown;
    iterations?: unknown;
    maxPlanRounds?: unknown;
    sourcePackagePath?: unknown;
    sourceAnalysisMode?: unknown;
    authStartupMode?: unknown;
    authCredentials?: unknown;
    allowAccountCreation?: MaybeBoolean;
    preferSharedPassword?: MaybeBoolean;
}

export interface PrepareBurpScanLaunchInput {
    userId: number;
    initialRequest: string;
    rateLimit?: unknown;
    parallelAgents?: unknown;
    scanInstructions?: unknown;
    iterations?: unknown;
    maxPlanRounds?: unknown;
    sourcePackagePath?: unknown;
    sourceAnalysisMode?: unknown;
}

export class ScanLaunchConfigService {
    constructor(
        private readonly warn: WarnFn = (message, meta) => logger.warn(message, meta),
    ) {}

    public prepareWebLaunch(input: PrepareWebScanLaunchInput): PreparedScanLaunch {
        const requestedUseNuclei = this.normalizeBoolean(input.useNuclei);
        const requestedUseFfuf = this.normalizeBoolean(input.useFfuf);
        if (requestedUseNuclei) {
            this.warn('nucleiEnabled was requested but Nuclei integration is not yet implemented - ignoring', {
                scanId: 'pre-creation',
            });
        }
        if (requestedUseFfuf) {
            this.warn('ffufEnabled was requested but FFUF integration is not yet implemented - ignoring', {
                scanId: 'pre-creation',
            });
        }

        const legacyIdorUsers = this.parseJsonArray<any>(input.idorUsers);
        const authStartup = resolveAuthStartupConfig({
            authStartupMode: input.authStartupMode,
            authCredentials: input.authCredentials,
            allowAccountCreation: input.allowAccountCreation,
            preferSharedPassword: input.preferSharedPassword,
            idorUsers: legacyIdorUsers,
        });
        const runtimeIdorUsers = authStartup.credentials.length > 0
            ? toLegacyIdorUsers(authStartup)
            : legacyIdorUsers;

        const runtimeConfig: WebScanRuntimeConfig = {
            userId: input.userId,
            rateLimit: this.resolvePositiveNumber(input.rateLimit, 5),
            useNuclei: false,
            useFfuf: false,
            idorUsers: runtimeIdorUsers,
            parallelAgents: 1,
            requestedParallelAgents: this.resolveRequestedParallelAgents(input.parallelAgents),
            maxIterations: this.resolvePositiveNumber(input.iterations, 50),
            maxPlanRounds: this.resolveMaxPlanRounds(input.maxPlanRounds),
            customSystemPrompt: this.normalizeString(input.scanInstructions),
            sessionCookies: this.normalizeString(input.sessionCookies),
            sourcePackagePath: this.normalizeString(input.sourcePackagePath),
            sourceAnalysisMode: this.resolveSourceAnalysisMode(input.sourceAnalysisMode),
            authStartup,
        };

        return this.buildPreparedLaunch(runtimeConfig);
    }

    public prepareBurpLaunch(input: PrepareBurpScanLaunchInput): PreparedScanLaunch {
        const runtimeConfig: WebScanRuntimeConfig = {
            userId: input.userId,
            rateLimit: this.resolvePositiveNumber(input.rateLimit, 5),
            useNuclei: false,
            useFfuf: false,
            idorUsers: [],
            parallelAgents: 1,
            requestedParallelAgents: this.resolveRequestedParallelAgents(input.parallelAgents),
            maxIterations: this.resolvePositiveNumber(input.iterations, 50),
            maxPlanRounds: this.resolveMaxPlanRounds(input.maxPlanRounds),
            customSystemPrompt: this.normalizeString(input.scanInstructions),
            sessionCookies: undefined,
            initialRequest: input.initialRequest,
            sourcePackagePath: this.normalizeString(input.sourcePackagePath),
            sourceAnalysisMode: this.resolveSourceAnalysisMode(input.sourceAnalysisMode),
            authStartup: defaultAuthStartupConfig(),
        };

        return this.buildPreparedLaunch(runtimeConfig);
    }

    private buildPreparedLaunch(runtimeConfig: WebScanRuntimeConfig): PreparedScanLaunch {
        const safeLegacyUsers = (runtimeConfig.idorUsers || []).map((entry: any) => ({
            ...entry,
            password: entry?.password ? '[REDACTED]' : undefined,
        }));

        return {
            scanMetadata: {
                sourcePackagePath: runtimeConfig.sourcePackagePath,
                sourceAnalysisMode: runtimeConfig.sourceAnalysisMode,
            },
            runtimeConfig,
            persistedConfig: {
                ...runtimeConfig,
                effectiveParallelAgents: 1,
                executionMode: 'single-agent',
                idorUsers: safeLegacyUsers,
                authStartup: runtimeConfig.authStartup
                    ? redactAuthStartupConfig(runtimeConfig.authStartup)
                    : undefined,
            },
        };
    }

    private normalizeString(value: unknown): string | undefined {
        if (typeof value !== 'string') {
            return undefined;
        }

        const trimmed = value.trim();
        return trimmed ? trimmed : undefined;
    }

    private normalizeBoolean(value: unknown): boolean {
        if (typeof value === 'boolean') {
            return value;
        }
        if (typeof value === 'number') {
            return value !== 0;
        }
        if (typeof value !== 'string') {
            return false;
        }

        return ['true', '1', 'yes', 'on'].includes(value.trim().toLowerCase());
    }

    private parseJsonArray<T = any>(value: unknown): T[] {
        if (Array.isArray(value)) {
            return value as T[];
        }
        if (typeof value !== 'string' || !value.trim()) {
            return [];
        }

        try {
            const parsed = JSON.parse(value);
            return Array.isArray(parsed) ? parsed as T[] : [];
        } catch {
            return [];
        }
    }

    private resolvePositiveNumber(value: unknown, fallback: number): number {
        const parsed = Number(value);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
    }

    private resolveRequestedParallelAgents(value: unknown): number {
        const parsed = Number(value);
        if (!Number.isFinite(parsed)) {
            return 1;
        }
        return Math.max(1, Math.min(10, parsed));
    }

    private resolveMaxPlanRounds(value: unknown): number {
        if (value === undefined || value === null || value === '') {
            return 0;
        }

        const parsed = Number(value);
        if (!Number.isFinite(parsed)) {
            return 0;
        }

        return Math.max(0, Math.min(99, parsed));
    }

    private resolveSourceAnalysisMode(value: unknown): string | undefined {
        return typeof value === 'string' && VALID_SOURCE_ANALYSIS_MODES.has(value)
            ? value
            : undefined;
    }
}

export const scanLaunchConfigService = new ScanLaunchConfigService();
