import { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';
import type { ActiveScanRuntime } from './ScanRuntimeContract';

export interface ScanLogCacheEntry {
    logs: string[];
    phase: string;
    cachedAt: number;
}

export type ScanRuntimeHandle =
    | { kind: 'agent'; scanId: string; agent: OrchestratorAgent }
    | { kind: 'pool'; scanId: string; pool: AgentPool }
    | { kind: 'runtime'; scanId: string; runtime: ActiveScanRuntime };

export class ScanRuntimeRegistry {
    private readonly activeAgents = new Map<string, OrchestratorAgent>();
    private readonly activePools = new Map<string, AgentPool>();
    private readonly activeRuntimes = new Map<string, ActiveScanRuntime>();
    private readonly scanLogCache = new Map<string, ScanLogCacheEntry>();

    constructor(private readonly maxCachedScans: number = 20) {}

    public registerAgent(scanId: string, agent: OrchestratorAgent): void {
        this.activeAgents.set(scanId, agent);
    }

    public registerPool(scanId: string, pool: AgentPool): void {
        this.activePools.set(scanId, pool);
    }

    public registerRuntime(scanId: string, runtime: ActiveScanRuntime): void {
        this.activeRuntimes.set(scanId, runtime);
    }

    public unregister(scanId: string): void {
        this.activeAgents.delete(scanId);
        this.activePools.delete(scanId);
        this.activeRuntimes.delete(scanId);
    }

    public getAgent(scanId: string): OrchestratorAgent | undefined {
        const directAgent = this.activeAgents.get(scanId);
        if (directAgent) {
            return directAgent;
        }

        return this.activeRuntimes.get(scanId)?.getAgent?.();
    }

    public getPool(scanId: string): AgentPool | undefined {
        return this.activePools.get(scanId);
    }

    public getActiveRuntime(scanId: string): ActiveScanRuntime | undefined {
        return this.activeRuntimes.get(scanId);
    }

    public getRuntime(scanId: string): ScanRuntimeHandle | undefined {
        const agent = this.activeAgents.get(scanId);
        if (agent) {
            return { kind: 'agent', scanId, agent };
        }

        const pool = this.activePools.get(scanId);
        if (pool) {
            return { kind: 'pool', scanId, pool };
        }

        const runtime = this.activeRuntimes.get(scanId);
        if (runtime) {
            return { kind: 'runtime', scanId, runtime };
        }

        return undefined;
    }

    public hasActiveRuntime(scanId: string): boolean {
        return this.activeAgents.has(scanId) || this.activePools.has(scanId) || this.activeRuntimes.has(scanId);
    }

    public getActiveAgentCount(): number {
        return this.activeAgents.size;
    }

    public getActivePoolCount(): number {
        return this.activePools.size;
    }

    public getActiveRuntimeCount(): number {
        return this.activeRuntimes.size;
    }

    public getTotalActiveRuntimeCount(): number {
        return this.activeAgents.size + this.activePools.size + this.activeRuntimes.size;
    }

    public cacheLogs(scanId: string, snapshot: Omit<ScanLogCacheEntry, 'cachedAt'>): ScanLogCacheEntry {
        const entry: ScanLogCacheEntry = {
            ...snapshot,
            cachedAt: Date.now(),
        };

        this.scanLogCache.set(scanId, entry);
        this.trimLogCache();
        return entry;
    }

    public getCachedLogs(scanId: string): ScanLogCacheEntry | undefined {
        return this.scanLogCache.get(scanId);
    }

    public captureAgentLogs(scanId: string, agent: OrchestratorAgent, phaseOverride?: string): ScanLogCacheEntry {
        const state = agent.getState();
        return this.cacheLogs(scanId, {
            logs: agent.getLogs(0),
            phase: phaseOverride ?? state.phase,
        });
    }

    public capturePoolLogs(scanId: string, pool: AgentPool, phase: string): ScanLogCacheEntry {
        return this.cacheLogs(scanId, {
            logs: pool.getLogs(0),
            phase,
        });
    }

    public captureRuntimeLogs(scanId: string, runtime: ActiveScanRuntime, phaseOverride?: string): ScanLogCacheEntry {
        const snapshot = runtime.captureLogs?.(phaseOverride) || {
            logs: runtime.getLogs(0),
            phase: phaseOverride ?? runtime.getPhase(),
        };

        return this.cacheLogs(scanId, snapshot);
    }

    private trimLogCache(): void {
        while (this.scanLogCache.size > this.maxCachedScans) {
            const oldest = this.scanLogCache.keys().next().value;
            if (!oldest) {
                break;
            }
            this.scanLogCache.delete(oldest);
        }
    }
}

export const scanRuntimeRegistry = new ScanRuntimeRegistry();
