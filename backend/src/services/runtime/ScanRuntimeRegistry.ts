import { AgentPool } from '../../agents/AgentPool';
import { OrchestratorAgent } from '../../agents/OrchestratorAgent';

export interface ScanLogCacheEntry {
    logs: string[];
    phase: string;
    cachedAt: number;
}

export type ScanRuntimeHandle =
    | { kind: 'agent'; scanId: string; agent: OrchestratorAgent }
    | { kind: 'pool'; scanId: string; pool: AgentPool };

export class ScanRuntimeRegistry {
    private readonly activeAgents = new Map<string, OrchestratorAgent>();
    private readonly activePools = new Map<string, AgentPool>();
    private readonly scanLogCache = new Map<string, ScanLogCacheEntry>();

    constructor(private readonly maxCachedScans: number = 20) {}

    public registerAgent(scanId: string, agent: OrchestratorAgent): void {
        this.activeAgents.set(scanId, agent);
    }

    public registerPool(scanId: string, pool: AgentPool): void {
        this.activePools.set(scanId, pool);
    }

    public unregister(scanId: string): void {
        this.activeAgents.delete(scanId);
        this.activePools.delete(scanId);
    }

    public getAgent(scanId: string): OrchestratorAgent | undefined {
        return this.activeAgents.get(scanId);
    }

    public getPool(scanId: string): AgentPool | undefined {
        return this.activePools.get(scanId);
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

        return undefined;
    }

    public hasActiveRuntime(scanId: string): boolean {
        return this.activeAgents.has(scanId) || this.activePools.has(scanId);
    }

    public getActiveAgentCount(): number {
        return this.activeAgents.size;
    }

    public getActivePoolCount(): number {
        return this.activePools.size;
    }

    public getTotalActiveRuntimeCount(): number {
        return this.activeAgents.size + this.activePools.size;
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
