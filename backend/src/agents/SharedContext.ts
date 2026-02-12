/**
 * Shared Context - Shared data pool between agents
 * Thread-safe data structure
 */

import { EventEmitter } from 'events';

export interface DiscoveredEndpoint {
    url: string;
    method: string;
    params?: Record<string, string>;
    headers?: Record<string, string>;
    body?: string;
    source: string; // Which agent discovered this
    priority: number; // 1-10, higher priority endpoints are tested first
    tested: boolean;
    testResults?: any;
}

export interface SharedVulnerability {
    id: string;
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';

    // CVSS 4.0
    cvssVector?: string;  // e.g., "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    cvssScore?: number;   // 0.0 - 10.0

    // CWE Reference
    cwe?: string;         // e.g., "CWE-89"
    cweName?: string;     // e.g., "SQL Injection"

    // Pentest Report Fields
    description: string;  // What the vulnerability is
    impact: string;       // What could happen if exploited
    remediation: string;  // How to fix it

    // PoC (Proof of Concept)
    poc: string[];        // Step-by-step reproduction steps

    // Request/Response Evidence
    endpoint: string;     // Full URL
    method: string;       // HTTP method
    request?: {
        url: string;
        method: string;
        headers: Record<string, string>;
        body?: string;
    };
    response?: {
        status: number;
        headers: Record<string, string>;
        body: string;
    };

    // Raw evidence
    evidence: string;

    // Metadata
    foundBy: string;      // Agent ID
    timestamp: Date;
    verified: boolean;    // Verified by RecheckAgent?
}

export interface SharedSession {
    name: string;
    cookies?: string;
    authHeader?: string;
    userId?: string;
}

export interface AgentMessage {
    from: string;
    to: string | 'all';
    type: 'discovery' | 'finding' | 'task' | 'status' | 'data';
    payload: any;
    timestamp: Date;
}

export class SharedContext extends EventEmitter {
    private endpoints: Map<string, DiscoveredEndpoint> = new Map();
    private vulnerabilities: SharedVulnerability[] = [];
    private sessions: SharedSession[] = [];
    private messageQueue: AgentMessage[] = [];
    private testedUrls: Set<string> = new Set();

    // Stats
    private stats = {
        totalEndpoints: 0,
        testedEndpoints: 0,
        totalRequests: 0,
        vulnerabilitiesFound: 0
    };

    constructor(public readonly scanId: string, public readonly targetUrl: string) {
        super();
    }

    // ============ ENDPOINT MANAGEMENT ============

    addEndpoint(endpoint: DiscoveredEndpoint): boolean {
        const key = `${endpoint.method}:${endpoint.url}`;

        if (this.endpoints.has(key)) {
            return false; // Already exists
        }

        this.endpoints.set(key, { ...endpoint, tested: false });
        this.stats.totalEndpoints++;
        this.emit('endpoint:discovered', endpoint);
        return true;
    }

    getUntestedEndpoints(limit: number = 10): DiscoveredEndpoint[] {
        return Array.from(this.endpoints.values())
            .filter(e => !e.tested)
            .sort((a, b) => b.priority - a.priority)
            .slice(0, limit);
    }

    markEndpointTested(url: string, method: string, result?: any): void {
        const key = `${method}:${url}`;
        const endpoint = this.endpoints.get(key);
        if (endpoint) {
            endpoint.tested = true;
            endpoint.testResults = result;
            this.stats.testedEndpoints++;
            this.testedUrls.add(url);
            this.emit('endpoint:tested', endpoint);
        }
    }

    isUrlTested(url: string): boolean {
        return this.testedUrls.has(url);
    }

    getAllEndpoints(): DiscoveredEndpoint[] {
        return Array.from(this.endpoints.values());
    }

    // ============ VULNERABILITY MANAGEMENT ============

    addVulnerability(vuln: SharedVulnerability): void {
        this.vulnerabilities.push(vuln);
        this.stats.vulnerabilitiesFound++;
        this.emit('vulnerability:found', vuln);
    }

    getVulnerabilities(): SharedVulnerability[] {
        return this.vulnerabilities;
    }

    // ============ SESSION MANAGEMENT ============

    addSession(session: SharedSession): void {
        const existing = this.sessions.findIndex(s => s.name === session.name);
        if (existing >= 0) {
            this.sessions[existing] = session;
        } else {
            this.sessions.push(session);
        }
        this.emit('session:added', session);
    }

    getSessions(): SharedSession[] {
        return this.sessions;
    }

    // ============ MESSAGING ============

    sendMessage(message: Omit<AgentMessage, 'timestamp'>): void {
        const msg: AgentMessage = { ...message, timestamp: new Date() };
        this.messageQueue.push(msg);
        this.emit('message', msg);

        if (message.to === 'all') {
            this.emit('broadcast', msg);
        } else {
            this.emit(`message:${message.to}`, msg);
        }
    }

    getMessagesFor(agentId: string): AgentMessage[] {
        return this.messageQueue.filter(m => m.to === agentId || m.to === 'all');
    }

    // ============ STATISTICS ============

    incrementRequests(): void {
        this.stats.totalRequests++;
    }

    getStats() {
        return { ...this.stats };
    }

    // ============ TASK QUEUE ============

    private taskQueue: { task: string; priority: number; data: any }[] = [];

    addTask(task: string, data: any, priority: number = 5): void {
        this.taskQueue.push({ task, data, priority });
        this.taskQueue.sort((a, b) => b.priority - a.priority);
        this.emit('task:added', { task, data, priority });
    }

    getNextTask(): { task: string; priority: number; data: any } | null {
        return this.taskQueue.shift() || null;
    }

    // ============ CLEANUP ============

    clear(): void {
        this.endpoints.clear();
        this.vulnerabilities = [];
        this.sessions = [];
        this.messageQueue = [];
        this.testedUrls.clear();
        this.taskQueue = [];
        this.removeAllListeners();
    }
}
