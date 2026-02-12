/**
 * Agent Pool - Multi-agent management
 * Starts workers, coordinates them, and collects results
 */

import { BurpMCPClient } from '../services/burp-mcp';
import { SharedContext } from './SharedContext';
import { WorkerAgent, WorkerRole } from './WorkerAgent';
import { RecheckAgent } from './RecheckAgent';
import { addVulnerability, updateScanStatus } from '../db/init';
import { logger } from '../utils/logger';

export interface PoolConfig {
    crawlerCount: number;
    scannerCount: number;
    fuzzerCount: number;
    analyzerCount: number;
    maxIterationsPerWorker: number;
    rateLimit: number;
}

const DEFAULT_CONFIG: PoolConfig = {
    crawlerCount: 1,
    scannerCount: 2,
    fuzzerCount: 1,
    analyzerCount: 1,
    maxIterationsPerWorker: 20,
    rateLimit: 5
};

export class AgentPool {
    private scanId: string;
    private targetUrl: string;
    private config: PoolConfig;
    private burp: BurpMCPClient;

    private context: SharedContext;
    private workers: WorkerAgent[] = [];
    private recheckAgent: RecheckAgent | null = null;
    private isRunning: boolean = false;
    private logs: string[] = [];

    constructor(
        scanId: string,
        targetUrl: string,
        burp: BurpMCPClient,
        config?: Partial<PoolConfig>
    ) {
        this.scanId = scanId;
        this.targetUrl = targetUrl;
        this.burp = burp;
        this.config = { ...DEFAULT_CONFIG, ...config };

        // Create shared context
        this.context = new SharedContext(scanId, targetUrl);

        // Listen for context events
        this.setupContextListeners();
    }

    private setupContextListeners(): void {
        // Log all worker logs
        this.context.on('worker:log', ({ workerId, message }) => {
            this.logs.push(message);
        });

        // Save vulnerabilities to DB
        this.context.on('vulnerability:found', (vuln) => {
            this.log(`[VULN] ${vuln.severity.toUpperCase()}: ${vuln.name}`);

            // Format request/response as strings
            let requestStr = '';
            let responseStr = '';
            
            if (vuln.request) {
                // Format request object to HTTP string
                const req = vuln.request;
                requestStr = `${req.method} ${req.url} HTTP/1.1\n`;
                Object.entries(req.headers || {}).forEach(([key, value]) => {
                    requestStr += `${key}: ${value}\n`;
                });
                if (req.body) {
                    requestStr += `\n${req.body}`;
                }
            } else {
                // Fallback to endpoint if no request object
                requestStr = `${vuln.method || 'GET'} ${vuln.endpoint} HTTP/1.1`;
            }
            
            if (vuln.response) {
                // Format response object to HTTP string
                const resp = vuln.response;
                responseStr = `HTTP/1.1 ${resp.status} ${this.getStatusText(resp.status)}\n`;
                Object.entries(resp.headers || {}).forEach(([key, value]) => {
                    responseStr += `${key}: ${value}\n`;
                });
                if (resp.body) {
                    responseStr += `\n${resp.body}`;
                }
            }

            addVulnerability({
                scanId: this.scanId,
                name: vuln.name,
                description: vuln.description,
                severity: vuln.severity,
                cvssScore: this.estimateCvss(vuln.severity),
                remediation: vuln.remediation || '',
                cwe: vuln.cwe || '',
                cve: '',
                request: requestStr,
                response: responseStr,
                evidence: vuln.evidence
            });
        });

        // Log discoveries
        this.context.on('endpoint:discovered', (endpoint) => {
            this.log(`[DISCOVERY] ${endpoint.method} ${endpoint.url}`);
        });
    }

    public async start(): Promise<void> {
        if (this.isRunning) return;

        this.isRunning = true;
        this.log(`Agent Pool starting with ${this.getTotalWorkerCount()} workers`);

        updateScanStatus(this.scanId, 'initializing');

        try {
            // Check Burp connection
            const burpOk = await this.burp.isAvailable();
            if (!burpOk) {
                throw new Error('Burp MCP not available');
            }
            this.log('Burp MCP: Connected');

            // Add target to scope
            await this.burp.callTool('add_to_scope', { url: this.targetUrl });
            this.log(`Added ${this.targetUrl} to Burp scope`);

            // Add initial endpoint
            this.context.addEndpoint({
                url: this.targetUrl,
                method: 'GET',
                priority: 10,
                source: 'initial',
                tested: false
            });

            // Create workers
            this.createWorkers();

            // Create recheck agent for vulnerability verification
            this.recheckAgent = new RecheckAgent(this.scanId, this.context, this.burp);
            this.log('Recheck Agent created for vulnerability verification');

            updateScanStatus(this.scanId, 'testing');
            this.log('Phase: PARALLEL TESTING');

            // Start all workers and recheck agent in parallel
            const workerPromises = this.workers.map(worker => worker.start());
            const recheckPromise = this.recheckAgent.start();

            // Wait for all workers to complete
            await Promise.all(workerPromises);

            // Stop recheck agent after workers are done
            this.recheckAgent.stop();
            await recheckPromise;

            // Reporting phase
            await this.generateReport();

            updateScanStatus(this.scanId, 'completed');
            this.log('Scan completed successfully');

        } catch (error: any) {
            this.log(`Pool error: ${error.message}`);
            updateScanStatus(this.scanId, 'failed', error.message);
        } finally {
            this.isRunning = false;
            this.cleanup();
        }
    }

    public stop(): void {
        this.log('Stopping all workers...');
        this.isRunning = false;

        for (const worker of this.workers) {
            worker.stop();
        }

        if (this.recheckAgent) {
            this.recheckAgent.stop();
        }
    }

    public pause(): void {
        for (const worker of this.workers) {
            worker.pause();
        }
    }

    public resume(): void {
        for (const worker of this.workers) {
            worker.resume();
        }
    }

    public getState() {
        return {
            isRunning: this.isRunning,
            workerCount: this.workers.length,
            workers: this.workers.map(w => w.getStatus()),
            stats: this.context.getStats(),
            logsCount: this.logs.length
        };
    }

    public getLogs(since: number = 0): string[] {
        return this.logs.slice(since);
    }

    public getContext(): SharedContext {
        return this.context;
    }

    // ============ PRIVATE METHODS ============

    private createWorkers(): void {
        const workerConfig = {
            maxIterations: this.config.maxIterationsPerWorker,
            rateLimit: this.config.rateLimit
        };

        // Create crawlers
        for (let i = 0; i < this.config.crawlerCount; i++) {
            this.workers.push(new WorkerAgent('crawler', this.context, this.burp, workerConfig));
        }

        // Create scanners
        for (let i = 0; i < this.config.scannerCount; i++) {
            this.workers.push(new WorkerAgent('scanner', this.context, this.burp, workerConfig));
        }

        // Create fuzzers
        for (let i = 0; i < this.config.fuzzerCount; i++) {
            this.workers.push(new WorkerAgent('fuzzer', this.context, this.burp, workerConfig));
        }

        // Create analyzers
        for (let i = 0; i < this.config.analyzerCount; i++) {
            this.workers.push(new WorkerAgent('analyzer', this.context, this.burp, workerConfig));
        }

        this.log(`Created ${this.workers.length} workers: ${this.workers.map(w => w.role).join(', ')}`);
    }

    private async generateReport(): Promise<void> {
        updateScanStatus(this.scanId, 'reporting');
        this.log('Phase: REPORTING');

        const stats = this.context.getStats();
        const vulns = this.context.getVulnerabilities();

        this.log(`Scan Summary:`);
        this.log(`- Endpoints Discovered: ${stats.totalEndpoints}`);
        this.log(`- Endpoints Tested: ${stats.testedEndpoints}`);
        this.log(`- Total Requests: ${stats.totalRequests}`);
        this.log(`- Vulnerabilities Found: ${stats.vulnerabilitiesFound}`);

        if (vulns.length > 0) {
            this.log(`Vulnerabilities:`);
            for (const v of vulns) {
                this.log(`  [${v.severity.toUpperCase()}] ${v.name} at ${v.endpoint}`);
            }
        }
    }

    private getTotalWorkerCount(): number {
        return this.config.crawlerCount +
            this.config.scannerCount +
            this.config.fuzzerCount +
            this.config.analyzerCount;
    }

    private estimateCvss(severity: string): number {
        const scores: Record<string, number> = {
            'critical': 9.5,
            'high': 8.0,
            'medium': 5.5,
            'low': 3.0,
            'info': 0.0
        };
        return scores[severity?.toLowerCase()] || 5.0;
    }

    private getStatusText(status: number): string {
        const statusTexts: Record<number, string> = {
            200: 'OK',
            201: 'Created',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable'
        };
        return statusTexts[status] || 'Unknown';
    }

    private cleanup(): void {
        this.context.clear();
        this.workers = [];
    }

    private log(message: string): void {
        const line = `[${new Date().toISOString()}] [POOL] ${message}`;
        this.logs.push(line);
        logger.info(message, { scanId: this.scanId, component: 'AgentPool' });
    }
}
