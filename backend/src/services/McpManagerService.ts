
import { spawn, ChildProcess } from 'child_process';
import { db } from '../db/init';
import { logger } from '../utils/logger';
import path from 'path';

/**
 * Interface representing an MCP Server configuration from the database.
 */
export interface McpServerConfig {
    name: string;
    command: string;
    args: string; // JSON array string
    env_vars: string; // JSON object string
    status: 'stopped' | 'running' | 'error' | 'maintenance';
    is_enabled: number;
}

/**
 * Interface for a running MCP Server instance.
 */
interface RunningServer {
    process: ChildProcess;
    startTime: number;
    logs: string[];
}

class McpManagerService {
    private runningServers: Map<string, RunningServer> = new Map();
    // In-memory log buffer for real-time UI feed (limited size)
    private globalLogBuffer: Array<{ server: string; message: string; timestamp: string; type: 'stdout' | 'stderr' | 'system' }> = [];
    private readonly MAX_LOG_SIZE = 1000;

    constructor() {
        // Automatically load and start enabled servers on initialization
        this.initialize();
    }

    /**
     * Load enabled servers from DB and attempt to start them.
     */
    public async initialize() {
        logger.info('Initializing McpManagerService...');
        try {
            const servers = this.getAllServers();
            for (const server of servers) {
                if (server.is_enabled && server.status !== 'maintenance') {
                    await this.startServer(server.name);
                }
            }

            // Check if pentesting-cyber-mcp is installed, if not, offer/install it?
            // For now, we assume user adds it via UI or we seed it later.
        } catch (error) {
            logger.error('Failed to initialize MCP Manager', { error });
        }
    }

    /**
     * DB Access: Get all servers
     */
    public getAllServers(): McpServerConfig[] {
        return db.prepare('SELECT * FROM mcp_servers').all() as McpServerConfig[];
    }

    /**
     * DB Access: Get single server
     */
    public getServer(name: string): McpServerConfig | undefined {
        return db.prepare('SELECT * FROM mcp_servers WHERE name = ?').get(name) as McpServerConfig;
    }

    /**
     * Add or Update a server config
     */
    public upsertServer(config: Omit<McpServerConfig, 'status'>) {
        const exists = this.getServer(config.name);
        if (exists) {
            db.prepare(`
                UPDATE mcp_servers 
                SET command = ?, args = ?, env_vars = ?, is_enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE name = ?
            `).run(config.command, config.args, config.env_vars, config.is_enabled, config.name);
        } else {
            db.prepare(`
                INSERT INTO mcp_servers (name, command, args, env_vars, status)
                VALUES (?, ?, ?, ?, 'stopped')
            `).run(config.name, config.command, config.args, config.env_vars);
        }
    }

    /**
     * Delete a server
     */
    public deleteServer(name: string) {
        this.stopServer(name); // Stop first
        db.prepare('DELETE FROM mcp_servers WHERE name = ?').run(name);
    }

    /**
     * Start a specific MCP server process
     */
    public async startServer(name: string) {
        const config = this.getServer(name);
        if (!config) {
            throw new Error(`Server ${name} not found`);
        }

        if (this.runningServers.has(name)) {
            logger.warn(`Server ${name} is already running.`);
            return;
        }

        this.log(name, 'system', `Starting server: ${config.command}`);

        try {
            const args = JSON.parse(config.args || '[]');
            const env = JSON.parse(config.env_vars || '{}');

            // Merge env with process.env
            const finalEnv = { ...process.env, ...env };

            const child = spawn(config.command, args, {
                env: finalEnv,
                shell: true, // Use shell to ensure command resolution
                cwd: process.cwd() // Run from backend dir usually
            });

            const runningServer: RunningServer = {
                process: child,
                startTime: Date.now(),
                logs: []
            };

            this.runningServers.set(name, runningServer);
            this.updateStatus(name, 'running');

            // Handle Output
            child.stdout?.on('data', (data) => {
                const msg = data.toString().trim();
                if (msg) this.log(name, 'stdout', msg);
            });

            child.stderr?.on('data', (data) => {
                const msg = data.toString().trim();
                if (msg) this.log(name, 'stderr', msg);
            });

            child.on('error', (err) => {
                this.log(name, 'stderr', `Process Error: ${err.message}`);
                this.updateStatus(name, 'error');
            });

            child.on('close', (code) => {
                this.log(name, 'system', `Process exited with code ${code}`);
                this.runningServers.delete(name);
                this.updateStatus(name, 'stopped');
            });

        } catch (error: any) {
            this.log(name, 'stderr', `Failed to spawn: ${error.message}`);
            this.updateStatus(name, 'error');
        }
    }

    /**
     * Stop a running server
     */
    public stopServer(name: string) {
        const server = this.runningServers.get(name);
        if (server) {
            this.log(name, 'system', 'Stopping server...');
            server.process.kill(); // SIGTERM
            this.runningServers.delete(name);
            this.updateStatus(name, 'stopped');
        }
    }

    /**
     * Restart helper
     */
    public async restartServer(name: string) {
        this.stopServer(name);
        // Wait small delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        await this.startServer(name);
    }

    /**
     * Update DB status
     */
    private updateStatus(name: string, status: string) {
        db.prepare('UPDATE mcp_servers SET status = ? WHERE name = ?').run(status, name);
    }

    /**
     * Central logging for UI
     */
    private log(server: string, type: 'stdout' | 'stderr' | 'system', message: string) {
        const entry = {
            server,
            message,
            timestamp: new Date().toISOString(),
            type
        };

        // Add to global buffer
        this.globalLogBuffer.push(entry);
        if (this.globalLogBuffer.length > this.MAX_LOG_SIZE) {
            this.globalLogBuffer.shift();
        }

        // Add to individual instance history
        const instance = this.runningServers.get(server);
        if (instance) {
            instance.logs.push(`[${entry.timestamp}] [${type}] ${message}`);
            if (instance.logs.length > 200) instance.logs.shift();
        }

        // TODO: Emit via WebSocket if connected
    }

    /**
     * Get logs for API
     */
    public getLogs(limit: number = 100) {
        return this.globalLogBuffer.slice(-limit);
    }
}

export const mcpManager = new McpManagerService();
