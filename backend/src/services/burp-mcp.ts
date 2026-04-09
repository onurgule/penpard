/**
 * Burp Suite MCP Client for PenPard MCP Connect Extension
 * 
 * Connects to our custom Burp extension via MCP protocol.
 */

import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// Resolve Burp MCP URL: DB config → env var → default
function getBurpMcpUrl(): string {
    try {
        const { db } = require('../db/init');
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
        if (row && row.value) {
            const cfg = JSON.parse(row.value);
            const protocol = cfg.useHttps ? 'https' : 'http';
            return `${protocol}://${cfg.host}:${cfg.port}`;
        }
    } catch { /* DB not ready yet, use fallback */ }
    return process.env.BURP_MCP_URL || 'http://localhost:9876';
}

// Lazy getter — resolves on each use so config changes take effect without restart
const BURP_MCP_URL_GETTER = { get url() { return getBurpMcpUrl(); } };

interface MCPRequest {
    jsonrpc: '2.0';
    id: string;
    method: string;
    params?: any;
}

interface MCPTool {
    name: string;
    description?: string;
    inputSchema?: any;
}

export class BurpMCPClient {
    private get baseUrl(): string {
        return getBurpMcpUrl();
    }
    private get messageUrl(): string {
        return `${this.baseUrl}/message`;
    }

    constructor() {
        // URL is now resolved dynamically via getter — no static assignment needed
    }

    async isAvailable(): Promise<boolean> {
        try {
            const response = await axios.get(`${this.baseUrl}/health`, {
                timeout: 3000,
            });

            const available = response.status === 200;
            logger.info('Burp MCP availability check', {
                url: this.baseUrl,
                status: response.status,
                available
            });

            return available;
        } catch (error: any) {
            logger.warn('Burp MCP not available', {
                url: this.baseUrl,
                error: error.message
            });
            return false;
        }
    }

    async sendRequest(method: string, params?: any): Promise<any> {
        const id = uuidv4();
        const request: MCPRequest = {
            jsonrpc: '2.0',
            id,
            method,
            params,
        };

        logger.info('Sending MCP request', { method, id });

        try {
            const response = await axios.post(this.messageUrl, request, {
                headers: { 'Content-Type': 'application/json' },
                timeout: 60000, // 60 seconds for scans
            });

            if (response.data?.error) {
                throw new Error(response.data.error.message);
            }

            return response.data?.result;
        } catch (error: any) {
            logger.error('MCP request failed', {
                method,
                error: error.message,
                status: error.response?.status
            });
            throw error;
        }
    }

    async listTools(): Promise<MCPTool[]> {
        try {
            const result = await this.sendRequest('tools/list');
            logger.info('Available Burp MCP tools', {
                tools: result?.tools?.map((t: MCPTool) => t.name)
            });
            return result?.tools || [];
        } catch (error: any) {
            logger.error('Failed to list MCP tools', { error: error.message });
            return [];
        }
    }

    async callTool(name: string, args: any): Promise<any> {
        logger.info('Calling MCP tool', { name, args });
        return await this.sendRequest('tools/call', { name, arguments: args });
    }

    disconnect(): void {
        logger.info('Disconnected from Burp MCP');
    }
}

export const burpMCP = new BurpMCPClient();
