/**
 * Burp Suite MCP Client for PenPard MCP Connect Extension
 * 
 * Connects to our custom Burp extension via MCP protocol.
 */

import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { addVulnerability, updateScanStatus } from '../db/init';

// Use localhost for npm, host.docker.internal for Docker
const BURP_MCP_URL = process.env.BURP_MCP_URL || 'http://localhost:9876';

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

interface ScannerIssue {
    name: string;
    severity: string;
    confidence: string;
    url: string;
    path: string;
    detail: string;
    remediation: string;
    request?: string;
    response?: string;
}

export class BurpMCPClient {
    private baseUrl: string;
    private messageUrl: string;

    constructor() {
        this.baseUrl = BURP_MCP_URL;
        this.messageUrl = `${this.baseUrl}/message`;
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

    async scan(scanId: string, targetUrl: string, config: any = {}): Promise<void> {
        logger.info('Starting Burp MCP scan', { scanId, targetUrl, config });

        try {
            updateScanStatus(scanId, 'initializing');

            // Initialize MCP connection
            await this.sendRequest('initialize');

            // Add target to scope
            updateScanStatus(scanId, 'configuring');
            await this.callTool('add_to_scope', { url: targetUrl });

            // Start the scan
            updateScanStatus(scanId, 'scanning');
            const scanResult = await this.callTool('start_scan', {
                url: targetUrl,
                crawlOnly: false
            });

            logger.info('Scan started', { scanId, result: scanResult });

            // Wait a bit for scan to run
            await new Promise(r => setTimeout(r, 10000));

            // Poll for issues
            updateScanStatus(scanId, 'analyzing');
            await this.pollForIssues(scanId, 5); // Check 5 times

            updateScanStatus(scanId, 'completed');
            logger.info('Burp MCP scan completed', { scanId });

        } catch (error: any) {
            logger.error('Burp MCP scan failed', { scanId, error: error.message });
            throw error;
        }
    }

    private async pollForIssues(scanId: string, attempts: number): Promise<void> {
        for (let i = 0; i < attempts; i++) {
            try {
                const result = await this.callTool('get_scanner_issues', { count: 100 });
                const issues = result?.issues || [];

                logger.info('Got scanner issues', { scanId, count: issues.length, attempt: i + 1 });

                for (const issue of issues) {
                    // Save vulnerability
                    addVulnerability({
                        scanId,
                        name: issue.name,
                        description: issue.detail || '',
                        severity: this.mapSeverity(issue.severity),
                        cvssScore: this.estimateCvss(issue.severity, issue.confidence),
                        remediation: issue.remediation || '',
                        request: issue.request || '',
                        response: issue.response || '',
                    });

                    // Send request to Repeater if we have the request
                    if (issue.request && issue.request.trim()) {
                        try {
                            // Parse the request to extract host, port, and HTTPS info
                            const requestLines = issue.request.split('\n');
                            const requestLine = requestLines[0];
                            const urlMatch = requestLine.match(/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(https?:\/\/[^\s]+)/i);
                            
                            if (urlMatch) {
                                const method = urlMatch[1];
                                const fullUrl = urlMatch[2];
                                const url = new URL(fullUrl);
                                const host = url.hostname;
                                const port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
                                const useHttps = url.protocol === 'https:';
                                
                                // Send to Repeater
                                await this.callTool('send_to_repeater', {
                                    host: host,
                                    port: port,
                                    useHttps: useHttps,
                                    request: issue.request,
                                    name: `${issue.name} - ${scanId}`
                                });
                                
                                logger.info('Sent vulnerability request to Repeater', {
                                    scanId,
                                    vulnerability: issue.name,
                                    url: fullUrl
                                });
                            }
                        } catch (error: any) {
                            logger.warn('Failed to send request to Repeater', {
                                scanId,
                                vulnerability: issue.name,
                                error: error.message
                            });
                        }
                    }
                }

                if (issues.length > 0) {
                    return; // Got issues, done
                }

                // Wait before next poll
                await new Promise(r => setTimeout(r, 5000));

            } catch (error: any) {
                logger.warn('Error polling for issues', { error: error.message });
            }
        }
    }

    private mapSeverity(severity: string): string {
        if (!severity) return 'medium';
        const map: Record<string, string> = {
            HIGH: 'high',
            MEDIUM: 'medium',
            LOW: 'low',
            INFORMATION: 'info',
            INFO: 'info',
        };
        return map[severity.toUpperCase()] || 'medium';
    }

    private estimateCvss(severity: string, confidence: string): number {
        const severityScores: Record<string, number> = {
            HIGH: 8.0,
            MEDIUM: 5.5,
            LOW: 3.0,
            INFORMATION: 0.0,
            INFO: 0.0,
        };

        const confidenceMultiplier: Record<string, number> = {
            CERTAIN: 1.0,
            FIRM: 0.9,
            TENTATIVE: 0.7,
        };

        const base = severityScores[severity?.toUpperCase()] || 5.0;
        const multiplier = confidenceMultiplier[confidence?.toUpperCase()] || 0.8;

        return Math.round(base * multiplier * 10) / 10;
    }

    disconnect(): void {
        logger.info('Disconnected from Burp MCP');
    }
}

export const burpMCP = new BurpMCPClient();
