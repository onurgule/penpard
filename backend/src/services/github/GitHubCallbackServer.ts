import http, { type IncomingMessage, type ServerResponse } from 'http';
import net, { type AddressInfo } from 'net';
import { URL } from 'url';
import { logger } from '../../utils/logger';
import type { GitHubAuthSessionSummary } from './types';
import type { GitHubCallbackListenerConfig } from './config';
import { getGitHubCallbackListenerConfig } from './config';

const CALLBACK_PORT_SCAN_WINDOW = 25;

type CallbackHandler = (query: {
    code?: string;
    state?: string;
    error?: string;
    errorDescription?: string;
}) => Promise<{ session: GitHubAuthSessionSummary | null; html: string }>;

export class GitHubCallbackServer {
    private server: http.Server | null = null;
    private listeningPromise: Promise<void> | null = null;
    private listenerError: string | null = null;
    private activeConfigSignature: string | null = null;
    private suggestedCallbackUrl: string | null = null;

    constructor(
        private readonly handleCallback: CallbackHandler,
        private readonly getConfig: () => GitHubCallbackListenerConfig = getGitHubCallbackListenerConfig,
    ) {}

    getListenerError(): string | null {
        return this.listenerError;
    }

    getSuggestedCallbackUrl(): string | null {
        return this.suggestedCallbackUrl;
    }

    getListenerUrl(): string {
        return this.getConfig().url;
    }

    private getConfigSignature(config: GitHubCallbackListenerConfig): string {
        return `${config.host}:${config.port}${config.path}`;
    }

    async ensureListening(): Promise<void> {
        const config = this.getConfig();
        const desiredSignature = this.getConfigSignature(config);

        if (this.server?.listening && this.activeConfigSignature === desiredSignature) {
            this.listenerError = null;
            this.suggestedCallbackUrl = null;
            return;
        }

        if (this.server?.listening) {
            await this.stop();
        }

        if (this.listeningPromise) {
            return this.listeningPromise;
        }

        this.listenerError = null;
        this.suggestedCallbackUrl = null;

        this.listeningPromise = new Promise<void>((resolve, reject) => {
            const server = http.createServer((req, res) => {
                void this.handleRequest(req, res).catch((error) => {
                    logger.error('GitHub callback request handling failed', {
                        error: error instanceof Error ? error.message : String(error),
                    });
                    if (!res.headersSent) {
                        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
                    }
                    res.end('<h1>GitHub callback failed</h1><p>Return to PenPard and try again.</p>');
                });
            });

            server.once('error', (error: NodeJS.ErrnoException) => {
                void this.handleServerError(error, config, reject);
            });

            server.listen(config.port, config.host, () => {
                this.server = server;
                this.listenerError = null;
                this.suggestedCallbackUrl = null;
                this.activeConfigSignature = desiredSignature;
                resolve();
            });
        }).finally(() => {
            this.listeningPromise = null;
        });

        return this.listeningPromise;
    }

    async stop(): Promise<void> {
        if (!this.server) {
            return;
        }

        const server = this.server;
        this.server = null;
        this.activeConfigSignature = null;
        this.suggestedCallbackUrl = null;

        await new Promise<void>((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolve();
            });
        });
    }

    private async handleServerError(
        error: NodeJS.ErrnoException,
        config: GitHubCallbackListenerConfig,
        reject: (reason?: unknown) => void,
    ): Promise<void> {
        this.listenerError = await this.buildListenerError(error, config);
        this.server = null;
        this.activeConfigSignature = null;
        reject(new Error(this.listenerError));
    }

    private async buildListenerError(error: NodeJS.ErrnoException, config: GitHubCallbackListenerConfig): Promise<string> {
        const address = `${config.host}:${config.port}`;
        if (error.code !== 'EADDRINUSE') {
            this.suggestedCallbackUrl = null;
            return `GitHub callback listener could not start on ${address}: ${error.message}`;
        }

        const suggestedCallbackUrl = await this.findSuggestedCallbackUrl(config);
        this.suggestedCallbackUrl = suggestedCallbackUrl;

        if (!suggestedCallbackUrl) {
            return `GitHub callback listener could not start on ${address}. Port ${config.port} is already in use. Choose another loopback callback URL in PenPard Settings, then update the same callback URL in your GitHub App settings.`;
        }

        return `GitHub callback listener could not start on ${address}. Port ${config.port} is already in use. Save ${suggestedCallbackUrl} in PenPard Settings, then update the same callback URL in your GitHub App settings.`;
    }

    private async findSuggestedCallbackUrl(config: GitHubCallbackListenerConfig): Promise<string | null> {
        const startingPort = Math.max(1, config.port + 1);
        const endingPort = Math.min(65535, config.port + CALLBACK_PORT_SCAN_WINDOW);

        for (let port = startingPort; port <= endingPort; port += 1) {
            if (await this.isPortAvailable(config.host, port)) {
                return this.buildCallbackUrlWithPort(config, port);
            }
        }

        const ephemeralPort = await this.getEphemeralPort(config.host);
        if (!ephemeralPort || ephemeralPort === config.port) {
            return null;
        }

        return this.buildCallbackUrlWithPort(config, ephemeralPort);
    }

    private buildCallbackUrlWithPort(config: GitHubCallbackListenerConfig, port: number): string {
        const suggestedUrl = new URL(config.url);
        suggestedUrl.port = String(port);
        return suggestedUrl.toString();
    }

    private async isPortAvailable(host: string, port: number): Promise<boolean> {
        return new Promise((resolve) => {
            const probe = net.createServer();

            probe.once('error', () => {
                resolve(false);
            });

            probe.listen(port, host, () => {
                probe.close((error) => {
                    resolve(!error);
                });
            });
        });
    }

    private async getEphemeralPort(host: string): Promise<number | null> {
        return new Promise((resolve) => {
            const probe = net.createServer();

            probe.once('error', () => {
                resolve(null);
            });

            probe.listen(0, host, () => {
                const address = probe.address();
                const port = address && typeof address !== 'string'
                    ? (address as AddressInfo).port
                    : null;

                probe.close((error) => {
                    if (error) {
                        resolve(null);
                        return;
                    }
                    resolve(port);
                });
            });
        });
    }

    private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
        const config = this.getConfig();
        const url = new URL(req.url || '/', config.url);

        if (req.method !== 'GET' || url.pathname !== config.path) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not found');
            return;
        }

        const result = await this.handleCallback({
            code: url.searchParams.get('code') || undefined,
            state: url.searchParams.get('state') || undefined,
            error: url.searchParams.get('error') || undefined,
            errorDescription: url.searchParams.get('error_description') || undefined,
        });

        res.writeHead(result.session?.status === 'completed' ? 200 : 400, {
            'Content-Type': 'text/html; charset=utf-8',
        });
        res.end(result.html);
    }
}
