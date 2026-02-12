import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { Express } from 'express';
import { logger } from '../utils/logger';

export interface HttpsConfig {
    enabled: boolean;
    port: number;
    certPath?: string;
    keyPath?: string;
    caPath?: string;
    autoGenerateSelfSigned?: boolean;
    letsEncrypt?: {
        enabled: boolean;
        domain: string;
        email: string;
        staging?: boolean;
    };
}

const DEFAULT_CERT_DIR = path.join(__dirname, '../../certs');
const SELF_SIGNED_CERT = path.join(DEFAULT_CERT_DIR, 'selfsigned.crt');
const SELF_SIGNED_KEY = path.join(DEFAULT_CERT_DIR, 'selfsigned.key');

/**
 * HTTPS Server manager with support for self-signed and Let's Encrypt certificates.
 */
export class HttpsServer {
    private httpsServer: https.Server | null = null;
    private httpServer: http.Server | null = null;
    private config: HttpsConfig;

    constructor(config: HttpsConfig) {
        this.config = config;
    }

    /**
     * Start the HTTPS server.
     */
    async start(app: Express): Promise<void> {
        if (!this.config.enabled) {
            logger.info('HTTPS is disabled, starting HTTP only');
            return;
        }

        try {
            const credentials = await this.getCredentials();
            
            this.httpsServer = https.createServer(credentials, app);
            
            this.httpsServer.listen(this.config.port, () => {
                logger.info(`HTTPS server running on port ${this.config.port}`);
                console.log(`
╔═══════════════════════════════════════════╗
║       PENPARD HTTPS SERVER                ║
║       Running on https://localhost:${this.config.port}   ║
╚═══════════════════════════════════════════╝
                `);
            });

            // Optional: Start HTTP redirect server
            this.startHttpRedirect();

        } catch (error) {
            logger.error('Failed to start HTTPS server:', error);
            throw error;
        }
    }

    /**
     * Get SSL/TLS credentials.
     */
    private async getCredentials(): Promise<https.ServerOptions> {
        // Check for Let's Encrypt certificates first
        if (this.config.letsEncrypt?.enabled) {
            const leCreds = await this.getLetsEncryptCredentials();
            if (leCreds) return leCreds;
        }

        // Check for custom certificates
        if (this.config.certPath && this.config.keyPath) {
            if (fs.existsSync(this.config.certPath) && fs.existsSync(this.config.keyPath)) {
                logger.info('Using custom SSL certificates');
                return {
                    cert: fs.readFileSync(this.config.certPath),
                    key: fs.readFileSync(this.config.keyPath),
                    ca: this.config.caPath ? fs.readFileSync(this.config.caPath) : undefined,
                };
            }
        }

        // Fall back to self-signed certificates
        if (this.config.autoGenerateSelfSigned !== false) {
            return this.getSelfSignedCredentials();
        }

        throw new Error('No valid SSL certificates found');
    }

    /**
     * Get or generate self-signed certificates.
     */
    private getSelfSignedCredentials(): https.ServerOptions {
        // Ensure cert directory exists
        if (!fs.existsSync(DEFAULT_CERT_DIR)) {
            fs.mkdirSync(DEFAULT_CERT_DIR, { recursive: true });
        }

        // Generate if not exists
        if (!fs.existsSync(SELF_SIGNED_CERT) || !fs.existsSync(SELF_SIGNED_KEY)) {
            logger.info('Generating self-signed SSL certificate...');
            this.generateSelfSignedCert();
        }

        logger.info('Using self-signed SSL certificate');
        return {
            cert: fs.readFileSync(SELF_SIGNED_CERT),
            key: fs.readFileSync(SELF_SIGNED_KEY),
        };
    }

    /**
     * Generate a self-signed certificate using OpenSSL.
     */
    private generateSelfSignedCert(): void {
        try {
            // Check if OpenSSL is available
            execSync('openssl version', { encoding: 'utf8' });

            const subject = '/C=US/ST=Local/L=Local/O=PenPard/OU=Development/CN=localhost';
            
            execSync(`openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "${SELF_SIGNED_KEY}" \
                -out "${SELF_SIGNED_CERT}" \
                -subj "${subject}" \
                -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`, 
                { encoding: 'utf8', stdio: 'pipe' }
            );

            logger.info('Self-signed certificate generated successfully');
        } catch (error) {
            // Fallback: Generate using Node.js crypto (requires node-forge or similar)
            logger.warn('OpenSSL not available, using fallback certificate generation');
            this.generateFallbackCert();
        }
    }

    /**
     * Fallback certificate generation without OpenSSL.
     */
    private generateFallbackCert(): void {
        // Simple PEM format self-signed cert (for development only)
        // In production, proper certificates should be used
        const crypto = require('crypto');
        
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });

        // Create a simple self-signed certificate structure
        // Note: This is a simplified version; production should use proper X.509
        const certPem = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Qw0LBQAwPTELMAkGA1UE
BhMCVVMxDDAKBgNVBAgMA0xvYzEMMAoGA1UEBwwDTG9jMRIwEAYDVQQKDAlQZW5Q
YXJkMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowPTELMAkGA1UEBhMC
VVMxDDAKBgNVBAgMA0xvYzEMMAoGA1UEBwwDTG9jMRIwEAYDVQQKDAlQZW5QYXJk
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWu
sH8MUBkLmFrNr6H1pLZzXfDOWMcEqpOXpnEFq6FqBWxGk7dXqVNxGYyazAkF9xBl
PLACEHOLDER_FOR_ACTUAL_CERT_GENERATION
-----END CERTIFICATE-----`;

        fs.writeFileSync(SELF_SIGNED_KEY, privateKey);
        fs.writeFileSync(SELF_SIGNED_CERT, certPem);
        
        logger.warn('Using placeholder certificate - replace with proper cert for production');
    }

    /**
     * Get Let's Encrypt certificates.
     */
    private async getLetsEncryptCredentials(): Promise<https.ServerOptions | null> {
        const leConfig = this.config.letsEncrypt;
        if (!leConfig?.enabled || !leConfig.domain || !leConfig.email) {
            return null;
        }

        const certDir = `/etc/letsencrypt/live/${leConfig.domain}`;
        const certPath = path.join(certDir, 'fullchain.pem');
        const keyPath = path.join(certDir, 'privkey.pem');

        if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            logger.info(`Using Let's Encrypt certificate for ${leConfig.domain}`);
            return {
                cert: fs.readFileSync(certPath),
                key: fs.readFileSync(keyPath),
            };
        }

        // Attempt to obtain certificate using certbot
        logger.info(`Attempting to obtain Let's Encrypt certificate for ${leConfig.domain}`);
        try {
            const staging = leConfig.staging ? '--staging' : '';
            execSync(`certbot certonly --standalone ${staging} \
                -d ${leConfig.domain} \
                --email ${leConfig.email} \
                --agree-tos \
                --non-interactive`, 
                { encoding: 'utf8', stdio: 'pipe' }
            );

            if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
                return {
                    cert: fs.readFileSync(certPath),
                    key: fs.readFileSync(keyPath),
                };
            }
        } catch (error) {
            logger.error('Failed to obtain Let\'s Encrypt certificate:', error);
        }

        return null;
    }

    /**
     * Start HTTP to HTTPS redirect server.
     */
    private startHttpRedirect(): void {
        const httpPort = 80;
        
        this.httpServer = http.createServer((req, res) => {
            const host = req.headers.host?.split(':')[0] || 'localhost';
            const redirectUrl = `https://${host}:${this.config.port}${req.url}`;
            
            res.writeHead(301, { Location: redirectUrl });
            res.end();
        });

        this.httpServer.listen(httpPort, () => {
            logger.info(`HTTP redirect server running on port ${httpPort}`);
        }).on('error', (err: any) => {
            if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
                logger.warn(`Could not start HTTP redirect on port ${httpPort} - requires elevated privileges or port in use`);
            }
        });
    }

    /**
     * Stop the HTTPS server.
     */
    stop(): void {
        if (this.httpsServer) {
            this.httpsServer.close();
            logger.info('HTTPS server stopped');
        }
        if (this.httpServer) {
            this.httpServer.close();
            logger.info('HTTP redirect server stopped');
        }
    }

    /**
     * Get certificate expiry date.
     */
    getCertificateExpiry(): Date | null {
        try {
            const certPath = this.config.certPath || SELF_SIGNED_CERT;
            if (!fs.existsSync(certPath)) return null;

            const certPem = fs.readFileSync(certPath, 'utf8');
            // Parse certificate to get expiry (simplified)
            const match = certPem.match(/Not After\s*:\s*(.+)/);
            if (match) {
                return new Date(match[1]);
            }
        } catch {
            // Ignore errors
        }
        return null;
    }

    /**
     * Check if certificate needs renewal (within 30 days of expiry).
     */
    needsRenewal(): boolean {
        const expiry = this.getCertificateExpiry();
        if (!expiry) return false;
        
        const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
        return (expiry.getTime() - Date.now()) < thirtyDaysMs;
    }
}

/**
 * Create HTTPS server with default configuration.
 */
export function createHttpsServer(app: Express, config?: Partial<HttpsConfig>): HttpsServer {
    const defaultConfig: HttpsConfig = {
        enabled: process.env.HTTPS_ENABLED === 'true',
        port: parseInt(process.env.HTTPS_PORT || '4443', 10),
        certPath: process.env.SSL_CERT_PATH,
        keyPath: process.env.SSL_KEY_PATH,
        autoGenerateSelfSigned: true,
        letsEncrypt: {
            enabled: process.env.LETSENCRYPT_ENABLED === 'true',
            domain: process.env.LETSENCRYPT_DOMAIN || '',
            email: process.env.LETSENCRYPT_EMAIL || '',
            staging: process.env.LETSENCRYPT_STAGING === 'true',
        },
    };

    return new HttpsServer({ ...defaultConfig, ...config });
}
