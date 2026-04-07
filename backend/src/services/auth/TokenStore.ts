/**
 * PenPard Auth State Management — TokenStore
 * 
 * Per-identity token storage with JWT parsing, expiry tracking,
 * rotation handling, and refresh token management.
 */

import { TokenState, TokenType, AuthCaptureSource, redactSecret } from './types';
import { logger } from '../../utils/logger';
import { randomUUID } from 'crypto';

export class TokenStore {
    private tokens: Map<string, TokenState> = new Map();
    private readonly identityId: string;

    constructor(identityId: string) {
        this.identityId = identityId;
    }

    // ═══════════════════════════════════════════════════════════
    //  TOKEN MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * Store or update a token. If a token with the same headerName already exists
     * for this identity, the old one is marked as superseded.
     */
    store(token: Omit<TokenState, 'id' | 'identityId' | 'superseded'>): TokenState {
        const fullToken: TokenState = {
            ...token,
            id: randomUUID(),
            identityId: this.identityId,
            superseded: false,
        };

        // Auto-detect JWT
        if (fullToken.tokenType === 'bearer' || fullToken.tokenType === 'opaque') {
            const jwtPayload = TokenStore.parseJWT(fullToken.value);
            if (jwtPayload) {
                fullToken.tokenType = 'jwt';
                fullToken.jwtPayload = jwtPayload;
                if (jwtPayload.exp && typeof jwtPayload.exp === 'number') {
                    fullToken.expiresAt = new Date(jwtPayload.exp * 1000);
                }
            }
        }

        // Supersede existing tokens with same headerName (unless it's a refresh token)
        if (!fullToken.isRefreshToken) {
            for (const [id, existing] of this.tokens.entries()) {
                if (existing.headerName === fullToken.headerName && !existing.superseded && !existing.isRefreshToken) {
                    existing.superseded = true;
                    logger.info(`TokenStore: Superseded token ${redactSecret(existing.value, 'token')} for ${existing.headerName}`);
                }
            }
        }

        this.tokens.set(fullToken.id, fullToken);
        return fullToken;
    }

    /**
     * Store a token from a raw Authorization header value.
     * Parses "Bearer abc123" → prefix="Bearer ", value="abc123"
     */
    storeFromAuthHeader(headerValue: string, source: AuthCaptureSource): TokenState | null {
        if (!headerValue || !headerValue.trim()) return null;

        const trimmed = headerValue.trim();
        let prefix = '';
        let value = trimmed;

        // Split prefix (Bearer, Token, Basic) from value
        const spaceIdx = trimmed.indexOf(' ');
        if (spaceIdx > 0) {
            prefix = trimmed.substring(0, spaceIdx + 1); // include the trailing space
            value = trimmed.substring(spaceIdx + 1).trim();
        }

        if (!value) return null;

        const tokenType = this.detectTokenType(prefix, value);

        return this.store({
            tokenType,
            headerName: 'Authorization',
            headerValuePrefix: prefix,
            value,
            expiresAt: null,                // will be set if JWT detected
            isRefreshToken: false,
            source,
            capturedAt: new Date(),
        });
    }

    /**
     * Store a custom header token (e.g., X-API-Key).
     */
    storeCustomHeader(headerName: string, headerValue: string, source: AuthCaptureSource): TokenState {
        return this.store({
            tokenType: 'api_key',
            headerName,
            headerValuePrefix: '',
            value: headerValue,
            expiresAt: null,
            isRefreshToken: false,
            source,
            capturedAt: new Date(),
        });
    }

    /**
     * Store a refresh token.
     */
    storeRefreshToken(value: string, endpoint: string, source: AuthCaptureSource, bodyTemplate?: string, accessTokenPath?: string): TokenState {
        return this.store({
            tokenType: 'opaque',
            headerName: '__refresh__',    // internal marker, not sent in headers
            headerValuePrefix: '',
            value,
            expiresAt: null,
            isRefreshToken: true,
            refreshEndpoint: endpoint,
            refreshMethod: 'POST',
            refreshBodyTemplate: bodyTemplate,
            newAccessTokenJsonPath: accessTokenPath,
            source,
            capturedAt: new Date(),
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  RETRIEVAL
    // ═══════════════════════════════════════════════════════════

    /** Get the active (non-superseded) token for a given header name. */
    getActive(headerName: string = 'Authorization'): TokenState | null {
        for (const token of this.tokens.values()) {
            if (token.headerName === headerName && !token.superseded && !token.isRefreshToken) {
                return token;
            }
        }
        return null;
    }

    /** Get all active (non-superseded, non-refresh) tokens. */
    getAllActive(): TokenState[] {
        const result: TokenState[] = [];
        for (const token of this.tokens.values()) {
            if (!token.superseded && !token.isRefreshToken) {
                result.push(token);
            }
        }
        return result;
    }

    /** Get the active refresh token. */
    getRefreshToken(): TokenState | null {
        for (const token of this.tokens.values()) {
            if (token.isRefreshToken && !token.superseded) {
                return token;
            }
        }
        return null;
    }

    /** Get a token by ID. */
    getById(id: string): TokenState | undefined {
        return this.tokens.get(id);
    }

    /** Get all tokens (including superseded). */
    getAll(): TokenState[] {
        return [...this.tokens.values()];
    }

    /** Total active token count. */
    get activeCount(): number {
        return this.getAllActive().length;
    }

    // ═══════════════════════════════════════════════════════════
    //  EXPIRY & ROTATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if any active token is expiring soon.
     * Returns seconds until expiry, or null if no expiry known.
     */
    getSecondsUntilExpiry(headerName: string = 'Authorization'): number | null {
        const token = this.getActive(headerName);
        if (!token || !token.expiresAt) return null;
        return Math.max(0, Math.floor((token.expiresAt.getTime() - Date.now()) / 1000));
    }

    /**
     * Check if the active token is expired.
     */
    isExpired(headerName: string = 'Authorization'): boolean {
        const seconds = this.getSecondsUntilExpiry(headerName);
        if (seconds === null) return false; // no expiry known → assume valid
        return seconds <= 0;
    }

    /**
     * Check if the active token is expiring soon (within threshold seconds).
     */
    isExpiringSoon(thresholdSeconds: number = 60, headerName: string = 'Authorization'): boolean {
        const seconds = this.getSecondsUntilExpiry(headerName);
        if (seconds === null) return false;
        return seconds <= thresholdSeconds;
    }

    /**
     * Rotate the active token — replace with a new value.
     * Used when a refresh response provides a new access token.
     */
    rotate(headerName: string, newValue: string, source: AuthCaptureSource): TokenState | null {
        const current = this.getActive(headerName);
        if (!current) return null;

        current.superseded = true;
        current.lastRotatedAt = new Date();

        return this.store({
            tokenType: current.tokenType,
            headerName: current.headerName,
            headerValuePrefix: current.headerValuePrefix,
            value: newValue,
            expiresAt: null,    // will be set if JWT
            isRefreshToken: false,
            source,
            capturedAt: new Date(),
        });
    }

    /** Clear all tokens. */
    clear(): void {
        this.tokens.clear();
    }

    // ═══════════════════════════════════════════════════════════
    //  FORMATTING
    // ═══════════════════════════════════════════════════════════

    /**
     * Format the active Authorization header value.
     * Returns "Bearer abc123" or null if no active token.
     */
    formatAuthHeader(headerName: string = 'Authorization'): string | null {
        const token = this.getActive(headerName);
        if (!token) return null;
        return `${token.headerValuePrefix}${token.value}`;
    }

    /**
     * Get all custom headers (non-Authorization active tokens).
     */
    getCustomHeaders(): Record<string, string> {
        const headers: Record<string, string> = {};
        for (const token of this.getAllActive()) {
            if (token.headerName !== 'Authorization' && token.headerName !== '__refresh__') {
                headers[token.headerName] = `${token.headerValuePrefix}${token.value}`;
            }
        }
        return headers;
    }

    /**
     * Redacted summary for logging.
     */
    toRedactedSummary(): string {
        const active = this.getAllActive();
        if (active.length === 0) return 'TokenStore: empty';

        const lines = active.map(t => {
            const expiry = t.expiresAt ? ` exp=${t.expiresAt.toISOString()}` : '';
            const jwt = t.jwtPayload ? ` JWT(sub=${t.jwtPayload.sub || '?'})` : '';
            return `  ${t.headerName}: ${t.headerValuePrefix}${redactSecret(t.value, 'token')} [${t.tokenType}${expiry}${jwt}]`;
        });

        const refresh = this.getRefreshToken();
        if (refresh) {
            lines.push(`  [refresh] ${redactSecret(refresh.value, 'token')} → ${refresh.refreshEndpoint || '?'}`);
        }

        return `TokenStore (${active.length} active):\n${lines.join('\n')}`;
    }

    // ═══════════════════════════════════════════════════════════
    //  STATIC HELPERS
    // ═══════════════════════════════════════════════════════════

    /**
     * Parse a JWT and return the decoded payload (claims).
     * Returns null if the string is not a valid JWT.
     */
    static parseJWT(tokenValue: string): Record<string, any> | null {
        try {
            const parts = tokenValue.split('.');
            if (parts.length !== 3) return null;

            // Base64url decode the payload (part 2)
            const payload = parts[1];
            const padded = payload.replace(/-/g, '+').replace(/_/g, '/');
            const decoded = Buffer.from(padded, 'base64').toString('utf-8');
            const parsed = JSON.parse(decoded);

            // Sanity check: JWTs should have at least one of these claims
            if (parsed && typeof parsed === 'object' && (parsed.exp || parsed.iat || parsed.sub || parsed.iss)) {
                return parsed;
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Detect token type from prefix and value.
     */
    private detectTokenType(prefix: string, value: string): TokenType {
        if (prefix.toLowerCase().startsWith('bearer')) {
            return TokenStore.parseJWT(value) ? 'jwt' : 'bearer';
        }
        if (prefix.toLowerCase().startsWith('basic')) return 'custom';
        if (prefix.toLowerCase().startsWith('token')) return 'opaque';
        if (value.match(/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/)) return 'jwt';
        if (value.length > 20 && value.match(/^[a-zA-Z0-9_-]+$/)) return 'opaque';
        return 'custom';
    }
}
