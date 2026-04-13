import crypto from 'crypto';
import axios from 'axios';
import { GitHubApiClient, isGitHubAuthFailure } from './GitHubApiClient';
import { GitHubAppConfigService, githubAppConfigService } from './GitHubAppConfigService';
import { GitHubAuthSessionStore } from './GitHubAuthSessionStore';
import { GITHUB_AUTH_SESSION_TTL_MS, GITHUB_AUTHORIZE_URL, GITHUB_TOKEN_URL } from './config';
import { GitHubIntegrationStore } from './GitHubIntegrationStore';
import {
    GitHubAuthStartResult,
    GitHubAuthSessionSummary,
    GitHubIntegrationMetadata,
    GitHubTokenSet,
} from './types';

function base64UrlEncode(buffer: Buffer): string {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateCodeVerifier(): string {
    return base64UrlEncode(crypto.randomBytes(48));
}

function generateCodeChallenge(codeVerifier: string): string {
    return base64UrlEncode(crypto.createHash('sha256').update(codeVerifier).digest());
}

function addSeconds(seconds?: number): string | null {
    if (!seconds) return null;
    return new Date(Date.now() + (seconds * 1000)).toISOString();
}

export class GitHubOAuthService {
    constructor(
        private readonly authSessions: GitHubAuthSessionStore,
        private readonly integrations: GitHubIntegrationStore,
        private readonly githubApi: GitHubApiClient,
        private readonly appConfig: GitHubAppConfigService = githubAppConfigService,
    ) {}

    startAuthorization(userId: number, options: { runtime: 'electron' | 'web'; origin?: string | null }): GitHubAuthStartResult {
        const config = this.appConfig.getResolvedConfig();
        const state = crypto.randomUUID();
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = generateCodeChallenge(codeVerifier);
        const expiresAt = new Date(Date.now() + GITHUB_AUTH_SESSION_TTL_MS).toISOString();

        const query = new URLSearchParams({
            client_id: config.clientId,
            redirect_uri: config.callbackUrl,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            prompt: 'select_account',
        });

        const authorizationUrl = `${GITHUB_AUTHORIZE_URL}?${query.toString()}`;
        const session = this.authSessions.createPendingSession({
            userId,
            state,
            codeVerifier,
            redirectUri: config.callbackUrl,
            appRedirectUrl: 'about:blank',
            authorizationUrl,
            expiresAt,
        });

        const appRedirectUrl = options.runtime === 'electron'
            ? this.authSessions.buildElectronReturnUrl(session.id, 'success')
            : this.authSessions.buildWebReturnUrl(options.origin || this.authSessions.getDefaultWebOrigin(), session.id, 'success');
        this.authSessions.updateAppRedirectUrl(session.id, appRedirectUrl);

        return {
            sessionId: session.id,
            authorizationUrl,
            expiresAt,
            callbackUrl: config.callbackUrl,
        };
    }

    async exchangeAuthorizationCode(params: {
        code: string;
        state: string;
    }): Promise<{
        sessionId: string;
        tokenSet: GitHubTokenSet;
        metadata: GitHubIntegrationMetadata;
        result: NonNullable<GitHubAuthSessionSummary['result']>;
        userId: number;
    }> {
        const config = this.appConfig.getResolvedConfig();
        const session = this.authSessions.getPendingSessionByState(params.state);

        if (!session) {
            throw new Error('GitHub callback state is invalid or expired.');
        }

        if (session.status !== 'pending') {
            throw new Error('This GitHub authorization session is no longer pending.');
        }

        if (new Date(session.expiresAt).getTime() <= Date.now()) {
            this.authSessions.markFailed(session.id, 'GitHub authorization session expired before the callback completed.');
            throw new Error('GitHub authorization session expired before the callback completed.');
        }

        const body = new URLSearchParams({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code: params.code,
            redirect_uri: session.redirectUri,
            code_verifier: session.codeVerifier,
        });

        const tokenResponse = await axios.post(GITHUB_TOKEN_URL, body.toString(), {
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            timeout: 10000,
            validateStatus: (status) => status < 500,
        });

        if (tokenResponse.status !== 200 || !tokenResponse.data?.access_token) {
            const errorMessage = tokenResponse.data?.error_description
                || tokenResponse.data?.error
                || `GitHub token exchange failed with HTTP ${tokenResponse.status}.`;
            this.authSessions.markFailed(session.id, errorMessage);
            throw new Error(errorMessage);
        }

        const tokenSet: GitHubTokenSet = {
            accessToken: tokenResponse.data.access_token,
            refreshToken: tokenResponse.data.refresh_token || undefined,
            tokenType: tokenResponse.data.token_type || 'bearer',
            scope: tokenResponse.data.scope || '',
            expiresAt: addSeconds(tokenResponse.data.expires_in),
            refreshTokenExpiresAt: addSeconds(tokenResponse.data.refresh_token_expires_in),
        };

        const user = await this.githubApi.fetchCurrentUser(tokenSet.accessToken);
        const result = {
            username: user.login,
            avatarUrl: user.avatarUrl,
            connected: true,
        };

        return {
            sessionId: session.id,
            tokenSet,
            metadata: {
                authType: 'github_app_user_token',
                externalUserId: user.id,
                displayName: user.name || user.login,
                tokenExpiresAt: tokenSet.expiresAt || null,
                refreshTokenExpiresAt: tokenSet.refreshTokenExpiresAt || null,
                lastValidatedAt: new Date().toISOString(),
                lastValidationError: null,
                lastDiscoveryError: null,
            },
            result,
            userId: session.userId,
        };
    }

    async refreshAccessToken(userId: number): Promise<string> {
        const config = this.appConfig.getResolvedConfig();
        const integration = this.integrations.getIntegration(userId);
        if (!integration?.isActive || !integration.refreshToken) {
            throw new Error('GitHub refresh token is not available. Reconnect GitHub in Settings.');
        }

        const body = new URLSearchParams({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            grant_type: 'refresh_token',
            refresh_token: integration.refreshToken,
        });

        const response = await axios.post(GITHUB_TOKEN_URL, body.toString(), {
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            timeout: 10000,
            validateStatus: (status) => status < 500,
        });

        if (response.status !== 200 || !response.data?.access_token) {
            const message = response.data?.error_description || response.data?.error || `GitHub token refresh failed with HTTP ${response.status}.`;
            this.integrations.invalidateConnection(userId, message);
            throw new Error(message);
        }

        const refreshed: GitHubTokenSet = {
            accessToken: response.data.access_token,
            refreshToken: response.data.refresh_token || integration.refreshToken,
            tokenType: response.data.token_type || 'bearer',
            scope: response.data.scope || integration.scope || '',
            expiresAt: addSeconds(response.data.expires_in),
            refreshTokenExpiresAt: addSeconds(response.data.refresh_token_expires_in) || integration.metadata.refreshTokenExpiresAt || null,
        };

        this.integrations.updateTokens(userId, refreshed, {
            tokenExpiresAt: refreshed.expiresAt || null,
            refreshTokenExpiresAt: refreshed.refreshTokenExpiresAt || null,
        });

        return refreshed.accessToken;
    }

    async getUsableAccessToken(userId: number): Promise<string> {
        const integration = this.integrations.getIntegration(userId);
        if (!integration?.isActive || !integration.accessToken) {
            throw new Error('GitHub is not connected. Connect GitHub in Settings first.');
        }

        if (!integration.expiresAt) {
            return integration.accessToken;
        }

        const expiresSoon = new Date(integration.expiresAt).getTime() <= (Date.now() + (60 * 1000));
        if (expiresSoon) {
            return this.refreshAccessToken(userId);
        }

        return integration.accessToken;
    }

    async validateCurrentToken(userId: number): Promise<boolean> {
        try {
            const token = await this.getUsableAccessToken(userId);
            await this.githubApi.fetchCurrentUser(token);
            this.integrations.markValidation(userId, null);
            return true;
        } catch (error) {
            const message = error instanceof Error ? error.message : 'GitHub token validation failed.';
            this.integrations.markValidation(userId, message);
            if (isGitHubAuthFailure(error)) {
                this.integrations.invalidateConnection(userId, message);
            }
            return false;
        }
    }
}
