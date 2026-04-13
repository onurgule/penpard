import { logger } from '../utils/logger';
import { GitHubApiClient, isGitHubAuthFailure } from './github/GitHubApiClient';
import { GitHubAppConfigService, githubAppConfigService } from './github/GitHubAppConfigService';
import { GitHubAuthSessionStore } from './github/GitHubAuthSessionStore';
import { GitHubCallbackServer } from './github/GitHubCallbackServer';
import { GitHubCopilotSdkService, type CopilotPromptRequest, type CopilotPromptResponse } from './github/GitHubCopilotSdkService';
import { GitHubIntegrationStore, StoredGitHubIntegration } from './github/GitHubIntegrationStore';
import { GitHubOAuthService } from './github/GitHubOAuthService';
import { GitHubAppConfigSummary, GitHubAuthSessionSummary, GitHubConnectionStatus, GitHubCopilotModel } from './github/types';
import type { ProviderExecutionOptions } from './llm/LlmRuntimeTypes';

const GITHUB_STATUS_VALIDATION_TTL_MS = 5 * 60 * 1000;

function escapeHtml(input: string): string {
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function buildReturnUrl(session: GitHubAuthSessionSummary | null, status: 'success' | 'error'): string | null {
    if (!session?.appRedirectUrl) {
        return null;
    }

    const url = new URL(session.appRedirectUrl);
    url.searchParams.set('githubAuthSession', session.id);
    url.searchParams.set('githubAuthResult', status);
    return url.toString();
}

interface GitHubIntegrationServiceDeps {
    appConfig?: GitHubAppConfigService;
    authSessions?: GitHubAuthSessionStore;
    integrations?: GitHubIntegrationStore;
    githubApi?: GitHubApiClient;
    oauth?: GitHubOAuthService;
    copilot?: GitHubCopilotSdkService;
    callbackServer?: GitHubCallbackServer;
}

export class GitHubIntegrationService {
    private readonly appConfig: GitHubAppConfigService;
    private readonly authSessions: GitHubAuthSessionStore;
    private readonly integrations: GitHubIntegrationStore;
    private readonly githubApi: GitHubApiClient;
    private readonly oauth: GitHubOAuthService;
    private readonly copilot: GitHubCopilotSdkService;
    private readonly callbackServer: GitHubCallbackServer;

    constructor(deps: GitHubIntegrationServiceDeps = {}) {
        this.appConfig = deps.appConfig ?? githubAppConfigService;
        this.authSessions = deps.authSessions ?? new GitHubAuthSessionStore();
        this.integrations = deps.integrations ?? new GitHubIntegrationStore();
        this.githubApi = deps.githubApi ?? new GitHubApiClient();
        this.oauth = deps.oauth ?? new GitHubOAuthService(this.authSessions, this.integrations, this.githubApi, this.appConfig);
        this.copilot = deps.copilot ?? new GitHubCopilotSdkService();
        this.callbackServer = deps.callbackServer ?? new GitHubCallbackServer(
            (query) => this.completeAuthorizationCallback(query),
            () => this.appConfig.getCallbackListenerConfig(),
        );
    }

    async ensureCallbackServerReady(): Promise<void> {
        await this.callbackServer.ensureListening();
    }

    getCallbackListenerError(): string | null {
        return this.callbackServer.getListenerError();
    }

    getCallbackUrl(): string {
        return this.callbackServer.getListenerUrl();
    }

    private getSafeCallbackUrl(): string | undefined {
        try {
            return this.getCallbackUrl();
        } catch {
            return undefined;
        }
    }

    async startAuthorization(userId: number, options: { runtime: 'electron' | 'web'; origin?: string | null }) {
        const configurationError = this.getEffectiveConfigurationError();
        if (configurationError) {
            throw new Error(configurationError);
        }

        await this.ensureCallbackServerReady();
        return this.oauth.startAuthorization(userId, options);
    }

    getAuthorizationSession(userId: number, sessionId: string): GitHubAuthSessionSummary | null {
        return this.authSessions.getById(sessionId, userId);
    }

    private getEffectiveConfigurationError(): string | undefined {
        return this.appConfig.getConfigurationError(this.callbackServer.getListenerError());
    }

    private getAppConfigSummary(): GitHubAppConfigSummary {
        const summary = this.appConfig.getConfigSummary();
        const listenerError = this.callbackServer.getListenerError();
        if (!listenerError) {
            return summary;
        }

        return {
            ...summary,
            configured: false,
            configurationError: listenerError,
            recommendedCallbackUrl: this.callbackServer.getSuggestedCallbackUrl() || undefined,
        };
    }

    private getAvailableModels(models: GitHubCopilotModel[]): GitHubCopilotModel[] {
        return models.filter((model) => model.isAvailable);
    }

    private toConnectionStatus(configurationError: string | undefined, integration: StoredGitHubIntegration | null): GitHubConnectionStatus {
        const appConfig = this.getAppConfigSummary();
        const selectedModel = this.integrations.getProviderConfig()?.model || null;
        const callbackUrl = this.getSafeCallbackUrl() || appConfig.callbackUrl;

        if (!integration?.isActive) {
            return {
                configured: !configurationError,
                configurationError,
                connected: false,
                providerReady: false,
                callbackUrl,
                selectedModel,
                appConfig,
            };
        }

        const models = integration.metadata.modelsCache?.models || [];
        const availableModels = this.getAvailableModels(models);
        const providerReady = availableModels.length > 0;

        return {
            configured: !configurationError,
            configurationError,
            connected: true,
            providerReady,
            username: integration.username,
            name: integration.metadata.displayName,
            avatarUrl: integration.avatarUrl,
            connectedAt: integration.connectedAt || undefined,
            tokenExpiresAt: integration.metadata.tokenExpiresAt || integration.expiresAt || null,
            authType: integration.metadata.authType || 'github_app_user_token',
            availableModelCount: availableModels.length,
            lastDiscoveryError: integration.metadata.lastDiscoveryError || null,
            lastValidatedAt: integration.metadata.lastValidatedAt || null,
            callbackUrl,
            selectedModel,
            appConfig,
        };
    }

    getGitHubAppConfigSummary(): GitHubAppConfigSummary {
        return this.getAppConfigSummary();
    }

    async saveGitHubAppConfig(input: { clientId: string; callbackUrl: string; clientSecret?: string | null; confirmCallbackRegistration?: boolean | null }): Promise<GitHubAppConfigSummary> {
        this.appConfig.saveConfig(input);

        try {
            await this.ensureCallbackServerReady();
        } catch (error) {
            logger.warn('GitHub callback listener failed after saving GitHub App config', {
                error: error instanceof Error ? error.message : String(error),
            });
        }

        return this.getAppConfigSummary();
    }

    private reconcilePersistedStateForUser(userId: number, options?: {
        expireSessions?: boolean;
        deactivateProviderConfigWhenDisconnected?: boolean;
    }): {
        integration: StoredGitHubIntegration | null;
        invalidatedConnection: boolean;
        deactivatedProviderConfig: boolean;
    } {
        if (options?.expireSessions !== false) {
            this.authSessions.expireStaleSessions();
        }

        const integration = this.integrations.getIntegration(userId);
        if (!integration?.isActive) {
            return {
                integration: null,
                invalidatedConnection: false,
                deactivatedProviderConfig: options?.deactivateProviderConfigWhenDisconnected === false
                    ? false
                    : this.integrations.deactivateProviderConfig() > 0,
            };
        }

        const integrityError = this.getStoredConnectionIntegrityError(integration);
        if (!integrityError) {
            return {
                integration,
                invalidatedConnection: false,
                deactivatedProviderConfig: false,
            };
        }

        this.integrations.invalidateConnection(userId, integrityError);
        return {
            integration: null,
            invalidatedConnection: true,
            deactivatedProviderConfig: true,
        };
    }

    reconcilePersistedStateOnStartup(runtimeUserId = 1): {
        expiredSessions: number;
        purgedInactiveSecrets: number;
        invalidatedConnections: number;
        deactivatedProviderConfig: boolean;
        migratedLegacyProviderConfig: boolean;
        removedLegacyProviderConfig: boolean;
    } {
        const expiredSessions = this.authSessions.expireStaleSessions();
        const legacyProviderCleanup = this.integrations.reconcileCopilotProviderConfig();
        const purgedInactiveSecrets = this.integrations.purgeInactiveConnectionSecrets();

        let invalidatedConnections = 0;
        for (const userId of this.integrations.listGitHubUserIds()) {
            const reconciled = this.reconcilePersistedStateForUser(userId, {
                expireSessions: false,
                deactivateProviderConfigWhenDisconnected: false,
            });
            if (reconciled.invalidatedConnection) {
                invalidatedConnections += 1;
            }
        }

        const runtimeReconciliation = this.reconcilePersistedStateForUser(runtimeUserId, {
            expireSessions: false,
            deactivateProviderConfigWhenDisconnected: true,
        });

        return {
            expiredSessions,
            purgedInactiveSecrets,
            invalidatedConnections,
            deactivatedProviderConfig: runtimeReconciliation.deactivatedProviderConfig,
            migratedLegacyProviderConfig: legacyProviderCleanup.migratedLegacyConfig,
            removedLegacyProviderConfig: legacyProviderCleanup.removedLegacyConfig,
        };
    }

    cancelAuthorizationSession(userId: number, sessionId: string, reason = 'GitHub browser launch failed before authorization completed.'): GitHubAuthSessionSummary | null {
        const session = this.authSessions.getById(sessionId, userId);
        if (!session) {
            return null;
        }

        if (session.status !== 'pending') {
            return session;
        }

        const failedSession = this.authSessions.markFailed(sessionId, reason);
        this.reconcilePersistedStateForUser(userId, { expireSessions: false });
        return failedSession;
    }

    async completeAuthorizationCallback(query: {
        code?: string;
        state?: string;
        error?: string;
        errorDescription?: string;
    }): Promise<{ session: GitHubAuthSessionSummary | null; html: string }> {
        if (query.error) {
            const message = query.errorDescription || query.error;
            const pendingSession = query.state ? this.authSessions.getPendingSessionByState(query.state) : null;
            const session = pendingSession
                ? this.authSessions.markFailed(pendingSession.id, message)
                : null;
            if (pendingSession) {
                this.reconcilePersistedStateForUser(pendingSession.userId, { expireSessions: false });
            }
            return {
                session,
                html: this.renderCallbackPage({
                    success: false,
                    title: 'GitHub connection failed',
                    message,
                    returnUrl: buildReturnUrl(session, 'error'),
                }),
            };
        }

        if (!query.code || !query.state) {
            return {
                session: null,
                html: this.renderCallbackPage({
                    success: false,
                    title: 'GitHub callback was incomplete',
                    message: 'The GitHub callback did not include the authorization code and state required to finish the login flow.',
                    returnUrl: null,
                }),
            };
        }

        try {
            const exchanged = await this.oauth.exchangeAuthorizationCode({
                code: query.code,
                state: query.state,
            });

            let models: GitHubCopilotModel[] = [];
            let discoveryError: string | null = null;

            try {
                models = await this.copilot.listModels(exchanged.tokenSet.accessToken);
                if (this.getAvailableModels(models).length === 0) {
                    discoveryError = 'GitHub Copilot SDK did not return any selectable models for this account.';
                }
            } catch (error) {
                discoveryError = error instanceof Error ? error.message : 'GitHub Copilot model discovery failed after sign-in.';
                logger.warn('GitHub Copilot model discovery failed immediately after sign-in', { error: discoveryError });
            }

            this.integrations.saveConnection(exchanged.userId, {
                user: {
                    id: exchanged.metadata.externalUserId || 0,
                    login: exchanged.result.username || '',
                    avatarUrl: exchanged.result.avatarUrl || '',
                    name: exchanged.metadata.displayName,
                },
                tokenSet: exchanged.tokenSet,
                metadata: {
                    ...exchanged.metadata,
                    modelsCache: models.length ? { models, fetchedAt: new Date().toISOString() } : undefined,
                    lastDiscoveryError: discoveryError,
                },
            });

            const session = this.authSessions.markCompleted(exchanged.sessionId, {
                ...exchanged.result,
                modelCount: this.getAvailableModels(models).length,
                discoveryError,
            });

            return {
                session,
                html: this.renderCallbackPage({
                    success: true,
                    title: 'GitHub connected',
                    message: discoveryError
                        ? `GitHub sign-in completed for @${exchanged.result.username}, but Copilot model discovery failed: ${discoveryError}`
                        : `GitHub sign-in completed for @${exchanged.result.username}.`,
                    returnUrl: buildReturnUrl(session, discoveryError ? 'error' : 'success'),
                }),
            };
        } catch (error) {
            const message = error instanceof Error ? error.message : 'GitHub authorization could not be completed.';
            const pendingSession = query.state ? this.authSessions.getPendingSessionByState(query.state) : null;
            const session = pendingSession
                ? this.authSessions.markFailed(pendingSession.id, message)
                : null;
            if (pendingSession) {
                this.reconcilePersistedStateForUser(pendingSession.userId, { expireSessions: false });
            }
            return {
                session,
                html: this.renderCallbackPage({
                    success: false,
                    title: 'GitHub connection failed',
                    message,
                    returnUrl: buildReturnUrl(session, 'error'),
                }),
            };
        }
    }

    private getStoredConnectionIntegrityError(integration: StoredGitHubIntegration): string | null {
        if (!integration.isActive) {
            return null;
        }

        if (!integration.username?.trim() && !integration.metadata.externalUserId) {
            return 'Stored GitHub identity metadata is incomplete. Reconnect GitHub in Settings.';
        }

        if (!integration.metadata.authType) {
            return 'Stored GitHub authentication metadata is incomplete. Reconnect GitHub in Settings.';
        }

        if (!integration.accessToken?.trim()) {
            return 'Stored GitHub access token is missing. Reconnect GitHub in Settings.';
        }

        const accessTokenExpiresAt = integration.expiresAt || integration.metadata.tokenExpiresAt || null;
        if (!accessTokenExpiresAt) {
            return null;
        }

        if (new Date(accessTokenExpiresAt).getTime() > Date.now()) {
            return null;
        }

        if (!integration.refreshToken?.trim()) {
            return 'GitHub access token expired and no refresh token is available. Reconnect GitHub in Settings.';
        }

        const refreshTokenExpiresAt = integration.metadata.refreshTokenExpiresAt || null;
        if (refreshTokenExpiresAt && new Date(refreshTokenExpiresAt).getTime() <= Date.now()) {
            return 'GitHub refresh token expired. Reconnect GitHub in Settings.';
        }

        return null;
    }

    private getEffectiveIntegration(userId: number): StoredGitHubIntegration | null {
        return this.reconcilePersistedStateForUser(userId).integration;
    }

    private shouldRefreshConnectionValidation(integration: StoredGitHubIntegration): boolean {
        const lastValidatedAt = integration.metadata.lastValidatedAt;
        if (!lastValidatedAt) {
            return true;
        }

        const lastValidatedAtTime = new Date(lastValidatedAt).getTime();
        if (Number.isNaN(lastValidatedAtTime)) {
            return true;
        }

        return lastValidatedAtTime <= (Date.now() - GITHUB_STATUS_VALIDATION_TTL_MS);
    }

    getConnectionStatus(userId: number): GitHubConnectionStatus {
        const configurationError = this.getEffectiveConfigurationError();
        const integration = this.getEffectiveIntegration(userId);
        return this.toConnectionStatus(configurationError, integration);
    }

    async getResolvedConnectionStatus(userId: number): Promise<GitHubConnectionStatus> {
        const initialStatus = this.getConnectionStatus(userId);
        if (!initialStatus.connected) {
            return initialStatus;
        }

        const integration = this.getEffectiveIntegration(userId);
        if (!integration || !this.shouldRefreshConnectionValidation(integration)) {
            return this.getConnectionStatus(userId);
        }

        await this.oauth.validateCurrentToken(userId);
        return this.getConnectionStatus(userId);
    }

    async listModels(userId: number, refresh = false): Promise<GitHubCopilotModel[]> {
        const integration = this.getEffectiveIntegration(userId);
        if (!integration) {
            throw new Error('GitHub is not connected.');
        }

        if (!refresh && integration.metadata.modelsCache?.models?.length) {
            return integration.metadata.modelsCache.models;
        }

        return this.withAccessToken(userId, async (token) => {
            const models = await this.copilot.listModels(token);
            const availableModels = this.getAvailableModels(models);
            const discoveryError = availableModels.length === 0
                ? 'GitHub Copilot SDK did not return any selectable models for this account.'
                : null;
            this.integrations.cacheModels(userId, models, discoveryError);
            return models;
        }, async (message) => {
            this.integrations.cacheModels(userId, integration.metadata.modelsCache?.models || [], message);
        });
    }

    getCachedModel(userId: number, modelId: string): GitHubCopilotModel | null {
        const integration = this.getEffectiveIntegration(userId);
        return integration?.metadata.modelsCache?.models.find((model) => model.id === modelId) || null;
    }

    isModelSelectable(userId: number, modelId: string): { selectable: boolean; error?: string } {
        const model = this.getCachedModel(userId, modelId);
        if (!model) {
            return {
                selectable: false,
                error: 'The selected GitHub Copilot model is not in the discovered model list. Refresh models in Settings and try again.',
            };
        }

        if (!model.isAvailable) {
            return {
                selectable: false,
                error: `The selected GitHub Copilot model (${model.name}) is not enabled for this account.`,
            };
        }

        return { selectable: true };
    }

    async generateCopilotResponse(
        userId: number,
        modelId: string,
        request: CopilotPromptRequest,
        executionOptions: ProviderExecutionOptions = {},
    ): Promise<CopilotPromptResponse> {
        let selection = this.isModelSelectable(userId, modelId);
        if (!selection.selectable) {
            await this.listModels(userId, true);
            selection = this.isModelSelectable(userId, modelId);
        }

        if (!selection.selectable) {
            throw new Error(selection.error);
        }

        return this.withAccessToken(userId, async (token) => this.copilot.generate(token, modelId, request, executionOptions));
    }

    async getRuntimeAccessToken(userId: number): Promise<string> {
        return this.oauth.getUsableAccessToken(userId);
    }

    async validateToken(userId: number): Promise<boolean> {
        return this.oauth.validateCurrentToken(userId);
    }

    disconnect(userId: number): void {
        this.integrations.disconnect(userId);
    }

    async withAccessToken<T>(
        userId: number,
        action: (accessToken: string) => Promise<T>,
        onFailure?: (message: string) => Promise<void> | void,
    ): Promise<T> {
        const runAction = async (accessToken: string) => action(accessToken);

        try {
            const accessToken = await this.oauth.getUsableAccessToken(userId);
            return await runAction(accessToken);
        } catch (error) {
            if (isGitHubAuthFailure(error)) {
                try {
                    const refreshed = await this.oauth.refreshAccessToken(userId);
                    return await runAction(refreshed);
                } catch (refreshError) {
                    const message = refreshError instanceof Error ? refreshError.message : 'GitHub authentication failed.';
                    if (onFailure) {
                        await onFailure(message);
                    }
                    this.integrations.invalidateConnection(userId, message);
                    throw refreshError;
                }
            }

            const message = error instanceof Error ? error.message : 'GitHub request failed.';
            if (onFailure) {
                await onFailure(message);
            }
            throw error;
        }
    }

    private renderCallbackPage(input: {
        success: boolean;
        title: string;
        message: string;
        returnUrl: string | null;
    }): string {
        const escapedTitle = escapeHtml(input.title);
        const escapedMessage = escapeHtml(input.message);
        const accent = input.success ? '#22c55e' : '#f97316';
        const returnUrl = input.returnUrl;
        const subtitle = input.success
            ? 'You can close this browser tab if PenPard is already open.'
            : 'Return to PenPard to review the error and try again.';

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapedTitle}</title>
  <style>
    body { font-family: Arial, sans-serif; background: #020617; color: #e2e8f0; margin: 0; min-height: 100vh; display: grid; place-items: center; }
    .card { width: min(480px, calc(100vw - 32px)); background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 16px; padding: 28px; box-shadow: 0 24px 80px rgba(2, 6, 23, 0.45); }
    .badge { display: inline-block; padding: 6px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; background: rgba(15, 23, 42, 0.8); border: 1px solid ${accent}; color: ${accent}; }
    h1 { margin: 18px 0 12px; font-size: 24px; }
    p { margin: 0 0 14px; line-height: 1.6; color: #cbd5e1; }
    a.button { display: inline-flex; align-items: center; justify-content: center; padding: 12px 18px; border-radius: 12px; background: ${accent}; color: #020617; text-decoration: none; font-weight: 700; margin-top: 16px; }
    small { display: block; margin-top: 14px; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">${input.success ? 'Connected' : 'Action required'}</span>
    <h1>${escapedTitle}</h1>
    <p>${escapedMessage}</p>
    <p>${escapeHtml(subtitle)}</p>
    ${returnUrl ? `<a class="button" href="${escapeHtml(returnUrl)}">${input.success ? 'Return to PenPard' : 'Open PenPard'}</a>` : ''}
    <small>If PenPard does not open automatically, switch back to the app and refresh the GitHub Copilot section in Settings.</small>
  </div>
  ${returnUrl ? `<script>setTimeout(function(){ window.location.href = ${JSON.stringify(returnUrl)}; }, 400);</script>` : ''}
</body>
</html>`;
    }
}

export const githubIntegration = new GitHubIntegrationService();
