import type { GitHubAppConfigSource } from './config';

export type GitHubCopilotReasoningEffort = 'low' | 'medium' | 'high' | 'xhigh';

export interface GitHubUser {
    id: number;
    login: string;
    avatarUrl: string;
    name?: string;
}

export interface GitHubCopilotModel {
    id: string;
    name: string;
    isAvailable: boolean;
    policyState?: 'enabled' | 'disabled' | 'unconfigured';
    billingMultiplier?: number;
    supportsVision: boolean;
    supportsReasoningEffort: boolean;
    supportedReasoningEfforts: GitHubCopilotReasoningEffort[];
    defaultReasoningEffort?: GitHubCopilotReasoningEffort;
    maxContextWindowTokens?: number;
    maxPromptTokens?: number;
    maxPromptImages?: number;
    supportedImageMimeTypes: string[];
}

export interface GitHubTokenSet {
    accessToken: string;
    refreshToken?: string;
    tokenType: string;
    scope?: string;
    expiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
}

export type GitHubAuthSessionStatus = 'pending' | 'completed' | 'failed' | 'expired';

export interface GitHubAuthSessionSummary {
    id: string;
    provider: 'github';
    status: GitHubAuthSessionStatus;
    createdAt: string;
    expiresAt: string;
    completedAt?: string | null;
    appRedirectUrl?: string | null;
    authorizationUrl?: string | null;
    errorMessage?: string | null;
    result?: {
        username?: string;
        avatarUrl?: string;
        connected?: boolean;
        modelCount?: number;
        discoveryError?: string | null;
    };
}

export interface GitHubAuthStartResult {
    sessionId: string;
    authorizationUrl: string;
    expiresAt: string;
    callbackUrl: string;
}

export interface GitHubAppConfigSummary {
    source: GitHubAppConfigSource;
    clientId: string;
    callbackUrl: string;
    hasClientSecret: boolean;
    configured: boolean;
    configurationError?: string;
    recommendedCallbackUrl?: string;
    requiresCallbackRegistrationConfirmation?: boolean;
}

export interface GitHubConnectionStatus {
    configured: boolean;
    configurationError?: string;
    connected: boolean;
    providerReady: boolean;
    username?: string;
    name?: string;
    avatarUrl?: string;
    connectedAt?: string;
    tokenExpiresAt?: string | null;
    authType?: string;
    availableModelCount?: number;
    lastDiscoveryError?: string | null;
    lastValidatedAt?: string | null;
    callbackUrl?: string;
    selectedModel?: string | null;
    appConfig?: GitHubAppConfigSummary;
}

export interface GitHubIntegrationMetadata {
    authType?: string;
    externalUserId?: number;
    displayName?: string;
    tokenExpiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
    lastValidatedAt?: string | null;
    lastValidationError?: string | null;
    modelsCache?: {
        models: GitHubCopilotModel[];
        fetchedAt: string;
    };
    lastDiscoveryError?: string | null;
}
