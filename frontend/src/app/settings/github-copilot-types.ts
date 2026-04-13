export const GITHUB_COPILOT_PROVIDER = 'github_copilot' as const;

export interface GitHubAppConfigSummary {
    source: 'ui' | 'environment' | 'none';
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
    availableModelCount?: number;
    lastDiscoveryError?: string | null;
    callbackUrl?: string;
    selectedModel?: string | null;
    appConfig?: GitHubAppConfigSummary;
}

export interface GitHubCopilotModel {
    id: string;
    name: string;
    isAvailable: boolean;
    policyState?: 'enabled' | 'disabled' | 'unconfigured';
    supportsVision: boolean;
    supportsReasoningEffort: boolean;
    supportedReasoningEfforts: Array<'low' | 'medium' | 'high' | 'xhigh'>;
}

export interface GitHubAuthSession {
    id: string;
    status: 'pending' | 'completed' | 'failed' | 'expired';
    authorizationUrl?: string | null;
    errorMessage?: string | null;
    result?: {
        username?: string;
        modelCount?: number;
        discoveryError?: string | null;
    };
}
