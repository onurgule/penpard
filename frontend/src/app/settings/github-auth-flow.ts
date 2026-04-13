import { GITHUB_COPILOT_PROVIDER } from './github-copilot-types';

const LEGACY_GITHUB_MODELS_PROVIDER = 'github_models';

export interface GitHubAuthUiState {
    sessionId: string | null;
    authorizationUrl: string | null;
    busy: boolean;
    message: string | null;
}

export interface GitHubAuthStartResponse {
    sessionId: string;
    authorizationUrl: string;
}

export interface ProviderLikeConfig {
    provider: string;
    is_active: number;
}

export const idleGitHubAuthUiState: GitHubAuthUiState = {
    sessionId: null,
    authorizationUrl: null,
    busy: false,
    message: null,
};

export function normalizeGitHubProviderSelection<T extends ProviderLikeConfig>(configs: T[], githubProviderReady: boolean): T[] {
    if (githubProviderReady) {
        return configs;
    }

    let changed = false;
    const normalized = configs.map((config) => {
        const isGitHubProvider = config.provider === GITHUB_COPILOT_PROVIDER || config.provider === LEGACY_GITHUB_MODELS_PROVIDER;
        if (!isGitHubProvider || config.is_active !== 1) {
            return config;
        }

        changed = true;
        return {
            ...config,
            is_active: 0,
        };
    });

    return changed ? normalized : configs;
}

export function isGitHubProviderSelected<T extends ProviderLikeConfig>(configs: T[], githubProviderReady: boolean): boolean {
    if (!githubProviderReady) {
        return false;
    }

    return configs.some((config) => config.provider === GITHUB_COPILOT_PROVIDER && config.is_active === 1);
}

export async function startGitHubBrowserAuthFlow(input: {
    requestStartAuthorization: () => Promise<GitHubAuthStartResponse>;
    openAuthorizationUrl: (url: string) => Promise<void>;
    cancelPendingAuthorization: (sessionId: string, reason: string) => Promise<void>;
}): Promise<{ state: GitHubAuthUiState; errorMessage?: string }> {
    const started = await input.requestStartAuthorization();

    try {
        await input.openAuthorizationUrl(started.authorizationUrl);
        return {
            state: {
                sessionId: started.sessionId,
                authorizationUrl: started.authorizationUrl,
                busy: true,
                message: 'Approve PenPard in your browser, then return here.',
            },
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to open browser';
        try {
            await input.cancelPendingAuthorization(started.sessionId, `Browser launch failed: ${message}`);
        } catch {
            // The UI should still clear pending state even if session cancellation fails.
        }

        return {
            state: idleGitHubAuthUiState,
            errorMessage: message,
        };
    }
}
