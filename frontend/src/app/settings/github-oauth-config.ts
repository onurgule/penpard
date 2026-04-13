import type { GitHubAppConfigSummary } from './github-copilot-types';

export const DEFAULT_GITHUB_CALLBACK_URL = 'http://127.0.0.1:5050/api/integrations/github/callback';

export interface GitHubAppConfigDraft {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
}

function normalize(value: string | null | undefined): string {
    return (value || '').trim();
}

export function createGitHubAppConfigDraft(summary?: GitHubAppConfigSummary | null): GitHubAppConfigDraft {
    return {
        clientId: normalize(summary?.clientId),
        clientSecret: '',
        callbackUrl: normalize(summary?.callbackUrl) || DEFAULT_GITHUB_CALLBACK_URL,
    };
}

export function isGitHubAppConfigDirty(summary: GitHubAppConfigSummary | null | undefined, draft: GitHubAppConfigDraft): boolean {
    return normalize(draft.clientId) !== normalize(summary?.clientId)
        || normalize(draft.callbackUrl) !== normalize(summary?.callbackUrl || DEFAULT_GITHUB_CALLBACK_URL)
        || normalize(draft.clientSecret) !== '';
}

export function requiresGitHubAppClientSecret(summary: GitHubAppConfigSummary | null | undefined, draft: GitHubAppConfigDraft): boolean {
    return !(summary?.source === 'ui' && summary.hasClientSecret) && normalize(draft.clientSecret) === '';
}

export function toGitHubAppConfigPayload(draft: GitHubAppConfigDraft): GitHubAppConfigDraft {
    return {
        clientId: normalize(draft.clientId),
        clientSecret: normalize(draft.clientSecret),
        callbackUrl: normalize(draft.callbackUrl) || DEFAULT_GITHUB_CALLBACK_URL,
    };
}
