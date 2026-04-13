import { URL } from 'url';

export const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
export const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
export const GITHUB_USER_URL = 'https://api.github.com/user';
export const GITHUB_PROVIDER = 'github';
export const GITHUB_COPILOT_PROVIDER = 'github_copilot';
export const LEGACY_GITHUB_MODELS_PROVIDER = 'github_models';
export const GITHUB_DEFAULT_CALLBACK_HOST = '127.0.0.1';
export const GITHUB_DEFAULT_CALLBACK_PORT = 5050;
export const GITHUB_CALLBACK_PATH = '/api/integrations/github/callback';
export const GITHUB_AUTH_SESSION_TTL_MS = 10 * 60 * 1000;

export type GitHubAppConfigSource = 'ui' | 'environment' | 'none';

const PLACEHOLDER_VALUES = new Set([
    '',
    'CHANGE_ME',
    'PLACEHOLDER',
    'PLACEHOLDER_CLIENT_ID',
    'PLACEHOLDER_CLIENT_SECRET',
    'YOUR_GITHUB_APP_CLIENT_ID',
    'YOUR_GITHUB_APP_CLIENT_SECRET',
]);

export class GitHubConfigurationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'GitHubConfigurationError';
    }
}

export interface GitHubCallbackListenerConfig {
    host: string;
    port: number;
    path: string;
    url: string;
}

export interface GitHubAppConfig {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
}

export interface GitHubRawAppConfig {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
}

export function normalizeGitHubConfigValue(value: string | null | undefined): string {
    return (value || '').trim();
}

export function hasConfiguredGitHubValue(value: string | null | undefined): boolean {
    const normalized = normalizeGitHubConfigValue(value);
    return normalized !== '' && !PLACEHOLDER_VALUES.has(normalized);
}

export function buildDefaultGitHubCallbackUrl(): string {
    return `http://${GITHUB_DEFAULT_CALLBACK_HOST}:${GITHUB_DEFAULT_CALLBACK_PORT}${GITHUB_CALLBACK_PATH}`;
}

export function getGitHubEnvironmentConfigSnapshot(): GitHubRawAppConfig {
    return {
        clientId: normalizeGitHubConfigValue(process.env.GITHUB_APP_CLIENT_ID || process.env.GITHUB_OAUTH_CLIENT_ID),
        clientSecret: normalizeGitHubConfigValue(process.env.GITHUB_APP_CLIENT_SECRET || process.env.GITHUB_OAUTH_CLIENT_SECRET),
        callbackUrl: normalizeGitHubConfigValue(process.env.GITHUB_APP_CALLBACK_URL || process.env.GITHUB_OAUTH_CALLBACK_URL),
    };
}

export function validateGitHubCallbackUrl(rawCallbackUrl: string): string {
    const normalizedCallbackUrl = normalizeGitHubConfigValue(rawCallbackUrl);

    if (!hasConfiguredGitHubValue(normalizedCallbackUrl)) {
        throw new GitHubConfigurationError(
            `GitHub browser auth is not configured. Save the GitHub App callback URL in Settings, or set GITHUB_APP_CALLBACK_URL to the exact GitHub App callback URL, for example ${buildDefaultGitHubCallbackUrl()}.`
        );
    }

    let parsed: URL;
    try {
        parsed = new URL(normalizedCallbackUrl);
    } catch {
        throw new GitHubConfigurationError('GITHUB_APP_CALLBACK_URL must be a valid URL.');
    }

    if (parsed.protocol !== 'http:') {
        throw new GitHubConfigurationError('GITHUB_APP_CALLBACK_URL must use http:// loopback, not https:// or a custom scheme.');
    }

    if (parsed.hostname !== GITHUB_DEFAULT_CALLBACK_HOST) {
        throw new GitHubConfigurationError(
            `GITHUB_APP_CALLBACK_URL must use ${GITHUB_DEFAULT_CALLBACK_HOST} as the loopback host. GitHub recommends not using localhost for native-app callbacks.`
        );
    }

    if (parsed.pathname !== GITHUB_CALLBACK_PATH) {
        throw new GitHubConfigurationError(
            `GITHUB_APP_CALLBACK_URL must use the ${GITHUB_CALLBACK_PATH} path so PenPard can finish the OAuth callback.`
        );
    }

    if (!parsed.port) {
        throw new GitHubConfigurationError('GITHUB_APP_CALLBACK_URL must include an explicit loopback port.');
    }

    return parsed.toString();
}

export function validateGitHubAppConfig(input: GitHubRawAppConfig): GitHubAppConfig {
    const clientId = normalizeGitHubConfigValue(input.clientId);
    const clientSecret = normalizeGitHubConfigValue(input.clientSecret);

    if (!hasConfiguredGitHubValue(clientId)) {
        throw new GitHubConfigurationError(
            'GitHub browser auth is not configured. Save the GitHub App client ID in Settings, or set GITHUB_APP_CLIENT_ID to the client ID from your GitHub App registration.'
        );
    }

    if (!hasConfiguredGitHubValue(clientSecret)) {
        throw new GitHubConfigurationError(
            'GitHub browser auth is not configured. Save the GitHub App client secret in Settings, or set GITHUB_APP_CLIENT_SECRET to the client secret from your GitHub App registration.'
        );
    }

    return {
        clientId,
        clientSecret,
        callbackUrl: validateGitHubCallbackUrl(input.callbackUrl || buildDefaultGitHubCallbackUrl()),
    };
}

export function getGitHubCallbackListenerConfig(): GitHubCallbackListenerConfig {
    const callbackUrl = validateGitHubCallbackUrl(
        getGitHubEnvironmentConfigSnapshot().callbackUrl || buildDefaultGitHubCallbackUrl(),
    );
    const parsed = new URL(callbackUrl);

    return {
        host: parsed.hostname,
        port: Number(parsed.port || '80'),
        path: parsed.pathname,
        url: parsed.toString(),
    };
}

export function getGitHubEnvironmentAppConfig(): GitHubAppConfig {
    return validateGitHubAppConfig({
        ...getGitHubEnvironmentConfigSnapshot(),
        callbackUrl: getGitHubEnvironmentConfigSnapshot().callbackUrl || buildDefaultGitHubCallbackUrl(),
    });
}

export function getGitHubAppConfig(): GitHubAppConfig {
    return getGitHubEnvironmentAppConfig();
}

export function getGitHubConfigurationError(...extraErrors: Array<string | null | undefined>): string | undefined {
    try {
        getGitHubEnvironmentAppConfig();
        const extraError = extraErrors.find((value) => typeof value === 'string' && value.trim());
        return extraError || undefined;
    } catch (error) {
        return error instanceof Error ? error.message : 'GitHub browser auth is not configured.';
    }
}
