import { URL } from 'url';
import { GitHubAppConfigStore, githubAppConfigStore } from './GitHubAppConfigStore';
import {
    buildDefaultGitHubCallbackUrl,
    getGitHubEnvironmentConfigSnapshot,
    hasConfiguredGitHubValue,
    validateGitHubAppConfig,
    validateGitHubCallbackUrl,
    type GitHubAppConfig,
    type GitHubCallbackListenerConfig,
    type GitHubRawAppConfig,
} from './config';
import type { GitHubAppConfigSummary } from './types';

function buildCallbackRegistrationError(callbackUrl: string): string {
    return `GitHub Apps require redirect_uri to exactly match one of the callback URLs registered on the app. Add ${callbackUrl} to your GitHub App callback URLs, then confirm the update in PenPard before connecting GitHub.`;
}

function toListenerConfig(callbackUrl: string): GitHubCallbackListenerConfig {
    const parsed = new URL(callbackUrl);
    return {
        host: parsed.hostname,
        port: Number(parsed.port || '80'),
        path: parsed.pathname,
        url: parsed.toString(),
    };
}

function hasAnyConfiguredValue(config: GitHubRawAppConfig): boolean {
    return [config.clientId, config.clientSecret, config.callbackUrl].some((value) => hasConfiguredGitHubValue(value));
}

export class GitHubAppConfigService {
    constructor(
        private readonly store: GitHubAppConfigStore = githubAppConfigStore,
    ) {}

    private getStoredRawConfig(): (GitHubRawAppConfig & { callbackRegistrationConfirmed: boolean }) | null {
        const stored = this.store.getStoredConfig();
        if (!stored) {
            return null;
        }

        return {
            clientId: stored.clientId,
            clientSecret: stored.clientSecret || '',
            callbackUrl: stored.callbackUrl || buildDefaultGitHubCallbackUrl(),
            callbackRegistrationConfirmed: stored.callbackRegistrationConfirmed,
        };
    }

    private getEnvironmentRawConfig(): GitHubRawAppConfig {
        const snapshot = getGitHubEnvironmentConfigSnapshot();
        return {
            clientId: snapshot.clientId,
            clientSecret: snapshot.clientSecret,
            callbackUrl: snapshot.callbackUrl || buildDefaultGitHubCallbackUrl(),
        };
    }

    private buildSummary(
        source: 'ui' | 'environment' | 'none',
        config: GitHubRawAppConfig,
        hasClientSecret: boolean,
        callbackRegistrationConfirmed = true,
    ): GitHubAppConfigSummary {
        try {
            validateGitHubAppConfig(config);

            if (!callbackRegistrationConfirmed) {
                return {
                    source,
                    clientId: config.clientId,
                    callbackUrl: config.callbackUrl,
                    hasClientSecret,
                    configured: false,
                    configurationError: buildCallbackRegistrationError(config.callbackUrl),
                    requiresCallbackRegistrationConfirmation: true,
                };
            }

            return {
                source,
                clientId: config.clientId,
                callbackUrl: config.callbackUrl,
                hasClientSecret,
                configured: true,
                requiresCallbackRegistrationConfirmation: false,
            };
        } catch (error) {
            return {
                source,
                clientId: config.clientId,
                callbackUrl: config.callbackUrl,
                hasClientSecret,
                configured: false,
                configurationError: error instanceof Error ? error.message : 'GitHub browser auth is not configured.',
                requiresCallbackRegistrationConfirmation: false,
            };
        }
    }

    getResolvedConfig(): GitHubAppConfig {
        const storedConfig = this.getStoredRawConfig();
        if (storedConfig) {
            return validateGitHubAppConfig(storedConfig);
        }

        return validateGitHubAppConfig(this.getEnvironmentRawConfig());
    }

    getConfigurationError(...extraErrors: Array<string | null | undefined>): string | undefined {
        const summary = this.getConfigSummary();
        if (!summary.configured) {
            return summary.configurationError || 'GitHub browser auth is not configured.';
        }

        const extraError = extraErrors.find((value) => typeof value === 'string' && value.trim());
        return extraError || undefined;
    }

    getCallbackListenerConfig(): GitHubCallbackListenerConfig {
        const storedConfig = this.getStoredRawConfig();
        if (storedConfig) {
            return toListenerConfig(validateGitHubCallbackUrl(storedConfig.callbackUrl || buildDefaultGitHubCallbackUrl()));
        }

        const environmentConfig = this.getEnvironmentRawConfig();
        return toListenerConfig(validateGitHubCallbackUrl(environmentConfig.callbackUrl || buildDefaultGitHubCallbackUrl()));
    }

    getConfigSummary(): GitHubAppConfigSummary {
        const storedConfig = this.getStoredRawConfig();
        if (storedConfig) {
            return this.buildSummary('ui', storedConfig, hasConfiguredGitHubValue(storedConfig.clientSecret), storedConfig.callbackRegistrationConfirmed);
        }

        const environmentConfig = this.getEnvironmentRawConfig();
        if (hasAnyConfiguredValue(environmentConfig)) {
            return this.buildSummary('environment', environmentConfig, hasConfiguredGitHubValue(environmentConfig.clientSecret));
        }

        return this.buildSummary('none', environmentConfig, false);
    }

    saveConfig(input: { clientId: string; callbackUrl: string; clientSecret?: string | null; confirmCallbackRegistration?: boolean | null }): GitHubAppConfigSummary {
        const existing = this.getStoredRawConfig();
        const normalizedClientSecret = hasConfiguredGitHubValue(input.clientSecret)
            ? input.clientSecret || ''
            : existing?.clientSecret || '';
        const validated = validateGitHubAppConfig({
            clientId: input.clientId,
            clientSecret: normalizedClientSecret,
            callbackUrl: input.callbackUrl || buildDefaultGitHubCallbackUrl(),
        });

        const existingEffectiveCallbackUrl = existing?.callbackUrl
            || this.getEnvironmentRawConfig().callbackUrl
            || buildDefaultGitHubCallbackUrl();
        const callbackChanged = validated.callbackUrl !== validateGitHubCallbackUrl(existingEffectiveCallbackUrl || buildDefaultGitHubCallbackUrl());
        const callbackRegistrationConfirmed = input.confirmCallbackRegistration === true
            ? true
            : callbackChanged
                ? false
                : existing?.callbackRegistrationConfirmed ?? true;

        this.store.saveConfig({
            clientId: validated.clientId,
            callbackUrl: validated.callbackUrl,
            clientSecret: hasConfiguredGitHubValue(input.clientSecret) ? validated.clientSecret : null,
            callbackRegistrationConfirmed,
        });

        return this.getConfigSummary();
    }
}

export const githubAppConfigService = new GitHubAppConfigService();
