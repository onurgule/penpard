import { db } from '../../db/init';
import { logger } from '../../utils/logger';
import { decryptSecret, encryptSecret } from './crypto';
import {
    GITHUB_COPILOT_PROVIDER,
    GITHUB_PROVIDER,
    LEGACY_GITHUB_MODELS_PROVIDER,
} from './config';
import { GitHubIntegrationMetadata, GitHubCopilotModel, GitHubTokenSet, GitHubUser } from './types';

interface UserIntegrationRow {
    access_token_encrypted: string | null;
    token_iv: string | null;
    refresh_token_encrypted: string | null;
    refresh_token_iv: string | null;
    token_scope: string | null;
    external_username: string | null;
    external_avatar_url: string | null;
    connected_at: string | null;
    expires_at: string | null;
    is_active: number;
    metadata_json: string | null;
}

export interface StoredGitHubIntegration {
    userId: number;
    isActive: boolean;
    username?: string;
    avatarUrl?: string;
    connectedAt?: string | null;
    scope?: string | null;
    expiresAt?: string | null;
    metadata: GitHubIntegrationMetadata;
    accessToken?: string | null;
    refreshToken?: string | null;
}

function parseMetadata(raw: string | null): GitHubIntegrationMetadata {
    if (!raw) return {};
    try {
        return JSON.parse(raw) as GitHubIntegrationMetadata;
    } catch {
        return {};
    }
}

function decryptOptional(encrypted?: string | null, iv?: string | null): string | null {
    if (!encrypted || !iv) return null;
    try {
        return decryptSecret(encrypted, iv);
    } catch (error) {
        logger.error('Failed to decrypt GitHub integration secret', { error });
        return null;
    }
}

function getProviderConfigRow(provider: string): { model: string | null; settings_json: string | null; is_active: number } | undefined {
    return db.prepare('SELECT model, settings_json, is_active FROM llm_config WHERE provider = ?').get(provider) as
        | { model: string | null; settings_json: string | null; is_active: number }
        | undefined;
}

function currentCopilotProviderModel(): string | null {
    return getProviderConfigRow(GITHUB_COPILOT_PROVIDER)?.model || null;
}

export class GitHubIntegrationStore {
    private getRow(userId: number): UserIntegrationRow | undefined {
        return db.prepare(`
            SELECT
                access_token_encrypted,
                token_iv,
                refresh_token_encrypted,
                refresh_token_iv,
                token_scope,
                external_username,
                external_avatar_url,
                connected_at,
                expires_at,
                is_active,
                metadata_json
            FROM user_integrations
            WHERE user_id = ? AND provider = ?
        `).get(userId, GITHUB_PROVIDER) as UserIntegrationRow | undefined;
    }

    getIntegration(userId: number): StoredGitHubIntegration | null {
        const row = this.getRow(userId);
        if (!row) {
            return null;
        }

        return {
            userId,
            isActive: row.is_active === 1,
            username: row.external_username || undefined,
            avatarUrl: row.external_avatar_url || undefined,
            connectedAt: row.connected_at,
            scope: row.token_scope,
            expiresAt: row.expires_at,
            metadata: parseMetadata(row.metadata_json),
            accessToken: decryptOptional(row.access_token_encrypted, row.token_iv),
            refreshToken: decryptOptional(row.refresh_token_encrypted, row.refresh_token_iv),
        };
    }

    listGitHubUserIds(): number[] {
        const rows = db.prepare(`
            SELECT DISTINCT user_id
            FROM user_integrations
            WHERE provider = ?
            ORDER BY user_id ASC
        `).all(GITHUB_PROVIDER) as Array<{ user_id: number }>;

        return rows.map((row) => row.user_id);
    }

    getProviderConfig(): { model: string | null; isActive: boolean } | null {
        const row = getProviderConfigRow(GITHUB_COPILOT_PROVIDER);
        if (!row) {
            return null;
        }

        return {
            model: row.model,
            isActive: row.is_active === 1,
        };
    }

    reconcileCopilotProviderConfig(): { migratedLegacyConfig: boolean; removedLegacyConfig: boolean } {
        const legacyConfig = getProviderConfigRow(LEGACY_GITHUB_MODELS_PROVIDER);
        const copilotConfig = getProviderConfigRow(GITHUB_COPILOT_PROVIDER);

        if (legacyConfig && !copilotConfig) {
            db.prepare(`
                UPDATE llm_config
                SET provider = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider = ?
            `).run(GITHUB_COPILOT_PROVIDER, LEGACY_GITHUB_MODELS_PROVIDER);

            return { migratedLegacyConfig: true, removedLegacyConfig: false };
        }

        if (legacyConfig && copilotConfig) {
            if ((!copilotConfig.model || copilotConfig.model === 'gpt-5') && legacyConfig.model) {
                db.prepare(`
                    UPDATE llm_config
                    SET model = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                `).run(legacyConfig.model, GITHUB_COPILOT_PROVIDER);
            }

            if ((copilotConfig.settings_json === '{}' || !copilotConfig.settings_json) && legacyConfig.settings_json) {
                db.prepare(`
                    UPDATE llm_config
                    SET settings_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                `).run(legacyConfig.settings_json, GITHUB_COPILOT_PROVIDER);
            }

            db.prepare('DELETE FROM llm_config WHERE provider = ?').run(LEGACY_GITHUB_MODELS_PROVIDER);
            return { migratedLegacyConfig: false, removedLegacyConfig: true };
        }

        return { migratedLegacyConfig: false, removedLegacyConfig: false };
    }

    deactivateProviderConfig(): number {
        const result = db.prepare(`
            UPDATE llm_config
            SET is_active = 0,
                is_online = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE provider IN (?, ?)
              AND (is_active != 0 OR is_online != 0)
        `).run(GITHUB_COPILOT_PROVIDER, LEGACY_GITHUB_MODELS_PROVIDER);

        return result.changes;
    }

    purgeInactiveConnectionSecrets(): number {
        const result = db.prepare(`
            UPDATE user_integrations
            SET access_token_encrypted = NULL,
                token_iv = NULL,
                refresh_token_encrypted = NULL,
                refresh_token_iv = NULL,
                token_scope = NULL,
                expires_at = NULL
            WHERE provider = ?
              AND is_active = 0
              AND (
                access_token_encrypted IS NOT NULL
                OR token_iv IS NOT NULL
                OR refresh_token_encrypted IS NOT NULL
                OR refresh_token_iv IS NOT NULL
                OR token_scope IS NOT NULL
                OR expires_at IS NOT NULL
              )
        `).run(GITHUB_PROVIDER);

        return result.changes;
    }

    ensureProviderConfig(defaultModel = 'gpt-5'): void {
        const currentModel = currentCopilotProviderModel();

        db.prepare(`
            INSERT OR IGNORE INTO llm_config (provider, api_key, model, is_active, is_online, settings_json)
            VALUES (?, '', ?, 0, 0, '{}')
        `).run(GITHUB_COPILOT_PROVIDER, currentModel || defaultModel);

        if (!currentModel) {
            db.prepare(`
                UPDATE llm_config
                SET model = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider = ?
            `).run(defaultModel, GITHUB_COPILOT_PROVIDER);
        }
    }

    saveConnection(userId: number, input: {
        user: GitHubUser;
        tokenSet: GitHubTokenSet;
        metadata: GitHubIntegrationMetadata;
    }): void {
        const access = encryptSecret(input.tokenSet.accessToken);
        const refresh = input.tokenSet.refreshToken ? encryptSecret(input.tokenSet.refreshToken) : { encrypted: null, iv: null };

        db.prepare(`
            INSERT INTO user_integrations (
                user_id,
                provider,
                access_token_encrypted,
                token_iv,
                refresh_token_encrypted,
                refresh_token_iv,
                token_scope,
                external_username,
                external_avatar_url,
                connected_at,
                expires_at,
                is_active,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 1, ?)
            ON CONFLICT(user_id, provider) DO UPDATE SET
                access_token_encrypted = excluded.access_token_encrypted,
                token_iv = excluded.token_iv,
                refresh_token_encrypted = excluded.refresh_token_encrypted,
                refresh_token_iv = excluded.refresh_token_iv,
                token_scope = excluded.token_scope,
                external_username = excluded.external_username,
                external_avatar_url = excluded.external_avatar_url,
                connected_at = CURRENT_TIMESTAMP,
                expires_at = excluded.expires_at,
                is_active = 1,
                metadata_json = excluded.metadata_json
        `).run(
            userId,
            GITHUB_PROVIDER,
            access.encrypted,
            access.iv,
            refresh.encrypted,
            refresh.iv,
            input.tokenSet.scope || '',
            input.user.login,
            input.user.avatarUrl,
            input.tokenSet.expiresAt || null,
            JSON.stringify(input.metadata),
        );

        const cachedModels = input.metadata.modelsCache?.models || [];
        const currentModel = currentCopilotProviderModel();
        this.ensureProviderConfig(currentModel || cachedModels.find((model) => model.isAvailable)?.id || 'gpt-5');
    }

    updateTokens(userId: number, tokenSet: GitHubTokenSet, metadataPatch?: Partial<GitHubIntegrationMetadata>): void {
        const existing = this.getIntegration(userId);
        if (!existing) {
            throw new Error('GitHub is not connected.');
        }

        const access = encryptSecret(tokenSet.accessToken);
        const refreshToken = tokenSet.refreshToken || existing.refreshToken || null;
        const refresh = refreshToken ? encryptSecret(refreshToken) : { encrypted: null, iv: null };
        const metadata = {
            ...existing.metadata,
            ...metadataPatch,
            tokenExpiresAt: tokenSet.expiresAt || existing.metadata.tokenExpiresAt || null,
            refreshTokenExpiresAt: tokenSet.refreshTokenExpiresAt || existing.metadata.refreshTokenExpiresAt || null,
            lastValidationError: null,
        };

        db.prepare(`
            UPDATE user_integrations
            SET access_token_encrypted = ?,
                token_iv = ?,
                refresh_token_encrypted = ?,
                refresh_token_iv = ?,
                token_scope = ?,
                expires_at = ?,
                is_active = 1,
                metadata_json = ?
            WHERE user_id = ? AND provider = ?
        `).run(
            access.encrypted,
            access.iv,
            refresh.encrypted,
            refresh.iv,
            tokenSet.scope || existing.scope || '',
            tokenSet.expiresAt || null,
            JSON.stringify(metadata),
            userId,
            GITHUB_PROVIDER,
        );
    }

    updateMetadata(userId: number, mutate: (metadata: GitHubIntegrationMetadata) => GitHubIntegrationMetadata): void {
        const existing = this.getIntegration(userId);
        if (!existing) {
            return;
        }

        db.prepare(`
            UPDATE user_integrations
            SET metadata_json = ?
            WHERE user_id = ? AND provider = ?
        `).run(JSON.stringify(mutate(existing.metadata)), userId, GITHUB_PROVIDER);
    }

    cacheModels(userId: number, models: GitHubCopilotModel[], errorMessage?: string | null): void {
        this.updateMetadata(userId, (metadata) => ({
            ...metadata,
            modelsCache: {
                models,
                fetchedAt: new Date().toISOString(),
            },
            lastDiscoveryError: errorMessage || null,
        }));

        const currentModel = currentCopilotProviderModel();
        if (!currentModel) {
            const defaultModel = models.find((model) => model.isAvailable)?.id;
            if (defaultModel) {
                db.prepare(`
                    UPDATE llm_config
                    SET model = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                `).run(defaultModel, GITHUB_COPILOT_PROVIDER);
            }
        }
    }

    markValidation(userId: number, validationError?: string | null): void {
        this.updateMetadata(userId, (metadata) => ({
            ...metadata,
            lastValidatedAt: new Date().toISOString(),
            lastValidationError: validationError || null,
        }));
    }

    invalidateConnection(userId: number, reason: string): void {
        const existing = this.getIntegration(userId);
        if (!existing) {
            return;
        }

        db.prepare(`
            UPDATE user_integrations
            SET is_active = 0,
                access_token_encrypted = NULL,
                token_iv = NULL,
                refresh_token_encrypted = NULL,
                refresh_token_iv = NULL,
                expires_at = NULL,
                metadata_json = ?
            WHERE user_id = ? AND provider = ?
        `).run(JSON.stringify({
            ...existing.metadata,
            lastValidationError: reason,
        }), userId, GITHUB_PROVIDER);

        this.deactivateProviderConfig();
    }

    disconnect(userId: number): void {
        db.prepare(`
            UPDATE user_integrations
            SET is_active = 0,
                access_token_encrypted = NULL,
                token_iv = NULL,
                refresh_token_encrypted = NULL,
                refresh_token_iv = NULL,
                token_scope = NULL,
                expires_at = NULL
            WHERE user_id = ? AND provider = ?
        `).run(userId, GITHUB_PROVIDER);

        this.deactivateProviderConfig();
    }
}
