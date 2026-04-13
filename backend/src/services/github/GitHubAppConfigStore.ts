import { db } from '../../db/init';
import { logger } from '../../utils/logger';
import { decryptSecret, encryptSecret } from './crypto';
import { buildDefaultGitHubCallbackUrl, normalizeGitHubConfigValue } from './config';

const GITHUB_APP_CONFIG_KEY = 'github_app_oauth_config';

interface SettingsRow {
    value: string | null;
}

interface PersistedGitHubAppConfigRecord {
    clientId?: string;
    callbackUrl?: string;
    clientSecretEncrypted?: string | null;
    clientSecretIv?: string | null;
    callbackRegistrationConfirmed?: boolean;
}

export interface StoredGitHubAppConfig {
    clientId: string;
    callbackUrl: string;
    clientSecret?: string;
    hasClientSecret: boolean;
    callbackRegistrationConfirmed: boolean;
}

function isCallbackRegistrationConfirmed(record: PersistedGitHubAppConfigRecord | null): boolean {
    return record?.callbackRegistrationConfirmed !== false;
}

function parseRecord(raw: string | null): PersistedGitHubAppConfigRecord | null {
    if (!raw) {
        return null;
    }

    try {
        return JSON.parse(raw) as PersistedGitHubAppConfigRecord;
    } catch (error) {
        logger.error('Failed to parse stored GitHub App config', { error });
        return null;
    }
}

function decryptClientSecret(record: PersistedGitHubAppConfigRecord | null): string {
    if (!record?.clientSecretEncrypted || !record.clientSecretIv) {
        return '';
    }

    try {
        return decryptSecret(record.clientSecretEncrypted, record.clientSecretIv);
    } catch (error) {
        logger.error('Failed to decrypt stored GitHub App client secret', { error });
        return '';
    }
}

export class GitHubAppConfigStore {
    private getRecord(): PersistedGitHubAppConfigRecord | null {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(GITHUB_APP_CONFIG_KEY) as SettingsRow | undefined;
        return parseRecord(row?.value || null);
    }

    hasStoredConfig(): boolean {
        return this.getRecord() !== null;
    }

    getStoredConfig(): StoredGitHubAppConfig | null {
        const record = this.getRecord();
        if (!record) {
            return null;
        }

        const clientSecret = decryptClientSecret(record);
        return {
            clientId: normalizeGitHubConfigValue(record.clientId),
            callbackUrl: normalizeGitHubConfigValue(record.callbackUrl) || buildDefaultGitHubCallbackUrl(),
            clientSecret: clientSecret || undefined,
            hasClientSecret: clientSecret !== '',
            callbackRegistrationConfirmed: isCallbackRegistrationConfirmed(record),
        };
    }

    getStoredSummary(): Omit<StoredGitHubAppConfig, 'clientSecret'> | null {
        const record = this.getRecord();
        if (!record) {
            return null;
        }

        return {
            clientId: normalizeGitHubConfigValue(record.clientId),
            callbackUrl: normalizeGitHubConfigValue(record.callbackUrl) || buildDefaultGitHubCallbackUrl(),
            hasClientSecret: Boolean(record.clientSecretEncrypted && record.clientSecretIv),
            callbackRegistrationConfirmed: isCallbackRegistrationConfirmed(record),
        };
    }

    saveConfig(input: { clientId: string; callbackUrl: string; clientSecret?: string | null; callbackRegistrationConfirmed: boolean }): void {
        const existing = this.getRecord();
        const normalizedClientSecret = normalizeGitHubConfigValue(input.clientSecret);
        const encryptedSecret = normalizedClientSecret
            ? encryptSecret(normalizedClientSecret)
            : {
                encrypted: existing?.clientSecretEncrypted || null,
                iv: existing?.clientSecretIv || null,
            };

        const nextRecord: PersistedGitHubAppConfigRecord = {
            clientId: normalizeGitHubConfigValue(input.clientId),
            callbackUrl: normalizeGitHubConfigValue(input.callbackUrl),
            clientSecretEncrypted: encryptedSecret.encrypted,
            clientSecretIv: encryptedSecret.iv,
            callbackRegistrationConfirmed: input.callbackRegistrationConfirmed,
        };

        db.prepare(`
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
        `).run(GITHUB_APP_CONFIG_KEY, JSON.stringify(nextRecord));
    }
}

export const githubAppConfigStore = new GitHubAppConfigStore();
