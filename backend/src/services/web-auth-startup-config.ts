import { AuthStartupConfig, AuthStartupCredential, CredentialPrivilege } from './auth';

type MaybeBoolean = boolean | string | number | null | undefined;

function normalizeBoolean(value: MaybeBoolean, defaultValue: boolean = false): boolean {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value !== 0;
    if (typeof value !== 'string') return defaultValue;
    const normalized = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off'].includes(normalized)) return false;
    return defaultValue;
}

function normalizeString(value: unknown): string | undefined {
    if (typeof value !== 'string') return undefined;
    const trimmed = value.trim();
    return trimmed ? trimmed : undefined;
}

function normalizePrivilege(value: unknown): CredentialPrivilege {
    if (value === 'low' || value === 'high' || value === 'unknown') return value;
    return 'unknown';
}

function parseJsonArray<T = any>(value: unknown): T[] {
    if (Array.isArray(value)) return value as T[];
    if (typeof value !== 'string' || !value.trim()) return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed as T[] : [];
    } catch {
        return [];
    }
}

function normalizeCredential(input: any): AuthStartupCredential | null {
    const username = normalizeString(input?.username);
    const email = normalizeString(input?.email);
    const password = normalizeString(input?.password);
    const label = normalizeString(input?.label);
    const role = normalizeString(input?.role);

    if (!username && !email && !password && !label && !role) {
        return null;
    }

    return {
        username,
        email,
        password,
        label,
        role,
        privilege: normalizePrivilege(input?.privilege),
        source: 'scan_config',
    };
}

function credentialsFromLegacyUsers(value: unknown): AuthStartupCredential[] {
    return parseJsonArray<any>(value)
        .map((entry) => normalizeCredential({
            username: entry?.username,
            email: entry?.email,
            password: entry?.password,
            label: entry?.label,
            role: entry?.role,
            privilege: entry?.privilege,
        }))
        .filter((entry): entry is AuthStartupCredential => !!entry);
}

export function defaultAuthStartupConfig(): AuthStartupConfig {
    return {
        mode: 'no_credentials',
        credentials: [],
        allowAccountCreation: false,
        preferSharedPassword: true,
    };
}

export function resolveAuthStartupConfig(input: {
    authStartupMode?: unknown;
    authCredentials?: unknown;
    allowAccountCreation?: MaybeBoolean;
    preferSharedPassword?: MaybeBoolean;
    idorUsers?: unknown;
}): AuthStartupConfig {
    const explicitMode = normalizeString(input.authStartupMode);
    const parsedCredentials = parseJsonArray<any>(input.authCredentials)
        .map((entry) => normalizeCredential(entry))
        .filter((entry): entry is AuthStartupCredential => !!entry);
    const fallbackCredentials = parsedCredentials.length > 0 ? parsedCredentials : credentialsFromLegacyUsers(input.idorUsers);

    const mode = explicitMode === 'provided_credentials' && fallbackCredentials.length > 0
        ? 'provided_credentials'
        : 'no_credentials';

    return {
        mode,
        credentials: mode === 'provided_credentials' ? fallbackCredentials : [],
        allowAccountCreation: normalizeBoolean(input.allowAccountCreation, false),
        preferSharedPassword: normalizeBoolean(input.preferSharedPassword, true),
    };
}

export function redactAuthStartupConfig(config: AuthStartupConfig): AuthStartupConfig {
    return {
        ...config,
        credentials: config.credentials.map((credential) => ({
            ...credential,
            password: credential.password ? '[REDACTED]' : undefined,
        })),
    };
}

export function toLegacyIdorUsers(config: AuthStartupConfig): Array<{
    username?: string;
    password?: string;
    email?: string;
    role?: string;
    label?: string;
    privilege?: CredentialPrivilege;
}> {
    return config.credentials.map((credential) => ({
        username: credential.username,
        password: credential.password,
        email: credential.email,
        role: credential.role,
        label: credential.label,
        privilege: credential.privilege,
    }));
}
