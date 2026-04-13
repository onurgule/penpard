export interface PromptIdentityDescriptor {
    identityId: string;
    label?: string | null;
    username?: string | null;
    email?: string | null;
    role?: string | null;
    privilege?: string | null;
    source?: string | null;
}

export interface PromptIdentityContext {
    identityId: string;
    label: string;
    role?: string;
    privilege: string;
    source?: string;
}

function normalizeString(value: unknown): string {
    return typeof value === 'string' ? value.trim() : '';
}

function titleCaseIdentityId(identityId: string): string {
    const normalized = identityId.replace(/[-_]+/g, ' ').trim();
    if (!normalized) {
        return 'Account';
    }

    return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function isSensitiveLabel(label: string, username: string, email: string): boolean {
    if (!label) {
        return true;
    }

    const lower = label.toLowerCase();
    if (email && lower === email.toLowerCase()) {
        return true;
    }

    if (username && lower === username.toLowerCase()) {
        return true;
    }

    return /\S+@\S+/.test(label);
}

export function buildPromptIdentityLabel(descriptor: Pick<PromptIdentityDescriptor, 'identityId' | 'label' | 'username' | 'email'>): string {
    const identityId = normalizeString(descriptor.identityId) || 'account';
    const label = normalizeString(descriptor.label);
    const username = normalizeString(descriptor.username);
    const email = normalizeString(descriptor.email);

    if (label && !isSensitiveLabel(label, username, email)) {
        return label;
    }

    switch (identityId) {
        case 'primary-user':
            return 'Primary User';
        case '__none__':
            return 'Anonymous';
        default:
            return titleCaseIdentityId(identityId);
    }
}

export function buildPromptIdentityContext(descriptor: PromptIdentityDescriptor): PromptIdentityContext {
    return {
        identityId: normalizeString(descriptor.identityId) || 'account',
        label: buildPromptIdentityLabel(descriptor),
        role: normalizeString(descriptor.role) || undefined,
        privilege: normalizeString(descriptor.privilege) || 'unknown',
        source: normalizeString(descriptor.source) || undefined,
    };
}
