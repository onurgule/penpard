/**
 * PenPard Auth State Management — IdentityRegistry
 * 
 * Manages identity profiles and credential sets.
 * Creates and tracks User A / User B / attacker identities
 * for multi-user isolation during IDOR and BAC testing.
 */

import { IdentityProfile, CredentialSet, IdentityRole, CredentialSource } from './types';
import { logger } from '../../utils/logger';

export class IdentityRegistry {
    private identities: Map<string, IdentityProfile> = new Map();
    private readonly scanId: string;

    constructor(scanId: string) {
        this.scanId = scanId;
    }

    // ═══════════════════════════════════════════════════════════
    //  IDENTITY MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * Create the primary identity (the main test user).
     * This is the default identity used for all requests unless overridden.
     */
    createPrimary(label: string = 'Primary User', opts?: {
        username?: string;
        userId?: string;
        email?: string;
        tenantId?: string;
        roleInApp?: string;
        credentialSet?: CredentialSet;
    }): IdentityProfile {
        return this.create('primary-user', label, 'primary', opts);
    }

    /**
     * Create a secondary identity (for IDOR/BAC comparison testing).
     */
    createSecondary(id: string, label: string, opts?: {
        username?: string;
        userId?: string;
        email?: string;
        tenantId?: string;
        roleInApp?: string;
        credentialSet?: CredentialSet;
    }): IdentityProfile {
        return this.create(id, label, 'secondary', opts);
    }

    /**
     * Create an attacker identity (unauthenticated or minimal-privilege).
     */
    createAttacker(label: string = 'Unauthenticated', opts?: {
        username?: string;
        credentialSet?: CredentialSet;
    }): IdentityProfile {
        return this.create('attacker', label, 'attacker', opts);
    }

    /**
     * General identity creation.
     */
    create(id: string, label: string, role: IdentityRole, opts?: {
        username?: string;
        userId?: string;
        email?: string;
        tenantId?: string;
        roleInApp?: string;
        credentialSet?: CredentialSet;
    }): IdentityProfile {
        // Prevent duplicate IDs
        if (this.identities.has(id)) {
            logger.warn(`IdentityRegistry: Identity "${id}" already exists — updating`);
            const existing = this.identities.get(id)!;
            if (opts?.username) existing.username = opts.username;
            if (opts?.userId) existing.userId = opts.userId;
            if (opts?.email) existing.email = opts.email;
            if (opts?.tenantId) existing.tenantId = opts.tenantId;
            if (opts?.roleInApp) existing.roleInApp = opts.roleInApp;
            if (opts?.credentialSet) existing.credentialSet = opts.credentialSet;
            return existing;
        }

        const profile: IdentityProfile = {
            id,
            label,
            role,
            username: opts?.username,
            userId: opts?.userId,
            email: opts?.email,
            tenantId: opts?.tenantId,
            roleInApp: opts?.roleInApp,
            credentialSet: opts?.credentialSet,
            createdAt: new Date(),
            isActive: true,
            lastValidatedAt: null,
            deactivationReason: undefined,
        };

        this.identities.set(id, profile);
        logger.info(`IdentityRegistry: Created identity "${id}" (${label}, ${role})`);
        return profile;
    }

    /**
     * Initialize identities from scan config's idorUsers array.
     * Each IDOR user becomes a secondary identity.
     */
    initializeFromIdorUsers(idorUsers: Array<{
        username?: string;
        password?: string;
        userId?: string;
        email?: string;
        role?: string;
        label?: string;
    }>): IdentityProfile[] {
        const created: IdentityProfile[] = [];

        for (let i = 0; i < idorUsers.length; i++) {
            const user = idorUsers[i];
            const id = `idor-user-${i + 1}`;
            const label = user.label || user.username || `IDOR User ${i + 1}`;

            let credentialSet: CredentialSet | undefined;
            if (user.username && user.password) {
                credentialSet = {
                    username: user.username,
                    password: user.password,
                    loginMethod: 'unknown',
                    capturedAt: new Date(),
                    source: 'scan_config',
                };
            }

            const profile = this.createSecondary(id, label, {
                username: user.username,
                userId: user.userId,
                email: user.email,
                roleInApp: user.role,
                credentialSet,
            });

            created.push(profile);
        }

        return created;
    }

    // ═══════════════════════════════════════════════════════════
    //  RETRIEVAL
    // ═══════════════════════════════════════════════════════════

    /** Get identity by ID. */
    get(id: string): IdentityProfile | undefined {
        return this.identities.get(id);
    }

    /** Get the primary identity. */
    getPrimary(): IdentityProfile | undefined {
        for (const identity of this.identities.values()) {
            if (identity.role === 'primary') return identity;
        }
        return undefined;
    }

    /** Get the default identity ID (primary, or first available). */
    getDefaultId(): string {
        const primary = this.getPrimary();
        if (primary) return primary.id;
        const first = this.identities.values().next().value;
        return first?.id || 'primary-user';
    }

    /** Get all identities. */
    getAll(): IdentityProfile[] {
        return [...this.identities.values()];
    }

    /** Get all active identities. */
    getActive(): IdentityProfile[] {
        return this.getAll().filter(p => p.isActive);
    }

    /** Get all secondary identities (for IDOR testing). */
    getSecondaries(): IdentityProfile[] {
        return this.getAll().filter(p => p.role === 'secondary');
    }

    /** Check if an identity exists. */
    has(id: string): boolean {
        return this.identities.has(id);
    }

    /** Total identity count. */
    get size(): number {
        return this.identities.size;
    }

    /** The special "anonymous" identity ID for unauthenticated requests. */
    static readonly ANONYMOUS_ID = '__none__';

    // ═══════════════════════════════════════════════════════════
    //  STATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /** Mark an identity as validated. */
    markValidated(id: string): void {
        const identity = this.identities.get(id);
        if (identity) {
            identity.lastValidatedAt = new Date();
        }
    }

    /** Deactivate an identity (session expired, locked out, etc.) */
    deactivate(id: string, reason: string): void {
        const identity = this.identities.get(id);
        if (identity) {
            identity.isActive = false;
            identity.deactivationReason = reason;
            logger.warn(`IdentityRegistry: Deactivated "${id}" — ${reason}`);
        }
    }

    /** Reactivate an identity (after successful re-login). */
    reactivate(id: string): void {
        const identity = this.identities.get(id);
        if (identity) {
            identity.isActive = true;
            identity.deactivationReason = undefined;
            identity.lastValidatedAt = new Date();
            logger.info(`IdentityRegistry: Reactivated "${id}"`);
        }
    }

    /** Update identity metadata from JWT claims or response data. */
    updateFromClaims(id: string, claims: Record<string, any>): void {
        const identity = this.identities.get(id);
        if (!identity) return;

        if (claims.sub && !identity.userId) identity.userId = String(claims.sub);
        if (claims.email && !identity.email) identity.email = String(claims.email);
        if (claims.role && !identity.roleInApp) identity.roleInApp = String(claims.role);
        if (claims.tenant_id && !identity.tenantId) identity.tenantId = String(claims.tenant_id);
        if (claims.name && identity.label === identity.id) identity.label = String(claims.name);
    }

    /**
     * Set the login URL for an identity's credential set.
     * Called when login page is detected via redirect.
     */
    setLoginUrl(id: string, loginUrl: string): void {
        const identity = this.identities.get(id);
        if (identity?.credentialSet) {
            identity.credentialSet.loginUrl = loginUrl;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  SUMMARY
    // ═══════════════════════════════════════════════════════════

    /** Summary for logging. */
    toSummary(): string {
        const identities = this.getAll();
        if (identities.length === 0) return 'IdentityRegistry: no identities';

        const lines = identities.map(i => {
            const status = i.isActive ? '✓' : `✗(${i.deactivationReason})`;
            const user = i.username ? ` user=${i.username}` : '';
            const role = i.roleInApp ? ` appRole=${i.roleInApp}` : '';
            return `  ${status} ${i.id}: ${i.label} [${i.role}]${user}${role}`;
        });

        return `IdentityRegistry (${identities.length}):\n${lines.join('\n')}`;
    }
}
