import { IdentityRegistry, RequestAuthIntent } from '../../services/auth';

const ENUMERATION_TOOLS = new Set(['spider_url', 'get_sitemap', 'extract_links']);

export interface ToolExecutionGuardInput {
    toolName: string;
    isFocusedScope: boolean;
    rateLimitPauseUntil: Date | null;
    now?: Date;
}

export interface ToolExecutionGuardResult {
    allowed: boolean;
    logMessage?: string;
    response?: any;
}

export function evaluateToolExecutionGuard(input: ToolExecutionGuardInput): ToolExecutionGuardResult {
    const now = input.now ?? new Date();

    if (input.rateLimitPauseUntil && now < input.rateLimitPauseUntil) {
        const remainingMs = input.rateLimitPauseUntil.getTime() - now.getTime();
        const remainingMin = Math.ceil(remainingMs / 60000);
        return {
            allowed: false,
            logMessage: `Rate limited - waiting ${remainingMin} more minutes`,
            response: { error: `Rate limited. Waiting ${remainingMin} minutes.`, skipped: true },
        };
    }

    if (input.isFocusedScope && ENUMERATION_TOOLS.has(input.toolName)) {
        return {
            allowed: false,
            logMessage: `Blocked "${input.toolName}" because operator instructions define a focused scope.`,
            response: {
                error: `Tool "${input.toolName}" is blocked because operator instructions define a specific scope. Do NOT enumerate. Go directly to the target endpoint and test for the specified vulnerability type.`,
                blocked: true,
            },
        };
    }

    return { allowed: true };
}

export function resolveAuthIdentityId(args: Record<string, any> | undefined): string {
    if (typeof args?.identityId === 'string' && args.identityId.trim()) {
        return args.identityId.trim();
    }
    if (args?.disableAutoAuth === true) {
        return IdentityRegistry.ANONYMOUS_ID;
    }
    return 'primary-user';
}

export function hasCustomAuthHeader(headers: Record<string, string> | undefined): boolean {
    if (!headers) return false;

    return Object.entries(headers).some(([name, value]) => {
        const lower = name.toLowerCase();
        return [
            'x-api-key',
            'x-auth-token',
            'x-access-token',
            'x-session-token',
            'api-key',
            'apikey',
            'x-token',
        ].includes(lower) && typeof value === 'string' && value.trim().length > 0;
    });
}

export function resolveRequestAuthIntent(options: {
    requestedIntent?: unknown;
    identityId?: string;
    inferIntent: () => RequestAuthIntent;
}): RequestAuthIntent {
    if (typeof options.requestedIntent === 'string') {
        const normalized = options.requestedIntent.trim().toLowerCase() as RequestAuthIntent;
        if ([
            'authenticated',
            'anonymous_auth_probe',
            'account_creation',
            'session_refresh',
            'browser_sync',
            'unknown',
        ].includes(normalized)) {
            return normalized;
        }
    }

    const inferred = options.inferIntent();
    if (options.identityId === IdentityRegistry.ANONYMOUS_ID && inferred === 'authenticated') {
        return 'unknown';
    }
    return inferred;
}
