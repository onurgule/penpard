import { IdentityRegistry, RequestAuthIntent } from '../../services/auth';
import { ScopedMissionPolicy } from '../../services/runtime/ScopedMissionPolicy';

const ENUMERATION_TOOLS = new Set(['spider_url', 'get_sitemap', 'extract_links']);

export interface ToolExecutionGuardInput {
    toolName: string;
    toolArgs?: Record<string, any>;
    isFocusedScope: boolean;
    scopePolicy?: ScopedMissionPolicy;
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
        input.scopePolicy?.recordBoundaryBlock(`Blocked "${input.toolName}" because the scoped mission does not allow broad enumeration.`);
        return {
            allowed: false,
            logMessage: `Blocked "${input.toolName}" because operator instructions define a focused scope.`,
            response: {
                error: `Tool "${input.toolName}" is blocked because operator instructions define a specific scope. Do NOT enumerate. Go directly to the target endpoint and test for the specified vulnerability type.`,
                blocked: true,
            },
        };
    }

    if (input.scopePolicy && isScopedPolicyTool(input.toolName)) {
        const decision = input.scopePolicy.evaluateTool({
            toolName: input.toolName,
            method: typeof input.toolArgs?.method === 'string' ? input.toolArgs.method : undefined,
            url: typeof input.toolArgs?.url === 'string' ? input.toolArgs.url : undefined,
            useInitialRequestBaseline: input.toolArgs?.useInitialRequestBaseline === true,
        });
        if (!decision.allowed) {
            const reason = decision.reason || `Blocked "${input.toolName}" because it would leave the active scoped mission boundary.`;
            return {
                allowed: false,
                logMessage: reason,
                response: {
                    error: reason,
                    blocked: true,
                    boundaryReason: reason,
                },
            };
        }
    }

    return { allowed: true };
}

function isScopedPolicyTool(toolName: string): toolName is
    | 'send_http_request'
    | 'send_to_scanner'
    | 'browser_navigate'
    | 'browser_fill_and_submit'
    | 'browser_get_page_state'
    | 'browser_get_frontend_analysis'
    | 'browser_evaluate_js'
    | 'browser_screenshot'
    | 'browser_correlate_burp' {
    return [
        'send_http_request',
        'send_to_scanner',
        'browser_navigate',
        'browser_fill_and_submit',
        'browser_get_page_state',
        'browser_get_frontend_analysis',
        'browser_evaluate_js',
        'browser_screenshot',
        'browser_correlate_burp',
    ].includes(toolName);
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
