import type { AuthStartupInventory, AuthStartupMode } from '../../services/auth';
import { AttackPlan, InstructionAnalysis } from './types';

type LogFn = (channel: 'system', message: string) => void;

interface FallbackPlannerInput {
    targetUrl: string;
    planRound: number;
    instructionAnalysis: InstructionAnalysis | null;
    startupAuthInventory: AuthStartupInventory | null;
    authStartupMode?: AuthStartupMode;
    discoveredEndpoints: Iterable<string>;
}

export class OrchestratorFallbackPlanner {
    constructor(private readonly log?: LogFn) {}

    public createPlan(input: FallbackPlannerInput): AttackPlan {
        const baseUrl = input.targetUrl.replace(/\/$/, '');
        const authMode = input.authStartupMode || 'no_credentials';

        if (input.instructionAnalysis?.is_focused) {
            const analysis = input.instructionAnalysis;
            const endpoints = analysis.focused_endpoints.length > 0
                ? analysis.focused_endpoints
                : [baseUrl];
            const vulnLabel = analysis.focused_vulns.length > 0
                ? analysis.focused_vulns.join(', ')
                : 'common vulnerabilities';

            this.log?.('system', `Generating focused fallback plan: ${endpoints.join(', ')} -> ${vulnLabel}`);

            return {
                round: input.planRound,
                analysis: `Focused fallback: Testing ${endpoints.join(', ')} for ${vulnLabel}`,
                steps: endpoints.slice(0, 3).flatMap((endpoint, index) => [
                    {
                        step: index * 2 + 1,
                        objective: `Test ${endpoint} for ${vulnLabel}`,
                        approach: `Send targeted ${vulnLabel} payloads to ${endpoint}`,
                        tools: ['send_http_request', 'generate_payloads'],
                        status: 'pending' as const,
                    },
                    {
                        step: index * 2 + 2,
                        objective: `Deep scan ${endpoint} with Burp Scanner for ${vulnLabel}`,
                        approach: `Send ${endpoint} to Burp Scanner for thorough automated testing`,
                        tools: ['send_to_scanner'],
                        status: 'pending' as const,
                    },
                ]).slice(0, 5),
            };
        }

        if (input.planRound <= 1) {
            const authTargets = (input.startupAuthInventory?.authRoutes || [])
                .slice(0, 6)
                .map((route) => {
                    try {
                        return route.startsWith('http') ? route : new URL(route, input.targetUrl).toString();
                    } catch {
                        return route;
                    }
                });
            const primaryAuthRoute = authTargets[0] || `${baseUrl}/login`;
            const registrationRoute = authTargets.find((route) => /register|sign[\s-]?up|create-account/i.test(route)) || `${baseUrl}/register`;
            const resetRoute = authTargets.find((route) => /forgot|reset|recover/i.test(route)) || `${baseUrl}/forgot-password`;

            if (authMode === 'provided_credentials') {
                return {
                    round: input.planRound,
                    analysis: 'Fallback: round-one auth startup continuation with provided credentials',
                    steps: [
                        { step: 1, objective: 'Validate discovered login surface and auth controls', approach: `Review startup auth inventory and revisit ${primaryAuthRoute} in the browser to confirm login fields, DOM triggers, hidden inputs, and CSRF handling`, tools: ['browser_navigate', 'browser_get_page_state', 'browser_correlate_burp'], status: 'pending' },
                        { step: 2, objective: 'Complete browser-driven login with supplied identity', approach: 'Use the discovered login form and real browser session to confirm authenticated state instead of replaying blind raw requests', tools: ['browser_fill_and_submit', 'browser_get_page_state'], status: 'pending' },
                        { step: 3, objective: 'Harvest and normalize auth traffic', approach: 'Pull Burp history and harvested requests for the login flow to capture cookies, Authorization headers, CSRF values, redirect chains, and storage-backed session data', tools: ['get_proxy_history', 'harvest_traffic'], status: 'pending' },
                        { step: 4, objective: 'Validate authenticated reachability with managed auth state', approach: 'Replay an authenticated endpoint using the normalized auth/session model captured during startup', tools: ['send_http_request'], status: 'pending' },
                        { step: 5, objective: 'Map secondary identities for later authorization tests', approach: 'Prepare alternate provided users and confirm whether role or privilege differences exist for later IDOR/BAC testing', tools: ['browser_get_page_state', 'send_http_request'], status: 'pending' },
                    ],
                };
            }

            return {
                round: input.planRound,
                analysis: 'Fallback: round-one auth-surface-first startup continuation without credentials',
                steps: [
                    { step: 1, objective: 'Revisit discovered auth entry points in the browser', approach: `Use the startup inventory to review ${primaryAuthRoute}, ${registrationRoute}, and other discovered auth routes for forms, buttons, hidden inputs, CSRF, validation, and SSO triggers`, tools: ['browser_navigate', 'browser_get_page_state', 'browser_correlate_burp'], status: 'pending' },
                    { step: 2, objective: 'Attempt safe self-registration or onboarding identity creation', approach: `If registration or invite onboarding exists, try to create one or more test accounts starting at ${registrationRoute} and preserve the resulting credentials and roles`, tools: ['browser_fill_and_submit', 'browser_get_page_state'], status: 'pending' },
                    { step: 3, objective: 'Inventory password reset, recovery, OTP, and activation gates', approach: `Examine ${resetRoute} and other recovery checkpoints to understand recovery routes, email verification, MFA/TOTP, and session bootstrap requirements`, tools: ['browser_navigate', 'browser_get_page_state'], status: 'pending' },
                    { step: 4, objective: 'Harvest proxied auth traffic and session transport evidence', approach: 'Use Burp history and harvested requests to capture Set-Cookie behavior, redirect chains, storage-backed tokens, Authorization headers, and CSRF transport from real browser execution', tools: ['get_proxy_history', 'harvest_traffic'], status: 'pending' },
                    { step: 5, objective: 'Carry normalized auth intelligence into the first authenticated checks', approach: 'Replay a startup-discovered auth or post-auth endpoint with the managed auth/session state to validate that later scan rounds can reuse the captured identities safely', tools: ['send_http_request'], status: 'pending' },
                ],
            };
        }

        const discoveredEndpoints = Array.from(input.discoveredEndpoints);
        const fallbackTargets = discoveredEndpoints.length > 0
            ? discoveredEndpoints.slice(0, 5)
            : [baseUrl];

        return {
            round: input.planRound,
            analysis: discoveredEndpoints.length > 0
                ? 'Fallback: Testing discovered endpoints'
                : 'Fallback: Re-centering on the target root because no endpoints have been retained yet',
            steps: fallbackTargets.map((endpoint, index) => ({
                step: index + 1,
                objective: `Test ${endpoint} for common vulns`,
                approach: `Send test payloads to ${endpoint}`,
                tools: ['send_http_request', 'send_to_scanner'],
                status: 'pending' as const,
            })),
        };
    }
}
