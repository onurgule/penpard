/**
 * OrchestratorBurpToolHandlers
 *
 * Owns the mapping of Burp-passthrough tool handlers.
 * Previously, OrchestratorAgent manually wired 8+ inline lambdas that
 * called `this.burp.callTool(...)` directly. This factory moves that
 * wiring to a dedicated module so the agent no longer needs a direct
 * BurpMCPClient field for tool handler construction.
 *
 * The agent still passes in narrower collaborators (requestExecutor,
 * browserTools, domainCoordinator) that already own their own Burp
 * relationship. This module handles only the "pure passthrough" Burp
 * tools that don't belong in any domain collaborator.
 */

import {
    normalizeCookiesAndAuthEntries,
    normalizeProxyHistoryItems,
    normalizeSessionCookieResult,
} from '../../services/burp-tool-result';
import { ToolCall } from './types';

type ToolHandler = (toolCall: ToolCall) => Promise<any>;

export interface BurpToolClient {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
    isAvailable(): Promise<boolean>;
    disconnect(): void;
}

interface BurpToolHandlersConfig {
    burp: BurpToolClient;
    targetUrl: string;
}

/**
 * Creates the set of Burp-passthrough tool handlers.
 * Each handler delegates to `burp.callTool(...)` with appropriate
 * arg normalization. These are the tools that have no domain collaborator
 * and are pure proxy-to-Burp calls.
 */
export function createBurpToolHandlers(config: BurpToolHandlersConfig): Record<string, ToolHandler> {
    const { burp, targetUrl } = config;
    const targetHostname = (() => {
        try { return new URL(targetUrl).hostname; } catch { return ''; }
    })();

    return {
        get_proxy_history: async (toolCall) => ({
            items: normalizeProxyHistoryItems(
                await burp.callTool('get_proxy_history', { ...toolCall.args, excludePenPard: true }),
            ),
        }),

        get_session_cookies: async (toolCall) => normalizeSessionCookieResult(
            await burp.callTool('get_session_cookies', {
                host: toolCall.args?.host || targetHostname,
            }),
        ),

        get_cookies_and_auth_for_host: async (toolCall) => ({
            entries: normalizeCookiesAndAuthEntries(await burp.callTool('get_cookies_and_auth_for_host', {
                host: toolCall.args?.host || targetHostname,
                maxItems: toolCall.args?.maxItems ?? 50,
            })),
        }),

        send_to_scanner: (toolCall) => burp.callTool('send_to_scanner', toolCall.args),
        get_sitemap: (toolCall) => burp.callTool('get_sitemap', toolCall.args || {}),
        spider_url: (toolCall) => burp.callTool('spider_url', toolCall.args),
        check_authorization: (toolCall) => burp.callTool('check_authorization', toolCall.args),
        generate_payloads: (toolCall) => burp.callTool('generate_payloads', toolCall.args),
        extract_links: (toolCall) => burp.callTool('extract_links', toolCall.args),
        analyze_response: async () => ({ status: 'Analysis requested - handled by LLM' }),
        none: async () => ({ status: 'No tool call (step complete)' }),
    };
}
