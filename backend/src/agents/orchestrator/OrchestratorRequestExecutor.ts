import { AuthStateManager, IdentityRegistry } from '../../services/auth';
import { getHeaderValue } from '../../services/burp-request';
import { normalizeProxyHistoryItems, normalizeSendHttpResponse } from '../../services/burp-tool-result';
import { hasCustomAuthHeader, resolveAuthIdentityId, resolveRequestAuthIntent } from './OrchestratorToolPolicy';
import { RequestExecutionExchange, ToolCall } from './types';

interface BurpToolClient {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

interface RequestHistoryEntry {
    count: number;
    lastResponse: any;
    timestamp: Date;
}

interface NormalizedBurpHttpResult {
    result: any;
    statusCode: number;
    responseHeaders: Record<string, any> | Array<string>;
    responseBody: string;
}

export interface OrchestratorRequestExecutorOptions {
    scanId: string;
    burp: BurpToolClient;
    authManager: AuthStateManager;
    initialRequest?: string;
    log: (channel: string, message: string) => void;
    delay?: (ms: number) => Promise<void>;
    maxSameRequest?: number;
    rateLimitPauseMs: number;
    setRateLimitPauseUntil: (until: Date | null) => void;
    onEndpointDiscovered?: (url: string) => void;
    onManagedAuthRefreshed?: (identityId: string) => Promise<void>;
}

export class OrchestratorRequestExecutor {
    private readonly requestHistory = new Map<string, RequestHistoryEntry>();
    private lastExchange: RequestExecutionExchange | null = null;

    constructor(private readonly options: OrchestratorRequestExecutorOptions) {}

    public getLastExchange(): RequestExecutionExchange | null {
        return this.lastExchange;
    }

    public async execute(toolCall: ToolCall): Promise<any> {
        const url = toolCall.args.url;
        const method = toolCall.args.method || 'GET';
        const identityId = resolveAuthIdentityId(toolCall.args);
        const preserveExplicitAuth = toolCall.args?.preserveExplicitAuth === true;

        const decodedUrl = (() => {
            try {
                return decodeURIComponent(url);
            } catch {
                return url;
            }
        })();
        const unionNullMatch = decodedUrl.match(/union\s+select\s+null(?:,\s*null)*/gi);
        if (unionNullMatch) {
            const nullCount = (unionNullMatch[0].match(/null/gi) || []).length;
            if (nullCount >= 5) {
                this.options.log('tool', `Blocked SQLMap-style payload (${nullCount} nulls). Use send_to_scanner.`);
                const baseUrl = url.split('?')[0];
                return {
                    error: `SQLMap-style fuzzing blocked. Use send_to_scanner with ${baseUrl} instead.`,
                    blocked: true,
                    suggestion: { tool: 'send_to_scanner', args: { url: baseUrl } },
                };
            }
        }

        const originalBody = this.normalizeRequestBody(toolCall.args.body ?? toolCall.args.data ?? '');
        const originalHeaders = toolCall.args.headers as Record<string, string> | undefined;
        const requestIntent = resolveRequestAuthIntent({
            requestedIntent: toolCall.args.requestIntent,
            identityId,
            inferIntent: () => this.options.authManager.inferRequestIntent(url, method),
        });
        const existingAuthContext = this.options.authManager.inject(url, method, identityId, requestIntent);
        const explicitAuthorization = getHeaderValue(originalHeaders, 'authorization');
        const explicitCookie = getHeaderValue(originalHeaders, 'cookie');
        const explicitCustomAuth = hasCustomAuthHeader(originalHeaders);

        if (
            !preserveExplicitAuth &&
            identityId !== IdentityRegistry.ANONYMOUS_ID &&
            (
                (!!explicitAuthorization && !existingAuthContext.authorizationHeader) ||
                (!!explicitCookie && !existingAuthContext.cookies) ||
                (explicitCustomAuth && Object.keys(existingAuthContext.customHeaders).length === 0)
            )
        ) {
            this.options.authManager.captureFromStructuredRequest({
                requestHeaders: originalHeaders || {},
                url,
                body: originalBody,
            }, identityId);
        }

        let preparedRequest = this.options.authManager.prepareRequest(
            originalHeaders,
            originalBody,
            url,
            method,
            identityId,
            preserveExplicitAuth,
            requestIntent,
        );
        let requestDiagnostics = this.options.authManager.assessPreparedRequest({
            originalHeaders,
            preparedHeaders: preparedRequest.headers,
            url,
            method,
            identityId,
            preserveExplicitAuth,
            intent: requestIntent,
        });
        const isBurpOriginatedRequest = !!this.options.initialRequest?.trim();
        if (isBurpOriginatedRequest && requestDiagnostics.warning) {
            this.options.log('system', `Auth Warning: ${requestDiagnostics.warning}`);
        }
        if (requestDiagnostics.authSuppressedForIntent) {
            this.options.log('system', `Auth Guardrail: suppressing stored auth for ${requestIntent} on ${method} ${url}`);
        }

        const requestKey = this.buildRequestHistoryKey(
            method,
            url,
            preparedRequest.body,
            preparedRequest.headers,
            identityId,
        );

        const existing = this.requestHistory.get(requestKey);
        if (existing && existing.count >= (this.options.maxSameRequest ?? 2)) {
            this.options.log('tool', `Skipping exact duplicate request (${existing.count}x): ${method} ${url.substring(0, 80)}`);
            return {
                ...existing.lastResponse,
                cached: true,
                message: `Cached response. This exact request was sent ${existing.count} times already. Try different parameters or payloads.`,
            };
        }

        let requestArgs: Record<string, any> = {};
        const sendThroughBurp = async (headers: Record<string, string>, body: string) => {
            const args = {
                ...toolCall.args,
                headers,
                body,
                identityId,
            } as Record<string, any>;
            delete args.data;

            requestArgs = args;
            return this.options.burp.callTool('send_http_request', {
                ...args,
                use_proxy: true,
                penpard_source: `Orchestrator/${this.options.scanId}`,
            });
        };

        let normalizedResult = this.normalizeBurpHttpResult(
            await sendThroughBurp(preparedRequest.headers, preparedRequest.body),
        );
        let result = normalizedResult.result;
        let { rawRequest, rawResponse } = await this.getLatestProxyEvidence(url);
        let statusCode = normalizedResult.statusCode;
        let responseHeaders = normalizedResult.responseHeaders;
        let responseBody = normalizedResult.responseBody;
        let authHealth = this.options.authManager.handleResponse(
            statusCode,
            responseHeaders,
            responseBody,
            url,
            identityId,
            requestIntent,
        );
        let retriedAfterAuthInjection = false;

        const shouldRetryWithManagedAuth =
            statusCode === 401 &&
            identityId !== IdentityRegistry.ANONYMOUS_ID &&
            isBurpOriginatedRequest &&
            requestDiagnostics.likelyRequiresAuth &&
            requestDiagnostics.storedAuthAvailable &&
            !requestDiagnostics.outgoingAuthorizationPresent &&
            !requestDiagnostics.outgoingCookiePresent &&
            !requestDiagnostics.outgoingCustomAuthPresent &&
            !requestDiagnostics.explicitAuthorizationKeyPresent &&
            !requestDiagnostics.explicitCookieKeyPresent &&
            !requestDiagnostics.explicitCustomAuthKeyPresent;

        if (shouldRetryWithManagedAuth) {
            this.options.log('system', `Auth Recovery: ${method} ${url} received 401 without outgoing auth. Retrying once with stored auth material...`);

            preparedRequest = this.options.authManager.prepareRequest(
                originalHeaders,
                originalBody,
                url,
                method,
                identityId,
                false,
                requestIntent,
            );
            requestDiagnostics = this.options.authManager.assessPreparedRequest({
                originalHeaders,
                preparedHeaders: preparedRequest.headers,
                url,
                method,
                identityId,
                preserveExplicitAuth: false,
                intent: requestIntent,
            });

            if (
                requestDiagnostics.outgoingAuthorizationPresent ||
                requestDiagnostics.outgoingCookiePresent ||
                requestDiagnostics.outgoingCustomAuthPresent
            ) {
                normalizedResult = this.normalizeBurpHttpResult(
                    await sendThroughBurp(preparedRequest.headers, preparedRequest.body),
                );
                result = normalizedResult.result;
                statusCode = normalizedResult.statusCode;
                responseHeaders = normalizedResult.responseHeaders;
                responseBody = normalizedResult.responseBody;
                authHealth = this.options.authManager.handleResponse(
                    statusCode,
                    responseHeaders,
                    responseBody,
                    url,
                    identityId,
                    requestIntent,
                );
                retriedAfterAuthInjection = true;
                result = {
                    ...result,
                    retriedAfterAuthInjection: true,
                };
            } else {
                this.options.log('system', `Auth Warning: Stored auth recovery was attempted for ${identityId}, but PenPard still could not prepare any auth headers for retry.`);
            }
        }

        if (
            authHealth.needsRefresh &&
            !authHealth.needsRelogin &&
            (!preserveExplicitAuth || retriedAfterAuthInjection) &&
            identityId !== IdentityRegistry.ANONYMOUS_ID
        ) {
            this.options.log('system', `Auth State Engine: Session for ${identityId} needs refresh - retrying once...`);

            try {
                const refreshed = await this.options.authManager.refreshSession(identityId, this.options.burp);
                if (refreshed) {
                    await this.options.onManagedAuthRefreshed?.(identityId);

                    const retryPreparedRequest = this.options.authManager.prepareRequest(
                        originalHeaders,
                        originalBody,
                        url,
                        method,
                        identityId,
                        false,
                        requestIntent,
                    );

                    normalizedResult = this.normalizeBurpHttpResult(
                        await sendThroughBurp(retryPreparedRequest.headers, retryPreparedRequest.body),
                    );
                    result = normalizedResult.result;
                    statusCode = normalizedResult.statusCode;
                    responseHeaders = normalizedResult.responseHeaders;
                    responseBody = normalizedResult.responseBody;
                    authHealth = this.options.authManager.handleResponse(
                        statusCode,
                        responseHeaders,
                        responseBody,
                        url,
                        identityId,
                        requestIntent,
                    );

                    result = {
                        ...result,
                        retriedAfterRefresh: true,
                    };
                }
            } catch (error: any) {
                this.options.log('error', `Auth refresh failed: ${error.message}`);
            }
        }

        if (requestDiagnostics.warning) {
            result = {
                ...result,
                authWarning: requestDiagnostics.warning,
            };
        }
        if (authHealth.needsRelogin) {
            this.options.log('system', `Auth State Engine: Session for ${identityId} is dead - re-login required`);
        }
        if (authHealth.isCSRFFailure) {
            this.options.log('system', `Auth State Engine: CSRF validation failed for ${identityId} - token may need refresh`);
        }

        if (statusCode === 429) {
            this.options.setRateLimitPauseUntil(new Date(Date.now() + this.options.rateLimitPauseMs));
            this.options.log('tool', '429 Rate Limited! Pausing for 1 minute...');
            result = { ...result, rateLimited: true, message: 'Rate limited. Pausing 1 minute.' };
        }

        ({ rawRequest, rawResponse } = await this.getLatestProxyEvidence(url));

        this.requestHistory.set(requestKey, {
            count: (existing?.count || 0) + 1,
            lastResponse: result,
            timestamp: new Date(),
        });

        this.lastExchange = {
            action: {
                ...toolCall,
                args: requestArgs,
            },
            result,
            rawRequest,
            rawResponse,
        };

        this.options.onEndpointDiscovered?.(url);
        return result;
    }

    private normalizeRequestBody(rawBody: any): string {
        if (rawBody === undefined || rawBody === null) return '';
        if (typeof rawBody === 'string') return rawBody;
        return JSON.stringify(rawBody);
    }

    private buildRequestHistoryKey(
        method: string,
        url: string,
        body: string,
        headers: Record<string, string>,
        identityId: string,
    ): string {
        const sortedEntries = Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));
        return `${identityId}:${method}:${url}:${body}:${JSON.stringify(sortedEntries)}`;
    }

    private normalizeBurpHttpResult(result: any): NormalizedBurpHttpResult {
        const normalized = normalizeSendHttpResponse(result);
        const baseResult = normalized.raw && typeof normalized.raw === 'object'
            ? normalized.raw
            : { rawResult: normalized.raw };

        return {
            result: {
                ...baseResult,
                statusCode: normalized.statusCode,
                headers: normalized.headers,
                body: normalized.body,
            },
            statusCode: normalized.statusCode,
            responseHeaders: normalized.headers,
            responseBody: normalized.body,
        };
    }

    private async getLatestProxyEvidence(url: string): Promise<{ rawRequest?: string; rawResponse?: string }> {
        try {
            await (this.options.delay || defaultDelay)(200);
            const proxyHistory = await this.options.burp.callTool('get_proxy_history', {
                count: 1,
                includeDetails: true,
                urlRegex: url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\?.*/, ''),
            });
            const entry = normalizeProxyHistoryItems(proxyHistory)[0];
            return {
                rawRequest: typeof entry?.request === 'string' ? entry.request : undefined,
                rawResponse: typeof entry?.response === 'string' ? entry.response : undefined,
            };
        } catch (error: any) {
            this.options.log('debug', `Could not fetch raw proxy data: ${error.message}`);
            return {};
        }
    }
}

async function defaultDelay(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
}
