import { AuthStateManager, RequestAuthIntent } from '../../services/auth';
import { normalizeProxyHistoryItems, normalizeSendHttpResponse } from '../../services/burp-tool-result';
import { resolveAuthIdentityId, resolveRequestAuthIntent } from './OrchestratorToolPolicy';
import {
    applyStoredInitialRequestBodyMutations,
    applyStoredInitialRequestQueryMutations,
    type InitialRequestProfile,
    mergeStoredInitialRequestHeaders,
    parseInitialRequestProfile,
} from './OrchestratorInitialRequestProfile';
import {
    ManagedAuthRequestInterceptor,
    RequestExecutionContext,
    RequestPreparationInterceptor,
    RequestResponseInterceptor,
    RequestTransportController,
} from './OrchestratorRequestPipeline';
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

export interface RequestExecutionAftermath {
    url: string;
    method: string;
    statusCode: number;
    identityId: string;
    requestIntent: RequestAuthIntent;
    result: any;
    rawRequest?: string;
    rawResponse?: string;
}

export interface OrchestratorRequestExecutorOptions {
    scanId: string;
    burp: BurpToolClient;
    authManager: AuthStateManager;
    initialRequest?: string;
    log: (channel: string, message: string) => void;
    delay?: (ms: number) => Promise<void>;
    maxSameRequest?: number;
    disableDuplicateResponseCache?: boolean;
    rateLimitPauseMs: number;
    setRateLimitPauseUntil: (until: Date | null) => void;
    onRequestAftermath?: (aftermath: RequestExecutionAftermath) => Promise<void> | void;
    onManagedAuthRefreshed?: (identityId: string) => Promise<void>;
}

export class OrchestratorRequestExecutor {
    private readonly requestHistory = new Map<string, RequestHistoryEntry>();
    private readonly preparationInterceptors: RequestPreparationInterceptor[];
    private readonly responseInterceptors: RequestResponseInterceptor[];
    private readonly initialRequestProfile: InitialRequestProfile | null;
    private lastExchange: RequestExecutionExchange | null = null;

    constructor(private readonly options: OrchestratorRequestExecutorOptions) {
        this.initialRequestProfile = this.options.initialRequest?.trim()
            ? parseInitialRequestProfile(this.options.initialRequest.trim())
            : null;

        const authInterceptor = new ManagedAuthRequestInterceptor({
            authManager: this.options.authManager,
            burp: this.options.burp,
            log: this.options.log,
            onManagedAuthRefreshed: this.options.onManagedAuthRefreshed,
        });

        this.preparationInterceptors = [authInterceptor];
        this.responseInterceptors = [authInterceptor];
    }

    public getLastExchange(): RequestExecutionExchange | null {
        return this.lastExchange;
    }

    public async execute(toolCall: ToolCall<'send_http_request'>): Promise<any> {
        const context = this.buildExecutionContext(toolCall);
        const blocked = this.enforceRequestGuardrails(context);
        if (blocked) {
            return blocked;
        }

        await this.runPreparationInterceptors(context);

        const requestHistoryKey = this.buildRequestHistoryKey(
            context.method,
            context.url,
            context.preparedRequest.body,
            context.preparedRequest.headers,
            context.identityId,
        );
        const cached = this.getCachedDuplicateResponse(requestHistoryKey, context);
        if (cached) {
            return cached;
        }

        await this.executeTransport(context, context.preparedRequest);
        await this.runResponseInterceptors(context);
        this.applyRuntimeFinalization(context);
        await this.captureProxyEvidence(context);
        this.recordRequestHistory(requestHistoryKey, context);
        await this.runRequestAftermath(context);

        return context.result;
    }

    private buildExecutionContext(toolCall: ToolCall<'send_http_request'>): RequestExecutionContext {
        const preserveExplicitAuth = toolCall.args?.preserveExplicitAuth === true;
        const useInitialRequestBaseline = toolCall.args?.useInitialRequestBaseline === true && !!this.initialRequestProfile;
        const advisoryReason = typeof (toolCall.args as Record<string, any> | undefined)?.__advisoryReason === 'string'
            ? (toolCall.args as Record<string, any>).__advisoryReason as string
            : undefined;
        const explicitHeaders = this.normalizeRequestHeaders(toolCall.args.headers as Record<string, string> | undefined);
        const hasExplicitBody = Object.prototype.hasOwnProperty.call(toolCall.args, 'body')
            || Object.prototype.hasOwnProperty.call(toolCall.args, 'data');
        const explicitBody = hasExplicitBody
            ? this.normalizeRequestBody(toolCall.args.body ?? toolCall.args.data ?? '')
            : undefined;
        const baselineBody = explicitBody !== undefined
            ? explicitBody
            : useInitialRequestBaseline
                ? applyStoredInitialRequestBodyMutations(
                    this.initialRequestProfile?.body || '',
                    this.initialRequestProfile?.contentType,
                    toolCall.args.bodyMutations,
                )
                : '';
        const requestedUrl = typeof toolCall.args.url === 'string' ? toolCall.args.url : '';
        const baseUrl = useInitialRequestBaseline
            ? (!requestedUrl || requestedUrl.includes('<preserved>'))
                ? this.initialRequestProfile?.url || ''
                : requestedUrl
            : requestedUrl;
        const url = applyStoredInitialRequestQueryMutations(baseUrl, toolCall.args.queryMutations);
        const method = toolCall.args.method || (useInitialRequestBaseline ? this.initialRequestProfile?.method : undefined) || 'GET';
        const identityId = resolveAuthIdentityId(toolCall.args);
        const originalBody = baselineBody;
        const originalHeaders = useInitialRequestBaseline
            ? mergeStoredInitialRequestHeaders(this.initialRequestProfile, explicitHeaders, true)
            : explicitHeaders;
        const requestIntent = resolveRequestAuthIntent({
            requestedIntent: toolCall.args.requestIntent,
            identityId,
            inferIntent: () => this.options.authManager.inferRequestIntent(url, method),
        });

        return {
            toolCall,
            url,
            method,
            identityId,
            preserveExplicitAuth,
            requestIntent,
            originalHeaders,
            originalBody,
            isBurpOriginatedRequest: !!this.options.initialRequest?.trim(),
            preparedRequest: {
                headers: { ...(originalHeaders || {}) },
                body: originalBody,
            },
            requestDiagnostics: null,
            requestArgs: {},
            advisoryReason,
            result: null,
            statusCode: 0,
            responseHeaders: {},
            responseBody: '',
        };
    }

    private enforceRequestGuardrails(context: RequestExecutionContext): any | null {
        const decodedUrl = (() => {
            try {
                return decodeURIComponent(context.url);
            } catch {
                return context.url;
            }
        })();
        const unionNullMatch = decodedUrl.match(/union\s+select\s+null(?:,\s*null)*/gi);
        if (!unionNullMatch) {
            return null;
        }

        const nullCount = (unionNullMatch[0].match(/null/gi) || []).length;
        if (nullCount < 5) {
            return null;
        }

        this.options.log('tool', `Blocked SQLMap-style payload (${nullCount} nulls). Use send_to_scanner.`);
        const baseUrl = context.url.split('?')[0];
        return {
            error: `SQLMap-style fuzzing blocked. Use send_to_scanner with ${baseUrl} instead.`,
            blocked: true,
            suggestion: { tool: 'send_to_scanner', args: { url: baseUrl } },
        };
    }

    private async runPreparationInterceptors(context: RequestExecutionContext): Promise<void> {
        for (const interceptor of this.preparationInterceptors) {
            await interceptor.beforeTransport(context);
        }
    }

    private getCachedDuplicateResponse(requestHistoryKey: string, context: RequestExecutionContext): any | null {
        if (this.options.disableDuplicateResponseCache) {
            return null;
        }

        const existing = this.requestHistory.get(requestHistoryKey);
        if (!existing || existing.count < (this.options.maxSameRequest ?? 2)) {
            return null;
        }

        this.options.log(
            'tool',
            `Skipping exact duplicate request (${existing.count}x): ${context.method} ${context.url.substring(0, 80)}`,
        );
        return {
            ...existing.lastResponse,
            cached: true,
            skipped: true,
            requestSent: false,
            burpVisible: false,
            message: `Cached response. This exact request was sent ${existing.count} times already. Try different parameters or payloads.`,
        };
    }

    private async executeTransport(
        context: RequestExecutionContext,
        preparedRequest: RequestExecutionContext['preparedRequest'],
    ): Promise<void> {
        const requestArgs = {
            ...context.toolCall.args,
            url: context.url,
            method: context.method,
            headers: preparedRequest.headers,
            body: preparedRequest.body,
            identityId: context.identityId,
        } as Record<string, any>;
        delete requestArgs.data;
        delete requestArgs.queryMutations;
        delete requestArgs.bodyMutations;
        delete requestArgs.useInitialRequestBaseline;
        delete requestArgs.__advisoryReason;

        context.preparedRequest = preparedRequest;
        context.requestArgs = requestArgs;

        const advisorySource = context.advisoryReason
            ? `/advisory:${encodeURIComponent(context.advisoryReason).slice(0, 64)}`
            : '';

        const normalizedResult = this.normalizeBurpHttpResult(
            await this.options.burp.callTool('send_http_request', {
                ...requestArgs,
                use_proxy: true,
                penpard_source: `Orchestrator/${this.options.scanId}${advisorySource}`,
            }),
        );

        this.applyResponseNormalization(context, normalizedResult);
    }

    private applyResponseNormalization(context: RequestExecutionContext, normalizedResult: NormalizedBurpHttpResult): void {
        context.result = normalizedResult.result;
        context.statusCode = normalizedResult.statusCode;
        context.responseHeaders = normalizedResult.responseHeaders;
        context.responseBody = normalizedResult.responseBody;
    }

    private async runResponseInterceptors(context: RequestExecutionContext): Promise<void> {
        const transportController: RequestTransportController = {
            reexecute: async (preparedRequest) => this.executeTransport(context, preparedRequest),
        };

        for (const interceptor of this.responseInterceptors) {
            await interceptor.afterResponse(context, transportController);
        }
    }

    private applyRuntimeFinalization(context: RequestExecutionContext): void {
        if (context.statusCode !== 429) {
            return;
        }

        this.options.setRateLimitPauseUntil(new Date(Date.now() + this.options.rateLimitPauseMs));
        this.options.log('tool', '429 Rate Limited! Pausing for 1 minute...');
        context.result = {
            ...context.result,
            rateLimited: true,
            message: 'Rate limited. Pausing 1 minute.',
        };
    }

    private async captureProxyEvidence(context: RequestExecutionContext): Promise<void> {
        const evidence = await this.getLatestProxyEvidence(context.url);
        this.lastExchange = {
            action: {
                ...context.toolCall,
                args: context.requestArgs,
            },
            result: context.result,
            rawRequest: evidence.rawRequest,
            rawResponse: evidence.rawResponse,
        };
    }

    private recordRequestHistory(requestHistoryKey: string, context: RequestExecutionContext): void {
        const existing = this.requestHistory.get(requestHistoryKey);
        this.requestHistory.set(requestHistoryKey, {
            count: (existing?.count || 0) + 1,
            lastResponse: context.result,
            timestamp: new Date(),
        });
    }

    private async runRequestAftermath(context: RequestExecutionContext): Promise<void> {
        await this.options.onRequestAftermath?.({
            url: context.url,
            method: context.method,
            statusCode: context.statusCode,
            identityId: context.identityId,
            requestIntent: context.requestIntent,
            result: context.result,
            rawRequest: this.lastExchange?.rawRequest,
            rawResponse: this.lastExchange?.rawResponse,
        });
    }

    private normalizeRequestBody(rawBody: any): string {
        if (rawBody === undefined || rawBody === null) return '';
        if (typeof rawBody === 'string') return rawBody;
        return JSON.stringify(rawBody);
    }

    private normalizeRequestHeaders(headers: Record<string, string> | undefined): Record<string, string> | undefined {
        if (!headers) {
            return undefined;
        }

        return Object.fromEntries(
            Object.entries(headers).map(([name, value]) => [name, String(value)]),
        );
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
