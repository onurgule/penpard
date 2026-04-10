import { IdentityRegistry, RequestAuthDiagnostics, RequestAuthIntent } from '../../services/auth';
import { getHeaderValue } from '../../services/burp-request';
import { hasCustomAuthHeader } from './OrchestratorToolPolicy';
import { ToolCall } from './types';

interface BurpToolClient {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

interface RequestPreparedState {
    headers: Record<string, string>;
    body: string;
}

interface AuthContextSnapshot {
    authorizationHeader?: string | null;
    cookies?: string | null;
    customHeaders: Record<string, string>;
}

interface AuthResponseHealth {
    needsRefresh: boolean;
    needsRelogin: boolean;
    isCSRFFailure: boolean;
}

export interface RequestExecutionContext {
    toolCall: ToolCall<'send_http_request'>;
    url: string;
    method: string;
    identityId: string;
    preserveExplicitAuth: boolean;
    requestIntent: RequestAuthIntent;
    originalHeaders?: Record<string, string>;
    originalBody: string;
    isBurpOriginatedRequest: boolean;
    preparedRequest: RequestPreparedState;
    requestDiagnostics: RequestAuthDiagnostics | null;
    requestArgs: Record<string, any>;
    result: any;
    statusCode: number;
    responseHeaders: Record<string, any> | Array<string>;
    responseBody: string;
}

export interface RequestTransportController {
    reexecute(preparedRequest: RequestPreparedState): Promise<void>;
}

export interface RequestPreparationInterceptor {
    beforeTransport(context: RequestExecutionContext): Promise<void> | void;
}

export interface RequestResponseInterceptor {
    afterResponse(context: RequestExecutionContext, controller: RequestTransportController): Promise<void> | void;
}

export interface RequestPipelineAuthManager {
    inject(
        url: string,
        method?: string,
        identityId?: string,
        intent?: RequestAuthIntent,
    ): AuthContextSnapshot;
    captureFromStructuredRequest(
        request: {
            requestHeaders: Record<string, string>;
            url: string;
            body?: string;
        },
        identityId?: string,
    ): unknown;
    prepareRequest(
        existingHeaders: Record<string, string> | undefined,
        body: string | undefined,
        url: string,
        method?: string,
        identityId?: string,
        preserveExplicitAuth?: boolean,
        intent?: RequestAuthIntent,
    ): RequestPreparedState;
    assessPreparedRequest(opts: {
        originalHeaders?: Record<string, string>;
        preparedHeaders: Record<string, string>;
        url: string;
        method?: string;
        identityId?: string;
        preserveExplicitAuth?: boolean;
        intent?: RequestAuthIntent;
    }): RequestAuthDiagnostics;
    handleResponse(
        statusCode: number,
        headers: Record<string, string> | Array<string>,
        body: string,
        requestUrl: string,
        identityId?: string,
        intent?: RequestAuthIntent,
    ): AuthResponseHealth;
    refreshSession(identityId: string, burpClient: BurpToolClient): Promise<boolean>;
}

interface ManagedAuthRequestInterceptorOptions {
    authManager: RequestPipelineAuthManager;
    burp: BurpToolClient;
    log: (channel: string, message: string) => void;
    onManagedAuthRefreshed?: (identityId: string) => Promise<void>;
}

export class ManagedAuthRequestInterceptor implements RequestPreparationInterceptor, RequestResponseInterceptor {
    constructor(private readonly options: ManagedAuthRequestInterceptorOptions) {}

    public beforeTransport(context: RequestExecutionContext): void {
        const existingAuthContext = this.options.authManager.inject(
            context.url,
            context.method,
            context.identityId,
            context.requestIntent,
        );
        const explicitAuthorization = getHeaderValue(context.originalHeaders, 'authorization');
        const explicitCookie = getHeaderValue(context.originalHeaders, 'cookie');
        const explicitCustomAuth = hasCustomAuthHeader(context.originalHeaders);

        if (
            !context.preserveExplicitAuth &&
            context.identityId !== IdentityRegistry.ANONYMOUS_ID &&
            (
                (!!explicitAuthorization && !existingAuthContext.authorizationHeader) ||
                (!!explicitCookie && !existingAuthContext.cookies) ||
                (explicitCustomAuth && Object.keys(existingAuthContext.customHeaders).length === 0)
            )
        ) {
            this.options.authManager.captureFromStructuredRequest({
                requestHeaders: context.originalHeaders || {},
                url: context.url,
                body: context.originalBody,
            }, context.identityId);
        }

        this.prepareOutgoingRequest(context, context.preserveExplicitAuth);

        if (context.isBurpOriginatedRequest && context.requestDiagnostics?.warning) {
            this.options.log('system', `Auth Warning: ${context.requestDiagnostics.warning}`);
        }
        if (context.requestDiagnostics?.authSuppressedForIntent) {
            this.options.log(
                'system',
                `Auth Guardrail: suppressing stored auth for ${context.requestIntent} on ${context.method} ${context.url}`,
            );
        }
    }

    public async afterResponse(context: RequestExecutionContext, controller: RequestTransportController): Promise<void> {
        let authHealth = this.handleResponse(context);

        if (this.shouldRetryWithManagedAuth(context)) {
            this.options.log(
                'system',
                `Auth Recovery: ${context.method} ${context.url} received 401 without outgoing auth. Retrying once with stored auth material...`,
            );

            this.prepareOutgoingRequest(context, false);

            if (this.hasOutgoingManagedAuth(context.requestDiagnostics)) {
                await controller.reexecute(context.preparedRequest);
                authHealth = this.handleResponse(context);
                context.result = {
                    ...context.result,
                    retriedAfterAuthInjection: true,
                };
            } else {
                this.options.log(
                    'system',
                    `Auth Warning: Stored auth recovery was attempted for ${context.identityId}, but PenPard still could not prepare any auth headers for retry.`,
                );
            }
        }

        if (
            authHealth.needsRefresh &&
            !authHealth.needsRelogin &&
            (!context.preserveExplicitAuth || context.result?.retriedAfterAuthInjection === true) &&
            context.identityId !== IdentityRegistry.ANONYMOUS_ID
        ) {
            this.options.log('system', `Auth State Engine: Session for ${context.identityId} needs refresh - retrying once...`);

            try {
                const refreshed = await this.options.authManager.refreshSession(context.identityId, this.options.burp);
                if (refreshed) {
                    await this.options.onManagedAuthRefreshed?.(context.identityId);

                    const retryPreparedRequest = this.options.authManager.prepareRequest(
                        context.originalHeaders,
                        context.originalBody,
                        context.url,
                        context.method,
                        context.identityId,
                        false,
                        context.requestIntent,
                    );

                    await controller.reexecute(retryPreparedRequest);
                    authHealth = this.handleResponse(context);
                    context.result = {
                        ...context.result,
                        retriedAfterRefresh: true,
                    };
                }
            } catch (error: any) {
                this.options.log('error', `Auth refresh failed: ${error.message}`);
            }
        }

        if (context.requestDiagnostics?.warning) {
            context.result = {
                ...context.result,
                authWarning: context.requestDiagnostics.warning,
            };
        }
        if (authHealth.needsRelogin) {
            this.options.log('system', `Auth State Engine: Session for ${context.identityId} is dead - re-login required`);
        }
        if (authHealth.isCSRFFailure) {
            this.options.log('system', `Auth State Engine: CSRF validation failed for ${context.identityId} - token may need refresh`);
        }
    }

    private prepareOutgoingRequest(context: RequestExecutionContext, preserveExplicitAuth: boolean): void {
        const preparedRequest = this.options.authManager.prepareRequest(
            context.originalHeaders,
            context.originalBody,
            context.url,
            context.method,
            context.identityId,
            preserveExplicitAuth,
            context.requestIntent,
        );

        context.preparedRequest = {
            headers: preparedRequest.headers,
            body: preparedRequest.body,
        };
        context.requestDiagnostics = this.options.authManager.assessPreparedRequest({
            originalHeaders: context.originalHeaders,
            preparedHeaders: preparedRequest.headers,
            url: context.url,
            method: context.method,
            identityId: context.identityId,
            preserveExplicitAuth,
            intent: context.requestIntent,
        });
    }

    private handleResponse(context: RequestExecutionContext): AuthResponseHealth {
        return this.options.authManager.handleResponse(
            context.statusCode,
            context.responseHeaders as Record<string, string> | Array<string>,
            context.responseBody,
            context.url,
            context.identityId,
            context.requestIntent,
        );
    }

    private hasOutgoingManagedAuth(diagnostics: RequestAuthDiagnostics | null): boolean {
        if (!diagnostics) {
            return false;
        }

        return (
            diagnostics.outgoingAuthorizationPresent ||
            diagnostics.outgoingCookiePresent ||
            diagnostics.outgoingCustomAuthPresent
        );
    }

    private shouldRetryWithManagedAuth(context: RequestExecutionContext): boolean {
        const diagnostics = context.requestDiagnostics;
        if (!diagnostics) {
            return false;
        }

        return (
            context.statusCode === 401 &&
            context.identityId !== IdentityRegistry.ANONYMOUS_ID &&
            context.isBurpOriginatedRequest &&
            diagnostics.likelyRequiresAuth &&
            diagnostics.storedAuthAvailable &&
            !diagnostics.outgoingAuthorizationPresent &&
            !diagnostics.outgoingCookiePresent &&
            !diagnostics.outgoingCustomAuthPresent &&
            !diagnostics.explicitAuthorizationKeyPresent &&
            !diagnostics.explicitCookieKeyPresent &&
            !diagnostics.explicitCustomAuthKeyPresent
        );
    }
}
