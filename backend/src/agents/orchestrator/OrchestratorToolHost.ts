import { createBurpToolHandlers, BurpToolClient } from './OrchestratorBurpToolHandlers';
import { OrchestratorBrowserTools } from './OrchestratorBrowserTools';
import { OrchestratorDomainCoordinator } from './OrchestratorDomainCoordinator';
import { OrchestratorRequestExecutor } from './OrchestratorRequestExecutor';
import { evaluateToolExecutionGuard } from './OrchestratorToolPolicy';
import { OrchestratorToolDispatcher } from './OrchestratorToolDispatcher';
import { OrchestratorToolRegistry } from './OrchestratorToolRegistry';
import { ToolCall } from './types';

type LogFn = (channel: string, message: string) => void;

interface OrchestratorToolHostOptions {
    burp: BurpToolClient;
    targetUrl: string;
    requestExecutor: OrchestratorRequestExecutor;
    browserTools: OrchestratorBrowserTools;
    domainCoordinator: OrchestratorDomainCoordinator;
    isFocusedScope: () => boolean;
    getRateLimitPauseUntil: () => Date | null;
    log: LogFn;
}

export class OrchestratorToolHost {
    private readonly registry: OrchestratorToolRegistry;
    private readonly dispatcher: OrchestratorToolDispatcher;

    constructor(private readonly options: OrchestratorToolHostOptions) {
        this.registry = new OrchestratorToolRegistry({
            handlers: {
                ...createBurpToolHandlers({ burp: options.burp, targetUrl: options.targetUrl }),
                send_http_request: (toolCall) => options.requestExecutor.execute(toolCall as ToolCall<'send_http_request'>),
                browser_navigate: (toolCall) => options.browserTools.navigate(toolCall as ToolCall<'browser_navigate'>),
                browser_get_page_state: () => options.browserTools.getPageState(),
                browser_get_frontend_analysis: () => options.browserTools.getFrontendAnalysis(),
                browser_fill_and_submit: (toolCall) => options.browserTools.fillAndSubmit(toolCall as ToolCall<'browser_fill_and_submit'>),
                browser_evaluate_js: (toolCall) => options.browserTools.evaluateJs(toolCall as ToolCall<'browser_evaluate_js'>),
                browser_screenshot: () => options.browserTools.screenshot(),
                browser_correlate_burp: () => options.browserTools.correlateBurp(),
                harvest_traffic: () => options.domainCoordinator.executeHarvestTraffic(),
                get_hypotheses: (toolCall) => options.domainCoordinator.executeGetHypotheses(toolCall as ToolCall<'get_hypotheses'>),
                get_coverage: () => options.domainCoordinator.executeGetCoverage(),
                repeater_test: (toolCall) => options.domainCoordinator.executeRepeaterTest(toolCall as ToolCall<'repeater_test'>),
            },
        });

        this.dispatcher = new OrchestratorToolDispatcher({
            log: options.log,
            guard: (toolCall) => {
                const guardResult = evaluateToolExecutionGuard({
                    toolName: toolCall.tool,
                    isFocusedScope: options.isFocusedScope(),
                    rateLimitPauseUntil: options.getRateLimitPauseUntil(),
                });

                if (!guardResult.allowed && guardResult.logMessage) {
                    options.log('tool', guardResult.logMessage);
                }

                return guardResult.allowed ? null : guardResult.response;
            },
            handlers: this.registry.getHandlers(),
        });
    }

    public getParserToolRegistry(): Pick<OrchestratorToolRegistry, 'isKnown' | 'normalizeToolCall'> {
        return this.registry;
    }

    public async execute(toolCall: ToolCall): Promise<any> {
        return this.dispatcher.execute(toolCall);
    }
}
