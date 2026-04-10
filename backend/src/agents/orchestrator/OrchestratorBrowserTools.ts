import { browserService } from '../../services/BrowserService';
import { OrchestratorBrowserSession } from './OrchestratorBrowserSession';
import { OrchestratorBrowserRuntime } from './OrchestratorBrowserRuntime';
import { OrchestratorScanSurface } from './OrchestratorScanSurface';
import { ToolCall } from './types';

type LogFn = (channel: 'tool' | 'system' | 'error', message: string) => void;

interface OrchestratorBrowserToolsOptions {
    browserSession: OrchestratorBrowserSession;
    scanSurface: OrchestratorScanSurface;
    log?: LogFn;
    browser?: OrchestratorBrowserRuntime;
    onFrontendDelta?: (trigger: string, newEndpoints: string[]) => void;
}

export class OrchestratorBrowserTools {
    constructor(private readonly options: OrchestratorBrowserToolsOptions) {}

    public async navigate(toolCall: ToolCall<'browser_navigate'>): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        const url = toolCall.args?.url;
        if (!url) return { error: 'Missing required arg: url' };

        this.options.log?.('tool', `browser_navigate -> ${url}`);
        const result = await this.browser.executeAction(sessionId, {
            type: 'goto',
            url,
        });

        this.options.scanSurface.noteBrowserNavigation(url);
        void this.runDeltaFrontendAnalysis('navigation');
        await this.options.browserSession.syncAuthFromBrowser();

        return result;
    }

    public async getPageState(): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        this.options.log?.('tool', 'browser_get_page_state');
        const state = await this.browser.getFullPageState(sessionId);

        this.options.browserSession.syncAuthFromPageState(state, 'primary-user');

        return {
            ...state,
            cookies: state.contextCookies || [],
            localStorage: state.localStorageData || {},
            sessionStorage: state.sessionStorageData || {},
        };
    }

    public async getFrontendAnalysis(): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        this.options.log?.('tool', 'browser_get_frontend_analysis');
        const analysis = await this.browser.getFrontendAnalysis(sessionId);

        await this.options.scanSurface.recordFrontendAnalysis(analysis, 'browser-tool');
        return analysis;
    }

    public async fillAndSubmit(toolCall: ToolCall<'browser_fill_and_submit'>): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        const { fields, submit_selector } = toolCall.args || {};
        if (!fields || !Array.isArray(fields)) {
            return { error: 'Missing required arg: fields (array of {selector, value})' };
        }

        this.options.log?.('tool', `browser_fill_and_submit (${fields.length} fields)`);

        for (const field of fields) {
            if (!field.selector || field.value === undefined) continue;
            await this.browser.executeAction(sessionId, {
                type: 'fill',
                selector: field.selector,
                value: String(field.value),
            });
        }

        if (submit_selector) {
            await this.browser.executeAction(sessionId, {
                type: 'click',
                selector: submit_selector,
            });
            try {
                await this.browser.executeAction(sessionId, {
                    type: 'waitForNavigation',
                    timeout: 5000,
                });
            } catch {
                /* navigation may not happen for AJAX forms */
            }
        }

        const newState = await this.browser.getPageState(sessionId);

        void this.runDeltaFrontendAnalysis('form-submission');
        await this.options.browserSession.syncAuthFromBrowser();

        return {
            submitted: true,
            newUrl: newState?.url || 'unknown',
            newTitle: newState?.title || '',
            forms: newState?.forms?.length || 0,
        };
    }

    public async evaluateJs(toolCall: ToolCall<'browser_evaluate_js'>): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        const script = toolCall.args?.script;
        if (!script) return { error: 'Missing required arg: script' };

        this.options.log?.('tool', `browser_evaluate_js (${String(script).substring(0, 80)}...)`);
        return this.browser.executeAction(sessionId, {
            type: 'evaluate',
            script,
        });
    }

    public async screenshot(): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        this.options.log?.('tool', 'browser_screenshot');

        const result = await this.browser.executeAction(sessionId, {
            type: 'screenshot',
        });

        return {
            captured: true,
            mimeType: result?.mimeType || 'image/png',
            sizeBytes: result?.base64?.length || 0,
            note: 'Screenshot captured and stored. Can be used as finding evidence.',
        };
    }

    public async correlateBurp(): Promise<any> {
        const sessionId = await this.options.browserSession.ensureSession();
        this.options.log?.('tool', 'browser_correlate_burp');
        const correlation = await this.browser.correlateBrowserWithBurp(sessionId);

        this.options.scanSurface.applyBurpCorrelation(correlation);
        return correlation;
    }

    public async runDeltaFrontendAnalysis(trigger: string): Promise<void> {
        const newEndpoints = await this.options.scanSurface.runDeltaFrontendAnalysis(trigger);
        if (newEndpoints.length > 0) {
            this.options.onFrontendDelta?.(trigger, newEndpoints);
        }
    }

    private get browser(): OrchestratorBrowserRuntime {
        return this.options.browser || browserService;
    }
}
