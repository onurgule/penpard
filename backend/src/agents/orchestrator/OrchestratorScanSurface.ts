import { saveScanAuthInventory, saveScanEndpointInventory } from '../../db/init';
import { CoverageTracker } from '../../services/CoverageTracker';
import { browserService } from '../../services/BrowserService';
import { EndpointIntelligenceService, EndpointInventorySnapshot } from '../../services/EndpointIntelligenceService';
import { AuthStartupConfig, AuthStartupInventory, AuthStateManager } from '../../services/auth';
import { WebAuthStartupService } from '../../services/WebAuthStartupService';
import { OrchestratorBrowserSession } from './OrchestratorBrowserSession';

/** Narrow interface — the scan surface only needs callTool from the Burp client */
interface ScanSurfaceBurp {
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

type LogFn = (channel: 'system' | 'error' | 'debug', message: string) => void;

interface EndpointInventoryBuildArgs {
    browserSessionId: string;
    authInventory: AuthStartupInventory | null;
    allowAiClassification: boolean;
}

interface AuthStartupRunResult {
    browserSessionId: string;
    inventory: AuthStartupInventory;
}

interface OrchestratorScanSurfaceOptions {
    scanId: string;
    userId?: number;
    targetUrl: string;
    burp: ScanSurfaceBurp;
    authManager: AuthStateManager;
    browserSession: OrchestratorBrowserSession;
    coverageTracker: CoverageTracker;
    log?: LogFn;
    buildEndpointInventory?: (args: EndpointInventoryBuildArgs) => Promise<EndpointInventorySnapshot>;
    runAuthStartup?: (config: AuthStartupConfig) => Promise<AuthStartupRunResult>;
    persistAuthInventory?: (scanId: string, inventoryJson: string) => void;
    persistEndpointInventory?: (scanId: string, inventoryJson: string) => void;
    browser?: Pick<typeof browserService, 'getFrontendAnalysis' | 'isSessionAlive'>;
}

export class OrchestratorScanSurface {
    private readonly discoveredEndpoints = new Set<string>();
    private startupAuthInventory: AuthStartupInventory | null = null;
    private endpointInventory: EndpointInventorySnapshot | null = null;

    constructor(private readonly options: OrchestratorScanSurfaceOptions) {}

    public restoreDiscoveredEndpoints(endpoints: Iterable<string>): number {
        for (const endpoint of endpoints) {
            this.addDiscoveredEndpoint(endpoint);
        }
        return this.discoveredEndpoints.size;
    }

    public getDiscoveredEndpoints(): string[] {
        return Array.from(this.discoveredEndpoints);
    }

    public getDiscoveredEndpointCount(): number {
        return this.discoveredEndpoints.size;
    }

    public getDiscoveredEndpointPreview(limit: number = 25): string[] {
        return this.getDiscoveredEndpoints().slice(0, limit);
    }

    public hasDiscoveredEndpoint(endpoint: string): boolean {
        return this.discoveredEndpoints.has(endpoint);
    }

    public noteRequestDiscoveredEndpoint(url: string): void {
        try {
            const parsed = new URL(url);
            this.addDiscoveredEndpoint(parsed.pathname);
        } catch {
            /* ignore malformed discoveries from request execution */
        }
    }

    public recordRequestExecution(event: { url: string; method?: string; statusCode?: number }): void {
        try {
            const parsed = new URL(event.url);
            const method = String(event.method || 'GET').toUpperCase();
            this.addDiscoveredEndpoint(parsed.pathname);
            this.options.coverageTracker.addRoute(parsed.pathname, method, 'burp');
            this.options.coverageTracker.inferWorkflowFromRoute(parsed.pathname);
        } catch {
            /* ignore malformed request aftermath */
        }
    }

    public noteBrowserNavigation(url: string): void {
        try {
            const pathname = new URL(url).pathname;
            this.addDiscoveredEndpoint(pathname);
            this.options.coverageTracker.markExercisedInBrowser(pathname, 'GET');
            this.options.coverageTracker.inferWorkflowFromRoute(pathname);
        } catch {
            /* ignore malformed URLs */
        }
    }

    public async recordFrontendAnalysis(analysis: any, trigger: string = 'browser-tool'): Promise<string[]> {
        const newEndpoints = this.collectNewEndpoints(Array.isArray(analysis?.apiEndpoints) ? analysis.apiEndpoints : []);
        await this.refreshEndpointInventory(trigger, false);
        return newEndpoints;
    }

    public async runDeltaFrontendAnalysis(trigger: string): Promise<string[]> {
        const browserSessionId = this.options.browserSession.getSessionId();
        if (!browserSessionId) return [];

        this.options.log?.('system', `Delta frontend analysis (trigger: ${trigger})`);
        try {
            const browser = this.options.browser || browserService;
            if (!browser.isSessionAlive(browserSessionId)) {
                return [];
            }

            const newAnalysis = await browser.getFrontendAnalysis(browserSessionId);
            const newEndpoints = (Array.isArray(newAnalysis?.apiEndpoints) ? newAnalysis.apiEndpoints : []).filter(
                (endpoint: string) => !this.discoveredEndpoints.has(endpoint),
            );

            if (newEndpoints.length > 0) {
                newEndpoints.forEach((endpoint: string) => {
                    this.addDiscoveredEndpoint(endpoint);
                    this.options.coverageTracker.addRoute(endpoint, 'GET', 'frontend-js');
                });
                this.options.log?.('system', `✓ Delta analysis: ${newEndpoints.length} new endpoint(s) discovered`);
            }

            if (Array.isArray(newAnalysis?.frontendRoutes)) {
                newAnalysis.frontendRoutes.forEach((route: string) => {
                    this.options.coverageTracker.addRoute(route, 'GET', 'frontend-js');
                });
            }

            if (newEndpoints.length > 0) {
                await this.refreshEndpointInventory(`delta-${trigger}`, false);
            }

            return newEndpoints;
        } catch (error: any) {
            this.options.log?.('error', `Delta frontend analysis failed (non-fatal): ${error.message}`);
            return [];
        }
    }

    public applyBurpCorrelation(correlation: any): string[] {
        const newEndpoints = this.collectNewEndpoints(
            Array.isArray(correlation?.frontendOnlyEndpoints) ? correlation.frontendOnlyEndpoints : [],
        );

        if (newEndpoints.length > 0) {
            this.options.log?.('system', `Browser⇔Burp correlation: ${newEndpoints.length} untested endpoints found`);
        }

        return newEndpoints;
    }

    public async runAuthStartup(authStartup: AuthStartupConfig): Promise<void> {
        this.options.log?.('system', 'Starting browser-first auth discovery before normal planning...');

        const runner = this.options.runAuthStartup || (async (config: AuthStartupConfig) => {
            const service = new WebAuthStartupService(
                this.options.scanId,
                this.options.userId || 1,
                this.options.targetUrl,
                this.options.burp as any,
                this.options.authManager,
                (kind, message) => this.options.log?.(kind === 'burp' ? 'debug' : kind, message),
            );
            return service.run(config);
        });

        const { browserSessionId, inventory } = await runner(authStartup);
        this.options.browserSession.setSessionId(browserSessionId);
        await this.captureAuthStartupInventory(inventory);
    }

    public async refreshEndpointInventory(trigger: string, allowAiClassification: boolean = false): Promise<void> {
        const browserSessionId = this.options.browserSession.getSessionId();
        if (!browserSessionId) return;

        try {
            const inventory = await (this.options.buildEndpointInventory || ((args: EndpointInventoryBuildArgs) => {
                const service = new EndpointIntelligenceService(
                    this.options.scanId,
                    this.options.targetUrl,
                    this.options.burp as any,
                    (level, message) => this.options.log?.(
                        level === 'error' ? 'error' : level === 'system' ? 'system' : 'debug',
                        message,
                    ),
                );
                return service.buildInventory({
                    browserSessionId: args.browserSessionId,
                    authInventory: args.authInventory,
                    allowAiClassification: args.allowAiClassification,
                });
            }))({
                browserSessionId,
                authInventory: this.startupAuthInventory,
                allowAiClassification,
            });

            this.endpointInventory = inventory;
            (this.options.persistEndpointInventory || saveScanEndpointInventory)(
                this.options.scanId,
                JSON.stringify(inventory),
            );
            this.options.log?.('system', `✓ Endpoint intelligence refreshed (${trigger}): ${inventory.summary}`);
        } catch (error: any) {
            this.options.log?.('error', `Endpoint intelligence refresh failed (${trigger}): ${error.message}`);
        }
    }

    public getStartupAuthInventory(): AuthStartupInventory | null {
        return this.startupAuthInventory;
    }

    public getEndpointInventory(): EndpointInventorySnapshot | null {
        return this.endpointInventory;
    }

    public buildStartupAuthPromptBlock(): string {
        if (!this.startupAuthInventory) return '';
        return `\n\n================================================================
  WEB AUTH STARTUP INVENTORY (captured before planning)
================================================================

${this.buildStartupAuthSummary()}

Rules for subsequent work:
- Browser-driven auth discovery already ran before the first plan.
- Use this inventory as evidence, not as a guess.
- Reuse captured cookies, tokens, CSRF values, and identity state instead of rebuilding auth assumptions.
- Keep round 1 auth-surface-first unless operator instructions explicitly narrow scope elsewhere.
`;
    }

    public buildEndpointInventoryPromptBlock(): string {
        if (!this.endpointInventory) return '';
        return `\n\n================================================================
  ENDPOINT INTELLIGENCE (browser + JS + Burp)
================================================================

${this.buildEndpointInventorySummary()}

Rules for subsequent work:
- Treat these endpoints and classifications as structured evidence gathered from rendered DOM, loaded JavaScript, browser execution, and Burp traffic.
- Prioritize auth-relevant endpoints early, especially login/register/reset/session-bootstrap/auth-refresh/admin routes.
- Do not waste time on socket polling, HMR, or other noise already filtered from this inventory.
`;
    }

    public buildStartupAuthSummary(): string {
        if (!this.startupAuthInventory) {
            return 'No startup auth inventory was captured.';
        }

        const inventory = this.startupAuthInventory;
        const formLines = inventory.forms.slice(0, 8).map((form) => {
            const visibleFields = form.fields
                .slice(0, 8)
                .map((field) => `${field.name || field.id || 'unnamed'}:${field.type}`)
                .join(', ') || 'no fields';
            const hidden = form.hiddenInputs
                .slice(0, 5)
                .map((field) => field.name || field.id || 'hidden')
                .join(', ') || 'none';
            return `- [${form.type}] ${form.method} ${form.action || '(same page)'} fields=${visibleFields} hidden=${hidden}`;
        }).join('\n') || '- none';

        const elementLines = inventory.domElements.slice(0, 10).map((element) =>
            `- [${element.type}] ${element.tagName} text="${element.text}" selector=${element.selector || 'n/a'} href=${element.href || element.action || ''}`,
        ).join('\n') || '- none';

        const credentialLines = inventory.discoveredCredentials.slice(0, 10).map((credential) =>
            `- ${credential.identityId || 'unknown'} ${credential.label || credential.username || credential.email || 'credential'} created=${credential.created ? 'yes' : 'no'} success=${credential.success ? 'yes' : 'no'} role=${credential.role || 'unknown'} privilege=${credential.privilege || 'unknown'}`,
        ).join('\n') || '- none';

        const blockerLines = inventory.blockers.slice(0, 8).map((blocker) => `- ${blocker}`).join('\n') || '- none';

        return [
            `Startup mode: ${inventory.mode}`,
            `Summary: ${inventory.summary}`,
            `Browser session: ${inventory.browserSessionId || 'not available'}`,
            `Registration available: ${inventory.registrationAvailable ? 'yes' : 'no'}`,
            `Password reset available: ${inventory.passwordResetAvailable ? 'yes' : 'no'}`,
            `Activation required: ${inventory.activationRequired ? 'yes' : 'no'}`,
            `SSO providers: ${inventory.ssoProviders.join(', ') || 'none'}`,
            `Auth routes: ${inventory.authRoutes.join(', ') || 'none'}`,
            `Forms:\n${formLines}`,
            `DOM auth controls:\n${elementLines}`,
            `Credentials:\n${credentialLines}`,
            `Transport: ${[
                inventory.transport.authorizationSchemes.length > 0 ? `authorization=${inventory.transport.authorizationSchemes.join(',')}` : '',
                inventory.transport.cookieNames.length > 0 ? `cookies=${inventory.transport.cookieNames.slice(0, 8).join(',')}` : '',
                inventory.transport.localStorageKeys.length > 0 ? `localStorage=${inventory.transport.localStorageKeys.slice(0, 8).join(',')}` : '',
                inventory.transport.sessionStorageKeys.length > 0 ? `sessionStorage=${inventory.transport.sessionStorageKeys.slice(0, 8).join(',')}` : '',
                inventory.transport.csrfHeaders.length > 0 ? `csrfHeaders=${inventory.transport.csrfHeaders.join(',')}` : '',
                inventory.transport.csrfFormFields.length > 0 ? `csrfFields=${inventory.transport.csrfFormFields.join(',')}` : '',
            ].filter(Boolean).join(' | ') || 'none observed'}`,
            `Blockers:\n${blockerLines}`,
        ].join('\n');
    }

    public buildEndpointInventorySummary(): string {
        if (!this.endpointInventory) {
            return 'No endpoint intelligence was captured.';
        }

        const inventory = this.endpointInventory;
        const endpointLines = inventory.records.slice(0, 20).map((record) => {
            const method = record.methods.join(', ') || 'GET';
            const observed = `${record.observedInBurp ? 'burp' : 'no-burp'} / ${record.exercisedInBrowser ? 'browser' : 'not-browser'}`;
            return `- [${record.classification}] ${method} ${record.path} source=${record.primarySource} confidence=${record.confidence} observed=${observed} inferredOnly=${record.inferredOnly ? 'yes' : 'no'}`;
        }).join('\n') || '- none';

        const authLines = inventory.records
            .filter((record) => record.likelyAuthRelevant)
            .slice(0, 12)
            .map((record) => `- ${record.path} (${record.classification})`)
            .join('\n') || '- none';

        return [
            `Summary: ${inventory.summary}`,
            `JS artifacts: ${inventory.jsArtifacts.count} captured, ${inventory.jsArtifacts.totalBytes} bytes analyzed`,
            `Auth-relevant endpoints:\n${authLines}`,
            `Top records:\n${endpointLines}`,
        ].join('\n');
    }

    private async captureAuthStartupInventory(inventory: AuthStartupInventory): Promise<void> {
        this.startupAuthInventory = inventory;

        try {
            (this.options.persistAuthInventory || saveScanAuthInventory)(
                this.options.scanId,
                JSON.stringify(inventory),
            );
        } catch (error: any) {
            this.options.log?.('error', `Failed to persist auth startup inventory: ${error.message}`);
        }

        inventory.authRoutes.forEach((route) => {
            if (typeof route !== 'string' || !route.trim()) return;
            try {
                const absolute = route.startsWith('http') ? route : new URL(route, this.options.targetUrl).toString();
                this.addDiscoveredEndpoint(absolute);
                this.options.coverageTracker.addRoute(new URL(absolute).pathname, 'GET', 'browser-navigation');
            } catch {
                this.addDiscoveredEndpoint(route);
            }
        });

        inventory.traffic.forEach((entry) => {
            if (!entry?.url) return;
            this.addDiscoveredEndpoint(entry.url);
            try {
                const parsed = new URL(entry.url);
                this.options.coverageTracker.addRoute(
                    parsed.pathname,
                    entry.method || 'GET',
                    entry.source === 'browser' ? 'browser-navigation' : 'burp',
                );
            } catch {
                /* ignore malformed URLs */
            }
        });

        this.options.log?.('system', `✓ Auth startup inventory captured: ${inventory.summary}`);
        await this.refreshEndpointInventory('startup', true);
    }

    private collectNewEndpoints(endpoints: string[]): string[] {
        const newEndpoints: string[] = [];
        endpoints.forEach((endpoint) => {
            if (typeof endpoint !== 'string' || !endpoint.trim() || this.discoveredEndpoints.has(endpoint)) {
                return;
            }
            this.discoveredEndpoints.add(endpoint);
            newEndpoints.push(endpoint);
        });
        return newEndpoints;
    }

    private addDiscoveredEndpoint(endpoint: string): void {
        if (typeof endpoint !== 'string' || !endpoint.trim()) {
            return;
        }
        this.discoveredEndpoints.add(endpoint);
    }
}
