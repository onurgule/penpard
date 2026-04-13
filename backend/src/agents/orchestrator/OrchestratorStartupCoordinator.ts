/**
 * OrchestratorStartupCoordinator
 *
 * Owns the deterministic, runtime-environment preparation steps that must
 * complete before the agent's first planning round:
 *
 *   1. Burp readiness check + target scope registration
 *   2. LLM readiness / active-config check
 *   3. Mindset library (TTP) loading
 *   4. Auth state engine initialization
 *   5. Browser-first auth startup orchestration
 *   6. Source analysis execution
 *
 * Returns a typed `StartupResult` that the agent consumes for
 * prompt assembly and conversation seeding.
 *
 * Does NOT own:
 *   - System prompt assembly (reasoning-adjacent — the agent decides what the
 *     LLM sees)
 *   - Operator instruction analysis (requires LLM call and mutates agent
 *     reasoning state: isFocusedScope, instructionAnalysis)
 *   - Context message injection into conversation history
 *   - Initial request message injection
 *   - Phase transitions and scan-status updates
 *
 * Design rationale:
 *   This class is a deterministic startup pipeline. Every step either succeeds,
 *   fails with a logged error and continues, or throws a fatal error (LLM
 *   missing). The output is a pure data product with no side-effects on agent
 *   reasoning state.
 */

import { MindsetTTP } from '../../services/mindset-service';
import { AuthStartupConfig, AuthStartupMode } from '../../services/auth';
import { SourceAnalysisMode } from '../../services/source-analysis/SourceAnalysisMode';

// ── Narrow interfaces for injectable dependencies ──

export interface StartupBurpClient {
    isAvailable(): Promise<boolean>;
    callTool(tool: string, args: Record<string, any>): Promise<any>;
}

export interface StartupLlmCheck {
    hasActiveConfig(): boolean;
}

export interface StartupMindsetLoader {
    getRelevantTTPs(targetUrl: string): MindsetTTP[];
}

export interface StartupAuthManagerInit {
    initialize(
        config: {
            sessionCookies?: string;
            idorUsers?: any[];
            initialRequest?: string;
            authStartup: AuthStartupConfig;
        },
        burp: StartupBurpClient,
        browserSessionId: string | null,
    ): Promise<void>;

    identityRegistry: { size: number };
    getTotalCookies(): number;
    getTotalTokens(): number;
    getSystemPromptBlock(): string;
}

export interface StartupScanSurface {
    runAuthStartup(config: AuthStartupConfig): Promise<void>;
    buildStartupAuthPromptBlock(): string;
    buildEndpointInventoryPromptBlock(): string;
    getStartupAuthInventory(): any | null;
    getEndpointInventory(): any | null;
    buildStartupAuthSummary(): string;
    buildEndpointInventorySummary(): string;
}

export interface StartupBrowserSession {
    getSessionId(): string | null;
}

export interface StartupSourceAnalyzer {
    analyzeSource(scanId: string, packagePath: string, mode: SourceAnalysisMode): Promise<any>;
    buildAgentContextBlock(result: any): string;
}

type LogFn = (channel: string, message: string) => void;

// ── Startup configuration ──

export interface StartupConfig {
    scanId: string;
    targetUrl: string;
    sessionCookies?: string;
    idorUsers?: any[];
    initialRequest?: string;
    authStartup?: AuthStartupConfig;
    useMindsetLibrary?: boolean;
    sourcePackagePath?: string;
    sourceAnalysisMode?: string;
}

// ── Startup result — the typed data product ──

export interface StartupResult {
    /** Mindset TTPs loaded from past report analyses. Empty if none available or disabled. */
    mindsetTTPs: MindsetTTP[];

    /** Source analysis context block for system prompt injection. Empty string if not applicable. */
    sourceContextBlock: string;

    /** Auth state engine system prompt block. */
    sessionCookiesBlock: string;

    /** Web auth startup inventory prompt block. */
    startupAuthBlock: string;

    /** Endpoint intelligence prompt block. */
    endpointInventoryBlock: string;
}

// ── Dependencies bag ──

export interface StartupCoordinatorDeps {
    burp: StartupBurpClient;
    llm: StartupLlmCheck;
    mindset: StartupMindsetLoader;
    authManager: StartupAuthManagerInit;
    scanSurface: StartupScanSurface;
    browserSession: StartupBrowserSession;
    sourceAnalyzer?: StartupSourceAnalyzer;
    log: LogFn;
}

// ── The coordinator ──

export class OrchestratorStartupCoordinator {
    constructor(private readonly deps: StartupCoordinatorDeps) {}

    /**
     * Execute the deterministic startup pipeline.
     *
     * Ordering contract:
     *   1. Burp → must be available for auth startup and scanning
     *   2. LLM → fatal if missing (no point continuing)
     *   3. Mindset → data load, no dependencies
     *   4. Auth state engine init → before browser auth startup
     *   5. Auth startup (browser-first) → before source analysis
     *   6. Source analysis → after auth so planning always sees auth first
     *
     * @throws Error if LLM is not configured (hard requirement).
     */
    public async run(config: StartupConfig): Promise<StartupResult> {
        // ── 1. Burp readiness check ──
        await this.checkBurpReadiness(config.targetUrl);

        // ── 2. LLM readiness check ──
        this.checkLlmReadiness();

        // ── 3. Mindset library loading ──
        const mindsetTTPs = this.loadMindsetTTPs(config);

        // ── 4. Auth state engine initialization ──
        await this.initializeAuthEngine(config);

        // ── 5. Browser-first auth startup ──
        const authStartup = config.authStartup || {
            mode: 'no_credentials' as AuthStartupMode,
            credentials: [],
            allowAccountCreation: false,
            preferSharedPassword: true,
        };
        await this.runAuthStartup(authStartup);

        // ── 6. Source analysis ──
        const sourceContextBlock = await this.runSourceAnalysis(config);

        // ── Collect prompt blocks from auth/endpoint inventories ──
        const sessionCookiesBlock = this.deps.authManager.getSystemPromptBlock();
        const startupAuthBlock = this.deps.scanSurface.buildStartupAuthPromptBlock();
        const endpointInventoryBlock = this.deps.scanSurface.buildEndpointInventoryPromptBlock();

        return {
            mindsetTTPs,
            sourceContextBlock,
            sessionCookiesBlock,
            startupAuthBlock,
            endpointInventoryBlock,
        };
    }

    // ────────────────────────────────────────────────────────────

    private async checkBurpReadiness(targetUrl: string): Promise<void> {
        const burpOk = await this.deps.burp.isAvailable();
        if (!burpOk) {
            this.deps.log('error', 'Burp MCP not available! HTTP requests will fail.');
            return;
        }

        this.deps.log('system', '✓ Burp MCP: Connected');
        try {
            await this.deps.burp.callTool('add_to_scope', { url: targetUrl });
            this.deps.log('burp', `Added ${targetUrl} to Burp scope`);
        } catch (e: any) {
            this.deps.log('error', `Scope error: ${e.message}`);
        }
    }

    private checkLlmReadiness(): void {
        if (!this.deps.llm.hasActiveConfig()) {
            throw new Error('No active LLM configured. Please configure an LLM provider in Settings.');
        }
        this.deps.log('system', '✓ LLM: Connected');
    }

    private loadMindsetTTPs(config: StartupConfig): MindsetTTP[] {
        if (config.useMindsetLibrary === false) {
            return [];
        }

        try {
            const ttps = this.deps.mindset.getRelevantTTPs(config.targetUrl);
            if (ttps.length > 0) {
                this.deps.log('system', `📚 Mindset Library: Loaded ${ttps.length} TTPs from past reports`);
            } else {
                this.deps.log('system', '📚 Mindset Library: No TTPs available (upload red team reports to build library)');
            }
            return ttps;
        } catch (e: any) {
            this.deps.log('error', `Failed to load mindset library: ${e.message}`);
            return [];
        }
    }

    private async initializeAuthEngine(config: StartupConfig): Promise<void> {
        this.deps.log('system', '🔐 Initializing Auth State Engine...');

        const authStartup = config.authStartup || {
            mode: 'no_credentials' as AuthStartupMode,
            credentials: [],
            allowAccountCreation: false,
            preferSharedPassword: true,
        };

        await this.deps.authManager.initialize(
            {
                sessionCookies: config.sessionCookies,
                idorUsers: config.idorUsers,
                initialRequest: config.initialRequest,
                authStartup,
            },
            this.deps.burp,
            this.deps.browserSession.getSessionId(),
        );

        this.deps.log(
            'system',
            `✓ Auth State Engine: ${this.deps.authManager.identityRegistry.size} identities, ${this.deps.authManager.getTotalCookies()} cookies, ${this.deps.authManager.getTotalTokens()} tokens`,
        );
    }

    private async runAuthStartup(authStartup: AuthStartupConfig): Promise<void> {
        this.deps.log('system', '🔑 Running browser-first auth startup...');
        await this.deps.scanSurface.runAuthStartup(authStartup);
    }

    private async runSourceAnalysis(config: StartupConfig): Promise<string> {
        if (!config.sourcePackagePath || !config.sourceAnalysisMode || !this.deps.sourceAnalyzer) {
            return '';
        }

        try {
            const mode = config.sourceAnalysisMode as SourceAnalysisMode;
            this.deps.log('system', `🔬 Source Analysis: Running ${mode} analysis on ${config.sourcePackagePath}...`);
            const sourceResult = await this.deps.sourceAnalyzer.analyzeSource(config.scanId, config.sourcePackagePath, mode);
            const contextBlock = this.deps.sourceAnalyzer.buildAgentContextBlock(sourceResult);
            this.deps.log('system', `✓ Source Analysis complete: ${sourceResult.framework}, ${sourceResult.dependencies.length} deps, ${sourceResult.cves.length} CVEs`);
            if (mode === SourceAnalysisMode.FULL_SOURCE_AWARE) {
                const full = sourceResult as any;
                this.deps.log('system', `  Modules: ${full.modules?.length || 0}, Functions: ${full.functions?.length || 0}, Endpoints: ${full.endpoints?.length || 0}, Security Flows: ${full.securityFlows?.length || 0}`);
            }
            return contextBlock;
        } catch (e: any) {
            this.deps.log('error', `Source analysis failed: ${e.message} — continuing without source context`);
            return '';
        }
    }
}
