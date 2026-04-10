import type { BrowserAction, BrowserSessionOptions, BrowserSessionVisibility } from '../../services/BrowserService';

export interface OrchestratorBrowserCookie {
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
}

export interface OrchestratorBrowserRuntime {
    launchSession(userId: number, options: BrowserSessionOptions): Promise<string>;
    closeSession(sessionId: string): Promise<void>;
    isSessionAlive(sessionId: string): boolean;
    getSessionVisibility(sessionId: string): BrowserSessionVisibility | null;
    executeAction(sessionId: string, action: BrowserAction): Promise<any>;
    getPageState(sessionId: string): Promise<any>;
    getFullPageState(sessionId: string): Promise<any>;
    getFrontendAnalysis(sessionId: string): Promise<any>;
    correlateBrowserWithBurp(sessionId: string): Promise<any>;
    syncCookiesToSession(sessionId: string, cookies: OrchestratorBrowserCookie[]): Promise<number>;
}
