import type { Browser, BrowserContext, Page } from 'playwright-core';
import type { BrowserLifecycleState } from '../../types/browserLifecycle';

export interface BrowserSessionOptions {
    targetUrl?: string;
    scanId?: string;
    findingId?: number;
    proxyHost?: string;
    proxyPort?: number;
    label?: string;
    headless?: boolean;
}

export interface BrowserAction {
    type: 'goto' | 'click' | 'fill' | 'select' | 'submit' | 'evaluate' | 'waitForNavigation' | 'waitForSelector' | 'screenshot' | 'back' | 'forward' | 'reload';
    url?: string;
    selector?: string;
    value?: string;
    script?: string;
    timeout?: number;
}

export interface PageState {
    url: string;
    title: string;
    forms: Array<{ action: string; method: string; fields: Array<{ name: string; type: string; id: string }> }>;
    links: Array<{ href: string; text: string }>;
    textSummary: string;
}

export interface BrowserTrafficEvent {
    id: number;
    kind: 'request' | 'response';
    method: string;
    url: string;
    timestamp: string;
    originCategory?: 'target' | 'internal' | 'external';
    resourceType?: string;
    requestHeaders?: Record<string, string>;
    responseHeaders?: Record<string, string>;
    requestBody?: string;
    statusCode?: number;
}

export interface CapturedJsArtifact {
    id: string;
    sessionId: string;
    scanId?: string;
    pageUrl: string;
    scriptUrl?: string;
    origin: string;
    type: 'external' | 'inline';
    contentType: string;
    contentHash: string;
    bytes: number;
    storedAt: string;
    filePath: string;
    evidence: string[];
}

export interface BrowserContinuitySnapshot {
    url: string;
    cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>;
    storage: Array<{
        origin: string;
        localStorageData: Record<string, string>;
        sessionStorageData: Record<string, string>;
    }>;
}

export interface BrowserSessionVisibility {
    sessionId: string;
    lifecycleState: BrowserLifecycleState;
    isHeadless: boolean | null;
    transitioning: boolean;
    isLive: boolean;
    lastKnownUrl: string | null;
    lastError: string | null;
    detail: string | null;
}

export interface BrowserVisibilityResult extends BrowserSessionVisibility {
    message: string;
    reopened: boolean;
}

export interface LiveSession {
    browser: Browser | null;
    context: BrowserContext | null;
    page: Page | null;
    sessionId: string;
    userId: number;
    userDataDir: string;
    scanId?: string;
    targetUrl?: string;
    targetOrigin: string | null;
    isHeadless: boolean;
    proxyServer: string;
    executablePath: string;
    brandingExtPath: string | null;
    transitioning: boolean;
    lifecycleState: BrowserLifecycleState;
    lifecycleDetail: string | null;
    lastError: string | null;
    lastKnownUrl: string | null;
    lastKnownTitle: string | null;
    hasBeenVisible: boolean;
    generation: number;
    networkEvents: BrowserTrafficEvent[];
    nextTrafficEventId: number;
    jsArtifacts: Map<string, CapturedJsArtifact>;
    jsArtifactsDir: string | null;
}

export type ReadyLiveSession = LiveSession & {
    browser: Browser;
    context: BrowserContext;
    page: Page;
};
