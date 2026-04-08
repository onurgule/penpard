import http, { IncomingMessage, ServerResponse } from 'http';
import { chromium, type BrowserContext, type Page } from 'playwright-core';

type RequestLogEntry = {
    method: string;
    url: string;
    host: string;
};

type BrowserServiceMethodName =
    | 'launchSession'
    | 'syncCookiesToSession'
    | 'getFullPageState'
    | 'getFrontendAnalysis'
    | 'getTrafficSnapshot'
    | 'executeAction'
    | 'closeSession';

type HarnessSession = {
    context: BrowserContext;
    page: Page;
};

function delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function html(title: string, body: string): string {
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>${title}</title>
  </head>
  <body>
    ${body}
  </body>
</html>`;
}

async function withPatchedBrowserService<T>(
    browserService: any,
    patches: Partial<Record<BrowserServiceMethodName, any>>,
    fn: () => Promise<T>,
): Promise<T> {
    const originals = new Map<BrowserServiceMethodName, any>();

    for (const [name, replacement] of Object.entries(patches) as Array<[BrowserServiceMethodName, any]>) {
        originals.set(name, browserService[name]);
        browserService[name] = replacement;
    }

    try {
        return await fn();
    } finally {
        for (const [name, original] of originals.entries()) {
            browserService[name] = original;
        }
    }
}

async function main(): Promise<void> {
    const requestLog: RequestLogEntry[] = [];
    const serverSockets = new Set<any>();

    const targetServer = http.createServer((req: IncomingMessage, res: ServerResponse) => {
        const host = String(req.headers.host || '');
        const url = String(req.url || '/');
        requestLog.push({
            method: String(req.method || 'GET').toUpperCase(),
            url,
            host,
        });

        if (url.startsWith('/reset-password/socket.io/')) {
            res.writeHead(200, {
                'content-type': 'application/json',
                'cache-control': 'no-store',
            });
            res.end(JSON.stringify({ ok: true, transport: 'polling' }));
            return;
        }

        if (url === '/') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(html('Home', '<h1>Target Home</h1><p>No auth links are exposed from the landing page.</p>'));
            return;
        }

        if (url === '/reset-password') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(html(
                'Reset Password',
                `
                  <h1>Reset Password</h1>
                  <script>
                    fetch('/reset-password/socket.io/?EIO=4&transport=polling&t=boot', { credentials: 'include' }).catch(() => {});
                  </script>
                `,
            ));
            return;
        }

        if ([
            '/login',
            '/signin',
            '/sign-in',
            '/register',
            '/signup',
            '/sign-up',
            '/forgot-password',
            '/auth',
            '/sso',
        ].includes(url)) {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
            res.end(html(`Auth Route ${url}`, `<h1>${url}</h1>`));
            return;
        }

        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('not found');
    });

    targetServer.on('connection', (socket) => {
        serverSockets.add(socket);
        socket.on('close', () => serverSockets.delete(socket));
    });

    await new Promise<void>((resolve) => targetServer.listen(0, '127.0.0.1', () => resolve()));
    const address = targetServer.address();
    if (!address || typeof address === 'string') {
        throw new Error('Could not determine target server port');
    }

    const origin = `http://127.0.0.1:${address.port}`;

    const summarize = (label: string, entries: RequestLogEntry[]) => ({
        label,
        targetUrls: entries.map((entry) => entry.url),
        blindAuthRouteHits: entries
            .map((entry) => entry.url)
            .filter((url) => [
                '/login',
                '/signin',
                '/sign-in',
                '/register',
                '/signup',
                '/sign-up',
                '/forgot-password',
                '/reset-password',
                '/auth',
                '/sso',
            ].includes(url)),
        socketPollingHits: entries
            .map((entry) => entry.url)
            .filter((url) => url.includes('/reset-password/socket.io/')),
    });

    const { WebAuthStartupService } = await import('../src/services/WebAuthStartupService');
    const { AuthStateManager } = await import('../src/services/auth');
    const { defaultAuthStartupConfig } = await import('../src/services/web-auth-startup-config');
    const { browserService } = await import('../src/services/BrowserService');

    const browser = await chromium.launch({
        headless: true,
        executablePath: chromium.executablePath(),
    });

    try {
        {
            const context = await browser.newContext();
            const page = await context.newPage();
            const before = requestLog.length;
            await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded', timeout: 15000 });
            await delay(1200);
            console.log(JSON.stringify(summarize('manual-open', requestLog.slice(before)), null, 2));
            await context.close();
        }

        {
            const sessions = new Map<string, HarnessSession>();
            let nextId = 1;

            const buildState = async (page: Page) => {
                const url = page.url();
                let title = '';
                try {
                    title = await page.title();
                } catch {
                    title = '';
                }
                return {
                    url,
                    title,
                    forms: [],
                    links: [],
                    buttons: [],
                    metaTags: [],
                    antiAutomationMarkers: [],
                    indexedDbNames: [],
                    localStorageData: {},
                    sessionStorageData: {},
                    contextCookies: [],
                    textSummary: '',
                };
            };

            const before = requestLog.length;
            await withPatchedBrowserService(browserService as any, {
                launchSession: async (_userId: number, options: { targetUrl?: string }) => {
                    const context = await browser.newContext();
                    const page = await context.newPage();
                    if (options.targetUrl) {
                        await page.goto(options.targetUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
                    }
                    const sessionId = `harness-session-${nextId++}`;
                    sessions.set(sessionId, { context, page });
                    return sessionId;
                },
                syncCookiesToSession: async () => {},
                getFullPageState: async (sessionId: string) => {
                    const session = sessions.get(sessionId);
                    if (!session) throw new Error(`Unknown session ${sessionId}`);
                    return await buildState(session.page);
                },
                getFrontendAnalysis: async () => ({
                    apiEndpoints: [],
                    graphqlIndicators: [],
                    websocketUrls: [],
                    tokenPatterns: [],
                    csrfTokens: [],
                    frontendRoutes: [],
                    hiddenParams: [],
                    inlineScriptInsights: [],
                }),
                getTrafficSnapshot: () => [],
                executeAction: async (sessionId: string, action: { type: string; url?: string; selector?: string; value?: string; timeout?: number }) => {
                    const session = sessions.get(sessionId);
                    if (!session) throw new Error(`Unknown session ${sessionId}`);
                    if (action.type === 'goto' && action.url) {
                        await session.page.goto(action.url, { waitUntil: 'domcontentloaded', timeout: action.timeout || 15000 });
                        return {
                            url: session.page.url(),
                            title: await session.page.title(),
                        };
                    }
                    if (action.type === 'fill' && action.selector) {
                        await session.page.fill(action.selector, String(action.value || ''), { timeout: action.timeout || 8000 });
                        return { filled: action.selector };
                    }
                    if (action.type === 'click' && action.selector) {
                        await session.page.click(action.selector, { timeout: action.timeout || 8000 });
                        return { clicked: action.selector };
                    }
                    if (action.type === 'waitForNavigation') {
                        await session.page.waitForLoadState('domcontentloaded', { timeout: action.timeout || 6000 });
                        return { url: session.page.url() };
                    }
                    return null;
                },
                closeSession: async (sessionId: string) => {
                    const session = sessions.get(sessionId);
                    if (!session) return;
                    sessions.delete(sessionId);
                    await session.context.close();
                },
            }, async () => {
                const authManager = new AuthStateManager('socketio-noise-repro', `${origin}/`);
                const startup = new WebAuthStartupService(
                    'socketio-noise-repro',
                    1,
                    `${origin}/`,
                    {
                        async callTool() {
                            return { content: [{ text: JSON.stringify({ items: [] }) }] };
                        },
                    } as any,
                    authManager,
                    () => {},
                );

                const result = await startup.run(defaultAuthStartupConfig());
                await delay(1200);
                console.log(JSON.stringify(summarize('web-auth-startup', requestLog.slice(before)), null, 2));
                await (browserService as any).closeSession(result.browserSessionId);
            });

            for (const session of sessions.values()) {
                await session.context.close().catch(() => {});
            }
        }
    } finally {
        await browser.close();
        targetServer.closeAllConnections();
        for (const socket of serverSockets) {
            socket.destroy();
        }
        await new Promise<void>((resolve, reject) => targetServer.close((error) => error ? reject(error) : resolve()));
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
