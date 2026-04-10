import { normalizeProxyHistoryItems } from '../burp-tool-result';
import { logger } from '../../utils/logger';
import type { BrowserAction, CapturedJsArtifact, PageState } from './browserTypes';
import { BrowserSessionStore } from './BrowserSessionStore';
import { BrowserSessionPersistence } from './BrowserSessionPersistence';
import { BrowserTelemetry } from './BrowserTelemetry';
import { isPenPardInternalUrl } from './BrowserUrlPolicy';

export class BrowserActionRunner {
    constructor(
        private readonly store: BrowserSessionStore,
        private readonly persistence: BrowserSessionPersistence,
        private readonly telemetry: BrowserTelemetry,
        private readonly delay: (ms: number) => Promise<void>,
    ) {}

    public async executeAction(sessionId: string, action: BrowserAction): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, `execute browser action "${action.type}"`);
        const { page } = session;
        let result: any = null;

        this.persistence.updateSession(sessionId, {
            mode: 'ai',
            last_activity_at: new Date().toISOString(),
        });

        try {
            switch (action.type) {
                case 'goto': {
                    if (!action.url) throw new Error('URL required for goto action');
                    if (isPenPardInternalUrl(action.url, session.targetOrigin)) {
                        throw new Error(`Blocked navigation to internal PenPard origin: ${action.url}`);
                    }
                    await page.goto(action.url, {
                        waitUntil: 'domcontentloaded',
                        timeout: action.timeout || 30000,
                    });
                    result = { url: page.url(), title: await page.title() };
                    break;
                }
                case 'click': {
                    if (!action.selector) throw new Error('Selector required for click action');
                    await page.click(action.selector, { timeout: action.timeout || 10000 });
                    result = { clicked: action.selector };
                    break;
                }
                case 'fill': {
                    if (!action.selector || action.value === undefined) {
                        throw new Error('Selector and value required for fill action');
                    }
                    await page.fill(action.selector, action.value, { timeout: action.timeout || 10000 });
                    result = { filled: action.selector, value: action.value };
                    break;
                }
                case 'select': {
                    if (!action.selector || !action.value) {
                        throw new Error('Selector and value required for select action');
                    }
                    await page.selectOption(action.selector, action.value, { timeout: action.timeout || 10000 });
                    result = { selected: action.selector, value: action.value };
                    break;
                }
                case 'submit': {
                    if (!action.selector) throw new Error('Selector required for submit action');
                    await page.click(action.selector, { timeout: action.timeout || 10000 });
                    await page.waitForLoadState('domcontentloaded').catch(() => {});
                    result = { submitted: action.selector, url: page.url() };
                    break;
                }
                case 'evaluate': {
                    if (!action.script) throw new Error('Script required for evaluate action');
                    result = await page.evaluate(action.script);
                    break;
                }
                case 'waitForNavigation': {
                    await page.waitForLoadState('networkidle', { timeout: action.timeout || 30000 });
                    result = { url: page.url(), title: await page.title() };
                    break;
                }
                case 'waitForSelector': {
                    if (!action.selector) throw new Error('Selector required for waitForSelector');
                    await page.waitForSelector(action.selector, { timeout: action.timeout || 10000 });
                    result = { found: action.selector };
                    break;
                }
                case 'screenshot': {
                    const buffer = await page.screenshot({ type: 'png', fullPage: false });
                    result = { screenshot: buffer.toString('base64'), mimeType: 'image/png' };
                    break;
                }
                case 'back': {
                    await page.goBack({ timeout: action.timeout || 10000 });
                    result = { url: page.url() };
                    break;
                }
                case 'forward': {
                    await page.goForward({ timeout: action.timeout || 10000 });
                    result = { url: page.url() };
                    break;
                }
                case 'reload': {
                    await page.reload({ timeout: action.timeout || 30000 });
                    result = { url: page.url() };
                    break;
                }
                default:
                    throw new Error(`Unknown action type: ${(action as any).type}`);
            }

            this.store.updateLastKnownPageState(session, page);

            this.persistence.addAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify(action),
                pageUrl: this.store.safePageUrl(session) || undefined,
                pageTitle: await page.title().catch(() => ''),
                source: 'ai',
            });

            this.persistence.updateSession(sessionId, {
                current_url: this.store.safePageUrl(session),
                last_activity_at: this.store.now(),
            });

            return result;
        } catch (error: any) {
            const maybeLifecycleError = /Target page, context or browser has been closed|Target closed|Browser has been closed|closed|crash/i.test(error.message || '');
            if (maybeLifecycleError) {
                this.store.invalidateSession(
                    sessionId,
                    session.isHeadless ? 'stale_reference' : 'manually_closed',
                    session.isHeadless ? 'Browser action hit a dead browser handle' : 'Visible browser window disappeared during browser action',
                    error.message,
                );
            }
            this.persistence.addAction({
                sessionId,
                actionType: action.type,
                actionData: JSON.stringify({ ...action, error: error.message }),
                pageUrl: this.store.safePageUrl(session) || undefined,
                pageTitle: '',
                source: 'ai',
            });
            throw error;
        }
    }

    public async getPageState(sessionId: string): Promise<PageState> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'inspect the current page');
        const { page } = session;

        const state = await page.evaluate(`(() => {
            const forms = Array.from(document.querySelectorAll('form')).slice(0, 20).map(form => ({
                action: form.action || '',
                method: (form.method || 'get').toUpperCase(),
                fields: Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 30).map(field => ({
                    name: field.name || '',
                    type: field.type || field.tagName.toLowerCase(),
                    id: field.id || '',
                })),
            }));
            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 50).map(a => ({
                href: a.href || '',
                text: (a.textContent || '').trim().substring(0, 100),
            }));
            const bodyText = document.body ? document.body.innerText : '';
            const textSummary = bodyText.substring(0, 2000);
            return { forms, links, textSummary };
        })()`) as { forms: any[]; links: any[]; textSummary: string };

        return {
            url: this.store.safePageUrl(session) || 'about:blank',
            title: await page.title(),
            ...state,
        };
    }

    public async captureScreenshot(sessionId: string): Promise<{ base64: string; mimeType: string }> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'capture a screenshot');
        const buffer = await session.page.screenshot({ type: 'png', fullPage: false });
        this.store.updateLastKnownPageState(session);

        this.persistence.addAction({
            sessionId,
            actionType: 'screenshot',
            actionData: JSON.stringify({ timestamp: new Date().toISOString() }),
            pageUrl: this.store.safePageUrl(session) || undefined,
            pageTitle: await session.page.title().catch(() => ''),
            source: 'ai',
        });

        return { base64: buffer.toString('base64'), mimeType: 'image/png' };
    }

    public async getSessionInfo(sessionId: string): Promise<any> {
        const dbSession = this.persistence.getSession(sessionId);
        if (!dbSession) return null;

        const liveSession = this.store.get(sessionId);
        if (liveSession) {
            const visibility = this.store.buildVisibilityState(liveSession);
            dbSession.current_url = visibility.lastKnownUrl || dbSession.current_url;
            dbSession.title = await this.store.safePageTitle(liveSession);
            dbSession.isLive = visibility.isLive;
            dbSession.lifecycle_state = liveSession.lifecycleState;
            dbSession.lifecycle_detail = liveSession.lifecycleDetail;
            dbSession.last_error = liveSession.lastError;
            dbSession.runtime = visibility;
        } else {
            dbSession.isLive = false;
        }

        return dbSession;
    }

    public async getFullPageState(sessionId: string): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'inspect loaded scripts');
        const { page, context } = session;

        const state = await page.evaluate(`(async () => {
            const allElements = document.querySelectorAll('*');
            const tagCounts = {};
            allElements.forEach(el => { tagCounts[el.tagName] = (tagCounts[el.tagName] || 0) + 1; });

            const sanitize = (value, limit = 500) => String(value || '').trim().substring(0, limit);
            const escapeCss = (value) => {
                if (!value) return '';
                if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(value);
                return String(value).replace(/([ #;?%&,.+*~\\':"!^$\\[\\]()=>|/@])/g, '\\\\$1');
            };
            const getSelector = (el) => {
                if (!el || !el.tagName) return '';
                if (el.id) return '#' + escapeCss(el.id);
                if (el.name) return el.tagName.toLowerCase() + '[name="' + escapeCss(el.name) + '"]';
                if (el.getAttribute && el.getAttribute('data-testid')) {
                    return el.tagName.toLowerCase() + '[data-testid="' + escapeCss(el.getAttribute('data-testid')) + '"]';
                }
                const parts = [];
                let current = el;
                let depth = 0;
                while (current && current.nodeType === Node.ELEMENT_NODE && depth < 4) {
                    const tag = current.tagName.toLowerCase();
                    let part = tag;
                    if (current.classList && current.classList.length > 0) {
                        part += '.' + Array.from(current.classList).slice(0, 2).map(escapeCss).join('.');
                    }
                    const siblings = current.parentElement ? Array.from(current.parentElement.children).filter(child => child.tagName === current.tagName) : [];
                    if (siblings.length > 1) {
                        part += ':nth-of-type(' + (siblings.indexOf(current) + 1) + ')';
                    }
                    parts.unshift(part);
                    current = current.parentElement;
                    depth++;
                }
                return parts.join(' > ');
            };
            const getFieldLabel = (field) => {
                if (!field) return '';
                const aria = field.getAttribute('aria-label');
                if (aria) return sanitize(aria, 120);
                if (field.id) {
                    const explicit = document.querySelector('label[for="' + field.id.replace(/"/g, '\\\\"') + '"]');
                    if (explicit) return sanitize(explicit.textContent, 120);
                }
                const wrapped = field.closest('label');
                if (wrapped) return sanitize(wrapped.textContent, 120);
                return '';
            };

            const forms = Array.from(document.querySelectorAll('form')).slice(0, 30).map((form, formIndex) => {
                const fields = Array.from(form.querySelectorAll('input, textarea, select')).slice(0, 50).map(field => ({
                    name: field.name || '',
                    type: field.type || field.tagName.toLowerCase(),
                    id: field.id || '',
                    value: field.type === 'hidden' ? sanitize(field.value, 300) : '',
                    placeholder: field.placeholder || '',
                    autocomplete: field.autocomplete || '',
                    required: !!field.required,
                    label: getFieldLabel(field),
                    selector: getSelector(field),
                }));
                const hiddenInputs = fields.filter(field => field.type === 'hidden');
                const submitElements = Array.from(form.querySelectorAll('button, input[type="submit"], input[type="button"]')).slice(0, 10).map(button => ({
                    selector: getSelector(button),
                    tagName: button.tagName.toLowerCase(),
                    text: sanitize(button.innerText || button.value || button.textContent, 120),
                    type: button.type || button.tagName.toLowerCase(),
                }));
                const inlineValidation = Array.from(form.querySelectorAll('[aria-live], .error, .invalid-feedback, .form-error, [data-error], [role="alert"]'))
                    .slice(0, 20)
                    .map(node => sanitize(node.textContent, 160))
                    .filter(Boolean);

                return {
                    action: form.action || '',
                    method: (form.method || 'get').toUpperCase(),
                    id: form.id || ('form-' + (formIndex + 1)),
                    name: form.name || '',
                    selector: getSelector(form),
                    fields,
                    hiddenInputs,
                    submitElements,
                    inlineValidation,
                };
            });

            const hiddenInputs = Array.from(document.querySelectorAll('input[type="hidden"]')).slice(0, 100).map(el => ({
                name: el.name || '',
                id: el.id || '',
                value: sanitize(el.value, 300),
                form: el.form ? (el.form.id || el.form.action || 'unnamed-form') : 'no-form',
                selector: getSelector(el),
            }));

            const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 120).map(a => ({
                href: a.href || '',
                text: sanitize(a.textContent, 120),
                selector: getSelector(a),
            }));

            const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="button"], input[type="submit"]'))
                .slice(0, 120)
                .map(button => ({
                    selector: getSelector(button),
                    tagName: button.tagName.toLowerCase(),
                    text: sanitize(button.innerText || button.value || button.textContent, 120),
                    type: button.type || button.tagName.toLowerCase(),
                    formId: button.form ? (button.form.id || button.form.action || '') : '',
                }));

            const metaTags = Array.from(document.querySelectorAll('meta')).map(m => ({
                name: m.name || m.httpEquiv || m.getAttribute('property') || '',
                content: sanitize(m.content, 500),
            }));

            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || '',
                type: s.type || '',
                isInline: !s.src,
                contentPreview: !s.src ? sanitize(s.textContent, 500) : '',
                contentLength: !s.src ? (s.textContent || '').length : 0,
            }));

            let localStorageData = {};
            try {
                for (let i = 0; i < localStorage.length && i < 50; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = sanitize(localStorage.getItem(key), 500);
                }
            } catch {}

            let sessionStorageData = {};
            try {
                for (let i = 0; i < sessionStorage.length && i < 50; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = sanitize(sessionStorage.getItem(key), 500);
                }
            } catch {}

            let indexedDbNames = [];
            try {
                if (window.indexedDB && typeof window.indexedDB.databases === 'function') {
                    const dbs = await window.indexedDB.databases();
                    indexedDbNames = dbs.map(db => sanitize(db && db.name, 120)).filter(Boolean);
                }
            } catch {}

            const antiAutomationMarkers = [
                ...Array.from(document.querySelectorAll('[data-sitekey], iframe[src*="captcha"], script[src*="turnstile"], [class*="captcha"], [id*="captcha"], [name*="captcha"]'))
                    .slice(0, 20)
                    .map(node => sanitize(node.getAttribute('class') || node.getAttribute('id') || node.tagName, 160)),
            ].filter(Boolean);

            const bodyText = document.body ? document.body.innerText : '';
            return {
                tagCounts,
                totalElements: allElements.length,
                forms,
                hiddenInputs,
                links,
                buttons,
                metaTags,
                scripts,
                cookies: document.cookie,
                localStorageData,
                sessionStorageData,
                indexedDbNames,
                antiAutomationMarkers,
                textSummary: bodyText.substring(0, 3000),
            };
        })()`);

        let contextCookies: any[] = [];
        try { contextCookies = await context.cookies(); } catch {}

        return {
            url: this.store.safePageUrl(session) || 'about:blank',
            title: await page.title(),
            ...(state as any),
            contextCookies,
        };
    }

    public async getLoadedScripts(sessionId: string): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'capture JavaScript artifacts');

        return session.page.evaluate(`(() => {
            const MAX_INLINE_LENGTH = 25000;
            const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                src: s.src || null,
                type: s.type || 'text/javascript',
                async: s.async,
                defer: s.defer,
                isModule: s.type === 'module',
                isInline: !s.src,
                content: !s.src ? (s.textContent || '').substring(0, MAX_INLINE_LENGTH) : null,
                contentPreview: !s.src ? (s.textContent || '').substring(0, 2000) : null,
                contentLength: !s.src ? (s.textContent || '').length : null,
            }));
            const preloads = Array.from(document.querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')).map(l => ({
                href: l.href || '',
                rel: l.rel || '',
                as: l.getAttribute('as') || '',
            }));
            return { scripts, preloads, totalScripts: scripts.length };
        })()`);
    }

    public async captureJavaScriptArtifacts(sessionId: string): Promise<CapturedJsArtifact[]> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'capture JavaScript artifacts');
        const loadedScripts = await this.getLoadedScripts(sessionId);
        return this.telemetry.captureInlineScriptArtifacts(session, loadedScripts);
    }

    public getCapturedJavaScriptArtifacts(sessionId: string): CapturedJsArtifact[] {
        return this.telemetry.getCapturedJavaScriptArtifacts(sessionId);
    }

    public async getFrontendAnalysis(sessionId: string): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'analyze the frontend');
        await this.captureJavaScriptArtifacts(sessionId).catch(() => {});

        return session.page.evaluate(`(() => {
            const results = {
                apiEndpoints: [],
                graphqlIndicators: [],
                websocketUrls: [],
                tokenPatterns: [],
                csrfTokens: [],
                frontendRoutes: [],
                hiddenParams: [],
                inlineScriptInsights: [],
            };

            const allScriptContent = Array.from(document.querySelectorAll('script:not([src])'))
                .map(s => s.textContent || '').join('\\n');
            const scriptSrcs = Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src);

            const apiPatterns = [
                /["'\`](\\/api\\/[^"'\`\\s]{2,80})["'\`]/g,
                /["'\`](https?:\\/\\/[^"'\`\\s]*\\/api\\/[^"'\`\\s]{2,120})["'\`]/g,
                /fetch\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /axios\\.[a-z]+\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /\\.(?:get|post|put|delete|patch)\\s*\\(\\s*["'\`]([^"'\`]+)["'\`]/g,
                /XMLHttpRequest[^]*?\\.open\\s*\\(\\s*["'][A-Z]+["']\\s*,\\s*["'\`]([^"'\`]+)["'\`]/g,
                /url\\s*[:=]\\s*["'\`](\\/[^"'\`\\s]{2,80})["'\`]/g,
                /endpoint\\s*[:=]\\s*["'\`]([^"'\`\\s]{2,80})["'\`]/g,
            ];
            const foundEndpoints = new Set();
            for (const pat of apiPatterns) {
                let m;
                while ((m = pat.exec(allScriptContent)) !== null) {
                    const ep = m[1];
                    if (ep && !ep.includes('{{') && ep.length < 200) foundEndpoints.add(ep);
                }
            }
            results.apiEndpoints = [...foundEndpoints].slice(0, 100);

            if (allScriptContent.includes('graphql') || allScriptContent.includes('GraphQL') ||
                allScriptContent.includes('__schema') || allScriptContent.includes('mutation ') ||
                allScriptContent.includes('query {')) {
                results.graphqlIndicators.push('GraphQL usage detected in inline scripts');
                const gqlUrlMatch = allScriptContent.match(/["'\`]([^"'\`]*graphql[^"'\`]*)["'\`]/gi);
                if (gqlUrlMatch) results.graphqlIndicators.push(...gqlUrlMatch.slice(0, 10).map(s => s.replace(/["'\`]/g, '')));
            }
            scriptSrcs.forEach(src => {
                if (src.toLowerCase().includes('graphql')) results.graphqlIndicators.push('GraphQL script: ' + src);
            });

            const wsPatterns = /["'\`](wss?:\\/\\/[^"'\`\\s]+)["'\`]/g;
            let wsMatch;
            while ((wsMatch = wsPatterns.exec(allScriptContent)) !== null) {
                results.websocketUrls.push(wsMatch[1]);
            }
            if (allScriptContent.includes('new WebSocket')) results.websocketUrls.push('WebSocket constructor usage detected');

            if (allScriptContent.match(/bearer/i)) results.tokenPatterns.push('Bearer token pattern detected');
            if (allScriptContent.match(/localStorage\\.getItem\\s*\\(\\s*["'\`](token|access_token|auth_token|jwt)/i))
                results.tokenPatterns.push('Token stored in localStorage');
            if (allScriptContent.match(/sessionStorage\\.getItem\\s*\\(\\s*["'\`](token|access_token|auth_token|jwt)/i))
                results.tokenPatterns.push('Token stored in sessionStorage');
            const jwtInStorage = [];
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    const v = k ? localStorage.getItem(k) : '';
                    if (v && v.match(/^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\./)) jwtInStorage.push(k);
                }
            } catch {}
            if (jwtInStorage.length > 0) results.tokenPatterns.push('JWT-like values present in localStorage keys: ' + jwtInStorage.join(', '));

            const csrfPatterns = [
                /csrf[_-]?token/gi,
                /xsrf[_-]?token/gi,
                /_token/gi,
            ];
            csrfPatterns.forEach(p => {
                if (allScriptContent.match(p)) results.csrfTokens.push('Pattern in JS: ' + p.source);
            });
            document.querySelectorAll('meta[name*="csrf" i], meta[name*="xsrf" i], input[name*="csrf" i], input[name*="xsrf" i], [data-csrf], [data-xsrf]').forEach(el => {
                results.csrfTokens.push({
                    name: el.getAttribute('name') || el.getAttribute('property') || '',
                    value: (el.getAttribute('value') || el.getAttribute('content') || '').substring(0, 100),
                    tag: el.tagName,
                });
            });

            const routePatterns = /(?:path|route)\\s*[:=]\\s*["'\`](\\/[^"'\`]{1,80})["'\`]/g;
            let routeMatch;
            const foundRoutes = new Set();
            while ((routeMatch = routePatterns.exec(allScriptContent)) !== null) {
                foundRoutes.add(routeMatch[1]);
            }
            results.frontendRoutes = [...foundRoutes].slice(0, 50);

            const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
            hiddenInputs.forEach(inp => {
                results.hiddenParams.push({
                    name: inp.name || '',
                    value: (inp.value || '').substring(0, 200),
                    id: inp.id || '',
                });
            });

            return results;
        })()`);
    }

    public async getSessionStorageData(sessionId: string): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'read browser storage');

        const browserStorage = await session.page.evaluate(`(() => {
            let localStorageData = {};
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key) localStorageData[key] = localStorage.getItem(key);
                }
            } catch(e) {}
            let sessionStorageData = {};
            try {
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key) sessionStorageData[key] = sessionStorage.getItem(key);
                }
            } catch(e) {}
            return { cookies: document.cookie, localStorageData, sessionStorageData };
        })()`);

        let contextCookies: any[] = [];
        try { contextCookies = await session.context.cookies(); } catch {}

        return { url: this.store.safePageUrl(session) || 'about:blank', ...(browserStorage as any), contextCookies };
    }

    public async syncCookiesToSession(sessionId: string, cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>): Promise<number> {
        const session = this.store.assertReadySession(sessionId, 'sync cookies into the browser session');
        if (!cookies.length) return 0;

        await session.context.addCookies(cookies as any);
        this.persistence.updateSession(sessionId, {
            last_activity_at: new Date().toISOString(),
        });

        this.persistence.addAction({
            sessionId,
            actionType: 'sync_cookies',
            actionData: JSON.stringify({ count: cookies.length }),
            pageUrl: this.store.safePageUrl(session) || undefined,
            pageTitle: await session.page.title().catch(() => ''),
            source: 'system',
        });

        return cookies.length;
    }

    public getTrafficSnapshot(sessionId: string) {
        return this.telemetry.getTrafficSnapshot(sessionId);
    }

    public async correlateBrowserWithBurp(sessionId: string): Promise<any> {
        const session = await this.store.waitForSessionReady(sessionId, this.delay, 15000, 'correlate browser traffic with Burp');
        const currentUrl = this.store.safePageUrl(session) || 'about:blank';
        let host = '';
        try { host = new URL(currentUrl).hostname; } catch {}

        let burpHistory: any[] = [];
        let burpAvailable = false;
        try {
            const { burpMCP } = require('../burp-mcp');
            burpAvailable = await burpMCP.isAvailable();
            if (burpAvailable) {
                const result = await burpMCP.callTool('get_proxy_history', { count: 50, excludePenPard: true });
                burpHistory = normalizeProxyHistoryItems(result);
            }
        } catch (error: any) {
            logger.warn('Burp MCP correlation failed', { error: error.message });
        }

        const actions = this.persistence.getActions(sessionId);
        const browserTraffic = this.getTrafficSnapshot(sessionId);

        const matchedRequests = burpHistory.filter((entry: any) => {
            const entryUrl = entry.url || '';
            try {
                const entryHost = new URL(entryUrl).hostname;
                return entryHost === host &&
                    !isPenPardInternalUrl(entryUrl, session.targetOrigin) &&
                    !/\/socket\.io\/|\/sockjs\/|\/__webpack_hmr|transport=polling/i.test(entryUrl);
            } catch {
                return false;
            }
        });

        const burpEndpoints = [...new Set(matchedRequests.map((entry: any) => {
            try { return new URL(entry.url).pathname; } catch { return entry.url; }
        }))];

        let frontendEndpoints: string[] = [];
        try {
            const analysis = await this.getFrontendAnalysis(sessionId);
            frontendEndpoints = analysis.apiEndpoints || [];
        } catch {}

        const burpPathSet = new Set(burpEndpoints);
        const frontendOnly = frontendEndpoints.filter((endpoint) => !burpPathSet.has(endpoint));

        return {
            burpAvailable,
            currentUrl,
            host,
            browserActionsCount: actions.length,
            browserTrafficCount: browserTraffic.length,
            burpRequestsForHost: matchedRequests.length,
            totalBurpHistory: burpHistory.length,
            matchedRequests: matchedRequests.slice(0, 30).map((entry: any) => ({
                method: entry.method,
                url: entry.url,
                status: entry.status,
                mimeType: entry.mimeType,
            })),
            browserTraffic: browserTraffic.slice(-30),
            burpEndpoints,
            frontendEndpoints,
            frontendOnlyEndpoints: frontendOnly,
            insight: frontendOnly.length > 0
                ? `Found ${frontendOnly.length} API endpoint(s) in frontend JavaScript that have NOT been seen in Burp traffic. These may be untested attack surface.`
                : 'All frontend-discovered endpoints match Burp traffic.',
        };
    }

    public async compareSessionStates(sessionIdA: string, sessionIdB: string): Promise<any> {
        await this.store.waitForSessionReady(sessionIdA, this.delay, 15000, 'compare browser sessions');
        await this.store.waitForSessionReady(sessionIdB, this.delay, 15000, 'compare browser sessions');

        const [stateA, stateB] = await Promise.all([
            this.getSessionStorageData(sessionIdA),
            this.getSessionStorageData(sessionIdB),
        ]);

        const cookiesA = new Set((stateA.contextCookies || []).map((cookie: any) => `${cookie.name}=${cookie.value}`));
        const cookiesB = new Set((stateB.contextCookies || []).map((cookie: any) => `${cookie.name}=${cookie.value}`));
        const sharedCookies = [...cookiesA].filter((cookie) => cookiesB.has(cookie));
        const onlyA = [...cookiesA].filter((cookie) => !cookiesB.has(cookie));
        const onlyB = [...cookiesB].filter((cookie) => !cookiesA.has(cookie));

        const lsKeysA = Object.keys(stateA.localStorageData || {});
        const lsKeysB = Object.keys(stateB.localStorageData || {});
        const lsDiffs: any[] = [];
        const allLsKeys = new Set([...lsKeysA, ...lsKeysB]);
        allLsKeys.forEach((key) => {
            const vA = stateA.localStorageData?.[key];
            const vB = stateB.localStorageData?.[key];
            if (vA !== vB) lsDiffs.push({ key, sessionA: vA || '(missing)', sessionB: vB || '(missing)' });
        });

        return {
            sessionA: { id: sessionIdA, url: stateA.url },
            sessionB: { id: sessionIdB, url: stateB.url },
            urlMatch: stateA.url === stateB.url,
            cookies: {
                sharedCount: sharedCookies.length,
                onlyInA: onlyA.length,
                onlyInB: onlyB.length,
                onlyInAList: onlyA.slice(0, 20),
                onlyInBList: onlyB.slice(0, 20),
                isolated: onlyA.length > 0 || onlyB.length > 0,
            },
            localStorage: {
                differencesCount: lsDiffs.length,
                differences: lsDiffs.slice(0, 20),
            },
            insight: (onlyA.length > 0 || onlyB.length > 0)
                ? 'Sessions have different cookies — session isolation is working. Suitable for IDOR/BAC testing.'
                : 'Sessions share identical cookies — may need different login states for access control testing.',
        };
    }
}
