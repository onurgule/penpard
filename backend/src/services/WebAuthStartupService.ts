import { v4 as uuidv4 } from 'uuid';
import { BurpMCPClient } from './burp-mcp';
import { browserService } from './BrowserService';
import {
    AuthStateManager,
    AuthStartupConfig,
    AuthStartupCredential,
    AuthStartupInventory,
    AuthInventoryElement,
    AuthInventoryField,
    AuthInventoryForm,
    AuthSurfaceType,
} from './auth';
import { normalizeProxyHistoryItems } from './burp-tool-result';

type LogFn = (kind: 'system' | 'error' | 'debug' | 'burp', message: string) => void;

const TYPE_PATTERNS: Array<[AuthSurfaceType, RegExp[]]> = [
    ['login', [/login/i, /sign[\s-]?in/i, /authenticate/i]],
    ['register', [/register/i, /sign[\s-]?up/i, /create account/i]],
    ['forgot_password', [/forgot/i, /forgot password/i]],
    ['reset_password', [/reset password/i, /password reset/i]],
    ['recover_account', [/recover account/i, /account recovery/i]],
    ['verify_email', [/verify email/i]],
    ['activation', [/activate account/i, /account activation/i]],
    ['onboarding', [/onboarding/i, /get started/i]],
    ['otp', [/\botp\b/i, /one[- ]time/i, /verification code/i]],
    ['mfa', [/\bmfa\b/i, /2fa/i, /two[- ]factor/i]],
    ['totp', [/\btotp\b/i, /authenticator/i]],
    ['sso', [/\bsso\b/i, /continue with/i, /sign in with/i]],
    ['invite', [/invite/i]],
    ['magic_link', [/magic link/i]],
];

const COMMON_AUTH_PATHS = ['/login', '/signin', '/sign-in', '/register', '/signup', '/sign-up', '/forgot-password', '/reset-password', '/auth', '/sso'];

export class WebAuthStartupService {
    constructor(
        private readonly scanId: string,
        private readonly userId: number,
        private readonly targetUrl: string,
        private readonly burp: BurpMCPClient,
        private readonly authManager: AuthStateManager,
        private readonly log: LogFn,
    ) {}

    async run(config: AuthStartupConfig): Promise<{ browserSessionId: string; inventory: AuthStartupInventory }> {
        const inventory = this.createInventory(config);
        const browserSessionId = await browserService.launchSession(this.userId, {
            targetUrl: this.targetUrl,
            scanId: this.scanId,
            headless: true,
        });
        inventory.browserSessionId = browserSessionId;

        await this.seed(browserSessionId, 'primary-user');
        await this.sync(browserSessionId, 'primary-user');
        await this.discover(browserSessionId, inventory, 'primary-user');

        if (config.mode === 'provided_credentials' && config.credentials.length > 0) {
            const firstId = this.resolveIdentityId(config.credentials[0], 0);
            await this.attemptLogin(browserSessionId, firstId, config.credentials[0], inventory);
            for (let i = 1; i < config.credentials.length; i++) {
                await this.runSecondaryLogin(this.resolveIdentityId(config.credentials[i], i), config.credentials[i], inventory);
            }
        } else if (config.allowAccountCreation) {
            const generated = this.generateCredentials(config.preferSharedPassword);
            for (let i = 0; i < generated.length; i++) {
                const identityId = i === 0 ? 'primary-user' : `generated-user-${i}`;
                const success = i === 0
                    ? await this.attemptRegistration(browserSessionId, identityId, generated[i], inventory)
                    : await this.runSecondaryRegistration(identityId, generated[i], inventory);
                inventory.discoveredCredentials.push({ ...generated[i], identityId, created: true, success });
            }
        }

        await this.sync(browserSessionId, 'primary-user');
        await this.captureBurp(browserSessionId, inventory, 'primary-user');
        inventory.transport = this.inferTransport(inventory, 'primary-user');
        inventory.summary = this.buildSummary(inventory);
        inventory.status = 'completed';
        inventory.completedAt = new Date().toISOString();
        this.authManager.setStartupInventory(inventory);
        return { browserSessionId, inventory };
    }

    private createInventory(config: AuthStartupConfig): AuthStartupInventory {
        return {
            mode: config.mode,
            status: 'partial',
            authRoutes: [],
            forms: [],
            domElements: [],
            traffic: [],
            actions: [],
            discoveredCredentials: config.credentials.map((credential, index) => ({ ...credential, identityId: this.resolveIdentityId(credential, index), created: false, success: false })),
            ssoProviders: [],
            blockers: [],
            registrationAvailable: false,
            passwordResetAvailable: false,
            activationRequired: false,
            transport: {
                carriesAuthorizationHeader: false,
                authorizationSchemes: [],
                cookieNames: [],
                localStorageKeys: [],
                sessionStorageKeys: [],
                indexedDbNames: [],
                csrfHeaders: [],
                csrfFormFields: [],
                csrfMetaNames: [],
                csrfCookieNames: [],
                mixedTransport: false,
                evidence: [],
            },
            startedAt: new Date().toISOString(),
            summary: '',
        };
    }

    private resolveIdentityId(credential: AuthStartupCredential, index: number): string {
        const existing = this.authManager.identityRegistry.getAll().find((identity) =>
            (!!credential.username && identity.username === credential.username) ||
            (!!credential.email && identity.email === credential.email),
        );
        return existing?.id || (index === 0 ? 'primary-user' : `provided-user-${index}`);
    }

    private async seed(sessionId: string, identityId: string): Promise<void> {
        const cookies = this.authManager.exportForBrowser(identityId);
        if (cookies.length > 0) await browserService.syncCookiesToSession(sessionId, cookies);
    }

    private async sync(sessionId: string, identityId: string): Promise<void> {
        const state = await browserService.getFullPageState(sessionId);
        this.authManager.syncFromBrowser(state.contextCookies || [], identityId);
        this.authManager.syncFromBrowserStorage({ localStorageData: state.localStorageData || {}, sessionStorageData: state.sessionStorageData || {} }, identityId);
        this.authManager.detectCSRFFromPage(state, identityId);
    }

    private async discover(sessionId: string, inventory: AuthStartupInventory, identityId: string): Promise<void> {
        await this.captureState(sessionId, inventory, identityId, 'discovery', 'initial auth inventory');
        const origin = new URL(this.targetUrl).origin;
        const urls = new Set<string>(COMMON_AUTH_PATHS.map((path) => `${origin}${path}`));
        for (const route of inventory.authRoutes) urls.add(route.startsWith('http') ? route : `${origin}${route}`);
        for (const url of Array.from(urls).slice(0, 8)) {
            const before = this.lastTrafficId(sessionId);
            try {
                await browserService.executeAction(sessionId, { type: 'goto', url, timeout: 15000 });
                await this.captureState(sessionId, inventory, identityId, 'navigate', `discover ${url}`, before);
            } catch (error: any) {
                inventory.blockers.push(`auth discovery failed for ${url}: ${error.message}`);
            }
        }
    }

    private async attemptLogin(sessionId: string, identityId: string, credential: AuthStartupCredential, inventory: AuthStartupInventory): Promise<boolean> {
        this.ensureIdentity(identityId, credential, false);
        const form = await this.findTypedForm(sessionId, inventory, identityId, 'login');
        if (!form || !credential.password) return false;
        const userField = form.fields.find((field) => this.matchesField(field, ['user', 'email', 'login'])) || form.fields[0];
        const passField = form.fields.find((field) => this.matchesField(field, ['pass']));
        const submit = form.submitElements[0]?.selector;
        if (!userField?.selector || !passField?.selector || !submit) return false;

        const before = this.lastTrafficId(sessionId);
        await browserService.executeAction(sessionId, { type: 'fill', selector: userField.selector, value: credential.username || credential.email || '', timeout: 8000 });
        await browserService.executeAction(sessionId, { type: 'fill', selector: passField.selector, value: credential.password, timeout: 8000 });
        await browserService.executeAction(sessionId, { type: 'click', selector: submit, timeout: 8000 });
        try { await browserService.executeAction(sessionId, { type: 'waitForNavigation', timeout: 6000 }); } catch {}
        await this.sync(sessionId, identityId);
        await this.captureState(sessionId, inventory, identityId, 'login', `login ${credential.username || credential.email || identityId}`, before);
        const success = this.hasAuth(identityId);
        const tracked = inventory.discoveredCredentials.find((entry) => entry.identityId === identityId);
        if (tracked) tracked.success = success;
        return success;
    }

    private async attemptRegistration(sessionId: string, identityId: string, credential: AuthStartupCredential, inventory: AuthStartupInventory): Promise<boolean> {
        this.ensureIdentity(identityId, credential, true);
        const form = await this.findTypedForm(sessionId, inventory, identityId, 'register');
        if (!form || !credential.password || form.antiAutomationMarkers.length > 0) return false;
        const submit = form.submitElements[0]?.selector;
        if (!submit) return false;

        const before = this.lastTrafficId(sessionId);
        for (const field of form.fields) {
            const value = this.registrationValue(field, credential);
            if (!field.selector || value === undefined) continue;
            await browserService.executeAction(sessionId, { type: 'fill', selector: field.selector, value, timeout: 8000 });
        }
        await browserService.executeAction(sessionId, { type: 'click', selector: submit, timeout: 8000 });
        try { await browserService.executeAction(sessionId, { type: 'waitForNavigation', timeout: 6000 }); } catch {}
        await this.sync(sessionId, identityId);
        await this.captureState(sessionId, inventory, identityId, 'register', `register ${credential.username || credential.email || identityId}`, before);
        const success = this.hasAuth(identityId);
        if (!success && /verify your email|check your email|activation/i.test(String((await browserService.getFullPageState(sessionId)).textSummary || ''))) {
            inventory.activationRequired = true;
        }
        return success;
    }

    private async runSecondaryLogin(identityId: string, credential: AuthStartupCredential, inventory: AuthStartupInventory): Promise<void> {
        const sessionId = await browserService.launchSession(this.userId, { targetUrl: this.targetUrl, scanId: this.scanId, headless: true });
        try {
            await this.attemptLogin(sessionId, identityId, credential, inventory);
            await this.captureBurp(sessionId, inventory, identityId);
        } finally {
            await browserService.closeSession(sessionId);
        }
    }

    private async runSecondaryRegistration(identityId: string, credential: AuthStartupCredential, inventory: AuthStartupInventory): Promise<boolean> {
        const sessionId = await browserService.launchSession(this.userId, { targetUrl: this.targetUrl, scanId: this.scanId, headless: true });
        try {
            const success = await this.attemptRegistration(sessionId, identityId, credential, inventory);
            await this.captureBurp(sessionId, inventory, identityId);
            return success;
        } finally {
            await browserService.closeSession(sessionId);
        }
    }

    private async findTypedForm(sessionId: string, inventory: AuthStartupInventory, identityId: string, type: AuthSurfaceType): Promise<AuthInventoryForm | undefined> {
        let form = inventory.forms.find((candidate) => candidate.type === type);
        if (form) return form;
        const origin = new URL(this.targetUrl).origin;
        const paths = type === 'login' ? ['/login', '/signin', '/auth'] : ['/register', '/signup', '/create-account'];
        for (const path of paths) {
            try {
                const before = this.lastTrafficId(sessionId);
                await browserService.executeAction(sessionId, { type: 'goto', url: `${origin}${path}`, timeout: 15000 });
                await this.captureState(sessionId, inventory, identityId, 'navigate', `${type} route ${path}`, before);
                form = inventory.forms.find((candidate) => candidate.type === type);
                if (form) return form;
            } catch {}
        }
        return undefined;
    }

    private async captureState(sessionId: string, inventory: AuthStartupInventory, identityId: string, type: 'navigate' | 'click' | 'submit' | 'login' | 'register' | 'discovery', label: string, afterId: number = 0): Promise<void> {
        const state = await browserService.getFullPageState(sessionId);
        await browserService.captureJavaScriptArtifacts(sessionId).catch(() => []);
        const forms = (Array.isArray(state.forms) ? state.forms : []).map((form: any) => this.classifyForm(form, state)).filter((form: AuthInventoryForm | null): form is AuthInventoryForm => !!form);
        const elements = this.classifyElements(state);
        forms.forEach((form: AuthInventoryForm) => {
            if (!inventory.forms.some((existing) => `${existing.type}:${existing.selector || existing.action || existing.formId}` === `${form.type}:${form.selector || form.action || form.formId}`)) inventory.forms.push(form);
            inventory.registrationAvailable ||= form.type === 'register';
            inventory.passwordResetAvailable ||= ['forgot_password', 'reset_password', 'recover_account'].includes(form.type);
            if (form.action) this.addRoute(inventory, form.action);
            form.hiddenInputs.forEach((field: AuthInventoryField) => {
                if (/csrf|token/i.test(field.name) && !inventory.transport.csrfFormFields.includes(field.name)) {
                    inventory.transport.csrfFormFields.push(field.name);
                }
            });
        });
        elements.forEach((element) => {
            if (!inventory.domElements.some((existing) => `${existing.type}:${existing.selector || existing.href || existing.text}` === `${element.type}:${element.selector || element.href || element.text}`)) inventory.domElements.push(element);
            if (element.href) this.addRoute(inventory, element.href);
            if (element.provider && !inventory.ssoProviders.includes(element.provider)) inventory.ssoProviders.push(element.provider);
        });
        for (const meta of Array.isArray(state.metaTags) ? state.metaTags : []) {
            const name = String(meta?.name || '');
            if (/csrf|xsrf/i.test(name) && !inventory.transport.csrfMetaNames.includes(name)) {
                inventory.transport.csrfMetaNames.push(name);
            }
        }
        if (Array.isArray(state.indexedDbNames)) inventory.transport.indexedDbNames.push(...state.indexedDbNames.filter((name: string) => !inventory.transport.indexedDbNames.includes(name)));
        if (state.localStorageData) inventory.transport.localStorageKeys.push(...Object.keys(state.localStorageData).filter((key) => !inventory.transport.localStorageKeys.includes(key)));
        if (state.sessionStorageData) inventory.transport.sessionStorageKeys.push(...Object.keys(state.sessionStorageData).filter((key) => !inventory.transport.sessionStorageKeys.includes(key)));
        await this.captureTraffic(sessionId, inventory, identityId, afterId, type);
        inventory.actions.push({ id: uuidv4(), type, label, identityId, outcome: 'success', observedUrls: [String(state.url || this.targetUrl)] });
    }

    private classifyForm(form: any, state: any): AuthInventoryForm | null {
        const haystack = [form.action, form.id, form.name, ...(Array.isArray(form.fields) ? form.fields.map((field: any) => `${field.name} ${field.label || ''} ${field.placeholder || ''} ${field.autocomplete || ''}`) : []), ...(Array.isArray(form.submitElements) ? form.submitElements.map((element: any) => element.text) : [])].join(' ');
        const type = this.detectType(haystack);
        if (type === 'unknown') return null;
        return {
            type,
            formId: String(form.id || form.name || form.action || uuidv4()),
            selector: form.selector || undefined,
            action: String(form.action || ''),
            method: String(form.method || 'GET'),
            fields: (Array.isArray(form.fields) ? form.fields : []).map((field: any) => ({ name: String(field.name || ''), type: String(field.type || 'text'), id: field.id || undefined, label: field.label || undefined, placeholder: field.placeholder || undefined, autocomplete: field.autocomplete || undefined, selector: field.selector || undefined, value: field.value || undefined, required: field.required === true })),
            hiddenInputs: (Array.isArray(form.hiddenInputs) ? form.hiddenInputs : []).map((field: any) => ({ name: String(field.name || ''), type: String(field.type || 'hidden'), id: field.id || undefined, selector: field.selector || undefined, value: field.value || undefined })),
            submitElements: (Array.isArray(form.submitElements) ? form.submitElements : []).map((element: any) => ({ type, selector: String(element.selector || ''), tagName: String(element.tagName || 'button'), text: String(element.text || '') })),
            antiAutomationMarkers: Array.isArray(state.antiAutomationMarkers) ? state.antiAutomationMarkers : [],
            inlineValidation: Array.isArray(form.inlineValidation) ? form.inlineValidation : [],
        };
    }

    private classifyElements(state: any): AuthInventoryElement[] {
        const out: AuthInventoryElement[] = [];
        for (const link of Array.isArray(state.links) ? state.links : []) {
            const type = this.detectType(`${link.text || ''} ${link.href || ''}`);
            if (type === 'unknown') continue;
            out.push({ type, selector: String(link.selector || ''), tagName: 'a', text: String(link.text || ''), href: String(link.href || ''), provider: this.providerFromText(String(link.text || '')) });
        }
        for (const button of Array.isArray(state.buttons) ? state.buttons : []) {
            const type = this.detectType(`${button.text || ''} ${button.formId || ''}`);
            if (type === 'unknown') continue;
            out.push({ type, selector: String(button.selector || ''), tagName: String(button.tagName || 'button'), text: String(button.text || ''), formId: String(button.formId || ''), provider: this.providerFromText(String(button.text || '')) });
        }
        return out;
    }

    private detectType(value: string): AuthSurfaceType {
        for (const [type, patterns] of TYPE_PATTERNS) {
            if (patterns.some((pattern) => pattern.test(value))) return type;
        }
        return 'unknown';
    }

    private matchesField(field: AuthInventoryField, keywords: string[]): boolean {
        const haystack = `${field.name} ${field.label || ''} ${field.placeholder || ''} ${field.autocomplete || ''} ${field.type}`.toLowerCase();
        return keywords.some((keyword) => haystack.includes(keyword));
    }

    private registrationValue(field: AuthInventoryField, credential: AuthStartupCredential): string | undefined {
        const haystack = `${field.name} ${field.label || ''} ${field.placeholder || ''} ${field.autocomplete || ''} ${field.type}`.toLowerCase();
        if (haystack.includes('email')) return credential.email;
        if (haystack.includes('confirm') && haystack.includes('pass')) return credential.password;
        if (haystack.includes('pass')) return credential.password;
        if (haystack.includes('user') || haystack.includes('login')) return credential.username || credential.email;
        if (haystack.includes('first')) return 'Pen';
        if (haystack.includes('last')) return 'Pard';
        if (haystack.includes('name')) return 'PenPard';
        return undefined;
    }

    private providerFromText(text: string): string | undefined {
        const value = text.toLowerCase();
        if (value.includes('google')) return 'Google';
        if (value.includes('github')) return 'GitHub';
        if (value.includes('microsoft')) return 'Microsoft';
        if (value.includes('okta')) return 'Okta';
        return undefined;
    }

    private generateCredentials(preferSharedPassword: boolean): AuthStartupCredential[] {
        const seed = Date.now();
        const sharedPassword = `PenPard!${seed}`;
        return ['a', 'b'].map((suffix, index) => ({
            username: `penpard_${seed}_${suffix}`,
            email: `penpard_${seed}_${suffix}@example.test`,
            password: preferSharedPassword ? sharedPassword : `PenPard!${seed + index}`,
            label: `Generated User ${index + 1}`,
            role: 'unknown',
            privilege: 'unknown',
            source: 'browser_login',
        }));
    }

    private ensureIdentity(identityId: string, credential: AuthStartupCredential, created: boolean): void {
        if (this.authManager.identityRegistry.get(identityId)) return;
        this.authManager.registerIdentity({
            identityId,
            label: credential.label || credential.username || credential.email || (created ? 'Generated User' : 'Provided User'),
            role: identityId === 'primary-user' ? 'primary' : 'secondary',
            username: credential.username || credential.email,
            email: credential.email,
            roleInApp: credential.role,
            credentialSet: credential.password ? { username: credential.username || credential.email || identityId, password: credential.password, loginMethod: 'browser', capturedAt: new Date(), source: credential.source || 'scan_config' } : undefined,
        });
    }

    private hasAuth(identityId: string): boolean {
        return (this.authManager.getCookieJar(identityId)?.size || 0) > 0 || (this.authManager.getTokenStore(identityId)?.activeCount || 0) > 0;
    }

    private addRoute(inventory: AuthStartupInventory, route: string): void {
        if (!route) return;
        let normalized = route;
        try { normalized = new URL(route).pathname; } catch { if (!route.startsWith('/')) return; }
        if (!inventory.authRoutes.includes(normalized)) inventory.authRoutes.push(normalized);
    }

    private lastTrafficId(sessionId: string): number {
        const events = browserService.getTrafficSnapshot(sessionId);
        return events.length > 0 ? events[events.length - 1].id : 0;
    }

    private async captureTraffic(sessionId: string, inventory: AuthStartupInventory, identityId: string, afterId: number, actionType: 'navigate' | 'click' | 'submit' | 'login' | 'register' | 'discovery'): Promise<void> {
        const intent = actionType === 'register'
            ? 'account_creation'
            : ['login', 'discovery'].includes(actionType)
                ? 'anonymous_auth_probe'
                : 'authenticated';
        for (const event of browserService.getTrafficSnapshot(sessionId).filter((item) => item.id > afterId)) {
            if (event.kind === 'request' && event.requestHeaders) {
                this.authManager.captureFromStructuredRequest({ requestHeaders: event.requestHeaders, url: event.url, body: event.requestBody || '' }, identityId, 'browser_network_request');
                inventory.traffic.push({ source: 'browser', method: event.method, url: event.url, requestHeaders: event.requestHeaders, authorizationScheme: this.authHeaderScheme(event.requestHeaders) });
            }
            if (event.kind === 'response') {
                this.authManager.handleResponse(event.statusCode || 0, event.responseHeaders || {}, '', event.url, identityId, intent);
                inventory.traffic.push({ source: 'browser', method: event.method, url: event.url, statusCode: event.statusCode, responseHeaders: event.responseHeaders, setCookieNames: this.setCookieNames(event.responseHeaders), authorizationScheme: this.authHeaderScheme(event.responseHeaders) });
            }
        }
    }

    private async captureBurp(_sessionId: string, inventory: AuthStartupInventory, identityId: string): Promise<void> {
        try {
            const host = new URL(this.targetUrl).hostname;
            for (const entry of normalizeProxyHistoryItems(await this.burp.callTool('get_proxy_history', { count: 80, includeDetails: true }))) {
                const entryUrl = typeof entry?.url === 'string' ? entry.url : '';
                if (!entryUrl) continue;
                try { if (new URL(entryUrl).hostname !== host) continue; } catch { continue; }
                if (/\/socket\.io\/|\/sockjs\/|\/__webpack_hmr|transport=polling|[?&]EIO=/i.test(entryUrl)) continue;
                const intent = this.authManager.inferRequestIntent(entryUrl, String(entry.method || 'GET').toUpperCase());
                if (entry.requestHeaders) this.authManager.captureFromStructuredRequest({ requestHeaders: entry.requestHeaders, url: entryUrl, body: typeof entry.requestBody === 'string' ? entry.requestBody : '' }, identityId);
                if (entry.responseHeaders) this.authManager.handleResponse(Number(entry.statusCode || entry.status || 0), entry.responseHeaders, typeof entry.responseBody === 'string' ? entry.responseBody : '', entryUrl, identityId, intent);
                inventory.traffic.push({ source: 'burp', method: String(entry.method || 'GET').toUpperCase(), url: entryUrl, statusCode: Number(entry.statusCode || entry.status || 0) || undefined, requestHeaders: entry.requestHeaders, responseHeaders: entry.responseHeaders, setCookieNames: this.setCookieNames(entry.responseHeaders), authorizationScheme: this.authHeaderScheme(entry.requestHeaders) });
            }
        } catch (error: any) {
            this.log('debug', `Burp auth correlation failed: ${error.message}`);
        }
    }

    private inferTransport(inventory: AuthStartupInventory, identityId: string) {
        const authSchemes = new Set<string>();
        const cookieNames = new Set<string>();
        const csrfHeaders = new Set<string>();
        const csrfCookieNames = new Set<string>();
        const csrfFields = new Set<string>(inventory.transport.csrfFormFields);
        for (const entry of inventory.traffic) {
            const scheme = entry.authorizationScheme;
            if (scheme) authSchemes.add(scheme);
            (entry.setCookieNames || []).forEach((name) => {
                cookieNames.add(name);
                if (/csrf|xsrf/i.test(name)) csrfCookieNames.add(name);
            });
            Object.keys(entry.requestHeaders || {}).forEach((name) => { if (/csrf|xsrf/i.test(name)) csrfHeaders.add(name); });
            Object.keys(entry.responseHeaders || {}).forEach((name) => { if (/csrf|xsrf/i.test(name)) csrfHeaders.add(name); });
        }
        this.authManager.getCookieJar(identityId)?.getAll().forEach((cookie) => { cookieNames.add(cookie.name); if (cookie.isCSRFCookie) csrfCookieNames.add(cookie.name); });
        const tokenStore = this.authManager.getTokenStore(identityId);
        if (tokenStore?.getActive()) authSchemes.add(tokenStore.getActive()!.headerValuePrefix.trim() || tokenStore.getActive()!.tokenType);
        const csrf = this.authManager.getCSRFManager(identityId)?.getPrimary();
        if (csrf?.headerName) csrfHeaders.add(csrf.headerName);
        if (csrf?.tokenName) csrfFields.add(csrf.tokenName);
        return {
            carriesAuthorizationHeader: authSchemes.size > 0,
            authorizationSchemes: [...authSchemes],
            cookieNames: [...cookieNames],
            localStorageKeys: [...new Set(inventory.transport.localStorageKeys)],
            sessionStorageKeys: [...new Set(inventory.transport.sessionStorageKeys)],
            indexedDbNames: [...new Set(inventory.transport.indexedDbNames)],
            csrfHeaders: [...csrfHeaders],
            csrfFormFields: [...csrfFields],
            csrfMetaNames: [...new Set(inventory.transport.csrfMetaNames)],
            csrfCookieNames: [...csrfCookieNames],
            mixedTransport: authSchemes.size > 0 && cookieNames.size > 0,
            evidence: [`traffic=${inventory.traffic.length}`, `identities=${this.authManager.identityRegistry.getAll().length}`],
        };
    }

    private authHeaderScheme(headers?: Record<string, string>): string | undefined {
        if (!headers) return undefined;
        const value = Object.entries(headers).find(([name]) => name.toLowerCase() === 'authorization')?.[1];
        if (!value) return undefined;
        return String(value).split(/\s+/, 1)[0];
    }

    private setCookieNames(headers?: Record<string, string>): string[] {
        if (!headers) return [];
        const value = Object.entries(headers).find(([name]) => name.toLowerCase() === 'set-cookie')?.[1];
        if (!value) return [];
        if (Array.isArray(value)) {
            return value
                .map((entry) => String(entry).split('=', 1)[0].trim())
                .filter(Boolean);
        }
        return String(value)
            .split(/,(?=[^;]+?=)/)
            .map((entry) => entry.split('=', 1)[0].trim())
            .filter(Boolean);
    }

    private buildSummary(inventory: AuthStartupInventory): string {
        const transport = [];
        if (inventory.transport.authorizationSchemes.length > 0) transport.push(`authorization=${inventory.transport.authorizationSchemes.join(',')}`);
        if (inventory.transport.cookieNames.length > 0) transport.push(`cookies=${inventory.transport.cookieNames.slice(0, 5).join(',')}`);
        if (inventory.transport.localStorageKeys.length > 0) transport.push(`localStorage=${inventory.transport.localStorageKeys.slice(0, 5).join(',')}`);
        if (inventory.transport.sessionStorageKeys.length > 0) transport.push(`sessionStorage=${inventory.transport.sessionStorageKeys.slice(0, 5).join(',')}`);
        return `Auth-first startup: routes=${inventory.authRoutes.length}, forms=${inventory.forms.length}, auth-controls=${inventory.domElements.length}, credentials=${inventory.discoveredCredentials.length}, transport=${transport.join(' | ') || 'not yet inferred'}`;
    }
}
