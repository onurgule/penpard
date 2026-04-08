import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { browserService, CapturedJsArtifact } from './BrowserService';
import { BurpMCPClient } from './burp-mcp';
import { llmProvider } from './LLMProviderService';
import {
    AuthStartupInventory,
    AuthSurfaceType,
} from './auth';
import { normalizeProxyHistoryItems } from './burp-tool-result';
import { logger } from '../utils/logger';

export type EndpointDiscoverySource = 'js' | 'dom' | 'burp' | 'browser_navigation' | 'sitemap' | 'inferred';

export type EndpointAuthClassification =
    | 'login'
    | 'register'
    | 'forgot_password'
    | 'reset_password'
    | 'session_bootstrap'
    | 'profile_account'
    | 'auth_refresh'
    | 'logout'
    | 'admin_only'
    | 'auth_gateway'
    | 'unrelated'
    | 'unknown';

export interface EndpointIntelligenceRecord {
    id: string;
    endpoint: string;
    path: string;
    methods: string[];
    primarySource: EndpointDiscoverySource;
    sources: EndpointDiscoverySource[];
    confidence: number;
    classification: EndpointAuthClassification;
    likelyAuthRelevant: boolean;
    observedInBurp: boolean;
    exercisedInBrowser: boolean;
    inferredOnly: boolean;
    notes: string[];
    evidence: string[];
    scriptSources: string[];
    domSources: string[];
    authSignals: string[];
    storageKeys: string[];
    observedStatusCodes: number[];
}

export interface EndpointInventorySnapshot {
    scanId: string;
    targetUrl: string;
    targetOrigin: string;
    generatedAt: string;
    summary: string;
    authRelevantCount: number;
    observedInBurpCount: number;
    exercisedInBrowserCount: number;
    jsArtifacts: {
        count: number;
        analyzedCount: number;
        totalBytes: number;
        storedDir?: string;
    };
    classifications: Record<string, number>;
    records: EndpointIntelligenceRecord[];
}

interface EndpointSeed {
    endpoint: string;
    path: string;
    method?: string;
    source: EndpointDiscoverySource;
    confidence: number;
    classification: EndpointAuthClassification;
    likelyAuthRelevant: boolean;
    observedInBurp?: boolean;
    exercisedInBrowser?: boolean;
    inferredOnly?: boolean;
    notes?: string[];
    evidence?: string[];
    scriptSource?: string;
    domSource?: string;
    authSignals?: string[];
    storageKeys?: string[];
    statusCodes?: number[];
}

interface JavaScriptDigResult {
    candidates: EndpointSeed[];
    artifactCount: number;
    totalBytes: number;
}

const STATIC_ASSET_RE = /\.(?:css|js|mjs|png|jpg|jpeg|gif|svg|woff2?|ttf|ico|map|webp|avif)(?:\?|$)/i;
const NOISE_RE = /\/socket\.io\/|\/sockjs\/|\/__webpack_hmr|\/vite\/|\/@vite\/client|hot-update|transport=polling|[?&]EIO=/i;
const STORAGE_KEY_RE = /(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\(\s*['"`]([^'"`]+)['"`]\s*\)/gi;

const CLASSIFICATION_PRIORITY: EndpointAuthClassification[] = [
    'login',
    'register',
    'forgot_password',
    'reset_password',
    'session_bootstrap',
    'profile_account',
    'auth_refresh',
    'logout',
    'admin_only',
    'auth_gateway',
    'unknown',
    'unrelated',
];

const SOURCE_PRIORITY: EndpointDiscoverySource[] = ['burp', 'browser_navigation', 'dom', 'js', 'sitemap', 'inferred'];

const AUTH_CLASSIFICATIONS = new Set<EndpointAuthClassification>([
    'login',
    'register',
    'forgot_password',
    'reset_password',
    'session_bootstrap',
    'profile_account',
    'auth_refresh',
    'logout',
    'admin_only',
    'auth_gateway',
]);

function dedupeStrings(values: Array<string | undefined | null>): string[] {
    return Array.from(new Set(values.filter((value): value is string => typeof value === 'string' && value.trim().length > 0)));
}

function clampConfidence(value: number): number {
    return Math.max(0, Math.min(1, Number(value.toFixed(2))));
}

function sourcePriority(source: EndpointDiscoverySource): number {
    const index = SOURCE_PRIORITY.indexOf(source);
    return index === -1 ? SOURCE_PRIORITY.length : index;
}

function classificationPriority(classification: EndpointAuthClassification): number {
    const index = CLASSIFICATION_PRIORITY.indexOf(classification);
    return index === -1 ? CLASSIFICATION_PRIORITY.length : index;
}

function isNoiseUrl(url: string): boolean {
    return NOISE_RE.test(url);
}

function isStaticAssetUrl(url: string): boolean {
    return STATIC_ASSET_RE.test(url);
}

function safeJsonParse<T>(text: string): T | null {
    try {
        return JSON.parse(text) as T;
    } catch {
        return null;
    }
}

function jsonBlock<T>(text: string): T | null {
    const direct = safeJsonParse<T>(text.trim());
    if (direct) return direct;
    const match = text.match(/\{[\s\S]*\}$/) || text.match(/\{[\s\S]*\}/);
    if (!match) return null;
    return safeJsonParse<T>(match[0]);
}

function authSurfaceToClassification(type: AuthSurfaceType): EndpointAuthClassification {
    switch (type) {
        case 'login':
            return 'login';
        case 'register':
            return 'register';
        case 'forgot_password':
        case 'recover_account':
            return 'forgot_password';
        case 'reset_password':
            return 'reset_password';
        case 'verify_email':
        case 'activation':
        case 'onboarding':
        case 'otp':
        case 'mfa':
        case 'totp':
        case 'sso':
        case 'invite':
        case 'magic_link':
            return 'auth_gateway';
        default:
            return 'unknown';
    }
}

class JavaScriptDiggingWorker {
    constructor(
        private readonly targetUrl: string,
        private readonly targetOrigin: string,
        private readonly log?: (level: 'system' | 'debug' | 'error', message: string) => void,
    ) {}

    public async analyze(artifacts: CapturedJsArtifact[], allowAiClassification: boolean): Promise<JavaScriptDigResult> {
        const candidates: EndpointSeed[] = [];
        let totalBytes = 0;
        const artifactContexts: Array<{
            endpoint: string;
            scriptSource: string;
            classification: EndpointAuthClassification;
            confidence: number;
            evidence: string;
            authSignals: string[];
        }> = [];

        for (const artifact of artifacts) {
            const content = this.readArtifactContent(artifact);
            if (!content) continue;
            totalBytes += Buffer.byteLength(content, 'utf8');
            candidates.push(...this.extractStorageSignals(content, artifact));

            for (const seed of this.extractEndpoints(content, artifact)) {
                candidates.push(seed);
                artifactContexts.push({
                    endpoint: seed.endpoint,
                    scriptSource: seed.scriptSource || artifact.scriptUrl || artifact.filePath,
                    classification: seed.classification,
                    confidence: seed.confidence,
                    evidence: (seed.evidence || []).join(' | ').slice(0, 400),
                    authSignals: seed.authSignals || [],
                });
            }
        }

        if (allowAiClassification && artifactContexts.length > 0) {
            await this.applyAiClassification(candidates, artifactContexts.slice(0, 40));
        }

        return {
            candidates,
            artifactCount: artifacts.length,
            totalBytes,
        };
    }

    private readArtifactContent(artifact: CapturedJsArtifact): string {
        try {
            if (!artifact.filePath || !fs.existsSync(artifact.filePath)) return '';
            const content = fs.readFileSync(artifact.filePath, 'utf8');
            return content.length > 200_000 ? content.slice(0, 200_000) : content;
        } catch (error: any) {
            this.log?.('debug', `JS artifact read failed for ${artifact.filePath}: ${error.message}`);
            return '';
        }
    }

    private extractStorageSignals(content: string, artifact: CapturedJsArtifact): EndpointSeed[] {
        const seeds: EndpointSeed[] = [];
        const storageKeys = new Set<string>();
        let match: RegExpExecArray | null;
        while ((match = STORAGE_KEY_RE.exec(content)) !== null) {
            storageKeys.add(match[1]);
        }

        const authSignals = dedupeStrings([
            /authorization/i.test(content) ? 'Authorization header handling' : '',
            /\bbearer\b/i.test(content) ? 'Bearer token handling' : '',
            /\bcsrf\b|\bxsrf\b/i.test(content) ? 'CSRF token handling' : '',
            /\brefresh[_-]?token\b/i.test(content) ? 'Refresh token handling' : '',
            /\bindexeddb\b/i.test(content) ? 'IndexedDB usage' : '',
        ]);

        if (storageKeys.size === 0 && authSignals.length === 0) {
            return seeds;
        }

        seeds.push({
            endpoint: this.targetOrigin,
            path: '/',
            source: 'js',
            confidence: 0.35,
            classification: authSignals.some((signal) => /Authorization|Bearer|CSRF|Refresh/i.test(signal)) ? 'session_bootstrap' : 'unknown',
            likelyAuthRelevant: authSignals.length > 0,
            notes: storageKeys.size > 0 ? [`Storage keys: ${Array.from(storageKeys).join(', ')}`] : [],
            evidence: authSignals,
            scriptSource: artifact.scriptUrl || artifact.filePath,
            authSignals,
            storageKeys: Array.from(storageKeys),
        });

        return seeds;
    }

    private extractEndpoints(content: string, artifact: CapturedJsArtifact): EndpointSeed[] {
        const seeds: EndpointSeed[] = [];
        const patterns: Array<{
            type: string;
            regex: RegExp;
            method?: string;
            confidence: number;
            pathGroup: number;
            methodGroup?: number;
        }> = [
            { type: 'fetch', regex: /fetch\s*\(\s*['"`]([^'"`]+)['"`]/gi, method: 'GET', confidence: 0.7, pathGroup: 1 },
            { type: 'axios-call', regex: /axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi, confidence: 0.82, pathGroup: 2, methodGroup: 1 },
            { type: 'xhr', regex: /open\s*\(\s*['"`]([A-Z]+)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi, confidence: 0.78, pathGroup: 2, methodGroup: 1 },
            { type: 'graphql', regex: /['"`]([^'"`]*graphql[^'"`]+)['"`]/gi, method: 'POST', confidence: 0.76, pathGroup: 1 },
            { type: 'websocket', regex: /new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]/gi, method: 'GET', confidence: 0.74, pathGroup: 1 },
            { type: 'route', regex: /(?:path|route|href|action)\s*[:=]\s*['"`](\/[^'"`\s]{1,180})['"`]/gi, method: 'GET', confidence: 0.56, pathGroup: 1 },
            { type: 'api-path', regex: /['"`]((?:\/|(?:api|rest|graphql|auth)\/)[^'"`\s]{2,200})['"`]/gi, method: 'GET', confidence: 0.52, pathGroup: 1 },
        ];

        for (const pattern of patterns) {
            let match: RegExpExecArray | null;
            while ((match = pattern.regex.exec(content)) !== null) {
                const rawPath = match[pattern.pathGroup];
                const normalized = this.normalizeCandidateUrl(rawPath, artifact.pageUrl);
                if (!normalized) continue;
                if (isNoiseUrl(normalized.endpoint) || isStaticAssetUrl(normalized.endpoint)) continue;

                const snippet = this.snippet(content, match.index, rawPath.length);
                const classification = this.classify(normalized.endpoint, snippet);
                const authSignals = this.authSignals(rawPath, snippet);
                const confidence = clampConfidence(
                    pattern.confidence +
                    (classification !== 'unknown' && classification !== 'unrelated' ? 0.08 : 0) -
                    (/\$\{|\{\{/.test(rawPath) ? 0.12 : 0),
                );

                seeds.push({
                    endpoint: normalized.endpoint,
                    path: normalized.path,
                    method: pattern.methodGroup ? String(match[pattern.methodGroup]).toUpperCase() : pattern.method,
                    source: 'js',
                    confidence,
                    classification,
                    likelyAuthRelevant: AUTH_CLASSIFICATIONS.has(classification),
                    evidence: [`${pattern.type}: ${snippet}`],
                    notes: [`Script origin: ${artifact.origin || this.targetOrigin}`],
                    scriptSource: artifact.scriptUrl || artifact.filePath,
                    authSignals,
                    storageKeys: [],
                });
            }
        }

        return seeds;
    }

    private normalizeCandidateUrl(rawPath: string, pageUrl: string): { endpoint: string; path: string } | null {
        const cleaned = rawPath
            .trim()
            .replace(/\$\{[^}]+\}/g, ':var')
            .replace(/\{\{[^}]+\}\}/g, ':var');

        if (!cleaned || /\s/.test(cleaned) || cleaned.length > 240) {
            return null;
        }

        try {
            if (/^wss?:\/\//i.test(cleaned)) {
                const wsUrl = new URL(cleaned);
                return { endpoint: wsUrl.toString(), path: wsUrl.pathname + wsUrl.search };
            }

            if (/^https?:\/\//i.test(cleaned)) {
                const absolute = new URL(cleaned);
                return { endpoint: absolute.toString(), path: absolute.pathname + absolute.search };
            }

            if (cleaned.startsWith('//')) {
                const resolved = new URL(`${new URL(this.targetUrl).protocol}${cleaned}`);
                return { endpoint: resolved.toString(), path: resolved.pathname + resolved.search };
            }

            const base = pageUrl || this.targetUrl;
            const resolved = cleaned.startsWith('/') || cleaned.startsWith('./') || cleaned.startsWith('../')
                ? new URL(cleaned, base)
                : new URL(cleaned.startsWith('api/') || cleaned.startsWith('rest/') || cleaned.startsWith('auth/') || cleaned.startsWith('graphql')
                    ? `/${cleaned}`
                    : cleaned, this.targetUrl);
            return { endpoint: resolved.toString(), path: resolved.pathname + resolved.search };
        } catch {
            return null;
        }
    }

    private classify(endpoint: string, evidence: string): EndpointAuthClassification {
        const text = `${endpoint} ${evidence}`.toLowerCase();

        if (/login|signin|sign-in/.test(text)) return 'login';
        if (/register|signup|sign-up|create-account/.test(text)) return 'register';
        if (/forgot|recover/.test(text)) return 'forgot_password';
        if (/reset-password|password\/reset|reset/.test(text)) return 'reset_password';
        if (/refresh/.test(text)) return 'auth_refresh';
        if (/logout|signout|sign-out/.test(text)) return 'logout';
        if (/oauth|sso|saml|oidc|auth0|okta|google|github|microsoft/.test(text)) return 'auth_gateway';
        if (/profile|account|\/me\b|current-user|currentuser|user-profile/.test(text)) return 'profile_account';
        if (/admin|role|permission|manage-users|user-management/.test(text)) return 'admin_only';
        if (/auth|session|token|verify-email|activate|onboarding|otp|mfa|2fa|totp/.test(text)) return 'session_bootstrap';
        if (isNoiseUrl(endpoint)) return 'unrelated';
        return 'unknown';
    }

    private authSignals(rawPath: string, snippet: string): string[] {
        const combined = `${rawPath} ${snippet}`;
        return dedupeStrings([
            /\bauthorization\b/i.test(combined) ? 'Authorization header' : '',
            /\bbearer\b/i.test(combined) ? 'Bearer token' : '',
            /\bcsrf\b|\bxsrf\b/i.test(combined) ? 'CSRF token' : '',
            /\blocalstorage\b/i.test(combined) ? 'localStorage' : '',
            /\bsessionstorage\b/i.test(combined) ? 'sessionStorage' : '',
            /\brefresh[_-]?token\b/i.test(combined) ? 'refresh token' : '',
            /\bgraphql\b/i.test(combined) ? 'GraphQL' : '',
            /\bwebsocket\b|wss?:\/\//i.test(combined) ? 'WebSocket' : '',
        ]);
    }

    private snippet(content: string, index: number, length: number): string {
        const start = Math.max(0, index - 80);
        const end = Math.min(content.length, index + length + 120);
        return content.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 240);
    }

    private async applyAiClassification(
        candidates: EndpointSeed[],
        contexts: Array<{
            endpoint: string;
            scriptSource: string;
            classification: EndpointAuthClassification;
            confidence: number;
            evidence: string;
            authSignals: string[];
        }>,
    ): Promise<void> {
        try {
            const response = await llmProvider.generate({
                systemPrompt: 'You are a JavaScript security analysis worker. Output ONLY valid JSON, no markdown.',
                userPrompt: `Analyze the following endpoint candidates extracted from JavaScript that was actually loaded by a target application in a proxied browser session.

Classify each item into one of:
- login
- register
- forgot_password
- reset_password
- session_bootstrap
- profile_account
- auth_refresh
- logout
- admin_only
- auth_gateway
- unrelated
- unknown

You may also infer up to 8 additional endpoints only when the JavaScript strongly implies them.

Candidates:
${JSON.stringify(contexts, null, 2).slice(0, 18000)}

Return JSON exactly like:
{
  "records":[
    {"endpoint":"https://target/rest/user/login","classification":"login","confidence":0.91,"likelyAuthRelevant":true,"notes":["Used in axios.post login flow"]}
  ],
  "inferred":[
    {"endpoint":"https://target/rest/user/logout","classification":"logout","confidence":0.62,"notes":["Nearby login/session code implies logout sibling route"]}
  ]
}`,
            }, 'endpoint-intelligence-js-worker');

            const parsed = jsonBlock<{
                records?: Array<{
                    endpoint?: string;
                    classification?: EndpointAuthClassification;
                    confidence?: number;
                    likelyAuthRelevant?: boolean;
                    notes?: string[];
                }>;
                inferred?: Array<{
                    endpoint?: string;
                    classification?: EndpointAuthClassification;
                    confidence?: number;
                    notes?: string[];
                }>;
            }>(response.text);

            if (!parsed) {
                return;
            }

            for (const record of parsed.records || []) {
                if (!record.endpoint) continue;
                const match = candidates.find((candidate) => candidate.endpoint === record.endpoint);
                if (!match) continue;
                if (record.classification) {
                    match.classification = record.classification;
                    match.likelyAuthRelevant = AUTH_CLASSIFICATIONS.has(record.classification);
                }
                if (typeof record.confidence === 'number') {
                    match.confidence = clampConfidence(record.confidence);
                }
                if (Array.isArray(record.notes) && record.notes.length > 0) {
                    match.notes = dedupeStrings([...(match.notes || []), ...record.notes]);
                }
            }

            for (const inferred of parsed.inferred || []) {
                if (!inferred.endpoint) continue;
                const normalized = this.normalizeCandidateUrl(inferred.endpoint, this.targetUrl);
                if (!normalized) continue;
                if (isNoiseUrl(normalized.endpoint) || isStaticAssetUrl(normalized.endpoint)) continue;

                const inferredClassification = inferred.classification || this.classify(normalized.endpoint, '');
                candidates.push({
                    endpoint: normalized.endpoint,
                    path: normalized.path,
                    source: 'inferred',
                    confidence: clampConfidence(inferred.confidence ?? 0.55),
                    classification: inferredClassification,
                    likelyAuthRelevant: AUTH_CLASSIFICATIONS.has(inferredClassification),
                    inferredOnly: true,
                    notes: inferred.notes || ['Inferred from loaded JavaScript by JS digging worker'],
                    evidence: ['LLM inferred from loaded JavaScript context'],
                    authSignals: [],
                    storageKeys: [],
                });
            }
        } catch (error: any) {
            logger.warn('JavaScript digging worker AI classification failed', { error: error.message });
            this.log?.('debug', `JS digging worker AI classification failed: ${error.message}`);
        }
    }
}

export class EndpointIntelligenceService {
    constructor(
        private readonly scanId: string,
        private readonly targetUrl: string,
        private readonly burp: BurpMCPClient,
        private readonly log?: (level: 'system' | 'debug' | 'error', message: string) => void,
    ) {}

    public async buildInventory(options: {
        browserSessionId?: string | null;
        authInventory?: AuthStartupInventory | null;
        allowAiClassification?: boolean;
    }): Promise<EndpointInventorySnapshot> {
        const targetHost = new URL(this.targetUrl).hostname;
        const targetOrigin = new URL(this.targetUrl).origin;
        const records = new Map<string, EndpointIntelligenceRecord>();
        let jsArtifacts: CapturedJsArtifact[] = [];
        let jsDigResult: JavaScriptDigResult = { candidates: [], artifactCount: 0, totalBytes: 0 };

        if (options.browserSessionId) {
            jsArtifacts = await browserService.captureJavaScriptArtifacts(options.browserSessionId).catch(() => []);
            const worker = new JavaScriptDiggingWorker(this.targetUrl, targetOrigin, this.log);
            jsDigResult = await worker.analyze(jsArtifacts, options.allowAiClassification === true);
            for (const candidate of jsDigResult.candidates) {
                const sameHost = this.sameHost(candidate.endpoint, targetHost);
                if (!sameHost && !AUTH_CLASSIFICATIONS.has(candidate.classification)) {
                    continue;
                }
                this.upsert(records, candidate);
            }

            for (const event of browserService.getTrafficSnapshot(options.browserSessionId)) {
                if (event.originCategory === 'internal') continue;
                if (event.kind !== 'request' && event.kind !== 'response') continue;
                if (isNoiseUrl(event.url) || isStaticAssetUrl(event.url)) continue;

                const sameHost = this.sameHost(event.url, targetHost);
                const classification = this.classifyFromUrl(event.url);
                if (!sameHost && !AUTH_CLASSIFICATIONS.has(classification)) continue;

                this.upsert(records, {
                    endpoint: event.url,
                    path: this.pathOf(event.url),
                    method: event.method,
                    source: 'browser_navigation',
                    confidence: sameHost ? 0.78 : 0.64,
                    classification,
                    likelyAuthRelevant: AUTH_CLASSIFICATIONS.has(classification),
                    exercisedInBrowser: true,
                    evidence: [`browser ${event.kind} ${event.resourceType || 'request'}`],
                    statusCodes: typeof event.statusCode === 'number' ? [event.statusCode] : [],
                    authSignals: dedupeStrings([
                        event.requestHeaders?.authorization ? 'Authorization header observed' : '',
                        event.requestHeaders?.cookie ? 'Cookie observed' : '',
                    ]),
                    storageKeys: [],
                });
            }
        }

        if (options.authInventory) {
            this.applyAuthInventory(records, options.authInventory);
        }

        const burpHistory = await this.loadBurpHistory();
        for (const entry of burpHistory) {
            const entryUrl = String(entry?.url || '');
            if (!entryUrl || isNoiseUrl(entryUrl) || isStaticAssetUrl(entryUrl)) continue;
            const classification = this.classifyFromUrl(entryUrl);
            const sameHost = this.sameHost(entryUrl, targetHost);
            if (!sameHost && !AUTH_CLASSIFICATIONS.has(classification)) continue;

            const requestHeaders = this.normalizeHeaders(entry.requestHeaders || entry.headers || {});
            const authSignals = dedupeStrings([
                requestHeaders.authorization ? 'Authorization header observed' : '',
                requestHeaders.cookie ? 'Cookie observed' : '',
                requestHeaders['x-csrf-token'] || requestHeaders['x-xsrf-token'] ? 'CSRF header observed' : '',
            ]);

            this.upsert(records, {
                endpoint: entryUrl,
                path: this.pathOf(entryUrl),
                method: String(entry.method || 'GET').toUpperCase(),
                source: 'burp',
                confidence: 0.9,
                classification,
                likelyAuthRelevant: AUTH_CLASSIFICATIONS.has(classification),
                observedInBurp: true,
                evidence: [`Burp proxy ${entry.statusCode || entry.status || 0}`],
                statusCodes: [Number(entry.statusCode || entry.status || 0)].filter((value) => Number.isFinite(value) && value > 0),
                authSignals,
                storageKeys: [],
            });
        }

        const sortedRecords = Array.from(records.values())
            .map((record) => ({
                ...record,
                inferredOnly: record.sources.every((source) => source === 'inferred'),
                methods: record.methods.sort(),
                sources: record.sources.sort((a, b) => sourcePriority(a) - sourcePriority(b)) as EndpointDiscoverySource[],
                notes: dedupeStrings(record.notes),
                evidence: dedupeStrings(record.evidence).slice(0, 8),
                scriptSources: dedupeStrings(record.scriptSources).slice(0, 6),
                domSources: dedupeStrings(record.domSources).slice(0, 6),
                authSignals: dedupeStrings(record.authSignals),
                storageKeys: dedupeStrings(record.storageKeys),
                observedStatusCodes: Array.from(new Set(record.observedStatusCodes)).sort((a, b) => a - b),
            }))
            .sort((a, b) => {
                const classificationDiff = classificationPriority(a.classification) - classificationPriority(b.classification);
                if (classificationDiff !== 0) return classificationDiff;
                if (b.confidence !== a.confidence) return b.confidence - a.confidence;
                return a.endpoint.localeCompare(b.endpoint);
            });

        const classifications: Record<string, number> = {};
        for (const record of sortedRecords) {
            classifications[record.classification] = (classifications[record.classification] || 0) + 1;
        }

        const authRelevantCount = sortedRecords.filter((record) => record.likelyAuthRelevant).length;
        const observedInBurpCount = sortedRecords.filter((record) => record.observedInBurp).length;
        const exercisedInBrowserCount = sortedRecords.filter((record) => record.exercisedInBrowser).length;

        return {
            scanId: this.scanId,
            targetUrl: this.targetUrl,
            targetOrigin,
            generatedAt: new Date().toISOString(),
            summary: `${sortedRecords.length} endpoint(s), ${authRelevantCount} auth-relevant, ${observedInBurpCount} seen in Burp, ${exercisedInBrowserCount} exercised in browser`,
            authRelevantCount,
            observedInBurpCount,
            exercisedInBrowserCount,
            jsArtifacts: {
                count: jsArtifacts.length,
                analyzedCount: jsDigResult.artifactCount,
                totalBytes: jsDigResult.totalBytes,
                storedDir: jsArtifacts[0]?.filePath ? path.dirname(jsArtifacts[0].filePath) : undefined,
            },
            classifications,
            records: sortedRecords,
        };
    }

    private async loadBurpHistory(): Promise<any[]> {
        try {
            return normalizeProxyHistoryItems(await this.burp.callTool('get_proxy_history', {
                count: 150,
                includeDetails: true,
                excludePenPard: true,
            }));
        } catch (error: any) {
            logger.warn('Endpoint intelligence could not load Burp history', { error: error.message });
            this.log?.('debug', `Endpoint intelligence Burp history load failed: ${error.message}`);
            return [];
        }
    }

    private applyAuthInventory(records: Map<string, EndpointIntelligenceRecord>, inventory: AuthStartupInventory): void {
        for (const form of inventory.forms) {
            const endpoint = this.normalizeRoute(form.action);
            if (!endpoint) continue;
            this.upsert(records, {
                endpoint,
                path: this.pathOf(endpoint),
                method: (form.method || 'GET').toUpperCase(),
                source: 'dom',
                confidence: 0.86,
                classification: authSurfaceToClassification(form.type),
                likelyAuthRelevant: true,
                exercisedInBrowser: true,
                evidence: [`form:${form.formId || form.selector || form.action}`],
                domSource: form.selector || form.formId,
                notes: [
                    form.fields.length > 0
                        ? `Fields: ${form.fields.map((field) => `${field.name || field.id || 'unnamed'}:${field.type}`).slice(0, 6).join(', ')}`
                        : 'No visible fields captured',
                    form.hiddenInputs.length > 0
                        ? `Hidden inputs: ${form.hiddenInputs.map((field) => field.name || field.id || 'hidden').slice(0, 6).join(', ')}`
                        : '',
                ],
                authSignals: form.antiAutomationMarkers.length > 0 ? ['Anti-automation markers present'] : [],
                storageKeys: [],
            });
        }

        for (const element of inventory.domElements) {
            const endpoint = this.normalizeRoute(element.href || element.action || element.routeHint || '');
            if (!endpoint) continue;
            this.upsert(records, {
                endpoint,
                path: this.pathOf(endpoint),
                method: 'GET',
                source: 'dom',
                confidence: 0.72,
                classification: authSurfaceToClassification(element.type),
                likelyAuthRelevant: true,
                exercisedInBrowser: true,
                evidence: [`DOM ${element.tagName}: ${element.text || element.selector}`],
                domSource: element.selector,
                notes: element.provider ? [`Provider: ${element.provider}`] : [],
                authSignals: element.provider ? [`SSO provider ${element.provider}`] : [],
                storageKeys: [],
            });
        }

        for (const traffic of inventory.traffic) {
            if (!traffic.url || isNoiseUrl(traffic.url) || isStaticAssetUrl(traffic.url)) continue;
            const classification = this.classifyFromUrl(traffic.url);
            this.upsert(records, {
                endpoint: traffic.url,
                path: this.pathOf(traffic.url),
                method: traffic.method,
                source: traffic.source === 'burp' ? 'burp' : 'browser_navigation',
                confidence: traffic.source === 'burp' ? 0.88 : 0.76,
                classification,
                likelyAuthRelevant: AUTH_CLASSIFICATIONS.has(classification),
                observedInBurp: traffic.source === 'burp',
                exercisedInBrowser: traffic.source === 'browser',
                evidence: [`startup traffic ${traffic.statusCode || 0}`],
                authSignals: dedupeStrings([
                    traffic.authorizationScheme ? `${traffic.authorizationScheme} auth observed` : '',
                    ...(traffic.setCookieNames || []).map((cookieName) => `Set-Cookie ${cookieName}`),
                ]),
                storageKeys: traffic.storageKeys || [],
                statusCodes: traffic.statusCode ? [traffic.statusCode] : [],
            });
        }
    }

    private upsert(records: Map<string, EndpointIntelligenceRecord>, seed: EndpointSeed): void {
        const key = seed.endpoint;
        const existing = records.get(key);
        if (!existing) {
            records.set(key, {
                id: `endpoint-${createHash('sha1').update(key).digest('hex').slice(0, 16)}`,
                endpoint: seed.endpoint,
                path: seed.path,
                methods: dedupeStrings([seed.method || 'GET']),
                primarySource: seed.source,
                sources: [seed.source],
                confidence: clampConfidence(seed.confidence),
                classification: seed.classification,
                likelyAuthRelevant: seed.likelyAuthRelevant,
                observedInBurp: seed.observedInBurp === true,
                exercisedInBrowser: seed.exercisedInBrowser === true,
                inferredOnly: seed.inferredOnly === true,
                notes: seed.notes || [],
                evidence: seed.evidence || [],
                scriptSources: seed.scriptSource ? [seed.scriptSource] : [],
                domSources: seed.domSource ? [seed.domSource] : [],
                authSignals: seed.authSignals || [],
                storageKeys: seed.storageKeys || [],
                observedStatusCodes: seed.statusCodes || [],
            });
            return;
        }

        existing.methods = dedupeStrings([...existing.methods, seed.method || 'GET']);
        existing.sources = dedupeStrings([...existing.sources, seed.source]) as EndpointDiscoverySource[];
        existing.notes = dedupeStrings([...existing.notes, ...(seed.notes || [])]);
        existing.evidence = dedupeStrings([...existing.evidence, ...(seed.evidence || [])]);
        existing.scriptSources = dedupeStrings([...existing.scriptSources, seed.scriptSource]);
        existing.domSources = dedupeStrings([...existing.domSources, seed.domSource]);
        existing.authSignals = dedupeStrings([...existing.authSignals, ...(seed.authSignals || [])]);
        existing.storageKeys = dedupeStrings([...existing.storageKeys, ...(seed.storageKeys || [])]);
        existing.observedStatusCodes = Array.from(new Set([...existing.observedStatusCodes, ...(seed.statusCodes || [])]));
        existing.confidence = Math.max(existing.confidence, clampConfidence(seed.confidence));
        existing.observedInBurp ||= seed.observedInBurp === true;
        existing.exercisedInBrowser ||= seed.exercisedInBrowser === true;
        existing.inferredOnly = existing.inferredOnly && seed.inferredOnly === true;
        existing.likelyAuthRelevant ||= seed.likelyAuthRelevant;

        if (
            classificationPriority(seed.classification) < classificationPriority(existing.classification) ||
            (existing.classification === 'unknown' && seed.classification !== 'unknown')
        ) {
            existing.classification = seed.classification;
        }

        if (sourcePriority(seed.source) < sourcePriority(existing.primarySource)) {
            existing.primarySource = seed.source;
        }
    }

    private classifyFromUrl(url: string): EndpointAuthClassification {
        const lower = url.toLowerCase();
        if (/login|signin|sign-in/.test(lower)) return 'login';
        if (/register|signup|sign-up|create-account/.test(lower)) return 'register';
        if (/forgot|recover/.test(lower)) return 'forgot_password';
        if (/reset/.test(lower)) return 'reset_password';
        if (/refresh/.test(lower)) return 'auth_refresh';
        if (/logout|signout|sign-out/.test(lower)) return 'logout';
        if (/oauth|sso|saml|oidc|auth0|okta|google|github|microsoft/.test(lower)) return 'auth_gateway';
        if (/profile|account|\/me\b|current-user/.test(lower)) return 'profile_account';
        if (/admin|manage-users|permissions|roles/.test(lower)) return 'admin_only';
        if (/auth|session|token|verify|activate|onboarding|otp|mfa|2fa|totp/.test(lower)) return 'session_bootstrap';
        if (isNoiseUrl(url)) return 'unrelated';
        return 'unknown';
    }

    private normalizeRoute(route: string): string | null {
        if (!route) return null;
        try {
            return new URL(route, this.targetUrl).toString();
        } catch {
            return null;
        }
    }

    private pathOf(url: string): string {
        try {
            const parsed = new URL(url);
            return parsed.pathname + parsed.search;
        } catch {
            return url;
        }
    }

    private sameHost(url: string, targetHost: string): boolean {
        try {
            return new URL(url).hostname === targetHost;
        } catch {
            return false;
        }
    }

    private normalizeHeaders(headers: any): Record<string, string> {
        if (!headers || typeof headers !== 'object') return {};
        const normalized: Record<string, string> = {};
        for (const [name, value] of Object.entries(headers)) {
            normalized[String(name).toLowerCase()] = String(value);
        }
        return normalized;
    }
}
