/**
 * PenPard Auth State Management — CSRFManager
 * 
 * Per-identity CSRF token lifecycle: detection, storage, refresh, injection.
 * Supports hidden input, meta tag, cookie-to-header, and response header delivery.
 */

import { CSRFState, CSRFDeliveryMechanism, CSRF_PARAM_NAMES, CSRF_HEADER_NAMES, CSRF_COOKIE_PATTERNS, redactSecret } from './types';
import { CookieJar } from './CookieJar';
import { logger } from '../../utils/logger';

export class CSRFManager {
    private csrfStates: Map<string, CSRFState> = new Map(); // keyed by tokenName
    private readonly identityId: string;

    constructor(identityId: string) {
        this.identityId = identityId;
    }

    // ═══════════════════════════════════════════════════════════
    //  DETECTION & CAPTURE
    // ═══════════════════════════════════════════════════════════

    /**
     * Detect CSRF tokens from HTML page state (hidden inputs + meta tags).
     * Called after browser page load or form discovery.
     */
    detectFromPageState(pageState: {
        forms?: Array<{ fields?: Array<{ name: string; type: string; value: string }> }>;
        metaTags?: Array<{ name: string; content: string }>;
    }): CSRFState | null {
        // Check hidden inputs in forms
        if (pageState.forms) {
            for (const form of pageState.forms) {
                if (!form.fields) continue;
                for (const field of form.fields) {
                    if (field.type !== 'hidden') continue;
                    const name = field.name?.toLowerCase() || '';
                    if (CSRF_PARAM_NAMES.includes(name) && field.value) {
                        return this.store({
                            tokenName: field.name,
                            tokenValue: field.value,
                            deliveryMechanism: 'hidden_input',
                            rotatesPerRequest: false,
                        });
                    }
                }
            }
        }

        // Check meta tags
        if (pageState.metaTags) {
            for (const meta of pageState.metaTags) {
                const name = meta.name?.toLowerCase() || '';
                if (CSRF_PARAM_NAMES.some(p => name.includes(p)) && meta.content) {
                    return this.store({
                        tokenName: meta.name,
                        tokenValue: meta.content,
                        deliveryMechanism: 'meta_tag',
                        rotatesPerRequest: false,
                    });
                }
            }
        }

        return null;
    }

    /**
     * Detect CSRF tokens from response headers.
     * Some frameworks return CSRF tokens in response headers.
     */
    detectFromResponseHeaders(headers: Record<string, string>): CSRFState | null {
        for (const [name, value] of Object.entries(headers)) {
            const lower = name.toLowerCase();
            if (CSRF_HEADER_NAMES.includes(lower) && value) {
                return this.store({
                    tokenName: name,
                    tokenValue: value,
                    deliveryMechanism: 'response_header',
                    headerName: name,
                    rotatesPerRequest: false,
                });
            }
        }
        return null;
    }

    /**
     * Detect cookie-to-header CSRF pattern (e.g., XSRF-TOKEN cookie → X-XSRF-TOKEN header).
     * Called from CookieJar when a CSRF cookie is detected.
     */
    detectFromCSRFCookie(cookieName: string, cookieValue: string): CSRFState | null {
        // Map cookie name to expected header name
        const headerMap: Record<string, string> = {
            'xsrf-token': 'X-XSRF-TOKEN',
            '_xsrf': 'X-XSRF-TOKEN',
            'csrf-token': 'X-CSRF-Token',
            'csrftoken': 'X-CSRFToken',
            '_csrf': 'X-CSRF-Token',
        };

        const lower = cookieName.toLowerCase();
        const headerName = headerMap[lower];
        if (headerName) {
            return this.store({
                tokenName: cookieName,
                tokenValue: cookieValue,
                deliveryMechanism: 'cookie_to_header',
                headerName,
                cookieName,
                rotatesPerRequest: false,
            });
        }

        // Generic CSRF cookie → try to guess header
        if (CSRF_COOKIE_PATTERNS.some(p => p.test(cookieName))) {
            const guessedHeader = `X-${cookieName.replace(/[_-]/g, '-').split('-').map(
                p => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase()
            ).join('-')}`;
            return this.store({
                tokenName: cookieName,
                tokenValue: cookieValue,
                deliveryMechanism: 'cookie_to_header',
                headerName: guessedHeader,
                cookieName,
                rotatesPerRequest: false,
            });
        }

        return null;
    }

    /**
     * Detect CSRF from request parameters (body or query string).
     * Called from harvested request analysis.
     */
    detectFromRequestParams(params: Array<{ name: string; value: string; location: string }>): CSRFState | null {
        for (const param of params) {
            const lower = param.name.toLowerCase();
            if (CSRF_PARAM_NAMES.includes(lower) && param.value) {
                return this.store({
                    tokenName: param.name,
                    tokenValue: param.value,
                    deliveryMechanism: 'hidden_input',
                    rotatesPerRequest: false,
                });
            }
        }
        return null;
    }

    // ═══════════════════════════════════════════════════════════
    //  STORAGE & STATE
    // ═══════════════════════════════════════════════════════════

    /** Store or update a CSRF state. */
    store(partial: {
        tokenName: string;
        tokenValue: string;
        deliveryMechanism: CSRFDeliveryMechanism;
        headerName?: string;
        cookieName?: string;
        formAction?: string;
        rotatesPerRequest: boolean;
    }): CSRFState {
        const existing = this.csrfStates.get(partial.tokenName);
        const state: CSRFState = {
            identityId: this.identityId,
            tokenName: partial.tokenName,
            tokenValue: partial.tokenValue,
            deliveryMechanism: partial.deliveryMechanism,
            headerName: partial.headerName,
            cookieName: partial.cookieName,
            formAction: partial.formAction,
            rotatesPerRequest: partial.rotatesPerRequest,
            capturedAt: existing?.capturedAt || new Date(),
            lastRefreshedAt: new Date(),
        };

        // Detect rotation: if token value changed, may rotate per request
        if (existing && existing.tokenValue !== state.tokenValue) {
            state.rotatesPerRequest = true;
            logger.info(`CSRFManager: Token ${partial.tokenName} rotated — marking as per-request rotation`);
        }

        this.csrfStates.set(partial.tokenName, state);
        return state;
    }

    /** Get the primary CSRF state (first non-empty one). */
    getPrimary(): CSRFState | null {
        for (const state of this.csrfStates.values()) {
            if (state.tokenValue) return state;
        }
        return null;
    }

    /** Get CSRF state by token name. */
    getByName(name: string): CSRFState | undefined {
        return this.csrfStates.get(name);
    }

    /** Get all CSRF states. */
    getAll(): CSRFState[] {
        return [...this.csrfStates.values()];
    }

    /** Whether any CSRF token has been detected. */
    get hasCSRF(): boolean {
        return this.csrfStates.size > 0;
    }

    /** Clear all CSRF state. */
    clear(): void {
        this.csrfStates.clear();
    }

    // ═══════════════════════════════════════════════════════════
    //  REFRESH
    // ═══════════════════════════════════════════════════════════

    /**
     * Refresh CSRF token value from a CookieJar (for cookie-to-header pattern).
     * Call this before each state-changing request if `rotatesPerRequest`.
     */
    refreshFromCookieJar(cookieJar: CookieJar): boolean {
        let updated = false;
        for (const [name, state] of this.csrfStates.entries()) {
            if (state.deliveryMechanism !== 'cookie_to_header' || !state.cookieName) continue;

            // Find the CSRF cookie across all domains
            const allCookies = cookieJar.getCSRFCookies();
            const matchingCookie = allCookies.find(c => c.name.toLowerCase() === state.cookieName!.toLowerCase());
            if (matchingCookie && matchingCookie.value !== state.tokenValue) {
                state.tokenValue = matchingCookie.value;
                state.lastRefreshedAt = new Date();
                updated = true;
            }
        }
        return updated;
    }

    /**
     * Mark that CSRF validation failed (e.g., 422/419 response).
     * This flags the token as stale and needing refresh.
     */
    markStale(tokenName?: string): void {
        if (tokenName) {
            const state = this.csrfStates.get(tokenName);
            if (state) {
                state.tokenValue = '';  // force refresh
                state.rotatesPerRequest = true;
            }
        } else {
            // Mark all as stale
            for (const state of this.csrfStates.values()) {
                state.tokenValue = '';
                state.rotatesPerRequest = true;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  INJECTION
    // ═══════════════════════════════════════════════════════════

    /**
     * Get the CSRF header(s) to include in a request.
     * Returns { headerName: headerValue } or empty object.
     */
    getHeadersForRequest(): Record<string, string> {
        const headers: Record<string, string> = {};
        const orderedStates = [...this.csrfStates.values()].sort((a, b) => {
            const priority = (state: CSRFState): number => {
                if (state.deliveryMechanism === 'cookie_to_header') return 0;
                if (state.deliveryMechanism === 'response_header') return 1;
                return 10;
            };

            const priorityDiff = priority(a) - priority(b);
            if (priorityDiff !== 0) return priorityDiff;

            const refreshedDiff = b.lastRefreshedAt.getTime() - a.lastRefreshedAt.getTime();
            if (refreshedDiff !== 0) return refreshedDiff;

            return a.tokenName.localeCompare(b.tokenName);
        });

        for (const state of orderedStates) {
            if (!state.tokenValue) continue;

            if (state.deliveryMechanism === 'cookie_to_header' && state.headerName) {
                headers[state.headerName] = state.tokenValue;
            } else if (state.deliveryMechanism === 'response_header' && state.headerName) {
                headers[state.headerName] = state.tokenValue;
            }
        }
        return headers;
    }

    /**
     * Get the CSRF body field(s) to include in a POST body.
     * Returns { fieldName: fieldValue } or empty object.
     */
    getBodyFieldsForRequest(): Record<string, string> {
        const fields: Record<string, string> = {};
        const orderedStates = [...this.csrfStates.values()].sort((a, b) => {
            const priority = (state: CSRFState): number => {
                if (state.deliveryMechanism === 'hidden_input') return 0;
                if (state.deliveryMechanism === 'meta_tag') return 1;
                return 10;
            };

            const priorityDiff = priority(a) - priority(b);
            if (priorityDiff !== 0) return priorityDiff;

            const refreshedDiff = b.lastRefreshedAt.getTime() - a.lastRefreshedAt.getTime();
            if (refreshedDiff !== 0) return refreshedDiff;

            return a.tokenName.localeCompare(b.tokenName);
        });

        for (const state of orderedStates) {
            if (!state.tokenValue) continue;

            if (state.deliveryMechanism === 'hidden_input' || state.deliveryMechanism === 'meta_tag') {
                fields[state.tokenName] = state.tokenValue;
            }
        }
        return fields;
    }

    /**
     * Redacted summary for logging.
     */
    toRedactedSummary(): string {
        const states = this.getAll();
        if (states.length === 0) return 'CSRFManager: no tokens detected';

        const lines = states.map(s => {
            const rotation = s.rotatesPerRequest ? ' ⟳per-request' : '';
            return `  ${s.tokenName}=${redactSecret(s.tokenValue, 'token')} [${s.deliveryMechanism}${rotation}]`;
        });

        return `CSRFManager (${states.length} tokens):\n${lines.join('\n')}`;
    }
}
