import { ParsedBurpRequest, parseRawBurpRequest, prepareBurpDispatchRequest } from '../../services/burp-request';

export interface InitialRequestMutation {
    name?: string;
    value?: string | number | boolean | null;
}

export interface InitialRequestProfile {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string;
    headerNames: string[];
    sensitiveHeaderNames: string[];
    queryParameterNames: string[];
    bodyParameterNames: string[];
    contentType?: string;
}

interface ParsedJsonBody {
    raw: string;
    value: Record<string, unknown>;
}

function getParsedRequest(rawRequest: string): ParsedBurpRequest | null {
    const direct = parseRawBurpRequest(rawRequest.trim());
    if (direct) {
        return direct;
    }

    const prepared = prepareBurpDispatchRequest({ rawRequest: rawRequest.trim() });
    if (!prepared?.request) {
        return null;
    }

    return parseRawBurpRequest(prepared.request);
}

function unique(values: string[]): string[] {
    return [...new Set(values.filter((value) => !!value))];
}

function isSensitiveHeaderName(name: string): boolean {
    return /^(authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-csrftoken)$/i.test(name);
}

function extractQueryParameterNames(url: string): string[] {
    try {
        const parsed = new URL(url);
        return unique([...parsed.searchParams.keys()]);
    } catch {
        return [];
    }
}

function parseJsonBody(body: string): ParsedJsonBody | null {
    if (!body.trim()) {
        return null;
    }

    try {
        const parsed = JSON.parse(body);
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
            return null;
        }

        return {
            raw: body,
            value: { ...(parsed as Record<string, unknown>) },
        };
    } catch {
        return null;
    }
}

function parseFormBody(body: string): URLSearchParams | null {
    if (!body.trim()) {
        return null;
    }

    try {
        return new URLSearchParams(body);
    } catch {
        return null;
    }
}

function extractBodyParameterNames(body: string, contentType?: string): string[] {
    const normalizedContentType = (contentType || '').toLowerCase();
    if (!body.trim()) {
        return [];
    }

    if (normalizedContentType.includes('application/json')) {
        const parsed = parseJsonBody(body);
        return parsed ? unique(Object.keys(parsed.value)) : [];
    }

    if (normalizedContentType.includes('application/x-www-form-urlencoded')) {
        const parsed = parseFormBody(body);
        return parsed ? unique([...parsed.keys()]) : [];
    }

    return [];
}

function normalizeMutationValue(value: InitialRequestMutation['value']): string | number | boolean | null {
    if (value === undefined) {
        return '';
    }
    return value;
}

export function parseInitialRequestProfile(rawRequest: string): InitialRequestProfile | null {
    const parsed = getParsedRequest(rawRequest);
    if (!parsed) {
        return null;
    }

    const filteredHeaders = Object.fromEntries(
        Object.entries(parsed.headers).filter(([name]) => !name.toLowerCase().startsWith('x-penpard')),
    );
    const headerNames = unique(Object.keys(filteredHeaders));
    const contentType = headerNames.find((name) => name.toLowerCase() === 'content-type')
        ? filteredHeaders[headerNames.find((name) => name.toLowerCase() === 'content-type') as string]
        : undefined;

    return {
        method: parsed.method,
        url: parsed.url,
        headers: filteredHeaders,
        body: parsed.body || '',
        headerNames,
        sensitiveHeaderNames: headerNames.filter((name) => isSensitiveHeaderName(name)),
        queryParameterNames: extractQueryParameterNames(parsed.url),
        bodyParameterNames: extractBodyParameterNames(parsed.body || '', contentType),
        contentType,
    };
}

export function mergeStoredInitialRequestHeaders(
    profile: InitialRequestProfile | null,
    explicitHeaders?: Record<string, string>,
    preserveExplicitAuth?: boolean,
): Record<string, string> | undefined {
    if (!profile) {
        return explicitHeaders;
    }

    if (!preserveExplicitAuth) {
        return explicitHeaders;
    }

    return {
        ...profile.headers,
        ...(explicitHeaders || {}),
    };
}

export function applyStoredInitialRequestQueryMutations(
    baseUrl: string,
    mutations?: InitialRequestMutation[],
): string {
    if (!mutations?.length) {
        return baseUrl;
    }

    let parsed: URL;
    try {
        parsed = new URL(baseUrl);
    } catch {
        return baseUrl;
    }

    for (const mutation of mutations) {
        const name = typeof mutation?.name === 'string' ? mutation.name.trim() : '';
        if (!name) {
            continue;
        }
        parsed.searchParams.set(name, String(normalizeMutationValue(mutation.value)));
    }
    return parsed.toString();
}

export function applyStoredInitialRequestBodyMutations(
    body: string,
    contentType: string | undefined,
    mutations?: InitialRequestMutation[],
): string {
    if (!mutations?.length || !body.trim()) {
        return body;
    }

    const normalizedContentType = (contentType || '').toLowerCase();

    if (normalizedContentType.includes('application/json')) {
        const parsed = parseJsonBody(body);
        if (!parsed) {
            return body;
        }

        for (const mutation of mutations) {
            const name = typeof mutation?.name === 'string' ? mutation.name.trim() : '';
            if (!name) {
                continue;
            }
            parsed.value[name] = normalizeMutationValue(mutation.value);
        }

        return JSON.stringify(parsed.value);
    }

    if (normalizedContentType.includes('application/x-www-form-urlencoded')) {
        const parsed = parseFormBody(body);
        if (!parsed) {
            return body;
        }

        for (const mutation of mutations) {
            const name = typeof mutation?.name === 'string' ? mutation.name.trim() : '';
            if (!name) {
                continue;
            }
            parsed.set(name, String(normalizeMutationValue(mutation.value)));
        }

        return parsed.toString();
    }

    return body;
}

function formatList(values: string[]): string {
    return values.length > 0 ? values.join(', ') : 'none';
}

function isSensitivePathSegment(segment: string): boolean {
    return /^\d+$/.test(segment)
        || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)
        || /^[0-9a-f]{16,}$/i.test(segment);
}

function sanitizePathname(pathname: string): string {
    return pathname
        .split('/')
        .map((segment) => (isSensitivePathSegment(segment) ? '<preserved>' : segment))
        .join('/');
}

export function buildInitialRequestUrlTemplate(profile: InitialRequestProfile): string {
    const parsed = new URL(profile.url);
    const sanitizedPathname = sanitizePathname(parsed.pathname);
    if (profile.queryParameterNames.length === 0) {
        return `${parsed.origin}${sanitizedPathname}`;
    }

    const sanitizedQuery = profile.queryParameterNames
        .map((name) => `${encodeURIComponent(name)}=<preserved>`)
        .join('&');
    return `${parsed.origin}${sanitizedPathname}?${sanitizedQuery}`;
}

export function buildInitialRequestPromptSummary(profile: InitialRequestProfile): string {
    const lines = [
        `Stored request method: ${profile.method}`,
        `Stored request URL template: ${buildInitialRequestUrlTemplate(profile)}`,
        `Stored header names: ${formatList(profile.headerNames)}`,
        `Sensitive header names preserved server-side: ${formatList(profile.sensitiveHeaderNames)}`,
        `Query parameter names: ${formatList(profile.queryParameterNames)}`,
        `Body content type: ${profile.contentType || 'unknown'}`,
        `Body parameter names: ${formatList(profile.bodyParameterNames)}`,
        `Stored body present: ${profile.body.trim() ? 'yes' : 'no'}`,
    ];

    return lines.join('\n');
}

export function buildInitialRequestLogSummary(profile: InitialRequestProfile): string {
    const parsed = new URL(profile.url);
    return `Burp request profile stored - ${profile.method} ${sanitizePathname(parsed.pathname)} - headers=${profile.headerNames.length} queryParams=${profile.queryParameterNames.length} bodyParams=${profile.bodyParameterNames.length}`;
}
