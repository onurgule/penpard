export interface ParsedBurpRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body: string;
    host: string;
    scheme: 'http' | 'https';
    pathWithQuery: string;
}

export function parseRawBurpRequest(raw: string): ParsedBurpRequest | null {
    try {
        const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        const headerBodySplit = normalized.indexOf('\n\n');
        const headerSection = headerBodySplit >= 0 ? normalized.substring(0, headerBodySplit) : normalized;
        const body = headerBodySplit >= 0 ? normalized.substring(headerBodySplit + 2) : '';

        const lines = headerSection.split('\n');
        if (lines.length < 1) return null;

        const requestLine = lines[0].trim();
        const parts = requestLine.split(/\s+/);
        if (parts.length < 2) return null;

        const method = parts[0].toUpperCase();
        const pathWithQuery = parts[1];

        const headers: Record<string, string> = {};
        let host = '';
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;

            const colonIdx = line.indexOf(':');
            if (colonIdx <= 0) continue;

            const name = line.substring(0, colonIdx).trim();
            const value = line.substring(colonIdx + 1).trim();
            headers[name] = value;

            if (name.toLowerCase() === 'host') {
                host = value;
            }
        }

        if (!host) return null;

        const isHttp = host.endsWith(':80') || host.startsWith('http://');
        const scheme = isHttp ? 'http' : 'https';
        const cleanHost = host.replace(/^https?:\/\//, '');
        const url = `${scheme}://${cleanHost}${pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`}`;

        return {
            method,
            url,
            headers,
            body,
            host: cleanHost,
            scheme,
            pathWithQuery,
        };
    } catch {
        return null;
    }
}

export function serializeStructuredBurpRequest(request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
}): string {
    const parsedUrl = new URL(request.url);
    const method = request.method.toUpperCase();
    const pathWithQuery = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;
    const headers = { ...(request.headers || {}) };

    const hostHeader = headers.Host || headers.host || parsedUrl.host;
    const lines = [`${method} ${pathWithQuery} HTTP/1.1`, `Host: ${hostHeader}`];

    for (const [name, value] of Object.entries(headers)) {
        if (name.toLowerCase() === 'host') continue;
        lines.push(`${name}: ${value}`);
    }

    const body = request.body || '';
    lines.push('');
    if (body) {
        lines.push(body);
    }

    return lines.join('\r\n');
}

export interface PreparedBurpDispatchRequest {
    method: string;
    host: string;
    port: number;
    useHttps: boolean;
    fullUrl: string;
    request: string;
}

export function prepareBurpDispatchRequest(input: {
    rawRequest?: string;
    url?: string;
    method?: string;
    headers?: Record<string, any>;
    body?: string;
}): PreparedBurpDispatchRequest | null {
    const structuredUrl = typeof input.url === 'string' && input.url.trim() ? input.url.trim() : '';
    const rawRequest = typeof input.rawRequest === 'string' && input.rawRequest.trim()
        ? input.rawRequest
        : (structuredUrl
            ? serializeStructuredBurpRequest({
                method: input.method || 'GET',
                url: structuredUrl,
                headers: normalizeStructuredHeaders(input.headers),
                body: typeof input.body === 'string' ? input.body : (input.body === undefined || input.body === null ? '' : String(input.body)),
            })
            : '');

    if (!rawRequest) {
        return null;
    }

    const normalized = rawRequest.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const headerBodySplit = normalized.indexOf('\n\n');
    const headerSection = headerBodySplit >= 0 ? normalized.substring(0, headerBodySplit) : normalized;
    const bodySection = headerBodySplit >= 0 ? normalized.substring(headerBodySplit + 2) : '';
    const lines = headerSection.split('\n');

    if (lines.length === 0) {
        return null;
    }

    const requestLine = lines[0].trim();
    const requestLineMatch = requestLine.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\S+))?$/i);
    if (!requestLineMatch) {
        return null;
    }

    const method = requestLineMatch[1].toUpperCase();
    const requestTarget = requestLineMatch[2];
    const httpVersion = requestLineMatch[3] || 'HTTP/1.1';
    const rawHeaders = lines.slice(1).filter((line) => line.trim().length > 0);
    const hostHeader = rawHeaders
        .map((line) => parseHeaderLine(line))
        .find((header) => header?.name.toLowerCase() === 'host');

    let metadataUrl = tryParseUrl(requestTarget);
    if (!metadataUrl && structuredUrl) {
        metadataUrl = tryParseUrl(structuredUrl);
    }
    if (!metadataUrl && hostHeader) {
        metadataUrl = tryParseUrl(buildUrlFromHostHeader(hostHeader.value, requestTarget));
    }
    if (!metadataUrl) {
        return null;
    }

    const useHttps = metadataUrl.protocol === 'https:';
    const port = Number(metadataUrl.port) || (useHttps ? 443 : 80);
    const hostValue = port === (useHttps ? 443 : 80) ? metadataUrl.hostname : `${metadataUrl.hostname}:${port}`;
    const pathWithQuery = requestTarget.startsWith('http://') || requestTarget.startsWith('https://')
        ? `${metadataUrl.pathname || '/'}${metadataUrl.search || ''}`
        : (requestTarget.startsWith('/') ? requestTarget : `/${requestTarget}`);

    const normalizedHeaders = [
        `Host: ${hostValue}`,
        ...rawHeaders
            .map((line) => parseHeaderLine(line))
            .filter((header): header is { name: string; value: string } => !!header && header.name.toLowerCase() !== 'host')
            .map((header) => `${header.name}: ${header.value}`),
    ];

    const normalizedBody = bodySection
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .replace(/\n/g, '\r\n');
    const request = [
        `${method} ${pathWithQuery} ${httpVersion}`,
        ...normalizedHeaders,
        '',
        normalizedBody,
    ].join('\r\n');
    const fullUrl = `${metadataUrl.protocol}//${hostValue}${pathWithQuery}`;

    return {
        method,
        host: metadataUrl.hostname,
        port,
        useHttps,
        fullUrl,
        request,
    };
}

export function getHeaderValue(headers: Record<string, string> | undefined, name: string): string | undefined {
    if (!headers) return undefined;
    const lowerName = name.toLowerCase();
    const key = Object.keys(headers).find(candidate => candidate.toLowerCase() === lowerName);
    if (!key) return undefined;
    const value = headers[key];
    return typeof value === 'string' ? value : undefined;
}

export function hasHeaderKey(headers: Record<string, string> | undefined, name: string): boolean {
    if (!headers) return false;
    const lowerName = name.toLowerCase();
    return Object.keys(headers).some(candidate => candidate.toLowerCase() === lowerName);
}

function normalizeStructuredHeaders(headers: Record<string, any> | undefined): Record<string, string> | undefined {
    if (!headers) return undefined;

    const normalized: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
        if (value === undefined || value === null) continue;
        normalized[name] = String(value);
    }
    return normalized;
}

function tryParseUrl(candidate: string): URL | null {
    try {
        return new URL(candidate);
    } catch {
        return null;
    }
}

function parseHeaderLine(line: string): { name: string; value: string } | null {
    const colonIndex = line.indexOf(':');
    if (colonIndex <= 0) {
        return null;
    }

    const name = line.substring(0, colonIndex).trim();
    const value = line.substring(colonIndex + 1).trim().replace(/[\r\n]+/g, ' ');
    if (!name) {
        return null;
    }

    return { name, value };
}

function buildUrlFromHostHeader(hostHeader: string, requestTarget: string): string {
    const cleanHost = hostHeader.trim().replace(/^https?:\/\//i, '');
    const normalizedPath = requestTarget.startsWith('/') ? requestTarget : `/${requestTarget}`;
    const looksHttp = /^http:\/\//i.test(hostHeader) || /:80$/i.test(cleanHost);
    const looksHttps = /^https:\/\//i.test(hostHeader) || /:443$/i.test(cleanHost) || /:8443$/i.test(cleanHost);
    const scheme = looksHttp ? 'http' : (looksHttps ? 'https' : 'https');
    return `${scheme}://${cleanHost}${normalizedPath}`;
}
