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
