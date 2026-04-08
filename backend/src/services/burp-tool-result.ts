export interface NormalizedSendHttpResponse {
    statusCode: number;
    headers: Record<string, any> | Array<string>;
    body: string;
    raw: any;
}

function readWrappedText(result: any): string | null {
    const text = result?.content?.[0]?.text;
    return typeof text === 'string' ? text : null;
}

export function unwrapBurpToolResult<T = any>(result: any): T {
    const wrappedText = readWrappedText(result);
    if (!wrappedText) {
        return (result ?? {}) as T;
    }

    try {
        return JSON.parse(wrappedText) as T;
    } catch {
        return ({ text: wrappedText } as unknown) as T;
    }
}

export function normalizeProxyHistoryItems(result: any): any[] {
    const payload = unwrapBurpToolResult<any>(result);
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.history)) return payload.history;
    if (Array.isArray(payload?.entries)) return payload.entries;
    return [];
}

export function normalizeCookiesAndAuthEntries(result: any): any[] {
    const payload = unwrapBurpToolResult<any>(result);
    if (Array.isArray(payload?.entries)) return payload.entries;
    if (Array.isArray(payload)) return payload;
    return [];
}

export function normalizeSessionCookieResult(result: any): {
    cookieHeader?: string;
    fromUrl?: string;
    note?: string;
} {
    const payload = unwrapBurpToolResult<any>(result);
    if (!payload || typeof payload !== 'object') return {};
    return {
        cookieHeader: typeof payload.cookieHeader === 'string' ? payload.cookieHeader : undefined,
        fromUrl: typeof payload.fromUrl === 'string' ? payload.fromUrl : undefined,
        note: typeof payload.note === 'string' ? payload.note : undefined,
    };
}

export function normalizeSendHttpResponse(result: any): NormalizedSendHttpResponse {
    const payload = unwrapBurpToolResult<any>(result);
    if (payload && typeof payload === 'object') {
        const statusCode = Number(
            payload.statusCode ??
            payload.status ??
            payload.response?.statusCode ??
            payload.response?.status ??
            0,
        ) || 0;
        const headers = payload.headers ??
            payload.responseHeaders ??
            payload.response?.headers ??
            {};
        const body = String(
            payload.body ??
            payload.text ??
            payload.responseBody ??
            payload.response?.body ??
            '',
        );

        return { statusCode, headers, body, raw: payload };
    }

    return {
        statusCode: 0,
        headers: {},
        body: '',
        raw: payload,
    };
}
