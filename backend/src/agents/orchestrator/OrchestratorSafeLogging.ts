import { sanitizeLogMessage } from '../../utils/logger';

const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'<>]+/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/g;
const LOCALHOST_RE = /\blocalhost(?::\d{2,5})?\b/gi;
const HOST_HEADER_RE = /(\bhost\s*:\s*)[^\s,;]+/gi;

function normalizeWhitespace(value: string): string {
    return value.replace(/\s+/g, ' ').trim();
}

function hasMatch(pattern: RegExp, value: string): boolean {
    pattern.lastIndex = 0;
    return pattern.test(value);
}

function stripUrls(value: string): string {
    return value.replace(URL_RE, ' ');
}

function restoreNetworkMarkers(raw: string, sanitized: string): string {
    const markers: string[] = [];
    const rawWithoutUrls = stripUrls(raw);

    if (hasMatch(URL_RE, raw) && !sanitized.includes('[URL]')) {
        markers.push('[URL]');
    }
    if (hasMatch(IPV4_RE, rawWithoutUrls) && !sanitized.includes('[IP]')) {
        markers.push('[IP]');
    }
    if (hasMatch(LOCALHOST_RE, rawWithoutUrls) && !sanitized.includes('[HOST]')) {
        markers.push('[HOST]');
    }

    if (markers.length === 0) {
        return sanitized;
    }

    return `${sanitized} ${markers.join(' ')}`.trim();
}

export function sanitizeOrchestratorLogText(value: unknown): string {
    const raw = typeof value === 'string' ? value : String(value || '');
    const sanitized = sanitizeLogMessage(raw)
        .replace(URL_RE, '[URL]')
        .replace(IPV4_RE, '[IP]')
        .replace(LOCALHOST_RE, '[HOST]')
        .replace(HOST_HEADER_RE, '$1[HOST]');

    return restoreNetworkMarkers(raw, sanitized);
}

export function safeSnippetForLog(value: unknown, maxChars = 160): string {
    const sanitized = normalizeWhitespace(sanitizeOrchestratorLogText(value));
    if (!sanitized) {
        return '';
    }

    return sanitized.length > maxChars
        ? `${sanitized.slice(0, maxChars)}...`
        : sanitized;
}

export function summarizeLlmResponseForLog(text: string): string {
    const trimmed = (text || '').trim();
    if (!trimmed) {
        return 'empty response';
    }

    const shape = /^[\[{]/.test(trimmed) ? 'json-like' : 'text';
    return `${shape} response (${trimmed.length} chars)`;
}

export function summarizeToolCallForLog(tool: string, args: unknown): string {
    if (!args || typeof args !== 'object' || Array.isArray(args)) {
        return `${tool} (no structured args)`;
    }

    const record = args as Record<string, unknown>;
    const details: string[] = [];

    if (typeof record.method === 'string' && record.method.trim()) {
        details.push(`method=${record.method.toUpperCase()}`);
    }
    if (typeof record.identityId === 'string' && record.identityId.trim()) {
        details.push(`identity=${record.identityId}`);
    }
    if (typeof record.url === 'string' && record.url.trim()) {
        details.push('url=[URL]');
    }
    if (typeof record.host === 'string' && record.host.trim()) {
        details.push('host=[HOST]');
    }
    if (Array.isArray(record.queryMutations) && record.queryMutations.length > 0) {
        details.push(`queryMutations=${record.queryMutations.length}`);
    }
    if (Array.isArray(record.bodyMutations) && record.bodyMutations.length > 0) {
        details.push(`bodyMutations=${record.bodyMutations.length}`);
    }
    if (Array.isArray(record.mutations) && record.mutations.length > 0) {
        details.push(`mutations=${record.mutations.length}`);
    }

    const keys = Object.keys(record).sort();
    if (keys.length > 0) {
        details.push(`keys=${keys.join(',')}`);
    }

    return details.length > 0 ? `${tool} (${details.join(' | ')})` : tool;
}
