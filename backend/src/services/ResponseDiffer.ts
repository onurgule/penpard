/**
 * ResponseDiffer — Response comparison for mutation analysis.
 *
 * Compares an original harvested response against a mutated response
 * to determine whether the mutation caused a meaningful behavioral change.
 * Used by the hypothesis engine to update confidence scores.
 */

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface ResponseDiff {
    statusCodeChanged: boolean;
    originalStatus: number;
    mutatedStatus: number;
    bodyLengthDelta: number;
    bodyLengthRatio: number;
    structureChanged: boolean;
    headerDiffs: string[];
    keywordSignals: string[];
    timingDeltaMs: number;
    significant: boolean;
    summary: string;
}

export interface ResponseSnapshot {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    mimeType?: string;
    timingMs?: number;
}

// ─────────────────────────────────────────────────────────────
// Diff Logic
// ─────────────────────────────────────────────────────────────

/**
 * Compare two HTTP responses and produce a structured diff result.
 */
export function diffResponses(original: ResponseSnapshot, mutated: ResponseSnapshot): ResponseDiff {
    const statusCodeChanged = original.statusCode !== mutated.statusCode;
    const originalBodyLen = original.body?.length || 0;
    const mutatedBodyLen = mutated.body?.length || 0;
    const bodyLengthDelta = Math.abs(originalBodyLen - mutatedBodyLen);
    const bodyLengthRatio = originalBodyLen > 0 ? mutatedBodyLen / originalBodyLen : (mutatedBodyLen > 0 ? Infinity : 1);

    const structureChanged = hasStructuralDiff(original.body, mutated.body, original.mimeType);

    const headerDiffs = computeHeaderDiffs(original.headers, mutated.headers);

    const keywordSignals = detectKeywordSignals(original.body, mutated.body);

    const timingDeltaMs = Math.abs((original.timingMs || 0) - (mutated.timingMs || 0));

    // Significance determination
    const significant = determineSignificance({
        statusCodeChanged,
        bodyLengthRatio,
        bodyLengthDelta,
        structureChanged,
        headerDiffs,
        keywordSignals,
        timingDeltaMs,
        originalStatus: original.statusCode,
        mutatedStatus: mutated.statusCode,
    });

    const summary = buildSummary({
        statusCodeChanged, originalStatus: original.statusCode, mutatedStatus: mutated.statusCode,
        bodyLengthDelta, bodyLengthRatio, structureChanged, headerDiffs, keywordSignals, timingDeltaMs, significant,
    });

    return {
        statusCodeChanged,
        originalStatus: original.statusCode,
        mutatedStatus: mutated.statusCode,
        bodyLengthDelta,
        bodyLengthRatio,
        structureChanged,
        headerDiffs,
        keywordSignals,
        timingDeltaMs,
        significant,
        summary,
    };
}

// ─────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────

function hasStructuralDiff(bodyA: string, bodyB: string, mimeType?: string): boolean {
    if (!bodyA && !bodyB) return false;
    if (!bodyA || !bodyB) return true;

    // JSON structural comparison (key set diff)
    if (mimeType?.includes('json') || (bodyA.startsWith('{') && bodyB.startsWith('{'))) {
        try {
            const objA = JSON.parse(bodyA);
            const objB = JSON.parse(bodyB);
            const keysA = new Set(deepKeys(objA));
            const keysB = new Set(deepKeys(objB));
            const added = [...keysB].filter(k => !keysA.has(k));
            const removed = [...keysA].filter(k => !keysB.has(k));
            return added.length > 0 || removed.length > 0;
        } catch {
            // Not valid JSON despite looking like it — fall through
        }
    }

    // HTML structural comparison (tag set diff)
    if (mimeType?.includes('html') || bodyA.includes('<html') || bodyA.includes('<!DOCTYPE')) {
        const tagsA = extractHtmlTags(bodyA);
        const tagsB = extractHtmlTags(bodyB);
        if (Math.abs(tagsA.length - tagsB.length) > 3) return true;
    }

    // Length-based heuristic for unknown types
    const ratio = bodyA.length > 0 ? bodyB.length / bodyA.length : (bodyB.length > 0 ? Infinity : 1);
    return ratio < 0.5 || ratio > 2.0;
}

function deepKeys(obj: any, prefix: string = ''): string[] {
    if (obj === null || typeof obj !== 'object') return [];
    const keys: string[] = [];
    for (const key of Object.keys(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        keys.push(fullKey);
        if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
            keys.push(...deepKeys(obj[key], fullKey));
        }
    }
    return keys;
}

function extractHtmlTags(html: string): string[] {
    const tagPattern = /<\/?([a-zA-Z][a-zA-Z0-9]*)/g;
    const tags: string[] = [];
    let match: RegExpExecArray | null;
    while ((match = tagPattern.exec(html)) !== null) {
        tags.push(match[1].toLowerCase());
    }
    return tags;
}

function computeHeaderDiffs(headersA: Record<string, string>, headersB: Record<string, string>): string[] {
    const diffs: string[] = [];
    const allKeys = new Set([...Object.keys(headersA || {}), ...Object.keys(headersB || {})]);

    for (const key of allKeys) {
        const lk = key.toLowerCase();
        // Skip noisy headers
        if (['date', 'content-length', 'etag', 'x-request-id', 'x-trace-id'].includes(lk)) continue;

        const vA = headersA?.[key] || '';
        const vB = headersB?.[key] || '';
        if (vA !== vB) {
            if (!vA) diffs.push(`+${key}: ${vB.substring(0, 60)}`);
            else if (!vB) diffs.push(`-${key}`);
            else diffs.push(`~${key}: ${vA.substring(0, 30)} → ${vB.substring(0, 30)}`);
        }
    }
    return diffs;
}

function detectKeywordSignals(bodyA: string, bodyB: string): string[] {
    const signals: string[] = [];
    const bLower = (bodyB || '').toLowerCase();
    const aLower = (bodyA || '').toLowerCase();

    // SQL error signals (appeared in mutated but not original)
    const sqlErrors = ['sql syntax', 'mysql_fetch', 'ora-', 'sqlite', 'postgresql', 'database error', 'query failed', 'unclosed quotation'];
    for (const err of sqlErrors) {
        if (bLower.includes(err) && !aLower.includes(err)) {
            signals.push(`SQL_ERROR: "${err}" appeared in mutated response`);
        }
    }

    // Stack trace / debug info
    if (bLower.includes('stack trace') && !aLower.includes('stack trace')) signals.push('STACK_TRACE_LEAKED');
    if (bLower.includes('internal server error') && !aLower.includes('internal server error')) signals.push('INTERNAL_ERROR');

    // Auth / access signals
    if (bLower.includes('unauthorized') && !aLower.includes('unauthorized')) signals.push('AUTH_DENIED');
    if (bLower.includes('forbidden') && !aLower.includes('forbidden')) signals.push('FORBIDDEN_APPEARED');
    if (aLower.includes('forbidden') && !bLower.includes('forbidden')) signals.push('FORBIDDEN_BYPASSED');

    // Data leak signals (mutated shows data that original did not)
    if (bLower.includes('password') && !aLower.includes('password')) signals.push('PASSWORD_FIELD_EXPOSED');
    if (bLower.includes('email') && !aLower.includes('email') && bLower.includes('@')) signals.push('EMAIL_DATA_LEAKED');

    // Reflected input
    if (bLower.includes('<script') && !aLower.includes('<script')) signals.push('SCRIPT_TAG_REFLECTED');
    if (bLower.includes('onerror=') && !aLower.includes('onerror=')) signals.push('EVENT_HANDLER_REFLECTED');

    return signals;
}

function determineSignificance(ctx: {
    statusCodeChanged: boolean;
    bodyLengthRatio: number;
    bodyLengthDelta: number;
    structureChanged: boolean;
    headerDiffs: string[];
    keywordSignals: string[];
    timingDeltaMs: number;
    originalStatus: number;
    mutatedStatus: number;
}): boolean {
    // Keyword signals (SQL errors, stack traces, XSS reflection) are always significant
    if (ctx.keywordSignals.length > 0) return true;

    // Status code changed meaningfully
    if (ctx.statusCodeChanged) {
        // 200→500 or 403→200 are always significant
        const o = ctx.originalStatus;
        const m = ctx.mutatedStatus;
        if ((o >= 200 && o < 300) && (m >= 400)) return true;        // Success → error
        if ((o >= 400) && (m >= 200 && m < 300)) return true;        // Error → success (bypass)
        if ((o === 403 || o === 401) && (m >= 200 && m < 300)) return true;  // Auth bypass
    }

    // Major body size change (suggests different content returned)
    if (ctx.bodyLengthDelta > 500 && (ctx.bodyLengthRatio < 0.5 || ctx.bodyLengthRatio > 2.0)) return true;

    // Structural change in JSON response
    if (ctx.structureChanged) return true;

    // Timing-based blind injection signal (>4 seconds difference)
    if (ctx.timingDeltaMs > 4000) return true;

    // Many header changes
    if (ctx.headerDiffs.length >= 3) return true;

    return false;
}

function buildSummary(d: Omit<ResponseDiff, 'summary'>): string {
    const parts: string[] = [];

    if (d.statusCodeChanged) parts.push(`Status: ${d.originalStatus} → ${d.mutatedStatus}`);
    if (d.bodyLengthDelta > 0) parts.push(`Body Δ: ${d.bodyLengthDelta} bytes (ratio: ${d.bodyLengthRatio.toFixed(2)})`);
    if (d.structureChanged) parts.push('Response structure changed');
    if (d.headerDiffs.length > 0) parts.push(`${d.headerDiffs.length} header diff(s)`);
    if (d.keywordSignals.length > 0) parts.push(`Signals: ${d.keywordSignals.join(', ')}`);
    if (d.timingDeltaMs > 1000) parts.push(`Timing Δ: ${d.timingDeltaMs}ms`);

    const verdict = d.significant ? '⚠️ SIGNIFICANT' : '○ Not significant';
    return `${verdict} | ${parts.join(' | ') || 'No notable changes'}`;
}
