export type ScopedRequestLoginPresence = 'unknown' | 'present' | 'absent';

export interface ScopedRequestIntakeFormValues {
    description: string;
    environment: string;
    serviceName: string;
    testData: string;
    testUsers: string;
    loginPresent: ScopedRequestLoginPresence;
    authMechanismHints: string;
    hasScreenshotOrAttachment: boolean;
    attachmentMetadata: string;
    attachmentSummary: string;
    newScreenCount: string;
    newInputCount: string;
    operatorNotes: string;
}

export interface StructuredAttachmentMetadataPayload {
    label?: string;
    kind?: string;
    mimeType?: string;
    note?: string;
}

export interface StructuredSecurityTestRequestPayload {
    targetUrl: string;
    description: string;
    environment?: string;
    serviceName?: string;
    testData: string[];
    testUsers: string[];
    loginPresent: boolean | null;
    authMechanismHints: string[];
    hasScreenshotOrAttachment: boolean | null;
    attachmentMetadata: StructuredAttachmentMetadataPayload[];
    attachmentSummary?: string;
    newScreenCount: number | null;
    newInputCount: number | null;
    operatorNotes?: string;
}

export function createDefaultScopedRequestIntake(): ScopedRequestIntakeFormValues {
    return {
        description: '',
        environment: '',
        serviceName: '',
        testData: '',
        testUsers: '',
        loginPresent: 'unknown',
        authMechanismHints: '',
        hasScreenshotOrAttachment: false,
        attachmentMetadata: '',
        attachmentSummary: '',
        newScreenCount: '',
        newInputCount: '',
        operatorNotes: '',
    };
}

export function validateScopedRequestIntake(targetUrl: string, values: ScopedRequestIntakeFormValues): string | null {
    if (!String(targetUrl || '').trim()) {
        return 'Target URL is required.';
    }
    if (!String(values.description || '').trim()) {
        return 'Request description is required in Scoped Test Mode.';
    }
    return null;
}

export function buildScopedSecurityTestRequest(
    targetUrl: string,
    values: ScopedRequestIntakeFormValues,
): StructuredSecurityTestRequestPayload {
    return {
        targetUrl,
        description: values.description.trim(),
        environment: normalizeOptionalString(values.environment),
        serviceName: normalizeOptionalString(values.serviceName),
        testData: splitMultilineList(values.testData),
        testUsers: splitMultilineList(values.testUsers),
        loginPresent: normalizeLoginPresence(values.loginPresent),
        authMechanismHints: splitMultilineList(values.authMechanismHints),
        hasScreenshotOrAttachment: values.hasScreenshotOrAttachment ? true : null,
        attachmentMetadata: parseAttachmentMetadata(values.attachmentMetadata),
        attachmentSummary: normalizeOptionalString(values.attachmentSummary),
        newScreenCount: normalizeOptionalNumber(values.newScreenCount),
        newInputCount: normalizeOptionalNumber(values.newInputCount),
        operatorNotes: normalizeOptionalString(values.operatorNotes),
    };
}

export function splitMultilineList(value: string): string[] {
    return [...new Set(
        String(value || '')
            .split(/\r?\n|,/)
            .map((entry) => entry.trim())
            .filter(Boolean),
    )];
}

export function parseAttachmentMetadata(value: string): StructuredAttachmentMetadataPayload[] {
    return splitMultilineList(value)
        .map((entry) => {
            const [kind, ...rest] = entry.split(':');
            if (rest.length === 0) {
                return {
                    label: kind.trim(),
                };
            }

            return {
                kind: kind.trim() || undefined,
                label: rest.join(':').trim() || undefined,
            };
        })
        .filter((entry) => entry.label || entry.kind)
        .slice(0, 8);
}

function normalizeOptionalString(value: string): string | undefined {
    const trimmed = String(value || '').trim();
    return trimmed ? trimmed : undefined;
}

function normalizeOptionalNumber(value: string): number | null {
    const trimmed = String(value || '').trim();
    if (!trimmed) {
        return null;
    }
    const numeric = Number(trimmed);
    return Number.isFinite(numeric) && numeric >= 0 ? Math.round(numeric) : null;
}

function normalizeLoginPresence(value: ScopedRequestLoginPresence): boolean | null {
    if (value === 'present') {
        return true;
    }
    if (value === 'absent') {
        return false;
    }
    return null;
}
