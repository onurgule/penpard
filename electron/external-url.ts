export function isSafeExternalUrl(rawUrl: string): boolean {
    try {
        const url = new URL(rawUrl);
        if (url.protocol === 'https:') {
            return true;
        }
        if (url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === '[::1]')) {
            return true;
        }
        return false;
    } catch {
        return false;
    }
}

export async function openExternalUrl(
    rawUrl: string,
    opener: (url: string) => Promise<unknown>,
): Promise<{ success: boolean; error?: string }> {
    if (!rawUrl || !isSafeExternalUrl(rawUrl)) {
        return { success: false, error: 'Invalid or unsupported URL' };
    }

    try {
        await opener(rawUrl);
        return { success: true };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Failed to open the external browser.',
        };
    }
}
