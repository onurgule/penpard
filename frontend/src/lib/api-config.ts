/**
 * Centralized API Configuration
 * 
 * All frontend API calls should import API_URL from this module
 * instead of defining their own. This ensures Electron, Docker,
 * and local dev environments all resolve the backend correctly.
 */

// Base API URL — works in dev, Docker, and Electron
export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api';

/**
 * Set a custom API URL at runtime (stored in localStorage).
 * Useful for pointing to a remote backend.
 */
export function setApiUrl(url: string): void {
    if (typeof window !== 'undefined') {
        localStorage.setItem('penpard_api_url', url);
        // Force page reload so the new URL takes effect
        window.location.reload();
    }
}

/**
 * Clear custom API URL (revert to default)
 */
export function clearApiUrl(): void {
    if (typeof window !== 'undefined') {
        localStorage.removeItem('penpard_api_url');
    }
}

/**
 * Resolve the effective API URL.
 * Priority: localStorage override > env var > default
 */
export function getEffectiveApiUrl(): string {
    if (typeof window !== 'undefined') {
        const override = localStorage.getItem('penpard_api_url');
        if (override) return override;
    }
    return API_URL;
}
