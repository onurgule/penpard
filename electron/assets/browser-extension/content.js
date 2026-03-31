/**
 * PenPard Browser – Branding content script
 *
 * Injects a PenPard-branded favicon into every page so the Chromium taskbar
 * icon and tab header display the PenPard Browser icon instead of the site's
 * own favicon.  The injected icon is the composite PenPard + Chrome-badge
 * variant embedded as a data-URI so no external requests are needed.
 */
(function applyPenPardBranding() {
    'use strict';

    // We use the extension's own icon URL via chrome.runtime.getURL
    const ICON_URL = chrome.runtime.getURL('icons/icon-32.png');

    function setFavicon() {
        // Remove all existing favicons / shortcut icons
        const existing = document.querySelectorAll(
            'link[rel="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]'
        );
        existing.forEach(el => el.remove());

        // Create and inject our branded favicon
        const link = document.createElement('link');
        link.rel = 'icon';
        link.type = 'image/png';
        link.href = ICON_URL;

        // Insert into <head> (create if missing – unlikely but safe)
        const head = document.head || document.documentElement;
        head.appendChild(link);
    }

    // Apply immediately if head exists
    if (document.head) {
        setFavicon();
    }

    // Re-apply after DOM is fully parsed (pages may set favicons dynamically)
    document.addEventListener('DOMContentLoaded', setFavicon, { once: true });

    // Watch for dynamic favicon changes via MutationObserver on <head>
    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (
                    node.nodeName === 'LINK' &&
                    node !== document.querySelector('link[rel="icon"][href^="chrome-extension://"]') &&
                    (node.rel === 'icon' || node.rel === 'shortcut icon')
                ) {
                    // A page tried to add its own favicon – override it
                    setFavicon();
                    return;
                }
            }
        }
    });

    // Start observing once head is available
    function startObserving() {
        if (document.head) {
            observer.observe(document.head, { childList: true });
        } else {
            document.addEventListener('DOMContentLoaded', () => {
                observer.observe(document.head, { childList: true });
            }, { once: true });
        }
    }
    startObserving();
})();
