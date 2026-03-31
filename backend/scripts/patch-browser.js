/**
 * Patches the Playwright Chromium executable to use the PenPard icon.
 * This ensures the Windows taskbar icon shows the PenPard identity
 * instead of the generic Chrome logo.
 */
const fs = require('fs');
const path = require('path');
const { rcedit } = require('rcedit');
const { chromium } = require('playwright-core');

const ICON_PATH = path.join(__dirname, '..', '..', 'electron', 'assets', 'browser-icon.ico');

async function main() {
    console.log('Resolving Playwright Chromium path...');
    
    // Playwright path
    const chromeExePath = chromium.executablePath();
    
    if (!fs.existsSync(chromeExePath)) {
        console.error('Chromium not found. Please run "npx playwright install chromium" in the backend directory first.');
        process.exit(1);
    }
    
    console.log(`Found Chromium: ${chromeExePath}`);
    
    const chromeDir = path.dirname(chromeExePath);
    const penpardExePath = path.join(chromeDir, 'penpard_isolated.exe');
    
    console.log(`Copying to: ${penpardExePath}`);
    fs.copyFileSync(chromeExePath, penpardExePath);
    
    const rceditOpts = {
        icon: ICON_PATH,
        'version-string': {
            'CompanyName': 'PenPard',
            'FileDescription': 'PenPard Browser',
            'ProductName': 'PenPard Browser',
            'InternalName': 'penpard_browser',
            'OriginalFilename': 'penpard.exe'
        }
    };

    const chromeDllPath = path.join(chromeDir, 'chrome.dll');
    console.log(`Patching DLL icon and metadata at: ${chromeDllPath}...`);
    try {
        await rcedit(chromeDllPath, rceditOpts);
        console.log('✓ Successfully patched chrome.dll');
    } catch (err) {
        console.warn('⚠ Could not patch chrome.dll (might be in use or protected):', err.message);
    }
    
    console.log(`Patching executable icon and metadata at: ${penpardExePath}...`);
    try {
        await rcedit(penpardExePath, rceditOpts);
        console.log('✓ Successfully patched penpard_isolated.exe');
    } catch (err) {
        console.error('Failed to patch executable:', err);
        process.exit(1);
    }
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
