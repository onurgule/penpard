import { app, BrowserWindow, shell, ipcMain, session, protocol, net } from 'electron';
import { spawn, fork, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { pathToFileURL } from 'url';
import { appUpdater } from './updater';

// Keep a global reference of the window and backend process
let mainWindow: BrowserWindow | null = null;
let backendProcess: ChildProcess | null = null;
let backendStartTime: number | null = null;

// Configuration
const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

// CRITICAL: Register custom protocol scheme BEFORE app.ready
// This must happen at module load time, not inside whenReady()
// "standard: true" makes relative URLs (like /dashboard) resolve correctly
// "secure: true" treats it as a secure context  
// "supportFetchAPI: true" allows fetch() calls from this origin
if (!isDev) {
    protocol.registerSchemesAsPrivileged([
        {
            scheme: 'penpard',
            privileges: {
                standard: true,
                secure: true,
                supportFetchAPI: true,
                corsEnabled: true,
            }
        }
    ]);
}
const BACKEND_PORT = 4000;
const FRONTEND_PORT = 3000;

// Get the correct paths based on whether we're in dev or production
function getBackendPath(): string {
    if (isDev) {
        return path.join(__dirname, '../../backend');
    }
    return path.join(process.resourcesPath, 'backend');
}

/** Production: path to frontend/out directory (for custom protocol) */
function getFrontendOutPath(): string {
    // __dirname is app.asar/electron/dist, frontend is at app.asar/frontend/out
    return path.join(__dirname, '../../frontend/out');
}

function getFrontendPath(): string {
    if (isDev) {
        return `http://localhost:${FRONTEND_PORT}`;
    }
    // Use custom protocol so /dashboard etc. resolve to app files, not file:///C:/dashboard/
    return 'penpard://app/';
}

function getDataPath(): string {
    // Use user's app data folder for database and configs
    const userDataPath = app.getPath('userData');
    const dataPath = path.join(userDataPath, 'data');

    // Ensure directory exists
    if (!fs.existsSync(dataPath)) {
        fs.mkdirSync(dataPath, { recursive: true });
    }

    return dataPath;
}

// Start the backend server
async function startBackend(): Promise<void> {
    return new Promise((resolve, reject) => {
        const backendPath = getBackendPath();
        const dataPath = getDataPath();

        console.log(`Starting backend from: ${backendPath}`);
        console.log(`Data path: ${dataPath}`);

        const env = {
            ...process.env,
            NODE_ENV: isDev ? 'development' : 'production',
            PORT: String(BACKEND_PORT),
            DATABASE_PATH: path.join(dataPath, 'penpard.db'),
        };

        if (isDev) {
            // In development, use tsx to run TypeScript directly
            backendProcess = spawn('npm', ['run', 'dev'], {
                cwd: backendPath,
                env,
                shell: true,
                stdio: 'pipe',
            });
        } else {
            // In production, run the compiled JavaScript using fork
            // fork() uses Electron's bundled Node.js with ELECTRON_RUN_AS_NODE
            const backendEntry = path.join(backendPath, 'dist', 'index.js');
            
            console.log(`Backend entry: ${backendEntry}`);
            console.log(`Backend exists: ${fs.existsSync(backendEntry)}`);

            // Use fork which properly utilizes Electron's Node.js runtime
            backendProcess = fork(backendEntry, [], {
                cwd: backendPath,
                env: {
                    ...env,
                    ELECTRON_RUN_AS_NODE: '1',
                },
                stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
            });
        }

        backendProcess.stdout?.on('data', (data) => {
            const output = data.toString();
            console.log(`[Backend] ${output}`);

            // Check if server is ready
            if (output.includes('Server running on port')) {
                backendStartTime = Date.now();
                resolve();
            }
        });

        backendProcess.stderr?.on('data', (data) => {
            console.error(`[Backend Error] ${data.toString()}`);
        });

        backendProcess.on('error', (err) => {
            console.error('Failed to start backend:', err);
            reject(err);
        });

        backendProcess.on('exit', (code) => {
            console.log(`Backend process exited with code ${code}`);
            if (code !== 0 && code !== null) {
                reject(new Error(`Backend exited with code ${code}`));
            }
        });

        // Fallback timeout - resolve after 10 seconds even if we didn't see the ready message
        setTimeout(() => {
            resolve();
        }, 10000);
    });
}

// Stop the backend server
function stopBackend(): void {
    if (backendProcess) {
        console.log('Stopping backend process...');
        const pid = backendProcess.pid;

        try {
            // Kill via the child process handle first
            backendProcess.kill('SIGTERM');
        } catch (e) {
            // ignore
        }

        if (pid) {
            try {
                if (process.platform === 'win32') {
                    // On Windows, kill the process tree synchronously
                    require('child_process').execSync(`taskkill /pid ${pid} /f /t`, { 
                        stdio: 'ignore',
                        timeout: 5000
                    });
                } else {
                    process.kill(pid, 'SIGKILL');
                }
            } catch (e) {
                // Process may already be dead
            }
        }

        backendProcess = null;
        backendStartTime = null;
        console.log('Backend process stopped.');
    }
}

// Create the main application window
async function createWindow(): Promise<void> {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1024,
        minHeight: 768,
        title: 'PenPard',
        icon: path.join(__dirname, '../assets/icon.png'),
        frame: false, // Frameless window for custom titlebar
        titleBarStyle: 'hidden', // Hide default titlebar
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            webSecurity: true,
        },
        show: false, // Don't show until ready
        backgroundColor: '#0a0a0f', // Dark background to match app theme
    });

    // Send maximize/unmaximize events to renderer
    mainWindow.on('maximize', () => {
        mainWindow?.webContents.send('window-maximized');
    });

    mainWindow.on('unmaximize', () => {
        mainWindow?.webContents.send('window-unmaximized');
    });

    // Show window when ready
    mainWindow.once('ready-to-show', () => {
        mainWindow?.show();
    });

    // Load the frontend
    if (isDev) {
        mainWindow.loadURL(`http://localhost:${FRONTEND_PORT}`);
        mainWindow.webContents.openDevTools();
    } else {
        const frontendUrl = getFrontendPath();
        console.log(`Loading frontend from: ${frontendUrl}`);
        mainWindow.loadURL(frontendUrl).catch(err => {
            console.error('Failed to load frontend:', err);
        });
    }

    // Handle external links
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// IPC Handlers
ipcMain.handle('get-backend-url', () => {
    return `http://localhost:${BACKEND_PORT}`;
});

ipcMain.handle('get-app-version', () => {
    return app.getVersion();
});

ipcMain.handle('get-data-path', () => {
    return getDataPath();
});

// Window control handlers
ipcMain.handle('window-minimize', () => {
    mainWindow?.minimize();
});

ipcMain.handle('window-maximize', () => {
    if (mainWindow?.isMaximized()) {
        mainWindow.unmaximize();
        return false;
    } else {
        mainWindow?.maximize();
        return true;
    }
});

ipcMain.handle('window-close', () => {
    mainWindow?.close();
});

ipcMain.handle('window-is-maximized', () => {
    return mainWindow?.isMaximized() || false;
});

// Menu action handlers
ipcMain.handle('menu-action', (_event, action: string) => {
    switch (action) {
        case 'new-web-scan':
            mainWindow?.webContents.send('navigate-to', '/scan/web');
            break;
        case 'new-mobile-scan':
            mainWindow?.webContents.send('navigate-to', '/scan/mobile');
            break;
        case 'open-reports':
            mainWindow?.webContents.send('navigate-to', '/reports');
            break;
        case 'open-dashboard':
            mainWindow?.webContents.send('navigate-to', '/dashboard');
            break;
        case 'settings':
            mainWindow?.webContents.send('navigate-to', '/settings');
            break;
        case 'settings-llm':
            mainWindow?.webContents.send('navigate-to', '/settings');
            break;
        case 'settings-mcp':
            mainWindow?.webContents.send('navigate-to', '/settings');
            break;
        case 'settings-prompts':
            mainWindow?.webContents.send('navigate-to', '/settings/prompts');
            break;
        case 'toggle-devtools':
            mainWindow?.webContents.toggleDevTools();
            break;
        case 'reload':
            mainWindow?.webContents.reload();
            break;
        case 'zoom-in':
            const currentZoomIn = mainWindow?.webContents.getZoomLevel() || 0;
            mainWindow?.webContents.setZoomLevel(currentZoomIn + 0.5);
            break;
        case 'zoom-out':
            const currentZoomOut = mainWindow?.webContents.getZoomLevel() || 0;
            mainWindow?.webContents.setZoomLevel(currentZoomOut - 0.5);
            break;
        case 'zoom-reset':
            mainWindow?.webContents.setZoomLevel(0);
            break;
        case 'show-shortcuts':
            mainWindow?.webContents.send('show-shortcuts-modal');
            break;
        case 'show-tour':
            mainWindow?.webContents.send('start-tour');
            break;
        case 'about':
            mainWindow?.webContents.send('show-about-modal');
            break;
        case 'docs':
            shell.openExternal('https://penpard.com/docs');
            break;
        case 'exit':
            app.quit();
            break;
        default:
            console.log('Unknown menu action:', action);
    }
});

// Advanced features IPC handlers

// Backend status
ipcMain.handle('backend-status', async () => {
    const running = backendProcess !== null && !backendProcess.killed;
    let healthy = false;
    
    if (running) {
        try {
            const response = await fetch(`http://localhost:${BACKEND_PORT}/api/health`);
            healthy = response.ok;
        } catch {
            healthy = false;
        }
    }
    
    return {
        running,
        healthy,
        pid: backendProcess?.pid || null,
        uptime: backendStartTime ? Date.now() - backendStartTime : 0,
        port: BACKEND_PORT
    };
});

// Backend restart
ipcMain.handle('backend-restart', async () => {
    try {
        stopBackend();
        await new Promise(resolve => setTimeout(resolve, 2000));
        await startBackend();
        return { success: true };
    } catch (error) {
        return { success: false, error: String(error) };
    }
});

// Frontend restart (reload)
ipcMain.handle('frontend-restart', () => {
    mainWindow?.webContents.reload();
});

// Clear cache and data
ipcMain.handle('clear-cache-data', async (_event, options: { cache: boolean; data: boolean; logs: boolean }) => {
    const results = { cache: false, data: false, logs: false };
    
    if (options.cache) {
        await session.defaultSession.clearCache();
        await session.defaultSession.clearStorageData();
        results.cache = true;
    }
    
    if (options.data) {
        stopBackend();
        const dbPath = path.join(getDataPath(), 'penpard.db');
        if (fs.existsSync(dbPath)) {
            fs.unlinkSync(dbPath);
            results.data = true;
        }
    }
    
    if (options.logs) {
        const logsPath = isDev 
            ? path.join(__dirname, '../../backend/logs')
            : path.join(process.resourcesPath, 'backend/logs');
        if (fs.existsSync(logsPath)) {
            fs.readdirSync(logsPath).forEach(file => {
                if (file.endsWith('.log')) {
                    try {
                        fs.unlinkSync(path.join(logsPath, file));
                    } catch (e) {
                        console.error('Failed to delete log file:', file, e);
                    }
                }
            });
            results.logs = true;
        }
    }
    
    return results;
});

// Get logs
ipcMain.handle('get-logs', async (_event, type: string, limit: number = 100) => {
    const logsPath = isDev 
        ? path.join(__dirname, '../../backend/logs')
        : path.join(process.resourcesPath, 'backend/logs');
    const logFile = path.join(logsPath, `${type}.log`);
    
    if (!fs.existsSync(logFile)) return [];
    
    try {
        const content = fs.readFileSync(logFile, 'utf-8');
        const lines = content.split('\n').filter(Boolean).slice(-limit);
        return lines;
    } catch {
        return [];
    }
});

// Open logs folder
ipcMain.handle('open-logs-folder', () => {
    const logsPath = isDev 
        ? path.join(__dirname, '../../backend/logs')
        : path.join(process.resourcesPath, 'backend/logs');
    shell.openPath(logsPath);
});

// Register custom protocol handler for production.
// With scheme registered as "standard: true", the URL penpard://app/ behaves like http://app/
// So /dashboard becomes penpard://app/dashboard (NOT file:///C:/dashboard/)
function registerPenpardProtocol(): void {
    const frontendOut = path.normalize(getFrontendOutPath());
    console.log(`[Protocol] Frontend out path: ${frontendOut}`);
    
    protocol.handle('penpard', (request) => {
        try {
            const url = new URL(request.url);
            // With standard: true, pathname is e.g. "/" or "/dashboard" or "/_next/static/..."
            let segment = decodeURIComponent(url.pathname);
            // Remove leading slash
            if (segment.startsWith('/')) segment = segment.substring(1);
            // Root -> index.html
            if (segment === '' || segment === '/') segment = 'index.html';
            
            // IMPORTANT: Next.js uses assetPrefix "./" which means _next assets 
            // referenced from /dashboard/ resolve to /dashboard/_next/...
            // But _next is always at the root of frontend/out. Fix this:
            if (segment.includes('_next/') && !segment.startsWith('_next/')) {
                const nextIdx = segment.indexOf('_next/');
                segment = segment.substring(nextIdx);
            }
            
            const localPath = path.join(frontendOut, segment);
            const withIndex = path.join(localPath, 'index.html');
            
            let resolved: string;
            if (path.extname(segment)) {
                // Has file extension (e.g. .js, .css, .html) -> serve directly
                resolved = localPath;
            } else if (fs.existsSync(withIndex)) {
                // Directory with index.html (e.g. /dashboard -> /dashboard/index.html)
                resolved = withIndex;
            } else if (fs.existsSync(localPath + '.html')) {
                // HTML file without extension
                resolved = localPath + '.html';
            } else {
                // Dynamic route resolution: /scan/abc-123 -> /scan/_/index.html
                // Next.js static export generates [id] routes under a "_" placeholder folder
                const parts = segment.split('/').filter(Boolean);
                let dynamicResolved: string | null = null;
                
                if (parts.length >= 2) {
                    // Try replacing the last segment with "_" (generateStaticParams placeholder)
                    const parentParts = [...parts];
                    parentParts[parentParts.length - 1] = '_';
                    const dynamicPath = path.join(frontendOut, ...parentParts, 'index.html');
                    if (fs.existsSync(dynamicPath)) {
                        dynamicResolved = dynamicPath;
                    }
                }
                
                // Also try replacing deeper segments for nested dynamic routes
                // e.g. /scan/abc-123/details -> /scan/_/details/index.html
                if (!dynamicResolved && parts.length >= 3) {
                    for (let i = parts.length - 1; i >= 1; i--) {
                        const tryParts = [...parts];
                        tryParts[i] = '_';
                        const tryPath = path.join(frontendOut, ...tryParts, 'index.html');
                        if (fs.existsSync(tryPath)) {
                            dynamicResolved = tryPath;
                            break;
                        }
                    }
                }
                
                if (dynamicResolved) {
                    resolved = dynamicResolved;
                } else {
                    // Final fallback: try as-is, or serve index.html for SPA routing
                    resolved = fs.existsSync(localPath) 
                        ? localPath 
                        : path.join(frontendOut, 'index.html');
                }
            }
            
            const normalized = path.normalize(resolved);
            
            // Security: prevent directory traversal
            if (!normalized.startsWith(frontendOut)) {
                console.error(`[Protocol] Blocked traversal attempt: ${segment}`);
                return new Response('Forbidden', { status: 403 });
            }
            
            if (!fs.existsSync(normalized)) {
                // For asset files that don't exist, try stripping path prefixes
                if (path.extname(segment)) {
                    const parts = segment.split('/');
                    for (let i = 1; i < parts.length; i++) {
                        const stripped = parts.slice(i).join('/');
                        const candidate = path.normalize(path.join(frontendOut, stripped));
                        if (candidate.startsWith(frontendOut) && fs.existsSync(candidate)) {
                            return net.fetch(pathToFileURL(candidate).toString());
                        }
                    }
                    // Asset truly not found
                    console.warn(`[Protocol] Asset not found: ${segment}`);
                    return new Response('Not Found', { status: 404 });
                }
                // For routes without extension, serve index.html (SPA fallback)
                const fallback = path.join(frontendOut, 'index.html');
                return net.fetch(pathToFileURL(fallback).toString());
            }
            
            return net.fetch(pathToFileURL(normalized).toString());
        } catch (e) {
            console.error('[Protocol] Error:', e);
            return new Response('Internal Error', { status: 500 });
        }
    });
    
    console.log('[Protocol] penpard:// protocol handler registered');
}

// App lifecycle
app.whenReady().then(async () => {
    try {
        console.log('Starting PenPard...');
        console.log(`Running in ${isDev ? 'development' : 'production'} mode`);

        if (!isDev) {
            registerPenpardProtocol();
        }

        // Start backend first
        await startBackend();
        console.log('Backend started successfully');

        // Then create the window
        await createWindow();

        // Initialize auto-updater (only in production)
        if (!isDev && mainWindow) {
            appUpdater.init(mainWindow);
            // Check for updates after a short delay
            setTimeout(() => {
                appUpdater.checkForUpdates();
            }, 5000);
        }

    } catch (error) {
        console.error('Failed to start application:', error);
        app.quit();
    }
});

app.on('window-all-closed', () => {
    stopBackend();

    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (mainWindow === null) {
        createWindow();
    }
});

app.on('before-quit', () => {
    stopBackend();
});

// Handle second instance
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
    app.quit();
} else {
    app.on('second-instance', () => {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.focus();
        }
    });
}
