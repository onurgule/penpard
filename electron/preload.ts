import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
    // Get the backend URL (useful for switching between local and remote)
    getBackendUrl: () => ipcRenderer.invoke('get-backend-url'),

    // Get application version
    getAppVersion: () => ipcRenderer.invoke('get-app-version'),

    // Get the data path for storing files
    getDataPath: () => ipcRenderer.invoke('get-data-path'),

    // Platform info
    platform: process.platform,

    // Check if running in Electron
    isElectron: true,

    // Window controls
    windowMinimize: () => ipcRenderer.invoke('window-minimize'),
    windowMaximize: () => ipcRenderer.invoke('window-maximize'),
    windowClose: () => ipcRenderer.invoke('window-close'),
    windowIsMaximized: () => ipcRenderer.invoke('window-is-maximized'),

    // Window state listeners
    onWindowMaximized: (callback: () => void) => {
        ipcRenderer.on('window-maximized', callback);
    },
    onWindowUnmaximized: (callback: () => void) => {
        ipcRenderer.on('window-unmaximized', callback);
    },

    // Menu actions
    menuAction: (action: string) => ipcRenderer.invoke('menu-action', action),

    // Navigation listener (from menu actions)
    onNavigate: (callback: (route: string) => void) => {
        ipcRenderer.on('navigate-to', (_event, route) => callback(route));
    },

    // Modal triggers from menu
    onShowShortcuts: (callback: () => void) => {
        ipcRenderer.on('show-shortcuts-modal', callback);
    },
    onStartTour: (callback: () => void) => {
        ipcRenderer.on('start-tour', callback);
    },
    onShowAbout: (callback: () => void) => {
        ipcRenderer.on('show-about-modal', callback);
    },

    // Auto-updater
    updaterCheck: () => ipcRenderer.invoke('updater-check'),
    updaterDownload: () => ipcRenderer.invoke('updater-download'),
    updaterInstall: () => ipcRenderer.invoke('updater-install'),
    updaterStatus: () => ipcRenderer.invoke('updater-status'),
    onUpdaterStatus: (callback: (status: any) => void) => {
        ipcRenderer.on('updater-status', (_event, status) => callback(status));
    },

    // Advanced features
    backendRestart: () => ipcRenderer.invoke('backend-restart'),
    frontendRestart: () => ipcRenderer.invoke('frontend-restart'),
    getBackendStatus: () => ipcRenderer.invoke('backend-status'),
    clearCacheData: (options: { cache: boolean; data: boolean; logs: boolean }) => 
        ipcRenderer.invoke('clear-cache-data', options),
    getLogs: (type: string, limit?: number) => ipcRenderer.invoke('get-logs', type, limit || 100),
    openLogsFolder: () => ipcRenderer.invoke('open-logs-folder'),
});

// Type definitions for the exposed API
declare global {
    interface Window {
        electronAPI?: {
            getBackendUrl: () => Promise<string>;
            getAppVersion: () => Promise<string>;
            getDataPath: () => Promise<string>;
            platform: string;
            isElectron: boolean;

            // Window controls
            windowMinimize: () => Promise<void>;
            windowMaximize: () => Promise<boolean>;
            windowClose: () => Promise<void>;
            windowIsMaximized: () => Promise<boolean>;

            // Window state listeners
            onWindowMaximized: (callback: () => void) => void;
            onWindowUnmaximized: (callback: () => void) => void;

            // Menu actions
            menuAction: (action: string) => Promise<void>;

            // Navigation
            onNavigate: (callback: (route: string) => void) => void;

            // Modal triggers
            onShowShortcuts: (callback: () => void) => void;
            onStartTour: (callback: () => void) => void;
            onShowAbout: (callback: () => void) => void;

            // Auto-updater
            updaterCheck: () => Promise<any>;
            updaterDownload: () => Promise<void>;
            updaterInstall: () => Promise<void>;
            updaterStatus: () => Promise<any>;
            onUpdaterStatus: (callback: (status: any) => void) => void;

            // Advanced features
            backendRestart: () => Promise<{ success: boolean; error?: string }>;
            frontendRestart: () => Promise<void>;
            getBackendStatus: () => Promise<{
                running: boolean;
                healthy: boolean;
                pid: number | null;
                uptime: number;
                port: number;
            }>;
            clearCacheData: (options: { cache: boolean; data: boolean; logs: boolean }) => Promise<{
                cache: boolean;
                data: boolean;
                logs: boolean;
            }>;
            getLogs: (type: string, limit?: number) => Promise<string[]>;
            openLogsFolder: () => Promise<void>;
        };
    }
}
