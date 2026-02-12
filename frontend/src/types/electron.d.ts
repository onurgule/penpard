// Global type definitions for Electron API
// This file extends the Window interface to include the electronAPI property

export interface BackendStatus {
    running: boolean;
    healthy: boolean;
    pid: number | null;
    uptime: number;
    port: number;
}

export interface ClearCacheOptions {
    cache: boolean;
    data: boolean;
    logs: boolean;
}

export interface ClearCacheResult {
    cache: boolean;
    data: boolean;
    logs: boolean;
}

export interface RestartResult {
    success: boolean;
    error?: string;
}

declare global {
    interface Window {
        electronAPI?: {
            // App info
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
            backendRestart: () => Promise<RestartResult>;
            frontendRestart: () => Promise<void>;
            getBackendStatus: () => Promise<BackendStatus>;
            clearCacheData: (options: ClearCacheOptions) => Promise<ClearCacheResult>;
            getLogs: (type: string, limit?: number) => Promise<string[]>;
            openLogsFolder: () => Promise<void>;
        };
    }
}

export { };
