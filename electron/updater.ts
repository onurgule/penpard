import { autoUpdater, UpdateInfo } from 'electron-updater';
import { BrowserWindow, ipcMain, dialog, app } from 'electron';

// Update server URL - using GitHub releases for open source distribution
const UPDATE_SERVER_URL = 'https://github.com/penpard/penpard/releases/latest/download';

// Simple logger wrapper using console
const log = {
    info: (...args: any[]) => console.log('[Updater]', ...args),
    warn: (...args: any[]) => console.warn('[Updater]', ...args),
    error: (...args: any[]) => console.error('[Updater]', ...args),
};

export interface UpdateStatus {
    checking: boolean;
    available: boolean;
    downloading: boolean;
    downloaded: boolean;
    error: string | null;
    progress: number;
    version: string | null;
    releaseNotes: string | null;
}

/**
 * Auto-updater manager for Electron applications.
 * Handles checking, downloading, and installing updates.
 */
export class AppUpdater {
    private mainWindow: BrowserWindow | null = null;
    private status: UpdateStatus = {
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
        error: null,
        progress: 0,
        version: null,
        releaseNotes: null,
    };

    constructor() {
        // Configure auto-updater
        autoUpdater.autoDownload = false; // Don't auto-download, let user decide
        autoUpdater.autoInstallOnAppQuit = true;
        
        // Set custom update server
        autoUpdater.setFeedURL({
            provider: 'generic',
            url: UPDATE_SERVER_URL,
            channel: 'latest',
        });

        this.setupEventHandlers();
        this.setupIpcHandlers();
    }

    /**
     * Initialize with main window reference.
     */
    init(mainWindow: BrowserWindow): void {
        this.mainWindow = mainWindow;
    }

    /**
     * Setup auto-updater event handlers.
     */
    private setupEventHandlers(): void {
        autoUpdater.on('checking-for-update', () => {
            log.info('Checking for updates...');
            this.status = { ...this.status, checking: true, error: null };
            this.sendStatusToWindow();
        });

        autoUpdater.on('update-available', (info: UpdateInfo) => {
            log.info('Update available:', info.version);
            this.status = {
                ...this.status,
                checking: false,
                available: true,
                version: info.version,
                releaseNotes: typeof info.releaseNotes === 'string' 
                    ? info.releaseNotes 
                    : Array.isArray(info.releaseNotes) 
                        ? info.releaseNotes.map(n => n.note).join('\n')
                        : null,
            };
            this.sendStatusToWindow();
            this.promptUserForUpdate(info);
        });

        autoUpdater.on('update-not-available', (info: UpdateInfo) => {
            log.info('No updates available');
            this.status = {
                ...this.status,
                checking: false,
                available: false,
                version: info.version,
            };
            this.sendStatusToWindow();
        });

        autoUpdater.on('error', (err: Error) => {
            // Don't spam logs for expected errors (e.g. update server not configured yet)
            const isExpected = err.message?.includes('ERR_UPDATER_CHANNEL_FILE_NOT_FOUND') 
                || err.message?.includes('404')
                || err.message?.includes('ECONNREFUSED')
                || err.message?.includes('ENOTFOUND');
            
            if (isExpected) {
                log.info('Update check skipped (server not ready)');
            } else {
                log.error('Update error:', err);
            }
            
            this.status = {
                ...this.status,
                checking: false,
                downloading: false,
                error: isExpected ? null : err.message,
            };
            this.sendStatusToWindow();
        });

        autoUpdater.on('download-progress', (progress) => {
            log.info(`Download progress: ${progress.percent.toFixed(1)}%`);
            this.status = {
                ...this.status,
                downloading: true,
                progress: progress.percent,
            };
            this.sendStatusToWindow();
        });

        autoUpdater.on('update-downloaded', (info: UpdateInfo) => {
            log.info('Update downloaded:', info.version);
            this.status = {
                ...this.status,
                downloading: false,
                downloaded: true,
                progress: 100,
            };
            this.sendStatusToWindow();
            this.promptUserToRestart(info);
        });
    }

    /**
     * Setup IPC handlers for renderer communication.
     */
    private setupIpcHandlers(): void {
        ipcMain.handle('updater-check', async () => {
            return this.checkForUpdates();
        });

        ipcMain.handle('updater-download', async () => {
            return this.downloadUpdate();
        });

        ipcMain.handle('updater-install', async () => {
            return this.installUpdate();
        });

        ipcMain.handle('updater-status', () => {
            return this.status;
        });
    }

    /**
     * Check for updates.
     */
    async checkForUpdates(): Promise<UpdateStatus> {
        try {
            await autoUpdater.checkForUpdates();
        } catch (error: any) {
            log.error('Failed to check for updates:', error);
            this.status.error = error.message;
        }
        return this.status;
    }

    /**
     * Download available update.
     */
    async downloadUpdate(): Promise<void> {
        if (!this.status.available) {
            throw new Error('No update available to download');
        }
        
        this.status.downloading = true;
        this.sendStatusToWindow();
        
        await autoUpdater.downloadUpdate();
    }

    /**
     * Install downloaded update and restart.
     */
    installUpdate(): void {
        if (!this.status.downloaded) {
            throw new Error('No update downloaded to install');
        }
        
        autoUpdater.quitAndInstall(false, true);
    }

    /**
     * Send status to renderer window.
     */
    private sendStatusToWindow(): void {
        if (this.mainWindow && !this.mainWindow.isDestroyed()) {
            this.mainWindow.webContents.send('updater-status', this.status);
        }
    }

    /**
     * Prompt user about available update.
     */
    private async promptUserForUpdate(info: UpdateInfo): Promise<void> {
        if (!this.mainWindow) return;

        const result = await dialog.showMessageBox(this.mainWindow, {
            type: 'info',
            title: 'Update Available',
            message: `A new version (${info.version}) is available!`,
            detail: `Would you like to download and install it now?\n\n${
                typeof info.releaseNotes === 'string' ? info.releaseNotes.slice(0, 500) : ''
            }`,
            buttons: ['Download Now', 'Later'],
            defaultId: 0,
            cancelId: 1,
        });

        if (result.response === 0) {
            await this.downloadUpdate();
        }
    }

    /**
     * Prompt user to restart and install update.
     */
    private async promptUserToRestart(info: UpdateInfo): Promise<void> {
        if (!this.mainWindow) return;

        const result = await dialog.showMessageBox(this.mainWindow, {
            type: 'info',
            title: 'Update Ready',
            message: `Version ${info.version} has been downloaded.`,
            detail: 'Would you like to restart PenPard now to apply the update?',
            buttons: ['Restart Now', 'Later'],
            defaultId: 0,
            cancelId: 1,
        });

        if (result.response === 0) {
            this.installUpdate();
        }
    }

    /**
     * Get current update status.
     */
    getStatus(): UpdateStatus {
        return this.status;
    }

    /**
     * Set the update feed URL (for custom update servers).
     */
    setFeedURL(url: string): void {
        autoUpdater.setFeedURL({
            provider: 'generic',
            url,
        });
    }
}

// Export singleton instance
export const appUpdater = new AppUpdater();
