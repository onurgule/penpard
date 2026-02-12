'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
    Minus, 
    Square, 
    X, 
    Shield,
    ChevronDown,
    RefreshCw,
    Activity,
    FileText,
    Trash2,
    Download,
    ArrowDownCircle
} from 'lucide-react';
import ProcessStatusModal from './modals/ProcessStatusModal';
import LogViewerModal from './modals/LogViewerModal';
import ClearDataModal from './modals/ClearDataModal';

interface MenuItem {
    label?: string;
    action?: string;
    shortcut?: string;
    separator?: boolean;
}

const menuStructure: { [key: string]: MenuItem[] } = {
    File: [
        { label: 'New Web Scan', action: 'new-web-scan', shortcut: 'Ctrl+N' },
        { label: 'New Mobile Scan', action: 'new-mobile-scan', shortcut: 'Ctrl+Shift+N' },
        { separator: true },
        { label: 'Open Reports', action: 'open-reports', shortcut: 'Ctrl+O' },
        { separator: true },
        { label: 'Exit', action: 'exit', shortcut: 'Alt+F4' },
    ],
    Edit: [
        { label: 'Undo', action: 'undo', shortcut: 'Ctrl+Z' },
        { label: 'Redo', action: 'redo', shortcut: 'Ctrl+Y' },
        { separator: true },
        { label: 'Cut', action: 'cut', shortcut: 'Ctrl+X' },
        { label: 'Copy', action: 'copy', shortcut: 'Ctrl+C' },
        { label: 'Paste', action: 'paste', shortcut: 'Ctrl+V' },
    ],
    View: [
        { label: 'Reload', action: 'reload', shortcut: 'Ctrl+R' },
        { separator: true },
        { label: 'Zoom In', action: 'zoom-in', shortcut: 'Ctrl+Plus' },
        { label: 'Zoom Out', action: 'zoom-out', shortcut: 'Ctrl+Minus' },
        { label: 'Reset Zoom', action: 'zoom-reset', shortcut: 'Ctrl+0' },
        { separator: true },
        { label: 'Toggle DevTools', action: 'toggle-devtools', shortcut: 'F12' },
    ],
    Scan: [
        { label: 'Quick Web Scan', action: 'new-web-scan', shortcut: 'Ctrl+W' },
        { label: 'Quick Mobile Scan', action: 'new-mobile-scan', shortcut: 'Ctrl+M' },
        { separator: true },
        { label: 'Dashboard', action: 'open-dashboard', shortcut: 'Ctrl+H' },
    ],
    Settings: [
        { label: 'LLM Configuration', action: 'settings-llm', shortcut: 'Ctrl+L' },
        { label: 'MCP Servers', action: 'settings-mcp' },
        { label: 'Custom Prompts', action: 'settings-prompts' },
        { separator: true },
        { label: 'Preferences', action: 'settings', shortcut: 'Ctrl+,' },
        { separator: true },
        { label: 'Restart Backend', action: 'restart-backend' },
        { label: 'Restart Frontend', action: 'restart-frontend' },
        { separator: true },
        { label: 'Process Status', action: 'process-status' },
        { label: 'View Logs', action: 'view-logs' },
        { label: 'Clear Cache & Data', action: 'clear-data' },
    ],
    Help: [
        { label: 'Documentation', action: 'docs', shortcut: 'F1' },
        { label: 'Keyboard Shortcuts', action: 'show-shortcuts', shortcut: 'Ctrl+/' },
        { label: 'Show Tour', action: 'show-tour' },
        { separator: true },
        { label: 'About PenPard', action: 'about' },
    ],
};

export default function CustomTitlebar() {
    const [isMaximized, setIsMaximized] = useState(false);
    const [activeMenu, setActiveMenu] = useState<string | null>(null);
    const [isElectron, setIsElectron] = useState(false);
    const [showProcessStatus, setShowProcessStatus] = useState(false);
    const [showLogViewer, setShowLogViewer] = useState(false);
    const [showClearData, setShowClearData] = useState(false);
    const [isRestarting, setIsRestarting] = useState(false);
    
    // Update state
    const [updateAvailable, setUpdateAvailable] = useState(false);
    const [updateVersion, setUpdateVersion] = useState<string | null>(null);
    const [updateDownloading, setUpdateDownloading] = useState(false);
    const [updateDownloaded, setUpdateDownloaded] = useState(false);
    const [updateProgress, setUpdateProgress] = useState(0);

    useEffect(() => {
        // Check if running in Electron
        if (typeof window !== 'undefined' && window.electronAPI?.isElectron) {
            setIsElectron(true);
            
            // Check initial maximized state
            window.electronAPI.windowIsMaximized().then(setIsMaximized);

            // Listen for maximize/unmaximize events
            window.electronAPI.onWindowMaximized(() => setIsMaximized(true));
            window.electronAPI.onWindowUnmaximized(() => setIsMaximized(false));
            
            // Listen for update status
            window.electronAPI.onUpdaterStatus((status) => {
                setUpdateAvailable(status.available);
                setUpdateVersion(status.version);
                setUpdateDownloading(status.downloading);
                setUpdateDownloaded(status.downloaded);
                setUpdateProgress(status.progress || 0);
            });
            
            // Check initial update status
            window.electronAPI.updaterStatus().then((status) => {
                if (status) {
                    setUpdateAvailable(status.available);
                    setUpdateVersion(status.version);
                    setUpdateDownloaded(status.downloaded);
                }
            });
        }
    }, []);

    // Don't render if not in Electron
    if (!isElectron) {
        return null;
    }

    const handleMinimize = () => {
        window.electronAPI?.windowMinimize();
    };

    const handleMaximize = async () => {
        if (window.electronAPI) {
            const maximized = await window.electronAPI.windowMaximize();
            setIsMaximized(maximized);
        }
    };

    const handleClose = () => {
        window.electronAPI?.windowClose();
    };

    const handleUpdateClick = async () => {
        if (!window.electronAPI) return;
        
        if (updateDownloaded) {
            // Install and restart
            window.electronAPI.updaterInstall();
        } else if (updateAvailable && !updateDownloading) {
            // Start download
            window.electronAPI.updaterDownload();
        }
    };

    const handleMenuClick = (menuName: string) => {
        setActiveMenu(activeMenu === menuName ? null : menuName);
    };

    const handleMenuItemClick = async (action?: string) => {
        setActiveMenu(null);
        
        if (!action || !window.electronAPI) return;

        // Handle advanced menu actions locally
        switch (action) {
            case 'restart-backend':
                if (isRestarting) return;
                setIsRestarting(true);
                try {
                    const result = await window.electronAPI.backendRestart();
                    if (!result.success) {
                        console.error('Backend restart failed:', result.error);
                    }
                } finally {
                    setIsRestarting(false);
                }
                return;
            case 'restart-frontend':
                window.electronAPI.frontendRestart();
                return;
            case 'process-status':
                setShowProcessStatus(true);
                return;
            case 'view-logs':
                setShowLogViewer(true);
                return;
            case 'clear-data':
                setShowClearData(true);
                return;
            default:
                // Let main process handle other actions
                window.electronAPI.menuAction(action);
        }
    };

    return (
        <>
            {/* Titlebar */}
            <div 
                className="fixed top-0 left-0 right-0 h-10 z-[60] flex items-center justify-between bg-dark-950/95 backdrop-blur-md border-b border-white/5 titlebar-drag"
            >
                {/* Left: Logo + App Name + Menu */}
                <div className="flex items-center h-full">
                    {/* Logo */}
                    <div className="flex items-center gap-2 px-4">
                        <Shield className="w-4 h-4 text-cyan-400" />
                        <span className="text-xs font-bold text-cyan-400 tracking-wider">
                            PENPARD
                        </span>
                    </div>

                    {/* Menu Bar */}
                    <div className="flex h-full titlebar-no-drag">
                        {Object.keys(menuStructure).map((menuName) => (
                            <button
                                key={menuName}
                                onClick={() => handleMenuClick(menuName)}
                                className={`px-3 h-full text-xs text-gray-400 hover:text-white hover:bg-white/5 transition-colors flex items-center gap-1 ${
                                    activeMenu === menuName ? 'bg-white/10 text-white' : ''
                                }`}
                            >
                                {menuName}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Center: Update Available Indicator */}
                {(updateAvailable || updateDownloading || updateDownloaded) && (
                    <div className="flex items-center titlebar-no-drag">
                        <button
                            onClick={handleUpdateClick}
                            disabled={updateDownloading}
                            className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium transition-all ${
                                updateDownloaded
                                    ? 'bg-green-500 text-white hover:bg-green-400'
                                    : updateDownloading
                                    ? 'bg-yellow-500/20 text-yellow-400 cursor-wait'
                                    : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                            }`}
                        >
                            {updateDownloaded ? (
                                <>
                                    <ArrowDownCircle className="w-3.5 h-3.5" />
                                    <span>Install v{updateVersion}</span>
                                </>
                            ) : updateDownloading ? (
                                <>
                                    <Download className="w-3.5 h-3.5 animate-bounce" />
                                    <span>Downloading... {updateProgress.toFixed(0)}%</span>
                                </>
                            ) : (
                                <>
                                    <Download className="w-3.5 h-3.5" />
                                    <span>Update v{updateVersion}</span>
                                </>
                            )}
                        </button>
                    </div>
                )}

                {/* Right: Window Controls */}
                <div className="flex h-full titlebar-no-drag">
                    <button
                        onClick={handleMinimize}
                        className="w-12 h-full flex items-center justify-center text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                        title="Minimize"
                    >
                        <Minus className="w-4 h-4" />
                    </button>
                    <button
                        onClick={handleMaximize}
                        className="w-12 h-full flex items-center justify-center text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                        title={isMaximized ? 'Restore' : 'Maximize'}
                    >
                        {isMaximized ? (
                            <svg className="w-3.5 h-3.5" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
                                <rect x="2" y="0" width="8" height="8" rx="1" />
                                <rect x="0" y="2" width="8" height="8" rx="1" fill="#0a0a0f" />
                            </svg>
                        ) : (
                            <Square className="w-3.5 h-3.5" />
                        )}
                    </button>
                    <button
                        onClick={handleClose}
                        className="w-12 h-full flex items-center justify-center text-gray-400 hover:text-white hover:bg-red-600/80 transition-colors"
                        title="Close"
                    >
                        <X className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Dropdown Menus */}
            <AnimatePresence>
                {activeMenu && (
                    <>
                        {/* Backdrop */}
                        <div
                            className="fixed inset-0 z-[55]"
                            onClick={() => setActiveMenu(null)}
                        />

                        {/* Menu Dropdown */}
                        <motion.div
                            initial={{ opacity: 0, y: -5 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -5 }}
                            transition={{ duration: 0.1 }}
                            className="fixed z-[56] glass-darker rounded-lg shadow-2xl overflow-hidden min-w-[220px] border border-white/10"
                            style={{
                                left: getMenuPosition(activeMenu),
                                top: 40,
                            }}
                        >
                            {menuStructure[activeMenu].map((item, index) => {
                                if (item.separator) {
                                    return (
                                        <div
                                            key={`sep-${index}`}
                                            className="h-px bg-white/5 my-1 mx-2"
                                        />
                                    );
                                }

                                return (
                                    <button
                                        key={index}
                                        onClick={() => handleMenuItemClick(item.action)}
                                        className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:text-white hover:bg-white/10 transition-colors flex items-center justify-between"
                                    >
                                        <span>{item.label}</span>
                                        {item.shortcut && (
                                            <span className="text-xs text-gray-500 font-mono ml-4">
                                                {item.shortcut}
                                            </span>
                                        )}
                                    </button>
                                );
                            })}
                        </motion.div>
                    </>
                )}
            </AnimatePresence>

            {/* Advanced Modals */}
            <ProcessStatusModal 
                isOpen={showProcessStatus} 
                onClose={() => setShowProcessStatus(false)} 
            />
            <LogViewerModal 
                isOpen={showLogViewer} 
                onClose={() => setShowLogViewer(false)} 
            />
            <ClearDataModal 
                isOpen={showClearData} 
                onClose={() => setShowClearData(false)} 
            />
        </>
    );
}

// Helper function to calculate menu position based on menu name
function getMenuPosition(menuName: string): number {
    const menuOrder = Object.keys(menuStructure);
    const index = menuOrder.indexOf(menuName);
    // Logo area (~100px) + each menu button (~60px)
    return 100 + (index * 60);
}
