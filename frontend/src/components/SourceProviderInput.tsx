'use client';

import { useState } from 'react';
import { FolderOpen, Github, FileArchive, UploadCloud } from 'lucide-react';
import axios from 'axios';
import { API_URL } from '@/lib/api-config';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';

export type SourceType = 'local' | 'zip' | 'git';

interface Props {
    sourceType: SourceType;
    setSourceType: (type: SourceType) => void;
    
    localPath: string;
    setLocalPath: (path: string) => void;
    
    zipFile: File | null;
    setZipFile: (file: File | null) => void;
    
    gitUrl: string;
    setGitUrl: (url: string) => void;
    
    gitToken: string;
    setGitToken: (token: string) => void;
    
    disabled?: boolean;
}

export default function SourceProviderInput({
    sourceType, setSourceType,
    localPath, setLocalPath,
    zipFile, setZipFile,
    gitUrl, setGitUrl,
    gitToken, setGitToken,
    disabled
}: Props) {
    const [isSelecting, setIsSelecting] = useState(false);

    const handleSelectDirectory = async () => {
        setIsSelecting(true);
        try {
            const token = useAuthStore.getState().token;
            const res = await axios.get(`${API_URL}/scans/system/select-directory`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.data.path) {
                setLocalPath(res.data.path);
            }
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to open directory picker. Ensure backend is running locally.');
        } finally {
            setIsSelecting(false);
        }
    };

    return (
        <div className="bg-dark-900 border border-dark-600 rounded-lg overflow-hidden">
            {/* Tabs */}
            <div className="flex border-b border-dark-600 bg-dark-800/50">
                <button
                    type="button"
                    onClick={() => setSourceType('local')}
                    disabled={disabled}
                    className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-colors ${sourceType === 'local' ? 'text-cyan-400 border-b-2 border-cyan-400 bg-dark-800' : 'text-gray-400 hover:text-white'}`}
                >
                    <FolderOpen className="w-4 h-4" /> Local Path
                </button>
                <button
                    type="button"
                    onClick={() => setSourceType('zip')}
                    disabled={disabled}
                    className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-colors ${sourceType === 'zip' ? 'text-cyan-400 border-b-2 border-cyan-400 bg-dark-800' : 'text-gray-400 hover:text-white'}`}
                >
                    <FileArchive className="w-4 h-4" /> ZIP Upload
                </button>
                <button
                    type="button"
                    onClick={() => setSourceType('git')}
                    disabled={disabled}
                    className={`flex-1 py-3 text-sm font-medium flex items-center justify-center gap-2 transition-colors ${sourceType === 'git' ? 'text-cyan-400 border-b-2 border-cyan-400 bg-dark-800' : 'text-gray-400 hover:text-white'}`}
                >
                    <Github className="w-4 h-4" /> Git Repo
                </button>
            </div>

            {/* Content */}
            <div className="p-4">
                {sourceType === 'local' && (
                    <div>
                        <label className="block text-gray-400 text-xs mb-1">Local Directory Path</label>
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={localPath}
                                onChange={(e) => setLocalPath(e.target.value)}
                                placeholder="E.g., C:\Projects\my-app"
                                disabled={disabled}
                                className="flex-1 px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
                            />
                            <button
                                type="button"
                                onClick={handleSelectDirectory}
                                disabled={disabled || isSelecting}
                                className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white text-sm rounded-lg transition-colors border border-dark-500 whitespace-nowrap"
                            >
                                {isSelecting ? 'Opening...' : 'Browse...'}
                            </button>
                        </div>
                    </div>
                )}

                {sourceType === 'zip' && (
                    <div>
                        <label className="block text-gray-400 text-xs mb-1">Upload ZIP Archive</label>
                        <div className="relative">
                            <input
                                type="file"
                                accept=".zip"
                                onChange={(e) => setZipFile(e.target.files?.[0] || null)}
                                disabled={disabled}
                                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed z-10"
                            />
                            <div className={`p-6 border-2 border-dashed rounded-lg text-center transition-colors ${zipFile ? 'border-cyan-500 bg-cyan-500/10' : 'border-dark-600 bg-dark-800 hover:bg-dark-700'}`}>
                                <UploadCloud className={`w-8 h-8 mx-auto mb-2 ${zipFile ? 'text-cyan-400' : 'text-gray-500'}`} />
                                <p className="text-sm font-medium text-white mb-1">
                                    {zipFile ? zipFile.name : 'Click or drag a .zip file here'}
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {sourceType === 'git' && (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-gray-400 text-xs mb-1">Repository URL</label>
                            <input
                                type="text"
                                value={gitUrl}
                                onChange={(e) => setGitUrl(e.target.value)}
                                placeholder="https://github.com/user/repo"
                                disabled={disabled}
                                className="w-full px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
                            />
                        </div>
                        <div>
                            <label className="block text-gray-400 text-xs mb-1">Access Token (Optional for private repos)</label>
                            <input
                                type="password"
                                value={gitToken}
                                onChange={(e) => setGitToken(e.target.value)}
                                placeholder="ghp_..."
                                disabled={disabled}
                                className="w-full px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
                            />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
