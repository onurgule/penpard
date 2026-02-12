
'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import {
    ArrowLeft,
    Cpu,
    Zap,
    Server,
    Terminal,
    Play,
    Square,
    RefreshCw,
    Trash2,
    Plus,
    X,
    FileText,
    Lock,
    BarChart3,
    BookOpen,
    Shield,
    Save,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';
import axios from 'axios';
import ReportTemplateEditor from '@/components/ReportTemplateEditor';
import { API_URL } from '@/lib/api-config';

type LLMProvider = 'gemini' | 'deepseek' | 'openai' | 'anthropic' | 'ollama';

interface LLMConfig {
    provider: LLMProvider;
    api_key: string;
    model?: string;
    is_active: number;
    settings_json?: string;
    updated_at?: string;
}

interface McpServer {
    name: string;
    command: string;
    args?: string;
    env_vars?: string;
    status: 'stopped' | 'running' | 'error';
    is_enabled: number;
}

export default function SettingsPage() {
    const router = useRouter();
    const { token, isAuthenticated, changeKey } = useAuthStore();

    // LLM State
    const [configs, setConfigs] = useState<LLMConfig[]>([]);
    const [statusMap, setStatusMap] = useState<Record<string, string>>({});

    // MCP State
    const [servers, setServers] = useState<McpServer[]>([]);
    const [mcpLogs, setMcpLogs] = useState<string[]>([]);

    // Burp Suite Config State
    const [burpHost, setBurpHost] = useState('127.0.0.1');
    const [burpPort, setBurpPort] = useState(9876);
    const [burpUseHttps, setBurpUseHttps] = useState(false);
    const [burpStatus, setBurpStatus] = useState<'unknown' | 'online' | 'offline' | 'checking'>('unknown');
    const [burpSaving, setBurpSaving] = useState(false);

    // Lock Key Change State
    const [currentKey, setCurrentKey] = useState('');
    const [newKey, setNewKey] = useState('');
    const [confirmKey, setConfirmKey] = useState('');
    const [isChangingKey, setIsChangingKey] = useState(false);

    // Config Modal State
    const [isMcpModalOpen, setIsMcpModalOpen] = useState(false);
    const [newMcpServer, setNewMcpServer] = useState<Partial<McpServer>>({
        name: '',
        command: '',
        args: '[]',
        env_vars: '{}',
        status: 'stopped',
        is_enabled: 1
    });

    // Auth guard - redirect to login if not authenticated
    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    useEffect(() => {
        if (isAuthenticated && token) {
            fetchSettings();
            fetchMcpServers();
            fetchBurpConfig();
            // Poll logs for demo
            const interval = setInterval(fetchMcpLogs, 3000);
            return () => clearInterval(interval);
        }
    }, [isAuthenticated, token]);

    const fetchSettings = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/llm`, { headers: { Authorization: `Bearer ${token}` }, timeout: 5000 });
            setConfigs(res.data.configs || []);
        } catch {
            // Backend may not be ready yet
        }
    };

    const fetchBurpConfig = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/burp`, { headers: { Authorization: `Bearer ${token}` }, timeout: 5000 });
            if (res.data.config) {
                setBurpHost(res.data.config.host || '127.0.0.1');
                setBurpPort(res.data.config.port || 9876);
                setBurpUseHttps(res.data.config.useHttps || false);
            }
        } catch { /* Backend may not be ready */ }
    };

    const saveBurpConfig = async () => {
        setBurpSaving(true);
        try {
            await axios.post(`${API_URL}/config/burp`, { host: burpHost, port: burpPort, useHttps: burpUseHttps }, { headers: { Authorization: `Bearer ${token}` } });
            toast.success('Burp Suite configuration saved');
            testBurpConnection();
        } catch {
            toast.error('Failed to save Burp config');
        } finally {
            setBurpSaving(false);
        }
    };

    const testBurpConnection = async () => {
        setBurpStatus('checking');
        try {
            const res = await axios.post(`${API_URL}/config/burp/test`, { host: burpHost, port: burpPort, useHttps: burpUseHttps }, { headers: { Authorization: `Bearer ${token}` } });
            setBurpStatus(res.data.status === 'online' ? 'online' : 'offline');
            if (res.data.status === 'online') {
                toast.success(res.data.message || 'Burp Suite is online!');
            } else {
                toast.error(res.data.message || 'Burp Suite is offline');
            }
        } catch {
            setBurpStatus('offline');
            toast.error('Connection test failed');
        }
    };

    const fetchMcpServers = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/mcp`, { headers: { Authorization: `Bearer ${token}` }, timeout: 5000 });
            setServers(res.data.servers || []);
        } catch {
            // Backend may not be ready yet
        }
    };

    const fetchMcpLogs = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/mcp/logs`, { headers: { Authorization: `Bearer ${token}` }, timeout: 5000 });
            setMcpLogs(res.data.logs?.map((l: any) => `[${l.server}] ${l.message}`) || []);
        } catch {
            // Backend may not be ready yet
        }
    };

    const updateConfig = async (provider: string, data: Partial<LLMConfig>) => {
        try {
            // Optimistic update logic was causing issues with controlled inputs if not careful
            // Here we trust the local state 'configs' is already updated by onChange handler
            // But we need to ensure we send the correct merged object to backend

            const currentConfig = configs.find(c => c.provider === provider);
            const configToSave = {
                provider,
                api_key: '',
                is_active: 0,
                model: 'default',
                ...currentConfig,
                ...data
            };

            // Backend call
            await axios.post(`${API_URL}/config/llm`, configToSave, { headers: { Authorization: `Bearer ${token}` } });
            toast.success('Settings Saved');

            // Refresh to get 'updated_at' etc
            fetchSettings();
        } catch (e) {
            toast.error('Failed to update settings');
        }
    };

    const handleLocalConfigChange = (provider: LLMProvider, field: keyof LLMConfig, value: any) => {
        setConfigs(prev => {
            const existing = prev.find(c => c.provider === provider);
            if (existing) {
                return prev.map(c => c.provider === provider ? { ...c, [field]: value } : c);
            } else {
                return [...prev, { provider, api_key: '', is_active: 0, model: 'default', [field]: value }];
            }
        });
    };

    const testConnection = async (provider: string) => {
        setStatusMap(prev => ({ ...prev, [provider]: 'checking' }));
        try {
            const res = await axios.post(`${API_URL}/config/llm/test`, { provider }, { headers: { Authorization: `Bearer ${token}` } });
            setStatusMap(prev => ({ ...prev, [provider]: res.data.status }));
            toast.success('Connection Successful');
        } catch (e) {
            setStatusMap(prev => ({ ...prev, [provider]: 'offline' }));
            toast.error('Connection Failed: Check API Key');
        }
    };

    const handleMcpAction = async (name: string, action: string) => {
        try {
            await axios.post(`${API_URL}/config/mcp/${name}/${action}`, {}, { headers: { Authorization: `Bearer ${token}` } });
            toast.success(`Action ${action} sent`);
            fetchMcpServers();
        } catch (e) {
            toast.error('Action failed');
        }
    };

    const handleAddMcpServer = async () => {
        if (!newMcpServer.name || !newMcpServer.command) {
            toast.error('Name and Command are required');
            return;
        }

        try {
            await axios.post(`${API_URL}/config/mcp`, newMcpServer, { headers: { Authorization: `Bearer ${token}` } });
            toast.success('Server added');
            setIsMcpModalOpen(false);
            setNewMcpServer({ name: '', command: '', args: '[]', env_vars: '{}', status: 'stopped', is_enabled: 1 });
            fetchMcpServers();
        } catch (e) {
            toast.error('Failed to add server');
        }
    };

    const handleChangeKey = async () => {
        if (!currentKey || !newKey) {
            toast.error('Please fill in all fields');
            return;
        }
        if (newKey !== confirmKey) {
            toast.error('New keys do not match');
            return;
        }
        if (newKey.length < 6) {
            toast.error('Key must be at least 6 characters');
            return;
        }

        setIsChangingKey(true);
        try {
            await changeKey(currentKey, newKey);
            toast.success('Lock key changed successfully');
            setCurrentKey('');
            setNewKey('');
            setConfirmKey('');
        } catch (e: any) {
            toast.error(e.message || 'Failed to change lock key');
        } finally {
            setIsChangingKey(false);
        }
    };

    if (!isAuthenticated) return null;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link href="/dashboard" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                        <span>Dashboard</span>
                    </Link>
                    <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                        System Configuration
                    </h1>
                </div>
            </header>

            {/* Quick Links */}
            <div className="max-w-7xl mx-auto px-4 py-4">
                <div className="flex gap-4 flex-wrap">
                    <Link
                        href="/settings/prompt-library"
                        className="px-4 py-2 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 hover:from-cyan-500/20 hover:to-blue-500/20 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 border border-cyan-500/30 text-cyan-400"
                    >
                        <BookOpen className="w-4 h-4" />
                        Prompt Library
                    </Link>
                    <Link
                        href="/settings/prompts"
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 border border-slate-700"
                    >
                        <Terminal className="w-4 h-4 text-cyan-400" />
                        Prompt Templates & Logo
                    </Link>
                    <Link
                        href="/settings/token-usage"
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 border border-slate-700"
                    >
                        <BarChart3 className="w-4 h-4 text-amber-400" />
                        Token Usage
                    </Link>
                </div>
            </div>

            <main className="max-w-7xl mx-auto px-4 py-4 grid grid-cols-1 lg:grid-cols-2 gap-8 relative">

                {/* Left Col: LLM Config */}
                <div className="space-y-6" data-tour="settings">
                    <div className="flex items-center gap-3 mb-4">
                        <Cpu className="w-6 h-6 text-cyan-400" />
                        <h2 className="text-xl font-bold">LLM Orchestration</h2>
                    </div>

                    <div className="space-y-4">
                        {['openai', 'gemini', 'anthropic', 'deepseek', 'ollama'].map(p => {
                            const provider = p as LLMProvider;
                            const config = configs.find(c => c.provider === provider) || { provider, api_key: '', is_active: 0, model: 'default' };

                            return (
                                <motion.div key={provider} layout className={`p-5 rounded-xl border transition-colors ${config.is_active ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'}`}>
                                    <div className="flex justify-between items-start mb-4">
                                        <div className="flex items-center gap-4">
                                            <div className="w-12 h-12 rounded-lg bg-slate-800 flex items-center justify-center border border-slate-700">
                                                <Zap className={`w-6 h-6 ${config.is_active ? 'text-cyan-400 fill-cyan-400/20' : 'text-slate-500'}`} />
                                            </div>
                                            <div>
                                                <h3 className="font-bold text-lg capitalize tracking-wide">{provider}</h3>
                                                <div className="flex items-center gap-2 text-xs font-mono">
                                                    <span className={`w-2 h-2 rounded-full ${statusMap[provider] === 'online' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : statusMap[provider] === 'offline' ? 'bg-red-500' : 'bg-slate-600'}`}></span>
                                                    <span className="text-slate-400 uppercase">{statusMap[provider] || 'Unknown'}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => updateConfig(provider, { is_active: config.is_active ? 0 : 1 })}
                                            className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border transition-all ${config.is_active ? 'bg-cyan-500 text-white border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.4)] hover:bg-red-500 hover:border-red-500 hover:shadow-[0_0_15px_rgba(239,68,68,0.4)]' : 'border-slate-700 text-slate-400 hover:border-cyan-500 hover:text-white'}`}
                                            title={config.is_active ? 'Click to deactivate' : 'Click to activate'}
                                        >
                                            {config.is_active ? 'Active Driver' : 'Select Network'}
                                        </button>
                                    </div>

                                    <div className="space-y-4 pt-2">
                                        <div>
                                            <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">API Key</label>
                                            <input
                                                type="password"
                                                value={config.api_key || ''}
                                                onChange={(e) => handleLocalConfigChange(provider, 'api_key', e.target.value)}
                                                onBlur={(e) => updateConfig(provider, { api_key: e.target.value })}
                                                placeholder="sk-..."
                                                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                                            />
                                        </div>

                                        <div>
                                            <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">Model Name</label>
                                            <input
                                                type="text"
                                                value={config.model || ''}
                                                onChange={(e) => handleLocalConfigChange(provider, 'model', e.target.value)}
                                                onBlur={(e) => updateConfig(provider, { model: e.target.value })}
                                                placeholder={
                                                    provider === 'openai' ? 'gpt-4o (or Azure deployment name)' :
                                                        provider === 'anthropic' ? 'claude-3-5-sonnet-20241022' :
                                                            provider === 'gemini' ? 'gemini-1.5-pro' :
                                                                provider === 'deepseek' ? 'deepseek-chat' :
                                                                    provider === 'ollama' ? 'llama3.2' : 'default'
                                                }
                                                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                                            />
                                        </div>

                                        {(provider === 'openai' || provider === 'ollama') && (
                                            <div>
                                                <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">
                                                    {provider === 'openai' ? 'Endpoint URL (Azure / Custom)' : 'Base URL'}
                                                </label>
                                                <input
                                                    value={(() => {
                                                        try { return JSON.parse(config.settings_json || '{}').baseUrl || ''; } catch { return ''; }
                                                    })()}
                                                    onChange={(e) => {
                                                        const newVal = e.target.value;
                                                        const currentSettings = JSON.parse(config.settings_json || '{}');
                                                        handleLocalConfigChange(provider, 'settings_json', JSON.stringify({ ...currentSettings, baseUrl: newVal }));
                                                    }}
                                                    onBlur={(e) => {
                                                        const currentSettings = JSON.parse(config.settings_json || '{}');
                                                        updateConfig(provider, { settings_json: JSON.stringify({ ...currentSettings, baseUrl: e.target.value }) });
                                                    }}
                                                    placeholder={provider === 'openai' ? 'https://your-resource.openai.azure.com/' : 'http://localhost:11434'}
                                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                                                />
                                                {provider === 'openai' && (
                                                    <p className="text-[10px] text-slate-600 mt-1">Leave empty for standard OpenAI. For Azure, enter your resource endpoint.</p>
                                                )}
                                            </div>
                                        )}

                                        {provider === 'openai' && (() => {
                                            try {
                                                const s = JSON.parse(config.settings_json || '{}');
                                                return s.baseUrl && s.baseUrl.includes('azure');
                                            } catch { return false; }
                                        })() && (
                                            <div>
                                                <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">API Version</label>
                                                <input
                                                    value={(() => {
                                                        try { return JSON.parse(config.settings_json || '{}').apiVersion || ''; } catch { return ''; }
                                                    })()}
                                                    onChange={(e) => {
                                                        const newVal = e.target.value;
                                                        const currentSettings = JSON.parse(config.settings_json || '{}');
                                                        handleLocalConfigChange(provider, 'settings_json', JSON.stringify({ ...currentSettings, apiVersion: newVal }));
                                                    }}
                                                    onBlur={(e) => {
                                                        const currentSettings = JSON.parse(config.settings_json || '{}');
                                                        updateConfig(provider, { settings_json: JSON.stringify({ ...currentSettings, apiVersion: e.target.value }) });
                                                    }}
                                                    placeholder="2025-01-01-preview"
                                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                                                />
                                            </div>
                                        )}

                                        <div className="flex justify-between items-center pt-2 border-t border-slate-800/50">
                                            <div className="text-[10px] text-slate-500 font-mono">
                                                {config.updated_at ? 'Synced' : 'Not synced'}
                                            </div>
                                            <button
                                                onClick={async () => {
                                                    // Force save before testing!
                                                    await updateConfig(provider, {
                                                        api_key: config.api_key,
                                                        model: config.model,
                                                        settings_json: config.settings_json
                                                    });
                                                    testConnection(provider);
                                                }}
                                                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-2 border border-slate-700/50"
                                            >
                                                <RefreshCw className={`w-3 h-3 ${statusMap[provider] === 'checking' ? 'animate-spin' : ''}`} />
                                                Save & Test
                                            </button>
                                        </div>
                                    </div>
                                </motion.div>
                            );
                        })}
                    </div>
                </div>

                {/* Right Col: Burp Suite + MCP Manager */}
                <div className="space-y-6">

                    {/* Burp Suite Configuration */}
                    <div>
                        <div className="flex items-center gap-3 mb-4">
                            <Shield className="w-6 h-6 text-orange-400" />
                            <h2 className="text-xl font-bold">Burp Suite Connection</h2>
                            <div className={`ml-auto px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                burpStatus === 'online' ? 'bg-green-500/20 text-green-400' :
                                burpStatus === 'checking' ? 'bg-yellow-500/20 text-yellow-400 animate-pulse' :
                                burpStatus === 'offline' ? 'bg-red-500/20 text-red-400' :
                                'bg-slate-700/50 text-slate-400'
                            }`}>
                                {burpStatus === 'checking' ? 'Testing...' : burpStatus}
                            </div>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
                            <p className="text-xs text-slate-500 mb-4">Configure the PenPard MCP Connect extension address. Ensure Burp Suite is running with the extension loaded.</p>
                            <div className="grid grid-cols-2 gap-3 mb-3">
                                <div>
                                    <label className="text-[10px] uppercase font-bold text-slate-500 mb-1 block">Host / IP</label>
                                    <input
                                        type="text"
                                        value={burpHost}
                                        onChange={e => setBurpHost(e.target.value)}
                                        placeholder="127.0.0.1"
                                        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/50 outline-none transition-all font-mono"
                                    />
                                </div>
                                <div>
                                    <label className="text-[10px] uppercase font-bold text-slate-500 mb-1 block">Port</label>
                                    <input
                                        type="number"
                                        value={burpPort}
                                        onChange={e => setBurpPort(Number(e.target.value))}
                                        placeholder="9876"
                                        className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/50 outline-none transition-all font-mono"
                                    />
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <button
                                    onClick={saveBurpConfig}
                                    disabled={burpSaving}
                                    className="px-4 py-2 bg-orange-500 hover:bg-orange-400 text-black text-xs font-bold rounded-lg transition-all disabled:opacity-50 flex items-center gap-1.5"
                                >
                                    <Save className="w-3 h-3" />
                                    {burpSaving ? 'Saving...' : 'Save & Test'}
                                </button>
                                <button
                                    onClick={testBurpConnection}
                                    disabled={burpStatus === 'checking'}
                                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold rounded-lg border border-slate-700 transition-all disabled:opacity-50 flex items-center gap-1.5"
                                >
                                    <Play className="w-3 h-3" />
                                    Test Connection
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* MCP Server Hub */}
                    <div className="flex items-center gap-3 mb-4">
                        <Server className="w-6 h-6 text-purple-400" />
                        <h2 className="text-xl font-bold">MCP Server Hub</h2>
                    </div>

                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm">
                        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
                            <h3 className="font-semibold text-slate-300 flex items-center gap-2">
                                <Terminal className="w-4 h-4 text-purple-400" />
                                Installed Servers
                            </h3>
                            <button
                                onClick={() => setIsMcpModalOpen(true)}
                                className="p-2 hover:bg-slate-800 rounded-lg text-cyan-400 transition-colors flex items-center gap-1 text-sm font-bold active:scale-95 transform"
                            >
                                <Plus className="w-4 h-4" /> Add Server
                            </button>
                        </div>
                        <div className="divide-y divide-slate-800">
                            {servers.map(server => (
                                <div key={server.name} className="p-4 flex items-center justify-between group hover:bg-white/5 transition-colors">
                                    <div className="flex items-center gap-4">
                                        <div className={`p-2.5 rounded-lg border ${server.status === 'running' ? 'bg-green-500/10 text-green-400 border-green-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                                            <Server className="w-5 h-5" />
                                        </div>
                                        <div>
                                            <div className="font-bold text-sm text-slate-200">{server.name}</div>
                                            <div className="text-xs text-slate-500 font-mono truncate max-w-[200px] mt-0.5">{server.command}</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-1 opacity-60 group-hover:opacity-100 transition-opacity">
                                        {server.status === 'running' ? (
                                            <>
                                                <button onClick={() => handleMcpAction(server.name, 'restart')} title="Restart" className="p-2 hover:bg-yellow-500/20 hover:text-yellow-400 text-slate-400 rounded-lg transition-colors"><RefreshCw className="w-4 h-4" /></button>
                                                <button onClick={() => handleMcpAction(server.name, 'stop')} title="Stop" className="p-2 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors"><Square className="w-4 h-4" /></button>
                                            </>
                                        ) : (
                                            <button onClick={() => handleMcpAction(server.name, 'start')} title="Start" className="p-2 hover:bg-green-500/20 hover:text-green-400 text-slate-400 rounded-lg transition-colors"><Play className="w-4 h-4" /></button>
                                        )}
                                        <button onClick={() => handleMcpAction(server.name, 'delete')} title="Delete" className="p-2 hover:bg-red-900/30 hover:text-red-500 text-slate-500 rounded-lg transition-colors"><Trash2 className="w-4 h-4" /></button>
                                    </div>
                                </div>
                            ))}
                            {servers.length === 0 && (
                                <div className="p-12 text-center text-slate-500 text-sm border-t border-slate-800/50 border-dashed m-2 rounded-lg">
                                    No MCP servers detected. Add one to extend capabilities.
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Console Output */}
                    <div className="bg-black/80 rounded-xl border border-slate-800 overflow-hidden font-mono text-xs shadow-inner">
                        <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 text-slate-400 flex justify-between items-center backdrop-blur">
                            <span className="flex items-center gap-2 font-bold"><Terminal className="w-3 h-3" /> System Stream</span>
                            <div className="flex gap-1.5">
                                <span className="w-2.5 h-2.5 rounded-full bg-red-500/50 border border-red-500/50"></span>
                                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/50 border border-yellow-500/50"></span>
                                <span className="w-2.5 h-2.5 rounded-full bg-green-500/50 border border-green-500/50"></span>
                            </div>
                        </div>
                        <div className="h-64 overflow-y-auto p-4 space-y-1.5 text-slate-300 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                            {mcpLogs.length > 0 ? mcpLogs.map((log, i) => (
                                <div key={i} className="opacity-90 hover:opacity-100 font-mono tracking-tight leading-relaxed break-all">
                                    <span className="text-cyan-500/50 mr-2">$</span>
                                    {log}
                                </div>
                            )) : <div className="text-slate-600 italic px-2 py-1">Waiting for system events...</div>}
                        </div>
                    </div>
                    {/* Report Template Editor */}
                    <div className="mt-8">
                        <div className="flex items-center gap-3 mb-4">
                            <FileText className="w-6 h-6 text-yellow-400" />
                            <h2 className="text-xl font-bold">Report Customization</h2>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 backdrop-blur-sm">
                            <ReportTemplateEditor />
                        </div>
                    </div>
                </div>

                {/* Add MCP Modal */}
                {isMcpModalOpen && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
                        <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 w-full max-w-lg shadow-[0_0_50px_rgba(0,0,0,0.5)] scale-100 animate-in zoom-in-95 duration-200">
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">Install MCP Server</h3>
                                <button onClick={() => setIsMcpModalOpen(false)} className="text-slate-500 hover:text-white"><X className="w-5 h-5" /></button>
                            </div>

                            <div className="space-y-5">
                                <div>
                                    <label className="text-xs uppercase font-bold text-slate-500 block mb-1.5 ml-1">Server Name</label>
                                    <input
                                        className="w-full bg-slate-950/50 border border-slate-800 rounded-lg p-3 text-sm focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all"
                                        placeholder="e.g. filesystem-mcp"
                                        value={newMcpServer.name}
                                        onChange={e => setNewMcpServer({ ...newMcpServer, name: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs uppercase font-bold text-slate-500 block mb-1.5 ml-1">Command (Executable)</label>
                                    <input
                                        className="w-full bg-slate-950/50 border border-slate-800 rounded-lg p-3 text-sm focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all font-mono"
                                        placeholder="npx"
                                        value={newMcpServer.command}
                                        onChange={e => setNewMcpServer({ ...newMcpServer, command: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs uppercase font-bold text-slate-500 block mb-1.5 ml-1">Arguments (JSON Array)</label>
                                    <input
                                        className="w-full bg-slate-950/50 border border-slate-800 rounded-lg p-3 text-sm focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all font-mono"
                                        placeholder='["-y", "@modelcontextprotocol/server-filesystem", "./files"]'
                                        value={newMcpServer.args || ''}
                                        onChange={e => setNewMcpServer({ ...newMcpServer, args: e.target.value })}
                                    />
                                    <p className="text-[10px] text-slate-500 mt-1 ml-1">Must be a valid JSON array of strings.</p>
                                </div>
                                <div>
                                    <label className="text-xs uppercase font-bold text-slate-500 block mb-1.5 ml-1">Environment Vars (JSON Object)</label>
                                    <textarea
                                        className="w-full bg-slate-950/50 border border-slate-800 rounded-lg p-3 text-sm focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-all font-mono h-20"
                                        placeholder='{"API_KEY": "123"}'
                                        value={newMcpServer.env_vars || ''}
                                        onChange={e => setNewMcpServer({ ...newMcpServer, env_vars: e.target.value })}
                                    />
                                </div>
                                <div className="flex justify-end gap-3 mt-8 pt-4 border-t border-slate-800/50">
                                    <button
                                        onClick={() => setIsMcpModalOpen(false)}
                                        className="px-5 py-2.5 rounded-lg text-slate-400 hover:bg-slate-800 text-sm font-medium transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        onClick={handleAddMcpServer}
                                        className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white text-sm font-bold shadow-lg shadow-purple-900/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
                                    >
                                        Install Server
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Lock Key Section */}
                <div className="col-span-full mt-4">
                    <div className="flex items-center gap-3 mb-4">
                        <Lock className="w-6 h-6 text-orange-400" />
                        <h2 className="text-xl font-bold">Lock Key</h2>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 backdrop-blur-sm max-w-lg">
                        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Change Lock Key</h3>
                        <div className="space-y-3">
                            <div>
                                <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">Current Key</label>
                                <input
                                    type="password"
                                    value={currentKey}
                                    onChange={(e) => setCurrentKey(e.target.value)}
                                    placeholder="Enter current lock key"
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none transition-all placeholder:text-slate-700"
                                />
                            </div>
                            <div>
                                <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">New Key</label>
                                <input
                                    type="password"
                                    value={newKey}
                                    onChange={(e) => setNewKey(e.target.value)}
                                    placeholder="At least 6 characters"
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none transition-all placeholder:text-slate-700"
                                />
                            </div>
                            <div>
                                <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">Confirm New Key</label>
                                <input
                                    type="password"
                                    value={confirmKey}
                                    onChange={(e) => setConfirmKey(e.target.value)}
                                    placeholder="Repeat new key"
                                    onKeyDown={(e) => e.key === 'Enter' && handleChangeKey()}
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:border-orange-500 focus:ring-1 focus:ring-orange-500 outline-none transition-all placeholder:text-slate-700"
                                />
                            </div>
                            <button
                                onClick={handleChangeKey}
                                disabled={isChangingKey}
                                className="px-5 py-2 rounded-lg bg-orange-500 hover:bg-orange-400 text-black text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
                            >
                                <Lock className="w-3.5 h-3.5" />
                                {isChangingKey ? 'Changing...' : 'Change Lock Key'}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Keyboard Shortcuts Hint */}
                <div className="col-span-full mt-4" data-tour="shortcuts-hint">
                    <div className="text-center text-slate-500 text-sm py-4 border-t border-slate-800">
                        Press <kbd className="px-2 py-1 bg-slate-800 rounded text-xs font-mono mx-1">Ctrl + /</kbd> to view keyboard shortcuts
                    </div>
                </div>

            </main>
        </div>
    );
}
