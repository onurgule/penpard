'use client';

import { RefreshCw, Save, Server } from 'lucide-react';

export interface LocalLlmCardProps {
    host: string;
    port: string;
    model: string;
    isActive: boolean;
    testStatus?: string;
    saving: boolean;
    onChangeHost: (value: string) => void;
    onChangePort: (value: string) => void;
    onChangeModel: (value: string) => void;
    onSave: () => void;
    onSaveAndTest: () => void;
    onToggleActive: () => void;
}

export default function LocalLlmProviderCard(props: LocalLlmCardProps) {
    return (
        <div
            id="local-llm-provider-card"
            data-provider="local_llm"
            className={`p-5 rounded-xl border transition-colors ${
                props.isActive
                    ? 'border-cyan-500/50 bg-cyan-500/5'
                    : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
            }`}
        >
            <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-lg bg-slate-800 flex items-center justify-center border border-slate-700">
                        <Server className={`w-6 h-6 ${props.isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                    </div>
                    <div>
                        <h3 className="font-bold text-lg tracking-wide">Local LLM</h3>
                        <div className="flex items-center gap-2 text-xs font-mono">
                            <span
                                className={`w-2 h-2 rounded-full ${
                                    props.testStatus === 'online'
                                        ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]'
                                        : props.testStatus === 'offline'
                                            ? 'bg-red-500'
                                            : 'bg-slate-600'
                                }`}
                            ></span>
                            <span className="text-slate-400 uppercase">
                                {props.testStatus || 'Unknown'}
                            </span>
                        </div>
                    </div>
                </div>
                <button
                    id="local-llm-activate-btn"
                    onClick={props.onToggleActive}
                    className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border transition-all ${
                        props.isActive
                            ? 'bg-cyan-500 text-white border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.4)] hover:bg-red-500 hover:border-red-500 hover:shadow-[0_0_15px_rgba(239,68,68,0.4)]'
                            : 'border-slate-700 text-slate-400 hover:border-cyan-500 hover:text-white'
                    }`}
                    title={props.isActive ? 'Click to deactivate' : 'Click to activate'}
                >
                    {props.isActive ? 'Active Driver' : 'Select Network'}
                </button>
            </div>

            <p className="text-xs text-slate-500 mb-4">
                Connect to a self-hosted OpenAI-compatible LLM endpoint. No API key required.
            </p>

            <div className="space-y-4 pt-2">
                <div className="grid grid-cols-2 gap-3">
                    <div>
                        <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">
                            Host / IP
                        </label>
                        <input
                            id="local-llm-host"
                            type="text"
                            value={props.host}
                            onChange={(e) => props.onChangeHost(e.target.value)}
                            placeholder="127.0.0.1"
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">
                            Port
                        </label>
                        <input
                            id="local-llm-port"
                            type="number"
                            value={props.port}
                            onChange={(e) => props.onChangePort(e.target.value)}
                            placeholder="8080"
                            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                        />
                    </div>
                </div>

                <div>
                    <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">
                        Model Name
                    </label>
                    <input
                        id="local-llm-model"
                        type="text"
                        value={props.model}
                        onChange={(e) => props.onChangeModel(e.target.value)}
                        placeholder="llama3.2"
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                    />
                    <p className="text-[10px] text-slate-600 mt-1">
                        The model ID your local server uses. Requests go to <code className="text-slate-500">/v1/chat/completions</code>.
                    </p>
                </div>

                <div className="flex justify-between items-center pt-2 border-t border-slate-800/50">
                    <button
                        id="local-llm-save-btn"
                        onClick={props.onSave}
                        disabled={props.saving}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-200 transition-colors flex items-center gap-2 border border-slate-700/50 disabled:opacity-50"
                    >
                        <Save className="w-3 h-3" />
                        {props.saving ? 'Saving...' : 'Save'}
                    </button>
                    <button
                        id="local-llm-save-test-btn"
                        onClick={props.onSaveAndTest}
                        disabled={props.saving}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-2 border border-slate-700/50 disabled:opacity-50"
                    >
                        <RefreshCw className={`w-3 h-3 ${props.testStatus === 'checking' ? 'animate-spin' : ''}`} />
                        Save & Test
                    </button>
                </div>
            </div>
        </div>
    );
}
