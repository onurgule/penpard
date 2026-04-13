'use client';

import { CheckCircle2, ExternalLink, Github, Loader2, RefreshCw, Save, Unplug } from 'lucide-react';
import type { GitHubAppConfigDraft } from './github-oauth-config';
import {
    GITHUB_COPILOT_PROVIDER,
    type GitHubAppConfigSummary,
    type GitHubConnectionStatus,
    type GitHubCopilotModel,
} from './github-copilot-types';

interface GitHubCopilotProviderCardProps {
    status: GitHubConnectionStatus;
    appConfig: GitHubAppConfigSummary;
    appConfigDraft: GitHubAppConfigDraft;
    appConfigDirty: boolean;
    appConfigSaving: boolean;
    appConfigRequiresSecret: boolean;
    models: GitHubCopilotModel[];
    modelsError: string | null;
    authBusy: boolean;
    authMessage: string | null;
    authSessionId: string | null;
    authorizationUrl: string | null;
    refreshingModels: boolean;
    providerActive: boolean;
    selectedModel: string;
    testStatus?: string;
    onToggleProvider: () => void;
    onDisconnect: () => void;
    onConnect: () => void;
    onSaveAppConfig: () => void;
    onConfirmCallbackRegistration: () => void;
    onChangeAppConfig: (field: keyof GitHubAppConfigDraft, value: string) => void;
    onUseSuggestedCallbackUrl: (value: string) => void;
    onSelectModel: (modelId: string) => void;
    onRefreshModels: () => void;
    onTestConnection: () => void;
    onOpenBrowserAgain: () => void;
    onRefreshAuthSession: () => void;
}

function getSelectableModels(models: GitHubCopilotModel[]): GitHubCopilotModel[] {
    return models.filter((model) => model.isAvailable);
}

function getConfigSourceLabel(source: GitHubAppConfigSummary['source']): string {
    switch (source) {
        case 'ui':
            return 'Saved in PenPard';
        case 'environment':
            return 'Environment fallback';
        default:
            return 'Not configured';
    }
}

export default function GitHubCopilotProviderCard(props: GitHubCopilotProviderCardProps) {
    const selectableModels = getSelectableModels(props.models);
    const configError = props.appConfig.configurationError || props.status.configurationError;
    const recommendedCallbackUrl = props.appConfig.recommendedCallbackUrl?.trim() || '';
    const requiresCallbackRegistrationConfirmation = props.appConfig.requiresCallbackRegistrationConfirmation === true;
    const canApplySuggestedCallbackUrl = recommendedCallbackUrl !== ''
        && recommendedCallbackUrl !== props.appConfigDraft.callbackUrl.trim();
    const confirmRegistrationDisabled = props.appConfigSaving || props.appConfigDirty;
    const saveDisabled = props.appConfigSaving
        || !props.appConfigDirty
        || !props.appConfigDraft.clientId.trim()
        || !props.appConfigDraft.callbackUrl.trim()
        || props.appConfigRequiresSecret;

    return (
        <div
            data-provider={GITHUB_COPILOT_PROVIDER}
            className={`p-5 rounded-xl border transition-colors ${
                props.status.connected
                    ? 'border-green-500/50 bg-green-500/5'
                    : 'border-slate-800 bg-slate-900/50 hover:border-slate-700'
            }`}
        >
            <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center border ${
                        props.status.connected
                            ? 'bg-green-500/10 border-green-500/30'
                            : 'bg-slate-800 border-slate-700'
                    }`}>
                        {props.status.connected && props.status.avatarUrl ? (
                            <img
                                src={props.status.avatarUrl}
                                alt={props.status.username}
                                className="w-12 h-12 rounded-lg"
                            />
                        ) : (
                            <Github className={`w-6 h-6 ${props.status.connected ? 'text-green-400' : 'text-slate-500'}`} />
                        )}
                    </div>
                    <div>
                        <h3 className="font-bold text-lg tracking-wide">Copilot SDK / GitHub Copilot Models</h3>
                        <div className="flex items-center gap-2 text-xs font-mono">
                            {props.status.connected ? (
                                <>
                                    <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                                    <span className="text-green-400">Connected as @{props.status.username}</span>
                                </>
                            ) : (
                                <>
                                    <span className="w-2 h-2 rounded-full bg-slate-600"></span>
                                    <span className="text-slate-400">Not connected</span>
                                </>
                            )}
                        </div>
                    </div>
                </div>

                {props.status.connected ? (
                    <div className="flex items-center gap-2">
                        <button
                            onClick={props.onToggleProvider}
                            disabled={!props.status.providerReady}
                            className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                                props.providerActive
                                    ? 'bg-cyan-500 text-white border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.4)] hover:bg-red-500 hover:border-red-500'
                                    : 'border-slate-700 text-slate-400 hover:border-cyan-500 hover:text-white'
                            }`}
                        >
                            {props.providerActive ? 'Active Provider' : 'Use Provider'}
                        </button>
                        <button
                            onClick={props.onDisconnect}
                            className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                            title="Disconnect GitHub"
                        >
                            <Unplug className="w-4 h-4" />
                        </button>
                    </div>
                ) : (
                    <button
                        onClick={props.onConnect}
                        disabled={!props.status.configured || props.authBusy}
                        className="px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border border-green-500/50 text-green-400 hover:bg-green-500/10 transition-all flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {props.authBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Github className="w-3.5 h-3.5" />}
                        {props.authBusy ? 'Waiting for Browser' : 'Connect GitHub'}
                    </button>
                )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                        <p className="text-xs font-bold uppercase tracking-[0.25em] text-slate-400">GitHub App OAuth</p>
                        <p className="text-xs text-slate-500 mt-1">
                            Save the GitHub App client ID, client secret, and callback URL here. PenPard uses the saved values as the primary OAuth source.
                        </p>
                    </div>
                    <span className="rounded-full border border-slate-700 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-300">
                        {getConfigSourceLabel(props.appConfig.source)}
                    </span>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                    <label className="block text-xs text-slate-400">
                        <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Client ID</span>
                        <input
                            type="text"
                            value={props.appConfigDraft.clientId}
                            onChange={(event) => props.onChangeAppConfig('clientId', event.target.value)}
                            placeholder="Iv23li..."
                            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 outline-none transition-all focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                        />
                    </label>

                    <label className="block text-xs text-slate-400">
                        <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Callback URL</span>
                        <input
                            type="text"
                            value={props.appConfigDraft.callbackUrl}
                            onChange={(event) => props.onChangeAppConfig('callbackUrl', event.target.value)}
                            placeholder="http://127.0.0.1:5050/api/integrations/github/callback"
                            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 outline-none transition-all focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                        />
                    </label>
                </div>

                <label className="block text-xs text-slate-400">
                    <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-slate-500">Client Secret</span>
                    <input
                        type="password"
                        value={props.appConfigDraft.clientSecret}
                        onChange={(event) => props.onChangeAppConfig('clientSecret', event.target.value)}
                        placeholder={props.appConfig.source === 'ui' && props.appConfig.hasClientSecret
                            ? 'Leave blank to keep the saved secret'
                            : 'Paste a GitHub App client secret'}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-mono text-slate-100 outline-none transition-all focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                    />
                </label>

                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-3">
                    <div className="space-y-1 text-[10px] text-slate-500">
                        <p>
                            {props.appConfig.source === 'ui' && props.appConfig.hasClientSecret
                                ? 'Leave the client secret blank to preserve the saved secret.'
                                : 'Saving a UI-managed GitHub App config requires a client secret.'}
                        </p>
                        {configError && <p className="text-orange-400">{configError}</p>}
                        {recommendedCallbackUrl && (
                            <p className="text-cyan-300">
                                Recommended free callback URL: {recommendedCallbackUrl}. GitHub Apps only accept callback URLs that are already registered on the app.
                            </p>
                        )}
                        {requiresCallbackRegistrationConfirmation && (
                            <p className="text-amber-300">
                                GitHub will reject the authorization request until this exact callback URL is registered on the GitHub App. Update the GitHub App callback URLs first, then confirm that change here.
                            </p>
                        )}
                        {props.appConfigRequiresSecret && !configError && (
                            <p className="text-orange-400">Enter a client secret before saving a new UI override.</p>
                        )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                        {canApplySuggestedCallbackUrl && (
                            <button
                                onClick={() => props.onUseSuggestedCallbackUrl(recommendedCallbackUrl)}
                                disabled={props.appConfigSaving}
                                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-bold uppercase tracking-wider text-slate-200 transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                                Use Suggested URL
                            </button>
                        )}
                        {requiresCallbackRegistrationConfirmation && (
                            <button
                                onClick={props.onConfirmCallbackRegistration}
                                disabled={confirmRegistrationDisabled}
                                className="inline-flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-bold uppercase tracking-wider text-amber-200 transition-colors hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                                I've Updated GitHub App Settings
                            </button>
                        )}
                        <button
                            onClick={props.onSaveAppConfig}
                            disabled={saveDisabled}
                            className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-xs font-bold uppercase tracking-wider text-cyan-300 transition-colors hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                            {props.appConfigSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                            {props.appConfigSaving ? 'Saving...' : 'Save App Config'}
                        </button>
                    </div>
                </div>
            </div>

            {props.status.connected ? (
                <div className="space-y-4 pt-2">
                    <div>
                        <label className="text-[10px] uppercase text-slate-500 font-bold tracking-wider mb-1 block">Model</label>
                        {props.models.length > 0 ? (
                            <select
                                value={props.selectedModel}
                                onChange={(event) => props.onSelectModel(event.target.value)}
                                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all"
                            >
                                {props.models.map((model) => (
                                    <option key={model.id} value={model.id} disabled={!model.isAvailable}>
                                        {model.isAvailable ? model.name : `${model.name} (Unavailable)`}
                                    </option>
                                ))}
                            </select>
                        ) : (
                            <input
                                type="text"
                                value={props.selectedModel}
                                onChange={(event) => props.onSelectModel(event.target.value)}
                                placeholder="gpt-5"
                                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all placeholder:text-slate-700"
                            />
                        )}
                        <p className="text-[10px] text-slate-600 mt-1">Models discovered through Copilot SDK. Only enabled Copilot models are selectable.</p>
                        {(props.modelsError || props.status.lastDiscoveryError) && (
                            <p className="text-[10px] text-orange-400 mt-2">{props.modelsError || props.status.lastDiscoveryError}</p>
                        )}
                        {props.status.connected && !props.status.providerReady && !(props.modelsError || props.status.lastDiscoveryError) && (
                            <p className="text-[10px] text-orange-400 mt-2">GitHub is connected, but no enabled Copilot models are ready yet.</p>
                        )}
                    </div>
                    <div className="flex justify-between items-center pt-2 border-t border-slate-800/50 gap-3">
                        <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                            {selectableModels.length || props.status.availableModelCount || 0} selectable models
                        </div>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={props.onRefreshModels}
                                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-200 transition-colors flex items-center gap-2 border border-slate-700/50"
                            >
                                <RefreshCw className={`w-3 h-3 ${props.refreshingModels ? 'animate-spin' : ''}`} />
                                Refresh Models
                            </button>
                            <button
                                onClick={props.onTestConnection}
                                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-2 border border-slate-700/50"
                            >
                                <RefreshCw className={`w-3 h-3 ${props.testStatus === 'checking' ? 'animate-spin' : ''}`} />
                                Test
                            </button>
                        </div>
                    </div>
                </div>
            ) : (
                <div className="space-y-3 mt-2">
                    {props.authBusy ? (
                        <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-4 space-y-3">
                            <div className="flex items-center gap-2 text-sm text-green-300">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                <span>{props.authMessage || 'Approve PenPard in your browser, then return here.'}</span>
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <button
                                    onClick={props.onOpenBrowserAgain}
                                    className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-100 transition-colors flex items-center gap-2 border border-slate-700"
                                >
                                    <ExternalLink className="w-3.5 h-3.5" />
                                    Open Browser Again
                                </button>
                                <button
                                    onClick={props.onRefreshAuthSession}
                                    disabled={!props.authSessionId}
                                    className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-cyan-300 transition-colors flex items-center gap-2 border border-slate-700 disabled:opacity-50"
                                >
                                    <RefreshCw className="w-3.5 h-3.5" />
                                    Refresh Status
                                </button>
                            </div>
                            {props.authorizationUrl && (
                                <p className="text-[10px] text-slate-500 break-all">{props.authorizationUrl}</p>
                            )}
                        </div>
                    ) : (
                        <p className="text-xs text-slate-500">
                            Connect your GitHub account to discover and use Copilot-provided models through the Copilot SDK. PenPard stores the resulting GitHub user token locally and never exposes it to the frontend.
                        </p>
                    )}
                    {!!props.authMessage && !props.authBusy && (
                        <p className="text-xs text-orange-300">{props.authMessage}</p>
                    )}
                </div>
            )}
        </div>
    );
}
