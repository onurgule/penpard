
import { db } from '../db/init';
import { logger } from '../utils/logger';
import { OpenAI } from 'openai';
import { Anthropic } from '@anthropic-ai/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';
import axios from 'axios';
import { githubIntegration } from './GitHubIntegrationService';
import { GITHUB_COPILOT_PROVIDER, LEGACY_GITHUB_MODELS_PROVIDER } from './github/config';
import { computePromptMetrics } from './llm/LlmTimeoutPolicy';
import {
    LlmCallOptions,
    LlmExecutionError,
    ProviderAttemptDiagnostics,
    ProviderAttemptResult,
    ProviderExecutionOptions,
} from './llm/LlmRuntimeTypes';

const GITHUB_RUNTIME_USER_ID = 1;
const SUPPORTED_LLM_PROVIDERS = ['openai', 'anthropic', 'gemini', 'deepseek', 'ollama', GITHUB_COPILOT_PROVIDER] as const;
const SUPPORTED_LLM_PROVIDER_SET = new Set<string>(SUPPORTED_LLM_PROVIDERS);
type SupportedLlmProvider = (typeof SUPPORTED_LLM_PROVIDERS)[number];

// Prepared statement for token usage logging (created lazily)
let logTokenStmt: any = null;
function getLogTokenStmt() {
    if (!logTokenStmt) {
        logTokenStmt = db.prepare(`
            INSERT INTO token_usage (provider, model, input_tokens, output_tokens, total_tokens, scan_id, report_export_id, context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);
    }
    return logTokenStmt;
}

/**
 * Interface for LLM Configuration DB Row
 */
export interface LLMConfig {
    provider: SupportedLlmProvider;
    api_key: string;
    model: string;
    is_active: number;
    is_online: number;
    settings_json: string; // { baseUrl?: string, maxTokens?: number, temperature?: number }
}

export interface LLMConfigSummary extends Omit<LLMConfig, 'api_key'> {
    api_key: string;
    has_api_key: boolean;
}

export interface GenerationImage {
    data: string;        // base64 encoded image data (no prefix)
    mimeType: string;    // 'image/png' | 'image/jpeg' | 'image/webp' | 'image/gif'
}

export interface GenerationRequest {
    systemPrompt: string;
    userPrompt: string;
    images?: GenerationImage[];  // Optional images for vision-capable models
    temperature?: number;
}

export interface GenerationResponse {
    text: string;
    usage?: {
        input_tokens: number;
        output_tokens: number;
    };
}

export interface GenerationMetadata {
    scanId?: string;
    userId?: number;
    reportExportId?: string;
    context?: string;
    analysisId?: string;
    callSite?: LlmCallOptions['callSite'];
    criticality?: LlmCallOptions['criticality'];
    queueMode?: LlmCallOptions['queueMode'];
    promptMetrics?: LlmCallOptions['promptMetrics'];
}

interface ProviderBackedGenerationResponse extends GenerationResponse {
    diagnostics?: Partial<ProviderAttemptDiagnostics>;
}

function isSupportedProvider(provider: string): provider is SupportedLlmProvider {
    return SUPPORTED_LLM_PROVIDER_SET.has(provider);
}

function assertSupportedProvider(provider: string): asserts provider is SupportedLlmProvider {
    if (!isSupportedProvider(provider)) {
        throw new Error(`Unsupported LLM provider: ${provider}`);
    }
}

class LLMProviderService {
    private normalizeSettingsJson(settingsJson: string | null | undefined): string {
        if (!settingsJson || !settingsJson.trim()) {
            return '{}';
        }

        let parsed: unknown;
        try {
            parsed = JSON.parse(settingsJson);
        } catch {
            throw new Error('LLM settings_json must be valid JSON.');
        }

        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('LLM settings_json must be a JSON object.');
        }

        return JSON.stringify(parsed);
    }

    private normalizeGitHubProviderState(userId: number = GITHUB_RUNTIME_USER_ID): void {
        const githubConfig = db.prepare('SELECT provider, is_active FROM llm_config WHERE provider = ?').get(GITHUB_COPILOT_PROVIDER) as Pick<LLMConfig, 'provider' | 'is_active'> | undefined;
        if (!githubConfig?.is_active) {
            return;
        }

        const status = githubIntegration.getConnectionStatus(userId);
        if (status.connected) {
            return;
        }

        db.prepare(`
            UPDATE llm_config
            SET is_active = 0,
                is_online = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE provider IN (?, ?)
        `).run(GITHUB_COPILOT_PROVIDER, LEGACY_GITHUB_MODELS_PROVIDER);
    }

    /**
     * Get the currently active LLM provider configuration.
     * There should only be one active provider ideally, or the UI selects one.
     * For now, we return the first active one or throw.
     */
    public getActiveConfig(userId: number = GITHUB_RUNTIME_USER_ID): LLMConfig {
        this.normalizeGitHubProviderState(userId);
        const config = this.getAllConfigs(userId).find((entry) => entry.is_active === 1);
        if (!config) {
            throw new Error('No active LLM provider configured.');
        }
        return config;
    }

    public getAllConfigs(userId: number = GITHUB_RUNTIME_USER_ID): LLMConfig[] {
        this.normalizeGitHubProviderState(userId);
        const configs = db.prepare('SELECT * FROM llm_config WHERE provider != ?').all(LEGACY_GITHUB_MODELS_PROVIDER) as Array<LLMConfig & { provider: string }>;
        return configs.filter((config): config is LLMConfig => isSupportedProvider(config.provider));
    }

    public getAllConfigSummaries(userId: number = GITHUB_RUNTIME_USER_ID): LLMConfigSummary[] {
        return this.getAllConfigs(userId).map((config) => ({
            ...config,
            api_key: '',
            has_api_key: !!config.api_key?.trim(),
        }));
    }

    public updateConfig(data: LLMConfig, userId: number = GITHUB_RUNTIME_USER_ID) {
        assertSupportedProvider(data.provider);
        if (data.provider === GITHUB_COPILOT_PROVIDER && data.is_active) {
            const status = githubIntegration.getConnectionStatus(userId);
            if (!status.connected) {
                throw new Error('GitHub is not connected. Connect GitHub before selecting GitHub Copilot.');
            }
            if (!status.providerReady) {
                throw new Error(status.lastDiscoveryError || 'GitHub Copilot is connected, but no selectable Copilot models were discovered yet.');
            }

            const selectedModel = data.model || githubIntegration.getConnectionStatus(userId).selectedModel || '';
            const selection = githubIntegration.isModelSelectable(userId, selectedModel);
            if (!selection.selectable) {
                throw new Error(selection.error || 'The selected GitHub Copilot model is not currently available.');
            }
        }

        const existing = db.prepare('SELECT * FROM llm_config WHERE provider = ?').get(data.provider) as LLMConfig | undefined;
        const normalizedModel = String(
            data.model
            || (data.provider === GITHUB_COPILOT_PROVIDER ? githubIntegration.getConnectionStatus(userId).selectedModel || '' : ''),
        ).trim();
        const normalizedApiKey = data.provider === GITHUB_COPILOT_PROVIDER
            ? ''
            : (data.api_key && data.api_key.trim())
                ? data.api_key
                : (existing?.api_key || '');
        const normalizedData: LLMConfig = {
            ...data,
            api_key: normalizedApiKey,
            model: normalizedModel,
            settings_json: this.normalizeSettingsJson(data.settings_json),
        };

        if (!normalizedData.model) {
            throw new Error(`Model is required for provider '${normalizedData.provider}'.`);
        }

        const persistConfig = db.transaction((config: LLMConfig) => {
            const exists = db.prepare('SELECT 1 FROM llm_config WHERE provider = ?').get(config.provider);
            if (config.is_active) {
                db.prepare('UPDATE llm_config SET is_active = 0 WHERE provider != ?').run(config.provider);
            }

            if (exists) {
                db.prepare(`
                    UPDATE llm_config 
                    SET api_key = ?, model = ?, is_active = ?, settings_json = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                `).run(config.api_key, config.model, config.is_active, config.settings_json, config.provider);
            } else {
                db.prepare(`
                    INSERT INTO llm_config (provider, api_key, model, is_active, settings_json)
                    VALUES (?, ?, ?, ?, ?)
                `).run(config.provider, config.api_key, config.model, config.is_active, config.settings_json);
            }
        });

        persistConfig(normalizedData);
    }

    public async checkConnection(provider: string, userId: number = GITHUB_RUNTIME_USER_ID): Promise<{ success: boolean; error?: string }> {
        if (!isSupportedProvider(provider)) {
            return { success: false, error: `Unsupported provider '${provider}'.` };
        }

        this.normalizeGitHubProviderState(userId);
        const config = db.prepare('SELECT * FROM llm_config WHERE provider = ?').get(provider) as LLMConfig;

        if (!config) {
            return { success: false, error: `No configuration found for provider '${provider}'. Please save API key first.` };
        }

        if (!config.api_key || config.api_key.trim() === '') {
            // github_copilot uses a token from user_integrations, not llm_config.api_key
            if (config.provider === GITHUB_COPILOT_PROVIDER) {
                const status = githubIntegration.getConnectionStatus(userId);
                if (!status.connected) {
                    return { success: false, error: 'GitHub is not connected. Click "Connect GitHub" in settings to link your account.' };
                }
                if (!status.providerReady) {
                    return { success: false, error: status.lastDiscoveryError || 'GitHub Copilot is connected, but no selectable models are ready yet.' };
                }
            } else {
                return { success: false, error: `API key is empty for provider '${provider}'. Please enter a valid API key.` };
            }
        }

        try {
            await this.generateText(config, { systemPrompt: 'You are a test assistant.', userPrompt: 'Say hello in one word.' }, undefined, { userId });
            db.prepare('UPDATE llm_config SET is_online = 1 WHERE provider = ?').run(provider);
            return { success: true };
        } catch (e: any) {
            logger.error(`LLM Connection Check Failed for ${provider}`, { error: e.message || e });
            db.prepare('UPDATE llm_config SET is_online = 0 WHERE provider = ?').run(provider);
            return { success: false, error: e.message || 'Unknown error during API call' };
        }
    }

    /**
     * Primary generation method used by agents.
     */
    public async generate(request: GenerationRequest, context?: string, metadata: GenerationMetadata = {}): Promise<GenerationResponse> {
        const normalizedMetadata = {
            ...metadata,
            context: metadata.context || context,
        };
        const result = await this.executeAttempt(request, normalizedMetadata);
        return {
            text: result.text,
            usage: result.usage,
        };
    }

    public async executeAttempt(
        request: GenerationRequest,
        metadata: GenerationMetadata = {},
        executionOptions: ProviderExecutionOptions = {},
    ): Promise<ProviderAttemptResult> {
        const runtimeUserId = metadata.userId ?? GITHUB_RUNTIME_USER_ID;
        const config = this.getActiveConfig(runtimeUserId);
        const startedAtMs = Date.now();
        const promptMetrics = metadata.promptMetrics || computePromptMetrics(request);
        const result = await this.generateText(
            config,
            request,
            metadata.context,
            metadata,
            executionOptions,
        );

        return {
            text: result.text,
            usage: result.usage,
            provider: config.provider,
            model: config.model,
            executionMs: Date.now() - startedAtMs,
            promptMetrics,
            diagnostics: {
                streamingStarted: false,
                anyEventReceived: true,
                partialOutputReceived: result.text.length > 0,
                assistantMessageReceived: false,
                idleReceived: false,
                finalizationReceived: true,
                firstEventAtMs: Date.now() - startedAtMs,
                firstProgressAtMs: Date.now() - startedAtMs,
                partialOutputAtMs: Date.now() - startedAtMs,
                lastEventAtMs: Date.now() - startedAtMs,
                lastProgressAtMs: Date.now() - startedAtMs,
                idleAtMs: null,
                finalizationAtMs: Date.now() - startedAtMs,
                finalContentLength: result.text.length,
                progressEventCount: result.text.length > 0 ? 1 : 0,
                attemptPhase: 'completed',
                completionSignal: 'provider_response',
                livenessCategory: null,
                warningCategory: null,
                rawProviderError: null,
                ...(result.diagnostics || {}),
            },
        };
    }

    /**
     * Check if the currently active LLM provider supports vision (image input).
     * Returns { supported: boolean, provider: string, model: string }
     */
    public checkVisionSupport(userId: number = GITHUB_RUNTIME_USER_ID): { supported: boolean; provider: string; model: string } {
        try {
            const config = this.getActiveConfig(userId);
            const model = (config.model || '').toLowerCase();
            const provider = config.provider;

            let supported = false;

            switch (provider) {
                case 'openai':
                    // GPT-4o, GPT-4 Turbo, GPT-4V, o1, o3 all support vision
                    supported = model.includes('gpt-4') || model.includes('o1') || model.includes('o3');
                    break;
                case 'anthropic':
                    // Claude 3+ models support vision
                    supported = model.includes('claude-3') || model.includes('claude-4');
                    break;
                case 'gemini':
                    // All Gemini 1.5+ and 2.0 models support vision
                    supported = true;
                    break;
                case 'deepseek':
                    // DeepSeek-VL supports vision, but most DeepSeek models don't
                    supported = model.includes('-vl') || model.includes('vision');
                    break;
                case 'ollama':
                    // Some Ollama models support vision (llava, bakllava, etc.)
                    supported = model.includes('llava') || model.includes('vision') || model.includes('moondream');
                    break;
                case GITHUB_COPILOT_PROVIDER:
                    supported = githubIntegration.getCachedModel(userId, config.model)?.supportsVision
                        || model.includes('vision')
                        || model.includes('gpt-4')
                        || model.includes('gpt-5')
                        || model.includes('o1')
                        || model.includes('o3')
                        || model.includes('gemini');
                    break;
                default:
                    supported = false;
            }

            return { supported, provider, model: config.model };
        } catch {
            return { supported: false, provider: 'none', model: 'none' };
        }
    }

    /**
     * Log token usage to DB for tracking/analytics.
     */
    private logTokenUsage(
        provider: string,
        model: string,
        usage?: { input_tokens: number; output_tokens: number },
        scanId?: string,
        context?: string,
        reportExportId?: string,
    ) {
        if (!usage) return;
        try {
            const total = usage.input_tokens + usage.output_tokens;
            getLogTokenStmt().run(
                provider,
                model,
                usage.input_tokens,
                usage.output_tokens,
                total,
                scanId || null,
                reportExportId || null,
                context || null
            );
        } catch (err: any) {
            logger.warn('Failed to log token usage', { error: err.message });
        }
    }

    private async generateText(
        config: LLMConfig,
        req: GenerationRequest,
        context?: string,
        metadata: GenerationMetadata = {},
        executionOptions: ProviderExecutionOptions = {},
    ): Promise<ProviderBackedGenerationResponse> {
        const settings = JSON.parse(config.settings_json || '{}');
        const temperature = typeof req.temperature === 'number'
            ? req.temperature
            : (settings.temperature ?? 0.7);

        logger.info('llm.provider.generate', {
            provider: config.provider,
            model: config.model,
            scanId: metadata.scanId,
            reportExportId: metadata.reportExportId,
            analysisId: metadata.analysisId,
            context: metadata.context || context,
            callSite: metadata.callSite,
        });

        let result: ProviderBackedGenerationResponse;

        switch (config.provider) {
            case 'openai':
                result = await this.callOpenAI(config, req, temperature);
                break;
            case 'anthropic':
                result = await this.callAnthropic(config, req, temperature);
                break;
            case 'gemini':
                result = await this.callGemini(config, req, temperature);
                break;
            case 'deepseek':
                result = await this.callDeepSeek(config, req, temperature);
                break;
            case 'ollama':
                result = await this.callOllama(config, req, temperature);
                break;
            case GITHUB_COPILOT_PROVIDER:
                result = await this.callGitHubCopilot(config, req, metadata.userId, executionOptions);
                break;
            default:
                throw new Error(`Unsupported provider: ${config.provider}`);
        }

        if (!result.text || !result.text.trim()) {
            throw new LlmExecutionError({
                failureCategory: 'malformed_provider_result',
                message: `${config.provider} (${config.model}) returned an empty response.`,
            });
        }

        // Log token usage after every successful call
        this.logTokenUsage(
            config.provider,
            config.model,
            result.usage,
            metadata.scanId,
            metadata.context || context,
            metadata.reportExportId,
        );

        return result;
    }

    private async callOpenAI(config: LLMConfig, req: GenerationRequest, temp: number) {
        const settings = JSON.parse(config.settings_json || '{}');

        // Support Azure OpenAI: if baseUrl contains 'azure', use Azure configuration
        const isAzure = settings.baseUrl && settings.baseUrl.includes('azure');

        const openai = new OpenAI({
            apiKey: config.api_key,
            ...(isAzure ? {
                baseURL: `${settings.baseUrl.replace(/\/$/, '')}/openai/deployments/${config.model}`,
                defaultQuery: { 'api-version': settings.apiVersion || '2025-01-01-preview' },
                defaultHeaders: { 'api-key': config.api_key },
            } : settings.baseUrl ? {
                baseURL: settings.baseUrl,
            } : {}),
        });

        // Build user message — support vision (images) if provided
        let userContent: any;
        if (req.images && req.images.length > 0) {
            const parts: any[] = [{ type: 'text', text: req.userPrompt }];
            for (const img of req.images) {
                parts.push({
                    type: 'image_url',
                    image_url: { url: `data:${img.mimeType};base64,${img.data}`, detail: 'high' }
                });
            }
            userContent = parts;
        } else {
            userContent = req.userPrompt;
        }

        const completion = await openai.chat.completions.create({
            messages: [
                { role: 'system', content: req.systemPrompt },
                { role: 'user', content: userContent }
            ],
            model: config.model,
            temperature: temp,
        });

        return {
            text: completion.choices[0].message.content || '',
            usage: completion.usage ? {
                input_tokens: completion.usage.prompt_tokens,
                output_tokens: completion.usage.completion_tokens
            } : undefined
        };
    }

    private async callAnthropic(config: LLMConfig, req: GenerationRequest, temp: number) {
        const anthropic = new Anthropic({ apiKey: config.api_key });

        // Build user message — support vision (images) if provided
        let userContent: any;
        if (req.images && req.images.length > 0) {
            const parts: any[] = [];
            for (const img of req.images) {
                parts.push({
                    type: 'image',
                    source: {
                        type: 'base64',
                        media_type: img.mimeType,
                        data: img.data,
                    }
                });
            }
            parts.push({ type: 'text', text: req.userPrompt });
            userContent = parts;
        } else {
            userContent = req.userPrompt;
        }

        const message = await anthropic.messages.create({
            model: config.model,
            max_tokens: 4096,
            temperature: temp,
            system: req.systemPrompt,
            messages: [
                { role: 'user', content: userContent }
            ]
        });

        // Helper to extract text from ContentBlock
        const text = message.content.map(block => {
            return block.type === 'text' ? block.text : '';
        }).join('');

        return {
            text: text,
            usage: {
                input_tokens: message.usage.input_tokens,
                output_tokens: message.usage.output_tokens
            }
        };
    }

    private async callGemini(config: LLMConfig, req: GenerationRequest, temp: number) {
        const genAI = new GoogleGenerativeAI(config.api_key);
        
        // Gemini 2.0 supports systemInstruction parameter
        const model = genAI.getGenerativeModel({ 
            model: config.model,
            systemInstruction: req.systemPrompt,
            generationConfig: {
                temperature: temp
            }
        });

        // Build content parts — support vision (images) if provided
        let contentParts: any;
        if (req.images && req.images.length > 0) {
            const parts: any[] = [];
            for (const img of req.images) {
                parts.push({
                    inlineData: {
                        mimeType: img.mimeType,
                        data: img.data,
                    }
                });
            }
            parts.push({ text: req.userPrompt });
            contentParts = parts;
        } else {
            contentParts = req.userPrompt;
        }

        const result = await model.generateContent(contentParts);
        const response = await result.response;
        
        // Extract token usage from Gemini response if available
        const usageMetadata = response.usageMetadata;
        
        return {
            text: response.text(),
            usage: usageMetadata ? {
                input_tokens: usageMetadata.promptTokenCount || 0,
                output_tokens: usageMetadata.candidatesTokenCount || 0,
            } : undefined
        };
    }

    private async callDeepSeek(config: LLMConfig, req: GenerationRequest, temp: number) {
        // DeepSeek is OpenAI compatible usually
        const openai = new OpenAI({
            apiKey: config.api_key,
            baseURL: 'https://api.deepseek.com/v1' // Verify actual endpoint
        });
        const completion = await openai.chat.completions.create({
            messages: [
                { role: 'system', content: req.systemPrompt },
                { role: 'user', content: req.userPrompt }
            ],
            model: config.model,
            temperature: temp,
        });
        return {
            text: completion.choices[0].message.content || '',
            usage: completion.usage ? {
                input_tokens: completion.usage.prompt_tokens,
                output_tokens: completion.usage.completion_tokens
            } : undefined
        };
    }

    private async callOllama(config: LLMConfig, req: GenerationRequest, temp: number) {
        const settings = JSON.parse(config.settings_json || '{}');
        const baseUrl = settings.baseUrl || 'http://localhost:11434';

        const response = await axios.post(`${baseUrl}/api/generate`, {
            model: config.model,
            prompt: `${req.systemPrompt}\n\n${req.userPrompt}`,
            stream: false,
            options: { temperature: temp }
        });

        // Ollama returns prompt_eval_count and eval_count for token metrics
        const data = response.data;
        return {
            text: data.response,
            usage: (data.prompt_eval_count || data.eval_count) ? {
                input_tokens: data.prompt_eval_count || 0,
                output_tokens: data.eval_count || 0,
            } : undefined
        };
    }

    private async callGitHubCopilot(
        config: LLMConfig,
        req: GenerationRequest,
        userId: number | undefined,
        executionOptions: ProviderExecutionOptions,
    ) {
        return githubIntegration.generateCopilotResponse(userId ?? GITHUB_RUNTIME_USER_ID, config.model, {
            systemPrompt: req.systemPrompt,
            userPrompt: req.userPrompt,
            images: req.images,
        }, executionOptions);
    }
}

export const llmProvider = new LLMProviderService();
