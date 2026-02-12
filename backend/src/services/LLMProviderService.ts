
import { db } from '../db/init';
import { logger } from '../utils/logger';
import { OpenAI } from 'openai';
import { Anthropic } from '@anthropic-ai/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';
import axios from 'axios';

// Prepared statement for token usage logging (created lazily)
let logTokenStmt: any = null;
function getLogTokenStmt() {
    if (!logTokenStmt) {
        logTokenStmt = db.prepare(`
            INSERT INTO token_usage (provider, model, input_tokens, output_tokens, total_tokens, scan_id, context)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
    }
    return logTokenStmt;
}

/**
 * Interface for LLM Configuration DB Row
 */
export interface LLMConfig {
    provider: 'openai' | 'anthropic' | 'gemini' | 'deepseek' | 'ollama' | 'qwen';
    api_key: string;
    model: string;
    is_active: number;
    is_online: number;
    settings_json: string; // { baseUrl?: string, maxTokens?: number, temperature?: number }
}

export interface GenerationImage {
    data: string;        // base64 encoded image data (no prefix)
    mimeType: string;    // 'image/png' | 'image/jpeg' | 'image/webp' | 'image/gif'
}

export interface GenerationRequest {
    systemPrompt: string;
    userPrompt: string;
    images?: GenerationImage[];  // Optional images for vision-capable models
}

export interface GenerationResponse {
    text: string;
    usage?: {
        input_tokens: number;
        output_tokens: number;
    };
}

class LLMProviderService {

    /**
     * Get the currently active LLM provider configuration.
     * There should only be one active provider ideally, or the UI selects one.
     * For now, we return the first active one or throw.
     */
    public getActiveConfig(): LLMConfig {
        const config = db.prepare('SELECT * FROM llm_config WHERE is_active = 1').get() as LLMConfig;
        if (!config) {
            throw new Error('No active LLM provider configured.');
        }
        return config;
    }

    public getAllConfigs(): LLMConfig[] {
        return db.prepare('SELECT * FROM llm_config').all() as LLMConfig[];
    }

    public updateConfig(data: LLMConfig) {
        const exists = db.prepare('SELECT 1 FROM llm_config WHERE provider = ?').get(data.provider);
        if (exists) {
            db.prepare(`
                UPDATE llm_config 
                SET api_key = ?, model = ?, is_active = ?, settings_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider = ?
            `).run(data.api_key, data.model, data.is_active, data.settings_json, data.provider);
        } else {
            db.prepare(`
                INSERT INTO llm_config (provider, api_key, model, is_active, settings_json)
                VALUES (?, ?, ?, ?, ?)
            `).run(data.provider, data.api_key, data.model, data.is_active, data.settings_json);
        }
    }

    public async checkConnection(provider: string): Promise<{ success: boolean; error?: string }> {
        const config = db.prepare('SELECT * FROM llm_config WHERE provider = ?').get(provider) as LLMConfig;

        if (!config) {
            return { success: false, error: `No configuration found for provider '${provider}'. Please save API key first.` };
        }

        if (!config.api_key || config.api_key.trim() === '') {
            return { success: false, error: `API key is empty for provider '${provider}'. Please enter a valid API key.` };
        }

        try {
            await this.generateText(config, { systemPrompt: 'You are a test assistant.', userPrompt: 'Say hello in one word.' });
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
    public async generate(request: GenerationRequest, context?: string): Promise<GenerationResponse> {
        const config = this.getActiveConfig();
        return this.generateText(config, request, context);
    }

    /**
     * Check if the currently active LLM provider supports vision (image input).
     * Returns { supported: boolean, provider: string, model: string }
     */
    public checkVisionSupport(): { supported: boolean; provider: string; model: string } {
        try {
            const config = this.getActiveConfig();
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
    private logTokenUsage(provider: string, model: string, usage?: { input_tokens: number; output_tokens: number }, scanId?: string, context?: string) {
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
                context || null
            );
        } catch (err: any) {
            logger.warn('Failed to log token usage', { error: err.message });
        }
    }

    private async generateText(config: LLMConfig, req: GenerationRequest, context?: string): Promise<GenerationResponse> {
        const settings = JSON.parse(config.settings_json || '{}');
        const temperature = settings.temperature || 0.7;

        logger.info(`Generating text with ${config.provider} (${config.model})`);

        let result: GenerationResponse;

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
            default:
                throw new Error(`Unsupported provider: ${config.provider}`);
        }

        // Log token usage after every successful call
        this.logTokenUsage(config.provider, config.model, result.usage, undefined, context);

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
}

export const llmProvider = new LLMProviderService();
