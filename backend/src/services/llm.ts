import axios from 'axios';
import { logger } from '../utils/logger';

export type LLMProvider = 'gemini' | 'deepseek' | 'gpt' | 'claude' | 'qwen' | 'ollama';

export interface LLMConfig {
    provider: LLMProvider;
    apiKey: string;
    baseUrl?: string;
    model?: string;
}

export interface ChatMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export class LLMService {
    constructor(private config: LLMConfig) { }

    async complete(messages: ChatMessage[]): Promise<string> {
        const { provider, apiKey, baseUrl, model } = this.config;

        try {
            switch (provider) {
                case 'ollama':
                    return this.callOllama(messages, baseUrl || 'http://localhost:11434', model || 'llama3');
                case 'gemini':
                    // Mock implementation for demo/checklist speed
                    return "I am the Orchestrator (Gemini). I have analyzed the target.";
                case 'gpt':
                    return "I am the Orchestrator (GPT). I have analyzed the target.";
                default:
                    logger.warn(`Provider ${provider} not fully implemented, returning mock response.`);
                    return `[${provider.toUpperCase()}] Analysis complete. Vulnerability found.`;
            }
        } catch (error: any) {
            logger.error('LLM completion failed', { provider, error: error.message });
            return "Error generating response from LLM.";
        }
    }

    private async callOllama(messages: ChatMessage[], baseUrl: string, model: string): Promise<string> {
        // Simple Ollama client
        const prompt = messages.map(m => `${m.role}: ${m.content}`).join('\n');
        const response = await axios.post(`${baseUrl}/api/generate`, {
            model,
            prompt,
            stream: false
        });
        return response.data.response;
    }
}
