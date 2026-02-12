/**
 * LLM Queue - Queues LLM calls and applies rate limiting
 * Prevents parallel agents from making simultaneous LLM requests
 */

import { llmProvider, GenerationRequest, GenerationResponse } from './LLMProviderService';
import { logger } from '../utils/logger';

interface QueuedRequest {
    request: GenerationRequest;
    resolve: (value: GenerationResponse) => void;
    reject: (error: any) => void;
    timestamp: number;
}

class LLMQueue {
    private queue: QueuedRequest[] = [];
    private processing: boolean = false;
    private readonly maxConcurrent: number = 1; // Max 1 concurrent LLM call (for Gemini rate limits)
    private readonly requestDelay: number = 2000; // 2 second delay between requests (for Gemini rate limits)
    private activeRequests: number = 0;
    private readonly timeout: number = 30000; // 30 second timeout

    async enqueue(request: GenerationRequest): Promise<GenerationResponse> {
        return new Promise((resolve, reject) => {
            this.queue.push({
                request,
                resolve,
                reject,
                timestamp: Date.now()
            });

            this.processQueue();
        });
    }

    private async processQueue(): Promise<void> {
        if (this.processing || this.activeRequests >= this.maxConcurrent) {
            return;
        }

        if (this.queue.length === 0) {
            return;
        }

        this.processing = true;

        while (this.queue.length > 0 && this.activeRequests < this.maxConcurrent) {
            const item = this.queue.shift();
            if (!item) break;

            this.activeRequests++;
            this.processing = false;

            // Process in background
            this.processRequest(item).finally(() => {
                this.activeRequests--;
                // Wait a bit before next request
                setTimeout(() => {
                    this.processQueue();
                }, this.requestDelay);
            });

            // Continue processing if we have capacity
            if (this.activeRequests < this.maxConcurrent) {
                this.processing = true;
            }
        }

        this.processing = false;
    }

    private async processRequest(item: QueuedRequest): Promise<void> {
        let timeoutId: NodeJS.Timeout | null = null;
        
        const timeoutPromise = new Promise<never>((_, reject) => {
            timeoutId = setTimeout(() => {
                reject(new Error('LLM request timeout after 30 seconds'));
            }, this.timeout);
        });

        try {
            const response = await Promise.race([
                llmProvider.generate(item.request),
                timeoutPromise
            ]);
            
            if (timeoutId) clearTimeout(timeoutId);
            item.resolve(response);
        } catch (error: any) {
            if (timeoutId) clearTimeout(timeoutId);
            
            // Retry once if it's a rate limit or timeout error
            if (error.message?.includes('rate limit') || 
                error.message?.includes('timeout') ||
                error.status === 429 ||
                error.code === 'ECONNRESET') {
                
                logger.warn('LLM request failed, retrying once...', { error: error.message });
                
                // Wait a bit before retry
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                try {
                    const retryTimeoutPromise = new Promise<never>((_, reject) => {
                        setTimeout(() => reject(new Error('LLM retry timeout')), this.timeout);
                    });
                    
                    const retryResponse = await Promise.race([
                        llmProvider.generate(item.request),
                        retryTimeoutPromise
                    ]);
                    
                    item.resolve(retryResponse);
                    return;
                } catch (retryError: any) {
                    logger.error('LLM retry also failed', { error: retryError.message });
                    item.reject(retryError);
                    return;
                }
            }
            
            item.reject(error);
        }
    }

    getQueueLength(): number {
        return this.queue.length;
    }

    getActiveRequests(): number {
        return this.activeRequests;
    }
}

export const llmQueue = new LLMQueue();
