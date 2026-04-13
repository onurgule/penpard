import { getVulnerabilitiesByScan, saveChatMessage } from '../db/init';
import type { GenerationRequest, GenerationResponse } from './LLMProviderService';
import { llmRuntime } from './llm/LlmRuntime';
import type { ScanRuntimeService } from './runtime/ScanRuntimeService';
import { scanRuntimeService } from './runtime/ScanRuntimeService';
import { logger } from '../utils/logger';

export interface ScanChatContext {
    id: string;
    target: string;
    type: string;
    status: string;
    user_id?: number;
    created_at: string;
    completed_at?: string | null;
}

export interface ScanChatResult {
    message: string;
    response?: string;
    scanStatus?: string;
    isLive?: boolean;
}

interface ScanChatServiceOptions {
    runtimeService?: Pick<ScanRuntimeService, 'getActiveAgent'>;
    generate?: (request: GenerationRequest, metadata: { scanId: string; context: string; userId?: number }) => Promise<GenerationResponse>;
    persistChatMessage?: (scanId: string, role: 'human' | 'assistant', content: string) => void;
    loadFindings?: (scanId: string) => any[];
}

export class ScanChatServiceError extends Error {
    constructor(
        message: string,
        public readonly statusCode: number = 500,
        public readonly details?: string,
    ) {
        super(message);
        this.name = 'ScanChatServiceError';
    }
}

export class ScanChatService {
    private readonly runtimeService: Pick<ScanRuntimeService, 'getActiveAgent'>;
    private readonly generate: (request: GenerationRequest, metadata: { scanId: string; context: string; userId?: number }) => Promise<GenerationResponse>;
    private readonly persistChatMessage: (scanId: string, role: 'human' | 'assistant', content: string) => void;
    private readonly loadFindings: (scanId: string) => any[];

    constructor(options: ScanChatServiceOptions = {}) {
        this.runtimeService = options.runtimeService || scanRuntimeService;
        this.generate = options.generate || ((request, metadata) => llmRuntime.generate(request, {
            scanId: metadata.scanId,
            callSite: 'scan_post_chat',
            context: metadata.context,
            ...(typeof metadata.userId === 'number' ? { userId: metadata.userId } : {}),
        }));
        this.persistChatMessage = options.persistChatMessage || saveChatMessage;
        this.loadFindings = options.loadFindings || getVulnerabilitiesByScan;
    }

    public async handleCommand(scan: ScanChatContext, command: string): Promise<ScanChatResult> {
        this.persistChatMessage(scan.id, 'human', command);

        const agent = this.runtimeService.getActiveAgent(scan.id);
        if (agent) {
            await agent.handleUserCommand(command);
            return { message: 'Command sent to agent' };
        }

        return this.answerWithoutActiveRuntime(scan, command);
    }

    private async answerWithoutActiveRuntime(scan: ScanChatContext, command: string): Promise<ScanChatResult> {
        const vulnerabilities = this.loadFindings(scan.id);
        const systemPrompt = buildPostScanChatSystemPrompt(scan, vulnerabilities);

        try {
            const metadata = {
                scanId: scan.id,
                context: 'scan-post-chat',
                ...(typeof scan.user_id === 'number' ? { userId: scan.user_id } : {}),
            };
            const response = await this.generate({
                systemPrompt,
                userPrompt: command,
            }, metadata);

            this.persistChatMessage(scan.id, 'assistant', response.text);

            return {
                message: 'Response from LLM',
                response: response.text,
                scanStatus: scan.status,
                isLive: false,
            };
        } catch (error: any) {
            logger.error('LLM query failed', { scanId: scan.id, error: error.message });
            throw new ScanChatServiceError(
                'LLM query failed. Please check your LLM configuration.',
                500,
                error.message,
            );
        }
    }
}

export function buildPostScanChatSystemPrompt(scan: ScanChatContext, vulnerabilities: any[]): string {
    const vulnerabilitySummary = vulnerabilities.length > 0
        ? vulnerabilities.map((finding) =>
            `- [${finding.severity?.toUpperCase()}] ${finding.name}: ${finding.description}`,
        ).join('\n')
        : 'No vulnerabilities found.';

    return `You are PenPard, an AI security assistant. You have completed a security scan and are now answering follow-up questions.

IMPORTANT: Detect the language of the user's question and ALWAYS respond in the SAME language. If the user writes in Turkish, respond in Turkish. If in English, respond in English.

SCAN DETAILS:
- Target: ${scan.target}
- Type: ${scan.type}
- Status: ${scan.status}
- Created: ${scan.created_at}
- Completed: ${scan.completed_at || 'Not completed'}

FINDINGS (${vulnerabilities.length} total):
${vulnerabilitySummary}

Answer the user's question based on this scan data. Be helpful, specific, and security-focused. Remember to respond in the user's language.`;
}

export const scanChatService = new ScanChatService();
