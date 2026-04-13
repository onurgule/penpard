import { llmRuntime } from '../../services/llm/LlmRuntime';
import {
    buildInstructionAnalysisUserPrompt,
    INSTRUCTION_ANALYSIS_SYSTEM_PROMPT,
} from '../../prompts/orchestratorPrompts';
import { InstructionAnalysis } from './types';
import { OrchestratorLlmResponseParser } from './OrchestratorLlmResponseParser';

type LogFn = (channel: 'system' | 'error', message: string) => void;

export class OrchestratorInstructionAnalyzer {
    constructor(
        private readonly parser: Pick<OrchestratorLlmResponseParser, 'extractJsonObject'>,
        private readonly log?: LogFn,
    ) {}

    public async analyze(instructions: string, targetUrl: string, scanId: string, userId?: number): Promise<InstructionAnalysis | null> {
        this.log?.('system', 'Analyzing operator instructions with LLM...');

        try {
            const response = await llmRuntime.generate({
                systemPrompt: INSTRUCTION_ANALYSIS_SYSTEM_PROMPT,
                userPrompt: buildInstructionAnalysisUserPrompt(instructions, targetUrl),
            }, {
                scanId,
                userId,
                callSite: 'instruction_analysis',
                context: 'orchestrator-instruction-analysis',
            });

            const parsed = this.parser.extractJsonObject(response.text);
            if (!parsed || typeof parsed.is_focused !== 'boolean') {
                return null;
            }

            return {
                is_focused: parsed.is_focused,
                focused_endpoints: Array.isArray(parsed.focused_endpoints) ? parsed.focused_endpoints : [],
                focused_vulns: Array.isArray(parsed.focused_vulns) ? parsed.focused_vulns : [],
                skip_recon: !!parsed.skip_recon,
                auto_finish: !!parsed.auto_finish,
                summary: typeof parsed.summary === 'string' ? parsed.summary : '',
            };
        } catch (error: any) {
            this.log?.('error', `Instruction analysis failed: ${error.message}`);
            return null;
        }
    }
}
