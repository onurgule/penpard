import { llmQueue } from '../../services/LLMQueue';
import {
    buildConversationContextBlock,
    buildDirectExecutionUserPrompt,
    EXECUTE_STEP_PROMPT,
    PLAN_PROMPT,
    REPLAN_PROMPT,
} from '../../prompts/orchestratorPrompts';
import { AttackPlan, ConversationMessage, LLMResponse, PlanStep, StepExecutionResult } from './types';
import { OrchestratorLlmResponseParser } from './OrchestratorLlmResponseParser';

type LogFn = (channel: 'system' | 'warn' | 'error', message: string) => void;

interface PlannerDependencies {
    parser: Pick<OrchestratorLlmResponseParser, 'extractJsonObject' | 'parseAgentResponse'>;
    log?: LogFn;
    delay: (ms: number) => Promise<void>;
    handleRateLimitError: (error: any) => void;
}

interface SharedPlannerInput {
    systemPrompt: string;
    conversationHistory: ConversationMessage[];
    rateLimitPauseUntil: Date | null;
}

interface PlanRequest extends SharedPlannerInput {
    planRound: number;
    findingsCount: number;
    endpointsSummary: string;
    previousResults: string;
    authStartupSummary: string;
    authStartupDirective: string;
    operatorInstructionsReminder: string;
    mindsetTtps: string;
}

interface StepRequest extends SharedPlannerInput {
    step: PlanStep;
    previousResults: string[];
    totalActions: number;
    budgetPressureReminder: string;
    operatorInstructionsReminder: string;
}

interface ReplanRequest extends SharedPlannerInput {
    roundResults: StepExecutionResult[];
    findings: any[];
    discoveredEndpoints: string[];
    hypothesisStatus: string;
    coverageStatus: string;
    operatorInstructionsReminder: string;
    planRound: number;
}

interface DirectExecutionTurnRequest extends SharedPlannerInput {
    round: number;
    maxRounds: number;
}

type PlannerDecision =
    | { kind: 'complete' }
    | { kind: 'plan'; plan: AttackPlan };

export class OrchestratorPlanner {
    constructor(private readonly deps: PlannerDependencies) {}

    public async createPlan(input: PlanRequest): Promise<PlannerDecision | null> {
        try {
            if (input.rateLimitPauseUntil && new Date() < input.rateLimitPauseUntil) {
                await this.deps.delay(30_000);
                return null;
            }

            const planPrompt = PLAN_PROMPT
                .replace('{ROUND}', String(input.planRound))
                .replace('{FINDINGS_COUNT}', String(input.findingsCount))
                .replace('{ENDPOINTS_SUMMARY}', input.endpointsSummary)
                .replace('{PREVIOUS_RESULTS}', input.previousResults)
                .replace('{AUTH_STARTUP_SUMMARY}', input.authStartupSummary)
                .replace('{AUTH_STARTUP_DIRECTIVE}', input.authStartupDirective)
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', input.operatorInstructionsReminder)
                .replace('{MINDSET_TTPS}', input.mindsetTtps);

            input.conversationHistory.push({ role: 'user', content: planPrompt });

            const recentMessages = input.conversationHistory.slice(-14);
            const contextBlock = buildConversationContextBlock(recentMessages.slice(0, -1));
            const response = await llmQueue.enqueue({
                systemPrompt: input.systemPrompt,
                userPrompt: `${contextBlock}${planPrompt}\n\nIMPORTANT: Respond with ONLY a valid JSON object. No markdown code fences, no explanation, no text before or after the JSON.`,
            });

            input.conversationHistory.push({ role: 'assistant', content: response.text });

            let parsed = this.deps.parser.extractJsonObject(response.text);
            if (!parsed) {
                this.deps.log?.('warn', `Plan JSON parse failed. LLM response (first 300 chars): ${response.text.substring(0, 300)}`);

                try {
                    this.deps.log?.('system', '🔄 Retrying plan creation — asking LLM to return valid JSON...');
                    const retryResponse = await llmQueue.enqueue({
                        systemPrompt: 'You are a JSON repair assistant. The user will give you text that should be JSON. Extract or fix the JSON and return ONLY a valid JSON object. No markdown, no explanation, no code fences.',
                        userPrompt: `Fix or extract the JSON from this text. Return ONLY valid JSON:\n\n${response.text.substring(0, 2000)}`,
                    });
                    parsed = this.deps.parser.extractJsonObject(retryResponse.text);
                } catch {
                    // Ignore repair errors and let the caller decide on fallback planning.
                }

                if (!parsed) {
                    this.deps.log?.('error', 'Failed to parse plan JSON from LLM (even after retry)');
                    return null;
                }

                this.deps.log?.('system', '✅ JSON repair successful');
            }

            if (parsed.answer && String(parsed.answer).toLowerCase().includes('complete')) {
                return { kind: 'complete' };
            }

            if (!Array.isArray(parsed.plan) || parsed.plan.length === 0) {
                this.deps.log?.('error', 'Invalid plan format from LLM');
                return null;
            }

            const steps: PlanStep[] = parsed.plan.slice(0, 5).map((step: any, index: number) => ({
                step: index + 1,
                objective: step.objective || `Step ${index + 1}`,
                approach: step.approach || '',
                tools: Array.isArray(step.tools) ? step.tools : ['send_http_request'],
                status: 'pending',
            }));

            return {
                kind: 'plan',
                plan: {
                    round: input.planRound,
                    analysis: parsed.analysis || '',
                    steps,
                },
            };
        } catch (error: any) {
            this.deps.log?.('error', `Plan creation failed: ${error.message}`);
            this.deps.handleRateLimitError(error);
            return null;
        }
    }

    public async askForStepExecution(input: StepRequest): Promise<LLMResponse | null> {
        try {
            if (input.rateLimitPauseUntil && new Date() < input.rateLimitPauseUntil) {
                await this.deps.delay(30_000);
                return null;
            }

            const previousResultsBlock = input.previousResults.length > 0
                ? `\n\nPREVIOUS RESULTS FOR THIS STEP:\n${input.previousResults.slice(-3).join('\n')}\n\nContinue testing or move to next action for this step.`
                : '';

            const stepPrompt = EXECUTE_STEP_PROMPT
                .replace('{STEP_NUM}', String(input.step.step))
                .replace('{OBJECTIVE}', input.step.objective)
                .replace('{APPROACH}', input.step.approach)
                .replace('{TOOLS}', input.step.tools.join(', '))
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', input.operatorInstructionsReminder)
                + previousResultsBlock
                + input.budgetPressureReminder;

            input.conversationHistory.push({ role: 'user', content: stepPrompt });

            const recentMessages = input.conversationHistory.slice(-11);
            const contextBlock = buildConversationContextBlock(recentMessages.slice(0, -1));
            const response = await llmQueue.enqueue({
                systemPrompt: input.systemPrompt,
                userPrompt: `${contextBlock}${stepPrompt}\n\nRespond with ONLY a valid JSON object.`,
            });

            input.conversationHistory.push({ role: 'assistant', content: response.text });
            return this.deps.parser.parseAgentResponse(response.text);
        } catch (error: any) {
            this.deps.log?.('error', `Step execution LLM call failed: ${error.message}`);
            this.deps.handleRateLimitError(error);
            return null;
        }
    }

    public async shouldContinueTesting(input: ReplanRequest): Promise<boolean> {
        try {
            const stepSummary = input.roundResults.map((result) =>
                `Step "${result.step.objective}": ${result.step.result} | Tool calls: ${result.toolResults.length} | Findings: ${result.findings.length}`,
            ).join('\n');

            const replanPrompt = REPLAN_PROMPT
                .replace('{STEP_RESULTS}', stepSummary)
                .replace('{ALL_FINDINGS}', input.findings.map((finding) => `[${finding.severity || 'MEDIUM'}] ${finding.name}`).join('\n') || 'None yet')
                .replace('{ENDPOINTS}', input.discoveredEndpoints.join(', ') || 'None discovered')
                .replace('{OPERATOR_INSTRUCTIONS_REMINDER}', input.operatorInstructionsReminder)
                .replace('{HYPOTHESIS_STATUS}', input.hypothesisStatus)
                .replace('{COVERAGE_STATUS}', input.coverageStatus);

            input.conversationHistory.push({ role: 'user', content: replanPrompt });

            const recentMessages = input.conversationHistory.slice(-11);
            const contextBlock = buildConversationContextBlock(recentMessages.slice(0, -1));
            const response = await llmQueue.enqueue({
                systemPrompt: input.systemPrompt,
                userPrompt: `${contextBlock}${replanPrompt}\n\nRespond with ONLY a valid JSON object.`,
            });

            input.conversationHistory.push({ role: 'assistant', content: response.text });

            const parsed = this.deps.parser.extractJsonObject(response.text);
            if (parsed?.answer && String(parsed.answer).toLowerCase().includes('complete')) {
                return false;
            }

            return true;
        } catch (error: any) {
            this.deps.log?.('error', `Replan check failed: ${error.message}`);
            return input.planRound < 3;
        }
    }

    public async executeDirectInstructionTurn(input: DirectExecutionTurnRequest): Promise<LLMResponse | null> {
        try {
            if (input.rateLimitPauseUntil && new Date() < input.rateLimitPauseUntil) {
                await this.deps.delay(30_000);
                return null;
            }

            const recentMessages = input.conversationHistory.slice(-12);
            const contextBlock = buildConversationContextBlock(recentMessages);
            const response = await llmQueue.enqueue({
                systemPrompt: input.systemPrompt,
                userPrompt: `${contextBlock}${buildDirectExecutionUserPrompt(input.round, input.maxRounds)}`,
            });

            input.conversationHistory.push({ role: 'assistant', content: response.text });
            return this.deps.parser.parseAgentResponse(response.text);
        } catch (error: any) {
            this.deps.log?.('error', `Direct execution LLM call failed: ${error.message}`);
            this.deps.handleRateLimitError(error);
            return null;
        }
    }
}
