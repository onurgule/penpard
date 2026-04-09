export interface ToolCall {
    tool: string;
    args: Record<string, any>;
}

export interface RequestExecutionExchange {
    action?: ToolCall;
    result?: any;
    rawRequest?: string;
    rawResponse?: string;
}

export type AgentPhase =
    | 'planning'
    | 'executing'
    | 'replanning'
    | 'reporting'
    | 'completed'
    | 'failed'
    | 'stopped';

export interface ConversationMessage {
    role: string;
    content: string;
}

export interface PlanStep {
    step: number;
    objective: string;
    approach: string;
    tools: string[];
    status: 'pending' | 'executing' | 'completed' | 'skipped';
    result?: string;
}

export interface AttackPlan {
    round: number;
    analysis: string;
    steps: PlanStep[];
}

export interface AgentReflection {
    evaluationPreviousGoal?: string;
    memory?: string;
    nextGoal?: string;
}

export interface LLMResponse {
    thought: string;
    reflection?: AgentReflection;
    action?: ToolCall;
    actions?: ToolCall[];
    answer?: string;
    finding?: any;
    findings?: any[];
}

export interface InstructionAnalysis {
    is_focused: boolean;
    focused_endpoints: string[];
    focused_vulns: string[];
    skip_recon: boolean;
    auto_finish: boolean;
    summary: string;
}

export interface StepExecutionResult {
    step: PlanStep;
    findings: any[];
    toolResults: string[];
}
