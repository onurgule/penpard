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
