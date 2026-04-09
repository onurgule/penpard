import { ToolCall } from './types';

type ToolHandler = (toolCall: ToolCall) => Promise<any>;
type ToolGuard = (toolCall: ToolCall) => any | null;
type ToolLogger = (channel: string, message: string) => void;

interface OrchestratorToolDispatcherOptions {
    handlers: Record<string, ToolHandler>;
    guard: ToolGuard;
    log: ToolLogger;
}

export class OrchestratorToolDispatcher {
    constructor(private readonly options: OrchestratorToolDispatcherOptions) {}

    public async execute(toolCall: ToolCall): Promise<any> {
        this.options.log('tool', `Executing: ${toolCall.tool}`);

        try {
            const guardResponse = this.options.guard(toolCall);
            if (guardResponse) {
                return guardResponse;
            }

            const handler = this.options.handlers[toolCall.tool];
            if (!handler) {
                const available = Object.keys(this.options.handlers).sort().join(', ');
                this.options.log('error', `Unknown tool: ${toolCall.tool}`);
                return { error: `Unknown tool: ${toolCall.tool}. Available: ${available}` };
            }

            return await handler(toolCall);
        } catch (error: any) {
            this.options.log('error', `Tool error: ${error.message}`);
            return { error: error.message };
        }
    }
}
