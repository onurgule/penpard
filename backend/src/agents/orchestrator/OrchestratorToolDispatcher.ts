import type { ScopedMissionGuardSeverity } from '../../services/runtime/ScopedMissionPolicy';
import { ToolCall } from './types';

type ToolHandler = (toolCall: ToolCall) => Promise<any>;
export interface ToolGuardResult {
    response: any;
    severity: ScopedMissionGuardSeverity;
    advisoryReason?: string;
}
type ToolGuard = (toolCall: ToolCall) => ToolGuardResult | null;
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
            const guardResult = this.options.guard(toolCall);
            if (guardResult && guardResult.severity === 'hard') {
                return guardResult.response;
            }

            const handler = this.options.handlers[toolCall.tool];
            if (!handler) {
                const available = Object.keys(this.options.handlers).sort().join(', ');
                this.options.log('error', `Unknown tool: ${toolCall.tool}`);
                return { error: `Unknown tool: ${toolCall.tool}. Available: ${available}` };
            }

            if (guardResult && guardResult.severity === 'advisory') {
                const reason = guardResult.advisoryReason || 'Scoped boundary advisory';
                this.options.log('tool', `Advisory boundary (continuing through Burp): ${reason}`);
                if (toolCall.args && typeof toolCall.args === 'object') {
                    (toolCall.args as Record<string, any>).__advisoryReason = reason;
                }
                const result = await handler(toolCall);
                if (toolCall.args && typeof toolCall.args === 'object') {
                    delete (toolCall.args as Record<string, any>).__advisoryReason;
                }
                return wrapAdvisoryResult(result, reason);
            }

            return await handler(toolCall);
        } catch (error: any) {
            this.options.log('error', `Tool error: ${error.message}`);
            return { error: error.message };
        }
    }
}

function wrapAdvisoryResult(result: any, reason: string): any {
    if (result === null || result === undefined) {
        return { boundaryAdvisory: true, boundaryReason: reason };
    }
    if (typeof result !== 'object') {
        return { value: result, boundaryAdvisory: true, boundaryReason: reason };
    }
    return { ...result, boundaryAdvisory: true, boundaryReason: reason };
}
