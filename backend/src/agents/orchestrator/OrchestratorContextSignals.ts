import type { AuthStartupMode } from '../../services/auth';
import { buildOperatorInstructionsReminder } from '../../prompts/orchestratorPrompts';
import type { InstructionAnalysis } from './types';

type LogFn = (channel: 'system', message: string) => void;

export class OrchestratorContextSignals {
    private readonly emittedBudgetSignals = new Set<number>();

    constructor(private readonly log?: LogFn) {}

    public resetBudgetSignals(): void {
        this.emittedBudgetSignals.clear();
    }

    public buildOperatorInstructionsReminder(
        customSystemPrompt?: string,
        analysis?: InstructionAnalysis | null,
    ): string {
        return buildOperatorInstructionsReminder(customSystemPrompt, analysis);
    }

    public buildAuthStartupDirective(planRound: number, authStartupMode: AuthStartupMode = 'no_credentials'): string {
        if (planRound > 1) {
            return 'Auth startup already executed. Reuse its inventory and only expand into generic crawling when auth surfaces, session transport, and created identities are already understood.';
        }

        if (authStartupMode === 'provided_credentials') {
            return 'Round 1 MUST stay auth-surface-first: verify the login entry point, confirm browser-driven sign-in/session carry, inventory auth routes/forms/buttons, and reuse the normalized session state before generic recon.';
        }

        return 'Round 1 MUST stay auth-surface-first: inventory login/register/reset/SSO/onboarding flows, attempt safe self-registration when available, preserve any created identities, and only then widen into generic recon.';
    }

    public buildBudgetPressureReminder(totalActions: number, maxIterations: number): string {
        const remaining = Math.max(0, maxIterations - totalActions);

        if (remaining <= 2) {
            if (!this.emittedBudgetSignals.has(2)) {
                this.emittedBudgetSignals.add(2);
                this.log?.('system', `Action budget critical: only ${remaining} iteration(s) remain. Prioritize decisive validation and conclude cleanly.`);
            }

            return '\n\n[ACTION BUDGET WARNING]\n'
                + `Only ${remaining} iteration(s) remain before the scan must stop. Do not broaden scope. `
                + 'Prioritize the single highest-value validation or finish with a clear answer if the current step is already proven.\n';
        }

        if (remaining <= 5) {
            if (!this.emittedBudgetSignals.has(5)) {
                this.emittedBudgetSignals.add(5);
                this.log?.('system', `Action budget tightening: ${remaining} iteration(s) remain. Focus on the highest-confidence validations.`);
            }

            return '\n\n[ACTION BUDGET WARNING]\n'
                + `Only ${remaining} iteration(s) remain in the global action budget. `
                + 'Narrow to the highest-confidence proof path, reuse existing evidence, and avoid speculative expansion.\n';
        }

        return '';
    }
}
