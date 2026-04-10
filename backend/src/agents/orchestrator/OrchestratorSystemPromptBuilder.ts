import { DEFAULT_WEB_PROMPT } from '../../prompts/orchestratorPrompts';
import type { OrchestratorPersistenceSeam } from './OrchestratorPersistenceSeam';

interface SystemPromptSections {
    targetUrl: string;
    accounts: any[];
    customSystemPrompt?: string;
    sessionCookiesBlock?: string;
    startupAuthBlock?: string;
    endpointInventoryBlock?: string;
    sourceContextBlock?: string;
    initialRequestAppendix?: string;
}

export class OrchestratorSystemPromptBuilder {
    constructor(private readonly persistence: Pick<OrchestratorPersistenceSeam, 'loadLegacyPromptTemplate'>) {}

    public async build(sections: SystemPromptSections): Promise<string> {
        const promptTemplate = await this.loadPromptTemplate();
        const accountsJson = JSON.stringify(sections.accounts, null, 2);
        const basePrompt = promptTemplate
            .replace('{TARGET_WEBSITE}', sections.targetUrl)
            .replace('{TARGET_WEBSITE_ACCOUNTS}', accountsJson);

        let systemPrompt = sections.customSystemPrompt
            ? `WARNING: THIS IS THE MOST IMPORTANT - OPERATOR SCAN INSTRUCTIONS (follow these above all else):\n${sections.customSystemPrompt}\n\n---\n\n${basePrompt}`
            : basePrompt;

        systemPrompt += sections.sessionCookiesBlock || '';
        systemPrompt += sections.startupAuthBlock || '';
        systemPrompt += sections.endpointInventoryBlock || '';
        systemPrompt += sections.sourceContextBlock || '';
        systemPrompt += sections.initialRequestAppendix || '';

        return systemPrompt;
    }

    private async loadPromptTemplate(): Promise<string> {
        try {
            const { promptLibrary } = await import('../../services/PromptLibraryService');
            const activePrompt = promptLibrary.getActivePromptTemplate();
            if (activePrompt && activePrompt.template) {
                return activePrompt.template;
            }
        } catch {
            /* fall through to legacy/default prompt resolution */
        }

        return this.persistence.loadLegacyPromptTemplate() || DEFAULT_WEB_PROMPT;
    }
}
