/**
 * OrchestratorPersistenceSeam
 *
 * Owns the narrow DB/persistence queries that were previously inline
 * in OrchestratorAgent:
 *   - loadVulnerabilitiesForReporting (was: direct db.prepare in phaseReporting)
 *   - loadPromptTemplate (was: direct db.prepare in loadPromptTemplate)
 *
 * This removes the direct `db` import from OrchestratorAgent so the agent
 * no longer reaches into raw SQL for concerns that belong in persistence.
 *
 * Both methods accept injectable implementations for testing.
 */

import { db } from '../../db/init';
import { logger } from '../../utils/logger';

/** Minimal vulnerability record needed by the reporting phase */
export interface VulnerabilityRecord {
    name: string;
    severity: string;
    [key: string]: any;
}

export interface OrchestratorPersistenceSeamDeps {
    loadVulnerabilities?: (scanId: string) => VulnerabilityRecord[];
    loadLegacyPromptTemplate?: () => string | null;
}

export class OrchestratorPersistenceSeam {
    private readonly loadVulns: (scanId: string) => VulnerabilityRecord[];
    private readonly loadLegacyPrompt: () => string | null;

    constructor(deps: OrchestratorPersistenceSeamDeps = {}) {
        this.loadVulns = deps.loadVulnerabilities ?? defaultLoadVulnerabilities;
        this.loadLegacyPrompt = deps.loadLegacyPromptTemplate ?? defaultLoadLegacyPromptTemplate;
    }

    /**
     * Load all vulnerabilities for a scan — used by the reporting phase.
     */
    public loadVulnerabilitiesForReporting(scanId: string): VulnerabilityRecord[] {
        return this.loadVulns(scanId);
    }

    /**
     * Load the legacy custom prompt template from Settings > Prompt Templates.
     * Returns null if no custom template is configured.
     */
    public loadLegacyPromptTemplate(): string | null {
        return this.loadLegacyPrompt();
    }
}

function defaultLoadVulnerabilities(scanId: string): VulnerabilityRecord[] {
    return db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId) as VulnerabilityRecord[];
}

function defaultLoadLegacyPromptTemplate(): string | null {
    try {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('prompts') as any;
        if (row) {
            const prompts = JSON.parse(row.value);
            const webPrompt = prompts.find((p: any) => p.key === 'web_prompt');
            if (webPrompt?.template) return webPrompt.template;
        }
    } catch (e) {
        logger.warn('Could not load custom prompts from settings DB');
    }
    return null;
}
