/**
 * Mindset Service — TTP library management, deduplication, and Orchestrator formatting
 * Part of the Red Team Report Learning Engine
 */

import { getActiveTTPs, getAllTTPs, upsertMindsetProfile } from '../db/init';
import { llmRuntime } from './llm/LlmRuntime';
import { logger } from '../utils/logger';

// ── Interfaces ──

export interface MindsetTTP {
    id: string;
    source_analysis_id: string;
    source_finding_id: number | null;
    title: string;
    vulnerability_class: string;
    discovery_strategy_json: string | null;
    preconditions_json: string | null;
    entrypoint_hints_json: string | null;
    request_templates_json: string | null;
    payload_templates_json: string | null;
    verification_criteria_json: string | null;
    confidence: number;
    generalization_notes: string | null;
    is_active: number;
}

export interface MindsetProfile {
    total_ttps: number;
    common_vuln_classes: { class: string; count: number }[];
    common_strategies: string[];
    sophistication_score: number; // 1-10
    preferred_sequences: string[];
    updated_at: string;
}

// ── Prompts ──

const DEDUP_PROMPT = `Given two TTPs (Tactic, Technique, Procedure) extracted from pentest reports, decide if they should be merged or kept separate.

TTP A:
{TTP_A}

TTP B:
{TTP_B}

Decision criteria:
- MERGE: Same vulnerability_class AND very similar discovery_strategy AND similar entrypoint patterns
- KEEP_BOTH: Same class but fundamentally different approach or different target patterns
- REPLACE: B is strictly better (higher confidence, more complete templates, better generalization)

Respond ONLY with JSON: {"decision": "merge|keep_both|replace", "reason": "..."}`;

// ── Service ──

class MindsetService {

    /**
     * Get all active TTPs from the library
     */
    getRelevantTTPs(targetUrl?: string): MindsetTTP[] {
        const ttps = getActiveTTPs() as MindsetTTP[];
        // Future: filter by target URL patterns, tech stack, etc.
        return ttps;
    }

    /**
     * Format TTPs as context block for Orchestrator planning prompts
     */
    formatTTPsForPlanning(ttps: MindsetTTP[]): string {
        if (!ttps.length) return 'None loaded.';

        const lines = ttps.slice(0, 15).map((ttp, i) => {
            const strategy = ttp.discovery_strategy_json ? JSON.parse(ttp.discovery_strategy_json) : [];
            const hints = ttp.entrypoint_hints_json ? JSON.parse(ttp.entrypoint_hints_json) : {};
            const criteria = ttp.verification_criteria_json ? JSON.parse(ttp.verification_criteria_json) : [];

            return `[TTP-${i + 1}] id="${ttp.id}" class="${ttp.vulnerability_class}" confidence=${ttp.confidence}
  Title: ${ttp.title}
  Strategy: ${strategy.join(' → ')}
  Look for: endpoints matching ${JSON.stringify(hints.endpoints || [])}, params like ${JSON.stringify(hints.params || [])}
  Verify: ${criteria.slice(0, 2).join('; ')}
  Notes: ${ttp.generalization_notes || 'N/A'}`;
        });

        return lines.join('\n\n');
    }

    /**
     * Rebuild aggregated mindset profile from all TTPs
     */
    async rebuildProfile(): Promise<MindsetProfile> {
        const allTTPs = getAllTTPs() as MindsetTTP[];

        // Count vulnerability classes
        const classCounts = new Map<string, number>();
        const allStrategies = new Set<string>();

        for (const ttp of allTTPs) {
            classCounts.set(ttp.vulnerability_class, (classCounts.get(ttp.vulnerability_class) || 0) + 1);
            if (ttp.discovery_strategy_json) {
                const strategies = JSON.parse(ttp.discovery_strategy_json);
                strategies.forEach((s: string) => allStrategies.add(s));
            }
        }

        const common_vuln_classes = Array.from(classCounts.entries())
            .map(([cls, count]) => ({ class: cls, count }))
            .sort((a, b) => b.count - a.count);

        // Sophistication based on diversity and confidence
        const avgConfidence = allTTPs.length > 0
            ? allTTPs.reduce((sum, t) => sum + t.confidence, 0) / allTTPs.length
            : 0;
        const sophistication_score = Math.min(10, Math.round(
            (common_vuln_classes.length * 0.5) + (avgConfidence * 5) + (allStrategies.size * 0.3)
        ));

        const profile: MindsetProfile = {
            total_ttps: allTTPs.length,
            common_vuln_classes,
            common_strategies: Array.from(allStrategies).slice(0, 20),
            sophistication_score,
            preferred_sequences: this.inferSequences(allTTPs),
            updated_at: new Date().toISOString(),
        };

        upsertMindsetProfile(JSON.stringify(profile));
        return profile;
    }

    /**
     * Infer common test sequences from TTPs
     */
    private inferSequences(ttps: MindsetTTP[]): string[] {
        const sequences = new Map<string, number>();
        for (const ttp of ttps) {
            if (ttp.discovery_strategy_json) {
                const strategy = JSON.parse(ttp.discovery_strategy_json);
                if (strategy.length >= 2) {
                    const seq = strategy.join(' → ');
                    sequences.set(seq, (sequences.get(seq) || 0) + 1);
                }
            }
        }
        return Array.from(sequences.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([seq]) => seq);
    }

    /**
     * Check if a new TTP should be deduplicated against existing ones
     */
    async shouldDedup(existingTTP: MindsetTTP, newTTPJson: string): Promise<'merge' | 'keep_both' | 'replace'> {
        try {
            const existingStr = JSON.stringify({
                title: existingTTP.title,
                vulnerability_class: existingTTP.vulnerability_class,
                discovery_strategy: existingTTP.discovery_strategy_json ? JSON.parse(existingTTP.discovery_strategy_json) : [],
                entrypoint_hints: existingTTP.entrypoint_hints_json ? JSON.parse(existingTTP.entrypoint_hints_json) : {},
                confidence: existingTTP.confidence,
            });

            const prompt = DEDUP_PROMPT
                .replace('{TTP_A}', existingStr)
                .replace('{TTP_B}', newTTPJson);

            const response = await llmRuntime.generate({
                systemPrompt: 'You are a security analysis deduplication engine. Return ONLY valid JSON.',
                userPrompt: prompt,
            }, {
                callSite: 'red_team_ttp_derivation',
                context: 'mindset-ttp-deduplication',
            });

            const parsed = this.parseJSON(response.text);
            if (parsed?.decision && ['merge', 'keep_both', 'replace'].includes(parsed.decision)) {
                return parsed.decision;
            }
        } catch (e: any) {
            logger.error(`TTP dedup failed: ${e.message}`);
        }
        return 'keep_both'; // default: keep both
    }

    private parseJSON(text: string): any {
        try { return JSON.parse(text); } catch { }
        const m = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
        if (m) { try { return JSON.parse(m[1].trim()); } catch { } }
        const f = text.indexOf('{');
        const l = text.lastIndexOf('}');
        if (f !== -1 && l > f) { try { return JSON.parse(text.substring(f, l + 1)); } catch { } }
        return null;
    }
}

export const mindsetService = new MindsetService();
