import type { LLMConfig } from '../LLMProviderService';
import { llmProvider } from '../LLMProviderService';
import type { StructuredSecurityTestRequest } from './ScopedScanTypes';

export interface FocusedAnchoringSignal {
    phrase: string;
    weight: number;
}

export interface FocusedAnchoringProfileInput {
    targetUrl: string;
    request: StructuredSecurityTestRequest;
    objectiveTitle?: string;
}

export interface FocusedAnchoringProfile {
    key: string;
    provider: string | null;
    model: string | null;
    buildSignals(input: FocusedAnchoringProfileInput): FocusedAnchoringSignal[];
}

interface FocusedAnchoringProfileDependencies {
    getActiveConfig: typeof llmProvider.getActiveConfig;
}

abstract class BaseFocusedAnchoringProfile implements FocusedAnchoringProfile {
    public readonly provider: string | null;
    public readonly model: string | null;

    public constructor(
        protected readonly activeConfig: LLMConfig | null,
    ) {
        this.provider = activeConfig?.provider || null;
        this.model = activeConfig?.model || null;
    }

    public abstract get key(): string;

    public buildSignals(input: FocusedAnchoringProfileInput): FocusedAnchoringSignal[] {
        const weighted = new Map<string, number>();
        const addSignals = (phrases: string[], baseWeight: number) => {
            for (const phrase of phrases) {
                const normalized = normalizePhrase(phrase);
                if (!normalized) {
                    continue;
                }
                const current = weighted.get(normalized) || 0;
                weighted.set(normalized, Math.max(current, baseWeight));
            }
        };

        addSignals([input.request.description], 1);
        addSignals([input.request.serviceName || '', input.objectiveTitle || ''], 0.9);
        addSignals(input.request.authMechanismHints || [], 0.65);
        addSignals(input.request.testData || [], 0.55);
        addSignals(input.request.testUsers || [], 0.5);
        addSignals([input.request.attachmentSummary || '', input.request.operatorNotes || ''], 0.45);
        addSignals(extractUrlSegments(input.targetUrl), 0.8);
        addSignals(this.expandSignals(input), 0.6);

        return [...weighted.entries()]
            .map(([phrase, weight]) => ({ phrase, weight: Number(weight.toFixed(2)) }))
            .sort((left, right) => right.weight - left.weight || left.phrase.localeCompare(right.phrase))
            .slice(0, 24);
    }

    protected expandSignals(input: FocusedAnchoringProfileInput): string[] {
        return tokenizeText([
            input.request.description,
            input.request.serviceName,
            input.request.operatorNotes,
            input.request.attachmentSummary,
            input.objectiveTitle,
        ].filter(Boolean).join(' '));
    }
}

class GenericFocusedAnchoringProfile extends BaseFocusedAnchoringProfile {
    public get key(): string {
        return this.activeConfig?.provider ? `generic:${this.activeConfig.provider}` : 'generic:fallback';
    }
}

class QwenFocusedAnchoringProfile extends BaseFocusedAnchoringProfile {
    public get key(): string {
        return 'local_qwen';
    }

    protected expandSignals(input: FocusedAnchoringProfileInput): string[] {
        const base = super.expandSignals(input);
        const expanded = new Set<string>(base);
        for (const phrase of [
            input.request.description,
            input.request.serviceName,
            input.objectiveTitle,
        ]) {
            for (const token of splitCompoundTokens(phrase)) {
                expanded.add(token);
            }
        }
        return [...expanded];
    }
}

function normalizePhrase(value: string): string | null {
    const trimmed = String(value || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .slice(0, 120);
    return trimmed || null;
}

function tokenizeText(value: string): string[] {
    const tokens = value
        .toLowerCase()
        .split(/[^a-z0-9/_-]+/i)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length >= 3 && entry.length <= 40);

    const phrases = new Set<string>();
    for (const token of tokens) {
        phrases.add(token);
    }
    for (let index = 0; index < tokens.length - 1; index += 1) {
        const pair = `${tokens[index]} ${tokens[index + 1]}`;
        if (pair.length <= 80) {
            phrases.add(pair);
        }
    }

    return [...phrases];
}

function splitCompoundTokens(value: string | undefined): string[] {
    if (!value) {
        return [];
    }

    return value
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .split(/[^A-Za-z0-9]+/)
        .map((entry) => entry.trim().toLowerCase())
        .filter((entry) => entry.length >= 3 && entry.length <= 40);
}

function extractUrlSegments(targetUrl: string): string[] {
    try {
        const parsed = new URL(targetUrl);
        return parsed.pathname
            .split('/')
            .map((entry) => entry.trim().toLowerCase())
            .filter((entry) => entry.length >= 2 && entry.length <= 60);
    } catch {
        return [];
    }
}

function isQwenModel(model: string | null | undefined): boolean {
    const normalized = String(model || '').trim().toLowerCase();
    return normalized.includes('qwen') || normalized.includes('qwq');
}

export class FocusedAnchoringProfileResolver {
    constructor(
        private readonly deps: FocusedAnchoringProfileDependencies = {
            getActiveConfig: llmProvider.getActiveConfig.bind(llmProvider),
        },
    ) {}

    public resolve(userId?: number): FocusedAnchoringProfile {
        let activeConfig: LLMConfig | null = null;
        try {
            activeConfig = this.deps.getActiveConfig(userId);
        } catch {
            activeConfig = null;
        }

        if (activeConfig?.provider === 'local_llm' && isQwenModel(activeConfig.model)) {
            return new QwenFocusedAnchoringProfile(activeConfig);
        }

        return new GenericFocusedAnchoringProfile(activeConfig);
    }
}

export const focusedAnchoringProfileResolver = new FocusedAnchoringProfileResolver();
