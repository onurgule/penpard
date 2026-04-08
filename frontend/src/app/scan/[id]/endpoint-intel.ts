export interface EndpointInventoryRecord {
    id: string;
    endpoint: string;
    path: string;
    methods: string[];
    primarySource: string;
    sources: string[];
    confidence: number;
    classification: string;
    likelyAuthRelevant: boolean;
    observedInBurp: boolean;
    exercisedInBrowser: boolean;
    inferredOnly: boolean;
    notes: string[];
    evidence: string[];
    scriptSources: string[];
    domSources: string[];
    authSignals: string[];
    storageKeys: string[];
    observedStatusCodes: number[];
}

export interface EndpointInventorySnapshot {
    scanId: string;
    targetUrl: string;
    targetOrigin: string;
    generatedAt: string;
    summary: string;
    authRelevantCount: number;
    observedInBurpCount: number;
    exercisedInBrowserCount: number;
    jsArtifacts: {
        count: number;
        analyzedCount: number;
        totalBytes: number;
        storedDir?: string;
    };
    classifications: Record<string, number>;
    records: EndpointInventoryRecord[];
}

export interface EndpointDisplayRow {
    id: string;
    title: string;
    methods: string;
    source: string;
    confidenceLabel: string;
    classification: string;
    authBadge: string;
    observedLabel: string;
    evidence: string;
    sourceDetail: string;
    inferredOnly: boolean;
}

export function buildEndpointDisplayRows(snapshot: EndpointInventorySnapshot | null | undefined, limit: number = 30): EndpointDisplayRow[] {
    if (!snapshot?.records?.length) return [];

    return snapshot.records.slice(0, limit).map((record) => ({
        id: record.id,
        title: record.path || record.endpoint,
        methods: record.methods.join(', ') || 'GET',
        source: record.primarySource,
        confidenceLabel: `${Math.round((record.confidence || 0) * 100)}%`,
        classification: record.classification.replace(/_/g, ' '),
        authBadge: record.likelyAuthRelevant ? 'auth-relevant' : 'general',
        observedLabel: [
            record.observedInBurp ? 'Burp' : 'No Burp',
            record.exercisedInBrowser ? 'Browser' : 'Not Browser',
            record.inferredOnly ? 'Inferred' : '',
        ].filter(Boolean).join(' · '),
        evidence: record.evidence[0] || record.notes[0] || record.authSignals[0] || 'No evidence recorded yet',
        sourceDetail: record.scriptSources[0] || record.domSources[0] || record.endpoint,
        inferredOnly: record.inferredOnly,
    }));
}
