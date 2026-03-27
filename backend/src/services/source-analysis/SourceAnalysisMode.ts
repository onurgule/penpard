export enum SourceAnalysisMode {
    VERSION_AWARE = 'version_aware',
    FULL_SOURCE_AWARE = 'full_source_aware',
}

export interface DependencyInfo {
    name: string;
    currentVersion: string;
    latestVersion?: string;
    ecosystem: string;
}

export interface CVEInfo {
    id: string;
    packageName: string;
    severity: string;
    affectedRange: string;
    fixedVersion?: string;
    description: string;
    confidence: 'confirmed' | 'partial';
}

export interface TestingHint {
    category: string;
    hint: string;
}

export interface SourceAnalysisResult {
    mode: SourceAnalysisMode;
    framework: string;
    technologyStack: string[];
    dependencies: DependencyInfo[];
    cves: CVEInfo[];
    testingHints: TestingHint[];
    analyzedAt: string;
}

export interface ModuleSummary {
    name: string;
    path: string;
    purpose: string;
}

export interface FunctionSummary {
    name: string;
    filePath: string;
    purpose: string;
    securityRelevant: boolean;
}

export interface EndpointSummary {
    method: string;
    path: string;
    handler: string;
    authRequired: boolean;
    description: string;
    userInputs: string[];
}

export interface SecurityFlow {
    category: string;
    description: string;
    components: string[];
    riskLevel: string;
}

export interface FullSourceAnalysisResult extends SourceAnalysisResult {
    applicationSummary: string;
    architectureSummary: string;
    modules: ModuleSummary[];
    functions: FunctionSummary[];
    endpoints: EndpointSummary[];
    securityFlows: SecurityFlow[];
}

export function isFullSourceResult(result: SourceAnalysisResult): result is FullSourceAnalysisResult {
    return result.mode === SourceAnalysisMode.FULL_SOURCE_AWARE;
}
