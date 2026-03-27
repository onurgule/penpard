import {
    SourceAnalysisMode, FullSourceAnalysisResult,
} from './SourceAnalysisMode';
import { extractDependencies, detectFramework, detectTechnologyStack } from './utils/dependency-inventory';
import { mapCVEs } from './utils/cve-mapping';
import { extractRoutes } from './utils/route-extractor';
import {
    buildFileTree, summarizeModules, summarizeFunctions,
    analyzeSecurityFlows, generateApplicationSummary, generateArchitectureSummary,
} from './utils/source-summarizer';
import { llmProvider } from '../LLMProviderService';
import { logger } from '../../utils/logger';

async function enrichEndpointDescriptions(
    endpoints: { method: string; path: string; handler: string; authRequired: boolean; description: string; userInputs: string[] }[],
): Promise<typeof endpoints> {
    if (endpoints.length === 0) return endpoints;

    const batch = endpoints.slice(0, 30);
    const endpointList = batch.map(e =>
        `${e.method} ${e.path} -> ${e.handler} (auth: ${e.authRequired}, inputs: ${e.userInputs.join(',')})`
    ).join('\n');

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a code analysis assistant. Output ONLY valid JSON, no markdown.',
            userPrompt: `Add a short description (1 sentence) to each endpoint based on its path, handler, and inputs.

Endpoints:
${endpointList.slice(0, 4000)}

Return JSON array with same order: [{"index":0,"description":"..."}]
Return ONLY the JSON array.`,
        }, 'source-analysis-endpoint-descriptions');

        const text = response.text.trim();
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]) as Array<{ index: number; description: string }>;
            for (const item of parsed) {
                if (item.index >= 0 && item.index < batch.length && item.description) {
                    batch[item.index].description = String(item.description).slice(0, 200);
                }
            }
        }
    } catch (e: any) {
        logger.warn(`Failed to enrich endpoint descriptions: ${e.message}`);
    }

    return endpoints;
}

async function generateTestingHintsDeep(
    framework: string,
    stack: string[],
    endpoints: { method: string; path: string; authRequired: boolean; userInputs: string[] }[],
    securityFlows: { category: string; description: string; riskLevel: string }[],
) {
    const endpointSummary = endpoints.slice(0, 20).map(e =>
        `${e.method} ${e.path} (auth: ${e.authRequired}, inputs: ${e.userInputs.join(',')})`
    ).join('\n');

    const flowSummary = securityFlows.map(f =>
        `${f.category} [${f.riskLevel}]: ${f.description}`
    ).join('\n');

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a penetration testing advisor. Output ONLY valid JSON, no markdown.',
            userPrompt: `Generate security testing hints for a ${framework} application (${stack.join(', ')}).

Key endpoints:
${endpointSummary.slice(0, 2000)}

Security flows:
${flowSummary.slice(0, 2000)}

Provide 8-15 precise, actionable testing hints based on the actual code structure. Focus on:
- Specific endpoint vulnerabilities (IDOR, auth bypass, injection points)
- Security flow weaknesses
- Missing checks identified from code analysis
- High-value targets for testing

Return JSON array: [{"category":"endpoint|auth|flow|injection|config","hint":"..."}]
Return ONLY the JSON array.`,
        }, 'source-analysis-deep-hints');

        const text = response.text.trim();
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[0]).slice(0, 15).map((h: any) => ({
                category: String(h.category || 'general').slice(0, 50),
                hint: String(h.hint || '').slice(0, 300),
            }));
        }
    } catch (e: any) {
        logger.warn(`Failed to generate deep testing hints: ${e.message}`);
    }

    return [{ category: 'general', hint: `Perform thorough testing of all ${endpoints.length} endpoints.` }];
}

export async function analyzeFullSource(sourcePath: string): Promise<FullSourceAnalysisResult> {
    logger.info(`Starting Full Source Aware analysis: ${sourcePath}`);

    // Stage 1: dependency analysis (same as Version Aware)
    logger.info('Stage 1/6: Extracting dependencies...');
    const dependencies = await extractDependencies(sourcePath);
    const framework = detectFramework(dependencies);
    const technologyStack = detectTechnologyStack(dependencies);

    logger.info('Stage 2/6: Mapping CVEs...');
    const cves = await mapCVEs(dependencies);

    // Stage 3: structural map
    logger.info('Stage 3/6: Building file tree and module summaries...');
    const files = buildFileTree(sourcePath);
    const modules = await summarizeModules(files, sourcePath);

    // Stage 4: function analysis
    logger.info('Stage 4/6: Analyzing functions...');
    const functions = await summarizeFunctions(files);

    // Stage 5: route extraction + enrichment
    logger.info('Stage 5/6: Extracting routes and analyzing security flows...');
    const rawEndpoints = await extractRoutes(sourcePath);
    const endpoints = await enrichEndpointDescriptions(rawEndpoints);

    // Stage 6: security flow synthesis
    const securityFlows = await analyzeSecurityFlows(files, modules, functions);

    // Generate summaries
    logger.info('Stage 6/6: Generating summaries...');
    const [applicationSummary, architectureSummary, testingHints] = await Promise.all([
        generateApplicationSummary(files, modules, framework, technologyStack),
        generateArchitectureSummary(modules, functions, framework),
        generateTestingHintsDeep(framework, technologyStack, endpoints, securityFlows),
    ]);

    logger.info(`Full Source Aware analysis complete: ${dependencies.length} deps, ${cves.length} CVEs, ${modules.length} modules, ${functions.length} functions, ${endpoints.length} endpoints, ${securityFlows.length} security flows`);

    return {
        mode: SourceAnalysisMode.FULL_SOURCE_AWARE,
        framework,
        technologyStack,
        dependencies,
        cves,
        testingHints,
        analyzedAt: new Date().toISOString(),
        applicationSummary,
        architectureSummary,
        modules,
        functions,
        endpoints,
        securityFlows,
    };
}
