import { SourceAnalysisMode, SourceAnalysisResult, TestingHint } from './SourceAnalysisMode';
import { extractDependencies, detectFramework, detectTechnologyStack } from './utils/dependency-inventory';
import { mapCVEs } from './utils/cve-mapping';
import { llmProvider } from '../LLMProviderService';
import { logger } from '../../utils/logger';

async function generateTestingHints(
    framework: string,
    stack: string[],
    depsWithCves: { name: string; version: string; cveCount: number }[],
): Promise<TestingHint[]> {
    const riskyDeps = depsWithCves.filter(d => d.cveCount > 0)
        .map(d => `${d.name}@${d.version} (${d.cveCount} CVEs)`)
        .join(', ');

    try {
        const response = await llmProvider.generate({
            systemPrompt: 'You are a penetration testing advisor. Output ONLY valid JSON, no markdown.',
            userPrompt: `Generate testing hints for a ${framework} application.

Stack: ${stack.join(', ')}
${riskyDeps ? `Risky dependencies: ${riskyDeps}` : 'No known CVEs in dependencies.'}

Provide 5-10 concise testing hints based on:
- Known misconfigurations for ${framework}
- Common default routes, admin panels, debug endpoints
- Auth middleware bypass patterns for this stack
- Version-specific known weaknesses
- Dependency-specific attack surface

Return JSON array: [{"category":"framework|auth|config|dependency|endpoint","hint":"..."}]
Return ONLY the JSON array.`,
        }, 'source-analysis-testing-hints');

        const text = response.text.trim();
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]) as TestingHint[];
            return parsed.slice(0, 10).map(h => ({
                category: String(h.category || 'general').slice(0, 50),
                hint: String(h.hint || '').slice(0, 300),
            }));
        }
    } catch (e: any) {
        logger.warn(`Failed to generate testing hints: ${e.message}`);
    }

    return [
        { category: 'framework', hint: `Test ${framework} default endpoints and admin panels.` },
        { category: 'config', hint: 'Check for exposed configuration files and debug modes.' },
    ];
}

export async function analyzeVersionAware(sourcePath: string): Promise<SourceAnalysisResult> {
    logger.info(`Starting Version Aware analysis: ${sourcePath}`);

    const dependencies = await extractDependencies(sourcePath);
    const framework = detectFramework(dependencies);
    const technologyStack = detectTechnologyStack(dependencies);

    logger.info(`Detected framework: ${framework}, stack: ${technologyStack.join(', ')}, ${dependencies.length} dependencies`);

    const cves = await mapCVEs(dependencies);

    const depCveCounts = dependencies.map(d => ({
        name: d.name,
        version: d.currentVersion,
        cveCount: cves.filter(c => c.packageName === d.name).length,
    }));

    const testingHints = await generateTestingHints(framework, technologyStack, depCveCounts);

    logger.info(`Version Aware analysis complete: ${dependencies.length} deps, ${cves.length} CVEs, ${testingHints.length} hints`);

    return {
        mode: SourceAnalysisMode.VERSION_AWARE,
        framework,
        technologyStack,
        dependencies,
        cves,
        testingHints,
        analyzedAt: new Date().toISOString(),
    };
}
