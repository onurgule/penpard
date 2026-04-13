import fs from 'fs';
import { SourceAnalysisMode, SourceAnalysisResult } from './SourceAnalysisMode';
import { analyzeVersionAware } from './VersionAwareAnalysisService';
import { analyzeFullSource } from './FullSourceAnalysisService';
import { saveSourceAnalysisResult, getSourceAnalysisResult } from '../../db/init';
import { logger } from '../../utils/logger';

export async function analyzeSource(
    scanId: string,
    sourcePath: string,
    mode: SourceAnalysisMode,
    userId?: number,
): Promise<SourceAnalysisResult> {
    if (!fs.existsSync(sourcePath)) {
        throw new Error(`Source path does not exist: ${sourcePath}`);
    }

    const stat = fs.statSync(sourcePath);
    if (!stat.isDirectory()) {
        throw new Error(`Source path is not a directory: ${sourcePath}`);
    }

    // Check for cached result
    const cached = getSourceAnalysisResult(scanId);
    if (cached && cached.mode === mode) {
        logger.info(`Using cached source analysis result for scan ${scanId}`);
        return cached;
    }

    logger.info(`Running source analysis: mode=${mode}, path=${sourcePath}`);

    let result: SourceAnalysisResult;

    switch (mode) {
        case SourceAnalysisMode.VERSION_AWARE:
            result = await analyzeVersionAware(sourcePath, userId);
            break;
        case SourceAnalysisMode.FULL_SOURCE_AWARE:
            result = await analyzeFullSource(sourcePath, userId);
            break;
        default:
            throw new Error(`Unknown source analysis mode: ${mode}`);
    }

    // Cache result
    try {
        saveSourceAnalysisResult(scanId, JSON.stringify(result));
        logger.info(`Cached source analysis result for scan ${scanId}`);
    } catch (e: any) {
        logger.warn(`Failed to cache source analysis result: ${e.message}`);
    }

    return result;
}

export function buildAgentContextBlock(result: SourceAnalysisResult): string {
    const lines: string[] = [];

    if (result.mode === SourceAnalysisMode.VERSION_AWARE) {
        lines.push('═══════════════════════════════════════════════════════════════');
        lines.push('  SOURCE INTELLIGENCE (Version Aware)');
        lines.push('═══════════════════════════════════════════════════════════════');
        lines.push('');
        lines.push(`Framework: ${result.framework}`);
        lines.push(`Stack: ${result.technologyStack.join(', ')}`);
        lines.push('');

        if (result.dependencies.length > 0) {
            lines.push('Key Dependencies:');
            for (const dep of result.dependencies.slice(0, 30)) {
                const latest = dep.latestVersion ? ` (latest: ${dep.latestVersion})` : '';
                lines.push(`  - ${dep.name}@${dep.currentVersion}${latest}`);
            }
            if (result.dependencies.length > 30) {
                lines.push(`  ... and ${result.dependencies.length - 30} more`);
            }
            lines.push('');
        }

        if (result.cves.length > 0) {
            lines.push('Known CVEs:');
            for (const cve of result.cves.slice(0, 20)) {
                const fixed = cve.fixedVersion ? ` — fix: ${cve.fixedVersion}` : '';
                lines.push(`  - ${cve.id} [${cve.severity}] ${cve.packageName}: ${cve.description.slice(0, 100)}${fixed}`);
            }
            if (result.cves.length > 20) {
                lines.push(`  ... and ${result.cves.length - 20} more CVEs`);
            }
            lines.push('');
        }

        if (result.testingHints.length > 0) {
            lines.push('Testing Hints:');
            for (const hint of result.testingHints) {
                lines.push(`  [${hint.category}] ${hint.hint}`);
            }
            lines.push('');
        }

        lines.push('Mode: Version Aware — use dependency/version/CVE context to guide targeted testing.');
        lines.push('Do NOT attempt deep code analysis. Focus on smart, version-informed testing.');
    } else {
        const full = result as any;
        lines.push('═══════════════════════════════════════════════════════════════');
        lines.push('  SOURCE INTELLIGENCE (Full Source Aware)');
        lines.push('═══════════════════════════════════════════════════════════════');
        lines.push('');
        lines.push(`Framework: ${result.framework}`);
        lines.push(`Stack: ${result.technologyStack.join(', ')}`);
        lines.push('');

        if (full.applicationSummary) {
            lines.push(`Application: ${full.applicationSummary}`);
            lines.push('');
        }

        if (full.architectureSummary) {
            lines.push(`Architecture: ${full.architectureSummary}`);
            lines.push('');
        }

        if (full.modules?.length > 0) {
            lines.push('Modules:');
            for (const mod of full.modules.slice(0, 15)) {
                lines.push(`  - ${mod.name}: ${mod.purpose}`);
            }
            lines.push('');
        }

        if (full.endpoints?.length > 0) {
            lines.push('Route Map:');
            for (const ep of full.endpoints.slice(0, 30)) {
                const auth = ep.authRequired ? ' [AUTH]' : '';
                const inputs = ep.userInputs?.length > 0 ? ` (inputs: ${ep.userInputs.join(', ')})` : '';
                lines.push(`  ${ep.method} ${ep.path}${auth}${inputs} — ${ep.description || ep.handler}`);
            }
            if (full.endpoints.length > 30) {
                lines.push(`  ... and ${full.endpoints.length - 30} more endpoints`);
            }
            lines.push('');
        }

        const secFunctions = (full.functions || []).filter((f: any) => f.securityRelevant);
        if (secFunctions.length > 0) {
            lines.push('Security-Relevant Functions:');
            for (const fn of secFunctions.slice(0, 20)) {
                lines.push(`  - ${fn.name} (${fn.filePath}): ${fn.purpose}`);
            }
            lines.push('');
        }

        if (full.securityFlows?.length > 0) {
            lines.push('Security Flows:');
            for (const flow of full.securityFlows) {
                lines.push(`  [${flow.riskLevel.toUpperCase()}] ${flow.category}: ${flow.description}`);
                if (flow.components?.length > 0) {
                    lines.push(`    Components: ${flow.components.join(', ')}`);
                }
            }
            lines.push('');
        }

        if (result.cves.length > 0) {
            lines.push('Known CVEs:');
            for (const cve of result.cves.slice(0, 20)) {
                const fixed = cve.fixedVersion ? ` — fix: ${cve.fixedVersion}` : '';
                lines.push(`  - ${cve.id} [${cve.severity}] ${cve.packageName}: ${cve.description.slice(0, 100)}${fixed}`);
            }
            if (result.cves.length > 20) {
                lines.push(`  ... and ${result.cves.length - 20} more CVEs`);
            }
            lines.push('');
        }

        if (result.testingHints.length > 0) {
            lines.push('Testing Hints:');
            for (const hint of result.testingHints) {
                lines.push(`  [${hint.category}] ${hint.hint}`);
            }
            lines.push('');
        }

        lines.push('Mode: Full Source Aware — use deep code understanding to drive precise, source-informed testing.');
        lines.push('Prioritize high-risk endpoints, test auth flows, and validate findings against implementation reality.');
    }

    return '\n\n' + lines.join('\n') + '\n';
}
