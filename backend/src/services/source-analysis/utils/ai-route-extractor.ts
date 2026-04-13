import fs from 'fs';
import path from 'path';
import { EndpointSummary } from '../SourceAnalysisMode';
import { llmRuntime } from '../../llm/LlmRuntime';
import { logger } from '../../../utils/logger';

const SOURCE_EXTENSIONS = new Set([
    '.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs',
    '.py', '.rb', '.java', '.kt', '.go', '.rs',
    '.php', '.cs',
]);

const ROUTE_INDICATOR_PATTERNS = [
    // JS/TS
    /app\.|router\.|fastify\.|express\.|@(Get|Post|Put|Delete|Patch|Controller)\b/i,
    // Python
    /@app\.|@router\.|@blueprint\.|urlpatterns|path\s*\(|re_path/i,
    // Java/Spring
    /@(Get|Post|Put|Delete|Patch|Request)Mapping/i,
    // Go
    /\.HandleFunc|\.Handle\(|gin\.|mux\.|echo\.|fiber\./i,
    // Ruby/Rails
    /resources?\s+:|get\s+['"]|post\s+['"]|namespace\s+:/i,
    // PHP/Laravel
    /Route::(get|post|put|patch|delete|resource)/i,
];

function isSourceFile(filePath: string): boolean {
    return SOURCE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function looksLikeRouteFile(content: string): boolean {
    return ROUTE_INDICATOR_PATTERNS.some(p => p.test(content));
}

/**
 * Collect source files that are likely to contain route definitions.
 * We filter aggressively to keep token costs low.
 */
function collectRouteFiles(sourcePath: string): { relativePath: string; content: string }[] {
    const files: { relativePath: string; content: string }[] = [];
    const MAX_DEPTH = 6;
    const MAX_FILE_SIZE = 100_000; // 100KB per file
    const MAX_TOTAL_CHARS = 300_000; // ~75K tokens budget
    let totalChars = 0;

    function walk(dir: string, depth: number) {
        if (depth > MAX_DEPTH || totalChars >= MAX_TOTAL_CHARS) return;
        let entries: fs.Dirent[];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

        for (const entry of entries) {
            if (totalChars >= MAX_TOTAL_CHARS) return;
            if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'vendor' ||
                entry.name === '__pycache__' || entry.name === 'target' || entry.name === 'dist' ||
                entry.name === 'build' || entry.name === '.next' || entry.name === 'test' ||
                entry.name === 'tests' || entry.name === '__tests__' || entry.name === 'spec') {
                continue;
            }

            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath, depth + 1);
            } else if (isSourceFile(fullPath)) {
                try {
                    const stat = fs.statSync(fullPath);
                    if (stat.size > MAX_FILE_SIZE) continue;

                    const content = fs.readFileSync(fullPath, 'utf-8');
                    if (looksLikeRouteFile(content)) {
                        const relPath = path.relative(sourcePath, fullPath).replace(/\\/g, '/');
                        files.push({ relativePath: relPath, content });
                        totalChars += content.length;
                    }
                } catch { /* skip */ }
            }
        }
    }

    walk(sourcePath, 0);
    return files;
}

const SYSTEM_PROMPT = `You are an expert source code analyst specializing in web application security testing.
Your task is to identify ALL API endpoints (routes) defined in the given source code — including dynamically constructed routes, programmatically generated routes, middleware-mounted sub-routes, and any routes that a simple regex pattern match would miss.

For each endpoint you discover, return a JSON array of objects with these exact fields:
- method: HTTP method (GET, POST, PUT, DELETE, PATCH, ALL)
- path: The full URL path (including any prefix from router mounts)
- handler: The file and approximate line where this route is defined
- authRequired: boolean — whether authentication/authorization middleware or decorators are applied
- description: A brief one-line description of what this endpoint likely does
- userInputs: array of strings indicating where user input enters (e.g. "body", "query", "path: id", "headers", "file upload")
- source: "ai" (always set this to "ai")

IMPORTANT:
- Focus on routes that a regex scanner would MISS: variable-based paths, loop-generated routes, decorator chains, route factories, programmatic registration, etc.
- DO NOT include obvious static routes like \`app.get('/health')\` — those are already found by the static scanner.
- If you find no additional dynamic routes, return an empty array [].
- Return ONLY valid JSON — no markdown fences, no explanation, just the JSON array.`;

export async function extractRoutesWithAI(sourcePath: string, existingRoutes: EndpointSummary[], userId?: number): Promise<EndpointSummary[]> {
    const routeFiles = collectRouteFiles(sourcePath);

    if (routeFiles.length === 0) {
        logger.info('AI Route Extractor: No route-relevant files found');
        return [];
    }

    // Build context for the LLM — include file:line info so AI knows where static routes were found
    const existingRoutesStr = existingRoutes.length > 0
        ? `\n\nThe following routes have ALREADY been found by the static regex scanner (DO NOT repeat these):\n${existingRoutes.map(r => `${r.method} ${r.path} [found in ${r.handler || 'unknown'}]`).join('\n')}`
        : '';

    const fileContents = routeFiles.map(f =>
        `--- FILE: ${f.relativePath} ---\n${f.content}\n--- END FILE ---`
    ).join('\n\n');

    const userPrompt = `Analyze the following source code files and extract ALL dynamically defined API endpoints that a simple regex pattern would miss.${existingRoutesStr}\n\nSource Code:\n${fileContents}`;

    logger.info(`AI Route Extractor: Sending ${routeFiles.length} files (~${Math.round(fileContents.length / 4)} tokens) to LLM`);

    try {
        const response = await llmRuntime.generate({
            systemPrompt: SYSTEM_PROMPT,
            userPrompt,
        }, {
            userId,
            callSite: 'source_analysis',
            context: 'ai-route-extraction',
        });

        // Parse JSON response
        let parsed: any[];
        try {
            const cleaned = response.text.trim().replace(/^```json?\s*/i, '').replace(/```\s*$/i, '').trim();
            parsed = JSON.parse(cleaned);
        } catch {
            logger.warn('AI Route Extractor: Failed to parse LLM response as JSON', {
                responseLength: response.text.length,
                routeFileCount: routeFiles.length,
            });
            return [];
        }

        if (!Array.isArray(parsed)) return [];

        // Convert to EndpointSummary and deduplicate against existing
        const existingKeys = new Set(existingRoutes.map(r => `${r.method}:${r.path}`));
        const results: EndpointSummary[] = [];

        for (const ep of parsed) {
            if (!ep.method || !ep.path) continue;
            const key = `${String(ep.method).toUpperCase()}:${ep.path}`;
            if (existingKeys.has(key)) continue; // skip duplicates (vs static AND vs self)
            existingKeys.add(key); // track to prevent self-duplicates

            results.push({
                method: String(ep.method).toUpperCase(),
                path: String(ep.path),
                handler: String(ep.handler || 'ai-detected'),
                authRequired: Boolean(ep.authRequired),
                description: String(ep.description || ''),
                userInputs: Array.isArray(ep.userInputs) ? ep.userInputs.map(String) : [],
            });
        }

        logger.info(`AI Route Extractor: Discovered ${results.length} additional dynamic routes`);
        return results;

    } catch (err: any) {
        logger.error('AI Route Extractor failed', { error: err.message });
        throw new Error(`AI analysis failed: ${err.message}`);
    }
}
