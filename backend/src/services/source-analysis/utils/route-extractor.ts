import fs from 'fs';
import path from 'path';
import { EndpointSummary } from '../SourceAnalysisMode';
import { logger } from '../../../utils/logger';

interface RoutePattern {
    regex: RegExp;
    extract: (match: RegExpMatchArray, filePath: string) => Partial<EndpointSummary> | null;
}

const EXPRESS_PATTERNS: RoutePattern[] = [
    {
        regex: /(?:app|router)\.(get|post|put|patch|delete|all|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
        extract: (match, filePath) => ({
            method: match[1].toUpperCase(),
            path: match[2],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
    {
        regex: /router\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
        extract: (match, filePath) => ({
            method: match[1].toUpperCase(),
            path: match[2],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
];

const FASTIFY_PATTERNS: RoutePattern[] = [
    {
        regex: /fastify\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
        extract: (match, filePath) => ({
            method: match[1].toUpperCase(),
            path: match[2],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
];

const PYTHON_FLASK_PATTERNS: RoutePattern[] = [
    {
        regex: /@(?:app|blueprint|bp)\.route\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]+)\])?/gi,
        extract: (match, filePath) => ({
            method: match[2] ? match[2].replace(/['"]/g, '').split(',')[0].trim().toUpperCase() : 'GET',
            path: match[1],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
];

const PYTHON_FASTAPI_PATTERNS: RoutePattern[] = [
    {
        regex: /@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/gi,
        extract: (match, filePath) => ({
            method: match[1].toUpperCase(),
            path: match[2],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
];

const DJANGO_PATTERNS: RoutePattern[] = [
    {
        regex: /(?:path|re_path|url)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z_][\w.]*)/gi,
        extract: (match, filePath) => ({
            method: 'ALL',
            path: '/' + match[1],
            handler: match[2],
        }),
    },
];

const SPRING_PATTERNS: RoutePattern[] = [
    {
        regex: /@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/gi,
        extract: (match, filePath) => {
            const method = match[0].includes('GetMapping') ? 'GET'
                : match[0].includes('PostMapping') ? 'POST'
                    : match[0].includes('PutMapping') ? 'PUT'
                        : match[0].includes('DeleteMapping') ? 'DELETE'
                            : match[0].includes('PatchMapping') ? 'PATCH' : 'ALL';
            return {
                method,
                path: match[1],
                handler: path.basename(filePath, path.extname(filePath)),
            };
        },
    },
];

const RAILS_PATTERNS: RoutePattern[] = [
    {
        regex: /(?:get|post|put|patch|delete)\s+['"]([^'"]+)['"]/gi,
        extract: (match, filePath) => ({
            method: match[0].trim().split(/\s/)[0].toUpperCase(),
            path: match[1],
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
    {
        regex: /resources?\s+:(\w+)/gi,
        extract: (match) => ({
            method: 'REST',
            path: `/${match[1]}`,
            handler: `${match[1]}_controller`,
        }),
    },
];

const NESTJS_PATTERNS: RoutePattern[] = [
    {
        regex: /@(Get|Post|Put|Patch|Delete)\s*\(\s*['"]?([^'")]*)?['"]?\s*\)/gi,
        extract: (match, filePath) => ({
            method: match[1].toUpperCase(),
            path: match[2] || '/',
            handler: path.basename(filePath, path.extname(filePath)),
        }),
    },
];

const ALL_PATTERNS = [
    ...EXPRESS_PATTERNS,
    ...FASTIFY_PATTERNS,
    ...PYTHON_FLASK_PATTERNS,
    ...PYTHON_FASTAPI_PATTERNS,
    ...DJANGO_PATTERNS,
    ...SPRING_PATTERNS,
    ...RAILS_PATTERNS,
    ...NESTJS_PATTERNS,
];

const AUTH_INDICATORS = [
    /auth/i, /authenticate/i, /authorize/i, /passport/i, /jwt/i,
    /token/i, /session/i, /login/i, /guard/i, /middleware.*auth/i,
    /requireAuth/i, /isAuthenticated/i, /protect/i, /secure/i,
];

const SOURCE_EXTENSIONS = new Set([
    '.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs',
    '.py', '.rb', '.java', '.kt', '.go', '.rs',
    '.php', '.cs',
]);

function isSourceFile(filePath: string): boolean {
    return SOURCE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function detectAuthRequirement(fileContent: string, routeLine: number): boolean {
    const lines = fileContent.split('\n');
    const contextStart = Math.max(0, routeLine - 5);
    const contextEnd = Math.min(lines.length, routeLine + 3);
    const context = lines.slice(contextStart, contextEnd).join('\n');

    return AUTH_INDICATORS.some(pattern => pattern.test(context));
}

function extractUserInputs(fileContent: string, routePath: string): string[] {
    const inputs: string[] = [];

    const paramMatches = routePath.match(/:(\w+)/g) || routePath.match(/\{(\w+)\}/g) || [];
    for (const p of paramMatches) {
        inputs.push(`path: ${p.replace(/[:{}]/g, '')}`);
    }

    if (/req\.body|request\.body|request\.json|request\.form/i.test(fileContent)) {
        inputs.push('body');
    }
    if (/req\.query|request\.args|request\.query_params/i.test(fileContent)) {
        inputs.push('query');
    }
    if (/req\.params|request\.params/i.test(fileContent)) {
        inputs.push('params');
    }
    if (/req\.file|req\.files|upload|multipart/i.test(fileContent)) {
        inputs.push('file upload');
    }
    if (/req\.headers|request\.headers/i.test(fileContent)) {
        inputs.push('headers');
    }

    return [...new Set(inputs)];
}

export async function extractRoutes(sourcePath: string): Promise<EndpointSummary[]> {
    const endpoints: EndpointSummary[] = [];
    const MAX_DEPTH = 6;

    function walk(dir: string, depth: number) {
        if (depth > MAX_DEPTH) return;
        let entries: fs.Dirent[];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

        for (const entry of entries) {
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
                    const content = fs.readFileSync(fullPath, 'utf-8');
                    if (content.length > 500_000) continue;

                    for (const pattern of ALL_PATTERNS) {
                        let match;
                        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
                        while ((match = regex.exec(content)) !== null) {
                            const extracted = pattern.extract(match, fullPath);
                            if (extracted?.path) {
                                const lineNum = content.slice(0, match.index).split('\n').length;
                                const relativePath = path.relative(sourcePath, fullPath).replace(/\\/g, '/');

                                endpoints.push({
                                    method: extracted.method || 'ALL',
                                    path: extracted.path,
                                    handler: `${relativePath}:${lineNum}`,
                                    authRequired: detectAuthRequirement(content, lineNum),
                                    description: '',
                                    userInputs: extractUserInputs(content, extracted.path),
                                });
                            }
                        }
                    }
                } catch { /* skip unreadable files */ }
            }
        }
    }

    walk(sourcePath, 0);

    const deduped = new Map<string, EndpointSummary>();
    for (const ep of endpoints) {
        const key = `${ep.method}:${ep.path}`;
        if (!deduped.has(key)) {
            deduped.set(key, ep);
        }
    }

    const result = Array.from(deduped.values());
    logger.info(`Extracted ${result.length} unique routes from source`);
    return result;
}
