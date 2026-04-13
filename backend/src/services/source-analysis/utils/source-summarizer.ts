import fs from 'fs';
import path from 'path';
import { ModuleSummary, FunctionSummary, SecurityFlow } from '../SourceAnalysisMode';
import { llmRuntime } from '../../llm/LlmRuntime';
import { logger } from '../../../utils/logger';

const SOURCE_EXTENSIONS = new Set([
    '.ts', '.js', '.tsx', '.jsx', '.mjs', '.cjs',
    '.py', '.rb', '.java', '.kt', '.go', '.rs',
    '.php', '.cs',
]);

const SKIP_DIRS = new Set([
    'node_modules', 'vendor', '__pycache__', 'target', 'dist', 'build',
    '.next', '.git', '.svn', 'coverage', '.cache', 'tmp', 'temp',
    'test', 'tests', '__tests__', 'spec', 'e2e', '.idea', '.vscode',
]);

const MAX_FILE_SIZE = 100_000;
const CHUNK_SIZE = 6_000;
const MAX_FILES_TO_ANALYZE = 80;

interface FileInfo {
    relativePath: string;
    absolutePath: string;
    size: number;
    priority: number;
}

function prioritizeFile(relativePath: string): number {
    const lower = relativePath.toLowerCase();
    if (/route|controller|handler|endpoint|api|view/.test(lower)) return 10;
    if (/auth|login|session|token|security|guard|middleware|protect/.test(lower)) return 9;
    if (/model|schema|entity|migration|database|db/.test(lower)) return 7;
    if (/service|provider|repository|store/.test(lower)) return 6;
    if (/config|env|setting/.test(lower)) return 5;
    if (/util|helper|lib/.test(lower)) return 3;
    if (/index|main|app|server/.test(lower)) return 8;
    return 1;
}

export function buildFileTree(sourcePath: string): FileInfo[] {
    const files: FileInfo[] = [];
    const MAX_DEPTH = 8;

    function walk(dir: string, depth: number) {
        if (depth > MAX_DEPTH) return;
        let entries: fs.Dirent[];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

        for (const entry of entries) {
            if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                walk(fullPath, depth + 1);
            } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
                try {
                    const stat = fs.statSync(fullPath);
                    if (stat.size > MAX_FILE_SIZE) continue;
                    const relativePath = path.relative(sourcePath, fullPath).replace(/\\/g, '/');
                    files.push({
                        relativePath,
                        absolutePath: fullPath,
                        size: stat.size,
                        priority: prioritizeFile(relativePath),
                    });
                } catch { /* skip */ }
            }
        }
    }

    walk(sourcePath, 0);
    files.sort((a, b) => b.priority - a.priority);
    return files.slice(0, MAX_FILES_TO_ANALYZE);
}

function chunkText(text: string, maxChars: number): string[] {
    const chunks: string[] = [];
    const lines = text.split('\n');
    let current = '';

    for (const line of lines) {
        if (current.length + line.length + 1 > maxChars && current.length > 0) {
            chunks.push(current);
            current = '';
        }
        current += (current ? '\n' : '') + line;
    }
    if (current) chunks.push(current);
    return chunks;
}

export async function summarizeModules(files: FileInfo[], sourcePath: string, userId?: number): Promise<ModuleSummary[]> {
    const dirMap = new Map<string, FileInfo[]>();
    for (const f of files) {
        const dir = path.dirname(f.relativePath);
        if (!dirMap.has(dir)) dirMap.set(dir, []);
        dirMap.get(dir)!.push(f);
    }

    const modules: ModuleSummary[] = [];
    const dirsToSummarize = Array.from(dirMap.entries())
        .sort((a, b) => {
            const maxA = Math.max(...a[1].map(f => f.priority));
            const maxB = Math.max(...b[1].map(f => f.priority));
            return maxB - maxA;
        })
        .slice(0, 20);

    for (const [dir, dirFiles] of dirsToSummarize) {
        const fileList = dirFiles.map(f => path.basename(f.relativePath)).join(', ');
        let sampleContent = '';
        for (const f of dirFiles.slice(0, 3)) {
            try {
                const content = fs.readFileSync(f.absolutePath, 'utf-8');
                sampleContent += `\n--- ${f.relativePath} ---\n${content.slice(0, 2000)}\n`;
            } catch { /* skip */ }
        }

        if (!sampleContent.trim()) continue;

        try {
            const response = await llmRuntime.generate({
                systemPrompt: 'You are a code analysis assistant. Be extremely concise. Answer in 1-2 sentences only.',
                userPrompt: `What is the purpose of this module/directory "${dir}"?\n\nFiles: ${fileList}\n\nCode samples:\n${sampleContent.slice(0, 4000)}\n\nRespond with ONLY a 1-2 sentence description of the module purpose.`,
            }, {
                userId,
                callSite: 'source_analysis',
                context: 'source-analysis-module-summary',
            });

            modules.push({
                name: dir || 'root',
                path: dir || '.',
                purpose: response.text.trim().slice(0, 300),
            });
        } catch (e: any) {
            logger.warn(`Failed to summarize module ${dir}: ${e.message}`);
            modules.push({ name: dir || 'root', path: dir || '.', purpose: `Contains: ${fileList}` });
        }
    }

    return modules;
}

export async function summarizeFunctions(files: FileInfo[], userId?: number): Promise<FunctionSummary[]> {
    const functions: FunctionSummary[] = [];
    const highPriorityFiles = files.filter(f => f.priority >= 6).slice(0, 25);

    for (const file of highPriorityFiles) {
        try {
            const content = fs.readFileSync(file.absolutePath, 'utf-8');
            const chunks = chunkText(content, CHUNK_SIZE);
            const firstChunks = chunks.slice(0, 2);
            const codeSnippet = firstChunks.join('\n...\n');

            const response = await llmRuntime.generate({
                systemPrompt: 'You are a code analysis assistant. Output ONLY valid JSON, no markdown.',
                userPrompt: `Extract the important functions/methods from this file. For each, give name, purpose (1 sentence), and whether it is security-relevant (handles auth, user input, DB queries, file operations, or crypto).

File: ${file.relativePath}

\`\`\`
${codeSnippet.slice(0, 5000)}
\`\`\`

Return JSON array: [{"name":"funcName","purpose":"...","securityRelevant":true/false}]
Limit to the 8 most important functions. Return ONLY the JSON array.`,
            }, {
                userId,
                callSite: 'source_analysis',
                context: 'source-analysis-function-summary',
            });

            try {
                const text = response.text.trim();
                const jsonMatch = text.match(/\[[\s\S]*\]/);
                if (jsonMatch) {
                    const parsed = JSON.parse(jsonMatch[0]) as Array<{ name: string; purpose: string; securityRelevant: boolean }>;
                    for (const fn of parsed) {
                        functions.push({
                            name: fn.name,
                            filePath: file.relativePath,
                            purpose: fn.purpose?.slice(0, 200) || '',
                            securityRelevant: !!fn.securityRelevant,
                        });
                    }
                }
            } catch { /* skip parse errors */ }
        } catch (e: any) {
            logger.warn(`Failed to analyze functions in ${file.relativePath}: ${e.message}`);
        }
    }

    return functions;
}

export async function analyzeSecurityFlows(
    files: FileInfo[],
    modules: ModuleSummary[],
    functions: FunctionSummary[],
    userId?: number,
): Promise<SecurityFlow[]> {
    const securityFiles = files.filter(f => f.priority >= 7).slice(0, 10);
    let securityContext = '';

    for (const f of securityFiles) {
        try {
            const content = fs.readFileSync(f.absolutePath, 'utf-8');
            securityContext += `\n--- ${f.relativePath} ---\n${content.slice(0, 3000)}\n`;
        } catch { /* skip */ }
    }

    const moduleSummary = modules.map(m => `${m.name}: ${m.purpose}`).join('\n');
    const secFunctions = functions.filter(f => f.securityRelevant);
    const funcSummary = secFunctions.map(f => `${f.name} (${f.filePath}): ${f.purpose}`).join('\n');

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'You are a security code analyst. Output ONLY valid JSON, no markdown.',
            userPrompt: `Analyze the security-relevant flows in this application.

Modules:
${moduleSummary.slice(0, 2000)}

Security-relevant functions:
${funcSummary.slice(0, 2000)}

Code samples:
${securityContext.slice(0, 6000)}

Identify security-relevant flows in these categories: authentication, authorization, object lookup/IDOR, database access, file upload, outbound requests, redirect logic, deserialization, template rendering, command execution, caching/session, crypto/token handling.

Return JSON array: [{"category":"...","description":"...","components":["file1.ts","funcName"],"riskLevel":"high|medium|low"}]
Return ONLY the JSON array. Max 12 flows.`,
        }, {
            userId,
            callSite: 'source_analysis',
            context: 'source-analysis-security-flows',
        });

        const text = response.text.trim();
        const jsonMatch = text.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]) as SecurityFlow[];
            return parsed.slice(0, 12).map(f => ({
                category: String(f.category || '').slice(0, 100),
                description: String(f.description || '').slice(0, 300),
                components: Array.isArray(f.components) ? f.components.map(String).slice(0, 10) : [],
                riskLevel: String(f.riskLevel || 'medium'),
            }));
        }
    } catch (e: any) {
        logger.warn(`Failed to analyze security flows: ${e.message}`);
    }

    return [];
}

export async function generateApplicationSummary(
    files: FileInfo[],
    modules: ModuleSummary[],
    framework: string,
    stack: string[],
    userId?: number,
): Promise<string> {
    const moduleSummary = modules.map(m => `${m.name}: ${m.purpose}`).join('\n');
    const fileTree = files.slice(0, 40).map(f => f.relativePath).join('\n');

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'You are a code analysis assistant. Be concise but thorough.',
            userPrompt: `Summarize this application in 3-5 sentences.

Framework: ${framework}
Stack: ${stack.join(', ')}

File structure:
${fileTree.slice(0, 3000)}

Module summaries:
${moduleSummary.slice(0, 3000)}

Describe: what the application does, its purpose, its architecture style, and any notable design patterns.`,
        }, {
            userId,
            callSite: 'source_analysis',
            context: 'source-analysis-app-summary',
        });

        return response.text.trim().slice(0, 1000);
    } catch (e: any) {
        logger.warn(`Failed to generate application summary: ${e.message}`);
        return `${framework} application with ${files.length} source files across ${modules.length} modules.`;
    }
}

export async function generateArchitectureSummary(
    modules: ModuleSummary[],
    functions: FunctionSummary[],
    framework: string,
    userId?: number,
): Promise<string> {
    const moduleSummary = modules.map(m => `${m.name}: ${m.purpose}`).join('\n');
    const keyFunctions = functions.filter(f => f.securityRelevant).slice(0, 20);
    const funcList = keyFunctions.map(f => `${f.filePath}/${f.name}: ${f.purpose}`).join('\n');

    try {
        const response = await llmRuntime.generate({
            systemPrompt: 'You are a software architect analyst. Be concise.',
            userPrompt: `Describe the architecture of this ${framework} application in 3-5 sentences.

Modules:
${moduleSummary.slice(0, 2000)}

Key functions:
${funcList.slice(0, 2000)}

Describe: layer separation, data flow patterns, component relationships, and architectural style.`,
        }, {
            userId,
            callSite: 'source_analysis',
            context: 'source-analysis-arch-summary',
        });

        return response.text.trim().slice(0, 1000);
    } catch (e: any) {
        logger.warn(`Failed to generate architecture summary: ${e.message}`);
        return `${framework} application organized into ${modules.length} modules.`;
    }
}
