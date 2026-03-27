import fs from 'fs';
import path from 'path';
import { DependencyInfo } from '../SourceAnalysisMode';
import { logger } from '../../../utils/logger';

interface ManifestParser {
    files: string[];
    ecosystem: string;
    parse: (content: string, filePath: string) => DependencyInfo[];
}

const MANIFEST_PARSERS: ManifestParser[] = [
    {
        files: ['package.json'],
        ecosystem: 'npm',
        parse: (content) => {
            try {
                const pkg = JSON.parse(content);
                const deps: DependencyInfo[] = [];
                const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
                for (const [name, version] of Object.entries(allDeps)) {
                    deps.push({
                        name,
                        currentVersion: String(version).replace(/^[\^~>=<]*/, ''),
                        ecosystem: 'npm',
                    });
                }
                return deps;
            } catch { return []; }
        },
    },
    {
        files: ['package-lock.json'],
        ecosystem: 'npm',
        parse: (content) => {
            try {
                const lock = JSON.parse(content);
                const deps: DependencyInfo[] = [];
                const packages = lock.packages || {};
                for (const [pkgPath, info] of Object.entries(packages) as [string, any][]) {
                    if (!pkgPath || pkgPath === '') continue;
                    const name = pkgPath.replace(/^node_modules\//, '');
                    if (name.startsWith('.') || !info.version) continue;
                    deps.push({
                        name,
                        currentVersion: info.version,
                        ecosystem: 'npm',
                    });
                }
                if (deps.length === 0 && lock.dependencies) {
                    for (const [name, info] of Object.entries(lock.dependencies) as [string, any][]) {
                        deps.push({ name, currentVersion: info.version || '0.0.0', ecosystem: 'npm' });
                    }
                }
                return deps;
            } catch { return []; }
        },
    },
    {
        files: ['requirements.txt'],
        ecosystem: 'PyPI',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            for (const line of content.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
                const match = trimmed.match(/^([a-zA-Z0-9._-]+)\s*(?:[=<>!~]+\s*(.+))?$/);
                if (match) {
                    deps.push({
                        name: match[1],
                        currentVersion: match[2]?.replace(/[=<>!~]/g, '').trim() || 'unknown',
                        ecosystem: 'PyPI',
                    });
                }
            }
            return deps;
        },
    },
    {
        files: ['Pipfile.lock'],
        ecosystem: 'PyPI',
        parse: (content) => {
            try {
                const lock = JSON.parse(content);
                const deps: DependencyInfo[] = [];
                for (const section of ['default', 'develop']) {
                    const pkgs = lock[section] || {};
                    for (const [name, info] of Object.entries(pkgs) as [string, any][]) {
                        deps.push({
                            name,
                            currentVersion: (info.version || '').replace(/^==/, '') || 'unknown',
                            ecosystem: 'PyPI',
                        });
                    }
                }
                return deps;
            } catch { return []; }
        },
    },
    {
        files: ['go.mod'],
        ecosystem: 'Go',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
            const lines = requireBlock ? requireBlock[1].split('\n') : content.split('\n');
            for (const line of lines) {
                const match = line.trim().match(/^([^\s]+)\s+(v[\d.]+\S*)/);
                if (match && !match[1].startsWith('//')) {
                    deps.push({
                        name: match[1],
                        currentVersion: match[2],
                        ecosystem: 'Go',
                    });
                }
            }
            return deps;
        },
    },
    {
        files: ['Cargo.toml'],
        ecosystem: 'crates.io',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            let inDeps = false;
            for (const line of content.split('\n')) {
                const trimmed = line.trim();
                if (trimmed.match(/^\[(.*dependencies.*)\]/i)) { inDeps = true; continue; }
                if (trimmed.startsWith('[') && inDeps) { inDeps = false; continue; }
                if (!inDeps) continue;
                const simple = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
                if (simple) {
                    deps.push({ name: simple[1], currentVersion: simple[2], ecosystem: 'crates.io' });
                    continue;
                }
                const table = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
                if (table) {
                    deps.push({ name: table[1], currentVersion: table[2], ecosystem: 'crates.io' });
                }
            }
            return deps;
        },
    },
    {
        files: ['Gemfile.lock'],
        ecosystem: 'RubyGems',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            let inSpecs = false;
            for (const line of content.split('\n')) {
                if (line.trim() === 'specs:') { inSpecs = true; continue; }
                if (line.trim() === '' || (!line.startsWith('  ') && !line.startsWith('\t'))) {
                    if (inSpecs) inSpecs = false;
                    continue;
                }
                if (!inSpecs) continue;
                const match = line.trim().match(/^([a-zA-Z0-9._-]+)\s+\(([^)]+)\)/);
                if (match) {
                    deps.push({ name: match[1], currentVersion: match[2], ecosystem: 'RubyGems' });
                }
            }
            return deps;
        },
    },
    {
        files: ['composer.json'],
        ecosystem: 'Packagist',
        parse: (content) => {
            try {
                const pkg = JSON.parse(content);
                const deps: DependencyInfo[] = [];
                const allDeps = { ...pkg.require, ...pkg['require-dev'] };
                for (const [name, version] of Object.entries(allDeps)) {
                    if (name === 'php' || name.startsWith('ext-')) continue;
                    deps.push({
                        name,
                        currentVersion: String(version).replace(/^[\^~>=<*|]*/, ''),
                        ecosystem: 'Packagist',
                    });
                }
                return deps;
            } catch { return []; }
        },
    },
    {
        files: ['pom.xml'],
        ecosystem: 'Maven',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/gs;
            let match;
            while ((match = depRegex.exec(content)) !== null) {
                deps.push({
                    name: `${match[1]}:${match[2]}`,
                    currentVersion: match[3] || 'managed',
                    ecosystem: 'Maven',
                });
            }
            return deps;
        },
    },
    {
        files: ['build.gradle', 'build.gradle.kts'],
        ecosystem: 'Maven',
        parse: (content) => {
            const deps: DependencyInfo[] = [];
            const implRegex = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\('"]\s*([^:'"]+):([^:'"]+):([^)'"]+)/g;
            let match;
            while ((match = implRegex.exec(content)) !== null) {
                deps.push({
                    name: `${match[1]}:${match[2]}`,
                    currentVersion: match[3].trim(),
                    ecosystem: 'Maven',
                });
            }
            return deps;
        },
    },
];

function findManifestFiles(sourcePath: string): { filePath: string; parser: ManifestParser }[] {
    const found: { filePath: string; parser: ManifestParser }[] = [];
    const MAX_DEPTH = 3;

    function walk(dir: string, depth: number) {
        if (depth > MAX_DEPTH) return;
        let entries: fs.Dirent[];
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

        for (const entry of entries) {
            if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'vendor' ||
                entry.name === '__pycache__' || entry.name === 'target' || entry.name === 'dist' || entry.name === 'build') {
                continue;
            }
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath, depth + 1);
            } else {
                for (const parser of MANIFEST_PARSERS) {
                    if (parser.files.includes(entry.name)) {
                        found.push({ filePath: fullPath, parser });
                    }
                }
            }
        }
    }

    walk(sourcePath, 0);
    return found;
}

function deduplicateDeps(deps: DependencyInfo[]): DependencyInfo[] {
    const seen = new Map<string, DependencyInfo>();
    for (const dep of deps) {
        const key = `${dep.ecosystem}:${dep.name}`;
        const existing = seen.get(key);
        if (!existing || (dep.currentVersion !== 'unknown' && existing.currentVersion === 'unknown')) {
            seen.set(key, dep);
        }
    }
    return Array.from(seen.values());
}

export function detectFramework(deps: DependencyInfo[]): string {
    const names = new Set(deps.map(d => d.name.toLowerCase()));

    if (names.has('next')) return 'Next.js';
    if (names.has('nuxt')) return 'Nuxt.js';
    if (names.has('@angular/core')) return 'Angular';
    if (names.has('express')) return 'Express.js';
    if (names.has('fastify')) return 'Fastify';
    if (names.has('koa')) return 'Koa';
    if (names.has('hapi') || names.has('@hapi/hapi')) return 'Hapi';
    if (names.has('nestjs') || names.has('@nestjs/core')) return 'NestJS';
    if (names.has('django') || names.has('django-rest-framework')) return 'Django';
    if (names.has('flask')) return 'Flask';
    if (names.has('fastapi')) return 'FastAPI';
    if (names.has('rails') || names.has('railties')) return 'Ruby on Rails';
    if (names.has('sinatra')) return 'Sinatra';
    if (names.has('spring-boot') || names.has('org.springframework.boot:spring-boot-starter-web')) return 'Spring Boot';
    if (names.has('laravel') || names.has('laravel/framework')) return 'Laravel';
    if (names.has('symfony') || names.has('symfony/framework-bundle')) return 'Symfony';
    if (names.has('gin-gonic/gin')) return 'Gin (Go)';
    if (names.has('actix-web')) return 'Actix Web (Rust)';
    if (names.has('rocket')) return 'Rocket (Rust)';
    if (names.has('react')) return 'React';
    if (names.has('vue')) return 'Vue.js';
    if (names.has('svelte') || names.has('@sveltejs/kit')) return 'Svelte';

    const ecosystems = new Set(deps.map(d => d.ecosystem));
    if (ecosystems.has('npm')) return 'Node.js';
    if (ecosystems.has('PyPI')) return 'Python';
    if (ecosystems.has('Go')) return 'Go';
    if (ecosystems.has('Maven')) return 'Java/JVM';
    if (ecosystems.has('crates.io')) return 'Rust';
    if (ecosystems.has('RubyGems')) return 'Ruby';
    if (ecosystems.has('Packagist')) return 'PHP';

    return 'Unknown';
}

export function detectTechnologyStack(deps: DependencyInfo[]): string[] {
    const stack: string[] = [];
    const names = new Set(deps.map(d => d.name.toLowerCase()));

    if (names.has('express') || names.has('fastify') || names.has('koa') || names.has('@nestjs/core')) stack.push('Node.js Backend');
    if (names.has('react') || names.has('react-dom')) stack.push('React');
    if (names.has('next')) stack.push('Next.js');
    if (names.has('vue')) stack.push('Vue.js');
    if (names.has('@angular/core')) stack.push('Angular');
    if (names.has('typescript')) stack.push('TypeScript');
    if (names.has('mongoose') || names.has('mongodb')) stack.push('MongoDB');
    if (names.has('pg') || names.has('sequelize') || names.has('typeorm') || names.has('prisma') || names.has('@prisma/client')) stack.push('SQL Database');
    if (names.has('redis') || names.has('ioredis')) stack.push('Redis');
    if (names.has('jsonwebtoken') || names.has('passport')) stack.push('JWT/Auth');
    if (names.has('bcrypt') || names.has('bcryptjs')) stack.push('Password Hashing');
    if (names.has('multer')) stack.push('File Upload');
    if (names.has('puppeteer') || names.has('playwright')) stack.push('Browser Automation');
    if (names.has('ws') || names.has('socket.io')) stack.push('WebSockets');
    if (names.has('graphql') || names.has('apollo-server') || names.has('@apollo/server')) stack.push('GraphQL');
    if (names.has('docker-compose') || names.has('dockerode')) stack.push('Docker');
    if (names.has('aws-sdk') || names.has('@aws-sdk/client-s3')) stack.push('AWS');
    if (names.has('stripe')) stack.push('Stripe Payments');
    if (names.has('django') || names.has('flask') || names.has('fastapi')) stack.push('Python Backend');
    if (names.has('rails') || names.has('railties')) stack.push('Ruby on Rails');

    const ecosystems = new Set(deps.map(d => d.ecosystem));
    if (ecosystems.has('npm') && stack.length === 0) stack.push('Node.js');
    if (ecosystems.has('PyPI') && !stack.some(s => s.includes('Python'))) stack.push('Python');
    if (ecosystems.has('Go')) stack.push('Go');
    if (ecosystems.has('Maven')) stack.push('Java');

    return [...new Set(stack)];
}

export async function extractDependencies(sourcePath: string): Promise<DependencyInfo[]> {
    logger.info(`Extracting dependencies from: ${sourcePath}`);
    const manifests = findManifestFiles(sourcePath);

    if (manifests.length === 0) {
        logger.warn('No manifest/lockfiles found in source path');
        return [];
    }

    logger.info(`Found ${manifests.length} manifest/lock files`);
    const allDeps: DependencyInfo[] = [];

    for (const { filePath, parser } of manifests) {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const deps = parser.parse(content, filePath);
            allDeps.push(...deps);
            logger.info(`Parsed ${deps.length} deps from ${path.basename(filePath)} (${parser.ecosystem})`);
        } catch (e: any) {
            logger.warn(`Failed to parse ${filePath}: ${e.message}`);
        }
    }

    return deduplicateDeps(allDeps);
}
