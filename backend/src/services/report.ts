import { PDFDocument, rgb, StandardFonts, PDFPage, PDFFont, RGB } from 'pdf-lib';
import fs from 'fs';
import path from 'path';
import { logger } from '../utils/logger';
import { llmProvider, GenerationRequest } from './LLMProviderService';

const REPORTS_DIR = path.join(__dirname, '../../reports');
const LOGOS_DIR = path.join(__dirname, '../../uploads/logos');
const SCREENSHOTS_DIR = path.join(__dirname, '../../screenshots');

if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
}
if (!fs.existsSync(SCREENSHOTS_DIR)) {
    fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

// ═══════════════════════════════════════════════════════════
//  INTERFACES
// ═══════════════════════════════════════════════════════════

interface Scan {
    id: string;
    type: string;
    target: string;
    status: string;
    created_at: string;
    completed_at: string;
}

interface Vulnerability {
    id: number;
    name: string;
    description?: string;
    severity: string;
    cvss_score?: number;
    cvss_vector?: string;
    cwe?: string;
    cve?: string;
    request?: string;
    response?: string;
    evidence?: string;
    remediation?: string;
    screenshot_path?: string;
    created_at?: string;
}

// ═══════════════════════════════════════════════════════════
//  LLM-POWERED HIGHLIGHT ANALYSIS
// ═══════════════════════════════════════════════════════════

interface HighlightResult {
    textHighlights: string[];     // Text patterns to highlight in request/response
    screenshotHighlights?: Array<{  // Pixel regions to highlight in screenshot (from vision LLM)
        x: number;
        y: number;
        width: number;
        height: number;
        label?: string;
    }>;
}

/**
 * Ask the active LLM to analyze a vulnerability and determine what
 * should be highlighted in the request/response.
 * Works with ANY LLM (text-only analysis).
 */
async function askLLMForHighlights(vuln: Vulnerability): Promise<string[]> {
    try {
        const requestSnippet = vuln.request ? vuln.request.slice(0, 2000) : 'N/A';
        const responseSnippet = vuln.response ? vuln.response.slice(0, 2000) : 'N/A';
        const evidenceSnippet = vuln.evidence ? String(vuln.evidence).slice(0, 500) : '';

        const prompt = `You are a security report annotation assistant. Your job is to identify the EXACT text strings that should be visually highlighted with red boxes in a penetration test report to draw attention to the key evidence of a vulnerability.

VULNERABILITY:
- Name: ${vuln.name}
- Severity: ${vuln.severity}
- CVSS: ${vuln.cvss_score || 'N/A'}
- CWE: ${vuln.cwe || 'N/A'}
- Description: ${(vuln.description || '').slice(0, 500)}

HTTP REQUEST:
${requestSnippet}

HTTP RESPONSE:
${responseSnippet}

${evidenceSnippet ? `ADDITIONAL EVIDENCE:\n${evidenceSnippet}` : ''}

TASK: Identify the most important text strings that should be highlighted with red boxes. These should be:
1. The actual payload/injection (e.g., "' OR 1=1--", "<script>alert(1)</script>")
2. The vulnerable parameter or endpoint
3. Key indicators in the response proving the vulnerability (e.g., error messages, leaked data, unexpected status codes)
4. Response time if it's a time-based attack

Return a JSON array of strings. Each string must be the EXACT text as it appears in the request or response. Maximum 6 highlights. Shorter, more specific strings are better (5-50 characters).

Example output: ["' OR 1=1--", "mysql_fetch_array()", "200 OK", "Welcome admin"]

Respond with ONLY a valid JSON array. No explanation.`;

        const response = await llmProvider.generate({
            systemPrompt: 'You are a security report annotation assistant. You ONLY respond with valid JSON arrays.',
            userPrompt: prompt,
        }, 'report-highlight-analysis');

        // Parse the response
        const text = response.text.trim();
        // Try to extract JSON array
        const match = text.match(/\[[\s\S]*?\]/);
        if (match) {
            const parsed = JSON.parse(match[0]);
            if (Array.isArray(parsed)) {
                return parsed
                    .filter((s: any) => typeof s === 'string' && s.length >= 2 && s.length <= 200)
                    .slice(0, 6);
            }
        }
        return [];
    } catch (err: any) {
        logger.warn('LLM highlight analysis failed, falling back to pattern detection', { error: err.message });
        return [];
    }
}

/**
 * Ask a vision-capable LLM to identify highlight regions in a screenshot.
 * Returns pixel coordinates for red box annotations.
 */
async function askLLMForScreenshotHighlights(
    vuln: Vulnerability,
    screenshotBase64: string,
    mimeType: string = 'image/png'
): Promise<Array<{ x: number; y: number; width: number; height: number; label?: string }>> {
    try {
        const visionCheck = llmProvider.checkVisionSupport();
        if (!visionCheck.supported) {
            logger.info('Active LLM does not support vision, skipping screenshot highlight analysis');
            return [];
        }

        const prompt = `You are a security report annotation assistant analyzing a screenshot of a web page that contains a vulnerability.

VULNERABILITY:
- Name: ${vuln.name}
- Severity: ${vuln.severity}
- Description: ${(vuln.description || '').slice(0, 300)}

Look at the attached screenshot. Identify the areas in this image that are most relevant to this vulnerability and should be highlighted with red boxes to draw the reader's attention.

Focus on:
1. Input fields where the payload was injected
2. Error messages or leaked data visible on the page
3. URL bar showing the vulnerable endpoint
4. Any visual indicator of the vulnerability

Return a JSON array of objects with pixel coordinates:
[{"x": 100, "y": 200, "width": 300, "height": 50, "label": "SQL injection in login field"}]

Where x,y is the top-left corner of the rectangle. Maximum 4 highlight areas.
Respond with ONLY a valid JSON array.`;

        const response = await llmProvider.generate({
            systemPrompt: 'You are a security report screenshot annotation assistant. You ONLY respond with valid JSON arrays of coordinate objects.',
            userPrompt: prompt,
            images: [{ data: screenshotBase64, mimeType }],
        }, 'report-screenshot-analysis');

        const text = response.text.trim();
        const match = text.match(/\[[\s\S]*?\]/);
        if (match) {
            const parsed = JSON.parse(match[0]);
            if (Array.isArray(parsed)) {
                return parsed
                    .filter((r: any) => typeof r.x === 'number' && typeof r.y === 'number' &&
                        typeof r.width === 'number' && typeof r.height === 'number')
                    .slice(0, 4);
            }
        }
        return [];
    } catch (err: any) {
        logger.warn('Vision screenshot analysis failed', { error: err.message });
        return [];
    }
}

/**
 * Capture a screenshot of a web page using puppeteer (if available).
 * Returns the file path of the saved screenshot, or null if capture fails.
 */
async function capturePageScreenshot(url: string, scanId: string, vulnId: number): Promise<string | null> {
    try {
        // Dynamic import — puppeteer is optional
        let puppeteer: any;
        try {
            puppeteer = require('puppeteer');
        } catch {
            try {
                puppeteer = require('puppeteer-core');
            } catch {
                logger.info('Puppeteer not available, skipping screenshot capture');
                return null;
            }
        }

        const screenshotPath = path.join(SCREENSHOTS_DIR, `vuln-${scanId}-${vulnId}.png`);

        // If screenshot already exists (captured during scan), just return it
        if (fs.existsSync(screenshotPath)) {
            return screenshotPath;
        }

        // Try to find Chrome/Chromium executable
        const possiblePaths = [
            // Windows
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
            process.env.CHROME_PATH || '',
        ].filter(Boolean);

        let executablePath: string | undefined;
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                executablePath = p;
                break;
            }
        }

        const browser = await puppeteer.launch({
            headless: 'new',
            ...(executablePath ? { executablePath } : {}),
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
        });

        try {
            const page = await browser.newPage();
            await page.setViewport({ width: 1280, height: 800 });
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
            await page.screenshot({ path: screenshotPath, fullPage: false });
            logger.info('Screenshot captured', { url, path: screenshotPath });
            return screenshotPath;
        } finally {
            await browser.close();
        }
    } catch (err: any) {
        logger.warn('Screenshot capture failed', { error: err.message });
        return null;
    }
}

/**
 * Pre-process all vulnerabilities: get LLM highlights and capture screenshots.
 * Called once before building the PDF to avoid blocking during page layout.
 */
async function prepareVulnerabilityAnnotations(
    scan: Scan,
    vulns: Vulnerability[]
): Promise<Map<number, HighlightResult>> {
    const results = new Map<number, HighlightResult>();

    for (const vuln of vulns) {
        try {
            // 1. Get LLM-based text highlights (always try)
            let textHighlights = await askLLMForHighlights(vuln);

            // If LLM fails or returns empty, fall back to pattern detection
            if (textHighlights.length === 0) {
                textHighlights = detectHighlightPatterns(vuln);
            }

            // 2. Handle screenshot + vision analysis
            let screenshotHighlights: Array<{ x: number; y: number; width: number; height: number; label?: string }> = [];

            // Check if there's an existing screenshot
            let screenshotPath = vuln.screenshot_path;
            if (!screenshotPath || !fs.existsSync(screenshotPath)) {
                // Try to extract URL from request and capture screenshot
                const urlMatch = vuln.request?.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(https?:\/\/\S+)/i)
                    || vuln.request?.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/i);

                if (urlMatch) {
                    let targetUrl = urlMatch[1];
                    // If it's a relative URL, prepend the target
                    if (!targetUrl.startsWith('http')) {
                        targetUrl = `${scan.target.replace(/\/$/, '')}${targetUrl.startsWith('/') ? '' : '/'}${targetUrl}`;
                    }
                    screenshotPath = await capturePageScreenshot(targetUrl, scan.id, vuln.id) || undefined;
                }
            }

            // 3. If we have a screenshot AND vision LLM, get coordinate highlights
            if (screenshotPath && fs.existsSync(screenshotPath)) {
                const visionCheck = llmProvider.checkVisionSupport();
                if (visionCheck.supported) {
                    const imgBuffer = fs.readFileSync(screenshotPath);
                    const base64 = imgBuffer.toString('base64');
                    const mimeType = screenshotPath.endsWith('.jpg') || screenshotPath.endsWith('.jpeg')
                        ? 'image/jpeg' : 'image/png';

                    screenshotHighlights = await askLLMForScreenshotHighlights(vuln, base64, mimeType);
                }
            }

            results.set(vuln.id, {
                textHighlights,
                screenshotHighlights: screenshotHighlights.length > 0 ? screenshotHighlights : undefined,
            });

        } catch (err: any) {
            logger.warn(`Annotation preparation failed for vuln ${vuln.id}`, { error: err.message });
            results.set(vuln.id, {
                textHighlights: detectHighlightPatterns(vuln),
            });
        }
    }

    return results;
}

// ═══════════════════════════════════════════════════════════
//  DESIGN CONSTANTS
// ═══════════════════════════════════════════════════════════

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 50;
const CONTENT_W = PAGE_W - MARGIN * 2;

const C = {
    // Brand
    primary: rgb(0, 0.71, 0.83),       // Cyan #00B5D4
    primaryDark: rgb(0, 0.55, 0.65),
    accent: rgb(0.13, 0.59, 1),         // Blue
    // Backgrounds
    dark: rgb(0.08, 0.08, 0.12),
    darkAlt: rgb(0.12, 0.12, 0.17),
    cardBg: rgb(0.95, 0.96, 0.97),
    codeBg: rgb(0.94, 0.94, 0.96),
    // Text
    white: rgb(1, 1, 1),
    text: rgb(0.15, 0.15, 0.2),
    textLight: rgb(0.45, 0.45, 0.5),
    textMuted: rgb(0.6, 0.6, 0.65),
    // Severity
    critical: rgb(0.86, 0.14, 0.22),
    high: rgb(0.93, 0.35, 0.13),
    medium: rgb(0.92, 0.63, 0.05),
    low: rgb(0.18, 0.50, 0.87),
    info: rgb(0.5, 0.5, 0.55),
    // Lines
    line: rgb(0.85, 0.85, 0.88),
    lineLight: rgb(0.9, 0.9, 0.92),
};

// Burp-style panel colors
const BURP = {
    bg: rgb(0.12, 0.13, 0.16),         // Dark panel background
    headerBg: rgb(0.16, 0.17, 0.21),   // Tab/header area
    text: rgb(0.82, 0.84, 0.86),       // Default text
    method: rgb(0.35, 0.78, 0.95),     // HTTP method (cyan)
    header: rgb(0.65, 0.72, 0.78),     // Header names (muted)
    headerVal: rgb(0.82, 0.84, 0.86),  // Header values
    status2xx: rgb(0.36, 0.82, 0.47),  // 2xx green
    status4xx: rgb(0.93, 0.60, 0.20),  // 4xx orange
    status5xx: rgb(0.90, 0.30, 0.25),  // 5xx red
    lineNum: rgb(0.4, 0.42, 0.46),     // Line numbers
    highlight: rgb(0.95, 0.15, 0.15),  // Red highlight border
    highlightBg: rgb(0.95, 0.15, 0.15),// Red highlight fill (very light)
    string: rgb(0.58, 0.82, 0.45),     // JSON string values (green)
    bodyText: rgb(0.88, 0.72, 0.40),   // Request body (amber)
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function severityColor(sev: string): RGB {
    return (C as any)[sev] || C.info;
}

function severityLabel(sev: string): string {
    return sev.charAt(0).toUpperCase() + sev.slice(1);
}

// ═══════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════

function truncate(text: string, max: number): string {
    if (text.length <= max) return text;
    return text.slice(0, max - 3) + '...';
}

function wrapText(text: string, maxChars: number): string[] {
    if (!text) return [];
    const lines: string[] = [];
    // Split by newlines first
    for (const paragraph of text.split('\n')) {
        const words = paragraph.split(' ');
        let currentLine = '';
        for (const word of words) {
            if ((currentLine + ' ' + word).trim().length > maxChars) {
                if (currentLine) lines.push(currentLine.trim());
                currentLine = word;
            } else {
                currentLine += ' ' + word;
            }
        }
        if (currentLine.trim()) lines.push(currentLine.trim());
    }
    return lines;
}

function formatDate(dateStr: string): string {
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric',
            hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
        });
    } catch {
        return dateStr;
    }
}

function formatDateShort(dateStr: string): string {
    try {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric'
        });
    } catch {
        return dateStr;
    }
}

function calcDuration(start: string, end: string): string {
    try {
        const ms = new Date(end).getTime() - new Date(start).getTime();
        if (ms < 0) return 'N/A';
        const mins = Math.floor(ms / 60000);
        const secs = Math.floor((ms % 60000) / 1000);
        if (mins > 60) {
            const hours = Math.floor(mins / 60);
            const remMins = mins % 60;
            return `${hours}h ${remMins}m ${secs}s`;
        }
        return `${mins}m ${secs}s`;
    } catch {
        return 'N/A';
    }
}

/**
 * Detect patterns to highlight in request/response based on vulnerability type.
 * Returns an array of string patterns that should get red annotation boxes.
 */
function detectHighlightPatterns(vuln: Vulnerability): string[] {
    const patterns: string[] = [];
    const name = (vuln.name || '').toLowerCase();
    const desc = (vuln.description || '').toLowerCase();
    const combined = name + ' ' + desc;

    // SQL Injection patterns
    if (combined.includes('sql') || combined.includes('sqli')) {
        patterns.push(
            "' OR '1'='1", "'OR'1'='1", "' or '1'='1",
            "1=1", "' OR 1=1", "OR 1=1--", "1'='1",
            "UNION SELECT", "union select",
            "' OR ''='", "1; DROP", "sleep(",
            "SLEEP(", "WAITFOR", "benchmark(",
            "' OR TRUE--", "admin'--", "' --",
            "1=1-- -", "' OR '1'='1'--",
        );
    }

    // XSS patterns
    if (combined.includes('xss') || combined.includes('cross-site scripting')) {
        patterns.push(
            '<script>', '</script>', 'alert(', 'onerror=',
            'onload=', '<img src=', 'javascript:', '<svg',
            'document.cookie', 'prompt(', 'confirm(',
        );
    }

    // Authentication / Auth bypass
    if (combined.includes('auth') || combined.includes('bypass') || combined.includes('login')) {
        patterns.push(
            '"token":', '"authentication":', '"jwt":', '"access_token":',
            'HTTP/1.1 200', 'HTTP/2 200', '200 OK',
        );
    }

    // IDOR
    if (combined.includes('idor') || combined.includes('insecure direct')) {
        patterns.push('id=', 'user_id=', 'userId=', 'account_id=');
    }

    // SSRF
    if (combined.includes('ssrf') || combined.includes('server-side request')) {
        patterns.push('http://127.0.0.1', 'http://localhost', 'http://169.254', 'file://');
    }

    // Path traversal / LFI
    if (combined.includes('traversal') || combined.includes('lfi') || combined.includes('local file')) {
        patterns.push('../', '..\\', '/etc/passwd', 'root:x:', 'win.ini');
    }

    // Response time (for blind injections)
    if (combined.includes('time-based') || combined.includes('blind')) {
        patterns.push('Response time:', 'response_time', 'elapsed');
    }

    // Registration / validation
    if (combined.includes('registration') || combined.includes('validation')) {
        patterns.push('201', '200 OK', '"success"', '"status":');
    }

    // Open Redirect
    if (combined.includes('redirect') || combined.includes('open redirect')) {
        patterns.push('redirect=', 'url=http', 'next=http', 'return_url=', 'Location:');
    }

    // Command Injection
    if (combined.includes('command injection') || combined.includes('os command') || combined.includes('rce')) {
        patterns.push('| id', '; id', '`id`', '$(id)', '&& id', '; ls', '; cat');
    }

    // JWT / Token issues
    if (combined.includes('jwt') || combined.includes('token')) {
        patterns.push('eyJ', 'alg":"none', '"alg":"HS256"', 'Bearer ');
    }

    // Also extract specific payload from evidence field
    if (vuln.evidence) {
        const ev = typeof vuln.evidence === 'string' ? vuln.evidence : String(vuln.evidence);
        // Look for quoted strings in evidence that might be payloads
        const quotedMatches = ev.match(/"payload":\s*"([^"]+)"/i) || ev.match(/"injected":\s*"([^"]+)"/i);
        if (quotedMatches && quotedMatches[1]) {
            patterns.push(quotedMatches[1]);
        }
    }

    // Deduplicate and filter out very short patterns
    return [...new Set(patterns)].filter(p => p.length >= 2);
}

function riskRating(vulns: Vulnerability[]): { label: string; color: RGB; score: number } {
    const critical = vulns.filter(v => v.severity === 'critical').length;
    const high = vulns.filter(v => v.severity === 'high').length;
    const medium = vulns.filter(v => v.severity === 'medium').length;

    if (critical > 0) return { label: 'CRITICAL', color: C.critical, score: 10 };
    if (high > 2) return { label: 'HIGH', color: C.high, score: 8 };
    if (high > 0) return { label: 'HIGH', color: C.high, score: 7 };
    if (medium > 3) return { label: 'MEDIUM', color: C.medium, score: 5 };
    if (medium > 0) return { label: 'MEDIUM', color: C.medium, score: 4 };
    if (vulns.length > 0) return { label: 'LOW', color: C.low, score: 2 };
    return { label: 'NONE', color: C.info, score: 0 };
}

// ═══════════════════════════════════════════════════════════
//  PDF BUILDER CLASS
// ═══════════════════════════════════════════════════════════

class ReportBuilder {
    private doc: PDFDocument;
    private page!: PDFPage;
    private fontBold!: PDFFont;
    private fontRegular!: PDFFont;
    private fontMono!: PDFFont;
    private yPos: number = 0;
    private pageNum: number = 0;
    private totalPages: number = 0;
    private pages: PDFPage[] = [];
    private scan: Scan;
    private vulns: Vulnerability[];
    private annotations: Map<number, HighlightResult>;

    constructor(doc: PDFDocument, scan: Scan, vulns: Vulnerability[], annotations?: Map<number, HighlightResult>) {
        this.doc = doc;
        this.scan = scan;
        this.vulns = vulns;
        this.annotations = annotations || new Map();
    }

    async init() {
        this.fontBold = await this.doc.embedFont(StandardFonts.HelveticaBold);
        this.fontRegular = await this.doc.embedFont(StandardFonts.Helvetica);
        this.fontMono = await this.doc.embedFont(StandardFonts.Courier);
    }

    // ── Page Management ──────────────────────────────────

    newPage(): PDFPage {
        this.page = this.doc.addPage([PAGE_W, PAGE_H]);
        this.pages.push(this.page);
        this.pageNum++;
        this.yPos = PAGE_H - MARGIN;
        return this.page;
    }

    ensureSpace(needed: number) {
        if (this.yPos - needed < MARGIN + 30) {
            this.newPage();
            this.drawPageHeader();
        }
    }

    drawPageHeader() {
        // Thin top bar
        this.page.drawRectangle({ x: 0, y: PAGE_H - 28, width: PAGE_W, height: 28, color: C.dark });
        this.page.drawText('PENPARD', { x: MARGIN, y: PAGE_H - 20, size: 9, font: this.fontBold, color: C.primary });
        this.page.drawText('Security Assessment Report', { x: MARGIN + 65, y: PAGE_H - 20, size: 8, font: this.fontRegular, color: C.textMuted });

        const targetText = truncate(this.scan.target, 40);
        const tw = this.fontRegular.widthOfTextAtSize(targetText, 8);
        this.page.drawText(targetText, { x: PAGE_W - MARGIN - tw, y: PAGE_H - 20, size: 8, font: this.fontRegular, color: C.textMuted });

        this.yPos = PAGE_H - MARGIN - 15;
    }

    addPageNumbers() {
        const total = this.pages.length;
        for (let i = 0; i < total; i++) {
            const p = this.pages[i];
            // Skip cover page (index 0)
            if (i === 0) continue;
            const numText = `${i} / ${total - 1}`;
            const tw = this.fontRegular.widthOfTextAtSize(numText, 8);
            p.drawText(numText, { x: PAGE_W - MARGIN - tw, y: 20, size: 8, font: this.fontRegular, color: C.textMuted });

            // Footer line
            p.drawLine({ start: { x: MARGIN, y: 35 }, end: { x: PAGE_W - MARGIN, y: 35 }, thickness: 0.5, color: C.lineLight });
            p.drawText(`Generated by PenPard — ${formatDateShort(new Date().toISOString())}`, { x: MARGIN, y: 20, size: 7, font: this.fontRegular, color: C.textMuted });
        }
    }

    // ── Drawing Primitives ───────────────────────────────

    drawText(text: string, opts: { x?: number; size?: number; font?: PDFFont; color?: RGB; maxWidth?: number } = {}) {
        const x = opts.x ?? MARGIN;
        const size = opts.size ?? 10;
        const font = opts.font ?? this.fontRegular;
        const color = opts.color ?? C.text;
        this.page.drawText(text, { x, y: this.yPos, size, font, color });
    }

    drawWrapped(text: string, opts: { x?: number; size?: number; font?: PDFFont; color?: RGB; maxChars?: number; maxLines?: number; lineHeight?: number } = {}): number {
        const x = opts.x ?? MARGIN;
        const size = opts.size ?? 9;
        const font = opts.font ?? this.fontRegular;
        const color = opts.color ?? C.text;
        const maxChars = opts.maxChars ?? 90;
        const maxLines = opts.maxLines ?? 999;
        const lh = opts.lineHeight ?? (size + 4);

        const lines = wrapText(text, maxChars);
        let drawn = 0;
        for (const line of lines.slice(0, maxLines)) {
            this.ensureSpace(lh);
            this.page.drawText(line, { x, y: this.yPos, size, font, color });
            this.yPos -= lh;
            drawn++;
        }
        if (lines.length > maxLines) {
            this.page.drawText('...', { x, y: this.yPos, size, font, color: C.textMuted });
            this.yPos -= lh;
        }
        return drawn;
    }

    drawLine(opts: { indent?: number; color?: RGB } = {}) {
        const indent = opts.indent ?? 0;
        this.page.drawLine({
            start: { x: MARGIN + indent, y: this.yPos },
            end: { x: PAGE_W - MARGIN, y: this.yPos },
            thickness: 0.5,
            color: opts.color ?? C.line,
        });
        this.yPos -= 8;
    }

    gap(px: number) { this.yPos -= px; }

    // ── Burp-Style Evidence Panel ─────────────────────────

    /**
     * Draws a Burp Suite-style dark panel with request/response text.
     * Automatically detects and highlights key patterns with red boxes.
     * The red box is a border-only rectangle that does NOT obscure text.
     */
    drawBurpPanel(
        label: string,
        text: string,
        highlightPatterns: string[],
        opts: { maxLines?: number; isResponse?: boolean } = {}
    ) {
        if (!text) return;
        const isResp = opts.isResponse ?? false;
        const fontSize = 6.5;
        const lineHeight = 9.5;
        const lineNumWidth = 28;
        const textX = MARGIN + lineNumWidth + 4;
        const headerHeight = 18;
        const maxCharsPerLine = 95;
        const BOTTOM_LIMIT = 45;

        const rawLines = text.split('\n');
        // Show ALL lines — no truncation
        const displayLines = rawLines;

        // Collect highlight rects per-page; flush before page break
        const pageHighlightRects: Array<{ x: number; y: number; w: number; h: number }> = [];

        // Helper: draw the Burp panel header (called at start and after each page break)
        const drawPanelHeader = (continuation: boolean) => {
            this.ensureSpace(headerHeight + lineHeight + 10);
            const blockTop = this.yPos + 6;

            // Header bg
            this.page.drawRectangle({
                x: MARGIN,
                y: blockTop - headerHeight,
                width: CONTENT_W,
                height: headerHeight,
                color: BURP.headerBg,
            });

            // Tab label
            const tabLabel = continuation ? `${label} (continued)` : label;
            const tabLabelW = this.fontBold.widthOfTextAtSize(tabLabel, 8) + 16;
            this.page.drawRectangle({
                x: MARGIN + 4,
                y: blockTop - headerHeight + 2,
                width: tabLabelW,
                height: headerHeight - 4,
                color: BURP.bg,
            });
            this.page.drawText(tabLabel, {
                x: MARGIN + 12,
                y: blockTop - headerHeight + 6,
                size: 8,
                font: this.fontBold,
                color: BURP.method,
            });

            this.yPos = blockTop - headerHeight - 4;
        };

        // Helper: wrap a single long line into multiple sub-lines (no truncation)
        const wrapLine = (line: string): string[] => {
            if (line.length <= maxCharsPerLine) return [line];
            const wrapped: string[] = [];
            let remaining = line;
            while (remaining.length > 0) {
                wrapped.push(remaining.slice(0, maxCharsPerLine));
                remaining = remaining.slice(maxCharsPerLine);
            }
            return wrapped;
        };

        // Draw header for the first page
        drawPanelHeader(false);

        let prevCleanLine = '';

        for (let i = 0; i < displayLines.length; i++) {
            const line = displayLines[i];
            const cleanLine = line.replace(/[\r\t]/g, '  ');
            const subLines = wrapLine(cleanLine);

            for (let si = 0; si < subLines.length; si++) {
                const displayText = subLines[si];

                // Page break: if too close to the bottom, flush highlights and start new page
                if (this.yPos - lineHeight < BOTTOM_LIMIT) {
                    this.flushHighlightRects(pageHighlightRects);
                    this.newPage();
                    this.drawPageHeader();
                    drawPanelHeader(true);
                }

                // Dark background strip for this line
                this.page.drawRectangle({
                    x: MARGIN,
                    y: this.yPos - 3,
                    width: CONTENT_W,
                    height: lineHeight,
                    color: BURP.bg,
                });

                // Line number separator
                this.page.drawLine({
                    start: { x: MARGIN + lineNumWidth, y: this.yPos - 3 },
                    end: { x: MARGIN + lineNumWidth, y: this.yPos - 3 + lineHeight },
                    thickness: 0.5,
                    color: rgb(0.22, 0.24, 0.28),
                });

                // Line number (only for the first sub-line of each original line)
                if (si === 0) {
                    const lineNumStr = String(i + 1).padStart(3, ' ');
                    this.page.drawText(lineNumStr, {
                        x: MARGIN + 4,
                        y: this.yPos,
                        size: 6,
                        font: this.fontMono,
                        color: BURP.lineNum,
                    });
                }

                // Syntax coloring
                let textColor = BURP.text;
                if (i === 0 && si === 0) {
                    textColor = isResp ? this.getStatusColor(cleanLine) : BURP.method;
                } else if (cleanLine.match(/^[A-Za-z-]+:\s/)) {
                    textColor = BURP.header;
                } else if (cleanLine.startsWith('{') || cleanLine.startsWith('[') || cleanLine.startsWith('"')) {
                    textColor = BURP.string;
                } else if (i > 0 && !cleanLine.includes(':') && cleanLine.trim().length > 0 &&
                    !prevCleanLine.match(/^[A-Za-z-]+:\s/)) {
                    textColor = BURP.bodyText;
                }

                // Draw the text — FULL, no truncation
                this.page.drawText(displayText, {
                    x: textX,
                    y: this.yPos,
                    size: fontSize,
                    font: this.fontMono,
                    color: textColor,
                });

                // Detect highlights (on first sub-line where offsets are correct)
                if (si === 0) {
                    for (const pattern of highlightPatterns) {
                        if (!pattern || pattern.length < 2) continue;
                        const idx = cleanLine.toLowerCase().indexOf(pattern.toLowerCase());
                        if (idx !== -1 && idx < displayText.length) {
                            const preText = displayText.slice(0, Math.min(idx, displayText.length));
                            const matchText = displayText.slice(idx, Math.min(idx + pattern.length, displayText.length));
                            if (!matchText) continue;

                            const preWidth = this.fontMono.widthOfTextAtSize(preText, fontSize);
                            const matchWidth = this.fontMono.widthOfTextAtSize(matchText, fontSize);

                            pageHighlightRects.push({
                                x: textX + preWidth - 2,
                                y: this.yPos - 3,
                                w: matchWidth + 4,
                                h: lineHeight + 2,
                            });
                        }
                    }
                }

                this.yPos -= lineHeight;
            }
            prevCleanLine = cleanLine;
        }

        // Flush remaining highlight rects
        this.flushHighlightRects(pageHighlightRects);

        this.yPos -= 8;
    }

    /**
     * Merge overlapping highlight rects and draw them, then clear the array.
     */
    private flushHighlightRects(rects: Array<{ x: number; y: number; w: number; h: number }>) {
        if (rects.length === 0) return;

        rects.sort((a, b) => b.y - a.y || a.x - b.x);
        const merged: typeof rects = [];
        for (const rect of rects) {
            const last = merged[merged.length - 1];
            if (last && last.y === rect.y && rect.x <= last.x + last.w + 2) {
                const newRight = Math.max(last.x + last.w, rect.x + rect.w);
                last.x = Math.min(last.x, rect.x);
                last.w = newRight - last.x;
                last.h = Math.max(last.h, rect.h);
            } else {
                merged.push({ ...rect });
            }
        }

        for (const rect of merged) {
            this.page.drawRectangle({
                x: rect.x, y: rect.y, width: rect.w, height: rect.h,
                color: rgb(0.95, 0.15, 0.15), opacity: 0.08,
            });
            this.page.drawRectangle({
                x: rect.x, y: rect.y, width: rect.w, height: rect.h,
                borderColor: BURP.highlight, borderWidth: 1.5,
            });
        }

        rects.length = 0;
    }

    private getStatusColor(line: string): RGB {
        if (line.match(/\b[23]\d{2}\b/)) return BURP.status2xx;
        if (line.match(/\b4\d{2}\b/)) return BURP.status4xx;
        if (line.match(/\b5\d{2}\b/)) return BURP.status5xx;
        return BURP.text;
    }

    /**
     * Embed a screenshot image into the PDF with optional red highlight boxes.
     * The screenshot is scaled to fit the content width while maintaining aspect ratio.
     * Red highlight rectangles from LLM vision analysis are drawn on top.
     */
    async drawScreenshotWithHighlights(
        screenshotPath: string,
        highlights: Array<{ x: number; y: number; width: number; height: number; label?: string }>,
        caption?: string
    ) {
        try {
            if (!fs.existsSync(screenshotPath)) return;

            const imgBuffer = fs.readFileSync(screenshotPath);
            const isPng = screenshotPath.endsWith('.png');
            const pdfImage = isPng
                ? await this.doc.embedPng(imgBuffer)
                : await this.doc.embedJpg(imgBuffer);

            const imgW = pdfImage.width;
            const imgH = pdfImage.height;

            // Scale to fit content width
            const scale = Math.min(CONTENT_W / imgW, 1);
            const drawW = imgW * scale;
            const drawH = imgH * scale;

            // Cap the height to avoid huge screenshots
            const maxH = 350;
            const finalScale = drawH > maxH ? (maxH / drawH) : 1;
            const finalW = drawW * finalScale;
            const finalH = drawH * finalScale;

            this.ensureSpace(finalH + 30);

            const imgX = MARGIN;
            const imgY = this.yPos - finalH;

            // Draw the screenshot
            this.page.drawImage(pdfImage, {
                x: imgX,
                y: imgY,
                width: finalW,
                height: finalH,
            });

            // Draw a subtle border around the screenshot
            this.page.drawRectangle({
                x: imgX,
                y: imgY,
                width: finalW,
                height: finalH,
                borderColor: rgb(0.3, 0.3, 0.35),
                borderWidth: 0.75,
            });

            // Merge overlapping screenshot highlights before drawing
            const sortedHL = [...highlights].sort((a, b) => a.y - b.y || a.x - b.x);
            const mergedHL: typeof highlights = [];
            for (const hl of sortedHL) {
                const last = mergedHL[mergedHL.length - 1];
                if (last &&
                    hl.x < last.x + last.width && hl.x + hl.width > last.x &&
                    hl.y < last.y + last.height && hl.y + hl.height > last.y) {
                    // Overlapping — merge into bounding box
                    const nx = Math.min(last.x, hl.x);
                    const ny = Math.min(last.y, hl.y);
                    last.width = Math.max(last.x + last.width, hl.x + hl.width) - nx;
                    last.height = Math.max(last.y + last.height, hl.y + hl.height) - ny;
                    last.x = nx;
                    last.y = ny;
                } else {
                    mergedHL.push({ ...hl });
                }
            }

            // Draw red highlight boxes (scaled from original image coordinates)
            const coordScale = (finalW / imgW);
            for (const hl of mergedHL) {
                const rx = imgX + hl.x * coordScale;
                // Image y-axis in PDF is flipped (bottom-up), so:
                const ry = imgY + finalH - (hl.y + hl.height) * coordScale;
                const rw = hl.width * coordScale;
                const rh = hl.height * coordScale;

                // Subtle red fill
                this.page.drawRectangle({
                    x: rx, y: ry, width: rw, height: rh,
                    color: rgb(0.95, 0.15, 0.15),
                    opacity: 0.08,
                });
                // Red border
                this.page.drawRectangle({
                    x: rx, y: ry, width: rw, height: rh,
                    borderColor: BURP.highlight,
                    borderWidth: 2,
                });

                // Label (if provided)
                if (hl.label) {
                    const labelY = ry + rh + 3;
                    if (labelY < imgY + finalH) {
                        this.page.drawText(truncate(hl.label, 40), {
                            x: rx + 2,
                            y: labelY,
                            size: 6,
                            font: this.fontBold,
                            color: BURP.highlight,
                        });
                    }
                }
            }

            this.yPos = imgY - 4;

            // Caption
            if (caption) {
                this.page.drawText(caption, {
                    x: MARGIN,
                    y: this.yPos,
                    size: 7,
                    font: this.fontRegular,
                    color: C.textMuted,
                });
                this.yPos -= 12;
            }

            this.gap(6);
        } catch (err: any) {
            logger.warn('Failed to embed screenshot', { error: err.message });
        }
    }

    // ── Section Drawing Methods ──────────────────────────

    drawLabelValue(label: string, value: string, opts: { labelWidth?: number; size?: number } = {}) {
        const lw = opts.labelWidth ?? 120;
        const size = opts.size ?? 10;
        this.page.drawText(label, { x: MARGIN, y: this.yPos, size, font: this.fontBold, color: C.textLight });
        // Wrap value if too long
        const valLines = wrapText(value, 65);
        for (let i = 0; i < valLines.length; i++) {
            this.page.drawText(valLines[i], { x: MARGIN + lw, y: this.yPos, size, font: this.fontRegular, color: C.text });
            if (i < valLines.length - 1) this.yPos -= (size + 4);
        }
        this.yPos -= (size + 8);
    }

    drawSectionTitle(title: string, opts: { size?: number; icon?: string } = {}) {
        const size = opts.size ?? 16;
        this.ensureSpace(40);
        // Accent bar
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 2, width: 4, height: size + 4, color: C.primary });
        this.page.drawText(title, { x: MARGIN + 14, y: this.yPos, size, font: this.fontBold, color: C.text });
        this.yPos -= (size + 16);
    }

    drawSubsectionTitle(title: string) {
        this.ensureSpace(25);
        this.page.drawText(title, { x: MARGIN, y: this.yPos, size: 11, font: this.fontBold, color: C.primaryDark });
        this.yPos -= 18;
    }

    drawCodeBlock(text: string, opts: { maxLines?: number } = {}) {
        if (!text) return;
        const lh = 11;
        const maxChars = 95;
        const BOTTOM_LIMIT = 45;
        const allLines = text.split('\n');

        this.yPos -= 6;
        for (const line of allLines) {
            const cleanLine = line.replace(/[\r\t]/g, ' ');
            // Wrap long lines instead of truncating
            const subLines: string[] = [];
            if (cleanLine.length <= maxChars) {
                subLines.push(cleanLine);
            } else {
                let rem = cleanLine;
                while (rem.length > 0) {
                    subLines.push(rem.slice(0, maxChars));
                    rem = rem.slice(maxChars);
                }
            }

            for (const sub of subLines) {
                if (this.yPos - lh < BOTTOM_LIMIT) {
                    this.newPage();
                    this.drawPageHeader();
                    this.yPos -= 6;
                }
                // Background strip
                this.page.drawRectangle({
                    x: MARGIN, y: this.yPos - 3,
                    width: CONTENT_W, height: lh,
                    color: C.codeBg,
                });
                this.page.drawText(sub, { x: MARGIN + 8, y: this.yPos, size: 7, font: this.fontMono, color: C.text });
                this.yPos -= lh;
            }
        }
        this.yPos -= 8;
    }

    drawSeverityBadge(severity: string, x: number, y: number) {
        const color = severityColor(severity);
        const label = severity.toUpperCase();
        const badgeW = this.fontBold.widthOfTextAtSize(label, 8) + 14;
        this.page.drawRectangle({ x, y: y - 4, width: badgeW, height: 16, color, borderColor: color, borderWidth: 0 });
        // Rounded effect (small rectangles at corners won't work in pdf-lib, but the solid badge looks clean)
        this.page.drawText(label, { x: x + 7, y, size: 8, font: this.fontBold, color: C.white });
        return badgeW;
    }

    // ═══════════════════════════════════════════════════════
    //  REPORT SECTIONS
    // ═══════════════════════════════════════════════════════

    buildCoverPage() {
        this.newPage();

        // Full-height dark background
        this.page.drawRectangle({ x: 0, y: 0, width: PAGE_W, height: PAGE_H, color: C.dark });

        // Accent line at top
        this.page.drawRectangle({ x: 0, y: PAGE_H - 6, width: PAGE_W, height: 6, color: C.primary });

        // Classification
        const classText = 'CONFIDENTIAL';
        const classW = this.fontBold.widthOfTextAtSize(classText, 10);
        this.page.drawRectangle({ x: PAGE_W - classW - 30, y: PAGE_H - 50, width: classW + 20, height: 22, color: C.critical });
        this.page.drawText(classText, { x: PAGE_W - classW - 20, y: PAGE_H - 44, size: 10, font: this.fontBold, color: C.white });

        // Brand
        this.yPos = PAGE_H - 200;
        this.page.drawText('PENPARD', { x: MARGIN + 10, y: this.yPos, size: 48, font: this.fontBold, color: C.primary });
        this.yPos -= 30;

        // Accent line
        this.page.drawRectangle({ x: MARGIN + 10, y: this.yPos, width: 80, height: 3, color: C.primary });
        this.yPos -= 35;

        // Title
        this.page.drawText('Penetration Test Report', { x: MARGIN + 10, y: this.yPos, size: 26, font: this.fontBold, color: C.white });
        this.yPos -= 35;
        this.page.drawText('Web Application Security Assessment', { x: MARGIN + 10, y: this.yPos, size: 14, font: this.fontRegular, color: C.textMuted });

        // Target info block
        this.yPos = 300;
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 130, width: CONTENT_W, height: 140, color: C.darkAlt });

        const infoY = this.yPos;
        const infoItems = [
            ['TARGET', this.scan.target],
            ['SCAN TYPE', this.scan.type.toUpperCase()],
            ['DATE', formatDate(this.scan.created_at)],
            ['DURATION', this.scan.completed_at ? calcDuration(this.scan.created_at, this.scan.completed_at) : 'In Progress'],
            ['STATUS', this.scan.status.toUpperCase()],
        ];

        let iy = infoY;
        for (const [label, value] of infoItems) {
            this.page.drawText(label, { x: MARGIN + 16, y: iy, size: 8, font: this.fontBold, color: C.primary });
            this.page.drawText(value, { x: MARGIN + 130, y: iy, size: 9, font: this.fontRegular, color: C.white });
            iy -= 24;
        }

        // Risk rating badge
        const risk = riskRating(this.vulns);
        this.page.drawText('OVERALL RISK:', { x: MARGIN + 16, y: 120, size: 10, font: this.fontBold, color: C.textMuted });
        this.page.drawRectangle({ x: MARGIN + 130, y: 114, width: 90, height: 22, color: risk.color });
        this.page.drawText(risk.label, { x: MARGIN + 145, y: 120, size: 12, font: this.fontBold, color: C.white });

        // Scan ID
        this.page.drawText(`Report ID: ${this.scan.id}`, { x: MARGIN + 10, y: 60, size: 8, font: this.fontMono, color: C.textMuted });
        this.page.drawText(`Generated: ${new Date().toISOString()}`, { x: MARGIN + 10, y: 45, size: 8, font: this.fontMono, color: C.textMuted });
    }

    buildTableOfContents() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('Table of Contents');
        this.gap(5);

        const tocItems = [
            ['1', 'Executive Summary'],
            ['2', 'Scope & Methodology'],
            ['3', 'Risk Overview'],
            ['4', 'Findings Summary'],
            ['5', 'Detailed Findings'],
            ['6', 'Remediation Priority'],
            ['7', 'Disclaimer'],
        ];

        for (const [num, title] of tocItems) {
            this.page.drawText(`${num}.`, { x: MARGIN + 10, y: this.yPos, size: 12, font: this.fontBold, color: C.primary });
            this.page.drawText(title, { x: MARGIN + 35, y: this.yPos, size: 12, font: this.fontRegular, color: C.text });
            // Dotted line effect
            const dotsX = MARGIN + 35 + this.fontRegular.widthOfTextAtSize(title, 12) + 10;
            let dx = dotsX;
            while (dx < PAGE_W - MARGIN - 20) {
                this.page.drawText('.', { x: dx, y: this.yPos, size: 10, font: this.fontRegular, color: C.lineLight });
                dx += 5;
            }
            this.yPos -= 24;
        }
    }

    buildExecutiveSummary() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('1. Executive Summary');

        const risk = riskRating(this.vulns);
        const totalVulns = this.vulns.length;
        const counts: Record<string, number> = {};
        for (const sev of SEVERITY_ORDER) {
            counts[sev] = this.vulns.filter(v => v.severity === sev).length;
        }

        // Summary paragraph
        const summaryText = totalVulns === 0
            ? `A security assessment was performed on ${this.scan.target}. No vulnerabilities were identified during the testing period. However, the absence of findings does not guarantee the application is free of vulnerabilities.`
            : `A security assessment was performed on ${this.scan.target} on ${formatDateShort(this.scan.created_at)}. The assessment identified ${totalVulns} vulnerabilit${totalVulns === 1 ? 'y' : 'ies'} across the application: ${counts.critical} Critical, ${counts.high} High, ${counts.medium} Medium, ${counts.low} Low, and ${counts.info} Informational. The overall risk level is assessed as ${risk.label}.`;

        this.drawWrapped(summaryText, { size: 10, lineHeight: 16, maxChars: 85 });
        this.gap(15);

        // Risk score card
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 55, width: CONTENT_W, height: 65, color: C.cardBg });
        this.page.drawText('Overall Risk Assessment', { x: MARGIN + 15, y: this.yPos - 10, size: 10, font: this.fontBold, color: C.text });
        this.drawSeverityBadge(risk.label.toLowerCase(), MARGIN + 180, this.yPos - 10);

        // Severity bar chart
        const barY = this.yPos - 40;
        const barMaxW = CONTENT_W - 30;
        const maxCount = Math.max(...Object.values(counts), 1);
        let barX = MARGIN + 15;
        for (const sev of SEVERITY_ORDER) {
            const w = Math.max((counts[sev] / maxCount) * (barMaxW / SEVERITY_ORDER.length - 6), counts[sev] > 0 ? 20 : 2);
            this.page.drawRectangle({ x: barX, y: barY, width: w, height: 14, color: severityColor(sev) });
            if (counts[sev] > 0) {
                this.page.drawText(String(counts[sev]), { x: barX + w + 3, y: barY + 2, size: 8, font: this.fontBold, color: severityColor(sev) });
            }
            this.page.drawText(severityLabel(sev), { x: barX, y: barY - 12, size: 7, font: this.fontRegular, color: C.textMuted });
            barX += barMaxW / SEVERITY_ORDER.length;
        }

        this.yPos -= 90;

        // Key statistics
        this.drawSubsectionTitle('Key Statistics');
        this.drawLabelValue('Total Vulnerabilities', String(totalVulns));
        this.drawLabelValue('Scan Duration', this.scan.completed_at ? calcDuration(this.scan.created_at, this.scan.completed_at) : 'N/A');
        this.drawLabelValue('Target', this.scan.target);

        if (this.vulns.length > 0) {
            const avgCvss = this.vulns.filter(v => v.cvss_score).reduce((sum, v) => sum + (v.cvss_score || 0), 0) / this.vulns.filter(v => v.cvss_score).length;
            if (!isNaN(avgCvss)) {
                this.drawLabelValue('Average CVSS Score', avgCvss.toFixed(1));
            }
            const highestCvss = Math.max(...this.vulns.filter(v => v.cvss_score).map(v => v.cvss_score!));
            if (isFinite(highestCvss)) {
                this.drawLabelValue('Highest CVSS Score', String(highestCvss));
            }
        }
    }

    buildScopeMethodology() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('2. Scope & Methodology');

        this.drawSubsectionTitle('Scope');
        this.drawWrapped(`The assessment targeted ${this.scan.target}. Testing was performed using PenPard's AI-driven orchestration engine with Burp Suite Professional integration.`, { size: 10, lineHeight: 16 });
        this.gap(10);

        this.drawSubsectionTitle('Methodology');
        this.drawWrapped('The assessment followed a structured, AI-guided methodology aligned with industry standards:', { size: 10, lineHeight: 16 });
        this.gap(8);

        const phases = [
            ['1. Reconnaissance', 'Automated discovery of endpoints, parameters, and application structure via Burp Suite spidering and sitemap analysis.'],
            ['2. Mapping & Analysis', 'AI-driven analysis of application architecture, authentication flows, and potential attack surfaces.'],
            ['3. Vulnerability Testing', 'Targeted testing for OWASP Top 10 vulnerabilities including SQL Injection, Cross-Site Scripting, Broken Access Control, SSRF, IDOR, and more. Payloads were context-aware and AI-generated.'],
            ['4. Exploitation & Validation', 'Each suspected vulnerability was verified with additional payloads by the Recheck Agent to confirm exploitability and reduce false positives.'],
            ['5. Reporting', 'Findings were classified using CVSS 4.0 scoring and mapped to CWE/CVE identifiers where applicable.'],
        ];

        for (const [title, desc] of phases) {
            this.ensureSpace(50);
            this.page.drawText(title, { x: MARGIN + 10, y: this.yPos, size: 10, font: this.fontBold, color: C.text });
            this.yPos -= 16;
            this.drawWrapped(desc, { x: MARGIN + 10, size: 9, lineHeight: 13, maxChars: 85 });
            this.gap(6);
        }

        this.gap(10);
        this.drawSubsectionTitle('Standards Reference');
        const standards = [
            'OWASP Testing Guide v4.2',
            'OWASP Top 10 (2021)',
            'OWASP API Security Top 10 (2023)',
            'CVSS v4.0 Scoring Framework',
            'CWE (Common Weakness Enumeration)',
            'PTES (Penetration Testing Execution Standard)',
        ];
        for (const std of standards) {
            this.ensureSpace(14);
            this.page.drawText('•', { x: MARGIN + 10, y: this.yPos, size: 10, font: this.fontRegular, color: C.primary });
            this.page.drawText(std, { x: MARGIN + 25, y: this.yPos, size: 9, font: this.fontRegular, color: C.text });
            this.yPos -= 16;
        }
    }

    buildRiskOverview() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('3. Risk Overview');

        if (this.vulns.length === 0) {
            this.drawWrapped('No vulnerabilities were identified during this assessment.', { size: 11 });
            return;
        }

        // Severity distribution table
        this.drawSubsectionTitle('Severity Distribution');
        this.gap(5);

        // Table header
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 4, width: CONTENT_W, height: 20, color: C.dark });
        const colX = [MARGIN + 10, MARGIN + 120, MARGIN + 220, MARGIN + 340];
        this.page.drawText('Severity', { x: colX[0], y: this.yPos, size: 9, font: this.fontBold, color: C.white });
        this.page.drawText('Count', { x: colX[1], y: this.yPos, size: 9, font: this.fontBold, color: C.white });
        this.page.drawText('Percentage', { x: colX[2], y: this.yPos, size: 9, font: this.fontBold, color: C.white });
        this.page.drawText('Bar', { x: colX[3], y: this.yPos, size: 9, font: this.fontBold, color: C.white });
        this.yPos -= 22;

        for (const sev of SEVERITY_ORDER) {
            const count = this.vulns.filter(v => v.severity === sev).length;
            const pct = this.vulns.length > 0 ? ((count / this.vulns.length) * 100).toFixed(0) : '0';

            // Zebra striping
            if (SEVERITY_ORDER.indexOf(sev) % 2 === 0) {
                this.page.drawRectangle({ x: MARGIN, y: this.yPos - 4, width: CONTENT_W, height: 20, color: C.cardBg });
            }

            this.drawSeverityBadge(sev, colX[0], this.yPos);
            this.page.drawText(String(count), { x: colX[1], y: this.yPos, size: 10, font: this.fontBold, color: C.text });
            this.page.drawText(`${pct}%`, { x: colX[2], y: this.yPos, size: 10, font: this.fontRegular, color: C.text });

            // Progress bar
            const barWidth = 120;
            this.page.drawRectangle({ x: colX[3], y: this.yPos - 2, width: barWidth, height: 12, color: C.lineLight });
            if (count > 0) {
                const fillW = (count / this.vulns.length) * barWidth;
                this.page.drawRectangle({ x: colX[3], y: this.yPos - 2, width: fillW, height: 12, color: severityColor(sev) });
            }
            this.yPos -= 24;
        }

        // Total row
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 4, width: CONTENT_W, height: 20, color: C.dark });
        this.page.drawText('TOTAL', { x: colX[0], y: this.yPos, size: 9, font: this.fontBold, color: C.white });
        this.page.drawText(String(this.vulns.length), { x: colX[1], y: this.yPos, size: 10, font: this.fontBold, color: C.white });
        this.page.drawText('100%', { x: colX[2], y: this.yPos, size: 10, font: this.fontBold, color: C.white });
        this.yPos -= 35;

        // Top vulnerabilities list
        if (this.vulns.length > 0) {
            this.drawSubsectionTitle('Most Critical Findings');
            const topVulns = [...this.vulns]
                .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
                .slice(0, 5);

            for (let i = 0; i < topVulns.length; i++) {
                const v = topVulns[i];
                this.ensureSpace(20);
                this.page.drawText(`${i + 1}.`, { x: MARGIN + 5, y: this.yPos, size: 10, font: this.fontBold, color: C.primary });
                const bw = this.drawSeverityBadge(v.severity, MARGIN + 25, this.yPos);
                this.page.drawText(truncate(v.name, 55), { x: MARGIN + 30 + bw, y: this.yPos, size: 10, font: this.fontRegular, color: C.text });
                if (v.cvss_score) {
                    const scoreText = `CVSS ${v.cvss_score}`;
                    const stw = this.fontBold.widthOfTextAtSize(scoreText, 9);
                    this.page.drawText(scoreText, { x: PAGE_W - MARGIN - stw, y: this.yPos, size: 9, font: this.fontBold, color: severityColor(v.severity) });
                }
                this.yPos -= 22;
            }
        }
    }

    buildFindingsSummary() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('4. Findings Summary');

        if (this.vulns.length === 0) {
            this.drawWrapped('No vulnerabilities were identified.', { size: 11 });
            return;
        }

        // Summary table header
        this.page.drawRectangle({ x: MARGIN, y: this.yPos - 4, width: CONTENT_W, height: 20, color: C.dark });
        this.page.drawText('#', { x: MARGIN + 5, y: this.yPos, size: 8, font: this.fontBold, color: C.white });
        this.page.drawText('Vulnerability', { x: MARGIN + 25, y: this.yPos, size: 8, font: this.fontBold, color: C.white });
        this.page.drawText('Severity', { x: MARGIN + 300, y: this.yPos, size: 8, font: this.fontBold, color: C.white });
        this.page.drawText('CVSS', { x: MARGIN + 380, y: this.yPos, size: 8, font: this.fontBold, color: C.white });
        this.page.drawText('CWE', { x: MARGIN + 430, y: this.yPos, size: 8, font: this.fontBold, color: C.white });
        this.yPos -= 22;

        // Sort: critical first
        const sorted = [...this.vulns].sort((a, b) => {
            return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        });

        for (let i = 0; i < sorted.length; i++) {
            const v = sorted[i];
            this.ensureSpace(22);

            if (i % 2 === 0) {
                this.page.drawRectangle({ x: MARGIN, y: this.yPos - 4, width: CONTENT_W, height: 18, color: C.cardBg });
            }

            this.page.drawText(String(i + 1), { x: MARGIN + 5, y: this.yPos, size: 8, font: this.fontRegular, color: C.textMuted });
            this.page.drawText(truncate(v.name, 45), { x: MARGIN + 25, y: this.yPos, size: 8, font: this.fontRegular, color: C.text });
            this.drawSeverityBadge(v.severity, MARGIN + 300, this.yPos);
            this.page.drawText(v.cvss_score ? String(v.cvss_score) : '-', { x: MARGIN + 385, y: this.yPos, size: 9, font: this.fontBold, color: C.text });
            this.page.drawText(v.cwe ? `CWE-${v.cwe}` : '-', { x: MARGIN + 430, y: this.yPos, size: 8, font: this.fontRegular, color: C.textMuted });
            this.yPos -= 20;
        }
    }

    async buildDetailedFindings() {
        const sorted = [...this.vulns].sort((a, b) => {
            return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        });

        // Section title on new page
        this.newPage();
        this.drawPageHeader();
        this.drawSectionTitle('5. Detailed Findings');
        this.gap(5);

        for (let i = 0; i < sorted.length; i++) {
            const v = sorted[i];

            // Each finding starts with enough space or a new page
            this.ensureSpace(200);

            // Finding header
            this.page.drawRectangle({ x: MARGIN, y: this.yPos - 6, width: CONTENT_W, height: 28, color: C.dark });
            this.page.drawText(`${i + 1}.`, { x: MARGIN + 8, y: this.yPos, size: 11, font: this.fontBold, color: C.primary });
            const bw = this.drawSeverityBadge(v.severity, MARGIN + 30, this.yPos);
            this.page.drawText(truncate(v.name, 50), { x: MARGIN + 38 + bw, y: this.yPos, size: 11, font: this.fontBold, color: C.white });
            this.yPos -= 36;

            // Metadata row
            const meta: string[] = [];
            if (v.cvss_score) meta.push(`CVSS: ${v.cvss_score}`);
            if (v.cvss_vector) meta.push(`Vector: ${truncate(v.cvss_vector, 40)}`);
            if (v.cwe) meta.push(`CWE-${v.cwe}`);
            if (v.cve) meta.push(v.cve);
            if (meta.length > 0) {
                this.page.drawText(meta.join('  |  '), { x: MARGIN, y: this.yPos, size: 8, font: this.fontMono, color: C.textLight });
                this.yPos -= 18;
            }

            // Description
            if (v.description) {
                this.drawSubsectionTitle('Description & Impact');
                this.drawWrapped(v.description, { size: 9, lineHeight: 14, maxChars: 90, maxLines: 20 });
                this.gap(10);
            }

            // ── Burp Suite-style evidence panels with LLM highlights ──
            const annotation = this.annotations.get(v.id);
            const highlightPatterns = annotation?.textHighlights || detectHighlightPatterns(v);

            // Show highlight source indicator
            if (annotation?.textHighlights && annotation.textHighlights.length > 0) {
                this.page.drawText('AI-Analyzed Evidence Highlights', {
                    x: MARGIN,
                    y: this.yPos,
                    size: 7,
                    font: this.fontBold,
                    color: C.primary,
                });
                this.yPos -= 12;
            }

            // HTTP Request evidence (Burp-style) — FULL content, no truncation
            if (v.request) {
                this.drawBurpPanel('Request', v.request, highlightPatterns, { maxLines: Infinity });
            }

            // HTTP Response evidence (Burp-style) — FULL content, no truncation
            if (v.response) {
                this.drawBurpPanel('Response', v.response, highlightPatterns, { maxLines: Infinity, isResponse: true });
            }

            // Additional evidence — FULL content, no truncation
            if (v.evidence) {
                let evidenceText: string;
                if (typeof v.evidence === 'string') {
                    try {
                        const parsed = JSON.parse(v.evidence);
                        evidenceText = typeof parsed === 'object' ? JSON.stringify(parsed, null, 2) : String(parsed);
                    } catch {
                        evidenceText = v.evidence;
                    }
                } else if (typeof v.evidence === 'object') {
                    evidenceText = JSON.stringify(v.evidence, null, 2);
                } else {
                    evidenceText = String(v.evidence);
                }

                if (evidenceText && evidenceText !== '{}' && evidenceText !== 'null') {
                    this.drawBurpPanel('Evidence', evidenceText, highlightPatterns, { maxLines: Infinity });
                }
            }

            // ── Screenshot with LLM vision highlights ──
            const screenshotPath = v.screenshot_path;
            if (screenshotPath && fs.existsSync(screenshotPath)) {
                this.ensureSpace(180);
                this.drawSubsectionTitle('Page Screenshot');
                await this.drawScreenshotWithHighlights(
                    screenshotPath,
                    annotation?.screenshotHighlights || [],
                    `Captured from ${this.scan.target} — AI-annotated highlight regions`
                );
            }

            // Remediation
            if (v.remediation) {
                this.ensureSpace(50);
                this.drawSubsectionTitle('Remediation');
                // Green left bar for remediation
                const remStartY = this.yPos;
                this.page.drawRectangle({ x: MARGIN, y: this.yPos - 60, width: 3, height: 70, color: rgb(0.15, 0.68, 0.38) });
                this.drawWrapped(v.remediation, { x: MARGIN + 12, size: 9, lineHeight: 13, maxChars: 85, maxLines: 10 });
                this.gap(8);
            }

            // Separator between findings
            if (i < sorted.length - 1) {
                this.ensureSpace(20);
                this.drawLine({ color: C.line });
                this.gap(10);
            }
        }
    }

    buildRemediationPriority() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('6. Remediation Priority');

        if (this.vulns.length === 0) {
            this.drawWrapped('No remediation steps required — no vulnerabilities were found.', { size: 11 });
            return;
        }

        this.drawWrapped('The following prioritization is recommended based on severity and potential business impact:', { size: 10, lineHeight: 16 });
        this.gap(15);

        const priorities = [
            { label: 'Immediate (24-48 hours)', sevs: ['critical'], color: C.critical, desc: 'These vulnerabilities pose an immediate threat and can lead to full system compromise, data breach, or service disruption.' },
            { label: 'Short-term (1-2 weeks)', sevs: ['high'], color: C.high, desc: 'High-severity findings that could be exploited to gain unauthorized access or extract sensitive data.' },
            { label: 'Medium-term (1-3 months)', sevs: ['medium'], color: C.medium, desc: 'Moderate-risk issues that should be addressed as part of the regular development cycle.' },
            { label: 'Long-term / Hardening', sevs: ['low', 'info'], color: C.low, desc: 'Low-risk findings and informational items for defense-in-depth improvements.' },
        ];

        for (const p of priorities) {
            const count = this.vulns.filter(v => p.sevs.includes(v.severity)).length;
            if (count === 0) continue;

            this.ensureSpace(60);
            this.page.drawRectangle({ x: MARGIN, y: this.yPos + 2, width: 4, height: 14, color: p.color });
            this.page.drawText(`${p.label} — ${count} finding${count > 1 ? 's' : ''}`, { x: MARGIN + 14, y: this.yPos, size: 11, font: this.fontBold, color: C.text });
            this.yPos -= 18;
            this.drawWrapped(p.desc, { x: MARGIN + 14, size: 9, lineHeight: 13, maxChars: 80 });
            this.gap(8);

            // List affected vulns
            const affected = this.vulns.filter(v => p.sevs.includes(v.severity));
            for (const v of affected) {
                this.ensureSpace(16);
                this.page.drawText('•', { x: MARGIN + 20, y: this.yPos, size: 9, font: this.fontRegular, color: p.color });
                this.page.drawText(truncate(v.name, 70), { x: MARGIN + 32, y: this.yPos, size: 9, font: this.fontRegular, color: C.text });
                this.yPos -= 16;
            }
            this.gap(12);
        }
    }

    buildDisclaimer() {
        this.newPage();
        this.drawPageHeader();

        this.drawSectionTitle('7. Disclaimer');
        this.gap(5);

        const disclaimerParagraphs = [
            'This report was generated with the autonomous assistance of PenPard, an open-source AI-powered penetration testing tool available at github.com/onurgule/penpard. PenPard uses Large Language Models integrated with Burp Suite Professional to plan, execute, and report security assessments.',
            'This report is provided "as is" for informational purposes only. The findings in this report are based on the state of the application at the time of testing and may not reflect the current security posture.',
            'While every effort has been made to ensure accuracy, AI-assisted automated testing may not identify all vulnerabilities. The absence of findings does not guarantee the application is free from security issues. It is recommended that findings be validated by qualified security professionals before implementing remediation measures in production environments.',
            'This report is confidential and intended solely for the authorized recipient. Unauthorized distribution, reproduction, or use of this report is strictly prohibited.',
            'The testing was conducted with proper authorization. The assessors assume no liability for any damage, loss, or disruption resulting from the use of information contained in this report.',
        ];

        for (const para of disclaimerParagraphs) {
            this.drawWrapped(para, { size: 9, lineHeight: 14, maxChars: 88 });
            this.gap(12);
        }

        // End marker
        this.gap(30);
        this.drawLine({ color: C.primary });
        this.gap(10);
        this.page.drawText('— End of Report —', {
            x: (PAGE_W - this.fontBold.widthOfTextAtSize('— End of Report —', 12)) / 2,
            y: this.yPos, size: 12, font: this.fontBold, color: C.primary
        });
    }

    // ═══════════════════════════════════════════════════════
    //  MAIN BUILD
    // ═══════════════════════════════════════════════════════

    async build(): Promise<Uint8Array> {
        await this.init();

        this.buildCoverPage();
        this.buildTableOfContents();
        this.buildExecutiveSummary();
        this.buildScopeMethodology();
        this.buildRiskOverview();
        this.buildFindingsSummary();
        await this.buildDetailedFindings();
        this.buildRemediationPriority();
        this.buildDisclaimer();

        // Add page numbers to all pages (after all pages are created)
        this.addPageNumbers();

        return this.doc.save();
    }
}

// ═══════════════════════════════════════════════════════════
//  EXPORT
// ═══════════════════════════════════════════════════════════

export async function generatePdfReport(
    scan: Scan,
    vulnerabilities: Vulnerability[]
): Promise<string> {
    logger.info('Generating PDF report', { scanId: scan.id, vulnCount: vulnerabilities.length });

    // ── Pre-process: LLM highlight analysis + screenshot capture ──
    // This runs before PDF generation so the builder has all data ready
    let annotations: Map<number, HighlightResult> = new Map();
    try {
        logger.info('Starting AI-powered annotation analysis for report...');
        annotations = await prepareVulnerabilityAnnotations(scan, vulnerabilities);
        logger.info(`Annotation analysis complete: ${annotations.size} vulnerabilities analyzed`);
    } catch (err: any) {
        logger.warn('Annotation pre-processing failed, using fallback patterns', { error: err.message });
    }

    const pdfDoc = await PDFDocument.create();

    // PDF metadata
    pdfDoc.setTitle(`PenPard Security Assessment — ${scan.target}`);
    pdfDoc.setAuthor('PenPard — AI-Powered Penetration Testing');
    pdfDoc.setSubject(`Penetration Test Report for ${scan.target}`);
    pdfDoc.setCreator('PenPard v1.0');
    pdfDoc.setProducer('PenPard Report Engine');
    pdfDoc.setCreationDate(new Date());

    const builder = new ReportBuilder(pdfDoc, scan, vulnerabilities, annotations);
    const pdfBytes = await builder.build();

    const reportPath = path.join(REPORTS_DIR, `report-${scan.id}.pdf`);
    fs.writeFileSync(reportPath, pdfBytes);

    logger.info('PDF report generated', { scanId: scan.id, path: reportPath, pages: pdfDoc.getPageCount() });

    return reportPath;
}
