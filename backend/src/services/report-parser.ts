/**
 * Report Parser Service — PDF/DOCX text extraction + LLM-powered structuring
 * Part of the Red Team Mind Reconstruction Engine
 */

import fs from 'fs';
import path from 'path';
import { llmRuntime } from './llm/LlmRuntime';
import { buildJsonObjectResponseFormat, parseStructuredJsonResponse } from './llm/LlmStructuredOutput';
import { logger } from '../utils/logger';
import { saveAnalysisLog } from '../db/init';

// ── Interfaces ──

export interface ParsedReportMetadata {
    title: string;
    author?: string;
    date?: string;
    scope?: string;
    page_count?: number;
}

export interface ParsedFinding {
    title: string;
    severity: string;
    cvss?: string;
    description: string;
    poc_steps: string[];
    raw_http_requests: string[];
    payloads: string[];
    evidence: string[];
    recommendation: string;
}

export interface ParsedReport {
    report_metadata: ParsedReportMetadata;
    findings: ParsedFinding[];
    raw_text_length: number;
}

// ── Text Extraction ──

async function extractTextFromPDF(filePath: string): Promise<string> {
    const pdfParse = require('pdf-parse');
    const buffer = fs.readFileSync(filePath);
    const data = await pdfParse(buffer);
    return data.text || '';
}

function extractTextFromDOCX(filePath: string): string {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(filePath);
    const docEntry = zip.getEntry('word/document.xml');
    if (!docEntry) {
        throw new Error('Invalid DOCX file: word/document.xml not found');
    }
    const xmlContent = docEntry.getData().toString('utf-8');
    // Strip XML tags, keep text content
    const text = xmlContent
        .replace(/<w:br[^>]*\/>/gi, '\n')
        .replace(/<w:p[^>]*>/gi, '\n')
        .replace(/<w:tab[^>]*\/>/gi, '\t')
        .replace(/<[^>]+>/g, '')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/\n{3,}/g, '\n\n')
        .trim();
    return text;
}

// ── LLM-Powered Structuring ──

const EXTRACTION_PROMPT = `You are a security report parser. Given raw text from a penetration test report, extract ALL vulnerability findings into structured JSON.

For each finding, extract:
- title: The vulnerability name/title
- severity: "critical", "high", "medium", "low", or "info"
- cvss: CVSS score/vector if mentioned (e.g. "8.1" or "CVSS:3.1/AV:N/AC:L/...")
- description: Full description of the vulnerability
- poc_steps: Array of step-by-step proof of concept instructions
- raw_http_requests: Array of raw HTTP requests/responses (exact text if present)
- payloads: Array of payloads used in testing
- evidence: Array of evidence items (output snippets, observations)
- recommendation: Remediation recommendation

Also extract report metadata:
- title: Report title
- author: Author name(s)
- date: Report date
- scope: Target scope/URLs

IMPORTANT:
- Extract EVERY finding from the report, do not skip any
- If a field is not present in the report, use empty string or empty array
- Preserve raw HTTP requests exactly as written
- Include all payloads mentioned

Respond with ONLY valid JSON in this exact format:
{
  "report_metadata": { "title": "", "author": "", "date": "", "scope": "" },
  "findings": [
    {
      "title": "",
      "severity": "",
      "cvss": "",
      "description": "",
      "poc_steps": [],
      "raw_http_requests": [],
      "payloads": [],
      "evidence": [],
      "recommendation": ""
    }
  ]
}`;

function chunkText(text: string, maxChunkSize: number = 25000): string[] {
    if (text.length <= maxChunkSize) return [text];

    const chunks: string[] = [];
    let remaining = text;

    while (remaining.length > 0) {
        if (remaining.length <= maxChunkSize) {
            chunks.push(remaining);
            break;
        }

        // Try to split at paragraph/section boundaries
        let splitIdx = remaining.lastIndexOf('\n\n', maxChunkSize);
        if (splitIdx < maxChunkSize * 0.5) {
            splitIdx = remaining.lastIndexOf('\n', maxChunkSize);
        }
        if (splitIdx < maxChunkSize * 0.5) {
            splitIdx = maxChunkSize;
        }

        chunks.push(remaining.substring(0, splitIdx));
        remaining = remaining.substring(splitIdx).trim();
    }

    return chunks;
}

function parseJSONResponse(response: { text: string; finishReason?: string | null }): any {
    return parseStructuredJsonResponse<any>(response, { label: 'Report parser response' });
}

// ── Main Parser ──

export class ReportParserService {

    async parseReport(filePath: string, analysisId: string, userId?: number): Promise<ParsedReport> {
        const ext = path.extname(filePath).toLowerCase();

        // Step 1: Extract raw text
        this.log(analysisId, '📄 Extracting text from report...');
        let rawText: string;

        if (ext === '.pdf') {
            rawText = await extractTextFromPDF(filePath);
        } else if (ext === '.docx') {
            rawText = extractTextFromDOCX(filePath);
        } else {
            throw new Error(`Unsupported file format: ${ext}. Only PDF and DOCX are supported.`);
        }

        if (!rawText || rawText.trim().length < 50) {
            throw new Error('Report appears to be empty or contains too little text to analyze.');
        }

        this.log(analysisId, `📊 Extracted ${rawText.length} characters of text`);

        // Step 2: Chunk text if needed
        const chunks = chunkText(rawText);
        this.log(analysisId, `📦 Split into ${chunks.length} chunk(s) for LLM processing`);

        // Step 3: LLM extraction
        let allFindings: ParsedFinding[] = [];
        let metadata: ParsedReportMetadata = { title: '' };

        for (let i = 0; i < chunks.length; i++) {
            this.log(analysisId, `🤖 Processing chunk ${i + 1}/${chunks.length} with LLM...`);

            const chunkInstruction = chunks.length > 1
                ? `\n\nThis is chunk ${i + 1} of ${chunks.length} of the report. Extract any findings present in this chunk.`
                : '';

            try {
                const response = await llmRuntime.generate({
                    systemPrompt: EXTRACTION_PROMPT,
                    userPrompt: `${chunks[i]}${chunkInstruction}`,
                    responseFormat: buildJsonObjectResponseFormat(),
                    reasoningMode: 'disabled',
                }, {
                    analysisId,
                    userId,
                    callSite: 'report_parser_extraction',
                    context: 'report-parser-extraction',
                });

                const parsed = parseJSONResponse(response);

                if (parsed.findings && Array.isArray(parsed.findings)) {
                    allFindings.push(...parsed.findings);
                }

                if (i === 0 && parsed.report_metadata) {
                    metadata = parsed.report_metadata;
                }
            } catch (error: any) {
                this.log(analysisId, `⚠️ Error processing chunk ${i + 1}: ${error.message}`);
                logger.error(`Report parser chunk ${i + 1} failed`, { error: error.message, analysisId });
            }
        }

        this.log(analysisId, `✅ Extracted ${allFindings.length} findings from report`);

        return {
            report_metadata: metadata,
            findings: allFindings,
            raw_text_length: rawText.length,
        };
    }

    private log(analysisId: string, message: string) {
        const timestamp = new Date().toLocaleTimeString();
        const logMsg = `[${timestamp}] ${message}`;
        saveAnalysisLog(analysisId, logMsg);
        logger.info(message, { analysisId });
    }
}

export const reportParser = new ReportParserService();
