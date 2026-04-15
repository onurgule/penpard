/**
 * Report Learning Agent — Red Team Report Learning Engine
 * 
 * 3-Phase Analysis:
 * 1. Extract & Normalize findings
 * 2. Derive TTPs per finding (tactics, templates, verification criteria)
 * 3. Build/update aggregated mindset profile
 */

import { v4 as uuidv4 } from 'uuid';
import { llmRuntime } from '../services/llm/LlmRuntime';
import { logger } from '../utils/logger';
import {
    saveAnalysisLog,
    updateAnalysisStatus,
    updateAnalysisFinding,
    updateAnalysisBehavioralProfile,
    getAnalysisFindings,
    addTTP,
    getActiveTTPs,
} from '../db/init';
import { mindsetService } from '../services/mindset-service';
import { buildJsonObjectResponseFormat, parseStructuredJsonResponse } from '../services/llm/LlmStructuredOutput';
import type { ParsedReport, ParsedFinding } from '../services/report-parser';

// ── Prompts ──

const TTP_EXTRACTION_PROMPT = `You are a security tactics analyst. Given a vulnerability finding with PoC, payloads, and HTTP requests, derive a reusable TTP (Tactic, Technique, Procedure) that can be applied to OTHER applications.

Extract:
- vulnerability_class: IDOR, SQLi, XSS, SSRF, Auth_Bypass, Privilege_Escalation, Business_Logic, Path_Traversal, XXE, CSRF, Info_Disclosure, etc.
- discovery_strategy: array of ordered steps (e.g. ["enumerate_object_ids","swap_auth_context","compare_response"])
- preconditions: {auth: bool, roles: ["user"], notes: "needs two accounts"}
- entrypoint_hints: {endpoints: ["/api/resource/{id}"], params: ["id","userId","orderId"]}
- request_templates: [{method, path, headers:[], body}] with {variable} slots for dynamic parts
- payload_templates: [{type:"param"|"header"|"body", name, generator:"increment|uuid_variant|auth_swap|sqli_boolean|xss_reflect", constraints:"..."}]
- verification_criteria: ["Response contains other user data", "HTTP 200 where should be 403", "SQL error in response"]
- confidence: 0.0-1.0 (how generalizable is this to other apps?)
- generalization_notes: one sentence on how to apply this pattern elsewhere

IMPORTANT:
- Make templates GENERIC. Replace specific IDs, tokens, domains with {variable} placeholders.
- The TTP should be useful for testing DIFFERENT applications, not just the one in the report.
- If the finding is too app-specific to generalize, set confidence low (0.2-0.4).

Respond with ONLY valid JSON matching this schema exactly.`;

const MINDSET_PROFILE_PROMPT = `You are a security methodology analyst. Given ALL TTPs (tactics/techniques/procedures) derived from multiple pentest reports, build an aggregated mindset profile.

Analyze:
1. What vulnerability classes are most common?
2. What discovery strategies are preferred?
3. What are the typical test sequences? (e.g. recon → parameter discovery → tamper → compare)
4. How sophisticated is the overall approach? (1-10)
5. What tools were likely used based on patterns?

Respond with ONLY valid JSON:
{
  "common_vuln_classes": [{"class": "IDOR", "count": 5}, ...],
  "preferred_strategies": ["enumerate_ids", "swap_auth", ...],
  "typical_sequences": ["recon → param_discovery → tamper → compare", ...],
  "sophistication_score": 7,
  "likely_tools": ["Burp Suite", "sqlmap", ...],
  "testing_style": "systematic|opportunistic|hybrid",
  "focus_areas": ["authorization", "input_validation", ...]
}`;

// ── Helper ──

// ── Agent ──

export class ReportLearningAgent {
    private analysisId: string;
    private readonly userId?: number;
    private logs: string[] = [];
    private isRunning: boolean = false;

    constructor(analysisId: string, userId?: number) {
        this.analysisId = analysisId;
        this.userId = userId;
    }

    async analyze(parsedReport: ParsedReport): Promise<void> {
        this.isRunning = true;
        const findingCount = parsedReport.findings.length;

        try {
            // Phase 1: Validate & normalize extracted findings
            this.log(`📋 Phase 1: Validating ${findingCount} extracted findings...`);
            const dbFindings = getAnalysisFindings(this.analysisId);

            for (let i = 0; i < dbFindings.length; i++) {
                const f = dbFindings[i];
                // Normalize severity
                const severity = (f.severity || 'medium').toLowerCase();
                if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
                    updateAnalysisFinding(f.id, { severity: 'medium' });
                }
                this.log(`  ✓ [${i + 1}/${findingCount}] ${f.title} [${severity}]`);
            }

            // Phase 2: Derive TTPs per finding
            this.log(`🧬 Phase 2: Deriving TTPs from ${findingCount} findings...`);

            for (let i = 0; i < dbFindings.length; i++) {
                if (!this.isRunning) break;
                const dbFinding = dbFindings[i];
                const parsedFinding = parsedReport.findings[i];

                this.log(`  🔬 [${i + 1}/${findingCount}] Deriving TTP: ${dbFinding.title}`);

                try {
                    await this.deriveTTP(dbFinding, parsedFinding);
                } catch (error: any) {
                    this.log(`  ⚠️ Failed to derive TTP for "${dbFinding.title}": ${error.message}`);
                }

                await this.delay(1000);
            }

            // Phase 3: Build/update aggregated mindset profile
            if (this.isRunning) {
                this.log(`📊 Phase 3: Building mindset profile...`);
                await this.buildMindsetProfile(parsedReport);
            }

            this.log(`✅ Learning complete. Derived TTPs from ${findingCount} findings.`);
            updateAnalysisStatus(this.analysisId, 'completed');

        } catch (error: any) {
            this.log(`❌ Analysis failed: ${error.message}`);
            updateAnalysisStatus(this.analysisId, 'failed', error.message);
            throw error;
        } finally {
            this.isRunning = false;
        }
    }

    // ── Phase 2: TTP Derivation ──

    private async deriveTTP(dbFinding: any, parsedFinding: ParsedFinding): Promise<void> {
        const context = this.buildFindingContext(parsedFinding);

        const response = await llmRuntime.generate({
            systemPrompt: TTP_EXTRACTION_PROMPT,
            userPrompt: context,
            responseFormat: buildJsonObjectResponseFormat(),
            reasoningMode: 'disabled',
        }, {
            analysisId: this.analysisId,
            userId: this.userId,
            callSite: 'red_team_ttp_derivation',
            context: 'red-team-ttp-derivation',
        });

        const result = parseStructuredJsonResponse<any>(response, { label: `TTP derivation for ${dbFinding.title}` });
        if (!result || !result.vulnerability_class) {
            this.log(`  ⚠️ Could not derive TTP for "${dbFinding.title}"`);
            return;
        }

        const ttpId = uuidv4();

        // Save TTP to library
        addTTP({
            id: ttpId,
            sourceAnalysisId: this.analysisId,
            sourceFindingId: dbFinding.id,
            title: dbFinding.title,
            vulnerabilityClass: result.vulnerability_class,
            discoveryStrategyJson: JSON.stringify(result.discovery_strategy || []),
            preconditionsJson: JSON.stringify(result.preconditions || {}),
            entrypointHintsJson: JSON.stringify(result.entrypoint_hints || {}),
            requestTemplatesJson: JSON.stringify(result.request_templates || []),
            payloadTemplatesJson: JSON.stringify(result.payload_templates || []),
            verificationCriteriaJson: JSON.stringify(result.verification_criteria || []),
            confidence: typeof result.confidence === 'number' ? result.confidence : 0.5,
            generalizationNotes: result.generalization_notes || null,
        });

        // Update finding with derived info
        updateAnalysisFinding(dbFinding.id, {
            discovery_method: result.vulnerability_class,
            reasoning_chain_json: JSON.stringify(result.discovery_strategy || []),
        });

        const strategy = (result.discovery_strategy || []).join(' → ');
        this.log(`  ✓ TTP: ${result.vulnerability_class} | Strategy: ${strategy} | Confidence: ${Math.round((result.confidence || 0.5) * 100)}%`);
    }

    // ── Phase 3: Mindset Profile ──

    private async buildMindsetProfile(parsedReport: ParsedReport): Promise<void> {
        // Use the mindset service to rebuild from all TTPs
        try {
            const profile = await mindsetService.rebuildProfile();

            // Also store a summary as the behavioral profile for this analysis
            updateAnalysisBehavioralProfile(this.analysisId, JSON.stringify(profile));

            this.log(`✓ Mindset Profile: ${profile.total_ttps} TTPs, ${profile.common_vuln_classes.length} vuln classes, sophistication: ${profile.sophistication_score}/10`);
            if (profile.common_vuln_classes.length > 0) {
                this.log(`  Top classes: ${profile.common_vuln_classes.slice(0, 5).map(c => `${c.class}(${c.count})`).join(', ')}`);
            }
            if (profile.preferred_sequences.length > 0) {
                this.log(`  Sequences: ${profile.preferred_sequences.slice(0, 3).join(' | ')}`);
            }
        } catch (error: any) {
            this.log(`⚠️ Mindset profile build failed: ${error.message}`);
        }
    }

    // ── Utilities ──

    private buildFindingContext(finding: ParsedFinding): string {
        return `Vulnerability: ${finding.title}
Severity: ${finding.severity}
CVSS: ${finding.cvss || 'N/A'}

Description:
${finding.description}

Proof of Concept Steps:
${finding.poc_steps.map((s: string, i: number) => `${i + 1}. ${s}`).join('\n') || 'None provided'}

Raw HTTP Requests:
${finding.raw_http_requests.slice(0, 5).join('\n---\n') || 'None provided'}

Payloads Used:
${finding.payloads.join('\n') || 'None provided'}

Evidence:
${finding.evidence.join('\n') || 'None provided'}`;
    }

    stop(): void {
        this.isRunning = false;
        this.log('⏹️ Analysis stopped by user');
    }

    getLogs(): string[] {
        return this.logs;
    }

    private log(message: string) {
        const timestamp = new Date().toLocaleTimeString();
        const logMsg = `[${timestamp}] ${message}`;
        this.logs.push(logMsg);
        saveAnalysisLog(this.analysisId, logMsg);
        logger.info(message, { analysisId: this.analysisId });
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
