/**
 * Report Analysis Routes — Red Team Report Learning Engine
 * Upload, analyze, retrieve findings, TTPs, and mindset profile
 */

import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';
import {
    createAnalysis,
    getAnalysis,
    getUserAnalyses,
    updateAnalysisStatus,
    updateAnalysisMetadata,
    addAnalysisFinding,
    getAnalysisFindings,
    getAnalysisLogs,
    deleteAnalysis,
    getAllTTPs,
    getTTPById,
    getTTPsByAnalysis,
    toggleTTPActive,
    getMindsetProfile,
} from '../db/init';
import { reportParser } from '../services/report-parser';
import { ReportLearningAgent } from '../agents/RedTeamReconstructionAgent';
import { llmRuntime } from '../services/llm/LlmRuntime';
import { llmProvider } from '../services/LLMProviderService';
import { getCachedPlaybook, cachePlaybook } from '../db/init';

const router = Router();

// ── Multer setup for report uploads ──

const uploadsDir = path.join(__dirname, '../../uploads/reports');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadsDir,
    filename(req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, `report-${uuidv4()}${ext}`);
    },
});

const upload = multer({
    storage,
    fileFilter(req, file, cb) {
        const allowedTypes = ['.pdf', '.docx'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF and DOCX files are allowed'));
        }
    },
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
});

// ══════════════════════════════════════════════════════
// REPORT UPLOAD & ANALYSIS
// ══════════════════════════════════════════════════════

router.post('/upload', authenticateToken, upload.single('report'), async (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ error: true, message: 'No report file uploaded' });
        }

        const analysisId = uuidv4();

        createAnalysis({
            id: analysisId,
            userId: user.id,
            filename: file.originalname,
            filePath: file.path,
        });

        // Start async analysis pipeline
        (async () => {
            try {
                updateAnalysisStatus(analysisId, 'parsing');

                // Step 1: Parse report
                const parsedReport = await reportParser.parseReport(file.path, analysisId, user.id);

                // Save metadata
                updateAnalysisMetadata(analysisId, JSON.stringify(parsedReport.report_metadata));

                // Save extracted findings to DB
                for (const finding of parsedReport.findings) {
                    addAnalysisFinding({
                        analysisId,
                        title: finding.title,
                        severity: finding.severity,
                        cvssScore: finding.cvss ? parseFloat(finding.cvss) : undefined,
                        cvssVector: finding.cvss && finding.cvss.includes('CVSS:') ? finding.cvss : undefined,
                        description: finding.description,
                        pocStepsJson: JSON.stringify(finding.poc_steps),
                        rawHttpRequestsJson: JSON.stringify(finding.raw_http_requests),
                        payloadsJson: JSON.stringify(finding.payloads),
                        evidenceJson: JSON.stringify(finding.evidence),
                        recommendation: finding.recommendation,
                    });
                }

                // Step 2: Run learning agent (TTP derivation + mindset profile)
                updateAnalysisStatus(analysisId, 'analyzing');
                const agent = new ReportLearningAgent(analysisId, user.id);
                await agent.analyze(parsedReport);

            } catch (error: any) {
                logger.error('Report analysis pipeline failed', { analysisId, error: error.message });
                updateAnalysisStatus(analysisId, 'failed', error.message);
            }
        })();

        res.json({
            analysisId,
            message: 'Report uploaded. Learning pipeline started.',
        });

    } catch (error: any) {
        logger.error('Report upload error', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to upload report: ' + (error.message || '') });
    }
});

// ── List user's analyses ──

router.get('/', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const user = req.user!;
        const analyses = getUserAnalyses(user.id);
        res.json({ analyses });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list analyses' });
    }
});

// ── Get analysis status + results ──

router.get('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);

        if (!analysis) return res.status(404).json({ error: true, message: 'Analysis not found' });
        if (analysis.user_id !== user.id) return res.status(403).json({ error: true, message: 'Access denied' });

        res.json({
            ...analysis,
            report_metadata: analysis.report_metadata_json ? JSON.parse(analysis.report_metadata_json) : null,
            behavioral_profile: analysis.behavioral_profile_json ? JSON.parse(analysis.behavioral_profile_json) : null,
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get analysis' });
    }
});

// ── Get analysis findings ──

router.get('/:id/findings', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        const findings = getAnalysisFindings(id).map(f => ({
            ...f,
            poc_steps: f.poc_steps_json ? JSON.parse(f.poc_steps_json) : [],
            raw_http_requests: f.raw_http_requests_json ? JSON.parse(f.raw_http_requests_json) : [],
            payloads: f.payloads_json ? JSON.parse(f.payloads_json) : [],
            evidence: f.evidence_json ? JSON.parse(f.evidence_json) : [],
            reasoning_chain: f.reasoning_chain_json ? JSON.parse(f.reasoning_chain_json) : [],
        }));

        res.json({ findings });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get findings' });
    }
});

// ── Get analysis logs ──

router.get('/:id/logs', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });
        res.json({ logs: getAnalysisLogs(id) });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get logs' });
    }
});

// ── Delete analysis ──

router.delete('/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        if (analysis.file_path && fs.existsSync(analysis.file_path)) {
            fs.unlinkSync(analysis.file_path);
        }
        deleteAnalysis(id, user.id);
        res.json({ message: 'Analysis deleted' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to delete analysis' });
    }
});

// ══════════════════════════════════════════════════════
// TTP LIBRARY
// ══════════════════════════════════════════════════════

// ── List all TTPs ──

router.get('/ttps/list', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttps = getAllTTPs().map(t => ({
            ...t,
            discovery_strategy: t.discovery_strategy_json ? JSON.parse(t.discovery_strategy_json) : [],
            preconditions: t.preconditions_json ? JSON.parse(t.preconditions_json) : {},
            entrypoint_hints: t.entrypoint_hints_json ? JSON.parse(t.entrypoint_hints_json) : {},
            request_templates: t.request_templates_json ? JSON.parse(t.request_templates_json) : [],
            payload_templates: t.payload_templates_json ? JSON.parse(t.payload_templates_json) : [],
            verification_criteria: t.verification_criteria_json ? JSON.parse(t.verification_criteria_json) : [],
        }));
        res.json({ ttps });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list TTPs' });
    }
});

// ── Get single TTP ──

router.get('/ttps/:ttpId', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttp = getTTPById(req.params.ttpId);
        if (!ttp) return res.status(404).json({ error: true, message: 'TTP not found' });
        res.json({
            ...ttp,
            discovery_strategy: ttp.discovery_strategy_json ? JSON.parse(ttp.discovery_strategy_json) : [],
            preconditions: ttp.preconditions_json ? JSON.parse(ttp.preconditions_json) : {},
            entrypoint_hints: ttp.entrypoint_hints_json ? JSON.parse(ttp.entrypoint_hints_json) : {},
            request_templates: ttp.request_templates_json ? JSON.parse(ttp.request_templates_json) : [],
            payload_templates: ttp.payload_templates_json ? JSON.parse(ttp.payload_templates_json) : [],
            verification_criteria: ttp.verification_criteria_json ? JSON.parse(ttp.verification_criteria_json) : [],
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get TTP' });
    }
});

// ── Toggle TTP active/inactive ──

router.patch('/ttps/:ttpId/toggle', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const ttp = getTTPById(req.params.ttpId);
        if (!ttp) return res.status(404).json({ error: true, message: 'TTP not found' });
        const newState = !ttp.is_active;
        toggleTTPActive(req.params.ttpId, newState);
        res.json({ message: `TTP ${newState ? 'activated' : 'deactivated'}`, is_active: newState });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to toggle TTP' });
    }
});

// ── Generate TTP test playbook ──

const TTP_TEST_PLAYBOOK_PROMPT_V1 = `You are an offensive security testing guide. You produce clear, actionable testing playbooks for penetration testers.

Given the following TTP (Tactic, Technique, Procedure) extracted from a real pentest report, produce a **Testing Playbook** that a tester can follow to check whether this vulnerability exists on a target application.

TTP DETAILS:
- Vulnerability Class: {VULN_CLASS}
- Discovery Strategy: {DISCOVERY_STRATEGY}
- Preconditions: {PRECONDITIONS}
- Entrypoint Hints: {ENTRYPOINT_HINTS}
- Request Templates: {REQUEST_TEMPLATES}
- Payload Templates: {PAYLOAD_TEMPLATES}
- Verification Criteria: {VERIFICATION_CRITERIA}
- Generalization Notes: {GENERALIZATION_NOTES}

{TARGET_CONTEXT}

OUTPUT RULES:
- Markdown only. No introductory prose.
- Do NOT include real customer domains. Use placeholders like {TARGET} or https://target.example.com.
- No blue-team or defensive content. This is offensive testing guidance only.

OUTPUT MUST include exactly these sections in this order:

## 1. Objective
One sentence: what you are testing for.

## 2. Preconditions
Accounts, roles, auth tokens, or environment needed before testing.

## 3. Target Discovery
What endpoints, parameters, or patterns to look for in the target application.

## 4. Test Steps
Numbered, minimal, safe steps to perform the test.

## 5. Sample Requests
HTTP request skeletons (method, path, headers, body). Use placeholders for domains.

## 6. Payload Variations
Templated payloads to try if the initial payload does not work.

## 7. Success Signals
What response patterns, status codes, or behaviors indicate the vulnerability is present.

## 8. False Positive Traps
Common mistakes that make a tester think the vuln is present when it is not.

## 9. Notes
Rate limit warnings, non-destructive reminders, scope considerations.`;

router.post('/ttps/:ttpId/test-playbook', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const ttp = getTTPById(req.params.ttpId);
        if (!ttp) return res.status(404).json({ error: true, message: 'TTP not found' });

        // Check cache first
        const cached = getCachedPlaybook(ttp.id);
        if (cached) {
            return res.json({ ttp_id: ttp.id, playbook_markdown: cached.content });
        }

        // Build context from TTP fields
        const discovery = ttp.discovery_strategy_json ? JSON.parse(ttp.discovery_strategy_json) : [];
        const preconditions = ttp.preconditions_json ? JSON.parse(ttp.preconditions_json) : {};
        const entrypoints = ttp.entrypoint_hints_json ? JSON.parse(ttp.entrypoint_hints_json) : {};
        const requestTmpl = ttp.request_templates_json ? JSON.parse(ttp.request_templates_json) : [];
        const payloadTmpl = ttp.payload_templates_json ? JSON.parse(ttp.payload_templates_json) : [];
        const criteria = ttp.verification_criteria_json ? JSON.parse(ttp.verification_criteria_json) : [];

        // Build optional target context section
        const tc = req.body?.target_context;
        let targetContextBlock = '';
        if (tc && (tc.base_url || tc.notes || tc.auth_context)) {
            targetContextBlock = `TARGET CONTEXT (provided by tester):\n- Base URL: ${tc.base_url || 'Not specified'}\n- Notes: ${tc.notes || 'None'}\n- Auth Context: ${tc.auth_context || 'None'}`;
        }

        const userPrompt = TTP_TEST_PLAYBOOK_PROMPT_V1
            .replace('{VULN_CLASS}', ttp.vulnerability_class || 'Unknown')
            .replace('{DISCOVERY_STRATEGY}', JSON.stringify(discovery))
            .replace('{PRECONDITIONS}', JSON.stringify(preconditions))
            .replace('{ENTRYPOINT_HINTS}', JSON.stringify(entrypoints))
            .replace('{REQUEST_TEMPLATES}', JSON.stringify(requestTmpl))
            .replace('{PAYLOAD_TEMPLATES}', JSON.stringify(payloadTmpl))
            .replace('{VERIFICATION_CRITERIA}', JSON.stringify(criteria))
            .replace('{GENERALIZATION_NOTES}', ttp.generalization_notes || 'None')
            .replace('{TARGET_CONTEXT}', targetContextBlock);

        const response = await llmRuntime.generate({
            systemPrompt: 'You are an offensive security testing guide. Output ONLY valid markdown. No extra prose.',
            userPrompt,
        }, {
            userId: req.user?.id,
            callSite: 'red_team_ttp_derivation',
            context: 'report-analysis-test-playbook',
        });

        // Get model info for cache
        let modelName = 'unknown';
        try { modelName = llmProvider.getActiveConfig(req.user?.id || 1).model; } catch { /* ignore */ }
        const totalTokens = (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0);

        // Cache the result
        cachePlaybook(ttp.id, response.text, modelName, totalTokens);

        res.json({ ttp_id: ttp.id, playbook_markdown: response.text });
    } catch (error: any) {
        logger.error('Test playbook generation failed', { ttpId: req.params.ttpId, error: error.message });
        res.status(500).json({ error: true, message: 'Failed to generate test playbook: ' + (error.message || '') });
    }
});

// ── Get mindset profile ──

router.get('/mindset-profile/current', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const profile = getMindsetProfile();
        res.json({
            profile: profile?.profile_json ? JSON.parse(profile.profile_json) : null,
            updated_at: profile?.updated_at || null,
        });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get mindset profile' });
    }
});

// ── Export analysis (without defensive data) ──

router.get('/:id/export', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { id } = req.params;
        const user = req.user!;
        const analysis = getAnalysis(id);
        if (!analysis || analysis.user_id !== user.id) return res.status(404).json({ error: true, message: 'Analysis not found' });

        const findings = getAnalysisFindings(id).map(f => ({
            title: f.title,
            severity: f.severity,
            cvss_score: f.cvss_score,
            description: f.description,
            poc_steps: f.poc_steps_json ? JSON.parse(f.poc_steps_json) : [],
            raw_http_requests: f.raw_http_requests_json ? JSON.parse(f.raw_http_requests_json) : [],
            payloads: f.payloads_json ? JSON.parse(f.payloads_json) : [],
            recommendation: f.recommendation,
            discovery_method: f.discovery_method,
            reasoning_chain: f.reasoning_chain_json ? JSON.parse(f.reasoning_chain_json) : [],
        }));

        const ttps = getTTPsByAnalysis(id).map(t => ({
            id: t.id,
            title: t.title,
            vulnerability_class: t.vulnerability_class,
            discovery_strategy: t.discovery_strategy_json ? JSON.parse(t.discovery_strategy_json) : [],
            preconditions: t.preconditions_json ? JSON.parse(t.preconditions_json) : {},
            entrypoint_hints: t.entrypoint_hints_json ? JSON.parse(t.entrypoint_hints_json) : {},
            request_templates: t.request_templates_json ? JSON.parse(t.request_templates_json) : [],
            payload_templates: t.payload_templates_json ? JSON.parse(t.payload_templates_json) : [],
            verification_criteria: t.verification_criteria_json ? JSON.parse(t.verification_criteria_json) : [],
            confidence: t.confidence,
            generalization_notes: t.generalization_notes,
        }));

        const exportData = {
            analysis_id: analysis.id,
            filename: analysis.filename,
            status: analysis.status,
            created_at: analysis.created_at,
            report_metadata: analysis.report_metadata_json ? JSON.parse(analysis.report_metadata_json) : null,
            findings,
            learned_ttps: ttps,
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="penpard-learning-${id}.json"`);
        res.json(exportData);
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to export analysis' });
    }
});

export default router;
