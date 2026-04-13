import crypto from 'crypto';
import { buildSourceReportSections } from '../source-analysis/SourceReportEnricher';
import type { SourceAnalysisResult } from '../source-analysis/SourceAnalysisMode';
import type {
    CanonicalReportFinding,
    CanonicalReportModel,
    CountsBySeverity,
    ReportEnrichmentMode,
    ReportNarrativePatch,
    ReportSeverity,
} from './types';

const severityOrder: ReportSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface ScanRecord {
    id: string;
    target: string;
    type: string;
    status: string;
    created_at: string;
    completed_at?: string | null;
}

interface VulnerabilityRecord {
    id: number;
    name: string;
    description?: string | null;
    severity: string;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe?: string | null;
    cve?: string | null;
    request?: string | null;
    response?: string | null;
    evidence?: string | null;
    remediation?: string | null;
    screenshot_path?: string | null;
}

export function stableStringify(value: unknown): string {
    return JSON.stringify(sortObject(value));
}

function sortObject(value: unknown): unknown {
    if (Array.isArray(value)) {
        return value.map((entry) => sortObject(entry));
    }
    if (value && typeof value === 'object') {
        return Object.keys(value as Record<string, unknown>)
            .sort()
            .reduce<Record<string, unknown>>((acc, key) => {
                acc[key] = sortObject((value as Record<string, unknown>)[key]);
                return acc;
            }, {});
    }
    return value;
}

export function createSnapshotFingerprint(
    scan: ScanRecord,
    vulnerabilities: VulnerabilityRecord[],
    sourceAnalysis?: SourceAnalysisResult | null,
): string {
    const fingerprintInput = {
        scan: {
            id: scan.id,
            target: scan.target,
            type: scan.type,
            status: scan.status,
            created_at: scan.created_at,
            completed_at: scan.completed_at || null,
        },
        vulnerabilities: vulnerabilities
            .map((vulnerability) => ({
                id: vulnerability.id,
                name: vulnerability.name,
                description: vulnerability.description || null,
                severity: normalizeSeverity(vulnerability.severity),
                cvss_score: vulnerability.cvss_score ?? null,
                cvss_vector: vulnerability.cvss_vector ?? null,
                cwe: vulnerability.cwe ?? null,
                cve: vulnerability.cve ?? null,
                request: vulnerability.request ?? null,
                response: vulnerability.response ?? null,
                evidence: vulnerability.evidence ?? null,
                remediation: vulnerability.remediation ?? null,
                screenshot_path: vulnerability.screenshot_path ?? null,
            }))
            .sort((left, right) => left.id - right.id),
        sourceAnalysis: sourceAnalysis || null,
    };

    return crypto.createHash('sha256').update(stableStringify(fingerprintInput)).digest('hex');
}

export function createDeterministicReportModel(
    scan: ScanRecord,
    vulnerabilities: VulnerabilityRecord[],
    sourceAnalysis: SourceAnalysisResult | null | undefined,
    fingerprint: string,
): CanonicalReportModel {
    const findings = vulnerabilities
        .map((vulnerability, index) => toCanonicalFinding(vulnerability, index))
        .sort((left, right) => left.sortOrder - right.sortOrder || left.id - right.id);

    const counts = createCountsBySeverity(findings);
    const totalFindings = findings.length;
    const riskRating = determineRiskRating(counts);
    const topFindingNames = findings.slice(0, 3).map((finding) => finding.title);
    const sourceSections = sourceAnalysis ? buildSourceReportSections(sourceAnalysis) : null;

    return {
        schemaVersion: 1,
        fingerprint,
        generatedAt: scan.completed_at || scan.created_at,
        scan: {
            id: scan.id,
            target: scan.target,
            type: scan.type,
            status: scan.status,
            createdAt: scan.created_at,
            completedAt: scan.completed_at || null,
            duration: calculateDuration(scan.created_at, scan.completed_at || null),
        },
        summary: {
            riskRating,
            totalFindings,
            countsBySeverity: counts,
            executiveSummary: buildExecutiveSummary(scan.target, counts, topFindingNames),
            methodology: buildMethodology(scan.type),
            scopeSummary: `Assessment target: ${scan.target}. Exported from PenPard scan ${scan.id}.`,
            remediationOverview: buildRemediationOverview(counts),
        },
        findingsSummary: findings.map((finding) => ({
            id: finding.id,
            title: finding.title,
            severity: finding.severity,
            cvssScore: finding.cvssScore,
            cwe: finding.cwe,
        })),
        findings,
        remediationPriorities: buildRemediationPriorities(findings),
        sourceIntelligence: sourceSections,
        narrativeMeta: {
            enrichmentMode: 'deterministic',
            llmEnriched: false,
            llmFailed: false,
            llmFailureReason: null,
        },
    };
}

export function applyNarrativePatch(
    baseReport: CanonicalReportModel,
    patch: ReportNarrativePatch,
    enrichmentMode: ReportEnrichmentMode,
): CanonicalReportModel {
    const findingPatchMap = new Map(patch.findings.map((entry) => [entry.findingId, entry]));

    return {
        ...baseReport,
        summary: {
            ...baseReport.summary,
            executiveSummary: patch.executiveSummary || baseReport.summary.executiveSummary,
            remediationOverview: patch.remediationOverview || baseReport.summary.remediationOverview,
        },
        findings: baseReport.findings.map((finding) => {
            const findingPatch = findingPatchMap.get(finding.id);
            if (!findingPatch) return finding;

            return {
                ...finding,
                description: findingPatch.description || finding.description,
                impact: findingPatch.impact || finding.impact,
                remediation: findingPatch.remediation || finding.remediation,
            };
        }),
        narrativeMeta: {
            enrichmentMode,
            llmEnriched: true,
            llmFailed: false,
            llmFailureReason: null,
        },
    };
}

function toCanonicalFinding(vulnerability: VulnerabilityRecord, index: number): CanonicalReportFinding {
    const severity = normalizeSeverity(vulnerability.severity);
    const description = cleanNarrative(vulnerability.description) || `PenPard recorded ${vulnerability.name} during the scan, but no detailed narrative was persisted.`;
    const endpoint = extractEndpoint(vulnerability.request || null);
    const evidence = normalizeEvidence(vulnerability.evidence || null);

    return {
        id: vulnerability.id,
        title: vulnerability.name,
        severity,
        sortOrder: severityOrder.indexOf(severity) * 100000 + index,
        cvssScore: vulnerability.cvss_score ?? null,
        cvssVector: vulnerability.cvss_vector ?? null,
        cwe: vulnerability.cwe ?? null,
        cve: vulnerability.cve ?? null,
        endpoint,
        description,
        impact: buildDefaultImpact(severity, vulnerability.name, endpoint),
        remediation: cleanNarrative(vulnerability.remediation) || buildDefaultRemediation(severity, vulnerability.name),
        evidence: {
            request: cleanMultiline(vulnerability.request),
            response: cleanMultiline(vulnerability.response),
            additional: evidence,
            screenshotPath: vulnerability.screenshot_path || null,
        },
    };
}

function createCountsBySeverity(findings: CanonicalReportFinding[]): CountsBySeverity {
    return severityOrder.reduce<CountsBySeverity>((acc, severity) => {
        acc[severity] = findings.filter((finding) => finding.severity === severity).length;
        return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function normalizeSeverity(severity: string): ReportSeverity {
    const normalized = String(severity || '').toLowerCase();
    if (severityOrder.includes(normalized as ReportSeverity)) {
        return normalized as ReportSeverity;
    }
    return 'info';
}

function determineRiskRating(counts: CountsBySeverity): string {
    if (counts.critical > 0) return 'Critical';
    if (counts.high > 0) return 'High';
    if (counts.medium > 0) return 'Moderate';
    if (counts.low > 0) return 'Low';
    return 'Informational';
}

function buildExecutiveSummary(target: string, counts: CountsBySeverity, topFindingNames: string[]): string {
    const findingSummary = severityOrder
        .map((severity) => `${counts[severity]} ${severity}`)
        .join(', ');
    const topFindings = topFindingNames.length > 0
        ? ` The most urgent items were ${topFindingNames.join(', ')}.`
        : ' No vulnerabilities were recorded.';

    return `PenPard completed a security assessment of ${target}. The resulting finding distribution was ${findingSummary}.${topFindings}`;
}

function buildMethodology(scanType: string): string {
    if (scanType === 'mobile') {
        return 'PenPard combined mobile artifact analysis with deterministic finding normalization and report composition.';
    }
    return 'PenPard combined autonomous web testing, captured evidence, and deterministic report composition for this assessment.';
}

function buildRemediationOverview(counts: CountsBySeverity): string {
    if (counts.critical + counts.high === 0) {
        return 'No critical or high-severity findings require immediate emergency remediation. Address medium and low findings through regular hardening and validation work.';
    }

    return 'Prioritize critical and high-severity findings first, then validate medium-severity issues before the next release window. Lower-severity items should still be tracked as defense-in-depth work.';
}

function buildRemediationPriorities(findings: CanonicalReportFinding[]) {
    const priorityGroups = [
        {
            label: 'Immediate (24-48 hours)',
            description: 'Address critical findings immediately to reduce material compromise risk.',
            severityLevels: ['critical'] as ReportSeverity[],
        },
        {
            label: 'Short-term (1-2 weeks)',
            description: 'High-severity findings should be scheduled next because they can materially expand attacker capability.',
            severityLevels: ['high'] as ReportSeverity[],
        },
        {
            label: 'Medium-term (1-3 months)',
            description: 'Medium-severity findings should be resolved within the normal development cycle.',
            severityLevels: ['medium'] as ReportSeverity[],
        },
        {
            label: 'Long-term / Hardening',
            description: 'Low and informational findings should be addressed as part of defense-in-depth improvements.',
            severityLevels: ['low', 'info'] as ReportSeverity[],
        },
    ];

    return priorityGroups
        .map((group) => ({
            ...group,
            findingIds: findings
                .filter((finding) => group.severityLevels.includes(finding.severity))
                .map((finding) => finding.id),
        }))
        .filter((group) => group.findingIds.length > 0);
}

function buildDefaultImpact(severity: ReportSeverity, title: string, endpoint: string | null): string {
    const endpointText = endpoint ? ` affecting ${endpoint}` : '';
    switch (severity) {
        case 'critical':
            return `${title}${endpointText} could enable severe compromise, including unauthorized access, sensitive data exposure, or full application impact if exploited reliably.`;
        case 'high':
            return `${title}${endpointText} could materially expand attacker capability and should be treated as a near-term business risk.`;
        case 'medium':
            return `${title}${endpointText} increases attack surface and may allow meaningful abuse when chained with other weaknesses.`;
        case 'low':
            return `${title}${endpointText} weakens overall security posture and should be remediated as part of hardening work.`;
        default:
            return `${title}${endpointText} is informational evidence that should be reviewed and tracked as needed.`;
    }
}

function buildDefaultRemediation(severity: ReportSeverity, title: string): string {
    const urgency = severity === 'critical' || severity === 'high'
        ? 'Expedite validation and remediation for this issue.'
        : 'Plan remediation during the next hardening or release cycle.';
    return `${urgency} Review the affected code path for ${title}, apply input validation and authorization controls as appropriate, and confirm the fix with targeted retesting.`;
}

function cleanNarrative(value?: string | null): string {
    return String(value || '').replace(/\s+/g, ' ').trim();
}

function cleanMultiline(value?: string | null): string | null {
    const cleaned = String(value || '').replace(/\r\n/g, '\n').trim();
    return cleaned.length > 0 ? cleaned : null;
}

function normalizeEvidence(value?: string | null): string | null {
    if (!value) return null;

    try {
        const parsed = JSON.parse(value);
        return JSON.stringify(parsed, null, 2);
    } catch {
        return cleanMultiline(value);
    }
}

function extractEndpoint(request: string | null): string | null {
    if (!request) return null;

    const absoluteMatch = request.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(https?:\/\/\S+)/i);
    if (absoluteMatch) return absoluteMatch[1];

    const relativeMatch = request.match(/(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/i);
    return relativeMatch?.[1] || null;
}

function calculateDuration(start: string, end: string | null): string | null {
    if (!end) return null;
    const startTime = new Date(start).getTime();
    const endTime = new Date(end).getTime();
    if (!Number.isFinite(startTime) || !Number.isFinite(endTime) || endTime < startTime) {
        return null;
    }

    const totalSeconds = Math.floor((endTime - startTime) / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}
