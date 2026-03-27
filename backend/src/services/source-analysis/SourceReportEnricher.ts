import {
    SourceAnalysisResult, FullSourceAnalysisResult, isFullSourceResult,
} from './SourceAnalysisMode';

export interface ReportSection {
    title: string;
    subsections: ReportSubsection[];
}

export interface ReportSubsection {
    heading: string;
    paragraphs?: string[];
    table?: { headers: string[]; rows: string[][] };
}

export function buildSourceReportSections(result: SourceAnalysisResult): ReportSection {
    if (isFullSourceResult(result)) {
        return buildFullSourceSection(result);
    }
    return buildVersionAwareSection(result);
}

function buildVersionAwareSection(result: SourceAnalysisResult): ReportSection {
    const subsections: ReportSubsection[] = [];

    subsections.push({
        heading: 'Detected Framework & Stack',
        paragraphs: [
            `Framework: ${result.framework}`,
            `Technology Stack: ${result.technologyStack.join(', ') || 'Not determined'}`,
            `Analysis Mode: Version Aware`,
            `Analyzed: ${result.analyzedAt}`,
        ],
    });

    if (result.dependencies.length > 0) {
        const rows = result.dependencies.slice(0, 50).map(d => [
            d.name,
            d.currentVersion,
            d.latestVersion || '-',
            d.ecosystem,
        ]);
        subsections.push({
            heading: 'Dependency Inventory',
            paragraphs: [`${result.dependencies.length} dependencies detected.`],
            table: {
                headers: ['Package', 'Current Version', 'Latest Version', 'Ecosystem'],
                rows,
            },
        });
    }

    if (result.cves.length > 0) {
        const rows = result.cves.slice(0, 40).map(c => [
            c.id,
            c.packageName,
            c.severity,
            c.affectedRange,
            c.fixedVersion || '-',
            c.description.slice(0, 80),
        ]);
        subsections.push({
            heading: 'Known CVE Exposure',
            paragraphs: [`${result.cves.length} known CVEs identified across detected dependency versions.`],
            table: {
                headers: ['CVE ID', 'Package', 'Severity', 'Affected Range', 'Fixed In', 'Description'],
                rows,
            },
        });
    } else {
        subsections.push({
            heading: 'Known CVE Exposure',
            paragraphs: ['No known CVEs were identified for the detected dependency versions.'],
        });
    }

    if (result.testingHints.length > 0) {
        subsections.push({
            heading: 'Version-Aware Testing Notes',
            paragraphs: result.testingHints.map(h => `[${h.category}] ${h.hint}`),
        });
    }

    return { title: 'Source Intelligence', subsections };
}

function buildFullSourceSection(result: FullSourceAnalysisResult): ReportSection {
    const subsections: ReportSubsection[] = [];

    subsections.push({
        heading: 'Detected Framework & Stack',
        paragraphs: [
            `Framework: ${result.framework}`,
            `Technology Stack: ${result.technologyStack.join(', ') || 'Not determined'}`,
            `Analysis Mode: Full Source Aware`,
            `Analyzed: ${result.analyzedAt}`,
        ],
    });

    if (result.applicationSummary) {
        subsections.push({
            heading: 'Application Summary',
            paragraphs: [result.applicationSummary],
        });
    }

    if (result.architectureSummary) {
        subsections.push({
            heading: 'Architecture Overview',
            paragraphs: [result.architectureSummary],
        });
    }

    if (result.modules.length > 0) {
        const rows = result.modules.map(m => [m.name, m.path, m.purpose]);
        subsections.push({
            heading: 'Module Summary',
            paragraphs: [`${result.modules.length} modules identified.`],
            table: {
                headers: ['Module', 'Path', 'Purpose'],
                rows,
            },
        });
    }

    if (result.functions.length > 0) {
        const secFunctions = result.functions.filter(f => f.securityRelevant);
        const otherFunctions = result.functions.filter(f => !f.securityRelevant);

        if (secFunctions.length > 0) {
            const rows = secFunctions.slice(0, 30).map(f => [f.name, f.filePath, f.purpose]);
            subsections.push({
                heading: 'Security-Relevant Functions',
                paragraphs: [`${secFunctions.length} security-relevant functions identified.`],
                table: { headers: ['Function', 'File', 'Purpose'], rows },
            });
        }

        if (otherFunctions.length > 0) {
            const rows = otherFunctions.slice(0, 30).map(f => [f.name, f.filePath, f.purpose]);
            subsections.push({
                heading: 'Important Functions',
                paragraphs: [`${otherFunctions.length} additional important functions identified.`],
                table: { headers: ['Function', 'File', 'Purpose'], rows },
            });
        }
    }

    if (result.endpoints.length > 0) {
        const rows = result.endpoints.slice(0, 40).map(e => [
            e.method,
            e.path,
            e.authRequired ? 'Yes' : 'No',
            e.userInputs.join(', ') || '-',
            e.description || e.handler,
        ]);
        subsections.push({
            heading: 'Endpoint Map',
            paragraphs: [`${result.endpoints.length} endpoints detected.`],
            table: {
                headers: ['Method', 'Path', 'Auth Required', 'User Inputs', 'Description'],
                rows,
            },
        });
    }

    if (result.securityFlows.length > 0) {
        const rows = result.securityFlows.map(f => [
            f.category,
            f.riskLevel,
            f.description,
            f.components.join(', '),
        ]);
        subsections.push({
            heading: 'Security-Relevant Flows',
            paragraphs: [`${result.securityFlows.length} security-relevant flows identified in the codebase.`],
            table: {
                headers: ['Category', 'Risk', 'Description', 'Components'],
                rows,
            },
        });
    }

    if (result.dependencies.length > 0) {
        const rows = result.dependencies.slice(0, 50).map(d => [
            d.name, d.currentVersion, d.latestVersion || '-', d.ecosystem,
        ]);
        subsections.push({
            heading: 'Dependency Inventory',
            paragraphs: [`${result.dependencies.length} dependencies detected.`],
            table: {
                headers: ['Package', 'Current Version', 'Latest Version', 'Ecosystem'],
                rows,
            },
        });
    }

    if (result.cves.length > 0) {
        const rows = result.cves.slice(0, 40).map(c => [
            c.id, c.packageName, c.severity, c.affectedRange, c.fixedVersion || '-', c.description.slice(0, 80),
        ]);
        subsections.push({
            heading: 'Known CVE Exposure',
            paragraphs: [`${result.cves.length} known CVEs identified.`],
            table: {
                headers: ['CVE ID', 'Package', 'Severity', 'Affected Range', 'Fixed In', 'Description'],
                rows,
            },
        });
    } else {
        subsections.push({
            heading: 'Known CVE Exposure',
            paragraphs: ['No known CVEs were identified for the detected dependency versions.'],
        });
    }

    if (result.testingHints.length > 0) {
        subsections.push({
            heading: 'Source-Aware Testing Observations',
            paragraphs: result.testingHints.map(h => `[${h.category}] ${h.hint}`),
        });
    }

    return { title: 'Source-Aware Analysis', subsections };
}
