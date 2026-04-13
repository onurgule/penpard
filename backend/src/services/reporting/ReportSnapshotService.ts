import { v4 as uuidv4 } from 'uuid';
import {
    getReportSnapshot,
    getReportSnapshotByFingerprint,
    getScan,
    getSourceAnalysisResult,
    getVulnerabilitiesByScan,
    upsertReportSnapshot,
} from '../../db/init';
import { logger } from '../../utils/logger';
import { createDeterministicReportModel, createSnapshotFingerprint } from './reporting-model';
import type { CanonicalReportModel, ReportSnapshotRecord } from './types';

export class ReportSnapshotService {
    public getOrCreateSnapshot(scanId: string): { snapshot: ReportSnapshotRecord; report: CanonicalReportModel } {
        const scan = getScan(scanId);
        if (!scan) {
            throw new Error('Scan not found');
        }

        if (!['completed', 'stopped'].includes(scan.status)) {
            throw new Error(`Scan status "${scan.status}" is not exportable`);
        }

        const vulnerabilities = getVulnerabilitiesByScan(scanId);
        const sourceAnalysis = getSourceAnalysisResult(scanId);
        const fingerprint = createSnapshotFingerprint(scan as any, vulnerabilities as any[], sourceAnalysis);
        const existing = getReportSnapshotByFingerprint(scanId, fingerprint) as ReportSnapshotRecord | undefined;

        if (existing) {
            return {
                snapshot: existing,
                report: this.parseReport(existing.report_json),
            };
        }

        const report = createDeterministicReportModel(scan as any, vulnerabilities as any[], sourceAnalysis, fingerprint);
        const snapshot = upsertReportSnapshot({
            id: uuidv4(),
            scanId,
            fingerprint,
            reportJson: JSON.stringify(report),
        }) as ReportSnapshotRecord;

        logger.info('Created report snapshot', { scanId, snapshotId: snapshot.id, fingerprint });
        return { snapshot, report };
    }

    public getSnapshotById(snapshotId: string): { snapshot: ReportSnapshotRecord; report: CanonicalReportModel } {
        const snapshot = getReportSnapshot(snapshotId) as ReportSnapshotRecord | undefined;
        if (!snapshot) {
            throw new Error('Report snapshot not found');
        }
        return {
            snapshot,
            report: this.parseReport(snapshot.report_json),
        };
    }

    public parseReport(reportJson: string): CanonicalReportModel {
        const parsed = JSON.parse(reportJson) as CanonicalReportModel;
        if (!parsed || parsed.schemaVersion !== 1 || !parsed.scan?.id) {
            throw new Error('Invalid canonical report snapshot');
        }
        return parsed;
    }
}

export const reportSnapshotService = new ReportSnapshotService();
