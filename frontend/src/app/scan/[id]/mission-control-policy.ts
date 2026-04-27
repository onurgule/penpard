import type { ScanMode } from './focused-plan';

export interface MissionControlPolicyInput {
    scanMode: ScanMode;
    status: string;
    legacyRecoveryRequested: boolean;
}

export interface MissionControlPolicy {
    isLegacyScopedRecoveryState: boolean;
    showLegacyRecoveryTools: boolean;
    showScopedSecondaryContext: boolean;
}

export function deriveMissionControlPolicy(input: MissionControlPolicyInput): MissionControlPolicy {
    const isScopedScan = input.scanMode === 'scoped';
    const isLegacyScopedRecoveryState = isScopedScan && input.status === 'awaiting_review';

    return {
        isLegacyScopedRecoveryState,
        showLegacyRecoveryTools: isScopedScan && input.legacyRecoveryRequested,
        showScopedSecondaryContext: isScopedScan,
    };
}
