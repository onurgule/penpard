import { updateScanStatus } from '../../db/init';

type ScanStatusWriter = (scanId: string, status: string, errorMessage?: string) => unknown;

export interface OrchestratorScanStatusOverrides {
    initializing?: string;
    planning?: string;
    testing?: string;
    reporting?: string;
    completed?: string;
    failed?: string;
    paused?: string;
    stopped?: string;
}

export class OrchestratorScanStatus {
    constructor(
        private readonly scanId: string,
        private readonly writeStatus: ScanStatusWriter = updateScanStatus,
        private readonly overrides: OrchestratorScanStatusOverrides = {},
    ) {}

    public set(status: string, errorMessage?: string): void {
        this.writeStatus(this.scanId, status, errorMessage);
    }

    public initializing(): void {
        this.set(this.overrides.initializing || 'initializing');
    }

    public planning(): void {
        this.set(this.overrides.planning || 'planning');
    }

    public testing(): void {
        this.set(this.overrides.testing || 'testing');
    }

    public reporting(): void {
        this.set(this.overrides.reporting || 'reporting');
    }

    public completed(): void {
        this.set(this.overrides.completed || 'completed');
    }

    public failed(errorMessage?: string): void {
        this.set(this.overrides.failed || 'failed', errorMessage);
    }

    public paused(): void {
        this.set(this.overrides.paused || 'paused');
    }

    public stopped(errorMessage?: string): void {
        this.set(this.overrides.stopped || 'stopped', errorMessage);
    }
}
