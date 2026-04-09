import { updateScanStatus } from '../../db/init';

type ScanStatusWriter = (scanId: string, status: string, errorMessage?: string) => unknown;

export class OrchestratorScanStatus {
    constructor(
        private readonly scanId: string,
        private readonly writeStatus: ScanStatusWriter = updateScanStatus,
    ) {}

    public set(status: string, errorMessage?: string): void {
        this.writeStatus(this.scanId, status, errorMessage);
    }

    public initializing(): void {
        this.set('initializing');
    }

    public planning(): void {
        this.set('planning');
    }

    public testing(): void {
        this.set('testing');
    }

    public reporting(): void {
        this.set('reporting');
    }

    public completed(): void {
        this.set('completed');
    }

    public failed(errorMessage?: string): void {
        this.set('failed', errorMessage);
    }

    public paused(): void {
        this.set('paused');
    }

    public stopped(errorMessage?: string): void {
        this.set('stopped', errorMessage);
    }
}
