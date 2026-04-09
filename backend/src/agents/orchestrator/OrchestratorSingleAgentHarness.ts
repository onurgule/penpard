type RunKind = 'initial' | 'continuation';

interface OrchestratorSingleAgentHarnessOptions<TContinuationOptions> {
    beforeRun: (kind: RunKind) => void;
    runInitial: () => Promise<void>;
    runContinuation: (options: TContinuationOptions) => Promise<void>;
    handleFailure: (kind: RunKind, error: any) => void;
    finalizeRun: () => Promise<void>;
}

export class OrchestratorSingleAgentHarness<TContinuationOptions> {
    private currentRunPromise: Promise<void> | null = null;

    constructor(private readonly options: OrchestratorSingleAgentHarnessOptions<TContinuationOptions>) {}

    public async waitForCompletion(): Promise<void> {
        await (this.currentRunPromise ?? Promise.resolve());
    }

    public async start(): Promise<void> {
        await this.run('initial', () => this.options.runInitial());
    }

    public async continueScan(options: TContinuationOptions): Promise<void> {
        await this.run('continuation', () => this.options.runContinuation(options));
    }

    private async run(kind: RunKind, executor: () => Promise<void>): Promise<void> {
        if (this.currentRunPromise) {
            throw new Error(kind === 'continuation'
                ? 'Cannot continue while the single-agent harness is already running'
                : 'Single-agent harness is already running');
        }

        this.currentRunPromise = (async () => {
            this.options.beforeRun(kind);

            try {
                await executor();
            } catch (error: any) {
                this.options.handleFailure(kind, error);
            } finally {
                await this.options.finalizeRun();
            }
        })();

        try {
            await this.currentRunPromise;
        } finally {
            this.currentRunPromise = null;
        }
    }
}
