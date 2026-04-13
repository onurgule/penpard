import 'dotenv/config';

import { initDatabase, recoverOrphanedScans, validateSchema } from './db/init';
import { githubIntegration } from './services/GitHubIntegrationService';
import { logger } from './utils/logger';
import { createApp } from './app';
import { reportExportService } from './services/reporting/ReportExportService';

const PORT = process.env.PORT || 4000;

export async function initializeBackendServices(): Promise<void> {
    await initDatabase();
    logger.info('Database initialized');

    validateSchema();
    logger.info('Database schema validated - all required tables present');

    const orphanedCount = recoverOrphanedScans();
    if (orphanedCount > 0) {
        logger.warn(`Recovered ${orphanedCount} orphaned scan(s) - marked as 'interrupted'`);
    }

    await reportExportService.recoverPendingExports();

    const githubCleanup = githubIntegration.reconcilePersistedStateOnStartup();
    if (
        githubCleanup.expiredSessions > 0
        || githubCleanup.purgedInactiveSecrets > 0
        || githubCleanup.invalidatedConnections > 0
        || githubCleanup.deactivatedProviderConfig
        || githubCleanup.migratedLegacyProviderConfig
        || githubCleanup.removedLegacyProviderConfig
    ) {
        logger.warn('GitHub persisted state normalized on startup', githubCleanup);
    }

    try {
        await githubIntegration.ensureCallbackServerReady();
        logger.info(`GitHub callback listener ready at ${githubIntegration.getCallbackUrl()}`);
    } catch (error) {
        logger.warn('GitHub callback listener is unavailable', {
            error: error instanceof Error ? error.message : String(error),
        });
    }
}

export async function startServer() {
    await initializeBackendServices();

    const app = createApp();
    return app.listen(PORT, () => {
        logger.info(`Server running on port ${PORT}`);
        console.log(`
╔═══════════════════════════════════════════╗
║       PENPARD BACKEND SERVER              ║
║       Running on http://localhost:${PORT}    ║
╚═══════════════════════════════════════════╝
      `);

        import('./services/PromptLibraryService').then(({ promptLibrary }) => {
            promptLibrary.fetchFromRemote().then((result) => {
                if (result.success) {
                    logger.info(`Prompt Library: fetched ${result.count} prompts from penpard.com`);
                } else {
                    logger.info(`Prompt Library: using ${result.count} cached/built-in prompts (${result.error || 'remote unavailable'})`);
                }
            }).catch(() => { /* noop */ });
        }).catch(() => { /* noop */ });
    });
}

if (require.main === module) {
    startServer().catch((error) => {
        logger.error('Failed to start server', { error });
        process.exit(1);
    });
}
