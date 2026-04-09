import { updateScanStatus } from '../db/init';
import { logger } from '../utils/logger';
import { MobSFService } from './mobsf';

export class MobileScanService {
    public launch(scanId: string, apkPath: string): void {
        void this.start(scanId, apkPath).catch(() => {
            /* start already records terminal failure state */
        });
    }

    public async start(scanId: string, apkPath: string): Promise<void> {
        logger.info('Starting mobile scan', { scanId, apkPath });

        updateScanStatus(scanId, 'analyzing');

        try {
            const mobsf = new MobSFService();
            const mobsfAvailable = await mobsf.isAvailable();

            if (!mobsfAvailable) {
                const errorMessage = 'MobSF is not connected. Cannot start mobile scan without MobSF. Please ensure MobSF is running and configured in Settings.';
                logger.error(errorMessage, { scanId });
                updateScanStatus(scanId, 'failed', errorMessage);
                return;
            }

            await mobsf.analyze(scanId, apkPath);
            updateScanStatus(scanId, 'completed');
            logger.info('Mobile scan completed', { scanId });
        } catch (error: any) {
            logger.error('Mobile scan error', { scanId, error: error.message });
            updateScanStatus(scanId, 'failed', error.message);
            throw error;
        }
    }
}

export const mobileScanService = new MobileScanService();
