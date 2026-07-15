import { logger, task } from '@trigger.dev/sdk/v3';
import { EncryptionService } from '@/core/encryption';
import { GitEngine } from '@/core/git_engine';

export const githubScanTask = task({
  id: 'github-scan',
  retry: {
    maxAttempts: 3,
  },
  run: async (payload: {
    scan_id: string;
    user_id: string;
    repository: string;
    encrypted_token: string;
  }) => {
    try {
      logger.info('Starting github scan', { repository: payload.repository });

      // 1. Decrypt the GitHub token
      const base64Key = process.env.ENCRYPTION_KEY || '';
      if (!base64Key) {
        throw new Error('ENCRYPTION_KEY is not set in environment');
      }

      const encryptionService = new EncryptionService(base64Key);
      const githubToken = encryptionService
        .decrypt(payload.encrypted_token)
        .trim();

      // 2. Initialize GitEngine and load patterns
      await GitEngine.loadGitleaksPatterns();
      const gitEngine = new GitEngine(githubToken);

      // 3. Scan Target
      logger.info(`Resolving and scanning target: ${payload.repository}`);
      const scanResult = await gitEngine.scanTarget(payload.repository);
      logger.info(
        `Scan complete. Found ${scanResult.discoveredKeys.length} keys.`
      );

      // 4. Report back to keysentry-api webhook securely
      const apiHost = process.env.KEYSENTRY_API_URL || 'http://localhost:8001';
      const internalSecret = process.env.INTERNAL_API_SECRET || '';

      if (!internalSecret) {
        logger.warn(
          'INTERNAL_API_SECRET not set, webhook may fail if required by API'
        );
      }

      logger.info(`Sending results to ${apiHost}/api/v1/scans/webhook`);

      const response = await fetch(`${apiHost}/api/v1/scans/webhook`, {
        body: JSON.stringify({
          files_scanned: scanResult.filesScanned,
          keys_found: scanResult.discoveredKeys,
          repos_scanned: scanResult.reposScanned,
          scan_id: payload.scan_id,
          user_id: payload.user_id,
        }),
        headers: {
          'Content-Type': 'application/json',
          'X-Atlas-Api-Key': process.env.ATLAS_API_KEY || '',
          'X-Internal-Token': internalSecret,
        },
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(`Webhook failed: ${response.statusText}`);
      }

      return {
        files_scanned: scanResult.filesScanned,
        keys_found: scanResult.discoveredKeys.length,
        repos_scanned: scanResult.reposScanned,
        scan_id: payload.scan_id,
      };
    } catch (error: any) {
      logger.error(`Scan failed: ${error.message}`);

      const apiHost = process.env.KEYSENTRY_API_URL || 'http://localhost:8001';
      const internalSecret = process.env.INTERNAL_API_SECRET || '';

      try {
        await fetch(`${apiHost}/api/v1/scans/webhook`, {
          body: JSON.stringify({
            error: error.message,
            scan_id: payload.scan_id,
            status: 'failed',
            user_id: payload.user_id,
          }),
          headers: {
            'Content-Type': 'application/json',
            'X-Atlas-Api-Key': process.env.ATLAS_API_KEY || '',
            'X-Internal-Token': internalSecret,
          },
          method: 'POST',
        });
      } catch (e) {
        logger.error('Failed to notify API of scan failure');
      }

      // Rethrow to let Trigger.dev handle retries/failure
      throw error;
    }
  },
});
