import { logger, task } from '@trigger.dev/sdk/v3';
import { config } from '@/core/config';
import { EncryptionService } from '@/core/encryption';
import { ScanApiClient } from '../core/api';
import { GithubEngine } from '../engines/github.engine';
import { PatternEngine } from '../engines/pattern.engine';

export interface RepoScanPayload {
  scan_id: string;
  user_id: string;
  repository: string;
  encrypted_token: string;
}

/**
 * scanSingleRepoTask handles the scanning of a single specific GitHub repository.
 * It streams the tarball into memory, scans files via the ScannerEngine,
 * and periodically chunks progress back to the KeySentry API.
 */
export const scanSingleRepoTask = task({
  id: 'github-scan-repo',
  retry: { maxAttempts: 3 },
  run: async (payload: RepoScanPayload, { ctx }: any) => {
    const attempt = ctx?.attempt?.number ?? 1;
    const apiClient = new ScanApiClient();

    try {
      logger.info(`Starting individual repo scan (attempt ${attempt})`, {
        repository: payload.repository,
      });

      const base64Key = config.encryptionKey;
      if (!base64Key)
        throw new Error('ENCRYPTION_KEY is not set in environment');

      const encryptionService = new EncryptionService(base64Key);
      const githubToken = encryptionService
        .decrypt(payload.encrypted_token)
        .trim();

      await PatternEngine.loadGitleaksPatterns();
      const githubEngine = new GithubEngine(githubToken);

      const onProgress = async (chunkFiles: number, chunkKeys: any[]) => {
        try {
          await apiClient.sendWebhook({
            attempt,
            files_scanned: chunkFiles,
            keys_found: chunkKeys,
            repos_scanned: 0,
            scan_id: payload.scan_id,
            status: 'in_progress',
            user_id: payload.user_id,
          });
        } catch (_e) {
          logger.warn(
            `Failed to send progress webhook for ${payload.repository}`
          );
        }
      };

      const result = await githubEngine.scanRepositoryTarball(
        payload.repository,
        onProgress
      );

      logger.info(
        `Repo ${payload.repository} complete. Found ${result.keysFound.length} keys.`
      );

      await apiClient.sendWebhook({
        attempt,
        repos_scanned: 1,
        scan_id: payload.scan_id,
        scanned_repositories: [payload.repository],
        status: 'in_progress',
        user_id: payload.user_id,
      });

      return result;
    } catch (error: any) {
      logger.error(
        `Repo scan failed for ${payload.repository}: ${error.message}`
      );
      throw error;
    }
  },
});
