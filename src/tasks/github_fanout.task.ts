import { type RepoScanPayload, scanSingleRepoTask } from './scan_repo.task';
import { logger, task } from '@trigger.dev/sdk/v3';
import { config } from '@/core/config';
import { EncryptionService } from '@/core/encryption';
import { ScanApiClient } from '../core/api';
import { GithubEngine } from '../engines/github.engine';

/**
 * githubScanTask is the orchestrator for GitHub repository discovery.
 * It lists all repositories for a given user or organization, filters out already scanned ones,
 * and fans out the workload concurrently to `scanSingleRepoTask`.
 */
export const githubScanTask = task({
  id: 'github-scan',
  onFailure: async ({ payload, error, ctx }: any) => {
    // This executes even if the task is killed due to MAX_DURATION_EXCEEDED
    const attempt = ctx?.attempt?.number ?? 1;
    const isLastAttempt = attempt >= 3;
    const apiClient = new ScanApiClient();

    try {
      await apiClient.sendWebhook({
        attempt,
        error: error?.message || 'Task failed or timed out',
        scan_id: payload.scan_id,
        status: isLastAttempt ? 'failed' : 'in_progress',
        user_id: payload.user_id,
      });
    } catch (_e) {
      logger.error('Failed to notify API of scan failure in onFailure hook');
    }
  },
  retry: { maxAttempts: 3 },
  run: async (payload: RepoScanPayload, { ctx }: any) => {
    const attempt = ctx?.attempt?.number ?? 1;
    const apiClient = new ScanApiClient();

    try {
      logger.info(`Starting github fan-out task (attempt ${attempt})`, {
        target: payload.repository,
      });

      const alreadyScannedRepos = await apiClient.fetchExistingScanRepos(
        payload.scan_id
      );

      const base64Key = config.encryptionKey;
      if (!base64Key)
        throw new Error('ENCRYPTION_KEY is not set in environment');

      const encryptionService = new EncryptionService(base64Key);
      const githubToken = encryptionService
        .decrypt(payload.encrypted_token)
        .trim();

      const githubEngine = new GithubEngine(githubToken);
      const allRepos = await githubEngine.getRepositories(payload.repository);
      const reposToScan = allRepos.filter(
        (repo: string) => !alreadyScannedRepos.includes(repo)
      );

      logger.info(
        `Found ${reposToScan.length} repos to scan (skipped ${alreadyScannedRepos.length}).`
      );

      if (reposToScan.length > 0) {
        // Wait for all sub-tasks to complete so we don't succeed prematurely
        const promises = reposToScan.map((repo: string) =>
          scanSingleRepoTask.triggerAndWait({
            encrypted_token: payload.encrypted_token,
            repository: repo,
            scan_id: payload.scan_id,
            user_id: payload.user_id,
          })
        );
        await Promise.all(promises);
      }

      await apiClient.sendWebhook({
        attempt,
        scan_id: payload.scan_id,
        status: 'succeeded',
        user_id: payload.user_id,
      });

      return { reposDiscovered: reposToScan.length, status: 'succeeded' };
    } catch (error: any) {
      logger.error(`Fan-out task failed: ${error.message}`);
      throw error; // Let onFailure handle the webhook
    }
  },
});
