import { logger, task } from '@trigger.dev/sdk/v3';
import { config } from '@/core/config';
import { EncryptionService } from '@/core/encryption';
import { GitEngine } from '@/core/git_engine';

export const githubScanTask = task({
  id: 'github-scan',
  retry: {
    maxAttempts: 3,
  },
  run: async (
    payload: {
      scan_id: string;
      user_id: string;
      repository: string;
      encrypted_token: string;
    },
    { ctx }
  ) => {
    let attempt = 1;
    if (ctx && ctx.attempt && typeof ctx.attempt.number === 'number') {
      attempt = ctx.attempt.number;
    }

    try {
      logger.info(`Starting github scan (attempt ${attempt})`, {
        repository: payload.repository,
      });

      const apiHost = config.apiHost;
      const internalSecret = config.internalSecret;

      if (!internalSecret) {
        logger.warn(
          'INTERNAL_API_SECRET not set, webhook may fail if required by API'
        );
      }

      // 0. Fetch existing scan state
      let alreadyScannedRepos: string[] = [];
      try {
        const scanResp = await fetch(
          `${apiHost}/api/v1/scans/internal/${payload.scan_id}`,
          {
            headers: {
              'X-Internal-Token': internalSecret,
            },
          }
        );
        if (scanResp.ok) {
          const scanData = await scanResp.json();
          if (
            scanData &&
            scanData.scan &&
            Array.isArray(scanData.scan.sources)
          ) {
            alreadyScannedRepos = scanData.scan.sources;
            logger.info(
              `Found ${alreadyScannedRepos.length} already scanned repos from previous attempts.`
            );
          }
        }
      } catch (e) {
        logger.warn(
          'Failed to fetch existing scan state, assuming 0 already scanned repos.'
        );
      }

      // 1. Decrypt the GitHub token
      const base64Key = config.encryptionKey;
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

      const onProgress = async (
        repoName: string,
        resultChunk: any,
        accumulatedRepos: number,
        accumulatedFiles: number,
        isRepoComplete: boolean
      ) => {
        try {
          await fetch(`${apiHost}/api/v1/scans/webhook`, {
            body: JSON.stringify({
              attempt: attempt,
              files_scanned: resultChunk.filesScanned, // sending incremental values
              keys_found: resultChunk.discoveredKeys,
              repos_scanned: resultChunk.reposScanned || 0, // incremental
              scan_id: payload.scan_id,
              scanned_repositories: isRepoComplete ? [repoName] : [],
              status: 'in_progress',
              user_id: payload.user_id,
            }),
            headers: {
              'Content-Type': 'application/json',
              'X-Atlas-Api-Key': config.atlasApiKey,
              'X-Internal-Token': internalSecret,
            },
            method: 'POST',
          });
        } catch (e) {
          logger.warn(`Failed to send progress webhook for ${repoName}`);
        }
      };

      const scanResult = await gitEngine.scanTarget(
        payload.repository,
        alreadyScannedRepos,
        onProgress
      );
      logger.info(
        `Scan complete. Found ${scanResult.discoveredKeys.length} new keys in this run.`
      );

      // 4. Report final success to keysentry-api webhook
      logger.info(`Sending final success to ${apiHost}/api/v1/scans/webhook`);

      const response = await fetch(`${apiHost}/api/v1/scans/webhook`, {
        body: JSON.stringify({
          attempt: attempt,
          files_scanned: 0, // already accumulated incrementally
          keys_found: [], // already accumulated incrementally
          repos_scanned: 0, // already accumulated incrementally
          scan_id: payload.scan_id,
          scanned_repositories: [],
          status: 'succeeded',
          user_id: payload.user_id,
        }),
        headers: {
          'Content-Type': 'application/json',
          'X-Atlas-Api-Key': config.atlasApiKey,
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

      let attempt = 1;
      if (ctx && ctx.attempt && typeof ctx.attempt.number === 'number') {
        attempt = ctx.attempt.number;
      }

      const maxAttempts = 3; // From retry config
      const isLastAttempt = attempt >= maxAttempts;

      const apiHost = config.apiHost;
      const internalSecret = config.internalSecret;

      try {
        await fetch(`${apiHost}/api/v1/scans/webhook`, {
          body: JSON.stringify({
            attempt: attempt,
            error: error.message,
            scan_id: payload.scan_id,
            status: isLastAttempt ? 'failed' : 'in_progress',
            user_id: payload.user_id,
          }),
          headers: {
            'Content-Type': 'application/json',
            'X-Atlas-Api-Key': config.atlasApiKey,
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
