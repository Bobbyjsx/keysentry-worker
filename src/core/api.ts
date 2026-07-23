import { logger } from '@trigger.dev/sdk/v3';
import { config } from '@/core/config';
import type { DiscoveredKey } from '../engines/scanner.engine';

export type WebhookPayload = {
  scan_id: string;
  user_id: string;
  attempt: number;
  status: 'in_progress' | 'succeeded' | 'failed';
  files_scanned?: number;
  repos_scanned?: number;
  keys_found?: DiscoveredKey[];
  scanned_repositories?: string[];
  error?: string;
};

/**
 * ScanApiClient handles all outbound communication to the KeySentry API.
 * It encapsulates webhook triggers, reporting progress, and fetching state,
 * reducing boilerplate across worker tasks.
 */
export class ScanApiClient {
  private apiHost = config.apiHost;
  private internalSecret = config.internalSecret;
  private atlasApiKey = config.atlasApiKey;

  public async request(url: string, options?: RequestInit): Promise<Response> {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...(options?.headers || {}),
        'X-Internal-Token': this.internalSecret,
      },
    });
    return response;
  }
  public async fetchExistingScanRepos(scanId: string): Promise<string[]> {
    try {
      const response = await this.request(
        `${this.apiHost}/api/v1/scans/internal/${scanId}`
      );
      if (response.ok) {
        const data = await response.json();
        if (
          data?.scan?.scannedRepositories &&
          Array.isArray(data.scan.scannedRepositories)
        ) {
          return data.scan.scannedRepositories.map((s: any) => s.value || s);
        }
      }
    } catch (e) {
      logger.error(`Failed to fetch scan repos: ${e}`);
    }
    return [];
  }

  public async sendWebhook(payload: WebhookPayload) {
    const response = await this.request(
      `${this.apiHost}/api/v1/scans/webhook`,
      {
        body: JSON.stringify({
          ...payload,
          files_scanned: payload.files_scanned ?? 0,
          keys_found: payload.keys_found ?? [],
          repos_scanned: payload.repos_scanned ?? 0,
          scanned_repositories: payload.scanned_repositories ?? [],
        }),
        headers: {
          'Content-Type': 'application/json',
          'X-Atlas-Api-Key': this.atlasApiKey,
          'X-Internal-Token': this.internalSecret,
        },
        method: 'POST',
      }
    );

    if (!response.ok) {
      throw new Error(`Webhook failed: ${response.statusText}`);
    }
  }
}
