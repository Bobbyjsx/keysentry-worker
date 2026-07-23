import { Readable } from 'node:stream';
import * as zlib from 'node:zlib';
import * as tar from 'tar-stream';
import { type DiscoveredKey, ScannerEngine } from './scanner.engine';
import { Octokit } from '@octokit/rest';
import { logger } from '@trigger.dev/sdk/v3';

/**
 * GithubEngine processes repository discovery and streaming.
 * It uses the Octokit REST API to fetch organizations/users and
 * downloads repositories as tarballs directly into memory for high-performance scanning.
 */
export class GithubEngine {
  private octokit: Octokit;

  constructor(githubToken: string) {
    this.octokit = new Octokit({ auth: githubToken });
  }

  public async getRepositories(target: string): Promise<string[]> {
    if (target.includes('/')) {
      return [target];
    }

    const { data: entity } = await this.octokit.rest.users.getByUsername({
      username: target,
    });

    let repos: any[] = [];
    if (entity.type === 'Organization') {
      logger.info(`Using Organization scan for '${target}'`);
      repos = await this.octokit.paginate(this.octokit.rest.repos.listForOrg, {
        org: target,
      });
    } else {
      const { data: authUser } =
        await this.octokit.rest.users.getAuthenticated();
      if (authUser.login.toLowerCase() === target.toLowerCase()) {
        logger.info(
          `Using authenticated user scan for '${target}' (fetching private & public repos)`
        );
        // Use listForAuthenticatedUser to ensure we fetch private repositories
        const allAuthRepos = await this.octokit.paginate(
          this.octokit.rest.repos.listForAuthenticatedUser,
          {
            affiliation: 'owner,collaborator,organization_member',
            per_page: 100,
          }
        );
        logger.info(
          `Fetched ${allAuthRepos.length} total repos for authenticated user.`
        );
        // Filter out repositories that do not belong to the target username
        repos = allAuthRepos.filter(
          (r) => r.owner.login.toLowerCase() === target.toLowerCase()
        );
        logger.info(
          `After filtering for owner '${target}', ${repos.length} repos remain.`
        );
      } else {
        logger.info(
          `Using non-authenticated public scan for '${target}' (token owner is '${authUser.login}')`
        );
        repos = await this.octokit.paginate(
          this.octokit.rest.repos.listForUser,
          {
            username: target,
          }
        );
      }
    }
    return repos.map((r) => r.full_name);
  }

  public async scanRepositoryTarball(
    repoName: string,
    onChunkScanned?: (
      filesScannedChunk: number,
      keysFoundChunk: DiscoveredKey[]
    ) => Promise<void>
  ): Promise<{ filesScanned: number; keysFound: DiscoveredKey[] }> {
    const [owner, repo] = repoName.split('/');
    if (!owner || !repo) {
      throw new Error("Invalid repository name format. Expected 'owner/repo'");
    }

    let response: any;
    try {
      response = await this.octokit.rest.repos.downloadTarballArchive({
        owner,
        ref: 'HEAD',
        repo,
      });
    } catch (err: any) {
      if (err.status === 404) {
        console.warn(`Repository ${repoName} is empty or not found (404)`);
        return { filesScanned: 0, keysFound: [] };
      }
      throw err;
    }

    const buffer = Buffer.from(response.data as ArrayBuffer);

    return new Promise((resolve, reject) => {
      let filesScanned = 0;
      const discoveredKeys: DiscoveredKey[] = [];
      const extract = tar.extract();

      let chunkFiles = 0;
      const chunkKeys: DiscoveredKey[] = [];

      extract.on('entry', (header, stream, next) => {
        // Only scan text-like files, ignore binaries and directories
        if (
          header.type === 'file' &&
          /\.(js|ts|py|json|env|txt|md|yml|yaml|go|rb|php|java|c|cpp|h|cs|html|css|sh|jsonc)$/i.test(
            header.name
          )
        ) {
          const chunks: Buffer[] = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          stream.on('end', async () => {
            const text = Buffer.concat(chunks).toString('utf8');
            // Remove the top level directory from tarball header (e.g. owner-repo-sha/file.txt)
            const filePath = header.name.split('/').slice(1).join('/');

            const htmlUrlPrefix = `https://github.com/${repoName}/blob/HEAD`;
            const keys = ScannerEngine.scanText(
              text,
              repoName,
              filePath,
              htmlUrlPrefix
            );

            filesScanned++;
            discoveredKeys.push(...keys);

            chunkFiles++;
            chunkKeys.push(...keys);

            if (chunkFiles >= 100 && onChunkScanned) {
              await onChunkScanned(chunkFiles, [...chunkKeys]);
              chunkFiles = 0;
              chunkKeys.length = 0;
            }

            next();
          });
          stream.resume();
        } else {
          // Ignore entry
          stream.on('end', () => next());
          stream.resume();
        }
      });

      extract.on('finish', async () => {
        if (chunkFiles > 0 && onChunkScanned) {
          await onChunkScanned(chunkFiles, chunkKeys);
        }
        resolve({ filesScanned, keysFound: discoveredKeys });
      });

      extract.on('error', reject);

      const readable = Readable.from(buffer);
      const gunzip = zlib.createGunzip();

      gunzip.on('error', reject);

      readable.pipe(gunzip).pipe(extract);
    });
  }
}
