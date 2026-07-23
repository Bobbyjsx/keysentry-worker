import toml from 'toml';
import { Octokit } from '@octokit/rest';
import { logger } from '@trigger.dev/sdk/v3';

export interface DiscoveredKey {
  provider: string;
  key_hash: string;
  source: string;
  link: string;
  repository: string;
  risk_level: string;
}

export interface ScanResult {
  discoveredKeys: DiscoveredKey[];
  filesScanned: number;
}

export class GitEngine {
  private octokit: Octokit;
  private static gitleaksPatterns: Record<string, RegExp> | null = null;

  private static readonly FALLBACK_PATTERNS: Record<string, RegExp> = {
    AWS: /(AKIA[0-9A-Z]{16})/g,
    'Generic Token': /bearer\s+([a-zA-Z0-9\-._~+/]+=*)/gi,
    'OpenAI (Legacy/Test)': /sk-[a-zA-Z0-9]{48}/g,
    Stripe: /(sk_live_[0-9a-zA-Z]{24})/g,
  };

  constructor(githubToken: string) {
    this.octokit = new Octokit({ auth: githubToken });
  }

  public static async loadGitleaksPatterns(): Promise<void> {
    if (GitEngine.gitleaksPatterns !== null) {
      return;
    }

    try {
      const response = await fetch(
        'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch patterns: ${response.statusText}`);
      }

      const text = await response.text();
      const config = toml.parse(text);
      const patterns: Record<string, RegExp> = {};

      if (Array.isArray(config.rules)) {
        for (const rule of config.rules) {
          if (rule.id && rule.regex) {
            try {
              patterns[rule.id] = new RegExp(rule.regex, 'g');
            } catch (_e) {
              // Ignore invalid regex patterns
            }
          }
        }
      }

      if (Object.keys(patterns).length > 0) {
        GitEngine.gitleaksPatterns = {
          ...patterns,
          ...GitEngine.FALLBACK_PATTERNS,
        };
      } else {
        GitEngine.gitleaksPatterns = GitEngine.FALLBACK_PATTERNS;
      }
    } catch (error) {
      console.error('Error loading gitleaks patterns:', error);
      GitEngine.gitleaksPatterns = GitEngine.FALLBACK_PATTERNS;
    }
  }

  public async scanTarget(
    target: string,
    alreadyScannedRepos: string[] = [],
    onProgress?: (
      repoName: string,
      incrementalResult: {
        discoveredKeys: DiscoveredKey[];
        filesScanned: number;
        reposScanned: number;
      },
      accumulatedRepos: number,
      accumulatedFiles: number,
      isRepoComplete: boolean
    ) => Promise<void>
  ): Promise<{
    discoveredKeys: DiscoveredKey[];
    reposScanned: number;
    filesScanned: number;
  }> {
    let reposScanned = 0;
    let filesScanned = 0;
    const discoveredKeys: DiscoveredKey[] = [];

    const FLUSH_INTERVAL_MS = 1500; // 1.5 seconds
    let lastFlushTime = Date.now();
    let pendingFilesScanned = 0;
    let pendingReposScanned = 0;
    let pendingDiscoveredKeys: DiscoveredKey[] = [];

    const flushProgress = async (
      repoName: string,
      isRepoComplete = false,
      force = false
    ) => {
      const now = Date.now();
      if ((force || now - lastFlushTime >= FLUSH_INTERVAL_MS) && onProgress) {
        if (
          pendingFilesScanned > 0 ||
          pendingReposScanned > 0 ||
          pendingDiscoveredKeys.length > 0 ||
          isRepoComplete
        ) {
          await onProgress(
            repoName,
            {
              discoveredKeys: pendingDiscoveredKeys,
              filesScanned: pendingFilesScanned,
              reposScanned: pendingReposScanned,
            },
            reposScanned + pendingReposScanned,
            filesScanned + pendingFilesScanned,
            isRepoComplete
          );
          reposScanned += pendingReposScanned;
          filesScanned += pendingFilesScanned;
          discoveredKeys.push(...pendingDiscoveredKeys);

          pendingFilesScanned = 0;
          pendingReposScanned = 0;
          pendingDiscoveredKeys = [];
          lastFlushTime = now;
        }
      }
    };

    if (target.includes('/')) {
      if (alreadyScannedRepos.includes(target)) {
        return { discoveredKeys: [], filesScanned: 0, reposScanned: 0 };
      }
      const result = await this.scanRepository(
        target,
        async (chunkFiles, chunkKeys) => {
          pendingFilesScanned += chunkFiles;
          pendingDiscoveredKeys.push(...chunkKeys);
          await flushProgress(target, false, false);
        }
      );
      pendingReposScanned++;
      await flushProgress(target, true, true);
      return {
        discoveredKeys,
        filesScanned,
        reposScanned,
      };
    }

    try {
      const { data: entity } = await this.octokit.rest.users.getByUsername({
        username: target,
      });

      let repos: any[] = [];
      if (entity.type === 'Organization') {
        repos = await this.octokit.paginate(
          this.octokit.rest.repos.listForOrg,
          {
            org: target,
          }
        );
      } else {
        repos = await this.octokit.paginate(
          this.octokit.rest.repos.listForUser,
          {
            username: target,
          }
        );
      }

      for (const repo of repos) {
        if (alreadyScannedRepos.includes(repo.full_name)) {
          if (logger) {
            logger.info(
              `Skipping already scanned repository: ${repo.full_name}`
            );
          }
          continue;
        }

        if (logger) {
          logger.info(`Scanning discovered repository: ${repo.full_name}`);
        }

        const result = await this.scanRepository(
          repo.full_name,
          async (chunkFiles, chunkKeys) => {
            pendingFilesScanned += chunkFiles;
            pendingDiscoveredKeys.push(...chunkKeys);
            await flushProgress(repo.full_name, false, false);
          }
        );

        pendingReposScanned++;
        await flushProgress(repo.full_name, true, true);
      }
    } catch (e: any) {
      if (logger) {
        logger.error(`Error resolving target ${target}: ${e.message}`);
      }
      throw new Error(`Failed to resolve target '${target}': ${e.message}`);
    }

    return { discoveredKeys, filesScanned, reposScanned };
  }

  public async scanRepository(
    repoName: string,
    onChunkScanned?: (
      filesScannedChunk: number,
      keysFoundChunk: DiscoveredKey[]
    ) => Promise<void>
  ): Promise<ScanResult> {
    const discoveredKeys: DiscoveredKey[] = [];
    let filesScanned = 0;
    const [owner, repo] = repoName.split('/');

    if (!owner || !repo) {
      throw new Error("Invalid repository name format. Expected 'owner/repo'");
    }

    try {
      // 1. Fetch repo tree
      const { data: treeData } = await this.octokit.rest.git.getTree({
        owner,
        recursive: 'true',
        repo,
        tree_sha: 'HEAD',
      });

      // 2. Filter for text-like files
      const textFiles = treeData.tree.filter(
        (file) =>
          file.type === 'blob' &&
          file.path &&
          /\.(js|ts|py|json|env|txt|md|yml|yaml)$/.test(file.path)
      );

      const patternsToUse =
        GitEngine.gitleaksPatterns || GitEngine.FALLBACK_PATTERNS;

      // 3. Scan files
      for (const file of textFiles) {
        if (!file.path) continue;

        const chunkKeys: DiscoveredKey[] = [];

        try {
          const { data: contentData } =
            await this.octokit.rest.repos.getContent({
              owner,
              path: file.path,
              repo,
            });

          if (
            !Array.isArray(contentData) &&
            contentData.type === 'file' &&
            contentData.content
          ) {
            const text = Buffer.from(contentData.content, 'base64').toString(
              'utf8'
            );

            for (const [provider, pattern] of Object.entries(patternsToUse)) {
              // reset regex state if global
              if (pattern.global) {
                pattern.lastIndex = 0;
              }
              const matches = text.matchAll(pattern);

              for (const match of matches) {
                const matchedText = match[1] || match[0];
                let hashedKey = '';

                if (matchedText.length > 10) {
                  hashedKey = `${matchedText.slice(0, 5)}...${matchedText.slice(-5)}`;
                } else {
                  hashedKey = `${matchedText.slice(0, 2)}...`;
                }

                chunkKeys.push({
                  key_hash: hashedKey,
                  link: contentData.html_url || '',
                  provider,
                  repository: repoName,
                  risk_level: 'high',
                  source: file.path,
                });
              }
            }
          }
        } catch (_err) {
          // Skip unreadable files
        }

        filesScanned++;
        discoveredKeys.push(...chunkKeys);
        if (onChunkScanned) {
          await onChunkScanned(1, chunkKeys);
        }
      }
    } catch (e: any) {
      if (logger) {
        logger.warn(
          `Skipping repository ${repoName} due to error: ${e.message}`
        );
      } else {
        console.warn(
          `Skipping repository ${repoName} due to error: ${e.message}`
        );
      }
      return { discoveredKeys: [], filesScanned: 0 };
    }

    return { discoveredKeys, filesScanned };
  }
}
