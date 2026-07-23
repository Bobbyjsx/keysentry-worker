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

  public async scanTarget(target: string): Promise<{
    discoveredKeys: DiscoveredKey[];
    reposScanned: number;
    filesScanned: number;
  }> {
    let reposScanned = 0;
    let filesScanned = 0;
    const discoveredKeys: DiscoveredKey[] = [];

    if (target.includes('/')) {
      const result = await this.scanRepository(target);
      return {
        discoveredKeys: result.discoveredKeys,
        filesScanned: result.filesScanned,
        reposScanned: 1,
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
        if (logger) {
          logger.info(`Scanning discovered repository: ${repo.full_name}`);
        }
        const result = await this.scanRepository(repo.full_name);
        discoveredKeys.push(...result.discoveredKeys);
        reposScanned++;
        filesScanned += result.filesScanned;
      }
    } catch (e: any) {
      if (logger) {
        logger.error(`Error resolving target ${target}: ${e.message}`);
      }
      throw new Error(`Failed to resolve target '${target}': ${e.message}`);
    }

    return { discoveredKeys, filesScanned, reposScanned };
  }

  public async scanRepository(repoName: string): Promise<ScanResult> {
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

      filesScanned = textFiles.length;

      const patternsToUse =
        GitEngine.gitleaksPatterns || GitEngine.FALLBACK_PATTERNS;

      // 3. Scan files
      for (const file of textFiles) {
        if (!file.path) continue;

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

                discoveredKeys.push({
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
