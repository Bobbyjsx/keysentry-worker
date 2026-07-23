import { PatternEngine } from './pattern.engine';

export interface DiscoveredKey {
  provider: string;
  key_hash: string;
  source: string;
  link: string;
  repository: string;
  risk_level: string;
}

/**
 * ScannerEngine is the core pattern matching engine.
 * It takes raw text inputs (like source code files) and runs them against
 * the pre-compiled regex signatures from PatternEngine to identify leaked keys.
 */
export class ScannerEngine {
  public static scanText(
    text: string,
    repository: string,
    filePath: string,
    htmlUrlPrefix: string
  ): DiscoveredKey[] {
    const keys: DiscoveredKey[] = [];
    const patternsToUse = PatternEngine.getPatterns();

    for (const [provider, pattern] of Object.entries(patternsToUse)) {
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

        keys.push({
          key_hash: hashedKey,
          // Build basic file link manually
          link: `${htmlUrlPrefix}/${filePath}`,
          provider,
          repository,
          risk_level: 'high',
          source: filePath,
        });
      }
    }

    return keys;
  }
}
