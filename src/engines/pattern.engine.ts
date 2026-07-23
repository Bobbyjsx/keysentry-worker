import toml from 'toml';

/**
 * PatternEngine is responsible for loading, compiling, and caching regex patterns.
 * It parses remote Gitleaks configuration files (TOML) to ensure
 * KeySentry is using the most up-to-date threat signatures.
 */
export class PatternEngine {
  private static gitleaksPatterns: Record<string, RegExp> | null = null;

  public static readonly FALLBACK_PATTERNS: Record<string, RegExp> = {
    AWS: /(AKIA[0-9A-Z]{16})/g,
    'Generic Token': /bearer\s+([a-zA-Z0-9\-._~+/]+=*)/gi,
    'OpenAI (Legacy/Test)': /sk-[a-zA-Z0-9]{48}/g,
    Stripe: /(sk_live_[0-9a-zA-Z]{24})/g,
  };

  public static async loadGitleaksPatterns(): Promise<void> {
    if (PatternEngine.gitleaksPatterns !== null) {
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
        PatternEngine.gitleaksPatterns = {
          ...patterns,
          ...PatternEngine.FALLBACK_PATTERNS,
        };
      } else {
        PatternEngine.gitleaksPatterns = PatternEngine.FALLBACK_PATTERNS;
      }
    } catch (error) {
      console.error('Error loading gitleaks patterns:', error);
      PatternEngine.gitleaksPatterns = PatternEngine.FALLBACK_PATTERNS;
    }
  }

  public static getPatterns(): Record<string, RegExp> {
    return PatternEngine.gitleaksPatterns || PatternEngine.FALLBACK_PATTERNS;
  }
}
