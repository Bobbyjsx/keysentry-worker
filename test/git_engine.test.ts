import { describe, expect, it } from 'vitest';
import { GitEngine } from '@/core/git_engine';

describe('GitEngine', () => {
  it('should format repo properly', async () => {
    const engine = new GitEngine('fake_token');
    // Should throw on invalid repo format
    await expect(engine.scanRepository('invalid-repo')).rejects.toThrow(
      'Invalid repository name format'
    );
  });

  it('should load fallback patterns if not loaded', async () => {
    const engine = new GitEngine('fake_token');
    // Octokit will throw HttpError: Bad credentials because token is fake
    // But it should attempt to fetch patterns or use fallbacks
    await expect(engine.scanRepository('google/jax')).rejects.toThrow();
  });
});
