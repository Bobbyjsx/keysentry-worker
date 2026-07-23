import { describe, expect, it } from 'vitest';
import { GithubEngine } from '@/engines/github.engine';

describe('GithubEngine', () => {
  it('should format repo properly', async () => {
    const engine = new GithubEngine('fake_token');
    // Should throw on invalid repo format
    await expect(engine.scanRepositoryTarball('invalid-repo')).rejects.toThrow(
      'Invalid repository name format'
    );
  });

  it('should attempt fetch and throw bad credentials', async () => {
    const engine = new GithubEngine('fake_token');
    // Octokit will throw HttpError: Bad credentials because token is fake
    await expect(engine.scanRepositoryTarball('google/jax')).rejects.toThrow();
  });
});
