import { Effect, Exit } from 'effect';
import { describe, expect, it } from 'vitest';
import { parseGithubRepository } from './contracts';

describe('GitHub repository contract', () => {
  it('normalizes one public repository identity', () =>
    Effect.runPromise(
      parseGithubRepository('https://github.com/BleedingDev/codebase-radar.git'),
    ).then(repository => {
      expect(repository).toEqual({
        owner: 'BleedingDev',
        repository: 'codebase-radar',
        url: 'https://github.com/BleedingDev/codebase-radar',
      });
    }));

  it('rejects credentials, query strings, and nested paths', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          'https://token@github.com/org/repo',
          'https://github.com/org/repo?ref=main',
          'https://github.com/org/repo/tree/main',
        ],
        input => Effect.exit(parseGithubRepository(input)),
      ),
    ).then(results => {
      expect(results.every(Exit.isFailure)).toBe(true);
    }));
});
