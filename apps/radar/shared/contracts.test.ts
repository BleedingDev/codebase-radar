import { Effect, Exit } from 'effect';
import { describe, expect, it } from 'vitest';
import { decisionHeadline } from './audience';
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

describe('decision headline', () => {
  it('states the next decision without a composite score', () => {
    expect(decisionHeadline(2, 4, 8)).toBe('2 issues need attention now.');
    expect(decisionHeadline(0, 3, 8)).toBe('Nothing urgent. Start with 3 checks.');
    expect(decisionHeadline(0, 0, 0)).toBe('Nothing needs attention now.');
  });
});
