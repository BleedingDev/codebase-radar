import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import { decisionHeadline } from './audience';
import { parseGithubRepository } from './contracts';
import { FindingTaskpack, PrioritizationBrief } from './domain';

describe('GitHub repository contract', () => {
  it('normalizes shorthand and full URLs to one public repository identity', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          'BleedingDev/codebase-radar',
          'https://github.com/BleedingDev/codebase-radar.git',
        ],
        parseGithubRepository,
      ),
    ).then(repositories => {
      expect(repositories).toEqual([
        {
          owner: 'BleedingDev',
          repository: 'codebase-radar',
          url: 'https://github.com/BleedingDev/codebase-radar',
        },
        {
          owner: 'BleedingDev',
          repository: 'codebase-radar',
          url: 'https://github.com/BleedingDev/codebase-radar',
        },
      ]);
    }));

  it('rejects credentials, query strings, and nested paths', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          '',
          'owner',
          'github.com/org/repo',
          'https://token@github.com/org/repo',
          'http://github.com/org/repo',
          'https://example.com/org/repo',
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

describe('canonical finding compatibility boundaries', () => {
  it('rejects noncanonical nested findings in taskpacks and briefs', () => {
    const finding = {
      id: 'finding-one',
      fingerprint: 'fingerprint-one',
      mechanism: 'dependency cycle',
      title: 'Dependency cycle',
      category: 'architecture',
      action: 'investigate',
      summary: 'A cycle is present.',
      technicalSummary: 'Two modules form a cycle.',
      recommendation: 'Separate the shared boundary.',
      scores: {
        consequence: 50,
        blastRadius: 40,
        confidence: 90,
        effort: 30,
        changeExposure: 20,
        priority: 60,
      },
      evidence: [
        {
          analyzer: 'TraceDecay',
          kind: 'direct',
          message: 'Cycle evidence.',
          path: 'src/a.ts',
          line: 1,
        },
      ],
      externalReferences: [],
      tags: ['zeta', 'alpha'],
      statusComparedToPrevious: 'new',
    };
    const repository = {
      owner: 'Owner',
      name: 'Repository',
      url: 'https://github.com/Owner/Repository',
      commitSha: 'a'.repeat(40),
      defaultBranch: 'main',
    };
    const taskpack = {
      schemaVersion: 'codebase-radar.taskpack/v1',
      scanId: 'scan-current',
      repository,
      finding,
      objective: 'Resolve the cycle.',
      acceptanceCriteria: [],
      guardrails: [],
      suggestedInvestigation: [],
    };
    const brief = {
      schemaVersion: 'codebase-radar.prioritization-brief/v1',
      scanId: 'scan-current',
      repository,
      audience: 'technical',
      objective: 'Prioritize the backlog.',
      decisionRules: [],
      candidates: [finding],
      requiredOutput: [],
    };
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(FindingTaskpack)(taskpack)),
    ).toBe(true);
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(PrioritizationBrief)(brief)),
    ).toBe(true);
  });
});
