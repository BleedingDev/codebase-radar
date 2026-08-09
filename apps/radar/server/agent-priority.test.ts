import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AgentPriorityItem,
  AgentPriorityOutput,
  Finding,
  FindingScores,
  RepositorySnapshot,
  ScanComparison,
  ScanProfile,
  ScanResult,
  ScanSummary,
} from '../shared/domain';
import { isValidPriorityOutput } from './prioritization-brief';

const firstFinding = new Finding({
  id: 'finding-one',
  fingerprint: 'one',
  title: 'First finding',
  category: 'reliability',
  action: 'investigate',
  summary: 'Check the first finding.',
  technicalSummary: 'Bounded evidence for the first finding.',
  recommendation: 'Inspect it.',
  scores: new FindingScores({
    consequence: 70,
    blastRadius: 60,
    confidence: 80,
    effort: 40,
    changeExposure: 50,
    priority: 68,
  }),
  evidence: [],
  externalReferences: [],
  tags: [],
  statusComparedToPrevious: 'new',
});

const secondFinding = new Finding({
  ...firstFinding,
  id: 'finding-two',
  fingerprint: 'two',
  title: 'Second finding',
});

const scan = new ScanResult({
  schemaVersion: 'codebase-radar.scan-result/v1',
  scanId: 'scan-one',
  repository: new RepositorySnapshot({
    owner: 'owner',
    name: 'repository',
    url: 'https://github.com/owner/repository',
    commitSha: 'abc123',
    defaultBranch: 'main',
  }),
  createdAt: '2026-08-09T10:00:00.000Z',
  completedAt: '2026-08-09T10:01:00.000Z',
  profile: new ScanProfile({
    version: '2026-08-09',
    frameworks: [],
    languageCoverage: ['typescript'],
    limitations: [],
  }),
  summary: new ScanSummary({
    headline: 'Review ready.',
    healthScore: 0,
    fixNow: 0,
    investigate: 2,
    monitor: 0,
    doNotFix: 0,
  }),
  findings: [firstFinding, secondFinding],
  analyzerRuns: [],
  comparison: new ScanComparison({
    newFindingIds: ['finding-one', 'finding-two'],
    resolvedFingerprints: [],
    persistentFindingIds: [],
    priorityDelta: 0,
  }),
});

describe('provider priority output', () => {
  it('accepts one bounded list containing only scan finding identifiers', () => {
    const output = new AgentPriorityOutput({
      summary: 'Start with the first item.',
      orderedItems: [
        new AgentPriorityItem({
          findingId: 'finding-one',
          action: 'investigate',
          reason: 'It carries the stronger direct consequence.',
          nextMove: 'Inspect the evidence and confirm reachability.',
        }),
      ],
      notNowFindingIds: ['finding-two'],
      unsupportedClaims: [],
    });
    expect(isValidPriorityOutput(scan, output)).toBe(true);
  });

  it('rejects invented or repeated finding identifiers', () => {
    const output = new AgentPriorityOutput({
      summary: 'Invalid list.',
      orderedItems: [
        new AgentPriorityItem({
          findingId: 'finding-one',
          action: 'investigate',
          reason: 'Review it.',
          nextMove: 'Inspect it.',
        }),
      ],
      notNowFindingIds: ['finding-one', 'invented'],
      unsupportedClaims: [],
    });
    expect(isValidPriorityOutput(scan, output)).toBe(false);
  });

  it('enforces the five-item output boundary through the Effect schema', () => {
    const item = new AgentPriorityItem({
      findingId: 'finding-one',
      action: 'investigate',
      reason: 'Review it.',
      nextMove: 'Inspect it.',
    });
    return Effect.runPromiseExit(
      Schema.decodeEffect(AgentPriorityOutput)({
        summary: 'Too many items.',
        orderedItems: [item, item, item, item, item, item],
        notNowFindingIds: [],
        unsupportedClaims: [],
      }),
    ).then(exit => expect(Exit.isFailure(exit)).toBe(true));
  });
});
