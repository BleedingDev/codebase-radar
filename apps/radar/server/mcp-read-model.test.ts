import { createHash } from 'node:crypto';
import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalyzerCoverage,
  CanonicalRepositoryPathSet,
  CompleteAnalyzerRun,
  encodeCanonicalRepositoryPathSet,
  Evidence,
  Finding,
  FindingScores,
  GitHubSourceIdentity,
  LegacyScanResult,
  LocalSourceIdentity,
  RequiredAnalyzerIds,
  RepositoryPathSetDigest,
  ScanComparison,
  ScanProfile,
  ScanRecord,
  ScanSummary,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  buildFindingTaskpack,
  buildPrioritizationBrief,
  listImprovementBacklog,
  requireCompleteScanResult,
} from './mcp-read-model';

const canonicalPathSetDigest = (paths: ReadonlyArray<string>) =>
  Schema.decodeUnknownSync(RepositoryPathSetDigest)(
    `sha256:${createHash('sha256')
      .update(
        encodeCanonicalRepositoryPathSet(
          Schema.decodeUnknownSync(CanonicalRepositoryPathSet)(paths),
        ),
      )
      .digest('hex')}`,
  );

const completeAnalyzerPathSetDigest = canonicalPathSetDigest(['src/fixture.ts']);

const commitSha = 'a'.repeat(40);

const analyzerRuns = () =>
  RequiredAnalyzerIds.map(
    analyzer =>
      new CompleteAnalyzerRun({
        analyzer,
        analyzerVersion: '1.0.0',
        profileVersion: 'dogfood:max/v1',
        status: 'complete',
        durationMs: 1,
        coverage: new AnalyzerCoverage({
          eligibleFiles: 1,
          analyzedFiles: 1,
          eligiblePathSetDigest: completeAnalyzerPathSetDigest,
          analyzedPathSetDigest: completeAnalyzerPathSetDigest,
          omittedCapabilities: [],
          warnings: [],
        }),
        observationCount: 1,
      }),
  );

const finding = (id: string) =>
  new Finding({
    id,
    fingerprint: `fingerprint-${id}`,
    mechanism: 'canonical mechanism',
    title: `Finding ${id}`,
    category: 'architecture',
    action: 'investigate',
    summary: `Summary ${id}`,
    technicalSummary: `Technical summary ${id}`,
    recommendation: `Recommendation ${id}`,
    scores: new FindingScores({
      consequence: 70,
      blastRadius: 60,
      confidence: 80,
      effort: 40,
      changeExposure: 50,
      priority: 68,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: `Evidence ${id}`,
        path: `src/${id}.ts`,
        line: 1,
      }),
    ],
    externalReferences: [],
    tags: ['architecture'],
    statusComparedToPrevious: 'new',
  });

const githubSource = () => new GitHubSourceIdentity({
  codebaseId: 'github:owner/repository',
  owner: 'Owner',
  repository: 'Repository',
  url: 'https://github.com/Owner/Repository',
  commitSha,
  defaultBranch: 'main',
  snapshotDigest: `git:${commitSha}`,
});

const completeResult = (
  source: SuccessfulScanResult['source'] = githubSource(),
) => {
  const findings = [finding('finding-one'), finding('finding-two')];
  return new SuccessfulScanResult({
    schemaVersion: 'codebase-radar.scan-result/v2',
    resultKind: 'complete',
    analysisPolicy: 'dogfood:max/v1',
    scanId: 'scan-current',
    source,
    createdAt: '2026-08-11T10:00:00.000Z',
    completedAt: '2026-08-11T10:01:00.000Z',
    profile: new ScanProfile({
      frameworks: ['react'],
      languageCoverage: ['TypeScript'],
      limitations: [],
    }),
    summary: new ScanSummary({
      headline: 'Canonical review ready.',
      healthScore: 80,
      fixNow: 0,
      investigate: findings.length,
      monitor: 0,
      doNotFix: 0,
    }),
    findings,
    analyzerRuns: analyzerRuns(),
    comparison: new ScanComparison({
      basisCodebaseId: source.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      newFingerprints: findings.map(item => item.fingerprint),
      resolvedFingerprints: [],
      persistentFingerprints: [],
      priorityDelta: 0,
    }),
  });
};

const recordFor = (result: SuccessfulScanResult) =>
  new ScanRecord({
    id: result.scanId,
    githubUrl: 'https://github.com/Owner/Repository',
    owner: 'Owner',
    repository: 'Repository',
    audience: 'technical',
    status: 'completed',
    progress: 1,
    stage: 'completed',
    createdAt: result.createdAt,
    updatedAt: result.completedAt,
    result,
  });

describe('MCP canonical read model', () => {
  it('returns every complete GitHub finding unchanged through backlog, brief, and taskpack reads', () => {
    const result = completeResult();
    const record = recordFor(result);
    const backlog = Effect.runSync(listImprovementBacklog(record));
    const brief = Effect.runSync(buildPrioritizationBrief(record));
    const taskpack = Effect.runSync(buildFindingTaskpack(record, 'finding-two'));

    expect(backlog.findings).toHaveLength(2);
    expect(backlog.findings).toEqual(result.findings);
    expect(brief.candidates).toEqual(result.findings);
    expect(taskpack.finding).toEqual(result.findings[1]);
    expect(taskpack.finding.mechanism).toBe('canonical mechanism');
    expect(taskpack.finding.scores.priority).toBe(68);
  });

  it('rejects legacy-noncanonical inputs rather than returning a partial compatibility view', () => {
    const legacy = new LegacyScanResult({
      schemaVersion: 'codebase-radar.scan-result/v2',
      resultKind: 'legacy-noncanonical',
      legacyProfileVersion: 'legacy/v1',
      legacyReason: 'Legacy input has no complete canonical source identity.',
      scanId: 'legacy-scan',
      source: {
        _tag: 'LegacyGitHubSourceIdentity',
        codebaseId: 'github:owner/repository',
        owner: 'Owner',
        repository: 'Repository',
        url: 'https://github.com/Owner/Repository',
        commitSha,
        defaultBranch: 'main',
        snapshotDigest: `git:${commitSha}`,
      },
      createdAt: '2026-08-11T10:00:00.000Z',
      completedAt: '2026-08-11T10:01:00.000Z',
      profile: {
        version: 'legacy/v1',
        frameworks: [],
        languageCoverage: [],
        limitations: [],
      },
      summary: {
        headline: 'Legacy.',
        healthScore: 0,
        fixNow: 0,
        investigate: 0,
        monitor: 0,
        doNotFix: 0,
      },
      findings: [],
      analyzerRuns: [],
      comparison: {
        newFindingIds: [],
        resolvedFingerprints: [],
        persistentFindingIds: [],
        priorityDelta: 0,
      },
    });
    const exit = Effect.runSyncExit(requireCompleteScanResult(legacy));

    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('returns typed hosted-source rejection for a complete local result', () => {
    const result = completeResult(
      new LocalSourceIdentity({
        codebaseId: 'local:repository',
        repository: 'repository',
        snapshotDigest: `sha256:${'b'.repeat(64)}`,
        dirty: false,
      }),
    );
    const record = recordFor(result);
    const backlog = Effect.runSyncExit(listImprovementBacklog(record));
    const taskpack = Effect.runSyncExit(buildFindingTaskpack(record, 'finding-one'));
    const brief = Effect.runSyncExit(buildPrioritizationBrief(record));

    expect(Exit.isFailure(backlog)).toBe(true);
    expect(Exit.isFailure(taskpack)).toBe(true);
    expect(Exit.isFailure(brief)).toBe(true);
  });
});
