import {
  AnalyzerCoverage,
  CompleteAnalyzerRun,
  Evidence,
  Finding,
  FindingScores,
  GitHubSourceIdentity,
  RequiredAnalyzerIds,
  ScanComparison,
  ScanProfile,
  ScanSummary,
  SuccessfulScanResult,
  type SourceIdentity,
} from '../src/index.js';

export const commitSha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const codebaseId = 'github:owner/repository';
export const singlePathSetDigest =
  'sha256:4f35a3347982cf7e2b9be7080461e55c9472d4dee20d960361d5566b1e8cce0a';

export const githubIdentity = () =>
  new GitHubSourceIdentity({
    codebaseId,
    owner: 'Owner',
    repository: 'Repository',
    url: 'https://github.com/Owner/Repository',
    commitSha,
    defaultBranch: 'main',
    snapshotDigest: `git:${commitSha}`,
  });

export const finding = () =>
  new Finding({
    id: 'finding-one',
    fingerprint: 'fingerprint-one',
    mechanism: 'structural dependency cycle',
    title: 'Dependency cycle',
    category: 'architecture',
    action: 'investigate',
    summary: 'A cycle is present.',
    technicalSummary: 'Three modules form one import cycle.',
    recommendation: 'Separate the shared boundary.',
    scores: new FindingScores({
      consequence: 50,
      blastRadius: 40,
      confidence: 90,
      effort: 30,
      changeExposure: 20,
      priority: 60,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: 'Cycle A -> B -> C -> A.',
        path: 'src/a.ts',
        line: 1,
      }),
    ],
    externalReferences: [],
    tags: ['architecture'],
    statusComparedToPrevious: 'new',
  });

export const analyzerRuns = () =>
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
          eligiblePathSetDigest: singlePathSetDigest,
          analyzedPathSetDigest: singlePathSetDigest,
          omittedCapabilities: [],
          warnings: [],
        }),
        observationCount: 1,
      }),
  );

export const successfulResult = (source: SourceIdentity = githubIdentity()) =>
  new SuccessfulScanResult({
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
      headline: 'One investigation is ready.',
      healthScore: 80,
      fixNow: 0,
      investigate: 1,
      monitor: 0,
      doNotFix: 0,
    }),
    findings: [finding()],
    analyzerRuns: analyzerRuns(),
    comparison: new ScanComparison({
      basisCodebaseId: source.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      newFingerprints: ['fingerprint-one'],
      resolvedFingerprints: [],
      persistentFingerprints: [],
      priorityDelta: 0,
    }),
  });

export const v1Result = () => ({
  schemaVersion: 'codebase-radar.scan-result/v1',
  scanId: 'scan-previous',
  repository: {
    owner: 'Owner',
    name: 'Repository',
    url: 'https://github.com/Owner/Repository',
    commitSha,
    defaultBranch: 'main',
  },
  createdAt: '2026-08-11T09:00:00.000Z',
  completedAt: '2026-08-11T09:01:00.000Z',
  profile: {
    version: 'dogfood:max/v1',
    frameworks: ['react'],
    languageCoverage: ['TypeScript'],
    limitations: [],
  },
  summary: {
    headline: 'One investigation is ready.',
    healthScore: 80,
    fixNow: 0,
    investigate: 1,
    monitor: 0,
    doNotFix: 0,
  },
  findings: [
    {
      id: 'finding-one',
      fingerprint: 'fingerprint-one',
      mechanism: 'structural dependency cycle',
      title: 'Dependency cycle',
      category: 'architecture',
      action: 'investigate',
      summary: 'A cycle is present.',
      technicalSummary: 'Three modules form one import cycle.',
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
          message: 'Cycle A -> B -> C -> A.',
          path: 'src/a.ts',
          line: 1,
        },
      ],
      externalReferences: [],
      tags: ['architecture'],
      statusComparedToPrevious: 'new',
    },
  ],
  analyzerRuns: RequiredAnalyzerIds.map(analyzer => ({
    analyzer,
    analyzerVersion: '1.0.0',
    profileVersion: 'dogfood:max/v1',
    status: 'complete',
    durationMs: 1,
    coverage: {
      eligibleFiles: 1,
      analyzedFiles: 1,
      omittedCapabilities: [],
      warnings: [],
    },
    observationCount: 1,
  })),
  comparison: {
    newFindingIds: ['finding-one'],
    resolvedFingerprints: [],
    persistentFindingIds: [],
    priorityDelta: 0,
  },
});
