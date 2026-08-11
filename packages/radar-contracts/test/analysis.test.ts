import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalysisIncomplete,
  AnalysisInterrupted,
  AnalysisProgressStream,
  AnalysisProgressTerminal,
  AnalysisProgressUpdate,
  AnalysisRequestSchema,
  decodeAnalysisRequest,
  EmptyRepositoryPathSetDigest,
  RequiredAnalyzerIds,
} from '../src/index.js';
import {
  analyzerRuns,
  githubIdentity,
  successfulResult,
  v1Result,
} from './fixtures.js';
import { ScanResultFromV1 } from '../src/report.js';

const source = {
  _tag: 'GitHubSource',
  owner: 'Owner',
  repository: 'Repository',
  revision: { _tag: 'CommitRevision', commitSha: githubIdentity().commitSha },
};

const update = (sequence: number, completedWork: number) =>
  new AnalysisProgressUpdate({
    scanId: 'scan-current',
    sequence,
    timestamp: `2026-08-11T10:00:0${sequence}.000Z`,
    stage: sequence === 0 ? 'preflight' : 'analyzing',
    completedWork,
    totalWork: 4,
    percent: completedWork * 25,
    terminal: false,
  });

const terminal = (
  sequence: number,
  outcome: 'succeeded' | 'failed' | 'interrupted',
  completedWork: number,
) =>
  new AnalysisProgressTerminal({
    scanId: 'scan-current',
    sequence,
    timestamp: `2026-08-11T10:00:0${sequence}.000Z`,
    stage: 'terminal',
    completedWork,
    totalWork: 4,
    percent: completedWork * 25,
    terminal: true,
    outcome,
  });

const attemptedRuns = () =>
  analyzerRuns().map(run => ({
    ...run,
    _tag: 'AttemptedAnalyzerRun',
  }));

describe('AnalysisRequest', () => {
  it('contains no selectable policy or agent profile controls', () => {
    const forbiddenFields = [
      { profile: 'alternate' },
      { profileId: 'forbidden' },
      { analyzers: ['TraceDecay'] },
      { skipAnalyzers: ['JSCPD'] },
      { truncate: true },
      { maximumFindings: 1 },
      { threshold: 50 },
    ];
    for (const forbidden of forbiddenFields) {
      const exit = Effect.runSync(
        Effect.exit(
          decodeAnalysisRequest({
            scanId: 'scan-current',
            source,
            createdAt: '2026-08-11T10:00:00.000Z',
            ...forbidden,
          }),
        ),
      );
      expect(Exit.isFailure(exit)).toBe(true);
    }
  });

  it('accepts only an older compatible canonical baseline', () => {
    const baseline = successfulResult();
    const valid = {
      scanId: 'scan-next',
      source,
      createdAt: '2026-08-11T11:00:00.000Z',
      baseline,
    };
    expect(Exit.isSuccess(Schema.decodeUnknownExit(AnalysisRequestSchema)(valid))).toBe(
      true,
    );
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({
          ...valid,
          scanId: baseline.scanId,
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({
          ...valid,
          createdAt: baseline.completedAt,
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({
          ...valid,
          source: {
            ...source,
            owner: 'Other',
          },
        }),
      ),
    ).toBe(true);
    const v1Legacy = Schema.decodeUnknownSync(ScanResultFromV1)(v1Result());
    expect(v1Legacy.resultKind).toBe('legacy-noncanonical');
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({
          ...valid,
          baseline: v1Legacy,
        }),
      ),
    ).toBe(true);
    const weakLegacyInput = v1Result();
    weakLegacyInput.profile.version = '2026-08-09';
    const weakLegacy = Schema.decodeUnknownSync(ScanResultFromV1)(weakLegacyInput);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({ ...valid, baseline: weakLegacy }),
      ),
    ).toBe(true);
  });

  it('rejects impossible calendar timestamps', () => {
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisRequestSchema)({
          scanId: 'scan-current',
          source,
          createdAt: '2026-02-30T10:00:00.000Z',
        }),
      ),
    ).toBe(true);
  });
});

describe('AnalysisProgress stream', () => {
  it('accepts successful, failed, and interrupted terminal outcomes', () => {
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisProgressStream)([
          update(0, 1),
          update(1, 2),
          terminal(2, 'succeeded', 4),
        ]),
      ),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisProgressStream)([
          update(0, 1),
          terminal(1, 'failed', 1),
        ]),
      ),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisProgressStream)([
          update(0, 1),
          terminal(1, 'interrupted', 1),
        ]),
      ),
    ).toBe(true);
  });

  it('rejects missing, repeated, regressing, and post-terminal events', () => {
    const invalidStreams = [
      [update(0, 1)],
      [update(2, 1), terminal(3, 'failed', 1)],
      [update(0, 1), terminal(1, 'failed', 1), terminal(2, 'failed', 1)],
      [update(0, 2), update(1, 1), terminal(2, 'failed', 1)],
      [update(0, 1), terminal(1, 'failed', 1), update(2, 2)],
      [update(0, 1), terminal(1, 'failed', 4)],
      [
        update(0, 1),
        new AnalysisProgressTerminal({
          scanId: 'scan-current',
          sequence: 1,
          timestamp: '2026-08-11T10:00:01.000Z',
          stage: 'terminal',
          completedWork: 5,
          totalWork: 4,
          percent: 100,
          terminal: true,
          outcome: 'failed',
        }),
      ],
    ];
    for (const events of invalidStreams) {
      expect(
        Exit.isFailure(Schema.decodeUnknownExit(AnalysisProgressStream)(events)),
      ).toBe(true);
    }
  });

  it('keeps incomplete boundary progress below one hundred percent', () => {
    const boundaryUpdate = new AnalysisProgressUpdate({
      scanId: 'scan-current',
      sequence: 0,
      timestamp: '2026-08-11T10:00:00.000Z',
      stage: 'analyzing',
      completedWork: 999,
      totalWork: 1_000,
      percent: 99,
      terminal: false,
    });
    const boundaryFailure = new AnalysisProgressTerminal({
      scanId: 'scan-current',
      sequence: 1,
      timestamp: '2026-08-11T10:00:01.000Z',
      stage: 'terminal',
      completedWork: 999,
      totalWork: 1_000,
      percent: 99,
      terminal: true,
      outcome: 'failed',
    });
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisProgressStream)([
          boundaryUpdate,
          boundaryFailure,
        ]),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisProgressStream)([
          { ...boundaryUpdate, percent: 100 },
          boundaryFailure,
        ]),
      ),
    ).toBe(true);
  });
});

describe('analysis failures', () => {
  it('requires stable violation codes', () => {
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          _tag: 'AnalysisIncomplete',
          violations: ['free-form failure'],
          analyzerRuns: [],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          _tag: 'AnalysisIncomplete',
          violations: RequiredAnalyzerIds.map(analyzer => ({
            code: 'analyzer_missing',
            analyzer,
          })),
          analyzerRuns: [],
        }),
      ),
    ).toBe(true);
  });

  it('rejects local paths in public failure text', () => {
    const attackedMessages = [
      'Failed under /Users/alice/private/repository',
      'Failed under C:\\Users\\alice\\private',
      'Failed under \\\\server\\share\\private',
    ];
    for (const message of attackedMessages) {
      expect(
        Exit.isFailure(
          Schema.decodeUnknownExit(AnalysisInterrupted)({
            _tag: 'AnalysisInterrupted',
            message,
          }),
        ),
      ).toBe(true);
    }
  });

  it('preserves completed attempts beside one timed-out attempt', () => {
    const runs = attemptedRuns();
    const last = runs.at(-1);
    expect(last).toBeDefined();
    if (!last) return;
    const timedOut = {
      ...last,
      status: 'timed_out',
      diagnostic: 'Analyzer reached its execution deadline.',
    };
    const incomplete = {
      _tag: 'AnalysisIncomplete',
      violations: [
        { code: 'analyzer_timed_out', analyzer: last.analyzer },
      ],
      analyzerRuns: [...runs.slice(0, -1), timedOut],
    };
    const decoded = Schema.decodeUnknownExit(AnalysisIncomplete)(incomplete);
    expect(Exit.isSuccess(decoded)).toBe(true);
    if (Exit.isFailure(decoded)) return;
    expect(decoded.value.analyzerRuns).toHaveLength(7);
    expect(decoded.value.analyzerRuns.filter(run => run.status === 'complete')).toHaveLength(6);
    expect(decoded.value.analyzerRuns.at(-1)?.status).toBe('timed_out');
  });

  it('preserves nominal complete status with incomplete coverage evidence', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (!first) return;
    const incomplete = {
      _tag: 'AnalysisIncomplete',
      violations: [
        { code: 'coverage_incomplete', analyzer: first.analyzer },
      ],
      analyzerRuns: [
        {
          ...first,
          coverage: {
            ...first.coverage,
            eligibleFiles: 10,
            analyzedFiles: 9,
          },
        },
        ...runs.slice(1),
      ],
    };
    const decoded = Schema.decodeUnknownExit(AnalysisIncomplete)(incomplete);
    expect(Exit.isSuccess(decoded)).toBe(true);
    if (Exit.isFailure(decoded)) return;
    expect(decoded.value.analyzerRuns[0]?.status).toBe('complete');
    expect(decoded.value.analyzerRuns[0]?.coverage.analyzedFiles).toBe(9);
  });

  it('retains an empty-digest complete attempt only with correlated failure evidence', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (first === undefined) return;
    const emptyDigestAttempt = {
      ...first,
      coverage: {
        ...first.coverage,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
      },
    };
    const withCoverageViolation = {
      _tag: 'AnalysisIncomplete',
      violations: [{ code: 'coverage_incomplete', analyzer: first.analyzer }],
      analyzerRuns: [emptyDigestAttempt, ...runs.slice(1)],
    };
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(AnalysisIncomplete)(withCoverageViolation)),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          ...withCoverageViolation,
          violations: [{ code: 'inventory_truncated' }],
        }),
      ),
    ).toBe(true);
  });

  it('retains malformed not-applicable coverage only with correlated failure evidence', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (first === undefined) return;
    const malformedNotApplicable = {
      ...first,
      status: 'not_applicable',
      reason: {
        code: 'no-eligible-input',
        message: 'Runtime claimed no eligible input while retaining an omission.',
      },
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: ['unsupported-mode'],
        warnings: [],
      },
      observationCount: 0,
    };
    const withCoverageViolation = {
      _tag: 'AnalysisIncomplete',
      violations: [{ code: 'coverage_incomplete', analyzer: first.analyzer }],
      analyzerRuns: [malformedNotApplicable, ...runs.slice(1)],
    };
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(AnalysisIncomplete)(withCoverageViolation)),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          ...withCoverageViolation,
          violations: [{ code: 'inventory_truncated' }],
        }),
      ),
    ).toBe(true);
  });

  it('preserves core-reported zero-input contradictions for every analyzer', () => {
    const runs = attemptedRuns().map(run => ({
      ...run,
      status: 'not_applicable',
      reason: {
        code: 'no-eligible-input',
        message: 'Runtime reported no eligible input.',
      },
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      },
      observationCount: 0,
    }));
    const failure = {
      _tag: 'AnalysisIncomplete',
      violations: runs.map(run => ({
        code: 'coverage_incomplete',
        analyzer: run.analyzer,
      })),
      analyzerRuns: runs,
    };
    expect(runs).toHaveLength(RequiredAnalyzerIds.length);
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(AnalysisIncomplete)(failure)),
    ).toBe(true);
  });

  it('permits a locally valid not-applicable attempt when core reports its coverage contradiction', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (first === undefined) return;
    const validNotApplicable = {
      ...first,
      status: 'not_applicable',
      reason: {
        code: 'no-eligible-input',
        message: 'Runtime reported no eligible input.',
      },
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      },
      observationCount: 0,
    };
    const withCoverageViolation = {
      _tag: 'AnalysisIncomplete',
      violations: [{ code: 'coverage_incomplete', analyzer: first.analyzer }],
      analyzerRuns: [validNotApplicable, ...runs.slice(1)],
    };
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(AnalysisIncomplete)(withCoverageViolation)),
    ).toBe(true);
  });

  it('rejects uncorrelated, duplicate, and unordered incomplete evidence', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    const second = runs[1];
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    if (!first || !second) return;
    const failed = {
      ...first,
      status: 'failed',
      diagnostic: 'Analyzer failed.',
    };
    const invalidValues = [
      {
        _tag: 'AnalysisIncomplete',
        violations: [{ code: 'analyzer_failed' }],
        analyzerRuns: [failed, ...runs.slice(1)],
      },
      {
        _tag: 'AnalysisIncomplete',
        violations: [
          { code: 'analyzer_failed', analyzer: first.analyzer },
        ],
        analyzerRuns: [failed, first, ...runs.slice(1)],
      },
      {
        _tag: 'AnalysisIncomplete',
        violations: [
          { code: 'analyzer_failed', analyzer: first.analyzer },
        ],
        analyzerRuns: [second, failed, ...runs.slice(2)],
      },
      {
        _tag: 'AnalysisIncomplete',
        violations: [
          { code: 'analyzer_timed_out', analyzer: first.analyzer },
        ],
        analyzerRuns: [failed, ...runs.slice(1)],
      },
      {
        _tag: 'AnalysisIncomplete',
        violations: [
          { code: 'analyzer_failed', analyzer: first.analyzer },
          { code: 'analyzer_failed', analyzer: first.analyzer },
        ],
        analyzerRuns: [failed, ...runs.slice(1)],
      },
    ];
    for (const value of invalidValues) {
      expect(
        Exit.isFailure(Schema.decodeUnknownExit(AnalysisIncomplete)(value)),
      ).toBe(true);
    }
  });

  it('correlates attempted policy drift with runtime mismatch evidence', () => {
    const runs = attemptedRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (!first) return;
    const mismatchedRuns = [
      { ...first, profileVersion: 'alternate-policy' },
      ...runs.slice(1),
    ];
    const inventoryOnly = {
      _tag: 'AnalysisIncomplete',
      violations: [{ code: 'inventory_truncated' }],
      analyzerRuns: mismatchedRuns,
    };
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(AnalysisIncomplete)(inventoryOnly)),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          ...inventoryOnly,
          violations: [{ code: 'runtime_mismatch' }],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AnalysisIncomplete)({
          ...inventoryOnly,
          violations: [{ code: 'runtime_mismatch' }],
          analyzerRuns: runs,
        }),
      ),
    ).toBe(true);
  });
});
