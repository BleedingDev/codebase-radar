import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Deferred, Effect, Exit, Fiber, Layer, Option, Ref } from 'effect';
import { describe, expect, it } from 'vitest';
import { AnalysisObserver, RadarAnalysis } from '@codebase-radar/core';
import {
  AnalysisRequest,
  AnalysisProgressTerminal,
  AnalysisProgressUpdate,
  AnalysisSourceRejected,
  AnalysisSourceUnavailable,
  AnalyzerCoverage,
  CompleteAnalyzerRun,
  DefaultBranchRevision,
  Evidence,
  Finding,
  FindingScores,
  GitHubSource,
  GitHubSourceIdentity,
  RequiredAnalyzerIds,
  ScanComparison,
  ScanProfile,
  ScanSummary,
  SuccessfulScanResult,
  type AnalysisFailure,
  type AnalysisProgress,
} from '@codebase-radar/contracts';
import { ScanRecord } from '../shared/domain';
import { RadarAnalysisObserverLive } from './analysis-observer';
import {
  persistAndAttachScan,
  RepositoryScanAlreadyActive,
  ScanCapacityUnavailable,
  ScanCoordinator,
  ScanCoordinatorLive,
} from './scan-runner';
import { requireCompleteScanResult } from './mcp-read-model';
import {
  decodeStoredPostgresScanRow,
  decodeStoredScan,
  encodeStoredScan,
  MemoryStoreLive,
  RadarStore,
  StorageError,
} from './store';

const TestServices = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);
const onePathSetDigest = `sha256:${'a'.repeat(64)}`;

const runs = () =>
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
          eligiblePathSetDigest: onePathSetDigest,
          analyzedPathSetDigest: onePathSetDigest,
          omittedCapabilities: [],
          warnings: [],
        }),
        observationCount: 1,
      }),
  );

const findingsFor = () => [
  new Finding({
    id: 'finding-high',
    fingerprint: 'fingerprint-high',
    mechanism: 'Structural dependency cycle',
    title: 'High-priority dependency cycle',
    category: 'architecture',
    action: 'investigate',
    summary: 'A bounded cycle is present.',
    technicalSummary: 'Three modules form a direct import cycle.',
    recommendation: 'Separate the shared boundary.',
    scores: new FindingScores({
      consequence: 70,
      blastRadius: 70,
      confidence: 90,
      effort: 30,
      changeExposure: 30,
      priority: 75,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: 'A -> B -> C -> A.',
        path: 'src/a.ts',
        line: 1,
      }),
    ],
    externalReferences: [],
    tags: ['architecture'],
    statusComparedToPrevious: 'new',
  }),
  new Finding({
    id: 'finding-normal',
    fingerprint: 'fingerprint-normal',
    mechanism: 'Repeated dependency boundary',
    title: 'Repeated boundary',
    category: 'architecture',
    action: 'investigate',
    summary: 'A repeated boundary is present.',
    technicalSummary: 'The same dependency boundary appears in two modules.',
    recommendation: 'Extract the shared boundary.',
    scores: new FindingScores({
      consequence: 50,
      blastRadius: 50,
      confidence: 80,
      effort: 40,
      changeExposure: 20,
      priority: 55,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: 'The boundary is duplicated.',
        path: 'src/b.ts',
        line: 1,
      }),
    ],
    externalReferences: [],
    tags: ['architecture'],
    statusComparedToPrevious: 'new',
  }),
];

const canonicalResult = (
  request: AnalysisRequest,
  findings: ReadonlyArray<Finding> = [],
): Effect.Effect<SuccessfulScanResult, AnalysisSourceRejected> => {
  if (request.source._tag !== 'GitHubSource') {
    return Effect.fail(
      new AnalysisSourceRejected({
        message: 'The test result requires a GitHub source.',
      }),
    );
  }
  const source = new GitHubSourceIdentity({
    codebaseId: `github:${request.source.owner.toLowerCase()}/${request.source.repository.toLowerCase()}`,
    owner: request.source.owner,
    repository: request.source.repository,
    url: `https://github.com/${request.source.owner}/${request.source.repository}`,
    commitSha: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    defaultBranch: 'main',
    snapshotDigest: 'git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  });
  const newFingerprints = findings
    .filter(finding => finding.statusComparedToPrevious === 'new')
    .map(finding => finding.fingerprint)
    .sort();
  return Effect.succeed(
    new SuccessfulScanResult({
      schemaVersion: 'codebase-radar.scan-result/v2',
      resultKind: 'complete',
      analysisPolicy: 'dogfood:max/v1',
      scanId: request.scanId,
      source,
      createdAt: request.createdAt,
      completedAt: request.createdAt,
      profile: new ScanProfile({
        frameworks: [],
        languageCoverage: ['TypeScript'],
        limitations: [],
      }),
      summary: new ScanSummary({
        headline: 'Canonical review ready.',
        healthScore: 80,
        fixNow: findings.filter(finding => finding.action === 'fix now').length,
        investigate: findings.filter(finding => finding.action === 'investigate')
          .length,
        monitor: findings.filter(finding => finding.action === 'monitor').length,
        doNotFix: findings.filter(finding => finding.action === 'do not fix')
          .length,
      }),
      findings,
      analyzerRuns: runs(),
      comparison: new ScanComparison({
        basisCodebaseId: source.codebaseId,
        basisPolicyId: 'dogfood:max/v1',
        ...(request.baseline === undefined
          ? {}
          : { previousScanId: request.baseline.scanId }),
        newFingerprints,
        resolvedFingerprints: [],
        persistentFingerprints: [],
        priorityDelta: 0,
      }),
    }),
  );
};

const initialProgress = (request: AnalysisRequest) =>
  new AnalysisProgressUpdate({
    scanId: request.scanId,
    sequence: 0,
    timestamp: request.createdAt,
    completedWork: 0,
    totalWork: 2,
    percent: 0,
    stage: 'preflight',
    terminal: false,
  });

const completedProgress = (request: AnalysisRequest) =>
  new AnalysisProgressTerminal({
    scanId: request.scanId,
    sequence: 1,
    timestamp: request.createdAt,
    completedWork: 2,
    totalWork: 2,
    percent: 100,
    stage: 'terminal',
    terminal: true,
    outcome: 'succeeded',
  });

const fakeAnalysisLive = (
  analyze: (
    request: AnalysisRequest,
    observer: (progress: AnalysisProgress) => Effect.Effect<void>,
  ) => Effect.Effect<SuccessfulScanResult, AnalysisFailure>,
) =>
  Layer.succeed(
    RadarAnalysis,
    RadarAnalysis.of({
      analyze: request =>
        AnalysisObserver.use(observer => analyze(request, observer.observe)),
    }),
  );

const coordinatorLive = (analysis: ReturnType<typeof fakeAnalysisLive>) =>
  ScanCoordinatorLive.pipe(
    Layer.provide(analysis),
    Layer.provideMerge(MemoryStoreLive),
  );

const queueScan = Effect.fn('queueScan')(function* (
  owner: string,
  repository: string,
) {
  const store = yield* RadarStore;
  const coordinator = yield* ScanCoordinator;
  const admission = yield* coordinator.reserve(owner, repository);
  const scan = yield* store.createScan({
    githubUrl: `https://github.com/${owner}/${repository}`,
    owner,
    repository,
    audience: 'technical',
  });
  yield* admission.enqueue(scan);
  return scan;
});

describe('repository scan history', () => {
  it('deduplicates repositories, preserves all history, and canonicalizes URLs', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const first = yield* store.createScan({
          githubUrl: 'https://example.test/not-used',
          owner: 'Acme',
          repository: 'Radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const other = yield* store.createScan({
          githubUrl: 'https://github.com/Elsewhere/App',
          owner: 'Elsewhere',
          repository: 'App',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const newest = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });

        const repositories = yield* store.listRecentRepositories();
        const history = yield* store.listRepositoryScans('ACME', 'RADAR');

        expect(first.githubUrl).toBe('https://github.com/acme/radar');
        expect(repositories.map(scan => scan.id)).toEqual([newest.id, other.id]);
        expect(history.map(scan => scan.id)).toEqual([newest.id, first.id]);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('uses only the newest compatible completed canonical baseline', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<AnalysisRequest>>([]);
        const analysis = fakeAnalysisLive((request, observer) =>
          Effect.gen(function* () {
            yield* observer(initialProgress(request));
            yield* observer(completedProgress(request));
            yield* Ref.update(calls, values => [...values, request]);
            return yield* canonicalResult(request);
          }),
        );
        return yield* Effect.gen(function* () {
          const store = yield* RadarStore;
          const first = yield* queueScan('Acme', 'Radar');
          yield* Effect.sleep('10 millis');
          const second = yield* queueScan('acme', 'radar');
          yield* Effect.sleep('10 millis');
          const requests = yield* Ref.get(calls);
          const completed = yield* store.getScan(second.id);

          expect(requests).toHaveLength(2);
          expect(requests[1]?.baseline?.scanId).toBe(first.id);
          expect(Option.getOrUndefined(completed)?.result?.resultKind).toBe(
            'complete',
          );
        }).pipe(Effect.provide(coordinatorLive(analysis)));
      }).pipe(Effect.provide(TestServices)),
    ));

  it('does not use a result completed after the next scan started', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const first = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const next = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });
        const result = yield* canonicalResult(
          new AnalysisRequest({
            scanId: first.id,
            source: new GitHubSource({
              owner: 'acme',
              repository: 'radar',
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: first.createdAt,
          }),
        );
        yield* store.completeScan(
          first.id,
          new SuccessfulScanResult({
            ...result,
            completedAt: next.createdAt,
          }),
        );

        const baseline = yield* store.getPreviousResult(
          'acme',
          'radar',
          { createdAt: next.createdAt, id: next.id },
        );

        expect(Option.isNone(baseline)).toBe(true);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));
});

describe('stored result compatibility', () => {
  it('keeps persisted v1 records displayable but rejects them as canonical input', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const legacy = JSON.stringify({
          id: 'scan-legacy',
          githubUrl: 'https://github.com/owner/repository',
          owner: 'owner',
          repository: 'repository',
          audience: 'technical',
          status: 'completed',
          progress: 100,
          stage: 'Ready',
          createdAt: '2026-08-11T10:00:00.000Z',
          updatedAt: '2026-08-11T10:01:00.000Z',
          result: {
            schemaVersion: 'codebase-radar.scan-result/v1',
            scanId: 'scan-legacy',
            repository: {
              owner: 'owner',
              name: 'repository',
              url: 'https://github.com/owner/repository',
              commitSha: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              defaultBranch: 'main',
            },
            createdAt: '2026-08-11T10:00:00.000Z',
            completedAt: '2026-08-11T10:01:00.000Z',
            profile: {
              version: 'dogfood:max/v1',
              frameworks: [],
              languageCoverage: ['TypeScript'],
              limitations: [],
            },
            summary: {
              headline: 'Legacy review ready.',
              healthScore: 100,
              fixNow: 0,
              investigate: 0,
              monitor: 0,
              doNotFix: 0,
            },
            findings: [],
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
              previousScanId: 'scan-untrusted-historical-basis',
              newFindingIds: [],
              resolvedFingerprints: [],
              persistentFindingIds: [],
              priorityDelta: 0,
            },
          },
        });
        const decoded = yield* decodeStoredScan(legacy);
        const rewritten = yield* encodeStoredScan(decoded);
        if (decoded.result === undefined) {
          return yield* new StorageError({
            message: 'The persisted legacy scan lost its display result.',
          });
        }
        const canonicalConsumer = yield* Effect.exit(
          requireCompleteScanResult(decoded.result),
        );
        const normalizedRow = {
          id: decoded.id,
          owner: decoded.owner,
          repository: decoded.repository,
          status: decoded.status,
          record_json: rewritten,
          created_at: decoded.createdAt,
          updated_at: decoded.updatedAt,
          lease_token: null,
          lease_expires_at: null,
          baseline_scan_id: null,
        };
        const rowDecoded = yield* decodeStoredPostgresScanRow(normalizedRow);
        const nonNullLegacyBaseline = yield* Effect.exit(
          decodeStoredPostgresScanRow({
            ...normalizedRow,
            baseline_scan_id: 'scan-legacy-baseline',
          }),
        );

        expect(decoded.status).toBe('completed');
        expect(decoded.result?.resultKind).toBe('legacy-noncanonical');
        expect(Exit.isFailure(canonicalConsumer)).toBe(true);
        expect(rowDecoded.result?.comparison.previousScanId).toBeUndefined();
        expect(Exit.isFailure(nonNullLegacyBaseline)).toBe(true);
        expect(rewritten).toContain('codebase-radar.scan-result/v2');
        expect(rewritten).toContain('legacy-noncanonical');
        expect(rewritten).not.toContain('codebase-radar.scan-result/v1');
      }),
    ));

  it('round-trips every canonical finding through the persisted v2 codec', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const request = new AnalysisRequest({
          scanId: 'scan-codec',
          source: new GitHubSource({
            owner: 'acme',
            repository: 'radar',
            revision: new DefaultBranchRevision({}),
          }),
          createdAt: '2026-08-11T10:00:00.000Z',
        });
        const result = yield* canonicalResult(request, findingsFor());
        const record = new ScanRecord({
          id: request.scanId,
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
          status: 'completed',
          progress: 100,
          stage: 'Your review is ready',
          createdAt: request.createdAt,
          updatedAt: request.createdAt,
          result,
        });
        const encoded = yield* encodeStoredScan(record);
        const decoded = yield* decodeStoredScan(encoded);

        expect(decoded.result?.resultKind).toBe('complete');
        expect(decoded.result?.findings.map(finding => finding.id)).toEqual([
          'finding-high',
          'finding-normal',
        ]);
      }),
    ));

  it('requires normalized PostgreSQL columns to match the canonical record and basis', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const request = new AnalysisRequest({
          scanId: 'scan-postgres-coherence',
          source: new GitHubSource({
            owner: 'acme',
            repository: 'radar',
            revision: new DefaultBranchRevision({}),
          }),
          createdAt: '2026-08-11T10:00:00.000Z',
        });
        const result = yield* canonicalResult(request, findingsFor());
        const record = new ScanRecord({
          id: request.scanId,
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
          status: 'completed',
          progress: 100,
          stage: 'Your review is ready',
          createdAt: request.createdAt,
          updatedAt: '2026-08-11T10:01:00.000Z',
          result,
        });
        const recordJson = yield* encodeStoredScan(record);
        const row = {
          id: record.id,
          owner: record.owner,
          repository: record.repository,
          status: record.status,
          record_json: recordJson,
          created_at: record.createdAt,
          updated_at: record.updatedAt,
          lease_token: null,
          lease_expires_at: null,
          baseline_scan_id: null,
        };

        expect((yield* decodeStoredPostgresScanRow(row)).id).toBe(record.id);

        const exits = yield* Effect.forEach(
          [
            { ...row, owner: 'ACME' },
            { ...row, repository: 'RADAR' },
            { ...row, baseline_scan_id: 'scan-unrelated-basis' },
            { ...row, lease_token: 'stale-terminal-lease' },
          ],
          malformed => Effect.exit(decodeStoredPostgresScanRow(malformed)),
        );
        expect(exits.every(Exit.isFailure)).toBe(true);
      }),
    ));

  it('rejects noncanonical active records before they can become durable work', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          {
            id: 'scan-queued-progress',
            githubUrl: 'https://github.com/acme/radar',
            owner: 'acme',
            repository: 'radar',
            audience: 'technical',
            status: 'queued',
            progress: 1,
            stage: 'Queued',
            createdAt: '2026-08-11T10:00:00.000Z',
            updatedAt: '2026-08-11T10:00:00.000Z',
          },
          {
            id: 'scan-active-error',
            githubUrl: 'https://github.com/acme/radar',
            owner: 'acme',
            repository: 'radar',
            audience: 'technical',
            status: 'running',
            progress: 20,
            stage: 'Scanning',
            error: 'A running scan cannot retain a terminal error.',
            createdAt: '2026-08-11T10:00:00.000Z',
            updatedAt: '2026-08-11T10:01:00.000Z',
          },
          {
            id: 'scan-noncanonical-url',
            githubUrl: 'https://github.com/Acme/Radar',
            owner: 'acme',
            repository: 'radar',
            audience: 'technical',
            status: 'queued',
            progress: 0,
            stage: 'Queued',
            createdAt: '2026-08-11T10:00:00.000Z',
            updatedAt: '2026-08-11T10:00:00.000Z',
          },
        ],
        record => Effect.exit(decodeStoredScan(JSON.stringify(record))),
      ).pipe(
        Effect.tap(exits =>
          Effect.sync(() => {
            expect(exits.every(Exit.isFailure)).toBe(true);
          }),
        ),
      ),
    ));

  it('rejects unexpected fields in persisted scan records', () =>
    Effect.runPromise(
      Effect.exit(
        decodeStoredScan(
          JSON.stringify({
            ...new ScanRecord({
              id: 'scan-strict',
              githubUrl: 'https://github.com/acme/radar',
              owner: 'acme',
              repository: 'radar',
              audience: 'technical',
              status: 'queued',
              progress: 2,
              stage: 'Queued',
              createdAt: '2026-08-11T10:00:00.000Z',
              updatedAt: '2026-08-11T10:00:00.000Z',
            }),
            unexpected: 'not part of a persisted ScanRecord',
          }),
        ),
      ).pipe(
        Effect.tap(exit =>
          Effect.sync(() => {
            expect(Exit.isFailure(exit)).toBe(true);
          }),
        ),
      ),
    ));

  it('rejects incoherent terminal states in persisted scan records', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          {
            id: 'scan-completed-without-result',
            githubUrl: 'https://github.com/acme/radar',
            owner: 'acme',
            repository: 'radar',
            audience: 'technical',
            status: 'completed',
            progress: 100,
            stage: 'Ready',
            createdAt: '2026-08-11T10:00:00.000Z',
            updatedAt: '2026-08-11T10:00:01.000Z',
          },
          {
            id: 'scan-failed-without-error',
            githubUrl: 'https://github.com/acme/radar',
            owner: 'acme',
            repository: 'radar',
            audience: 'technical',
            status: 'failed',
            progress: 100,
            stage: 'Failed',
            createdAt: '2026-08-11T10:00:00.000Z',
            updatedAt: '2026-08-11T10:00:01.000Z',
          },
        ],
        record => Effect.exit(decodeStoredScan(JSON.stringify(record))),
      ).pipe(
        Effect.tap(exits =>
          Effect.sync(() => {
            expect(exits.every(Exit.isFailure)).toBe(true);
          }),
        ),
      ),
    ));
});

describe('scan state transitions', () => {
  it('keeps queued and running progress monotonic at the store boundary', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* store.createScan({
          githubUrl: 'https://github.com/acme/monotonic',
          owner: 'acme',
          repository: 'monotonic',
          audience: 'technical',
        });
        expect(scan.progress).toBe(0);
        yield* store.updateScan(scan.id, {
          status: 'running',
          progress: 75,
          stage: 'Advanced',
        });
        yield* store.updateScan(scan.id, {
          status: 'running',
          progress: 25,
          stage: 'Stale',
        });
        const invalid = yield* Effect.exit(store.updateScan(scan.id, {
          status: 'running',
          progress: 101,
          stage: 'Invalid',
        }));
        const current = Option.getOrUndefined(yield* store.getScan(scan.id));
        expect(current?.progress).toBe(75);
        expect(current?.stage).toBe('Advanced');
        expect(Exit.isFailure(invalid)).toBe(true);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('refuses an empty terminal error rather than writing an incoherent failed record', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* store.createScan({
          githubUrl: 'https://github.com/acme/terminal-error',
          owner: 'acme',
          repository: 'terminal-error',
          audience: 'technical',
        });
        const rejected = yield* Effect.exit(
          store.failScanIfActive(scan.id, {
            stage: 'Scan failed safely',
            error: '   ',
          }),
        );
        const current = Option.getOrUndefined(yield* store.getScan(scan.id));

        expect(Exit.isFailure(rejected)).toBe(true);
        expect(current?.status).toBe('queued');
        expect(current?.error).toBeUndefined();
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('does not advance observer history when the fenced store rejects a regression', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* store.createScan({
          githubUrl: 'https://github.com/acme/observer-fence',
          owner: 'acme',
          repository: 'observer-fence',
          audience: 'technical',
        });
        const claim = yield* store.claimScan(
          scan.id,
          new Date(Date.now() + 60_000).toISOString(),
        );
        if (Option.isNone(claim)) {
          return yield* new StorageError({
            message: 'The test scan could not acquire its lease.',
          });
        }
        yield* store.updateScan(
          scan.id,
          {
            status: 'running',
            progress: 50,
            stage: 'Recovered work is already durable',
          },
          claim.value.lease,
        );
        const observer = yield* AnalysisObserver.pipe(
          Effect.provide(
            RadarAnalysisObserverLive(scan.id, claim.value.lease),
          ),
        );
        const request = new AnalysisRequest({
          scanId: scan.id,
          source: new GitHubSource({
            owner: scan.owner,
            repository: scan.repository,
            revision: new DefaultBranchRevision({}),
          }),
          createdAt: scan.createdAt,
        });
        yield* observer.observe(initialProgress(request));
        yield* observer.observe(
          new AnalysisProgressUpdate({
            ...initialProgress(request),
            completedWork: 1,
            percent: 50,
            stage: 'analyzing',
          }),
        );

        const current = Option.getOrUndefined(yield* store.getScan(scan.id));
        expect(current?.progress).toBe(50);
        expect(current?.stage).toBe('Running the required analysis policy');
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('does not persist a structurally surplus result through the store boundary', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* store.createScan({
          githubUrl: 'https://github.com/acme/store-boundary',
          owner: 'acme',
          repository: 'store-boundary',
          audience: 'technical',
        });
        const result = yield* canonicalResult(
          new AnalysisRequest({
            scanId: scan.id,
            source: new GitHubSource({
              owner: 'acme',
              repository: 'store-boundary',
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: scan.createdAt,
          }),
        );
        const surplus = {
          ...result,
          unexpected: 'not part of the canonical result contract',
        };
        const rejected = yield* store.completeScan(scan.id, surplus).pipe(
          Effect.flip,
        );
        const preserved = yield* store.getScan(scan.id);

        expect(rejected).toBeInstanceOf(StorageError);
        expect(Option.getOrUndefined(preserved)?.status).toBe('queued');
        expect(Option.getOrUndefined(preserved)?.result).toBeUndefined();
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('atomically rejects a canonical result for another source or comparison basis', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* store.createScan({
          githubUrl: 'https://github.com/acme/transaction',
          owner: 'acme',
          repository: 'transaction',
          audience: 'technical',
        });
        const foreignResult = yield* canonicalResult(
          new AnalysisRequest({
            scanId: scan.id,
            source: new GitHubSource({
              owner: 'acme',
              repository: 'foreign',
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: scan.createdAt,
          }),
        );
        const foreignExit = yield* Effect.exit(
          store.completeScan(scan.id, foreignResult),
        );

        const baselineCreatedAt = new Date(Date.parse(scan.createdAt) - 1_000).toISOString();
        const baseline = yield* canonicalResult(
          new AnalysisRequest({
            scanId: 'scan-transaction-baseline',
            source: new GitHubSource({
              owner: scan.owner,
              repository: scan.repository,
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: baselineCreatedAt,
          }),
        );
        const compared = yield* canonicalResult(
          new AnalysisRequest({
            scanId: scan.id,
            source: new GitHubSource({
              owner: scan.owner,
              repository: scan.repository,
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: scan.createdAt,
            baseline,
          }),
        );
        const missingBasisExit = yield* Effect.exit(
          store.completeScan(scan.id, compared),
        );
        const withoutBaseline = yield* canonicalResult(
          new AnalysisRequest({
            scanId: scan.id,
            source: new GitHubSource({
              owner: scan.owner,
              repository: scan.repository,
              revision: new DefaultBranchRevision({}),
            }),
            createdAt: scan.createdAt,
          }),
        );
        const completed = yield* store.completeScan(scan.id, withoutBaseline);

        expect(Exit.isFailure(foreignExit)).toBe(true);
        expect(Exit.isFailure(missingBasisExit)).toBe(true);
        expect(completed.status).toBe('completed');
        expect(completed.result?.comparison.previousScanId).toBeUndefined();
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('attaches a persisted scan before honoring request interruption', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const persisted = yield* Deferred.make<string>();
        const allowAttachment = yield* Deferred.make<void>();
        const attached = yield* Deferred.make<string>();
        const persist = store
          .createScan({
            githubUrl: 'https://github.com/acme/interrupted',
            owner: 'acme',
            repository: 'interrupted',
            audience: 'technical',
          })
          .pipe(
            Effect.tap(scan => Deferred.succeed(persisted, scan.id)),
            Effect.tap(() => Deferred.await(allowAttachment)),
          );
        const fiber = yield* Effect.forkChild(
          persistAndAttachScan(persist, scan =>
            Deferred.succeed(attached, scan.id).pipe(Effect.asVoid),
          ),
        );
        const scanId = yield* Deferred.await(persisted);
        const interruptor = yield* Effect.forkChild(Fiber.interrupt(fiber));
        yield* Effect.yieldNow;
        yield* Deferred.succeed(allowAttachment, undefined);
        yield* Fiber.join(interruptor);

        expect(yield* Deferred.await(attached)).toBe(scanId);
        expect(Option.getOrUndefined(yield* store.getScan(scanId))?.status).toBe(
          'queued',
        );
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('keeps an attached scan running after its request fiber disconnects', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const started = yield* Deferred.make<void>();
        const releaseAnalysis = yield* Deferred.make<void>();
        const requestAttached = yield* Deferred.make<ScanRecord>();
        const waitForResponse = yield* Deferred.make<void>();
        const analysis = fakeAnalysisLive((request, observer) =>
          Effect.gen(function* () {
            yield* observer(initialProgress(request));
            yield* Deferred.succeed(started, undefined);
            yield* Deferred.await(releaseAnalysis);
            yield* observer(completedProgress(request));
            return yield* canonicalResult(request);
          }),
        );
        return yield* Effect.gen(function* () {
          const store = yield* RadarStore;
          const coordinator = yield* ScanCoordinator;
          const request = Effect.acquireUseRelease(
            coordinator.reserve('acme', 'disconnect'),
            admission =>
              persistAndAttachScan(
                store.createScan({
                  githubUrl: 'https://github.com/acme/disconnect',
                  owner: 'acme',
                  repository: 'disconnect',
                  audience: 'technical',
                }),
                scan => admission.enqueue(scan),
              ).pipe(
                Effect.tap(scan => Deferred.succeed(requestAttached, scan)),
                Effect.andThen(Deferred.await(waitForResponse)),
              ),
            admission => admission.release,
          );
          const requestFiber = yield* Effect.forkChild(request);
          const scan = yield* Deferred.await(requestAttached);
          yield* Deferred.await(started);
          yield* Fiber.interrupt(requestFiber);
          yield* Deferred.succeed(releaseAnalysis, undefined);
          yield* Effect.sleep('10 millis');
          const completed = yield* store.getScan(scan.id);

          expect(Option.getOrUndefined(completed)?.status).toBe('completed');
          expect(Option.getOrUndefined(completed)?.result?.resultKind).toBe(
            'complete',
          );
        }).pipe(Effect.provide(coordinatorLive(analysis)));
      }).pipe(Effect.provide(TestServices)),
    ));

  it('keeps progress observation non-failing and persists all canonical findings once', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make(0);
        const started = yield* Deferred.make<void>();
        const release = yield* Deferred.make<void>();
        const terminalObserved = yield* Deferred.make<void>();
        const allowResult = yield* Deferred.make<void>();
        const analysis = fakeAnalysisLive((request, observer) =>
          Effect.gen(function* () {
            yield* Ref.update(calls, value => value + 1);
            yield* observer(
              new AnalysisProgressUpdate({
                ...initialProgress(request),
                sequence: 9,
                completedWork: 1,
                percent: 50,
                stage: 'materializing',
              }),
            );
            yield* observer(initialProgress(request));
            yield* Deferred.succeed(started, undefined);
            yield* Deferred.await(release);
            yield* observer(completedProgress(request));
            yield* observer(
              new AnalysisProgressUpdate({
                ...initialProgress(request),
                sequence: 1,
                completedWork: 1,
                percent: 50,
                stage: 'comparing',
              }),
            );
            yield* Deferred.succeed(terminalObserved, undefined);
            yield* Deferred.await(allowResult);
            return yield* canonicalResult(request, findingsFor());
          }),
        );
        return yield* Effect.gen(function* () {
          const store = yield* RadarStore;
          const scan = yield* queueScan('acme', 'radar');
          yield* Deferred.await(started);
          const running = yield* store.getScan(scan.id);
          expect(Option.getOrUndefined(running)?.status).toBe('running');
          expect(Option.getOrUndefined(running)?.progress).toBe(0);
          expect(Option.getOrUndefined(running)?.result).toBeUndefined();

          yield* Deferred.succeed(release, undefined);
          yield* Deferred.await(terminalObserved);
          const terminal = yield* store.getScan(scan.id);
          expect(Option.getOrUndefined(terminal)?.progress).toBe(100);
          expect(Option.getOrUndefined(terminal)?.stage).toBe(
            'Finalizing canonical scan result',
          );
          yield* Deferred.succeed(allowResult, undefined);
          yield* Effect.sleep('10 millis');
          const completed = yield* store.getScan(scan.id);
          yield* store.updateScan(scan.id, {
            status: 'running',
            progress: 3,
            stage: 'Late progress must not reopen a completed scan',
          });
          const preserved = yield* store.getScan(scan.id);

          expect(yield* Ref.get(calls)).toBe(1);
          expect(Option.getOrUndefined(completed)?.status).toBe('completed');
          expect(Option.getOrUndefined(completed)?.result?.findings.map(
            finding => finding.id,
          )).toEqual(['finding-high', 'finding-normal']);
          expect(Option.getOrUndefined(preserved)?.result?.findings.map(
            finding => finding.id,
          )).toEqual(['finding-high', 'finding-normal']);
        }).pipe(Effect.provide(coordinatorLive(analysis)));
      }).pipe(Effect.provide(TestServices)),
    ));

  it('persists a typed failure with no partial result', () => {
    const analysis = fakeAnalysisLive((request, observer) =>
      observer(initialProgress(request)).pipe(
        Effect.andThen(
          Effect.fail(
            new AnalysisSourceUnavailable({
              message: 'The public GitHub snapshot is unavailable.',
            }),
          ),
        ),
      ),
    );
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* queueScan('acme', 'unavailable');
        yield* Effect.sleep('10 millis');
        const failed = yield* store.getScan(scan.id);

        expect(Option.getOrUndefined(failed)?.status).toBe('failed');
        expect(Option.getOrUndefined(failed)?.result).toBeUndefined();
        expect(Option.getOrUndefined(failed)?.error).toBe(
          'The public GitHub snapshot is unavailable.',
        );
      }).pipe(
        Effect.provide(coordinatorLive(analysis)),
        Effect.provide(TestServices),
      ),
    );
  });

  it('rejects a canonical result that belongs to another scan', () => {
    const analysis = fakeAnalysisLive((request, observer) =>
      observer(initialProgress(request)).pipe(
        Effect.andThen(canonicalResult(request)),
        Effect.map(
          result =>
            new SuccessfulScanResult({
              ...result,
              scanId: 'scan-from-another-request',
            }),
        ),
      ),
    );
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* queueScan('acme', 'misaligned-result');
        yield* Effect.sleep('10 millis');
        const failed = yield* store.getScan(scan.id);

        expect(Option.getOrUndefined(failed)?.status).toBe('failed');
        expect(Option.getOrUndefined(failed)?.result).toBeUndefined();
        expect(Option.getOrUndefined(failed)?.error).toBe(
          'The analysis runtime returned a result for a different GitHub scan.',
        );
      }).pipe(
        Effect.provide(coordinatorLive(analysis)),
        Effect.provide(TestServices),
      ),
    );
  });

  it('rejects an analysis result with unexpected fields without persisting it', () => {
    const analysis = fakeAnalysisLive((request, observer) =>
      observer(initialProgress(request)).pipe(
        Effect.andThen(canonicalResult(request)),
        Effect.map(result => ({
          ...result,
          unexpected: 'not part of the canonical result contract',
        })),
      ),
    );
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const scan = yield* queueScan('acme', 'strict-result');
        yield* Effect.sleep('10 millis');
        const failed = yield* store.getScan(scan.id);

        expect(Option.getOrUndefined(failed)?.status).toBe('failed');
        expect(Option.getOrUndefined(failed)?.result).toBeUndefined();
        expect(Option.getOrUndefined(failed)?.error).toBe(
          'The analysis runtime returned an invalid canonical result.',
        );
      }).pipe(
        Effect.provide(coordinatorLive(analysis)),
        Effect.provide(TestServices),
      ),
    );
  });

  it('keeps different repositories admitted while one queued scan is running', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make(0);
        const firstStarted = yield* Deferred.make<void>();
        const releaseFirst = yield* Deferred.make<void>();
        const analysis = fakeAnalysisLive((request, observer) =>
          Effect.gen(function* () {
            const first = yield* Ref.modify(calls, count => [count === 0, count + 1]);
            yield* observer(initialProgress(request));
            if (first) {
              yield* Deferred.succeed(firstStarted, undefined);
              yield* Deferred.await(releaseFirst);
            }
            yield* observer(completedProgress(request));
            return yield* canonicalResult(request);
          }),
        );
        return yield* Effect.gen(function* () {
          const store = yield* RadarStore;
          const scans = yield* Effect.all([
            queueScan('acme', 'concurrent-one'),
            queueScan('acme', 'concurrent-two'),
          ], { concurrency: 'unbounded' });
          yield* Deferred.await(firstStarted);
          const active = yield* Effect.forEach(scans, scan => store.getScan(scan.id));

          expect(active.map(Option.getOrUndefined).filter(
            scan => scan?.status === 'running',
          )).toHaveLength(1);
          expect(active.map(Option.getOrUndefined).filter(
            scan => scan?.status === 'queued',
          )).toHaveLength(1);

          yield* Deferred.succeed(releaseFirst, undefined);
          yield* Effect.sleep('15 millis');
          const finished = yield* Effect.forEach(scans, scan => store.getScan(scan.id));

          expect(yield* Ref.get(calls)).toBe(2);
          expect(finished.map(Option.getOrUndefined).every(
            scan => scan?.status === 'completed',
          )).toBe(true);
        }).pipe(Effect.provide(coordinatorLive(analysis)));
      }).pipe(Effect.provide(TestServices)),
    ));

  it('marks active work failed on scoped restart while preserving terminal records', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const started = yield* Deferred.make<void>();
        const neverFinish = yield* Deferred.make<void>();
        const analysis = fakeAnalysisLive((request, observer) =>
          Effect.gen(function* () {
            yield* observer(initialProgress(request));
            yield* Deferred.succeed(started, undefined);
            yield* Deferred.await(neverFinish);
            return yield* canonicalResult(request);
          }),
        );
        const store = yield* RadarStore;
        const scanId = yield* Effect.scoped(
          Effect.gen(function* () {
            const coordinator = yield* ScanCoordinator;
            const admission = yield* coordinator.reserve('acme', 'restart');
            const scan = yield* store.createScan({
              githubUrl: 'https://github.com/acme/restart',
              owner: 'acme',
              repository: 'restart',
              audience: 'technical',
            });
            yield* admission.enqueue(scan);
            yield* Deferred.await(started);
            return scan.id;
          }).pipe(
            Effect.provide(
              ScanCoordinatorLive.pipe(
                Layer.provide(analysis),
              ),
            ),
          ),
        );
        const restarted = yield* store.getScan(scanId);

        expect(Option.getOrUndefined(restarted)?.status).toBe('failed');
        expect(Option.getOrUndefined(restarted)?.stage).toBe(
          'Scan stopped before completion',
        );
        expect(Option.getOrUndefined(restarted)?.result).toBeUndefined();
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));
});

describe('scan admission', () => {
  it('atomically excludes concurrent scans of the same repository', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const coordinator = yield* ScanCoordinator;
        const admission = yield* coordinator.reserve('Acme', 'Radar');
        const duplicate = yield* coordinator
          .reserve('acme', 'radar')
          .pipe(Effect.flip);

        expect(duplicate).toBeInstanceOf(RepositoryScanAlreadyActive);
        yield* admission.release;
        const retried = yield* coordinator.reserve('ACME', 'RADAR');
        yield* retried.release;
      }).pipe(
        Effect.provide(
          coordinatorLive(
            fakeAnalysisLive((request, observer) =>
              observer(initialProgress(request)).pipe(
                Effect.andThen(canonicalResult(request)),
              ),
            ),
          ),
        ),
        Effect.provide(TestServices),
      ),
    ));

  it('rejects immediately when all process-wide scan slots are reserved', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const coordinator = yield* ScanCoordinator;
        const admissions = yield* Effect.forEach(
          Array.from({ length: 32 }, (_, index) => index),
          index => coordinator.reserve('acme', `repository-${index}`),
        );
        const rejected = yield* coordinator
          .reserve('acme', 'one-too-many')
          .pipe(Effect.flip);

        expect(rejected).toBeInstanceOf(ScanCapacityUnavailable);
        yield* Effect.forEach(admissions, admission => admission.release, {
          discard: true,
        });
      }).pipe(
        Effect.provide(
          coordinatorLive(
            fakeAnalysisLive(() =>
              Effect.fail(
                new AnalysisSourceUnavailable({
                  message: 'No scan should run while testing reservations.',
                }),
              ),
            ),
          ),
        ),
        Effect.provide(TestServices),
      ),
    ));
});
