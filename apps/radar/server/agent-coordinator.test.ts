import { NodeServices } from '@effect/platform-node';
import { createHash } from 'node:crypto';
import { Deferred, Effect, Option, Ref, Schema } from 'effect';
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
  RequiredAnalyzerIds,
  RepositoryPathSetDigest,
  ScanComparison,
  ScanProfile,
  ScanRecord,
  ScanSummary,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  AgentCoordinator,
  AgentCoordinatorLive,
  selectFairOwner,
  verifyBoundAgentReviewScan,
} from './agent-coordinator';
import { AgentRuntime, AgentRuntimeError } from './agent-runtime';
import {
  AgentStore,
  MemoryAgentStoreLive,
  makeScanAccessVisibilityAttestation,
  publicGitHubVisibilityPolicyVersion,
  ScanAccessGrant,
} from './agent-store';
import { AgentScanVisibilityGate } from './agent-visibility-gate';
import {
  canonicalFindingInventoryDigest,
  canonicalResultDigest,
} from './agent-priority-overlay';
import { RadarStore, StorageError } from './store';

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

const unavailableStore = () => new StorageError({ message: 'Unavailable in this test.' });
const unavailableRuntime = () => new AgentRuntimeError({ message: 'Unavailable in this test.' });

const unavailableScanSource = new GitHubSourceIdentity({
  codebaseId: 'github:test-owner/test-repository',
  owner: 'test-owner',
  repository: 'test-repository',
  url: 'https://github.com/test-owner/test-repository',
  commitSha: 'c'.repeat(40),
  defaultBranch: 'main',
  snapshotDigest: `git:${'c'.repeat(40)}`,
});

const unavailableScanGrant = (ownerId: string) => {
  const canonicalResultDigest = 'a'.repeat(64);
  const findingInventoryDigest = 'b'.repeat(64);
  const visibility = makeScanAccessVisibilityAttestation(
    publicGitHubVisibilityPolicyVersion,
    unavailableScanSource,
    canonicalResultDigest,
    findingInventoryDigest,
  );
  return new ScanAccessGrant({
    reviewOwnerId: ownerId,
    scanId: 'scan-not-visible',
    canonicalResultDigest,
    source: unavailableScanSource,
    findingInventoryDigest,
    visibilityPolicyVersion: visibility.policyVersion,
    visibilityAttestation: visibility.attestation,
  });
};

const completeAnalyzerRuns = () =>
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

const completeScanResult = () => {
  const finding = new Finding({
    id: 'finding-one',
    fingerprint: 'fingerprint-one',
    mechanism: 'dependency cycle',
    title: 'Dependency cycle',
    category: 'architecture',
    action: 'investigate',
    summary: 'A canonical dependency cycle is present.',
    technicalSummary: 'The canonical analysis observed a dependency cycle.',
    recommendation: 'Separate the affected module boundary.',
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
        message: 'Canonical evidence.',
        path: 'src/cycle.ts',
        line: 1,
      }),
    ],
    externalReferences: [],
    tags: ['architecture'],
    statusComparedToPrevious: 'new',
  });
  return new SuccessfulScanResult({
    schemaVersion: 'codebase-radar.scan-result/v2',
    resultKind: 'complete',
    analysisPolicy: 'dogfood:max/v1',
    scanId: 'scan-bound',
    source: unavailableScanSource,
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
      investigate: 1,
      monitor: 0,
      doNotFix: 0,
    }),
    findings: [finding],
    analyzerRuns: completeAnalyzerRuns(),
    comparison: new ScanComparison({
      basisCodebaseId: unavailableScanSource.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      newFingerprints: [finding.fingerprint],
      resolvedFingerprints: [],
      persistentFingerprints: [],
      priorityDelta: 0,
    }),
  });
};

const recordFor = (result: SuccessfulScanResult) =>
  new ScanRecord({
    id: result.scanId,
    githubUrl: result.source._tag === 'GitHubSourceIdentity'
      ? result.source.url
      : 'https://github.com/test-owner/test-repository',
    owner: 'test-owner',
    repository: 'test-repository',
    audience: 'technical',
    status: 'completed',
    progress: 100,
    stage: 'ready',
    createdAt: result.createdAt,
    updatedAt: result.completedAt,
    result,
  });

const separatelyAttestedGrant = (
  ownerId: string,
  result: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  inventory: string,
) => {
  const resultDigest = canonicalResultDigest(result);
  const visibility = makeScanAccessVisibilityAttestation(
    publicGitHubVisibilityPolicyVersion,
    source,
    resultDigest,
    inventory,
  );
  return new ScanAccessGrant({
    reviewOwnerId: ownerId,
    scanId: result.scanId,
    canonicalResultDigest: resultDigest,
    source,
    findingInventoryDigest: inventory,
    visibilityPolicyVersion: visibility.policyVersion,
    visibilityAttestation: visibility.attestation,
  });
};

const makeRadarStore = (read: Deferred.Deferred<void>) =>
  RadarStore.of({
    storage: 'memory',
    ready: Effect.void,
    createProfile: () => Effect.fail(unavailableStore()),
    createScan: () => Effect.fail(unavailableStore()),
    updateScan: () => Effect.fail(unavailableStore()),
    completeScan: () => Effect.fail(unavailableStore()),
    failScanIfActive: () => Effect.void,
    claimScan: () => Effect.succeed(Option.none()),
    claimNextScan: () => Effect.succeed(Option.none()),
    renewScanLease: () => Effect.succeed(Option.none()),
    getScan: () =>
      Deferred.succeed(read, undefined).pipe(
        Effect.andThen(Effect.succeed(Option.none())),
      ),
    listRecentScans: () => Effect.succeed([]),
    listRecentRepositories: () => Effect.succeed([]),
    listRepositoryScans: () => Effect.succeed([]),
    getPreviousResult: () => Effect.succeed(Option.none()),
  });

const blockingRadarStore = (entered: Deferred.Deferred<void>) =>
  RadarStore.of({
    storage: 'memory',
    ready: Effect.void,
    createProfile: () => Effect.fail(unavailableStore()),
    createScan: () => Effect.fail(unavailableStore()),
    updateScan: () => Effect.fail(unavailableStore()),
    completeScan: () => Effect.fail(unavailableStore()),
    failScanIfActive: () => Effect.void,
    claimScan: () => Effect.succeed(Option.none()),
    claimNextScan: () => Effect.succeed(Option.none()),
    renewScanLease: () => Effect.succeed(Option.none()),
    getScan: () =>
      Deferred.succeed(entered, undefined).pipe(Effect.andThen(Effect.never)),
    listRecentScans: () => Effect.succeed([]),
    listRecentRepositories: () => Effect.succeed([]),
    listRepositoryScans: () => Effect.succeed([]),
    getPreviousResult: () => Effect.succeed(Option.none()),
  });

const completeRadarStore = (record: ScanRecord) =>
  RadarStore.of({
    storage: 'memory',
    ready: Effect.void,
    createProfile: () => Effect.fail(unavailableStore()),
    createScan: () => Effect.fail(unavailableStore()),
    updateScan: () => Effect.fail(unavailableStore()),
    completeScan: () => Effect.fail(unavailableStore()),
    failScanIfActive: () => Effect.void,
    claimScan: () => Effect.succeed(Option.none()),
    claimNextScan: () => Effect.succeed(Option.none()),
    renewScanLease: () => Effect.succeed(Option.none()),
    getScan: () => Effect.succeed(Option.some(record)),
    listRecentScans: () => Effect.succeed([]),
    listRecentRepositories: () => Effect.succeed([]),
    listRepositoryScans: () => Effect.succeed([]),
    getPreviousResult: () => Effect.succeed(Option.none()),
  });

const makeRuntime = (providerCalls: Ref.Ref<number>) =>
  AgentRuntime.of({
    ready: Effect.void,
    beginLogin: () => Effect.fail(unavailableRuntime()),
    pollLogin: () => Effect.fail(unavailableRuntime()),
    submitLoginInput: () => Effect.fail(unavailableRuntime()),
    cancelLogin: () => Effect.void,
    refreshStatus: () => Effect.fail(unavailableRuntime()),
    disconnect: () => Effect.void,
    prioritizeChunk: () =>
      Ref.update(providerCalls, count => count + 1).pipe(
        Effect.andThen(Effect.fail(unavailableRuntime())),
      ),
    prioritizeMerge: () =>
      Ref.update(providerCalls, count => count + 1).pipe(
        Effect.andThen(Effect.fail(unavailableRuntime())),
      ),
  });

const recoveringRuntime = (started: Deferred.Deferred<void>) =>
  AgentRuntime.of({
    ready: Effect.void,
    beginLogin: () => Effect.fail(unavailableRuntime()),
    pollLogin: () => Effect.fail(unavailableRuntime()),
    submitLoginInput: () => Effect.fail(unavailableRuntime()),
    cancelLogin: () => Effect.void,
    refreshStatus: () => Effect.fail(unavailableRuntime()),
    disconnect: () => Effect.void,
    prioritizeChunk: () =>
      Deferred.succeed(started, undefined).pipe(Effect.andThen(Effect.never)),
    prioritizeMerge: () => Effect.fail(unavailableRuntime()),
  });

describe('agent review fair scheduling', () => {
  it('rotates eligible owners instead of draining the first owner queue', () => {
    const first = selectFairOwner(
      ['owner-one', 'owner-two', 'owner-three'],
      new Map([
        ['owner-one', 4],
        ['owner-two', 1],
        ['owner-three', 1],
      ]),
      new Set(),
    );
    const second = selectFairOwner(
      ['owner-two', 'owner-three', 'owner-one'],
      new Map([
        ['owner-one', 3],
        ['owner-two', 1],
        ['owner-three', 1],
      ]),
      new Set(),
    );
    const third = selectFairOwner(
      ['owner-three', 'owner-one', 'owner-two'],
      new Map([
        ['owner-one', 3],
        ['owner-two', 0],
        ['owner-three', 1],
      ]),
      new Set(),
    );

    expect([first, second, third]).toEqual([
      'owner-one',
      'owner-two',
      'owner-three',
    ]);
  });

  it('does not schedule a second provider process for an active owner', () => {
    const selected = selectFairOwner(
      ['owner-one', 'owner-two'],
      new Map([
        ['owner-one', 3],
        ['owner-two', 1],
      ]),
      new Set(['owner-one']),
    );

    expect(selected).toBe('owner-two');
  });

  it('makes zero provider calls when persisted scan revalidation fails', () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const scanRead = yield* Deferred.make<void>();
          const providerCalls = yield* Ref.make(0);
          yield* Effect.gen(function* () {
            const store = yield* AgentStore;
            const coordinator = yield* AgentCoordinator;
            const ownerId = yield* store.getOrCreateSession();
            const profile = yield* store.createProfile(ownerId, 'codex');
            const review = yield* store.createReview(
              ownerId,
              profile.id,
              unavailableScanGrant(ownerId),
            );
            yield* coordinator.enqueue(ownerId, review);
            yield* Deferred.await(scanRead);

            expect(yield* Ref.get(providerCalls)).toBe(0);
          }).pipe(
            Effect.provide(AgentCoordinatorLive),
            Effect.provide(MemoryAgentStoreLive),
            Effect.provideService(RadarStore, makeRadarStore(scanRead)),
            Effect.provideService(AgentRuntime, makeRuntime(providerCalls)),
            Effect.provideService(
              AgentScanVisibilityGate,
              AgentScanVisibilityGate.of({ verify: () => Effect.void }),
            ),
          );
        }),
      ).pipe(
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('cancels an active persisted review before any provider disclosure', () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const scanRead = yield* Deferred.make<void>();
          const providerCalls = yield* Ref.make(0);
          yield* Effect.gen(function* () {
            const store = yield* AgentStore;
            const coordinator = yield* AgentCoordinator;
            const ownerId = yield* store.getOrCreateSession();
            const profile = yield* store.createProfile(ownerId, 'codex');
            const review = yield* store.createReview(
              ownerId,
              profile.id,
              unavailableScanGrant(ownerId),
            );

            yield* coordinator.enqueue(ownerId, review);
            yield* Deferred.await(scanRead);
            yield* coordinator.cancel(ownerId, review.id);

            const cancelled = yield* store.getReview(ownerId, review.id);
            expect(Option.isSome(cancelled)).toBe(true);
            if (Option.isSome(cancelled)) {
              expect(cancelled.value.status).toBe('failed');
              expect(cancelled.value.diagnostic).toBe('The priority review was cancelled.');
            }
            expect(yield* Ref.get(providerCalls)).toBe(0);
          }).pipe(
            Effect.provide(AgentCoordinatorLive),
            Effect.provide(MemoryAgentStoreLive),
            Effect.provideService(RadarStore, blockingRadarStore(scanRead)),
            Effect.provideService(AgentRuntime, makeRuntime(providerCalls)),
            Effect.provideService(
              AgentScanVisibilityGate,
              AgentScanVisibilityGate.of({ verify: () => Effect.void }),
            ),
          );
        }),
      ).pipe(
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('recovers a queued persisted review when the coordinator starts', () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const store = yield* AgentStore;
          const ownerId = yield* store.getOrCreateSession();
          const profile = yield* store.createProfile(ownerId, 'codex');
          yield* store.updateProfile(ownerId, profile.id, { state: 'connected' });
          const result = completeScanResult();
          const review = yield* store.createReview(
            ownerId,
            profile.id,
            separatelyAttestedGrant(
              ownerId,
              result,
              unavailableScanSource,
              canonicalFindingInventoryDigest(result),
            ),
          );
          const providerStarted = yield* Deferred.make<void>();

          yield* Effect.gen(function* () {
            yield* AgentCoordinator;
            yield* Deferred.await(providerStarted);

            const recovered = yield* store.getReview(ownerId, review.id);
            expect(Option.isSome(recovered)).toBe(true);
            if (Option.isSome(recovered)) {
              expect(recovered.value.status).toBe('running');
            }
          }).pipe(
            Effect.provide(AgentCoordinatorLive),
            Effect.provideService(AgentRuntime, recoveringRuntime(providerStarted)),
          );
        }).pipe(
          Effect.provide(MemoryAgentStoreLive),
          Effect.provideService(RadarStore, completeRadarStore(recordFor(completeScanResult()))),
          Effect.provideService(
            AgentScanVisibilityGate,
            AgentScanVisibilityGate.of({ verify: () => Effect.void }),
          ),
        ),
      ).pipe(
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('rejects separately attested source or inventory changes before visibility or provider disclosure', () => {
    const visibilityCalls = Effect.runSync(Ref.make(0));
    const result = completeScanResult();
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const mutatedSource = new GitHubSourceIdentity({
          ...unavailableScanSource,
          commitSha: 'd'.repeat(40),
          snapshotDigest: `git:${'d'.repeat(40)}`,
        });
        const grants = [
          separatelyAttestedGrant(
            ownerId,
            result,
            mutatedSource,
            canonicalFindingInventoryDigest(result),
          ),
          separatelyAttestedGrant(
            ownerId,
            result,
            unavailableScanSource,
            'e'.repeat(64),
          ),
        ];

        for (const grant of grants) {
          const review = yield* store.createReview(ownerId, profile.id, grant);
          const checked = yield* Effect.exit(
            verifyBoundAgentReviewScan({ ownerId, review }),
          );
          expect(checked._tag).toBe('Failure');
        }
        expect(yield* Ref.get(visibilityCalls)).toBe(0);
      }).pipe(
        Effect.provide(MemoryAgentStoreLive),
        Effect.provideService(RadarStore, completeRadarStore(recordFor(result))),
        Effect.provideService(
          AgentScanVisibilityGate,
          AgentScanVisibilityGate.of({
            verify: () => Ref.update(visibilityCalls, count => count + 1),
          }),
        ),
        Effect.provide(NodeServices.layer),
      ),
    );
  });
});
