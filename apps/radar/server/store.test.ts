import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Deferred, Effect, Fiber, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  RepositorySnapshot,
  ScanComparison,
  ScanProfile,
  ScanResult,
  ScanSummary,
} from '../shared/domain';
import {
  persistAndAttachScan,
  RepositoryScanAlreadyActive,
  ScanCapacityUnavailable,
  ScanCoordinator,
  ScanCoordinatorLive,
} from './scan-runner';
import { MemoryStoreLive, RadarStore } from './store';

const TestServices = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);

const resultFor = (scanId: string, createdAt: string) =>
  new ScanResult({
    schemaVersion: 'codebase-radar.scan-result/v1',
    scanId,
    repository: new RepositorySnapshot({
      owner: 'acme',
      name: 'radar',
      url: 'https://github.com/acme/radar',
      commitSha: scanId,
      defaultBranch: 'main',
    }),
    createdAt,
    completedAt: createdAt,
    profile: new ScanProfile({
      version: '2026-08-09',
      frameworks: [],
      languageCoverage: ['TypeScript'],
      limitations: [],
    }),
    summary: new ScanSummary({
      headline: 'Test result',
      healthScore: 100,
      fixNow: 0,
      investigate: 0,
      monitor: 0,
      doNotFix: 0,
    }),
    findings: [],
    analyzerRuns: [],
    comparison: new ScanComparison({
      newFindingIds: [],
      resolvedFingerprints: [],
      persistentFindingIds: [],
      priorityDelta: 0,
    }),
  });

describe('repository scan history', () => {
  it('deduplicates repositories and retains every case-insensitive scan', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const first = yield* store.createScan({
          githubUrl: 'https://github.com/Acme/Radar',
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
        const historicalSnapshot = yield* store.getScan(first.id);

        expect(repositories.map(scan => scan.id)).toEqual([newest.id, other.id]);
        expect(repositories[0]?.owner).toBe('acme');
        expect(repositories[0]?.repository).toBe('radar');
        expect(history.map(scan => scan.id)).toEqual([newest.id, first.id]);
        expect(Option.getOrUndefined(historicalSnapshot)?.id).toBe(first.id);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('applies the repository limit after deduplication', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        yield* store.createScan({
          githubUrl: 'https://github.com/ACME/RADAR',
          owner: 'ACME',
          repository: 'RADAR',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const other = yield* store.createScan({
          githubUrl: 'https://github.com/elsewhere/app',
          owner: 'elsewhere',
          repository: 'app',
          audience: 'technical',
        });

        const repositories = yield* store.listRecentRepositories(1.9);

        expect(repositories.map(scan => scan.id)).toEqual([other.id]);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('uses only the newest completed scan created before the current scan', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const older = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const current = yield* store.createScan({
          githubUrl: 'https://github.com/ACME/RADAR',
          owner: 'ACME',
          repository: 'RADAR',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const future = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });

        yield* store.updateScan(future.id, {
          status: 'completed',
          result: resultFor(future.id, future.createdAt),
        });
        yield* store.updateScan(older.id, {
          status: 'completed',
          result: resultFor(older.id, older.createdAt),
        });

        const previous = yield* store.getPreviousResult('Acme', 'Radar', {
          createdAt: current.createdAt,
          id: current.id,
        });
        const beforeOldest = yield* store.getPreviousResult('Acme', 'Radar', {
          createdAt: older.createdAt,
          id: older.id,
        });

        expect(Option.getOrUndefined(previous)?.scanId).toBe(older.id);
        expect(Option.isNone(beforeOldest)).toBe(true);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));
});

describe('scan state transitions', () => {
  it('attaches a persisted scan before honoring interruption', () =>
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
        expect(Option.isNone(yield* Deferred.poll(attached))).toBe(true);
        expect(
          Option.getOrUndefined(yield* store.getScan(scanId))?.status,
        ).toBe('queued');
        const interruptor = yield* Effect.forkChild(Fiber.interrupt(fiber));
        yield* Effect.yieldNow;
        yield* Deferred.succeed(allowAttachment, undefined);
        yield* Fiber.join(interruptor);

        expect(yield* Deferred.await(attached)).toBe(scanId);
        expect(
          Option.getOrUndefined(yield* store.getScan(scanId))?.status,
        ).toBe('queued');
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));

  it('fails queued and running scans without downgrading completed scans', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const queued = yield* store.createScan({
          githubUrl: 'https://github.com/acme/queued',
          owner: 'acme',
          repository: 'queued',
          audience: 'technical',
        });
        const running = yield* store.createScan({
          githubUrl: 'https://github.com/acme/running',
          owner: 'acme',
          repository: 'running',
          audience: 'technical',
        });
        const completed = yield* store.createScan({
          githubUrl: 'https://github.com/acme/completed',
          owner: 'acme',
          repository: 'completed',
          audience: 'technical',
        });
        const alreadyFailed = yield* store.createScan({
          githubUrl: 'https://github.com/acme/already-failed',
          owner: 'acme',
          repository: 'already-failed',
          audience: 'technical',
        });
        yield* store.updateScan(running.id, {
          status: 'running',
          progress: 50,
          stage: 'Running',
        });
        const completedResult = resultFor(completed.id, completed.createdAt);
        yield* store.updateScan(completed.id, {
          status: 'completed',
          progress: 100,
          stage: 'Complete',
          result: completedResult,
        });
        yield* store.updateScan(alreadyFailed.id, {
          status: 'failed',
          progress: 100,
          stage: 'Original failure',
          error: 'Original error',
        });

        yield* Effect.all(
          [queued.id, running.id, completed.id, alreadyFailed.id].map(id =>
            store.failScanIfActive(id, {
              stage: 'Stopped',
              error: 'Interrupted',
            }),
          ),
          { concurrency: 'unbounded' },
        );

        const [queuedAfter, runningAfter, completedAfter, failedAfter] =
          yield* Effect.all([
            store.getScan(queued.id),
            store.getScan(running.id),
            store.getScan(completed.id),
            store.getScan(alreadyFailed.id),
          ]);
        expect(Option.getOrUndefined(queuedAfter)?.status).toBe('failed');
        expect(Option.getOrUndefined(runningAfter)?.status).toBe('failed');
        expect(Option.getOrUndefined(completedAfter)?.status).toBe('completed');
        expect(Option.getOrUndefined(completedAfter)?.result).toEqual(
          completedResult,
        );
        expect(Option.getOrUndefined(completedAfter)?.error).toBeUndefined();
        expect(Option.getOrUndefined(failedAfter)?.stage).toBe(
          'Original failure',
        );
        expect(Option.getOrUndefined(failedAfter)?.error).toBe('Original error');
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));
});

describe('scan admission', () => {
  it('atomically deduplicates repository keys and releases unused claims', () =>
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
        Effect.provide(ScanCoordinatorLive),
        Effect.provide(MemoryStoreLive),
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
        Effect.provide(ScanCoordinatorLive),
        Effect.provide(MemoryStoreLive),
        Effect.provide(TestServices),
      ),
    ));
});
