import {
  Cause,
  Clock,
  Context,
  Effect,
  Layer,
  Option,
  Queue,
  Ref,
  Schema,
} from 'effect';
import { RadarAnalysis } from '@codebase-radar/core';
import {
  AnalysisRuntimeUnavailable,
  AnalysisSourceRejected,
  DefaultBranchRevision,
  decodeAnalysisRequest,
  decodeAnalysisSource,
  SuccessfulScanResultSchema,
  type AnalysisFailure,
} from '@codebase-radar/contracts';
import { ScanRecord } from '../shared/domain';
import { RadarAnalysisObserverLive } from './analysis-observer';
import {
  RadarStore,
  ScanClaim,
  StorageError,
} from './store';

export const scanLeaseMs = 2 * 60_000;
export const scanLeaseHeartbeatMs = 20_000;
export const scanRecoveryPollMs = 250;

const nextScanLeaseExpiry = Clock.currentTimeMillis.pipe(
  Effect.map(now => new Date(now + scanLeaseMs).toISOString()),
);

const githubSourceFor = (scan: ScanRecord) =>
  decodeAnalysisSource({
    _tag: 'GitHubSource',
    owner: scan.owner,
    repository: scan.repository,
    revision: new DefaultBranchRevision({}),
  }).pipe(
    Effect.flatMap(source =>
      source._tag === 'GitHubSource'
        ? Effect.succeed(source)
        : Effect.fail(
            new AnalysisSourceRejected({
              message: 'The scan source must be a public GitHub repository.',
            }),
          ),
    ),
    Effect.mapError(
      () =>
        new AnalysisSourceRejected({
          message: 'The stored GitHub repository identity is invalid.',
        }),
    ),
  );

const analysisRequestFor = Effect.fn('analysisRequestFor')(function* (
  claim: ScanClaim,
) {
  const source = yield* githubSourceFor(claim.scan);
  return yield* decodeAnalysisRequest({
    scanId: claim.scan.id,
    source,
    createdAt: claim.scan.createdAt,
    ...(claim.baseline === undefined ? {} : { baseline: claim.baseline }),
  }).pipe(
    Effect.mapError(
      () =>
        new AnalysisSourceRejected({
          message: 'The requested GitHub scan could not be validated.',
        }),
    ),
  );
});

const safeFailureMessage = (failure: AnalysisFailure | StorageError) => {
  switch (failure._tag) {
    case 'StorageError':
      return 'The scan worker could not persist its result safely.';
    case 'AnalysisIncomplete':
      return 'The required analysis policy could not complete safely.';
    default:
      return failure.message;
  }
};

const decodeCanonicalResult = Schema.decodeUnknownEffect(
  SuccessfulScanResultSchema,
  { onExcessProperty: 'error' },
);

const isResultForClaim = (
  claim: ScanClaim,
  result: typeof SuccessfulScanResultSchema.Type,
) => {
  const scan = claim.scan;
  return result.scanId === scan.id &&
    result.createdAt === scan.createdAt &&
    result.source._tag === 'GitHubSourceIdentity' &&
    result.source.codebaseId ===
      `github:${scan.owner.toLowerCase()}/${scan.repository.toLowerCase()}` &&
    result.source.owner === scan.owner.toLowerCase() &&
    result.source.repository === scan.repository.toLowerCase() &&
    result.source.url ===
      `https://github.com/${scan.owner.toLowerCase()}/${scan.repository.toLowerCase()}` &&
    result.comparison.basisCodebaseId === result.source.codebaseId &&
    result.comparison.basisPolicyId === result.analysisPolicy &&
    result.comparison.previousScanId === claim.baseline?.scanId;
};

const runClaimedScan = (claim: ScanClaim) =>
  Effect.gen(function* () {
    const store = yield* RadarStore;
    const analysis = yield* RadarAnalysis;
    const firstRenewal = yield* nextScanLeaseExpiry.pipe(
      Effect.flatMap(expiresAt =>
        store.renewScanLease(claim.scan.id, claim.lease, expiresAt),
      ),
    );
    if (Option.isNone(firstRenewal)) {
      return yield* new StorageError({
        message: 'The scan worker lease expired before analysis started.',
      });
    }
    const protocol = Effect.gen(function* () {
      yield* store.updateScan(
        claim.scan.id,
        {
          status: 'running',
          progress: 0,
          stage: 'Preparing the canonical GitHub scan',
        },
        firstRenewal.value,
      );
      const request = yield* analysisRequestFor(claim);
      const result = yield* analysis.analyze(request).pipe(
        Effect.provide(RadarAnalysisObserverLive(claim.scan.id, firstRenewal.value)),
      );
      const canonical = yield* decodeCanonicalResult(result).pipe(
        Effect.mapError(
          () =>
            new AnalysisRuntimeUnavailable({
              message: 'The analysis runtime returned an invalid canonical result.',
            }),
        ),
      );
      if (!isResultForClaim(claim, canonical)) {
        return yield* new AnalysisRuntimeUnavailable({
          message: 'The analysis runtime returned a result for a different GitHub scan.',
        });
      }
      yield* store.completeScan(claim.scan.id, canonical, firstRenewal.value);
    });
    const heartbeat = Effect.forever(
      Effect.sleep(scanLeaseHeartbeatMs).pipe(
        Effect.andThen(nextScanLeaseExpiry),
        Effect.flatMap(expiresAt =>
          store.renewScanLease(claim.scan.id, firstRenewal.value, expiresAt),
        ),
        Effect.flatMap(
          Option.match({
            onNone: () =>
              Effect.fail(
                new StorageError({
                  message: 'The scan worker lease could not be renewed safely.',
                }),
              ),
            onSome: () => Effect.void,
          }),
        ),
      ),
    );
    return yield* Effect.raceFirst(protocol, heartbeat);
  });

const processClaim = (claim: ScanClaim) =>
  runClaimedScan(claim).pipe(
    Effect.catch(failure =>
      Effect.uninterruptible(
        RadarStore.use(store =>
          store
            .failScanIfActive(
              claim.scan.id,
              {
                stage: 'Scan failed safely',
                error: safeFailureMessage(failure),
              },
              claim.lease,
            )
            .pipe(Effect.ignore),
        ),
      ),
    ),
    Effect.catchCause(cause =>
      Cause.hasInterruptsOnly(cause)
        ? Effect.failCause(cause)
        : Effect.uninterruptible(
            RadarStore.use(store =>
              store
                .failScanIfActive(
                  claim.scan.id,
                  {
                    stage: 'Scan failed safely',
                    error: 'The scan worker stopped unexpectedly.',
                  },
                  claim.lease,
                )
                .pipe(Effect.ignore),
            ),
          ),
    ),
    Effect.ensuring(
      RadarStore.use(store =>
        store.storage === 'memory'
          ? Effect.uninterruptible(
              store
                .failScanIfActive(claim.scan.id, {
                  stage: 'Scan stopped before completion',
                  error: 'The scan worker stopped before completion. Submit a new scan.',
                })
                .pipe(Effect.ignore),
            )
          : Effect.void,
      ),
    ),
  );

export class ScanCapacityUnavailable extends Schema.TaggedErrorClass<ScanCapacityUnavailable>()(
  'ScanCapacityUnavailable',
  { message: Schema.String },
) {}

export class RepositoryScanAlreadyActive extends Schema.TaggedErrorClass<RepositoryScanAlreadyActive>()(
  'RepositoryScanAlreadyActive',
  { message: Schema.String },
) {}

export class ScanAdmissionInvalid extends Schema.TaggedErrorClass<ScanAdmissionInvalid>()(
  'ScanAdmissionInvalid',
  { message: Schema.String },
) {}

export interface ScanAdmission {
  readonly enqueue: (scan: ScanRecord) => Effect.Effect<void, ScanAdmissionInvalid>;
  readonly release: Effect.Effect<void>;
}

export const persistAndAttachScan = <E, R>(
  persist: Effect.Effect<ScanRecord, E, R>,
  attach: (scan: ScanRecord) => Effect.Effect<void, ScanAdmissionInvalid>,
): Effect.Effect<ScanRecord, E | ScanAdmissionInvalid, R> =>
  Effect.uninterruptible(persist.pipe(Effect.tap(attach)));

export class ScanCoordinator extends Context.Service<ScanCoordinator, {
  readonly reserve: (
    owner: string,
    repository: string,
  ) => Effect.Effect<
    ScanAdmission,
    ScanCapacityUnavailable | RepositoryScanAlreadyActive
  >;
}>()('ScanCoordinator') {}

interface AdmissionEntry {
  readonly repositoryKey: string;
  readonly scan?: ScanRecord;
}

interface AdmissionState {
  readonly nextId: number;
  readonly entries: ReadonlyMap<number, AdmissionEntry>;
}

interface QueuedScan {
  readonly scan: ScanRecord;
  readonly admissionId?: number;
  readonly claim?: ScanClaim;
}

type ReservationResult =
  | { readonly _tag: 'Accepted'; readonly admissionId: number }
  | {
      readonly _tag: 'Rejected';
      readonly error: ScanCapacityUnavailable | RepositoryScanAlreadyActive;
    };

type EnqueueResult =
  | { readonly _tag: 'Accepted' }
  | { readonly _tag: 'Rejected'; readonly error: ScanAdmissionInvalid };

const maximumActiveScans = 32;
const repositoryKey = (owner: string, repository: string) =>
  `${owner.toLowerCase()}/${repository.toLowerCase()}`;

export const ScanCoordinatorLive = Layer.effect(
  ScanCoordinator,
  Effect.gen(function* () {
    const store = yield* RadarStore;
    const queue = yield* Queue.bounded<QueuedScan>(maximumActiveScans);
    const admissions = yield* Ref.make<AdmissionState>({
      nextId: 1,
      entries: new Map(),
    });
    const finishAdmission = (admissionId: number | undefined) =>
      admissionId === undefined
        ? Effect.void
        : Ref.update(admissions, current => {
            const entries = new Map(current.entries);
            entries.delete(admissionId);
            return { ...current, entries };
          });
    const releaseReservation = (admissionId: number) =>
      Ref.update(admissions, current => {
        const entry = current.entries.get(admissionId);
        if (entry?.scan !== undefined) return current;
        const entries = new Map(current.entries);
        entries.delete(admissionId);
        return { ...current, entries };
      });

    const recoverOne =
      store.storage === 'postgres'
        ? Queue.isFull(queue).pipe(
            Effect.flatMap(full =>
              full
                ? Effect.void
                : nextScanLeaseExpiry.pipe(
                    Effect.flatMap(expiresAt => store.claimNextScan(expiresAt)),
                    Effect.flatMap(
                      Option.match({
                        onNone: () => Effect.void,
                        onSome: claim =>
                          Queue.offer(queue, { scan: claim.scan, claim }).pipe(
                            Effect.filterOrFail(
                              accepted => accepted,
                              () =>
                                new StorageError({
                                  message: 'The recovered scan queue is unavailable.',
                                }),
                            ),
                            Effect.asVoid,
                          ),
                      }),
                    ),
                  ),
            ),
          ).pipe(Effect.ignore)
        : Effect.void;

    if (store.storage === 'postgres') {
      yield* recoverOne;
      yield* Effect.forever(
        Effect.sleep(scanRecoveryPollMs).pipe(Effect.andThen(recoverOne)),
      ).pipe(Effect.forkScoped({ startImmediately: true }));
    }

    yield* Effect.addFinalizer(() =>
      store.storage === 'memory'
        ? Ref.getAndSet(admissions, { nextId: 1, entries: new Map() }).pipe(
            Effect.flatMap(current =>
              Effect.forEach(
                current.entries.values(),
                entry =>
                  entry.scan === undefined
                    ? Effect.void
                    : store
                        .failScanIfActive(entry.scan.id, {
                          stage: 'Scan stopped before completion',
                          error: 'The scan worker stopped before completion. Submit a new scan.',
                        })
                        .pipe(Effect.ignore),
                { concurrency: 'unbounded', discard: true },
              ),
            ),
          )
        : Effect.void,
    );

    const worker = Effect.forever(
      Queue.take(queue).pipe(
        Effect.flatMap(queued => {
          const claimed = queued.claim === undefined
            ? nextScanLeaseExpiry.pipe(
                Effect.flatMap(expiresAt => store.claimScan(queued.scan.id, expiresAt)),
              )
            : Effect.succeed(Option.some(queued.claim));
          return claimed.pipe(
            Effect.flatMap(
              Option.match({
                onNone: () => Effect.void,
                onSome: processClaim,
              }),
            ),
            Effect.ensuring(finishAdmission(queued.admissionId)),
          );
        }),
      ),
    );
    yield* worker.pipe(Effect.forkScoped({ startImmediately: true }));

    return ScanCoordinator.of({
      reserve: (owner, repository) => {
        const key = repositoryKey(owner, repository);
        return Ref.modify(
          admissions,
          (current): readonly [ReservationResult, AdmissionState] => {
          if (current.entries.size >= maximumActiveScans) {
            return [
              {
                _tag: 'Rejected',
                error: new ScanCapacityUnavailable({
                  message: 'All scan slots are currently in use.',
                }),
              },
              current,
            ] satisfies readonly [ReservationResult, AdmissionState];
          }
          if (
            [...current.entries.values()].some(
              entry => entry.repositoryKey === key,
            )
          ) {
            return [
              {
                _tag: 'Rejected',
                error: new RepositoryScanAlreadyActive({
                  message: `A scan for ${owner}/${repository} is already active.`,
                }),
              },
              current,
            ] satisfies readonly [ReservationResult, AdmissionState];
          }
          const admissionId = current.nextId;
          const entries = new Map(current.entries).set(admissionId, {
            repositoryKey: key,
          });
          return [
            { _tag: 'Accepted', admissionId },
            { nextId: admissionId + 1, entries },
          ] satisfies readonly [ReservationResult, AdmissionState];
          },
        ).pipe(
          Effect.flatMap(result =>
            result._tag === 'Rejected'
              ? Effect.fail(result.error)
              : Effect.succeed(result.admissionId),
          ),
          Effect.map(admissionId =>
            ({
              enqueue: scan =>
                Effect.uninterruptible(
                  Ref.modify(
                    admissions,
                    (current): readonly [EnqueueResult, AdmissionState] => {
                    const entry = current.entries.get(admissionId);
                    if (entry === undefined) {
                      return [
                        {
                          _tag: 'Rejected',
                          error: new ScanAdmissionInvalid({
                            message: 'This scan admission is no longer active.',
                          }),
                        },
                        current,
                      ] satisfies readonly [EnqueueResult, AdmissionState];
                    }
                    if (entry.scan !== undefined) {
                      return [
                        {
                          _tag: 'Rejected',
                          error: new ScanAdmissionInvalid({
                            message: 'This scan admission has already been used.',
                          }),
                        },
                        current,
                      ] satisfies readonly [EnqueueResult, AdmissionState];
                    }
                    if (repositoryKey(scan.owner, scan.repository) !== key) {
                      return [
                        {
                          _tag: 'Rejected',
                          error: new ScanAdmissionInvalid({
                            message: 'The persisted scan does not match its admission.',
                          }),
                        },
                        current,
                      ] satisfies readonly [EnqueueResult, AdmissionState];
                    }
                    const entries = new Map(current.entries).set(admissionId, {
                      ...entry,
                      scan,
                    });
                    return [
                      { _tag: 'Accepted' },
                      { ...current, entries },
                    ] satisfies readonly [EnqueueResult, AdmissionState];
                    },
                  ).pipe(
                    Effect.flatMap(result =>
                      result._tag === 'Rejected'
                        ? Effect.fail(result.error)
                        : Queue.offer(queue, { admissionId, scan }).pipe(
                            Effect.filterOrFail(
                              accepted => accepted,
                              () =>
                                new ScanAdmissionInvalid({
                                  message: 'The scan queue is no longer available.',
                                }),
                            ),
                            Effect.asVoid,
                            Effect.onError(() => finishAdmission(admissionId)),
                          ),
                    ),
                  ),
                ),
              release: releaseReservation(admissionId),
            }) satisfies ScanAdmission,
          ),
        );
      },
    });
  }),
);
