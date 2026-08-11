import { PgClient } from '@effect/sql-pg';
import {
  Config,
  Context,
  Crypto,
  DateTime,
  Effect,
  Layer,
  Option,
  Ref,
  Schema,
} from 'effect';
import {
  Audience,
  AudienceProfile,
  ScanRecord,
} from '../shared/domain';
import {
  SuccessfulScanResultSchema,
  type SuccessfulScanResult,
} from '@codebase-radar/contracts';

const ScanStatus = Schema.Literals(['queued', 'running', 'completed', 'failed']);
const IsoTimestamp = Schema.String.check(
  Schema.isMinLength(24),
  Schema.isMaxLength(24),
  Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u),
);
const ScanProgress = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
  Schema.isLessThanOrEqualTo(100),
);

export class StorageError extends Schema.TaggedErrorClass<StorageError>()(
  'StorageError',
  {
    message: Schema.String,
    reason: Schema.optional(Schema.Literal('repository-active')),
  },
) {}

const ScanUpdateSchema = Schema.Struct({
  status: Schema.optional(Schema.Literal('running')),
  progress: Schema.optional(ScanProgress),
  stage: Schema.optional(Schema.String),
});
export type ScanUpdate = typeof ScanUpdateSchema.Type;

export class ScanLease extends Schema.Class<ScanLease>('ScanLease')({
  token: Schema.String,
  expiresAt: IsoTimestamp,
}) {}

export class ScanClaim extends Schema.Class<ScanClaim>('ScanClaim')({
  scan: ScanRecord,
  lease: ScanLease,
  baseline: Schema.optional(SuccessfulScanResultSchema),
}) {}

export class RadarStore extends Context.Service<RadarStore, {
  readonly storage: 'memory' | 'postgres';
  readonly ready: Effect.Effect<void, StorageError>;
  readonly createProfile: (input: {
    readonly audience: typeof Audience.Type;
    readonly displayName?: string;
  }) => Effect.Effect<AudienceProfile, StorageError>;
  readonly createScan: (input: {
    readonly githubUrl: string;
    readonly owner: string;
    readonly repository: string;
    readonly audience: typeof Audience.Type;
  }) => Effect.Effect<ScanRecord, StorageError>;
  readonly updateScan: (
    id: string,
    update: ScanUpdate,
    lease?: ScanLease,
  ) => Effect.Effect<ScanRecord, StorageError>;
  readonly completeScan: (
    id: string,
    result: SuccessfulScanResult,
    lease?: ScanLease,
  ) => Effect.Effect<ScanRecord, StorageError>;
  readonly failScanIfActive: (
    id: string,
    failure: {
      readonly stage: string;
      readonly error: string;
    },
    lease?: ScanLease,
  ) => Effect.Effect<void, StorageError>;
  /** Claims exactly one queued (or expired running) scan with a fenced lease. */
  readonly claimScan: (
    id: string,
    expiresAt: string,
  ) => Effect.Effect<Option.Option<ScanClaim>, StorageError>;
  /** Durable workers use this after startup to recover queued and stale work. */
  readonly claimNextScan: (
    expiresAt: string,
  ) => Effect.Effect<Option.Option<ScanClaim>, StorageError>;
  readonly renewScanLease: (
    id: string,
    lease: ScanLease,
    expiresAt: string,
  ) => Effect.Effect<Option.Option<ScanLease>, StorageError>;
  readonly getScan: (id: string) => Effect.Effect<Option.Option<ScanRecord>, StorageError>;
  readonly listRecentScans: (limit?: number) => Effect.Effect<ReadonlyArray<ScanRecord>, StorageError>;
  readonly listRecentRepositories: (
    limit?: number,
  ) => Effect.Effect<ReadonlyArray<ScanRecord>, StorageError>;
  readonly listRepositoryScans: (
    owner: string,
    repository: string,
  ) => Effect.Effect<ReadonlyArray<ScanRecord>, StorageError>;
  readonly getPreviousResult: (
    owner: string,
    repository: string,
    before: {
      readonly createdAt: string;
      readonly id: string;
    },
  ) => Effect.Effect<Option.Option<SuccessfulScanResult>, StorageError>;
}>()('RadarStore') {}

const nowIso = DateTime.nowAsDate.pipe(Effect.map(date => date.toISOString()));
const identityAndTime = (crypto: Crypto.Crypto) =>
  Effect.all([crypto.randomUUIDv7, nowIso]).pipe(Effect.mapError(storageFailure));
const ScanRecordJson = Schema.fromJsonString(ScanRecord);
const PostgresScanRowSchema = Schema.Struct({
  id: Schema.String,
  owner: Schema.String,
  repository: Schema.String,
  status: ScanStatus,
  record_json: Schema.String,
  created_at: IsoTimestamp,
  updated_at: IsoTimestamp,
  lease_token: Schema.NullOr(Schema.String),
  lease_expires_at: Schema.NullOr(IsoTimestamp),
  baseline_scan_id: Schema.NullOr(Schema.String),
});
type PostgresScanRow = typeof PostgresScanRowSchema.Type;

const decodeStoredScanWire = Schema.decodeUnknownEffect(ScanRecordJson, {
  onExcessProperty: 'error',
});

/** Encodes every scan record through the canonical v2 representation. */
export const encodeStoredScan = Schema.encodeEffect(ScanRecordJson, {
  onExcessProperty: 'error',
});

const decodePostgresScanRow = Schema.decodeUnknownEffect(PostgresScanRowSchema, {
  onExcessProperty: 'error',
});
const decodeCanonicalStoredResult = Schema.decodeUnknownEffect(
  SuccessfulScanResultSchema,
  { onExcessProperty: 'error' },
);
const decodeScanUpdate = Schema.decodeUnknownEffect(ScanUpdateSchema, {
  onExcessProperty: 'error',
});
const decodeLease = Schema.decodeUnknownEffect(ScanLease, {
  onExcessProperty: 'error',
});
const decodeTimestamp = Schema.decodeUnknownEffect(IsoTimestamp, {
  onExcessProperty: 'error',
});
const legacyResultMarker = /"schemaVersion"\s*:\s*"codebase-radar\.scan-result\/v1"/u;

const storageFailure = <Failure>(_cause: Failure) =>
  new StorageError({
    message: 'Radar storage could not complete this operation safely.',
  });

const repositoryActiveFailure = () =>
  new StorageError({
    message: 'A scan for this repository is already queued or running.',
    reason: 'repository-active',
  });

const storedRecordFailure = () =>
  new StorageError({
    message: 'Stored scan data did not satisfy the durable scan contract.',
  });

const validateFailure = (failure: { readonly stage: string; readonly error: string }) =>
  failure.error.trim().length > 0
    ? Effect.succeed(failure)
    : Effect.fail(storedRecordFailure());

const withoutTerminalFields = ({
  error: _error,
  result: _result,
  ...scan
}: ScanRecord) => scan;

const repositoryCodebaseId = (owner: string, repository: string) =>
  `github:${owner.toLowerCase()}/${repository.toLowerCase()}`;

const repositoryUrl = (owner: string, repository: string) =>
  `https://github.com/${owner.toLowerCase()}/${repository.toLowerCase()}`;

const resultMatchesRepository = (
  result: SuccessfulScanResult,
  owner: string,
  repository: string,
) =>
  result.source._tag === 'GitHubSourceIdentity' &&
  result.source.codebaseId === repositoryCodebaseId(owner, repository) &&
  result.source.owner === owner.toLowerCase() &&
  result.source.repository === repository.toLowerCase() &&
  result.source.url === repositoryUrl(owner, repository);

const isCompatiblePreviousResult = (
  result: ScanRecord['result'],
  owner: string,
  repository: string,
  before: {
    readonly createdAt: string;
    readonly id: string;
  },
): result is SuccessfulScanResult =>
  result?.resultKind === 'complete' &&
  resultMatchesRepository(result, owner, repository) &&
  result.scanId !== before.id &&
  result.completedAt < before.createdAt;

const isCompletionBoundToScan = (
  scan: ScanRecord,
  result: SuccessfulScanResult,
  expectedBaselineId: string | undefined,
) =>
  result.scanId === scan.id &&
  result.createdAt === scan.createdAt &&
  result.completedAt >= scan.createdAt &&
  resultMatchesRepository(result, scan.owner, scan.repository) &&
  result.comparison.basisCodebaseId === result.source.codebaseId &&
  result.comparison.basisPolicyId === result.analysisPolicy &&
  result.comparison.previousScanId === expectedBaselineId;

const validateStoredScan = (scan: ScanRecord) =>
  Effect.all([
    Schema.decodeUnknownEffect(ScanProgress, { onExcessProperty: 'error' })(
      scan.progress,
    ),
    decodeTimestamp(scan.createdAt),
    decodeTimestamp(scan.updatedAt),
  ]).pipe(
    Effect.mapError(storageFailure),
    Effect.flatMap(([, createdAt, updatedAt]) => {
      const hasCanonicalRepositoryIdentity =
        scan.owner === scan.owner.toLowerCase() &&
        scan.repository === scan.repository.toLowerCase() &&
        scan.githubUrl === repositoryUrl(scan.owner, scan.repository);
      const valid =
        hasCanonicalRepositoryIdentity &&
        createdAt <= updatedAt &&
        (scan.status === 'queued'
          ? scan.progress === 0 &&
            scan.error === undefined &&
            scan.result === undefined
          : scan.status === 'running'
            ? scan.error === undefined && scan.result === undefined
            : scan.status === 'completed'
              ? scan.error === undefined &&
                scan.progress === 100 &&
                scan.result !== undefined &&
                (scan.result.resultKind === 'legacy-noncanonical' ||
                  (scan.result.resultKind === 'complete' &&
                    isCompletionBoundToScan(
                      scan,
                      scan.result,
                      scan.result.comparison.previousScanId,
                    )))
              : scan.result === undefined &&
                scan.error !== undefined &&
                scan.error.trim().length > 0 &&
                scan.progress === 100);
      return valid ? Effect.succeed(scan) : Effect.fail(storedRecordFailure());
    }),
  );

/**
 * Decodes historical scan records through the canonical v1-to-v2 migration
 * and rejects status/result/error combinations that cannot exist durably.
 */
export const decodeStoredScan = (value: string) =>
  decodeStoredScanWire(value).pipe(Effect.flatMap(validateStoredScan));

const validatePostgresRow = (row: PostgresScanRow, scan: ScanRecord) => {
  const terminalLeaseIsCleared =
    (scan.status === 'completed' || scan.status === 'failed') &&
    row.lease_token === null &&
    row.lease_expires_at === null;
  const activeLeaseShape =
    (scan.status === 'queued' &&
      row.lease_token === null &&
      row.lease_expires_at === null) ||
    (scan.status === 'running' &&
      ((row.lease_token === null && row.lease_expires_at === null) ||
        (row.lease_token !== null &&
          row.lease_token.trim().length > 0 &&
          row.lease_expires_at !== null)));
  const expectedTerminalBaselineId =
    scan.status === 'completed' && scan.result?.resultKind === 'complete'
      ? scan.result?.comparison.previousScanId ?? null
      : null;
  const baselineMatches =
    scan.status === 'running'
      ? row.baseline_scan_id === null ||
        (row.baseline_scan_id.trim().length > 0 &&
          row.baseline_scan_id !== scan.id)
      : row.baseline_scan_id === expectedTerminalBaselineId;
  const matches =
    scan.id === row.id &&
    scan.owner === row.owner &&
    scan.repository === row.repository &&
    scan.status === row.status &&
    scan.createdAt === row.created_at &&
    scan.updatedAt === row.updated_at &&
    baselineMatches &&
    (terminalLeaseIsCleared || activeLeaseShape);
  return matches ? Effect.succeed(scan) : Effect.fail(storedRecordFailure());
};

/** Strictly decodes a normalized database row and proves it matches its JSON record. */
export const decodeStoredPostgresScanRow = (raw: PostgresScanRow) =>
  decodePostgresScanRow(raw).pipe(
    Effect.mapError(storageFailure),
    Effect.flatMap(row =>
      decodeStoredScan(row.record_json).pipe(
        Effect.mapError(storageFailure),
        Effect.flatMap(scan =>
          validateStoredScan(scan).pipe(
            Effect.flatMap(valid => validatePostgresRow(row, valid)),
          ),
        ),
      )),
  );

const leaseIsLive = (lease: ScanLease, now: string) => lease.expiresAt >= now;

const rowLeaseIsLive = (
  row: PostgresScanRow,
  lease: ScanLease,
  now: string,
) =>
  row.lease_token === lease.token &&
  row.lease_expires_at !== null &&
  row.lease_expires_at >= now;

const sameStoredResult = (
  left: SuccessfulScanResult,
  right: SuccessfulScanResult,
) => JSON.stringify(left) === JSON.stringify(right);

const newestCompatibleResult = (
  scans: Iterable<ScanRecord>,
  owner: string,
  repository: string,
  before: {
    readonly createdAt: string;
    readonly id: string;
  },
) => {
  const candidates = [...scans]
    .filter(
      scan =>
        scan.owner.toLowerCase() === owner.toLowerCase() &&
        scan.repository.toLowerCase() === repository.toLowerCase() &&
        scan.status === 'completed' &&
        isCompatiblePreviousResult(scan.result, owner, repository, before) &&
        (scan.createdAt < before.createdAt ||
          (scan.createdAt === before.createdAt && scan.id < before.id)),
    )
    .sort(
      (left, right) =>
        right.createdAt.localeCompare(left.createdAt) ||
        right.id.localeCompare(left.id),
    );
  const result = candidates[0]?.result;
  return isCompatiblePreviousResult(result, owner, repository, before)
    ? Option.some(result)
    : Option.none<SuccessfulScanResult>();
};

interface MemoryState {
  readonly profiles: ReadonlyMap<string, AudienceProfile>;
  readonly scans: ReadonlyMap<string, ScanRecord>;
  readonly leases: ReadonlyMap<string, ScanLease>;
  readonly baselineScanIds: ReadonlyMap<string, string | undefined>;
}

type MemoryCompletion =
  | { readonly _tag: 'missing' }
  | { readonly _tag: 'rejected' }
  | { readonly _tag: 'completed'; readonly scan: ScanRecord };

const makeMemoryStore = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  const state = yield* Ref.make<MemoryState>({
    profiles: new Map(),
    scans: new Map(),
    leases: new Map(),
    baselineScanIds: new Map(),
  });

  const getScan = (id: string) =>
    Ref.get(state).pipe(
      Effect.map(current => Option.fromUndefinedOr(current.scans.get(id))),
    );

  const claimMemoryScan = Effect.fn('RadarStore.claimMemoryScan')(function* (
    id: string,
    expiresAt: string,
  ) {
    const acceptedExpiry = yield* decodeTimestamp(expiresAt).pipe(
      Effect.mapError(storageFailure),
    );
    const [token, claimedAt] = yield* identityAndTime(crypto);
    if (acceptedExpiry <= claimedAt) {
      return yield* new StorageError({
        message: 'A scan lease must expire after it is claimed.',
      });
    }
    return yield* Ref.modify(state, current => {
      const scan = current.scans.get(id);
      const existingLease = current.leases.get(id);
      const claimable =
        scan !== undefined &&
        (scan.status === 'queued' ||
          (scan.status === 'running' &&
            (existingLease === undefined || existingLease.expiresAt < claimedAt)));
      if (!claimable || scan === undefined) {
        return [Option.none<ScanClaim>(), current] satisfies readonly [
          Option.Option<ScanClaim>,
          MemoryState,
        ];
      }
      const baseline = current.baselineScanIds.has(id)
        ? Option.fromUndefinedOr(
            current.baselineScanIds.get(id),
          ).pipe(
            Option.flatMap(baselineId => {
              const candidate = current.scans.get(baselineId)?.result;
              return isCompatiblePreviousResult(
                candidate,
                scan.owner,
                scan.repository,
                { createdAt: scan.createdAt, id: scan.id },
              )
                ? Option.some(candidate)
                : Option.none<SuccessfulScanResult>();
            }),
          )
        : newestCompatibleResult(
            current.scans.values(),
            scan.owner,
            scan.repository,
            { createdAt: scan.createdAt, id: scan.id },
          );
      const lease = new ScanLease({ token, expiresAt: acceptedExpiry });
      const running = new ScanRecord({
        ...scan,
        status: 'running',
        updatedAt: claimedAt,
      });
      const scans = new Map(current.scans).set(id, running);
      const leases = new Map(current.leases).set(id, lease);
      const baselineId = Option.match(baseline, {
        onNone: () => undefined,
        onSome: candidate => candidate.scanId,
      });
      const baselineScanIds = new Map(current.baselineScanIds).set(id, baselineId);
      return [
        Option.some(
          new ScanClaim({
            scan: running,
            lease,
            ...(Option.isSome(baseline) ? { baseline: baseline.value } : {}),
          }),
        ),
        { ...current, scans, leases, baselineScanIds },
      ] satisfies readonly [Option.Option<ScanClaim>, MemoryState];
    });
  });

  return RadarStore.of({
    storage: 'memory',
    ready: Effect.void,
    createProfile: Effect.fn('RadarStore.createProfile')(function* (input) {
      const [id, createdAt] = yield* identityAndTime(crypto);
      const profile = new AudienceProfile({
        id,
        audience: input.audience,
        ...(input.displayName
          ? { displayName: input.displayName.trim().slice(0, 80) }
          : {}),
        createdAt,
      });
      yield* Ref.update(state, current => ({
        ...current,
        profiles: new Map(current.profiles).set(id, profile),
      }));
      return profile;
    }),
    createScan: Effect.fn('RadarStore.createScan')(function* (input) {
      const [id, createdAt] = yield* identityAndTime(crypto);
      const owner = input.owner.toLowerCase();
      const repository = input.repository.toLowerCase();
      const scan = new ScanRecord({
        id,
        githubUrl: repositoryUrl(owner, repository),
        owner,
        repository,
        audience: input.audience,
        status: 'queued',
        progress: 0,
        stage: 'Queued for a bounded static scan',
        createdAt,
        updatedAt: createdAt,
      });
      yield* Ref.update(state, current => ({
        ...current,
        scans: new Map(current.scans).set(id, scan),
      }));
      return scan;
    }),
    updateScan: Effect.fn('RadarStore.updateScan')(function* (id, update, lease) {
      const accepted = yield* decodeScanUpdate(update).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      const updated = yield* Ref.modify(state, current => {
        const scan = current.scans.get(id);
        if (scan === undefined) {
          return [Option.none<ScanRecord>(), current] satisfies readonly [
            Option.Option<ScanRecord>,
            MemoryState,
          ];
        }
        if (scan.status !== 'queued' && scan.status !== 'running') {
          return [Option.some(scan), current] satisfies readonly [
            Option.Option<ScanRecord>,
            MemoryState,
          ];
        }
        if (scan.status === 'queued' && accepted.status !== 'running') {
          return [Option.some(scan), current] satisfies readonly [
            Option.Option<ScanRecord>,
            MemoryState,
          ];
        }
        const currentLease = current.leases.get(id);
        if (
          acceptedLease !== undefined &&
          (currentLease === undefined ||
            currentLease.token !== acceptedLease.token ||
            !leaseIsLive(currentLease, updatedAt))
        ) {
          return [Option.some(scan), current] satisfies readonly [
            Option.Option<ScanRecord>,
            MemoryState,
          ];
        }
        const requestedProgress = accepted.progress ?? scan.progress;
        const progress = Math.max(scan.progress, requestedProgress);
        const acceptsStage = accepted.progress === undefined ||
          requestedProgress >= scan.progress;
        const next = new ScanRecord({
          ...scan,
          ...(accepted.status === undefined ? {} : { status: accepted.status }),
          progress,
          ...(accepted.stage === undefined || !acceptsStage
            ? {}
            : { stage: accepted.stage }),
          updatedAt,
        });
        return [
          Option.some(next),
          { ...current, scans: new Map(current.scans).set(id, next) },
        ] satisfies readonly [Option.Option<ScanRecord>, MemoryState];
      });
      return yield* Option.match(updated, {
        onNone: () =>
          Effect.fail(new StorageError({ message: `Scan ${id} was not found.` })),
        onSome: Effect.succeed,
      });
    }),
    completeScan: Effect.fn('RadarStore.completeScan')(function* (id, result, lease) {
      const canonical = yield* decodeCanonicalStoredResult(result).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      const outcome: MemoryCompletion = yield* Ref.modify(
        state,
        (current): readonly [MemoryCompletion, MemoryState] => {
        const scan = current.scans.get(id);
        if (scan === undefined) {
          return [{ _tag: 'missing' }, current] satisfies readonly [
            MemoryCompletion,
            MemoryState,
          ];
        }
        if (scan.status === 'completed' && scan.result?.resultKind === 'complete') {
          return [
            sameStoredResult(scan.result, canonical)
              ? { _tag: 'completed', scan }
              : { _tag: 'rejected' },
            current,
          ] satisfies readonly [MemoryCompletion, MemoryState];
        }
        if (scan.status !== 'queued' && scan.status !== 'running') {
          return [{ _tag: 'rejected' }, current] satisfies readonly [
            MemoryCompletion,
            MemoryState,
          ];
        }
        const currentLease = current.leases.get(id);
        if (
          (acceptedLease !== undefined &&
            (currentLease === undefined ||
              currentLease.token !== acceptedLease.token ||
              !leaseIsLive(currentLease, updatedAt)))
        ) {
          return [{ _tag: 'rejected' }, current] satisfies readonly [
            MemoryCompletion,
            MemoryState,
          ];
        }
        const expectedBaselineId = current.baselineScanIds.get(id);
        if (!isCompletionBoundToScan(scan, canonical, expectedBaselineId)) {
          return [{ _tag: 'rejected' }, current] satisfies readonly [
            MemoryCompletion,
            MemoryState,
          ];
        }
        const completed = new ScanRecord({
          ...withoutTerminalFields(scan),
          status: 'completed',
          progress: 100,
          stage: 'Your review is ready',
          result: canonical,
          updatedAt,
        });
        const leases = new Map(current.leases);
        leases.delete(id);
        const baselineScanIds = new Map(current.baselineScanIds);
        baselineScanIds.delete(id);
        return [
          { _tag: 'completed', scan: completed },
          {
            ...current,
            scans: new Map(current.scans).set(id, completed),
            leases,
            baselineScanIds,
          },
        ] satisfies readonly [MemoryCompletion, MemoryState];
        },
      );
      switch (outcome._tag) {
        case 'completed':
          return outcome.scan;
        case 'missing':
          return yield* new StorageError({ message: `Scan ${id} was not found.` });
        case 'rejected':
          return yield* new StorageError({
            message: 'Scan completion did not match its active durable identity.',
          });
      }
    }),
    failScanIfActive: Effect.fn('RadarStore.failScanIfActive')(function* (
      id,
      failure,
      lease,
    ) {
      const acceptedFailure = yield* validateFailure(failure);
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      yield* Ref.update(state, current => {
        const scan = current.scans.get(id);
        const currentLease = current.leases.get(id);
        if (
          scan === undefined ||
          (scan.status !== 'queued' && scan.status !== 'running') ||
          (acceptedLease !== undefined &&
            (currentLease === undefined ||
              currentLease.token !== acceptedLease.token ||
              !leaseIsLive(currentLease, updatedAt)))
        ) {
          return current;
        }
        const failed = new ScanRecord({
          ...withoutTerminalFields(scan),
          status: 'failed',
          progress: 100,
          stage: acceptedFailure.stage,
          error: acceptedFailure.error,
          updatedAt,
        });
        const leases = new Map(current.leases);
        leases.delete(id);
        const baselineScanIds = new Map(current.baselineScanIds);
        baselineScanIds.delete(id);
        return {
          ...current,
          scans: new Map(current.scans).set(id, failed),
          leases,
          baselineScanIds,
        };
      });
    }),
    claimScan: claimMemoryScan,
    claimNextScan: () => Effect.succeed(Option.none<ScanClaim>()),
    renewScanLease: Effect.fn('RadarStore.renewScanLease')(function* (
      id,
      lease,
      expiresAt,
    ) {
      const acceptedLease = yield* decodeLease(lease).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedExpiry = yield* decodeTimestamp(expiresAt).pipe(
        Effect.mapError(storageFailure),
      );
      const currentTime = yield* nowIso;
      if (acceptedExpiry <= currentTime) return Option.none<ScanLease>();
      return yield* Ref.modify(state, current => {
        const currentLease = current.leases.get(id);
        const scan = current.scans.get(id);
        if (
          scan?.status !== 'running' ||
          currentLease === undefined ||
          currentLease.token !== acceptedLease.token ||
          !leaseIsLive(currentLease, currentTime)
        ) {
          return [Option.none<ScanLease>(), current] satisfies readonly [
            Option.Option<ScanLease>,
            MemoryState,
          ];
        }
        const renewed = new ScanLease({
          token: currentLease.token,
          expiresAt: currentLease.expiresAt >= acceptedExpiry
            ? currentLease.expiresAt
            : acceptedExpiry,
        });
        return [
          Option.some(renewed),
          { ...current, leases: new Map(current.leases).set(id, renewed) },
        ] satisfies readonly [Option.Option<ScanLease>, MemoryState];
      });
    }),
    getScan,
    listRecentScans: (limit = 8) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          [...current.scans.values()]
            .sort(
              (left, right) =>
                right.createdAt.localeCompare(left.createdAt) ||
                right.id.localeCompare(left.id),
            )
            .slice(0, Math.min(Math.max(limit, 1), 25)),
        ),
      ),
    listRecentRepositories: (limit = 8) =>
      Ref.get(state).pipe(
        Effect.map(current => {
          const newestByRepository = new Map<string, ScanRecord>();
          const scans = [...current.scans.values()].sort(
            (left, right) =>
              right.createdAt.localeCompare(left.createdAt) ||
              right.id.localeCompare(left.id),
          );
          for (const scan of scans) {
            const repositoryKey = `${scan.owner.toLowerCase()}/${scan.repository.toLowerCase()}`;
            if (!newestByRepository.has(repositoryKey)) {
              newestByRepository.set(repositoryKey, scan);
            }
          }
          return [...newestByRepository.values()].slice(
            0,
            Math.trunc(Math.min(Math.max(limit, 1), 25)),
          );
        }),
      ),
    listRepositoryScans: (owner, repository) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          [...current.scans.values()]
            .filter(
              scan =>
                scan.owner.toLowerCase() === owner.toLowerCase() &&
                scan.repository.toLowerCase() === repository.toLowerCase(),
            )
            .sort(
              (left, right) =>
                right.createdAt.localeCompare(left.createdAt) ||
                right.id.localeCompare(left.id),
            ),
        ),
      ),
    getPreviousResult: (owner, repository, before) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          newestCompatibleResult(
            current.scans.values(),
            owner,
            repository,
            before,
          ),
        ),
      ),
  });
});

export const MemoryStoreLive = Layer.effect(RadarStore, makeMemoryStore);

const makePostgresStore = Effect.gen(function* () {
  const sql = yield* PgClient.PgClient;
  const crypto = yield* Crypto.Crypto;

  yield* sql`
    create table if not exists audience_profiles (
      id text primary key,
      profile jsonb not null,
      created_at timestamptz not null
    )
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    create table if not exists scans (
      id text primary key,
      owner text not null,
      repository text not null,
      status text not null,
      record jsonb not null,
      lease_token text,
      lease_expires_at timestamptz,
      baseline_scan_id text,
      created_at timestamptz not null,
      updated_at timestamptz not null
    )
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    alter table scans add column if not exists lease_token text
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    alter table scans add column if not exists lease_expires_at timestamptz
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    alter table scans add column if not exists baseline_scan_id text
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    create index if not exists scans_repository_history_idx
    on scans(lower(owner), lower(repository), created_at desc, id desc)
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    create index if not exists scans_repository_completed_history_ci_idx
    on scans(lower(owner), lower(repository), created_at desc, id desc)
    where status = 'completed'
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    create unique index if not exists scans_active_repository_ci_idx
    on scans(lower(owner), lower(repository))
    where status in ('queued', 'running')
  `.pipe(Effect.mapError(storageFailure));

  const decodeScan = (recordJson: string) =>
    decodeStoredScan(recordJson).pipe(Effect.mapError(storageFailure));

  const rewriteLegacyResult = Effect.fn('RadarStore.rewriteLegacyResult')(
    function* (id: string, recordJson: string, scan: ScanRecord) {
      if (!legacyResultMarker.test(recordJson)) return scan;
      const canonicalJson = yield* encodeStoredScan(scan).pipe(
        Effect.mapError(storageFailure),
      );
      yield* sql`
        update scans set record = ${canonicalJson}::jsonb where id = ${id}
      `.pipe(Effect.mapError(storageFailure));
      return scan;
    },
  );

  const decodeStoredPostgresScan = (raw: PostgresScanRow) =>
    decodeStoredPostgresScanRow(raw).pipe(
      Effect.flatMap(scan =>
        legacyResultMarker.test(raw.record_json)
          ? rewriteLegacyResult(raw.id, raw.record_json, scan)
          : Effect.succeed(scan),
      ),
    );

  const selectScan = Effect.fn('RadarStore.selectScan')(function* (id: string) {
    const rows = yield* sql<PostgresScanRow>`
      select id, owner, repository, status, record::text record_json,
             to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
             to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
             lease_token,
             to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
             baseline_scan_id
      from scans where id = ${id} limit 1
    `.pipe(Effect.mapError(storageFailure));
    const row = rows[0];
    return row === undefined
      ? Option.none<ScanRecord>()
      : Option.some(yield* decodeStoredPostgresScan(row));
  });

  const findPreviousResult = Effect.fn('RadarStore.findPreviousResult')(function* (
    owner: string,
    repository: string,
    before: { readonly createdAt: string; readonly id: string },
  ) {
    const rows = yield* sql<PostgresScanRow>`
      select id, owner, repository, status, record::text record_json,
             to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
             to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
             lease_token,
             to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
             baseline_scan_id
      from scans
      where lower(owner) = lower(${owner})
        and lower(repository) = lower(${repository})
        and status = 'completed'
        and (
          created_at < ${before.createdAt}
          or (created_at = ${before.createdAt} and id < ${before.id})
        )
      order by created_at desc, id desc
    `.pipe(Effect.mapError(storageFailure));
    const scans = yield* Effect.forEach(rows, decodeStoredPostgresScan);
    return newestCompatibleResult(scans, owner, repository, before);
  });

  const baselineForRow = Effect.fn('RadarStore.baselineForRow')(function* (
    row: PostgresScanRow,
    scan: ScanRecord,
  ) {
    if (row.baseline_scan_id === null) {
      return yield* findPreviousResult(scan.owner, scan.repository, {
        createdAt: scan.createdAt,
        id: scan.id,
      });
    }
    const stored = yield* selectScan(row.baseline_scan_id);
    if (
      Option.isNone(stored) ||
      !isCompatiblePreviousResult(stored.value.result, scan.owner, scan.repository, {
        createdAt: scan.createdAt,
        id: scan.id,
      })
    ) {
      return yield* storedRecordFailure();
    }
    return Option.some(stored.value.result);
  });

  const claimLockedScan = Effect.fn('RadarStore.claimLockedScan')(function* (
    raw: PostgresScanRow,
    claimedAt: string,
    expiresAt: string,
  ) {
    const row = yield* decodePostgresScanRow(raw).pipe(Effect.mapError(storageFailure));
    const scan = yield* decodeScan(row.record_json).pipe(
      Effect.flatMap(valid => validateStoredScan(valid)),
    );
    yield* validatePostgresRow(row, scan);
    const claimable =
      scan.status === 'queued' ||
      (scan.status === 'running' &&
        (row.lease_expires_at === null || row.lease_expires_at < claimedAt));
    if (!claimable) return Option.none<ScanClaim>();
    const baseline = yield* baselineForRow(row, scan);
    const [token] = yield* identityAndTime(crypto);
    const lease = new ScanLease({ token, expiresAt });
    const running = new ScanRecord({
      ...scan,
      status: 'running',
      updatedAt: claimedAt,
    });
    const encoded = yield* encodeStoredScan(running).pipe(
      Effect.mapError(storageFailure),
    );
    const baselineId = Option.match(baseline, {
      onNone: () => undefined,
      onSome: candidate => candidate.scanId,
    });
    const expectedBaselineId = row.baseline_scan_id ?? baselineId;
    const updated = yield* sql<{ readonly id: string }>`
      update scans
      set status = 'running',
          record = ${encoded}::jsonb,
          lease_token = ${lease.token},
          lease_expires_at = ${lease.expiresAt},
          baseline_scan_id = ${expectedBaselineId},
          updated_at = ${running.updatedAt}
      where id = ${row.id}
        and status in ('queued', 'running')
      returning id
    `.pipe(Effect.mapError(storageFailure));
    if (updated[0] === undefined) return Option.none<ScanClaim>();
    return Option.some(
      new ScanClaim({
        scan: running,
        lease,
        ...(Option.isSome(baseline) ? { baseline: baseline.value } : {}),
      }),
    );
  });

  const claimBy = Effect.fn('RadarStore.claimBy')(function* (
    select: Effect.Effect<ReadonlyArray<PostgresScanRow>, StorageError>,
    expiresAt: string,
  ) {
    const acceptedExpiry = yield* decodeTimestamp(expiresAt).pipe(
      Effect.mapError(storageFailure),
    );
    const claimedAt = yield* nowIso;
    if (acceptedExpiry <= claimedAt) {
      return yield* new StorageError({
        message: 'A scan lease must expire after it is claimed.',
      });
    }
    return yield* sql.withTransaction(
      Effect.gen(function* () {
        const rows = yield* select;
        const raw = rows[0];
        return raw === undefined
          ? Option.none<ScanClaim>()
          : yield* claimLockedScan(raw, claimedAt, acceptedExpiry);
      }),
    ).pipe(Effect.mapError(storageFailure));
  });

  return RadarStore.of({
    storage: 'postgres',
    ready: sql`select 1`.pipe(Effect.asVoid, Effect.mapError(storageFailure)),
    createProfile: Effect.fn('RadarStore.createProfile')(function* (input) {
      const [id, createdAt] = yield* identityAndTime(crypto);
      const profile = new AudienceProfile({
        id,
        audience: input.audience,
        ...(input.displayName
          ? { displayName: input.displayName.trim().slice(0, 80) }
          : {}),
        createdAt,
      });
      yield* sql`
        insert into audience_profiles (id, profile, created_at)
        values (${profile.id}, ${sql.json(profile)}, ${profile.createdAt})
      `.pipe(Effect.mapError(storageFailure));
      return profile;
    }),
    createScan: Effect.fn('RadarStore.createScan')(function* (input) {
      const [id, createdAt] = yield* identityAndTime(crypto);
      const owner = input.owner.toLowerCase();
      const repository = input.repository.toLowerCase();
      const scan = new ScanRecord({
        id,
        githubUrl: repositoryUrl(owner, repository),
        owner,
        repository,
        audience: input.audience,
        status: 'queued',
        progress: 0,
        stage: 'Queued for a bounded static scan',
        createdAt,
        updatedAt: createdAt,
      });
      const encoded = yield* encodeStoredScan(scan).pipe(
        Effect.mapError(storageFailure),
      );
      const rows = yield* sql<{ readonly id: string }>`
        insert into scans (
          id, owner, repository, status, record, lease_token, lease_expires_at,
          baseline_scan_id, created_at, updated_at
        ) values (
          ${scan.id}, ${scan.owner}, ${scan.repository}, ${scan.status}, ${encoded}::jsonb,
          null, null, null, ${scan.createdAt}, ${scan.updatedAt}
        )
        on conflict (lower(owner), lower(repository))
        where status in ('queued', 'running')
        do nothing
        returning id
      `.pipe(Effect.mapError(storageFailure));
      if (rows[0] === undefined) return yield* repositoryActiveFailure();
      return scan;
    }),
    updateScan: Effect.fn('RadarStore.updateScan')(function* (id, update, lease) {
      const accepted = yield* decodeScanUpdate(update).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      return yield* sql.withTransaction(
        Effect.gen(function* () {
          const rows = yield* sql<PostgresScanRow>`
            select id, owner, repository, status, record::text record_json,
                   to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                   to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                   lease_token,
                   to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                   baseline_scan_id
            from scans where id = ${id} for update
          `.pipe(Effect.mapError(storageFailure));
          const raw = rows[0];
          if (raw === undefined) {
            return yield* new StorageError({ message: `Scan ${id} was not found.` });
          }
          const scan = yield* decodeStoredPostgresScan(raw);
          if (scan.status !== 'queued' && scan.status !== 'running') return scan;
          if (
            acceptedLease === undefined ||
            !rowLeaseIsLive(raw, acceptedLease, updatedAt) ||
            (scan.status === 'queued' && accepted.status !== 'running')
          ) {
            return scan;
          }
          const requestedProgress = accepted.progress ?? scan.progress;
          const progress = Math.max(scan.progress, requestedProgress);
          const acceptsStage = accepted.progress === undefined ||
            requestedProgress >= scan.progress;
          const next = new ScanRecord({
            ...scan,
            ...(accepted.status === undefined ? {} : { status: accepted.status }),
            progress,
            ...(accepted.stage === undefined || !acceptsStage
              ? {}
              : { stage: accepted.stage }),
            updatedAt,
          });
          const encoded = yield* encodeStoredScan(next).pipe(
            Effect.mapError(storageFailure),
          );
          yield* sql`
            update scans
            set status = ${next.status}, record = ${encoded}::jsonb, updated_at = ${next.updatedAt}
            where id = ${id}
          `.pipe(Effect.mapError(storageFailure));
          return next;
        }),
      ).pipe(Effect.mapError(storageFailure));
    }),
    completeScan: Effect.fn('RadarStore.completeScan')(function* (id, result, lease) {
      const canonical = yield* decodeCanonicalStoredResult(result).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      return yield* sql.withTransaction(
        Effect.gen(function* () {
          const rows = yield* sql<PostgresScanRow>`
            select id, owner, repository, status, record::text record_json,
                   to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                   to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                   lease_token,
                   to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                   baseline_scan_id
            from scans where id = ${id} for update
          `.pipe(Effect.mapError(storageFailure));
          const raw = rows[0];
          if (raw === undefined) {
            return yield* new StorageError({ message: `Scan ${id} was not found.` });
          }
          const scan = yield* decodeStoredPostgresScan(raw);
          if (scan.status === 'completed' && scan.result?.resultKind === 'complete') {
            return sameStoredResult(scan.result, canonical)
              ? scan
              : yield* new StorageError({
                  message: 'Scan completion did not match its terminal durable identity.',
                });
          }
          if (scan.status !== 'queued' && scan.status !== 'running') {
            return yield* new StorageError({
              message: 'Scan completion did not match its active durable identity.',
            });
          }
          if (
            acceptedLease === undefined ||
            !rowLeaseIsLive(raw, acceptedLease, updatedAt) ||
            !isCompletionBoundToScan(scan, canonical, raw.baseline_scan_id ?? undefined)
          ) {
            return yield* new StorageError({
              message: 'Scan completion did not match its active durable identity.',
            });
          }
          const completed = new ScanRecord({
            ...withoutTerminalFields(scan),
            status: 'completed',
            progress: 100,
            stage: 'Your review is ready',
            result: canonical,
            updatedAt,
          });
          const encoded = yield* encodeStoredScan(completed).pipe(
            Effect.mapError(storageFailure),
          );
          const baselineScanId = canonical.comparison.previousScanId ?? null;
          const updated = yield* sql<{ readonly id: string }>`
            update scans
            set status = 'completed', record = ${encoded}::jsonb,
                lease_token = null, lease_expires_at = null,
                baseline_scan_id = ${baselineScanId}, updated_at = ${completed.updatedAt}
            where id = ${id}
              and status in ('queued', 'running')
              and (${acceptedLease === undefined ? raw.lease_token : acceptedLease.token}) is not distinct from lease_token
            returning id
          `.pipe(Effect.mapError(storageFailure));
          if (updated[0] === undefined) {
            return yield* new StorageError({
              message: 'Scan completion did not match its active durable identity.',
            });
          }
          return completed;
        }),
      ).pipe(Effect.mapError(storageFailure));
    }),
    failScanIfActive: Effect.fn('RadarStore.failScanIfActive')(function* (
      id,
      failure,
      lease,
    ) {
      const acceptedFailure = yield* validateFailure(failure);
      const acceptedLease = lease === undefined
        ? undefined
        : yield* decodeLease(lease).pipe(Effect.mapError(storageFailure));
      const updatedAt = yield* nowIso;
      yield* sql.withTransaction(
        Effect.gen(function* () {
          const rows = yield* sql<PostgresScanRow>`
            select id, owner, repository, status, record::text record_json,
                   to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                   to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                   lease_token,
                   to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                   baseline_scan_id
            from scans where id = ${id} for update
          `.pipe(Effect.mapError(storageFailure));
          const raw = rows[0];
          if (raw === undefined) return;
          const scan = yield* decodeStoredPostgresScan(raw);
          if (
            (scan.status !== 'queued' && scan.status !== 'running') ||
            (scan.status === 'running' &&
              (acceptedLease === undefined ||
                !rowLeaseIsLive(raw, acceptedLease, updatedAt))) ||
            (scan.status === 'queued' &&
              ((acceptedLease !== undefined &&
                !rowLeaseIsLive(raw, acceptedLease, updatedAt)) ||
                (acceptedLease === undefined && raw.lease_token !== null)))
          ) {
            return;
          }
          const failed = new ScanRecord({
            ...withoutTerminalFields(scan),
            status: 'failed',
            progress: 100,
            stage: acceptedFailure.stage,
            error: acceptedFailure.error,
            updatedAt,
          });
          const encoded = yield* encodeStoredScan(failed).pipe(
            Effect.mapError(storageFailure),
          );
          yield* sql`
            update scans
            set status = 'failed', record = ${encoded}::jsonb,
                lease_token = null, lease_expires_at = null,
                baseline_scan_id = null, updated_at = ${failed.updatedAt}
            where id = ${id} and status in ('queued', 'running')
          `.pipe(Effect.mapError(storageFailure));
        }),
      ).pipe(Effect.mapError(storageFailure));
    }),
    claimScan: (id, expiresAt) =>
      claimBy(
        sql<PostgresScanRow>`
          select id, owner, repository, status, record::text record_json,
                 to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                 to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                 lease_token,
                 to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                 baseline_scan_id
          from scans where id = ${id} for update
        `.pipe(Effect.mapError(storageFailure)),
        expiresAt,
      ),
    claimNextScan: expiresAt =>
      claimBy(
        sql<PostgresScanRow>`
          select id, owner, repository, status, record::text record_json,
                 to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                 to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                 lease_token,
                 to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                 baseline_scan_id
          from scans
          where status = 'queued'
             or (status = 'running' and (lease_expires_at is null or lease_expires_at < now()))
          order by created_at, id
          for update skip locked
          limit 1
        `.pipe(Effect.mapError(storageFailure)),
        expiresAt,
      ),
    renewScanLease: Effect.fn('RadarStore.renewScanLease')(function* (
      id,
      lease,
      expiresAt,
    ) {
      const acceptedLease = yield* decodeLease(lease).pipe(
        Effect.mapError(storageFailure),
      );
      const acceptedExpiry = yield* decodeTimestamp(expiresAt).pipe(
        Effect.mapError(storageFailure),
      );
      const currentTime = yield* nowIso;
      if (acceptedExpiry <= currentTime) return Option.none<ScanLease>();
      const rows = yield* sql<{ readonly expires_at: string }>`
        update scans
        set lease_expires_at = case
              when lease_expires_at < ${acceptedExpiry} then ${acceptedExpiry}
              else lease_expires_at
            end
        where id = ${id}
          and status = 'running'
          and lease_token = ${acceptedLease.token}
          and lease_expires_at is not null
          and lease_expires_at >= ${currentTime}
        returning to_char(
          lease_expires_at at time zone 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        ) expires_at
      `.pipe(Effect.mapError(storageFailure));
      const row = rows[0];
      if (row === undefined) return Option.none<ScanLease>();
      const decoded = yield* Schema.decodeUnknownEffect(
        Schema.Struct({ expires_at: IsoTimestamp }),
        { onExcessProperty: 'error' },
      )(row).pipe(Effect.mapError(storageFailure));
      return Option.some(
        new ScanLease({ token: acceptedLease.token, expiresAt: decoded.expires_at }),
      );
    }),
    getScan: selectScan,
    listRecentScans: Effect.fn('RadarStore.listRecentScans')(function* (limit = 8) {
      const rows = yield* sql<PostgresScanRow>`
        select id, owner, repository, status, record::text record_json,
               to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
               to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
               lease_token,
               to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
               baseline_scan_id
        from scans order by created_at desc, id desc
        limit ${Math.min(Math.max(limit, 1), 25)}
      `.pipe(Effect.mapError(storageFailure));
      return yield* Effect.forEach(rows, decodeStoredPostgresScan);
    }),
    listRecentRepositories: Effect.fn('RadarStore.listRecentRepositories')(
      function* (limit = 8) {
        const repositoryLimit = Math.trunc(Math.min(Math.max(limit, 1), 25));
        const rows = yield* sql<PostgresScanRow>`
          select id, owner, repository, status, record_json, created_at, updated_at,
                 lease_token, lease_expires_at, baseline_scan_id
          from (
            select distinct on (lower(owner), lower(repository))
              id, owner, repository, status, record::text record_json,
              to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
              to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
              lease_token,
              to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
              baseline_scan_id
            from scans
            order by lower(owner), lower(repository), created_at desc, id desc
          ) latest_repositories
          order by created_at desc, id desc
          limit ${repositoryLimit}
        `.pipe(Effect.mapError(storageFailure));
        return yield* Effect.forEach(rows, decodeStoredPostgresScan);
      },
    ),
    listRepositoryScans: Effect.fn('RadarStore.listRepositoryScans')(
      function* (owner, repository) {
        const rows = yield* sql<PostgresScanRow>`
          select id, owner, repository, status, record::text record_json,
                 to_char(created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') created_at,
                 to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') updated_at,
                 lease_token,
                 to_char(lease_expires_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') lease_expires_at,
                 baseline_scan_id
          from scans
          where lower(owner) = lower(${owner})
            and lower(repository) = lower(${repository})
          order by created_at desc, id desc
        `.pipe(Effect.mapError(storageFailure));
        return yield* Effect.forEach(rows, decodeStoredPostgresScan);
      },
    ),
    getPreviousResult: findPreviousResult,
  });
});

export const RadarStoreLive = Layer.unwrap(
  Config.option(Config.redacted('DATABASE_URL')).pipe(
    Effect.map(databaseUrl =>
      Option.match(databaseUrl, {
        onNone: () => MemoryStoreLive,
        onSome: value =>
          Layer.effect(RadarStore, makePostgresStore).pipe(
            Layer.provide(
              PgClient.layer({
                url: value,
                maxConnections: 4,
                connectTimeout: '10 seconds',
                idleTimeout: '20 seconds',
                applicationName: 'codebase-radar',
              }),
            ),
            Layer.orDie,
          ),
      }),
    ),
  ),
);
