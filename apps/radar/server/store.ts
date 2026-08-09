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
  ScanResult,
} from '../shared/domain';

export class StorageError extends Schema.TaggedErrorClass<StorageError>()(
  'StorageError',
  { message: Schema.String },
) {}

export interface ScanUpdate {
  readonly status?: ScanRecord['status'];
  readonly progress?: number;
  readonly stage?: string;
  readonly error?: string;
  readonly result?: ScanResult;
}

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
  ) => Effect.Effect<ScanRecord, StorageError>;
  readonly getScan: (id: string) => Effect.Effect<Option.Option<ScanRecord>, StorageError>;
  readonly listRecentScans: (limit?: number) => Effect.Effect<ReadonlyArray<ScanRecord>, StorageError>;
  readonly getPreviousResult: (
    owner: string,
    repository: string,
    excludingScanId: string,
  ) => Effect.Effect<Option.Option<ScanResult>, StorageError>;
}>()('RadarStore') {}

const nowIso = DateTime.nowAsDate.pipe(Effect.map(date => date.toISOString()));
const identityAndTime = (crypto: Crypto.Crypto) =>
  Effect.all([crypto.randomUUIDv7, nowIso]).pipe(Effect.mapError(storageFailure));

interface MemoryState {
  readonly profiles: ReadonlyMap<string, AudienceProfile>;
  readonly scans: ReadonlyMap<string, ScanRecord>;
}

const makeMemoryStore = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  const state = yield* Ref.make<MemoryState>({ profiles: new Map(), scans: new Map() });

  const getScan = (id: string) =>
    Ref.get(state).pipe(
      Effect.map(current => Option.fromUndefinedOr(current.scans.get(id))),
    );

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
      const scan = new ScanRecord({
        id,
        githubUrl: input.githubUrl,
        owner: input.owner,
        repository: input.repository,
        audience: input.audience,
        status: 'queued',
        progress: 2,
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
    updateScan: Effect.fn('RadarStore.updateScan')(function* (id, update) {
      const current = yield* getScan(id);
      if (Option.isNone(current)) {
        return yield* new StorageError({ message: `Scan ${id} was not found.` });
      }
      const updatedAt = yield* nowIso;
      const next = new ScanRecord({ ...current.value, ...update, updatedAt });
      yield* Ref.update(state, value => ({
        ...value,
        scans: new Map(value.scans).set(id, next),
      }));
      return next;
    }),
    getScan,
    listRecentScans: (limit = 8) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          [...current.scans.values()]
            .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
            .slice(0, Math.min(Math.max(limit, 1), 25)),
        ),
      ),
    getPreviousResult: (owner, repository, excludingScanId) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          Option.fromUndefinedOr(
            [...current.scans.values()]
              .filter(
                scan =>
                  scan.id !== excludingScanId &&
                  scan.owner === owner &&
                  scan.repository === repository &&
                  scan.status === 'completed' &&
                  scan.result !== undefined,
              )
              .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0]
              ?.result,
          ),
        ),
      ),
  });
});

const MemoryStoreLive = Layer.effect(RadarStore, makeMemoryStore);

const storageFailure = <Failure>(cause: Failure) =>
  new StorageError({
    message: cause instanceof Error ? cause.message : String(cause),
  });

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
      created_at timestamptz not null,
      updated_at timestamptz not null
    )
  `.pipe(Effect.mapError(storageFailure));
  yield* sql`
    create index if not exists scans_repository_completed_idx
    on scans(owner, repository, updated_at desc)
    where status = 'completed'
  `.pipe(Effect.mapError(storageFailure));

  const decodeScan = (recordJson: string) =>
    Schema.decodeEffect(Schema.fromJsonString(ScanRecord))(recordJson).pipe(
      Effect.mapError(storageFailure),
    );

  const getScan = Effect.fn('RadarStore.getScan')(function* (id: string) {
    const rows = yield* sql<{ readonly record_json: string }>`
      select record::text record_json from scans where id = ${id} limit 1
    `.pipe(Effect.mapError(storageFailure));
    return rows[0]
      ? Option.some(yield* decodeScan(rows[0].record_json))
      : Option.none<ScanRecord>();
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
      const scan = new ScanRecord({
        id,
        githubUrl: input.githubUrl,
        owner: input.owner,
        repository: input.repository,
        audience: input.audience,
        status: 'queued',
        progress: 2,
        stage: 'Queued for a bounded static scan',
        createdAt,
        updatedAt: createdAt,
      });
      yield* sql`
        insert into scans (id, owner, repository, status, record, created_at, updated_at)
        values (
          ${scan.id}, ${scan.owner}, ${scan.repository}, ${scan.status},
          ${sql.json(scan)}, ${scan.createdAt}, ${scan.updatedAt}
        )
      `.pipe(Effect.mapError(storageFailure));
      return scan;
    }),
    updateScan: Effect.fn('RadarStore.updateScan')(function* (id, update) {
      const current = yield* getScan(id);
      if (Option.isNone(current)) {
        return yield* new StorageError({ message: `Scan ${id} was not found.` });
      }
      const updatedAt = yield* nowIso;
      const next = new ScanRecord({ ...current.value, ...update, updatedAt });
      yield* sql`
        update scans set
          status = ${next.status},
          record = ${sql.json(next)},
          updated_at = ${next.updatedAt}
        where id = ${id}
      `.pipe(Effect.mapError(storageFailure));
      return next;
    }),
    getScan,
    listRecentScans: Effect.fn('RadarStore.listRecentScans')(function* (limit = 8) {
      const rows = yield* sql<{ readonly record_json: string }>`
        select record::text record_json from scans order by created_at desc
        limit ${Math.min(Math.max(limit, 1), 25)}
      `.pipe(Effect.mapError(storageFailure));
      return yield* Effect.forEach(rows, row => decodeScan(row.record_json));
    }),
    getPreviousResult: Effect.fn('RadarStore.getPreviousResult')(
      function* (owner, repository, excludingScanId) {
        const rows = yield* sql<{ readonly record_json: string }>`
          select record::text record_json from scans
          where owner = ${owner}
            and repository = ${repository}
            and id <> ${excludingScanId}
            and status = 'completed'
          order by updated_at desc
          limit 1
        `.pipe(Effect.mapError(storageFailure));
        if (!rows[0]) return Option.none<ScanResult>();
        const scan = yield* decodeScan(rows[0].record_json);
        return Option.fromUndefinedOr(scan.result);
      },
    ),
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
