import { createCipheriv, createDecipheriv } from 'node:crypto';
import { PgClient } from '@effect/sql-pg';
import {
  Config,
  Context,
  Crypto,
  DateTime,
  Effect,
  Encoding,
  Layer,
  Option,
  Redacted,
  Ref,
  Result,
  Schema,
} from 'effect';
import {
  AgentPriorityReview,
  AgentProfile,
  AgentProvider,
} from '../shared/domain';

export class AgentStoreError extends Schema.TaggedErrorClass<AgentStoreError>()(
  'AgentStoreError',
  { message: Schema.String },
) {}

export class AgentCredentialFile extends Schema.Class<AgentCredentialFile>(
  'AgentCredentialFile',
)({
  path: Schema.Literals(['auth.json', '.credentials.json', '.claude.json']),
  content: Schema.String,
}) {}

export class AgentCredentialState extends Schema.Class<AgentCredentialState>(
  'AgentCredentialState',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-home/v1'),
  provider: AgentProvider,
  files: Schema.Array(AgentCredentialFile).check(Schema.isMaxLength(3)),
}) {}

class EncryptedAgentHome extends Schema.Class<EncryptedAgentHome>(
  'EncryptedAgentHome',
)({
  schemaVersion: Schema.Literal('codebase-radar.encrypted-agent-home/v2'),
  keyVersion: Schema.Literal('v1'),
  generation: Schema.Number,
  ciphertext: Schema.String,
  nonce: Schema.String,
  tag: Schema.String,
  wrappedKey: Schema.String,
  wrapNonce: Schema.String,
  wrapTag: Schema.String,
}) {}

class LegacyEncryptedAgentHome extends Schema.Class<LegacyEncryptedAgentHome>(
  'LegacyEncryptedAgentHome',
)({
  schemaVersion: Schema.Literal('codebase-radar.encrypted-agent-home/v1'),
  generation: Schema.Number,
  ciphertext: Schema.String,
  nonce: Schema.String,
  tag: Schema.String,
  wrappedKey: Schema.String,
  wrapNonce: Schema.String,
  wrapTag: Schema.String,
}) {}

const StoredAgentHome = Schema.Union([
  LegacyEncryptedAgentHome,
  EncryptedAgentHome,
]);

interface AgentProfileUpdate {
  readonly state: AgentProfile['state'];
  readonly accountLabel?: string;
  readonly diagnostic?: string;
}

interface MemoryProfile {
  readonly ownerId: string;
  readonly profile: AgentProfile;
  readonly generation: number;
  readonly home?: AgentCredentialState;
}

interface MemoryAgentState {
  readonly sessions: ReadonlySet<string>;
  readonly profiles: ReadonlyMap<string, MemoryProfile>;
  readonly reviews: ReadonlyMap<string, { readonly ownerId: string; readonly review: AgentPriorityReview }>;
}

export class AgentStore extends Context.Service<AgentStore, {
  readonly ready: Effect.Effect<void, AgentStoreError>;
  readonly getOrCreateSession: (candidate?: string) => Effect.Effect<string, AgentStoreError>;
  readonly createProfile: (
    ownerId: string,
    provider: typeof AgentProvider.Type,
  ) => Effect.Effect<AgentProfile, AgentStoreError>;
  readonly listProfiles: (ownerId: string) => Effect.Effect<ReadonlyArray<AgentProfile>, AgentStoreError>;
  readonly getProfile: (
    ownerId: string,
    profileId: string,
  ) => Effect.Effect<Option.Option<AgentProfile>, AgentStoreError>;
  readonly updateProfile: (
    ownerId: string,
    profileId: string,
    update: AgentProfileUpdate,
  ) => Effect.Effect<AgentProfile, AgentStoreError>;
  readonly readHome: (
    ownerId: string,
    profileId: string,
  ) => Effect.Effect<{ readonly generation: number; readonly state: Option.Option<AgentCredentialState> }, AgentStoreError>;
  readonly writeHome: (
    ownerId: string,
    profileId: string,
    expectedGeneration: number,
    state: AgentCredentialState,
  ) => Effect.Effect<number, AgentStoreError>;
  readonly createReview: (
    ownerId: string,
    profileId: string,
    scanId: string,
  ) => Effect.Effect<AgentPriorityReview, AgentStoreError>;
  readonly updateReview: (
    ownerId: string,
    review: AgentPriorityReview,
  ) => Effect.Effect<AgentPriorityReview, AgentStoreError>;
  readonly getReview: (
    ownerId: string,
    reviewId: string,
  ) => Effect.Effect<Option.Option<AgentPriorityReview>, AgentStoreError>;
  readonly failReviewIfActive: (
    ownerId: string,
    reviewId: string,
    diagnostic: string,
    failedAt: string,
  ) => Effect.Effect<void, AgentStoreError>;
  readonly failStaleReviews: (
    cutoff: string,
    failedAt: string,
  ) => Effect.Effect<void, AgentStoreError>;
  readonly deleteProfile: (ownerId: string, profileId: string) => Effect.Effect<void, AgentStoreError>;
}>()('AgentStore') {}

const nowIso = DateTime.nowAsDate.pipe(Effect.map(date => date.toISOString()));
const storeError = <Failure>(cause: Failure) =>
  new AgentStoreError({
    message: cause instanceof Error ? cause.message : String(cause),
  });

export const decodeStoredAgentHome = (value: string) =>
  Schema.decodeEffect(Schema.fromJsonString(StoredAgentHome), {
    onExcessProperty: 'error',
  })(value).pipe(Effect.mapError(storeError));

const legacyHomeDiagnostic =
  'The saved provider sign-in uses an obsolete encryption key. Sign in again.';

const makeAgentProfile = Effect.fn('makeAgentProfile')(function* (
  crypto: Crypto.Crypto,
  provider: typeof AgentProvider.Type,
) {
  const [id, createdAt] = yield* Effect.all([crypto.randomUUIDv7, nowIso]);
  return new AgentProfile({
    id,
    provider,
    state: 'disconnected',
    createdAt,
    updatedAt: createdAt,
  });
});

const makeReview = Effect.fn('makeReview')(function* (
  crypto: Crypto.Crypto,
  profileId: string,
  provider: typeof AgentProvider.Type,
  scanId: string,
) {
  const [id, createdAt] = yield* Effect.all([crypto.randomUUIDv7, nowIso]);
  return new AgentPriorityReview({
    schemaVersion: 'codebase-radar.priority-review/v1',
    id,
    scanId,
    profileId,
    provider,
    status: 'queued',
    createdAt,
    updatedAt: createdAt,
  });
});

const sessionCandidate = (value?: string) =>
  value && /^[0-9a-f]{8}-[0-9a-f-]{27}$/iu.test(value) ? Option.some(value) : Option.none<string>();

const makeMemoryAgentStore = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  const state = yield* Ref.make<MemoryAgentState>({
    sessions: new Set(),
    profiles: new Map(),
    reviews: new Map(),
  });

  const getProfileEntry = (ownerId: string, profileId: string) =>
    Ref.get(state).pipe(
      Effect.map(current =>
        Option.filter(
          Option.fromUndefinedOr(current.profiles.get(profileId)),
          entry => entry.ownerId === ownerId,
        ),
      ),
    );

  const failReviewIfActive = Effect.fn('AgentStore.failReviewIfActive')(
    function* (
      ownerId: string,
      reviewId: string,
      diagnostic: string,
      failedAt: string,
    ) {
      yield* Ref.update(state, current => {
        const entry = current.reviews.get(reviewId);
        if (
          !entry ||
          entry.ownerId !== ownerId ||
          (entry.review.status !== 'queued' && entry.review.status !== 'running')
        ) {
          return current;
        }
        const review = new AgentPriorityReview({
          ...entry.review,
          status: 'failed',
          diagnostic,
          updatedAt: failedAt,
        });
        return {
          ...current,
          reviews: new Map(current.reviews).set(reviewId, { ...entry, review }),
        };
      });
    },
  );

  return AgentStore.of({
    ready: Effect.void,
    getOrCreateSession: Effect.fn('AgentStore.getOrCreateSession')(function* (candidate) {
      const current = yield* Ref.get(state);
      const existing = Option.filter(sessionCandidate(candidate), id => current.sessions.has(id));
      if (Option.isSome(existing)) return existing.value;
      const id = yield* crypto.randomUUIDv7.pipe(Effect.mapError(storeError));
      yield* Ref.update(state, value => ({
        ...value,
        sessions: new Set(value.sessions).add(id),
      }));
      return id;
    }),
    createProfile: Effect.fn('AgentStore.createProfile')(function* (ownerId, provider) {
      const profile = yield* makeAgentProfile(crypto, provider).pipe(
        Effect.mapError(storeError),
      );
      yield* Ref.update(state, current => ({
        ...current,
        profiles: new Map(current.profiles).set(profile.id, {
          ownerId,
          profile,
          generation: 0,
        }),
      }));
      return profile;
    }),
    listProfiles: ownerId =>
      Ref.get(state).pipe(
        Effect.map(current =>
          [...current.profiles.values()]
            .filter(entry => entry.ownerId === ownerId)
            .map(entry => entry.profile)
            .sort((left, right) => left.createdAt.localeCompare(right.createdAt)),
        ),
      ),
    getProfile: (ownerId, profileId) =>
      getProfileEntry(ownerId, profileId).pipe(Effect.map(Option.map(entry => entry.profile))),
    updateProfile: Effect.fn('AgentStore.updateProfile')(function* (ownerId, profileId, update) {
      const entry = yield* getProfileEntry(ownerId, profileId);
      if (Option.isNone(entry)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      const updatedAt = yield* nowIso;
      const profile = new AgentProfile({
        ...entry.value.profile,
        state: update.state,
        ...(update.accountLabel === undefined ? {} : { accountLabel: update.accountLabel }),
        ...(update.diagnostic === undefined ? {} : { diagnostic: update.diagnostic }),
        updatedAt,
      });
      yield* Ref.update(state, current => ({
        ...current,
        profiles: new Map(current.profiles).set(profileId, { ...entry.value, profile }),
      }));
      return profile;
    }),
    readHome: Effect.fn('AgentStore.readHome')(function* (ownerId, profileId) {
      const entry = yield* getProfileEntry(ownerId, profileId);
      if (Option.isNone(entry)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      return {
        generation: entry.value.generation,
        state: Option.fromUndefinedOr(entry.value.home),
      };
    }),
    writeHome: Effect.fn('AgentStore.writeHome')(function* (ownerId, profileId, expectedGeneration, home) {
      const entry = yield* getProfileEntry(ownerId, profileId);
      if (Option.isNone(entry) || entry.value.generation !== expectedGeneration) {
        return yield* new AgentStoreError({ message: 'Provider state changed during this operation.' });
      }
      const generation = expectedGeneration + 1;
      yield* Ref.update(state, current => ({
        ...current,
        profiles: new Map(current.profiles).set(profileId, {
          ...entry.value,
          generation,
          home,
        }),
      }));
      return generation;
    }),
    createReview: Effect.fn('AgentStore.createReview')(function* (ownerId, profileId, scanId) {
      const entry = yield* getProfileEntry(ownerId, profileId);
      if (Option.isNone(entry)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      const review = yield* makeReview(crypto, profileId, entry.value.profile.provider, scanId).pipe(
        Effect.mapError(storeError),
      );
      yield* Ref.update(state, current => ({
        ...current,
        reviews: new Map(current.reviews).set(review.id, { ownerId, review }),
      }));
      return review;
    }),
    updateReview: Effect.fn('AgentStore.updateReview')(function* (ownerId, review) {
      const current = yield* Ref.get(state);
      const existing = current.reviews.get(review.id);
      if (!existing || existing.ownerId !== ownerId) return yield* new AgentStoreError({ message: 'Priority review was not found.' });
      yield* Ref.update(state, value => ({
        ...value,
        reviews: new Map(value.reviews).set(review.id, { ownerId, review }),
      }));
      return review;
    }),
    getReview: (ownerId, reviewId) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          Option.map(
            Option.filter(
              Option.fromUndefinedOr(current.reviews.get(reviewId)),
              entry => entry.ownerId === ownerId,
            ),
            entry => entry.review,
          ),
        ),
      ),
    failReviewIfActive,
    failStaleReviews: (cutoff, failedAt) =>
      Ref.get(state).pipe(
        Effect.flatMap(current =>
          Effect.forEach(
            [...current.reviews.values()].filter(
              entry => entry.review.updatedAt < cutoff,
            ),
            entry =>
              failReviewIfActive(
                entry.ownerId,
                entry.review.id,
                'The priority review was interrupted by a service restart. Retry it.',
                failedAt,
              ),
            { concurrency: 'unbounded', discard: true },
          ),
        ),
      ),
    deleteProfile: Effect.fn('AgentStore.deleteProfile')(function* (ownerId, profileId) {
      const entry = yield* getProfileEntry(ownerId, profileId);
      if (Option.isNone(entry)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      yield* Ref.update(state, current => ({
        ...current,
        profiles: new Map([...current.profiles].filter(([id]) => id !== profileId)),
      }));
    }),
  });
});

const decodeBase64 = (value: string) =>
  Result.match(Encoding.decodeBase64(value), {
    onFailure: error => Effect.fail(storeError(error.message)),
    onSuccess: Effect.succeed,
  });

const encryptedHomeAad = (
  ownerId: string,
  profileId: string,
  generation: number,
  keyVersion: EncryptedAgentHome['keyVersion'],
) => new TextEncoder().encode(
  `codebase-radar:${ownerId}:${profileId}:${generation}:${keyVersion}`,
);

const encryptBytes = Effect.fn('encryptBytes')(function* (
  key: Uint8Array,
  nonce: Uint8Array,
  value: Uint8Array,
  aad: Uint8Array,
) {
  return yield* Effect.try({
    try: () => {
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(aad);
      return {
        ciphertext: Uint8Array.from([...cipher.update(value), ...cipher.final()]),
        tag: Uint8Array.from(cipher.getAuthTag()),
      };
    },
    catch: storeError,
  });
});

const decryptBytes = Effect.fn('decryptBytes')(function* (
  key: Uint8Array,
  nonce: Uint8Array,
  value: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
) {
  return yield* Effect.try({
    try: () => {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      return Uint8Array.from([...decipher.update(value), ...decipher.final()]);
    },
    catch: storeError,
  });
});

const encryptHome = Effect.fn('encryptHome')(function* (
  crypto: Crypto.Crypto,
  kek: Uint8Array,
  ownerId: string,
  profileId: string,
  generation: number,
  state: AgentCredentialState,
) {
  const [dek, nonce, wrapNonce] = yield* Effect.all([
    crypto.randomBytes(32),
    crypto.randomBytes(12),
    crypto.randomBytes(12),
  ]).pipe(Effect.mapError(storeError));
  const aad = encryptedHomeAad(ownerId, profileId, generation, 'v1');
  const encrypted = yield* encryptBytes(
    dek,
    nonce,
    new TextEncoder().encode(JSON.stringify(state)),
    aad,
  );
  const wrapped = yield* encryptBytes(kek, wrapNonce, dek, aad);
  return new EncryptedAgentHome({
    schemaVersion: 'codebase-radar.encrypted-agent-home/v2',
    keyVersion: 'v1',
    generation,
    ciphertext: Encoding.encodeBase64(encrypted.ciphertext),
    nonce: Encoding.encodeBase64(nonce),
    tag: Encoding.encodeBase64(encrypted.tag),
    wrappedKey: Encoding.encodeBase64(wrapped.ciphertext),
    wrapNonce: Encoding.encodeBase64(wrapNonce),
    wrapTag: Encoding.encodeBase64(wrapped.tag),
  });
});

const decryptHome = Effect.fn('decryptHome')(function* (
  kek: Uint8Array,
  ownerId: string,
  profileId: string,
  encrypted: EncryptedAgentHome,
) {
  const [ciphertext, nonce, tag, wrappedKey, wrapNonce, wrapTag] = yield* Effect.all([
    decodeBase64(encrypted.ciphertext),
    decodeBase64(encrypted.nonce),
    decodeBase64(encrypted.tag),
    decodeBase64(encrypted.wrappedKey),
    decodeBase64(encrypted.wrapNonce),
    decodeBase64(encrypted.wrapTag),
  ]);
  const aad = encryptedHomeAad(
    ownerId,
    profileId,
    encrypted.generation,
    encrypted.keyVersion,
  );
  const dek = yield* decryptBytes(kek, wrapNonce, wrappedKey, wrapTag, aad);
  const plaintext = yield* decryptBytes(dek, nonce, ciphertext, tag, aad);
  return yield* Schema.decodeEffect(Schema.fromJsonString(AgentCredentialState))(
    new TextDecoder().decode(plaintext),
  ).pipe(Effect.mapError(storeError));
});

const makePostgresAgentStore = Effect.gen(function* () {
  const sql = yield* PgClient.PgClient;
  const crypto = yield* Crypto.Crypto;
  const configuredKey = yield* Config.redacted('RADAR_AGENT_HOME_KEY_V1').pipe(
    Effect.mapError(storeError),
  );
  const keyMaterial = Redacted.value(configuredKey);
  if (new TextEncoder().encode(keyMaterial).byteLength < 48) {
    return yield* new AgentStoreError({
      message: 'RADAR_AGENT_HOME_KEY_V1 must contain at least 48 bytes of random secret material.',
    });
  }
  const kek = yield* crypto.digest(
    'SHA-256',
    new TextEncoder().encode(keyMaterial),
  ).pipe(Effect.mapError(storeError));

  yield* sql`
    create table if not exists radar_sessions (
      id text primary key,
      created_at timestamptz not null,
      last_seen_at timestamptz not null
    )
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    create table if not exists agent_profiles (
      id text primary key,
      owner_id text not null,
      provider text not null,
      profile jsonb not null,
      encrypted_home jsonb,
      generation integer not null default 0,
      created_at timestamptz not null,
      updated_at timestamptz not null,
      unique(owner_id, provider)
    )
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    create table if not exists agent_priority_reviews (
      id text primary key,
      owner_id text not null,
      profile_id text not null references agent_profiles(id) on delete cascade,
      scan_id text not null,
      status text not null,
      record jsonb not null,
      created_at timestamptz not null,
      updated_at timestamptz not null
    )
  `.pipe(Effect.mapError(storeError));

  const decodeProfile = (value: string) =>
    Schema.decodeEffect(Schema.fromJsonString(AgentProfile))(value).pipe(
      Effect.mapError(storeError),
    );
  const decodeReview = (value: string) =>
    Schema.decodeEffect(Schema.fromJsonString(AgentPriorityReview))(value).pipe(
      Effect.mapError(storeError),
    );
  const getProfile = Effect.fn('AgentStore.getProfile')(function* (
    ownerId: string,
    profileId: string,
  ) {
    const rows = yield* sql<{ readonly profile_json: string }>`
      select profile::text profile_json
      from agent_profiles
      where owner_id = ${ownerId} and id = ${profileId}
      limit 1
    `.pipe(Effect.mapError(storeError));
    return rows[0]
      ? Option.some(yield* decodeProfile(rows[0].profile_json))
      : Option.none<AgentProfile>();
  });

  const failReviewIfActive = Effect.fn('AgentStore.failReviewIfActive')(
    function* (
      ownerId: string,
      reviewId: string,
      diagnostic: string,
      failedAt: string,
    ) {
      yield* sql`
        update agent_priority_reviews
        set status = 'failed',
            record = jsonb_set(
              jsonb_set(
                jsonb_set(record, '{status}', '"failed"'::jsonb),
                '{diagnostic}', to_jsonb(${diagnostic}::text)
              ),
              '{updatedAt}', to_jsonb(${failedAt}::text)
            ),
            updated_at = ${failedAt}
        where owner_id = ${ownerId}
          and id = ${reviewId}
          and status in ('queued', 'running')
      `.pipe(Effect.mapError(storeError));
    },
  );

  return AgentStore.of({
    ready: sql`select 1`.pipe(Effect.asVoid, Effect.mapError(storeError)),
    getOrCreateSession: Effect.fn('AgentStore.getOrCreateSession')(function* (candidate) {
      const accepted = sessionCandidate(candidate);
      if (Option.isSome(accepted)) {
        const rows = yield* sql<{ readonly id: string }>`
          update radar_sessions set last_seen_at = now()
          where id = ${accepted.value}
          returning id
        `.pipe(Effect.mapError(storeError));
        if (rows[0]) return rows[0].id;
      }
      const id = yield* crypto.randomUUIDv7.pipe(Effect.mapError(storeError));
      yield* sql`
        insert into radar_sessions (id, created_at, last_seen_at)
        values (${id}, now(), now())
      `.pipe(Effect.mapError(storeError));
      return id;
    }),
    createProfile: Effect.fn('AgentStore.createProfile')(function* (ownerId, provider) {
      const profile = yield* makeAgentProfile(crypto, provider).pipe(Effect.mapError(storeError));
      yield* sql`
        insert into agent_profiles (
          id, owner_id, provider, profile, generation, created_at, updated_at
        ) values (
          ${profile.id}, ${ownerId}, ${profile.provider}, ${sql.json(profile)}, 0,
          ${profile.createdAt}, ${profile.updatedAt}
        )
      `.pipe(Effect.mapError(storeError));
      return profile;
    }),
    listProfiles: Effect.fn('AgentStore.listProfiles')(function* (ownerId) {
      const rows = yield* sql<{ readonly profile_json: string }>`
        select profile::text profile_json
        from agent_profiles
        where owner_id = ${ownerId}
        order by created_at
      `.pipe(Effect.mapError(storeError));
      return yield* Effect.forEach(rows, row => decodeProfile(row.profile_json));
    }),
    getProfile,
    updateProfile: Effect.fn('AgentStore.updateProfile')(function* (ownerId, profileId, update) {
      const current = yield* getProfile(ownerId, profileId);
      if (Option.isNone(current)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      const updatedAt = yield* nowIso;
      const profile = new AgentProfile({
        ...current.value,
        state: update.state,
        ...(update.accountLabel === undefined ? {} : { accountLabel: update.accountLabel }),
        ...(update.diagnostic === undefined ? {} : { diagnostic: update.diagnostic }),
        updatedAt,
      });
      yield* sql`
        update agent_profiles
        set profile = ${sql.json(profile)}, updated_at = ${updatedAt}
        where owner_id = ${ownerId} and id = ${profileId}
      `.pipe(Effect.mapError(storeError));
      return profile;
    }),
    readHome: Effect.fn('AgentStore.readHome')(function* (ownerId, profileId) {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const rows = yield* sql<{
          readonly encrypted_home_json: string | null;
          readonly generation: number;
        }>`
          select encrypted_home::text encrypted_home_json, generation
          from agent_profiles
          where owner_id = ${ownerId} and id = ${profileId}
          limit 1
        `.pipe(Effect.mapError(storeError));
        const row = rows[0];
        if (!row) {
          return yield* new AgentStoreError({
            message: 'Provider profile was not found.',
          });
        }
        if (row.encrypted_home_json === null) {
          return {
            generation: row.generation,
            state: Option.none<AgentCredentialState>(),
          };
        }
        const stored = yield* decodeStoredAgentHome(row.encrypted_home_json);
        if (
          stored.schemaVersion ===
          'codebase-radar.encrypted-agent-home/v1'
        ) {
          const updatedAt = yield* nowIso;
          const invalidated = yield* sql<{ readonly generation: number }>`
            update agent_profiles
            set encrypted_home = null,
                profile = jsonb_set(
                  jsonb_set(
                    jsonb_set(
                      profile - 'accountLabel',
                      '{state}',
                      '"disconnected"'::jsonb
                    ),
                    '{diagnostic}',
                    to_jsonb(${legacyHomeDiagnostic}::text)
                  ),
                  '{updatedAt}',
                  to_jsonb(${updatedAt}::text)
                ),
                updated_at = ${updatedAt}
            where owner_id = ${ownerId}
              and id = ${profileId}
              and generation = ${row.generation}
              and encrypted_home = ${row.encrypted_home_json}::jsonb
            returning generation
          `.pipe(Effect.mapError(storeError));
          if (invalidated[0]) {
            return {
              generation: invalidated[0].generation,
              state: Option.none<AgentCredentialState>(),
            };
          }
          continue;
        }
        return {
          generation: row.generation,
          state: Option.some(
            yield* decryptHome(kek, ownerId, profileId, stored),
          ),
        };
      }
      return yield* new AgentStoreError({
        message: 'Provider state changed during this operation.',
      });
    }),
    writeHome: Effect.fn('AgentStore.writeHome')(function* (ownerId, profileId, expectedGeneration, state) {
      const generation = expectedGeneration + 1;
      const encrypted = yield* encryptHome(
        crypto,
        kek,
        ownerId,
        profileId,
        generation,
        state,
      );
      const rows = yield* sql<{ readonly generation: number }>`
        update agent_profiles
        set encrypted_home = ${sql.json(encrypted)},
            generation = ${generation},
            updated_at = now()
        where owner_id = ${ownerId}
          and id = ${profileId}
          and generation = ${expectedGeneration}
        returning generation
      `.pipe(Effect.mapError(storeError));
      if (!rows[0]) return yield* new AgentStoreError({ message: 'Provider state changed during this operation.' });
      return rows[0].generation;
    }),
    createReview: Effect.fn('AgentStore.createReview')(function* (ownerId, profileId, scanId) {
      const profile = yield* getProfile(ownerId, profileId);
      if (Option.isNone(profile)) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      const review = yield* makeReview(crypto, profileId, profile.value.provider, scanId).pipe(
        Effect.mapError(storeError),
      );
      yield* sql`
        insert into agent_priority_reviews (
          id, owner_id, profile_id, scan_id, status, record, created_at, updated_at
        ) values (
          ${review.id}, ${ownerId}, ${profileId}, ${scanId}, ${review.status},
          ${sql.json(review)}, ${review.createdAt}, ${review.updatedAt}
        )
      `.pipe(Effect.mapError(storeError));
      return review;
    }),
    updateReview: Effect.fn('AgentStore.updateReview')(function* (ownerId, review) {
      const rows = yield* sql<{ readonly id: string }>`
        update agent_priority_reviews
        set status = ${review.status}, record = ${sql.json(review)}, updated_at = ${review.updatedAt}
        where owner_id = ${ownerId} and id = ${review.id}
        returning id
      `.pipe(Effect.mapError(storeError));
      if (!rows[0]) return yield* new AgentStoreError({ message: 'Priority review was not found.' });
      return review;
    }),
    getReview: Effect.fn('AgentStore.getReview')(function* (ownerId, reviewId) {
      const rows = yield* sql<{ readonly record_json: string }>`
        select record::text record_json
        from agent_priority_reviews
        where owner_id = ${ownerId} and id = ${reviewId}
        limit 1
      `.pipe(Effect.mapError(storeError));
      return rows[0]
        ? Option.some(yield* decodeReview(rows[0].record_json))
        : Option.none<AgentPriorityReview>();
    }),
    failReviewIfActive,
    failStaleReviews: Effect.fn('AgentStore.failStaleReviews')(function* (cutoff, failedAt) {
      const diagnostic =
        'The priority review was interrupted by a service restart. Retry it.';
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
      }>`
        select id, owner_id
        from agent_priority_reviews
        where status in ('queued', 'running')
          and updated_at < ${cutoff}
      `.pipe(Effect.mapError(storeError));
      yield* Effect.forEach(
        rows,
        row => failReviewIfActive(row.owner_id, row.id, diagnostic, failedAt),
        { concurrency: 3, discard: true },
      );
    }),
    deleteProfile: Effect.fn('AgentStore.deleteProfile')(function* (ownerId, profileId) {
      const rows = yield* sql<{ readonly id: string }>`
        delete from agent_profiles
        where owner_id = ${ownerId} and id = ${profileId}
        returning id
      `.pipe(Effect.mapError(storeError));
      if (!rows[0]) return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
    }),
  });
});

export const MemoryAgentStoreLive = Layer.effect(AgentStore, makeMemoryAgentStore);

export const AgentStoreLive = Layer.unwrap(
  Config.option(Config.redacted('DATABASE_URL')).pipe(
    Effect.map(databaseUrl =>
      Option.match(databaseUrl, {
        onNone: () => MemoryAgentStoreLive,
        onSome: value =>
          Layer.effect(AgentStore, makePostgresAgentStore).pipe(
            Layer.provide(
              PgClient.layer({
                url: value,
                maxConnections: 3,
                connectTimeout: '10 seconds',
                idleTimeout: '20 seconds',
                applicationName: 'codebase-radar-agents',
              }),
            ),
            Layer.orDie,
          ),
      }),
    ),
  ),
);
