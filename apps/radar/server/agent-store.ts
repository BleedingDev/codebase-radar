import { createCipheriv, createDecipheriv, createHash } from 'node:crypto';
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
  AgentPriorityOutput,
  AgentPriorityReview,
  AgentProfile,
  AgentProvider,
  SourceIdentity,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  canonicalFindingInventoryDigest,
  canonicalOverlayFindingInventoryDigest,
  canonicalResultDigest,
  CompleteAgentPriorityOverlay,
  encodedAgentPriorityAggregateBytes,
  encodedAgentPriorityPresentationBytes,
  isExactCanonicalSource,
  legacyPriorityOutput,
  maxAgentPriorityAggregateBytes,
} from './agent-priority-overlay';

const NonNegativeInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
);
const BoundedIdentifier = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(300),
);
const BoundedDigest = Schema.String.check(
  Schema.isMinLength(64),
  Schema.isMaxLength(64),
  Schema.isPattern(/^[a-f0-9]{64}$/u),
);
const BoundedPolicyVersion = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(120),
  Schema.isPattern(/^[a-z0-9][a-z0-9./:-]*$/u),
);
const IsoTimestamp = Schema.String.check(
  Schema.isMinLength(24),
  Schema.isMaxLength(24),
  Schema.isPattern(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u),
);
const BoundedDatabaseJson = Schema.String.check(
  Schema.isMaxLength(8 * 1_024 * 1_024),
);
export const maxAgentCredentialFileBytes = 2 * 1_024 * 1_024;
export const maxAgentCredentialTotalBytes = 3 * 1_024 * 1_024;
export const maxAgentCredentialEncodedFileCharacters =
  Math.ceil(maxAgentCredentialFileBytes / 3) * 4;
export const maxAgentCredentialCiphertextCharacters = 5_600_000;
// GCM stores its authentication tag in the separate `tag` field, so this is
// the exact maximum plaintext represented by the Base64 ciphertext field.
export const maxAgentCredentialStateSerializedBytes = Math.floor(
  maxAgentCredentialCiphertextCharacters / 4,
) * 3;
export class AgentStoreError extends Schema.TaggedErrorClass<AgentStoreError>()(
  'AgentStoreError',
  { message: Schema.String },
) {}

export class AgentCredentialFile extends Schema.Class<AgentCredentialFile>(
  'AgentCredentialFile',
)({
  path: Schema.Literals(['auth.json', '.credentials.json', '.claude.json']),
  content: Schema.String.check(
    Schema.isMaxLength(maxAgentCredentialEncodedFileCharacters),
  ),
}) {}

export class AgentCredentialState extends Schema.Class<AgentCredentialState>(
  'AgentCredentialState',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-home/v1'),
  provider: AgentProvider,
  files: Schema.Array(AgentCredentialFile).check(Schema.isMaxLength(3)),
}) {}

export class ScanAccessGrant extends Schema.Class<ScanAccessGrant>(
  'ScanAccessGrant',
)({
  reviewOwnerId: BoundedIdentifier,
  scanId: BoundedIdentifier,
  canonicalResultDigest: BoundedDigest,
  source: SourceIdentity,
  findingInventoryDigest: BoundedDigest,
  visibilityPolicyVersion: BoundedPolicyVersion,
  visibilityAttestation: BoundedDigest,
}) {}

export class ScanAccessVisibilityAttestation extends Schema.Class<ScanAccessVisibilityAttestation>(
  'ScanAccessVisibilityAttestation',
)({
  policyVersion: BoundedPolicyVersion,
  attestation: BoundedDigest,
}) {}

export class AgentReviewLease extends Schema.Class<AgentReviewLease>(
  'AgentReviewLease',
)({
  token: BoundedIdentifier,
  deadlineAt: IsoTimestamp,
  expiresAt: IsoTimestamp,
}) {}

export class QueuedAgentReview extends Schema.Class<QueuedAgentReview>(
  'QueuedAgentReview',
)({
  ownerId: BoundedIdentifier,
  review: AgentPriorityReview,
  grant: ScanAccessGrant,
}) {}

export const maxQueuedReviewRecovery = 32;

export const publicGitHubVisibilityPolicyVersion =
  'codebase-radar.public-github-visibility/v1';

const visibilityAttestationDigest = (
  policyVersion: string,
  source: typeof SourceIdentity.Type,
  resultDigest: string,
  inventoryDigest: string,
) =>
  createHash('sha256').update(JSON.stringify({
    policyVersion,
    source,
    resultDigest,
    inventoryDigest,
  })).digest('hex');

export const makeScanAccessVisibilityAttestation = (
  policyVersion: string,
  source: typeof SourceIdentity.Type,
  resultDigest: string,
  findingInventoryDigest: string,
) =>
  new ScanAccessVisibilityAttestation({
    policyVersion,
    attestation: visibilityAttestationDigest(
      policyVersion,
      source,
      resultDigest,
      findingInventoryDigest,
    ),
  });

export const grantVisibleScanAccess = (
  reviewOwnerId: string,
  result: SuccessfulScanResult,
  visibility?: ScanAccessVisibilityAttestation,
) => {
  const resultDigest = canonicalResultDigest(result);
  const findingInventoryDigest = canonicalFindingInventoryDigest(result);
  const attestation = visibility ?? makeScanAccessVisibilityAttestation(
    publicGitHubVisibilityPolicyVersion,
    result.source,
    resultDigest,
    findingInventoryDigest,
  );
  return new ScanAccessGrant({
    reviewOwnerId,
    scanId: result.scanId,
    canonicalResultDigest: resultDigest,
    source: result.source,
    findingInventoryDigest,
    visibilityPolicyVersion: attestation.policyVersion,
    visibilityAttestation: attestation.attestation,
  });
};

class EncryptedAgentHome extends Schema.Class<EncryptedAgentHome>(
  'EncryptedAgentHome',
)({
  schemaVersion: Schema.Literal('codebase-radar.encrypted-agent-home/v2'),
  keyVersion: Schema.Literal('v1'),
  generation: NonNegativeInteger,
  ciphertext: Schema.String.check(
    Schema.isMaxLength(maxAgentCredentialCiphertextCharacters),
  ),
  nonce: Schema.String.check(Schema.isMaxLength(100)),
  tag: Schema.String.check(Schema.isMaxLength(100)),
  wrappedKey: Schema.String.check(Schema.isMaxLength(200)),
  wrapNonce: Schema.String.check(Schema.isMaxLength(100)),
  wrapTag: Schema.String.check(Schema.isMaxLength(100)),
}) {}

class LegacyEncryptedAgentHome extends Schema.Class<LegacyEncryptedAgentHome>(
  'LegacyEncryptedAgentHome',
)({
  schemaVersion: Schema.Literal('codebase-radar.encrypted-agent-home/v1'),
  generation: NonNegativeInteger,
  ciphertext: Schema.String.check(
    Schema.isMaxLength(maxAgentCredentialCiphertextCharacters),
  ),
  nonce: Schema.String.check(Schema.isMaxLength(100)),
  tag: Schema.String.check(Schema.isMaxLength(100)),
  wrappedKey: Schema.String.check(Schema.isMaxLength(200)),
  wrapNonce: Schema.String.check(Schema.isMaxLength(100)),
  wrapTag: Schema.String.check(Schema.isMaxLength(100)),
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

interface MemoryReview {
  readonly ownerId: string;
  readonly review: AgentPriorityReview;
  readonly grant: ScanAccessGrant;
  readonly lease?: AgentReviewLease;
}

interface MemoryAgentState {
  readonly sessions: ReadonlySet<string>;
  readonly profiles: ReadonlyMap<string, MemoryProfile>;
  readonly reviews: ReadonlyMap<string, MemoryReview>;
  readonly overlays: ReadonlyMap<
    string,
    { readonly ownerId: string; readonly overlay: CompleteAgentPriorityOverlay }
  >;
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
  ) => Effect.Effect<{
    readonly generation: number;
    readonly state: Option.Option<AgentCredentialState>;
  }, AgentStoreError>;
  readonly writeHome: (
    ownerId: string,
    profileId: string,
    expectedGeneration: number,
    state: AgentCredentialState,
  ) => Effect.Effect<number, AgentStoreError>;
  readonly createReview: (
    ownerId: string,
    profileId: string,
    grant: ScanAccessGrant,
  ) => Effect.Effect<AgentPriorityReview, AgentStoreError>;
  readonly listQueuedReviews: () => Effect.Effect<
    ReadonlyArray<QueuedAgentReview>,
    AgentStoreError
  >;
  readonly getReviewAccessGrant: (
    ownerId: string,
    reviewId: string,
  ) => Effect.Effect<Option.Option<ScanAccessGrant>, AgentStoreError>;
  readonly claimReview: (
    ownerId: string,
    reviewId: string,
    deadlineAt: string,
    expiresAt: string,
  ) => Effect.Effect<AgentReviewLease, AgentStoreError>;
  readonly renewReviewLease: (
    ownerId: string,
    reviewId: string,
    lease: AgentReviewLease,
    currentTime: string,
    expiresAt: string,
  ) => Effect.Effect<AgentReviewLease, AgentStoreError>;
  readonly completeReviewWithOverlay: (
    ownerId: string,
    reviewId: string,
    lease: AgentReviewLease,
    overlay: CompleteAgentPriorityOverlay,
    output: AgentPriorityOutput,
    completedAt: string,
  ) => Effect.Effect<AgentPriorityReview, AgentStoreError>;
  readonly getReview: (
    ownerId: string,
    reviewId: string,
  ) => Effect.Effect<Option.Option<AgentPriorityReview>, AgentStoreError>;
  readonly getPriorityOverlay: (
    ownerId: string,
    reviewId: string,
  ) => Effect.Effect<Option.Option<CompleteAgentPriorityOverlay>, AgentStoreError>;
  readonly failReviewIfActive: (
    ownerId: string,
    reviewId: string,
    failedAt: string,
  ) => Effect.Effect<void, AgentStoreError>;
  readonly failExpiredReviews: (
    now: string,
    failedAt: string,
  ) => Effect.Effect<void, AgentStoreError>;
  readonly cancelReview: (
    ownerId: string,
    reviewId: string,
    cancelledAt: string,
  ) => Effect.Effect<void, AgentStoreError>;
  readonly deleteProfile: (
    ownerId: string,
    profileId: string,
  ) => Effect.Effect<void, AgentStoreError>;
}>()('AgentStore') {}

const storeError = <Failure>(_failure: Failure) =>
  new AgentStoreError({ message: 'Agent storage operation failed.' });

const decodeIsoTimestamp = (value: string) =>
  Schema.decodeEffect(IsoTimestamp, { onExcessProperty: 'error' })(value).pipe(
    Effect.mapError(storeError),
  );

const decodeReviewLease = (value: AgentReviewLease) =>
  Schema.decodeEffect(AgentReviewLease, { onExcessProperty: 'error' })(value).pipe(
    Effect.mapError(storeError),
  );

const makeReviewLease = (
  token: string,
  deadlineAt: string,
  expiresAt: string,
) =>
  Schema.decodeEffect(AgentReviewLease, { onExcessProperty: 'error' })({
    token,
    deadlineAt,
    expiresAt,
  }).pipe(Effect.mapError(storeError));

const ReviewStatus = Schema.Literals(['queued', 'running', 'completed', 'failed']);
const StoredReviewRow = Schema.Struct({ record_json: BoundedDatabaseJson });
const StoredGrantRow = Schema.Struct({ grant_json: BoundedDatabaseJson });
const StoredOverlayRow = Schema.Struct({ overlay_json: BoundedDatabaseJson });
const StoredAgentProfileRow = Schema.Struct({
  id: BoundedIdentifier,
  owner_id: BoundedIdentifier,
  provider: AgentProvider,
  profile_json: BoundedDatabaseJson,
  created_at: IsoTimestamp,
  updated_at: IsoTimestamp,
});
const StoredAgentReviewDatabaseRow = Schema.Struct({
  id: BoundedIdentifier,
  owner_id: BoundedIdentifier,
  profile_id: BoundedIdentifier,
  scan_id: BoundedIdentifier,
  status: ReviewStatus,
  record_json: BoundedDatabaseJson,
  grant_json: Schema.NullOr(BoundedDatabaseJson),
  lease_token: Schema.NullOr(BoundedIdentifier),
  lease_expires_at: Schema.NullOr(IsoTimestamp),
  deadline_at: Schema.NullOr(IsoTimestamp),
  created_at: IsoTimestamp,
  updated_at: IsoTimestamp,
});
const StoredPriorityOverlayDatabaseRow = Schema.Struct({
  review_id: BoundedIdentifier,
  owner_id: BoundedIdentifier,
  scan_id: BoundedIdentifier,
  overlay_json: BoundedDatabaseJson,
  created_at: IsoTimestamp,
  updated_at: IsoTimestamp,
});

export interface DecodedStoredAgentProfileRow {
  readonly ownerId: string;
  readonly profile: AgentProfile;
}

export interface DecodedStoredAgentReviewRow {
  readonly ownerId: string;
  readonly review: AgentPriorityReview;
  readonly grant: Option.Option<ScanAccessGrant>;
  readonly lease: Option.Option<AgentReviewLease>;
}

export interface DecodedStoredPriorityOverlayRow {
  readonly reviewId: string;
  readonly ownerId: string;
  readonly overlay: CompleteAgentPriorityOverlay;
}

const coherentReviewResult = (review: AgentPriorityReview) => {
  if (review.status === 'completed') {
    return review.output !== undefined &&
      hasUniquePriorityOutputFindingIds(review.output) &&
      review.diagnostic === undefined;
  }
  if (review.status === 'failed') {
    return review.output === undefined && review.diagnostic !== undefined;
  }
  return review.output === undefined && review.diagnostic === undefined;
};

const hasUniquePriorityOutputFindingIds = (output: AgentPriorityOutput) => {
  const findingIds = [
    ...output.orderedItems.map(item => item.findingId),
    ...output.notNowFindingIds,
  ];
  return new Set(findingIds).size === findingIds.length;
};

const hasUniqueOverlayFindingIds = (overlay: CompleteAgentPriorityOverlay) =>
  new Set(overlay.orderedItems.map(item => item.findingId)).size ===
  overlay.orderedItems.length;

const storedRowError = () =>
  new AgentStoreError({ message: 'Stored agent data was rejected.' });

export const decodeStoredAgentReviewRow = (row: { readonly record_json: string }) =>
  Schema.decodeEffect(StoredReviewRow, { onExcessProperty: 'error' })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(value =>
      Schema.decodeEffect(Schema.fromJsonString(AgentPriorityReview), {
        onExcessProperty: 'error',
      })(value.record_json).pipe(
        Effect.mapError(storeError),
        Effect.flatMap(review =>
          coherentReviewResult(review) &&
          (review.output === undefined ||
            encodedAgentPriorityPresentationBytes(review.output) <= maxAgentPriorityAggregateBytes)
            ? Effect.succeed(review)
            : Effect.fail(storedRowError())),
      )),
  );

export const decodeStoredScanAccessGrantRow = (row: { readonly grant_json: string }) =>
  Schema.decodeEffect(StoredGrantRow, { onExcessProperty: 'error' })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(value =>
      Schema.decodeEffect(Schema.fromJsonString(ScanAccessGrant), {
        onExcessProperty: 'error',
      })(value.grant_json).pipe(Effect.mapError(storeError))),
  );

export const decodeStoredPriorityOverlayRow = (row: { readonly overlay_json: string }) =>
  Schema.decodeEffect(StoredOverlayRow, { onExcessProperty: 'error' })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(value =>
      Schema.decodeEffect(Schema.fromJsonString(CompleteAgentPriorityOverlay), {
        onExcessProperty: 'error',
      })(value.overlay_json).pipe(
        Effect.mapError(storeError),
        Effect.flatMap(overlay =>
          hasUniqueOverlayFindingIds(overlay) &&
          encodedAgentPriorityAggregateBytes(overlay) <= maxAgentPriorityAggregateBytes
            ? Effect.succeed(overlay)
            : Effect.fail(storedRowError())),
      )),
  );

export const decodeStoredAgentProfileDatabaseRow = (row: {
  readonly id: string;
  readonly owner_id: string;
  readonly provider: typeof AgentProvider.Type;
  readonly profile_json: string;
  readonly created_at: string;
  readonly updated_at: string;
}) =>
  Schema.decodeEffect(StoredAgentProfileRow, { onExcessProperty: 'error' })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(stored =>
      Schema.decodeEffect(Schema.fromJsonString(AgentProfile), {
        onExcessProperty: 'error',
      })(stored.profile_json).pipe(
        Effect.mapError(storeError),
        Effect.flatMap(profile =>
          profile.id === stored.id &&
          profile.provider === stored.provider &&
          profile.createdAt === stored.created_at &&
          profile.updatedAt === stored.updated_at
            ? Effect.succeed({ ownerId: stored.owner_id, profile })
            : Effect.fail(storedRowError())),
      )),
  );

export const decodeStoredAgentReviewDatabaseRow = (row: {
  readonly id: string;
  readonly owner_id: string;
  readonly profile_id: string;
  readonly scan_id: string;
  readonly status: typeof ReviewStatus.Type;
  readonly record_json: string;
  readonly grant_json: string | null;
  readonly lease_token: string | null;
  readonly lease_expires_at: string | null;
  readonly deadline_at: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}) =>
  Schema.decodeEffect(StoredAgentReviewDatabaseRow, {
    onExcessProperty: 'error',
  })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(stored =>
      Effect.gen(function* () {
        const review = yield* decodeStoredAgentReviewRow({
          record_json: stored.record_json,
        });
        if (
          review.id !== stored.id ||
          review.profileId !== stored.profile_id ||
          review.scanId !== stored.scan_id ||
          review.status !== stored.status ||
          review.createdAt !== stored.created_at ||
          review.updatedAt !== stored.updated_at
        ) {
          return yield* storedRowError();
        }
        const grant = stored.grant_json === null
          ? Option.none<ScanAccessGrant>()
          : Option.some(yield* decodeStoredScanAccessGrantRow({
              grant_json: stored.grant_json,
            }));
        if (
          Option.isSome(grant) &&
          (
            grant.value.reviewOwnerId !== stored.owner_id ||
            grant.value.scanId !== review.scanId ||
            !hasBoundVisibilityAttestation(grant.value)
          )
        ) {
          return yield* storedRowError();
        }
        const token = stored.lease_token;
        const expiresAt = stored.lease_expires_at;
        const deadlineAt = stored.deadline_at;
        const hasLease = token !== null && expiresAt !== null && deadlineAt !== null;
        const hasNoLease = token === null && expiresAt === null && deadlineAt === null;
        if (!hasLease && !hasNoLease) {
          return yield* storedRowError();
        }
        if (
          (review.status === 'running') !== hasLease ||
          (review.status !== 'running' && !hasNoLease) ||
          (hasLease && expiresAt > deadlineAt)
        ) {
          return yield* storedRowError();
        }
        const lease = hasLease
          ? Option.some(new AgentReviewLease({ token, expiresAt, deadlineAt }))
          : Option.none<AgentReviewLease>();
        return {
          ownerId: stored.owner_id,
          review,
          grant,
          lease,
        };
      }),
    ),
  );

export const decodeStoredPriorityOverlayDatabaseRow = (row: {
  readonly review_id: string;
  readonly owner_id: string;
  readonly scan_id: string;
  readonly overlay_json: string;
  readonly created_at: string;
  readonly updated_at: string;
}) =>
  Schema.decodeEffect(StoredPriorityOverlayDatabaseRow, {
    onExcessProperty: 'error',
  })(row).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(stored =>
      decodeStoredPriorityOverlayRow({ overlay_json: stored.overlay_json }).pipe(
        Effect.flatMap(overlay =>
          overlay.scanId === stored.scan_id
            ? Effect.succeed({
                reviewId: stored.review_id,
                ownerId: stored.owner_id,
                overlay,
              })
            : Effect.fail(storedRowError())),
      )),
  );

const decodeCompletionInputs = (
  overlay: CompleteAgentPriorityOverlay,
  output: AgentPriorityOutput,
) =>
  Schema.decodeEffect(CompleteAgentPriorityOverlay, {
    onExcessProperty: 'error',
  })(overlay).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(acceptedOverlay =>
      encodedAgentPriorityAggregateBytes(acceptedOverlay) > maxAgentPriorityAggregateBytes
        ? Effect.fail(new AgentStoreError({
            message: 'Priority review completion was rejected.',
          }))
        : Schema.decodeEffect(AgentPriorityOutput, { onExcessProperty: 'error' })(output).pipe(
        Effect.mapError(storeError),
        Effect.flatMap(acceptedOutput =>
          encodedAgentPriorityPresentationBytes(acceptedOutput) > maxAgentPriorityAggregateBytes
            ? Effect.fail(new AgentStoreError({
                message: 'Priority review completion was rejected.',
              }))
            : legacyPriorityOutput(acceptedOverlay).pipe(
            Effect.mapError(storeError),
            Effect.flatMap(expectedOutput =>
              sameStoredValue(expectedOutput, acceptedOutput)
                ? Effect.succeed({ overlay: acceptedOverlay, output: acceptedOutput })
                : Effect.fail(
                    new AgentStoreError({
                      message: 'Priority review completion was rejected.',
                    }),
                ),
            ),
          ),
        ),
      ),
    ),
  );

const nowIso = DateTime.nowAsDate.pipe(Effect.map(date => date.toISOString()));

const sessionCandidate = (value?: string) =>
  value && /^[0-9a-f]{8}-[0-9a-f-]{27}$/iu.test(value)
    ? Option.some(value)
    : Option.none<string>();

const sameStoredValue = (left: object, right: object) =>
  JSON.stringify(left) === JSON.stringify(right);

const hasBoundVisibilityAttestation = (grant: ScanAccessGrant) =>
  grant.visibilityAttestation === makeScanAccessVisibilityAttestation(
    grant.visibilityPolicyVersion,
    grant.source,
    grant.canonicalResultDigest,
    grant.findingInventoryDigest,
  ).attestation;

const overlayMatchesGrant = (
  grant: ScanAccessGrant,
  overlay: CompleteAgentPriorityOverlay,
) =>
  hasBoundVisibilityAttestation(grant) &&
  overlay.scanId === grant.scanId &&
  overlay.canonicalResultDigest === grant.canonicalResultDigest &&
  isExactCanonicalSource(overlay.source, grant.source) &&
  overlay.findingInventoryDigest === grant.findingInventoryDigest &&
  hasUniqueOverlayFindingIds(overlay) &&
  encodedAgentPriorityAggregateBytes(overlay) <= maxAgentPriorityAggregateBytes &&
  canonicalOverlayFindingInventoryDigest(overlay.orderedItems) ===
    grant.findingInventoryDigest;

const failedReview = (
  review: AgentPriorityReview,
  diagnostic: string,
  updatedAt: string,
) =>
  new AgentPriorityReview({
    ...review,
    status: 'failed',
    diagnostic,
    updatedAt,
  });

const makeProfile = Effect.fn('makeAgentProfile')(function* (
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

const makeReview = Effect.fn('makeAgentPriorityReview')(function* (
  crypto: Crypto.Crypto,
  profileId: string,
  provider: typeof AgentProvider.Type,
  grant: ScanAccessGrant,
) {
  const [id, createdAt] = yield* Effect.all([crypto.randomUUIDv7, nowIso]);
  return new AgentPriorityReview({
    schemaVersion: 'codebase-radar.priority-review/v1',
    id,
    scanId: grant.scanId,
    profileId,
    provider,
    status: 'queued',
    createdAt,
    updatedAt: createdAt,
  });
});

const decodeGrant = (grant: ScanAccessGrant, ownerId: string) =>
  Schema.decodeEffect(ScanAccessGrant, { onExcessProperty: 'error' })(grant).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(decoded =>
      decoded.reviewOwnerId === ownerId &&
      hasBoundVisibilityAttestation(decoded)
        ? Effect.succeed(decoded)
        : Effect.fail(new AgentStoreError({ message: 'Scan access grant was rejected.' })),
    ),
  );

const makeMemoryAgentStore = Effect.gen(function* () {
  const crypto = yield* Crypto.Crypto;
  const state = yield* Ref.make<MemoryAgentState>({
    sessions: new Set(),
    profiles: new Map(),
    reviews: new Map(),
    overlays: new Map(),
  });

  const profileEntry = (ownerId: string, profileId: string) =>
    Ref.get(state).pipe(
      Effect.map(current =>
        Option.filter(
          Option.fromUndefinedOr(current.profiles.get(profileId)),
          entry => entry.ownerId === ownerId,
        ),
      ),
    );

  const reviewEntry = (ownerId: string, reviewId: string) =>
    Ref.get(state).pipe(
      Effect.map(current =>
        Option.filter(
          Option.fromUndefinedOr(current.reviews.get(reviewId)),
          entry => entry.ownerId === ownerId,
        ),
      ),
    );

  const failActive = (
    ownerId: string,
    reviewId: string,
    diagnostic: string,
    failedAt: string,
  ) =>
    Ref.update(state, current => {
      const entry = current.reviews.get(reviewId);
      if (
        entry === undefined ||
        entry.ownerId !== ownerId ||
        (entry.review.status !== 'queued' && entry.review.status !== 'running')
      ) {
        return current;
      }
      return {
        ...current,
        reviews: new Map(current.reviews).set(reviewId, {
          ownerId: entry.ownerId,
          grant: entry.grant,
          review: failedReview(entry.review, diagnostic, failedAt),
        }),
      };
    });

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
      const profile = yield* makeProfile(crypto, provider).pipe(Effect.mapError(storeError));
      const created = yield* Ref.modify(state, current => {
        const hasProvider = [...current.profiles.values()].some(entry =>
          entry.ownerId === ownerId && entry.profile.provider === provider);
        if (hasProvider) return [{ created: false }, current];
        return [
          { created: true },
          {
            ...current,
            profiles: new Map(current.profiles).set(profile.id, {
              ownerId,
              profile,
              generation: 0,
            }),
          },
        ];
      });
      if (!created.created) {
        return yield* new AgentStoreError({
          message: 'A profile for this provider already exists.',
        });
      }
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
      profileEntry(ownerId, profileId).pipe(Effect.map(Option.map(entry => entry.profile))),
    updateProfile: Effect.fn('AgentStore.updateProfile')(function* (ownerId, profileId, update) {
      const updatedAt = yield* nowIso;
      const updated = yield* Ref.modify(state, current => {
        const entry = current.profiles.get(profileId);
        if (entry === undefined || entry.ownerId !== ownerId) {
          return [Option.none<AgentProfile>(), current];
        }
        const profile = new AgentProfile({
          ...entry.profile,
          state: update.state,
          ...(update.accountLabel === undefined ? {} : { accountLabel: update.accountLabel }),
          ...(update.diagnostic === undefined ? {} : { diagnostic: update.diagnostic }),
          updatedAt,
        });
        return [
          Option.some(profile),
          {
            ...current,
            profiles: new Map(current.profiles).set(profileId, { ...entry, profile }),
          },
        ];
      });
      if (Option.isNone(updated)) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      return updated.value;
    }),
    readHome: Effect.fn('AgentStore.readHome')(function* (ownerId, profileId) {
      const entry = yield* profileEntry(ownerId, profileId);
      if (Option.isNone(entry)) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      return {
        generation: entry.value.generation,
        state: Option.fromUndefinedOr(entry.value.home),
      };
    }),
    writeHome: Effect.fn('AgentStore.writeHome')(function* (
      ownerId,
      profileId,
      expectedGeneration,
      home,
    ) {
      const acceptedHome = yield* validateCredentialState(home);
      const written = yield* Ref.modify(state, current => {
        const entry = current.profiles.get(profileId);
        if (
          entry === undefined ||
          entry.ownerId !== ownerId ||
          entry.generation !== expectedGeneration
        ) {
          return [Option.none<number>(), current];
        }
        const generation = expectedGeneration + 1;
        return [
          Option.some(generation),
          {
            ...current,
            profiles: new Map(current.profiles).set(profileId, {
              ...entry,
              generation,
              home: acceptedHome,
            }),
          },
        ];
      });
      if (Option.isNone(written)) {
        return yield* new AgentStoreError({
          message: 'Provider state changed during this operation.',
        });
      }
      return written.value;
    }),
    createReview: Effect.fn('AgentStore.createReview')(function* (ownerId, profileId, grant) {
      const acceptedGrant = yield* decodeGrant(grant, ownerId);
      const [id, createdAt] = yield* Effect.all([
        crypto.randomUUIDv7.pipe(Effect.mapError(storeError)),
        nowIso,
      ]);
      const created = yield* Ref.modify(state, current => {
        const profile = current.profiles.get(profileId);
        if (profile === undefined || profile.ownerId !== ownerId) {
          return [Option.none<AgentPriorityReview>(), current];
        }
        const review = new AgentPriorityReview({
          schemaVersion: 'codebase-radar.priority-review/v1',
          id,
          scanId: acceptedGrant.scanId,
          profileId,
          provider: profile.profile.provider,
          status: 'queued',
          createdAt,
          updatedAt: createdAt,
        });
        return [
          Option.some(review),
          {
            ...current,
            reviews: new Map(current.reviews).set(review.id, {
              ownerId,
              review,
              grant: acceptedGrant,
            }),
          },
        ];
      });
      if (Option.isNone(created)) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      return created.value;
    }),
    listQueuedReviews: Effect.fn('AgentStore.listQueuedReviews')(function* () {
      const current = yield* Ref.get(state);
      const candidates = [...current.reviews.values()]
        .filter(entry => entry.review.status === 'queued')
        .sort((left, right) =>
          left.review.createdAt.localeCompare(right.review.createdAt) ||
          left.review.id.localeCompare(right.review.id))
        .slice(0, maxQueuedReviewRecovery);
      const queued = new Array<QueuedAgentReview>();
      for (const entry of candidates) {
        const acceptedGrant = yield* decodeGrant(entry.grant, entry.ownerId).pipe(
          Effect.option,
        );
        if (Option.isNone(acceptedGrant)) continue;
        queued.push(new QueuedAgentReview({
          ownerId: entry.ownerId,
          review: entry.review,
          grant: acceptedGrant.value,
        }));
      }
      return queued;
    }),
    getReviewAccessGrant: (ownerId, reviewId) =>
      reviewEntry(ownerId, reviewId).pipe(Effect.map(Option.map(entry => entry.grant))),
    claimReview: Effect.fn('AgentStore.claimReview')(function* (
      ownerId,
      reviewId,
      deadlineAt,
      expiresAt,
    ) {
      const token = yield* crypto.randomUUIDv7.pipe(Effect.mapError(storeError));
      const lease = yield* makeReviewLease(token, deadlineAt, expiresAt);
      if (lease.expiresAt > lease.deadlineAt) {
        return yield* new AgentStoreError({ message: 'Priority review lease exceeds its deadline.' });
      }
      const claimed = yield* Ref.modify(state, current => {
        const entry = current.reviews.get(reviewId);
        if (
          entry === undefined ||
          entry.ownerId !== ownerId ||
          entry.review.status !== 'queued'
        ) {
          return [Option.none<AgentReviewLease>(), current];
        }
        const review = new AgentPriorityReview({
          ...entry.review,
          status: 'running',
          updatedAt: lease.expiresAt,
        });
        return [
          Option.some(lease),
          {
            ...current,
            reviews: new Map(current.reviews).set(reviewId, {
              ownerId: entry.ownerId,
              review,
              grant: entry.grant,
              lease,
            }),
          },
        ];
      });
      if (Option.isNone(claimed)) {
        return yield* new AgentStoreError({ message: 'Priority review is no longer queued.' });
      }
      return claimed.value;
    }),
    renewReviewLease: Effect.fn('AgentStore.renewReviewLease')(function* (
      ownerId,
      reviewId,
      lease,
      currentTime,
      expiresAt,
    ) {
      const acceptedLease = yield* decodeReviewLease(lease);
      const acceptedCurrentTime = yield* decodeIsoTimestamp(currentTime);
      const acceptedExpiry = yield* decodeIsoTimestamp(expiresAt);
      if (
        acceptedExpiry > acceptedLease.deadlineAt ||
        acceptedExpiry <= acceptedCurrentTime
      ) {
        return yield* new AgentStoreError({ message: 'Priority review lease renewal was rejected.' });
      }
      const renewed = yield* Ref.modify(state, current => {
        const entry = current.reviews.get(reviewId);
        if (
          entry === undefined ||
          entry.ownerId !== ownerId ||
          entry.review.status !== 'running' ||
          entry.lease === undefined ||
          entry.lease.token !== acceptedLease.token ||
          entry.lease.deadlineAt !== acceptedLease.deadlineAt ||
          entry.lease.expiresAt !== acceptedLease.expiresAt ||
          entry.lease.expiresAt <= acceptedCurrentTime ||
          entry.lease.deadlineAt <= acceptedCurrentTime
        ) {
          return [Option.none<AgentReviewLease>(), current];
        }
        if (acceptedExpiry <= entry.lease.expiresAt) {
          return [Option.some(entry.lease), current];
        }
        const effectiveExpiry = acceptedExpiry > entry.lease.expiresAt
          ? acceptedExpiry
          : entry.lease.expiresAt;
        const nextLease = new AgentReviewLease({
          token: acceptedLease.token,
          deadlineAt: acceptedLease.deadlineAt,
          expiresAt: effectiveExpiry,
        });
        const review = new AgentPriorityReview({
          ...entry.review,
          updatedAt: effectiveExpiry,
        });
        return [
          Option.some(nextLease),
          {
            ...current,
            reviews: new Map(current.reviews).set(reviewId, {
              ownerId: entry.ownerId,
              review,
              grant: entry.grant,
              lease: nextLease,
            }),
          },
        ];
      });
      if (Option.isNone(renewed)) {
        return yield* new AgentStoreError({ message: 'Priority review lease is no longer active.' });
      }
      return renewed.value;
    }),
    completeReviewWithOverlay: Effect.fn('AgentStore.completeReviewWithOverlay')(
      function* (ownerId, reviewId, lease, overlay, output, completedAt) {
        const acceptedLease = yield* decodeReviewLease(lease);
        const acceptedCompletedAt = yield* decodeIsoTimestamp(completedAt);
        const accepted = yield* decodeCompletionInputs(overlay, output);
        const completed = yield* Ref.modify(state, current => {
          const entry = current.reviews.get(reviewId);
          const storedOverlay = current.overlays.get(reviewId);
          if (entry === undefined || entry.ownerId !== ownerId) {
            return [Option.none<AgentPriorityReview>(), current];
          }
          if (entry.review.status === 'completed') {
            if (
              storedOverlay !== undefined &&
              storedOverlay.ownerId === ownerId &&
              overlayMatchesGrant(entry.grant, accepted.overlay) &&
              sameStoredValue(storedOverlay.overlay, accepted.overlay) &&
              entry.review.output !== undefined &&
              sameStoredValue(entry.review.output, accepted.output) &&
              entry.review.updatedAt === acceptedCompletedAt
            ) {
              return [Option.some(entry.review), current];
            }
            return [Option.none<AgentPriorityReview>(), current];
          }
          if (
            entry.review.status !== 'running' ||
            entry.lease === undefined ||
            entry.lease.token !== acceptedLease.token ||
            entry.lease.deadlineAt !== acceptedLease.deadlineAt ||
            entry.lease.expiresAt !== acceptedLease.expiresAt ||
            acceptedCompletedAt >= entry.lease.expiresAt ||
            acceptedCompletedAt >= acceptedLease.deadlineAt ||
            entry.review.scanId !== entry.grant.scanId ||
            !overlayMatchesGrant(entry.grant, accepted.overlay) ||
            entry.review.provider !== accepted.overlay.provider
          ) {
            return [Option.none<AgentPriorityReview>(), current];
          }
          const review = new AgentPriorityReview({
            ...entry.review,
            status: 'completed',
            output: accepted.output,
            updatedAt: acceptedCompletedAt,
          });
          return [
            Option.some(review),
            {
              ...current,
              reviews: new Map(current.reviews).set(reviewId, {
                ownerId: entry.ownerId,
                review,
                grant: entry.grant,
              }),
              overlays: new Map(current.overlays).set(reviewId, {
                ownerId,
                overlay: accepted.overlay,
              }),
            },
          ];
        });
        if (Option.isNone(completed)) {
          return yield* new AgentStoreError({
            message: 'Priority review completion was rejected.',
          });
        }
        return completed.value;
      },
    ),
    getReview: (ownerId, reviewId) =>
      reviewEntry(ownerId, reviewId).pipe(Effect.map(Option.map(entry => entry.review))),
    getPriorityOverlay: (ownerId, reviewId) =>
      Ref.get(state).pipe(
        Effect.map(current =>
          Option.map(
            Option.filter(
              Option.fromUndefinedOr(current.overlays.get(reviewId)),
              entry => entry.ownerId === ownerId,
            ),
            entry => entry.overlay,
          ),
        ),
      ),
    failReviewIfActive: (ownerId, reviewId, failedAt) =>
      failActive(
        ownerId,
        reviewId,
        'The priority review stopped before completion. Retry it.',
        failedAt,
      ),
    failExpiredReviews: (now, failedAt) =>
      Ref.update(state, current => {
        const reviews = new Map(current.reviews);
        for (const [reviewId, entry] of current.reviews) {
          if (entry.review.status !== 'running' || entry.lease === undefined) continue;
          if (entry.lease.expiresAt > now && entry.lease.deadlineAt > now) continue;
          reviews.set(reviewId, {
            ownerId: entry.ownerId,
            grant: entry.grant,
            review: failedReview(
              entry.review,
              'The priority review lease expired before completion. Retry it.',
              failedAt,
            ),
          });
        }
        return { ...current, reviews };
      }),
    cancelReview: (ownerId, reviewId, cancelledAt) =>
      failActive(
        ownerId,
        reviewId,
        'The priority review was cancelled.',
        cancelledAt,
      ),
    deleteProfile: Effect.fn('AgentStore.deleteProfile')(function* (ownerId, profileId) {
      const deleted = yield* Ref.modify(state, current => {
        const profile = current.profiles.get(profileId);
        if (profile === undefined || profile.ownerId !== ownerId) {
          return [false, current];
        }
        const removed = new Set(
          [...current.reviews]
            .filter(([, review]) =>
              review.ownerId === ownerId && review.review.profileId === profileId)
            .map(([reviewId]) => reviewId),
        );
        return [
          true,
          {
            ...current,
            profiles: new Map([...current.profiles].filter(([id]) => id !== profileId)),
            reviews: new Map([...current.reviews].filter(([id]) => !removed.has(id))),
            overlays: new Map([...current.overlays].filter(([id]) => !removed.has(id))),
          },
        ];
      });
      if (!deleted) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
    }),
  });
});

export const decodeStoredAgentHome = (value: string) =>
  Schema.decodeEffect(BoundedDatabaseJson, { onExcessProperty: 'error' })(value).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(serialized =>
      Schema.decodeEffect(Schema.fromJsonString(StoredAgentHome), {
        onExcessProperty: 'error',
      })(serialized).pipe(Effect.mapError(storeError))),
  );

const decodeBase64 = (value: string) =>
  Result.match(Encoding.decodeBase64(value), {
    onFailure: storeError,
    onSuccess: Effect.succeed,
  });

const credentialStateError = () =>
  new AgentStoreError({
    message: 'Provider state exceeded the safe storage limit.',
  });

const permittedCredentialFiles = (
  provider: typeof AgentProvider.Type,
): ReadonlySet<string> =>
  provider === 'codex'
    ? new Set(['auth.json'])
    : new Set(['.credentials.json', '.claude.json']);

/**
 * Store writes are an untrusted boundary too: callers can construct a typed
 * value without going through captureHome. Validate decoded byte totals and
 * the serialized encrypted payload budget before accepting it.
 */
const validateCredentialState = (state: AgentCredentialState) =>
  Schema.decodeEffect(AgentCredentialState, { onExcessProperty: 'error' })(state).pipe(
    Effect.mapError(storeError),
    Effect.flatMap(accepted =>
      Effect.gen(function* () {
        const permittedFiles = permittedCredentialFiles(accepted.provider);
        const paths = new Set<string>();
        let totalBytes = 0;
        for (const file of accepted.files) {
          if (!permittedFiles.has(file.path) || paths.has(file.path)) {
            return yield* credentialStateError();
          }
          paths.add(file.path);
          const bytes = yield* decodeBase64(file.content);
          if (bytes.byteLength > maxAgentCredentialFileBytes) {
            return yield* credentialStateError();
          }
          totalBytes += bytes.byteLength;
          if (!Number.isSafeInteger(totalBytes) || totalBytes > maxAgentCredentialTotalBytes) {
            return yield* credentialStateError();
          }
        }
        if (new TextEncoder().encode(JSON.stringify(accepted)).byteLength >
          maxAgentCredentialStateSerializedBytes) {
          return yield* credentialStateError();
        }
        return accepted;
      }),
    ),
  );

const encryptedHomeAad = (
  ownerId: string,
  profileId: string,
  generation: number,
  keyVersion: EncryptedAgentHome['keyVersion'],
) => new TextEncoder().encode(
  `codebase-radar:${ownerId}:${profileId}:${generation}:${keyVersion}`,
);

const encryptBytes = Effect.fn('encryptAgentHomeBytes')(function* (
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

const decryptBytes = Effect.fn('decryptAgentHomeBytes')(function* (
  key: Uint8Array,
  nonce: Uint8Array,
  value: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
) {
  return yield* Effect.try({
    try: () => {
      const cipher = createDecipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(aad);
      cipher.setAuthTag(tag);
      return Uint8Array.from([...cipher.update(value), ...cipher.final()]);
    },
    catch: storeError,
  });
});

const encryptHome = Effect.fn('encryptAgentHome')(function* (
  crypto: Crypto.Crypto,
  kek: Uint8Array,
  ownerId: string,
  profileId: string,
  generation: number,
  state: AgentCredentialState,
) {
  const acceptedState = yield* validateCredentialState(state);
  const serialized = new TextEncoder().encode(JSON.stringify(acceptedState));
  if (serialized.byteLength > maxAgentCredentialStateSerializedBytes) {
    return yield* credentialStateError();
  }
  const [dek, nonce, wrapNonce] = yield* Effect.all([
    crypto.randomBytes(32),
    crypto.randomBytes(12),
    crypto.randomBytes(12),
  ]).pipe(Effect.mapError(storeError));
  const aad = encryptedHomeAad(ownerId, profileId, generation, 'v1');
  const encrypted = yield* encryptBytes(
    dek,
    nonce,
    serialized,
    aad,
  );
  const wrapped = yield* encryptBytes(kek, wrapNonce, dek, aad);
  const home = new EncryptedAgentHome({
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
  if (home.ciphertext.length > maxAgentCredentialCiphertextCharacters) {
    return yield* credentialStateError();
  }
  return home;
});

const decryptHome = Effect.fn('decryptAgentHome')(function* (
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
  const state = yield* Schema.decodeEffect(Schema.fromJsonString(AgentCredentialState), {
    onExcessProperty: 'error',
  })(new TextDecoder().decode(plaintext)).pipe(Effect.mapError(storeError));
  return yield* validateCredentialState(state);
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
      scan_access_grant jsonb,
      status text not null,
      record jsonb not null,
      lease_token text,
      lease_expires_at timestamptz,
      deadline_at timestamptz,
      created_at timestamptz not null,
      updated_at timestamptz not null
    )
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    alter table agent_priority_reviews
    add column if not exists scan_access_grant jsonb
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    alter table agent_priority_reviews
    add column if not exists lease_token text
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    alter table agent_priority_reviews
    add column if not exists lease_expires_at timestamptz
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    alter table agent_priority_reviews
    add column if not exists deadline_at timestamptz
  `.pipe(Effect.mapError(storeError));
  // Older revisions cleared only the token and expiry on terminal rows. Repair
  // those rows before any strict normalized-column decoder reads them.
  yield* sql`
    update agent_priority_reviews
    set lease_token = null,
        lease_expires_at = null,
        deadline_at = null
    where status <> 'running'
      and (
        lease_token is not null
        or lease_expires_at is not null
        or deadline_at is not null
      )
  `.pipe(Effect.mapError(storeError));
  yield* sql`
    create table if not exists agent_priority_overlays (
      review_id text primary key references agent_priority_reviews(id) on delete cascade,
      owner_id text not null,
      scan_id text not null,
      overlay jsonb not null,
      created_at timestamptz not null,
      updated_at timestamptz not null
    )
  `.pipe(Effect.mapError(storeError));

  const IdRow = Schema.Struct({ id: BoundedIdentifier });
  const HomeRow = Schema.Struct({
    encrypted_home_json: Schema.NullOr(BoundedDatabaseJson),
    generation: NonNegativeInteger,
  });
  const GenerationRow = Schema.Struct({ generation: NonNegativeInteger });
  const LeaseRenewalRow = Schema.Struct({ expires_at: IsoTimestamp });

  const decodeIdRow = (row: { readonly id: string }) =>
    Schema.decodeEffect(IdRow, { onExcessProperty: 'error' })(row).pipe(
      Effect.mapError(storeError),
    );
  const decodeHomeRow = (row: {
    readonly encrypted_home_json: string | null;
    readonly generation: number;
  }) =>
    Schema.decodeEffect(HomeRow, { onExcessProperty: 'error' })(row).pipe(
      Effect.mapError(storeError),
    );
  const decodeGenerationRow = (row: { readonly generation: number }) =>
    Schema.decodeEffect(GenerationRow, { onExcessProperty: 'error' })(row).pipe(
      Effect.mapError(storeError),
    );
  const decodeLeaseRenewalRow = (row: { readonly expires_at: string }) =>
    Schema.decodeEffect(LeaseRenewalRow, { onExcessProperty: 'error' })(row).pipe(
      Effect.mapError(storeError),
    );
  const getProfile = Effect.fn('AgentStore.getProfile')(function* (
    ownerId: string,
    profileId: string,
  ) {
    const rows = yield* sql<{
      readonly id: string;
      readonly owner_id: string;
      readonly provider: typeof AgentProvider.Type;
      readonly profile_json: string;
      readonly created_at: string;
      readonly updated_at: string;
    }>`
      select id,
             owner_id,
             provider,
             profile::text profile_json,
             to_char(
               created_at at time zone 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
             ) created_at,
             to_char(
               updated_at at time zone 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
             ) updated_at
      from agent_profiles
      where owner_id = ${ownerId} and id = ${profileId}
      limit 1
    `.pipe(Effect.mapError(storeError));
    const row = rows[0];
    return row === undefined
      ? Option.none<AgentProfile>()
      : Option.some((yield* decodeStoredAgentProfileDatabaseRow(row)).profile);
  });

  const failActive = (
    ownerId: string,
    reviewId: string,
    diagnostic: string,
    failedAt: string,
  ) =>
    sql`
      update agent_priority_reviews
      set status = 'failed',
          lease_token = null,
          lease_expires_at = null,
          deadline_at = null,
          record = jsonb_set(
            jsonb_set(
              jsonb_set(record - 'output', '{status}', '"failed"'::jsonb),
              '{diagnostic}', to_jsonb(${diagnostic}::text)
            ),
            '{updatedAt}', to_jsonb(${failedAt}::text)
          ),
          updated_at = ${failedAt}
      where owner_id = ${ownerId}
        and id = ${reviewId}
        and status in ('queued', 'running')
    `.pipe(Effect.mapError(storeError), Effect.asVoid);

  return AgentStore.of({
    ready: sql`select 1`.pipe(Effect.asVoid, Effect.mapError(storeError)),
    getOrCreateSession: Effect.fn('AgentStore.getOrCreateSession')(function* (candidate) {
      const candidateId = sessionCandidate(candidate);
      if (Option.isSome(candidateId)) {
        const rows = yield* sql<{ readonly id: string }>`
          update radar_sessions set last_seen_at = now()
          where id = ${candidateId.value}
          returning id
        `.pipe(Effect.mapError(storeError));
        const row = rows[0];
        if (row !== undefined) return (yield* decodeIdRow(row)).id;
      }
      const id = yield* crypto.randomUUIDv7.pipe(Effect.mapError(storeError));
      yield* sql`
        insert into radar_sessions (id, created_at, last_seen_at)
        values (${id}, now(), now())
      `.pipe(Effect.mapError(storeError));
      return id;
    }),
    createProfile: Effect.fn('AgentStore.createProfile')(function* (ownerId, provider) {
      const profile = yield* makeProfile(crypto, provider).pipe(Effect.mapError(storeError));
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
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
        readonly provider: typeof AgentProvider.Type;
        readonly profile_json: string;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        select id,
               owner_id,
               provider,
               profile::text profile_json,
               to_char(
                 created_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) created_at,
               to_char(
                 updated_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) updated_at
        from agent_profiles
        where owner_id = ${ownerId}
        order by created_at
      `.pipe(Effect.mapError(storeError));
      return yield* Effect.forEach(
        rows,
        row => decodeStoredAgentProfileDatabaseRow(row).pipe(
          Effect.map(decoded => decoded.profile),
        ),
      );
    }),
    getProfile,
    updateProfile: Effect.fn('AgentStore.updateProfile')(function* (ownerId, profileId, update) {
      const current = yield* getProfile(ownerId, profileId);
      if (Option.isNone(current)) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      const updatedAt = yield* nowIso;
      const profile = new AgentProfile({
        ...current.value,
        state: update.state,
        ...(update.accountLabel === undefined ? {} : { accountLabel: update.accountLabel }),
        ...(update.diagnostic === undefined ? {} : { diagnostic: update.diagnostic }),
        updatedAt,
      });
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
        readonly provider: typeof AgentProvider.Type;
        readonly profile_json: string;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        update agent_profiles
        set profile = ${sql.json(profile)}, updated_at = ${updatedAt}
        where owner_id = ${ownerId}
          and id = ${profileId}
          and updated_at = ${current.value.updatedAt}
          and profile = ${sql.json(current.value)}
        returning id,
                  owner_id,
                  provider,
                  profile::text profile_json,
                  to_char(
                    created_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                  ) created_at,
                  to_char(
                    updated_at at time zone 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                  ) updated_at
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      if (row === undefined) {
        return yield* new AgentStoreError({
          message: 'Provider profile changed during this operation.',
        });
      }
      return (yield* decodeStoredAgentProfileDatabaseRow(row)).profile;
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
        const raw = rows[0];
        if (raw === undefined) {
          return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
        }
        const row = yield* decodeHomeRow(raw);
        if (row.encrypted_home_json === null) {
          return { generation: row.generation, state: Option.none<AgentCredentialState>() };
        }
        const stored = yield* decodeStoredAgentHome(row.encrypted_home_json);
        if (stored.schemaVersion === 'codebase-radar.encrypted-agent-home/v1') {
          return yield* new AgentStoreError({
            message: 'The saved provider sign-in is obsolete. Sign in again.',
          });
        }
        return {
          generation: row.generation,
          state: Option.some(yield* decryptHome(kek, ownerId, profileId, stored)),
        };
      }
      return yield* new AgentStoreError({
        message: 'Provider state changed during this operation.',
      });
    }),
    writeHome: Effect.fn('AgentStore.writeHome')(function* (ownerId, profileId, expectedGeneration, state) {
      const acceptedState = yield* validateCredentialState(state);
      const generation = expectedGeneration + 1;
      const encrypted = yield* encryptHome(
        crypto,
        kek,
        ownerId,
        profileId,
        generation,
        acceptedState,
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
      const row = rows[0];
      if (row === undefined) {
        return yield* new AgentStoreError({ message: 'Provider state changed during this operation.' });
      }
      return (yield* decodeGenerationRow(row)).generation;
    }),
    createReview: Effect.fn('AgentStore.createReview')(function* (ownerId, profileId, grant) {
      const acceptedGrant = yield* decodeGrant(grant, ownerId);
      const profile = yield* getProfile(ownerId, profileId);
      if (Option.isNone(profile)) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      const review = yield* makeReview(
        crypto,
        profileId,
        profile.value.provider,
        acceptedGrant,
      ).pipe(Effect.mapError(storeError));
      yield* sql`
        insert into agent_priority_reviews (
          id, owner_id, profile_id, scan_id, scan_access_grant, status, record,
          created_at, updated_at
        ) values (
          ${review.id}, ${ownerId}, ${profileId}, ${review.scanId},
          ${sql.json(acceptedGrant)}, ${review.status}, ${sql.json(review)},
          ${review.createdAt}, ${review.updatedAt}
        )
      `.pipe(Effect.mapError(storeError));
      return review;
    }),
    listQueuedReviews: Effect.fn('AgentStore.listQueuedReviews')(function* () {
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
        readonly profile_id: string;
        readonly scan_id: string;
        readonly status: typeof ReviewStatus.Type;
        readonly record_json: string;
        readonly grant_json: string | null;
        readonly lease_token: string | null;
        readonly lease_expires_at: string | null;
        readonly deadline_at: string | null;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        select id,
               owner_id,
               profile_id,
               scan_id,
               status,
               record::text record_json,
               scan_access_grant::text grant_json,
               lease_token,
               to_char(
                 lease_expires_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) lease_expires_at,
               to_char(
                 deadline_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) deadline_at,
               to_char(
                 created_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) created_at,
               to_char(
                 updated_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) updated_at
        from agent_priority_reviews
        where status = 'queued'
          and scan_access_grant is not null
        order by created_at, id
        limit ${maxQueuedReviewRecovery}
      `.pipe(Effect.mapError(storeError));
      const queued = new Array<QueuedAgentReview>();
      for (const row of rows) {
        const stored = yield* decodeStoredAgentReviewDatabaseRow(row);
        if (Option.isNone(stored.grant)) {
          return yield* storedRowError();
        }
        queued.push(new QueuedAgentReview({
          ownerId: stored.ownerId,
          review: stored.review,
          grant: stored.grant.value,
        }));
      }
      return queued;
    }),
    getReviewAccessGrant: Effect.fn('AgentStore.getReviewAccessGrant')(function* (
      ownerId,
      reviewId,
    ) {
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
        readonly profile_id: string;
        readonly scan_id: string;
        readonly status: typeof ReviewStatus.Type;
        readonly record_json: string;
        readonly grant_json: string | null;
        readonly lease_token: string | null;
        readonly lease_expires_at: string | null;
        readonly deadline_at: string | null;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        select id,
               owner_id,
               profile_id,
               scan_id,
               status,
               record::text record_json,
               scan_access_grant::text grant_json,
               lease_token,
               to_char(
                 lease_expires_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) lease_expires_at,
               to_char(
                 deadline_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) deadline_at,
               to_char(
                 created_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) created_at,
               to_char(
                 updated_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) updated_at
        from agent_priority_reviews
        where owner_id = ${ownerId}
          and id = ${reviewId}
          and scan_access_grant is not null
        limit 1
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      if (row === undefined) return Option.none<ScanAccessGrant>();
      return (yield* decodeStoredAgentReviewDatabaseRow(row)).grant;
    }),
    claimReview: Effect.fn('AgentStore.claimReview')(function* (
      ownerId,
      reviewId,
      deadlineAt,
      expiresAt,
    ) {
      const token = yield* crypto.randomUUIDv7.pipe(Effect.mapError(storeError));
      const lease = yield* makeReviewLease(token, deadlineAt, expiresAt);
      if (lease.expiresAt > lease.deadlineAt) {
        return yield* new AgentStoreError({ message: 'Priority review lease exceeds its deadline.' });
      }
      const rows = yield* sql<{ readonly id: string }>`
        update agent_priority_reviews
        set status = 'running',
            lease_token = ${lease.token},
            lease_expires_at = ${lease.expiresAt},
            deadline_at = ${lease.deadlineAt},
            record = jsonb_set(
              jsonb_set(record - 'diagnostic', '{status}', '"running"'::jsonb),
              '{updatedAt}', to_jsonb(${lease.expiresAt}::text)
            ),
            updated_at = ${lease.expiresAt}
        where owner_id = ${ownerId}
          and id = ${reviewId}
          and status = 'queued'
          and scan_access_grant is not null
        returning id
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      if (row === undefined) {
        return yield* new AgentStoreError({ message: 'Priority review is no longer queued.' });
      }
      yield* decodeIdRow(row);
      return lease;
    }),
    renewReviewLease: Effect.fn('AgentStore.renewReviewLease')(function* (
      ownerId,
      reviewId,
      lease,
      currentTime,
      expiresAt,
    ) {
      const acceptedLease = yield* decodeReviewLease(lease);
      const acceptedCurrentTime = yield* decodeIsoTimestamp(currentTime);
      const acceptedExpiry = yield* decodeIsoTimestamp(expiresAt);
      if (
        acceptedExpiry > acceptedLease.deadlineAt ||
        acceptedExpiry <= acceptedCurrentTime
      ) {
        return yield* new AgentStoreError({ message: 'Priority review lease renewal was rejected.' });
      }
      const rows = yield* sql<{ readonly expires_at: string }>`
        update agent_priority_reviews
        set lease_expires_at = case
              when lease_expires_at < ${acceptedExpiry} then ${acceptedExpiry}
              else lease_expires_at
            end,
            record = case
              when lease_expires_at < ${acceptedExpiry}
                then jsonb_set(record, '{updatedAt}', to_jsonb(${acceptedExpiry}::text))
              else record
            end,
            updated_at = case
              when lease_expires_at < ${acceptedExpiry} then ${acceptedExpiry}
              else updated_at
            end
        where owner_id = ${ownerId}
          and id = ${reviewId}
          and status = 'running'
          and lease_token = ${acceptedLease.token}
          and deadline_at = ${acceptedLease.deadlineAt}
          and lease_expires_at is not null
          and lease_expires_at > ${acceptedCurrentTime}
          and deadline_at > ${acceptedCurrentTime}
          and deadline_at >= ${acceptedExpiry}
        returning to_char(
          lease_expires_at at time zone 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
        ) expires_at
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      if (row === undefined) {
        return yield* new AgentStoreError({ message: 'Priority review lease is no longer active.' });
      }
      const renewed = yield* decodeLeaseRenewalRow(row);
      return new AgentReviewLease({
        token: acceptedLease.token,
        deadlineAt: acceptedLease.deadlineAt,
        expiresAt: renewed.expires_at,
      });
    }),
    completeReviewWithOverlay: Effect.fn('AgentStore.completeReviewWithOverlay')(
      function* (ownerId, reviewId, lease, overlay, output, completedAt) {
        const acceptedLease = yield* decodeReviewLease(lease);
        const acceptedCompletedAt = yield* decodeIsoTimestamp(completedAt);
        const accepted = yield* decodeCompletionInputs(overlay, output);
        return yield* sql.withTransaction(
          Effect.gen(function* () {
            const rows = yield* sql<{
              readonly id: string;
              readonly owner_id: string;
              readonly profile_id: string;
              readonly scan_id: string;
              readonly status: typeof ReviewStatus.Type;
              readonly record_json: string;
              readonly grant_json: string | null;
              readonly lease_token: string | null;
              readonly lease_expires_at: string | null;
              readonly deadline_at: string | null;
              readonly created_at: string;
              readonly updated_at: string;
            }>`
              select id,
                     owner_id,
                     profile_id,
                     scan_id,
                     status,
                     record::text record_json,
                     scan_access_grant::text grant_json,
                     lease_token,
                     to_char(
                       lease_expires_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                     ) lease_expires_at,
                     to_char(
                       deadline_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                     ) deadline_at,
                     to_char(
                       created_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                     ) created_at,
                     to_char(
                       updated_at at time zone 'UTC',
                       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                     ) updated_at
              from agent_priority_reviews
              where owner_id = ${ownerId}
                and id = ${reviewId}
                and scan_access_grant is not null
              for update
            `.pipe(Effect.mapError(storeError));
            const raw = rows[0];
            if (raw === undefined) {
              return yield* new AgentStoreError({ message: 'Priority review completion was rejected.' });
            }
            const stored = yield* decodeStoredAgentReviewDatabaseRow(raw);
            if (stored.ownerId !== ownerId || Option.isNone(stored.grant)) {
              return yield* new AgentStoreError({ message: 'Priority review completion was rejected.' });
            }
            const review = stored.review;
            const grant = stored.grant.value;
            if (review.status === 'completed') {
              const overlayRows = yield* sql<{
                readonly review_id: string;
                readonly owner_id: string;
                readonly scan_id: string;
                readonly overlay_json: string;
                readonly created_at: string;
                readonly updated_at: string;
              }>`
                select review_id,
                       owner_id,
                       scan_id,
                       overlay::text overlay_json,
                       to_char(
                         created_at at time zone 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                       ) created_at,
                       to_char(
                         updated_at at time zone 'UTC',
                         'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                       ) updated_at
                from agent_priority_overlays
                where review_id = ${reviewId} and owner_id = ${ownerId}
                for update
              `.pipe(Effect.mapError(storeError));
              const storedOverlay = overlayRows[0];
              if (
                storedOverlay !== undefined &&
                overlayMatchesGrant(grant, accepted.overlay) &&
                sameStoredValue(
                  (yield* decodeStoredPriorityOverlayDatabaseRow(storedOverlay)).overlay,
                  accepted.overlay,
                ) &&
                review.output !== undefined &&
                sameStoredValue(review.output, accepted.output) &&
                review.updatedAt === acceptedCompletedAt
              ) {
                return review;
              }
              return yield* new AgentStoreError({ message: 'Priority review completion was rejected.' });
            }
            if (
              review.status !== 'running' ||
              Option.isNone(stored.lease) ||
              stored.lease.value.token !== acceptedLease.token ||
              stored.lease.value.deadlineAt !== acceptedLease.deadlineAt ||
              stored.lease.value.expiresAt !== acceptedLease.expiresAt ||
              acceptedCompletedAt >= stored.lease.value.expiresAt ||
              acceptedCompletedAt >= acceptedLease.deadlineAt ||
              review.scanId !== grant.scanId ||
              !overlayMatchesGrant(grant, accepted.overlay) ||
              review.provider !== accepted.overlay.provider
            ) {
              return yield* new AgentStoreError({ message: 'Priority review completion was rejected.' });
            }
            const completed = new AgentPriorityReview({
              ...review,
              status: 'completed',
              output: accepted.output,
              updatedAt: acceptedCompletedAt,
            });
            const updated = yield* sql<{ readonly id: string }>`
              update agent_priority_reviews
              set status = 'completed',
                  record = ${sql.json(completed)},
                  lease_token = null,
                  lease_expires_at = null,
                  deadline_at = null,
                  updated_at = ${acceptedCompletedAt}
              where owner_id = ${ownerId}
                and id = ${reviewId}
                and status = 'running'
                and lease_token = ${acceptedLease.token}
                and lease_expires_at > ${acceptedCompletedAt}
                and deadline_at = ${acceptedLease.deadlineAt}
              returning id
            `.pipe(Effect.mapError(storeError));
            const updatedRow = updated[0];
            if (updatedRow === undefined) {
              return yield* new AgentStoreError({ message: 'Priority review completion was rejected.' });
            }
            yield* decodeIdRow(updatedRow);
            yield* sql`
              insert into agent_priority_overlays (
                review_id, owner_id, scan_id, overlay, created_at, updated_at
              ) values (
                ${reviewId}, ${ownerId}, ${accepted.overlay.scanId}, ${sql.json(accepted.overlay)},
                ${acceptedCompletedAt}, ${acceptedCompletedAt}
              )
            `.pipe(Effect.mapError(storeError));
            return completed;
          }),
        ).pipe(Effect.mapError(storeError));
      },
    ),
    getReview: Effect.fn('AgentStore.getReview')(function* (ownerId, reviewId) {
      const rows = yield* sql<{
        readonly id: string;
        readonly owner_id: string;
        readonly profile_id: string;
        readonly scan_id: string;
        readonly status: typeof ReviewStatus.Type;
        readonly record_json: string;
        readonly grant_json: string | null;
        readonly lease_token: string | null;
        readonly lease_expires_at: string | null;
        readonly deadline_at: string | null;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        select id,
               owner_id,
               profile_id,
               scan_id,
               status,
               record::text record_json,
               scan_access_grant::text grant_json,
               lease_token,
               to_char(
                 lease_expires_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) lease_expires_at,
               to_char(
                 deadline_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) deadline_at,
               to_char(
                 created_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) created_at,
               to_char(
                 updated_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) updated_at
        from agent_priority_reviews
        where owner_id = ${ownerId} and id = ${reviewId}
        limit 1
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      return row === undefined
        ? Option.none<AgentPriorityReview>()
        : Option.some((yield* decodeStoredAgentReviewDatabaseRow(row)).review);
    }),
    getPriorityOverlay: Effect.fn('AgentStore.getPriorityOverlay')(function* (
      ownerId,
      reviewId,
    ) {
      const rows = yield* sql<{
        readonly review_id: string;
        readonly owner_id: string;
        readonly scan_id: string;
        readonly overlay_json: string;
        readonly created_at: string;
        readonly updated_at: string;
      }>`
        select review_id,
               owner_id,
               scan_id,
               overlay::text overlay_json,
               to_char(
                 created_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) created_at,
               to_char(
                 updated_at at time zone 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
               ) updated_at
        from agent_priority_overlays
        where owner_id = ${ownerId} and review_id = ${reviewId}
        limit 1
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      return row === undefined
        ? Option.none<CompleteAgentPriorityOverlay>()
        : Option.some((yield* decodeStoredPriorityOverlayDatabaseRow(row)).overlay);
    }),
    failReviewIfActive: (ownerId, reviewId, failedAt) =>
      failActive(
        ownerId,
        reviewId,
        'The priority review stopped before completion. Retry it.',
        failedAt,
      ),
    failExpiredReviews: Effect.fn('AgentStore.failExpiredReviews')(function* (now, failedAt) {
      yield* sql`
        update agent_priority_reviews
        set status = 'failed',
            lease_token = null,
            lease_expires_at = null,
            deadline_at = null,
            record = jsonb_set(
              jsonb_set(
                jsonb_set(record - 'output', '{status}', '"failed"'::jsonb),
                '{diagnostic}', '"The priority review lease expired before completion. Retry it."'::jsonb
              ),
              '{updatedAt}', to_jsonb(${failedAt}::text)
            ),
            updated_at = ${failedAt}
        where status = 'running'
          and (
            lease_expires_at is null or lease_expires_at <= ${now}
            or deadline_at is null or deadline_at <= ${now}
          )
      `.pipe(Effect.mapError(storeError));
    }),
    cancelReview: (ownerId, reviewId, cancelledAt) =>
      failActive(
        ownerId,
        reviewId,
        'The priority review was cancelled.',
        cancelledAt,
      ),
    deleteProfile: Effect.fn('AgentStore.deleteProfile')(function* (ownerId, profileId) {
      const rows = yield* sql<{ readonly id: string }>`
        delete from agent_profiles
        where owner_id = ${ownerId} and id = ${profileId}
        returning id
      `.pipe(Effect.mapError(storeError));
      const row = rows[0];
      if (row === undefined) {
        return yield* new AgentStoreError({ message: 'Provider profile was not found.' });
      }
      yield* decodeIdRow(row);
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
