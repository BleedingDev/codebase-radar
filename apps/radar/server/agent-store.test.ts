import { NodeServices } from '@effect/platform-node';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Effect, Encoding, Exit, Option, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AgentPriorityItem,
  AgentPriorityOutput,
  AgentPriorityReview,
  GitHubSourceIdentity,
} from '../shared/domain';
import {
  AgentCredentialFile,
  AgentCredentialState,
  AgentStore,
  decodeStoredAgentReviewRow,
  decodeStoredAgentHome,
  makeScanAccessVisibilityAttestation,
  maxAgentCredentialFileBytes,
  maxAgentCredentialCiphertextCharacters,
  maxAgentCredentialEncodedFileCharacters,
  maxAgentCredentialStateSerializedBytes,
  maxAgentCredentialTotalBytes,
  MemoryAgentStoreLive,
  publicGitHubVisibilityPolicyVersion,
  ScanAccessGrant,
} from './agent-store';
import {
  AgentPriorityOverlayItem,
  AgentPriorityModelHistoryEntry,
  canonicalOverlayFindingInventoryDigest,
  CompleteAgentPriorityOverlay,
  legacyPriorityOutput,
} from './agent-priority-overlay';

const scanSource = new GitHubSourceIdentity({
  codebaseId: 'github:owner/repository',
  owner: 'Owner',
  repository: 'Repository',
  url: 'https://github.com/Owner/Repository',
  commitSha: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  defaultBranch: 'main',
  snapshotDigest: 'git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
});

const oneFindingInventoryDigest = createHash('sha256').update(
  JSON.stringify([
    {
      findingId: 'finding-one',
      canonicalFindingDigest: 'b'.repeat(64),
    },
  ]),
).digest('hex');

const overlay = (scanId = 'scan-one') =>
  new CompleteAgentPriorityOverlay({
    schemaVersion: 'codebase-radar.complete-agent-priority-overlay/v3',
    scanId,
    canonicalResultDigest: 'a'.repeat(64),
    source: scanSource,
    findingInventoryDigest: oneFindingInventoryDigest,
    provider: 'codex',
    opinionKind: 'unverified-model-opinion',
    orderedItems: [
      new AgentPriorityOverlayItem({
        findingId: 'finding-one',
        canonicalFindingDigest: 'b'.repeat(64),
        action: 'investigate',
        opinionKind: 'unverified-model-opinion',
        rationale: 'The model ordering opinion is bounded.',
        nextMove: 'Inspect canonical evidence.',
        modelHistory: [
          new AgentPriorityModelHistoryEntry({
            phase: 'local',
            roundIndex: 0,
            windowIndex: 0,
            rank: 0,
            windowSize: 1,
          }),
        ],
      }),
    ],
    unsupportedClaims: [],
  });

const grant = (ownerId: string, scanId = 'scan-one') => {
  const canonicalResultDigest = 'a'.repeat(64);
  const findingInventoryDigest = canonicalOverlayFindingInventoryDigest(
    overlay(scanId).orderedItems,
  );
  const visibility = makeScanAccessVisibilityAttestation(
    publicGitHubVisibilityPolicyVersion,
    scanSource,
    canonicalResultDigest,
    findingInventoryDigest,
  );
  return new ScanAccessGrant({
    reviewOwnerId: ownerId,
    scanId,
    canonicalResultDigest,
    source: scanSource,
    findingInventoryDigest,
    visibilityPolicyVersion: visibility.policyVersion,
    visibilityAttestation: visibility.attestation,
  });
};

const presentation = (value = overlay()) => Effect.runSync(legacyPriorityOutput(value));

const withMemoryStore = <Value, Failure>(
  effect: Effect.Effect<Value, Failure, AgentStore>,
) =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(MemoryAgentStoreLive),
      Effect.provide(NodeServices.layer),
    ),
  );

describe('provider and review isolation', () => {
  it('keeps provider homes within their owner and provider boundary', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const firstOwner = yield* store.getOrCreateSession();
        const secondOwner = yield* store.getOrCreateSession();
        const first = yield* store.createProfile(firstOwner, 'codex');
        const second = yield* store.createProfile(secondOwner, 'claude');
        yield* Effect.all([
          store.writeHome(
            firstOwner,
            first.id,
            0,
            new AgentCredentialState({
              schemaVersion: 'codebase-radar.agent-home/v1',
              provider: 'codex',
              files: [
                new AgentCredentialFile({
                  path: 'auth.json',
                  content: Encoding.encodeBase64(
                    new TextEncoder().encode('{"token":"codex-private"}'),
                  ),
                }),
              ],
            }),
          ),
          store.writeHome(
            secondOwner,
            second.id,
            0,
            new AgentCredentialState({
              schemaVersion: 'codebase-radar.agent-home/v1',
              provider: 'claude',
              files: [
                new AgentCredentialFile({
                  path: '.credentials.json',
                  content: Encoding.encodeBase64(
                    new TextEncoder().encode('{"token":"claude-private"}'),
                  ),
                }),
              ],
            }),
          ),
        ], { concurrency: 'unbounded' });
        const foreign = yield* Effect.exit(store.readHome(secondOwner, first.id));
        const own = yield* store.readHome(firstOwner, first.id);

        expect(Option.isSome(own.state)).toBe(true);
        expect(Exit.isFailure(foreign)).toBe(true);
        expect(firstOwner).not.toBe(secondOwner);
      }),
    ));

  it('uses one atomic memory generation compare-and-swap', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const state = new AgentCredentialState({
          schemaVersion: 'codebase-radar.agent-home/v1',
          provider: 'codex',
          files: [
            new AgentCredentialFile({
              path: 'auth.json',
              content: Encoding.encodeBase64(new TextEncoder().encode('{"token":"one"}')),
            }),
          ],
        });
        const writes = yield* Effect.all([
          Effect.exit(store.writeHome(ownerId, profile.id, 0, state)),
          Effect.exit(store.writeHome(ownerId, profile.id, 0, state)),
        ], { concurrency: 'unbounded' });
        expect(writes.filter(Exit.isSuccess)).toHaveLength(1);
        expect((yield* store.readHome(ownerId, profile.id)).generation).toBe(1);
      }),
    ));

  it('atomically rejects a second profile for the same owner and provider', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const attempts = yield* Effect.all([
          Effect.exit(store.createProfile(ownerId, 'codex')),
          Effect.exit(store.createProfile(ownerId, 'codex')),
        ], { concurrency: 'unbounded' });

        expect(attempts.filter(Exit.isSuccess)).toHaveLength(1);
        expect(yield* store.listProfiles(ownerId)).toHaveLength(1);
      }),
    ));
});

describe('review grant, lease, and atomic completion', () => {
  it('rejects an owner-mismatched grant before a review exists', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const firstOwner = yield* store.getOrCreateSession();
        const secondOwner = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(firstOwner, 'codex');
        const rejected = yield* Effect.exit(
          store.createReview(firstOwner, profile.id, grant(secondOwner)),
        );

        expect(Exit.isFailure(rejected)).toBe(true);
      }),
    ));

  it('binds grants per owner and makes matching completion replay idempotent', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const foreignOwner = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const value = overlay();
        const output = presentation();
        const first = yield* store.completeReviewWithOverlay(
          ownerId,
          review.id,
          lease,
          value,
          output,
          '2099-01-01T00:01:00.000Z',
        );
        const replay = yield* store.completeReviewWithOverlay(
          ownerId,
          review.id,
          lease,
          value,
          output,
          '2099-01-01T00:01:00.000Z',
        );
        const replayWithDifferentCompletionTime = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            value,
            output,
            '2099-01-01T00:01:01.000Z',
          ),
        );
        const different = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            new CompleteAgentPriorityOverlay({
              ...value,
              unsupportedClaims: ['Different replay.'],
            }),
            output,
            '2099-01-01T00:01:00.000Z',
          ),
        );
        const foreignGrant = yield* store.getReviewAccessGrant(foreignOwner, review.id);
        const foreignOverlay = yield* store.getPriorityOverlay(foreignOwner, review.id);

        expect(first.status).toBe('completed');
        expect(replay.status).toBe('completed');
        expect(Exit.isFailure(replayWithDifferentCompletionTime)).toBe(true);
        expect(Exit.isFailure(different)).toBe(true);
        expect(Option.isNone(foreignGrant)).toBe(true);
        expect(Option.isNone(foreignOverlay)).toBe(true);
      }),
    ));

  it('does not resurrect cancelled or expired terminal reviews', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        yield* store.cancelReview(ownerId, review.id, '2099-01-01T00:01:00.000Z');
        const completion = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            overlay(),
            presentation(),
            '2099-01-01T00:02:00.000Z',
          ),
        );
        yield* store.failExpiredReviews(
          '2099-01-01T04:00:00.000Z',
          '2099-01-01T04:00:00.000Z',
        );
        const current = yield* store.getReview(ownerId, review.id);

        expect(Exit.isFailure(completion)).toBe(true);
        expect(Option.isSome(current)).toBe(true);
        if (Option.isSome(current)) expect(current.value.status).toBe('failed');
      }),
    ));

  it('does not let a second owner cancel another owner review', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const secondOwner = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        yield* store.cancelReview(secondOwner, review.id, '2099-01-01T00:01:00.000Z');
        const value = overlay();
        const completed = yield* store.completeReviewWithOverlay(
          ownerId,
          review.id,
          lease,
          value,
          presentation(value),
          '2099-01-01T00:01:00.000Z',
        );

        expect(completed.status).toBe('completed');
      }),
    ));

  it('renews a healthy lease beyond the old stale window', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T05:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const renewed = yield* store.renewReviewLease(
          ownerId,
          review.id,
          lease,
          '2099-01-01T00:04:00.000Z',
          '2099-01-01T02:45:00.000Z',
        );
        yield* store.failExpiredReviews(
          '2099-01-01T02:44:00.000Z',
          '2099-01-01T02:44:00.000Z',
        );
        const current = yield* store.getReview(ownerId, review.id);

        expect(renewed.expiresAt).toBe('2099-01-01T02:45:00.000Z');
        expect(Option.isSome(current)).toBe(true);
        if (Option.isSome(current)) expect(current.value.status).toBe('running');
      }),
    ));

  it('does not resurrect an expired lease before the sweeper runs', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T05:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const renewed = yield* Effect.exit(
          store.renewReviewLease(
            ownerId,
            review.id,
            lease,
            '2099-01-01T00:06:00.000Z',
            '2099-01-01T00:11:00.000Z',
          ),
        );

        expect(Exit.isFailure(renewed)).toBe(true);
      }),
    ));

  it('rejects completion after the renewable lease expires', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const value = overlay();
        const expired = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            value,
            presentation(value),
            '2099-01-01T00:05:01.000Z',
          ),
        );

        expect(Exit.isFailure(expired)).toBe(true);
      }),
    ));

  it('treats the exact lease boundary as expired for renewal and completion', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const value = overlay();
        const renewal = yield* Effect.exit(
          store.renewReviewLease(
            ownerId,
            review.id,
            lease,
            '2099-01-01T00:05:00.000Z',
            '2099-01-01T00:06:00.000Z',
          ),
        );
        const completion = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            value,
            presentation(value),
            '2099-01-01T00:05:00.000Z',
          ),
        );

        expect(Exit.isFailure(renewal)).toBe(true);
        expect(Exit.isFailure(completion)).toBe(true);
      }),
    ));

  it('requires the persisted presentation to be derived from the validated overlay', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, grant(ownerId));
        const lease = yield* store.claimReview(
          ownerId,
          review.id,
          '2099-01-01T03:00:00.000Z',
          '2099-01-01T00:05:00.000Z',
        );
        const value = overlay();
        const derived = presentation(value);
        const altered = new AgentPriorityOutput({
          ...derived,
          summary: 'Different presentation.',
        });
        const result = yield* Effect.exit(
          store.completeReviewWithOverlay(
            ownerId,
            review.id,
            lease,
            value,
            altered,
            '2099-01-01T00:01:00.000Z',
          ),
        );

        expect(Exit.isFailure(result)).toBe(true);
      }),
    ));
});

describe('encrypted home metadata', () => {
  it('derives the serialized credential ceiling from the ciphertext Base64 limit', () => {
    const base64Characters = (bytes: number) => Math.ceil(bytes / 3) * 4;

    expect(
      base64Characters(maxAgentCredentialStateSerializedBytes),
    ).toBeLessThanOrEqual(maxAgentCredentialCiphertextCharacters);
    expect(
      base64Characters(maxAgentCredentialStateSerializedBytes + 1),
    ).toBeGreaterThan(maxAgentCredentialCiphertextCharacters);
  });

  it('bounds each encoded credential before encryption', () => {
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AgentCredentialFile)({
          path: 'auth.json',
          content: 'a'.repeat(maxAgentCredentialEncodedFileCharacters),
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AgentCredentialFile)({
          path: 'auth.json',
          content: 'a'.repeat(maxAgentCredentialEncodedFileCharacters + 1),
        }),
      ),
    ).toBe(true);
  });
  it('rejects a credential state whose encoded ciphertext would exceed storage', () =>
    withMemoryStore(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'claude');
        const content = Encoding.encodeBase64(new Uint8Array(maxAgentCredentialFileBytes));
        const state = new AgentCredentialState({
          schemaVersion: 'codebase-radar.agent-home/v1',
          provider: 'claude',
          files: [
            new AgentCredentialFile({ path: '.credentials.json', content }),
            new AgentCredentialFile({ path: '.claude.json', content }),
          ],
        });
        const write = yield* Effect.exit(
          store.writeHome(ownerId, profile.id, 0, state),
        );

        expect(maxAgentCredentialTotalBytes).toBeLessThan(maxAgentCredentialFileBytes * 2);
        expect(Exit.isFailure(write)).toBe(true);
      }),
    ));

  it('keeps PostgreSQL terminal updates coherent with the normalized deadline column', () => {
    const source = readFileSync(new URL('./agent-store.ts', import.meta.url), 'utf8');

    expect(source).toContain('lease_expires_at = null,\n          deadline_at = null,');
    expect(source).toContain('lease_expires_at = null,\n                  deadline_at = null,');
    expect(source).toContain('lease_expires_at is null or lease_expires_at <= ${now}');
    expect(source).toContain('deadline_at = ${acceptedLease.deadlineAt}');
  });
  it('strictly rejects malformed stored security metadata', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const malformed = yield* Effect.exit(
          decodeStoredAgentHome('{"schemaVersion":"codebase-radar.encrypted-agent-home/v2"}'),
        );
        const oversized = yield* Effect.exit(
          decodeStoredAgentHome(
            JSON.stringify({
              schemaVersion: 'codebase-radar.encrypted-agent-home/v2',
              keyVersion: 'v1',
              generation: 0,
              ciphertext: 'x'.repeat(5_600_001),
              nonce: 'n',
              tag: 't',
              wrappedKey: 'w',
              wrapNonce: 'n',
              wrapTag: 't',
            }),
          ),
        );
        const malformedReviewRow = yield* Effect.exit(
          decodeStoredAgentReviewRow({ record_json: '{"status":"completed"}' }),
        );
        const oversizedReviewRow = yield* Effect.exit(
          decodeStoredAgentReviewRow({ record_json: 'x'.repeat(8 * 1_024 * 1_024 + 1) }),
        );
        const repeatedFindingOutput = new AgentPriorityOutput({
          opinionKind: 'unverified-model-opinion',
          summary: 'A malformed repeated presentation.',
          orderedItems: [
            new AgentPriorityItem({
              findingId: 'finding-one',
              action: 'investigate',
              opinionKind: 'unverified-model-opinion',
              reason: 'First duplicate.',
              nextMove: 'Inspect it.',
            }),
            new AgentPriorityItem({
              findingId: 'finding-one',
              action: 'investigate',
              opinionKind: 'unverified-model-opinion',
              reason: 'Second duplicate.',
              nextMove: 'Inspect it again.',
            }),
          ],
          notNowFindingIds: [],
          unsupportedClaims: [],
        });
        const duplicateReviewRow = yield* Effect.exit(
          decodeStoredAgentReviewRow({
            record_json: JSON.stringify(new AgentPriorityReview({
              schemaVersion: 'codebase-radar.priority-review/v1',
              id: 'review-one',
              scanId: 'scan-one',
              profileId: 'profile-one',
              provider: 'codex',
              status: 'completed',
              output: repeatedFindingOutput,
              createdAt: '2026-08-11T10:00:00.000Z',
              updatedAt: '2026-08-11T10:01:00.000Z',
            })),
          }),
        );

        expect(Exit.isFailure(malformed)).toBe(true);
        expect(Exit.isFailure(oversized)).toBe(true);
        expect(Exit.isFailure(malformedReviewRow)).toBe(true);
        expect(Exit.isFailure(oversizedReviewRow)).toBe(true);
        expect(Exit.isFailure(duplicateReviewRow)).toBe(true);
      }),
    ));
});
