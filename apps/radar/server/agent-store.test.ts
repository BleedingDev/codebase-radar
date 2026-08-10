import { NodeServices } from '@effect/platform-node';
import { Effect, Encoding, Exit, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import { AgentPriorityReview } from '../shared/domain';
import {
  AgentCredentialFile,
  AgentCredentialState,
  AgentStore,
  MemoryAgentStoreLive,
  decodeStoredAgentHome,
} from './agent-store';

const legacyEncryptedHome = {
  schemaVersion: 'codebase-radar.encrypted-agent-home/v1',
  generation: 4,
  ciphertext: 'Y2lwaGVydGV4dA==',
  nonce: 'bm9uY2U=',
  tag: 'dGFn',
  wrappedKey: 'd3JhcHBlZC1rZXk=',
  wrapNonce: 'd3JhcC1ub25jZQ==',
  wrapTag: 'd3JhcC10YWc=',
};

describe('provider identity isolation', () => {
  it('keeps provider homes inside their owning browser identity', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const firstOwner = yield* store.getOrCreateSession();
        const secondOwner = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(firstOwner, 'codex');
        yield* store.writeHome(
          firstOwner,
          profile.id,
          0,
          new AgentCredentialState({
            schemaVersion: 'codebase-radar.agent-home/v1',
            provider: 'codex',
            files: [
              new AgentCredentialFile({
                path: 'auth.json',
                content: Encoding.encodeBase64(
                  new TextEncoder().encode('{"token":"private"}'),
                ),
              }),
            ],
          }),
        );
        const ownHome = yield* store.readHome(firstOwner, profile.id);
        const foreignProfile = yield* store.getProfile(secondOwner, profile.id);
        const foreignHome = yield* Effect.exit(
          store.readHome(secondOwner, profile.id),
        );
        expect(firstOwner).not.toBe(secondOwner);
        expect(Option.isSome(ownHome.state)).toBe(true);
        expect(Option.isNone(foreignProfile)).toBe(true);
        expect(Exit.isFailure(foreignHome)).toBe(true);
      }).pipe(
        Effect.provide(MemoryAgentStoreLive),
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('terminalizes stale queued priority reviews after a restart window', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, 'scan-one');
        yield* store.failStaleReviews(
          '9999-01-01T00:00:00.000Z',
          '2026-08-10T00:00:00.000Z',
        );
        const updated = yield* store.getReview(ownerId, review.id);
        expect(Option.isSome(updated)).toBe(true);
        if (Option.isSome(updated)) {
          expect(updated.value.status).toBe('failed');
          expect(updated.value.diagnostic).toContain('service restart');
        }
      }).pipe(
        Effect.provide(MemoryAgentStoreLive),
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('does not downgrade a completed priority review during failure cleanup', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* AgentStore;
        const ownerId = yield* store.getOrCreateSession();
        const profile = yield* store.createProfile(ownerId, 'codex');
        const review = yield* store.createReview(ownerId, profile.id, 'scan-one');
        const completedAt = '2026-08-10T00:00:00.000Z';
        yield* store.updateReview(
          ownerId,
          new AgentPriorityReview({
            ...review,
            status: 'completed',
            updatedAt: completedAt,
          }),
        );
        yield* store.failReviewIfActive(
          ownerId,
          review.id,
          'The priority review was interrupted by a service restart. Retry it.',
          '2026-08-10T00:00:01.000Z',
        );
        const updated = yield* store.getReview(ownerId, review.id);
        expect(Option.isSome(updated)).toBe(true);
        if (Option.isSome(updated)) {
          expect(updated.value.status).toBe('completed');
          expect(updated.value.updatedAt).toBe(completedAt);
          expect(updated.value.diagnostic).toBeUndefined();
        }
      }).pipe(
        Effect.provide(MemoryAgentStoreLive),
        Effect.provide(NodeServices.layer),
      ),
    ));
});

describe('encrypted provider home rollout', () => {
  it('recognizes the exact legacy v1 envelope without pretending to migrate it', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const stored = yield* decodeStoredAgentHome(
          JSON.stringify(legacyEncryptedHome),
        );
        const malformedLegacy = yield* Effect.exit(
          decodeStoredAgentHome(
            JSON.stringify({
              schemaVersion: 'codebase-radar.encrypted-agent-home/v1',
              generation: 4,
            }),
          ),
        );
        const legacyWithKeyVersion = yield* Effect.exit(
          decodeStoredAgentHome(
            JSON.stringify({ ...legacyEncryptedHome, keyVersion: 'v1' }),
          ),
        );

        expect(stored.schemaVersion).toBe(
          'codebase-radar.encrypted-agent-home/v1',
        );
        expect(stored.generation).toBe(4);
        expect('keyVersion' in stored).toBe(false);
        expect(Exit.isFailure(malformedLegacy)).toBe(true);
        expect(Exit.isFailure(legacyWithKeyVersion)).toBe(true);
      }),
    ));

  it('preserves the generation across restart invalidation so reconnect can replace it', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const restarted = yield* decodeStoredAgentHome(
          JSON.stringify(legacyEncryptedHome),
        );
        const reconnected = yield* decodeStoredAgentHome(
          JSON.stringify({
            ...legacyEncryptedHome,
            schemaVersion: 'codebase-radar.encrypted-agent-home/v2',
            keyVersion: 'v1',
            generation: restarted.generation + 1,
          }),
        );
        const unsupportedKeyVersion = yield* Effect.exit(
          decodeStoredAgentHome(
            JSON.stringify({
              ...legacyEncryptedHome,
              schemaVersion: 'codebase-radar.encrypted-agent-home/v2',
              keyVersion: 'v2',
            }),
          ),
        );

        expect(restarted.generation).toBe(4);
        expect(reconnected.schemaVersion).toBe(
          'codebase-radar.encrypted-agent-home/v2',
        );
        expect(reconnected.generation).toBe(5);
        expect(Exit.isFailure(unsupportedKeyVersion)).toBe(true);
      }),
    ));
});
