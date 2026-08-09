import { NodeServices } from '@effect/platform-node';
import { Effect, Encoding, Exit, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AgentCredentialFile,
  AgentCredentialState,
  AgentStore,
  MemoryAgentStoreLive,
} from './agent-store';

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
});
