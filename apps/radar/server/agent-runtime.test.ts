import { Deferred, Effect, Exit, Fiber, Ref } from 'effect';
import { TestClock } from 'effect/testing';
import { describe, expect, it } from 'vitest';
import {
  type AgentLoginTerminal,
  releaseAgentLoginSlot,
  reserveAgentLoginSlot,
  superviseAgentLoginLifetime,
} from './agent-runtime';

describe('agent login admission', () => {
  it('allows only one active login for an owner and profile', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const reservations = yield* Ref.make<ReadonlySet<string>>(new Set());
        yield* reserveAgentLoginSlot(reservations, 'owner:profile', 4);
        const duplicate = yield* Effect.exit(
          reserveAgentLoginSlot(reservations, 'owner:profile', 4),
        );
        expect(Exit.isFailure(duplicate)).toBe(true);
        expect((yield* Ref.get(reservations)).size).toBe(1);
      }),
    ));

  it('enforces global capacity and releases slots for retry', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const reservations = yield* Ref.make<ReadonlySet<string>>(new Set());
        yield* reserveAgentLoginSlot(reservations, 'first', 1);
        const full = yield* Effect.exit(
          reserveAgentLoginSlot(reservations, 'second', 1),
        );
        expect(Exit.isFailure(full)).toBe(true);
        yield* releaseAgentLoginSlot(reservations, 'first');
        yield* reserveAgentLoginSlot(reservations, 'second', 1);
        expect(yield* Ref.get(reservations)).toEqual(new Set(['second']));
      }),
    ));
});

describe('agent login lifetime', () => {
  it('cancels the expiry watcher after process completion and finalizes once', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitCode = yield* Deferred.make<number>();
        const expiryWatcherStarted = yield* Deferred.make<void>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const expiryWatcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Deferred.await(exitCode),
          Deferred.succeed(expiryWatcherStarted, undefined).pipe(
            Effect.andThen(Effect.sleep('1 minute')),
            Effect.ensuring(
              Ref.update(expiryWatcherFinalizations, count => count + 1),
            ),
          ),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* Deferred.await(expiryWatcherStarted);
        yield* Deferred.succeed(exitCode, 0);
        yield* Fiber.join(lifetime);
        yield* TestClock.adjust('2 minutes');

        expect(yield* Ref.get(handled)).toEqual(['Finished']);
        expect(yield* Ref.get(expiryWatcherFinalizations)).toBe(1);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('expires once and cancels the process watcher', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const processWatcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Effect.never.pipe(
            Effect.ensuring(
              Ref.update(processWatcherFinalizations, count => count + 1),
            ),
          ),
          Effect.sleep('1 minute'),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* TestClock.adjust('1 minute');
        yield* Fiber.join(lifetime);

        expect(yield* Ref.get(handled)).toEqual(['Expired']);
        expect(yield* Ref.get(processWatcherFinalizations)).toBe(1);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('lets cancellation atomically win against later process completion', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitCode = yield* Deferred.make<number>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Deferred.await(exitCode),
          Effect.sleep('1 minute'),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        const claimed = yield* Deferred.succeed(terminal, {
          _tag: 'Cancelled',
        });
        yield* Deferred.succeed(exitCode, 0);
        yield* Fiber.join(lifetime);
        yield* TestClock.adjust('2 minutes');

        expect(claimed).toBe(true);
        expect(yield* Ref.get(handled)).toEqual(['Cancelled']);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('cancels watchers and finalizes when the owning scope interrupts the lifetime', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitWatcherStarted = yield* Deferred.make<void>();
        const expiryWatcherStarted = yield* Deferred.make<void>();
        const watcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const watcher = (started: Deferred.Deferred<void>) =>
          Deferred.succeed(started, undefined).pipe(
            Effect.andThen(Effect.never),
            Effect.ensuring(
              Ref.update(watcherFinalizations, count => count + 1),
            ),
          );
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          watcher(exitWatcherStarted),
          watcher(expiryWatcherStarted),
          () => Effect.void,
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* Deferred.await(exitWatcherStarted);
        yield* Deferred.await(expiryWatcherStarted);
        yield* Fiber.interrupt(lifetime);

        expect(yield* Ref.get(watcherFinalizations)).toBe(2);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }),
    ));
});
