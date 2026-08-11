import { Effect, Schema } from "effect";
import { describe, expect, it } from "vitest";
import {
  createDeterministicClock,
  decodeDeterministicClockOptions,
  DeterministicClockError,
} from "@codebase-radar/testkit";

describe("createDeterministicClock", () => {
  it("changes time only under explicit control", () => Effect.runPromise(
    Effect.gen(function* () {
      const clock = yield* createDeterministicClock({
        start: "2026-01-02T03:04:05.000Z",
        stepMs: 25,
      });

      expect(clock.now().toISOString()).toBe("2026-01-02T03:04:05.000Z");
      expect(clock.now().getTime()).toBe(clock.nowMs());
      expect((yield* clock.advance()).toISOString()).toBe("2026-01-02T03:04:05.025Z");
      expect(clock.now().getTime()).toBe(clock.nowMs());
      expect((yield* clock.set("2027-02-03T00:00:00.000Z")).toISOString())
        .toBe("2027-02-03T00:00:00.000Z");
      expect(clock.now().getTime()).toBe(clock.nowMs());
      clock.reset();
      expect(clock.now().toISOString()).toBe("2026-01-02T03:04:05.000Z");
      expect(clock.now().getTime()).toBe(clock.nowMs());
    }),
  ));

  it("returns typed Effect failures for invalid time and negative advances", () => Effect.runPromise(
    Effect.gen(function* () {
      const invalidStart = yield* Effect.flip(createDeterministicClock({ start: "invalid" }));
      expect(invalidStart._tag).toBe("DeterministicClockError");
      if (!(invalidStart instanceof DeterministicClockError)) return;
      expect(invalidStart.operation).toBe("create");
      expect(invalidStart.reason).toBe("invalid-instant");

      const clock = yield* createDeterministicClock();
      const invalidAdvance = yield* Effect.flip(clock.advance(-1));
      expect(invalidAdvance._tag).toBe("DeterministicClockError");
      if (!(invalidAdvance instanceof DeterministicClockError)) return;
      expect(invalidAdvance.operation).toBe("advance");
      expect(invalidAdvance.reason).toBe("invalid-duration");
    }),
  ));

  it("rejects ambiguous timestamps, imprecise durations, and schema drift", () => Effect.runPromise(
    Effect.gen(function* () {
      const ambiguous = yield* Effect.flip(
        createDeterministicClock({ start: "2026-01-02T03:04:05" }),
      );
      if (!(ambiguous instanceof DeterministicClockError)) return;
      expect(ambiguous.reason).toBe("invalid-instant");
      const invalidDate = yield* Effect.flip(
        createDeterministicClock({ start: "2026-02-30T03:04:05.000Z" }),
      );
      if (!(invalidDate instanceof DeterministicClockError)) return;
      expect(invalidDate.reason).toBe("invalid-instant");
      const fractionalStep = yield* Effect.flip(createDeterministicClock({ stepMs: 0.5 }));
      if (!(fractionalStep instanceof DeterministicClockError)) return;
      expect(fractionalStep.reason).toBe("invalid-duration");
      const unsafeStep = yield* Effect.flip(
        createDeterministicClock({ stepMs: Number.MAX_SAFE_INTEGER + 1 }),
      );
      if (!(unsafeStep instanceof DeterministicClockError)) return;
      expect(unsafeStep.reason).toBe("invalid-duration");

      const clock = yield* createDeterministicClock();
      const invalidSet = yield* Effect.flip(clock.set("2026-01-02T03:04:05"));
      if (!(invalidSet instanceof DeterministicClockError)) return;
      expect(invalidSet.reason).toBe("invalid-instant");
      const fractionalAdvance = yield* Effect.flip(clock.advance(0.5));
      if (!(fractionalAdvance instanceof DeterministicClockError)) return;
      expect(fractionalAdvance.reason).toBe("invalid-duration");

      const proxyInstant = new Proxy(new Date("2026-01-02T03:04:05.000Z"), {});
      const proxyFailure = yield* Effect.flip(createDeterministicClock({ start: proxyInstant }));
      expect(proxyFailure).toBeInstanceOf(DeterministicClockError);
      if (!(proxyFailure instanceof DeterministicClockError)) return;
      expect(proxyFailure.reason).toBe("invalid-instant");

      const maximumClock = yield* createDeterministicClock({
        start: new Date(8_640_000_000_000_000),
      });
      const overflow = yield* Effect.flip(maximumClock.advance(1));
      if (!(overflow instanceof DeterministicClockError)) return;
      expect(overflow.reason).toBe("range-exceeded");

      const schemaError = yield* Effect.flip(
        decodeDeterministicClockOptions({ stepMs: "slow" }),
      );
      expect(Schema.isSchemaError(schemaError)).toBe(true);
    }),
  ));
});
