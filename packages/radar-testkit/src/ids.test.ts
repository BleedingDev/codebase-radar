import { Effect, Schema } from "effect";
import { describe, expect, it } from "vitest";
import {
  createDeterministicRunIds,
  decodeDeterministicRunIdOptions,
  DeterministicRunIdError,
} from "./ids.js";

describe("createDeterministicRunIds", () => {
  it("generates resettable stable sequences", () => Effect.runPromise(
    Effect.gen(function* () {
      const ids = yield* createDeterministicRunIds({ prefix: "scan", start: 7, width: 3 });

      expect(yield* ids.peek()).toBe("scan-007");
      expect(yield* ids.next()).toBe("scan-007");
      expect(yield* ids.next()).toBe("scan-008");
      yield* ids.reset();
      expect(yield* ids.next()).toBe("scan-007");
      yield* ids.reset(42);
      expect(yield* ids.next()).toBe("scan-042");
    }),
  ));

  it("rejects unsafe start and increment values before duplicate IDs", () => Effect.runPromise(
    Effect.gen(function* () {
      const unsafeStart = yield* Effect.flip(
        createDeterministicRunIds({ start: Number.MAX_SAFE_INTEGER + 1 }),
      );
      expect(unsafeStart._tag).toBe("DeterministicRunIdError");
      if (!(unsafeStart instanceof DeterministicRunIdError)) return;
      expect(unsafeStart.reason).toBe("invalid-sequence");
      const zeroIncrement = yield* Effect.flip(createDeterministicRunIds({ increment: 0 }));
      if (!(zeroIncrement instanceof DeterministicRunIdError)) return;
      expect(zeroIncrement.reason).toBe("invalid-increment");
      const fractionalIncrement = yield* Effect.flip(createDeterministicRunIds({ increment: 0.5 }));
      if (!(fractionalIncrement instanceof DeterministicRunIdError)) return;
      expect(fractionalIncrement.reason).toBe("invalid-increment");

      const ids = yield* createDeterministicRunIds({
        prefix: "scan",
        start: Number.MAX_SAFE_INTEGER,
        width: 1,
      });
      expect(yield* ids.next()).toBe(`scan-${Number.MAX_SAFE_INTEGER}`);
      const peekExhaustion = yield* Effect.flip(ids.peek());
      if (!(peekExhaustion instanceof DeterministicRunIdError)) return;
      expect(peekExhaustion.reason).toBe("exhausted");
      const nextExhaustion = yield* Effect.flip(ids.next());
      if (!(nextExhaustion instanceof DeterministicRunIdError)) return;
      expect(nextExhaustion.reason).toBe("exhausted");
      const invalidReset = yield* Effect.flip(ids.reset(Number.MAX_SAFE_INTEGER + 1));
      if (!(invalidReset instanceof DeterministicRunIdError)) return;
      expect(invalidReset.reason).toBe("invalid-sequence");

      yield* ids.reset(Number.MAX_SAFE_INTEGER);
      expect(yield* ids.next()).toBe(`scan-${Number.MAX_SAFE_INTEGER}`);

      const noDuplicate = yield* createDeterministicRunIds({
        prefix: "scan",
        start: Number.MAX_SAFE_INTEGER - 1,
        increment: 2,
      });
      expect(yield* noDuplicate.next()).toBe(`scan-${Number.MAX_SAFE_INTEGER - 1}`);
      const noDuplicateError = yield* Effect.flip(noDuplicate.next());
      if (!(noDuplicateError instanceof DeterministicRunIdError)) return;
      expect(noDuplicateError.reason).toBe("exhausted");

      const schemaError = yield* Effect.flip(decodeDeterministicRunIdOptions({ width: "wide" }));
      expect(Schema.isSchemaError(schemaError)).toBe(true);

      const defectingOptions = Object.defineProperty({}, "start", {
        enumerable: true,
        get: () => Date.prototype.getTime.call(new Proxy(new Date(), {})),
      });
      const defectError = yield* Effect.flip(decodeDeterministicRunIdOptions(defectingOptions));
      expect(defectError).toBeInstanceOf(DeterministicRunIdError);
      if (!(defectError instanceof DeterministicRunIdError)) return;
      expect(defectError.reason).toBe("invalid-options");
    }),
  ));
});
