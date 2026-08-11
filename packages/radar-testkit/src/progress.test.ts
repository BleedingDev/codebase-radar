import { Effect, Schema } from "effect";
import { describe, expect, it } from "vitest";
import { createDeterministicClock, type Clock } from "./clock.js";
import {
  createProgressCapture,
  decodeProgressValue,
  ProgressCaptureError,
} from "./progress.js";

describe("createProgressCapture", () => {
  it("captures sequenced snapshots without retaining mutable references", () => Effect.runPromise(
    Effect.gen(function* () {
      const clock = yield* createDeterministicClock({ start: "2026-08-11T00:00:00.000Z" });
      const capture = yield* createProgressCapture({ clock });
      const event = { progress: 10 };

      yield* capture.observer(event);
      event.progress = 99;
      yield* clock.advance(500);
      yield* capture.record({ progress: 20 });

      expect(yield* capture.events()).toEqual([
        { at: "2026-08-11T00:00:00.000Z", sequence: 0, value: { progress: 10 } },
        { at: "2026-08-11T00:00:00.500Z", sequence: 1, value: { progress: 20 } },
      ]);

      const returned = yield* capture.last();
      if (returned !== undefined && typeof returned.value === "object" && returned.value !== null) {
        Object.assign(returned.value, { progress: 88 });
      }
      expect(yield* capture.values()).toEqual([{ progress: 10 }, { progress: 20 }]);
    }),
  ));

  it("resets sequence numbers when cleared", () => Effect.runPromise(
    Effect.gen(function* () {
      const capture = yield* createProgressCapture();
      yield* capture.record(1);
      capture.clear();
      expect((yield* capture.record(2)).sequence).toBe(0);
    }),
  ));

  it("models cloning and schema failures without retaining an event", () => Effect.runPromise(
    Effect.gen(function* () {
      const capture = yield* createProgressCapture();
      const blockedClone = new Proxy({ progress: 1 }, {});
      const cloneError = yield* Effect.flip(capture.record(blockedClone));
      expect(cloneError._tag).toBe("ProgressCaptureError");
      if (!(cloneError instanceof ProgressCaptureError)) return;
      expect(cloneError.reason).toBe("clone-failed");
      expect(yield* capture.events()).toEqual([]);

      const schemaError = yield* Effect.flip(decodeProgressValue(new Date()));
      expect(Schema.isSchemaError(schemaError)).toBe(true);

      const defectingValue = Object.defineProperty({}, "progress", {
        enumerable: true,
        get: () => Date.prototype.getTime.call(new Proxy(new Date(), {})),
      });
      const decodeError = yield* Effect.flip(decodeProgressValue(defectingValue));
      expect(decodeError).toBeInstanceOf(ProgressCaptureError);
      if (!(decodeError instanceof ProgressCaptureError)) return;
      expect(decodeError.operation).toBe("decode");
      expect(decodeError.reason).toBe("decode-failed");

      const invalidClock: Clock = {
        now: () => new Date(Number.NaN),
        nowMs: () => 0,
      };
      const clockCapture = yield* createProgressCapture({ clock: invalidClock });
      const clockError = yield* Effect.flip(clockCapture.record({ progress: 1 }));
      expect(clockError).toBeInstanceOf(ProgressCaptureError);
      if (!(clockError instanceof ProgressCaptureError)) return;
      expect(clockError.operation).toBe("timestamp");
      expect(clockError.reason).toBe("clock-failed");
    }),
  ));
});
