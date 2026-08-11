import { Effect, Schema } from "effect";
import {
  createDeterministicClock,
  type Clock,
  type DeterministicClockError,
} from "./clock.js";

export type ProgressValue = Schema.Json;

export const ProgressCaptureOperation = Schema.Literals([
  "clone",
  "decode",
  "timestamp",
]);

export const ProgressCaptureFailureReason = Schema.Literals([
  "clone-failed",
  "clock-failed",
  "decode-failed",
]);

export class ProgressCaptureError extends Schema.TaggedErrorClass<ProgressCaptureError>()(
  "ProgressCaptureError",
  {
    operation: ProgressCaptureOperation,
    reason: ProgressCaptureFailureReason,
  },
) {}

export interface CapturedProgress {
  readonly at: string;
  readonly sequence: number;
  readonly value: ProgressValue;
}

export interface ProgressCapture {
  readonly observer: (
    value: ProgressValue,
  ) => Effect.Effect<void, ProgressCaptureError | Schema.SchemaError>;
  clear(): void;
  events(): Effect.Effect<readonly CapturedProgress[], ProgressCaptureError | Schema.SchemaError>;
  last(): Effect.Effect<CapturedProgress | undefined, ProgressCaptureError | Schema.SchemaError>;
  record(
    value: ProgressValue,
  ): Effect.Effect<CapturedProgress, ProgressCaptureError | Schema.SchemaError>;
  values(): Effect.Effect<readonly ProgressValue[], ProgressCaptureError | Schema.SchemaError>;
}

export interface ProgressCaptureOptions {
  readonly clock?: Clock;
}

const decodeValue = Schema.decodeUnknownEffect(Schema.Json);

function captureError(
  operation: typeof ProgressCaptureOperation.Type,
  reason: typeof ProgressCaptureFailureReason.Type,
): ProgressCaptureError {
  return new ProgressCaptureError({ operation, reason });
}

export const decodeProgressValue = (
  value: Parameters<typeof decodeValue>[0],
) => Effect.suspend(() => decodeValue(value)).pipe(Effect.catchDefect(() => Effect.fail(
  captureError("decode", "decode-failed"),
)));

function snapshot(
  value: ProgressValue,
): Effect.Effect<ProgressValue, ProgressCaptureError | Schema.SchemaError> {
  return decodeProgressValue(value).pipe(
    Effect.flatMap(decoded => Effect.try({
      try: () => structuredClone(decoded),
      catch: () => captureError("clone", "clone-failed"),
    })),
    Effect.flatMap(decodeProgressValue),
  );
}

/**
 * Captures schema-decoded JSON snapshots rather than retaining caller-owned
 * references. Every cloning failure is represented in the returned Effect.
 */
export function createProgressCapture(
  options: ProgressCaptureOptions = {},
): Effect.Effect<
  ProgressCapture,
  DeterministicClockError | Schema.SchemaError
> {
  const makeCapture = (activeClock: Clock): ProgressCapture => {
    let captured: CapturedProgress[] = [];
    let nextSequence = 0;

    const copyEvent = (
      event: CapturedProgress,
    ): Effect.Effect<CapturedProgress, ProgressCaptureError | Schema.SchemaError> => snapshot(event.value)
      .pipe(Effect.map(value => ({ at: event.at, sequence: event.sequence, value })));

    const record = (
      value: ProgressValue,
    ): Effect.Effect<CapturedProgress, ProgressCaptureError | Schema.SchemaError> => snapshot(value).pipe(
      Effect.flatMap(snapshotValue => Effect.try({
        try: () => activeClock.now().toISOString(),
        catch: () => captureError("timestamp", "clock-failed"),
      }).pipe(Effect.flatMap(at => {
        const event: CapturedProgress = {
          at,
          sequence: nextSequence,
          value: snapshotValue,
        };
        nextSequence += 1;
        captured.push(event);
        return copyEvent(event);
      }))),
    );

    return {
      observer: value => record(value).pipe(Effect.asVoid),
      record,
      events: () => Effect.forEach(captured, copyEvent),
      values: () => Effect.forEach(captured, event => snapshot(event.value)),
      last: () => {
        const event = captured.at(-1);
        return event === undefined ? Effect.succeed(undefined) : copyEvent(event);
      },
      clear: () => {
        captured = [];
        nextSequence = 0;
      },
    };
  };

  return options.clock === undefined
    ? createDeterministicClock().pipe(Effect.map(makeCapture))
    : Effect.succeed(makeCapture(options.clock));
}
