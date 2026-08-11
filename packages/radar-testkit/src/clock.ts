import { Effect, Schema } from "effect";

const DEFAULT_START = "2000-01-01T00:00:00.000Z";
const SemanticTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;

export const DeterministicClockInstant = Schema.Union([
  Schema.Date,
  Schema.Number,
  Schema.String,
]);

export const DeterministicClockOptionsSchema = Schema.Struct({
  start: Schema.optional(DeterministicClockInstant),
  stepMs: Schema.optional(Schema.Number),
});

export const DeterministicClockOperation = Schema.Literals([
  "advance",
  "create",
  "set",
]);

export const DeterministicClockFailureReason = Schema.Literals([
  "invalid-duration",
  "invalid-instant",
  "range-exceeded",
]);

export class DeterministicClockError extends Schema.TaggedErrorClass<DeterministicClockError>()(
  "DeterministicClockError",
  {
    operation: DeterministicClockOperation,
    reason: DeterministicClockFailureReason,
  },
) {}

export interface Clock {
  now(): Date;
  nowMs(): number;
}

export interface DeterministicClock extends Clock {
  advance(byMs?: number): Effect.Effect<Date, DeterministicClockError>;
  reset(): void;
  set(instant: Date | number | string): Effect.Effect<Date, DeterministicClockError>;
}

export interface DeterministicClockOptions {
  readonly start?: Date | number | string;
  readonly stepMs?: number;
}

const decodeClockOptions = Schema.decodeUnknownEffect(
  DeterministicClockOptionsSchema,
);

function clockError(
  operation: typeof DeterministicClockOperation.Type,
  reason: typeof DeterministicClockFailureReason.Type,
): DeterministicClockError {
  return new DeterministicClockError({ operation, reason });
}

export const decodeDeterministicClockOptions = (
  value: Parameters<typeof decodeClockOptions>[0],
) => Effect.suspend(() => decodeClockOptions(value)).pipe(Effect.catchDefect(() => Effect.fail(
  clockError("create", "invalid-instant"),
)));

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  }
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

function isSemanticTimestamp(value: string): boolean {
  if (!SemanticTimestamp.test(value)) return false;

  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const hour = Number(value.slice(11, 13));
  const minute = Number(value.slice(14, 16));
  const second = Number(value.slice(17, 19));
  const offset = value.endsWith("Z") ? "" : value.slice(-6);
  const offsetHour = offset.length === 0 ? 0 : Number(offset.slice(1, 3));
  const offsetMinute = offset.length === 0 ? 0 : Number(offset.slice(4, 6));

  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth(year, month) &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    offsetHour <= 14 &&
    offsetMinute <= 59 &&
    (offsetHour !== 14 || offsetMinute === 0)
  );
}

function isValidEpochMs(value: number): boolean {
  return Number.isSafeInteger(value) && Number.isFinite(new Date(value).getTime());
}

function toEpochMs(
  instant: Date | number | string,
  operation: typeof DeterministicClockOperation.Type,
): Effect.Effect<number, DeterministicClockError> {
  if (typeof instant === "string" && !isSemanticTimestamp(instant)) {
    return Effect.fail(clockError(operation, "invalid-instant"));
  }
  return Effect.try({
    try: () => instant instanceof Date
      ? Date.prototype.getTime.call(instant)
      : typeof instant === "number"
        ? instant
        : new Date(instant).getTime(),
    catch: () => clockError(operation, "invalid-instant"),
  }).pipe(Effect.flatMap(value => isValidEpochMs(value)
    ? Effect.succeed(value)
    : Effect.fail(clockError(operation, "invalid-instant"))));
}

function validateDuration(
  value: number,
  operation: typeof DeterministicClockOperation.Type,
): Effect.Effect<number, DeterministicClockError> {
  return Number.isSafeInteger(value) && value >= 0
    ? Effect.succeed(value)
    : Effect.fail(clockError(operation, "invalid-duration"));
}

/**
 * Creates a manually controlled clock. Reading never changes time; tests must
 * explicitly call `advance` or `set`, which avoids ordering-dependent results.
 */
export function createDeterministicClock(
  options: DeterministicClockOptions = {},
): Effect.Effect<
  DeterministicClock,
  DeterministicClockError | Schema.SchemaError
> {
  return decodeDeterministicClockOptions(options).pipe(
    Effect.flatMap(decodedOptions => Effect.gen(function* () {
      const initialMs = yield* toEpochMs(
        decodedOptions.start ?? DEFAULT_START,
        "create",
      );
      const stepMs = yield* validateDuration(decodedOptions.stepMs ?? 1_000, "create");
      let currentMs = initialMs;

      return {
        now: () => new Date(currentMs),
        nowMs: () => currentMs,
        advance: (byMs = stepMs) => Effect.gen(function* () {
          const duration = yield* validateDuration(byMs, "advance");
          const nextMs = currentMs + duration;
          if (!isValidEpochMs(nextMs)) {
            return yield* Effect.fail(clockError("advance", "range-exceeded"));
          }
          currentMs = nextMs;
          return new Date(currentMs);
        }),
        set: instant => toEpochMs(instant, "set").pipe(
          Effect.map(nextMs => {
            currentMs = nextMs;
            return new Date(currentMs);
          }),
        ),
        reset: () => {
          currentMs = initialMs;
        },
      };
    })),
  );
}
