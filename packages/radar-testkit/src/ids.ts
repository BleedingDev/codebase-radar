import { Effect, Schema } from "effect";

export const DeterministicRunIdOptionsSchema = Schema.Struct({
  increment: Schema.optional(Schema.Number),
  prefix: Schema.optional(Schema.String),
  separator: Schema.optional(Schema.String),
  start: Schema.optional(Schema.Number),
  width: Schema.optional(Schema.Number),
});

export const DeterministicRunIdOperation = Schema.Literals([
  "create",
  "next",
  "peek",
  "reset",
]);

export const DeterministicRunIdFailureReason = Schema.Literals([
  "empty-prefix",
  "exhausted",
  "invalid-increment",
  "invalid-options",
  "invalid-sequence",
  "invalid-width",
]);

export class DeterministicRunIdError extends Schema.TaggedErrorClass<DeterministicRunIdError>()(
  "DeterministicRunIdError",
  {
    operation: DeterministicRunIdOperation,
    reason: DeterministicRunIdFailureReason,
  },
) {}

export interface DeterministicRunIds {
  next(): Effect.Effect<string, DeterministicRunIdError>;
  peek(): Effect.Effect<string, DeterministicRunIdError>;
  reset(nextSequence?: number): Effect.Effect<void, DeterministicRunIdError>;
}

export interface DeterministicRunIdOptions {
  readonly increment?: number;
  readonly prefix?: string;
  readonly separator?: string;
  readonly start?: number;
  readonly width?: number;
}

const decodeRunIdOptions = Schema.decodeUnknownEffect(
  DeterministicRunIdOptionsSchema,
);

function runIdError(
  operation: typeof DeterministicRunIdOperation.Type,
  reason: typeof DeterministicRunIdFailureReason.Type,
): DeterministicRunIdError {
  return new DeterministicRunIdError({ operation, reason });
}

export const decodeDeterministicRunIdOptions = (
  value: Parameters<typeof decodeRunIdOptions>[0],
) => Effect.suspend(() => decodeRunIdOptions(value)).pipe(Effect.catchDefect(() => Effect.fail(
  runIdError("create", "invalid-options"),
)));

function validateSequence(
  value: number,
  operation: typeof DeterministicRunIdOperation.Type,
): Effect.Effect<number, DeterministicRunIdError> {
  return Number.isSafeInteger(value) && value >= 0
    ? Effect.succeed(value)
    : Effect.fail(runIdError(operation, "invalid-sequence"));
}

function validateIncrement(
  value: number,
  operation: typeof DeterministicRunIdOperation.Type,
): Effect.Effect<number, DeterministicRunIdError> {
  return Number.isSafeInteger(value) && value > 0
    ? Effect.succeed(value)
    : Effect.fail(runIdError(operation, "invalid-increment"));
}

function validateWidth(
  value: number,
  operation: typeof DeterministicRunIdOperation.Type,
): Effect.Effect<number, DeterministicRunIdError> {
  return Number.isSafeInteger(value) && value >= 1 && value <= 32
    ? Effect.succeed(value)
    : Effect.fail(runIdError(operation, "invalid-width"));
}

/** Creates stable, human-readable identifiers, for example `radar-run-0001`. */
export function createDeterministicRunIds(
  options: DeterministicRunIdOptions = {},
): Effect.Effect<
  DeterministicRunIds,
  DeterministicRunIdError | Schema.SchemaError
> {
  return decodeDeterministicRunIdOptions(options).pipe(
    Effect.flatMap(decodedOptions => Effect.gen(function* () {
      const prefix = decodedOptions.prefix ?? "radar-run";
      if (prefix.length === 0) {
        return yield* Effect.fail(runIdError("create", "empty-prefix"));
      }
      const initialSequence = yield* validateSequence(decodedOptions.start ?? 1, "create");
      const increment = yield* validateIncrement(decodedOptions.increment ?? 1, "create");
      const width = yield* validateWidth(decodedOptions.width ?? 4, "create");
      const separator = decodedOptions.separator ?? "-";
      let sequence: number | undefined = initialSequence;
      const format = (value: number): string =>
        `${prefix}${separator}${String(value).padStart(width, "0")}`;
      const nextValue = (value: number): number | undefined => {
        const candidate = value + increment;
        return Number.isSafeInteger(candidate) ? candidate : undefined;
      };
      const currentSequence = (
        operation: typeof DeterministicRunIdOperation.Type,
      ): Effect.Effect<number, DeterministicRunIdError> => sequence === undefined
        ? Effect.fail(runIdError(operation, "exhausted"))
        : Effect.succeed(sequence);

      return {
        next: () => currentSequence("next").pipe(
          Effect.map(current => {
            sequence = nextValue(current);
            return format(current);
          }),
        ),
        peek: () => currentSequence("peek").pipe(Effect.map(format)),
        reset: (nextSequence = initialSequence) => validateSequence(nextSequence, "reset").pipe(
          Effect.tap(next => Effect.sync(() => {
            sequence = next;
          })),
          Effect.asVoid,
        ),
      };
    })),
  );
}
