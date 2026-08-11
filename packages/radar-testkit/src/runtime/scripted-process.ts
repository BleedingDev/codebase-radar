import { Effect, Option, Ref, Schema } from 'effect';

export const ScriptedCommandRequest = Schema.Struct({
  command: Schema.String,
  args: Schema.Array(Schema.String),
  cwd: Schema.String,
  env: Schema.optional(
    Schema.Record(Schema.String, Schema.UndefinedOr(Schema.String)),
  ),
  stdin: Schema.optional(Schema.String),
  timeoutMs: Schema.Natural,
  maxOutputBytes: Schema.optional(Schema.Natural),
  signal: Schema.optional(Schema.instanceOf(AbortSignal)),
});

export type ScriptedCommandRequest = typeof ScriptedCommandRequest.Type;

const scriptedCommandRequestInput = Schema.Struct({
  command: Schema.String,
  args: Schema.Array(Schema.String),
  cwd: Schema.String,
  env: Schema.optional(
    Schema.Record(Schema.String, Schema.UndefinedOr(Schema.String)),
  ),
  stdin: Schema.optional(Schema.String),
  timeoutMs: Schema.Number,
  maxOutputBytes: Schema.optional(Schema.Number),
  signal: Schema.optional(Schema.instanceOf(AbortSignal)),
});

type ScriptedCommandRequestInput = typeof scriptedCommandRequestInput.Type;

/**
 * Immutable, serializable process request evidence captured when a script is
 * claimed. Runtime-only cancellation signals are intentionally omitted.
 */
export const ScriptedCommandInvocationRequest = Schema.Struct({
  command: Schema.String,
  args: Schema.Array(Schema.String),
  cwd: Schema.String,
  env: Schema.optional(
    Schema.Record(Schema.String, Schema.UndefinedOr(Schema.String)),
  ),
  stdin: Schema.optional(Schema.String),
  timeoutMs: Schema.Number,
  maxOutputBytes: Schema.optional(Schema.Number),
});

export type ScriptedCommandInvocationRequest =
  typeof ScriptedCommandInvocationRequest.Type;

const outputOutcomeFields = {
  stdout: Schema.optional(Schema.String),
  stderr: Schema.optional(Schema.String),
  durationMs: Schema.optional(Schema.Natural),
};

export const ScriptedCommandOutcome = Schema.Union([
  Schema.Struct({
    ...outputOutcomeFields,
    kind: Schema.Literal('exit'),
    exitCode: Schema.Int,
  }),
  Schema.Struct({
    ...outputOutcomeFields,
    kind: Schema.Literal('missing-binary'),
    message: Schema.optional(Schema.String),
  }),
  Schema.Struct({
    ...outputOutcomeFields,
    kind: Schema.Literal('timeout'),
  }),
  Schema.Struct({
    ...outputOutcomeFields,
    kind: Schema.Literal('interrupted'),
    reason: Schema.optional(Schema.String),
  }),
]);

export type ScriptedCommandOutcome = typeof ScriptedCommandOutcome.Type;

export const ScriptedCommandCase = Schema.Struct({
  id: Schema.NonEmptyString,
  outcome: ScriptedCommandOutcome,
});

export type ScriptedCommandCase = typeof ScriptedCommandCase.Type;

const commandResultFields = {
  stdout: Schema.String,
  stderr: Schema.String,
  durationMs: Schema.Natural,
  truncated: Schema.Boolean,
};

export const ScriptedCommandResult = Schema.Union([
  Schema.Struct({
    ...commandResultFields,
    status: Schema.Literal('exited'),
    exitCode: Schema.Int,
  }),
  Schema.Struct({
    ...commandResultFields,
    status: Schema.Literal('missing-binary'),
    binary: Schema.String,
    message: Schema.String,
  }),
  Schema.Struct({
    ...commandResultFields,
    status: Schema.Literal('timed-out'),
    timeoutMs: Schema.Natural,
  }),
  Schema.Struct({
    ...commandResultFields,
    status: Schema.Literal('interrupted'),
    reason: Schema.String,
  }),
]);

export type ScriptedCommandResult = typeof ScriptedCommandResult.Type;

export const ScriptedCommandInvocation = Schema.Struct({
  sequence: Schema.Natural,
  scriptId: Schema.NonEmptyString,
  request: ScriptedCommandInvocationRequest,
});

export type ScriptedCommandInvocation = typeof ScriptedCommandInvocation.Type;

export const ScriptedProcessSnapshot = Schema.Struct({
  invocations: Schema.Array(ScriptedCommandInvocation),
  activeScriptIds: Schema.Array(Schema.NonEmptyString),
  finalizedScriptIds: Schema.Array(Schema.NonEmptyString),
  remainingScriptIds: Schema.Array(Schema.NonEmptyString),
});

export type ScriptedProcessSnapshot = typeof ScriptedProcessSnapshot.Type;

const scriptedCommandCases = Schema.Array(ScriptedCommandCase);

const scriptedExecutionRequest = Schema.Struct({
  scriptId: Schema.NonEmptyString,
  request: scriptedCommandRequestInput,
});

const scriptedProcessClaim = Schema.Struct({
  _tag: Schema.Literal('ScriptedProcessClaim'),
  scriptId: Schema.NonEmptyString,
  sequence: Schema.Natural,
});

type ScriptedProcessClaim = typeof scriptedProcessClaim.Type;

const scriptedProcessState = Schema.Struct({
  claimedScriptIds: Schema.Array(Schema.NonEmptyString),
  activeClaims: Schema.Array(scriptedProcessClaim),
  finalizedClaims: Schema.Array(scriptedProcessClaim),
  invocations: Schema.Array(ScriptedCommandInvocation),
});

type ScriptedProcessState = typeof scriptedProcessState.Type;

export class ScriptedProcessDefinitionError extends Schema.TaggedErrorClass<ScriptedProcessDefinitionError>()(
  'ScriptedProcessDefinitionError',
  { message: Schema.String },
) {}

export class UnknownProcessScriptError extends Schema.TaggedErrorClass<UnknownProcessScriptError>()(
  'UnknownProcessScriptError',
  {
    scriptId: Schema.NonEmptyString,
    message: Schema.String,
  },
) {}

export class DuplicateProcessScriptUseError extends Schema.TaggedErrorClass<DuplicateProcessScriptUseError>()(
  'DuplicateProcessScriptUseError',
  {
    scriptId: Schema.NonEmptyString,
    message: Schema.String,
  },
) {}

export class ScriptedProcessInvariantError extends Schema.TaggedErrorClass<ScriptedProcessInvariantError>()(
  'ScriptedProcessInvariantError',
  { message: Schema.String },
) {}

const encoder = new TextEncoder();

type ScriptedProcessId = typeof Schema.NonEmptyString.Type;

const capture = (value: string, maxOutputBytes: number | undefined) => {
  if (maxOutputBytes === undefined) {
    return { value, truncated: false };
  }
  const bytes = encoder.encode(value);
  if (bytes.byteLength <= maxOutputBytes) {
    return { value, truncated: false };
  }
  let captured = '';
  let capturedBytes = 0;
  for (const character of value) {
    const characterBytes = encoder.encode(character).byteLength;
    if (capturedBytes + characterBytes > maxOutputBytes) {
      break;
    }
    captured += character;
    capturedBytes += characterBytes;
  }
  return {
    value: captured,
    truncated: true,
  };
};

const invocationRequestFrom = (
  request: ScriptedCommandRequestInput,
): ScriptedCommandInvocationRequest => ({
  command: request.command,
  args: [...request.args],
  cwd: request.cwd,
  ...(request.env === undefined ? {} : { env: { ...request.env } }),
  ...(request.stdin === undefined ? {} : { stdin: request.stdin }),
  timeoutMs: request.timeoutMs,
  ...(request.maxOutputBytes === undefined
    ? {}
    : { maxOutputBytes: request.maxOutputBytes }),
});

const duration = (outcome: ScriptedCommandOutcome, fallback = 0) =>
  outcome.durationMs ?? fallback;

/**
 * A zero-I/O child-process adapter. Cases are selected by id instead of queue
 * position so independent commands can run concurrently without schedule-bound
 * fixtures.
 */
export class ScriptedProcessAdapter {
  readonly #cases: ReadonlyMap<ScriptedProcessId, ScriptedCommandCase>;
  readonly #caseOrder: ReadonlyArray<ScriptedProcessId>;
  readonly #state: Ref.Ref<ScriptedProcessState>;

  private constructor(
    cases: ReadonlyMap<ScriptedProcessId, ScriptedCommandCase>,
    caseOrder: ReadonlyArray<ScriptedProcessId>,
    state: Ref.Ref<ScriptedProcessState>,
  ) {
    this.#cases = cases;
    this.#caseOrder = caseOrder;
    this.#state = state;
  }

  static make(
    cases: ReadonlyArray<ScriptedCommandCase>,
  ): Effect.Effect<
    ScriptedProcessAdapter,
    Schema.SchemaError | ScriptedProcessDefinitionError
  > {
    return Schema.decodeEffect(scriptedCommandCases, {
      onExcessProperty: 'error',
    })(cases).pipe(
      Effect.flatMap(scripts =>
        Effect.gen(function* () {
          const casesById = new Map<ScriptedProcessId, ScriptedCommandCase>();
          for (const script of scripts) {
            if (casesById.has(script.id)) {
              return yield* Effect.fail(
                new ScriptedProcessDefinitionError({
                  message: `Duplicate child-process script id "${script.id}".`,
                }),
              );
            }
            casesById.set(script.id, script);
          }
          const state = yield* Ref.make<ScriptedProcessState>({
            claimedScriptIds: [],
            activeClaims: [],
            finalizedClaims: [],
            invocations: [],
          });
          return new ScriptedProcessAdapter(
            casesById,
            scripts.map(script => script.id),
            state,
          );
        }),
      ),
    );
  }

  execute(
    scriptId: string,
    request: ScriptedCommandRequest,
  ): Effect.Effect<
    ScriptedCommandResult,
    | Schema.SchemaError
    | UnknownProcessScriptError
    | DuplicateProcessScriptUseError
  > {
    return Schema.decodeEffect(scriptedExecutionRequest, {
      onExcessProperty: 'error',
    })({ scriptId, request }).pipe(
      Effect.flatMap(input =>
        Effect.fromOption(
          Option.fromUndefinedOr(this.#cases.get(input.scriptId)),
          () =>
            new UnknownProcessScriptError({
              scriptId: input.scriptId,
              message: `No child-process outcome is scripted for "${input.scriptId}".`,
            }),
        ).pipe(
          Effect.flatMap(script =>
            Effect.acquireUseRelease(
              this.#claim(input.scriptId, input.request),
              () =>
                Effect.yieldNow.pipe(
                  Effect.andThen(
                    Schema.decodeEffect(ScriptedCommandRequest, {
                      onExcessProperty: 'error',
                    })(input.request).pipe(
                      Effect.flatMap(decodedRequest =>
                        this.#materialize(script.outcome, decodedRequest),
                      ),
                    ),
                  ),
                ),
              claim => this.#finalize(claim),
            ),
          ),
        ),
      ),
    );
  }

  snapshot(): Effect.Effect<ScriptedProcessSnapshot> {
    return Ref.get(this.#state).pipe(
      Effect.map(state => ({
        invocations: this.#orderedInvocations(state.invocations).map(
          invocation => ({
            sequence: invocation.sequence,
            scriptId: invocation.scriptId,
            request: invocationRequestFrom(invocation.request),
          }),
        ),
        activeScriptIds: this.#orderedClaims(state.activeClaims).map(
          claim => claim.scriptId,
        ),
        finalizedScriptIds: this.#orderedClaims(state.finalizedClaims).map(
          claim => claim.scriptId,
        ),
        remainingScriptIds: this.#caseOrder.filter(
          id => !state.claimedScriptIds.includes(id),
        ),
      })),
    );
  }

  assertClean(): Effect.Effect<void, ScriptedProcessInvariantError> {
    return this.snapshot().pipe(
      Effect.flatMap(snapshot => {
        if (snapshot.activeScriptIds.length > 0) {
          return Effect.fail(
            new ScriptedProcessInvariantError({
              message: `Scripted child processes still active: ${snapshot.activeScriptIds.join(', ')}`,
            }),
          );
        }
        if (snapshot.finalizedScriptIds.length !== snapshot.invocations.length) {
          return Effect.fail(
            new ScriptedProcessInvariantError({
              message: 'Every claimed child-process script must finalize exactly once.',
            }),
          );
        }
        return Effect.void;
      }),
    );
  }

  assertExhausted(): Effect.Effect<void, ScriptedProcessInvariantError> {
    return this.snapshot().pipe(
      Effect.flatMap(snapshot =>
        snapshot.remainingScriptIds.length === 0
          ? Effect.void
          : Effect.fail(
              new ScriptedProcessInvariantError({
                message: `Unconsumed child-process scripts: ${snapshot.remainingScriptIds.join(', ')}`,
              }),
            ),
      ),
    );
  }

  #claim(
    scriptId: ScriptedProcessId,
    request: ScriptedCommandRequestInput,
  ): Effect.Effect<ScriptedProcessClaim, DuplicateProcessScriptUseError> {
    return Ref.modify<
      ScriptedProcessState,
      ScriptedProcessClaim | DuplicateProcessScriptUseError
    >(this.#state, state => {
      if (state.claimedScriptIds.includes(scriptId)) {
        return [
          new DuplicateProcessScriptUseError({
            scriptId,
            message: `Child-process script "${scriptId}" was already claimed.`,
          }),
          state,
        ];
      }
      const claim: ScriptedProcessClaim = {
        _tag: 'ScriptedProcessClaim',
        scriptId,
        sequence: this.#caseOrder.indexOf(scriptId),
      };
      return [
        claim,
        {
          ...state,
          claimedScriptIds: [...state.claimedScriptIds, scriptId],
          activeClaims: [...state.activeClaims, claim],
          invocations: [
            ...state.invocations,
            {
              sequence: claim.sequence,
              scriptId,
              request: invocationRequestFrom(request),
            },
          ],
        },
      ];
    }).pipe(
      Effect.flatMap(result =>
        result._tag === 'DuplicateProcessScriptUseError'
          ? Effect.fail(result)
          : Effect.succeed(result),
      ),
    );
  }

  #finalize(claim: ScriptedProcessClaim): Effect.Effect<void> {
    return Ref.update(this.#state, state => ({
      ...state,
      activeClaims: state.activeClaims.filter(
        active => active.sequence !== claim.sequence,
      ),
      finalizedClaims: [...state.finalizedClaims, claim],
    }));
  }

  #orderedClaims(
    claims: ReadonlyArray<ScriptedProcessClaim>,
  ): ReadonlyArray<ScriptedProcessClaim> {
    return this.#caseOrder.flatMap(scriptId =>
      claims
        .filter(claim => claim.scriptId === scriptId)
        .toSorted((left, right) => left.sequence - right.sequence),
    );
  }

  #orderedInvocations(
    invocations: ReadonlyArray<ScriptedCommandInvocation>,
  ): ReadonlyArray<ScriptedCommandInvocation> {
    return this.#caseOrder.flatMap(scriptId =>
      invocations
        .filter(invocation => invocation.scriptId === scriptId)
        .toSorted((left, right) => left.sequence - right.sequence),
    );
  }

  #materialize(
    outcome: ScriptedCommandOutcome,
    request: ScriptedCommandRequest,
  ): Effect.Effect<ScriptedCommandResult> {
    const stdout = capture(outcome.stdout ?? '', request.maxOutputBytes);
    const stderr = capture(outcome.stderr ?? '', request.maxOutputBytes);
    const base = {
      stdout: stdout.value,
      stderr: stderr.value,
      truncated: stdout.truncated || stderr.truncated,
    };

    if (request.signal?.aborted === true) {
      return Schema.decodeEffect(Schema.String)(request.signal.reason).pipe(
        Effect.orElseSucceed(() => 'aborted'),
        Effect.map(reason => ({
          ...base,
          status: 'interrupted',
          reason,
          durationMs: duration(outcome),
        })),
      );
    }

    switch (outcome.kind) {
      case 'exit':
        return Effect.succeed({
          ...base,
          status: 'exited',
          exitCode: outcome.exitCode,
          durationMs: duration(outcome),
        });
      case 'missing-binary':
        return Effect.succeed({
          ...base,
          status: 'missing-binary',
          binary: request.command,
          message: outcome.message ?? `Executable not found: ${request.command}`,
          durationMs: duration(outcome),
        });
      case 'timeout':
        return Effect.succeed({
          ...base,
          status: 'timed-out',
          timeoutMs: request.timeoutMs,
          durationMs: duration(outcome, request.timeoutMs),
        });
      case 'interrupted':
        return Effect.succeed({
          ...base,
          status: 'interrupted',
          reason: outcome.reason ?? 'scripted interruption',
          durationMs: duration(outcome),
        });
    }
  }
}
