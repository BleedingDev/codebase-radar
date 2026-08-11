import { Effect, Option, Ref, Schema } from 'effect';

export const ScriptedAnalyzerRequest = Schema.Struct({
  scanId: Schema.NonEmptyString,
  analyzerId: Schema.NonEmptyString,
});

export type ScriptedAnalyzerRequest = typeof ScriptedAnalyzerRequest.Type;

export const ScriptedAnalyzerRun = Schema.Struct({
  scanId: Schema.NonEmptyString,
  analyzerId: Schema.NonEmptyString,
});

export type ScriptedAnalyzerRun = typeof ScriptedAnalyzerRun.Type;

export const ScriptedAnalyzerOutcome = Schema.Union([
  Schema.Struct({
    status: Schema.Literal('complete'),
    payload: Schema.Json,
    observationCount: Schema.Natural,
  }),
  Schema.Struct({
    status: Schema.Literal('missing-binary'),
    binary: Schema.NonEmptyString,
  }),
  Schema.Struct({
    status: Schema.Literal('malformed-output'),
    rawOutput: Schema.String,
    diagnostic: Schema.String,
  }),
  Schema.Struct({
    status: Schema.Literal('nonzero-exit'),
    exitCode: Schema.Int,
    stderr: Schema.String,
  }),
  Schema.Struct({
    status: Schema.Literal('timed-out'),
    timeoutMs: Schema.Natural,
  }),
  Schema.Struct({
    status: Schema.Literal('truncated'),
    stream: Schema.Literals(['stdout', 'stderr', 'both']),
    captured: Schema.String,
    maxOutputBytes: Schema.Natural,
  }),
  Schema.Struct({
    status: Schema.Literal('interrupted'),
    reason: Schema.String,
  }),
]);

export type ScriptedAnalyzerOutcome = typeof ScriptedAnalyzerOutcome.Type;

export const ScriptedAnalyzerCase = Schema.Struct({
  scanId: Schema.NonEmptyString,
  analyzerId: Schema.NonEmptyString,
  outcome: ScriptedAnalyzerOutcome,
});

export type ScriptedAnalyzerCase = typeof ScriptedAnalyzerCase.Type;

export const AnalyzerCoverage = Schema.Struct({
  status: Schema.Literals(['complete', 'partial', 'none']),
  expectedAnalyzerIds: Schema.Array(Schema.NonEmptyString),
  attemptedAnalyzerIds: Schema.Array(Schema.NonEmptyString),
  completeAnalyzerIds: Schema.Array(Schema.NonEmptyString),
  incompleteAnalyzerIds: Schema.Array(Schema.NonEmptyString),
  missingAnalyzerIds: Schema.Array(Schema.NonEmptyString),
  unexpectedAnalyzerIds: Schema.Array(Schema.NonEmptyString),
});

export type AnalyzerCoverage = typeof AnalyzerCoverage.Type;

export const ScriptedAnalyzerSnapshot = Schema.Struct({
  attemptedRuns: Schema.Array(ScriptedAnalyzerRun),
  activeRuns: Schema.Array(ScriptedAnalyzerRun),
  finalizedRuns: Schema.Array(ScriptedAnalyzerRun),
  remainingRuns: Schema.Array(ScriptedAnalyzerRun),
});

export type ScriptedAnalyzerSnapshot = typeof ScriptedAnalyzerSnapshot.Type;

const scriptedAnalyzerCases = Schema.Array(ScriptedAnalyzerCase);

const analyzerCoverageRequest = Schema.Struct({
  scanId: Schema.NonEmptyString,
  expectedAnalyzerIds: Schema.Array(Schema.NonEmptyString),
});

const scriptedAnalyzerClaim = Schema.Struct({
  _tag: Schema.Literal('ScriptedAnalyzerClaim'),
  scanId: Schema.NonEmptyString,
  analyzerId: Schema.NonEmptyString,
  sequence: Schema.Natural,
});

type ScriptedAnalyzerClaim = typeof scriptedAnalyzerClaim.Type;

const scriptedAnalyzerResult = Schema.Struct({
  claim: scriptedAnalyzerClaim,
  outcome: ScriptedAnalyzerOutcome,
});

const scriptedAnalyzerState = Schema.Struct({
  attemptedClaims: Schema.Array(scriptedAnalyzerClaim),
  activeClaims: Schema.Array(scriptedAnalyzerClaim),
  finalizedClaims: Schema.Array(scriptedAnalyzerClaim),
  results: Schema.Array(scriptedAnalyzerResult),
});

type ScriptedAnalyzerState = typeof scriptedAnalyzerState.Type;

export class ScriptedAnalyzerDefinitionError extends Schema.TaggedErrorClass<ScriptedAnalyzerDefinitionError>()(
  'ScriptedAnalyzerDefinitionError',
  { message: Schema.String },
) {}

export class UnknownAnalyzerScriptError extends Schema.TaggedErrorClass<UnknownAnalyzerScriptError>()(
  'UnknownAnalyzerScriptError',
  {
    scanId: Schema.String,
    analyzerId: Schema.String,
    message: Schema.String,
  },
) {}

export class DuplicateAnalyzerRunError extends Schema.TaggedErrorClass<DuplicateAnalyzerRunError>()(
  'DuplicateAnalyzerRunError',
  {
    scanId: Schema.String,
    analyzerId: Schema.String,
    message: Schema.String,
  },
) {}

export class ScriptedAnalyzerInvariantError extends Schema.TaggedErrorClass<ScriptedAnalyzerInvariantError>()(
  'ScriptedAnalyzerInvariantError',
  { message: Schema.String },
) {}

const sameRun = (
  left: ScriptedAnalyzerRun,
  right: ScriptedAnalyzerRun,
) =>
  left.scanId === right.scanId && left.analyzerId === right.analyzerId;

const runFromClaim = (
  claim: ScriptedAnalyzerClaim,
): ScriptedAnalyzerRun => ({
  scanId: claim.scanId,
  analyzerId: claim.analyzerId,
});

/**
 * A zero-I/O analyzer-runtime double. Cases retain their structured scan and
 * analyzer identity, so delimiter-bearing identifiers remain independent.
 */
export class ScriptedAnalyzerRuntime {
  readonly #cases: ReadonlyMap<
    string,
    ReadonlyMap<string, ScriptedAnalyzerCase>
  >;
  readonly #caseOrder: ReadonlyArray<ScriptedAnalyzerRun>;
  readonly #state: Ref.Ref<ScriptedAnalyzerState>;

  private constructor(
    cases: ReadonlyMap<string, ReadonlyMap<string, ScriptedAnalyzerCase>>,
    caseOrder: ReadonlyArray<ScriptedAnalyzerRun>,
    state: Ref.Ref<ScriptedAnalyzerState>,
  ) {
    this.#cases = cases;
    this.#caseOrder = caseOrder;
    this.#state = state;
  }

  static make(
    cases: ReadonlyArray<ScriptedAnalyzerCase>,
  ): Effect.Effect<
    ScriptedAnalyzerRuntime,
    Schema.SchemaError | ScriptedAnalyzerDefinitionError
  > {
    return Schema.decodeEffect(scriptedAnalyzerCases, {
      onExcessProperty: 'error',
    })(cases).pipe(
      Effect.flatMap(scripts =>
        Effect.gen(function* () {
          const casesByScanId = new Map<
            string,
            Map<string, ScriptedAnalyzerCase>
          >();
          for (const script of scripts) {
            const analyzers = casesByScanId.get(script.scanId);
            if (analyzers === undefined) {
              casesByScanId.set(
                script.scanId,
                new Map([[script.analyzerId, script]]),
              );
              continue;
            }
            if (analyzers.has(script.analyzerId)) {
              return yield* Effect.fail(
                new ScriptedAnalyzerDefinitionError({
                  message: `Duplicate analyzer script for scan "${script.scanId}" and analyzer "${script.analyzerId}".`,
                }),
              );
            }
            analyzers.set(script.analyzerId, script);
          }
          const state = yield* Ref.make<ScriptedAnalyzerState>({
            attemptedClaims: [],
            activeClaims: [],
            finalizedClaims: [],
            results: [],
          });
          return new ScriptedAnalyzerRuntime(
            casesByScanId,
            scripts.map(script => ({
              scanId: script.scanId,
              analyzerId: script.analyzerId,
            })),
            state,
          );
        }),
      ),
    );
  }

  run(
    request: ScriptedAnalyzerRequest,
  ): Effect.Effect<
    ScriptedAnalyzerOutcome,
    | Schema.SchemaError
    | UnknownAnalyzerScriptError
    | DuplicateAnalyzerRunError
  > {
    return Schema.decodeEffect(ScriptedAnalyzerRequest, {
      onExcessProperty: 'error',
    })(request).pipe(
      Effect.flatMap(decodedRequest =>
        Effect.fromOption(
          Option.fromUndefinedOr(
            this.#cases
              .get(decodedRequest.scanId)
              ?.get(decodedRequest.analyzerId),
          ),
          () =>
            new UnknownAnalyzerScriptError({
              scanId: decodedRequest.scanId,
              analyzerId: decodedRequest.analyzerId,
              message: `No analyzer outcome is scripted for scan "${decodedRequest.scanId}" and analyzer "${decodedRequest.analyzerId}".`,
            }),
        ).pipe(
          Effect.flatMap(script =>
            Effect.acquireUseRelease(
              this.#claim(decodedRequest),
              claim =>
                Effect.yieldNow.pipe(
                  Effect.andThen(
                    Effect.uninterruptible(
                      this.#publish(claim, script.outcome).pipe(
                        Effect.as(script.outcome),
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

  coverage(
    scanId: string,
    expectedAnalyzerIds: ReadonlyArray<string>,
  ): Effect.Effect<AnalyzerCoverage, Schema.SchemaError> {
    return Schema.decodeEffect(analyzerCoverageRequest, {
      onExcessProperty: 'error',
    })({ scanId, expectedAnalyzerIds }).pipe(
      Effect.flatMap(input =>
        Ref.get(this.#state).pipe(
          Effect.flatMap(state => {
            const expected = this.#orderedAnalyzerIds(
              input.scanId,
              input.expectedAnalyzerIds,
            );
            const attempts = this.#orderedClaims(state.attemptedClaims)
              .filter(claim => claim.scanId === input.scanId)
              .map(claim => claim.analyzerId);
            const expectedSet = new Set(expected);
            const attemptedSet = new Set(attempts);
            const complete = expected.filter(analyzerId =>
              state.results.some(
                result =>
                  result.claim.scanId === input.scanId &&
                  result.claim.analyzerId === analyzerId &&
                  result.outcome.status === 'complete',
              ),
            );
            const incomplete = expected.filter(
              analyzerId =>
                attemptedSet.has(analyzerId) && !complete.includes(analyzerId),
            );
            const missing = expected.filter(
              analyzerId => !attemptedSet.has(analyzerId),
            );
            const unexpected = attempts.filter(
              analyzerId => !expectedSet.has(analyzerId),
            );
            return Schema.decodeEffect(AnalyzerCoverage)({
              status:
                incomplete.length === 0 &&
                missing.length === 0 &&
                unexpected.length === 0
                  ? 'complete'
                  : attempts.length === 0
                    ? 'none'
                    : 'partial',
              expectedAnalyzerIds: expected,
              attemptedAnalyzerIds: attempts,
              completeAnalyzerIds: complete,
              incompleteAnalyzerIds: incomplete,
              missingAnalyzerIds: missing,
              unexpectedAnalyzerIds: unexpected,
            });
          }),
        ),
      ),
    );
  }

  snapshot(): Effect.Effect<ScriptedAnalyzerSnapshot> {
    return Ref.get(this.#state).pipe(
      Effect.map(state => ({
        attemptedRuns: this.#orderedClaims(state.attemptedClaims).map(
          runFromClaim,
        ),
        activeRuns: this.#orderedClaims(state.activeClaims).map(runFromClaim),
        finalizedRuns: this.#orderedClaims(state.finalizedClaims).map(
          runFromClaim,
        ),
        remainingRuns: this.#caseOrder
          .filter(run => !state.attemptedClaims.some(claim => sameRun(claim, run)))
          .map(run => ({
            scanId: run.scanId,
            analyzerId: run.analyzerId,
          })),
      })),
    );
  }

  assertClean(): Effect.Effect<void, ScriptedAnalyzerInvariantError> {
    return this.snapshot().pipe(
      Effect.flatMap(snapshot => {
        if (snapshot.activeRuns.length > 0) {
          return Effect.fail(
            new ScriptedAnalyzerInvariantError({
              message: `Scripted analyzer runs still active: ${snapshot.activeRuns.map(run => `${run.scanId}/${run.analyzerId}`).join(', ')}`,
            }),
          );
        }
        if (snapshot.finalizedRuns.length !== snapshot.attemptedRuns.length) {
          return Effect.fail(
            new ScriptedAnalyzerInvariantError({
              message: 'Every attempted analyzer run must finalize exactly once.',
            }),
          );
        }
        return Effect.void;
      }),
    );
  }

  assertExhausted(): Effect.Effect<void, ScriptedAnalyzerInvariantError> {
    return this.snapshot().pipe(
      Effect.flatMap(snapshot =>
        snapshot.remainingRuns.length === 0
          ? Effect.void
          : Effect.fail(
              new ScriptedAnalyzerInvariantError({
                message: `Unconsumed analyzer scripts: ${snapshot.remainingRuns.map(run => `${run.scanId}/${run.analyzerId}`).join(', ')}`,
              }),
            ),
      ),
    );
  }

  #claim(
    request: ScriptedAnalyzerRequest,
  ): Effect.Effect<ScriptedAnalyzerClaim, DuplicateAnalyzerRunError> {
    return Ref.modify<
      ScriptedAnalyzerState,
      ScriptedAnalyzerClaim | DuplicateAnalyzerRunError
    >(this.#state, state => {
      if (state.attemptedClaims.some(claim => sameRun(claim, request))) {
        return [
          new DuplicateAnalyzerRunError({
            scanId: request.scanId,
            analyzerId: request.analyzerId,
            message: `Analyzer "${request.analyzerId}" already ran for scan "${request.scanId}".`,
          }),
          state,
        ];
      }
      const claim: ScriptedAnalyzerClaim = {
        _tag: 'ScriptedAnalyzerClaim',
        scanId: request.scanId,
        analyzerId: request.analyzerId,
        sequence: this.#caseOrder.findIndex(run => sameRun(run, request)),
      };
      return [
        claim,
        {
          ...state,
          attemptedClaims: [...state.attemptedClaims, claim],
          activeClaims: [...state.activeClaims, claim],
        },
      ];
    }).pipe(
      Effect.flatMap(result =>
        result._tag === 'DuplicateAnalyzerRunError'
          ? Effect.fail(result)
          : Effect.succeed(result),
      ),
    );
  }

  #publish(
    claim: ScriptedAnalyzerClaim,
    outcome: ScriptedAnalyzerOutcome,
  ): Effect.Effect<void> {
    return Ref.update(this.#state, state => ({
      ...state,
      results: [...state.results, { claim, outcome }],
    }));
  }

  #finalize(claim: ScriptedAnalyzerClaim): Effect.Effect<void> {
    return Ref.update(this.#state, state => ({
      ...state,
      activeClaims: state.activeClaims.filter(
        active => active.sequence !== claim.sequence,
      ),
      finalizedClaims: [...state.finalizedClaims, claim],
    }));
  }

  #orderedClaims(
    claims: ReadonlyArray<ScriptedAnalyzerClaim>,
  ): ReadonlyArray<ScriptedAnalyzerClaim> {
    return this.#caseOrder.flatMap(run =>
      claims
        .filter(claim => sameRun(claim, run))
        .toSorted((left, right) => left.sequence - right.sequence),
    );
  }

  #orderedAnalyzerIds(
    scanId: string,
    analyzerIds: ReadonlyArray<string>,
  ): ReadonlyArray<string> {
    const uniqueAnalyzerIds = Array.from(new Set(analyzerIds));
    const declaredAnalyzerIds = this.#caseOrder
      .filter(
        run =>
          run.scanId === scanId && uniqueAnalyzerIds.includes(run.analyzerId),
      )
      .map(run => run.analyzerId);
    const declaredAnalyzerIdSet = new Set(declaredAnalyzerIds);
    return [
      ...declaredAnalyzerIds,
      ...uniqueAnalyzerIds
        .filter(analyzerId => !declaredAnalyzerIdSet.has(analyzerId))
        .toSorted(),
    ];
  }
}
