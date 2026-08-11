import {
  AnalysisIncompleteValue,
  AnalysisInterrupted,
  AnalysisProgressTerminal,
  AnalysisProgressUpdate,
  AnalysisRequestSchema,
  AnalysisSourceRejected,
  AnalysisSourceUnavailable,
  AnalysisViolation,
  ContractLimits,
  ScanProfile,
  ScanResultSchemaVersion,
  ScanSummary,
  SuccessfulScanResult,
  SuccessfulScanResultSchema,
  type AnalysisProgress,
  type AnalysisRequest,
  type AttemptedAnalyzerRun,
} from '@codebase-radar/contracts';
import { Cause, Clock, Context, Deferred, Effect, Exit, Layer, Schema } from 'effect';
import { AnalyzerRuntime } from './internal/analyzers/index.js';
import { runRequiredAnalyzers } from './internal/analyzers/required.js';
import { compareFindings } from './internal/comparison/index.js';
import { inventoryRepository } from './internal/inventory/index.js';
import { evaluatePolicy } from './internal/policy/index.js';
import { prioritize } from './internal/prioritization/index.js';
import {
  SourceMaterializationError,
  SourceMaterializer,
} from './internal/source/index.js';
import {
  WorkspaceAllocator,
  WorkspaceReader,
} from './internal/workspace.js';
import { AnalysisObserver, RadarAnalysis } from './scanner-service.js';

const TotalWork = 11;
const ObserverDeliveryBound = '250 millis';

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const percentage = (completedWork: number) =>
  Math.floor((completedWork / TotalWork) * 100);

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const headlineFor = (fixNow: number, investigate: number, monitor: number) => {
  if (fixNow > 0) {
    return `${fixNow} ${fixNow === 1 ? 'issue needs' : 'issues need'} attention now.`;
  }
  if (investigate > 0) {
    return `Nothing urgent. Start with ${investigate} ${investigate === 1 ? 'check' : 'checks'}.`;
  }
  if (monitor > 0) {
    return `Nothing urgent. Keep an eye on ${monitor} ${monitor === 1 ? 'item' : 'items'}.`;
  }
  return 'Nothing needs attention now.';
};

const expectedCodebaseId = (source: AnalysisRequest['source']) =>
  source._tag === 'LocalDirectorySource'
    ? source.codebaseId
    : `github:${source.owner.toLowerCase()}/${source.repository.toLowerCase()}`;

const incompleteForFindingInventory = (attempts: ReadonlyArray<AttemptedAnalyzerRun>) =>
  new AnalysisIncompleteValue({
    analyzerRuns: attempts,
    violations: [new AnalysisViolation({ code: 'finding_inventory_exceeded' })],
  });

const incompleteForSemanticIntegrity = (attempts: ReadonlyArray<AttemptedAnalyzerRun>) =>
  new AnalysisIncompleteValue({
    analyzerRuns: attempts,
    violations: [new AnalysisViolation({ code: 'runtime_mismatch' })],
  });

const sourceMaterializationFailure = (error: SourceMaterializationError) => {
  if (
    error.reason === 'unsafe-entry' ||
    error.reason === 'nested-repository' ||
    error.reason === 'invalid-identity' ||
    error.reason === 'source-limit-exceeded'
  ) {
    return new AnalysisSourceRejected({
      message: 'The source could not be accepted for canonical analysis.',
    });
  }
  return new AnalysisSourceUnavailable({
    message: 'The source could not be materialized by the approved capability.',
  });
};

const decodeSuccessfulResult = Schema.decodeUnknownEffect(SuccessfulScanResultSchema, {
  onExcessProperty: 'error',
});

const decodeRequest = Schema.decodeUnknownEffect(AnalysisRequestSchema, {
  onExcessProperty: 'error',
});

type ProgressStage =
  | 'preflight'
  | 'materializing'
  | 'inventory'
  | 'analyzing'
  | 'prioritizing'
  | 'comparing';

type TerminalOutcome = 'succeeded' | 'failed' | 'interrupted';

const makeAnalyze = (
  sourceMaterializer: Context.Service.Shape<typeof SourceMaterializer>,
  analyzerRuntime: Context.Service.Shape<typeof AnalyzerRuntime>,
  workspaceReader: Context.Service.Shape<typeof WorkspaceReader>,
  workspaceAllocator: Context.Service.Shape<typeof WorkspaceAllocator>,
) => (rawRequest: AnalysisRequest) =>
  Effect.gen(function* () {
    const observer = yield* AnalysisObserver;
    const request = yield* decodeRequest(rawRequest).pipe(
      Effect.mapError(
        () =>
          new AnalysisSourceRejected({
            message: 'The analysis request did not satisfy the canonical request schema.',
          }),
      ),
    );
    let sequence = 0;
    let completedWork = 0;
    let terminal = false;
    let observerTimedOut = false;
    // Observer effects are detached from the scan's scope. The race only ever
    // waits on an interruptible Deferred/sleep pair, never on the observer's
    // loser; an uninterruptible observer therefore cannot block completion.
    // Once a progress observer exceeds the bound, later progress is disabled.
    // The terminal event gets one separate bounded best-effort delivery, so a
    // hostile observer can leave at most two detached fibers per analysis.
    const observeSafely = (progress: AnalysisProgress, terminalDelivery = false) =>
      Effect.suspend(() => {
        if (observerTimedOut && !terminalDelivery) return Effect.void;
        return Effect.gen(function* () {
          const settled = yield* Deferred.make<void>();
          const delivery = Effect.exit(observer.observe(progress)).pipe(
            Effect.asVoid,
            Effect.ensuring(Deferred.succeed(settled, undefined).pipe(Effect.asVoid)),
          );
          const fiber = yield* delivery.pipe(Effect.forkDetach({ startImmediately: true }));
          const delivered = yield* Effect.raceFirst(
            Deferred.await(settled).pipe(Effect.as(true)),
            Effect.sleep(ObserverDeliveryBound).pipe(Effect.as(false)),
          );
          if (!delivered) {
            if (!terminalDelivery) observerTimedOut = true;
            yield* Effect.sync(() => {
              fiber.interruptUnsafe();
            });
          }
        });
      });
    const emit = (stage: ProgressStage, completed: number) =>
      Effect.gen(function* () {
        completedWork = completed;
        const timestamp = new Date(yield* Clock.currentTimeMillis).toISOString();
        yield* observeSafely(
          new AnalysisProgressUpdate({
            scanId: request.scanId,
            sequence,
            timestamp,
            completedWork,
            totalWork: TotalWork,
            percent: percentage(completedWork),
            stage,
            terminal: false,
          }),
        );
        sequence += 1;
      });
    const emitTerminal = (outcome: TerminalOutcome) =>
      Effect.suspend(() => {
        if (terminal) return Effect.void;
        terminal = true;
        const terminalWork = outcome === 'succeeded' ? TotalWork : completedWork;
        return Effect.gen(function* () {
          const timestamp = new Date(yield* Clock.currentTimeMillis).toISOString();
          yield* observeSafely(
            new AnalysisProgressTerminal({
              scanId: request.scanId,
              sequence,
              timestamp,
              completedWork: terminalWork,
              totalWork: TotalWork,
              percent: percentage(terminalWork),
              stage: 'terminal',
              terminal: true,
              outcome,
            }),
            true,
          );
        });
      });

    const program = Effect.scoped(
      Effect.gen(function* () {
        yield* emit('preflight', 0);
        yield* emit('materializing', 1);
        const materialized = yield* sourceMaterializer.materialize(request.source).pipe(
          Effect.mapError(sourceMaterializationFailure),
        );
        if (materialized.identity.codebaseId !== expectedCodebaseId(request.source)) {
          return yield* Effect.fail(
            new AnalysisSourceRejected({
              message: 'The materialized source did not retain the requested codebase identity.',
            }),
          );
        }
        yield* emit('inventory', 2);
        const inventory = yield* inventoryRepository(materialized.workspace).pipe(
          Effect.provideService(WorkspaceReader, workspaceReader),
          Effect.mapError(
            () =>
              new AnalysisSourceUnavailable({
                message: 'The isolated source workspace could not be inventoried.',
              }),
          ),
        );
        const executions = yield* runRequiredAnalyzers({
          scanId: request.scanId,
          workspace: materialized.workspace,
          inventory,
          onCompleted: (_, completed) => emit('analyzing', completed + 2),
        }).pipe(
          Effect.provideService(AnalyzerRuntime, analyzerRuntime),
          Effect.provideService(WorkspaceAllocator, workspaceAllocator),
        );
        const policy = evaluatePolicy({
          inventory,
          executions,
        });
        if (policy._tag === 'PolicyIncomplete') {
          return yield* Effect.fail(policy.failure);
        }
        yield* emit('prioritizing', 10);
        const prioritized = yield* prioritize(policy.candidates);
        if (prioritized.length > ContractLimits.findings) {
          return yield* Effect.fail(incompleteForFindingInventory(policy.attempts));
        }
        const compared = compareFindings({
          findings: prioritized,
          source: materialized.identity,
          ...(request.baseline === undefined ? {} : { baseline: request.baseline }),
        });
        // Freeze completion before any advisory progress delivery or further
        // pure result shaping. This is the deterministic clock boundary for
        // the scan result rather than a timestamp affected by observer speed.
        const completedAtMillis = yield* Clock.currentTimeMillis;
        const completedAt = new Date(completedAtMillis).toISOString();
        yield* emit('comparing', 10);
        const fixNow = compared.findings.filter(
          finding => finding.action === 'fix now',
        ).length;
        const investigate = compared.findings.filter(
          finding => finding.action === 'investigate',
        ).length;
        const monitor = compared.findings.filter(
          finding => finding.action === 'monitor',
        ).length;
        const doNotFix = compared.findings.filter(
          finding => finding.action === 'do not fix',
        ).length;
        const healthScore = clamp(
          100 -
            compared.findings.reduce(
              (total, finding, index) =>
                total + finding.scores.priority * (index < 5 ? 0.11 : 0.025),
              0,
            ),
        );
        const result = new SuccessfulScanResult({
          schemaVersion: ScanResultSchemaVersion,
          resultKind: 'complete',
          analysisPolicy: 'dogfood:max/v1',
          scanId: request.scanId,
          source: materialized.identity,
          createdAt: request.createdAt,
          completedAt,
          profile: new ScanProfile({
            frameworks: inventory.frameworks,
            languageCoverage: [
              'GitHub Actions',
              'JavaScript',
              'JavaScript lockfiles',
              'TSX/JSX',
              'TypeScript',
            ].sort(compareText),
            limitations: [
              'Agent ranking is an external overlay and cannot change canonical evidence or scores.',
              'Canonical analysis does not execute untrusted dependencies, builds, tests, hooks, submodules, or project executables.',
              'Static analysis and advisories do not prove runtime reachability, exploitability, financial loss, or business impact.',
            ].sort(compareText),
          }),
          summary: new ScanSummary({
            headline: headlineFor(fixNow, investigate, monitor),
            healthScore,
            fixNow,
            investigate,
            monitor,
            doNotFix,
          }),
          findings: compared.findings,
          analyzerRuns: policy.analyzerRuns,
          comparison: compared.comparison,
        });
        return yield* decodeSuccessfulResult(result).pipe(
          Effect.mapError(() => incompleteForSemanticIntegrity(policy.attempts)),
        );
      }),
    );
    const resolveExit = <A, E>(
      exit: Exit.Exit<A, E>,
    ): Effect.Effect<A, E | AnalysisInterrupted> => {
      if (Exit.isSuccess(exit)) {
        return emitTerminal('succeeded').pipe(Effect.as(exit.value));
      }
      if (Cause.hasInterruptsOnly(exit.cause)) {
        return emitTerminal('interrupted').pipe(
          Effect.andThen(
            Effect.fail(
              new AnalysisInterrupted({ message: 'Analysis was interrupted.' }),
            ),
          ),
        );
      }
      return emitTerminal('failed').pipe(
        Effect.andThen(Effect.failCause(exit.cause)),
      );
    };
    return yield* Effect.uninterruptibleMask(restore =>
      Effect.exit(restore(program)).pipe(Effect.flatMap(resolveExit)));
  });

export const makeRadarAnalysisPrivateLive = () =>
  Layer.effect(
    RadarAnalysis,
    Effect.gen(function* () {
      const sourceMaterializer = yield* SourceMaterializer;
      const analyzerRuntime = yield* AnalyzerRuntime;
      const workspaceReader = yield* WorkspaceReader;
      const workspaceAllocator = yield* WorkspaceAllocator;
      return RadarAnalysis.of({
        analyze: makeAnalyze(
          sourceMaterializer,
          analyzerRuntime,
          workspaceReader,
          workspaceAllocator,
        ),
      });
    }),
  );
