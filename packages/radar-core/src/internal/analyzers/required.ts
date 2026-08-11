import {
  AttemptedAnalyzerRunValue,
  EmptyRepositoryPathSetDigest,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
import { Effect, Option, Schema } from 'effect';
import type { RepositoryInventory } from '../inventory/index.js';
import { boundedDiagnostic } from '../process/index.js';
import {
  DefaultAnalyzerScratchQuota,
  WorkspaceAllocator,
} from '../workspace.js';
import type {
  AnalyzerScratchHandle,
  SourceWorkspaceHandle,
} from '../workspace.js';
import { isAnalyzerApplicable } from './applicability.js';
import { AnalyzerExecution, AnalyzerRuntime } from './index.js';

const invalidExecution = (
  analyzer: typeof RequiredAnalyzerIds[number],
  execution: AnalyzerExecution,
  diagnostic: string,
) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: execution.run.analyzerVersion,
      profileVersion: execution.run.profileVersion,
      status: 'failed',
      durationMs: execution.run.durationMs,
      coverage: execution.run.coverage,
      observationCount: execution.run.observationCount,
      diagnostic: boundedDiagnostic(diagnostic),
    }),
    candidates: [],
  });

const unavailableExecution = (
  analyzer: typeof RequiredAnalyzerIds[number],
  diagnostic: string,
) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: 'unavailable-runtime',
      profileVersion: 'dogfood:max/v1',
      status: 'failed',
      durationMs: 0,
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      },
      observationCount: 0,
      diagnostic: boundedDiagnostic(diagnostic),
    }),
    candidates: [],
  });

const candidateEvidenceMatches = (
  analyzer: typeof RequiredAnalyzerIds[number],
  execution: AnalyzerExecution,
) =>
  execution.run.analyzer === analyzer &&
  !(execution.candidates.length > 0 &&
    (execution.run.status === 'not_applicable' || execution.run.observationCount === 0)) &&
  execution.candidates.every(candidate =>
    candidate.evidence.every(evidence => evidence.analyzer === analyzer),
  );

const decodeExecution = Schema.decodeUnknownEffect(AnalyzerExecution, {
  onExcessProperty: 'error',
});

const runOne = (
  scanId: string,
  analyzer: typeof RequiredAnalyzerIds[number],
  workspace: SourceWorkspaceHandle,
  scratch: AnalyzerScratchHandle,
  inventory: RepositoryInventory,
) =>
  Effect.gen(function* () {
    const runtime = yield* AnalyzerRuntime;
    const request = { scanId, analyzer, workspace, scratch, inventory };
    const runtimeResult = yield* Effect.result(runtime.run(request));
    if (runtimeResult._tag === 'Failure') {
      return unavailableExecution(
        analyzer,
        'The required analyzer runtime was unavailable.',
      );
    }
    const decoded = yield* Effect.option(decodeExecution(runtimeResult.success));
    const execution = Option.isSome(decoded)
      ? decoded.value
      : invalidExecution(
          analyzer,
          new AnalyzerExecution({
            run: new AttemptedAnalyzerRunValue({
              analyzer,
              analyzerVersion: 'unverified-runtime-output',
              profileVersion: 'dogfood:max/v1',
              status: 'failed',
              durationMs: 0,
              coverage: {
                eligibleFiles: 0,
                analyzedFiles: 0,
                eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
                analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
                omittedCapabilities: [],
                warnings: [],
              },
              observationCount: 0,
              diagnostic: 'Analyzer output did not satisfy the required schema.',
            }),
            candidates: [],
          }),
          'Analyzer output did not satisfy the required schema.',
        );
    return candidateEvidenceMatches(analyzer, execution) &&
      !(execution.run.status === 'not_applicable' && isAnalyzerApplicable(analyzer, inventory))
      ? execution
      : invalidExecution(
          analyzer,
          execution,
          'Analyzer output was not coherent with inventory applicability or evidence provenance.',
        );
  });

export const runRequiredAnalyzers = Effect.fn('runRequiredAnalyzers')(function* (input: {
  readonly scanId: string;
  readonly workspace: SourceWorkspaceHandle;
  readonly inventory: RepositoryInventory;
  readonly onCompleted: (
    analyzer: typeof RequiredAnalyzerIds[number],
    completed: number,
  ) => Effect.Effect<void>;
}) {
  const workspaceAllocator = yield* WorkspaceAllocator;
  const executions = new Array<AnalyzerExecution>();
  for (const [index, analyzer] of RequiredAnalyzerIds.entries()) {
    const execution = yield* Effect.scoped(
      Effect.gen(function* () {
        const scratch = yield* Effect.result(
          workspaceAllocator.allocateScratch(DefaultAnalyzerScratchQuota),
        );
        if (scratch._tag === 'Failure') {
          return unavailableExecution(
            analyzer,
            'A quota-bound analyzer scratch workspace was unavailable.',
          );
        }
        return yield* runOne(
          input.scanId,
          analyzer,
          input.workspace,
          scratch.success,
          input.inventory,
        );
      }),
    );
    executions.push(execution);
    yield* input.onCompleted(analyzer, index + 1);
  }
  return executions;
});
