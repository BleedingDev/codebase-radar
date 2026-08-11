import {
  AnalysisRuntimeUnavailable,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
import { Context, Effect, Layer, Schema } from 'effect';
import { ProcessRequest, type ProcessOutput } from '../process/index.js';
import { WorkspaceDescriptorHost } from '../workspace.js';
import {
  AnalyzerExecution,
  AnalyzerRuntime,
  type AnalyzerExecutionRequest,
} from './index.js';

const AnalyzerTimeoutMilliseconds = 120_000;
const AnalyzerMaximumOutputBytes = 8 * 1024 * 1024;

const parseJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Json));
const decodeExecution = Schema.decodeUnknownEffect(AnalyzerExecution, {
  onExcessProperty: 'error',
});

const unavailable = (message: string) => new AnalysisRuntimeUnavailable({ message });

const hasCanonicalJsonLine = (value: string) => {
  if (!value.endsWith('\n')) return false;
  const json = value.slice(0, -1);
  return json.length > 0 && json.trim() === json;
};

const executionMatchesRequest = (
  request: AnalyzerExecutionRequest,
  execution: AnalyzerExecution,
) =>
  execution.run.analyzer === request.analyzer &&
  execution.candidates.every(candidate =>
    candidate.evidence.every(evidence => evidence.analyzer === request.analyzer),
  );

const decodeOutput = (
  request: AnalyzerExecutionRequest,
  output: ProcessOutput,
): Effect.Effect<AnalyzerExecution, AnalysisRuntimeUnavailable> => {
  if (output.exitCode !== 0) {
    return Effect.fail(unavailable('The required analyzer process did not exit successfully.'));
  }
  if (output.timedOut) {
    return Effect.fail(unavailable('The required analyzer process timed out.'));
  }
  if (output.truncated) {
    return Effect.fail(unavailable('The required analyzer process output was truncated.'));
  }
  if (output.stderr.length > 0 || !hasCanonicalJsonLine(output.stdout)) {
    return Effect.fail(unavailable('The required analyzer process returned an invalid protocol response.'));
  }
  return parseJson(output.stdout.slice(0, -1)).pipe(
    Effect.flatMap(decodeExecution),
    Effect.flatMap(execution =>
      executionMatchesRequest(request, execution)
        ? Effect.succeed(execution)
        : Effect.fail(unavailable('The required analyzer process returned mismatched evidence.')),
    ),
    Effect.mapError(() => unavailable('The required analyzer process returned an invalid protocol response.')),
  );
};

const processRequestFor = (request: AnalyzerExecutionRequest) =>
  new ProcessRequest({
    analyzer: request.analyzer,
    inventory: request.inventory.analyzerInventory,
    timeoutMs: AnalyzerTimeoutMilliseconds,
    maxOutputBytes: AnalyzerMaximumOutputBytes,
  });

export const makeWorkspaceDescriptorAnalyzerRuntime = (
  host: Context.Service.Shape<typeof WorkspaceDescriptorHost>,
) =>
  AnalyzerRuntime.of({
    run: request => host.runAnalyzer(
      request.workspace,
      request.scratch,
      processRequestFor(request),
    ).pipe(
      Effect.scoped,
      Effect.mapError(() => unavailable('The required analyzer process was unavailable.')),
      Effect.flatMap(output => decodeOutput(request, output)),
    ),
  });

export const AnalyzerRuntimeWorkspaceDescriptorHostLive = Layer.effect(
  AnalyzerRuntime,
  Effect.gen(function* () {
    const host = yield* WorkspaceDescriptorHost;
    return makeWorkspaceDescriptorAnalyzerRuntime(host);
  }),
);
