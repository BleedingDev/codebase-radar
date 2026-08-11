import * as NodeServices from '@effect/platform-node/NodeServices';
import { RequiredAnalyzer } from '@codebase-radar/contracts';
import { ContractLimits } from '@codebase-radar/contracts/primitives';
import { SemanticAnalyzerProcessRequest } from '@codebase-radar/contracts/runtime';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Effect, FileSystem, Schema } from 'effect';
import {
  AnalyzerOutput,
  runJscpd,
  runOsv,
  runOxlint,
  runStrictestComparator,
  runZizmor,
} from './analyzers';
import { materializeAuditedAnalyzerInput } from './analyzer-input';
import { runCalldiff } from './calldiff';
import { RepositoryInventory } from './inventory';
import { runTraceDecay } from './tracedecay';

class SemanticRunnerFailure extends Schema.TaggedErrorClass<SemanticRunnerFailure>()(
  'SemanticRunnerFailure',
  { message: Schema.String },
) {}

const sandboxWorkspaceRoot = '/workspace';
const sandboxScratchRoot = '/scratch';
const sandboxRequestPath = '/run/radar/analyzer-request.json';
const maximumEncodedExecutionBytes = 8 * 1024 * 1024;
const SemanticRunnerServices = NodeServices.layer;
const decodeAnalyzer = Schema.decodeUnknownEffect(RequiredAnalyzer, {
  onExcessProperty: 'error',
});

const requiredScratch = Effect.suspend(() => {
  const scratch = process.env['RADAR_SCRATCH_ROOT'];
  return scratch === sandboxScratchRoot
    ? Effect.succeed(sandboxScratchRoot)
    : Effect.fail(
        new SemanticRunnerFailure({
          message: 'The bounded sandbox scratch root is required.',
        }),
      );
});

const requestFailure = () =>
  new SemanticRunnerFailure({
    message: 'The retained analyzer request was invalid.',
  });

const requiredProcessRequest = Effect.gen(function* () {
  const requestPath = process.env['RADAR_ANALYZER_REQUEST'];
  if (requestPath !== sandboxRequestPath) {
    return yield* Effect.fail(requestFailure());
  }
  const fs = yield* FileSystem.FileSystem;
  const info = yield* fs.stat(sandboxRequestPath).pipe(
    Effect.mapError(requestFailure),
  );
  if (
    info.type !== 'File' ||
    info.size > BigInt(ContractLimits.semanticAnalyzerRequestBytes)
  ) {
    return yield* Effect.fail(requestFailure());
  }
  return yield* fs.readFileString(sandboxRequestPath).pipe(
    Effect.flatMap(
      Schema.decodeEffect(
        Schema.fromJsonString(SemanticAnalyzerProcessRequest),
        { onExcessProperty: 'error' },
      ),
    ),
    Effect.mapError(requestFailure),
  );
});

const requestedAnalyzer = Effect.suspend(() => {
  const arguments_ = process.argv.slice(2);
  return arguments_.length === 2 && arguments_[0] === '--analyzer'
    ? decodeAnalyzer(arguments_[1]).pipe(
        Effect.mapError(
          () =>
            new SemanticRunnerFailure({
              message: 'The analyzer selector is not part of dogfood:max.',
            }),
        ),
      )
    : Effect.fail(
        new SemanticRunnerFailure({
          message: 'Exactly one analyzer selector is required.',
        }),
      );
});

const runtimeRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const materializeInventory = (
  request: SemanticAnalyzerProcessRequest,
) => {
  const eligible = request.inventory.entries.filter(entry =>
    entry.analyzers.includes(request.analyzer),
  );
  const eligiblePaths = eligible.map(entry => entry.path);
  return {
    entries: eligible,
    inventory: new RepositoryInventory({
      files: eligiblePaths,
      sourceFiles: eligiblePaths,
      lockfiles: request.analyzer === 'OSV-Scanner' ? eligiblePaths : [],
      tsconfigs: request.analyzer === 'strictest-comparator' ? eligiblePaths : [],
      workflowFiles: request.analyzer === 'zizmor' ? eligiblePaths : [],
      manifests: [],
      frameworks: request.inventory.frameworks,
      sourceBytes: eligible.reduce((total, entry) => total + entry.byteLength, 0),
      truncated: request.inventory.truncated,
    }),
  };
};

const runSelectedAnalyzer = Effect.fn('runSelectedSemanticAnalyzer')(
  function* (
    analyzer: typeof RequiredAnalyzer.Type,
    repositoryRoot: string,
    scratchRoot: string,
    inventory: RepositoryInventory,
  ) {
    switch (analyzer) {
      case 'strictest-comparator':
        return yield* runStrictestComparator(repositoryRoot, inventory);
      case 'Oxlint + Ultracite':
        return yield* runOxlint(repositoryRoot, inventory, runtimeRoot);
      case 'JSCPD':
        return yield* runJscpd(
          scratchRoot,
          repositoryRoot,
          inventory,
          runtimeRoot,
        );
      case 'Calldiff':
        return yield* runCalldiff(repositoryRoot, inventory, runtimeRoot);
      case 'zizmor':
        return yield* runZizmor(repositoryRoot, inventory, runtimeRoot);
      case 'OSV-Scanner':
        return yield* runOsv(
          scratchRoot,
          repositoryRoot,
          inventory,
          runtimeRoot,
        );
      case 'TraceDecay':
        return yield* runTraceDecay({
          scanRoot: scratchRoot,
          repoRoot: repositoryRoot,
          inventory,
          analyzerRoot: runtimeRoot,
        });
    }
  },
);

const encodeExecution = (output: AnalyzerOutput) =>
  Effect.try({
    try: () => `${JSON.stringify({ run: output.run, candidates: output.candidates })}\n`,
    catch: () =>
      new SemanticRunnerFailure({
        message: 'The analyzer response could not be encoded.',
      }),
  }).pipe(
    Effect.flatMap(encoded =>
      new TextEncoder().encode(encoded).byteLength <= maximumEncodedExecutionBytes
        ? Effect.succeed(encoded)
        : Effect.fail(
            new SemanticRunnerFailure({
              message: 'The analyzer response exceeded its output envelope.',
            }),
          ),
    ),
  );

const program = Effect.scoped(Effect.gen(function* () {
  const analyzer = yield* requestedAnalyzer;
  const request = yield* requiredProcessRequest;
  if (request.analyzer !== analyzer) return yield* Effect.fail(requestFailure());
  const scratchRoot = yield* requiredScratch;
  const repositoryRoot = process.cwd();
  if (repositoryRoot !== sandboxWorkspaceRoot) {
    return yield* Effect.fail(
      new SemanticRunnerFailure({
        message: 'The semantic runner must execute inside the isolated workspace mount.',
      }),
    );
  }
  const materialized = materializeInventory(request);
  const input = yield* materializeAuditedAnalyzerInput({
    sourceRoot: repositoryRoot,
    scratchRoot,
    entries: materialized.entries,
    maximumFiles: ContractLimits.semanticAnalyzerInventoryEntries,
    maximumBytes: materialized.inventory.sourceBytes,
  }).pipe(
    Effect.mapError(
      () =>
        new SemanticRunnerFailure({
          message: 'The audited analyzer input could not be safely materialized.',
        }),
    ),
  );
  const stagedPaths = [...input.stagedPaths];
  const analyzerInventory = new RepositoryInventory({
    files: stagedPaths,
    sourceFiles: stagedPaths,
    lockfiles: analyzer === 'OSV-Scanner' ? stagedPaths : [],
    tsconfigs: analyzer === 'strictest-comparator' ? stagedPaths : [],
    workflowFiles: analyzer === 'zizmor' ? stagedPaths : [],
    manifests: [],
    frameworks: materialized.inventory.frameworks,
    sourceBytes: input.stagedBytes,
    truncated: materialized.inventory.truncated,
    eligiblePathSetDigest: input.eligiblePathSetDigest,
  });
  const output = yield* runSelectedAnalyzer(
    analyzer,
    input.root,
    scratchRoot,
    analyzerInventory,
  );
  const encoded = yield* encodeExecution(
    new AnalyzerOutput({ run: output.run, candidates: output.candidates }),
  );
  yield* Effect.sync(() => {
    process.stdout.write(encoded);
  });
})).pipe(Effect.provide(SemanticRunnerServices));

Effect.runPromise(program).then(
  () => undefined,
  () => {
    process.stderr.write('The verified semantic analyzer failed safely.\n');
    process.exitCode = 1;
  },
);
