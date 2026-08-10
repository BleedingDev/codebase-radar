import {
  Clock,
  Config,
  Effect,
  FileSystem,
  Option,
  Path,
  Schema,
} from 'effect';
import { AnalyzerCoverage, AnalyzerRun, Evidence } from '../shared/domain';
import { AnalyzerOutput, FindingCandidate } from './analyzers';
import { RepositoryInventory } from './inventory';
import { boundedDiagnostic, runCommand } from './process';

class CalldiffDefinition extends Schema.Class<CalldiffDefinition>(
  'CalldiffDefinition',
)({
  path: Schema.String,
  line: Schema.Number,
}) {}

class CalldiffFailedFile extends Schema.Class<CalldiffFailedFile>(
  'CalldiffFailedFile',
)({
  path: Schema.String,
  diagnostic: Schema.String,
}) {}

class CalldiffEntrypoint extends Schema.Class<CalldiffEntrypoint>(
  'CalldiffEntrypoint',
)({
  key: Schema.String,
  path: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  occurrenceCount: Schema.Number,
  pathSamples: Schema.Array(Schema.String),
}) {}

class CalldiffDuplicate extends Schema.Class<CalldiffDuplicate>(
  'CalldiffDuplicate',
)({
  signatureId: Schema.String,
  key: Schema.String,
  label: Schema.String,
  local: Schema.Boolean,
  subtreeNodes: Schema.Number,
  maximumOccurrences: Schema.Number,
  definition: Schema.optional(CalldiffDefinition),
  entrypoints: Schema.Array(CalldiffEntrypoint),
}) {}

class CalldiffReport extends Schema.Class<CalldiffReport>('CalldiffReport')({
  schemaVersion: Schema.Literal('codebase-radar.calldiff-report/v1'),
  calldiffVersion: Schema.Literal('0.4.1'),
  maximumDepth: Schema.Number,
  eligibleFiles: Schema.Number,
  analyzedFiles: Schema.Number,
  functionCount: Schema.Number,
  entrypointCount: Schema.Number,
  failedFiles: Schema.Array(CalldiffFailedFile),
  duplicates: Schema.Array(CalldiffDuplicate),
}) {}

const decodeReport = (text: string) =>
  Schema.decodeEffect(Schema.fromJsonString(CalldiffReport))(text);

export const calldiffCandidates = (report: CalldiffReport) =>
  report.duplicates.map(duplicate => {
    const affectedTrees = duplicate.entrypoints.length;
    const extraOccurrences = Math.max(1, duplicate.maximumOccurrences - 1);
    const evidence = duplicate.entrypoints.map(
      entry =>
        new Evidence({
          analyzer: 'Calldiff',
          kind: 'direct',
          message: `${duplicate.key} occurs ${entry.occurrenceCount} times below ${entry.key}`,
          ruleId: 'repeated-call-tree-node',
          path: entry.path,
          line: entry.line,
          excerpt: entry.pathSamples.join('\n'),
        }),
    );
    return new FindingCandidate({
      fingerprintSeed: `calldiff:${duplicate.key}:${duplicate.signatureId}`,
      title: `${duplicate.key} repeats in ${affectedTrees} call ${affectedTrees === 1 ? 'tree' : 'trees'}`,
      category: 'maintainability',
      summary:
        'The same local callable or expandable call-site node appears more than once below a supported call-tree root. This can signal repeated work or duplicated orchestration, but it still needs semantic review.',
      technicalSummary: `Calldiff expanded ${report.entrypointCount} roots to depth ${report.maximumDepth}. ${duplicate.key} appears up to ${duplicate.maximumOccurrences} times and expands to at most ${duplicate.subtreeNodes} nodes across ${affectedTrees} roots.`,
      recommendation:
        'Inspect the repeated paths, then remove repeated work at their narrowest shared owner only when the calls have the same responsibility and lifetime.',
      evidence,
      tags: [
        'calldiff',
        'call-tree-duplication',
        duplicate.local ? 'local-callable' : 'repeated-subtree',
      ],
      consequence: Math.min(
        76,
        (duplicate.local ? 24 : 14) +
          extraOccurrences * 9 +
          Math.min(18, duplicate.subtreeNodes * 2),
      ),
      blastRadius: Math.min(
        82,
        (duplicate.local ? 28 : 22) +
          affectedTrees * 6 +
          Math.min(18, duplicate.subtreeNodes * 2),
      ),
      confidence: duplicate.local ? 88 : 60,
      effort: Math.min(
        82,
        (duplicate.local ? 30 : 45) +
          duplicate.subtreeNodes * 3 +
          affectedTrees * 2,
      ),
      changeExposure: Math.min(
        86,
        34 + affectedTrees * 6 + duplicate.subtreeNodes * 2,
      ),
    });
  });

const emptyOutput = (
  inventory: RepositoryInventory,
  status: typeof AnalyzerRun.fields.status.Type,
  diagnostic: string,
  durationMs: number,
) =>
  new AnalyzerOutput({
    run: new AnalyzerRun({
      analyzer: 'Calldiff',
      analyzerVersion: '0.4.1',
      profileVersion: 'all-root-call-trees-max/v2',
      status,
      durationMs,
      coverage: new AnalyzerCoverage({
        eligibleFiles: inventory.sourceFiles.length,
        analyzedFiles: 0,
        omittedCapabilities: [
          'dynamic dispatch, generated calls, and runtime-only edges',
          'Vue and Svelte single-file component callables',
          'path evidence beyond 32 samples per root',
        ],
        warnings: [diagnostic],
      }),
      observationCount: 0,
      diagnostic,
    }),
    candidates: [],
  });

export const runCalldiff = Effect.fn('runCalldiff')(function* (
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const script = pathService.resolve(root, 'calldiff-analyzer.mjs');
  const packageEntry = pathService.resolve(
    root,
    'node_modules/calldiff/dist/index.js',
  );
  if (!(yield* fs.exists(script)) || !(yield* fs.exists(packageEntry))) {
    return emptyOutput(
      inventory,
      'partial',
      'Pinned Calldiff runtime was not found.',
      0,
    );
  }
  const startedAt = yield* Clock.currentTimeMillis;
  const configuredPath = yield* Config.option(Config.string('PATH'));
  const environment = {
    PATH: Option.getOrUndefined(configuredPath),
    HOME: pathService.dirname(repoRoot),
    LANG: 'C.UTF-8',
    NO_COLOR: '1',
    CALLDIFF_GRAMMAR_CACHE: pathService.resolve(
      pathService.dirname(repoRoot),
      'calldiff-grammars',
    ),
  };
  const result = yield* runCommand({
    command: process.execPath,
    args: [script, repoRoot],
    cwd: repoRoot,
    env: environment,
    timeoutMs: 120_000,
    maxOutputBytes: 32 * 1024 * 1024,
  });
  const durationMs = (yield* Clock.currentTimeMillis) - startedAt;
  if (result.timedOut) {
    return emptyOutput(
      inventory,
      'timed_out',
      'Calldiff exceeded the 120 second analysis envelope.',
      durationMs,
    );
  }
  if (result.truncated) {
    return emptyOutput(
      inventory,
      'truncated',
      'Calldiff report exceeded the 32 MiB output envelope.',
      durationMs,
    );
  }
  if (result.exitCode !== 0) {
    return emptyOutput(
      inventory,
      'failed',
      boundedDiagnostic(result.stderr || result.stdout),
      durationMs,
    );
  }
  return yield* decodeReport(result.stdout).pipe(
    Effect.map(report => {
      const warnings = report.failedFiles.map(
        failure => `${failure.path}: ${boundedDiagnostic(failure.diagnostic, 180)}`,
      );
      return new AnalyzerOutput({
        run: new AnalyzerRun({
          analyzer: 'Calldiff',
          analyzerVersion: report.calldiffVersion,
          profileVersion: 'all-root-call-trees-max/v2',
          status: warnings.length > 0 ? 'partial' : 'complete',
          durationMs,
          coverage: new AnalyzerCoverage({
            eligibleFiles: report.eligibleFiles,
            analyzedFiles: report.analyzedFiles,
            omittedCapabilities: [
              'dynamic dispatch, generated calls, and runtime-only edges',
              'factory-wrapped callables Calldiff does not identify',
              'Vue and Svelte single-file component callables',
              'path evidence beyond 32 samples per root',
            ],
            warnings,
          }),
          observationCount: report.duplicates.length,
        }),
        candidates: calldiffCandidates(report),
      });
    }),
    Effect.catch(error =>
      Effect.succeed(
        emptyOutput(
          inventory,
          'failed',
          boundedDiagnostic(String(error)),
          durationMs,
        ),
      ),
    ),
  );
});
