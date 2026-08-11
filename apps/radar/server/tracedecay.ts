import {
  Clock,
  Config,
  Effect,
  FileSystem,
  Option,
  Path,
  Schema,
  Stream,
} from 'effect';
import { ChildProcess } from 'effect/unstable/process';
import { Evidence } from '@codebase-radar/contracts';
import {
  completeAnalyzerOutput,
  FindingCandidate,
  incompleteAnalyzerOutput,
  notApplicableAnalyzerOutput,
  pathSetProofAfterExactToolCoverage,
  unprovenPathSetProof,
} from './analyzers';
import { RepositoryInventory, repositoryRelative } from './inventory';
import { boundedDiagnostic, runCommand } from './process';

class TraceDecayFailure extends Schema.TaggedErrorClass<TraceDecayFailure>()(
  'TraceDecayFailure',
  { message: Schema.String },
) {}

class McpTextBlock extends Schema.Class<McpTextBlock>('McpTextBlock')({
  type: Schema.String,
  text: Schema.optional(Schema.String),
}) {}

class McpEnvelope extends Schema.Class<McpEnvelope>('McpEnvelope')({
  content: Schema.Array(McpTextBlock),
}) {}

class TraceStatus extends Schema.Class<TraceStatus>('TraceStatus')({
  file_count: Schema.Number,
  node_count: Schema.Number,
  edge_count: Schema.Number,
  total_source_bytes: Schema.Number,
  last_sync_duration_ms: Schema.Number,
}) {}

class ComplexityRow extends Schema.Class<ComplexityRow>('ComplexityRow')({
  cyclomatic_complexity: Schema.Number,
  fan_in: Schema.Number,
  fan_out: Schema.Number,
  file: Schema.String,
  line: Schema.Number,
  lines: Schema.Number,
  name: Schema.String,
  score: Schema.Number,
}) {}

class ComplexityResult extends Schema.Class<ComplexityResult>(
  'ComplexityResult',
)({
  ranking: Schema.Array(ComplexityRow),
  result_count: Schema.Number,
}) {}

class CircularResult extends Schema.Class<CircularResult>('CircularResult')({
  cycle_count: Schema.Number,
  cycles: Schema.Array(Schema.Array(Schema.String)),
}) {}

class HealthResult extends Schema.Class<HealthResult>('HealthResult')({
  files_analyzed: Schema.Number,
  quality_signal: Schema.Number,
}) {}

class CouplingRow extends Schema.Class<CouplingRow>('CouplingRow')({
  coupled_files: Schema.Number,
  file: Schema.String,
}) {}

class CouplingResult extends Schema.Class<CouplingResult>('CouplingResult')({
  ranking: Schema.Array(CouplingRow),
  result_count: Schema.Number,
}) {}

class HotspotRow extends Schema.Class<HotspotRow>('HotspotRow')({
  file: Schema.String,
  incoming: Schema.Number,
  line: Schema.Number,
  name: Schema.String,
  outgoing: Schema.Number,
  total: Schema.Number,
}) {}

class HotspotResult extends Schema.Class<HotspotResult>('HotspotResult')({
  hotspot_count: Schema.Number,
  hotspots: Schema.Array(HotspotRow),
}) {}

class TestRiskSummary extends Schema.Class<TestRiskSummary>('TestRiskSummary')({
  buckets: Schema.Struct({
    attributed: Schema.Number,
    excluded: Schema.Number,
    orphan_entry: Schema.Number,
    reachable_unattributed: Schema.Number,
  }),
  confidence: Schema.String,
  coverage_pct: Schema.Number,
  total_functions: Schema.Number,
}) {}

class TestRiskResult extends Schema.Class<TestRiskResult>('TestRiskResult')({
  risks: Schema.Array(Schema.Unknown),
  summary: TestRiskSummary,
}) {}

class TraceNode extends Schema.Class<TraceNode>('TraceNode')({
  file: Schema.String,
  id: Schema.String,
  line: Schema.Number,
  name: Schema.String,
}) {}

class RedundancyPair extends Schema.Class<RedundancyPair>('RedundancyPair')({
  a: TraceNode,
  b: TraceNode,
  overlap_kind: Schema.String,
  ranking_score: Schema.Number,
  severity: Schema.String,
  similarity: Schema.Number,
}) {}

class RedundancyResult extends Schema.Class<RedundancyResult>(
  'RedundancyResult',
)({
  pair_count: Schema.Number,
  pairs: Schema.Array(RedundancyPair),
}) {}

class DocSymbol extends Schema.Class<DocSymbol>('DocSymbol')({
  kind: Schema.String,
  line: Schema.Number,
  name: Schema.String,
}) {}

class DocFile extends Schema.Class<DocFile>('DocFile')({
  count: Schema.Number,
  file: Schema.String,
  symbols: Schema.Array(DocSymbol),
}) {}

class DocCoverageResult extends Schema.Class<DocCoverageResult>(
  'DocCoverageResult',
)({
  file_count: Schema.Number,
  files: Schema.Array(DocFile),
  total_undocumented: Schema.Number,
}) {}

class UnsafeMatch extends Schema.Class<UnsafeMatch>('UnsafeMatch')({
  file: Schema.String,
  in_test: Schema.Boolean,
  kind: Schema.String,
  line: Schema.Number,
  source: Schema.optional(Schema.String),
  symbol: Schema.optional(Schema.String),
}) {}

class UnsafeResult extends Schema.Class<UnsafeResult>('UnsafeResult')({
  match_count: Schema.Number,
  matches: Schema.Array(UnsafeMatch),
}) {}

class DeadSymbol extends Schema.Class<DeadSymbol>('DeadSymbol')({
  file: Schema.String,
  kind: Schema.String,
  line: Schema.Number,
  name: Schema.String,
  signature: Schema.String,
}) {}

class DeadCodeResult extends Schema.Class<DeadCodeResult>('DeadCodeResult')({
  dead_code_count: Schema.Number,
  symbols: Schema.Array(DeadSymbol),
}) {}

const decodeJson = <S extends Schema.Constraint>(schema: S, text: string) =>
  Schema.decodeEffect(Schema.fromJsonString(schema))(text);

const parseToolPayload = <S extends Schema.Constraint>(schema: S, stdout: string) =>
  Effect.gen(function* () {
    const envelope = yield* decodeJson(McpEnvelope, stdout);
    const textBlocks = envelope.content.flatMap(item =>
      item.type === 'text' && item.text ? [item.text] : [],
    );
    const decoded = yield* Effect.forEach(textBlocks, text =>
      decodeJson(schema, text).pipe(Effect.option),
    );
    const payloads = decoded.flatMap(result =>
      Option.isSome(result) ? [result.value] : [],
    );
    const payload = Option.fromUndefinedOr(payloads[0]);
    if (payloads.length !== 1 || Option.isNone(payload)) {
      return yield* new TraceDecayFailure({
        message: `Expected one TraceDecay payload, received ${payloads.length}.`,
      });
    }
    return payload.value;
  });

const traceDecayResultLimit = 10_000;

export const traceDecayCountTruncationWarning = (input: {
  readonly tool: string;
  readonly returned: number;
  readonly reported?: number;
  readonly limit: number;
}) => {
  if (input.reported !== undefined && input.returned !== input.reported) {
    return `${input.tool}: returned ${input.returned} of ${input.reported} reported results`;
  }
  return input.returned >= input.limit
    ? `${input.tool}: reached the ${input.limit}-result limit before completeness could be proven`
    : undefined;
};

export const runTraceDecay = Effect.fn('runTraceDecay')(function* (input: {
  readonly scanRoot: string;
  readonly repoRoot: string;
  readonly inventory: RepositoryInventory;
  readonly analyzerRoot: string;
}) {
  const { scanRoot, repoRoot, inventory, analyzerRoot } = input;
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const command = pathService.resolve(analyzerRoot, 'bin/tracedecay');
  const partial = (diagnostic: string, durationMs = 0) =>
    incompleteAnalyzerOutput({
      analyzer: 'TraceDecay',
      analyzerVersion: '0.0.73',
      status: 'partial',
      durationMs,
      eligibleFiles: inventory.sourceFiles.length,
      analyzedFiles: 0,
      observationCount: 0,
      diagnostic,
      warnings: [diagnostic],
      pathSetProof: unprovenPathSetProof(inventory, inventory.sourceFiles),
    });
  if (inventory.sourceFiles.length === 0) {
    return notApplicableAnalyzerOutput({
      analyzer: 'TraceDecay',
      analyzerVersion: '0.0.73',
      durationMs: 0,
      code: 'no-eligible-input',
      message: 'No supported source files were found.',
    });
  }
  if (!(yield* fs.exists(command))) {
    return partial('Pinned TraceDecay binary was not found.');
  }
  if (
    inventory.sourceFiles.length > 8_000 ||
    inventory.sourceBytes > 256 * 1024 * 1024
  ) {
    return partial('Repository exceeds the measured TraceDecay MVP safety envelope.');
  }

  const startedAt = yield* Clock.currentTimeMillis;
  return yield* Effect.scoped(
    Effect.gen(function* () {
      const home = pathService.resolve(scanRoot, 'tracedecay-home');
      const profile = pathService.resolve(scanRoot, 'tracedecay-profile');
      const runtime = pathService.resolve(scanRoot, 'tracedecay-runtime');
      const socket = pathService.resolve(runtime, 'daemon.sock');
      yield* Effect.all(
        [
          fs.makeDirectory(home, { recursive: true, mode: 0o700 }),
          fs.makeDirectory(profile, { recursive: true, mode: 0o700 }),
          fs.makeDirectory(runtime, { recursive: true, mode: 0o700 }),
        ],
        { concurrency: 'unbounded', discard: true },
      );
      const configuredPath = yield* Config.option(Config.string('PATH'));
      const environment = {
        PATH: Option.getOrUndefined(configuredPath),
        LANG: 'C.UTF-8',
        NO_COLOR: '1',
        HOME: home,
        TRACEDECAY_DATA_DIR: profile,
        TRACEDECAY_GLOBAL_DB: pathService.resolve(profile, 'global.db'),
        TRACEDECAY_DAEMON_SOCKET: socket,
        TRACEDECAY_DISABLE_GLOBAL_DB: '1',
        TRACEDECAY_SYNC_AUTO_WATCH: '0',
        TRACEDECAY_SYNC_READ_REFRESH: '0',
        TRACEDECAY_SYNC_SESSION_START_SYNC: '0',
        TRACEDECAY_SYNC_BACKSTOP_INTERVAL_MINS: '0',
        TRACEDECAY_SYNC_AUTO_INIT: '0',
        TRACEDECAY_SYNC_AUTO_TRACK_PR_BRANCHES: '0',
      };
      const daemon = yield* ChildProcess.make(
        command,
        ['daemon', 'run', '--socket', socket],
        {
          cwd: scanRoot,
          env: environment,
          extendEnv: false,
          shell: false,
          detached: true,
          stdin: 'ignore',
          stdout: 'pipe',
          stderr: 'pipe',
          forceKillAfter: '3 seconds',
        },
      );
      yield* Stream.runDrain(daemon.stdout).pipe(Effect.forkScoped);
      yield* Stream.runDrain(daemon.stderr).pipe(Effect.forkScoped);

      let ready = false;
      for (let attempt = 0; attempt < 50 && !ready; attempt += 1) {
        ready = yield* fs.exists(socket);
        if (!ready) yield* Effect.sleep('100 millis');
      }
      if (!ready) {
        return yield* new TraceDecayFailure({
          message: 'TraceDecay daemon did not become ready.',
        });
      }

      const init = yield* runCommand({
        command,
        args: ['init', repoRoot],
        cwd: scanRoot,
        env: environment,
        timeoutMs: 120_000,
        maxOutputBytes: 8 * 1024 * 1024,
      });
      if (init.exitCode !== 0 || init.timedOut) {
        return yield* new TraceDecayFailure({
          message: `TraceDecay init failed: ${boundedDiagnostic(init.stderr || init.stdout)}`,
        });
      }

      const statusResult = yield* runCommand({
        command,
        args: ['status', repoRoot, '--json'],
        cwd: scanRoot,
        env: environment,
        timeoutMs: 10_000,
      });
      if (
        statusResult.exitCode !== 0 ||
        statusResult.timedOut ||
        statusResult.truncated
      ) {
        return yield* new TraceDecayFailure({
          message: `TraceDecay status failed: ${boundedDiagnostic(statusResult.stderr || statusResult.stdout)}`,
        });
      }
      const status = yield* decodeJson(TraceStatus, statusResult.stdout);
      const warnings = new Array<string>();
      const executeTool = <S extends Schema.Constraint>(
        tool: string,
        args: Readonly<Record<string, string | number | boolean>>,
        schema: S,
      ) =>
        runCommand({
          command,
          args: ['tool', '--project', repoRoot, tool, '--args', '-', '--json'],
          cwd: scanRoot,
          env: environment,
          stdin: JSON.stringify(args),
          timeoutMs: 30_000,
          maxOutputBytes: 8 * 1024 * 1024,
        }).pipe(
          Effect.filterOrFail(
            result =>
              result.exitCode === 0 && !result.timedOut && !result.truncated,
            result =>
              new TraceDecayFailure({
                message: result.timedOut
                  ? `${tool}: timed out`
                  : result.truncated
                    ? `${tool}: output exceeded 8 MiB`
                  : `${tool}: ${boundedDiagnostic(result.stderr || result.stdout, 180)}`,
              }),
          ),
          Effect.flatMap(result => parseToolPayload(schema, result.stdout)),
          Effect.match({
            onFailure: failure => {
              warnings.push(failure.message);
              return Option.none();
            },
            onSuccess: Option.some,
          }),
        );

      const health = yield* executeTool(
        'health',
        { format: 'json', details: true },
        HealthResult,
      );
      const complexity = yield* executeTool(
        'complexity',
        { format: 'json', limit: traceDecayResultLimit },
        ComplexityResult,
      );
      const coupling = yield* executeTool(
        'coupling',
        { format: 'json', direction: 'fan_in', limit: traceDecayResultLimit },
        CouplingResult,
      );
      const circular = yield* executeTool(
        'circular',
        { format: 'json', max_depth: 32 },
        CircularResult,
      );
      const hotspots = yield* executeTool(
        'hotspots',
        { format: 'json', limit: traceDecayResultLimit },
        HotspotResult,
      );
      const testRisk = yield* executeTool(
        'test_risk',
        { format: 'json', limit: traceDecayResultLimit, include_tested: true },
        TestRiskResult,
      );
      const redundancy = yield* executeTool(
        'redundancy',
        {
          format: 'json',
          max_pairs: traceDecayResultLimit,
          min_lines: 3,
          similarity_threshold: 0,
          include_naming_only: true,
          include_generated_paths: false,
        },
        RedundancyResult,
      );
      const docCoverage = yield* executeTool(
        'doc_coverage',
        { format: 'json', limit: traceDecayResultLimit },
        DocCoverageResult,
      );
      const unsafePatterns = yield* executeTool(
        'unsafe_patterns',
        { format: 'json', limit: traceDecayResultLimit, exclude_tests: false },
        UnsafeResult,
      );
      const deadCode = yield* executeTool(
        'dead_code',
        { format: 'json', include_public: true },
        DeadCodeResult,
      );

      const countWarnings = [
        Option.match(complexity, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'complexity',
              returned: result.ranking.length,
              reported: result.result_count,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(coupling, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'coupling',
              returned: result.ranking.length,
              reported: result.result_count,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(circular, {
          onNone: () => undefined,
          onSome: result =>
            result.cycles.length !== result.cycle_count
              ? `circular: returned ${result.cycles.length} of ${result.cycle_count} detected cycles`
              : undefined,
        }),
        Option.match(hotspots, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'hotspots',
              returned: result.hotspots.length,
              reported: result.hotspot_count,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(testRisk, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'test_risk',
              returned: result.risks.length,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(redundancy, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'redundancy',
              returned: result.pairs.length,
              reported: result.pair_count,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(docCoverage, {
          onNone: () => undefined,
          onSome: result => {
            const totalSymbols = result.files.reduce(
              (total, file) => total + file.count,
              0,
            );
            return totalSymbols !== result.total_undocumented
              ? `doc_coverage: returned ${totalSymbols} of ${result.total_undocumented} undocumented symbols`
              : traceDecayCountTruncationWarning({
                tool: 'doc_coverage',
                returned: result.files.length,
                reported: result.file_count,
                limit: traceDecayResultLimit,
              });
          },
        }),
        Option.match(unsafePatterns, {
          onNone: () => undefined,
          onSome: result =>
            traceDecayCountTruncationWarning({
              tool: 'unsafe_patterns',
              returned: result.matches.length,
              reported: result.match_count,
              limit: traceDecayResultLimit,
            }),
        }),
        Option.match(deadCode, {
          onNone: () => undefined,
          onSome: result =>
            result.symbols.length !== result.dead_code_count
              ? `dead_code: returned ${result.symbols.length} of ${result.dead_code_count} dead symbols`
              : undefined,
        }),
        status.file_count !== inventory.sourceFiles.length
          ? `status: indexed ${status.file_count} files but the audited TraceDecay inventory contains ${inventory.sourceFiles.length}`
          : undefined,
        Option.match(health, {
          onNone: () => undefined,
          onSome: result =>
            result.files_analyzed !== inventory.sourceFiles.length
              ? `health: analyzed ${result.files_analyzed} files but the audited TraceDecay inventory contains ${inventory.sourceFiles.length}`
              : undefined,
        }),
      ];
      warnings.push(...countWarnings.filter((warning): warning is string => warning !== undefined));

      const couplingByFile = new Map(
        Option.match(coupling, {
          onNone: () => new Array<readonly [string, number]>(),
          onSome: result =>
            result.ranking.map(
              row => [row.file, row.coupled_files] satisfies readonly [string, number],
            ),
        }),
      );
      const hotspotByFile = new Map(
        Option.match(hotspots, {
          onNone: () => new Array<readonly [string, number]>(),
          onSome: result =>
            result.hotspots.map(
              row => [row.file, row.total] satisfies readonly [string, number],
            ),
        }),
      );
      const candidates = Option.match(complexity, {
        onNone: () => new Array<FindingCandidate>(),
        onSome: result =>
          result.ranking
            .filter(row => row.cyclomatic_complexity >= 10)
            .map(row => {
              const findingPath = pathService.isAbsolute(row.file)
                ? repositoryRelative(pathService, repoRoot, row.file)
                : row.file;
              const generated = /(?:test|spec|fixture|snapshot|generated)/iu.test(
                findingPath ?? '',
              );
              const coupledFiles = couplingByFile.get(findingPath ?? row.file) ?? 0;
              const graphEdges = hotspotByFile.get(findingPath ?? row.file) ?? 0;
              return new FindingCandidate({
                fingerprintSeed: `tracedecay:complexity:${findingPath}:${row.name}:${row.line}`,
                mechanism: 'Structural complexity hotspot',
                title: `Structural hotspot: ${row.name}`,
                category: 'maintainability',
                summary:
                  'A complex, connected area concentrates change risk and deserves focused simplification or tests.',
                technicalSummary: `TraceDecay measured cyclomatic complexity ${row.cyclomatic_complexity}, fan-in ${row.fan_in}, fan-out ${row.fan_out}, ${coupledFiles} coupled files, and ${graphEdges} graph edges for ${row.name}.`,
                recommendation:
                  'Inspect callers and attributed tests, then reduce one responsibility at a time without changing external behavior.',
                evidence: [
                  new Evidence({
                    analyzer: 'TraceDecay',
                    kind: 'strong_proxy',
                    message: `Cyclomatic complexity ${row.cyclomatic_complexity}; composite structural score ${row.score}`,
                    path: findingPath,
                    line: row.line,
                  }),
                ],
                externalReferences: [],
                tags: [
                  'tracedecay',
                  'complexity',
                  'hotspot',
                  ...(generated ? ['generated-or-test'] : []),
                ],
                consequence: Math.min(82, 35 + row.cyclomatic_complexity),
                blastRadius: Math.min(88, 48 + coupledFiles * 4 + row.fan_in * 2),
                confidence: 82,
                effort: Math.min(82, 42 + row.lines / 4),
                changeExposure: Math.min(90, 50 + graphEdges * 3 + row.fan_out * 2),
              });
            }),
      });

      if (Option.isSome(coupling)) {
        for (const row of coupling.value.ranking.filter(
          item => item.coupled_files >= 5,
        )) {
          const findingPath = pathService.isAbsolute(row.file)
            ? repositoryRelative(pathService, repoRoot, row.file)
            : row.file;
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:coupling:${findingPath}`,
              mechanism: 'Static file coupling',
              title: `High file coupling: ${findingPath}`,
              category: 'architecture',
              summary:
                'This file is connected to many other files, so local edits can have a wider-than-expected review and regression surface.',
              technicalSummary: `TraceDecay measured ${row.coupled_files} statically coupled files.`,
              recommendation:
                'Inspect the dependency direction and affected tests before changing the file; extract a stable boundary only where responsibilities are genuinely mixed.',
              evidence: [
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: 'strong_proxy',
                  message: `${row.coupled_files} coupled files`,
                  path: findingPath,
                }),
              ],
              externalReferences: [],
              tags: ['tracedecay', 'coupling', 'architecture'],
              consequence: Math.min(76, 30 + row.coupled_files * 3),
              blastRadius: Math.min(92, 40 + row.coupled_files * 5),
              confidence: 78,
              effort: 58,
              changeExposure: Math.min(94, 45 + row.coupled_files * 4),
            }),
          );
        }
      }

      if (Option.isSome(hotspots)) {
        for (const row of hotspots.value.hotspots.filter(item => item.total >= 8)) {
          const findingPath = pathService.isAbsolute(row.file)
            ? repositoryRelative(pathService, repoRoot, row.file)
            : row.file;
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:hotspot:${findingPath}:${row.name}:${row.line}`,
              mechanism: 'Static dependency hotspot',
              title: `Dependency hotspot: ${row.name}`,
              category: 'architecture',
              summary:
                'A highly connected symbol can amplify changes even when its implementation is locally simple.',
              technicalSummary: `TraceDecay measured ${row.incoming} incoming and ${row.outgoing} outgoing graph edges (${row.total} total).`,
              recommendation:
                'Inspect callers, callees, and attributed tests before editing this symbol; keep its public contract narrow.',
              evidence: [
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: 'strong_proxy',
                  message: `${row.total} dependency edges`,
                  path: findingPath,
                  line: row.line,
                }),
              ],
              externalReferences: [],
              tags: ['tracedecay', 'hotspot', 'change-impact'],
              consequence: Math.min(74, 28 + row.total * 2),
              blastRadius: Math.min(94, 38 + row.incoming * 4),
              confidence: 80,
              effort: 48,
              changeExposure: Math.min(96, 44 + row.total * 3),
            }),
          );
        }
      }

      if (Option.isSome(redundancy)) {
        for (const pair of redundancy.value.pairs) {
          const left = pair.a;
          const right = pair.b;
          const heuristic = pair.severity === 'naming_only';
          const generated = [left.file, right.file].some(file =>
            /(?:test|spec|fixture|snapshot|generated)/iu.test(file),
          );
          const confidence =
            pair.severity === 'definite'
              ? 94
              : pair.severity === 'likely'
                ? 72
                : 24;
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:redundancy:${[left.id, right.id].sort().join(':')}`,
              mechanism: 'Structural duplicate candidate',
              title: `${pair.severity === 'definite' ? 'Definite' : pair.severity === 'likely' ? 'Likely' : 'Possible'} duplicate: ${left.name} / ${right.name}`,
              category: 'maintainability',
              summary:
                'Two callable bodies share structural or lexical signals. Consolidation is valuable only when their responsibility and change cadence are also the same.',
              technicalSummary: `TraceDecay pair severity is ${pair.severity} via ${pair.overlap_kind}; ranking score ${pair.ranking_score.toFixed(3)}, similarity ${pair.similarity.toFixed(3)}.`,
              recommendation:
                'Compare intent, callers, and tests. Merge definite same-responsibility duplication; leave coincidental similarity alone.',
              evidence: [
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: heuristic ? 'inference' : 'strong_proxy',
                  message: `${left.name}: ${pair.severity} ${pair.overlap_kind} match`,
                  path: left.file,
                  line: left.line,
                }),
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: heuristic ? 'inference' : 'strong_proxy',
                  message: `${right.name}: matching callable`,
                  path: right.file,
                  line: right.line,
                }),
              ],
              externalReferences: [],
              tags: [
                'tracedecay',
                'redundancy',
                'structural-similarity',
                pair.severity,
                ...(heuristic ? ['heuristic-only'] : []),
                ...(generated ? ['generated-or-test'] : []),
              ],
              consequence: heuristic ? 18 : Math.min(72, 34 + pair.ranking_score * 32),
              blastRadius: heuristic ? 18 : 48,
              confidence,
              effort: 46,
              changeExposure: heuristic ? 24 : 56,
            }),
          );
        }
      }

      if (Option.isSome(deadCode)) {
        for (const symbol of deadCode.value.symbols) {
          const generated = /(?:test|spec|fixture|snapshot|generated)/iu.test(
            symbol.file,
          );
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:dead-code:${symbol.file}:${symbol.name}:${symbol.line}`,
              mechanism: 'Static reachability gap',
              title: `Possibly unreachable: ${symbol.name}`,
              category: 'maintainability',
              summary:
                'The static graph found no incoming edge, but framework registration, JSX, reflection, or external consumers can make this a false positive.',
              technicalSummary: `TraceDecay found no indexed caller for ${symbol.kind} ${symbol.signature}.`,
              recommendation:
                'Search framework and runtime entrypoints before deleting. Remove it only after proving that no supported entry path reaches it.',
              evidence: [
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: 'inference',
                  message: 'No incoming static graph edge',
                  path: symbol.file,
                  line: symbol.line,
                }),
              ],
              externalReferences: [],
              tags: [
                'tracedecay',
                'dead-code',
                'static-reachability-only',
                'heuristic-only',
                ...(generated ? ['generated-or-test'] : []),
              ],
              consequence: 24,
              blastRadius: 24,
              confidence: 42,
              effort: 26,
              changeExposure: 32,
            }),
          );
        }
      }

      if (Option.isSome(docCoverage)) {
        for (const file of docCoverage.value.files.filter(item =>
          /\.(?:[cm]?[jt]sx?|vue|svelte)$/iu.test(item.file),
        )) {
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:doc-coverage:${file.file}`,
              mechanism: 'Public API documentation coverage',
              title: `${file.count} undocumented public symbols in ${file.file}`,
              category: 'maintainability',
              summary:
                'Public code without a concise contract is harder for people and coding agents to use safely.',
              technicalSummary: `TraceDecay reported: ${file.symbols.map(symbol => `${symbol.kind} ${symbol.name}`).join(', ')}.`,
              recommendation:
                'Document behavior, invariants, failure modes, and ownership; avoid comments that merely repeat the signature.',
              evidence: file.symbols.map(
                symbol =>
                  new Evidence({
                    analyzer: 'TraceDecay',
                    kind: 'direct',
                    message: `Undocumented public ${symbol.kind}: ${symbol.name}`,
                    path: file.file,
                    line: symbol.line,
                  }),
              ),
              externalReferences: [],
              tags: ['tracedecay', 'documentation', 'public-contract'],
              consequence: Math.min(50, 18 + file.count * 2),
              blastRadius: Math.min(62, 24 + file.count * 3),
              confidence: 84,
              effort: Math.min(62, 20 + file.count * 2),
              changeExposure: 38,
            }),
          );
        }
      }

      if (Option.isSome(unsafePatterns)) {
        for (const match of unsafePatterns.value.matches) {
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `tracedecay:unsafe:${match.file}:${match.line}:${match.kind}`,
              mechanism: 'Unsafe failure pattern',
              title: `Unsafe failure pattern: ${match.kind}`,
              category: 'reliability',
              summary:
                'This site can panic, remain unfinished, or cross a language safety boundary and deserves explicit review.',
              technicalSummary: `TraceDecay matched ${match.kind}${match.symbol ? ` inside ${match.symbol}` : ''}.`,
              recommendation:
                'Replace avoidable panic paths with typed handling; justify unavoidable unsafe code with a narrow invariant.',
              evidence: [
                new Evidence({
                  analyzer: 'TraceDecay',
                  kind: 'direct',
                  message: `${match.kind} pattern`,
                  path: match.file,
                  line: match.line,
                  excerpt: match.source,
                }),
              ],
              externalReferences: [],
              tags: [
                'tracedecay',
                'unsafe-pattern',
                match.kind,
                ...(match.in_test ? ['generated-or-test'] : []),
              ],
              consequence: match.in_test ? 30 : 72,
              blastRadius: match.in_test ? 22 : 58,
              confidence: 92,
              effort: 34,
              changeExposure: match.in_test ? 20 : 66,
            }),
          );
        }
      }

      if (
        Option.isSome(testRisk) &&
        testRisk.value.summary.total_functions === 0 &&
        testRisk.value.summary.buckets.excluded > 0
      ) {
        const summary = testRisk.value.summary;
        candidates.push(
          new FindingCandidate({
            fingerprintSeed: 'tracedecay:test-risk:excluded',
            mechanism: 'Static test-risk attribution coverage',
            title: `Static test attribution excluded ${summary.buckets.excluded} functions`,
            category: 'reliability',
            summary:
              'The graph could not rank test risk for the indexed functions, so zero reported risks must not be treated like complete test evidence.',
            technicalSummary: `TraceDecay excluded ${summary.buckets.excluded} functions from test-risk ranking and produced a ${summary.confidence} result.`,
            recommendation:
              'Use the complexity and coupling backlog to choose tests until direct and depth-three attribution supports these entrypoints.',
            evidence: [
              new Evidence({
                analyzer: 'TraceDecay',
                kind: 'inference',
                message: `${summary.buckets.excluded} functions excluded from static test-risk attribution`,
              }),
            ],
            externalReferences: [],
            tags: [
              'tracedecay',
              'test-risk',
              'analysis-coverage',
              'heuristic-only',
            ],
            consequence: 34,
            blastRadius: 46,
            confidence: 52,
            effort: 68,
            changeExposure: 54,
          }),
        );
      } else if (
        Option.isSome(testRisk) &&
        testRisk.value.summary.total_functions > 0 &&
        testRisk.value.summary.coverage_pct < 100
      ) {
        const summary = testRisk.value.summary;
        candidates.push(
          new FindingCandidate({
            fingerprintSeed: 'tracedecay:test-risk:repository',
            mechanism: 'Static test attribution coverage',
            title: `Static test attribution covers ${summary.coverage_pct.toFixed(1)}% of functions`,
            category: 'reliability',
            summary:
              'The dependency graph cannot attribute every supported function to a direct or depth-three test path.',
            technicalSummary: `TraceDecay measured ${summary.coverage_pct.toFixed(1)}% static attribution across ${summary.total_functions} functions (${summary.confidence}). This is not executed line or branch coverage.`,
            recommendation:
              'Prioritize tests around high-complexity and high-coupling functions without direct attribution.',
            evidence: [
              new Evidence({
                analyzer: 'TraceDecay',
                kind: 'strong_proxy',
                message: `${summary.coverage_pct.toFixed(1)}% static test attribution`,
              }),
            ],
            externalReferences: [],
            tags: ['tracedecay', 'test-risk', 'static-attribution'],
            consequence: Math.min(76, 40 + (100 - summary.coverage_pct) * 0.3),
            blastRadius: Math.min(82, 42 + summary.total_functions / 5),
            confidence: 70,
            effort: 72,
            changeExposure: 72,
          }),
        );
      }

      if (Option.isSome(circular) && circular.value.cycle_count > 0) {
        const cycleCount = circular.value.cycle_count;
        candidates.push(
          new FindingCandidate({
            fingerprintSeed: 'tracedecay:circular:repository',
            mechanism: 'Static dependency cycle',
            title: `${cycleCount} dependency ${cycleCount === 1 ? 'cycle' : 'cycles'} detected`,
            category: 'architecture',
            summary:
              'Circular dependencies make changes harder to isolate and can turn local failures into broader regressions.',
            technicalSummary: `TraceDecay found ${cycleCount} static dependency cycles up to depth 32.`,
            recommendation:
              'Break the smallest high-traffic cycle first by moving the shared contract toward the stable dependency direction.',
            evidence: [
              new Evidence({
                analyzer: 'TraceDecay',
                kind: 'direct',
                message: `${cycleCount} static graph cycles detected`,
              }),
            ],
            externalReferences: [],
            tags: ['tracedecay', 'cycle', 'architecture'],
            consequence: Math.min(80, 48 + cycleCount * 4),
            blastRadius: Math.min(88, 58 + cycleCount * 3),
            confidence: 86,
            effort: 62,
            changeExposure: 78,
          }),
        );
      }

      const observationCount =
        Option.match(health, { onNone: () => 0, onSome: () => 1 }) +
        Option.match(complexity, {
          onNone: () => 0,
          onSome: result => result.result_count,
        }) +
        Option.match(coupling, {
          onNone: () => 0,
          onSome: result => result.result_count,
        }) +
        Option.match(circular, {
          onNone: () => 0,
          onSome: result => result.cycle_count,
        }) +
        Option.match(hotspots, {
          onNone: () => 0,
          onSome: result => result.hotspot_count,
        }) +
        Option.match(testRisk, {
          onNone: () => 0,
          onSome: result =>
            Math.max(
              1,
              result.summary.total_functions,
              result.summary.buckets.excluded,
            ),
        }) +
        Option.match(redundancy, {
          onNone: () => 0,
          onSome: result => result.pair_count,
        }) +
        Option.match(docCoverage, {
          onNone: () => 0,
          onSome: result => result.total_undocumented,
        }) +
        Option.match(unsafePatterns, {
          onNone: () => 0,
          onSome: result => result.match_count,
        }) +
        Option.match(deadCode, {
          onNone: () => 0,
          onSome: result => result.dead_code_count,
        });
      const durationMs = (yield* Clock.currentTimeMillis) - startedAt;
      const coverageWarnings = [
        'Static structure does not establish runtime coverage, dynamic dispatch, or business impact.',
        ...warnings,
      ];
      if (warnings.length > 0) {
        return incompleteAnalyzerOutput({
          analyzer: 'TraceDecay',
          analyzerVersion: '0.0.73',
          status: 'partial',
          durationMs,
          eligibleFiles: inventory.sourceFiles.length,
          analyzedFiles: status.file_count,
          observationCount,
          diagnostic: 'One or more TraceDecay reports were unavailable.',
          candidates,
          warnings: coverageWarnings,
          pathSetProof: unprovenPathSetProof(
            inventory,
            inventory.sourceFiles,
          ),
        });
      }
      const pathSetProof = pathSetProofAfterExactToolCoverage(
        inventory,
        inventory.sourceFiles,
        inventory.sourceFiles,
      ) ?? unprovenPathSetProof(inventory, inventory.sourceFiles);
      return completeAnalyzerOutput({
        analyzer: 'TraceDecay',
        analyzerVersion: '0.0.73',
        durationMs,
        eligibleFiles: inventory.sourceFiles.length,
        analyzedFiles: status.file_count,
        observationCount,
        candidates,
        warnings: coverageWarnings,
        pathSetProof,
      });
    }),
  ).pipe(
    Effect.catch(error =>
      Clock.currentTimeMillis.pipe(
        Effect.map(now => partial(boundedDiagnostic(String(error)), now - startedAt)),
      ),
    ),
  );
});
