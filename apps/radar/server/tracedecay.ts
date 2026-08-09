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
import { AnalyzerCoverage, AnalyzerRun, Evidence } from '../shared/domain';
import { AnalyzerOutput, FindingCandidate } from './analyzers';
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
  confidence: Schema.String,
  coverage_pct: Schema.Number,
  total_functions: Schema.Number,
}) {}

class TestRiskResult extends Schema.Class<TestRiskResult>('TestRiskResult')({
  summary: TestRiskSummary,
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
    new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'TraceDecay',
        analyzerVersion: '0.0.73',
        profileVersion: 'structural-baseline/v1',
        status: 'partial',
        durationMs,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.sourceFiles.length,
          analyzedFiles: 0,
          omittedCapabilities: ['runtime coverage', 'dynamic dispatch', 'business impact'],
          warnings: [diagnostic],
        }),
        observationCount: 0,
        diagnostic,
      }),
      candidates: [],
    });
  if (!(yield* fs.exists(command))) {
    return partial('Pinned TraceDecay binary was not found.');
  }
  if (
    inventory.sourceFiles.length > 1_500 ||
    inventory.sourceBytes > 20 * 1024 * 1024
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
        timeoutMs: 60_000,
        maxOutputBytes: 2 * 1024 * 1024,
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
      const status =
        statusResult.exitCode === 0
          ? yield* decodeJson(TraceStatus, statusResult.stdout)
          : new TraceStatus({
              file_count: inventory.sourceFiles.length,
              node_count: 0,
              edge_count: 0,
              total_source_bytes: inventory.sourceBytes,
              last_sync_duration_ms: 0,
            });
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
          timeoutMs: 10_000,
          maxOutputBytes: 2 * 1024 * 1024,
        }).pipe(
          Effect.filterOrFail(
            result =>
              result.exitCode === 0 && !result.timedOut && !result.truncated,
            result =>
              new TraceDecayFailure({
                message: result.timedOut
                  ? `${tool}: timed out`
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
        { format: 'json', limit: 20 },
        ComplexityResult,
      );
      const coupling = yield* executeTool(
        'coupling',
        { format: 'json', direction: 'fan_in', limit: 20 },
        CouplingResult,
      );
      const circular = yield* executeTool(
        'circular',
        { format: 'json', max_depth: 10 },
        CircularResult,
      );
      const hotspots = yield* executeTool(
        'hotspots',
        { format: 'json', limit: 20 },
        HotspotResult,
      );
      const testRisk = yield* executeTool(
        'test_risk',
        { format: 'json', limit: 20 },
        TestRiskResult,
      );

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
            .filter(row => row.cyclomatic_complexity >= 15)
            .slice(0, 6)
            .map(row => {
              const findingPath = pathService.isAbsolute(row.file)
                ? repositoryRelative(pathService, repoRoot, row.file)
                : row.file;
              const coupledFiles = couplingByFile.get(findingPath ?? row.file) ?? 0;
              const graphEdges = hotspotByFile.get(findingPath ?? row.file) ?? 0;
              return new FindingCandidate({
                fingerprintSeed: `tracedecay:complexity:${findingPath}:${row.name}:${row.line}`,
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
                tags: ['tracedecay', 'complexity', 'hotspot'],
                consequence: Math.min(82, 35 + row.cyclomatic_complexity),
                blastRadius: Math.min(88, 48 + coupledFiles * 4 + row.fan_in * 2),
                confidence: 82,
                effort: Math.min(82, 42 + row.lines / 4),
                changeExposure: Math.min(90, 50 + graphEdges * 3 + row.fan_out * 2),
              });
            }),
      });

      if (Option.isSome(circular) && circular.value.cycle_count > 0) {
        const cycleCount = circular.value.cycle_count;
        candidates.push(
          new FindingCandidate({
            fingerprintSeed: 'tracedecay:circular:repository',
            title: `${cycleCount} dependency ${cycleCount === 1 ? 'cycle' : 'cycles'} detected`,
            category: 'architecture',
            summary:
              'Circular dependencies make changes harder to isolate and can turn local failures into broader regressions.',
            technicalSummary: `TraceDecay found ${cycleCount} static dependency cycles up to depth 10.`,
            recommendation:
              'Break the smallest high-traffic cycle first by moving the shared contract toward the stable dependency direction.',
            evidence: [
              new Evidence({
                analyzer: 'TraceDecay',
                kind: 'direct',
                message: `${cycleCount} static graph cycles detected`,
              }),
            ],
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
        Option.match(testRisk, { onNone: () => 0, onSome: () => 1 });
      return new AnalyzerOutput({
        run: new AnalyzerRun({
          analyzer: 'TraceDecay',
          analyzerVersion: '0.0.73',
          profileVersion: 'structural-baseline/v1',
          status: warnings.length > 0 ? 'partial' : 'complete',
          durationMs: (yield* Clock.currentTimeMillis) - startedAt,
          coverage: new AnalyzerCoverage({
            eligibleFiles: inventory.sourceFiles.length,
            analyzedFiles: status.file_count,
            omittedCapabilities: [
              'runtime coverage',
              'dynamic dispatch',
              'business impact',
            ],
            warnings,
          }),
          observationCount,
        }),
        candidates,
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
