import {
  Cause,
  Config,
  Context,
  Effect,
  FileSystem,
  Layer,
  Option,
  Path,
  Queue,
  Schema,
} from 'effect';
import { ScanRecord } from '../shared/domain';
import {
  analyzerRoot,
  runJscpd,
  runOsv,
  runOxlint,
  runStrictestComparator,
  runZizmor,
} from './analyzers';
import { inventoryRepository } from './inventory';
import { boundedDiagnostic, runCommand } from './process';
import { buildScanResult } from './prioritize';
import { RadarStore } from './store';
import { runTraceDecay } from './tracedecay';

class ScanFailure extends Schema.TaggedErrorClass<ScanFailure>()('ScanFailure', {
  message: Schema.String,
}) {}

const performScan = Effect.fn('performScan')(function* (scan: ScanRecord) {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const store = yield* RadarStore;
  const scanRoot = yield* fs.makeTempDirectoryScoped({ prefix: 'codebase-radar-' });
  const repoRoot = pathService.resolve(scanRoot, 'repository');
  const configuredPath = yield* Config.option(Config.string('PATH'));
  const gitEnvironment = {
    PATH: Option.getOrUndefined(configuredPath),
    LANG: 'C.UTF-8',
    HOME: scanRoot,
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_LFS_SKIP_SMUDGE: '1',
    GIT_SSH_COMMAND: 'false',
    NO_COLOR: '1',
  };

  yield* store.updateScan(scan.id, {
    status: 'running',
    progress: 7,
    stage: 'Getting the latest version',
  });
  const clone = yield* runCommand({
    command: 'git',
    args: [
      '-c',
      'protocol.file.allow=never',
      '-c',
      'core.hooksPath=/dev/null',
      'clone',
      '--depth=1',
      '--single-branch',
      '--no-tags',
      '--no-recurse-submodules',
      '--filter=blob:none',
      scan.githubUrl,
      repoRoot,
    ],
    cwd: scanRoot,
    env: gitEnvironment,
    timeoutMs: 65_000,
    maxOutputBytes: 1_000_000,
  });
  if (clone.exitCode !== 0 || clone.timedOut) {
    return yield* new ScanFailure({
      message: `GitHub snapshot could not be cloned: ${boundedDiagnostic(clone.stderr || clone.stdout)}`,
    });
  }
  const [commit, branch] = yield* Effect.all(
    [
      runCommand({
        command: 'git',
        args: ['rev-parse', 'HEAD'],
        cwd: repoRoot,
        env: gitEnvironment,
        timeoutMs: 5_000,
      }),
      runCommand({
        command: 'git',
        args: ['branch', '--show-current'],
        cwd: repoRoot,
        env: gitEnvironment,
        timeoutMs: 5_000,
      }),
    ],
    { concurrency: 'unbounded' },
  );
  if (commit.exitCode !== 0) {
    return yield* new ScanFailure({
      message: 'The cloned snapshot has no resolvable commit.',
    });
  }

  yield* store.updateScan(scan.id, {
    progress: 16,
    stage: 'Reading the codebase',
  });
  const inventory = yield* inventoryRepository(repoRoot);
  if (inventory.sourceFiles.length === 0) {
    return yield* new ScanFailure({
      message: 'No supported TypeScript or JavaScript files were found.',
    });
  }
  const runtimeRoot = yield* analyzerRoot();
  const outputs = [];

  yield* store.updateScan(scan.id, {
    progress: 24,
    stage: 'Checking type safety',
  });
  outputs.push(yield* runStrictestComparator(repoRoot, inventory));

  yield* store.updateScan(scan.id, {
    progress: 34,
    stage: 'Checking code quality',
  });
  outputs.push(yield* runOxlint(repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 47,
    stage: 'Looking for repeated code',
  });
  outputs.push(yield* runJscpd(scanRoot, repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 57,
    stage: 'Checking automation safety',
  });
  outputs.push(yield* runZizmor(repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 65,
    stage: 'Checking known dependency risks',
  });
  outputs.push(yield* runOsv(scanRoot, repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 73,
    stage: 'Mapping change impact',
  });
  outputs.push(
    yield* runTraceDecay({
      scanRoot,
      repoRoot,
      inventory,
      analyzerRoot: runtimeRoot,
    }),
  );

  yield* store.updateScan(scan.id, {
    progress: 89,
    stage: 'Deciding what matters most',
  });
  const previous = yield* store.getPreviousResult(
    scan.owner,
    scan.repository,
    scan.id,
  );
  const result = yield* buildScanResult({
    scanId: scan.id,
    owner: scan.owner,
    repository: scan.repository,
    githubUrl: scan.githubUrl,
    commitSha: commit.stdout.trim(),
    defaultBranch: branch.stdout.trim() || 'default',
    createdAt: scan.createdAt,
    frameworks: inventory.frameworks,
    candidates: outputs.flatMap(output => output.candidates),
    analyzerRuns: outputs.map(output => output.run),
    ...(Option.isSome(previous) ? { previous: previous.value } : {}),
  });
  yield* store.updateScan(scan.id, {
    status: 'completed',
    progress: 100,
    stage: 'Your review is ready',
    result,
  });
});

export class ScanCoordinator extends Context.Service<ScanCoordinator, {
  readonly enqueue: (scan: ScanRecord) => Effect.Effect<void>;
}>()('ScanCoordinator') {}

export const ScanCoordinatorLive = Layer.effect(
  ScanCoordinator,
  Effect.gen(function* () {
    const store = yield* RadarStore;
    const queue = yield* Queue.bounded<ScanRecord>(32);
    yield* Effect.forever(
      Queue.take(queue).pipe(
        Effect.flatMap(scan =>
          performScan(scan).pipe(
            Effect.scoped,
            Effect.catchCause(cause =>
              store
                .updateScan(scan.id, {
                  status: 'failed',
                  progress: 100,
                  stage: 'Scan failed safely',
                  error: boundedDiagnostic(Cause.pretty(cause), 800),
                })
                .pipe(Effect.ignore),
            ),
          ),
        ),
      ),
    ).pipe(Effect.forkScoped);
    return ScanCoordinator.of({
      enqueue: scan => Queue.offer(queue, scan).pipe(Effect.asVoid),
    });
  }),
);
