import { maximalAnalysisViolations } from './analysis-policy';
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
  Ref,
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
import { runCalldiff } from './calldiff';
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
    progress: 44,
    stage: 'Looking for repeated code',
  });
  outputs.push(yield* runJscpd(scanRoot, repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 53,
    stage: 'Tracing repeated call-tree nodes',
  });
  outputs.push(yield* runCalldiff(repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 62,
    stage: 'Checking automation safety',
  });
  outputs.push(yield* runZizmor(repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 70,
    stage: 'Checking known dependency risks',
  });
  outputs.push(yield* runOsv(scanRoot, repoRoot, inventory, runtimeRoot));

  yield* store.updateScan(scan.id, {
    progress: 78,
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

  const policyViolations = maximalAnalysisViolations({
    inventoryTruncated: inventory.truncated,
    analyzerRuns: outputs.map(output => output.run),
  });
  if (policyViolations.length > 0) {
    return yield* new ScanFailure({
      message: `dogfood:max analysis was incomplete: ${policyViolations.join('; ')}`,
    });
  }

  yield* store.updateScan(scan.id, {
    progress: 89,
    stage: 'Deciding what matters most',
  });
  const previous = yield* store.getPreviousResult(
    scan.owner,
    scan.repository,
    { createdAt: scan.createdAt, id: scan.id },
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

export class ScanCapacityUnavailable extends Schema.TaggedErrorClass<ScanCapacityUnavailable>()(
  'ScanCapacityUnavailable',
  { message: Schema.String },
) {}

export class RepositoryScanAlreadyActive extends Schema.TaggedErrorClass<RepositoryScanAlreadyActive>()(
  'RepositoryScanAlreadyActive',
  { message: Schema.String },
) {}

export class ScanAdmissionInvalid extends Schema.TaggedErrorClass<ScanAdmissionInvalid>()(
  'ScanAdmissionInvalid',
  { message: Schema.String },
) {}

export interface ScanAdmission {
  readonly enqueue: (scan: ScanRecord) => Effect.Effect<void, ScanAdmissionInvalid>;
  readonly release: Effect.Effect<void>;
}

export const persistAndAttachScan = <E, R>(
  persist: Effect.Effect<ScanRecord, E, R>,
  attach: (scan: ScanRecord) => Effect.Effect<void, ScanAdmissionInvalid>,
): Effect.Effect<ScanRecord, E | ScanAdmissionInvalid, R> =>
  Effect.uninterruptible(persist.pipe(Effect.tap(attach)));

export class ScanCoordinator extends Context.Service<ScanCoordinator, {
  readonly reserve: (
    owner: string,
    repository: string,
  ) => Effect.Effect<
    ScanAdmission,
    ScanCapacityUnavailable | RepositoryScanAlreadyActive
  >;
}>()('ScanCoordinator') {}

interface AdmissionEntry {
  readonly repositoryKey: string;
  readonly scan?: ScanRecord;
}

interface AdmissionState {
  readonly nextId: number;
  readonly entries: ReadonlyMap<number, AdmissionEntry>;
}

interface QueuedScan {
  readonly admissionId: number;
  readonly scan: ScanRecord;
}

type ReservationResult =
  | { readonly _tag: 'Accepted'; readonly admissionId: number }
  | {
      readonly _tag: 'Rejected';
      readonly error: ScanCapacityUnavailable | RepositoryScanAlreadyActive;
    };

type EnqueueResult =
  | { readonly _tag: 'Accepted' }
  | { readonly _tag: 'Rejected'; readonly error: ScanAdmissionInvalid };

const maximumActiveScans = 32;
const repositoryKey = (owner: string, repository: string) =>
  `${owner.toLowerCase()}/${repository.toLowerCase()}`;

export const ScanCoordinatorLive = Layer.effect(
  ScanCoordinator,
  Effect.gen(function* () {
    const store = yield* RadarStore;
    const queue = yield* Queue.bounded<QueuedScan>(maximumActiveScans);
    const admissions = yield* Ref.make<AdmissionState>({
      nextId: 1,
      entries: new Map(),
    });
    const finishAdmission = (admissionId: number) =>
      Ref.update(admissions, current => {
        const entries = new Map(current.entries);
        entries.delete(admissionId);
        return { ...current, entries };
      });
    const releaseReservation = (admissionId: number) =>
      Ref.update(admissions, current => {
        const entry = current.entries.get(admissionId);
        if (entry?.scan !== undefined) return current;
        const entries = new Map(current.entries);
        entries.delete(admissionId);
        return { ...current, entries };
      });
    // Scope finalizers run last-in-first-out: the worker is interrupted before this
    // finalizer terminalizes only the queued work admitted by this process. Safely
    // reclaiming work after a hard crash requires durable leases and fenced writes.
    yield* Effect.addFinalizer(() =>
      Ref.getAndSet(admissions, { nextId: 1, entries: new Map() }).pipe(
        Effect.flatMap(current =>
          Effect.forEach(
            current.entries.values(),
            entry =>
              entry.scan === undefined
                ? Effect.void
                : store
                    .failScanIfActive(entry.scan.id, {
                      stage: 'Scan stopped before completion',
                      error: 'The scan worker stopped before completion. Submit a new scan.',
                    })
                    .pipe(Effect.ignore),
            { concurrency: 'unbounded', discard: true },
          ),
        ),
      ),
    );
    yield* Effect.forever(
      Queue.take(queue).pipe(
        Effect.flatMap(({ admissionId, scan }) =>
          performScan(scan).pipe(
            Effect.scoped,
            Effect.catchCause(cause =>
              store
                .failScanIfActive(scan.id, {
                  stage: 'Scan failed safely',
                  error: boundedDiagnostic(Cause.pretty(cause), 800),
                })
                .pipe(Effect.ignore),
            ),
            Effect.ensuring(finishAdmission(admissionId)),
          ),
        ),
      ),
    ).pipe(Effect.forkScoped);
    return ScanCoordinator.of({
      reserve: (owner, repository) => {
        const key = repositoryKey(owner, repository);
        return Ref.modify(admissions, (current): readonly [ReservationResult, AdmissionState] => {
          if (current.entries.size >= maximumActiveScans) {
            return [
              {
                _tag: 'Rejected',
                error: new ScanCapacityUnavailable({
                  message: 'All scan slots are currently in use.',
                }),
              },
              current,
            ];
          }
          if (
            [...current.entries.values()].some(
              entry => entry.repositoryKey === key,
            )
          ) {
            return [
              {
                _tag: 'Rejected',
                error: new RepositoryScanAlreadyActive({
                  message: `A scan for ${owner}/${repository} is already active.`,
                }),
              },
              current,
            ];
          }
          const admissionId = current.nextId;
          const entries = new Map(current.entries).set(admissionId, {
            repositoryKey: key,
          });
          return [
            { _tag: 'Accepted', admissionId },
            { nextId: admissionId + 1, entries },
          ];
        }).pipe(
          Effect.flatMap(result =>
            result._tag === 'Rejected'
              ? Effect.fail(result.error)
              : Effect.succeed(result.admissionId),
          ),
          Effect.map(admissionId =>
            ({
              enqueue: scan =>
                Effect.uninterruptible(
                  Ref.modify(
                    admissions,
                    (current): readonly [EnqueueResult, AdmissionState] => {
                      const entry = current.entries.get(admissionId);
                      if (entry === undefined) {
                        return [
                          {
                            _tag: 'Rejected',
                            error: new ScanAdmissionInvalid({
                              message: 'This scan admission is no longer active.',
                            }),
                          },
                          current,
                        ];
                      }
                      if (entry.scan !== undefined) {
                        return [
                          {
                            _tag: 'Rejected',
                            error: new ScanAdmissionInvalid({
                              message: 'This scan admission has already been used.',
                            }),
                          },
                          current,
                        ];
                      }
                      if (repositoryKey(scan.owner, scan.repository) !== key) {
                        return [
                          {
                            _tag: 'Rejected',
                            error: new ScanAdmissionInvalid({
                              message: 'The persisted scan does not match its admission.',
                            }),
                          },
                          current,
                        ];
                      }
                      const entries = new Map(current.entries).set(admissionId, {
                        ...entry,
                        scan,
                      });
                      return [{ _tag: 'Accepted' }, { ...current, entries }];
                    },
                  ).pipe(
                    Effect.flatMap(result =>
                      result._tag === 'Rejected'
                        ? Effect.fail(result.error)
                        : Queue.offer(queue, { admissionId, scan }).pipe(
                            Effect.filterOrFail(
                              accepted => accepted,
                              () =>
                                new ScanAdmissionInvalid({
                                  message: 'The scan queue is no longer available.',
                                }),
                            ),
                            Effect.asVoid,
                            Effect.onError(() => finishAdmission(admissionId)),
                          ),
                    ),
                  ),
                ),
              release: releaseReservation(admissionId),
            }) satisfies ScanAdmission,
          ),
        );
      },
    });
  }),
);
