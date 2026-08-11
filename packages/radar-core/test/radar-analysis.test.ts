import {
  AnalysisIncompleteValue,
  AnalysisInterrupted,
  AnalysisRequest,
  AnalysisRuntimeUnavailable,
  AnalyzerCoverage,
  AttemptedAnalyzerRunValue,
  CommitRevision,
  ContractLimits,
  Evidence,
  GitHubSource,
  GitHubSourceIdentity,
  LocalDirectorySource,
  LocalSourceIdentity,
  RequiredAnalyzerIds,
  isMonotonicProgress,
  type AnalysisProgress,
  type SuccessfulScanResult,
} from '@codebase-radar/contracts';
import { createHash } from 'node:crypto';
import { Clock, Deferred, Effect, Fiber, Layer, Option, Ref } from 'effect';
import { TestClock } from 'effect/testing';
import { describe, expect, it } from 'vitest';
import {
  AnalyzerExecution,
  AnalyzerRuntime,
  FindingCandidate,
} from '../src/internal/analyzers/index.js';
import { ProcessOutput } from '../src/internal/process/index.js';
import {
  SourceMaterializationError,
  SourceMaterializer,
  type MaterializedSource,
} from '../src/internal/source/index.js';
import {
  SourceSnapshot,
  WorkspaceAllocator,
  WorkspaceAllocatorLive,
  WorkspaceDescriptorHost,
  WorkspaceDirectoryBatch,
  WorkspaceDirectoryEntry,
  WorkspaceEntryStat,
  WorkspaceFileDigest,
  WorkspaceQuota,
  WorkspaceReaderLive,
  WorkspaceRelativePath,
  makeLinuxDescriptorWorkspaceHost,
} from '../src/internal/workspace.js';
import type {
  LinuxDescriptorExternalSourceOperations,
  LinuxDescriptorFileWriter,
  LinuxDescriptorReadOperations,
  LinuxDescriptorScratchLease,
  LinuxDescriptorStagingOperations,
  LinuxDescriptorWorkspaceBinding,
  LinuxDescriptorWorkspaceLease,
} from '../src/internal/workspace.js';
import { AnalysisObserver, RadarAnalysis } from '../src/index.js';
import { makeRadarAnalysisPrivateLive } from '../src/scanner-private.js';

const SnapshotDigest = `sha256:${'a'.repeat(64)}`;
const CreatedAt = '2026-08-11T00:00:00.000Z';
const NextCreatedAt = '2026-08-11T00:00:01.000Z';
const DeterministicTimeMillis = Date.parse(CreatedAt);

const source = new LocalDirectorySource({
  directory: '/private/input-repository',
  codebaseId: 'local:example',
});

const sourceIdentity = new LocalSourceIdentity({
  codebaseId: 'local:example',
  repository: 'example',
  snapshotDigest: SnapshotDigest,
  dirty: true,
});

const sourceSnapshot = new SourceSnapshot({
  snapshotDigest: SnapshotDigest,
  fileCount: 2,
  totalBytes: 256,
});

const GitCommitSha = 'c'.repeat(40);
const GitTreeDigest = `sha256:${'d'.repeat(64)}`;

const githubSource = new GitHubSource({
  owner: 'Example',
  repository: 'radar',
  revision: new CommitRevision({ commitSha: GitCommitSha }),
});

const githubIdentity = new GitHubSourceIdentity({
  codebaseId: 'github:example/radar',
  owner: 'Example',
  repository: 'radar',
  url: 'https://github.com/Example/radar',
  commitSha: GitCommitSha,
  defaultBranch: 'main',
  snapshotDigest: `git:${GitCommitSha}`,
});

const githubSnapshot = new SourceSnapshot({
  snapshotDigest: GitTreeDigest,
  fileCount: 2,
  totalBytes: 256,
});

const sourceQuota = new WorkspaceQuota({
  maximumEntries: 128,
  maximumFiles: 64,
  maximumBytes: 1_024 * 1_024,
});

const requestFor = (
  scanId: string,
  createdAt: string,
  baseline?: SuccessfulScanResult,
): AnalysisRequest =>
  new AnalysisRequest({
    scanId,
    source,
    createdAt,
    ...(baseline === undefined ? {} : { baseline }),
  });

const pathText = (path: WorkspaceRelativePath) => path.segments.join('/');

const directory = (name: string) => new WorkspaceDirectoryEntry({
  name,
  kind: 'directory',
});

const file = (name: string) => new WorkspaceDirectoryEntry({ name, kind: 'file' });

const batch = (entries: ReadonlyArray<WorkspaceDirectoryEntry>, truncated = false) =>
  new WorkspaceDirectoryBatch({ entries: [...entries], truncated });

const sourceDigest = () => new WorkspaceFileDigest({
  contentDigest: `sha256:${'b'.repeat(64)}`,
  byteLength: 128,
});

const processOutput = () => new ProcessOutput({
  exitCode: 0,
  stdout: '',
  stderr: '',
  durationMs: 0,
  timedOut: false,
  truncated: false,
});

const pathSetDigest = (paths: ReadonlyArray<string>) =>
  `sha256:${createHash('sha256').update(new TextEncoder().encode(JSON.stringify(paths))).digest('hex')}`;

const auditedPaths = (analyzer: typeof RequiredAnalyzerIds[number]) => {
  if (analyzer === 'strictest-comparator') return ['tsconfig.json'];
  if (analyzer === 'OSV-Scanner') return ['pnpm-lock.yaml'];
  if (analyzer === 'zizmor') return ['.github/workflows/ci.yml'];
  return ['src/index.ts'];
};

const coverageFor = (
  analyzer: typeof RequiredAnalyzerIds[number],
  eligibleFiles = 1,
  analyzedFiles = eligibleFiles,
) => new AnalyzerCoverage({
  eligibleFiles,
  analyzedFiles,
  eligiblePathSetDigest: pathSetDigest(auditedPaths(analyzer).slice(0, eligibleFiles)),
  analyzedPathSetDigest: pathSetDigest(auditedPaths(analyzer).slice(0, analyzedFiles)),
  omittedCapabilities: [],
  warnings: [],
});

interface BindingCounters {
  sourceCloseCount: number;
  sourceSealCount: number;
  scratchCloseCount: number;
}

interface BindingOptions {
  readonly inventoryTruncated?: boolean;
  readonly extraSourceFile?: boolean;
}

const readOperations = (options: BindingOptions): LinuxDescriptorReadOperations => ({
  readDirectory: path => Effect.succeed(
    pathText(path) === ''
      ? batch([
          directory('.github'),
          file('package.json'),
          file('pnpm-lock.yaml'),
          directory('src'),
          file('tsconfig.json'),
        ])
      : pathText(path) === '.github'
        ? batch([directory('workflows')])
        : pathText(path) === '.github/workflows'
          ? batch([file('ci.yml')])
      : pathText(path) === 'src'
        ? batch([
            file('index.ts'),
            ...(options.extraSourceFile === true ? [file('secondary.ts')] : []),
          ])
        : batch([]),
  ),
  stat: path => Effect.succeed(
    pathText(path) === '' ||
        pathText(path) === '.github' ||
        pathText(path) === '.github/workflows' ||
        pathText(path) === 'src'
      ? new WorkspaceEntryStat({ kind: 'directory', byteLength: 0 })
      : new WorkspaceEntryStat({
          kind: 'file',
          byteLength:
            options.inventoryTruncated === true && pathText(path) === 'src/index.ts'
              ? 2 * 1_024 * 1_024 + 1
              : 128,
        }),
  ),
  readText: path => Effect.succeed(
    pathText(path) === 'package.json'
      ? '{"dependencies":{"react":"19.0.0"}}'
      : 'export const stable = true;\n',
  ),
  digestRegularFile: () => Effect.succeed(sourceDigest()),
});

const writer = (): LinuxDescriptorFileWriter => ({
  write: () => Effect.void,
  close: () => Effect.void,
});

const stagingOperations = (options: BindingOptions): LinuxDescriptorStagingOperations => ({
  ...readOperations(options),
  makeDirectory: () => Effect.void,
  openFileWriter: () => Effect.succeed(writer()),
  runGitResolver: () => Effect.succeed(processOutput()),
});

const externalOperations = (
  options: BindingOptions,
): LinuxDescriptorExternalSourceOperations => ({
  ...readOperations(options),
  copyRegularFileTo: () => Effect.succeed(sourceDigest()),
  close: Effect.void,
});

const workspaceLease = (
  counters: BindingCounters,
  options: BindingOptions,
): LinuxDescriptorWorkspaceLease => ({
  staging: stagingOperations(options),
  source: readOperations(options),
  seal: Effect.sync(() => {
    counters.sourceSealCount += 1;
  }),
  close: Effect.sync(() => {
    counters.sourceCloseCount += 1;
  }),
});

const scratchLease = (
  counters: BindingCounters,
  options: BindingOptions,
): LinuxDescriptorScratchLease => ({
  scratch: stagingOperations(options),
  close: Effect.sync(() => {
    counters.scratchCloseCount += 1;
  }),
});

const descriptorBinding = (
  counters: BindingCounters,
  options: BindingOptions,
): LinuxDescriptorWorkspaceBinding => ({
  allocate: () => Effect.succeed(workspaceLease(counters, options)),
  allocateScratch: () => Effect.succeed(scratchLease(counters, options)),
  openExternalSource: () => Effect.succeed(externalOperations(options)),
  runAnalyzer: () => Effect.succeed(processOutput()),
});

const candidateFor = (
  analyzer: typeof RequiredAnalyzerIds[number],
  variant: string,
  fingerprintSeed = 'shared-risk',
) =>
  new FindingCandidate({
    fingerprintSeed,
    mechanism: 'shared-control-flow',
    title: 'Shared control-flow risk',
    category: 'reliability',
    summary: 'A deterministic static signal was observed.',
    technicalSummary: 'Two independent static observations support the same mechanism.',
    recommendation: 'Inspect the affected control-flow path.',
    evidence: [
      new Evidence({
        analyzer,
        kind: 'direct',
        message: `${analyzer} ${variant} observation`,
        path: 'src/index.ts',
        line: variant === 'alpha' ? 3 : 7,
      }),
    ],
    externalReferences: [],
    tags: ['deterministic'],
    consequence: variant === 'alpha' ? 72 : 64,
    blastRadius: 55,
    confidence: variant === 'alpha' ? 73 : 61,
    effort: 30,
    changeExposure: 40,
  });

const completeExecution = (
  analyzer: typeof RequiredAnalyzerIds[number],
  candidates: ReadonlyArray<FindingCandidate>,
) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: 'test-runtime-v1',
      profileVersion: 'dogfood:max/v1',
      status: 'complete',
      durationMs: 1,
      coverage: coverageFor(analyzer),
      observationCount: candidates.length,
    }),
    candidates: [...candidates],
  });

const timedOutExecution = (analyzer: typeof RequiredAnalyzerIds[number]) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: 'test-runtime-v1',
      profileVersion: 'dogfood:max/v1',
      status: 'timed_out',
      durationMs: 1,
      coverage: coverageFor(analyzer),
      observationCount: 0,
      diagnostic: 'The bounded analyzer invocation timed out.',
    }),
    candidates: [],
  });

const incompleteExecution = (
  analyzer: typeof RequiredAnalyzerIds[number],
  status: 'partial' | 'truncated',
) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: 'test-runtime-v1',
      profileVersion: 'dogfood:max/v1',
      status,
      durationMs: 1,
      coverage: coverageFor(analyzer),
      observationCount: 0,
      diagnostic: `The analyzer returned ${status} evidence.`,
    }),
    candidates: [],
  });

const incompleteCoverageExecution = (analyzer: typeof RequiredAnalyzerIds[number]) =>
  new AnalyzerExecution({
    run: new AttemptedAnalyzerRunValue({
      analyzer,
      analyzerVersion: 'test-runtime-v1',
      profileVersion: 'dogfood:max/v1',
      status: 'complete',
      durationMs: 1,
      coverage: coverageFor(analyzer, 2, 1),
      observationCount: 0,
    }),
    candidates: [],
  });

const candidatesOverResultCap = (
  analyzer: typeof RequiredAnalyzerIds[number],
  prefix: string,
) => {
  const candidates = new Array<FindingCandidate>();
  const count = Math.floor(ContractLimits.findings / 2) + 1;
  for (let index = 0; index < count; index += 1) {
    candidates.push(candidateFor(
      analyzer,
      `bulk-${index + 1}`,
      `${prefix}-${index + 1}`,
    ));
  }
  return candidates;
};

const sourceMaterializerLayer = (
  cleanup: Ref.Ref<number>,
  materialized?: Pick<MaterializedSource, 'identity' | 'snapshot'>,
) =>
  Layer.effect(
    SourceMaterializer,
    Effect.gen(function* () {
      const allocator = yield* WorkspaceAllocator;
      const accepted = materialized ?? {
        identity: sourceIdentity,
        snapshot: sourceSnapshot,
      };
      return SourceMaterializer.of({
        materialize: () =>
          Effect.addFinalizer(() => Ref.update(cleanup, count => count + 1)).pipe(
            Effect.andThen(allocator.allocate(sourceQuota)),
            Effect.flatMap(workspace => workspace.seal),
            Effect.map(workspace => ({
              identity: accepted.identity,
              snapshot: accepted.snapshot,
              workspace,
            })),
            Effect.mapError(() => new SourceMaterializationError({
              source: 'local',
              stage: 'workspace',
              reason: 'capability-unavailable',
            })),
          ),
      });
    }),
  );

const observer = (events: Ref.Ref<ReadonlyArray<AnalysisProgress>>) =>
  AnalysisObserver.of({
    observe: progress => Ref.update(events, observed => [...observed, progress]),
  });

const terminalOutcome = (events: ReadonlyArray<AnalysisProgress>) => {
  const terminal = events.at(-1);
  return terminal !== undefined && terminal._tag === 'AnalysisProgressTerminal'
    ? terminal.outcome
    : undefined;
};

interface AnalysisFixture {
  readonly runtime: ReturnType<typeof AnalyzerRuntime.of>;
  readonly cleanup: Ref.Ref<number>;
  readonly counters: BindingCounters;
  readonly options?: BindingOptions;
  readonly materialized?: Pick<MaterializedSource, 'identity' | 'snapshot'>;
}

interface ScanFixture extends AnalysisFixture {
  readonly request: AnalysisRequest;
  readonly observer: ReturnType<typeof AnalysisObserver.of>;
}

const analysisService = (input: AnalysisFixture) =>
  Effect.gen(function* () {
    const host = yield* makeLinuxDescriptorWorkspaceHost(
      descriptorBinding(input.counters, input.options ?? {}),
    );
    const workspaceLayer = Layer.mergeAll(
      WorkspaceAllocatorLive,
      WorkspaceReaderLive,
    ).pipe(Layer.provide(Layer.succeed(WorkspaceDescriptorHost, host)));
    const materializerLayer = sourceMaterializerLayer(
      input.cleanup,
      input.materialized,
    ).pipe(
      Layer.provide(workspaceLayer),
    );
    const dependencies = Layer.mergeAll(
      materializerLayer,
      Layer.succeed(AnalyzerRuntime, input.runtime),
      workspaceLayer,
    );
    const analysisLayer = makeRadarAnalysisPrivateLive().pipe(
      Layer.provide(dependencies),
    );
    return yield* RadarAnalysis.pipe(Effect.provide(analysisLayer));
  });

const scan = (input: ScanFixture) => analysisService(input).pipe(
  Effect.flatMap(analysis => analysis.analyze(input.request).pipe(
    Effect.provideService(AnalysisObserver, input.observer),
  )),
);

describe('RadarAnalysis', () => {
  it('accepts a Git commit identity with a distinct audited tree digest', () =>
    Effect.runPromise(
      Effect.scoped(Effect.gen(function* () {
        const cleanup = yield* Ref.make(0);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Effect.succeed(completeExecution(input.analyzer, [])),
        });
        const result = yield* scan({
          request: new AnalysisRequest({
            scanId: 'scan-github-tree-digest',
            source: githubSource,
            createdAt: CreatedAt,
          }),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
          materialized: { identity: githubIdentity, snapshot: githubSnapshot },
        });
        expect(result.source.snapshotDigest).toBe(`git:${GitCommitSha}`);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('succeeded');
      })),
    ));

  it('resolves the observer separately for each analyze invocation', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const firstEvents = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const secondEvents = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
            Effect.andThen(Effect.succeed(completeExecution(input.analyzer, []))),
          ),
        });
        const analysis = yield* analysisService({ runtime, cleanup, counters });
        const first = yield* analysis.analyze(
          requestFor('scan-observer-first', CreatedAt),
        ).pipe(Effect.provideService(AnalysisObserver, observer(firstEvents)));
        const second = yield* analysis.analyze(
          requestFor('scan-observer-second', NextCreatedAt),
        ).pipe(Effect.provideService(AnalysisObserver, observer(secondEvents)));
        expect(first.scanId).toBe('scan-observer-first');
        expect(second.scanId).toBe('scan-observer-second');
        expect(yield* Ref.get(calls)).toEqual([
          ...RequiredAnalyzerIds,
          ...RequiredAnalyzerIds,
        ]);
        const observedFirst = yield* Ref.get(firstEvents);
        const observedSecond = yield* Ref.get(secondEvents);
        expect(observedFirst.every(event => event.scanId === first.scanId)).toBe(true);
        expect(observedSecond.every(event => event.scanId === second.scanId)).toBe(true);
        expect(terminalOutcome(observedFirst)).toBe('succeeded');
        expect(terminalOutcome(observedSecond)).toBe('succeeded');
        expect(yield* Ref.get(cleanup)).toBe(2);
      }),
    ));

  it('does not let an uninterruptible observer stall completion or terminal delivery', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Effect.succeed(completeExecution(input.analyzer, [])),
        });
        const result = yield* scan({
          request: requestFor('scan-uninterruptible-observer', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: AnalysisObserver.of({
            observe: () => Effect.uninterruptible(Effect.never),
          }),
        }).pipe(Effect.timeoutOption('2 seconds'));
        expect(Option.isSome(result)).toBe(true);
        if (Option.isSome(result)) {
          expect(result.value.scanId).toBe('scan-uninterruptible-observer');
        }
        expect(yield* Ref.get(cleanup)).toBe(1);
      }),
    ));

  it('returns a byte-stable complete result after every required analyzer exactly once', () =>
    Effect.runPromise(
      Effect.scoped(Effect.gen(function* () {
        const firstCalls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const secondCalls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const firstEvents = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const secondEvents = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const firstCleanup = yield* Ref.make(0);
        const secondCleanup = yield* Ref.make(0);
        const firstCounters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const secondCounters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtimeFor = (
          calls: Ref.Ref<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>,
          reverseCandidates: boolean,
          yieldBeforeResult: boolean,
        ) =>
          AnalyzerRuntime.of({
            run: input => {
              const candidates = [
                candidateFor(input.analyzer, 'alpha'),
                candidateFor(input.analyzer, 'beta'),
              ];
              const ordered = reverseCandidates ? [...candidates].reverse() : candidates;
              const record = Ref.update(calls, prior => [...prior, input.analyzer]);
              const execution = Effect.succeed(completeExecution(input.analyzer, ordered));
              return yieldBeforeResult
                ? record.pipe(Effect.andThen(Effect.yieldNow), Effect.andThen(execution))
                : record.pipe(Effect.andThen(execution));
            },
          });
        const firstClock = yield* TestClock.make();
        const secondClock = yield* TestClock.make();
        yield* firstClock.setTime(DeterministicTimeMillis);
        yield* secondClock.setTime(DeterministicTimeMillis);
        const request = requestFor('scan-stable', CreatedAt);
        const first = yield* scan({
          request,
          runtime: runtimeFor(firstCalls, false, false),
          cleanup: firstCleanup,
          counters: firstCounters,
          observer: observer(firstEvents),
        }).pipe(Effect.provideService(Clock.Clock, firstClock));
        const second = yield* scan({
          request,
          runtime: runtimeFor(secondCalls, true, true),
          cleanup: secondCleanup,
          counters: secondCounters,
          observer: observer(secondEvents),
        }).pipe(Effect.provideService(Clock.Clock, secondClock));
        expect(JSON.stringify(first)).toBe(JSON.stringify(second));
        expect(first.findings).toHaveLength(1);
        expect(first.findings[0]?.evidence).toHaveLength(14);
        expect(first.analyzerRuns).toHaveLength(RequiredAnalyzerIds.length);
        expect(yield* Ref.get(firstCalls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(secondCalls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(firstCleanup)).toBe(1);
        expect(yield* Ref.get(secondCleanup)).toBe(1);
        expect(firstCounters.sourceSealCount).toBe(1);
        expect(firstCounters.sourceCloseCount).toBe(1);
        expect(firstCounters.scratchCloseCount).toBe(RequiredAnalyzerIds.length);
        const progress = yield* Ref.get(firstEvents);
        expect(progress).toHaveLength(13);
        expect(progress[0]?.sequence).toBe(0);
        expect(progress.at(-1)?._tag).toBe('AnalysisProgressTerminal');
        expect(terminalOutcome(progress)).toBe('succeeded');
        for (let index = 1; index < progress.length; index += 1) {
          const previous = progress[index - 1];
          const next = progress[index];
          if (previous === undefined || next === undefined) continue;
          expect(previous.sequence + 1).toBe(next.sequence);
          expect(next.completedWork).toBeGreaterThanOrEqual(previous.completedWork);
          expect(isMonotonicProgress(previous, next)).toBe(true);
        }
        const baselineBefore = JSON.stringify(first);
        const baselineEvents = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const baselineCleanup = yield* Ref.make(0);
        const baselineCalls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const baselineCounters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const compared = yield* scan({
          request: requestFor('scan-after-baseline', NextCreatedAt, first),
          runtime: runtimeFor(baselineCalls, true, true),
          cleanup: baselineCleanup,
          counters: baselineCounters,
          observer: observer(baselineEvents),
        });
        expect(JSON.stringify(first)).toBe(baselineBefore);
        expect(compared.comparison.previousScanId).toBe(first.scanId);
        expect(compared.findings[0]?.statusComparedToPrevious).toBe('persistent');
        expect(JSON.stringify(compared)).not.toContain('/private/input-repository');
      })),
    ));

  it('fails closed after recording every analyzer when an analyzer times out', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input =>
            Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
              Effect.andThen(
                Effect.succeed(
                  input.analyzer === 'Calldiff'
                    ? timedOutExecution(input.analyzer)
                    : completeExecution(input.analyzer, []),
                ),
              ),
            ),
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-timeout', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure') {
          expect(outcome.failure).toBeInstanceOf(AnalysisIncompleteValue);
          if (outcome.failure._tag === 'AnalysisIncomplete') {
            expect(outcome.failure.violations).toContainEqual({
              code: 'analyzer_timed_out',
              analyzer: 'Calldiff',
            });
          }
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(counters.sourceCloseCount).toBe(1);
        expect(counters.scratchCloseCount).toBe(RequiredAnalyzerIds.length);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('retains every attempted run and fails closed for partial, truncated, and failed analyzers', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
            Effect.andThen(
              input.analyzer === 'Calldiff'
                ? Effect.succeed(incompleteExecution(input.analyzer, 'partial'))
                : input.analyzer === 'JSCPD'
                  ? Effect.succeed(incompleteExecution(input.analyzer, 'truncated'))
                  : input.analyzer === 'TraceDecay'
                    ? Effect.fail(new AnalysisRuntimeUnavailable({
                        message: 'The fixture runtime failed before producing evidence.',
                      }))
                    : Effect.succeed(completeExecution(input.analyzer, [])),
            ),
          ),
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-strict-analyzer-failures', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure' && outcome.failure._tag === 'AnalysisIncomplete') {
          expect(outcome.failure.analyzerRuns).toHaveLength(RequiredAnalyzerIds.length);
          expect(outcome.failure.violations).toContainEqual({
            code: 'analyzer_partial',
            analyzer: 'Calldiff',
          });
          expect(outcome.failure.violations).toContainEqual({
            code: 'analyzer_truncated',
            analyzer: 'JSCPD',
          });
          expect(outcome.failure.violations).toContainEqual({
            code: 'analyzer_failed',
            analyzer: 'TraceDecay',
          });
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('fails closed when a nominally complete analyzer has incomplete coverage', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
            Effect.andThen(Effect.succeed(
              input.analyzer === 'OSV-Scanner'
                ? incompleteCoverageExecution(input.analyzer)
                : completeExecution(input.analyzer, []),
            )),
          ),
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-incomplete-coverage', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure' && outcome.failure._tag === 'AnalysisIncomplete') {
          expect(outcome.failure.violations).toContainEqual({
            code: 'coverage_incomplete',
            analyzer: 'OSV-Scanner',
          });
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('rejects a self-consistent runtime denominator below audited eligibility', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
            Effect.andThen(Effect.succeed(completeExecution(input.analyzer, []))),
          ),
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-underreported-coverage', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
          options: { extraSourceFile: true },
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure' && outcome.failure._tag === 'AnalysisIncomplete') {
          expect(outcome.failure.violations.map(violation => ({
            code: violation.code,
            analyzer: violation.analyzer,
          }))).toEqual([
            { code: 'coverage_incomplete', analyzer: 'Oxlint + Ultracite' },
            { code: 'coverage_incomplete', analyzer: 'JSCPD' },
            { code: 'coverage_incomplete', analyzer: 'Calldiff' },
            { code: 'coverage_incomplete', analyzer: 'TraceDecay' },
          ]);
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('fails closed when complete analyzer evidence exceeds the canonical finding cap', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input => {
            const candidates = input.analyzer === 'Oxlint + Ultracite'
              ? candidatesOverResultCap(input.analyzer, 'oxlint')
              : input.analyzer === 'Calldiff'
                ? candidatesOverResultCap(input.analyzer, 'calldiff')
                : [];
            const execution = completeExecution(input.analyzer, candidates);
            return Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
              Effect.andThen(Effect.succeed(execution)),
            );
          },
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-oversized-evidence', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure' && outcome.failure._tag === 'AnalysisIncomplete') {
          expect(outcome.failure.violations).toContainEqual({
            code: 'finding_inventory_exceeded',
          });
          expect(outcome.failure.analyzerRuns).toHaveLength(RequiredAnalyzerIds.length);
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('fails closed for a truncated inventory before returning findings', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const calls = yield* Ref.make<ReadonlyArray<typeof RequiredAnalyzerIds[number]>>([]);
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: input =>
            Ref.update(calls, prior => [...prior, input.analyzer]).pipe(
              Effect.andThen(Effect.succeed(completeExecution(input.analyzer, []))),
            ),
        });
        const outcome = yield* Effect.result(scan({
          request: requestFor('scan-truncated-inventory', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
          options: { inventoryTruncated: true },
        }));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure') {
          expect(outcome.failure).toBeInstanceOf(AnalysisIncompleteValue);
          if (outcome.failure._tag === 'AnalysisIncomplete') {
            expect(outcome.failure.violations).toContainEqual({
              code: 'inventory_truncated',
            });
          }
        }
        expect(yield* Ref.get(calls)).toEqual(RequiredAnalyzerIds);
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(counters.sourceCloseCount).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('failed');
      }),
    ));

  it('converts interruption into a typed failure and releases source and scratch scopes', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const started = yield* Deferred.make<void>();
        const events = yield* Ref.make<ReadonlyArray<AnalysisProgress>>([]);
        const cleanup = yield* Ref.make(0);
        const counters: BindingCounters = {
          sourceCloseCount: 0,
          sourceSealCount: 0,
          scratchCloseCount: 0,
        };
        const runtime = AnalyzerRuntime.of({
          run: () => Deferred.succeed(started, undefined).pipe(
            Effect.andThen(Effect.never),
          ),
        });
        const fiber = yield* Effect.forkChild(scan({
          request: requestFor('scan-interrupted', CreatedAt),
          runtime,
          cleanup,
          counters,
          observer: observer(events),
        }));
        yield* Deferred.await(started);
        yield* Fiber.interrupt(fiber);
        const outcome = yield* Effect.result(Fiber.join(fiber));
        expect(outcome._tag).toBe('Failure');
        if (outcome._tag === 'Failure') {
          expect(outcome.failure).toBeInstanceOf(AnalysisInterrupted);
        }
        expect(yield* Ref.get(cleanup)).toBe(1);
        expect(counters.sourceCloseCount).toBe(1);
        expect(counters.scratchCloseCount).toBe(1);
        expect(terminalOutcome(yield* Ref.get(events))).toBe('interrupted');
      }),
    ));
});
