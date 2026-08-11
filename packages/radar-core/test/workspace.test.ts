import { Effect, Fiber, Layer } from 'effect';
import { describe, expect, it } from 'vitest';
import { ProcessOutput } from '../src/internal/process/index.js';
import {
  WorkspaceAllocator,
  WorkspaceAllocatorLive,
  WorkspaceAccessError,
  WorkspaceDescriptorHost,
  WorkspaceDescriptorHostUnavailableLive,
  WorkspaceDirectoryBatch,
  WorkspaceEntryStat,
  WorkspaceFileDigest,
  WorkspaceQuota,
  WorkspaceRelativePath,
  WorkspaceRoot,
  makeLinuxDescriptorWorkspaceHost,
} from '../src/internal/workspace.js';
import type {
  AnalyzerScratchHandle,
  LinuxDescriptorExternalSourceOperations,
  LinuxDescriptorFileWriter,
  LinuxDescriptorReadOperations,
  LinuxDescriptorScratchLease,
  LinuxDescriptorStagingOperations,
  LinuxDescriptorWorkspaceBinding,
  LinuxDescriptorWorkspaceLease,
  SourceWorkspaceHandle,
  StagingWorkspaceHandle,
} from '../src/internal/workspace.js';

const quota = new WorkspaceQuota({
  maximumEntries: 64,
  maximumFiles: 32,
  maximumBytes: 4_096,
});

const emptyBatch = () => new WorkspaceDirectoryBatch({ entries: [], truncated: false });

const fileStat = () => new WorkspaceEntryStat({ kind: 'file', byteLength: 0 });

const emptyDigest = () => new WorkspaceFileDigest({
  contentDigest: `sha256:${'0'.repeat(64)}`,
  byteLength: 0,
});

const processOutput = () => new ProcessOutput({
  exitCode: 0,
  stdout: '',
  stderr: '',
  durationMs: 0,
  timedOut: false,
  truncated: false,
});

const reader = (
  readDirectory: LinuxDescriptorReadOperations['readDirectory'] = () =>
    Effect.succeed(emptyBatch()),
): LinuxDescriptorReadOperations => ({
  readDirectory,
  stat: () => Effect.succeed(fileStat()),
  readText: () => Effect.succeed(''),
  digestRegularFile: () => Effect.succeed(emptyDigest()),
});

const writer = (): LinuxDescriptorFileWriter => ({
  write: () => Effect.void,
  close: () => Effect.void,
});

const staging = (
  readDirectory: LinuxDescriptorReadOperations['readDirectory'] = () =>
    Effect.succeed(emptyBatch()),
): LinuxDescriptorStagingOperations => ({
  ...reader(readDirectory),
  makeDirectory: () => Effect.void,
  openFileWriter: () => Effect.succeed(writer()),
  runGitResolver: () => Effect.succeed(processOutput()),
});

const external = (): LinuxDescriptorExternalSourceOperations => ({
  ...reader(),
  copyRegularFileTo: () => Effect.succeed(emptyDigest()),
  close: Effect.void,
});

interface BindingState {
  closeCount: number;
  sealCount: number;
  scratchCloseCount: number;
}

const binding = (
  state: BindingState,
  sourceReadDirectory: LinuxDescriptorReadOperations['readDirectory'] = () =>
    Effect.succeed(emptyBatch()),
): LinuxDescriptorWorkspaceBinding => {
  const stagingOperations = staging();
  const sourceOperations = reader(sourceReadDirectory);
  const workspaceLease: LinuxDescriptorWorkspaceLease = {
    staging: stagingOperations,
    source: sourceOperations,
    seal: Effect.sync(() => {
      state.sealCount += 1;
    }),
    close: Effect.sync(() => {
      state.closeCount += 1;
    }),
  };
  const scratchLease: LinuxDescriptorScratchLease = {
    scratch: stagingOperations,
    close: Effect.sync(() => {
      state.scratchCloseCount += 1;
    }),
  };
  return {
    allocate: () => Effect.succeed(workspaceLease),
    allocateScratch: () => Effect.succeed(scratchLease),
    openExternalSource: () => Effect.succeed(external()),
    runAnalyzer: () => Effect.succeed(processOutput()),
  };
};

const allocatorLayer = (host: ReturnType<typeof WorkspaceDescriptorHost.of>) =>
  WorkspaceAllocatorLive.pipe(
    Layer.provide(Layer.succeed(WorkspaceDescriptorHost, host)),
  );

const sourceHandle = (
  allocator: ReturnType<typeof WorkspaceAllocator.of>,
) =>
  Effect.gen(function* () {
    const workspace = yield* allocator.allocate(quota);
    return yield* workspace.seal;
  });

describe('descriptor workspace lifecycle', () => {
  it('fails allocation closed with a typed capability error when no native host is installed', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const unavailableAllocator = WorkspaceAllocatorLive.pipe(
          Layer.provide(WorkspaceDescriptorHostUnavailableLive),
        );
        const rejected = yield* Effect.flip(
          Effect.scoped(
            Effect.gen(function* () {
              const allocator = yield* WorkspaceAllocator;
              return yield* allocator.allocate(quota);
            }),
          ).pipe(Effect.provide(unavailableAllocator)),
        );
        expect(rejected.reason).toBe('capability-unavailable');
      }),
    ));

  it('seals write capability, closes exactly once, and rejects a retained source handle', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const state: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        const host = yield* makeLinuxDescriptorWorkspaceHost(binding(state));
        let retained: SourceWorkspaceHandle | undefined;
        let retainedStaging: StagingWorkspaceHandle | undefined;
        yield* Effect.scoped(
          Effect.gen(function* () {
            const allocator = yield* WorkspaceAllocator;
            const workspace = yield* allocator.allocate(quota);
            const stagingHandle = yield* workspace.withHandle(Effect.succeed);
            retainedStaging = stagingHandle;
            const source = yield* workspace.seal;
            retained = source;
            const stale = yield* Effect.flip(host.withStaging(
              stagingHandle,
              operations => operations.makeDirectory(
                new WorkspaceRelativePath({ segments: ['stale'] }),
              ),
            ));
            expect(stale.reason).toBe('staging-sealed');
            yield* host.withSource(
              source,
              operations => operations.readDirectory(WorkspaceRoot, 1),
            );
          }).pipe(Effect.provide(allocatorLayer(host))),
        );
        expect(state.sealCount).toBe(1);
        expect(state.closeCount).toBe(1);
        if (retainedStaging !== undefined) {
          const closedStaging = yield* Effect.flip(host.withStaging(
            retainedStaging,
            operations => operations.makeDirectory(
              new WorkspaceRelativePath({ segments: ['after-scope'] }),
            ),
          ));
          expect(closedStaging.reason).toBe('workspace-closed');
        }
        if (retained === undefined) return;
        const closed = yield* Effect.flip(host.withSource(
          retained,
          operations => operations.readDirectory(WorkspaceRoot, 1),
        ));
        expect(closed.reason).toBe('workspace-closed');
      }),
    ));

  it('preserves a descriptor failure while scope finalization closes the lease', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const state: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        const host = yield* makeLinuxDescriptorWorkspaceHost(binding(
          state,
          () => Effect.fail(new WorkspaceAccessError({
            operation: 'read-directory',
            reason: 'unsafe-entry',
          })),
        ));
        yield* Effect.scoped(
          Effect.gen(function* () {
            const allocator = yield* WorkspaceAllocator;
            const source = yield* sourceHandle(allocator);
            const rejected = yield* Effect.flip(host.withSource(
              source,
              operations => operations.readDirectory(WorkspaceRoot, 1),
            ));
            expect(rejected.reason).toBe('unsafe-entry');
          }).pipe(Effect.provide(allocatorLayer(host))),
        );
        expect(state.closeCount).toBe(1);
      }),
    ));

  it('serializes an interrupted descriptor read with scope cleanup and leaves no live lease', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const state: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        let readStarted = false;
        const host = yield* makeLinuxDescriptorWorkspaceHost(binding(
          state,
          () => Effect.sync(() => {
            readStarted = true;
          }).pipe(Effect.andThen(Effect.never)),
        ));
        let retained: SourceWorkspaceHandle | undefined;
        const running = yield* Effect.scoped(
          Effect.gen(function* () {
            const allocator = yield* WorkspaceAllocator;
            const source = yield* sourceHandle(allocator);
            retained = source;
            return yield* host.withSource(
              source,
              operations => operations.readDirectory(WorkspaceRoot, 1),
            );
          }).pipe(Effect.provide(allocatorLayer(host))),
        ).pipe(Effect.forkChild);
        yield* Effect.whileLoop({
          while: () => !readStarted,
          body: () => Effect.yieldNow,
          step: () => undefined,
        });
        yield* Fiber.interrupt(running);
        expect(state.closeCount).toBe(1);
        if (retained === undefined) return;
        const closed = yield* Effect.flip(host.withSource(
          retained,
          operations => operations.readDirectory(WorkspaceRoot, 1),
        ));
        expect(closed.reason).toBe('workspace-closed');
      }),
    ));

  it('rejects cross-host handles before invoking a descriptor operation', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const firstState: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        const secondState: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        const first = yield* makeLinuxDescriptorWorkspaceHost(binding(firstState));
        const second = yield* makeLinuxDescriptorWorkspaceHost(binding(secondState));
        yield* Effect.scoped(
          Effect.gen(function* () {
            const allocator = yield* WorkspaceAllocator;
            const workspace = yield* allocator.allocate(quota);
            const handle = yield* workspace.withHandle(Effect.succeed);
            const rejected = yield* Effect.flip(second.withStaging(
              handle,
              operations => operations.makeDirectory(
                new WorkspaceRelativePath({ segments: ['wrong-host'] }),
              ),
            ));
            expect(rejected.reason).toBe('cross-host-handle');
          }).pipe(Effect.provide(allocatorLayer(first))),
        );
      }),
    ));

  it('releases a quota-bound analyzer scratch workspace on scope exit', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const state: BindingState = { closeCount: 0, sealCount: 0, scratchCloseCount: 0 };
        const host = yield* makeLinuxDescriptorWorkspaceHost(binding(state));
        let retained: AnalyzerScratchHandle | undefined;
        yield* Effect.scoped(
          Effect.gen(function* () {
            const allocator = yield* WorkspaceAllocator;
            retained = yield* allocator.allocateScratch(quota);
          }).pipe(Effect.provide(allocatorLayer(host))),
        );
        expect(state.scratchCloseCount).toBe(1);
        expect(retained === undefined).toBe(false);
      }),
    ));
});
