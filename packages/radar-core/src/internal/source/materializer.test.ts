import { createHash } from 'node:crypto';
import { Effect, Fiber, Layer } from 'effect';
import {
  BranchRevision,
  DefaultBranchRevision,
  GitHubSource,
  LocalDirectorySource,
} from '@codebase-radar/contracts/source';
import { describe, expect, it } from 'vitest';
import { ProcessOutput } from '../process/index.js';
import {
  WorkspaceAccessError,
  WorkspaceAllocationError,
  WorkspaceAllocatorLive,
  WorkspaceDescriptorHost,
  WorkspaceDirectoryBatch,
  WorkspaceDirectoryEntry,
  WorkspaceEntryStat,
  WorkspaceFileDigest,
  WorkspaceQuota,
  WorkspaceRelativePath,
  WorkspaceRoot,
  makeLinuxDescriptorWorkspaceHost,
} from '../workspace.js';
import type {
  LinuxDescriptorExternalSourceOperations,
  LinuxDescriptorFileWriter,
  LinuxDescriptorReadOperations,
  LinuxDescriptorScratchLease,
  LinuxDescriptorStagingOperations,
  LinuxDescriptorWorkspaceBinding,
  LinuxDescriptorWorkspaceLease,
} from '../workspace.js';
import {
  GitHubCodeloadArchiveError,
  GitHubCodeloadArchiveReceipt,
  GitHubCodeloadArchiveTransport,
  GitHubRevisionResolution,
  GitHubRevisionResolver,
  GitHubRevisionResolverError,
  SourceMaterializer,
  SourceMaterializerLive,
  SourceMaterializationLimits,
  decodeSourceMaterializationLimits,
  makeSourceMaterializerLayer,
} from './index.js';

const commitA = 'a'.repeat(40);
const commitB = 'b'.repeat(40);

const localSource = () => new LocalDirectorySource({
  directory: '/inert/source-repository',
  codebaseId: 'local:inert-source',
});

const defaultGitHubSource = () => new GitHubSource({
  owner: 'RadarOwner',
  repository: 'Fixture.Repository',
  revision: new DefaultBranchRevision({}),
});

const branchGitHubSource = () => new GitHubSource({
  owner: 'RadarOwner',
  repository: 'Fixture.Repository',
  revision: new BranchRevision({ branch: 'release' }),
});

const pathFromText = (text: string): WorkspaceRelativePath => new WorkspaceRelativePath({
  segments: text.split('/'),
});

const digest = (bytes: Uint8Array): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

type UnsafeFixtureKind =
  | 'symlink'
  | 'block-device'
  | 'character-device'
  | 'fifo'
  | 'socket'
  | 'unsupported';

interface FixtureDirectory {
  readonly kind: 'directory';
  readonly path: string;
}

interface FixtureFile {
  readonly kind: 'file';
  readonly path: string;
  readonly bytes: Uint8Array;
}

interface FixtureUnsafeEntry {
  readonly kind: UnsafeFixtureKind;
  readonly path: string;
}

type FixtureEntry = FixtureDirectory | FixtureFile | FixtureUnsafeEntry;

interface FixtureTree {
  readonly entries: Array<FixtureEntry>;
}

const directory = (path: string): FixtureDirectory => ({ kind: 'directory', path });

const file = (path: string, contents: string): FixtureFile => ({
  kind: 'file',
  path,
  bytes: bytes(contents),
});

const unsafe = (path: string, kind: UnsafeFixtureKind): FixtureUnsafeEntry => ({ path, kind });

const tree = (...entries: ReadonlyArray<FixtureEntry>): FixtureTree => ({
  entries: [...entries],
});

const emptyTree = (): FixtureTree => tree();

const entryName = (path: string): string => {
  const separator = path.lastIndexOf('/');
  return separator < 0 ? path : path.slice(separator + 1);
};

const parentPath = (path: string): string => {
  const separator = path.lastIndexOf('/');
  return separator < 0 ? '' : path.slice(0, separator);
};

const pathText = (path: WorkspaceRelativePath): string => path.segments.join('/');

const entryAt = (fixture: FixtureTree, path: WorkspaceRelativePath): FixtureEntry | undefined =>
  fixture.entries.find(entry => entry.path === pathText(path));

const entriesIn = (
  fixture: FixtureTree,
  path: WorkspaceRelativePath,
): ReadonlyArray<FixtureEntry> => fixture.entries.filter(
  entry => parentPath(entry.path) === pathText(path),
);

const replaceEntry = (fixture: FixtureTree, replacement: FixtureEntry): void => {
  const index = fixture.entries.findIndex(entry => entry.path === replacement.path);
  if (index < 0) {
    fixture.entries.push(replacement);
    return;
  }
  fixture.entries.splice(index, 1, replacement);
};

const removeEntry = (fixture: FixtureTree, path: string): void => {
  const index = fixture.entries.findIndex(entry => entry.path === path);
  if (index >= 0) fixture.entries.splice(index, 1);
};

const cloneFile = (entry: FixtureFile): FixtureFile => ({
  kind: 'file',
  path: entry.path,
  bytes: new Uint8Array(entry.bytes),
});

const processOutput = (stdout: string): ProcessOutput => new ProcessOutput({
  exitCode: 0,
  stdout,
  stderr: '',
  durationMs: 1,
  timedOut: false,
  truncated: false,
});

const defaultHead = (commit = commitA): string => `ref: refs/heads/main\tHEAD\n${commit}\tHEAD\n`;

const workspaceFailure = (
  operation: ConstructorParameters<typeof WorkspaceAccessError>[0]['operation'],
  reason: ConstructorParameters<typeof WorkspaceAccessError>[0]['reason'],
): WorkspaceAccessError => new WorkspaceAccessError({ operation, reason });

const allocationFailure = (
  reason: ConstructorParameters<typeof WorkspaceAllocationError>[0]['reason'],
): WorkspaceAllocationError => new WorkspaceAllocationError({ reason });

const entryLimitError = (operation: ConstructorParameters<typeof WorkspaceAccessError>[0]['operation']) =>
  workspaceFailure(operation, 'workspace-quota-exceeded');

interface FixtureBindingState {
  readonly source: FixtureTree;
  readonly staged: FixtureTree;
  readonly resolverOutputs: Array<ProcessOutput>;
  readonly commands: Array<{ readonly args: ReadonlyArray<string>; readonly timeoutMs: number; readonly maxOutputBytes: number }>;
  quota: WorkspaceQuota | undefined;
  closeCount: number;
  externalCloseCount: number;
  sealCount: number;
  copyCount: number;
  copyStarted: boolean;
  archiveStarted: boolean;
  sourceRootReplaced: boolean;
  mutateAfterFirstCopy: boolean;
  replaceRootAfterFirstCopy: boolean;
  blockCopy: boolean;
  activeStaging: LinuxDescriptorStagingOperations | undefined;
  allocationReason: ConstructorParameters<typeof WorkspaceAllocationError>[0]['reason'] | undefined;
}

interface FixtureBindingOptions {
  readonly source?: FixtureTree;
  readonly resolverOutputs?: ReadonlyArray<ProcessOutput>;
  readonly mutateAfterFirstCopy?: boolean;
  readonly replaceRootAfterFirstCopy?: boolean;
  readonly blockCopy?: boolean;
  readonly allocationReason?: ConstructorParameters<typeof WorkspaceAllocationError>[0]['reason'];
}

const countBytes = (fixture: FixtureTree): number => fixture.entries.reduce(
  (total, entry) => total + (entry.kind === 'file' ? entry.bytes.byteLength : 0),
  0,
);

const countFiles = (fixture: FixtureTree): number => fixture.entries.filter(
  entry => entry.kind === 'file',
).length;

const quotaFailure = (
  state: FixtureBindingState,
  operation: ConstructorParameters<typeof WorkspaceAccessError>[0]['operation'],
): WorkspaceAccessError | undefined => {
  const quota = state.quota;
  if (quota === undefined) return workspaceFailure(operation, 'capability-unavailable');
  return state.staged.entries.length > quota.maximumEntries ||
    countFiles(state.staged) > quota.maximumFiles ||
    countBytes(state.staged) > quota.maximumBytes
    ? entryLimitError(operation)
    : undefined;
};

const makeReadOperations = (
  fixture: FixtureTree,
  state: FixtureBindingState,
  external: boolean,
): LinuxDescriptorReadOperations => {
  const guarded = <A>(
    operation: ConstructorParameters<typeof WorkspaceAccessError>[0]['operation'],
    use: () => Effect.Effect<A, WorkspaceAccessError>,
  ): Effect.Effect<A, WorkspaceAccessError> => external && state.sourceRootReplaced
    ? Effect.fail(workspaceFailure(operation, 'unsafe-entry'))
    : use();
  return {
    readDirectory: (path, remainingEntries) => guarded('read-directory', () => {
      const children = entriesIn(fixture, path);
      const truncated = children.length > remainingEntries;
      const accepted = children.slice(0, remainingEntries).map(entry => new WorkspaceDirectoryEntry({
        name: entryName(entry.path),
        kind: entry.kind,
      }));
      return Effect.succeed(new WorkspaceDirectoryBatch({ entries: accepted, truncated }));
    }),
    stat: path => guarded('stat', () => {
      const entry = entryAt(fixture, path);
      return entry === undefined
        ? Effect.fail(workspaceFailure('stat', 'unsafe-entry'))
        : Effect.succeed(new WorkspaceEntryStat({
          kind: entry.kind,
          byteLength: entry.kind === 'file' ? entry.bytes.byteLength : 0,
        }));
    }),
    readText: (path, remainingBytes) => guarded('read-text', () => {
      const entry = entryAt(fixture, path);
      if (entry === undefined || entry.kind !== 'file') {
        return Effect.fail(workspaceFailure('read-text', 'unsafe-entry'));
      }
      const content = new TextDecoder().decode(entry.bytes);
      return content.length > remainingBytes
        ? Effect.fail(workspaceFailure('read-text', 'bound-exceeded'))
        : Effect.succeed(content);
    }),
    digestRegularFile: (path, remainingBytes) => guarded('digest-regular-file', () => {
      const entry = entryAt(fixture, path);
      if (entry === undefined || entry.kind !== 'file') {
        return Effect.fail(workspaceFailure('digest-regular-file', 'unsafe-entry'));
      }
      return entry.bytes.byteLength > remainingBytes
        ? Effect.fail(workspaceFailure('digest-regular-file', 'bound-exceeded'))
        : Effect.succeed(new WorkspaceFileDigest({
          contentDigest: digest(entry.bytes),
          byteLength: entry.bytes.byteLength,
        }));
    }),
  };
};

/**
 * This is a protocol-level descriptor binding only: it contains no pathname
 * I/O or target execution. Native no-follow/root-replacement guarantees are
 * exercised by the host integration binding rather than simulated here.
 */
const makeFixtureBinding = (options: FixtureBindingOptions = {}) => {
  const state: FixtureBindingState = {
    source: options.source ?? emptyTree(),
    staged: emptyTree(),
    resolverOutputs: [...(options.resolverOutputs ?? [])],
    commands: [],
    quota: undefined,
    closeCount: 0,
    externalCloseCount: 0,
    sealCount: 0,
    copyCount: 0,
    copyStarted: false,
    archiveStarted: false,
    sourceRootReplaced: false,
    mutateAfterFirstCopy: options.mutateAfterFirstCopy ?? false,
    replaceRootAfterFirstCopy: options.replaceRootAfterFirstCopy ?? false,
    blockCopy: options.blockCopy ?? false,
    activeStaging: undefined,
    allocationReason: options.allocationReason,
  };

  const stagingOperations = (): LinuxDescriptorStagingOperations => {
    const reader = makeReadOperations(state.staged, state, false);
    return {
      ...reader,
      makeDirectory: path => Effect.sync(() => {
        replaceEntry(state.staged, directory(pathText(path)));
        return quotaFailure(state, 'make-directory');
      }).pipe(Effect.flatMap(failure => failure === undefined ? Effect.void : Effect.fail(failure))),
      openFileWriter: path => Effect.sync(() => {
        const chunks = new Array<Uint8Array>();
        let closed = false;
        const writer: LinuxDescriptorFileWriter = {
          write: chunk => closed
            ? Effect.fail(workspaceFailure('write-file', 'workspace-closed'))
            : Effect.sync(() => {
              chunks.push(new Uint8Array(chunk));
              const pendingBytes = chunks.reduce((total, item) => total + item.byteLength, 0);
              const quota = state.quota;
              const existing = entryAt(state.staged, path);
              const existingBytes = existing !== undefined && existing.kind === 'file'
                ? existing.bytes.byteLength
                : 0;
              const projectedEntries = existing === undefined
                ? state.staged.entries.length + 1
                : state.staged.entries.length;
              const projectedFiles = existing !== undefined && existing.kind === 'file'
                ? countFiles(state.staged)
                : countFiles(state.staged) + 1;
              const projectedBytes = countBytes(state.staged) - existingBytes + pendingBytes;
              return quota === undefined ||
                projectedEntries > quota.maximumEntries ||
                projectedFiles > quota.maximumFiles ||
                projectedBytes > quota.maximumBytes
                ? workspaceFailure('write-file', 'workspace-quota-exceeded')
                : undefined;
            }).pipe(Effect.flatMap(failure => failure === undefined ? Effect.void : Effect.fail(failure))),
          close: commit => Effect.sync(() => {
            if (closed) return undefined;
            closed = true;
            if (!commit) return undefined;
            const total = chunks.reduce((length, item) => length + item.byteLength, 0);
            const content = new Uint8Array(total);
            let offset = 0;
            for (const item of chunks) {
              content.set(item, offset);
              offset += item.byteLength;
            }
            replaceEntry(state.staged, {
              kind: 'file',
              path: pathText(path),
              bytes: content,
            });
          }),
        };
        return writer;
      }),
      runGitResolver: command => Effect.sync(() => {
        state.commands.push({
          args: [...command.args],
          timeoutMs: command.timeoutMs,
          maxOutputBytes: command.maxOutputBytes,
        });
        const output = state.resolverOutputs.shift();
        return output;
      }).pipe(Effect.flatMap(output => output === undefined
        ? Effect.fail(workspaceFailure('run', 'process-failed'))
        : Effect.succeed(output))),
    };
  };

  const binding: LinuxDescriptorWorkspaceBinding = {
    allocate: quota => state.allocationReason === undefined
      ? Effect.sync(() => {
        state.quota = quota;
        state.staged.entries.splice(0, state.staged.entries.length);
        const staging = stagingOperations();
        state.activeStaging = staging;
        let closed = false;
        const lease: LinuxDescriptorWorkspaceLease = {
          staging,
          source: makeReadOperations(state.staged, state, false),
          seal: Effect.sync(() => {
            state.sealCount += 1;
          }),
          close: Effect.sync(() => {
            if (closed) return;
            closed = true;
            state.closeCount += 1;
          }),
        };
        return lease;
      })
      : Effect.fail(allocationFailure(state.allocationReason)),
    allocateScratch: quota => Effect.sync(() => {
      state.quota = quota;
      let closed = false;
      const lease: LinuxDescriptorScratchLease = {
        scratch: stagingOperations(),
        close: Effect.sync(() => {
          if (closed) return;
          closed = true;
        }),
      };
      return lease;
    }),
    openExternalSource: () => Effect.sync(() => {
      const reader = makeReadOperations(state.source, state, true);
      let closed = false;
      const external: LinuxDescriptorExternalSourceOperations = {
        ...reader,
        copyRegularFileTo: (sourcePath, destination, destinationPath, remainingBytes) => {
          state.copyStarted = true;
          if (state.blockCopy) return Effect.never;
          const sourceEntry = entryAt(state.source, sourcePath);
          if (sourceEntry === undefined || sourceEntry.kind !== 'file') {
            return Effect.fail(workspaceFailure('copy-regular-file', 'unsafe-entry'));
          }
          if (sourceEntry.bytes.byteLength > remainingBytes) {
            return Effect.fail(workspaceFailure('copy-regular-file', 'bound-exceeded'));
          }
          if (state.activeStaging === undefined || destination !== state.activeStaging) {
            return Effect.fail(workspaceFailure('copy-regular-file', 'unrecognized-handle'));
          }
          replaceEntry(state.staged, {
            ...cloneFile(sourceEntry),
            path: pathText(destinationPath),
          });
          const failure = quotaFailure(state, 'copy-regular-file');
          state.copyCount += 1;
          if (state.copyCount === 1 && state.mutateAfterFirstCopy) {
            const changed = entryAt(state.source, sourcePath);
            if (changed !== undefined && changed.kind === 'file') {
              replaceEntry(state.source, file(changed.path, 'changed-after-copy'));
            }
          }
          if (state.copyCount === 1 && state.replaceRootAfterFirstCopy) {
            state.sourceRootReplaced = true;
          }
          return failure === undefined
            ? Effect.succeed(new WorkspaceFileDigest({
              contentDigest: digest(sourceEntry.bytes),
              byteLength: sourceEntry.bytes.byteLength,
            }))
            : Effect.fail(failure);
        },
        close: Effect.sync(() => {
          if (closed) return;
          closed = true;
          state.externalCloseCount += 1;
        }),
      };
      return external;
    }),
    runAnalyzer: () => Effect.succeed(processOutput('')),
  };
  return { binding, state };
};

const archive = (
  stage: Parameters<typeof GitHubCodeloadArchiveTransport.of>[0]['stage'],
) => GitHubCodeloadArchiveTransport.of({ stage });

const resolvedRevision = (
  commitSha = commitA,
  owner = 'RadarOwner',
  repository = 'Fixture.Repository',
) => new GitHubRevisionResolution({
  owner,
  repository,
  defaultBranch: 'main',
  commitSha,
});

const resolver = (
  resolve: Parameters<typeof GitHubRevisionResolver.of>[0]['resolve'],
) => GitHubRevisionResolver.of({ resolve });

const standardResolver = () => resolver(() => Effect.succeed(resolvedRevision()));

const archiveWorkspaceFailure = (error: WorkspaceAccessError): GitHubCodeloadArchiveError =>
  new GitHubCodeloadArchiveError({
    operation: 'stage',
    code: error.reason === 'workspace-quota-exceeded' || error.reason === 'bound-exceeded'
      ? 'source-limit-exceeded'
      : 'archive-invalid',
  });

const archiveTree = (
  fixture: FixtureTree,
  receipt = commitA,
  afterStage?: () => void,
) => archive((request, staging) => Effect.gen(function* () {
  for (const entry of fixture.entries) {
    const path = pathFromText(entry.path);
    if (entry.kind === 'directory') {
      yield* staging.makeDirectory(path);
      continue;
    }
    if (entry.kind !== 'file') {
      return yield* Effect.fail(new GitHubCodeloadArchiveError({
        operation: 'stage',
        code: 'archive-invalid',
      }));
    }
    yield* staging.withFileWriter(path, writer => writer.write(entry.bytes));
  }
  afterStage?.();
  return new GitHubCodeloadArchiveReceipt({ commitSha: receipt });
}).pipe(Effect.catchTag(
  'WorkspaceAccessError',
  error => Effect.fail(archiveWorkspaceFailure(error)),
)));

const layerFor = (
  binding: LinuxDescriptorWorkspaceBinding,
  archives: ReturnType<typeof GitHubCodeloadArchiveTransport.of>,
  revisions: ReturnType<typeof GitHubRevisionResolver.of> = standardResolver(),
) => Effect.gen(function* () {
  const descriptor = yield* makeLinuxDescriptorWorkspaceHost(binding);
  const allocator = WorkspaceAllocatorLive.pipe(
    Layer.provide(Layer.succeed(WorkspaceDescriptorHost, descriptor)),
  );
  const dependencies = Layer.mergeAll(
    Layer.succeed(WorkspaceDescriptorHost, descriptor),
    allocator,
    Layer.succeed(GitHubRevisionResolver, revisions),
    Layer.succeed(GitHubCodeloadArchiveTransport, archives),
  );
  return SourceMaterializerLive.pipe(Layer.provide(dependencies));
});

const configuredLayerFor = (
  binding: LinuxDescriptorWorkspaceBinding,
  archives: ReturnType<typeof GitHubCodeloadArchiveTransport.of>,
  limits: SourceMaterializationLimits,
  revisions: ReturnType<typeof GitHubRevisionResolver.of> = standardResolver(),
) => Effect.gen(function* () {
  const descriptor = yield* makeLinuxDescriptorWorkspaceHost(binding);
  const allocator = WorkspaceAllocatorLive.pipe(
    Layer.provide(Layer.succeed(WorkspaceDescriptorHost, descriptor)),
  );
  const dependencies = Layer.mergeAll(
    Layer.succeed(WorkspaceDescriptorHost, descriptor),
    allocator,
  );
  return makeSourceMaterializerLayer(revisions, archives, limits).pipe(Layer.provide(dependencies));
});

const materialize = (
  binding: LinuxDescriptorWorkspaceBinding,
  archives: ReturnType<typeof GitHubCodeloadArchiveTransport.of>,
  source: LocalDirectorySource | GitHubSource,
  revisions: ReturnType<typeof GitHubRevisionResolver.of> = standardResolver(),
) => layerFor(binding, archives, revisions).pipe(Effect.flatMap(layer => Effect.gen(function* () {
  const service = yield* SourceMaterializer;
  return yield* service.materialize(source);
}).pipe(Effect.provide(layer))));

const materializeWithLimits = (
  binding: LinuxDescriptorWorkspaceBinding,
  archives: ReturnType<typeof GitHubCodeloadArchiveTransport.of>,
  source: LocalDirectorySource | GitHubSource,
  limits: SourceMaterializationLimits,
  revisions: ReturnType<typeof GitHubRevisionResolver.of> = standardResolver(),
) => configuredLayerFor(binding, archives, limits, revisions).pipe(Effect.flatMap(layer => Effect.gen(function* () {
  const service = yield* SourceMaterializer;
  return yield* service.materialize(source);
}).pipe(Effect.provide(layer))));

const localFixture = (): FixtureTree => tree(
  directory('.git'),
  file('.git/config', '[core]'),
  directory('src'),
  file('src/tracked.ts', 'tracked'),
  file('untracked.txt', 'untracked'),
);

const githubFixture = (): FixtureTree => tree(
  directory('src'),
  file('src/tracked.ts', 'tracked'),
  file('untracked.txt', 'untracked'),
);

const standardArchive = () => archiveTree(githubFixture());

describe('SourceMaterializer', () => {
  it('materializes a dirty local snapshot without source paths or Git metadata', () =>
    Effect.runPromise(Effect.gen(function* () {
      const fixture = makeFixtureBinding({ source: localFixture() });
      const result = yield* Effect.scoped(materialize(
        fixture.binding,
        standardArchive(),
        localSource(),
      ));
      expect(result.identity._tag).toBe('LocalSourceIdentity');
      if (result.identity._tag !== 'LocalSourceIdentity') return;
      expect(result.identity.dirty).toBe(true);
      expect(result.identity.commitSha).toBeUndefined();
      expect(result.identity.branch).toBeUndefined();
      expect(result.snapshot.fileCount).toBe(2);
      expect(result.snapshot.totalBytes).toBe(bytes('tracked').byteLength + bytes('untracked').byteLength);
      expect(JSON.stringify(result)).not.toContain('/inert/source-repository');
      expect(fixture.state.staged.entries.some(entry => entry.path === '.git')).toBe(false);
      expect(fixture.state.sealCount).toBe(1);
      expect(fixture.state.closeCount).toBe(1);
      expect(fixture.state.externalCloseCount).toBe(1);
    })),
  );

  it('rejects nested repositories and every non-regular descriptor entry', () =>
    Effect.runPromise(Effect.gen(function* () {
      const nested = makeFixtureBinding({
        source: tree(directory('vendor'), directory('vendor/.git'), file('vendor/.git/config', 'x')),
      });
      const nestedFailure = yield* Effect.scoped(Effect.flip(materialize(
        nested.binding,
        standardArchive(),
        localSource(),
      )));
      expect(nestedFailure.reason).toBe('nested-repository');

      const kinds: ReadonlyArray<UnsafeFixtureKind> = [
        'symlink',
        'block-device',
        'character-device',
        'fifo',
        'socket',
        'unsupported',
      ];
      for (const kind of kinds) {
        const hostile = makeFixtureBinding({ source: tree(unsafe(`hostile-${kind}`, kind)) });
        const failure = yield* Effect.scoped(Effect.flip(materialize(
          hostile.binding,
          standardArchive(),
          localSource(),
        )));
        expect(failure.reason).toBe('unsafe-entry');
        expect(JSON.stringify(failure)).not.toContain('/inert/source-repository');
      }
    })),
  );

  it('fails when an anchored local source changes during capture or the host rejects a root replacement', () =>
    Effect.runPromise(Effect.gen(function* () {
      const changed = makeFixtureBinding({
        source: tree(file('tracked.txt', 'before')),
        mutateAfterFirstCopy: true,
      });
      const changedFailure = yield* Effect.scoped(Effect.flip(materialize(
        changed.binding,
        standardArchive(),
        localSource(),
      )));
      expect(changedFailure.reason).toBe('transport-failed');

      const replaced = makeFixtureBinding({
        source: tree(file('tracked.txt', 'before')),
        replaceRootAfterFirstCopy: true,
      });
      const replacementFailure = yield* Effect.scoped(Effect.flip(materialize(
        replaced.binding,
        standardArchive(),
        localSource(),
      )));
      expect(replacementFailure.reason).toBe('unsafe-entry');
      expect(replaced.state.closeCount).toBe(1);
      expect(replaced.state.externalCloseCount).toBe(1);
    })),
  );

  it('enforces exact entry, file, and byte bounds while capture writes', () =>
    Effect.runPromise(Effect.gen(function* () {
      const exactLimits = new SourceMaterializationLimits({
        maximumEntries: 3,
        maximumFiles: 2,
        maximumBytes: 3,
        maximumArchiveBytes: 3,
        archiveTimeoutMs: 10,
        gitTimeoutMs: 10,
        gitOutputBytes: 64,
      });
      const exact = makeFixtureBinding({
        // The sorted last root entry is an empty directory. Once it is
        // counted, auditTree must probe that directory with a zero-entry
        // batch rather than rejecting it solely because the quota is exact.
        source: tree(file('alpha.txt', 'abc'), file('beta.txt', ''), directory('z-empty')),
      });
      const result = yield* Effect.scoped(materializeWithLimits(
        exact.binding,
        standardArchive(),
        localSource(),
        exactLimits,
      ));
      expect(result.snapshot.fileCount).toBe(2);
      expect(result.snapshot.totalBytes).toBe(3);

      const oversized = makeFixtureBinding({ source: tree(file('four.txt', 'abcd')) });
      const oversizedFailure = yield* Effect.scoped(Effect.flip(materializeWithLimits(
        oversized.binding,
        standardArchive(),
        localSource(),
        exactLimits,
      )));
      expect(oversizedFailure.reason).toBe('source-limit-exceeded');

      const extraEntry = makeFixtureBinding({
        source: tree(directory('empty'), file('three.txt', 'abc'), file('zero.txt', ''), file('extra.txt', '')),
      });
      const entryFailure = yield* Effect.scoped(Effect.flip(materializeWithLimits(
        extraEntry.binding,
        standardArchive(),
        localSource(),
        exactLimits,
      )));
      expect(entryFailure.reason).toBe('source-limit-exceeded');

      const segment = 'd'.repeat(255);
      const first = segment;
      const second = `${first}/${segment}`;
      const third = `${second}/${segment}`;
      const fourth = `${third}/${segment}`;
      const tooDeep = makeFixtureBinding({
        source: tree(
          directory(first),
          directory(second),
          directory(third),
          directory(fourth),
          file(`${fourth}/x`, 'x'),
        ),
      });
      const pathFailure = yield* Effect.scoped(Effect.flip(materialize(
        tooDeep.binding,
        standardArchive(),
        localSource(),
      )));
      expect(pathFailure.reason).toBe('source-limit-exceeded');
    })),
  );

  it('strictly decodes configured quotas before allocating a workspace', () =>
    Effect.runPromise(Effect.gen(function* () {
      const invalid = new SourceMaterializationLimits({
        maximumEntries: 1,
        maximumFiles: 2,
        maximumBytes: 1,
        maximumArchiveBytes: 1,
        archiveTimeoutMs: 1,
        gitTimeoutMs: 1,
        gitOutputBytes: 1,
      });
      const fixture = makeFixtureBinding({ source: tree(file('x', 'x')) });
      const failure = yield* Effect.scoped(Effect.flip(materializeWithLimits(
        fixture.binding,
        standardArchive(),
        localSource(),
        invalid,
      )));
      expect(failure.reason).toBe('invalid-response');
      expect(fixture.state.closeCount).toBe(0);

      const nonFinite = yield* Effect.flip(decodeSourceMaterializationLimits({
        maximumEntries: 1,
        maximumFiles: 1,
        maximumBytes: Number.POSITIVE_INFINITY,
        maximumArchiveBytes: 1,
        archiveTimeoutMs: 1,
        gitTimeoutMs: 1,
        gitOutputBytes: 1,
      }));
      expect(nonFinite).toBeDefined();

      const excess = yield* Effect.flip(decodeSourceMaterializationLimits({
        maximumEntries: 1,
        maximumFiles: 1,
        maximumBytes: 1,
        maximumArchiveBytes: 1,
        archiveTimeoutMs: 1,
        gitTimeoutMs: 1,
        gitOutputBytes: 1,
        unexpected: true,
      }));
      expect(excess).toBeDefined();
    })),
  );

  it('uses the fixed-origin resolver port and a pinned codeload request', () =>
    Effect.runPromise(Effect.gen(function* () {
      const fixture = makeFixtureBinding();
      let requestedCommit = '';
      let resolverOwner = '';
      let resolverRepository = '';
      let resolverTimeout = 0;
      let resolverBodyLimit = 0;
      const revisions = resolver((source, limits) => Effect.sync(() => {
        resolverOwner = source.owner;
        resolverRepository = source.repository;
        resolverTimeout = limits.gitTimeoutMs;
        resolverBodyLimit = limits.gitOutputBytes;
      }).pipe(Effect.as(resolvedRevision())));
      const archives = archive((request, staging) => Effect.gen(function* () {
        requestedCommit = request.commitSha;
        yield* staging.makeDirectory(pathFromText('src'));
        yield* staging.withFileWriter(pathFromText('src/index.ts'), writer => writer.write(bytes('safe')));
        return new GitHubCodeloadArchiveReceipt({ commitSha: request.commitSha });
      }).pipe(Effect.catchTag(
        'WorkspaceAccessError',
        error => Effect.fail(archiveWorkspaceFailure(error)),
      )));
      const result = yield* Effect.scoped(materialize(
        fixture.binding,
        archives,
        defaultGitHubSource(),
        revisions,
      ));
      expect(result.identity._tag).toBe('GitHubSourceIdentity');
      expect(requestedCommit).toBe(commitA);
      expect(resolverOwner).toBe('RadarOwner');
      expect(resolverRepository).toBe('Fixture.Repository');
      expect(resolverTimeout).toBe(60_000);
      expect(resolverBodyLimit).toBe(64 * 1024);
      expect(fixture.state.commands).toHaveLength(0);
    })),
  );

  it('rejects missing revisions and ref changes between resolution and archive staging', () =>
    Effect.runPromise(Effect.gen(function* () {
      const missing = makeFixtureBinding();
      const missingResolver = resolver(() => Effect.fail(new GitHubRevisionResolverError({
        operation: 'resolve',
        code: 'missing-revision',
      })));
      const missingFailure = yield* Effect.scoped(Effect.flip(materialize(
        missing.binding,
        standardArchive(),
        branchGitHubSource(),
        missingResolver,
      )));
      expect(missingFailure.reason).toBe('missing-revision');

      const changed = makeFixtureBinding();
      const changedArchive = archiveTree(githubFixture(), commitB);
      const changedFailure = yield* Effect.scoped(Effect.flip(materialize(
        changed.binding,
        changedArchive,
        defaultGitHubSource(),
      )));
      expect(changedFailure.reason).toBe('revision-changed');
      expect(JSON.stringify(changedFailure)).not.toContain('secret');

      const timedOut = makeFixtureBinding();
      const unavailableResolver = resolver(() => Effect.fail(new GitHubRevisionResolverError({
        operation: 'resolve',
        code: 'transport-failed',
      })));
      const timeoutFailure = yield* Effect.scoped(Effect.flip(materialize(
        timedOut.binding,
        standardArchive(),
        defaultGitHubSource(),
        unavailableResolver,
      )));
      expect(timeoutFailure.reason).toBe('transport-failed');
      expect(JSON.stringify(timeoutFailure)).not.toContain('credential');

      const mismatchedIdentity = makeFixtureBinding();
      const mismatchedResolver = resolver(() => Effect.succeed(resolvedRevision(
        commitA,
        'Elsewhere',
        'Fixture.Repository',
      )));
      const identityFailure = yield* Effect.scoped(Effect.flip(materialize(
        mismatchedIdentity.binding,
        standardArchive(),
        defaultGitHubSource(),
        mismatchedResolver,
      )));
      expect(identityFailure.reason).toBe('invalid-response');
      expect(mismatchedIdentity.state.closeCount).toBe(0);
    })),
  );

  it('passes exact archive quotas to the codeload capability and maps streamed quota rejection', () =>
    Effect.runPromise(Effect.gen(function* () {
      const limits = new SourceMaterializationLimits({
        maximumEntries: 4,
        maximumFiles: 2,
        maximumBytes: 3,
        maximumArchiveBytes: 3,
        archiveTimeoutMs: 7,
        gitTimeoutMs: 7,
        gitOutputBytes: 128,
      });
      const fixture = makeFixtureBinding({ resolverOutputs: [processOutput(defaultHead())] });
      let archiveBytes = 0;
      let archiveTimeout = 0;
      const tooLarge = archive(request => {
        archiveBytes = request.maximumArchiveBytes;
        archiveTimeout = request.timeoutMs;
        return Effect.fail(new GitHubCodeloadArchiveError({
          operation: 'stage',
          code: 'source-limit-exceeded',
        }));
      });
      const failure = yield* Effect.scoped(Effect.flip(materializeWithLimits(
        fixture.binding,
        tooLarge,
        defaultGitHubSource(),
        limits,
      )));
      expect(archiveBytes).toBe(3);
      expect(archiveTimeout).toBe(7);
      expect(failure.reason).toBe('source-limit-exceeded');
      expect(fixture.state.closeCount).toBe(1);
    })),
  );

  it('rejects hostile archive results and holds local and GitHub audited totals in parity', () =>
    Effect.runPromise(Effect.gen(function* () {
      const archiveFixture = tree(directory('src'), file('src/index.ts', 'stable'));
      const local = makeFixtureBinding({ source: archiveFixture });
      const localResult = yield* Effect.scoped(materialize(
        local.binding,
        standardArchive(),
        localSource(),
      ));

      const github = makeFixtureBinding({ resolverOutputs: [processOutput(defaultHead())] });
      const githubResult = yield* Effect.scoped(materialize(
        github.binding,
        archiveTree(archiveFixture),
        defaultGitHubSource(),
      ));
      expect(githubResult.snapshot.fileCount).toBe(localResult.snapshot.fileCount);
      expect(githubResult.snapshot.totalBytes).toBe(localResult.snapshot.totalBytes);
      expect(githubResult.snapshot.snapshotDigest).toBe(localResult.snapshot.snapshotDigest);

      const optionalEmptyDirectory = makeFixtureBinding({
        source: tree(directory('empty'), directory('src'), file('src/index.ts', 'stable')),
      });
      const optionalEmptyResult = yield* Effect.scoped(materialize(
        optionalEmptyDirectory.binding,
        standardArchive(),
        localSource(),
      ));
      expect(optionalEmptyResult.snapshot.snapshotDigest).toBe(localResult.snapshot.snapshotDigest);

      const nested = makeFixtureBinding({ resolverOutputs: [processOutput(defaultHead())] });
      const nestedArchive = archiveTree(tree(directory('.git'), file('.git/config', 'x')));
      const nestedFailure = yield* Effect.scoped(Effect.flip(materialize(
        nested.binding,
        nestedArchive,
        defaultGitHubSource(),
      )));
      expect(nestedFailure.reason).toBe('nested-repository');

      const raced = makeFixtureBinding({ resolverOutputs: [processOutput(defaultHead())] });
      const unsafeArchive = archiveTree(
        tree(file('safe.txt', 'safe')),
        commitA,
        () => raced.state.staged.entries.push(unsafe('raced-link', 'symlink')),
      );
      const unsafeFailure = yield* Effect.scoped(Effect.flip(materialize(
        raced.binding,
        unsafeArchive,
        defaultGitHubSource(),
      )));
      expect(unsafeFailure.reason).toBe('unsafe-entry');
    })),
  );

  it('releases local and GitHub staging leases exactly once on interruption', () =>
    Effect.runPromise(Effect.gen(function* () {
      const local = makeFixtureBinding({
        source: tree(file('blocked.txt', 'blocked')),
        blockCopy: true,
      });
      const localFiber = yield* Effect.scoped(materialize(
        local.binding,
        standardArchive(),
        localSource(),
      )).pipe(Effect.forkChild);
      yield* Effect.whileLoop({
        while: () => !local.state.copyStarted,
        body: () => Effect.yieldNow,
        step: () => undefined,
      });
      yield* Fiber.interrupt(localFiber);
      expect(local.state.closeCount).toBe(1);
      expect(local.state.externalCloseCount).toBe(1);

      const github = makeFixtureBinding({ resolverOutputs: [processOutput(defaultHead())] });
      const blockingArchive = archive((request, staging) => Effect.sync(() => {
        github.state.archiveStarted = true;
        return { request, staging };
      }).pipe(Effect.andThen(Effect.never)));
      const githubFiber = yield* Effect.scoped(materialize(
        github.binding,
        blockingArchive,
        defaultGitHubSource(),
      )).pipe(Effect.forkChild);
      yield* Effect.whileLoop({
        while: () => !github.state.archiveStarted,
        body: () => Effect.yieldNow,
        step: () => undefined,
      });
      yield* Fiber.interrupt(githubFiber);
      expect(github.state.closeCount).toBe(1);
      expect(github.state.externalCloseCount).toBe(0);
    })),
  );

  it('fails closed when quota enforcement is absent from the descriptor capability', () =>
    Effect.runPromise(Effect.gen(function* () {
      const fixture = makeFixtureBinding({
        source: tree(file('x.txt', 'x')),
        allocationReason: 'workspace-quota-unenforced',
      });
      const failure = yield* Effect.scoped(Effect.flip(materialize(
        fixture.binding,
        standardArchive(),
        localSource(),
      )));
      expect(failure.reason).toBe('capability-unavailable');
      expect(fixture.state.closeCount).toBe(0);
    })),
  );
});
