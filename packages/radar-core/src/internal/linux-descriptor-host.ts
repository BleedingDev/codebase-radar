import { createHash, randomBytes } from 'node:crypto';
import { constants, type Dir, type Dirent } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  opendir,
  rmdir,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import {
  launchResourceGovernedAnalyzer,
  type ResourceGovernedAnalyzerSession,
} from '@codebase-radar/analyzer-runtime/resource-governance';
import type { MaterializedAnalyzerRuntime } from '@codebase-radar/analyzer-runtime/runtime-sealed-generation';
import { Effect, Scope } from 'effect';
import {
  ProcessOutput,
  encodeSemanticAnalyzerRequest,
  type ProcessRequest,
} from './process/index.js';
import {
  WorkspaceAccessError,
  WorkspaceAllocationError,
  WorkspaceDirectoryBatch,
  WorkspaceDirectoryEntry,
  WorkspaceEntryStat,
  WorkspaceFileDigest,
  WorkspaceQuota,
  WorkspaceRelativePath,
  type LinuxDescriptorExternalSourceOperations,
  type LinuxDescriptorFileWriter,
  type LinuxDescriptorReadOperations,
  type LinuxDescriptorScratchLease,
  type LinuxDescriptorStagingOperations,
  type LinuxDescriptorWorkspaceBinding,
  type LinuxDescriptorWorkspaceLease,
} from './workspace.js';

const DirectoryOpenFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const RegularReadFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const RegularWriteFlags = constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  constants.O_NOFOLLOW;
const StreamChunkBytes = 64 * 1024;
const SemanticAnalyzerRequestFile = 'radar-analyzer-request.json';

interface FileIdentity {
  /** Decimal bigint fields avoid a lossy Number comparison on large inodes. */
  readonly device: string;
  readonly inode: string;
}

interface RetainedDirectory {
  readonly file: FileHandle;
  readonly identity: FileIdentity;
}

interface QuotaLedger {
  readonly quota: WorkspaceQuota;
  entries: number;
  files: number;
  bytes: number;
}

interface OwnedWorkspace {
  readonly parent: RetainedDirectory;
  readonly root: RetainedDirectory;
  readonly leaf: string;
  readonly ledger: QuotaLedger;
  sealed: boolean;
  closed: boolean;
  orphaned: boolean;
}

const retainedReadRoots = new WeakMap<LinuxDescriptorReadOperations, RetainedDirectory>();
const ownedStagingRoots = new WeakMap<LinuxDescriptorStagingOperations, OwnedWorkspace>();

export interface NodeLinuxDescriptorWorkspaceBindingOptions {
  /** An existing private (0700) directory controlled by the Radar service account. */
  readonly workspaceParent: string;
  /** Explicit delegated cgroup-v2 parent authenticated by the runtime verifier. */
  readonly resourceCgroupRoot: string;
  /** Opaque process-lifetime runtime materialized from the sealed verifier output. */
  readonly materializedRuntime: MaterializedAnalyzerRuntime;
}

const accessError = (
  operation: WorkspaceAccessError['operation'],
  reason: WorkspaceAccessError['reason'],
) => new WorkspaceAccessError({ operation, reason });

const allocationError = (reason: WorkspaceAllocationError['reason']) =>
  new WorkspaceAllocationError({ reason });

const descriptorPath = (file: FileHandle, name?: string) => {
  const root = `/proc/${process.pid}/fd/${file.fd}`;
  return name === undefined ? root : `${root}/${name}`;
};

const validName = (value: string) =>
  value.length > 0 &&
  value.length <= 255 &&
  value !== '.' &&
  value !== '..' &&
  !value.includes('/') &&
  !value.includes('\\') &&
  !value.includes('\0') &&
  !/[\u0000-\u001f\u007f]/u.test(value);

const absoluteSegments = (path: string): ReadonlyArray<string> | undefined => {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || path.includes('\0')) {
    return undefined;
  }
  const segments = path.split('/').filter(segment => segment.length > 0);
  return segments.length > 0 && segments.every(validName) ? segments : undefined;
};

const pathSegments = (path: WorkspaceRelativePath): ReadonlyArray<string> | undefined =>
  path.segments.every(validName) ? path.segments : undefined;

const identityOf = (file: FileHandle): Effect.Effect<FileIdentity, WorkspaceAccessError> =>
  Effect.tryPromise({
    try: () => file.stat({ bigint: true }),
    catch: () => accessError('stat', 'unsafe-entry'),
  }).pipe(
    Effect.flatMap(stat => stat.isDirectory() || stat.isFile()
      ? Effect.succeed({ device: stat.dev.toString(10), inode: stat.ino.toString(10) })
      : Effect.fail(accessError('stat', 'unsafe-entry'))),
  );

const sameIdentity = (left: FileIdentity, right: FileIdentity) =>
  left.device === right.device && left.inode === right.inode;

const closeQuietly = (file: FileHandle) =>
  Effect.tryPromise({
    try: () => file.close(),
    catch: () => accessError('close', 'cleanup-failed'),
  }).pipe(Effect.catch(() => Effect.void));

const closeDirectoryQuietly = (directory: Dir) =>
  Effect.tryPromise({
    try: () => directory.close(),
    catch: () => accessError('close', 'cleanup-failed'),
  }).pipe(Effect.catch(() => Effect.void));

const openDirectoryFrom = (
  parent: RetainedDirectory,
  name: string,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<RetainedDirectory, WorkspaceAccessError> => {
  if (!validName(name)) return Effect.fail(accessError(operation, 'unsafe-path'));
  return Effect.tryPromise({
    try: () => open(descriptorPath(parent.file, name), DirectoryOpenFlags),
    catch: () => accessError(operation, 'unsafe-entry'),
  }).pipe(
    Effect.flatMap(file => identityOf(file).pipe(
      Effect.map(identity => ({ file, identity })),
      Effect.tapError(() => closeQuietly(file)),
    )),
  );
};

const duplicateDirectory = (
  directory: RetainedDirectory,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<RetainedDirectory, WorkspaceAccessError> =>
  Effect.tryPromise({
    try: () => open(descriptorPath(directory.file), DirectoryOpenFlags),
    catch: () => accessError(operation, 'unsafe-entry'),
  }).pipe(
    Effect.flatMap(file => identityOf(file).pipe(
      Effect.map(identity => ({ file, identity })),
      Effect.tapError(() => closeQuietly(file)),
    )),
  );

const openAbsoluteDirectory = (
  path: string,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<RetainedDirectory, WorkspaceAccessError> => {
  const segments = absoluteSegments(path);
  if (segments === undefined) return Effect.fail(accessError(operation, 'unsafe-path'));
  return Effect.tryPromise({
    try: () => open('/', DirectoryOpenFlags),
    catch: () => accessError(operation, 'procfs-unavailable'),
  }).pipe(
    Effect.flatMap(file => identityOf(file).pipe(
      Effect.map(identity => ({ file, identity })),
      Effect.tapError(() => closeQuietly(file)),
    )),
    Effect.flatMap(root => Effect.gen(function* () {
      let current = root;
      for (const segment of segments) {
        const next = yield* openDirectoryFrom(current, segment, operation).pipe(
          Effect.tapError(() => closeQuietly(current.file)),
        );
        yield* closeQuietly(current.file);
        current = next;
      }
      return current;
    })),
  );
};

/**
 * Opens an existing directory component by component. `/proc/<pid>/fd/<fd>`
 * is only ever derived from a retained directory descriptor; callers cannot
 * provide a relative pathname to this host.
 */
const openDirectoryPath = (
  root: RetainedDirectory,
  segments: ReadonlyArray<string>,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<RetainedDirectory, WorkspaceAccessError> =>
  Effect.gen(function* () {
    const duplicate = yield* duplicateDirectory(root, operation);
    let current = duplicate;
    for (const segment of segments) {
      const next = yield* openDirectoryFrom(current, segment, operation).pipe(
        Effect.tapError(() => closeQuietly(current.file)),
      );
      yield* closeQuietly(current.file);
      current = next;
    }
    return current;
  });

const withParentDirectory = <A>(
  root: RetainedDirectory,
  segments: ReadonlyArray<string>,
  operation: WorkspaceAccessError['operation'],
  use: (parent: RetainedDirectory, name: string) => Effect.Effect<A, WorkspaceAccessError>,
): Effect.Effect<A, WorkspaceAccessError> => {
  const leaf = segments.at(-1);
  if (leaf === undefined || !validName(leaf)) return Effect.fail(accessError(operation, 'unsafe-path'));
  return Effect.acquireUseRelease(
    openDirectoryPath(root, segments.slice(0, -1), operation),
    parent => use(parent, leaf),
    parent => closeQuietly(parent.file),
  );
};

const classifyStat = (
  stat: Awaited<ReturnType<typeof lstat>>,
): WorkspaceEntryStat['kind'] => {
  if (stat.isFile()) return 'file';
  if (stat.isDirectory()) return 'directory';
  if (stat.isSymbolicLink()) return 'symlink';
  if (stat.isBlockDevice()) return 'block-device';
  if (stat.isCharacterDevice()) return 'character-device';
  if (stat.isFIFO()) return 'fifo';
  if (stat.isSocket()) return 'socket';
  return 'unsupported';
};

const statPath = (
  root: RetainedDirectory,
  path: WorkspaceRelativePath,
): Effect.Effect<WorkspaceEntryStat, WorkspaceAccessError> => {
  const segments = pathSegments(path);
  if (segments === undefined) return Effect.fail(accessError('stat', 'unsafe-path'));
  if (segments.length === 0) {
    return Effect.tryPromise({
      try: () => root.file.stat(),
      catch: () => accessError('stat', 'unsafe-entry'),
    }).pipe(Effect.map(() => new WorkspaceEntryStat({ kind: 'directory', byteLength: 0 })));
  }
  return withParentDirectory(root, segments, 'stat', (parent, name) =>
    Effect.tryPromise({
      try: () => lstat(descriptorPath(parent.file, name)),
      catch: () => accessError('stat', 'unsafe-entry'),
    }).pipe(Effect.map(stat => new WorkspaceEntryStat({
      kind: classifyStat(stat),
      byteLength: stat.isFile() ? Number(stat.size) : 0,
    }))),
  );
};

const openRegularFile = (
  root: RetainedDirectory,
  path: WorkspaceRelativePath,
  operation: 'read-text' | 'digest-regular-file' | 'copy-regular-file' | 'run-analyzer',
): Effect.Effect<FileHandle, WorkspaceAccessError> => {
  const segments = pathSegments(path);
  if (segments === undefined || segments.length === 0) {
    return Effect.fail(accessError(operation, 'unsafe-path'));
  }
  return withParentDirectory(root, segments, operation, (parent, name) =>
    Effect.tryPromise({
      try: () => open(descriptorPath(parent.file, name), RegularReadFlags),
      catch: () => accessError(operation, 'unsafe-entry'),
    }).pipe(
      Effect.flatMap(file => Effect.tryPromise({
        try: () => file.stat(),
        catch: () => accessError(operation, 'unsafe-entry'),
      }).pipe(
        Effect.flatMap(stat => stat.isFile()
          ? Effect.succeed(file)
          : Effect.fail(accessError(operation, 'unsafe-entry'))),
        Effect.tapError(() => closeQuietly(file)),
      )),
    ),
  );
};

const readBounded = (
  file: FileHandle,
  maximumBytes: number,
  operation: 'read-text' | 'digest-regular-file' | 'copy-regular-file' | 'run-analyzer',
): Effect.Effect<ReadonlyArray<Uint8Array>, WorkspaceAccessError> =>
  Effect.gen(function* () {
    const chunks = new Array<Uint8Array>();
    let total = 0;
    let position = 0;
    let complete = false;
    while (!complete) {
      const remainingProbe = maximumBytes - total + 1;
      const length = Math.max(1, Math.min(StreamChunkBytes, remainingProbe));
      const buffer = Buffer.allocUnsafe(length);
      const result = yield* Effect.tryPromise({
        try: () => file.read(buffer, 0, length, position),
        catch: () => accessError(operation, 'unsafe-entry'),
      });
      if (result.bytesRead === 0) {
        complete = true;
        continue;
      }
      if (total + result.bytesRead > maximumBytes) {
        return yield* Effect.fail(accessError(operation, 'bound-exceeded'));
      }
      chunks.push(buffer.subarray(0, result.bytesRead));
      total += result.bytesRead;
      position += result.bytesRead;
    }
    return chunks;
  });

const reserve = (
  ledger: QuotaLedger,
  entries: number,
  files: number,
  bytes: number,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<void, WorkspaceAccessError> =>
  Effect.suspend(() => {
    if (
      !Number.isSafeInteger(entries) ||
      !Number.isSafeInteger(files) ||
      !Number.isSafeInteger(bytes) ||
      entries < 0 ||
      files < 0 ||
      bytes < 0 ||
      ledger.entries + entries > ledger.quota.maximumEntries ||
      ledger.files + files > ledger.quota.maximumFiles ||
      ledger.bytes + bytes > ledger.quota.maximumBytes
    ) {
      return Effect.fail(accessError(operation, 'workspace-quota-exceeded'));
    }
    ledger.entries += entries;
    ledger.files += files;
    ledger.bytes += bytes;
    return Effect.void;
  });

const release = (
  ledger: QuotaLedger,
  entries: number,
  files: number,
  bytes: number,
) => Effect.sync(() => {
  ledger.entries = Math.max(0, ledger.entries - entries);
  ledger.files = Math.max(0, ledger.files - files);
  ledger.bytes = Math.max(0, ledger.bytes - bytes);
});

const readDirectory = (
  root: RetainedDirectory,
  path: WorkspaceRelativePath,
  remainingEntries: number,
): Effect.Effect<WorkspaceDirectoryBatch, WorkspaceAccessError> => {
  const segments = pathSegments(path);
  if (segments === undefined) return Effect.fail(accessError('read-directory', 'unsafe-path'));
  return Effect.acquireUseRelease(
    openDirectoryPath(root, segments, 'read-directory'),
    directory => Effect.acquireUseRelease(
      Effect.tryPromise({
        try: () => opendir(descriptorPath(directory.file)),
        catch: () => accessError('read-directory', 'unsafe-entry'),
      }),
      dir => Effect.gen(function* () {
        const entries = new Array<WorkspaceDirectoryEntry>();
        let truncated = false;
        let complete = false;
        while (!complete && entries.length <= remainingEntries) {
          const entry = yield* Effect.tryPromise({
            try: () => dir.read(),
            catch: () => accessError('read-directory', 'unsafe-entry'),
          });
          if (entry === null) {
            complete = true;
            continue;
          }
          if (!validName(entry.name)) {
            return yield* Effect.fail(accessError('read-directory', 'unsafe-entry'));
          }
          if (entries.length === remainingEntries) {
            truncated = true;
            complete = true;
            continue;
          }
          const details = yield* statPath(
            directory,
            new WorkspaceRelativePath({ segments: [entry.name] }),
          );
          entries.push(new WorkspaceDirectoryEntry({ name: entry.name, kind: details.kind }));
        }
        return new WorkspaceDirectoryBatch({ entries, truncated });
      }),
      dir => Effect.tryPromise({
        try: () => dir.close(),
        catch: () => accessError('read-directory', 'cleanup-failed'),
      }).pipe(Effect.catch(() => Effect.void)),
    ),
    directory => closeQuietly(directory.file),
  );
};

const readText = (
  root: RetainedDirectory,
  path: WorkspaceRelativePath,
  remainingBytes: number,
): Effect.Effect<string, WorkspaceAccessError> =>
  Effect.acquireUseRelease(
    openRegularFile(root, path, 'read-text'),
    file => readBounded(file, remainingBytes, 'read-text').pipe(
      Effect.flatMap(chunks => Effect.try({
        try: () => new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
        catch: () => accessError('read-text', 'unsafe-entry'),
      })),
    ),
    closeQuietly,
  );

const digestRegularFile = (
  root: RetainedDirectory,
  path: WorkspaceRelativePath,
  remainingBytes: number,
): Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError> =>
  Effect.acquireUseRelease(
    openRegularFile(root, path, 'digest-regular-file'),
    file => readBounded(file, remainingBytes, 'digest-regular-file').pipe(
      Effect.map(chunks => {
        const digest = createHash('sha256');
        let byteLength = 0;
        for (const chunk of chunks) {
          digest.update(chunk);
          byteLength += chunk.byteLength;
        }
        return new WorkspaceFileDigest({
          contentDigest: `sha256:${digest.digest('hex')}`,
          byteLength,
        });
      }),
    ),
    closeQuietly,
  );

const makeDirectory = (
  workspace: OwnedWorkspace,
  path: WorkspaceRelativePath,
): Effect.Effect<void, WorkspaceAccessError> => {
  const segments = pathSegments(path);
  if (segments === undefined || segments.length === 0) {
    return Effect.fail(accessError('make-directory', 'unsafe-path'));
  }
  return reserve(workspace.ledger, 1, 0, 0, 'make-directory').pipe(
    Effect.andThen(withParentDirectory(workspace.root, segments, 'make-directory', (parent, name) =>
      Effect.tryPromise({
        try: () => mkdir(descriptorPath(parent.file, name), { mode: 0o700 }),
        catch: () => accessError('make-directory', 'unsafe-entry'),
      }).pipe(
        Effect.andThen(openDirectoryFrom(parent, name, 'make-directory')),
        Effect.tap(directory => closeQuietly(directory.file)),
        Effect.asVoid,
      ),
    )),
    Effect.tapError(() => release(workspace.ledger, 1, 0, 0)),
  );
};

const openWriter = (
  workspace: OwnedWorkspace,
  path: WorkspaceRelativePath,
): Effect.Effect<LinuxDescriptorFileWriter, WorkspaceAccessError> => {
  const segments = pathSegments(path);
  if (segments === undefined || segments.length === 0) {
    return Effect.fail(accessError('write-file', 'unsafe-path'));
  }
  return reserve(workspace.ledger, 1, 1, 0, 'write-file').pipe(
    Effect.andThen(openDirectoryPath(
      workspace.root,
      segments.slice(0, -1),
      'write-file',
    ).pipe(
      Effect.flatMap(parent => {
        const name = segments.at(-1);
        if (name === undefined) {
          return Effect.fail(accessError('write-file', 'unsafe-path')).pipe(
            Effect.ensuring(closeQuietly(parent.file)),
          );
        }
        return Effect.tryPromise({
          try: () => open(descriptorPath(parent.file, name), RegularWriteFlags, 0o600),
          catch: () => accessError('write-file', 'unsafe-entry'),
        }).pipe(
          Effect.map(file => ({ parent, name, file })),
          Effect.tapError(() => closeQuietly(parent.file)),
        );
      }),
    )),
    Effect.tapError(() => release(workspace.ledger, 1, 1, 0)),
    Effect.map(resource => {
      let closed = false;
      let writtenBytes = 0;
      const writer: LinuxDescriptorFileWriter = {
        write: chunk => closed
          ? Effect.fail(accessError('write-file', 'workspace-closed'))
          : reserve(workspace.ledger, 0, 0, chunk.byteLength, 'write-file').pipe(
            Effect.andThen(Effect.tryPromise({
              try: () => resource.file.writeFile(chunk),
              catch: () => accessError('write-file', 'unsafe-entry'),
            })),
            Effect.tap(() => Effect.sync(() => {
              writtenBytes += chunk.byteLength;
            })),
            Effect.tapError(() => release(workspace.ledger, 0, 0, chunk.byteLength)),
            Effect.asVoid,
          ),
        close: commit => Effect.uninterruptible(Effect.suspend(() => {
          if (closed) return Effect.void;
          closed = true;
          return closeQuietly(resource.file).pipe(
            Effect.andThen(commit
              ? Effect.void
              : Effect.tryPromise({
                try: () => unlink(descriptorPath(resource.parent.file, resource.name)),
                catch: () => accessError('write-file', 'cleanup-failed'),
              }).pipe(
                Effect.asVoid,
                Effect.andThen(release(workspace.ledger, 1, 1, writtenBytes)),
              )),
            Effect.ensuring(closeQuietly(resource.parent.file)),
          );
        })),
      };
      return writer;
    }),
  );
};

const copyRegularFileTo = (
  source: RetainedDirectory,
  sourcePath: WorkspaceRelativePath,
  destination: LinuxDescriptorStagingOperations,
  destinationPath: WorkspaceRelativePath,
  remainingBytes: number,
): Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError> =>
  Effect.acquireUseRelease(
    openRegularFile(source, sourcePath, 'copy-regular-file'),
    file => Effect.acquireUseRelease(
      destination.openFileWriter(destinationPath),
      writer => readBounded(file, remainingBytes, 'copy-regular-file').pipe(
        Effect.flatMap(chunks => Effect.gen(function* () {
          const digest = createHash('sha256');
          let byteLength = 0;
          for (const chunk of chunks) {
            yield* writer.write(chunk);
            digest.update(chunk);
            byteLength += chunk.byteLength;
          }
          return new WorkspaceFileDigest({
            contentDigest: `sha256:${digest.digest('hex')}`,
            byteLength,
          });
        })),
      ),
      (writer, exit) => writer.close(exit._tag === 'Success').pipe(Effect.orDie),
    ),
    closeQuietly,
  );

const readOperations = (root: RetainedDirectory): LinuxDescriptorReadOperations => {
  const operations: LinuxDescriptorReadOperations = {
    readDirectory: (path, remainingEntries) => readDirectory(root, path, remainingEntries),
    stat: path => statPath(root, path),
    readText: (path, remainingBytes) => readText(root, path, remainingBytes),
    digestRegularFile: (path, remainingBytes) => digestRegularFile(root, path, remainingBytes),
  };
  retainedReadRoots.set(operations, root);
  return operations;
};

const stagingOperations = (workspace: OwnedWorkspace): LinuxDescriptorStagingOperations => {
  const operations: LinuxDescriptorStagingOperations = {
    ...readOperations(workspace.root),
    makeDirectory: path => workspace.sealed
      ? Effect.fail(accessError('make-directory', 'staging-sealed'))
      : makeDirectory(workspace, path),
    openFileWriter: path => workspace.sealed
      ? Effect.fail(accessError('write-file', 'staging-sealed'))
      : openWriter(workspace, path),
    runGitResolver: () => Effect.fail(accessError('run', 'process-rejected')),
  };
  ownedStagingRoots.set(operations, workspace);
  return operations;
};

interface CleanupBudget {
  remainingEntries: number;
}

const removeEmptyDirectory = (
  parent: RetainedDirectory,
  leaf: string,
  operation: WorkspaceAccessError['operation'],
): Effect.Effect<void, WorkspaceAccessError> =>
  Effect.tryPromise({
    try: () => rmdir(descriptorPath(parent.file, leaf)),
    catch: () => accessError(operation, 'cleanup-failed'),
  });

const readCleanupEntry = (directory: Dir): Effect.Effect<Dirent | null, WorkspaceAccessError> =>
  Effect.tryPromise({
    try: () => directory.read(),
    catch: () => accessError('close', 'cleanup-failed'),
  });

const cleanupDirectory = (
  directory: RetainedDirectory,
  budget: CleanupBudget,
): Effect.Effect<void, WorkspaceAccessError> =>
  Effect.acquireUseRelease(
    Effect.tryPromise({
      try: () => opendir(descriptorPath(directory.file)),
      catch: () => accessError('close', 'cleanup-failed'),
    }),
    cursor => Effect.gen(function* () {
      let entry = yield* readCleanupEntry(cursor);
      while (entry !== null) {
        const current = entry;
        if (budget.remainingEntries <= 0 || !validName(current.name)) {
          return yield* Effect.fail(accessError('close', 'cleanup-failed'));
        }
        budget.remainingEntries -= 1;
        const metadata = yield* Effect.tryPromise({
          try: () => lstat(descriptorPath(directory.file, current.name)),
          catch: () => accessError('close', 'cleanup-failed'),
        });
        if (metadata.isDirectory()) {
          const child = yield* openDirectoryFrom(directory, current.name, 'close');
          yield* cleanupDirectory(child, budget).pipe(
            Effect.ensuring(closeQuietly(child.file)),
          );
          yield* removeEmptyDirectory(directory, current.name, 'close');
        } else {
          yield* Effect.tryPromise({
            try: () => unlink(descriptorPath(directory.file, current.name)),
            catch: () => accessError('close', 'cleanup-failed'),
          });
        }
        entry = yield* readCleanupEntry(cursor);
      }
    }),
    closeDirectoryQuietly,
  );

const cleanupWorkspace = (workspace: OwnedWorkspace): Effect.Effect<void, WorkspaceAccessError> =>
  identityOf(workspace.root.file).pipe(
    Effect.flatMap(identity => sameIdentity(identity, workspace.root.identity)
      ? Effect.void
      : Effect.fail(accessError('close', 'cleanup-failed'))),
    Effect.andThen(Effect.tryPromise({
      try: () => workspace.root.file.chmod(0o700),
      catch: () => accessError('close', 'cleanup-failed'),
    })),
    Effect.andThen(cleanupDirectory(workspace.root, {
      remainingEntries: workspace.ledger.quota.maximumEntries,
    })),
    Effect.andThen(openDirectoryFrom(workspace.parent, workspace.leaf, 'close')),
    Effect.flatMap(current => (
      sameIdentity(current.identity, workspace.root.identity)
        ? removeEmptyDirectory(workspace.parent, workspace.leaf, 'close')
        : Effect.fail(accessError('close', 'cleanup-failed'))
    ).pipe(Effect.ensuring(closeQuietly(current.file)))),
  );

const closeWorkspace = (workspace: OwnedWorkspace) => Effect.uninterruptible(
  Effect.suspend(() => {
    if (workspace.closed) return Effect.void;
    workspace.closed = true;
    return cleanupWorkspace(workspace).pipe(
      Effect.tapError(() => Effect.sync(() => {
        workspace.orphaned = true;
      })),
      // A scope finalizer cannot carry a checked error. A failed bounded
      // cleanup is nevertheless terminal: leave the orphan marker intact and
      // fail the owning scope rather than reporting a false successful close.
      Effect.orDie,
      Effect.ensuring(closeQuietly(workspace.root.file)),
      Effect.ensuring(closeQuietly(workspace.parent.file)),
    );
  }),
);

const createWorkspace = (
  parent: RetainedDirectory,
  quota: WorkspaceQuota,
): Effect.Effect<OwnedWorkspace, WorkspaceAllocationError> =>
  Effect.gen(function* () {
    const leaseParent = yield* duplicateDirectory(parent, 'allocate').pipe(
      Effect.mapError(error => allocationError(error.reason)),
    );
    const leaf = `radar-${randomBytes(16).toString('hex')}`;
    const result = yield* Effect.result(
      Effect.tryPromise({
        try: () => mkdir(descriptorPath(leaseParent.file, leaf), { mode: 0o700 }),
        catch: () => allocationError('workspace-quota-unenforced'),
      }).pipe(
        Effect.andThen(openDirectoryFrom(leaseParent, leaf, 'allocate').pipe(
          Effect.tapError(() => removeEmptyDirectory(leaseParent, leaf, 'allocate').pipe(
            Effect.mapError(error => allocationError(error.reason)),
          )),
        )),
        Effect.map(root => ({
          parent: leaseParent,
          root,
          leaf,
          ledger: { quota, entries: 0, files: 0, bytes: 0 },
          sealed: false,
          closed: false,
          orphaned: false,
        })),
      ),
    );
    if (result._tag === 'Success') return result.success;
    yield* closeQuietly(leaseParent.file);
    return yield* Effect.fail(allocationError('workspace-quota-unenforced'));
  });

const sealWorkspace = (workspace: OwnedWorkspace): Effect.Effect<void, WorkspaceAccessError> =>
  Effect.suspend(() => {
    if (workspace.closed) return Effect.fail(accessError('seal', 'workspace-closed'));
    workspace.sealed = true;
    return Effect.tryPromise({
      try: () => workspace.root.file.chmod(0o500),
      catch: () => accessError('seal', 'read-only'),
    });
  });

const collectGovernedProcessOutput = (
  session: ResourceGovernedAnalyzerSession,
  request: ProcessRequest,
  signal: AbortSignal,
) => new Promise<ProcessOutput>(resolve => {
  const startedAt = Date.now();
  let stdout = '';
  let stderr = '';
  let outputBytes = 0;
  let exitCode = -1;
  let timedOut = false;
  let truncated = false;
  let childClosed = false;
  let completionSettled = false;
  let completed = false;
  let cancellationRequested = false;
  const requestCancellation = () => {
    if (cancellationRequested) return;
    cancellationRequested = true;
    session.cancel();
  };
  const onStdout = (chunk: Buffer) => append('stdout', chunk);
  const onStderr = (chunk: Buffer) => append('stderr', chunk);
  const onClose = () => {
    childClosed = true;
    finish();
  };
  const onError = () => {
    childClosed = true;
    finish();
  };
  const detach = () => {
    signal.removeEventListener('abort', requestCancellation);
    session.child.stdout?.off('data', onStdout);
    session.child.stderr?.off('data', onStderr);
    session.child.off('close', onClose);
    session.child.off('error', onError);
  };
  const finish = () => {
    if (completed || !childClosed || !completionSettled) return;
    completed = true;
    detach();
    resolve(new ProcessOutput({
      exitCode,
      stdout,
      stderr,
      durationMs: Math.max(0, Date.now() - startedAt),
      timedOut,
      truncated,
    }));
  };
  const append = (target: 'stdout' | 'stderr', chunk: Buffer) => {
    const permitted = Math.max(0, request.maxOutputBytes - outputBytes);
    const captured = chunk.subarray(0, permitted);
    outputBytes += chunk.byteLength;
    if (target === 'stdout') stdout += captured.toString('utf8');
    else stderr += captured.toString('utf8');
    if (outputBytes > request.maxOutputBytes) {
      truncated = true;
      requestCancellation();
    }
  };
  signal.addEventListener('abort', requestCancellation, { once: true });
  session.child.stdout?.on('data', onStdout);
  session.child.stderr?.on('data', onStderr);
  session.child.once('close', onClose);
  session.child.once('error', onError);
  if (session.child.exitCode !== null) childClosed = true;
  void session.completion.then(
    completion => {
      exitCode = completion.exitCode;
      timedOut = completion.reason === 'timeout';
      completionSettled = true;
      finish();
    },
    () => {
      completionSettled = true;
      finish();
    },
  );
});

const governedSemanticProcess = (
  source: RetainedDirectory,
  analyzerRequest: FileHandle,
  request: ProcessRequest,
  options: Pick<
    NodeLinuxDescriptorWorkspaceBindingOptions,
    'resourceCgroupRoot' | 'materializedRuntime'
  >,
): Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope> =>
  Effect.acquireUseRelease(
    Effect.tryPromise({
      try: signal => launchResourceGovernedAnalyzer({
        analyzerId: request.analyzer,
        cgroupRoot: options.resourceCgroupRoot,
        materializedRuntime: options.materializedRuntime,
        sourceFd: source.file.fd,
        analyzerRequestFd: analyzerRequest.fd,
        timeoutMs: request.timeoutMs,
        signal,
      }),
      catch: () => accessError('run-analyzer', 'process-rejected'),
    }),
    session => Effect.tryPromise({
      try: signal => collectGovernedProcessOutput(session, request, signal),
      catch: () => accessError('run-analyzer', 'process-failed'),
    }),
    session => Effect.sync(() => session.cancel()).pipe(
      Effect.andThen(Effect.promise(() => session.completion)),
      Effect.asVoid,
      Effect.orDie,
    ),
  );

const withSemanticAnalyzerRequest = <A>(
  scratch: OwnedWorkspace,
  request: ProcessRequest,
  use: (analyzerRequest: FileHandle) => Effect.Effect<A, WorkspaceAccessError, Scope.Scope>,
): Effect.Effect<A, WorkspaceAccessError, Scope.Scope> => encodeSemanticAnalyzerRequest(request).pipe(
  Effect.mapError(() => accessError('run-analyzer', 'process-rejected')),
  Effect.flatMap(payload => Effect.acquireUseRelease(
    openWriter(
      scratch,
      new WorkspaceRelativePath({ segments: [SemanticAnalyzerRequestFile] }),
    ),
    writer => writer.write(payload),
    (writer, exit) => writer.close(exit._tag === 'Success'),
  ).pipe(
    Effect.flatMap(() => Effect.acquireUseRelease(
      openRegularFile(
        scratch.root,
        new WorkspaceRelativePath({ segments: [SemanticAnalyzerRequestFile] }),
        'run-analyzer',
      ),
      use,
      closeQuietly,
    )),
  )),
);

const assertPrivateParent = (
  directory: RetainedDirectory,
): Effect.Effect<void, WorkspaceAllocationError> =>
  Effect.tryPromise({
    try: () => directory.file.stat(),
    catch: () => allocationError('workspace-quota-unenforced'),
  }).pipe(
    Effect.flatMap(stat => {
      const owner = typeof process.getuid === 'function' ? process.getuid() : -1;
      const privateMode = (Number(stat.mode) & 0o077) === 0;
      return stat.isDirectory() && privateMode && (owner < 0 || Number(stat.uid) === owner)
        ? Effect.void
        : Effect.fail(allocationError('workspace-quota-unenforced'));
    }),
  );

export const probeNodeLinuxDescriptorHost = (
  options: Pick<NodeLinuxDescriptorWorkspaceBindingOptions, 'workspaceParent'>,
): Effect.Effect<void, WorkspaceAllocationError> => {
  if (
    process.platform !== 'linux' ||
    constants.O_NOFOLLOW === undefined ||
    constants.O_DIRECTORY === undefined
  ) {
    return Effect.fail(allocationError('unsupported-platform'));
  }
  return Effect.acquireUseRelease(
    openAbsoluteDirectory(options.workspaceParent, 'allocate').pipe(
      Effect.mapError(error => allocationError(error.reason)),
    ),
    // Host-tool identity, isolation behavior, cgroup limits, seccomp, and
    // network denial are attested by the installed trusted runtime verifier.
    // This descriptor-only probe must not launch an unauthenticated sandbox
    // process that lacks that governance boundary.
    assertPrivateParent,
    directory => closeQuietly(directory.file),
  );
};

type DescriptorAnalyzerRunner = (
  source: RetainedDirectory,
  scratch: OwnedWorkspace,
  request: ProcessRequest,
) => Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope>;

interface DescriptorWorkspaceBindingOptions {
  readonly workspaceParent: string;
  readonly runAnalyzer: DescriptorAnalyzerRunner;
}

const makeDescriptorWorkspaceBinding = (
  options: DescriptorWorkspaceBindingOptions,
): Effect.Effect<LinuxDescriptorWorkspaceBinding, WorkspaceAllocationError, Scope.Scope> => {
  if (process.platform !== 'linux') return Effect.fail(allocationError('unsupported-platform'));
  return Effect.gen(function* () {
    const parent = yield* Effect.acquireRelease(
      openAbsoluteDirectory(options.workspaceParent, 'allocate').pipe(
        Effect.mapError(error => allocationError(error.reason)),
      ),
      directory => closeQuietly(directory.file),
    );
    yield* assertPrivateParent(parent);
    return {
      allocate: quota => createWorkspace(parent, quota).pipe(
        Effect.map(workspace => ({
          staging: stagingOperations(workspace),
          source: readOperations(workspace.root),
          seal: sealWorkspace(workspace),
          close: closeWorkspace(workspace),
        })),
      ),
      allocateScratch: quota => createWorkspace(parent, quota).pipe(
        Effect.map(workspace => ({
          scratch: stagingOperations(workspace),
          close: closeWorkspace(workspace),
        })),
      ),
      openExternalSource: directory => openAbsoluteDirectory(directory, 'open-external-source').pipe(
        Effect.map(root => ({
          ...readOperations(root),
          copyRegularFileTo: (sourcePath, destination, destinationPath, remainingBytes) =>
            copyRegularFileTo(root, sourcePath, destination, destinationPath, remainingBytes),
          close: closeQuietly(root.file),
        })),
      ),
      runAnalyzer: (source, scratch, request) => {
        const sourceRoot = retainedReadRoots.get(source);
        const scratchRoot = ownedStagingRoots.get(scratch);
        return sourceRoot === undefined || scratchRoot === undefined
          ? Effect.fail(accessError('run-analyzer', 'process-rejected'))
          : options.runAnalyzer(sourceRoot, scratchRoot, request);
      },
    } satisfies LinuxDescriptorWorkspaceBinding;
  });
};

/**
 * Creates the only production workspace binding. Runtime bytes and all launch
 * descriptors remain opaque in the trusted governance module; this host owns
 * only source/scratch descriptors and cannot bind a target runtime pathname.
 */
export const makeNodeLinuxDescriptorWorkspaceBinding = (
  options: NodeLinuxDescriptorWorkspaceBindingOptions,
): Effect.Effect<LinuxDescriptorWorkspaceBinding, WorkspaceAllocationError, Scope.Scope> =>
  makeDescriptorWorkspaceBinding({
    workspaceParent: options.workspaceParent,
    runAnalyzer: (source, scratch, request) => withSemanticAnalyzerRequest(
      scratch,
      request,
      analyzerRequest => governedSemanticProcess(source, analyzerRequest, request, options),
    ),
  });

/**
 * Lifecycle-only fixture binding. It never launches an analyzer and therefore
 * cannot represent production readiness or a substitute runtime capability.
 */
export const makeNodeLinuxDescriptorWorkspaceBindingForTest = (
  options: Pick<NodeLinuxDescriptorWorkspaceBindingOptions, 'workspaceParent'>,
): Effect.Effect<LinuxDescriptorWorkspaceBinding, WorkspaceAllocationError, Scope.Scope> =>
  makeDescriptorWorkspaceBinding({
    workspaceParent: options.workspaceParent,
    runAnalyzer: () => Effect.fail(accessError('run-analyzer', 'process-rejected')),
  });
