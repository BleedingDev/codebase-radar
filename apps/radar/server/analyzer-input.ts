import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { Effect, FileSystem, Schema } from 'effect';
import {
  CanonicalRepositoryPathSet,
  encodeCanonicalRepositoryPathSet,
  RepositoryPathSetDigest,
} from '@codebase-radar/contracts';

export class AnalyzerInputFailure extends Schema.TaggedErrorClass<AnalyzerInputFailure>()(
  'AnalyzerInputFailure',
  { message: Schema.String },
) {}

export type AuditedAnalyzerInput = {
  readonly root: string;
  readonly stagedPaths: CanonicalRepositoryPathSet;
  readonly stagedBytes: number;
  readonly eligiblePathSetDigest: RepositoryPathSetDigest;
};

type ManagedAuditedAnalyzerInput = AuditedAnalyzerInput & {
  readonly directories: ReadonlyArray<string>;
};

type SourceEntry = {
  readonly path: string;
  readonly byteLength: number;
  readonly segments: ReadonlyArray<string>;
  readonly sourcePath: string;
};

type CopyResult =
  | { readonly _tag: 'copied'; readonly byteLength: number }
  | { readonly _tag: 'rejected' };

const copyChunkBytes = 64 * 1024;

const inputFailure = (message: string) => new AnalyzerInputFailure({ message });

export const canonicalRepositoryPathSet = (
  paths: ReadonlyArray<string>,
): Effect.Effect<CanonicalRepositoryPathSet, AnalyzerInputFailure> =>
  Schema.decodeUnknownEffect(CanonicalRepositoryPathSet)(paths).pipe(
    Effect.mapError(() => inputFailure(
      'The audited analyzer paths must be unique and in canonical UTF-8 byte order.',
    )),
  );

/** Hashes only a contract-validated, already canonical path set. */
export const digestCanonicalRepositoryPathSet = (
  paths: CanonicalRepositoryPathSet,
) =>
  Schema.decodeUnknownSync(RepositoryPathSetDigest)(
    `sha256:${createHash('sha256')
      .update(encodeCanonicalRepositoryPathSet(paths))
      .digest('hex')}`,
  );

const within = (root: string, path: string) =>
  path.startsWith(`${root}${sep}`);

const pathSegments = (
  path: string,
): Effect.Effect<ReadonlyArray<string>, AnalyzerInputFailure> => {
  if (
    path.length === 0 ||
    path.includes('\0') ||
    path.includes('\\') ||
    path.startsWith('/')
  ) {
    return Effect.fail(
      inputFailure('The audited analyzer path is not repository-relative.'),
    );
  }
  const segments = path.split('/');
  return segments.some(
    segment => segment.length === 0 || segment === '.' || segment === '..',
  )
    ? Effect.fail(inputFailure('The audited analyzer path contains an unsafe segment.'))
    : Effect.succeed(segments);
};

const isSymbolicLink = (fs: FileSystem.FileSystem, path: string) =>
  fs.readLink(path).pipe(
    Effect.as(true),
    Effect.catch(() => Effect.succeed(false)),
  );

const regularDirectory = Effect.fn('auditedAnalyzerRegularDirectory')(
  function* (fs: FileSystem.FileSystem, path: string) {
    if (yield* isSymbolicLink(fs, path)) {
      return yield* Effect.fail(
        inputFailure('The analyzer workspace roots must be regular directories.'),
      );
    }
    const info = yield* fs.stat(path).pipe(
      Effect.mapError(() =>
        inputFailure('The analyzer workspace roots must be regular directories.')),
    );
    if (info.type !== 'Directory') {
      return yield* Effect.fail(
        inputFailure('The analyzer workspace roots must be regular directories.'),
      );
    }
  },
);

const regularSourcePath = Effect.fn('auditedAnalyzerRegularSourcePath')(
  function* (
    fs: FileSystem.FileSystem,
    sourceRoot: string,
    segments: ReadonlyArray<string>,
  ) {
    let current = sourceRoot;
    for (const [index, segment] of segments.entries()) {
      current = join(current, segment);
      if (yield* isSymbolicLink(fs, current)) {
        return yield* Effect.fail(
          inputFailure('The audited analyzer input contains a symbolic link.'),
        );
      }
      const info = yield* fs.stat(current).pipe(
        Effect.mapError(() =>
          inputFailure('The audited analyzer input is not a regular file.')),
      );
      const expectedType = index === segments.length - 1 ? 'File' : 'Directory';
      if (info.type !== expectedType) {
        return yield* Effect.fail(
          inputFailure('The audited analyzer input is not a regular file.'),
        );
      }
    }
  },
);

const prepareSourceEntry = (
  sourceRoot: string,
  entry: { readonly path: string; readonly byteLength: number },
): Effect.Effect<SourceEntry, AnalyzerInputFailure> =>
  pathSegments(entry.path).pipe(
    Effect.flatMap(segments => {
      if (!Number.isSafeInteger(entry.byteLength) || entry.byteLength < 0) {
        return Effect.fail(inputFailure('The audited analyzer input envelope is invalid.'));
      }
      const sourcePath = resolve(sourceRoot, ...segments);
      return within(sourceRoot, sourcePath)
        ? Effect.succeed({ ...entry, segments, sourcePath } satisfies SourceEntry)
        : Effect.fail(inputFailure('The audited analyzer path escapes its source root.'));
    }),
  );

const closeDescriptor = (descriptor: number) => {
  if (descriptor < 0) return;
  try {
    closeSync(descriptor);
  } catch {}
};

/**
 * The Node FileSystem service does not expose O_NOFOLLOW or lstat.  This
 * sealed-root descriptor boundary is intentionally synchronous so its final
 * file descriptor, inode, and byte accounting can be checked atomically.
 */
const copyChunkedNoFollow = (
  source: string,
  destination: string,
  expectedBytes: number,
): CopyResult => {
  let sourceDescriptor = -1;
  let destinationDescriptor = -1;
  try {
    sourceDescriptor = openSync(
      source,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    const before = fstatSync(sourceDescriptor);
    const listedBefore = lstatSync(source);
    if (
      !before.isFile() ||
      listedBefore.isSymbolicLink() ||
      before.dev !== listedBefore.dev ||
      before.ino !== listedBefore.ino ||
      before.size !== expectedBytes
    ) {
      return { _tag: 'rejected' };
    }
    destinationDescriptor = openSync(
      destination,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
    );
    const buffer = new Uint8Array(Math.min(copyChunkBytes, Math.max(1, expectedBytes)));
    let copied = 0;
    while (copied < expectedBytes) {
      const read = readSync(
        sourceDescriptor,
        buffer,
        0,
        Math.min(buffer.byteLength, expectedBytes - copied),
        null,
      );
      if (read <= 0) return { _tag: 'rejected' };
      let written = 0;
      while (written < read) {
        const next = writeSync(destinationDescriptor, buffer, written, read - written);
        if (next <= 0) return { _tag: 'rejected' };
        written += next;
      }
      copied += read;
    }
    if (readSync(sourceDescriptor, new Uint8Array(1), 0, 1, null) !== 0) {
      return { _tag: 'rejected' };
    }
    const after = fstatSync(sourceDescriptor);
    const listedAfter = lstatSync(source);
    return after.isFile() &&
      !listedAfter.isSymbolicLink() &&
      after.dev === before.dev &&
      after.ino === before.ino &&
      after.size === before.size &&
      listedAfter.dev === before.dev &&
      listedAfter.ino === before.ino
      ? { _tag: 'copied', byteLength: copied }
      : { _tag: 'rejected' };
  } catch {
    return { _tag: 'rejected' };
  } finally {
    closeDescriptor(destinationDescriptor);
    closeDescriptor(sourceDescriptor);
  }
};

const removeStagedRoot = (
  fs: FileSystem.FileSystem,
  root: string,
  directories: ReadonlyArray<string>,
) =>
  Effect.forEach(
    [...directories].sort((left, right) => right.length - left.length),
    directory => fs.chmod(directory, 0o700).pipe(Effect.ignore),
    { concurrency: 1, discard: true },
  ).pipe(
    Effect.andThen(
      fs.remove(root, { recursive: true, force: true }).pipe(
        Effect.retry({ times: 8 }),
      ),
    ),
    Effect.mapError(() => inputFailure('The audited analyzer input could not be removed.')),
  );

const stageAuditedInput = Effect.fn('stageAuditedAnalyzerInput')(function* (
  input: {
    readonly sourceRoot: string;
    readonly scratchRoot: string;
    readonly entries: ReadonlyArray<{
      readonly path: string;
      readonly byteLength: number;
    }>;
    readonly maximumFiles: number;
    readonly maximumBytes: number;
  },
) {
  if (
    !Number.isSafeInteger(input.maximumFiles) ||
    input.maximumFiles < 0 ||
    input.entries.length > input.maximumFiles ||
    !Number.isSafeInteger(input.maximumBytes) ||
    input.maximumBytes < 0
  ) {
    return yield* Effect.fail(inputFailure('The audited analyzer input envelope is invalid.'));
  }
  const fs = yield* FileSystem.FileSystem;
  const sourceRoot = resolve(input.sourceRoot);
  const scratchRoot = resolve(input.scratchRoot);
  yield* regularDirectory(fs, sourceRoot);
  yield* regularDirectory(fs, scratchRoot);
  const sourceRealRoot = yield* fs.realPath(sourceRoot).pipe(
    Effect.mapError(() => inputFailure('The analyzer workspace roots must be regular directories.')),
  );
  const auditedPaths = yield* canonicalRepositoryPathSet(
    input.entries.map(entry => entry.path),
  );
  const sourcePaths = yield* Effect.forEach(
    input.entries,
    entry => prepareSourceEntry(sourceRoot, entry),
    { concurrency: 1 },
  );
  const root = yield* fs.makeTempDirectory({
    directory: scratchRoot,
    prefix: 'analyzer-input-',
  }).pipe(
    Effect.mapError(() => inputFailure('The audited analyzer input could not be staged.')),
  );
  const directories = new Set<string>([root]);
  const stagedPaths = new Array<string>();
  let stagedBytes = 0;
  const stage = Effect.gen(function* () {
    for (const source of sourcePaths) {
      yield* regularSourcePath(fs, sourceRoot, source.segments);
      const sourceRealPath = yield* fs.realPath(source.sourcePath).pipe(
        Effect.mapError(() => inputFailure('The audited analyzer input is not a regular file.')),
      );
      if (!within(sourceRealRoot, sourceRealPath)) {
        return yield* Effect.fail(
          inputFailure('The audited analyzer input escapes its source root.'),
        );
      }
      const destination = resolve(root, ...source.segments);
      if (!within(root, destination)) {
        return yield* Effect.fail(
          inputFailure('The staged analyzer path escapes its input root.'),
        );
      }
      const destinationDirectory = dirname(destination);
      yield* fs.makeDirectory(destinationDirectory, { recursive: true, mode: 0o700 }).pipe(
        Effect.mapError(() => inputFailure('The audited analyzer input could not be staged.')),
      );
      let directory = destinationDirectory;
      while (within(root, directory)) {
        directories.add(directory);
        directory = dirname(directory);
      }
      if (source.byteLength > input.maximumBytes - stagedBytes) {
        return yield* Effect.fail(
          inputFailure('The staged analyzer input exceeded its audited byte envelope.'),
        );
      }
      const copied = yield* Effect.sync(() =>
        copyChunkedNoFollow(source.sourcePath, destination, source.byteLength),
      );
      if (copied._tag !== 'copied' || copied.byteLength !== source.byteLength) {
        return yield* Effect.fail(
          inputFailure('The audited analyzer input changed while it was staged.'),
        );
      }
      stagedBytes += copied.byteLength;
      stagedPaths.push(source.path);
    }
    yield* Effect.forEach(
      stagedPaths,
      path => fs.chmod(resolve(root, ...path.split('/')), 0o400),
      { concurrency: 1, discard: true },
    ).pipe(
      Effect.mapError(() => inputFailure('The audited analyzer input could not be sealed.')),
    );
    yield* Effect.forEach(
      [...directories],
      directory => fs.chmod(directory, 0o500),
      { concurrency: 1, discard: true },
    ).pipe(
      Effect.mapError(() => inputFailure('The audited analyzer input could not be sealed.')),
    );
    const stagedPathSet = yield* canonicalRepositoryPathSet(stagedPaths);
    const eligiblePathSetDigest = digestCanonicalRepositoryPathSet(auditedPaths);
    return digestCanonicalRepositoryPathSet(stagedPathSet) === eligiblePathSetDigest
      ? {
        root,
        stagedPaths: stagedPathSet,
        stagedBytes,
        eligiblePathSetDigest,
        directories: [...directories],
      } satisfies ManagedAuditedAnalyzerInput
      : yield* Effect.fail(
        inputFailure('The staged analyzer paths differ from the audited path set.'),
      );
  });
  return yield* stage.pipe(
    Effect.onError(() => removeStagedRoot(fs, root, [...directories]).pipe(Effect.ignore)),
  );
});

const removeStagedInput = (input: ManagedAuditedAnalyzerInput) =>
  Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    yield* removeStagedRoot(fs, input.root, input.directories);
  });

export const materializeAuditedAnalyzerInput = (input: {
  readonly sourceRoot: string;
  readonly scratchRoot: string;
  readonly entries: ReadonlyArray<{
    readonly path: string;
    readonly byteLength: number;
  }>;
  readonly maximumFiles: number;
  readonly maximumBytes: number;
}) =>
  Effect.acquireRelease(
    stageAuditedInput(input),
    view => removeStagedInput(view).pipe(Effect.orDie),
  );
