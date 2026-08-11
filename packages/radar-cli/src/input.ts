import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from 'node:fs';
import {
  Crypto,
  DateTime,
  Effect,
  Encoding,
  FileSystem,
  Path,
} from 'effect';
import {
  AnalysisRequest,
  BranchRevision,
  CommitRevision,
  ContractLimits,
  decodeAnalysisRequest,
  decodeAnalysisSource,
  decodeScanResultJson,
  DefaultBranchRevision,
  GitHubSource,
  LocalDirectorySource,
  TagRevision,
} from '@codebase-radar/contracts';
import type {
  AnalysisSource,
  GitHubRevision,
  SuccessfulScanResult,
} from '@codebase-radar/contracts';
import { CliRuntimeError, CliUsageError } from './errors.js';

const sourceUsageError = (message: string) => new CliUsageError({ message });

const readBoundedBaselineFile = (baselinePath: string) =>
  Effect.try({
    try: () => {
      const original = lstatSync(baselinePath, { throwIfNoEntry: false });
      if (
        original === undefined ||
        original.isSymbolicLink() ||
        !original.isFile()
      ) {
        return undefined;
      }
      const descriptor = openSync(
        baselinePath,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const metadata = fstatSync(descriptor);
        // Physical block counts are not portable across compressed/COW filesystems;
        // the logical byte cap and bounded descriptor reads are the resource boundary.
        if (
          !metadata.isFile() ||
          metadata.dev !== original.dev ||
          metadata.ino !== original.ino ||
          !Number.isSafeInteger(metadata.size) ||
          metadata.size < 0 ||
          metadata.size > ContractLimits.encodedResultBytes
        ) {
          return undefined;
        }
        const bytes = new Uint8Array(metadata.size);
        let offset = 0;
        while (offset < bytes.byteLength) {
          const read = readSync(
            descriptor,
            bytes,
            offset,
            Math.min(64 * 1024, bytes.byteLength - offset),
            offset,
          );
          if (read < 1) return undefined;
          offset += read;
        }
        const extra = new Uint8Array(1);
        if (readSync(descriptor, extra, 0, 1, bytes.byteLength) !== 0) {
          return undefined;
        }
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } finally {
        closeSync(descriptor);
      }
    },
    catch: () => sourceUsageError(
      'Baseline must be a bounded regular non-symlink file.',
    ),
  }).pipe(
    Effect.flatMap(contents =>
      contents === undefined
        ? Effect.fail(sourceUsageError('Baseline must be a bounded regular non-symlink file.'))
        : Effect.succeed(contents)),
  );

const revisionFromText = (value: string | undefined): Effect.Effect<GitHubRevision, CliUsageError> => {
  if (value === undefined) return Effect.succeed(new DefaultBranchRevision({}));
  if (value.startsWith('branch:')) {
    return Effect.succeed(new BranchRevision({ branch: value.slice('branch:'.length) }));
  }
  if (value.startsWith('tag:')) {
    return Effect.succeed(new TagRevision({ tag: value.slice('tag:'.length) }));
  }
  if (value.startsWith('commit:')) {
    return Effect.succeed(new CommitRevision({ commitSha: value.slice('commit:'.length) }));
  }
  return Effect.fail(sourceUsageError(
    'GitHub revision must be branch:<name>, tag:<name>, or commit:<sha>.',
  ));
};

export const makeGitHubSource = Effect.fn('makeGitHubSource')(function* (
  locator: string,
  revisionText: string | undefined,
) {
  const parts = locator.split('/');
  const owner = parts[0];
  const repository = parts[1];
  if (
    parts.length !== 2 ||
    owner === undefined ||
    repository === undefined ||
    owner.length === 0 ||
    repository.length === 0
  ) {
    return yield* Effect.fail(sourceUsageError(
      'GitHub source must be an owner/repository locator, not a URL or local path.',
    ));
  }
  const revision = yield* revisionFromText(revisionText);
  return yield* decodeAnalysisSource(new GitHubSource({ owner, repository, revision })).pipe(
    Effect.mapError(() => sourceUsageError('GitHub source is not a valid canonical repository reference.')),
  );
});

export const makeLocalDirectorySource = Effect.fn('makeLocalDirectorySource')(function* (
  directory: string,
) {
  const filesystem = yield* FileSystem.FileSystem;
  const paths = yield* Path.Path;
  const crypto = yield* Crypto.Crypto;
  const absolute = paths.resolve(directory);
  const canonicalDirectory = yield* filesystem.realPath(absolute).pipe(
    Effect.mapError(() => sourceUsageError('Scan path must be an accessible directory.')),
  );
  const info = yield* filesystem.stat(canonicalDirectory).pipe(
    Effect.mapError(() => sourceUsageError('Scan path must be an accessible directory.')),
  );
  if (info.type !== 'Directory') {
    return yield* Effect.fail(sourceUsageError('Scan path must name a directory.'));
  }
  const digest = yield* crypto.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalDirectory),
  ).pipe(
    Effect.mapError(() => new CliRuntimeError({ message: 'Unable to identify the local codebase.' })),
  );
  return yield* decodeAnalysisSource(new LocalDirectorySource({
    directory: canonicalDirectory,
    codebaseId: `local:${Encoding.encodeHex(digest)}`,
  })).pipe(
    Effect.mapError(() => sourceUsageError('Scan path could not be converted into a local source.')),
  );
});

export const readBaseline = Effect.fn('readBaseline')(function* (
  baselinePath: string | undefined,
) {
  if (baselinePath === undefined) return undefined;
  const contents = yield* readBoundedBaselineFile(baselinePath);
  const decoded = yield* decodeScanResultJson(contents).pipe(
    Effect.mapError(() => sourceUsageError('Baseline must be one accepted strict Scan Result document.')),
  );
  if (decoded.resultKind !== 'complete') {
    return yield* Effect.fail(sourceUsageError('Baseline must be a complete successful scan result.'));
  }
  return decoded;
});

export const makeAnalysisRequest = Effect.fn('makeAnalysisRequest')(function* (
  source: AnalysisSource,
  baseline: SuccessfulScanResult | undefined,
) {
  const crypto = yield* Crypto.Crypto;
  const createdAt = (yield* DateTime.nowAsDate).toISOString();
  const scanId = yield* crypto.randomUUIDv7.pipe(
    Effect.mapError(() => new CliRuntimeError({ message: 'Unable to create a scan identifier.' })),
  );
  return yield* decodeAnalysisRequest(new AnalysisRequest({
    scanId,
    source,
    createdAt,
    ...(baseline === undefined ? {} : { baseline }),
  })).pipe(
    Effect.mapError(() => sourceUsageError('The scan request is not valid for this source and baseline.')),
  );
});
