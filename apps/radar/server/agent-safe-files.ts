import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
} from 'node:fs';
import { Effect, Option, Schema } from 'effect';

export class AgentSafeFileError extends Schema.TaggedErrorClass<AgentSafeFileError>()(
  'AgentSafeFileError',
  { message: Schema.String },
) {}

export const maxAgentSandboxWritableEntries = 1_024;

interface SafeReadSuccess {
  readonly _tag: 'success';
  readonly bytes: Uint8Array;
}

interface SafeReadMissing {
  readonly _tag: 'missing';
}

interface SafeReadRejected {
  readonly _tag: 'rejected';
}

interface RetainedSandboxRoot {
  readonly descriptor: number;
}

interface DescriptorInvocation {
  readonly status: number;
  readonly bytes: Uint8Array;
}

type SafeRead = SafeReadSuccess | SafeReadMissing | SafeReadRejected;

const missingExitCode = 20;

const rejected = (): SafeReadRejected => ({ _tag: 'rejected' });

const safeRelativeParts = (parts: ReadonlyArray<string>) =>
  parts.length > 0 &&
  parts.every(
    part =>
      part.length > 0 &&
      part !== '.' &&
      part !== '..' &&
      !part.includes('/') &&
      !part.includes('\\') &&
      !part.includes('\u0000'),
  );

const positiveSafeInteger = (value: number) =>
  Number.isSafeInteger(value) && value >= 1;

const retainedDescriptorScript = String.raw`
import json
import os
import stat
import sys

ROOT_DESCRIPTOR = 3
MISSING = 20
REJECTED = 21
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW

def reject():
    raise SystemExit(REJECTED)

def safe_part(value):
    return isinstance(value, str) and value and value not in ('.', '..') and '/' not in value and '\\' not in value and '\\x00' not in value

def positive_integer(value):
    return type(value) is int and value >= 1 and value <= 9007199254740991

def non_sparse_regular(metadata):
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_size >= 0
        and metadata.st_blocks >= 0
        and metadata.st_blocks * 512 >= metadata.st_size
        and metadata.st_nlink == 1
    )

def same_inode(left, right):
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino

def open_directory(parent, name):
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            reject()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def open_parent(parts):
    current = os.dup(ROOT_DESCRIPTOR)
    try:
        for part in parts[:-1]:
            next_descriptor = open_directory(current, part)
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise

def read_regular(parts, maximum_bytes):
    parent = open_parent(parts)
    descriptor = -1
    try:
        descriptor = os.open(parts[-1], FILE_FLAGS, dir_fd=parent)
        before = os.fstat(descriptor)
        if not non_sparse_regular(before) or before.st_size > maximum_bytes:
            reject()
        remaining = before.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                reject()
            sys.stdout.buffer.write(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            reject()
        after = os.fstat(descriptor)
        if not same_inode(before, after) or before.st_size != after.st_size:
            reject()
        sys.stdout.buffer.flush()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)

def inspect_tree(maximum_bytes, maximum_entries):
    root_metadata = os.fstat(ROOT_DESCRIPTOR)
    if not stat.S_ISDIR(root_metadata.st_mode):
        reject()
    total_bytes = 0
    entries = 0
    inodes = set()

    def count(metadata):
        nonlocal entries
        entries += 1
        if entries > maximum_entries:
            reject()
        inodes.add((metadata.st_dev, metadata.st_ino))
        if len(inodes) > maximum_entries:
            reject()

    def visit(directory):
        nonlocal total_bytes
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if not safe_part(entry.name):
                    reject()
                metadata = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                count(metadata)
                if stat.S_ISLNK(metadata.st_mode):
                    reject()
                if stat.S_ISDIR(metadata.st_mode):
                    child = open_directory(directory, entry.name)
                    try:
                        child_metadata = os.fstat(child)
                        if not same_inode(metadata, child_metadata):
                            reject()
                        visit(child)
                    finally:
                        os.close(child)
                    continue
                if not non_sparse_regular(metadata):
                    reject()
                total_bytes += metadata.st_size
                if total_bytes > maximum_bytes:
                    reject()

    visit(ROOT_DESCRIPTOR)

def main():
    payload = json.loads(sys.argv[1])
    operation = payload.get('operation')
    if operation == 'read':
        parts = payload.get('parts')
        maximum_bytes = payload.get('maximumBytes')
        if not isinstance(parts, list) or not parts or not all(safe_part(part) for part in parts) or not positive_integer(maximum_bytes):
            reject()
        try:
            read_regular(parts, maximum_bytes)
        except FileNotFoundError:
            raise SystemExit(MISSING)
        except (OSError, TypeError, ValueError):
            reject()
        return
    if operation == 'quota':
        maximum_bytes = payload.get('maximumBytes')
        maximum_entries = payload.get('maximumEntries')
        if not positive_integer(maximum_bytes) or not positive_integer(maximum_entries):
            reject()
        try:
            inspect_tree(maximum_bytes, maximum_entries)
        except (OSError, TypeError, ValueError):
            reject()
        return
    reject()

main()
`;

const acquireRetainedSandboxRoot = (root: string) =>
  Effect.try({
    try: () => {
      let descriptor = -1;
      try {
        descriptor = openSync(
          root,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        const metadata = fstatSync(descriptor);
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
          closeSync(descriptor);
          return { descriptor: -1 };
        }
        return { descriptor };
      } catch {
        if (descriptor >= 0) {
          try {
            closeSync(descriptor);
          } catch {}
        }
        return { descriptor: -1 };
      }
    },
    catch: () => new AgentSafeFileError({
      message: 'The provider sandbox filesystem could not be secured.',
    }),
  }).pipe(
    Effect.flatMap(root =>
      root.descriptor >= 0
        ? Effect.succeed(root)
        : Effect.fail(new AgentSafeFileError({
          message: 'The provider sandbox filesystem could not be secured.',
        })),
    ),
  );

const closeRetainedSandboxRoot = (root: RetainedSandboxRoot) =>
  Effect.try({
    try: () => closeSync(root.descriptor),
    catch: () => new AgentSafeFileError({
      message: 'The provider sandbox filesystem could not be released.',
    }),
  }).pipe(Effect.ignore);

const invokeDescriptor = (
  root: RetainedSandboxRoot,
  payload: object,
  maximumOutputBytes: number,
): DescriptorInvocation | undefined => {
  try {
    const result = spawnSync(
      '/usr/bin/python3',
      ['-I', '-S', '-E', '-c', retainedDescriptorScript, JSON.stringify(payload)],
      {
        maxBuffer: maximumOutputBytes,
        stdio: ['ignore', 'pipe', 'pipe', root.descriptor],
      },
    );
    if (
      result.error !== undefined ||
      result.signal !== null ||
      result.status === null ||
      !(result.stdout instanceof Uint8Array)
    ) {
      return undefined;
    }
    return { status: result.status, bytes: Uint8Array.from(result.stdout) };
  } catch {
    return undefined;
  }
};

const readDescriptor = (
  root: RetainedSandboxRoot,
  parts: ReadonlyArray<string>,
  maximumBytes: number,
): SafeRead => {
  if (!safeRelativeParts(parts) || !positiveSafeInteger(maximumBytes)) return rejected();
  const result = invokeDescriptor(
    root,
    { operation: 'read', parts, maximumBytes },
    maximumBytes,
  );
  if (result === undefined) return rejected();
  if (result.status === missingExitCode) return { _tag: 'missing' };
  if (result.status !== 0 || result.bytes.byteLength > maximumBytes) return rejected();
  return { _tag: 'success', bytes: result.bytes };
};

const inspectTree = (
  root: RetainedSandboxRoot,
  maximumBytes: number,
  maximumEntries: number,
) => {
  if (!positiveSafeInteger(maximumBytes) || !positiveSafeInteger(maximumEntries)) {
    return false;
  }
  const result = invokeDescriptor(
    root,
    { operation: 'quota', maximumBytes, maximumEntries },
    1_024,
  );
  return result !== undefined && result.status === 0 && result.bytes.byteLength === 0;
};

export interface AgentSafeFileCapability {
  readonly readRegularFile: (
    parts: ReadonlyArray<string>,
    maximumBytes: number,
  ) => Effect.Effect<Option.Option<Uint8Array>, AgentSafeFileError>;
  readonly enforceWritableQuota: (
    maximumBytes: number,
    maximumEntries?: number,
  ) => Effect.Effect<void, AgentSafeFileError>;
}

const capabilityFor = (root: RetainedSandboxRoot): AgentSafeFileCapability => ({
  readRegularFile: (parts, maximumBytes) =>
    Effect.sync(() => readDescriptor(root, parts, maximumBytes)).pipe(
      Effect.flatMap(result => {
        switch (result._tag) {
          case 'success':
            return Effect.succeed(Option.some(result.bytes));
          case 'missing':
            return Effect.succeed(Option.none<Uint8Array>());
          case 'rejected':
            return Effect.fail(new AgentSafeFileError({
              message: 'The provider produced an unsafe result file.',
            }));
        }
      }),
    ),
  enforceWritableQuota: (
    maximumBytes,
    maximumEntries = maxAgentSandboxWritableEntries,
  ) =>
    Effect.sync(() => inspectTree(root, maximumBytes, maximumEntries)).pipe(
      Effect.flatMap(accepted =>
        accepted
          ? Effect.void
          : Effect.fail(new AgentSafeFileError({
            message: 'The provider exceeded the isolated writable-file limit.',
          })),
      ),
    ),
});

export const makeAgentSafeFileCapability = (root: string) =>
  acquireRetainedSandboxRoot(root).pipe(
    Effect.flatMap(retained =>
      Effect.acquireRelease(
        Effect.sync(() => capabilityFor(retained)),
        () => closeRetainedSandboxRoot(retained),
      ),
    ),
  );

export const readSandboxRegularFile = (
  root: string,
  parts: ReadonlyArray<string>,
  maximumBytes: number,
) =>
  Effect.scoped(
    makeAgentSafeFileCapability(root).pipe(
      Effect.flatMap(capability => capability.readRegularFile(parts, maximumBytes)),
    ),
  );

export const enforceSandboxWritableQuota = (
  root: string,
  maximumBytes: number,
  maximumEntries = maxAgentSandboxWritableEntries,
) =>
  Effect.scoped(
    makeAgentSafeFileCapability(root).pipe(
      Effect.flatMap(capability =>
        capability.enforceWritableQuota(maximumBytes, maximumEntries)),
    ),
  );
