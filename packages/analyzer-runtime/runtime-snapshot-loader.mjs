// Trusted out-of-sandbox runtime reconstruction. This file is intentionally
// self-contained: it consumes only inherited descriptors and writes only a
// private descriptor-rooted generation, never a pathname-backed package tree
// whose siblings could be swapped after preflight.

import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  symlinkSync,
  writeSync,
} from 'node:fs';
import { dirname, join, posix } from 'node:path';

const SnapshotFd = 3;
const RuntimeRootFd = 4;
const LoaderAddonFd = 5;
const LoaderProgramFd = 6;
const RuntimeRoot = `/proc/self/fd/${RuntimeRootFd}`;
const DirectoryCreationMode = 0o755;
const RuntimeManifestSha256 = 'e43f3c3e9f8073262b419130177acbfaccec8a11405fb6485924cc9d99644010';
const SemanticRunnerSha256 = '483a580f586da6e206f95207b7e64231bd0668bea1a8a71aa0576f470034ec1f';
const RuntimeNode = Object.freeze({
  path: 'bin/node',
  sha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
});
const RequiredSemanticRunnerPath = 'bin/radar-semantic-analyzer.mjs';
const OfflineOsvDatabase = Object.freeze({
  path: 'databases/osv/osv-scalibr/npm/all.zip',
  sha256: '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69',
  size: 218_758_368,
  generation: '1786418349414076',
  publishedAt: '2026-08-11T03:19:09Z',
  maxAgeDays: 7,
});
const OfflineOsvMaximumFutureClockSkewMs = 300_000;
const RuntimeBounds = Object.freeze({
  manifestBytes: 4 * 1024 * 1024,
  runtimeArtifactBytes: 256 * 1024 * 1024,
  aggregateBytes: 1024 * 1024 * 1024,
  entries: 100_000,
  chunkBytes: 64 * 1024,
});
const SnapshotMagic = Buffer.from('RDRSNAP1', 'ascii');
const SnapshotVersion = 1;
const sealedRuntimeSnapshotHeaderBytes = 144;
const sealedRuntimeSnapshotRecordPrefixBytes = 19;
const sealedRuntimeSnapshotPathBytes = 4 * 1024;
const sealedRuntimeSnapshotLinkBytes = 4 * 1024;
const sealedRuntimeSnapshotRecordKind = Object.freeze({ directory: 1, file: 2, symlink: 3 });
const FileWriteFlags = constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  constants.O_NOFOLLOW;
const SnapshotMaximumBytes = RuntimeBounds.aggregateBytes +
  RuntimeBounds.entries * (4 * 1024 + sealedRuntimeSnapshotRecordPrefixBytes);
const RequiredMemfdSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;

class SnapshotLoaderError extends Error {
  constructor(code, message, cause) {
    super(`[runtime-snapshot:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'SnapshotLoaderError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new SnapshotLoaderError(code, message, cause);
};

const closeQuietly = fd => {
  try {
    closeSync(fd);
  } catch {
    // The bwrap tmpfs is destroyed when this trusted loader exits.
  }
};

const closeInheritedControlFd = (fd, label) => {
  try {
    closeSync(fd);
  } catch (cause) {
    fail('control-fd-close', `The inherited ${label} descriptor could not be closed.`, cause);
  }
  try {
    fstatSync(fd, { bigint: true });
  } catch (cause) {
    if (cause?.code === 'EBADF') return;
    fail('control-fd-close', `The inherited ${label} descriptor remained observable after close.`, cause);
  }
  fail('control-fd-close', `The inherited ${label} descriptor remained open after close.`);
};

const compareSnapshotPaths = (left, right) =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

const assertSnapshotRelativePath = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > sealedRuntimeSnapshotPathBytes ||
    value.includes('\\') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError('invalid snapshot path');
  }
  const parts = value.split('/');
  if (parts.some(part => part.length === 0 || part === '.' || part === '..')) {
    throw new TypeError('invalid snapshot path');
  }
  return value;
};

const assertSnapshotLinkTarget = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > sealedRuntimeSnapshotLinkBytes ||
    value.startsWith('/') ||
    value.includes('\\') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError('invalid snapshot link');
  }
  return value;
};

const decodeSealedRuntimeSnapshotHeader = bytes => {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== sealedRuntimeSnapshotHeaderBytes) {
    throw new TypeError('invalid snapshot header');
  }
  if (!bytes.subarray(0, SnapshotMagic.byteLength).equals(SnapshotMagic) ||
    bytes.readUInt32BE(8) !== SnapshotVersion) {
    throw new TypeError('invalid snapshot header');
  }
  return Object.freeze({
    entryCount: bytes.readUInt32BE(12),
    manifestSha256: bytes.subarray(16, 48).toString('hex'),
    runnerSha256: bytes.subarray(48, 80).toString('hex'),
    nodeSha256: bytes.subarray(80, 112).toString('hex'),
    osvDatabaseSha256: bytes.subarray(112, 144).toString('hex'),
  });
};

const decodeSealedRuntimeSnapshotRecordPrefix = bytes => {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== sealedRuntimeSnapshotRecordPrefixBytes) {
    throw new TypeError('invalid snapshot record');
  }
  const kind = bytes.readUInt8(0);
  const mode = bytes.readUInt16BE(1);
  const pathBytes = bytes.readUInt32BE(3);
  const payloadBytes = bytes.readBigUInt64BE(7);
  if (
    !Object.values(sealedRuntimeSnapshotRecordKind).includes(kind) ||
    ![0o444, 0o555].includes(mode) ||
    pathBytes === 0 ||
    pathBytes > sealedRuntimeSnapshotPathBytes ||
    bytes.readUInt32BE(15) !== 0 ||
    (kind === sealedRuntimeSnapshotRecordKind.directory && payloadBytes !== 0n) ||
    (kind === sealedRuntimeSnapshotRecordKind.symlink && payloadBytes > BigInt(sealedRuntimeSnapshotLinkBytes))
  ) {
    throw new TypeError('invalid snapshot record');
  }
  return Object.freeze({ kind, mode, pathBytes, payloadBytes });
};

const snapshotMemfdSeals = fd => {
  let seals;
  try {
    const addon = { exports: {} };
    process.dlopen(addon, `/proc/self/fd/${LoaderAddonFd}`);
    const bridge = addon.exports;
    if (typeof bridge?.getSeals !== 'function') throw new TypeError('missing getSeals');
    seals = bridge.getSeals(fd);
    // The native image remains loaded after dlopen; do not retain the control
    // descriptor while parsing or materializing attacker-controlled archive
    // data.
    closeInheritedControlFd(LoaderAddonFd, 'memfd bridge');
  } catch (cause) {
    fail('snapshot-seal-unavailable', 'The sealed runtime snapshot kernel proof is unavailable.', cause);
  }
  if ((seals & RequiredMemfdSeals) !== RequiredMemfdSeals) {
    fail('snapshot-seal-invalid', 'The runtime snapshot does not have every required immutable memfd seal.');
  }
  return seals;
};

const parsedExtractedManifest = bytes => {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch (cause) {
    fail('manifest-invalid', 'The extracted runtime manifest is invalid.', cause);
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    Array.isArray(manifest) ||
    manifest.runtimeNode?.path !== RuntimeNode.path ||
    manifest.runtimeNode?.sha256 !== RuntimeNode.sha256 ||
    manifest.offlineOsvDatabase?.path !== OfflineOsvDatabase.path ||
    manifest.offlineOsvDatabase?.sha256 !== OfflineOsvDatabase.sha256 ||
    manifest.offlineOsvDatabase?.size !== OfflineOsvDatabase.size ||
    manifest.offlineOsvDatabase?.generation !== OfflineOsvDatabase.generation ||
    manifest.offlineOsvDatabase?.publishedAt !== OfflineOsvDatabase.publishedAt ||
    manifest.offlineOsvDatabase?.maxAgeDays !== OfflineOsvDatabase.maxAgeDays
  ) {
    fail('manifest-invalid', 'The extracted runtime manifest does not contain the pinned execution controls.');
  }
  return manifest;
};

const assertOfflineOsvDatabaseFresh = database => {
  const now = Date.now();
  const publishedAt = Date.parse(OfflineOsvDatabase.publishedAt);
  const expiresAt = publishedAt + OfflineOsvDatabase.maxAgeDays * 24 * 60 * 60 * 1000;
  if (
    !Number.isSafeInteger(now) ||
    now < publishedAt - OfflineOsvMaximumFutureClockSkewMs ||
    now > expiresAt ||
    database?.publishedAt !== OfflineOsvDatabase.publishedAt ||
    database?.maxAgeDays !== OfflineOsvDatabase.maxAgeDays
  ) {
    fail('osv-database-stale', 'The pinned offline OSV database is outside its seven-day freshness window.');
  }
};

const parseArguments = argv => {
  if (
    argv.length !== 5 ||
    argv[0] !== '--snapshot-fd' ||
    argv[1] !== String(SnapshotFd) ||
    argv[2] !== '--runtime-fd' ||
    argv[3] !== String(RuntimeRootFd) ||
    argv[4] !== '--materialize'
  ) {
    fail('arguments-invalid', 'The trusted snapshot loader received an invalid materialization invocation.');
  }
};

const checkedSnapshotStat = fd => {
  let stat;
  try {
    stat = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('snapshot-fd-invalid', 'The sealed runtime snapshot descriptor cannot be inspected.', cause);
  }
  if (
    !stat.isFile() ||
    stat.nlink !== 0n ||
    stat.size < BigInt(sealedRuntimeSnapshotHeaderBytes) ||
    stat.size > BigInt(SnapshotMaximumBytes)
  ) {
    fail('snapshot-fd-invalid', 'The sealed runtime snapshot descriptor is not an anonymous bounded regular file.');
  }
  snapshotMemfdSeals(fd);
  return Number(stat.size);
};

const makeReader = (fd, byteLength) => {
  let position = 0;
  const readExact = length => {
    if (!Number.isSafeInteger(length) || length < 0 || position + length > byteLength) {
      fail('archive-truncated', 'The sealed runtime archive ended unexpectedly.');
    }
    const result = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < result.byteLength) {
      const read = readSync(fd, result, offset, result.byteLength - offset, position + offset);
      if (read <= 0) fail('archive-truncated', 'The sealed runtime archive ended unexpectedly.');
      offset += read;
    }
    position += length;
    return result;
  };
  const copyPayload = ({ length, destination, hash }) => {
    if (!Number.isSafeInteger(length) || length < 0 || position + length > byteLength) {
      fail('archive-truncated', 'The sealed runtime archive payload is truncated.');
    }
    const buffer = Buffer.allocUnsafe(RuntimeBounds.chunkBytes);
    let remaining = length;
    while (remaining > 0) {
      const desired = Math.min(buffer.byteLength, remaining);
      const read = readSync(fd, buffer, 0, desired, position);
      if (read <= 0) fail('archive-truncated', 'The sealed runtime archive payload is truncated.');
      const chunk = buffer.subarray(0, read);
      if (hash !== undefined) hash.update(chunk);
      let offset = 0;
      while (offset < chunk.byteLength) {
        const written = writeSync(destination, chunk, offset, chunk.byteLength - offset, null);
        if (written <= 0) fail('runtime-write', 'The private runtime extraction could not make forward progress.');
        offset += written;
      }
      position += read;
      remaining -= read;
    }
  };
  return Object.freeze({ readExact, copyPayload, get position() { return position; } });
};

const assertExactDirectoryEntries = (path, expected) => {
  let entries;
  try {
    entries = readdirSync(path).sort(compareSnapshotPaths);
  } catch (cause) {
    fail('runtime-root-invalid', 'The private runtime tmpfs could not be enumerated.', cause);
  }
  if (entries.length !== expected.length || entries.some((entry, index) => entry !== expected[index])) {
    fail('runtime-root-invalid', 'The private runtime tmpfs contains an unexpected pre-mounted entry.');
  }
};

const assertInitialRuntimeRoot = () => {
  let metadata;
  try {
    metadata = fstatSync(RuntimeRootFd, { bigint: true });
  } catch (cause) {
    fail('runtime-root-invalid', 'The private runtime tmpfs is unavailable.', cause);
  }
  if (!metadata.isDirectory() || (metadata.mode & 0o7000n) !== 0n) {
    fail('runtime-root-invalid', 'The runtime extraction root must be a direct private directory.');
  }
  assertExactDirectoryEntries(RuntimeRoot, []);
};

const entryPath = path => join(RuntimeRoot, ...path.split('/'));

// Bubblewrap applies its mounts in order.  The governed invocation first
// read-only-binds this reconstructed runtime, then binds the separately sealed
// OSV ZIP over its final pathname.  Bubblewrap 0.9 cannot create that file
// after the parent is read-only, so materialize an authenticated empty leaf
// here.  This is deliberately not an archive record and never carries OSV
// payload bytes; only the separate sealed database FD may replace it.
const createOfflineOsvMountPlaceholder = ({ entries, directories }) => {
  if (entries.has(OfflineOsvDatabase.path)) {
    fail('archive-osv-database-invalid', 'The general runtime archive must not contain the offline OSV database path.');
  }
  let parent = '';
  for (const part of OfflineOsvDatabase.path.split('/').slice(0, -1)) {
    parent = parent === '' ? part : `${parent}/${part}`;
    if (!directories.has(parent)) {
      fail('archive-osv-parent-missing', 'The sealed runtime archive is missing the offline OSV mount parent.');
    }
  }
  const destination = entryPath(OfflineOsvDatabase.path);
  absent(destination);
  let output;
  try {
    output = openSync(destination, FileWriteFlags, 0o444);
    fsyncSync(output);
    fchmodSync(output, 0o444);
    const metadata = fstatSync(output, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1n ||
      metadata.size !== 0n ||
      (metadata.mode & 0o7777n) !== 0o444n
    ) {
      fail('runtime-osv-placeholder-invalid', 'The offline OSV mount placeholder has invalid metadata.');
    }
  } catch (cause) {
    if (cause instanceof SnapshotLoaderError) throw cause;
    fail('runtime-osv-placeholder-create', 'The offline OSV mount placeholder could not be created.', cause);
  } finally {
    closeQuietly(output);
  }
};

const readBoundedExtractedManifest = () => {
  const manifestPath = entryPath('runtime-manifest.json');
  let fd;
  try {
    fd = openSync(manifestPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(fd, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1n ||
      metadata.size < 1n ||
      metadata.size > BigInt(RuntimeBounds.manifestBytes)
    ) {
      fail('manifest-invalid', 'The extracted runtime manifest has invalid metadata.');
    }
    const bytes = Buffer.allocUnsafe(Number(metadata.size));
    let offset = 0;
    while (offset < bytes.byteLength) {
      const read = readSync(fd, bytes, offset, bytes.byteLength - offset, offset);
      if (read <= 0) fail('manifest-invalid', 'The extracted runtime manifest is truncated.');
      offset += read;
    }
    try {
      return parsedExtractedManifest(bytes);
    } catch (cause) {
      if (cause instanceof SnapshotLoaderError) throw cause;
      fail('manifest-invalid', 'The extracted runtime manifest is invalid.', cause);
    }
  } catch (cause) {
    if (cause instanceof SnapshotLoaderError) throw cause;
    fail('manifest-invalid', 'The extracted runtime manifest could not be retained.', cause);
  } finally {
    closeQuietly(fd);
  }
};

const hashExtractedRuntimeNode = expectedSha256 => {
  const nodePath = entryPath(RuntimeNode.path);
  let fd;
  try {
    fd = openSync(nodePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(fd, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1n ||
      (metadata.mode & 0o7777n) !== 0o555n ||
      metadata.size < 1n ||
      metadata.size > BigInt(RuntimeBounds.runtimeArtifactBytes)
    ) {
      fail('runtime-node-invalid', 'The extracted runtime Node has invalid metadata.');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(RuntimeBounds.chunkBytes);
    let position = 0;
    while (position < Number(metadata.size)) {
      const read = readSync(fd, buffer, 0, Math.min(buffer.byteLength, Number(metadata.size) - position), position);
      if (read <= 0) fail('runtime-node-invalid', 'The extracted runtime Node is truncated.');
      hash.update(buffer.subarray(0, read));
      position += read;
    }
    if (hash.digest('hex') !== expectedSha256) {
      fail('runtime-node-mismatch', 'The extracted runtime Node does not match its pinned SHA-256.');
    }
  } catch (cause) {
    if (cause instanceof SnapshotLoaderError) throw cause;
    fail('runtime-node-invalid', 'The extracted runtime Node could not be retained.', cause);
  } finally {
    closeQuietly(fd);
  }
  return nodePath;
};

const assertParent = (path, directories) => {
  const parent = dirname(path);
  if (parent !== '.' && !directories.has(parent)) {
    fail('archive-parent-missing', 'The sealed runtime archive has a child before its parent directory.');
  }
};

const absent = path => {
  try {
    lstatSync(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    fail('runtime-entry-invalid', 'The private runtime extraction could not inspect a destination.', error);
  }
  fail('runtime-entry-exists', 'The sealed runtime archive attempted to overwrite an existing destination.');
};

const normalizedLinkDestination = (path, target) => {
  const resolved = posix.normalize(posix.join(posix.dirname(path), target));
  if (
    resolved === '.' ||
    resolved === '..' ||
    resolved.startsWith('../') ||
    resolved.startsWith('/')
  ) {
    fail('archive-link-escape', 'The sealed runtime archive contains a link outside /runtime.');
  }
  return resolved;
};

const recordRank = kind => {
  if (kind === sealedRuntimeSnapshotRecordKind.directory) return 0;
  if (kind === sealedRuntimeSnapshotRecordKind.file) return 1;
  return 2;
};

const extract = ({ fd, byteLength }) => {
  const reader = makeReader(fd, byteLength);
  const header = decodeSealedRuntimeSnapshotHeader(reader.readExact(sealedRuntimeSnapshotHeaderBytes));
  if (
    header.entryCount > RuntimeBounds.entries ||
    header.manifestSha256 !== RuntimeManifestSha256 ||
    header.runnerSha256 !== SemanticRunnerSha256 ||
    header.nodeSha256 !== RuntimeNode.sha256 ||
    header.osvDatabaseSha256 !== OfflineOsvDatabase.sha256
  ) {
    fail('archive-identity-invalid', 'The sealed runtime archive does not match the trusted runtime identity.');
  }
  assertInitialRuntimeRoot();
  const directories = new Set();
  const entries = new Set();
  const directoryModes = [];
  let priorRank = -1;
  let priorPath;
  let manifestDigest;
  let runnerDigest;
  let nodeDigest;

  for (let index = 0; index < header.entryCount; index += 1) {
    const prefix = decodeSealedRuntimeSnapshotRecordPrefix(
      reader.readExact(sealedRuntimeSnapshotRecordPrefixBytes),
    );
    const pathBytes = reader.readExact(prefix.pathBytes);
    let path;
    try {
      path = new TextDecoder('utf-8', { fatal: true }).decode(pathBytes);
      assertSnapshotRelativePath(path);
    } catch (cause) {
      fail('archive-path-invalid', 'The sealed runtime archive contains an invalid path.', cause);
    }
    const rank = recordRank(prefix.kind);
    if (
      rank < priorRank ||
      (rank === priorRank && priorPath !== undefined && compareSnapshotPaths(priorPath, path) >= 0) ||
      entries.has(path)
    ) {
      fail('archive-order-invalid', 'The sealed runtime archive is not canonically ordered.');
    }
    priorRank = rank;
    priorPath = path;
    entries.add(path);
    assertParent(path, directories);
    const destination = entryPath(path);

    if (path === OfflineOsvDatabase.path) {
      fail('archive-osv-database-invalid', 'The large offline OSV database must not be part of the general runtime archive.');
    }

    if (prefix.kind === sealedRuntimeSnapshotRecordKind.directory) {
      absent(destination);
      try {
        mkdirSync(destination, { mode: DirectoryCreationMode });
      } catch (cause) {
        fail('runtime-directory-create', 'The private runtime directory could not be created.', cause);
      }
      directories.add(path);
      directoryModes.push({ path: destination, mode: prefix.mode });
      continue;
    }

    if (prefix.kind === sealedRuntimeSnapshotRecordKind.file) {
      if (prefix.payloadBytes > BigInt(RuntimeBounds.runtimeArtifactBytes)) {
        fail('archive-file-limit', 'The sealed runtime archive contains an oversized file.');
      }
      const payloadBytes = Number(prefix.payloadBytes);
      absent(destination);
      let output;
      try {
        output = openSync(destination, FileWriteFlags, prefix.mode);
        const hash =
          path === 'runtime-manifest.json' ||
          path === RequiredSemanticRunnerPath ||
          path === RuntimeNode.path
          ? createHash('sha256')
          : undefined;
        reader.copyPayload({ length: payloadBytes, destination: output, hash });
        fsyncSync(output);
        fchmodSync(output, prefix.mode);
        if (path === 'runtime-manifest.json') manifestDigest = hash.digest('hex');
        if (path === RequiredSemanticRunnerPath) runnerDigest = hash.digest('hex');
        if (path === RuntimeNode.path) nodeDigest = hash.digest('hex');
      } catch (cause) {
        if (cause instanceof SnapshotLoaderError) throw cause;
        fail('runtime-file-create', 'The private runtime file could not be extracted.', cause);
      } finally {
        closeQuietly(output);
      }
      continue;
    }

    const targetBytes = reader.readExact(Number(prefix.payloadBytes));
    let target;
    try {
      target = new TextDecoder('utf-8', { fatal: true }).decode(targetBytes);
      assertSnapshotLinkTarget(target);
      const resolved = normalizedLinkDestination(path, target);
      if (!entries.has(resolved)) {
        fail('archive-link-target-missing', 'The sealed runtime archive link target is not an extracted record.');
      }
    } catch (cause) {
      if (cause instanceof SnapshotLoaderError) throw cause;
      fail('archive-link-invalid', 'The sealed runtime archive contains an invalid symlink.', cause);
    }
    absent(destination);
    try {
      symlinkSync(target, destination);
    } catch (cause) {
      fail('runtime-link-create', 'The private runtime symlink could not be created.', cause);
    }
  }

  if (reader.position !== byteLength) {
    fail('archive-trailing-bytes', 'The sealed runtime archive has trailing bytes.');
  }
  if (
    manifestDigest !== RuntimeManifestSha256 ||
    runnerDigest !== SemanticRunnerSha256 ||
    nodeDigest !== header.nodeSha256
  ) {
    fail('archive-control-mismatch', 'The extracted runtime controls do not match the trust anchor.');
  }
  const manifest = readBoundedExtractedManifest();
  if (
    manifest.runtimeNode.sha256 !== header.nodeSha256 ||
    manifest.offlineOsvDatabase.sha256 !== header.osvDatabaseSha256
  ) {
    fail('archive-manifest-mismatch', 'The extracted manifest does not bind the sealed runtime controls.');
  }
  createOfflineOsvMountPlaceholder({ entries, directories });
  for (const directory of directoryModes.reverse()) chmodSync(directory.path, directory.mode);
  fchmodSync(RuntimeRootFd, 0o555);
  return manifest;
};

const main = () => {
  if (process.platform !== 'linux') {
    fail('unsupported-platform', 'The trusted runtime snapshot loader requires Linux.');
  }
  parseArguments(process.argv.slice(2));
  // Node resolved this standalone script before entering userland. It is now
  // safe—and required—to close the inherited loader program descriptor.
  closeInheritedControlFd(LoaderProgramFd, 'materializer program');
  const byteLength = checkedSnapshotStat(SnapshotFd);
  let manifest;
  try {
    manifest = extract({
      fd: SnapshotFd,
      byteLength,
    });
  } finally {
    // The runner never needs the archive after successful extraction. Closing
    // it removes its only in-sandbox capability to the sealed source bytes.
    closeQuietly(SnapshotFd);
  }
  assertOfflineOsvDatabaseFresh(manifest.offlineOsvDatabase);
  hashExtractedRuntimeNode(manifest.runtimeNode.sha256);
  const root = fstatSync(RuntimeRootFd, { bigint: true });
  if (!root.isDirectory() || (root.mode & 0o7777n) !== 0o555n) {
    fail('runtime-root-invalid', 'The materialized runtime root did not become immutable.');
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 'codebase-radar.analyzer-runtime-materialization/v1',
    kind: 'materialized',
    root: {
      device: root.dev.toString(10),
      inode: root.ino.toString(10),
      mode: root.mode.toString(10),
      size: root.size.toString(10),
      nlink: root.nlink.toString(10),
    },
  })}\n`);
};

try {
  main();
} catch {
  // Never echo an archive path, target filename, or attacker-controlled
  // parser field from the trusted loader boundary.
  process.stderr.write('[runtime-snapshot:failed] The sealed runtime could not be reconstructed.\n');
  process.exitCode = 1;
}
