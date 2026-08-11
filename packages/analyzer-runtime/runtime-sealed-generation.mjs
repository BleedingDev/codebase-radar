import { randomBytes, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
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
  opendirSync,
  readSync,
  readdirSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, posix, relative, sep } from 'node:path';
import {
  assertOfflineOsvDatabaseFresh,
  requiredOfflineOsvDatabase,
  requiredSemanticRunnerPath,
  requiredRuntimeNode,
  runtimeVerificationBounds,
  validateRuntimeManifest,
} from './runtime-manifest.mjs';
import {
  compareSnapshotPaths,
  decodeSealedRuntimeSnapshotHeader,
  encodeSealedRuntimeSnapshotHeader,
  encodeSealedRuntimeSnapshotRecordPrefix,
  sealedRuntimeSnapshotHeaderBytes,
  sealedRuntimeSnapshotRecordKind,
} from './runtime-snapshot-codec.mjs';
import {
  assertAnalyzerControlArtifactFd,
  inspectAnalyzerControl,
} from './runtime-control-root.mjs';
import {
  assertMaterializedRuntimeRootDescriptor,
  assertSealedRuntimeMemfdDescriptor,
  assertTrustedRuntimeControlDescriptor,
  loadRuntimeMemfdBridgeFromDescriptor,
} from './runtime-descriptor-proofs.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

// The independently authenticated Linux memfd bridge creates each archive and
// payload inode without a directory entry from its first syscall. Node has no
// built-in API for the required MFD_* flags or F_GET_SEALS proof.
const DirectoryOpenFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const RegularReadFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const FileModeReadOnly = 0o444;
const FileModeExecutable = 0o555;
const DirectoryModeReadOnly = 0o555;
const SnapshotSchemaVersion = 'codebase-radar.analyzer-runtime-sealed-generation/v1';
const SnapshotFdSealing = 'linux-memfd-seals/v1';
const SnapshotMaximumBytes = runtimeVerificationBounds.aggregateBytes +
  runtimeVerificationBounds.entries * (4 * 1024 + 19);
export const requiredAnalyzerControlFiles = Object.freeze([
  'runtime-snapshot-loader.mjs',
  'resource-governance-launcher.mjs',
  'runtime-memfd-addon.node',
]);
const MaterializerControlFile = 'runtime-snapshot-loader.mjs';
const GovernanceLauncherControlFile = 'resource-governance-launcher.mjs';
const MemfdAddonControlFile = 'runtime-memfd-addon.node';
const RequiredMemfdSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;
const sealedGenerationHandles = new WeakMap();

export class AnalyzerRuntimeSnapshotError extends Error {
  constructor(code, message, cause) {
    super(`[runtime-snapshot:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'AnalyzerRuntimeSnapshotError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new AnalyzerRuntimeSnapshotError(code, message, cause);
};

const closeQuietly = fd => {
  if (typeof fd !== 'number' || fd < 0) return;
  try {
    closeSync(fd);
  } catch {
    // Cleanup never turns a prior authentication failure into a success.
  }
};

const fdPath = fd => `/proc/self/fd/${fd}`;

const validGenerationPart = value =>
  typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value);

const assertDeadline = deadline => {
  if (process.hrtime.bigint() > deadline) {
    fail('deadline-exceeded', 'The bounded runtime snapshot operation exceeded its deadline.');
  }
};

const makeBudget = ({ maximumEntries = runtimeVerificationBounds.entries } = {}) => ({
  deadline: process.hrtime.bigint() + BigInt(runtimeVerificationBounds.deadlineMs) * 1_000_000n,
  entries: 0,
  maximumEntries,
  sourceBytes: 0n,
});

const reserveEntry = (budget, label) => {
  assertDeadline(budget.deadline);
  budget.entries += 1;
  if (budget.entries > budget.maximumEntries) {
    fail('entry-limit', `The runtime snapshot exceeds its entry bound while ${label}.`);
  }
};

const reserveBytes = (budget, size, limit, label) => {
  assertDeadline(budget.deadline);
  if (typeof size !== 'bigint' || size < 0n || size > BigInt(limit)) {
    fail('file-limit', `The runtime snapshot rejects an oversized ${label}.`);
  }
  const next = budget.sourceBytes + size;
  if (next > BigInt(runtimeVerificationBounds.aggregateBytes)) {
    fail('aggregate-limit', 'The runtime snapshot exceeds its aggregate byte bound.');
  }
  budget.sourceBytes = next;
  return Number(size);
};

const relativeParts = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\\') ||
    value.startsWith('/') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail('path-invalid', 'The runtime snapshot encountered an invalid relative path.');
  }
  const parts = value.split('/');
  if (parts.some(part => part.length === 0 || part === '.' || part === '..')) {
    fail('path-invalid', 'The runtime snapshot encountered path traversal.');
  }
  return parts;
};

const statIdentity = stat => Object.freeze({
  device: stat.dev,
  inode: stat.ino,
  mode: stat.mode,
  size: stat.size,
  nlink: stat.nlink,
});

const serializedDescriptorIdentity = stat => Object.freeze({
  device: stat.dev.toString(10),
  inode: stat.ino.toString(10),
  mode: stat.mode.toString(10),
  size: stat.size.toString(10),
  nlink: stat.nlink.toString(10),
});

const matchesSerializedDescriptorIdentity = (stat, expected) => {
  if (expected === undefined) return true;
  if (expected === null || typeof expected !== 'object') return false;
  const actual = serializedDescriptorIdentity(stat);
  return (
    expected.device === actual.device &&
    expected.inode === actual.inode &&
    expected.mode === actual.mode &&
    expected.size === actual.size &&
    expected.nlink === actual.nlink
  );
};

const sameIdentity = (left, right) =>
  left.device === right.device &&
  left.inode === right.inode &&
  left.mode === right.mode &&
  left.size === right.size &&
  left.nlink === right.nlink;

const checkedDirectoryStat = (fd, label) => {
  let stat;
  try {
    stat = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('descriptor-invalid', `The runtime snapshot could not inspect ${label}.`, cause);
  }
  if (!stat.isDirectory() || (stat.mode & 0o7000n) !== 0n) {
    fail('directory-invalid', `The runtime snapshot rejects unsafe directory ${label}.`);
  }
  return statIdentity(stat);
};

const checkedRegularStat = (fd, label, maximumBytes) => {
  let stat;
  try {
    stat = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('descriptor-invalid', `The runtime snapshot could not inspect ${label}.`, cause);
  }
  if (
    !stat.isFile() ||
    stat.nlink !== 1n ||
    (stat.mode & 0o7000n) !== 0n ||
    stat.size < 0n ||
    stat.size > BigInt(maximumBytes)
  ) {
    fail('file-invalid', `The runtime snapshot rejects unsafe file ${label}.`);
  }
  return statIdentity(stat);
};

const openDirectoryFrom = (parentFd, name, label) => {
  if (typeof name !== 'string' || !/^[^/\\\u0000-\u001f\u007f]+$/u.test(name)) {
    fail('path-invalid', `The runtime snapshot rejects a directory component for ${label}.`);
  }
  let fd;
  try {
    fd = openSync(`${fdPath(parentFd)}/${name}`, DirectoryOpenFlags);
  } catch (cause) {
    fail('directory-open', `The runtime snapshot could not retain ${label}.`, cause);
  }
  try {
    checkedDirectoryStat(fd, label);
    return fd;
  } catch (error) {
    closeQuietly(fd);
    throw error;
  }
};

const openDirectoryPath = (rootFd, path, expectedDirectories, label) => {
  let current;
  try {
    current = openSync(fdPath(rootFd), constants.O_RDONLY | constants.O_DIRECTORY);
  } catch (cause) {
    fail('root-descriptor', 'The runtime snapshot root descriptor could not be duplicated.', cause);
  }
  try {
    checkedDirectoryStat(current, 'runtime root');
    let currentPath = '';
    for (const part of relativeParts(path)) {
      const nextPath = currentPath === '' ? part : `${currentPath}/${part}`;
      const next = openDirectoryFrom(current, part, label);
      closeQuietly(current);
      current = next;
      const expected = expectedDirectories.get(nextPath);
      if (expected !== undefined && !sameIdentity(checkedDirectoryStat(current, nextPath), expected)) {
        fail('directory-replaced', `The runtime snapshot detected a replaced directory at ${nextPath}.`);
      }
      currentPath = nextPath;
    }
    return current;
  } catch (error) {
    closeQuietly(current);
    throw error;
  }
};

const lstatFrom = (parentFd, name, label) => {
  let stat;
  try {
    stat = lstatSync(`${fdPath(parentFd)}/${name}`, { bigint: true });
  } catch (cause) {
    fail('entry-missing', `The runtime snapshot could not inspect ${label}.`, cause);
  }
  return stat;
};

const openRegularPlan = (rootFd, plan, expectedDirectories) => {
  const parentPath = dirname(plan.path);
  const parent = parentPath === '.'
    ? (() => {
      try {
        return openSync(fdPath(rootFd), constants.O_RDONLY | constants.O_DIRECTORY);
      } catch (cause) {
        fail('root-descriptor', 'The runtime snapshot root descriptor could not be duplicated.', cause);
      }
    })()
    : openDirectoryPath(rootFd, parentPath, expectedDirectories, parentPath);
  try {
    const name = plan.path.slice(plan.path.lastIndexOf('/') + 1);
    let fd;
    try {
      fd = openSync(`${fdPath(parent)}/${name}`, RegularReadFlags);
    } catch (cause) {
      fail('file-open', `The runtime snapshot could not retain ${plan.path}.`, cause);
    }
    try {
      const stat = checkedRegularStat(fd, plan.path, plan.maximumBytes);
      if (!sameIdentity(stat, plan.identity)) {
        fail('file-replaced', `The runtime snapshot detected a replaced file at ${plan.path}.`);
      }
      return fd;
    } catch (error) {
      closeQuietly(fd);
      throw error;
    }
  } finally {
    closeQuietly(parent);
  }
};

const directoryEntries = (fd, label, budget) => {
  let directory;
  try {
    directory = opendirSync(fdPath(fd), { encoding: 'utf8', bufferSize: 128 });
  } catch (cause) {
    fail('directory-read', `The runtime snapshot could not enumerate ${label}.`, cause);
  }
  try {
    const entries = [];
    while (true) {
      assertDeadline(budget.deadline);
      const entry = directory.readSync();
      if (entry === null) break;
      if (
        entry.name.length === 0 ||
        entry.name === '.' ||
        entry.name === '..' ||
        entry.name.includes('/') ||
        entry.name.includes('\\') ||
        /[\u0000-\u001f\u007f]/u.test(entry.name)
      ) {
        fail('directory-entry-invalid', `The runtime snapshot rejects an unsafe name in ${label}.`);
      }
      entries.push(entry.name);
      if (entries.length > runtimeVerificationBounds.entries) {
        fail('entry-limit', `The runtime snapshot exceeds its directory entry bound in ${label}.`);
      }
    }
    return entries.sort(compareSnapshotPaths);
  } finally {
    try {
      directory.closeSync();
    } catch {
      // The caller is already failing closed on a directory read failure.
    }
  }
};

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

const readBoundedManifest = (rootFd, budget) => {
  let fd;
  try {
    fd = openSync(`${fdPath(rootFd)}/runtime-manifest.json`, RegularReadFlags);
  } catch (cause) {
    fail('manifest-open', 'The runtime manifest could not be retained.', cause);
  }
  try {
    const identity = checkedRegularStat(fd, 'runtime manifest', runtimeVerificationBounds.manifestBytes);
    const size = reserveBytes(budget, identity.size, runtimeVerificationBounds.manifestBytes, 'runtime manifest');
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      assertDeadline(budget.deadline);
      const read = readSync(fd, bytes, offset, bytes.byteLength - offset, offset);
      if (read <= 0) fail('manifest-truncated', 'The retained runtime manifest changed while it was read.');
      offset += read;
    }
    if (sha256(bytes) !== runtimeTrustAnchor.manifestSha256) {
      fail('manifest-mismatch', 'The retained runtime manifest does not match the trust anchor.');
    }
    let manifest;
    try {
      manifest = validateRuntimeManifest(JSON.parse(bytes.toString('utf8')));
    } catch (cause) {
      fail('manifest-invalid', 'The retained runtime manifest is invalid.', cause);
    }
    reserveEntry(budget, 'runtime manifest');
    return {
      bytes,
      manifest,
      identity,
      path: 'runtime-manifest.json',
      maximumBytes: runtimeVerificationBounds.manifestBytes,
      expectedHashes: new Set([runtimeTrustAnchor.manifestSha256]),
      packageTree: undefined,
      executable: false,
    };
  } finally {
    closeQuietly(fd);
  }
};

const addExpectedHash = (map, path, digest) => {
  const values = map.get(path) ?? new Set();
  values.add(digest);
  map.set(path, values);
};

const manifestExpectedFiles = manifest => {
  const result = new Map();
  const add = item => addExpectedHash(result, item.path, item.sha256);
  for (const file of manifest.controlFiles) add(file);
  add(manifest.semanticRunner);
  add(manifest.runtimeNode);
  add(manifest.pnpmIntegrityEvidence);
  for (const packageEntry of manifest.semanticRunner.bundledPackages) add(packageEntry.licenseFile);
  for (const analyzer of manifest.analyzers) {
    add(analyzer.licenseNotice);
    for (const legalFile of analyzer.legalFiles) add(legalFile);
    for (const platform of analyzer.platforms) {
      for (const checksum of platform.checksums) add(checksum);
    }
  }
  addExpectedHash(result, 'runtime-manifest.json', runtimeTrustAnchor.manifestSha256);
  return result;
};

const packageRecords = manifest => {
  const records = [];
  for (const analyzer of manifest.analyzers) {
    for (const packageCheck of analyzer.packages) {
      if (packageCheck.source !== 'npm') continue;
      const root = dirname(packageCheck.packageJson).split(sep).join('/');
      relativeParts(root);
      records.push(Object.freeze({
        identity: `${packageCheck.name}@${packageCheck.version}`,
        root,
        treeSha256: packageCheck.treeSha256,
      }));
    }
  }
  records.sort((left, right) => compareSnapshotPaths(left.root, right.root));
  const identities = new Set();
  for (const record of records) {
    if (identities.has(record.identity)) fail('package-duplicate', 'The manifest has duplicate package identities.');
    identities.add(record.identity);
  }
  return records;
};

const assertNoPackageOverlap = packages => {
  for (let index = 1; index < packages.length; index += 1) {
    const prior = packages[index - 1];
    const next = packages[index];
    if (next.root === prior.root || next.root.startsWith(`${prior.root}/`)) {
      fail('package-overlap', 'The manifest package closure has overlapping physical roots.');
    }
  }
};

const scanPackageTree = ({ rootFd, packageRecord, budget, directories }) => {
  const directoryStats = new Map();
  const files = [];
  const records = [];
  const root = openDirectoryPath(rootFd, packageRecord.root, new Map(), packageRecord.root);
  const stack = [{ fd: root, relativePath: '', fullPath: packageRecord.root, depth: 0 }];
  try {
    // Keep one retained directory descriptor per level, rather than recursive
    // JS calls or one descriptor per sibling. A hostile deep replacement then
    // reaches the explicit depth bound before it can exhaust the call stack.
    while (stack.length > 0) {
      assertDeadline(budget.deadline);
      const frame = stack[stack.length - 1];
      if (frame.entries === undefined) {
        const identity = checkedDirectoryStat(frame.fd, frame.fullPath);
        reserveEntry(budget, frame.fullPath);
        directoryStats.set(frame.fullPath, identity);
        directories.set(frame.fullPath, DirectoryModeReadOnly);
        records.push({ kind: 'directory', relativePath: frame.relativePath, identity });
        frame.entries = directoryEntries(frame.fd, frame.fullPath, budget);
        frame.index = 0;
      }
      if (frame.index >= frame.entries.length) {
        closeQuietly(frame.fd);
        stack.pop();
        continue;
      }
      const name = frame.entries[frame.index];
      frame.index += 1;
      const full = `${frame.fullPath}/${name}`;
      const relativeChild = frame.relativePath === '' ? name : `${frame.relativePath}/${name}`;
      const metadata = lstatFrom(frame.fd, name, full);
      if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
        if (frame.depth + 1 > runtimeVerificationBounds.directoryDepth) {
          fail('directory-depth-limit', 'The runtime package tree exceeds its bounded directory depth.');
        }
        const child = openDirectoryFrom(frame.fd, name, full);
        stack.push({
          fd: child,
          relativePath: relativeChild,
          fullPath: full,
          depth: frame.depth + 1,
        });
        continue;
      }
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        fail('package-entry-invalid', `The runtime package tree has an unsupported entry at ${full}.`);
      }
      const identityFile = statIdentity(metadata);
      if (identityFile.nlink !== 1n || (identityFile.mode & 0o7000n) !== 0n) {
        fail('package-entry-invalid', `The runtime package tree has unsafe metadata at ${full}.`);
      }
      const size = reserveBytes(
        budget,
        identityFile.size,
        runtimeVerificationBounds.packageFileBytes,
        full,
      );
      reserveEntry(budget, full);
      const plan = {
        path: full,
        maximumBytes: runtimeVerificationBounds.packageFileBytes,
        identity: identityFile,
        size,
        expectedHashes: new Set(),
        packageTree: undefined,
        executable: (Number(identityFile.mode & 0o111n) !== 0),
      };
      files.push(plan);
      records.push({ kind: 'file', relativePath: relativeChild, identity: identityFile, plan });
    }
  } finally {
    for (const frame of stack) closeQuietly(frame.fd);
  }
  const tree = { ...packageRecord, directoryStats, files, records };
  for (const file of files) file.packageTree = tree;
  return tree;
};

const addParents = (directories, path) => {
  const parts = relativeParts(path);
  parts.pop();
  let current = '';
  for (const part of parts) {
    current = current === '' ? part : `${current}/${part}`;
    directories.set(current, DirectoryModeReadOnly);
  }
};

const expectedPnpmLinks = (manifest, packageByIdentity) => {
  const result = new Map();
  for (const importer of manifest.pnpmImporters) {
    for (const edge of importer.edges) {
      if (edge.state !== 'present') continue;
      const target = packageByIdentity.get(edge.target);
      if (target === undefined) fail('pnpm-link-invalid', 'The manifest has an unmodeled pnpm link target.');
      const path = `${importer.namespace}/${edge.specifier}`;
      relativeParts(path);
      if (result.has(path)) fail('pnpm-link-invalid', 'The manifest has duplicate pnpm links.');
      result.set(path, target.root);
    }
  }
  return result;
};

const resolveExpectedLink = (path, links) => {
  let current = path;
  for (let count = 0; count < 8; count += 1) {
    let match;
    for (const link of links.keys()) {
      if (current === link || current.startsWith(`${link}/`)) {
        if (match === undefined || link.length > match.length) match = link;
      }
    }
    if (match === undefined) return current;
    current = `${links.get(match)}${current.slice(match.length)}`;
  }
  fail('pnpm-link-cycle', 'The manifest contains a cyclic pnpm link mapping.');
};

const isPhysicalPackagePath = (path, packageTrees) =>
  packageTrees.find(tree => path === tree.root || path.startsWith(`${tree.root}/`));

const sourceLinkIsPresent = (rootFd, linkPath, expectedDirectories) => {
  const parentPath = dirname(linkPath);
  const parent = parentPath === '.'
    ? openSync(fdPath(rootFd), constants.O_RDONLY | constants.O_DIRECTORY)
    : openDirectoryPath(rootFd, parentPath, expectedDirectories, parentPath);
  try {
    const name = linkPath.slice(linkPath.lastIndexOf('/') + 1);
    const metadata = lstatFrom(parent, name, linkPath);
    if (!metadata.isSymbolicLink()) {
      fail('link-invalid', `The runtime snapshot expected a symlink at ${linkPath}.`);
    }
  } finally {
    closeQuietly(parent);
  }
};

const makeDirectPlan = ({ rootFd, path, expectedHashes, budget, expectedDirectories }) => {
  const plan = {
    path,
    maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    identity: undefined,
    size: 0,
    expectedHashes: new Set(expectedHashes),
    packageTree: undefined,
    executable: false,
  };
  const fd = openRegularPlan(rootFd, {
    ...plan,
    identity: { device: -1n, inode: -1n, mode: -1n, size: -1n, nlink: -1n },
  }, expectedDirectories);
  try {
    // `openRegularPlan` intentionally requires a retained identity. For a
    // first observation, inspect the descriptor directly and retain it below.
  } finally {
    closeQuietly(fd);
  }
  return plan;
};

const observeDirectPlan = ({ rootFd, path, expectedHashes, budget, expectedDirectories }) => {
  const parentPath = dirname(path);
  const parent = parentPath === '.'
    ? openSync(fdPath(rootFd), constants.O_RDONLY | constants.O_DIRECTORY)
    : openDirectoryPath(rootFd, parentPath, expectedDirectories, parentPath);
  let fd;
  try {
    const name = path.slice(path.lastIndexOf('/') + 1);
    fd = openSync(`${fdPath(parent)}/${name}`, RegularReadFlags);
    const identity = checkedRegularStat(fd, path, runtimeVerificationBounds.runtimeArtifactBytes);
    const size = reserveBytes(budget, identity.size, runtimeVerificationBounds.runtimeArtifactBytes, path);
    reserveEntry(budget, path);
    return {
      path,
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
      identity,
      size,
      expectedHashes: new Set(expectedHashes),
      packageTree: undefined,
      executable: false,
    };
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('file-open', `The runtime snapshot could not retain ${path}.`, cause);
  } finally {
    closeQuietly(fd);
    closeQuietly(parent);
  }
};

const packageTreeDigest = tree => {
  const hash = createHash('sha256');
  for (const record of tree.records) {
    const mode = Number(record.identity.mode & 0o7777n).toString(8).padStart(4, '0');
    if (record.kind === 'directory') {
      hash.update(`d\0${record.relativePath === '' ? '.' : record.relativePath}\0${mode}\n`);
    } else {
      if (typeof record.plan.actualSha256 !== 'string') {
        fail('package-copy-incomplete', `The runtime package tree did not retain ${record.plan.path}.`);
      }
      hash.update(`f\0${record.relativePath}\0${mode}\0${record.plan.actualSha256}\n`);
    }
  }
  return hash.digest('hex');
};

const writeAll = (fd, bytes, deadline) => {
  let offset = 0;
  while (offset < bytes.byteLength) {
    assertDeadline(deadline);
    const written = writeSync(fd, bytes, offset, bytes.byteLength - offset, null);
    if (written <= 0) fail('snapshot-write', 'The sealed snapshot could not make forward write progress.');
    offset += written;
  }
};

const writeRecordPrefix = (fd, kind, mode, path, payloadBytes, deadline) => {
  const pathBytes = Buffer.from(path, 'utf8');
  writeAll(fd, encodeSealedRuntimeSnapshotRecordPrefix({
    kind,
    mode,
    pathBytes,
    payloadBytes: BigInt(payloadBytes),
  }), deadline);
  writeAll(fd, pathBytes, deadline);
};

const copyPlan = ({
  rootFd,
  plan,
  expectedDirectories,
  destinationFd,
  mirrorFd,
  deadline,
}) => {
  if (plan.cachedBytes !== undefined) {
    if (sha256(plan.cachedBytes) !== plan.actualSha256) {
      fail('cached-bytes-invalid', 'The retained runtime manifest bytes changed unexpectedly.');
    }
    writeRecordPrefix(
      destinationFd,
      sealedRuntimeSnapshotRecordKind.file,
      plan.executable ? FileModeExecutable : FileModeReadOnly,
      plan.path,
      plan.cachedBytes.byteLength,
      deadline,
    );
    writeAll(destinationFd, plan.cachedBytes, deadline);
    if (mirrorFd !== undefined) writeAll(mirrorFd, plan.cachedBytes, deadline);
    return;
  }
  const source = openRegularPlan(rootFd, plan, expectedDirectories);
  try {
    writeRecordPrefix(
      destinationFd,
      sealedRuntimeSnapshotRecordKind.file,
      plan.executable ? FileModeExecutable : FileModeReadOnly,
      plan.path,
      plan.size,
      deadline,
    );
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
    let remaining = plan.size;
    let position = 0;
    while (remaining > 0) {
      assertDeadline(deadline);
      const read = readSync(source, buffer, 0, Math.min(buffer.byteLength, remaining), position);
      if (read <= 0) fail('file-truncated', `The retained file ${plan.path} changed while copied.`);
      const chunk = buffer.subarray(0, read);
      hash.update(chunk);
      writeAll(destinationFd, chunk, deadline);
      if (mirrorFd !== undefined) writeAll(mirrorFd, chunk, deadline);
      position += read;
      remaining -= read;
    }
    const extra = readSync(source, buffer, 0, 1, position);
    if (extra !== 0) fail('file-grown', `The retained file ${plan.path} grew while copied.`);
    plan.actualSha256 = hash.digest('hex');
  } finally {
    closeQuietly(source);
  }
};

// Copies a separately mounted immutable asset such as the OSV database. It
// deliberately emits no snapshot record: non-OSV analyzer invocations must
// not pay to extract or even receive the 219 MiB database.
const copyRawPlan = ({ rootFd, plan, expectedDirectories, destinationFd, deadline }) => {
  if (plan.cachedBytes !== undefined) {
    if (sha256(plan.cachedBytes) !== plan.actualSha256) {
      fail('cached-bytes-invalid', 'The retained runtime control bytes changed unexpectedly.');
    }
    writeAll(destinationFd, plan.cachedBytes, deadline);
    return;
  }
  const source = openRegularPlan(rootFd, plan, expectedDirectories);
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
    let remaining = plan.size;
    let position = 0;
    while (remaining > 0) {
      assertDeadline(deadline);
      const read = readSync(source, buffer, 0, Math.min(buffer.byteLength, remaining), position);
      if (read <= 0) fail('file-truncated', `The retained file ${plan.path} changed while copied.`);
      const chunk = buffer.subarray(0, read);
      hash.update(chunk);
      writeAll(destinationFd, chunk, deadline);
      position += read;
      remaining -= read;
    }
    if (readSync(source, buffer, 0, 1, position) !== 0) {
      fail('file-grown', `The retained file ${plan.path} grew while copied.`);
    }
    plan.actualSha256 = hash.digest('hex');
  } finally {
    closeQuietly(source);
  }
};

const assertExpectedHashes = plan => {
  if (typeof plan.actualSha256 !== 'string') {
    fail('file-copy-incomplete', `The runtime snapshot did not copy ${plan.path}.`);
  }
  for (const expected of plan.expectedHashes) {
    if (plan.actualSha256 !== expected) {
      fail('checksum-mismatch', `The retained runtime file ${plan.path} does not match its manifest record.`);
    }
  }
};

const retainOfflineOsvMetadata = database => Object.freeze({
  ...database,
  validationEvidence: Object.freeze({
    ...database.validationEvidence,
    source: Object.freeze({ ...database.validationEvidence.source }),
    archive: Object.freeze({
      ...database.validationEvidence.archive,
      compressionMethods: Object.freeze([...database.validationEvidence.archive.compressionMethods]),
    }),
  }),
  validator: Object.freeze({ ...database.validator }),
});

const retainVerifierControlArtifact = ({ control, path, mode, label }) => {
  const source = control.files.find(candidate => candidate.path === path);
  if (
    source === undefined ||
    source.mode !== mode ||
    !Number.isSafeInteger(source.fd) ||
    !Number.isSafeInteger(source.byteLength) ||
    typeof source.sha256 !== 'string'
  ) {
    fail('control-capability-invalid', `The verified analyzer-control capability lacks ${label}.`);
  }
  let fd;
  try {
    fd = duplicateReadonlyFd(source.fd);
    const proof = assertAnalyzerControlArtifactFd({
      fd,
      byteLength: source.byteLength,
      sha256: source.sha256,
      mode,
      identity: source.identity,
    });
    // The control leaf serializes permission-only modes (`0444`/`0555`) for
    // its installation contract. The sealed-generation transport binds the
    // complete `stat.mode` value, so normalize the re-proven duplicate here.
    const identity = serializedDescriptorIdentity(fstatSync(proof.fd, { bigint: true }));
    fd = undefined;
    return Object.freeze({
      fd: proof.fd,
      byteLength: proof.byteLength,
      sha256: proof.sha256,
      identity,
    });
  } catch (cause) {
    closeQuietly(fd);
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('control-capability-invalid', `The verified analyzer-control ${label} could not be retained.`, cause);
  }
};

const createSealableMemfd = (bridge, { executable = false } = {}) => {
  let fd;
  try {
    fd = executable ? bridge.createExecutable() : bridge.createData();
    fchmodSync(fd, executable ? FileModeExecutable : FileModeReadOnly);
    const stat = fstatSync(fd, { bigint: true });
    if (
      !stat.isFile() ||
      stat.nlink !== 0n ||
      (stat.mode & 0o7777n) !== BigInt(executable ? FileModeExecutable : FileModeReadOnly)
    ) {
      fail('memfd-invalid', 'The trusted Linux memfd bridge did not create an anonymous regular file.');
    }
    return fd;
  } catch (cause) {
    closeQuietly(fd);
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('memfd-create', 'The trusted Linux memfd bridge could not create a snapshot descriptor.', cause);
  }
};

const sealMemfd = (bridge, fd, { executable = false, maximumBytes = SnapshotMaximumBytes } = {}) => {
  try {
    fsyncSync(fd);
    const added = bridge.seal(fd);
    const actual = bridge.getSeals(fd);
    if (
      (added & RequiredMemfdSeals) !== RequiredMemfdSeals ||
      (actual & RequiredMemfdSeals) !== RequiredMemfdSeals
    ) {
      fail('memfd-seal-proof', 'F_GET_SEALS did not prove the required immutable memfd seals.');
    }
    const stat = fstatSync(fd, { bigint: true });
    if (
      !stat.isFile() ||
      stat.nlink !== 0n ||
      stat.size > BigInt(maximumBytes) ||
      (stat.mode & 0o7777n) !== BigInt(executable ? FileModeExecutable : FileModeReadOnly)
    ) {
      fail('memfd-invalid', 'The sealed memfd has invalid metadata.');
    }
    return {
      fd,
      byteLength: Number(stat.size),
      seals: actual,
      identity: serializedDescriptorIdentity(stat),
    };
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('memfd-seal', 'The runtime snapshot memfd could not be sealed.', cause);
  }
};

const assertSealedMemfd = ({
  bridge,
  fd,
  label,
  maximumBytes,
  exactBytes,
  expectedIdentity,
  executable = false,
}) => {
  try {
    return assertSealedRuntimeMemfdDescriptor({
      bridge,
      fd,
      byteLength: exactBytes,
      identity: expectedIdentity,
      maximumBytes,
      executable,
      label,
    });
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('memfd-proof-invalid', `The ${label} is not a bounded sealed anonymous memfd.`, cause);
  }
};

const readSnapshotHeader = ({ fd, byteLength }) => {
  if (byteLength < sealedRuntimeSnapshotHeaderBytes) {
    fail('snapshot-header-invalid', 'The sealed runtime snapshot has no complete header.');
  }
  const bytes = Buffer.allocUnsafe(sealedRuntimeSnapshotHeaderBytes);
  let offset = 0;
  while (offset < bytes.byteLength) {
    let read;
    try {
      read = readSync(fd, bytes, offset, bytes.byteLength - offset, offset);
    } catch (cause) {
      fail('snapshot-header-unavailable', 'The sealed runtime snapshot header could not be read.', cause);
    }
    if (read <= 0) fail('snapshot-header-invalid', 'The sealed runtime snapshot header is truncated.');
    offset += read;
  }
  try {
    return decodeSealedRuntimeSnapshotHeader(bytes);
  } catch (cause) {
    fail('snapshot-header-invalid', 'The sealed runtime snapshot header is malformed.', cause);
  }
};

/**
 * Re-proves the kernel seals and fixed control identity of a transported
 * snapshot FD. This is intentionally lower-level than handle inspection: it
 * is for the short-lived trusted launcher after descriptor inheritance.
 */
export const assertSealedRuntimeSnapshotFd = ({
  fd,
  archiveBytes,
  manifestSha256,
  runnerSha256,
  nodeSha256,
  osvDatabaseSha256,
  snapshotIdentity,
  addonFd,
  addonBytes,
  addonSha256,
  addonIdentity,
}) => {
  if (process.platform !== 'linux') {
    fail('unsupported-platform', 'Sealed analyzer runtime snapshots require Linux.');
  }
  if (
    manifestSha256 !== runtimeTrustAnchor.manifestSha256 ||
    runnerSha256 !== runtimeTrustAnchor.runnerSha256 ||
    nodeSha256 !== requiredRuntimeNode.sha256 ||
    osvDatabaseSha256 !== requiredOfflineOsvDatabase.sha256
  ) {
    fail('snapshot-identity-invalid', 'The supplied sealed snapshot identity is not the compiled runtime identity.');
  }
  const proof = assertSealedMemfd({
    bridge: loadRuntimeMemfdBridgeFromFd({ addonFd, addonBytes, addonSha256, addonIdentity }),
    fd,
    label: 'runtime snapshot',
    maximumBytes: SnapshotMaximumBytes,
    exactBytes: archiveBytes,
    expectedIdentity: snapshotIdentity,
  });
  const header = readSnapshotHeader(proof);
  if (
    header.manifestSha256 !== manifestSha256 ||
    header.runnerSha256 !== runnerSha256 ||
    header.nodeSha256 !== nodeSha256 ||
    header.osvDatabaseSha256 !== osvDatabaseSha256
  ) {
    fail('snapshot-header-identity', 'The sealed runtime snapshot header does not match its transported identity.');
  }
  return Object.freeze({ ...proof, header });
};

export const assertSealedRuntimeNodeFd = ({
  nodeFd,
  nodeSha256,
  nodeBytes,
  nodeIdentity,
  addonFd,
  addonBytes,
  addonSha256,
  addonIdentity,
}) => {
  if (nodeSha256 !== requiredRuntimeNode.sha256) {
    fail('node-identity-invalid', 'The retained runtime Node does not match the compiled Node identity.');
  }
  return assertSealedMemfd({
    bridge: loadRuntimeMemfdBridgeFromFd({ addonFd, addonBytes, addonSha256, addonIdentity }),
    fd: nodeFd,
    label: 'runtime Node',
    maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    exactBytes: nodeBytes,
    expectedIdentity: nodeIdentity,
    executable: true,
  });
};

const sha256SealedFd = ({ fd, byteLength, label }) => {
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
  let remaining = byteLength;
  let position = 0;
  while (remaining > 0) {
    let read;
    try {
      read = readSync(fd, buffer, 0, Math.min(buffer.byteLength, remaining), position);
    } catch (cause) {
      fail('memfd-content-unavailable', `The ${label} could not be hashed.`, cause);
    }
    if (read <= 0) fail('memfd-content-invalid', `The ${label} is truncated.`);
    hash.update(buffer.subarray(0, read));
    position += read;
    remaining -= read;
  }
  return hash.digest('hex');
};

/**
 * Re-proves a transported offline OSV database descriptor. Content hashing is
 * intentionally opt-in for the branded in-process handle (its provenance is
 * already retained in the private WeakMap), but defaults on for a separately
 * inherited launcher FD where raw descriptor substitution is otherwise
 * possible. It streams with the same 64 KiB bound and never expands the ZIP.
 */
export const assertSealedOfflineOsvDatabaseFd = ({
  osvDatabaseFd,
  osvDatabaseSha256,
  osvDatabaseBytes,
  osvDatabaseGeneration,
  osvDatabaseIdentity,
  addonFd,
  addonBytes,
  addonSha256,
  addonIdentity,
  verifyContent = true,
}) => {
  if (process.platform !== 'linux') {
    fail('unsupported-platform', 'Sealed analyzer runtime snapshots require Linux.');
  }
  if (
    osvDatabaseSha256 !== requiredOfflineOsvDatabase.sha256 ||
    osvDatabaseBytes !== requiredOfflineOsvDatabase.size ||
    osvDatabaseGeneration !== requiredOfflineOsvDatabase.generation ||
    typeof verifyContent !== 'boolean'
  ) {
    fail('osv-database-identity-invalid', 'The supplied OSV database identity is not the compiled immutable generation.');
  }
  const proof = assertSealedMemfd({
    bridge: loadRuntimeMemfdBridgeFromFd({ addonFd, addonBytes, addonSha256, addonIdentity }),
    fd: osvDatabaseFd,
    label: 'offline OSV database',
    maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    exactBytes: osvDatabaseBytes,
    expectedIdentity: osvDatabaseIdentity,
  });
  if (verifyContent && sha256SealedFd({
    fd: proof.fd,
    byteLength: proof.byteLength,
    label: 'offline OSV database',
  }) !== osvDatabaseSha256) {
    fail('osv-database-content-mismatch', 'The sealed offline OSV database does not match its pinned SHA-256.');
  }
  return proof;
};

/**
 * Returns a live, branded sealed-generation capability. A structurally
 * similar plain object is rejected: archive control hashes alone cannot prove
 * that every package payload was authenticated during packing.
 */
export const inspectSealedAnalyzerRuntime = handle => {
  const record = sealedGenerationHandles.get(handle);
  if (record === undefined || record.closed) {
    fail('sealed-handle-invalid', 'A live sealed analyzer runtime handle is required.');
  }
  const snapshot = assertSealedRuntimeSnapshotFd(record);
  const node = assertSealedRuntimeNodeFd(record);
  const osvDatabase = assertSealedOfflineOsvDatabaseFd({
    ...record,
    verifyContent: false,
  });
  const loader = assertTrustedRuntimeControlFd({
    fd: record.loaderFd,
    byteLength: record.loaderBytes,
    sha256: record.loaderSha256,
    identity: record.loaderIdentity,
  });
  const launcher = assertTrustedRuntimeControlFd({
    fd: record.launcherFd,
    byteLength: record.launcherBytes,
    sha256: record.launcherSha256,
    identity: record.launcherIdentity,
  });
  const addon = assertTrustedRuntimeControlFd({
    fd: record.addonFd,
    byteLength: record.addonBytes,
    sha256: record.addonSha256,
    identity: record.addonIdentity,
  });
  return Object.freeze({
    schemaVersion: SnapshotSchemaVersion,
    sealing: SnapshotFdSealing,
    seals: snapshot.seals,
    snapshotFd: snapshot.fd,
    nodeFd: node.fd,
    nodeSeals: node.seals,
    nodeBytes: node.byteLength,
    nodeIdentity: node.identity,
    osvDatabaseFd: osvDatabase.fd,
    osvDatabaseSeals: osvDatabase.seals,
    osvDatabaseIdentity: osvDatabase.identity,
    loaderFd: loader.fd,
    loaderBytes: loader.byteLength,
    loaderSha256: loader.sha256,
    loaderIdentity: loader.identity,
    launcherFd: launcher.fd,
    launcherBytes: launcher.byteLength,
    launcherSha256: launcher.sha256,
    launcherIdentity: launcher.identity,
    addonFd: addon.fd,
    addonBytes: addon.byteLength,
    addonSha256: addon.sha256,
    addonIdentity: addon.identity,
    controlArtifacts: record.controlArtifacts,
    manifestSha256: record.manifestSha256,
    runnerSha256: record.runnerSha256,
    nodeSha256: record.nodeSha256,
    osvDatabaseSha256: record.osvDatabaseSha256,
    osvDatabaseRelativePath: requiredOfflineOsvDatabase.path,
    osvDatabaseBytes: requiredOfflineOsvDatabase.size,
    osvDatabaseGeneration: requiredOfflineOsvDatabase.generation,
    osvDatabaseMetadata: record.osvDatabaseMetadata,
    runtimeBytes: record.runtimeBytes,
    runtimeEntries: record.runtimeEntries,
    archiveBytes: snapshot.byteLength,
    snapshotIdentity: snapshot.identity,
  });
};

export const assertTrustedRuntimeControlFd = ({ fd, byteLength, sha256: expectedSha256, identity }) => {
  try {
    return assertTrustedRuntimeControlDescriptor({
      fd,
      byteLength,
      sha256: expectedSha256,
      identity,
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
      label: 'trusted runtime control',
    });
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('trusted-control-invalid', 'The trusted runtime control descriptor no longer matches its retained identity.', cause);
  }
};

/**
 * Loads the independently authenticated native bridge from a retained control
 * descriptor.  This is deliberately descriptor-only: launcher-side proof
 * never resolves the mutable control-root pathname after sealing.
 */
export const loadRuntimeMemfdBridgeFromFd = ({ addonFd, addonBytes, addonSha256, addonIdentity }) => {
  try {
    return loadRuntimeMemfdBridgeFromDescriptor({
      addonFd,
      addonBytes,
      addonSha256,
      addonIdentity,
      addonMaximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    });
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('memfd-bridge-unavailable', 'The retained runtime memfd bridge could not be loaded.', cause);
  }
};

const assertVerifiedIdentity = identity => {
  if (
    identity === null ||
    typeof identity !== 'object' ||
    identity.schemaVersion !== 'codebase-radar.analyzer-runtime-identity/v1' ||
    identity.manifestSha256 !== runtimeTrustAnchor.manifestSha256 ||
    identity.runnerSha256 !== runtimeTrustAnchor.runnerSha256 ||
    identity.policyDigest !== runtimeTrustAnchor.policyDigest ||
    identity.buildIdentity !== runtimeTrustAnchor.buildIdentity ||
    !validGenerationPart(identity.targetGeneration?.device) ||
    !validGenerationPart(identity.targetGeneration?.inode)
  ) {
    fail('identity-invalid', 'A current trusted analyzer runtime identity is required before snapshotting.');
  }
};

const sourcePlanForPath = ({ path, packageTrees, physicalFiles, links }) => {
  const resolved = resolveExpectedLink(path, links);
  const physical = physicalFiles.get(resolved);
  if (physical !== undefined) return physical;
  if (isPhysicalPackagePath(resolved, packageTrees) !== undefined) {
    fail('package-file-missing', `The manifest path ${path} is absent from its authenticated package tree.`);
  }
  return undefined;
};

const expectedExecutablePaths = manifest => {
  const paths = new Set([requiredSemanticRunnerPath, manifest.runtimeNode.path]);
  for (const analyzer of manifest.analyzers) {
    for (const platform of analyzer.platforms) {
      paths.add(platform.entrypoint);
      for (const native of platform.nativeExecutables) paths.add(native);
      for (const launcher of platform.launchers) paths.add(launcher.target);
    }
  }
  return paths;
};

/**
 * Copies an independently re-authenticated manifest closure into an anonymous
 * Linux inode. The returned descriptor is opened read-only and the sole write
 * descriptor is closed before this function returns. It is therefore an
 * immutable capability even though Node has no public memfd/fcntl-seal API.
 */
export const sealVerifiedAnalyzerRuntime = ({ root, identity, controlCapability }) => {
  if (process.platform !== 'linux') {
    fail('unsupported-platform', 'Sealed analyzer runtime snapshots require Linux.');
  }
  assertVerifiedIdentity(identity);
  if (typeof root !== 'string' || !isAbsolute(root) || root.length === 0 || root !== root.trim()) {
    fail('root-invalid', 'The analyzer runtime root must be an absolute trimmed path.');
  }
  if (controlCapability !== identity.analyzerControl) {
    fail('control-capability-invalid', 'Sealing requires the exact opaque analyzer-control capability returned with the runtime identity.');
  }
  let control;
  try {
    control = inspectAnalyzerControl(controlCapability);
  } catch (cause) {
    fail('control-capability-invalid', 'The verifier-returned analyzer-control capability is unavailable.', cause);
  }
  const budget = makeBudget();
  let rootFd;
  let snapshotWriter;
  let snapshotFd;
  let nodeWriter;
  let nodeFd;
  let osvDatabaseWriter;
  let osvDatabaseFd;
  let loaderControl;
  let launcherControl;
  let addonControl;
  try {
    loaderControl = retainVerifierControlArtifact({
      control,
      path: MaterializerControlFile,
      label: 'standalone runtime materializer',
      mode: '0444',
    });
    launcherControl = retainVerifierControlArtifact({
      control,
      path: GovernanceLauncherControlFile,
      label: 'standalone resource governance launcher',
      mode: '0444',
    });
    addonControl = retainVerifierControlArtifact({
      control,
      path: MemfdAddonControlFile,
      label: 'runtime memfd addon',
      mode: '0555',
    });
    const bridge = loadRuntimeMemfdBridgeFromFd({
      addonFd: addonControl.fd,
      addonBytes: addonControl.byteLength,
      addonSha256: addonControl.sha256,
      addonIdentity: addonControl.identity,
    });
    rootFd = openSync(root, DirectoryOpenFlags);
    const rootStat = checkedDirectoryStat(rootFd, 'runtime root');
    if (
      rootStat.device.toString(10) !== identity.targetGeneration.device ||
      rootStat.inode.toString(10) !== identity.targetGeneration.inode
    ) {
      fail('generation-replaced', 'The analyzer runtime generation changed before it could be sealed.');
    }

    const manifestPlan = readBoundedManifest(rootFd, budget);
    manifestPlan.cachedBytes = manifestPlan.bytes;
    manifestPlan.actualSha256 = runtimeTrustAnchor.manifestSha256;
    const manifest = manifestPlan.manifest;
    assertOfflineOsvDatabaseFresh(manifest.offlineOsvDatabase);
    const osvDatabaseMetadata = retainOfflineOsvMetadata(manifest.offlineOsvDatabase);
    const packages = packageRecords(manifest);
    assertNoPackageOverlap(packages);
    const directories = new Map();
    const packageTrees = packages.map(packageRecord =>
      scanPackageTree({ rootFd, packageRecord, budget, directories }),
    );
    const packageByIdentity = new Map(packageTrees.map(tree => [tree.identity, tree]));
    const physicalFiles = new Map();
    const expectedDirectories = new Map();
    for (const tree of packageTrees) {
      for (const [path, directory] of tree.directoryStats) expectedDirectories.set(path, directory);
      for (const file of tree.files) {
        if (physicalFiles.has(file.path)) fail('package-overlap', 'The package closure repeats a physical file.');
        physicalFiles.set(file.path, file);
      }
    }
    const pnpmLinks = expectedPnpmLinks(manifest, packageByIdentity);
    const allLinks = new Map(pnpmLinks);
    for (const analyzer of manifest.analyzers) {
      for (const platform of analyzer.platforms) {
        for (const launcher of platform.launchers) {
          const target = resolveExpectedLink(launcher.target, pnpmLinks);
          if (allLinks.has(launcher.path)) fail('link-duplicate', 'The manifest repeats a snapshot symlink path.');
          allLinks.set(launcher.path, target);
        }
      }
    }

    const directPlans = new Map([[manifestPlan.path, manifestPlan]]);
    addParents(directories, manifestPlan.path);
    for (const [path, hashes] of manifestExpectedFiles(manifest)) {
      const existing = sourcePlanForPath({ path, packageTrees, physicalFiles, links: pnpmLinks });
      if (existing !== undefined) {
        for (const digest of hashes) existing.expectedHashes.add(digest);
        continue;
      }
      if (directPlans.has(path)) {
        for (const digest of hashes) directPlans.get(path).expectedHashes.add(digest);
        continue;
      }
      const plan = observeDirectPlan({
        rootFd,
        path,
        expectedHashes: hashes,
        budget,
        expectedDirectories,
      });
      directPlans.set(path, plan);
      addParents(directories, path);
    }

    const nodePlan = directPlans.get(manifest.runtimeNode.path);
    if (nodePlan === undefined || nodePlan.path !== requiredRuntimeNode.path) {
      fail('runtime-node-missing', 'The pinned runtime Node is absent from the direct authenticated closure.');
    }
    // Keep the large immutable OSV ZIP outside the general code archive. It
    // is authenticated now and sealed once per analysis scope, but only the
    // OSV invocation receives it as a read-only FD mount.
    const osvDatabasePlan = observeDirectPlan({
      rootFd,
      path: manifest.offlineOsvDatabase.path,
      expectedHashes: new Set([manifest.offlineOsvDatabase.sha256]),
      budget,
      expectedDirectories,
    });
    if (
      osvDatabasePlan === undefined ||
      osvDatabasePlan.path !== requiredOfflineOsvDatabase.path ||
      osvDatabasePlan.size !== manifest.offlineOsvDatabase.size
    ) {
      fail('osv-database-missing', 'The pinned offline OSV database is absent or has the wrong byte length.');
    }
    // The code archive deliberately excludes the large ZIP, but its canonical
    // empty parent chain is materialized so only the OSV sandbox can bind the
    // separately sealed database over this exact destination.
    addParents(directories, manifest.offlineOsvDatabase.path);

    for (const [path, target] of allLinks) {
      relativeParts(path);
      relativeParts(target);
      sourceLinkIsPresent(rootFd, path, expectedDirectories);
      addParents(directories, path);
      // The archive never copies an attacker-controlled readlink payload. The
      // manifest's authenticated importer/launcher graph is the only source
      // of each target, reconstructed below as a root-contained relative link.
    }

    const executablePaths = expectedExecutablePaths(manifest);
    for (const logicalPath of executablePaths) {
      const path = resolveExpectedLink(logicalPath, pnpmLinks);
      const plan = physicalFiles.get(path) ?? directPlans.get(path);
      if (plan === undefined) {
        fail('executable-missing', 'A manifest-declared executable is absent from the sealed closure.');
      }
      plan.executable = true;
    }

    const files = [...physicalFiles.values(), ...directPlans.values()]
      .sort((left, right) => compareSnapshotPaths(left.path, right.path));
    const orderedDirectories = [...directories.keys()]
      .sort(compareSnapshotPaths);
    const orderedLinks = [...allLinks.entries()]
      .map(([path, target]) => ({ path, target }))
      .sort((left, right) => compareSnapshotPaths(left.path, right.path));
    const entryCount = orderedDirectories.length + files.length + orderedLinks.length;
    if (entryCount > runtimeVerificationBounds.entries) {
      fail('entry-limit', 'The sealed runtime archive exceeds its entry bound.');
    }

    snapshotWriter = createSealableMemfd(bridge);
    nodeWriter = createSealableMemfd(bridge, { executable: true });
    osvDatabaseWriter = createSealableMemfd(bridge);
    writeAll(snapshotWriter, encodeSealedRuntimeSnapshotHeader({
      entryCount,
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      nodeSha256: manifest.runtimeNode.sha256,
      osvDatabaseSha256: manifest.offlineOsvDatabase.sha256,
    }), budget.deadline);
    for (const path of orderedDirectories) {
      writeRecordPrefix(
        snapshotWriter,
        sealedRuntimeSnapshotRecordKind.directory,
        DirectoryModeReadOnly,
        path,
        0,
        budget.deadline,
      );
    }
    for (const plan of files) {
      copyPlan({
        rootFd,
        plan,
        expectedDirectories,
        destinationFd: snapshotWriter,
        ...(plan === nodePlan ? { mirrorFd: nodeWriter } : {}),
        deadline: budget.deadline,
      });
      assertExpectedHashes(plan);
    }
    for (const tree of packageTrees) {
      const actual = packageTreeDigest(tree);
      if (actual !== tree.treeSha256) {
        fail('package-tree-mismatch', 'A package tree changed while the sealed snapshot was copied.');
      }
    }
    copyRawPlan({
      rootFd,
      plan: osvDatabasePlan,
      expectedDirectories,
      destinationFd: osvDatabaseWriter,
      deadline: budget.deadline,
    });
    assertExpectedHashes(osvDatabasePlan);
    for (const link of orderedLinks) {
      const target = posix.relative(posix.dirname(link.path), link.target);
      if (target.length === 0 || target.startsWith('/') || posix.normalize(posix.join(posix.dirname(link.path), target)).startsWith('../')) {
        fail('link-target-invalid', 'The manifest produced a symlink outside the sealed runtime root.');
      }
      const payload = Buffer.from(target, 'utf8');
      writeRecordPrefix(
        snapshotWriter,
        sealedRuntimeSnapshotRecordKind.symlink,
        FileModeReadOnly,
        link.path,
        payload.byteLength,
        budget.deadline,
      );
      writeAll(snapshotWriter, payload, budget.deadline);
    }

    // This descriptor bootstraps the trusted outer loader without falling
    // back to process.execPath. It receives the exact bytes simultaneously
    // authenticated for /runtime/bin/node, then becomes a sealed capability.
    const sealedNode = sealMemfd(bridge, nodeWriter, {
      executable: true,
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    });
    nodeWriter = undefined;
    nodeFd = sealedNode.fd;
    const sealedOsvDatabase = sealMemfd(bridge, osvDatabaseWriter, {
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    });
    osvDatabaseWriter = undefined;
    osvDatabaseFd = sealedOsvDatabase.fd;
    const sealed = sealMemfd(bridge, snapshotWriter);
    snapshotWriter = undefined;
    snapshotFd = sealed.fd;
    const record = {
      fd: sealed.fd,
      archiveBytes: sealed.byteLength,
      snapshotIdentity: sealed.identity,
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      nodeSha256: manifest.runtimeNode.sha256,
      nodeFd: sealedNode.fd,
      nodeBytes: sealedNode.byteLength,
      nodeIdentity: sealedNode.identity,
      osvDatabaseFd: sealedOsvDatabase.fd,
      osvDatabaseSha256: manifest.offlineOsvDatabase.sha256,
      osvDatabaseBytes: sealedOsvDatabase.byteLength,
      osvDatabaseGeneration: manifest.offlineOsvDatabase.generation,
      osvDatabaseIdentity: sealedOsvDatabase.identity,
      osvDatabaseMetadata,
      loaderFd: loaderControl.fd,
      loaderBytes: loaderControl.byteLength,
      loaderSha256: loaderControl.sha256,
      loaderIdentity: loaderControl.identity,
      launcherFd: launcherControl.fd,
      launcherBytes: launcherControl.byteLength,
      launcherSha256: launcherControl.sha256,
      launcherIdentity: launcherControl.identity,
      addonFd: addonControl.fd,
      addonBytes: addonControl.byteLength,
      addonSha256: addonControl.sha256,
      addonIdentity: addonControl.identity,
      controlArtifacts: Object.freeze(control.files.map(file => Object.freeze({
        path: file.path,
        byteLength: file.byteLength,
        sha256: file.sha256,
        mode: file.mode,
        identity: file.identity,
      }))),
      runtimeBytes: Number(budget.sourceBytes),
      runtimeEntries: entryCount,
      closed: false,
    };
    const close = () => {
      if (record.closed) return;
      record.closed = true;
      const snapshot = snapshotFd;
      const node = nodeFd;
      const osvDatabase = osvDatabaseFd;
      const loader = loaderControl?.fd;
      const launcher = launcherControl?.fd;
      const addon = addonControl?.fd;
      snapshotFd = undefined;
      nodeFd = undefined;
      osvDatabaseFd = undefined;
      loaderControl = undefined;
      launcherControl = undefined;
      addonControl = undefined;
      closeQuietly(snapshot);
      closeQuietly(node);
      closeQuietly(osvDatabase);
      closeQuietly(loader);
      closeQuietly(launcher);
      closeQuietly(addon);
    };
    const handle = Object.freeze({
      schemaVersion: SnapshotSchemaVersion,
      sealing: SnapshotFdSealing,
      seals: sealed.seals,
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      nodeSha256: manifest.runtimeNode.sha256,
      osvDatabaseSha256: manifest.offlineOsvDatabase.sha256,
      osvDatabaseRelativePath: manifest.offlineOsvDatabase.path,
      osvDatabaseBytes: manifest.offlineOsvDatabase.size,
      osvDatabaseGeneration: manifest.offlineOsvDatabase.generation,
      osvDatabaseIdentity: sealedOsvDatabase.identity,
      runtimeBytes: Number(budget.sourceBytes),
      runtimeEntries: entryCount,
      archiveBytes: sealed.byteLength,
      snapshotIdentity: sealed.identity,
      close,
    });
    sealedGenerationHandles.set(handle, record);
    return handle;
  } catch (cause) {
    closeQuietly(snapshotFd);
    closeQuietly(snapshotWriter);
    closeQuietly(nodeFd);
    closeQuietly(nodeWriter);
    closeQuietly(osvDatabaseFd);
    closeQuietly(osvDatabaseWriter);
    closeQuietly(loaderControl?.fd);
    closeQuietly(launcherControl?.fd);
    closeQuietly(addonControl?.fd);
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('snapshot-failed', 'The analyzer runtime could not be sealed.', cause);
  } finally {
    closeQuietly(rootFd);
  }
};

const MaterializedSchemaVersion = 'codebase-radar.analyzer-runtime-materialized/v1';
const MaterializationParent = '/tmp/codebase-radar-runtime-generations-v1';
const MaterializationMarkerSchemaVersion = 'codebase-radar.analyzer-runtime-materialization-marker/v1';
const materializedRuntimeHandles = new WeakMap();
const pendingMaterializationCleanup = new Map();

const readSmallTrustedText = (path, maximumBytes, label) => {
  let fd;
  try {
    fd = openSync(path, RegularReadFlags);
    const metadata = fstatSync(fd, { bigint: true });
    if (!metadata.isFile() || metadata.nlink !== 1n || metadata.size < 1n || metadata.size > BigInt(maximumBytes)) {
      fail('materialization-marker-invalid', `The ${label} has invalid metadata.`);
    }
    const bytes = Buffer.allocUnsafe(Number(metadata.size));
    let offset = 0;
    while (offset < bytes.byteLength) {
      const read = readSync(fd, bytes, offset, bytes.byteLength - offset, offset);
      if (read <= 0) fail('materialization-marker-invalid', `The ${label} is truncated.`);
      offset += read;
    }
    return bytes.toString('utf8');
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('materialization-marker-unavailable', `The ${label} is unavailable.`, cause);
  } finally {
    closeQuietly(fd);
  }
};

const currentProcessStartTicks = pid => {
  const text = readSmallTrustedText(`/proc/${pid}/stat`, runtimeVerificationBounds.textBytes, 'process start record');
  // Comm can contain spaces/parentheses; field 22 is reliably after the last
  // closing parenthesis followed by the remaining whitespace-delimited tail.
  const close = text.lastIndexOf(')');
  const fields = close < 0 ? [] : text.slice(close + 2).trim().split(/\s+/u);
  const value = fields[19];
  if (!/^[1-9][0-9]*$/u.test(value ?? '')) {
    fail('materialization-marker-invalid', 'The process start record is malformed.');
  }
  return value;
};

const currentBootId = () => {
  const value = readSmallTrustedText('/proc/sys/kernel/random/boot_id', 256, 'boot identifier').trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)) {
    fail('materialization-marker-invalid', 'The boot identifier is malformed.');
  }
  return value;
};

const currentMaterializationMarker = generation => Object.freeze({
  schemaVersion: MaterializationMarkerSchemaVersion,
  generation,
  pid: process.pid,
  procStartTicks: currentProcessStartTicks(process.pid),
  bootId: currentBootId(),
});

const parseMaterializationMarker = ({ path, generation }) => {
  let marker;
  try {
    marker = JSON.parse(readSmallTrustedText(path, runtimeVerificationBounds.textBytes, 'materialization marker'));
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('materialization-marker-invalid', 'The materialization marker is invalid.', cause);
  }
  if (
    marker === null || typeof marker !== 'object' || Array.isArray(marker) ||
    Object.keys(marker).length !== 5 ||
    marker.schemaVersion !== MaterializationMarkerSchemaVersion ||
    marker.generation !== generation ||
    !Number.isSafeInteger(marker.pid) || marker.pid < 1 ||
    !/^[1-9][0-9]*$/u.test(marker.procStartTicks ?? '') ||
    !/^[0-9a-f-]{36}$/u.test(marker.bootId ?? '')
  ) {
    fail('materialization-marker-invalid', 'The materialization marker does not have the exact expected shape.');
  }
  return Object.freeze(marker);
};

const markerIsLive = marker => {
  if (marker.bootId !== currentBootId()) return false;
  try {
    return currentProcessStartTicks(marker.pid) === marker.procStartTicks;
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError && cause.code === 'materialization-marker-unavailable') return false;
    throw cause;
  }
};

const assertOwnedMaterializationGeneration = record => {
  let generation;
  let marker;
  let runtime;
  let children;
  try {
    generation = lstatSync(record.generationPath, { bigint: true });
    marker = lstatSync(record.markerPath, { bigint: true });
    runtime = lstatSync(record.runtimePath, { bigint: true });
    children = readdirSync(record.generationPath).sort(compareSnapshotPaths);
  } catch (cause) {
    fail('materialization-cleanup-unavailable', 'The owned materialization generation could not be revalidated for cleanup.', cause);
  }
  if (
    !generation.isDirectory() || generation.isSymbolicLink() ||
    !matchesSerializedDescriptorIdentity(generation, record.generationIdentity) ||
    !marker.isFile() || marker.isSymbolicLink() || marker.nlink !== 1n ||
    !matchesSerializedDescriptorIdentity(marker, record.markerIdentity) ||
    !runtime.isDirectory() || runtime.isSymbolicLink() ||
    !matchesSerializedDescriptorIdentity(runtime, record.runtimeRootIdentity) ||
    children.length !== 2 || children[0] !== 'marker.json' || children[1] !== 'runtime'
  ) {
    fail('materialization-cleanup-ambiguous', 'The materialization generation changed and cannot be safely removed.');
  }
  const parsedMarker = parseMaterializationMarker({ path: record.markerPath, generation: record.generation });
  if (
    parsedMarker.pid !== record.marker.pid ||
    parsedMarker.procStartTicks !== record.marker.procStartTicks ||
    parsedMarker.bootId !== record.marker.bootId
  ) {
    fail('materialization-cleanup-ambiguous', 'The materialization marker changed and cannot be safely removed.');
  }
};

const removeVerifiedMaterializationGeneration = record => {
  assertOwnedMaterializationGeneration(record);
  try {
    rmSync(record.generationPath, { recursive: true, force: false, maxRetries: 0 });
  } catch (cause) {
    fail('materialization-cleanup-failed', 'The owned materialization generation could not be removed.', cause);
  }
  try {
    lstatSync(record.generationPath, { bigint: true });
  } catch (cause) {
    if (cause?.code === 'ENOENT') return;
    fail('materialization-cleanup-failed', 'The materialization generation cleanup could not be confirmed.', cause);
  }
  fail('materialization-cleanup-failed', 'The materialization generation remained after cleanup.');
};

const closeOwnedMaterializationDescriptor = ({ record, key, identity, label }) => {
  const fd = record[key];
  if (fd === undefined) return;
  let metadata;
  try {
    metadata = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('materialization-close-ambiguous', `The retained ${label} descriptor could not be revalidated before close.`, cause);
  }
  if (!matchesSerializedDescriptorIdentity(metadata, identity)) {
    fail('materialization-close-ambiguous', `The retained ${label} descriptor changed before close.`);
  }
  try {
    closeSync(fd);
  } catch (cause) {
    fail('materialization-close-failed', `The retained ${label} descriptor could not be closed.`, cause);
  }
  record[key] = undefined;
};

const ensureMaterializationParent = () => {
  try {
    mkdirSync(MaterializationParent, { mode: 0o700 });
  } catch (cause) {
    if (cause?.code !== 'EEXIST') fail('materialization-parent-create', 'The private materialization parent could not be created.', cause);
  }
  let parent;
  try {
    parent = lstatSync(MaterializationParent, { bigint: true });
  } catch (cause) {
    fail('materialization-parent-invalid', 'The private materialization parent is unavailable.', cause);
  }
  const ownUid = BigInt(process.getuid?.() ?? -1);
  if (
    !parent.isDirectory() || parent.isSymbolicLink() ||
    parent.uid !== ownUid || parent.gid !== BigInt(process.getgid?.() ?? -1) ||
    (parent.mode & 0o7777n) !== 0o700n
  ) {
    fail('materialization-parent-invalid', 'The private materialization parent has unsafe metadata.');
  }
  let entries;
  try {
    entries = readdirSync(MaterializationParent).sort(compareSnapshotPaths);
  } catch (cause) {
    fail('materialization-parent-invalid', 'The private materialization parent could not be enumerated.', cause);
  }
  for (const entry of entries) {
    if (!/^generation-[0-9a-f]{32}$/u.test(entry)) {
      fail('materialization-orphan-ambiguous', 'The private materialization parent contains an unknown entry.');
    }
    const generationPath = join(MaterializationParent, entry);
    const before = lstatSync(generationPath, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== ownUid || (before.mode & 0o7777n) !== 0o700n) {
      fail('materialization-orphan-ambiguous', 'A prior materialization generation has unsafe metadata.');
    }
    const markerPath = join(generationPath, 'marker.json');
    const runtimePath = join(generationPath, 'runtime');
    const marker = parseMaterializationMarker({ path: markerPath, generation: entry });
    const children = readdirSync(generationPath).sort(compareSnapshotPaths);
    if (children.length !== 2 || children[0] !== 'marker.json' || children[1] !== 'runtime') {
      fail('materialization-orphan-ambiguous', 'A prior materialization generation has an ambiguous layout.');
    }
    const pending = pendingMaterializationCleanup.get(generationPath);
    if (pending !== undefined) {
      removeVerifiedMaterializationGeneration(pending);
      pendingMaterializationCleanup.delete(generationPath);
      continue;
    }
    if (markerIsLive(marker)) continue;
    let markerStat;
    let runtimeStat;
    try {
      markerStat = lstatSync(markerPath, { bigint: true });
      runtimeStat = lstatSync(runtimePath, { bigint: true });
    } catch (cause) {
      fail('materialization-orphan-ambiguous', 'A stale materialization generation could not be revalidated.', cause);
    }
    if (!runtimeStat.isDirectory() || runtimeStat.isSymbolicLink()) {
      fail('materialization-orphan-ambiguous', 'A stale materialization generation has an invalid runtime root.');
    }
    removeVerifiedMaterializationGeneration({
      generation: entry,
      generationPath,
      generationIdentity: serializedDescriptorIdentity(before),
      markerPath,
      markerIdentity: serializedDescriptorIdentity(markerStat),
      runtimePath,
      runtimeRootIdentity: serializedDescriptorIdentity(runtimeStat),
      marker,
    });
  }
};

const createMaterializationGeneration = () => {
  ensureMaterializationParent();
  const generation = `generation-${randomBytes(16).toString('hex')}`;
  const generationPath = join(MaterializationParent, generation);
  try {
    mkdirSync(generationPath, { mode: 0o700 });
    chmodSync(generationPath, 0o700);
    const markerPath = join(generationPath, 'marker.json');
    const marker = currentMaterializationMarker(generation);
    writeFileSync(markerPath, JSON.stringify(marker), {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    const runtimePath = join(generationPath, 'runtime');
    mkdirSync(runtimePath, { mode: 0o700 });
    chmodSync(runtimePath, 0o700);
    const runtimeRootFd = openSync(runtimePath, DirectoryOpenFlags);
    return Object.freeze({
      generation,
      generationPath,
      runtimePath,
      runtimeRootFd,
      markerPath,
      marker,
      markerIdentity: serializedDescriptorIdentity(lstatSync(markerPath, { bigint: true })),
    });
  } catch (cause) {
    try { rmSync(generationPath, { recursive: true, force: true, maxRetries: 0 }); } catch {}
    fail('materialization-create', 'The private materialization generation could not be created.', cause);
  }
};

const duplicateReadonlyFd = fd => {
  try {
    return openSync(fdPath(fd), constants.O_RDONLY);
  } catch (cause) {
    fail('descriptor-duplicate', 'A sealed descriptor could not be retained for the materialized runtime.', cause);
  }
};

const parseMaterializationAttestation = ({ stdout, expectedIdentity }) => {
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout, 'utf8') > runtimeVerificationBounds.textBytes) {
    fail('materialization-attestation-invalid', 'The materialization child returned invalid output.');
  }
  let value;
  try {
    value = JSON.parse(stdout);
  } catch (cause) {
    fail('materialization-attestation-invalid', 'The materialization child returned malformed output.', cause);
  }
  if (
    value?.schemaVersion !== 'codebase-radar.analyzer-runtime-materialization/v1' ||
    value?.kind !== 'materialized' ||
    !matchesSerializedDescriptorIdentity({
      dev: BigInt(expectedIdentity.device),
      ino: BigInt(expectedIdentity.inode),
      mode: BigInt(expectedIdentity.mode),
      size: BigInt(expectedIdentity.size),
      nlink: BigInt(expectedIdentity.nlink),
    }, value.root)
  ) {
    fail('materialization-attestation-invalid', 'The materialization child did not attest the retained runtime root.');
  }
};

const OfflineOsvMountPlaceholderPath = requiredOfflineOsvDatabase.path;
const materializedRuntimeRequiredPaths = (() => {
  const paths = new Set([
    'runtime-manifest.json',
    requiredSemanticRunnerPath,
    requiredRuntimeNode.path,
    OfflineOsvMountPlaceholderPath,
  ]);
  let current = '';
  for (const part of OfflineOsvMountPlaceholderPath.split('/').slice(0, -1)) {
    current = current === '' ? part : `${current}/${part}`;
    paths.add(current);
  }
  return Object.freeze(paths);
})();

/**
 * The reconstruction child only consumes sealed archive bytes, but its output
 * is still a host filesystem tree.  Re-walk it through the retained root
 * descriptor before it becomes a cross-process capability.  This validates
 * the exact bounded topology (including the empty OSV bind target), modes and
 * aggregate byte accounting without reopening the mutable target runtime.
 */
const validateMaterializedRuntimeTree = ({ runtimeRootFd, runtimeRootIdentity, sealed }) => {
  let root;
  try {
    root = openSync(fdPath(runtimeRootFd), DirectoryOpenFlags);
  } catch (cause) {
    fail('materialization-tree-unavailable', 'The materialized runtime root could not be duplicated for validation.', cause);
  }
  const budget = makeBudget({ maximumEntries: runtimeVerificationBounds.entries + 1 });
  const seen = new Set();
  const stack = [{ fd: root, path: '', depth: 0 }];
  try {
    const rootStat = checkedDirectoryStat(root, 'materialized runtime root');
    if (
      !sameIdentity(rootStat, {
        device: BigInt(runtimeRootIdentity.device),
        inode: BigInt(runtimeRootIdentity.inode),
        mode: BigInt(runtimeRootIdentity.mode),
        size: BigInt(runtimeRootIdentity.size),
        nlink: BigInt(runtimeRootIdentity.nlink),
      }) ||
      (rootStat.mode & 0o7777n) !== 0o555n
    ) {
      fail('materialization-tree-invalid', 'The materialized runtime root changed before validation.');
    }

    while (stack.length > 0) {
      assertDeadline(budget.deadline);
      const frame = stack.pop();
      try {
        const names = directoryEntries(frame.fd, frame.path === '' ? 'materialized runtime root' : frame.path, budget);
        for (const name of names) {
          assertDeadline(budget.deadline);
          const path = frame.path === '' ? name : `${frame.path}/${name}`;
          const metadata = lstatFrom(frame.fd, name, `materialized ${path}`);
          reserveEntry(budget, `materialized ${path}`);
          if (seen.has(path)) {
            fail('materialization-tree-invalid', 'The materialized runtime contains a duplicate path.');
          }
          seen.add(path);

          if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
            if (frame.depth + 1 > runtimeVerificationBounds.directoryDepth) {
              fail('materialization-tree-depth', 'The materialized runtime exceeds its bounded directory depth.');
            }
            let child;
            try {
              child = openDirectoryFrom(frame.fd, name, `materialized ${path}`);
              const childIdentity = checkedDirectoryStat(child, `materialized ${path}`);
              const observedIdentity = statIdentity(metadata);
              if (
                !sameIdentity(childIdentity, observedIdentity) ||
                (childIdentity.mode & 0o7777n) !== 0o555n
              ) {
                fail('materialization-tree-invalid', 'A materialized runtime directory changed or has an unsafe mode.');
              }
              stack.push({ fd: child, path, depth: frame.depth + 1 });
              child = undefined;
            } finally {
              closeQuietly(child);
            }
            continue;
          }

          if (metadata.isFile() && !metadata.isSymbolicLink()) {
            const observedIdentity = statIdentity(metadata);
            if (
              observedIdentity.nlink !== 1n ||
              (observedIdentity.mode & 0o7000n) !== 0n ||
              ![0o444n, 0o555n].includes(observedIdentity.mode & 0o7777n)
            ) {
              fail('materialization-tree-invalid', 'A materialized runtime file has unsafe metadata.');
            }
            const maximum = path === OfflineOsvMountPlaceholderPath
              ? 0
              : runtimeVerificationBounds.runtimeArtifactBytes;
            const size = reserveBytes(budget, observedIdentity.size, maximum, `materialized ${path}`);
            let child;
            try {
              child = openSync(`${fdPath(frame.fd)}/${name}`, RegularReadFlags);
              const retainedIdentity = checkedRegularStat(child, `materialized ${path}`, maximum);
              if (!sameIdentity(observedIdentity, retainedIdentity)) {
                fail('materialization-tree-invalid', 'A materialized runtime file changed during validation.');
              }
            } catch (cause) {
              if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
              fail('materialization-tree-unavailable', 'A materialized runtime file could not be retained for validation.', cause);
            } finally {
              closeQuietly(child);
            }
            if (
              path === OfflineOsvMountPlaceholderPath &&
              (size !== 0 || (observedIdentity.mode & 0o7777n) !== 0o444n)
            ) {
              fail('materialization-osv-placeholder-invalid', 'The materialized runtime has no valid empty offline OSV mount target.');
            }
            continue;
          }

          if (metadata.isSymbolicLink()) {
            if (metadata.size < 1n || metadata.size > 4_096n) {
              fail('materialization-tree-invalid', 'A materialized runtime link has invalid metadata.');
            }
            continue;
          }

          fail('materialization-tree-invalid', 'The materialized runtime contains an unsupported filesystem entry.');
        }
      } finally {
        closeQuietly(frame.fd);
      }
    }

    const expectedEntries = sealed.runtimeEntries + 1;
    const expectedBytes = BigInt(sealed.runtimeBytes) - BigInt(sealed.osvDatabaseBytes);
    if (
      !Number.isSafeInteger(expectedEntries) ||
      expectedEntries < 1 ||
      expectedEntries > runtimeVerificationBounds.entries + 1 ||
      expectedBytes < 0n ||
      budget.entries !== expectedEntries ||
      budget.sourceBytes !== expectedBytes ||
      [...materializedRuntimeRequiredPaths].some(path => !seen.has(path))
    ) {
      fail('materialization-tree-invalid', 'The materialized runtime tree does not exactly match the sealed archive closure.');
    }
    return Object.freeze({ entries: budget.entries, bytes: Number(budget.sourceBytes) });
  } finally {
    for (const frame of stack) closeQuietly(frame.fd);
  }
};

/** Materializes a branded sealed generation once for a production-layer lifetime. */
export const materializeSealedAnalyzerRuntime = sealedRuntime => {
  if (process.platform !== 'linux') {
    fail('unsupported-platform', 'Materialized analyzer runtimes require Linux.');
  }
  const sealed = inspectSealedAnalyzerRuntime(sealedRuntime);
  assertOfflineOsvDatabaseFresh(sealed.osvDatabaseMetadata);
  const generation = createMaterializationGeneration();
  let osvDatabaseFd;
  let launcherFd;
  let addonFd;
  let runtimeRootFd = generation.runtimeRootFd;
  try {
    const result = spawnSync(
      fdPath(sealed.nodeFd),
      [
        fdPath(6),
        '--snapshot-fd', '3',
        '--runtime-fd', '4',
        '--materialize',
      ],
      {
        cwd: '/',
        env: { HOME: '/nonexistent', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', NO_COLOR: '1', PATH: '/usr/bin:/bin' },
        shell: false,
        encoding: 'utf8',
        maxBuffer: runtimeVerificationBounds.textBytes,
        // FD 6 is the standalone materializer program.  Node resolves it
        // before entering JS; the loader then proves that it closes FD 6 and
        // the addon FD 5 before extracting untrusted package bytes.
        stdio: ['ignore', 'pipe', 'pipe', sealed.snapshotFd, runtimeRootFd, sealed.addonFd, sealed.loaderFd],
        windowsHide: true,
      },
    );
    if (result.error !== undefined || result.status !== 0 || result.signal !== null) {
      fail('materialization-child-failed', 'The trusted materialization child did not complete.');
    }
    const rootStat = fstatSync(runtimeRootFd, { bigint: true });
    const runtimeRootIdentity = serializedDescriptorIdentity(rootStat);
    parseMaterializationAttestation({ stdout: result.stdout, expectedIdentity: runtimeRootIdentity });
    if (!rootStat.isDirectory() || (rootStat.mode & 0o7777n) !== 0o555n) {
      fail('materialization-root-invalid', 'The materialized runtime root is not read-only.');
    }
    const materializedTree = validateMaterializedRuntimeTree({
      runtimeRootFd,
      runtimeRootIdentity,
      sealed,
    });
    osvDatabaseFd = duplicateReadonlyFd(sealed.osvDatabaseFd);
    launcherFd = duplicateReadonlyFd(sealed.launcherFd);
    addonFd = duplicateReadonlyFd(sealed.addonFd);
    const addonProof = assertTrustedRuntimeControlFd({
      fd: addonFd,
      byteLength: sealed.addonBytes,
      sha256: sealed.addonSha256,
      identity: sealed.addonIdentity,
    });
    const launcherProof = assertTrustedRuntimeControlFd({
      fd: launcherFd,
      byteLength: sealed.launcherBytes,
      sha256: sealed.launcherSha256,
      identity: sealed.launcherIdentity,
    });
    const osvProof = assertSealedOfflineOsvDatabaseFd({
      osvDatabaseFd,
      osvDatabaseSha256: sealed.osvDatabaseSha256,
      osvDatabaseBytes: sealed.osvDatabaseBytes,
      osvDatabaseGeneration: sealed.osvDatabaseGeneration,
      osvDatabaseIdentity: sealed.osvDatabaseIdentity,
      addonFd: addonProof.fd,
      addonBytes: addonProof.byteLength,
      addonSha256: addonProof.sha256,
      addonIdentity: addonProof.identity,
      verifyContent: false,
    });
    const record = {
      runtimeRootFd,
      runtimeRootIdentity,
      generationPath: generation.generationPath,
      generationIdentity: serializedDescriptorIdentity(lstatSync(generation.generationPath, { bigint: true })),
      runtimePath: generation.runtimePath,
      markerPath: generation.markerPath,
      marker: generation.marker,
      markerIdentity: generation.markerIdentity,
      manifestSha256: sealed.manifestSha256,
      runnerSha256: sealed.runnerSha256,
      nodeSha256: sealed.nodeSha256,
      osvDatabaseFd: osvProof.fd,
      osvDatabaseSha256: sealed.osvDatabaseSha256,
      osvDatabaseBytes: sealed.osvDatabaseBytes,
      osvDatabaseGeneration: sealed.osvDatabaseGeneration,
      osvDatabaseIdentity: osvProof.identity,
      osvDatabaseMetadata: sealed.osvDatabaseMetadata,
      launcherFd: launcherProof.fd,
      launcherBytes: launcherProof.byteLength,
      launcherSha256: launcherProof.sha256,
      launcherIdentity: launcherProof.identity,
      addonFd: addonProof.fd,
      addonBytes: addonProof.byteLength,
      addonSha256: addonProof.sha256,
      addonIdentity: addonProof.identity,
      controlArtifacts: sealed.controlArtifacts,
      runtimeEntries: materializedTree.entries,
      runtimeBytes: materializedTree.bytes,
      closed: false,
      closing: false,
    };
    const close = () => {
      if (record.closed) return;
      record.closing = true;
      try {
        closeOwnedMaterializationDescriptor({
          record,
          key: 'runtimeRootFd',
          identity: record.runtimeRootIdentity,
          label: 'runtime root',
        });
        closeOwnedMaterializationDescriptor({
          record,
          key: 'osvDatabaseFd',
          identity: record.osvDatabaseIdentity,
          label: 'offline OSV database',
        });
        closeOwnedMaterializationDescriptor({
          record,
          key: 'launcherFd',
          identity: record.launcherIdentity,
          label: 'resource governance launcher',
        });
        closeOwnedMaterializationDescriptor({
          record,
          key: 'addonFd',
          identity: record.addonIdentity,
          label: 'memfd bridge',
        });
        removeVerifiedMaterializationGeneration(record);
        pendingMaterializationCleanup.delete(record.generationPath);
        record.closed = true;
        record.closing = false;
      } catch (cause) {
        // Preserve the fully identity-bound cleanup record for an explicit
        // retry or the next same-process acquisition.  The capability is no
        // longer inspectable while closing, so callers cannot launch with a
        // partly torn-down tree.
        pendingMaterializationCleanup.set(record.generationPath, record);
        if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
        fail('materialization-cleanup-failed', 'The materialized runtime could not be closed cleanly.', cause);
      }
    };
    const handle = Object.freeze({
      schemaVersion: MaterializedSchemaVersion,
      manifestSha256: record.manifestSha256,
      runnerSha256: record.runnerSha256,
      nodeSha256: record.nodeSha256,
      osvDatabaseSha256: record.osvDatabaseSha256,
      osvDatabaseRelativePath: requiredOfflineOsvDatabase.path,
      osvDatabaseBytes: record.osvDatabaseBytes,
      osvDatabaseGeneration: record.osvDatabaseGeneration,
      runtimeRootIdentity,
      close,
    });
    materializedRuntimeHandles.set(handle, record);
    runtimeRootFd = undefined;
    osvDatabaseFd = undefined;
    launcherFd = undefined;
    addonFd = undefined;
    return handle;
  } catch (cause) {
    closeQuietly(runtimeRootFd);
    closeQuietly(osvDatabaseFd);
    closeQuietly(launcherFd);
    closeQuietly(addonFd);
    try { rmSync(generation.generationPath, { recursive: true, force: true, maxRetries: 0 }); } catch {}
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('materialization-failed', 'The sealed analyzer runtime could not be materialized.', cause);
  }
};

export const assertMaterializedAnalyzerRuntimeRootFd = ({
  runtimeRootFd,
  runtimeRootIdentity,
  manifestSha256,
  runnerSha256,
  nodeSha256,
}) => {
  if (
    manifestSha256 !== runtimeTrustAnchor.manifestSha256 ||
    runnerSha256 !== runtimeTrustAnchor.runnerSha256 ||
    nodeSha256 !== requiredRuntimeNode.sha256 ||
    !Number.isSafeInteger(runtimeRootFd) || runtimeRootFd < 0
  ) {
    fail('materialized-root-invalid', 'The materialized runtime root identity is invalid.');
  }
  try {
    return assertMaterializedRuntimeRootDescriptor({
      runtimeRootFd,
      runtimeRootIdentity,
      label: 'materialized analyzer runtime root',
    });
  } catch (cause) {
    if (cause instanceof AnalyzerRuntimeSnapshotError) throw cause;
    fail('materialized-root-invalid', 'The materialized runtime root does not match its retained identity.', cause);
  }
};

export const inspectMaterializedAnalyzerRuntime = handle => {
  const record = materializedRuntimeHandles.get(handle);
  if (record === undefined || record.closed || record.closing) {
    fail('materialized-handle-invalid', 'A live materialized analyzer runtime handle is required.');
  }
  // This capability can outlive the initial sealing/materialization pass for
  // many scans. Recheck its fixed OSV generation on every handoff so it
  // becomes unavailable at the seven-day boundary without repacking bytes.
  assertOfflineOsvDatabaseFresh(record.osvDatabaseMetadata);
  const root = assertMaterializedAnalyzerRuntimeRootFd(record);
  const database = assertSealedOfflineOsvDatabaseFd({
    ...record,
    addonFd: record.addonFd,
    addonBytes: record.addonBytes,
    addonSha256: record.addonSha256,
    addonIdentity: record.addonIdentity,
    verifyContent: false,
  });
  const launcher = assertTrustedRuntimeControlFd({
    fd: record.launcherFd,
    byteLength: record.launcherBytes,
    sha256: record.launcherSha256,
    identity: record.launcherIdentity,
  });
  const addon = assertTrustedRuntimeControlFd({
    fd: record.addonFd,
    byteLength: record.addonBytes,
    sha256: record.addonSha256,
    identity: record.addonIdentity,
  });
  return Object.freeze({
    schemaVersion: MaterializedSchemaVersion,
    runtimeRootFd: root.runtimeRootFd,
    runtimeRootIdentity: root.runtimeRootIdentity,
    runnerPath: '/runtime/bin/radar-semantic-analyzer.mjs',
    nodePath: '/runtime/bin/node',
    manifestSha256: record.manifestSha256,
    runnerSha256: record.runnerSha256,
    nodeSha256: record.nodeSha256,
    osvDatabaseFd: database.fd,
    osvDatabaseIdentity: database.identity,
    osvDatabaseSha256: record.osvDatabaseSha256,
    osvDatabaseRelativePath: requiredOfflineOsvDatabase.path,
    osvDatabaseBytes: record.osvDatabaseBytes,
    osvDatabaseGeneration: record.osvDatabaseGeneration,
    launcherFd: launcher.fd,
    launcherBytes: launcher.byteLength,
    launcherSha256: launcher.sha256,
    launcherIdentity: launcher.identity,
    addonFd: addon.fd,
    addonBytes: addon.byteLength,
    addonSha256: addon.sha256,
    addonIdentity: addon.identity,
    controlArtifacts: record.controlArtifacts,
  });
};
