import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  opendirSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { dirname, isAbsolute, join, sep } from 'node:path';
import { runtimeVerificationBounds } from './runtime-manifest.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

/**
 * The control directory is intentionally authenticated in a dependency leaf.
 * Both sealing and resource governance consume its retained descriptors, while
 * the public verifier can import the leaf without introducing a cycle.
 */
export const analyzerControlSchemaVersion = 'codebase-radar.analyzer-control/v1';

const controlArtifacts = Object.freeze([
  Object.freeze({ path: 'runtime-snapshot-loader.mjs', mode: '0444', maximumBytes: runtimeVerificationBounds.textBytes }),
  Object.freeze({ path: 'resource-governance-launcher.mjs', mode: '0444', maximumBytes: runtimeVerificationBounds.textBytes }),
  Object.freeze({ path: 'runtime-memfd-addon.node', mode: '0555', maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes }),
]);

const directoryOpenFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const regularOpenFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const capabilityRecords = new WeakMap();

export class AnalyzerControlVerificationError extends Error {
  constructor(code, message, cause) {
    super(`[analyzer-control:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'AnalyzerControlVerificationError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new AnalyzerControlVerificationError(code, message, cause);
};

// Modern bundles this module into the application entrypoint.  In that form
// import.meta.url describes the build-machine source module rather than a
// deployed file, so it must never define a production trust boundary.  The
// independently protected bootstrap always invokes an absolute entrypoint;
// locate its regular package root without consulting cwd or target bytes.
const trustedApplicationRoot = () => {
  const entrypoint = process.argv[1];
  if (entrypoint === undefined || !isAbsolute(entrypoint)) {
    fail('trusted-entrypoint-invalid', 'The trusted application entrypoint must be an absolute path.');
  }
  let entrypointDirectory;
  try {
    entrypointDirectory = dirname(realpathSync(entrypoint));
  } catch (cause) {
    fail('trusted-entrypoint-invalid', 'The trusted application entrypoint could not be resolved.', cause);
  }
  let candidate = entrypointDirectory;
  for (let depth = 0; depth <= 8; depth += 1) {
    try {
      const metadata = lstatSync(join(candidate, 'package.json'), { bigint: true });
      if (metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1n) {
        return realpathSync(candidate);
      }
    } catch {
      // The next bounded candidate may be the package root.
    }
    const parent = dirname(candidate);
    if (parent === candidate) break;
    candidate = parent;
  }
  fail('trusted-entrypoint-invalid', 'The trusted application package root could not be resolved.');
};

const closeQuietly = descriptor => {
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) return;
  try {
    closeSync(descriptor);
  } catch {
    // A cleanup failure must not turn a failed authentication into success.
  }
};

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);

const requireExactKeys = (value, keys, label) => {
  if (!isRecord(value)) fail('analyzer-control-anchor-invalid', `${label} must be an object.`);
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length ||
    actual.some(key => !keys.includes(key)) ||
    keys.some(key => !Object.hasOwn(value, key))
  ) {
    fail('analyzer-control-anchor-invalid', `${label} must have exactly the reviewed fields.`);
  }
  return value;
};

const isWithin = (root, candidate) => {
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  return candidate === root || candidate.startsWith(prefix);
};

const pathsOverlap = (left, right) => isWithin(left, right) || isWithin(right, left);

const assertAbsoluteCleanPath = (path, label) => {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path !== path.trim() ||
    !isAbsolute(path) ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(path)
  ) {
    fail('analyzer-control-root-invalid', `${label} must be an absolute, trimmed path without control characters.`);
  }
};

const timestamp = (metadata, field, code = 'analyzer-control-file-invalid') => {
  const value = metadata[`${field}Ns`];
  if (typeof value !== 'bigint') {
    fail(code, `Trusted analyzer-control ${field} metadata is unavailable.`);
  }
  return value;
};

const sameSnapshot = (left, right, code) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  left.uid === right.uid &&
  left.gid === right.gid &&
  timestamp(left, 'mtime', code) === timestamp(right, 'mtime', code) &&
  timestamp(left, 'ctime', code) === timestamp(right, 'ctime', code);

const serializedIdentity = metadata => Object.freeze({
  device: metadata.dev.toString(10),
  inode: metadata.ino.toString(10),
  // Descriptor identities use the same canonical decimal full st_mode as
  // sealed/materialized runtime transport. The reviewed permission policy is
  // carried separately by the artifact's `mode` field.
  mode: metadata.mode.toString(10),
  size: metadata.size.toString(10),
  nlink: metadata.nlink.toString(10),
});

const matchesIdentity = (metadata, identity) => {
  if (!isRecord(identity)) return false;
  const actual = serializedIdentity(metadata);
  return (
    identity.device === actual.device &&
    identity.inode === actual.inode &&
    identity.mode === actual.mode &&
    identity.size === actual.size &&
    identity.nlink === actual.nlink
  );
};

const assertRootMetadata = (metadata, label) => {
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== 0n ||
    metadata.gid !== 0n ||
    (metadata.mode & 0o7777n) !== 0o555n
  ) {
    fail('analyzer-control-root-invalid', `${label} must be a root:root canonical mode-0555 directory.`);
  }
};

const assertArtifactMetadata = ({ metadata, artifact, anchor, label }) => {
  const expectedMode = BigInt(`0o${artifact.mode}`);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== 0n ||
    metadata.gid !== 0n ||
    metadata.nlink !== 1n ||
    (metadata.mode & 0o7777n) !== expectedMode
  ) {
    fail('analyzer-control-file-invalid', `${label} must be a root:root independently linked regular file with mode ${artifact.mode}.`);
  }
  if (
    metadata.size < 1n ||
    metadata.size > BigInt(artifact.maximumBytes) ||
    metadata.size !== BigInt(anchor.byteLength)
  ) {
    fail('analyzer-control-file-oversize', `${label} does not match its bounded anchored byte length.`);
  }
};

const createBudget = () => ({
  deadline: process.hrtime.bigint() + BigInt(runtimeVerificationBounds.deadlineMs) * 1_000_000n,
  bytes: 0n,
});

const reserveBytes = (budget, bytes, label) => {
  if (process.hrtime.bigint() > budget.deadline) {
    fail('analyzer-control-time-limit', `Trusted ${label} verification exceeded its deadline.`);
  }
  const next = budget.bytes + bytes;
  if (next > BigInt(runtimeVerificationBounds.aggregateBytes)) {
    fail('analyzer-control-byte-limit', `Trusted ${label} verification exceeded its aggregate byte limit.`);
  }
  // The budget is deliberately private to a complete control-root pass.
  budget.bytes = next;
};

const hashDescriptor = ({ descriptor, metadata, label, budget }) => {
  const byteLength = Number(metadata.size);
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
  let position = 0;
  while (position < byteLength) {
    if (process.hrtime.bigint() > budget.deadline) {
      fail('analyzer-control-time-limit', `Trusted ${label} verification exceeded its deadline.`);
    }
    const bytesRead = readSync(
      descriptor,
      buffer,
      0,
      Math.min(buffer.byteLength, byteLength - position),
      position,
    );
    if (bytesRead <= 0) {
      fail('analyzer-control-file-changed', `${label} became shorter while it was hashed.`);
    }
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  const extra = Buffer.allocUnsafe(1);
  if (readSync(descriptor, extra, 0, 1, byteLength) !== 0) {
    fail('analyzer-control-file-changed', `${label} grew while it was hashed.`);
  }
  return hash.digest('hex');
};

const parsedAnchor = () => {
  const anchor = requireExactKeys(
    runtimeTrustAnchor.analyzerControl,
    ['schemaVersion', 'root', 'files'],
    'runtimeTrustAnchor.analyzerControl',
  );
  const root = requireExactKeys(anchor.root, ['uid', 'gid', 'mode'], 'runtimeTrustAnchor.analyzerControl.root');
  if (anchor.schemaVersion !== analyzerControlSchemaVersion || root.uid !== 0 || root.gid !== 0 || root.mode !== '0555') {
    fail('analyzer-control-anchor-invalid', 'The compiled analyzer-control root anchor is invalid.');
  }
  if (!Array.isArray(anchor.files) || anchor.files.length !== controlArtifacts.length) {
    fail('analyzer-control-anchor-invalid', 'The compiled analyzer-control file inventory is invalid.');
  }
  const files = anchor.files.map((value, index) => {
    const artifact = controlArtifacts[index];
    const file = requireExactKeys(
      value,
      ['path', 'byteLength', 'sha256', 'mode'],
      `runtimeTrustAnchor.analyzerControl.files[${index}]`,
    );
    if (
      file.path !== artifact.path ||
      file.mode !== artifact.mode ||
      !Number.isSafeInteger(file.byteLength) ||
      file.byteLength < 1 ||
      file.byteLength > artifact.maximumBytes ||
      typeof file.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(file.sha256)
    ) {
      fail('analyzer-control-anchor-invalid', 'The compiled analyzer-control file inventory is invalid.');
    }
    return Object.freeze({
      ...artifact,
      byteLength: file.byteLength,
      sha256: file.sha256,
    });
  });
  return Object.freeze({ root: Object.freeze({ uid: 0, gid: 0, mode: '0555' }), files: Object.freeze(files) });
};

const canonicalDirectory = ({ path, label, rootCode }) => {
  assertAbsoluteCleanPath(path, label);
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (cause) {
    fail(rootCode, `${label} is unavailable.`, cause);
  }
  assertRootMetadata(metadata, label);
  let canonical;
  try {
    canonical = realpathSync(path);
  } catch (cause) {
    fail(rootCode, `${label} could not be canonicalized.`, cause);
  }
  if (canonical !== path) {
    fail(rootCode, `${label} must already be its canonical path.`);
  }
  return Object.freeze({ path: canonical, metadata });
};

const canonicalTargetDirectory = path => {
  assertAbsoluteCleanPath(path, 'Analyzer runtime root');
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (cause) {
    fail('analyzer-control-runtime-root-invalid', 'Analyzer runtime root is unavailable.', cause);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('analyzer-control-runtime-root-invalid', 'Analyzer runtime root must be a non-symlink directory.');
  }
  let canonical;
  try {
    canonical = realpathSync(path);
  } catch (cause) {
    fail('analyzer-control-runtime-root-invalid', 'Analyzer runtime root could not be canonicalized.', cause);
  }
  if (canonical !== path) {
    fail('analyzer-control-runtime-root-invalid', 'Analyzer runtime root must already be its canonical path.');
  }
  return canonical;
};

const inspectDirectoryNames = ({ rootPath, descriptor }) => {
  let directory;
  const names = [];
  try {
    const path = process.platform === 'linux' ? `/proc/self/fd/${descriptor}` : rootPath;
    directory = opendirSync(path, { encoding: 'utf8', bufferSize: controlArtifacts.length + 1 });
    for (;;) {
      const entry = directory.readSync();
      if (entry === null) break;
      names.push(entry.name);
      if (names.length > controlArtifacts.length) {
        fail('analyzer-control-inventory-invalid', 'The trusted analyzer-control root has extra entries.');
      }
    }
  } catch (cause) {
    if (cause instanceof AnalyzerControlVerificationError) throw cause;
    fail('analyzer-control-root-unavailable', 'The trusted analyzer-control root could not be enumerated.', cause);
  } finally {
    try {
      directory?.closeSync();
    } catch {
      // Enumeration already completed or failed; no untrusted recovery path.
    }
  }
  const expected = controlArtifacts.map(artifact => artifact.path).sort();
  names.sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    fail('analyzer-control-inventory-invalid', 'The trusted analyzer-control root does not have the exact reviewed inventory.');
  }
};

const artifactPath = ({ rootPath, rootDescriptor, path }) =>
  process.platform === 'linux'
    ? `/proc/self/fd/${rootDescriptor}/${path}`
    : join(rootPath, path);

const retainArtifact = ({ rootPath, rootDescriptor, artifact, budget }) => {
  const path = artifactPath({ rootPath, rootDescriptor, path: artifact.path });
  const label = `analyzer-control artifact ${artifact.path}`;
  let before;
  try {
    before = lstatSync(path, { bigint: true });
  } catch (cause) {
    fail('analyzer-control-file-missing', `${label} is unavailable.`, cause);
  }
  assertArtifactMetadata({ metadata: before, artifact, anchor: artifact, label });
  let descriptor;
  try {
    descriptor = openSync(path, regularOpenFlags);
  } catch (cause) {
    fail('analyzer-control-file-invalid', `${label} could not be opened without following links.`, cause);
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    assertArtifactMetadata({ metadata: opened, artifact, anchor: artifact, label });
    if (!sameSnapshot(before, opened, 'analyzer-control-file-changed')) {
      fail('analyzer-control-file-changed', `${label} changed while it was opened.`);
    }
    reserveBytes(budget, opened.size, label);
    const sha256 = hashDescriptor({ descriptor, metadata: opened, label, budget });
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameSnapshot(opened, after, 'analyzer-control-file-changed')) {
      fail('analyzer-control-file-changed', `${label} changed while it was hashed.`);
    }
    if (sha256 !== artifact.sha256) {
      fail('analyzer-control-file-mismatch', `${label} does not match its compiled SHA-256.`);
    }
    const retained = Object.freeze({
      path: artifact.path,
      fd: descriptor,
      byteLength: artifact.byteLength,
      sha256,
      mode: artifact.mode,
      identity: serializedIdentity(after),
    });
    descriptor = undefined;
    return retained;
  } finally {
    closeQuietly(descriptor);
  }
};

/**
 * Verifies the root-owned, exact analyzer-control installation and returns an
 * opaque live capability. Only this module's WeakMap can reveal its retained
 * descriptors; copying the returned object's visible shape conveys no power.
 */
export const verifyAnalyzerControl = ({ controlRoot, runtimeRoot } = {}) => {
  const anchor = parsedAnchor();
  const control = canonicalDirectory({
    path: controlRoot,
    label: 'Analyzer control root',
    rootCode: 'analyzer-control-root-invalid',
  });
  if (pathsOverlap(control.path, trustedApplicationRoot())) {
    fail('analyzer-control-overlap', 'Analyzer control root must not overlap the trusted verifier module tree.');
  }
  if (runtimeRoot !== undefined) {
    const runtime = canonicalTargetDirectory(runtimeRoot);
    if (pathsOverlap(control.path, runtime)) {
      fail('analyzer-control-overlap', 'Analyzer control root must not overlap the target runtime root.');
    }
  }

  let rootDescriptor;
  const retained = [];
  try {
    rootDescriptor = openSync(control.path, directoryOpenFlags);
    const openedRoot = fstatSync(rootDescriptor, { bigint: true });
    assertRootMetadata(openedRoot, 'Analyzer control root');
    if (!sameSnapshot(control.metadata, openedRoot, 'analyzer-control-root-changed')) {
      fail('analyzer-control-root-changed', 'Analyzer control root changed while it was opened.');
    }
    inspectDirectoryNames({ rootPath: control.path, descriptor: rootDescriptor });
    const budget = createBudget();
    for (const artifact of anchor.files) {
      retained.push(retainArtifact({
        rootPath: control.path,
        rootDescriptor,
        artifact,
        budget,
      }));
    }
    const finalRoot = fstatSync(rootDescriptor, { bigint: true });
    if (!sameSnapshot(openedRoot, finalRoot, 'analyzer-control-root-changed')) {
      fail('analyzer-control-root-changed', 'Analyzer control root changed during verification.');
    }
    let closed = false;
    const record = {
      schemaVersion: analyzerControlSchemaVersion,
      controlRoot: control.path,
      files: Object.freeze(retained),
      closed: false,
    };
    const close = () => {
      if (closed) return;
      closed = true;
      record.closed = true;
      for (const file of record.files) closeQuietly(file.fd);
    };
    const capability = Object.freeze({ close });
    capabilityRecords.set(capability, record);
    return capability;
  } catch (cause) {
    for (const file of retained) closeQuietly(file.fd);
    if (cause instanceof AnalyzerControlVerificationError) throw cause;
    fail('analyzer-control-root-unavailable', 'The trusted analyzer-control root could not be retained.', cause);
  } finally {
    closeQuietly(rootDescriptor);
  }
};

/**
 * Trusted sibling modules use this immediately before descriptor transport.
 * It rejects structural lookalikes and re-checks every retained descriptor.
 */
export const inspectAnalyzerControl = capability => {
  const record = capabilityRecords.get(capability);
  if (record === undefined || record.closed) {
    fail('analyzer-control-capability-invalid', 'A live verified analyzer-control capability is required.');
  }
  const files = record.files.map(file => {
    const proof = assertAnalyzerControlArtifactFd({
      fd: file.fd,
      byteLength: file.byteLength,
      sha256: file.sha256,
      mode: file.mode,
      identity: file.identity,
    });
    // The role/path comes only from the verifier-retained record. It is never
    // accepted from a capability caller or reconstructed from a mutable path.
    return Object.freeze({ path: file.path, ...proof });
  });
  return Object.freeze({
    schemaVersion: record.schemaVersion,
    controlRoot: record.controlRoot,
    files: Object.freeze(files),
    close: capability.close,
  });
};

/** Re-proves one inherited or retained analyzer-control artifact descriptor. */
export const assertAnalyzerControlArtifactFd = ({ fd, byteLength, sha256, mode, identity } = {}) => {
  const artifact = controlArtifacts.find(candidate => candidate.mode === mode);
  if (
    !Number.isSafeInteger(fd) ||
    fd < 0 ||
    !Number.isSafeInteger(byteLength) ||
    byteLength < 1 ||
    artifact === undefined ||
    byteLength > artifact.maximumBytes ||
    typeof sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(sha256) ||
    !isRecord(identity)
  ) {
    fail('analyzer-control-capability-invalid', 'A bounded verified analyzer-control descriptor is required.');
  }
  let before;
  try {
    before = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('analyzer-control-capability-invalid', 'The analyzer-control descriptor is unavailable.', cause);
  }
  assertArtifactMetadata({
    metadata: before,
    artifact,
    anchor: { byteLength },
    label: 'retained analyzer-control artifact',
  });
  if (!matchesIdentity(before, identity)) {
    fail('analyzer-control-capability-invalid', 'The analyzer-control descriptor no longer matches its retained identity.');
  }
  const budget = createBudget();
  reserveBytes(budget, before.size, 'retained analyzer-control artifact');
  const actualSha256 = hashDescriptor({
    descriptor: fd,
    metadata: before,
    label: 'retained analyzer-control artifact',
    budget,
  });
  const after = fstatSync(fd, { bigint: true });
  if (!sameSnapshot(before, after, 'analyzer-control-capability-invalid') || actualSha256 !== sha256) {
    fail('analyzer-control-capability-invalid', 'The analyzer-control descriptor no longer matches its retained content.');
  }
  return Object.freeze({
    fd,
    byteLength,
    sha256,
    mode,
    identity: serializedIdentity(after),
  });
};
