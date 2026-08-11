import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  opendirSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';

export const runtimeManifestSchemaVersion =
  'codebase-radar.analyzer-runtime/v1';
export const dogfoodMaxProfile = 'dogfood:max/v1';
export const requiredHostIsolation = Object.freeze({
  kind: 'bubblewrap',
  path: '/usr/bin/bwrap',
  required: true,
  packageVersion: '0.9.0-1ubuntu0.1',
  versionOutput: 'bubblewrap 0.9.0',
});
export const requiredSemanticRunnerPath = 'bin/radar-semantic-analyzer.mjs';
export const requiredPnpmIntegrityEvidencePath = 'pnpm-integrity-evidence.json';
// The analyzer never executes the host Node binary. This record pins the
// extracted executable, not merely its upstream tarball provenance.
export const requiredRuntimeNode = Object.freeze({
  path: 'bin/node',
  versionOutput: 'v24.18.1',
  sha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
  archive: Object.freeze({
    url: 'https://nodejs.org/dist/v24.18.1/node-v24.18.1-linux-x64.tar.xz',
    sha256: 'd6c664df3f3f61458e8c277585571328522d705166723a7c7823a9253a4d15a0',
    member: 'node-v24.18.1-linux-x64/bin/node',
  }),
});
export const requiredManagedBinaryEntries = Object.freeze([
  'node',
  'osv-scanner',
  'radar-semantic-analyzer.mjs',
  'tracedecay',
  'zizmor',
]);
// OSV's v2.5.0 embedded osv-scalibr database format. The outer runtime
// snapshot stores this as one regular ZIP; it must never be unpacked by the
// trusted snapshot loader.
export const requiredOfflineOsvDatabase = Object.freeze({
  path: 'databases/osv/osv-scalibr/npm/all.zip',
  url: 'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=1786418349414076',
  generation: '1786418349414076',
  sha256: '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69',
  size: 218_758_368,
  entries: 226_504,
  uncompressedBytes: 371_036_838,
  signedDataDescriptorEntries: 226_504,
  dataDescriptorBytes: 3_624_064,
  publishedAt: '2026-08-11T03:19:09Z',
  maxAgeDays: 7,
});
export const requiredOsvNpmSnapshotValidator = Object.freeze({
  schemaVersion: 'codebase-radar.osv-npm-snapshot-validator/v1',
  path: 'osv-npm-snapshot-validator.mjs',
});
export const offlineOsvMaximumFutureClockSkewMs = 300_000;
export const requiredSandboxPaths = Object.freeze({
  workspace: '/workspace',
  scratch: '/scratch',
  request: '/run/radar/analyzer-request.json',
});
// Bubblewrap runs only the trusted reconstruction phase without a file-size
// rlimit. The loader applies this exact tuple immediately before executing
// the extracted analyzer Node, so large authenticated runtime files can be
// reconstructed while analyzer work remains constrained.
export const requiredAnalyzerPrlimitPath = '/usr/bin/prlimit';
export const requiredAnalyzerPrlimitArguments = Object.freeze([
  '--core=0:0',
  '--fsize=16777216:16777216',
  '--nofile=256:256',
  '--cpu=130:130',
  '--as=8589934592:8589934592',
]);
// Static authentication runs before the analyzer sandbox/cgroup exists. Keep
// every target-controlled read and directory walk inside these reviewable
// bounds, including source-package Merkle trees.
export const runtimeVerificationBounds = Object.freeze({
  manifestBytes: 4 * 1024 * 1024,
  textBytes: 4 * 1024 * 1024,
  packageFileBytes: 64 * 1024 * 1024,
  runtimeArtifactBytes: 256 * 1024 * 1024,
  aggregateBytes: 1024 * 1024 * 1024,
  entries: 100_000,
  packageTreeEntries: 16_384,
  packageTreeBytes: 128 * 1024 * 1024,
  directoryDepth: 64,
  deadlineMs: 30_000,
  chunkBytes: 64 * 1024,
  jsonArrayEntries: 4_096,
  jsonObjectProperties: 256,
  jsonStringBytes: 64 * 1024,
  jsonDepth: 64,
  jsonEntries: 16_384,
});
export const requiredBubblewrapProbeArguments = Object.freeze([
  '--die-with-parent',
  '--new-session',
  '--unshare-user',
  '--unshare-pid',
  '--unshare-uts',
  '--unshare-ipc',
  '--unshare-cgroup-try',
  '--unshare-net',
  '--clearenv',
  '--ro-bind',
  '/',
  '/',
  '--proc',
  '/proc',
  '--dev',
  '/dev',
  '/usr/bin/true',
]);
export const linuxX64Glibc = Object.freeze({
  os: 'linux',
  architecture: 'x64',
  libc: 'glibc',
});
export const requiredDogfoodAnalyzers = Object.freeze([
  Object.freeze({ id: 'strictest-comparator', analyzer: 'strictest-comparator' }),
  Object.freeze({ id: 'oxlint-ultracite', analyzer: 'Oxlint + Ultracite' }),
  Object.freeze({ id: 'jscpd', analyzer: 'JSCPD' }),
  Object.freeze({ id: 'calldiff', analyzer: 'Calldiff' }),
  Object.freeze({ id: 'zizmor', analyzer: 'zizmor' }),
  Object.freeze({ id: 'osv-scanner', analyzer: 'OSV-Scanner' }),
  Object.freeze({ id: 'tracedecay', analyzer: 'TraceDecay' }),
]);
export const requiredSemanticRunnerPackages = Object.freeze([
  Object.freeze({ name: '@effect/platform-node', version: '4.0.0-beta.102' }),
  Object.freeze({ name: '@effect/platform-node-shared', version: '4.0.0-beta.102' }),
  Object.freeze({ name: 'effect', version: '4.0.0-beta.102' }),
  Object.freeze({ name: 'fast-check', version: '4.9.0' }),
  Object.freeze({ name: 'pure-rand', version: '8.4.2' }),
  Object.freeze({ name: 'strip-json-comments', version: '5.0.3' }),
]);

// This value intentionally pins the complete semantic document, rather than
// trusting a target-supplied collection of individually plausible fields.
// It is updated together with runtime-manifest.json by the trusted workspace
// review/change process.
export const canonicalManifestPolicySha256 =
  '3b393279e851c73fd1df3d9061eafb169bfae1a71d325d9fbb378c0cccd22ecd';

const expectedAnalyzerById = new Map(
  requiredDogfoodAnalyzers.map(item => [item.id, item.analyzer]),
);
const sha256Pattern = /^[0-9a-f]{64}$/u;
const integrityPattern = /^sha512-[A-Za-z0-9+/]+={0,2}$/u;
const tokenPattern = /^[A-Za-z0-9@._+:/-]+$/u;
const readableLinePattern = /^[^\u0000-\u001f\u007f]+$/u;
const expectedPlatformKey = 'linux/x64/glibc';
const forbiddenEnvironmentPattern = /^(?:NODE_(?:OPTIONS|PATH|PRESERVE_SYMLINKS(?:_MAIN)?|COMPILE_CACHE|LOADER|REQUIRE)|LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|BUN_OPTIONS|DENO_.*|ESM_LOADER|TSX_.*|PYTHON.*|RUBYOPT)$/u;

export class RuntimeManifestError extends Error {
  constructor(code, message) {
    super(`[runtime:${code}] ${message}`);
    this.name = 'RuntimeManifestError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new RuntimeManifestError(code, message);
};

// The runtime tree is target-controlled at verification time.  In
// particular, `readFileSync` and `readdirSync` are unsafe here because they
// allocate based on target metadata before the verifier has applied a limit.
// Keep the accounting object private to this module: callers choose no limits
// and cannot reset a budget part-way through a verification phase.
const createVerificationBudget = () => ({
  deadline: process.hrtime.bigint() + BigInt(runtimeVerificationBounds.deadlineMs) * 1_000_000n,
  bytes: 0n,
  entries: 0,
});

const activeVerificationBudget = budget => budget ?? createVerificationBudget();

const assertBudgetDeadline = (budget, label) => {
  if (process.hrtime.bigint() > budget.deadline) {
    fail('verification-time-limit', `Runtime verification exceeded its ${runtimeVerificationBounds.deadlineMs}ms deadline while ${label}.`);
  }
};

const reserveVerificationBytes = (budget, bytes, label) => {
  assertBudgetDeadline(budget, label);
  const next = budget.bytes + bytes;
  if (next > BigInt(runtimeVerificationBounds.aggregateBytes)) {
    fail('verification-byte-limit', `Runtime verification exceeds its ${runtimeVerificationBounds.aggregateBytes} byte aggregate while ${label}.`);
  }
  budget.bytes = next;
};

const reserveVerificationEntry = (budget, label) => {
  assertBudgetDeadline(budget, label);
  const next = budget.entries + 1;
  if (next > runtimeVerificationBounds.entries) {
    fail('verification-entry-limit', `Runtime verification exceeds its ${runtimeVerificationBounds.entries} entry limit while ${label}.`);
  }
  budget.entries = next;
};

const metadataTimestamp = (metadata, field) => {
  const value = metadata[`${field}Ns`];
  if (typeof value !== 'bigint') {
    fail('verification-metadata-invalid', `Runtime metadata has no bigint ${field} timestamp.`);
  }
  return value;
};

const sameFileSnapshot = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  metadataTimestamp(left, 'mtime') === metadataTimestamp(right, 'mtime') &&
  metadataTimestamp(left, 'ctime') === metadataTimestamp(right, 'ctime');

const assertBoundedRegularFile = ({
  metadata,
  path,
  label,
  maximumBytes,
  invalidCode,
  hardlinkCode,
  oversizeCode,
}) => {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(invalidCode, `${label} at ${path} must be a regular non-symlink file.`);
  }
  if (metadata.nlink !== 1n) {
    fail(hardlinkCode, `${label} at ${path} must not be hard-linked.`);
  }
  const maximum = BigInt(maximumBytes);
  if (metadata.size < 0n || metadata.size > maximum) {
    fail(oversizeCode, `${label} at ${path} exceeds its ${maximumBytes} byte verification limit.`);
  }
  // A strict logical size bound protects allocation and streaming work even
  // for a sparse or copy-on-write file.  Do not infer hostility from
  // `st_blocks`: APFS, overlay, compressed, and COW filesystems legitimately
  // report fewer allocated blocks than logical bytes.
  return metadata;
};

const boundedRegularMetadata = ({
  path,
  label,
  maximumBytes,
  invalidCode,
  hardlinkCode,
  oversizeCode,
  missingCode = invalidCode,
}) => {
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (error) {
    fail(missingCode, `${label} at ${path} cannot be inspected: ${error instanceof Error ? error.message : String(error)}.`);
  }
  return assertBoundedRegularFile({
    metadata,
    path,
    label,
    maximumBytes,
    invalidCode,
    hardlinkCode,
    oversizeCode,
  });
};

const openBoundedRegularFile = ({
  path,
  label,
  maximumBytes,
  budget,
  invalidCode,
  hardlinkCode,
  oversizeCode,
  changedCode,
  missingCode,
}) => {
  const before = boundedRegularMetadata({
    path,
    label,
    maximumBytes,
    invalidCode,
    hardlinkCode,
    oversizeCode,
    missingCode,
  });
  assertBudgetDeadline(budget, `opening ${label}`);
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    fail(invalidCode, `${label} at ${path} cannot be opened without following links: ${error instanceof Error ? error.message : String(error)}.`);
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    assertBoundedRegularFile({
      metadata: opened,
      path,
      label,
      maximumBytes,
      invalidCode,
      hardlinkCode,
      oversizeCode,
    });
    if (!sameFileSnapshot(before, opened)) {
      fail(changedCode, `${label} at ${path} changed while opening it.`);
    }
    reserveVerificationBytes(budget, opened.size, `reading ${label}`);
    return { descriptor, metadata: opened };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
};

const assertDescriptorUnchanged = ({ descriptor, expected, path, label, changedCode }) => {
  const after = fstatSync(descriptor, { bigint: true });
  if (!sameFileSnapshot(expected, after)) {
    fail(changedCode, `${label} at ${path} changed while it was read.`);
  }
};

const readBoundedRegularFile = options => {
  const budget = activeVerificationBudget(options.budget);
  const { descriptor, metadata } = openBoundedRegularFile({ ...options, budget });
  try {
    const expectedBytes = Number(metadata.size);
    const contents = Buffer.allocUnsafe(expectedBytes);
    let offset = 0;
    while (offset < expectedBytes) {
      assertBudgetDeadline(budget, `reading ${options.label}`);
      const bytesRead = readSync(descriptor, contents, offset, expectedBytes - offset, offset);
      if (bytesRead <= 0) {
        fail(options.changedCode, `${options.label} at ${options.path} became shorter while it was read.`);
      }
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(descriptor, extra, 0, 1, expectedBytes) !== 0) {
      fail(options.changedCode, `${options.label} at ${options.path} grew while it was read.`);
    }
    assertDescriptorUnchanged({
      descriptor,
      expected: metadata,
      path: options.path,
      label: options.label,
      changedCode: options.changedCode,
    });
    assertBudgetDeadline(budget, `reading ${options.label}`);
    return contents;
  } finally {
    closeSync(descriptor);
  }
};

const sha256BoundedRegularFile = options => {
  const budget = activeVerificationBudget(options.budget);
  const { descriptor, metadata } = openBoundedRegularFile({ ...options, budget });
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
  try {
    const expectedBytes = Number(metadata.size);
    let offset = 0;
    while (offset < expectedBytes) {
      assertBudgetDeadline(budget, `hashing ${options.label}`);
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, expectedBytes - offset),
        offset,
      );
      if (bytesRead <= 0) {
        fail(options.changedCode, `${options.label} at ${options.path} became shorter while it was hashed.`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(descriptor, extra, 0, 1, expectedBytes) !== 0) {
      fail(options.changedCode, `${options.label} at ${options.path} grew while it was hashed.`);
    }
    assertDescriptorUnchanged({
      descriptor,
      expected: metadata,
      path: options.path,
      label: options.label,
      changedCode: options.changedCode,
    });
    assertBudgetDeadline(budget, `hashing ${options.label}`);
    return hash.digest('hex');
  } finally {
    closeSync(descriptor);
  }
};

const assertJsonTextBounds = (text, label, code, budget) => {
  const activeBudget = activeVerificationBudget(budget);
  let depth = 0;
  let entries = 0;
  let stringStart = -1;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    if (index % runtimeVerificationBounds.chunkBytes === 0) {
      assertBudgetDeadline(activeBudget, `preflighting ${label}`);
    }
    const character = text[index];
    if (stringStart >= 0) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === '\\') {
        escaped = true;
        continue;
      }
      if (character === '"') {
        if (Buffer.byteLength(text.slice(stringStart, index), 'utf8') > runtimeVerificationBounds.jsonStringBytes) {
          fail(`${code}-string-oversize`, `${label} contains a JSON string above its ${runtimeVerificationBounds.jsonStringBytes} byte limit.`);
        }
        stringStart = -1;
      }
      continue;
    }
    if (character === '"') {
      stringStart = index + 1;
      continue;
    }
    if (character === '{' || character === '[') {
      depth += 1;
      if (depth > runtimeVerificationBounds.jsonDepth) {
        fail(`${code}-depth-limit`, `${label} exceeds its ${runtimeVerificationBounds.jsonDepth} JSON nesting limit.`);
      }
      continue;
    }
    if (character === '}' || character === ']') {
      depth -= 1;
      continue;
    }
    if (character === ',') {
      entries += 1;
      if (entries > runtimeVerificationBounds.jsonEntries) {
        fail(`${code}-entry-limit`, `${label} exceeds its ${runtimeVerificationBounds.jsonEntries} JSON entry limit.`);
      }
    }
  }
  if (stringStart >= 0 || depth !== 0) {
    // Let JSON.parse produce the usual syntax diagnostic after the bounded
    // preflight; this branch exists only to avoid an unbounded nesting walk.
    return;
  }
};

const parseBoundedJson = ({ bytes, label, code, budget, invalidCode = `${code}-invalid` }) => {
  const activeBudget = activeVerificationBudget(budget);
  const text = bytes.toString('utf8');
  assertJsonTextBounds(text, label, code, activeBudget);
  assertBudgetDeadline(activeBudget, `parsing ${label}`);
  try {
    const parsed = JSON.parse(text);
    assertBudgetDeadline(activeBudget, `parsing ${label}`);
    return parsed;
  } catch (error) {
    if (error instanceof RuntimeManifestError) throw error;
    fail(invalidCode, `${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}.`);
  }
};

const boundedDirectoryEntries = ({
  directory,
  label,
  budget,
  entryCode,
  entryLimitCode = entryCode,
  maximumEntries = runtimeVerificationBounds.entries,
}) => {
  const activeBudget = activeVerificationBudget(budget);
  let handle;
  try {
    handle = opendirSync(directory, { bufferSize: 32 });
  } catch (error) {
    fail(entryCode, `Cannot enumerate ${label}: ${error instanceof Error ? error.message : String(error)}.`);
  }
  const entries = [];
  try {
    while (true) {
      assertBudgetDeadline(activeBudget, `enumerating ${label}`);
      const entry = handle.readSync();
      if (entry === null) break;
      reserveVerificationEntry(activeBudget, `enumerating ${label}`);
      if (entries.length >= maximumEntries) {
        fail(entryLimitCode, `${label} exceeds its ${maximumEntries} entry limit.`);
      }
      entries.push(entry);
    }
  } catch (error) {
    if (error instanceof RuntimeManifestError) throw error;
    fail(entryCode, `Cannot enumerate ${label}: ${error instanceof Error ? error.message : String(error)}.`);
  } finally {
    handle.closeSync();
  }
  return entries.sort((left, right) => left.name.localeCompare(right.name));
};

const isRecord = value =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const requireRecord = (value, label) => {
  if (!isRecord(value)) fail('manifest-schema', `${label} must be an object.`);
  return value;
};

const requireArray = (value, label, { allowEmpty = false } = {}) => {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    fail(
      'manifest-schema',
      `${label} must be ${allowEmpty ? 'an array' : 'a non-empty array'}.`,
    );
  }
  if (value.length > runtimeVerificationBounds.jsonArrayEntries) {
    fail(
      'manifest-schema',
      `${label} exceeds its ${runtimeVerificationBounds.jsonArrayEntries} entry limit.`,
    );
  }
  return value;
};

const requireString = (value, label) => {
  if (typeof value !== 'string' || value.length === 0) {
    fail('manifest-schema', `${label} must be a non-empty string.`);
  }
  if (Buffer.byteLength(value, 'utf8') > runtimeVerificationBounds.jsonStringBytes) {
    fail(
      'manifest-schema',
      `${label} exceeds its ${runtimeVerificationBounds.jsonStringBytes} byte string limit.`,
    );
  }
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    fail('manifest-schema', `${label} must not contain control characters.`);
  }
  return value;
};

const requireToken = (value, label) => {
  const token = requireString(value, label);
  if (!tokenPattern.test(token)) {
    fail('manifest-schema', `${label} contains unsupported characters.`);
  }
  return token;
};

const requireReadableLine = (value, label) => {
  const line = requireString(value, label);
  if (!readableLinePattern.test(line)) {
    fail('manifest-schema', `${label} must be one printable line.`);
  }
  return line;
};

const requireRelativePath = (value, label) => {
  const relativePath = requireString(value, label);
  if (
    isAbsolute(relativePath) ||
    relativePath.includes('\\') ||
    relativePath.startsWith('-') ||
    posix.normalize(relativePath) !== relativePath ||
    relativePath === '.' ||
    relativePath === '..' ||
    relativePath.startsWith('../')
  ) {
    fail('manifest-schema', `${label} must be a normalized relative path.`);
  }
  if (relativePath.split('/').length > runtimeVerificationBounds.directoryDepth) {
    fail(
      'manifest-schema',
      `${label} exceeds its ${runtimeVerificationBounds.directoryDepth} component limit.`,
    );
  }
  return relativePath;
};

const requireSha256 = (value, label) => {
  const checksum = requireString(value, label);
  if (!sha256Pattern.test(checksum)) {
    fail('manifest-schema', `${label} must be a lowercase SHA-256 digest.`);
  }
  return checksum;
};

const requireIntegrity = (value, label) => {
  const integrity = requireString(value, label);
  if (!integrityPattern.test(integrity)) {
    fail('manifest-schema', `${label} must be an npm SHA-512 integrity value.`);
  }
  return integrity;
};

const requireExactKeys = (record, keys, label) => {
  const expected = new Set(keys);
  const actual = Object.keys(record);
  if (actual.length > runtimeVerificationBounds.jsonObjectProperties) {
    fail(
      'manifest-schema',
      `${label} exceeds its ${runtimeVerificationBounds.jsonObjectProperties} property limit.`,
    );
  }
  const extras = actual.filter(key => !expected.has(key));
  const missing = keys.filter(key => !Object.hasOwn(record, key));
  if (extras.length > 0 || missing.length > 0) {
    const detail = [
      ...(missing.length > 0 ? [`missing ${missing.join(', ')}`] : []),
      ...(extras.length > 0 ? [`unsupported ${extras.join(', ')}`] : []),
    ].join('; ');
    fail('manifest-schema', `${label} has ${detail} field${actual.length === 1 ? '' : 's'}.`);
  }
};

const sha256Text = value => createHash('sha256').update(value).digest('hex');

const stableJson = value => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort((left, right) => left.localeCompare(right))
      .map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};

// Use the same canonical document bytes for generated evidence equality and
// for the enclosing manifest policy digest. Object key ordering must not be a
// way to smuggle a structurally different evidence record through preparation.
export const canonicalJsonText = value => stableJson(value);

export const canonicalManifestDigest = value => sha256Text(stableJson(value));

const platformKey = platform =>
  `${platform.os}/${platform.architecture}/${platform.libc}`;

const validateChecksum = (value, label) => {
  const checksum = requireRecord(value, label);
  requireExactKeys(checksum, ['path', 'sha256'], label);
  requireRelativePath(checksum.path, `${label}.path`);
  requireSha256(checksum.sha256, `${label}.sha256`);
};

const validateSemanticRunner = (value, label) => {
  const runner = requireRecord(value, label);
  requireExactKeys(runner, ['path', 'sha256', 'bundledPackages'], label);
  if (runner.path !== requiredSemanticRunnerPath) {
    fail('manifest-schema', `${label}.path must be ${requiredSemanticRunnerPath}.`);
  }
  requireSha256(runner.sha256, `${label}.sha256`);
  const packages = requireArray(runner.bundledPackages, `${label}.bundledPackages`);
  if (packages.length !== requiredSemanticRunnerPackages.length) {
    fail(
      'manifest-schema',
      `${label}.bundledPackages must contain exactly ${requiredSemanticRunnerPackages.length} packages.`,
    );
  }
  packages.forEach((item, index) => {
    const packageLabel = `${label}.bundledPackages[${index}]`;
    const packageEntry = requireRecord(item, packageLabel);
    requireExactKeys(
      packageEntry,
      ['name', 'version', 'sourceIntegrity', 'license', 'licenseFile'],
      packageLabel,
    );
    requireToken(packageEntry.name, `${packageLabel}.name`);
    requireToken(packageEntry.version, `${packageLabel}.version`);
    requireIntegrity(packageEntry.sourceIntegrity, `${packageLabel}.sourceIntegrity`);
    if (packageEntry.license !== 'MIT') {
      fail('manifest-schema', `${packageLabel}.license must be MIT.`);
    }
    validateChecksum(packageEntry.licenseFile, `${packageLabel}.licenseFile`);
    if (!packageEntry.licenseFile.path.startsWith('licenses/semantic-runner-')) {
      fail(
        'manifest-schema',
        `${packageLabel}.licenseFile must be inside licenses/semantic-runner-*.`
      );
    }
  });
  const expectedIdentities = requiredSemanticRunnerPackages.map(
    item => `${item.name}@${item.version}`,
  );
  const actualIdentities = packages.map(item => `${item.name}@${item.version}`);
  if (actualIdentities.some((identity, index) => identity !== expectedIdentities[index])) {
    fail(
      'manifest-schema',
      `${label}.bundledPackages must match the exact canonical semantic runner closure.`,
    );
  }
  return runner;
};

const validateRuntimeNode = (value, label) => {
  const node = requireRecord(value, label);
  requireExactKeys(node, ['path', 'versionOutput', 'sha256', 'archive'], label);
  if (node.path !== requiredRuntimeNode.path) {
    fail('runtime-node-mismatch', `${label}.path must be ${requiredRuntimeNode.path}.`);
  }
  if (node.versionOutput !== requiredRuntimeNode.versionOutput) {
    fail('runtime-node-mismatch', `${label}.versionOutput must be ${requiredRuntimeNode.versionOutput}.`);
  }
  if (node.sha256 !== requiredRuntimeNode.sha256) {
    fail('runtime-node-mismatch', `${label}.sha256 does not match the pinned Node executable.`);
  }
  const archive = requireRecord(node.archive, `${label}.archive`);
  requireExactKeys(archive, ['url', 'sha256', 'member'], `${label}.archive`);
  if (
    archive.url !== requiredRuntimeNode.archive.url ||
    archive.sha256 !== requiredRuntimeNode.archive.sha256 ||
    archive.member !== requiredRuntimeNode.archive.member
  ) {
    fail('runtime-node-mismatch', `${label}.archive does not match the pinned Node provenance.`);
  }
  return node;
};

const requireExactInteger = (value, expected, label) => {
  if (!Number.isSafeInteger(value) || value !== expected) {
    fail('osv-database-mismatch', `${label} does not match the pinned offline OSV database.`);
  }
  return value;
};

const requireOsvNatural = (value, label, { minimum = 0 } = {}) => {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail('osv-database-mismatch', `${label} must be a safe integer no smaller than ${minimum}.`);
  }
  return value;
};

const validateOsvValidationEvidence = (value, database, label) => {
  const evidence = requireRecord(value, label);
  requireExactKeys(evidence, ['schemaVersion', 'source', 'archive'], label);
  if (evidence.schemaVersion !== 'codebase-radar.osv-npm-snapshot-evidence/v1') {
    fail('osv-database-mismatch', `${label}.schemaVersion must be the reviewed OSV evidence schema.`);
  }
  const source = requireRecord(evidence.source, `${label}.source`);
  requireExactKeys(source, ['url', 'generation', 'publishedAt', 'maxAge'], `${label}.source`);
  if (
    source.url !== requiredOfflineOsvDatabase.url ||
    source.generation !== requiredOfflineOsvDatabase.generation ||
    source.publishedAt !== requiredOfflineOsvDatabase.publishedAt ||
    source.maxAge !== requiredOfflineOsvDatabase.maxAgeDays * 24 * 60 * 60
  ) {
    fail('osv-database-mismatch', `${label}.source does not match the pinned OSV release.`);
  }
  const archive = requireRecord(evidence.archive, `${label}.archive`);
  requireExactKeys(
    archive,
    [
      'size',
      'sha256',
      'format',
      'zip64',
      'entryCount',
      'compressedBytes',
      'uncompressedBytes',
      'storedEntries',
      'deflatedEntries',
      'signedDataDescriptorEntries',
      'dataDescriptorBytes',
      'compressionMethods',
      'centralDirectoryOffset',
      'centralDirectoryBytes',
      'structuralSha256',
    ],
    `${label}.archive`,
  );
  requireExactInteger(archive.size, database.size, `${label}.archive.size`);
  if (archive.sha256 !== database.sha256) {
    fail('osv-database-mismatch', `${label}.archive.sha256 does not match the pinned OSV database.`);
  }
  if (archive.format !== 'zip' || typeof archive.zip64 !== 'boolean') {
    fail('osv-database-mismatch', `${label}.archive has an unsupported ZIP representation.`);
  }
  requireExactInteger(archive.entryCount, database.entries, `${label}.archive.entryCount`);
  requireExactInteger(
    archive.uncompressedBytes,
    database.uncompressedBytes,
    `${label}.archive.uncompressedBytes`,
  );
  requireOsvNatural(archive.compressedBytes, `${label}.archive.compressedBytes`, { minimum: 1 });
  if (archive.compressedBytes > archive.size) {
    fail('osv-database-mismatch', `${label}.archive.compressedBytes exceeds archive size.`);
  }
  requireOsvNatural(archive.storedEntries, `${label}.archive.storedEntries`);
  requireOsvNatural(archive.deflatedEntries, `${label}.archive.deflatedEntries`);
  if (
    archive.storedEntries !== 0 ||
    archive.deflatedEntries !== archive.entryCount ||
    archive.signedDataDescriptorEntries !== database.signedDataDescriptorEntries ||
    archive.dataDescriptorBytes !== database.dataDescriptorBytes
  ) {
    fail('osv-database-mismatch', `${label}.archive must record the exact DEFLATE and signed-descriptor inventory.`);
  }
  const methods = requireArray(archive.compressionMethods, `${label}.archive.compressionMethods`);
  if (methods.length !== 1 || methods[0] !== 'deflate') {
    fail('osv-database-mismatch', `${label}.archive.compressionMethods must be exactly ["deflate"].`);
  }
  requireOsvNatural(
    archive.centralDirectoryOffset,
    `${label}.archive.centralDirectoryOffset`,
    { minimum: 1 },
  );
  requireOsvNatural(
    archive.centralDirectoryBytes,
    `${label}.archive.centralDirectoryBytes`,
    { minimum: 1 },
  );
  if (
    archive.centralDirectoryOffset > archive.size ||
    archive.centralDirectoryBytes > archive.size - archive.centralDirectoryOffset
  ) {
    fail('osv-database-mismatch', `${label}.archive central directory lies outside the archive.`);
  }
  requireSha256(archive.structuralSha256, `${label}.archive.structuralSha256`);
  return evidence;
};

const validateOsvSnapshotValidator = (value, label) => {
  const validator = requireRecord(value, label);
  requireExactKeys(validator, ['schemaVersion', 'path', 'byteLength', 'sha256'], label);
  if (
    validator.schemaVersion !== requiredOsvNpmSnapshotValidator.schemaVersion ||
    validator.path !== requiredOsvNpmSnapshotValidator.path
  ) {
    fail('osv-database-mismatch', `${label} does not identify the reviewed OSV snapshot validator.`);
  }
  requireOsvNatural(validator.byteLength, `${label}.byteLength`, { minimum: 1 });
  if (validator.byteLength > runtimeVerificationBounds.textBytes) {
    fail('osv-database-mismatch', `${label}.byteLength exceeds the trusted text limit.`);
  }
  requireSha256(validator.sha256, `${label}.sha256`);
  return validator;
};

export const validateOfflineOsvDatabase = (value, label = 'offline OSV database') => {
  const database = requireRecord(value, label);
  requireExactKeys(
    database,
    [
      'path',
      'url',
      'generation',
      'sha256',
      'size',
      'entries',
      'uncompressedBytes',
      'signedDataDescriptorEntries',
      'dataDescriptorBytes',
      'publishedAt',
      'maxAgeDays',
      'validationEvidence',
      'validator',
    ],
    label,
  );
  for (const key of ['path', 'url', 'generation', 'sha256', 'publishedAt']) {
    if (database[key] !== requiredOfflineOsvDatabase[key]) {
      fail('osv-database-mismatch', `${label}.${key} does not match the pinned offline OSV database.`);
    }
  }
  requireExactInteger(database.size, requiredOfflineOsvDatabase.size, `${label}.size`);
  requireExactInteger(database.entries, requiredOfflineOsvDatabase.entries, `${label}.entries`);
  requireExactInteger(
    database.uncompressedBytes,
    requiredOfflineOsvDatabase.uncompressedBytes,
    `${label}.uncompressedBytes`,
  );
  requireExactInteger(
    database.signedDataDescriptorEntries,
    requiredOfflineOsvDatabase.signedDataDescriptorEntries,
    `${label}.signedDataDescriptorEntries`,
  );
  requireExactInteger(
    database.dataDescriptorBytes,
    requiredOfflineOsvDatabase.dataDescriptorBytes,
    `${label}.dataDescriptorBytes`,
  );
  requireExactInteger(database.maxAgeDays, requiredOfflineOsvDatabase.maxAgeDays, `${label}.maxAgeDays`);
  validateOsvValidationEvidence(database.validationEvidence, database, `${label}.validationEvidence`);
  validateOsvSnapshotValidator(database.validator, `${label}.validator`);
  return database;
};

export const assertOfflineOsvDatabaseFresh = (database, now = Date.now()) => {
  if (!Number.isSafeInteger(now) || now < 0) {
    fail('osv-database-clock-invalid', 'The offline OSV database freshness check requires a valid clock.');
  }
  // Validate even exported direct callers; it keeps a caller from supplying a
  // target-shaped record to bypass the exact immutable generation policy.
  validateOfflineOsvDatabase(database, 'offline OSV database');
  const publishedAt = Date.parse(requiredOfflineOsvDatabase.publishedAt);
  const expiresAt = publishedAt + requiredOfflineOsvDatabase.maxAgeDays * 24 * 60 * 60 * 1000;
  if (
    !Number.isSafeInteger(publishedAt) ||
    now < publishedAt - offlineOsvMaximumFutureClockSkewMs ||
    now > expiresAt
  ) {
    fail('osv-database-stale', 'The pinned offline OSV database is outside its seven-day freshness window.');
  }
  return Object.freeze({ publishedAt, expiresAt });
};

const validateHostIsolation = (value, label) => {
  const isolation = requireRecord(value, label);
  requireExactKeys(
    isolation,
    ['kind', 'path', 'required', 'packageVersion', 'versionOutput'],
    label,
  );
  if (isolation.kind !== requiredHostIsolation.kind) {
    fail('host-isolation-mismatch', `${label}.kind must be ${requiredHostIsolation.kind}.`);
  }
  if (isolation.path !== requiredHostIsolation.path) {
    fail('host-isolation-mismatch', `${label}.path must be ${requiredHostIsolation.path}.`);
  }
  if (isolation.required !== true) {
    fail('host-isolation-mismatch', `${label}.required must be true.`);
  }
  if (isolation.packageVersion !== requiredHostIsolation.packageVersion) {
    fail(
      'host-isolation-mismatch',
      `${label}.packageVersion must be ${requiredHostIsolation.packageVersion}.`,
    );
  }
  if (isolation.versionOutput !== requiredHostIsolation.versionOutput) {
    fail(
      'host-isolation-mismatch',
      `${label}.versionOutput must be ${requiredHostIsolation.versionOutput}.`,
    );
  }
  return isolation;
};

const validatePnpmIntegrityEvidence = (value, label) => {
  const evidence = requireRecord(value, label);
  requireExactKeys(evidence, ['path', 'sha256'], label);
  if (evidence.path !== requiredPnpmIntegrityEvidencePath) {
    fail('manifest-schema', `${label}.path must be ${requiredPnpmIntegrityEvidencePath}.`);
  }
  requireSha256(evidence.sha256, `${label}.sha256`);
  return evidence;
};

const validateLicenseNotice = (value, label) => {
  const notice = requireRecord(value, label);
  requireExactKeys(notice, ['path', 'sha256', 'license'], label);
  requireRelativePath(notice.path, `${label}.path`);
  requireSha256(notice.sha256, `${label}.sha256`);
  requireToken(notice.license, `${label}.license`);
};

const validateLegalFile = (value, label) => {
  const legalFile = requireRecord(value, label);
  requireExactKeys(legalFile, ['kind', 'path', 'sha256'], label);
  if (legalFile.kind !== 'license' && legalFile.kind !== 'notice') {
    fail('manifest-schema', `${label}.kind must be "license" or "notice".`);
  }
  requireRelativePath(legalFile.path, `${label}.path`);
  requireSha256(legalFile.sha256, `${label}.sha256`);
};

const validateNpmPackage = (packageCheck, label) => {
  requireExactKeys(
    packageCheck,
    [
      'source',
      'name',
      'version',
      'packageJson',
      'sourceIntegrity',
      'treeSha256',
      'resolutionPaths',
    ],
    label,
  );
  requireToken(packageCheck.name, `${label}.name`);
  requireToken(packageCheck.version, `${label}.version`);
  requireRelativePath(packageCheck.packageJson, `${label}.packageJson`);
  if (!packageCheck.packageJson.startsWith('node_modules/')) {
    fail('manifest-schema', `${label}.packageJson must be inside node_modules.`);
  }
  requireIntegrity(packageCheck.sourceIntegrity, `${label}.sourceIntegrity`);
  requireSha256(packageCheck.treeSha256, `${label}.treeSha256`);
  const resolutionPaths = requireArray(
    packageCheck.resolutionPaths,
    `${label}.resolutionPaths`,
  );
  resolutionPaths.forEach((path, index) => {
    requireRelativePath(path, `${label}.resolutionPaths[${index}]`);
    if (!path.startsWith('node_modules/')) {
      fail(
        'manifest-schema',
        `${label}.resolutionPaths[${index}] must be inside node_modules.`,
      );
    }
  });
  if (new Set(resolutionPaths).size !== resolutionPaths.length) {
    fail('manifest-schema', `${label}.resolutionPaths contains duplicates.`);
  }
};

const validateReleasePackage = (packageCheck, label) => {
  requireExactKeys(
    packageCheck,
    ['source', 'name', 'version', 'sourceSha256'],
    label,
  );
  requireToken(packageCheck.name, `${label}.name`);
  requireToken(packageCheck.version, `${label}.version`);
  requireSha256(packageCheck.sourceSha256, `${label}.sourceSha256`);
};

const validatePackage = (value, label) => {
  const packageCheck = requireRecord(value, label);
  if (packageCheck.source === 'npm') {
    validateNpmPackage(packageCheck, label);
    return;
  }
  if (packageCheck.source === 'release') {
    validateReleasePackage(packageCheck, label);
    return;
  }
  fail('manifest-schema', `${label}.source must be "npm" or "release".`);
};

const validateProbeContract = (command, label) => {
  if (command.runner !== 'direct' && command.runner !== 'node') {
    fail('manifest-schema', `${label}.runner must be "direct" or "node".`);
  }
  requireRelativePath(command.path, `${label}.path`);
  const args = requireArray(command.args, `${label}.args`, { allowEmpty: true });
  args.forEach((argument, index) =>
    requireReadableLine(argument, `${label}.args[${index}]`),
  );
  if (!Number.isInteger(command.timeoutMs) || command.timeoutMs < 1_000 || command.timeoutMs > 30_000) {
    fail('manifest-schema', `${label}.timeoutMs must be an integer from 1000 through 30000.`);
  }
  if (!Number.isInteger(command.maxOutputBytes) || command.maxOutputBytes < 256 || command.maxOutputBytes > 65_536) {
    fail('manifest-schema', `${label}.maxOutputBytes must be an integer from 256 through 65536.`);
  }
  if (command.expectedStatus !== 0) {
    fail('manifest-schema', `${label}.expectedStatus must be 0.`);
  }
  if (command.expectedSignal !== null) {
    fail('manifest-schema', `${label}.expectedSignal must be null.`);
  }
};

const validateVersionCommand = (value, label) => {
  const command = requireRecord(value, label);
  requireExactKeys(
    command,
    [
      'runner',
      'path',
      'args',
      'expectedVersion',
      'expectedOutput',
      'timeoutMs',
      'maxOutputBytes',
      'expectedStatus',
      'expectedSignal',
    ],
    label,
  );
  validateProbeContract(command, label);
  const expectedVersion = requireToken(command.expectedVersion, `${label}.expectedVersion`);
  const expectedOutput = requireReadableLine(command.expectedOutput, `${label}.expectedOutput`);
  if (!expectedOutput.includes(expectedVersion)) {
    fail('manifest-schema', `${label}.expectedOutput must contain expectedVersion.`);
  }
};

const validateSmoke = (value, label) => {
  const smoke = requireRecord(value, label);
  requireExactKeys(
    smoke,
    [
      'kind',
      'runner',
      'path',
      'fixture',
      'args',
      'timeoutMs',
      'maxOutputBytes',
      'expectedStatus',
      'expectedSignal',
      'expected',
    ],
    label,
  );
  validateProbeContract(smoke, label);
  requireRelativePath(smoke.fixture, `${label}.fixture`);
  const expected = requireRecord(smoke.expected, `${label}.expected`);
  if (smoke.kind === 'calldiff-report/v1') {
    if (smoke.runner !== 'node') {
      fail('manifest-schema', `${label}.runner must be "node" for the Calldiff smoke.`);
    }
    requireExactKeys(
      expected,
      [
        'schemaVersion',
        'analyzerVersion',
        'eligibleFiles',
        'analyzedFiles',
        'failedFiles',
        'minimumFunctions',
      ],
      `${label}.expected`,
    );
    requireToken(expected.schemaVersion, `${label}.expected.schemaVersion`);
    requireToken(expected.analyzerVersion, `${label}.expected.analyzerVersion`);
    for (const field of [
      'eligibleFiles',
      'analyzedFiles',
      'failedFiles',
      'minimumFunctions',
    ]) {
      if (!Number.isInteger(expected[field]) || expected[field] < 0) {
        fail('manifest-schema', `${label}.expected.${field} must be a natural number.`);
      }
    }
    return smoke;
  }
  if (smoke.kind !== 'osv-offline-lockfiles/v1' || smoke.runner !== 'direct') {
    fail('manifest-schema', `${label}.kind and runner do not identify a reviewed smoke protocol.`);
  }
  if (smoke.path !== 'bin/osv-scanner' || smoke.fixture !== 'smoke/osv') {
    fail('manifest-schema', `${label} must use the pinned OSV-Scanner binary and fixture root.`);
  }
  requireExactKeys(
    expected,
    [
      'analyzerVersion',
      'vulnerableLockfile',
      'cleanLockfile',
      'requiredVulnerabilityId',
    ],
    `${label}.expected`,
  );
  if (expected.analyzerVersion !== '2.5.0') {
    fail('manifest-schema', `${label}.expected.analyzerVersion must be 2.5.0.`);
  }
  requireRelativePath(expected.vulnerableLockfile, `${label}.expected.vulnerableLockfile`);
  requireRelativePath(expected.cleanLockfile, `${label}.expected.cleanLockfile`);
  requireToken(expected.requiredVulnerabilityId, `${label}.expected.requiredVulnerabilityId`);
  if (expected.vulnerableLockfile === expected.cleanLockfile) {
    fail('manifest-schema', `${label}.expected lockfile fixtures must be distinct.`);
  }
  return smoke;
};

const validateLauncher = (value, label) => {
  const launcher = requireRecord(value, label);
  requireExactKeys(launcher, ['path', 'target'], label);
  requireRelativePath(launcher.path, `${label}.path`);
  requireRelativePath(launcher.target, `${label}.target`);
  if (!launcher.path.startsWith('node_modules/.bin/')) {
    fail('manifest-schema', `${label}.path must be a node_modules/.bin launcher.`);
  }
  if (!launcher.target.startsWith('node_modules/')) {
    fail('manifest-schema', `${label}.target must be inside node_modules.`);
  }
};

const validateDownload = (value, label, platform) => {
  const download = requireRecord(value, label);
  requireExactKeys(
    download,
    ['url', 'sourceSha256', 'format', 'archiveMember', 'output', 'installedSha256'],
    label,
  );
  const url = requireString(download.url, `${label}.url`);
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    fail('manifest-schema', `${label}.url must be a valid URL.`);
  }
  if (
    parsedUrl.protocol !== 'https:' ||
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.hash ||
    parsedUrl.search
  ) {
    fail('manifest-schema', `${label}.url must be an HTTPS URL without credentials, queries, or fragments.`);
  }
  requireSha256(download.sourceSha256, `${label}.sourceSha256`);
  if (download.format !== 'raw' && download.format !== 'tar.gz') {
    fail('manifest-schema', `${label}.format must be "raw" or "tar.gz".`);
  }
  const archiveMember = requireString(download.archiveMember, `${label}.archiveMember`);
  if (
    (download.format === 'raw' && archiveMember !== '-') ||
    (download.format === 'tar.gz' &&
      (!/^[A-Za-z0-9][A-Za-z0-9._+]*$/u.test(archiveMember) ||
        archiveMember === '.' ||
        archiveMember === '..'))
  ) {
    fail('manifest-schema', `${label}.archiveMember is invalid for ${download.format}.`);
  }
  requireRelativePath(download.output, `${label}.output`);
  requireSha256(download.installedSha256, `${label}.installedSha256`);
  if (download.output !== platform.entrypoint) {
    fail('manifest-schema', `${label}.output must equal its platform entrypoint.`);
  }
  const installedChecksum = platform.checksums.find(
    checksum => checksum.path === download.output,
  );
  if (installedChecksum?.sha256 !== download.installedSha256) {
    fail('manifest-schema', `${label}.installedSha256 must match the output checksum.`);
  }
};

const validatePlatform = (value, label) => {
  const platform = requireRecord(value, label);
  requireExactKeys(
    platform,
    [
      'os',
      'architecture',
      'libc',
      'entrypoint',
      'versionCommand',
      'smoke',
      'checksums',
      'nativeExecutables',
      'launchers',
      'download',
    ],
    label,
  );
  requireToken(platform.os, `${label}.os`);
  requireToken(platform.architecture, `${label}.architecture`);
  requireToken(platform.libc, `${label}.libc`);
  requireRelativePath(platform.entrypoint, `${label}.entrypoint`);
  if (platform.versionCommand !== null) {
    validateVersionCommand(platform.versionCommand, `${label}.versionCommand`);
  }
  if (platform.smoke !== null) validateSmoke(platform.smoke, `${label}.smoke`);
  if (
    platform.versionCommand === null &&
    platform.smoke === null &&
    !platform.entrypoint.endsWith('.json')
  ) {
    fail('manifest-schema', `${label} must define a bounded version command or smoke probe.`);
  }
  const checksums = requireArray(platform.checksums, `${label}.checksums`);
  checksums.forEach((checksum, index) =>
    validateChecksum(checksum, `${label}.checksums[${index}]`),
  );
  const checksumPaths = checksums.map(checksum => checksum.path);
  if (new Set(checksumPaths).size !== checksumPaths.length) {
    fail('manifest-schema', `${label}.checksums contains duplicate paths.`);
  }
  if (!checksumPaths.includes(platform.entrypoint)) {
    fail('manifest-schema', `${label}.entrypoint must have an installed checksum.`);
  }
  if (platform.versionCommand !== null && !checksumPaths.includes(platform.versionCommand.path)) {
    fail('manifest-schema', `${label}.versionCommand.path must have an installed checksum.`);
  }
  if (platform.smoke !== null && !checksumPaths.includes(platform.smoke.path)) {
    fail('manifest-schema', `${label}.smoke.path must have an installed checksum.`);
  }
  const nativeExecutables = requireArray(
    platform.nativeExecutables,
    `${label}.nativeExecutables`,
    { allowEmpty: true },
  );
  nativeExecutables.forEach((path, index) => {
    requireRelativePath(path, `${label}.nativeExecutables[${index}]`);
    if (!checksumPaths.includes(path)) {
      fail('manifest-schema', `${label}.nativeExecutables[${index}] must have an installed checksum.`);
    }
  });
  if (new Set(nativeExecutables).size !== nativeExecutables.length) {
    fail('manifest-schema', `${label}.nativeExecutables contains duplicates.`);
  }
  const launchers = requireArray(platform.launchers, `${label}.launchers`, {
    allowEmpty: true,
  });
  launchers.forEach((launcher, index) =>
    validateLauncher(launcher, `${label}.launchers[${index}]`),
  );
  if (new Set(launchers.map(launcher => launcher.path)).size !== launchers.length) {
    fail('manifest-schema', `${label}.launchers contains duplicate paths.`);
  }
  if (platform.download !== null) validateDownload(platform.download, `${label}.download`, platform);
};

const validateAnalyzer = (value, index) => {
  const label = `analyzers[${index}]`;
  const analyzer = requireRecord(value, label);
  requireExactKeys(
    analyzer,
    ['id', 'analyzer', 'version', 'profileVersions', 'licenseNotice', 'legalFiles', 'packages', 'platforms'],
    label,
  );
  requireToken(analyzer.id, `${label}.id`);
  requireReadableLine(analyzer.analyzer, `${label}.analyzer`);
  requireReadableLine(analyzer.version, `${label}.version`);
  const profileVersions = requireArray(analyzer.profileVersions, `${label}.profileVersions`);
  profileVersions.forEach((profile, profileIndex) =>
    requireToken(profile, `${label}.profileVersions[${profileIndex}]`),
  );
  if (new Set(profileVersions).size !== profileVersions.length) {
    fail('manifest-schema', `${label}.profileVersions contains duplicates.`);
  }
  validateLicenseNotice(analyzer.licenseNotice, `${label}.licenseNotice`);
  const legalFiles = requireArray(analyzer.legalFiles, `${label}.legalFiles`);
  legalFiles.forEach((legalFile, legalFileIndex) =>
    validateLegalFile(legalFile, `${label}.legalFiles[${legalFileIndex}]`),
  );
  if (new Set(legalFiles.map(legalFile => `${legalFile.kind}:${legalFile.path}`)).size !== legalFiles.length) {
    fail('manifest-schema', `${label}.legalFiles contains duplicate entries.`);
  }
  if (!legalFiles.some(legalFile => legalFile.kind === 'license')) {
    fail('manifest-schema', `${label}.legalFiles must include a license.`);
  }
  const packages = requireArray(analyzer.packages, `${label}.packages`);
  packages.forEach((packageCheck, packageIndex) =>
    validatePackage(packageCheck, `${label}.packages[${packageIndex}]`),
  );
  if (new Set(packages.map(packageCheck => `${packageCheck.source}:${packageCheck.name}@${packageCheck.version}`)).size !== packages.length) {
    fail('manifest-schema', `${label}.packages contains duplicate identities.`);
  }
  const platforms = requireArray(analyzer.platforms, `${label}.platforms`);
  platforms.forEach((platform, platformIndex) =>
    validatePlatform(platform, `${label}.platforms[${platformIndex}]`),
  );
  if (new Set(platforms.map(platformKey)).size !== platforms.length) {
    fail('manifest-schema', `${label}.platforms contains duplicate targets.`);
  }
};

const expectedPnpmNamespaceForPackageJson = packageJson => {
  const marker = '/node_modules/';
  const markerIndex = packageJson.lastIndexOf(marker);
  if (markerIndex <= 0) {
    fail('manifest-schema', 'Package metadata path ' + packageJson + ' has no pnpm importer namespace.');
  }
  return packageJson.slice(0, markerIndex + '/node_modules'.length);
};

const npmPackageMap = manifest => {
  const result = new Map();
  for (const packageCheck of manifest.semanticRunner.bundledPackages) {
    result.set(packageCheck.name + '@' + packageCheck.version, packageCheck);
  }
  for (const analyzer of manifest.analyzers) {
    for (const packageCheck of analyzer.packages) {
      if (packageCheck.source !== 'npm') continue;
      result.set(packageCheck.name + '@' + packageCheck.version, packageCheck);
    }
  }
  return result;
};

// Bundled semantic-runner packages are authenticated as release build inputs,
// but their bytes are embedded in the single runner and are intentionally not
// present as target node_modules roots. The physical pnpm graph must cover
// exactly the analyzer packages that remain in the deployed runtime.
const runtimeNpmPackageMap = manifest => {
  const result = new Map();
  for (const analyzer of manifest.analyzers) {
    for (const packageCheck of analyzer.packages) {
      if (packageCheck.source === 'npm') {
        result.set(packageCheck.name + '@' + packageCheck.version, packageCheck);
      }
    }
  }
  return result;
};

const validatePnpmEdge = (value, label, packages) => {
  const edge = requireRecord(value, label);
  requireExactKeys(
    edge,
    ['specifier', 'requested', 'state', 'target', 'resolver'],
    label,
  );
  requireToken(edge.specifier, label + '.specifier');
  requireReadableLine(edge.requested, label + '.requested');
  if (edge.state !== 'present' && edge.state !== 'absent') {
    fail('manifest-schema', label + '.state must be "present" or "absent".');
  }
  if (
    edge.resolver !== 'create-require' &&
    edge.resolver !== 'pnpm-link-import-only' &&
    edge.resolver !== 'absent'
  ) {
    fail('manifest-schema', label + '.resolver is invalid.');
  }
  if (edge.state === 'present' && edge.resolver === 'absent') {
    fail('manifest-schema', label + '.resolver cannot be absent for a present edge.');
  }
  if (edge.state === 'absent' && edge.resolver !== 'absent') {
    fail('manifest-schema', label + '.resolver must be absent for an absent edge.');
  }
  if (edge.target !== null) {
    requireToken(edge.target, label + '.target');
    const target = packages.get(edge.target);
    if (target === undefined) {
      fail('manifest-schema', label + '.target is not an authenticated package identity.');
    }
    if (target.name !== edge.specifier) {
      fail('manifest-schema', label + '.target does not match its specifier.');
    }
  }
  if (edge.state === 'present' && edge.target === null) {
    fail('manifest-schema', label + '.target is required for a present edge.');
  }
  return edge;
};

const validatePnpmImporters = manifest => {
  const packages = runtimeNpmPackageMap(manifest);
  const importers = requireArray(manifest.pnpmImporters, 'manifest.pnpmImporters');
  const expectedIds = new Set(['runtime-root', ...packages.keys()]);
  if (importers.length !== expectedIds.size) {
    fail('pnpm-importer-count', 'pnpm importer graph must contain exactly one root and one importer per authenticated package.');
  }
  const seen = new Set();
  for (let index = 0; index < importers.length; index += 1) {
    const label = 'manifest.pnpmImporters[' + index + ']';
    const importer = requireRecord(importers[index], label);
    requireExactKeys(importer, ['id', 'packageJson', 'namespace', 'edges'], label);
    requireToken(importer.id, label + '.id');
    requireRelativePath(importer.packageJson, label + '.packageJson');
    requireRelativePath(importer.namespace, label + '.namespace');
    if (!expectedIds.has(importer.id) || seen.has(importer.id)) {
      fail('pnpm-importer-invalid', label + '.id is missing, duplicate, or unmodeled.');
    }
    seen.add(importer.id);
    if (importer.id === 'runtime-root') {
      if (importer.packageJson !== 'package.json' || importer.namespace !== 'node_modules') {
        fail('pnpm-importer-invalid', 'runtime-root must use package.json and node_modules.');
      }
    } else {
      const packageCheck = packages.get(importer.id);
      if (
        packageCheck === undefined ||
        importer.packageJson !== packageCheck.packageJson ||
        importer.namespace !== expectedPnpmNamespaceForPackageJson(packageCheck.packageJson)
      ) {
        fail('pnpm-importer-invalid', label + ' does not pin its exact package namespace.');
      }
    }
    const edges = requireArray(importer.edges, label + '.edges', { allowEmpty: true });
    const edgeSpecifiers = new Set();
    for (let edgeIndex = 0; edgeIndex < edges.length; edgeIndex += 1) {
      const edge = validatePnpmEdge(edges[edgeIndex], label + '.edges[' + edgeIndex + ']', packages);
      if (edgeSpecifiers.has(edge.specifier)) {
        fail('pnpm-edge-duplicate', label + ' declares ' + edge.specifier + ' more than once.');
      }
      edgeSpecifiers.add(edge.specifier);
    }
  }
  if (seen.size !== expectedIds.size) {
    fail('pnpm-importer-invalid', 'pnpm importer graph does not cover every authenticated package.');
  }
  const root = importers.find(importer => importer.id === 'runtime-root');
  const rootSpecifiers = root.edges.map(edge => edge.specifier).sort();
  const requiredRootSpecifiers = [
    '@tsconfig/strictest',
    'calldiff',
    'jscpd',
    'oxlint',
    'tree-sitter-javascript',
    'typescript',
    'ultracite',
  ].sort();
  if (
    rootSpecifiers.length !== requiredRootSpecifiers.length ||
    rootSpecifiers.some((specifier, index) => specifier !== requiredRootSpecifiers[index])
  ) {
    fail('pnpm-root-importer-invalid', 'runtime-root must pin the seven direct analyzer-runtime dependencies.');
  }
  const fallback = requireRecord(
    manifest.pnpmFallbackNamespace,
    'manifest.pnpmFallbackNamespace',
  );
  requireExactKeys(fallback, ['path', 'state'], 'manifest.pnpmFallbackNamespace');
  if (
    fallback.path !== 'node_modules/.pnpm/node_modules' ||
    fallback.state !== 'absent'
  ) {
    fail('pnpm-fallback-policy', 'The pnpm hoist fallback namespace must be explicitly absent.');
  }
};

const validateGlobalOwnership = manifest => {
  const packageOwners = new Set();
  const packagePaths = new Set();
  const resolutionOwners = new Set();
  const profileOwners = new Set();
  const legalFileOwners = new Set();
  const artifactOwners = new Set();
  const nativeOwners = new Set();
  const launcherOwners = new Set();
  const downloadOwners = new Set();
  for (const analyzer of manifest.analyzers) {
    for (const profile of analyzer.profileVersions) {
      if (profileOwners.has(profile)) {
        fail('profile-duplicate', `Profile "${profile}" is owned by more than one analyzer.`);
      }
      profileOwners.add(profile);
    }
    for (const packageCheck of analyzer.packages) {
      const identity = `${packageCheck.source}:${packageCheck.name}@${packageCheck.version}`;
      if (packageOwners.has(identity)) {
        fail('package-duplicate', `Package provenance "${identity}" is owned by more than one analyzer.`);
      }
      packageOwners.add(identity);
      if (packageCheck.source === 'npm') {
        if (packagePaths.has(packageCheck.packageJson)) {
          fail('package-path-duplicate', `Package metadata path "${packageCheck.packageJson}" is owned more than once.`);
        }
        packagePaths.add(packageCheck.packageJson);
        for (const resolutionPath of packageCheck.resolutionPaths) {
          if (resolutionOwners.has(resolutionPath)) {
            fail('resolution-path-duplicate', `Resolved package path "${resolutionPath}" is owned more than once.`);
          }
          resolutionOwners.add(resolutionPath);
        }
      }
    }
    for (const legalFile of analyzer.legalFiles) {
      if (legalFileOwners.has(legalFile.path)) {
        fail('legal-path-duplicate', `Legal file "${legalFile.path}" is owned by more than one analyzer.`);
      }
      legalFileOwners.add(legalFile.path);
    }
    for (const platform of analyzer.platforms) {
      if (platformKey(platform) !== expectedPlatformKey) {
        fail('platform-policy', `Unsupported declared target ${platformKey(platform)}; only ${expectedPlatformKey} is supported.`);
      }
      for (const checksum of platform.checksums) {
        if (artifactOwners.has(checksum.path)) {
          fail('artifact-path-duplicate', `Artifact path "${checksum.path}" is owned by more than one analyzer.`);
        }
        artifactOwners.add(checksum.path);
      }
      for (const nativePath of platform.nativeExecutables) {
        if (nativeOwners.has(nativePath)) {
          fail('native-path-duplicate', `Native executable "${nativePath}" is owned more than once.`);
        }
        nativeOwners.add(nativePath);
      }
      for (const launcher of platform.launchers) {
        if (launcherOwners.has(launcher.path)) {
          fail('launcher-path-duplicate', `Launcher path "${launcher.path}" is owned by more than one analyzer.`);
        }
        launcherOwners.add(launcher.path);
      }
      if (platform.download !== null) {
        if (downloadOwners.has(platform.download.output)) {
          fail('download-output-duplicate', `Download output "${platform.download.output}" is owned more than once.`);
        }
        downloadOwners.add(platform.download.output);
      }
    }
  }
};

export const validateRuntimeManifest = value => {
  const manifest = requireRecord(value, 'manifest');
  requireExactKeys(
    manifest,
    [
      'schemaVersion',
      'manifestVersion',
      'profile',
      'managedBinaryDirectory',
      'controlFiles',
      'semanticRunner',
      'runtimeNode',
      'offlineOsvDatabase',
      'hostIsolation',
      'pnpmIntegrityEvidence',
      'pnpmFallbackNamespace',
      'pnpmImporters',
      'analyzers',
    ],
    'manifest',
  );
  if (manifest.schemaVersion !== runtimeManifestSchemaVersion) {
    fail('manifest-version', `Expected schema ${runtimeManifestSchemaVersion}; got ${String(manifest.schemaVersion)}.`);
  }
  if (manifest.manifestVersion !== 1) {
    fail('manifest-version', `Expected manifest version 1; got ${String(manifest.manifestVersion)}.`);
  }
  if (manifest.profile !== dogfoodMaxProfile) {
    fail('profile-mismatch', `Expected profile ${dogfoodMaxProfile}; got ${String(manifest.profile)}.`);
  }
  requireRelativePath(manifest.managedBinaryDirectory, 'manifest.managedBinaryDirectory');
  const controlFiles = requireArray(manifest.controlFiles, 'manifest.controlFiles');
  controlFiles.forEach((file, index) => validateChecksum(file, `manifest.controlFiles[${index}]`));
  if (new Set(controlFiles.map(file => file.path)).size !== controlFiles.length) {
    fail('manifest-schema', 'manifest.controlFiles contains duplicate paths.');
  }
  validateSemanticRunner(manifest.semanticRunner, 'manifest.semanticRunner');
  validateRuntimeNode(manifest.runtimeNode, 'manifest.runtimeNode');
  validateOfflineOsvDatabase(manifest.offlineOsvDatabase, 'manifest.offlineOsvDatabase');
  validateHostIsolation(manifest.hostIsolation, 'manifest.hostIsolation');
  validatePnpmIntegrityEvidence(
    manifest.pnpmIntegrityEvidence,
    'manifest.pnpmIntegrityEvidence',
  );
  const analyzers = requireArray(manifest.analyzers, 'manifest.analyzers');
  if (analyzers.length !== requiredDogfoodAnalyzers.length) {
    fail('analyzer-count', `Expected exactly ${requiredDogfoodAnalyzers.length} analyzers; got ${analyzers.length}.`);
  }
  analyzers.forEach(validateAnalyzer);
  const counts = new Map();
  for (const analyzer of analyzers) {
    counts.set(analyzer.id, (counts.get(analyzer.id) ?? 0) + 1);
  }
  for (const required of requiredDogfoodAnalyzers) {
    const count = counts.get(required.id) ?? 0;
    if (count === 0) {
      fail('analyzer-missing', `Required analyzer "${required.analyzer}" (${required.id}) is missing.`);
    }
    if (count > 1) {
      fail('analyzer-duplicate', `Required analyzer "${required.analyzer}" (${required.id}) appears ${count} times.`);
    }
    const entry = analyzers.find(analyzer => analyzer.id === required.id);
    if (entry.analyzer !== required.analyzer) {
      fail('analyzer-name-mismatch', `Analyzer ${required.id} must be named "${required.analyzer}"; got "${entry.analyzer}".`);
    }
    if (entry.platforms.length !== 1 || platformKey(entry.platforms[0]) !== expectedPlatformKey) {
      fail('platform-policy', `Analyzer "${required.analyzer}" must declare exactly ${expectedPlatformKey}.`);
    }
  }
  const extras = analyzers.filter(analyzer => !expectedAnalyzerById.has(analyzer.id));
  if (extras.length > 0) {
    fail('analyzer-extra', `Unexpected analyzer entries: ${extras.map(analyzer => analyzer.id).join(', ')}.`);
  }
  validateGlobalOwnership(manifest);
  validatePnpmImporters(manifest);
  const digest = canonicalManifestDigest(manifest);
  if (digest !== canonicalManifestPolicySha256) {
    fail('policy-mismatch', `Manifest does not match the reviewed ${dogfoodMaxProfile} policy (got ${digest}).`);
  }
  return manifest;
};

const readRuntimeManifestWithBudget = (manifestPath, budget) => {
  const bytes = readBoundedRegularFile({
    path: manifestPath,
    label: 'Analyzer runtime manifest',
    maximumBytes: runtimeVerificationBounds.manifestBytes,
    budget,
    invalidCode: 'manifest-invalid',
    hardlinkCode: 'manifest-invalid',
    oversizeCode: 'manifest-oversize',
    changedCode: 'manifest-changed',
    missingCode: 'manifest-missing',
  });
  return validateRuntimeManifest(
    parseBoundedJson({
      bytes,
      label: `Manifest at ${manifestPath}`,
      code: 'manifest-json',
      budget,
      invalidCode: 'manifest-json',
    }),
  );
};

export const readRuntimeManifest = manifestPath =>
  readRuntimeManifestWithBudget(manifestPath, createVerificationBudget());

export const detectRuntimePlatform = () => ({
  os: process.platform,
  architecture: process.arch,
  libc:
    process.platform === 'linux' && process.report?.getReport().header.glibcVersionRuntime
      ? 'glibc'
      : process.platform === 'linux'
        ? 'musl'
        : 'none',
});

const selectPlatform = (analyzer, target) => {
  if (platformKey(target) !== expectedPlatformKey) {
    fail('platform-unsupported', `Only ${expectedPlatformKey} is supported; got ${platformKey(target)}.`);
  }
  const matches = analyzer.platforms.filter(platform => platformKey(platform) === expectedPlatformKey);
  if (matches.length !== 1) {
    fail('platform-unsupported', `Analyzer "${analyzer.analyzer}" has no exact runtime for ${expectedPlatformKey}.`);
  }
  return matches[0];
};

const isWithin = (root, candidate) => {
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  return candidate === root || candidate.startsWith(prefix);
};

const canonicalRoot = requestedRoot => {
  if (typeof requestedRoot !== 'string' || requestedRoot.length === 0 || !isAbsolute(requestedRoot)) {
    fail('root-invalid', 'Analyzer runtime root must be a non-empty absolute path.');
  }
  let rootStat;
  try {
    rootStat = lstatSync(requestedRoot);
  } catch {
    fail('root-missing', `Analyzer runtime root does not exist: ${requestedRoot}.`);
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail('root-invalid', `Analyzer runtime root must be a non-symlink directory: ${requestedRoot}.`);
  }
  return realpathSync(requestedRoot);
};

const resolveRuntimePath = (root, relativePath) => {
  const candidate = resolve(root, relativePath);
  if (!isWithin(root, candidate)) {
    fail('path-escape', `Runtime path "${relativePath}" resolves outside ${root}.`);
  }
  return candidate;
};

const inspectPathComponents = (root, relativePath, allowPnpmLinks) => {
  const components = relativePath.split('/');
  let current = root;
  let linked = false;
  for (const component of components) {
    current = join(current, component);
    let info;
    try {
      info = lstatSync(current);
    } catch {
      return { candidate: current, linked };
    }
    if (!info.isSymbolicLink()) continue;
    linked = true;
    if (!allowPnpmLinks || !relativePath.startsWith('node_modules/')) {
      fail('symlink-rejected', `Runtime path "${relativePath}" contains an unmanaged symlink.`);
    }
    let resolved;
    try {
      resolved = realpathSync(current);
    } catch {
      fail('symlink-invalid', `Runtime path "${relativePath}" contains a broken symlink.`);
    }
    if (!isWithin(root, resolved)) {
      fail('path-escape', `Runtime path "${relativePath}" symlinks outside the runtime root.`);
    }
    const pnpmStore = join(root, 'node_modules', '.pnpm');
    if (!isWithin(pnpmStore, resolved)) {
      fail('pnpm-link-invalid', `Runtime path "${relativePath}" uses a non-pnpm package link.`);
    }
  }
  return { candidate: resolveRuntimePath(root, relativePath), linked };
};

const ensureFile = (
  root,
  relativePath,
  analyzerName,
  kind,
  {
    allowPnpmLinks = false,
    maximumBytes = runtimeVerificationBounds.runtimeArtifactBytes,
    budget,
  } = {},
) => {
  const { candidate } = inspectPathComponents(root, relativePath, allowPnpmLinks);
  let linkStat;
  try {
    linkStat = lstatSync(candidate, { bigint: true });
  } catch {
    fail(`${kind}-missing`, `Analyzer "${analyzerName}" ${kind} "${relativePath}" is missing.`);
  }
  if (linkStat.isSymbolicLink()) {
    fail('symlink-rejected', `Analyzer "${analyzerName}" ${kind} "${relativePath}" must not be a final symlink.`);
  }
  assertBoundedRegularFile({
    metadata: linkStat,
    path: candidate,
    label: `Analyzer "${analyzerName}" ${kind} "${relativePath}"`,
    maximumBytes,
    invalidCode: `${kind}-invalid`,
    hardlinkCode: 'hardlink-rejected',
    oversizeCode: `${kind}-oversize`,
  });
  const canonicalPath = realpathSync(candidate);
  if (!isWithin(root, canonicalPath)) {
    fail('path-escape', `Analyzer "${analyzerName}" ${kind} "${relativePath}" points outside the runtime root.`);
  }
  const canonicalMetadata = boundedRegularMetadata({
    path: canonicalPath,
    label: `Analyzer "${analyzerName}" ${kind} "${relativePath}"`,
    maximumBytes,
    invalidCode: `${kind}-invalid`,
    hardlinkCode: 'hardlink-rejected',
    oversizeCode: `${kind}-oversize`,
    missingCode: `${kind}-missing`,
  });
  if (!sameFileSnapshot(linkStat, canonicalMetadata)) {
    fail(`${kind}-changed`, `Analyzer "${analyzerName}" ${kind} "${relativePath}" changed while it was resolved.`);
  }
  assertBudgetDeadline(activeVerificationBudget(budget), `inspecting ${kind}`);
  return { absolutePath: candidate, canonicalPath, fileStat: statSync(canonicalPath) };
};

const ensureDirectory = (root, relativePath, kind) => {
  const { candidate } = inspectPathComponents(root, relativePath, false);
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    fail(`${kind}-missing`, `Runtime directory "${relativePath}" is missing.`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${kind}-invalid`, `Runtime directory "${relativePath}" must be a non-symlink directory.`);
  }
  return candidate;
};

const sha256File = (
  absolutePath,
  {
    label = 'Runtime artifact',
    maximumBytes = runtimeVerificationBounds.runtimeArtifactBytes,
    budget,
    invalidCode = 'artifact-invalid',
    hardlinkCode = 'hardlink-rejected',
    oversizeCode = 'artifact-oversize',
    changedCode = 'artifact-changed',
  } = {},
) =>
  sha256BoundedRegularFile({
    path: absolutePath,
    label,
    maximumBytes,
    budget,
    invalidCode,
    hardlinkCode,
    oversizeCode,
    changedCode,
    missingCode: invalidCode,
  });

const verifyChecksum = (root, analyzer, checksum, cache, packageRoots, budget) => {
  const allowPnpmLinks = checksum.path.startsWith('node_modules/');
  const file = ensureFile(root, checksum.path, analyzer.analyzer, 'artifact', {
    allowPnpmLinks,
    budget,
  });
  if (allowPnpmLinks && ![...packageRoots.values()].some(packageRoot => isWithin(packageRoot, file.canonicalPath))) {
    fail('resolution-unmodeled', `Analyzer "${analyzer.analyzer}" artifact "${checksum.path}" resolves outside the declared package closure.`);
  }
  const actual = cache.get(file.canonicalPath) ?? sha256File(file.canonicalPath, {
    label: `Analyzer "${analyzer.analyzer}" artifact "${checksum.path}"`,
    budget,
  });
  cache.set(file.canonicalPath, actual);
  if (actual !== checksum.sha256) {
    fail('checksum-mismatch', `Analyzer "${analyzer.analyzer}" artifact "${checksum.path}" expected sha256 ${checksum.sha256}; got ${actual}.`);
  }
};

const packageTreeDigest = (
  packageRoot,
  budget,
  { allowGeneratedPackageBins = false } = {},
) => {
  const activeBudget = activeVerificationBudget(budget);
  const hash = createHash('sha256');
  let treeEntries = 0;
  let treeBytes = 0n;
  const treeMode = (metadata, relativePath) => {
    const mode = Number(metadata.mode & 0o7777n);
    if ((mode & 0o7000) !== 0) {
      fail(
        'package-tree-mode-invalid',
        `Package tree ${packageRoot} contains special permission bits at ${relativePath}.`,
      );
    }
    return mode.toString(8).padStart(4, '0');
  };
  const assertTrustedFile = (metadata, relativePath) => {
    if (metadata.nlink !== 1n) {
      fail(
        'package-tree-hardlink',
        `Package tree ${packageRoot} contains a hard-linked trusted file at ${relativePath}.`,
      );
    }
  };
  let rootMetadata;
  try {
    rootMetadata = lstatSync(packageRoot, { bigint: true });
  } catch (error) {
    fail('package-tree-invalid', `Cannot inspect package tree root ${packageRoot}: ${error instanceof Error ? error.message : String(error)}.`);
  }
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    fail('package-tree-invalid', `Package tree root ${packageRoot} must be a regular non-symlink directory.`);
  }
  hash.update(`d\0.\0${treeMode(rootMetadata, '.')}\n`);
  const stack = [{ directory: packageRoot, prefix: '', depth: 0, entries: null, index: 0 }];
  while (stack.length > 0) {
    assertBudgetDeadline(activeBudget, `walking package tree ${packageRoot}`);
    const frame = stack.at(-1);
    if (frame.entries === null) {
      frame.entries = boundedDirectoryEntries({
        directory: frame.directory,
        label: `package tree ${packageRoot}`,
        budget: activeBudget,
        entryCode: 'package-tree-entry-limit',
        maximumEntries: runtimeVerificationBounds.packageTreeEntries,
      });
    }
    if (frame.index >= frame.entries.length) {
      stack.pop();
      continue;
    }
    const entry = frame.entries[frame.index];
    frame.index += 1;
    treeEntries += 1;
    if (treeEntries > runtimeVerificationBounds.packageTreeEntries) {
      fail('package-tree-entry-limit', `Package tree ${packageRoot} exceeds its ${runtimeVerificationBounds.packageTreeEntries} entry limit.`);
    }
    const relativePath = frame.prefix ? `${frame.prefix}/${entry.name}` : entry.name;
    const absolutePath = join(frame.directory, entry.name);
    let metadata;
    try {
      metadata = lstatSync(absolutePath, { bigint: true });
    } catch (error) {
      fail('package-tree-invalid', `Cannot inspect package tree ${packageRoot} at ${relativePath}: ${error instanceof Error ? error.message : String(error)}.`);
    }
    const mode = treeMode(metadata, relativePath);
    if (metadata.isSymbolicLink()) {
      fail('package-tree-symlink', `Package tree ${packageRoot} contains an unmodeled symlink at ${relativePath}.`);
    }
    if (metadata.isDirectory()) {
      if (relativePath === 'node_modules/.bin') {
        if (!allowGeneratedPackageBins) {
          fail(
            'package-tree-generated-bin',
            `Package tree ${packageRoot} contains package-manager-generated executable shims.`,
          );
        }
        const generatedEntries = boundedDirectoryEntries({
          directory: absolutePath,
          label: `generated package executables in ${packageRoot}`,
          budget: activeBudget,
          entryCode: 'package-tree-generated-bin',
          entryLimitCode: 'package-tree-generated-bin',
          maximumEntries: 256,
        });
        for (const generatedEntry of generatedEntries) {
          treeEntries += 1;
          if (treeEntries > runtimeVerificationBounds.packageTreeEntries) {
            fail('package-tree-entry-limit', `Package tree ${packageRoot} exceeds its ${runtimeVerificationBounds.packageTreeEntries} entry limit.`);
          }
          const generatedPath = `${relativePath}/${generatedEntry.name}`;
          const generatedAbsolutePath = join(absolutePath, generatedEntry.name);
          let generatedMetadata;
          try {
            generatedMetadata = lstatSync(generatedAbsolutePath, { bigint: true });
          } catch (error) {
            fail('package-tree-generated-bin', `Cannot inspect generated package executable ${generatedPath}: ${error instanceof Error ? error.message : String(error)}.`);
          }
          treeMode(generatedMetadata, generatedPath);
          if (!generatedMetadata.isFile() || generatedMetadata.isSymbolicLink()) {
            fail('package-tree-generated-bin', `Generated package executable ${generatedPath} must be a regular file.`);
          }
          assertTrustedFile(generatedMetadata, generatedPath);
          if (generatedMetadata.size > BigInt(runtimeVerificationBounds.textBytes)) {
            fail('package-tree-generated-bin', `Generated package executable ${generatedPath} exceeds its bounded text size.`);
          }
          treeBytes += generatedMetadata.size;
          if (treeBytes > BigInt(runtimeVerificationBounds.packageTreeBytes)) {
            fail('package-tree-byte-limit', `Package tree ${packageRoot} exceeds its ${runtimeVerificationBounds.packageTreeBytes} byte limit.`);
          }
          // pnpm writes absolute install-root paths into these generated
          // wrappers. Read them through the normal descriptor/identity bounds
          // so hostile source bytes stay bounded, but do not make an
          // installation pathname part of the package payload identity. The
          // atomic staging copier omits this exact namespace, and production
          // verification rejects it if it survives staging.
          sha256File(generatedAbsolutePath, {
            label: `Generated package executable ${generatedPath}`,
            maximumBytes: runtimeVerificationBounds.textBytes,
            budget: activeBudget,
            invalidCode: 'package-tree-generated-bin',
            hardlinkCode: 'package-tree-hardlink',
            oversizeCode: 'package-tree-generated-bin',
            changedCode: 'package-tree-changed',
          });
        }
        continue;
      }
      if (frame.depth + 1 > runtimeVerificationBounds.directoryDepth) {
        fail('package-tree-depth-limit', `Package tree ${packageRoot} exceeds its ${runtimeVerificationBounds.directoryDepth} directory depth limit.`);
      }
      hash.update(`d\0${relativePath}\0${mode}\n`);
      stack.push({
        directory: absolutePath,
        prefix: relativePath,
        depth: frame.depth + 1,
        entries: null,
        index: 0,
      });
      continue;
    }
    if (metadata.isFile()) {
      assertTrustedFile(metadata, relativePath);
      if (metadata.size > BigInt(runtimeVerificationBounds.packageFileBytes)) {
        fail('package-tree-oversize', `Package tree ${packageRoot} contains an oversized file at ${relativePath}.`);
      }
      treeBytes += metadata.size;
      if (treeBytes > BigInt(runtimeVerificationBounds.packageTreeBytes)) {
        fail('package-tree-byte-limit', `Package tree ${packageRoot} exceeds its ${runtimeVerificationBounds.packageTreeBytes} byte limit.`);
      }
      hash.update(`f\0${relativePath}\0${mode}\0`);
      hash.update(sha256File(absolutePath, {
        label: `Package tree ${packageRoot} file ${relativePath}`,
        maximumBytes: runtimeVerificationBounds.packageFileBytes,
        budget: activeBudget,
        invalidCode: 'package-tree-invalid',
        hardlinkCode: 'package-tree-hardlink',
        oversizeCode: 'package-tree-oversize',
        changedCode: 'package-tree-changed',
      }));
      hash.update('\n');
      continue;
    }
    fail('package-tree-invalid', `Package tree ${packageRoot} contains unsupported entry ${relativePath}.`);
  }
  return hash.digest('hex');
};

export const packageTreeSha256 = packageRoot =>
  packageTreeDigest(packageRoot, createVerificationBudget(), {
    allowGeneratedPackageBins: true,
  });

const assertPackageTreeSha256WithBudget = ({
  analyzer,
  packageName,
  packageRoot,
  expectedSha256,
}, budget) => {
  const actualTreeSha256 = packageTreeDigest(packageRoot, budget);
  if (actualTreeSha256 !== expectedSha256) {
    fail('package-tree-mismatch', `Analyzer "${analyzer}" package ${packageName} expected tree sha256 ${expectedSha256}; got ${actualTreeSha256}.`);
  }
};

export const assertPackageTreeSha256 = options =>
  assertPackageTreeSha256WithBudget(options, createVerificationBudget());

const packageIdentity = packageCheck => `${packageCheck.name}@${packageCheck.version}`;

const readPackageMetadata = (packageRoot, label, budget) => {
  const packageJson = join(packageRoot, 'package.json');
  const bytes = readBoundedRegularFile({
    path: packageJson,
    label: `${label} package.json`,
    maximumBytes: runtimeVerificationBounds.textBytes,
    budget,
    invalidCode: 'package-resolution-invalid',
    hardlinkCode: 'package-resolution-invalid',
    oversizeCode: 'package-resolution-oversize',
    changedCode: 'package-resolution-changed',
    missingCode: 'package-resolution-invalid',
  });
  const decoded = parseBoundedJson({
    bytes,
    label: `${label} package.json`,
    code: 'package-resolution',
    budget,
    invalidCode: 'package-resolution-invalid',
  });
  if (
    !isRecord(decoded) ||
    typeof decoded.name !== 'string' ||
    decoded.name.length === 0 ||
    typeof decoded.version !== 'string' ||
    decoded.version.length === 0
  ) {
    fail('package-resolution-invalid', `${label} package.json must declare a name and version.`);
  }
  return decoded;
};

const pnpmNamespaceForPackage = (root, packageRoot) => {
  const pnpmStore = join(root, 'node_modules', '.pnpm');
  if (!isWithin(pnpmStore, packageRoot)) {
    fail('pnpm-namespace-invalid', `Package root ${packageRoot} is outside the managed pnpm store.`);
  }
  let current = packageRoot;
  while (true) {
    const parent = dirname(current);
    if (parent === current || !isWithin(pnpmStore, parent)) {
      fail('pnpm-namespace-invalid', `Package root ${packageRoot} has no managed pnpm namespace.`);
    }
    if (posix.basename(parent) === 'node_modules') {
      const metadata = lstatSync(parent);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail('pnpm-namespace-invalid', `Package namespace ${parent} must be a regular directory.`);
      }
      return parent;
    }
    current = parent;
  }
};

const declaredPackageSpecifiers = (metadata, label) => {
  const specifiers = new Set();
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const dependencies = metadata[field];
    if (dependencies === undefined) continue;
    if (!isRecord(dependencies)) {
      fail('package-resolution-invalid', `${label} ${field} must be an object.`);
    }
    for (const specifier of Object.keys(dependencies)) {
      requireToken(specifier, `${label} ${field} specifier`);
      specifiers.add(specifier);
    }
  }
  return specifiers;
};

const packageNamespaceEntries = (namespace, label, budget) => {
  const entries = [];
  const visitScope = (directory, prefix) => {
    for (const entry of boundedDirectoryEntries({
      directory,
      label,
      budget,
      entryCode: 'pnpm-namespace-invalid',
      entryLimitCode: 'pnpm-namespace-entry-limit',
    })) {
      if (entry.name.startsWith('@') || entry.name === '.bin') {
        fail('pnpm-namespace-invalid', `${label} has an invalid scoped namespace entry ${entry.name}.`);
      }
      entries.push({
        specifier: `${prefix}/${entry.name}`,
        path: join(directory, entry.name),
      });
    }
  };
  for (const entry of boundedDirectoryEntries({
    directory: namespace,
    label,
    budget,
    entryCode: 'pnpm-namespace-invalid',
    entryLimitCode: 'pnpm-namespace-entry-limit',
  })) {
    const entryPath = join(namespace, entry.name);
    if (entry.name === '.bin') {
      fail('pnpm-namespace-invalid', `${label} contains an unmanaged .bin namespace.`);
    }
    if (entry.name.startsWith('@')) {
      const metadata = lstatSync(entryPath);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail('pnpm-namespace-invalid', `${label} scope ${entry.name} must be a regular non-symlink directory.`);
      }
      visitScope(entryPath, entry.name);
      continue;
    }
    entries.push({ specifier: entry.name, path: entryPath });
  }
  return entries;
};

const resolvePackageSpecifier = ({ importerRoot, importer, specifier }) => {
  const resolver = createRequire(join(importerRoot, 'package.json'));
  const candidates = [specifier, `${specifier}/package.json`];
  const failures = [];
  for (const candidate of candidates) {
    try {
      return resolver.resolve(candidate);
    } catch (error) {
      failures.push(error);
      // Some native platform packages intentionally have no package entrypoint;
      // package.json remains a resolution-only, execution-free identity probe.
    }
  }
  // An ESM-only dependency can intentionally expose neither a CommonJS entry
  // nor package.json through `exports`. Its authenticated pnpm sibling link is
  // still an exact, execution-free edge; the package Merkle identity covers
  // the ESM entrypoint. Any other resolution error is a broken graph.
  if (failures.length === candidates.length && failures.every(error => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED')) {
    return null;
  }
  fail('package-resolution-failed', `Package ${importer} cannot resolve ${specifier} without execution.`);
};

const verifyPnpmNamespace = ({ root, importerIdentity, importerRoot, packageRoots, budget }) => {
  const importerMetadata = readPackageMetadata(importerRoot, `Package ${importerIdentity}`, budget);
  if (packageIdentity(importerMetadata) !== importerIdentity) {
    fail('package-resolution-invalid', `Package root ${importerRoot} does not match ${importerIdentity}.`);
  }
  const declaredSpecifiers = declaredPackageSpecifiers(importerMetadata, `Package ${importerIdentity}`);
  const namespace = pnpmNamespaceForPackage(root, importerRoot);
  const seenSpecifiers = new Set();
  const evidence = [];
  for (const entry of packageNamespaceEntries(namespace, `Package ${importerIdentity}`, budget)) {
    if (seenSpecifiers.has(entry.specifier)) {
      fail('pnpm-namespace-invalid', `Package ${importerIdentity} has duplicate namespace entry ${entry.specifier}.`);
    }
    seenSpecifiers.add(entry.specifier);
    const linkMetadata = lstatSync(entry.path);
    if (!linkMetadata.isDirectory() && !linkMetadata.isSymbolicLink()) {
      fail('pnpm-namespace-invalid', `Package ${importerIdentity} namespace entry ${entry.specifier} is not a package directory or link.`);
    }
    let canonicalTarget;
    try {
      canonicalTarget = realpathSync(entry.path);
    } catch {
      fail('pnpm-namespace-invalid', `Package ${importerIdentity} namespace entry ${entry.specifier} is broken.`);
    }
    if (!isWithin(root, canonicalTarget)) {
      fail('path-escape', `Package ${importerIdentity} namespace entry ${entry.specifier} resolves outside the runtime root.`);
    }
    const targetMetadata = readPackageMetadata(
      canonicalTarget,
      `Package ${importerIdentity} namespace entry ${entry.specifier}`,
      budget,
    );
    const targetIdentity = packageIdentity(targetMetadata);
    const expectedRoot = packageRoots.get(targetIdentity);
    if (expectedRoot === undefined) {
      fail('package-shadow-unmodeled', `Package ${importerIdentity} has an unmodeled pnpm dependency ${entry.specifier} (${targetIdentity}).`);
    }
    if (canonicalTarget !== expectedRoot) {
      fail('package-resolution-root-mismatch', `Package ${importerIdentity} namespace entry ${entry.specifier} does not resolve to the authenticated ${targetIdentity} root.`);
    }
    if (targetMetadata.name !== entry.specifier) {
      fail('package-specifier-mismatch', `Package ${importerIdentity} namespace entry ${entry.specifier} identifies as ${targetMetadata.name}.`);
    }
    if (entry.specifier === importerMetadata.name) {
      if (linkMetadata.isSymbolicLink() || canonicalTarget !== importerRoot) {
        fail('pnpm-namespace-invalid', `Package ${importerIdentity} must be the direct self entry in its namespace.`);
      }
      continue;
    }
    if (!linkMetadata.isSymbolicLink()) {
      fail('pnpm-namespace-invalid', `Package ${importerIdentity} dependency ${entry.specifier} must be a pnpm sibling link.`);
    }
    if (!declaredSpecifiers.has(entry.specifier)) {
      fail('package-resolution-unmodeled', `Package ${importerIdentity} has an undeclared pnpm dependency ${entry.specifier}.`);
    }
    const resolved = resolvePackageSpecifier({
      importerRoot,
      importer: importerIdentity,
      specifier: entry.specifier,
    });
    if (resolved === null) {
      evidence.push({
        importer: importerIdentity,
        specifier: entry.specifier,
        package: targetIdentity,
        resolved: canonicalTarget,
        resolver: 'pnpm-link-import-only',
      });
      continue;
    }
    let canonicalResolved;
    try {
      canonicalResolved = realpathSync(resolved);
    } catch {
      fail('package-resolution-invalid', `Package ${importerIdentity} resolution for ${entry.specifier} is broken.`);
    }
    if (!isWithin(expectedRoot, canonicalResolved)) {
      fail('package-resolution-root-mismatch', `Package ${importerIdentity} resolution for ${entry.specifier} escapes authenticated ${targetIdentity}.`);
    }
    evidence.push({
      importer: importerIdentity,
      specifier: entry.specifier,
      package: targetIdentity,
      resolved: canonicalResolved,
      resolver: 'create-require',
    });
  }
  if (!seenSpecifiers.has(importerMetadata.name)) {
    fail('pnpm-namespace-invalid', `Package ${importerIdentity} is missing its direct self namespace entry.`);
  }
  return evidence;
};

const staticNamespaceEntries = (namespace, label, rootNamespace, budget) => {
  const entries = boundedDirectoryEntries({
    directory: namespace,
    label: label + ' namespace',
    budget,
    entryCode: 'pnpm-namespace-missing',
    entryLimitCode: 'pnpm-namespace-entry-limit',
  });
  const structuralRootEntries = new Set([
    '.bin',
    '.modules.yaml',
    '.package-map.json',
    '.pnpm',
    '.pnpm-workspace-state-v1.json',
  ]);
  const result = [];
  const visitScope = (directory, prefix) => {
    for (const entry of boundedDirectoryEntries({
      directory,
      label: label + ' scoped namespace',
      budget,
      entryCode: 'pnpm-namespace-invalid',
      entryLimitCode: 'pnpm-namespace-entry-limit',
    })) {
      if (entry.name.startsWith('@') || entry.name.startsWith('.')) {
        fail('pnpm-namespace-invalid', label + ' has invalid scoped entry ' + entry.name + '.');
      }
      result.push({ specifier: prefix + '/' + entry.name, path: join(directory, entry.name) });
    }
  };
  for (const entry of entries) {
    const entryPath = join(namespace, entry.name);
    if (entry.name.startsWith('.')) {
      if (!rootNamespace || !structuralRootEntries.has(entry.name)) {
        fail('pnpm-namespace-invalid', label + ' contains unmodeled namespace entry ' + entry.name + '.');
      }
      if (lstatSync(entryPath).isSymbolicLink()) {
        fail('pnpm-namespace-invalid', label + ' structural entry ' + entry.name + ' must not be a symlink.');
      }
      continue;
    }
    if (entry.name.startsWith('@')) {
      const metadata = lstatSync(entryPath);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail('pnpm-namespace-invalid', label + ' scope ' + entry.name + ' must be a regular non-symlink directory.');
      }
      visitScope(entryPath, entry.name);
      continue;
    }
    result.push({ specifier: entry.name, path: entryPath });
  }
  return result;
};

const staticResolvePackageSpecifier = ({ importerRoot, importer, specifier }) => {
  const resolver = createRequire(join(importerRoot, 'package.json'));
  const candidates = [specifier, specifier + '/package.json'];
  const failures = [];
  for (const candidate of candidates) {
    try {
      return { kind: 'resolved', path: resolver.resolve(candidate) };
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.every(error => error?.code === 'MODULE_NOT_FOUND')) {
    return { kind: 'missing' };
  }
  if (failures.every(error => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED')) {
    return { kind: 'pnpm-link-import-only' };
  }
  fail('package-resolution-failed', 'Package ' + importer + ' cannot resolve ' + specifier + ' without execution.');
};

const canonicalStaticPackageRoots = ({ root, packageRoots, manifest }) => {
  if (!(packageRoots instanceof Map) || packageRoots.size === 0) {
    fail('package-shadow-invalid', 'Package closure roots must be a non-empty Map.');
  }
  const expected = runtimeNpmPackageMap(manifest);
  if (packageRoots.size !== expected.size) {
    fail('package-shadow-invalid', 'Authenticated package roots do not match the manifest closure.');
  }
  const result = new Map();
  const seen = new Set();
  for (const [identity, packageCheck] of expected) {
    const packageRoot = packageRoots.get(identity);
    if (typeof packageRoot !== 'string') {
      fail('package-shadow-invalid', 'Package closure root ' + identity + ' is missing.');
    }
    let canonical;
    try {
      canonical = realpathSync(packageRoot);
    } catch {
      fail('package-shadow-invalid', 'Package closure root ' + identity + ' cannot be canonicalized.');
    }
    if (!isWithin(root, canonical) || seen.has(canonical)) {
      fail('package-shadow-invalid', 'Package closure root ' + identity + ' escapes the runtime root or aliases another package.');
    }
    const declaredRoot = dirname(resolveRuntimePath(root, packageCheck.packageJson));
    if (canonical !== declaredRoot) {
      fail('package-shadow-invalid', 'Package closure root ' + identity + ' does not match its manifest package metadata path.');
    }
    seen.add(canonical);
    result.set(identity, canonical);
  }
  for (const identity of packageRoots.keys()) {
    if (!expected.has(identity)) {
      fail('package-shadow-invalid', 'Package closure includes unmodeled root ' + identity + '.');
    }
  }
  return result;
};

const assertNoPnpmFallback = ({ root, manifest }) => {
  const fallbackPath = resolveRuntimePath(root, manifest.pnpmFallbackNamespace.path);
  try {
    lstatSync(fallbackPath);
  } catch {
    return;
  }
  fail(
    'pnpm-fallback-present',
    'Unmodeled pnpm fallback namespace ' + manifest.pnpmFallbackNamespace.path + ' is present.',
  );
};

const verifyStaticPnpmImporter = ({
  root,
  importer,
  importerRoot,
  packageRoots,
  rootNamespace,
  budget,
}) => {
  const namespace = resolveRuntimePath(root, importer.namespace);
  const namespaceMetadata = lstatSync(namespace);
  if (!namespaceMetadata.isDirectory() || namespaceMetadata.isSymbolicLink()) {
    fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' namespace must be a regular non-symlink directory.');
  }
  const actualEntries = new Map();
  for (const entry of staticNamespaceEntries(
    namespace,
    'Package ' + importer.id,
    rootNamespace,
    budget,
  )) {
    if (actualEntries.has(entry.specifier)) {
      fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' has duplicate namespace entry ' + entry.specifier + '.');
    }
    actualEntries.set(entry.specifier, entry.path);
  }
  const permitted = new Set(
    importer.edges
      .filter(edge => edge.state === 'present')
      .map(edge => edge.specifier),
  );
  let importerName = null;
  if (rootNamespace) {
    readPackageMetadata(importerRoot, 'Runtime root', budget);
  } else {
    const importerMetadata = readPackageMetadata(
      importerRoot,
      'Package ' + importer.id,
      budget,
    );
    if (packageIdentity(importerMetadata) !== importer.id) {
      fail('package-resolution-invalid', 'Package root ' + importerRoot + ' does not match ' + importer.id + '.');
    }
    importerName = importerMetadata.name;
    permitted.add(importerName);
  }
  for (const specifier of actualEntries.keys()) {
    if (!permitted.has(specifier)) {
      fail('package-shadow-unmodeled', 'Package ' + importer.id + ' has unmodeled pnpm dependency ' + specifier + '.');
    }
  }
  if (importerName !== null) {
    const selfPath = actualEntries.get(importerName);
    if (selfPath === undefined) {
      fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' is missing its direct self namespace entry.');
    }
    const selfMetadata = lstatSync(selfPath);
    if (!selfMetadata.isDirectory() || selfMetadata.isSymbolicLink()) {
      fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' self namespace entry must be a direct directory.');
    }
    if (realpathSync(selfPath) !== importerRoot) {
      fail('package-resolution-root-mismatch', 'Package ' + importer.id + ' self namespace entry does not resolve to its authenticated root.');
    }
  }
  const evidence = [];
  for (const edge of importer.edges) {
    const linkedPath = actualEntries.get(edge.specifier);
    const resolution = staticResolvePackageSpecifier({
      importerRoot,
      importer: importer.id,
      specifier: edge.specifier,
    });
    if (edge.state === 'absent') {
      if (linkedPath !== undefined) {
        fail('package-optional-present', 'Package ' + importer.id + ' absent edge ' + edge.specifier + ' is present.');
      }
      if (resolution.kind !== 'missing') {
        fail('package-resolution-fallback', 'Package ' + importer.id + ' absent edge ' + edge.specifier + ' resolved through an unmodeled fallback.');
      }
      evidence.push({
        importer: importer.id,
        specifier: edge.specifier,
        package: edge.target,
        resolved: null,
        resolver: 'absent',
      });
      continue;
    }
    if (linkedPath === undefined) {
      fail('package-resolution-missing', 'Package ' + importer.id + ' is missing required pnpm link ' + edge.specifier + '.');
    }
    const linkMetadata = lstatSync(linkedPath);
    if (!linkMetadata.isSymbolicLink()) {
      fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' dependency ' + edge.specifier + ' must be a direct pnpm sibling link.');
    }
    let canonicalTarget;
    try {
      canonicalTarget = realpathSync(linkedPath);
    } catch {
      fail('pnpm-namespace-invalid', 'Package ' + importer.id + ' dependency ' + edge.specifier + ' is a broken link.');
    }
    const expectedRoot = packageRoots.get(edge.target);
    if (
      expectedRoot === undefined ||
      canonicalTarget !== expectedRoot ||
      !isWithin(root, canonicalTarget)
    ) {
      fail('package-resolution-root-mismatch', 'Package ' + importer.id + ' dependency ' + edge.specifier + ' does not resolve to authenticated ' + edge.target + '.');
    }
    const targetMetadata = readPackageMetadata(
      canonicalTarget,
      'Package ' + importer.id + ' dependency ' + edge.specifier,
      budget,
    );
    if (
      targetMetadata.name !== edge.specifier ||
      packageIdentity(targetMetadata) !== edge.target
    ) {
      fail('package-specifier-mismatch', 'Package ' + importer.id + ' dependency ' + edge.specifier + ' does not match ' + edge.target + '.');
    }
    const resolutionMode = resolution.kind === 'resolved'
      ? 'create-require'
      : resolution.kind;
    if (resolutionMode !== edge.resolver) {
      fail('package-resolution-mode-mismatch', 'Package ' + importer.id + ' dependency ' + edge.specifier + ' expected ' + edge.resolver + '; got ' + resolutionMode + '.');
    }
    if (resolution.kind === 'resolved') {
      let canonicalResolved;
      try {
        canonicalResolved = realpathSync(resolution.path);
      } catch {
        fail('package-resolution-invalid', 'Package ' + importer.id + ' resolution for ' + edge.specifier + ' is broken.');
      }
      if (!isWithin(expectedRoot, canonicalResolved)) {
        fail('package-resolution-root-mismatch', 'Package ' + importer.id + ' resolution for ' + edge.specifier + ' escapes authenticated ' + edge.target + '.');
      }
      evidence.push({
        importer: importer.id,
        specifier: edge.specifier,
        package: edge.target,
        resolved: canonicalResolved,
        resolver: edge.resolver,
      });
      continue;
    }
    evidence.push({
      importer: importer.id,
      specifier: edge.specifier,
      package: edge.target,
      resolved: canonicalTarget,
      resolver: edge.resolver,
    });
  }
  return evidence;
};

const verifyPnpmResolutionGraphLegacy = ({ root: requestedRoot, packageRoots, budget }) => {
  const activeBudget = activeVerificationBudget(budget);
  if (!(packageRoots instanceof Map) || packageRoots.size === 0) {
    fail('package-shadow-invalid', 'Package closure roots must be a non-empty Map.');
  }
  const root = canonicalRoot(requestedRoot);
  const canonicalPackageRoots = new Map();
  const seenRoots = new Set();
  for (const [identity, packageRoot] of packageRoots) {
    if (typeof identity !== 'string' || typeof packageRoot !== 'string') {
      fail('package-shadow-invalid', 'Package closure roots must use string identities and paths.');
    }
    let canonicalPackageRoot;
    try {
      canonicalPackageRoot = realpathSync(packageRoot);
    } catch {
      fail('package-shadow-invalid', `Package closure root ${identity} cannot be canonicalized.`);
    }
    if (!isWithin(root, canonicalPackageRoot) || seenRoots.has(canonicalPackageRoot)) {
      fail('package-shadow-invalid', `Package closure root ${identity} escapes the runtime root or aliases another package.`);
    }
    seenRoots.add(canonicalPackageRoot);
    canonicalPackageRoots.set(identity, canonicalPackageRoot);
  }
  return [...canonicalPackageRoots.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([identity, packageRoot]) =>
      verifyPnpmNamespace({
        root,
        importerIdentity: identity,
        importerRoot: packageRoot,
        packageRoots: canonicalPackageRoots,
        budget: activeBudget,
      }),
    );
};

const verifyPnpmResolutionGraphWithBudget = ({
  root: requestedRoot,
  packageRoots,
  manifest,
}, budget) => {
  if (!isRecord(manifest)) {
    fail(
      'package-shadow-invalid',
      'A validated runtime manifest is required for pnpm graph verification.',
    );
  }
  const activeBudget = budget;
  const root = canonicalRoot(requestedRoot);
  const canonicalRoots = canonicalStaticPackageRoots({
    root,
    packageRoots,
    manifest,
  });
  assertNoPnpmFallback({ root, manifest });
  return manifest.pnpmImporters.flatMap(importer => {
    const rootNamespace = importer.id === 'runtime-root';
    const importerRoot = rootNamespace ? root : canonicalRoots.get(importer.id);
    if (importerRoot === undefined) {
      fail('package-shadow-invalid', 'Importer ' + importer.id + ' has no authenticated package root.');
    }
    return verifyStaticPnpmImporter({
      root,
      importer,
      importerRoot,
      packageRoots: canonicalRoots,
      rootNamespace,
      budget: activeBudget,
    });
  });
};

export const verifyPnpmResolutionGraph = options =>
  verifyPnpmResolutionGraphWithBudget(options, createVerificationBudget());

// Kept as a compatibility export for callers that previously requested the
// package-shadow check. It now authenticates every pnpm importer namespace,
// every sibling link, and every execution-free Node resolution edge.
export const verifyPackageClosureShadows = options => verifyPnpmResolutionGraph(options);

const verifyNpmPackage = (root, analyzer, packageCheck, packageRoots, budget) => {
  const metadata = ensureFile(root, packageCheck.packageJson, analyzer.analyzer, 'package-metadata', {
    allowPnpmLinks: true,
    maximumBytes: runtimeVerificationBounds.textBytes,
    budget,
  });
  const decoded = parseBoundedJson({
    bytes: readBoundedRegularFile({
      path: metadata.canonicalPath,
      label: `Analyzer "${analyzer.analyzer}" package metadata "${packageCheck.packageJson}"`,
      maximumBytes: runtimeVerificationBounds.textBytes,
      budget,
      invalidCode: 'package-metadata-invalid',
      hardlinkCode: 'hardlink-rejected',
      oversizeCode: 'package-metadata-oversize',
      changedCode: 'package-metadata-changed',
      missingCode: 'package-metadata-invalid',
    }),
    label: `Analyzer "${analyzer.analyzer}" package metadata "${packageCheck.packageJson}"`,
    code: 'package-metadata',
    budget,
    invalidCode: 'package-metadata-invalid',
  });
  if (decoded.name !== packageCheck.name || decoded.version !== packageCheck.version) {
    fail('version-mismatch', `Analyzer "${analyzer.analyzer}" expected package ${packageCheck.name}@${packageCheck.version}; got ${String(decoded.name)}@${String(decoded.version)}.`);
  }
  const packageRoot = dirname(metadata.canonicalPath);
  assertPackageTreeSha256WithBudget({
    analyzer: analyzer.analyzer,
    packageName: `${packageCheck.name}@${packageCheck.version}`,
    packageRoot,
    expectedSha256: packageCheck.treeSha256,
  }, budget);
  const identity = packageCheck.name + '@' + packageCheck.version;
  if (packageRoots.has(identity)) {
    fail(
      'package-duplicate',
      'Analyzer "' + analyzer.analyzer + '" repeats authenticated package ' + identity + '.',
    );
  }
  packageRoots.set(identity, packageRoot);
};

const verifyResolutionPaths = (root, analyzer, packageCheck, packageRoots, budget) => {
  if (packageCheck.source !== 'npm') return;
  const packageRoot = packageRoots.get(`${packageCheck.name}@${packageCheck.version}`);
  for (const relativePath of packageCheck.resolutionPaths) {
    const file = ensureFile(root, relativePath, analyzer.analyzer, 'resolution-path', {
      allowPnpmLinks: true,
      budget,
    });
    if (!isWithin(packageRoot, file.canonicalPath)) {
      fail('resolution-mismatch', `Analyzer "${analyzer.analyzer}" resolution path "${relativePath}" does not resolve into ${packageCheck.name}@${packageCheck.version}.`);
    }
  }
};

const verifyLauncher = (root, analyzer, launcher, packageRoots, budget) => {
  const { candidate } = inspectPathComponents(root, launcher.path, true);
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    fail('launcher-missing', `Analyzer "${analyzer.analyzer}" launcher "${launcher.path}" is missing.`);
  }
  if (!metadata.isSymbolicLink()) {
    fail('launcher-invalid', `Analyzer "${analyzer.analyzer}" launcher "${launcher.path}" must be a direct in-root symlink, not a package-manager script stub.`);
  }
  const target = ensureFile(root, launcher.target, analyzer.analyzer, 'launcher-target', {
    allowPnpmLinks: true,
    budget,
  });
  const resolved = realpathSync(candidate);
  if (!isWithin(root, resolved)) {
    fail('path-escape', `Analyzer "${analyzer.analyzer}" launcher "${launcher.path}" resolves outside the runtime root.`);
  }
  if (resolved !== target.canonicalPath) {
    fail('launcher-mismatch', `Analyzer "${analyzer.analyzer}" launcher "${launcher.path}" does not resolve to "${launcher.target}".`);
  }
  if (![...packageRoots.values()].some(packageRoot => isWithin(packageRoot, resolved))) {
    fail('resolution-unmodeled', `Analyzer "${analyzer.analyzer}" launcher "${launcher.path}" resolves outside the declared package closure.`);
  }
};

export const assertExactNativeMode = ({ analyzer, path, mode }) => {
  if ((mode & 0o7777) !== 0o755) {
    fail('native-mode-invalid', `Analyzer "${analyzer}" native executable "${path}" must have mode 0755.`);
  }
};

const verifyNativeMode = (root, analyzer, path, budget) => {
  const file = ensureFile(root, path, analyzer.analyzer, 'native-executable', {
    allowPnpmLinks: path.startsWith('node_modules/'),
    budget,
  });
  assertExactNativeMode({
    analyzer: analyzer.analyzer,
    path,
    mode: file.fileStat.mode,
  });
};

export const normalizeProbeOutput = output =>
  output.replace(/\r\n/gu, '\n').replace(/\r/gu, '\n').replace(/\n$/u, '');

export const assertExactVersionOutput = ({ analyzer, expectedOutput, actualOutput }) => {
  const normalized = normalizeProbeOutput(actualOutput);
  if (normalized !== expectedOutput) {
    fail('version-mismatch', `Analyzer "${analyzer}" expected exact normalized version output "${expectedOutput}"; got "${normalized || 'no version output'}".`);
  }
  return normalized;
};

export const minimalProbeEnvironment = temporaryHome => {
  const environment = {
    HOME: temporaryHome,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    PATH: '',
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_ignore_scripts: 'true',
    npm_config_offline: 'true',
    npm_config_update_notifier: 'false',
  };
  for (const key of Object.keys(environment)) {
    if (forbiddenEnvironmentPattern.test(key)) {
      fail('probe-environment-invalid', `Probe environment contains forbidden variable ${key}.`);
    }
  }
  return environment;
};

export const evaluateProbeResult = ({ analyzer, path, contract, result }) => {
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  const outputBytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
  if (result.error?.code === 'ETIMEDOUT') {
    fail('probe-timeout', `Analyzer "${analyzer}" command "${path}" exceeded ${contract.timeoutMs}ms.`);
  }
  if (result.error?.code === 'ENOBUFS' || outputBytes > contract.maxOutputBytes) {
    fail('probe-output-limit', `Analyzer "${analyzer}" command "${path}" exceeded ${contract.maxOutputBytes} output bytes.`);
  }
  if (result.error !== undefined) {
    fail('probe-command-failed', `Analyzer "${analyzer}" command "${path}" could not start: ${result.error.message}.`);
  }
  if ((result.signal ?? null) !== contract.expectedSignal) {
    fail('probe-signal-mismatch', `Analyzer "${analyzer}" command "${path}" expected signal ${String(contract.expectedSignal)}; got ${String(result.signal ?? null)}.`);
  }
  if (result.status !== contract.expectedStatus) {
    fail('probe-status-mismatch', `Analyzer "${analyzer}" command "${path}" expected status ${contract.expectedStatus}; got ${String(result.status)}.`);
  }
  return { stdout: normalizeProbeOutput(stdout), output: normalizeProbeOutput(`${stdout}${stderr}`) };
};

const hostIsolationProbeEnvironment = Object.freeze({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '',
});

const assertBoundedHostProbe = ({ name, result, limit }) => {
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  if (result.error?.code === 'ETIMEDOUT') {
    fail('host-isolation-probe-timeout', `${name} exceeded its bounded timeout.`);
  }
  if (
    result.error?.code === 'ENOBUFS' ||
    Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > limit
  ) {
    fail('host-isolation-probe-output-limit', `${name} exceeded its output limit.`);
  }
  if (result.error !== undefined) {
    fail('host-isolation-probe-failed', `${name} could not start: ${result.error.message}.`);
  }
  if (result.signal !== null || result.status !== 0) {
    fail(
      'host-isolation-probe-failed',
      `${name} exited with status ${String(result.status)} and signal ${String(result.signal)}: ${normalizeProbeOutput(stderr)}`,
    );
  }
  return { stdout: normalizeProbeOutput(stdout), stderr: normalizeProbeOutput(stderr) };
};

// The runtime must not silently fall back to direct Node execution. This is a
// host capability check, deliberately separate from the seven analyzers.
export const verifyRequiredHostIsolation = ({
  hostIsolation = requiredHostIsolation,
} = {}) => {
  const isolation = validateHostIsolation(hostIsolation, 'hostIsolation');
  if (process.platform !== 'linux') {
    fail(
      'host-isolation-required',
      `Required ${isolation.kind} isolation is only available on Linux; current host is ${process.platform}.`,
    );
  }
  let metadata;
  try {
    metadata = lstatSync(isolation.path);
  } catch {
    fail('host-isolation-missing', `Required host isolation binary ${isolation.path} is missing.`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail(
      'host-isolation-invalid',
      `Required host isolation binary ${isolation.path} must be an independently linked regular non-symlink file.`,
    );
  }
  if (Number(metadata.uid) !== 0 || (metadata.mode & 0o7777) !== 0o755) {
    fail(
      'host-isolation-invalid',
      `Required host isolation binary ${isolation.path} must be root-owned with exact mode 0755.`,
    );
  }
  if (realpathSync(isolation.path) !== isolation.path) {
    fail('host-isolation-invalid', `Required host isolation binary ${isolation.path} must resolve to itself.`);
  }
  const version = assertBoundedHostProbe({
    name: `${isolation.path} --version`,
    result: spawnSync(isolation.path, ['--version'], {
      encoding: 'utf8',
      env: hostIsolationProbeEnvironment,
      killSignal: 'SIGKILL',
      maxBuffer: 4_096,
      timeout: 5_000,
      windowsHide: true,
    }),
    limit: 4_096,
  });
  if (version.stdout !== isolation.versionOutput || version.stderr !== '') {
    fail(
      'host-isolation-version-invalid',
      `Required host isolation binary ${isolation.path} must return exactly ${isolation.versionOutput}; got ${version.stdout || 'no version output'}.`,
    );
  }
  assertBoundedHostProbe({
    name: `${isolation.path} strict namespace probe`,
    result: spawnSync(isolation.path, requiredBubblewrapProbeArguments, {
      encoding: 'utf8',
      env: hostIsolationProbeEnvironment,
      killSignal: 'SIGKILL',
      maxBuffer: 8_192,
      timeout: 5_000,
      windowsHide: true,
    }),
    limit: 8_192,
  });
  return {
    kind: isolation.kind,
    path: isolation.path,
    // This package version is reviewed build provenance, not a runtime trust
    // decision. Raw host-tool anchoring occurs at the resource-governance
    // boundary; dpkg-query is intentionally never in the runtime TCB.
    packageVersion: isolation.packageVersion,
    version: version.stdout,
    strictProbe: 'passed',
  };
};

const sandboxRuntimeRoot = '/runtime';
const sandboxProbeHome = '/tmp/home';
const sandboxProbeEnvironmentKeys = Object.freeze([
  'CALLDIFF_GRAMMAR_CACHE',
  'HOME',
  'LANG',
  'LC_ALL',
  'NO_COLOR',
  'OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY',
  'PATH',
  'npm_config_audit',
  'npm_config_fund',
  'npm_config_ignore_scripts',
  'npm_config_offline',
  'npm_config_update_notifier',
]);

export const buildSandboxProbeArguments = ({ root, contract, environment }) => {
  const sandboxEnvironment = {
    ...environment,
    HOME: sandboxProbeHome,
    PATH: `${sandboxRuntimeRoot}/bin:/usr/bin:/bin`,
    ...(environment.CALLDIFF_GRAMMAR_CACHE === undefined
      ? {}
      : { CALLDIFF_GRAMMAR_CACHE: '/tmp/grammar-cache' }),
  };
  const unsupported = Object.keys(sandboxEnvironment).filter(
    key => !sandboxProbeEnvironmentKeys.includes(key),
  );
  if (unsupported.length > 0) {
    fail(
      'probe-environment-invalid',
      `Sandbox probe environment contains unsupported keys: ${unsupported.sort().join(', ')}.`,
    );
  }
  const environmentArguments = Object.entries(sandboxEnvironment)
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([key, value]) => ['--setenv', key, value]);
  const mapArgument = argument => {
    if (typeof argument !== 'string') {
      fail('probe-command-invalid', 'Sandbox probe arguments must be strings.');
    }
    if (argument === root) return sandboxRuntimeRoot;
    if (argument.startsWith(`${root}${sep}`)) {
      return `${sandboxRuntimeRoot}/${relative(root, argument).split(sep).join('/')}`;
    }
    return argument;
  };
  const executable = contract.runner === 'node'
    ? process.execPath
    : `${sandboxRuntimeRoot}/${contract.path}`;
  const arguments_ = contract.runner === 'node'
    ? [`${sandboxRuntimeRoot}/${contract.path}`, ...contract.args.map(mapArgument)]
    : contract.args.map(mapArgument);
  return [
    '--unshare-all',
    '--die-with-parent',
    '--new-session',
    '--clearenv',
    '--proc',
    '/proc',
    '--dev',
    '/dev',
    '--ro-bind',
    '/usr',
    '/usr',
    '--ro-bind-try',
    '/bin',
    '/bin',
    '--ro-bind-try',
    '/lib',
    '/lib',
    '--ro-bind-try',
    '/lib64',
    '/lib64',
    '--ro-bind',
    root,
    sandboxRuntimeRoot,
    '--tmpfs',
    '/tmp',
    '--dir',
    sandboxProbeHome,
    '--chdir',
    sandboxRuntimeRoot,
    ...environmentArguments,
    executable,
    ...arguments_,
  ];
};

const spawnBounded = ({ root, analyzer, contract, environment }) => {
  const file = ensureFile(root, contract.path, analyzer.analyzer, 'probe-command', {
    allowPnpmLinks: contract.path.startsWith('node_modules/'),
  });
  if (contract.runner === 'direct') {
    assertExactNativeMode({
      analyzer: analyzer.analyzer,
      path: contract.path,
      mode: file.fileStat.mode,
    });
  }
  const result = spawnSync(
    requiredHostIsolation.path,
    buildSandboxProbeArguments({ root, contract, environment }),
    {
      cwd: '/',
      encoding: 'utf8',
      env: hostIsolationProbeEnvironment,
      killSignal: 'SIGKILL',
      maxBuffer: contract.maxOutputBytes,
      timeout: contract.timeoutMs,
      windowsHide: true,
    },
  );
  return evaluateProbeResult({
    analyzer: analyzer.analyzer,
    path: contract.path,
    contract,
    result,
  });
};

const verifyVersionCommand = (root, analyzer, command, temporaryHome) => {
  const result = spawnBounded({
    root,
    analyzer,
    contract: command,
    environment: minimalProbeEnvironment(temporaryHome),
  });
  return assertExactVersionOutput({
    analyzer: analyzer.analyzer,
    expectedOutput: command.expectedOutput,
    actualOutput: result.output,
  });
};

const parseSmokeJson = (analyzer, stdout) => {
  try {
    return JSON.parse(stdout);
  } catch (error) {
    fail('smoke-invalid-output', `Analyzer "${analyzer.analyzer}" smoke output is not JSON: ${error instanceof Error ? error.message : String(error)}.`);
  }
};

const verifyCalldiffSmoke = (root, analyzer, smoke, temporaryHome) => {
  const fixture = ensureDirectory(root, smoke.fixture, 'smoke-fixture');
  const result = spawnBounded({
    root,
    analyzer,
    contract: { ...smoke, args: [fixture] },
    environment: {
      ...minimalProbeEnvironment(temporaryHome),
      CALLDIFF_GRAMMAR_CACHE: join(temporaryHome, 'grammar-cache'),
    },
  });
  const report = parseSmokeJson(analyzer, result.stdout);
  const expected = smoke.expected;
  const mismatches = [];
  if (report.schemaVersion !== expected.schemaVersion) mismatches.push(`schema ${String(report.schemaVersion)}`);
  if (report.calldiffVersion !== expected.analyzerVersion) mismatches.push(`version ${String(report.calldiffVersion)}`);
  if (report.eligibleFiles !== expected.eligibleFiles) mismatches.push(`eligibleFiles ${String(report.eligibleFiles)}`);
  if (report.analyzedFiles !== expected.analyzedFiles) mismatches.push(`analyzedFiles ${String(report.analyzedFiles)}`);
  if (!Array.isArray(report.failedFiles) || report.failedFiles.length !== expected.failedFiles) {
    mismatches.push(`failedFiles ${String(report.failedFiles?.length)}`);
  }
  if (!Number.isInteger(report.functionCount) || report.functionCount < expected.minimumFunctions) {
    mismatches.push(`functionCount ${String(report.functionCount)}`);
  }
  if (mismatches.length > 0) {
    fail('smoke-mismatch', `Analyzer "${analyzer.analyzer}" offline smoke mismatch: ${mismatches.join(', ')}.`);
  }
  return `offline JS/TS/TSX smoke: ${report.analyzedFiles}/${report.eligibleFiles} files, ${report.functionCount} functions`;
};

const verifyOsvSmoke = (root, analyzer, smoke, temporaryHome) => {
  ensureDirectory(root, smoke.fixture, 'smoke-fixture');
  const config = `${smoke.fixture}/osv-scanner.toml`;
  ensureFile(root, config, analyzer.analyzer, 'smoke-config');
  const runLockfile = (relativeLockfile, expectedStatus) => {
    const lockfile = `${smoke.fixture}/${relativeLockfile}`;
    ensureFile(root, lockfile, analyzer.analyzer, 'smoke-lockfile');
    return parseSmokeJson(analyzer, spawnBounded({
      root,
      analyzer,
      contract: {
        ...smoke,
        expectedStatus,
        args: [
          'scan',
          'source',
          '--offline',
          '--local-db-path=/runtime/databases/osv',
          '--format=json',
          '--verbosity=error',
          '--no-resolve',
          '--config',
          join(root, config),
          '-L',
          join(root, lockfile),
        ],
      },
      environment: {
        ...minimalProbeEnvironment(temporaryHome),
        OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY: '/runtime/databases/osv',
      },
    }).stdout);
  };
  const vulnerable = runLockfile(smoke.expected.vulnerableLockfile, 1);
  const clean = runLockfile(smoke.expected.cleanLockfile, 0);
  const vulnerabilityIds = new Set();
  for (const result of Array.isArray(vulnerable.results) ? vulnerable.results : []) {
    for (const package_ of Array.isArray(result?.packages) ? result.packages : []) {
      for (const group of Array.isArray(package_?.groups) ? package_.groups : []) {
        for (const id of Array.isArray(group?.ids) ? group.ids : []) {
          if (typeof id === 'string') vulnerabilityIds.add(id);
        }
      }
      for (const vulnerability of Array.isArray(package_?.vulnerabilities)
        ? package_.vulnerabilities
        : []) {
        if (typeof vulnerability?.id === 'string') vulnerabilityIds.add(vulnerability.id);
      }
    }
  }
  if (!vulnerabilityIds.has(smoke.expected.requiredVulnerabilityId)) {
    fail(
      'smoke-mismatch',
      `Analyzer "${analyzer.analyzer}" offline vulnerable fixture omitted ${smoke.expected.requiredVulnerabilityId}.`,
    );
  }
  if (!Array.isArray(clean.results) || clean.results.length !== 0) {
    fail('smoke-mismatch', `Analyzer "${analyzer.analyzer}" offline clean fixture reported vulnerabilities.`);
  }
  return `offline npm smoke: ${vulnerabilityIds.size} vulnerability identifiers, clean fixture empty`;
};

const verifySmoke = (root, analyzer, smoke, temporaryHome) =>
  smoke.kind === 'calldiff-report/v1'
    ? verifyCalldiffSmoke(root, analyzer, smoke, temporaryHome)
    : verifyOsvSmoke(root, analyzer, smoke, temporaryHome);

const verifyManagedBinaryDirectory = (root, manifest, platforms, budget) => {
  const expectedPaths = [
    manifest.runtimeNode.path,
    manifest.semanticRunner.path,
    ...platforms.flatMap(platform =>
      platform.download === null ? [] : [platform.download.output],
    ),
  ];
  if (expectedPaths.some(path => posix.dirname(path) !== manifest.managedBinaryDirectory)) {
    fail(
      'managed-binary-path-invalid',
      `Every managed runtime executable must be a direct child of "${manifest.managedBinaryDirectory}".`,
    );
  }
  const expected = expectedPaths
    .map(path => posix.basename(path))
    .sort((left, right) => left.localeCompare(right));
  if (
    expected.length !== requiredManagedBinaryEntries.length ||
    expected.some((entry, index) => entry !== requiredManagedBinaryEntries[index])
  ) {
    fail(
      'managed-binary-inventory-invalid',
      'The manifest must declare exactly node, the semantic runner, tracedecay, zizmor, and osv-scanner in its managed bin directory.',
    );
  }
  if (new Set(expected).size !== expected.length) {
    fail('managed-binary-duplicate', 'Managed runtime executable paths must be unique.');
  }
  const directory = ensureDirectory(root, manifest.managedBinaryDirectory, 'native-directory');
  const entries = boundedDirectoryEntries({
    directory,
    label: `managed binary directory ${manifest.managedBinaryDirectory}`,
    budget,
    entryCode: 'native-directory-invalid',
    entryLimitCode: 'native-directory-entry-limit',
  });
  const actual = entries.map(entry => entry.name);
  const extras = actual.filter(name => !expected.includes(name));
  if (extras.length > 0) {
    fail('unexpected-native-tool', `Unmanaged native entries in "${manifest.managedBinaryDirectory}": ${extras.join(', ')}.`);
  }
  const missing = expected.filter(name => !actual.includes(name));
  if (missing.length > 0) {
    fail('native-tool-missing', `Managed native executables missing: ${missing.join(', ')}.`);
  }
  for (const entry of entries) {
    boundedRegularMetadata({
      path: join(directory, entry.name),
      label: `Managed native entry "${entry.name}"`,
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
      invalidCode: 'native-directory-invalid',
      hardlinkCode: 'native-directory-invalid',
      oversizeCode: 'native-directory-oversize',
      missingCode: 'native-directory-invalid',
    });
  }
};

const lockIntegrityEntries = (lockText, budget) => {
  const packagesStart = lockText.indexOf('\npackages:\n');
  const snapshotsStart = lockText.indexOf('\nsnapshots:\n');
  if (packagesStart < 0 || snapshotsStart < 0 || snapshotsStart <= packagesStart) {
    fail('integrity-evidence-invalid', 'pnpm lockfile has no packages section.');
  }
  const records = new Map();
  let key;
  let integrity;
  const commit = () => {
    if (key !== undefined && integrity !== undefined) records.set(key, integrity);
  };
  const packages = lockText.slice(packagesStart, snapshotsStart);
  let lineStart = 0;
  while (lineStart <= packages.length) {
    assertBudgetDeadline(budget, 'parsing pnpm lock integrity evidence');
    reserveVerificationEntry(budget, 'parsing pnpm lock integrity evidence');
    const lineEnd = packages.indexOf('\n', lineStart);
    const line = packages.slice(lineStart, lineEnd < 0 ? packages.length : lineEnd);
    lineStart = lineEnd < 0 ? packages.length + 1 : lineEnd + 1;
    const header = line.match(/^  (?:'([^']+)'|([^:\s][^:]*)):\s*$/u);
    if (header) {
      commit();
      key = header[1] ?? header[2];
      integrity = undefined;
      continue;
    }
    if (key !== undefined) {
      const match = line.match(/^    resolution: \{integrity: ([^,}]+)(?:,[^}]*)?\}$/u);
      if (match) integrity = match[1];
    }
  }
  commit();
  return records;
};

export const verifyNpmSourceIntegrityEvidence = (manifestValue, lockPath) => {
  if (typeof lockPath !== 'string' || !isAbsolute(lockPath)) {
    fail('integrity-evidence-missing', 'A trusted absolute pnpm lockfile path is required.');
  }
  const budget = createVerificationBudget();
  const bytes = readBoundedRegularFile({
    path: lockPath,
    label: 'Trusted pnpm lockfile',
    maximumBytes: runtimeVerificationBounds.textBytes,
    budget,
    invalidCode: 'integrity-evidence-invalid',
    hardlinkCode: 'integrity-evidence-invalid',
    oversizeCode: 'integrity-evidence-oversize',
    changedCode: 'integrity-evidence-changed',
    missingCode: 'integrity-evidence-missing',
  });
  const entries = lockIntegrityEntries(bytes.toString('utf8'), budget);
  const manifest = validateRuntimeManifest(manifestValue);
  for (const [exactKey, packageCheck] of npmPackageMap(manifest)) {
    const candidates = [...entries.entries()].filter(
      ([key]) => key === exactKey || key.startsWith(`${exactKey}(`),
    );
    if (candidates.length !== 1 || candidates[0][1] !== packageCheck.sourceIntegrity) {
      fail(
        'source-integrity-mismatch',
        `Authenticated package ${exactKey} does not match trusted pnpm lock evidence.`,
      );
    }
  }
};

const validateBundledIntegrityEvidence = (value, manifest) => {
  const evidence = requireRecord(value, 'pnpm integrity evidence');
  requireExactKeys(evidence, ['schemaVersion', 'packages'], 'pnpm integrity evidence');
  if (evidence.schemaVersion !== 'codebase-radar.pnpm-integrity-evidence/v1') {
    fail('integrity-evidence-invalid', 'Bundled pnpm integrity evidence has an unsupported schema version.');
  }
  const expected = npmPackageMap(manifest);
  const packages = requireArray(evidence.packages, 'pnpm integrity evidence.packages');
  if (packages.length !== expected.size) {
    fail('integrity-evidence-invalid', 'Bundled pnpm integrity evidence does not cover every authenticated package.');
  }
  const expectedIdentities = [...expected.keys()].sort((left, right) => left.localeCompare(right));
  const actualIdentities = [];
  for (let index = 0; index < packages.length; index += 1) {
    const entry = requireRecord(packages[index], `pnpm integrity evidence.packages[${index}]`);
    requireExactKeys(entry, ['name', 'version', 'sourceIntegrity'], `pnpm integrity evidence.packages[${index}]`);
    requireToken(entry.name, `pnpm integrity evidence.packages[${index}].name`);
    requireToken(entry.version, `pnpm integrity evidence.packages[${index}].version`);
    requireIntegrity(entry.sourceIntegrity, `pnpm integrity evidence.packages[${index}].sourceIntegrity`);
    const identity = `${entry.name}@${entry.version}`;
    const packageCheck = expected.get(identity);
    if (packageCheck === undefined || packageCheck.sourceIntegrity !== entry.sourceIntegrity) {
      fail('integrity-evidence-mismatch', `Bundled pnpm integrity evidence does not match authenticated package ${identity}.`);
    }
    actualIdentities.push(identity);
  }
  if (
    actualIdentities.some((identity, index) => identity !== expectedIdentities[index])
  ) {
    fail('integrity-evidence-invalid', 'Bundled pnpm integrity evidence packages must be unique and canonical-order sorted.');
  }
  return evidence;
};

const verifyBundledNpmSourceIntegrityEvidenceWithBudget = ({ root, manifest }, budget) => {
  const evidenceFile = ensureFile(
    root,
    manifest.pnpmIntegrityEvidence.path,
    'Analyzer runtime',
    'pnpm-integrity-evidence',
    {
      maximumBytes: runtimeVerificationBounds.textBytes,
      budget,
    },
  );
  const bytes = readBoundedRegularFile({
    path: evidenceFile.canonicalPath,
    label: 'Bundled pnpm integrity evidence',
    maximumBytes: runtimeVerificationBounds.textBytes,
    budget,
    invalidCode: 'integrity-evidence-invalid',
    hardlinkCode: 'hardlink-rejected',
    oversizeCode: 'integrity-evidence-oversize',
    changedCode: 'integrity-evidence-changed',
    missingCode: 'integrity-evidence-invalid',
  });
  const actualSha256 = sha256Text(bytes);
  if (actualSha256 !== manifest.pnpmIntegrityEvidence.sha256) {
    fail(
      'integrity-evidence-checksum-mismatch',
      `Bundled pnpm integrity evidence expected sha256 ${manifest.pnpmIntegrityEvidence.sha256}; got ${actualSha256}.`,
    );
  }
  const decoded = parseBoundedJson({
    bytes,
    label: 'Bundled pnpm integrity evidence',
    code: 'integrity-evidence',
    budget,
    invalidCode: 'integrity-evidence-invalid',
  });
  return validateBundledIntegrityEvidence(decoded, manifest);
};

export const verifyBundledNpmSourceIntegrityEvidence = options =>
  verifyBundledNpmSourceIntegrityEvidenceWithBudget(options, createVerificationBudget());

export const getRuntimePreparationPlan = (manifestValue, target) => {
  const manifest = validateRuntimeManifest(manifestValue);
  const outputs = new Set();
  const plan = [];
  for (const analyzer of manifest.analyzers) {
    const platform = selectPlatform(analyzer, target);
    if (platform.download === null) continue;
    if (!platform.download.output.startsWith(`${manifest.managedBinaryDirectory}/`)) {
      fail('manifest-schema', `Analyzer "${analyzer.analyzer}" download output must be inside "${manifest.managedBinaryDirectory}".`);
    }
    if (outputs.has(platform.download.output)) {
      fail('download-output-duplicate', `Download output "${platform.download.output}" is owned more than once.`);
    }
    outputs.add(platform.download.output);
    plan.push({ analyzerId: analyzer.id, ...platform.download });
  }
  return plan;
};

// This phase is deliberately execution-free.  It lets deployment checks prove
// that a staged layout is complete before the Linux-only canaries are allowed
// to start, and lets non-Linux hosts inspect the static boundary without
// claiming native acceptance.
export const verifyRuntimeIdentity = ({
  root: requestedRoot,
  target = linuxX64Glibc,
}) => {
  const budget = createVerificationBudget();
  const root = canonicalRoot(requestedRoot);
  const manifest = readRuntimeManifestWithBudget(
    resolveRuntimePath(root, 'runtime-manifest.json'),
    budget,
  );
  const selectedPlatforms = manifest.analyzers.map(analyzer => selectPlatform(analyzer, target));

  // The root importer is part of the static graph. Authenticate its control
  // bytes before createRequire can inspect package.json for any resolution.
  const checksumCache = new Map();
  const controlAnalyzer = { analyzer: 'Analyzer runtime' };
  for (const controlFile of manifest.controlFiles) {
    verifyChecksum(root, controlAnalyzer, controlFile, checksumCache, new Map(), budget);
  }
  verifyBundledNpmSourceIntegrityEvidenceWithBudget({ root, manifest }, budget);
  const semanticRunner = ensureFile(
    root,
    manifest.semanticRunner.path,
    'Semantic analyzer runner',
    'entrypoint',
    { budget },
  );
  verifyChecksum(
    root,
    { analyzer: 'Semantic analyzer runner' },
    manifest.semanticRunner,
    checksumCache,
    new Map(),
    budget,
  );
  const runtimeNode = ensureFile(
    root,
    manifest.runtimeNode.path,
    'Analyzer runtime Node',
    'runtime-node',
    { budget },
  );
  verifyChecksum(
    root,
    { analyzer: 'Analyzer runtime Node' },
    manifest.runtimeNode,
    checksumCache,
    new Map(),
    budget,
  );
  assertExactNativeMode({
    analyzer: 'Analyzer runtime Node',
    path: manifest.runtimeNode.path,
    mode: runtimeNode.fileStat.mode,
  });
  const osvValidator = ensureFile(
    root,
    manifest.offlineOsvDatabase.validator.path,
    'Offline OSV database',
    'osv-snapshot-validator',
    { maximumBytes: runtimeVerificationBounds.textBytes, budget },
  );
  if (osvValidator.fileStat.size !== manifest.offlineOsvDatabase.validator.byteLength) {
    fail('osv-validator-size-mismatch', 'The trusted OSV snapshot validator does not have its pinned byte length.');
  }
  const actualOsvValidatorSha256 = sha256File(osvValidator.canonicalPath, {
    label: 'Offline OSV snapshot validator',
    maximumBytes: runtimeVerificationBounds.textBytes,
    budget,
    invalidCode: 'osv-snapshot-validator-invalid',
    hardlinkCode: 'hardlink-rejected',
    oversizeCode: 'osv-snapshot-validator-oversize',
    changedCode: 'osv-snapshot-validator-changed',
  });
  if (actualOsvValidatorSha256 !== manifest.offlineOsvDatabase.validator.sha256) {
    fail('osv-validator-checksum-mismatch', 'The trusted OSV snapshot validator does not match its pinned SHA-256.');
  }
  const offlineOsvDatabase = ensureFile(
    root,
    manifest.offlineOsvDatabase.path,
    'Offline OSV database',
    'offline-osv-database',
    { budget },
  );
  if (offlineOsvDatabase.fileStat.size !== manifest.offlineOsvDatabase.size) {
    fail('osv-database-size-mismatch', 'The offline OSV database does not have its pinned byte length.');
  }
  verifyChecksum(
    root,
    { analyzer: 'Offline OSV database' },
    manifest.offlineOsvDatabase,
    checksumCache,
    new Map(),
    budget,
  );
  assertOfflineOsvDatabaseFresh(manifest.offlineOsvDatabase);
  for (const packageEntry of manifest.semanticRunner.bundledPackages) {
    verifyChecksum(
      root,
      { analyzer: `Semantic runner dependency ${packageEntry.name}` },
      packageEntry.licenseFile,
      checksumCache,
      new Map(),
      budget,
    );
  }

  const packageRoots = new Map();
  for (const analyzer of manifest.analyzers) {
    for (const packageCheck of analyzer.packages) {
      if (packageCheck.source === 'npm') {
        verifyNpmPackage(root, analyzer, packageCheck, packageRoots, budget);
      }
    }
  }
  // Authenticate every manifest-pinned pnpm importer namespace and resolution
  // edge before accepting any executable resolution path or launcher.
  verifyPnpmResolutionGraphWithBudget({ root, packageRoots, manifest }, budget);
  for (const analyzer of manifest.analyzers) {
    for (const packageCheck of analyzer.packages) {
      verifyResolutionPaths(root, analyzer, packageCheck, packageRoots, budget);
    }
  }

  for (let index = 0; index < manifest.analyzers.length; index += 1) {
    const analyzer = manifest.analyzers[index];
    const platform = selectedPlatforms[index];
    ensureFile(root, platform.entrypoint, analyzer.analyzer, 'entrypoint', {
      allowPnpmLinks: platform.entrypoint.startsWith('node_modules/'),
      budget,
    });
    verifyChecksum(root, analyzer, analyzer.licenseNotice, checksumCache, packageRoots, budget);
    for (const legalFile of analyzer.legalFiles) {
      verifyChecksum(root, analyzer, legalFile, checksumCache, packageRoots, budget);
    }
    for (const checksum of platform.checksums) {
      verifyChecksum(root, analyzer, checksum, checksumCache, packageRoots, budget);
    }
    for (const nativePath of platform.nativeExecutables) {
      verifyNativeMode(root, analyzer, nativePath, budget);
    }
    for (const launcher of platform.launchers) {
      verifyLauncher(root, analyzer, launcher, packageRoots, budget);
    }
  }
  verifyManagedBinaryDirectory(root, manifest, selectedPlatforms, budget);

  return { root, manifest, selectedPlatforms, semanticRunner };
};

export const verifyRuntime = ({ root: requestedRoot, target = detectRuntimePlatform() }) => {
  const host = detectRuntimePlatform();
  if (platformKey(host) !== expectedPlatformKey) {
    fail(
      'linux-acceptance-required',
      `Native analyzer acceptance must run on ${expectedPlatformKey}; current host is ${platformKey(host)}.`,
    );
  }
  const { root, manifest, selectedPlatforms } = verifyRuntimeIdentity({
    root: requestedRoot,
    target,
  });
  const hostIsolation = verifyRequiredHostIsolation({
    hostIsolation: manifest.hostIsolation,
  });

  const temporaryHome = mkdtempSync(join(tmpdir(), 'radar-runtime-probe-'));
  try {
    const evidence = [];
    for (let index = 0; index < manifest.analyzers.length; index += 1) {
      const analyzer = manifest.analyzers[index];
      const platform = selectedPlatforms[index];
      const probes = [];
      if (platform.versionCommand !== null) {
        probes.push(verifyVersionCommand(root, analyzer, platform.versionCommand, temporaryHome));
      }
      if (platform.smoke !== null) {
        probes.push(verifySmoke(root, analyzer, platform.smoke, temporaryHome));
      }
      evidence.push({
        analyzer: analyzer.analyzer,
        version: analyzer.version,
        entrypoint: platform.entrypoint,
        probes,
        checksumCount: platform.checksums.length + analyzer.legalFiles.length + 1,
      });
    }
    // Acceptance probes execute in a read-only sandbox, then the complete
    // static identity is authenticated again before any evidence is returned.
    verifyRuntimeIdentity({ root, target: host });
    return {
      schemaVersion: manifest.schemaVersion,
      manifestVersion: manifest.manifestVersion,
      profile: manifest.profile,
      platform: expectedPlatformKey,
      hostIsolation,
      analyzers: evidence,
    };
  } finally {
    rmSync(temporaryHome, { recursive: true, force: true });
  }
};

if (process.argv[1] !== undefined && basename(resolve(process.argv[1])) === 'runtime-manifest.mjs') {
  process.stderr.write('[runtime:untrusted-target-verifier] Use scripts/verify-runtime-tools.mjs from the trusted workspace.\n');
  process.exitCode = 1;
}
