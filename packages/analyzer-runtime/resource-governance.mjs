import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants as filesystemConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';
import {
  inspectMaterializedAnalyzerRuntime,
} from './runtime-sealed-generation.mjs';
import {
  requiredAnalyzerPrlimitArguments,
  requiredAnalyzerPrlimitPath,
  requiredOfflineOsvDatabase as requiredManifestOfflineOsvDatabase,
  requiredRuntimeNode,
  runtimeVerificationBounds,
} from './runtime-manifest.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';
import { inspectAnalyzerControl } from './runtime-control-root.mjs';
import {
  assertMaterializedRuntimeRootDescriptor,
  assertSealedRuntimeMemfdDescriptor,
  assertTrustedRuntimeControlDescriptor,
  loadRuntimeMemfdBridgeFromDescriptor,
  serializeRuntimeDescriptorIdentity,
} from './runtime-descriptor-proofs.mjs';

/**
 * This module owns the host-side boundary immediately outside Bubblewrap. It
 * deliberately does not make a cgroup or host-tool capability optional: a
 * caller either gets every bound below or a typed unavailable failure.
 */
export const resourceGovernanceSchemaVersion =
  'codebase-radar.analyzer-resource-governance/v1';

export const requiredCgroupControllers = Object.freeze(['cpu', 'memory', 'pids']);

export const requiredCgroupLimits = Object.freeze({
  pidsMax: '128',
  memoryMax: '2147483648',
  memorySwapMax: '0',
  memoryOomGroup: '1',
  cpuMax: '200000 100000',
});

// RLIMIT_NPROC is intentionally absent. It is accounted per real UID, not per
// analysis cgroup, so it would let unrelated scans deny a valid child. The
// per-analysis cgroup pids.max above is the authoritative PID boundary.
export const requiredPrlimitArguments = requiredAnalyzerPrlimitArguments;

export const requiredChildLimits = Object.freeze({
  core: Object.freeze({ soft: '0', hard: '0', unit: 'bytes' }),
  fsize: Object.freeze({ soft: '16777216', hard: '16777216', unit: 'bytes' }),
  nofile: Object.freeze({ soft: '256', hard: '256', unit: 'files' }),
  cpu: Object.freeze({ soft: '130', hard: '130', unit: 'seconds' }),
  as: Object.freeze({ soft: '8589934592', hard: '8589934592', unit: 'bytes' }),
});

export const requiredOfflineOsvDatabase = Object.freeze({
  generation: '1786418349414076',
  bytes: 218_758_368,
  sha256: '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69',
  runtimeRelativePath: requiredManifestOfflineOsvDatabase.path,
  sandboxPath: '/runtime/databases/osv/osv-scalibr/npm/all.zip',
  scannerArguments: Object.freeze([
    '--offline',
    '--local-db-path=/runtime/databases/osv',
    '--no-resolve',
  ]),
  environment: Object.freeze({
    OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY: '/runtime/databases/osv',
  }),
});

export const resourceSeccompPolicyArchitecture = 'x86_64';

const CgroupMount = '/sys/fs/cgroup';
const BubblewrapExecutable = '/usr/bin/bwrap';
const PrlimitExecutable = requiredAnalyzerPrlimitPath;
const LauncherNodeExecutable = '/usr/local/lib/radar-node-v24.18.1/bin/node';
const LauncherGovernanceDescriptor = 4;
const LauncherTestSnapshotDescriptor = 4;
const LauncherTestDatabaseDescriptor = 5;
const LauncherRuntimeRootDescriptor = 5;
const LauncherOsvDatabaseDescriptor = 6;
const LauncherSourceDescriptor = 7;
const LauncherRequestDescriptor = 8;
const LauncherAddonDescriptor = 9;
const SandboxRuntimeRootDescriptor = 3;
const SandboxSeccompDescriptor = 4;
const SandboxOsvDatabaseDescriptor = 5;
const SandboxSourceDescriptor = 6;
const SandboxRequestDescriptor = 7;
const SandboxWorkspaceRoot = '/workspace';
const SandboxRuntimeRoot = '/runtime';
const SandboxScratchRoot = '/scratch';
const SandboxRequestPath = '/run/radar/analyzer-request.json';
const SandboxOsvDatabasePath = requiredOfflineOsvDatabase.sandboxPath;
const SandboxOsvDatabaseRoot = '/runtime/databases/osv';
const AnalyzerScratchBytes = 16 * 1024 * 1024;
const MaximumAnalyzerRequestBytes = 1024 * 1024;
const allowedAnalyzerIds = new Set([
  'strictest-comparator',
  'Oxlint + Ultracite',
  'JSCPD',
  'Calldiff',
  'OSV-Scanner',
  'TraceDecay',
  'zizmor',
]);
const HostToolProbeTimeoutMs = 5_000;
const ResourceProbeTimeoutMs = 15_000;
const ResourceProbeOutputBytes = 32 * 1024;
const CgroupCleanupTimeoutMs = 5_000;
const LaunchHandshakeTimeoutMs = 5_000;
const MaximumBwrapArguments = 192;
const MaximumArgumentCharacters = 4_096;
const MaximumEnvironmentEntries = 32;
const MaximumEnvironmentValueCharacters = 4_096;
const MaximumHostToolBytes = 128 * 1024 * 1024;
const forbiddenEnvironmentKey = /^(?:NODE_(?:OPTIONS|PATH|PRESERVE_SYMLINKS(?:_MAIN)?|COMPILE_CACHE|LOADER|REQUIRE)|LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|BUN_OPTIONS|DENO_.*|ESM_LOADER|TSX_.*|PYTHON.*|RUBYOPT)$/u;
const environmentKey = /^[A-Z][A-Z0-9_]{0,63}$/u;
const cgroupName = /^radar-analysis-[0-9a-f-]{36}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const controlCharacters = /[\u0000-\u001f\u007f]/u;
const activeAnalysisCgroups = new Set();
const launchAdmissionQueue = [];
let launchAdmissionHeld = false;

const SeccompReturnErrno = 0x0005_0000 | 1;
const SeccompReturnEnosys = 0x0005_0000 | 38;
const BpfLoadWordAbsolute = 0x20;
const BpfJumpEqual = 0x15;
const BpfAluAnd = 0x54;
const BpfReturn = 0x06;
const AuditArchX86_64 = 0xc000_003e;
const X32SyscallBit = 0x4000_0000;
const SeccompDataNumberOffset = 0;
const SeccompDataArchitectureOffset = 4;
const SeccompDataArgumentZeroOffset = 16;
const CloneNamespaceFlags = 0x7e02_0000;

const deniedSyscalls = Object.freeze([
  // Namespace and mount construction.
  Object.freeze({ name: 'mount', number: 165 }),
  Object.freeze({ name: 'umount2', number: 166 }),
  Object.freeze({ name: 'pivot_root', number: 155 }),
  Object.freeze({ name: 'unshare', number: 272 }),
  Object.freeze({ name: 'setns', number: 308 }),
  Object.freeze({ name: 'clone3', number: 435 }),
  // Host inspection / escalation primitives.
  Object.freeze({ name: 'ptrace', number: 101 }),
  Object.freeze({ name: 'bpf', number: 321 }),
  Object.freeze({ name: 'perf_event_open', number: 298 }),
  Object.freeze({ name: 'keyctl', number: 250 }),
  Object.freeze({ name: 'add_key', number: 248 }),
  Object.freeze({ name: 'request_key', number: 249 }),
  Object.freeze({ name: 'userfaultfd', number: 323 }),
  Object.freeze({ name: 'open_by_handle_at', number: 304 }),
  Object.freeze({ name: 'name_to_handle_at', number: 303 }),
  Object.freeze({ name: 'process_vm_readv', number: 310 }),
  Object.freeze({ name: 'process_vm_writev', number: 311 }),
  Object.freeze({ name: 'pidfd_getfd', number: 438 }),
  // Kernel and module controls.
  Object.freeze({ name: 'init_module', number: 175 }),
  Object.freeze({ name: 'delete_module', number: 176 }),
  Object.freeze({ name: 'finit_module', number: 313 }),
  Object.freeze({ name: 'kexec_load', number: 246 }),
  Object.freeze({ name: 'reboot', number: 169 }),
  Object.freeze({ name: 'swapon', number: 167 }),
  Object.freeze({ name: 'swapoff', number: 168 }),
  // No new network endpoints, even inside an isolated network namespace.
  Object.freeze({ name: 'socket', number: 41 }),
]);

const frozen = value => Object.freeze(value);

export class ResourceGovernanceError extends Error {
  constructor(code, message, cause) {
    super(`[resource-governance:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'ResourceGovernanceError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new ResourceGovernanceError(code, message, cause);
};

const sha256 = value => createHash('sha256').update(value).digest('hex');

const isRecord = value => typeof value === 'object' && value !== null && !Array.isArray(value);

const requireRecord = (value, label, code = 'protocol-invalid') => {
  if (!isRecord(value)) fail(code, `${label} must be an object.`);
  return value;
};

const requireExactKeys = (value, keys, label, code = 'protocol-invalid') => {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  const extra = actual.filter(key => !expected.has(key));
  const missing = keys.filter(key => !Object.hasOwn(value, key));
  if (extra.length > 0 || missing.length > 0) {
    fail(code, `${label} has unsupported or missing fields.`);
  }
};

const requirePlainString = (value, label, { maximum = MaximumArgumentCharacters } = {}) => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximum ||
    controlCharacters.test(value)
  ) {
    fail('protocol-invalid', `${label} must be a bounded printable string.`);
  }
  return value;
};

const requireAbsolutePath = (value, label) => {
  const path = requirePlainString(value, label);
  if (!isAbsolute(path) || path !== resolve(path)) {
    fail('protocol-invalid', `${label} must be a canonical absolute path.`);
  }
  return path;
};

const readTrimmed = path => {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch (cause) {
    fail('cgroup-read-failed', 'A required cgroup control file could not be read.', cause);
  }
};

const writeControl = (path, value) => {
  try {
    writeFileSync(path, `${value}\n`, { encoding: 'utf8', flag: 'w' });
  } catch (cause) {
    fail('cgroup-write-failed', 'A required cgroup control file could not be written.', cause);
  }
};

const assertLinux = () => {
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    fail(
      'linux-required',
      `Resource governance requires linux/x64; current host is ${process.platform}/${process.arch}.`,
    );
  }
};

const isWithin = (root, candidate) => {
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  return candidate === root || candidate.startsWith(prefix);
};

const canonicalCgroupRoot = requestedRoot => {
  const root = requireAbsolutePath(requestedRoot, 'cgroupRoot');
  let metadata;
  try {
    metadata = lstatSync(root);
  } catch (cause) {
    fail('cgroup-root-missing', 'The configured delegated cgroup root is unavailable.', cause);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('cgroup-root-invalid', 'The configured delegated cgroup root must be a non-symlink directory.');
  }
  let canonical;
  try {
    canonical = realpathSync(root);
  } catch (cause) {
    fail('cgroup-root-invalid', 'The configured delegated cgroup root cannot be canonicalized.', cause);
  }
  if (!isWithin(CgroupMount, canonical) || canonical === CgroupMount) {
    fail('cgroup-root-invalid', 'The delegated cgroup root must be a proper descendant of /sys/fs/cgroup.');
  }
  return canonical;
};

const controllerSet = path => new Set(readTrimmed(path).split(/\s+/u).filter(Boolean));

const assertDelegatedCgroupRoot = root => {
  const available = controllerSet(join(root, 'cgroup.controllers'));
  const enabled = controllerSet(join(root, 'cgroup.subtree_control'));
  for (const controller of requiredCgroupControllers) {
    if (!available.has(controller) || !enabled.has(controller)) {
      fail(
        'cgroup-delegation-unavailable',
        'The delegated cgroup root does not expose every required CPU, memory, and PID controller.',
      );
    }
  }
  try {
    for (const control of ['cgroup.procs', 'cgroup.kill']) {
      const metadata = lstatSync(join(root, control));
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        fail(
          'cgroup-delegation-unavailable',
          `The delegated cgroup root has no canonical ${control} control.`,
        );
      }
    }
  } catch (cause) {
    if (cause instanceof ResourceGovernanceError) throw cause;
    fail('cgroup-delegation-unavailable', 'The delegated cgroup root has no process attachment control.', cause);
  }
};

const assertNoUnownedAnalysisCgroups = root => {
  let entries;
  try {
    entries = readdirSync(root);
  } catch (cause) {
    fail('cgroup-delegation-unavailable', 'The delegated cgroup root could not be enumerated.', cause);
  }
  const unowned = entries
    .filter(entry => cgroupName.test(entry))
    .map(entry => join(root, entry))
    .filter(path => !activeAnalysisCgroups.has(path));
  if (unowned.length > 0) {
    fail(
      'stale-analysis-cgroup-detected',
      'The delegated root contains an analysis cgroup not owned by this service instance.',
    );
  }
};

const validateOwnedCgroupPath = (root, value) => {
  const path = requireAbsolutePath(value, 'allocated cgroup path');
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  const leaf = path.startsWith(prefix) ? path.slice(prefix.length) : '';
  if (!cgroupName.test(leaf) || leaf.includes(sep)) {
    fail('cgroup-path-invalid', 'The launcher reported a cgroup outside its delegated root.');
  }
  return path;
};

const newAnalysisCgroupPath = root =>
  validateOwnedCgroupPath(root, join(root, `radar-analysis-${randomUUID()}`));

const currentUnifiedCgroupDirectory = () => {
  let membership;
  try {
    membership = readFileSync('/proc/self/cgroup', 'utf8').trim();
  } catch (cause) {
    fail('cgroup-membership-unavailable', 'The launcher could not read its original cgroup membership.', cause);
  }
  const match = /^0::(\/[\x21-\x7e]*)$/u.exec(membership);
  if (match === null || match[1].includes('..')) {
    fail('cgroup-membership-invalid', 'The launcher does not have one canonical unified cgroup membership.');
  }
  const candidate = resolve(CgroupMount, `.${match[1]}`);
  if (!isWithin(CgroupMount, candidate)) {
    fail('cgroup-membership-invalid', 'The launcher original cgroup escapes the unified cgroup mount.');
  }
  try {
    const canonical = realpathSync(candidate);
    const control = lstatSync(join(canonical, 'cgroup.procs'));
    if (!isWithin(CgroupMount, canonical) || !control.isFile() || control.isSymbolicLink()) {
      fail('cgroup-membership-invalid', 'The launcher original cgroup has no canonical attachment control.');
    }
    return canonical;
  } catch (cause) {
    if (cause instanceof ResourceGovernanceError) throw cause;
    fail('cgroup-membership-invalid', 'The launcher original cgroup cannot be authenticated.', cause);
  }
};

const cleanupReportedCgroup = path => {
  if (!existsSync(path)) return;
  writeControl(join(path, 'cgroup.kill'), '1');
  waitForCgroupEmpty(path);
  rmdirSync(path);
};

const readCgroupPopulated = path => {
  const match = /^populated\s+([01])$/mu.exec(readTrimmed(join(path, 'cgroup.events')));
  if (match === null) {
    fail('cgroup-events-invalid', 'The analysis cgroup did not expose a valid populated event.');
  }
  return match[1] === '1';
};

const sleepMilliseconds = milliseconds => {
  const view = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(view, 0, 0, milliseconds);
};

const waitForCgroupEmpty = path => {
  const deadline = Date.now() + CgroupCleanupTimeoutMs;
  while (readCgroupPopulated(path)) {
    if (Date.now() >= deadline) {
      fail('cgroup-cleanup-timeout', 'The analysis cgroup remained populated after termination.');
    }
    sleepMilliseconds(10);
  }
};

class AnalysisCgroupLease {
  #root;
  #path;
  #returnPath;
  #attached = false;
  #released = false;

  constructor(root, allocatedPath) {
    this.#root = root;
    this.#path = validateOwnedCgroupPath(root, allocatedPath);
    this.#returnPath = currentUnifiedCgroupDirectory();
    let created = false;
    try {
      mkdirSync(this.#path, { mode: 0o700 });
      created = true;
      const metadata = lstatSync(this.#path);
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        fail('cgroup-create-invalid', 'The new analysis cgroup is not a regular directory.');
      }
      this.#configure();
    } catch (cause) {
      let cleanupFailure;
      if (created) {
        try { writeFileSync(join(this.#path, 'cgroup.kill'), '1\n', { encoding: 'utf8', flag: 'w' }); } catch {}
        try { waitForCgroupEmpty(this.#path); } catch {}
        try { rmdirSync(this.#path); } catch (error) { cleanupFailure = error; }
      }
      if (cleanupFailure !== undefined) {
        fail(
          'cgroup-cleanup-failed',
          'A partially configured analysis cgroup could not be removed.',
          new AggregateError([cause, cleanupFailure], 'analysis cgroup setup and cleanup both failed'),
        );
      }
      if (!(cause instanceof ResourceGovernanceError)) {
        fail('cgroup-create-failed', 'A fresh analysis cgroup could not be created.', cause);
      }
      throw cause;
    }
  }

  get path() {
    return this.#path;
  }

  #configure() {
    const controls = [
      ['pids.max', requiredCgroupLimits.pidsMax],
      ['memory.max', requiredCgroupLimits.memoryMax],
      ['memory.swap.max', requiredCgroupLimits.memorySwapMax],
      ['memory.oom.group', requiredCgroupLimits.memoryOomGroup],
      ['cpu.max', requiredCgroupLimits.cpuMax],
    ];
    for (const [name, expected] of controls) {
      writeControl(join(this.#path, name), expected);
      if (readTrimmed(join(this.#path, name)) !== expected) {
        fail('cgroup-limit-mismatch', 'The analysis cgroup did not retain its required resource limit.');
      }
    }
    try {
      const metadata = lstatSync(join(this.#path, 'cgroup.kill'));
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        fail('cgroup-kill-unavailable', 'The analysis cgroup does not expose cgroup.kill.');
      }
    } catch (cause) {
      if (cause instanceof ResourceGovernanceError) throw cause;
      fail('cgroup-kill-unavailable', 'The analysis cgroup does not expose cgroup.kill.', cause);
    }
  }

  attachSelf() {
    if (this.#released) fail('cgroup-lifecycle-invalid', 'A released analysis cgroup cannot be attached.');
    writeControl(join(this.#path, 'cgroup.procs'), String(process.pid));
    if (
      !readTrimmed(join(this.#path, 'cgroup.procs'))
        .split(/\s+/u)
        .includes(String(process.pid))
    ) {
      fail('cgroup-attachment-failed', 'The launcher could not confirm its cgroup self-attachment.');
    }
    this.#attached = true;
  }

  release() {
    if (this.#released) return;
    let primaryError;
    try {
      // The launcher must leave before cgroup.kill; otherwise it would kill
      // itself and could not prove emptiness or remove its own cgroup.
      if (this.#attached) {
        writeControl(join(this.#returnPath, 'cgroup.procs'), String(process.pid));
      }
      writeControl(join(this.#path, 'cgroup.kill'), '1');
      waitForCgroupEmpty(this.#path);
      rmdirSync(this.#path);
      this.#released = true;
    } catch (cause) {
      primaryError = cause;
    }
    if (primaryError !== undefined) {
      throw primaryError instanceof ResourceGovernanceError
        ? primaryError
        : new ResourceGovernanceError(
          'cgroup-cleanup-failed',
          'The owned analysis cgroup could not be cleaned up.',
          primaryError,
        );
    }
  }
}

const validateTool = (value, label, expectedPath) => {
  const tool = requireRecord(value, label, 'resource-governance-anchor-invalid');
  requireExactKeys(tool, ['path', 'sha256', 'versionFirstLine'], label, 'resource-governance-anchor-invalid');
  if (tool.path !== expectedPath || !sha256Pattern.test(tool.sha256)) {
    fail('resource-governance-anchor-invalid', `${label} does not have a valid immutable identity.`);
  }
  requirePlainString(tool.versionFirstLine, `${label}.versionFirstLine`, { maximum: 512 });
  return frozen({
    path: tool.path,
    sha256: tool.sha256,
    versionFirstLine: tool.versionFirstLine,
  });
};

const validatedAnchor = anchor => {
  const governance = requireRecord(anchor, 'resourceGovernance', 'resource-governance-anchor-invalid');
  requireExactKeys(
    governance,
    ['schemaVersion', 'bwrap', 'prlimit', 'node', 'seccompPolicySha256'],
    'resourceGovernance',
    'resource-governance-anchor-invalid',
  );
  if (
    governance.schemaVersion !== resourceGovernanceSchemaVersion ||
    !sha256Pattern.test(governance.seccompPolicySha256)
  ) {
    fail('resource-governance-anchor-invalid', 'The resource governance trust anchor is incomplete.');
  }
  return frozen({
    schemaVersion: governance.schemaVersion,
    bwrap: validateTool(governance.bwrap, 'resourceGovernance.bwrap', BubblewrapExecutable),
    prlimit: validateTool(governance.prlimit, 'resourceGovernance.prlimit', PrlimitExecutable),
    node: validateTool(governance.node, 'resourceGovernance.node', LauncherNodeExecutable),
    seccompPolicySha256: governance.seccompPolicySha256,
  });
};

const fixedHostEnvironment = Object.freeze({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin',
});

const firstOutputLine = value => String(value).replace(/\r\n?/gu, '\n').split('\n', 1)[0];

const assertBoundedHostResult = (name, result) => {
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  if (result.error?.code === 'ETIMEDOUT') {
    fail('host-tool-timeout', `${name} did not complete within its bounded timeout.`);
  }
  if (
    result.error?.code === 'ENOBUFS' ||
    Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 4_096
  ) {
    fail('host-tool-output-limit', `${name} exceeded its bounded output limit.`);
  }
  if (result.error !== undefined || result.status !== 0 || result.signal !== null) {
    fail('host-tool-probe-failed', `${name} could not complete its identity probe.`);
  }
  if (stderr !== '') fail('host-tool-probe-failed', `${name} wrote an unexpected diagnostic.`);
  const normalized = stdout.replace(/\r\n?/gu, '\n').replace(/\n$/u, '');
  if (normalized.includes('\n') || normalized.length === 0) {
    fail('host-tool-probe-failed', `${name} did not return one exact version line.`);
  }
  return normalized;
};

export const verifyTrustedHostTool = tool => {
  let metadata;
  try {
    metadata = lstatSync(tool.path, { bigint: true });
  } catch (cause) {
    fail('host-tool-missing', 'A required canonical host tool is unavailable.', cause);
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1n ||
    metadata.uid !== 0n ||
    metadata.gid !== 0n ||
    (metadata.mode & 0o7777n) !== 0o755n ||
    metadata.size <= 0n ||
    metadata.size > BigInt(MaximumHostToolBytes)
  ) {
    fail('host-tool-metadata-invalid', 'A required host tool failed its canonical ownership or mode check.');
  }
  let canonical;
  try {
    canonical = realpathSync(tool.path);
  } catch (cause) {
    fail('host-tool-canonicalization-failed', 'A required host tool cannot be canonicalized.', cause);
  }
  if (canonical !== tool.path) {
    fail('host-tool-metadata-invalid', 'A required host tool must resolve to its canonical path.');
  }
  let descriptor;
  let opened;
  let digest;
  try {
    descriptor = openSync(
      tool.path,
      filesystemConstants.O_RDONLY |
        filesystemConstants.O_NOFOLLOW |
        filesystemConstants.O_CLOEXEC,
    );
    opened = fstatSync(descriptor, { bigint: true });
    if (
      opened.dev !== metadata.dev ||
      opened.ino !== metadata.ino ||
      opened.size !== metadata.size ||
      opened.mtimeNs !== metadata.mtimeNs
    ) {
      fail('host-tool-generation-changed', 'A required host tool changed while it was opened.');
    }
    digest = sha256(readFileSync(descriptor));
  } catch (cause) {
    if (cause instanceof ResourceGovernanceError) throw cause;
    fail('host-tool-read-failed', 'A required host tool could not be hashed.', cause);
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
  if (digest !== tool.sha256) {
    fail('host-tool-hash-mismatch', 'A required host tool did not match its independently pinned SHA-256.');
  }
  const version = assertBoundedHostResult(
    `${tool.path} --version`,
    spawnSync(tool.path, ['--version'], {
      cwd: '/',
      encoding: 'utf8',
      env: fixedHostEnvironment,
      killSignal: 'SIGKILL',
      maxBuffer: 4_096,
      timeout: HostToolProbeTimeoutMs,
      windowsHide: true,
    }),
  );
  if (version !== tool.versionFirstLine) {
    fail('host-tool-version-mismatch', 'A required host tool did not match its pinned version first line.');
  }
  return frozen({
    path: tool.path,
    sha256: tool.sha256,
    versionFirstLine: version,
    metadata: frozen({
      device: metadata.dev.toString(10),
      inode: metadata.ino.toString(10),
      size: Number(metadata.size),
      mode: (metadata.mode & 0o7777n).toString(8).padStart(4, '0'),
      uid: Number(metadata.uid),
      gid: Number(metadata.gid),
    }),
  });
};

const bpfInstruction = (code, jt, jf, k) => {
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeUInt16LE(code, 0);
  bytes.writeUInt8(jt, 2);
  bytes.writeUInt8(jf, 3);
  bytes.writeUInt32LE(k >>> 0, 4);
  return bytes;
};

/**
 * A classic-BPF seccomp filter. It is deliberately generated in trusted code,
 * hashed below, and supplied only on the launcher-owned sandbox FD 4. Callers cannot
 * replace it with a --seccomp argument of their own.
 */
export const buildResourceSeccompPolicy = () => {
  const instructions = [
    // Kill no process on a foreign ABI: resource governance is x86_64-only.
    bpfInstruction(BpfLoadWordAbsolute, 0, 0, SeccompDataArchitectureOffset),
    bpfInstruction(BpfJumpEqual, 1, 0, AuditArchX86_64),
    bpfInstruction(BpfReturn, 0, 0, SeccompReturnErrno),
    bpfInstruction(BpfLoadWordAbsolute, 0, 0, SeccompDataNumberOffset),
    // AUDIT_ARCH_X86_64 is shared by the native and x32 ABIs. Reject every
    // x32 syscall before comparing native syscall numbers so OR-ing the x32
    // bit cannot bypass the deny list on kernels that enable that ABI.
    bpfInstruction(BpfAluAnd, 0, 0, X32SyscallBit),
    bpfInstruction(BpfJumpEqual, 1, 0, 0),
    bpfInstruction(BpfReturn, 0, 0, SeccompReturnErrno),
    bpfInstruction(BpfLoadWordAbsolute, 0, 0, SeccompDataNumberOffset),
  ];
  for (const syscall of deniedSyscalls) {
    instructions.push(bpfInstruction(BpfJumpEqual, 0, 1, syscall.number));
    // glibc falls back from clone3(2) to the clone(2) path only for ENOSYS.
    // That fallback remains safe because clone namespace flags are masked
    // below, while ordinary threads and processes remain available.
    instructions.push(bpfInstruction(
      BpfReturn,
      0,
      0,
      syscall.name === 'clone3' ? SeccompReturnEnosys : SeccompReturnErrno,
    ));
  }
  // fork/threads are permitted, but namespace creation through clone(2) is
  // blocked by masking every CLONE_NEW* flag. clone3 returns ENOSYS above
  // because its flags live behind a pointer and cannot be safely inspected;
  // this makes libc use the safely masked legacy clone path.
  instructions.push(bpfInstruction(BpfJumpEqual, 0, 4, 56));
  instructions.push(bpfInstruction(BpfLoadWordAbsolute, 0, 0, SeccompDataArgumentZeroOffset));
  instructions.push(bpfInstruction(BpfAluAnd, 0, 0, CloneNamespaceFlags));
  instructions.push(bpfInstruction(BpfJumpEqual, 1, 0, 0));
  instructions.push(bpfInstruction(BpfReturn, 0, 0, SeccompReturnErrno));
  instructions.push(bpfInstruction(BpfReturn, 0, 0, 0x7fff_0000));
  return Buffer.concat(instructions);
};

export const resourceSeccompPolicySha256 = sha256(buildResourceSeccompPolicy());

const assertSeccompPolicyAnchor = anchor => {
  if (anchor.seccompPolicySha256 !== resourceSeccompPolicySha256) {
    fail('seccomp-policy-anchor-mismatch', 'The compiled seccomp policy did not match its immutable trust anchor.');
  }
};

const createSeccompFile = () => {
  let directory;
  let policyPath;
  let descriptor;
  try {
    directory = mkdtempSync(join(tmpdir(), 'radar-seccomp-'));
    chmodSync(directory, 0o700);
    policyPath = join(directory, 'policy.bpf');
    writeFileSync(policyPath, buildResourceSeccompPolicy(), { mode: 0o600, flag: 'wx' });
    const metadata = lstatSync(policyPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      fail('seccomp-policy-invalid', 'The operation-owned seccomp policy file was not a regular private file.');
    }
    descriptor = openSync(policyPath, 'r');
  } catch (cause) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (policyPath !== undefined) {
      try { unlinkSync(policyPath); } catch {}
    }
    if (directory !== undefined) {
      try { rmdirSync(directory); } catch {}
    }
    if (cause instanceof ResourceGovernanceError) throw cause;
    fail('seccomp-policy-create-failed', 'The operation-owned seccomp policy could not be created.', cause);
  }
  let released = false;
  return frozen({
    descriptor,
    release: () => {
      if (released) return;
      released = true;
      let failure;
      try { closeSync(descriptor); } catch (cause) { failure ??= cause; }
      try { unlinkSync(policyPath); } catch (cause) { failure ??= cause; }
      try { rmdirSync(directory); } catch (cause) { failure ??= cause; }
      if (failure !== undefined) {
        throw new ResourceGovernanceError(
          'seccomp-policy-cleanup-failed',
          'The operation-owned seccomp policy could not be removed.',
          failure,
        );
      }
    },
  });
};

const validateBwrapArguments = value => {
  if (!Array.isArray(value) || value.length === 0 || value.length > MaximumBwrapArguments) {
    fail('protocol-invalid', 'Bubblewrap arguments must be a bounded non-empty array.');
  }
  const arguments_ = value.map((item, index) => requirePlainString(item, `bwrapArguments[${index}]`));
  for (const forbidden of [
    '--share-net',
    '--unshare-all',
    '--unshare-net',
    '--seccomp',
    '--add-seccomp-fd',
    '--args',
    '--file',
    '--bind-data',
    '--ro-bind-data',
    '--sync-fd',
    '--block-fd',
    '--userns-block-fd',
    '--info-fd',
    '--json-status-fd',
    '--userns',
    '--userns2',
    '--pidns',
    '--share-user',
  ]) {
    if (arguments_.some(argument => argument === forbidden || argument.startsWith(`${forbidden}=`))) {
      fail(
        forbidden === '--share-net' ? 'network-policy-rejected' : 'protocol-invalid',
        'The launcher owns sandbox descriptor and namespace options.',
      );
    }
  }
  if (arguments_.some(argument => argument.startsWith('/proc/self/fd/'))) {
    fail('protocol-invalid', 'Callers cannot reference inherited descriptors.');
  }
  return frozen(arguments_);
};

/**
 * Canonical executable boundary. Trusted reconstruction has already completed
 * before this process exists, so the exact analyzer limits can safely wrap
 * bwrap and every untrusted descendant without constraining setup writes.
 */
const buildResourceGovernedCommandForDescriptor = (
  bwrapArguments,
  seccompDescriptor,
  { trustedArguments = false } = {},
) => frozen({
  executable: PrlimitExecutable,
  arguments: frozen([
    ...requiredPrlimitArguments,
    BubblewrapExecutable,
    '--unshare-all',
    '--unshare-net',
    '--seccomp',
    String(seccompDescriptor),
    ...(trustedArguments ? bwrapArguments : validateBwrapArguments(bwrapArguments)),
  ]),
});

export const buildResourceGovernedCommand = bwrapArguments =>
  buildResourceGovernedCommandForDescriptor(
    bwrapArguments,
    SandboxSeccompDescriptor,
  );

export const buildPrlimitedAnalyzerCommand = (executable, analyzerArguments) => {
  const path = requireAbsolutePath(executable, 'analyzer executable');
  if (!Array.isArray(analyzerArguments) || analyzerArguments.length > MaximumBwrapArguments) {
    fail('protocol-invalid', 'Analyzer arguments must be a bounded array.');
  }
  return frozen({
    executable: PrlimitExecutable,
    arguments: frozen([
      ...requiredPrlimitArguments,
      path,
      ...analyzerArguments.map((argument, index) =>
        requirePlainString(argument, `analyzerArguments[${index}]`)),
    ]),
  });
};

const validateEnvironment = value => {
  const environment = requireRecord(value, 'environment');
  const entries = Object.entries(environment);
  if (entries.length > MaximumEnvironmentEntries) {
    fail('protocol-invalid', 'The child environment exceeds its bounded inventory.');
  }
  const result = {};
  for (const [key, rawValue] of entries) {
    if (!environmentKey.test(key) || forbiddenEnvironmentKey.test(key)) {
      fail('protocol-invalid', 'The child environment contains a forbidden loader or malformed key.');
    }
    result[key] = requirePlainString(rawValue, `environment.${key}`, {
      maximum: MaximumEnvironmentValueCharacters,
    });
  }
  return frozen(result);
};

const validateTimeout = value => {
  if (!Number.isInteger(value) || value < 1 || value > 120_000) {
    fail('protocol-invalid', 'The child timeout must be an integer from 1 through 120000 milliseconds.');
  }
  return value;
};

const validateAbortSignal = value => {
  if (value === undefined) return undefined;
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof value.aborted !== 'boolean' ||
    typeof value.addEventListener !== 'function' ||
    typeof value.removeEventListener !== 'function'
  ) {
    fail('protocol-invalid', 'The launch cancellation signal must implement AbortSignal.');
  }
  return value;
};

const grantNextLaunchAdmission = () => {
  if (launchAdmissionHeld) return;
  while (launchAdmissionQueue.length > 0) {
    const waiter = launchAdmissionQueue.shift();
    if (waiter.settled) continue;
    launchAdmissionHeld = true;
    waiter.grant();
    return;
  }
};

/**
 * The Zerops container has a 4 GiB aggregate memory ceiling while every
 * analysis cgroup is allowed 2 GiB. A process-global FIFO permit therefore
 * admits exactly one analyzer at a time. The permit is acquired before an
 * operation-owned cgroup path is allocated and is retained through cleanup.
 */
const acquireLaunchAdmission = ({ signal, timeoutMs }) => {
  if (signal?.aborted === true) {
    return Promise.reject(new ResourceGovernanceError(
      'launch-cancelled',
      'The analyzer launch was cancelled before admission.',
    ));
  }
  return new Promise((resolvePromise, reject) => {
    const waiter = { settled: false, grant: undefined };
    const finish = callback => value => {
      if (waiter.settled) return;
      waiter.settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      callback(value);
    };
    const rejectWaiter = finish(reject);
    const grantWaiter = finish(() => {
      let released = false;
      resolvePromise(frozen({
        release: () => {
          if (released) return;
          released = true;
          launchAdmissionHeld = false;
          grantNextLaunchAdmission();
        },
      }));
    });
    waiter.grant = grantWaiter;
    const onAbort = () => {
      rejectWaiter(new ResourceGovernanceError(
        'launch-cancelled',
        'The analyzer launch was cancelled while waiting for admission.',
      ));
      grantNextLaunchAdmission();
    };
    const timer = setTimeout(() => {
      rejectWaiter(new ResourceGovernanceError(
        'launch-admission-timeout',
        'The analyzer launch deadline elapsed while waiting for admission.',
      ));
      grantNextLaunchAdmission();
    }, timeoutMs);
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
    launchAdmissionQueue.push(waiter);
    grantNextLaunchAdmission();
  });
};

const validateAnalyzerId = value => {
  const analyzerId = requirePlainString(value, 'analyzerId', { maximum: 128 });
  if (!allowedAnalyzerIds.has(analyzerId)) {
    fail('analyzer-id-invalid', 'The resource launcher received an unsupported analyzer identity.');
  }
  return analyzerId;
};

const isOsvAnalyzer = analyzerId => analyzerId === 'OSV-Scanner';

const validateInheritedSnapshot = value => {
  if (value !== LauncherTestSnapshotDescriptor) {
    fail('snapshot-descriptor-invalid', 'The launcher requires the sealed snapshot on FD 4.');
  }
  let metadata;
  try {
    metadata = fstatSync(LauncherTestSnapshotDescriptor);
  } catch (cause) {
    fail('snapshot-descriptor-unavailable', 'The sealed runtime snapshot descriptor is unavailable.', cause);
  }
  if (!metadata.isFile() || metadata.size <= 0) {
    fail('snapshot-descriptor-invalid', 'The sealed runtime snapshot descriptor is not a non-empty file.');
  }
  return value;
};

const validateInheritedDescriptor = ({ value, expected, label, kind, maximumBytes }) => {
  if (value !== expected) {
    fail('inherited-descriptor-invalid', `The launcher requires ${label} on FD ${expected}.`);
  }
  let metadata;
  try {
    metadata = fstatSync(expected);
  } catch (cause) {
    fail('inherited-descriptor-unavailable', `The inherited ${label} descriptor is unavailable.`, cause);
  }
  if (
    (kind === 'directory' ? !metadata.isDirectory() : !metadata.isFile()) ||
    (kind === 'file' && (metadata.size <= 0 || metadata.size > maximumBytes))
  ) {
    fail('inherited-descriptor-invalid', `The inherited ${label} descriptor has invalid metadata.`);
  }
  return expected;
};

const validateMaterializedRuntimeProtocol = (value, analyzerId) => {
  const runtime = requireRecord(value, 'materialized runtime protocol');
  requireExactKeys(
    runtime,
    [
      'manifestSha256',
      'runnerSha256',
      'nodeSha256',
      'runtimeRootIdentity',
      'osvDatabaseSha256',
      'osvDatabaseBytes',
      'osvDatabaseGeneration',
      'osvDatabaseIdentity',
      'launcherBytes',
      'launcherSha256',
      'launcherIdentity',
      'addonBytes',
      'addonSha256',
      'addonIdentity',
      'analyzerRequestBytes',
      'analyzerRequestSha256',
      'analyzerRequestIdentity',
    ],
    'materialized runtime protocol',
  );
  if (
    runtime.manifestSha256 !== runtimeTrustAnchor.manifestSha256 ||
    runtime.runnerSha256 !== runtimeTrustAnchor.runnerSha256 ||
    runtime.nodeSha256 !== requiredRuntimeNode.sha256 ||
    runtime.osvDatabaseSha256 !== requiredOfflineOsvDatabase.sha256 ||
    runtime.osvDatabaseBytes !== requiredOfflineOsvDatabase.bytes ||
    runtime.osvDatabaseGeneration !== requiredOfflineOsvDatabase.generation ||
    !Number.isSafeInteger(runtime.launcherBytes) || runtime.launcherBytes < 1 ||
    !sha256Pattern.test(runtime.launcherSha256) ||
    !Number.isSafeInteger(runtime.addonBytes) || runtime.addonBytes < 1 ||
    !sha256Pattern.test(runtime.addonSha256) ||
    !Number.isSafeInteger(runtime.analyzerRequestBytes) ||
    runtime.analyzerRequestBytes < 1 ||
    runtime.analyzerRequestBytes > MaximumAnalyzerRequestBytes ||
    !sha256Pattern.test(runtime.analyzerRequestSha256)
  ) {
    fail('materialized-runtime-invalid', 'The transported materialized runtime identity is invalid.');
  }
  try {
    assertMaterializedRuntimeRootDescriptor({
      runtimeRootFd: LauncherRuntimeRootDescriptor,
      runtimeRootIdentity: runtime.runtimeRootIdentity,
    });
    assertTrustedRuntimeControlDescriptor({
      fd: LauncherGovernanceDescriptor,
      byteLength: runtime.launcherBytes,
      sha256: runtime.launcherSha256,
      identity: runtime.launcherIdentity,
      maximumBytes: runtimeVerificationBounds.textBytes,
      requiredMode: 0o444,
      label: 'standalone resource governance launcher',
    });
    const addon = assertTrustedRuntimeControlDescriptor({
      fd: LauncherAddonDescriptor,
      byteLength: runtime.addonBytes,
      sha256: runtime.addonSha256,
      identity: runtime.addonIdentity,
      maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
      requiredMode: 0o555,
      label: 'runtime memfd bridge',
    });
    const bridge = loadRuntimeMemfdBridgeFromDescriptor({
      addonFd: addon.fd,
      addonBytes: addon.byteLength,
      addonSha256: addon.sha256,
      addonIdentity: addon.identity,
      addonMaximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    });
    assertSealedRuntimeMemfdDescriptor({
      bridge,
      fd: LauncherRequestDescriptor,
      byteLength: runtime.analyzerRequestBytes,
      identity: runtime.analyzerRequestIdentity,
      maximumBytes: MaximumAnalyzerRequestBytes,
      sha256: runtime.analyzerRequestSha256,
      label: 'analyzer request',
    });
    if (isOsvAnalyzer(analyzerId)) {
      assertSealedRuntimeMemfdDescriptor({
        bridge,
        fd: LauncherOsvDatabaseDescriptor,
        byteLength: runtime.osvDatabaseBytes,
        identity: runtime.osvDatabaseIdentity,
        maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
        sha256: runtime.osvDatabaseSha256,
        label: 'offline OSV database',
      });
    }
  } catch (cause) {
    fail('materialized-runtime-invalid', 'The inherited materialized runtime capability failed re-verification.', cause);
  }
  return frozen({ ...runtime });
};

const productionEnvironment = analyzerId => frozen({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/runtime/bin:/usr/bin:/bin',
  RADAR_ANALYZER_REQUEST: SandboxRequestPath,
  RADAR_SCRATCH_ROOT: SandboxScratchRoot,
  TMPDIR: SandboxScratchRoot,
  XDG_CACHE_HOME: `${SandboxScratchRoot}/cache`,
  ...(isOsvAnalyzer(analyzerId) ? requiredOfflineOsvDatabase.environment : {}),
});

export const buildMaterializedAnalyzerBwrapArguments = analyzerIdValue => {
  const analyzerId = validateAnalyzerId(analyzerIdValue);
  const environment = productionEnvironment(analyzerId);
  const arguments_ = [
    '--die-with-parent',
    '--new-session',
    '--clearenv',
    '--proc', '/proc',
    '--dev', '/dev',
    '--ro-bind', '/usr', '/usr',
    '--ro-bind-try', '/bin', '/bin',
    '--ro-bind-try', '/lib', '/lib',
    '--ro-bind-try', '/lib64', '/lib64',
    '--dir', '/etc',
    '--ro-bind-try', '/etc/ld.so.cache', '/etc/ld.so.cache',
    '--dir', '/run',
    '--dir', '/run/radar',
    '--size', String(AnalyzerScratchBytes),
    '--tmpfs', SandboxScratchRoot,
    '--ro-bind', `/proc/self/fd/${SandboxRuntimeRootDescriptor}`, SandboxRuntimeRoot,
    '--ro-bind', `/proc/self/fd/${SandboxSourceDescriptor}`, SandboxWorkspaceRoot,
    '--ro-bind', `/proc/self/fd/${SandboxRequestDescriptor}`, SandboxRequestPath,
  ];
  if (isOsvAnalyzer(analyzerId)) {
    arguments_.push(
      '--ro-bind', `/proc/self/fd/${SandboxOsvDatabaseDescriptor}`, SandboxOsvDatabasePath,
    );
  }
  for (const [key, value] of Object.entries(environment)) {
    arguments_.push('--setenv', key, value);
  }
  arguments_.push(
    '--chdir', SandboxWorkspaceRoot,
    `${SandboxRuntimeRoot}/bin/node`,
    `${SandboxRuntimeRoot}/bin/radar-semantic-analyzer.mjs`,
    '--analyzer', analyzerId,
  );
  return frozen(arguments_);
};

const validateLaunchRequest = (
  value,
  { requireInheritedSnapshot = true } = {},
) => {
  const request = requireRecord(value, 'launch request');
  if (request.schemaVersion !== resourceGovernanceSchemaVersion || request.kind !== 'launch') {
    fail('protocol-invalid', 'The launcher request has an unsupported schema or kind.');
  }
  const baseKeys = [
    'schemaVersion',
    'kind',
    'mode',
    'analyzerId',
    'cgroupRoot',
    'cgroupPath',
    'cwd',
    'timeoutMs',
    'tools',
  ];
  if (request.mode === 'test') {
    requireExactKeys(
      request,
      [...baseKeys, 'snapshotDescriptor', 'databaseDescriptor', 'bwrapArguments', 'environment'],
      'test launch request',
    );
  } else if (request.mode === 'materialized') {
    requireExactKeys(
      request,
      [
        ...baseKeys,
        'runtimeRootDescriptor',
        'osvDatabaseDescriptor',
        'sourceDescriptor',
        'requestDescriptor',
        'runtime',
      ],
      'materialized launch request',
    );
  } else {
    fail('protocol-invalid', 'The launcher request has an unsupported mode.');
  }
  if (request.cwd !== '/') fail('protocol-invalid', 'The launcher cwd must be /.');
  const analyzerId = validateAnalyzerId(request.analyzerId);
  const cgroupRoot = canonicalCgroupRoot(request.cgroupRoot);
  const common = {
    mode: request.mode,
    analyzerId,
    cgroupRoot,
    cgroupPath: validateOwnedCgroupPath(cgroupRoot, request.cgroupPath),
    cwd: request.cwd,
    timeoutMs: validateTimeout(request.timeoutMs),
    tools: validatedAnchor(request.tools),
  };
  if (request.mode === 'test') {
    if (!requireInheritedSnapshot && request.snapshotDescriptor !== LauncherTestSnapshotDescriptor) {
      fail('snapshot-descriptor-invalid', 'The launcher requires the test snapshot on FD 4.');
    }
    if (![null, LauncherTestDatabaseDescriptor].includes(request.databaseDescriptor)) {
      fail('inherited-descriptor-invalid', 'The test launcher database descriptor must be null or FD 5.');
    }
    if (requireInheritedSnapshot && request.databaseDescriptor === LauncherTestDatabaseDescriptor) {
      validateInheritedDescriptor({
        value: request.databaseDescriptor,
        expected: LauncherTestDatabaseDescriptor,
        label: 'test database',
        kind: 'file',
        maximumBytes: 256 * 1024 * 1024,
      });
    }
    return frozen({
      ...common,
      snapshotDescriptor: requireInheritedSnapshot
        ? validateInheritedSnapshot(request.snapshotDescriptor)
        : request.snapshotDescriptor,
      databaseDescriptor: request.databaseDescriptor,
      bwrapArguments: validateBwrapArguments(request.bwrapArguments),
      environment: validateEnvironment(request.environment),
    });
  }
  if (!requireInheritedSnapshot) {
    fail('protocol-invalid', 'A materialized launch protocol can only be validated after descriptor inheritance.');
  }
  validateInheritedDescriptor({
    value: request.runtimeRootDescriptor,
    expected: LauncherRuntimeRootDescriptor,
    label: 'materialized runtime root',
    kind: 'directory',
  });
  validateInheritedDescriptor({
    value: request.sourceDescriptor,
    expected: LauncherSourceDescriptor,
    label: 'source workspace',
    kind: 'directory',
  });
  validateInheritedDescriptor({
    value: request.requestDescriptor,
    expected: LauncherRequestDescriptor,
    label: 'analyzer request',
    kind: 'file',
    maximumBytes: MaximumAnalyzerRequestBytes,
  });
  const expectedOsvDescriptor = isOsvAnalyzer(analyzerId)
    ? LauncherOsvDatabaseDescriptor
    : null;
  if (request.osvDatabaseDescriptor !== expectedOsvDescriptor) {
    fail('osv-database-descriptor-invalid', 'Only OSV-Scanner may receive the sealed offline database FD 6.');
  }
  const runtime = validateMaterializedRuntimeProtocol(request.runtime, analyzerId);
  return frozen({
    ...common,
    runtimeRootDescriptor: LauncherRuntimeRootDescriptor,
    osvDatabaseDescriptor: expectedOsvDescriptor,
    sourceDescriptor: LauncherSourceDescriptor,
    requestDescriptor: LauncherRequestDescriptor,
    runtime,
    bwrapArguments: buildMaterializedAnalyzerBwrapArguments(analyzerId),
    environment: productionEnvironment(analyzerId),
  });
};

const probeProgram = [
  "const { spawnSync } = require('node:child_process');",
  "const fs = require('node:fs');",
  "const worker = spawnSync(process.execPath, ['-e', \"const { Worker } = require('node:worker_threads'); const worker = new Worker('0', { eval: true }); worker.once('error', () => process.exit(91)); worker.once('exit', code => process.exit(code));\"], { encoding: 'utf8' });",
  "const attempted = spawnSync('/usr/bin/bwrap', ['--unshare-user', '--ro-bind', '/usr', '/usr', '--proc', '/proc', '--dev', '/dev', '/usr/bin/true'], { encoding: 'utf8' });",
  "const net = require('node:net');",
  "const socket = net.connect({ host: '198.51.100.1', port: 9 });",
  "socket.once('error', error => process.stdout.write(JSON.stringify({ limits: fs.readFileSync('/proc/self/limits', 'utf8'), status: fs.readFileSync('/proc/self/status', 'utf8'), workerAttempt: { status: worker.status, signal: worker.signal, error: worker.error?.code ?? null }, namespaceAttempt: { status: attempted.status, signal: attempted.signal, error: attempted.error?.code ?? null }, networkError: error.code ?? null })));",
  "socket.once('connect', () => process.exit(97));",
  "setTimeout(() => process.exit(98), 1000).unref();",
].join('');

const buildProbeBwrapArguments = tools => [
  '--die-with-parent',
  '--new-session',
  '--clearenv',
  '--proc', '/proc',
  '--dev', '/dev',
  '--ro-bind', '/usr', '/usr',
  '--ro-bind-try', '/bin', '/bin',
  '--ro-bind-try', '/lib', '/lib',
  '--ro-bind-try', '/lib64', '/lib64',
  '--ro-bind', '/usr/local/lib/radar-node-v24.18.1', '/usr/local/lib/radar-node-v24.18.1',
  '--tmpfs', '/tmp',
  tools.node.path,
  '-e', probeProgram,
];

const parseLimitLine = (text, label) => {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const match = new RegExp(`^${escaped}\\s+(\\S+)\\s+(\\S+)\\s+(.+)$`, 'mu').exec(text);
  if (match === null) fail('child-limits-invalid', 'The sandbox child did not expose a required /proc/self/limits entry.');
  return frozen({ soft: match[1], hard: match[2], unit: match[3].trim() });
};

export const parseChildLimits = text => {
  if (typeof text !== 'string' || text.length === 0 || text.length > 16 * 1024) {
    fail('child-limits-invalid', 'The sandbox child limits probe was malformed.');
  }
  const actual = frozen({
    core: parseLimitLine(text, 'Max core file size'),
    fsize: parseLimitLine(text, 'Max file size'),
    nofile: parseLimitLine(text, 'Max open files'),
    cpu: parseLimitLine(text, 'Max cpu time'),
    as: parseLimitLine(text, 'Max address space'),
  });
  for (const [name, expected] of Object.entries(requiredChildLimits)) {
    const value = actual[name];
    if (value.soft !== expected.soft || value.hard !== expected.hard || value.unit !== expected.unit) {
      fail('child-limits-mismatch', 'The sandbox child did not inherit the required prlimit boundary.');
    }
  }
  if (/^Max processes\s+128\s+128\s+/mu.test(text)) {
    fail('child-limits-invalid', 'RLIMIT_NPROC must not be applied to shared-UID analyzer children.');
  }
  return actual;
};

const runInCgroup = ({ root, cgroupPath, tools, bwrapArguments, environment, timeoutMs, capture }) => {
  assertDelegatedCgroupRoot(root);
  const lease = new AnalysisCgroupLease(root, cgroupPath);
  let policy;
  let result;
  let primaryError;
  try {
    lease.attachSelf();
    policy = createSeccompFile();
    const command = buildResourceGovernedCommandForDescriptor(bwrapArguments, 3);
    if (
      command.executable !== tools.prlimit.path ||
      command.arguments.at(requiredPrlimitArguments.length) !== tools.bwrap.path
    ) {
      fail('resource-governance-anchor-invalid', 'The launcher command did not match its canonical host-tool paths.');
    }
    result = spawnSync(command.executable, command.arguments, {
      cwd: '/',
      encoding: capture ? 'utf8' : undefined,
      env: environment,
      killSignal: 'SIGKILL',
      maxBuffer: ResourceProbeOutputBytes,
      stdio: capture ? ['ignore', 'pipe', 'pipe', policy.descriptor] : ['ignore', 'inherit', 'inherit', policy.descriptor],
      timeout: timeoutMs,
      windowsHide: true,
    });
  } catch (cause) {
    primaryError = cause;
  } finally {
    try {
      policy?.release();
    } catch (cause) {
      primaryError ??= cause;
    }
    try {
      lease.release();
    } catch (cause) {
      primaryError ??= cause;
    }
  }
  if (primaryError !== undefined) {
    throw primaryError instanceof ResourceGovernanceError
      ? primaryError
      : new ResourceGovernanceError('launcher-spawn-failed', 'The bounded analyzer child could not be started.', primaryError);
  }
  return result;
};

const assertProbeResult = result => {
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  if (
    result.error !== undefined ||
    result.signal !== null ||
    result.status !== 0 ||
    Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > ResourceProbeOutputBytes
  ) {
    fail('resource-probe-failed', 'The bounded child resource-governance probe did not complete.');
  }
  let decoded;
  try {
    decoded = JSON.parse(stdout);
  } catch (cause) {
    fail('resource-probe-invalid', 'The bounded child resource-governance probe returned malformed output.', cause);
  }
  const probe = requireRecord(decoded, 'resource probe', 'resource-probe-invalid');
  requireExactKeys(
    probe,
    ['limits', 'status', 'workerAttempt', 'namespaceAttempt', 'networkError'],
    'resource probe',
    'resource-probe-invalid',
  );
  const limits = parseChildLimits(probe.limits);
  const workerAttempt = requireRecord(probe.workerAttempt, 'resource probe workerAttempt', 'resource-probe-invalid');
  requireExactKeys(workerAttempt, ['status', 'signal', 'error'], 'resource probe workerAttempt', 'resource-probe-invalid');
  if (workerAttempt.status !== 0 || workerAttempt.signal !== null || workerAttempt.error !== null) {
    fail('seccomp-thread-policy-invalid', 'The pinned Node child could not create and join a worker thread under seccomp.');
  }
  if (!/^Seccomp:\s*2$/mu.test(probe.status)) {
    fail('seccomp-not-applied', 'The bounded child did not report seccomp filter mode 2.');
  }
  const namespaceAttempt = requireRecord(probe.namespaceAttempt, 'resource probe namespaceAttempt', 'resource-probe-invalid');
  requireExactKeys(namespaceAttempt, ['status', 'signal', 'error'], 'resource probe namespaceAttempt', 'resource-probe-invalid');
  if (namespaceAttempt.status === 0 && namespaceAttempt.signal === null && namespaceAttempt.error === null) {
    fail('seccomp-not-enforced', 'The bounded child could create a nested namespace.');
  }
  if (probe.networkError !== 'EPERM') {
    fail('network-policy-not-enforced', 'The bounded child could create a network socket.');
  }
  return limits;
};

const probeEvidence = ({ root, cgroupPath, tools }) => {
  const result = runInCgroup({
    root,
    cgroupPath,
    tools,
    bwrapArguments: buildProbeBwrapArguments(tools),
    environment: fixedHostEnvironment,
    timeoutMs: ResourceProbeTimeoutMs,
    capture: true,
  });
  const limits = assertProbeResult(result);
  return frozen({
    schemaVersion: resourceGovernanceSchemaVersion,
    status: 'passed',
    cgroupV2: frozen({
      controllers: frozen([...requiredCgroupControllers]),
      pidsMax: requiredCgroupLimits.pidsMax,
      memoryMax: requiredCgroupLimits.memoryMax,
      memorySwapMax: requiredCgroupLimits.memorySwapMax,
      memoryOomGroup: requiredCgroupLimits.memoryOomGroup,
      cpuMax: requiredCgroupLimits.cpuMax,
      ownership: 'parent-pre-registered',
      launcherCrashCleanup: 'parent-supervised',
      staleCgroupPolicy: 'reject-unowned',
      cleanup: 'passed',
    }),
    tools: frozen({
      bwrap: verifyTrustedHostTool(tools.bwrap),
      prlimit: verifyTrustedHostTool(tools.prlimit),
      node: verifyTrustedHostTool(tools.node),
    }),
    launch: frozen({
      runtimeRootChildDescriptor: SandboxRuntimeRootDescriptor,
      seccompChildDescriptor: SandboxSeccompDescriptor,
      osvDatabaseChildDescriptor: SandboxOsvDatabaseDescriptor,
      osvDatabaseScope: 'OSV-Scanner-only',
      sourceChildDescriptor: SandboxSourceDescriptor,
      requestChildDescriptor: SandboxRequestDescriptor,
      namespaceArguments: frozen(['--unshare-all', '--unshare-net']),
      maximumConcurrentAnalyzers: 1,
      admission: 'fifo-interruptible-deadline-bound',
    }),
    offlineOsvDatabase: frozen({
      status: 'sealed-capability-required',
      generation: requiredOfflineOsvDatabase.generation,
      bytes: requiredOfflineOsvDatabase.bytes,
      sha256: requiredOfflineOsvDatabase.sha256,
      runtimeRelativePath: requiredOfflineOsvDatabase.runtimeRelativePath,
      sandboxPath: requiredOfflineOsvDatabase.sandboxPath,
      scannerArguments: requiredOfflineOsvDatabase.scannerArguments,
      environment: requiredOfflineOsvDatabase.environment,
      network: 'blocked',
    }),
    child: frozen({
      prlimitArguments: frozen([...requiredPrlimitArguments]),
      nproc: 'not-set',
      limits,
      seccompPolicySha256: resourceSeccompPolicySha256,
      seccomp: 'passed',
      network: 'blocked',
    }),
  });
};

const probeViaSelfAttachingLauncher = ({ root, tools, launcher, testLauncherPath }) => {
  const cgroupPath = newAnalysisCgroupPath(root);
  activeAnalysisCgroups.add(cgroupPath);
  let result;
  try {
    result = spawnSync(tools.node.path, [
      launcher === undefined ? testLauncherPath : '/proc/self/fd/3',
      '--probe',
    ], {
      cwd: '/',
      encoding: 'utf8',
      env: fixedHostEnvironment,
      input: JSON.stringify({
        schemaVersion: resourceGovernanceSchemaVersion,
        kind: 'probe',
        cgroupRoot: root,
        cgroupPath,
        tools,
      }),
      killSignal: 'SIGKILL',
      maxBuffer: ResourceProbeOutputBytes,
      ...(launcher === undefined
        ? {}
        : { stdio: ['pipe', 'pipe', 'pipe', launcher.fd] }),
      timeout: ResourceProbeTimeoutMs,
      windowsHide: true,
    });
  } finally {
    activeAnalysisCgroups.delete(cgroupPath);
    if (existsSync(cgroupPath)) cleanupReportedCgroup(cgroupPath);
  }
  if (
    result.error !== undefined ||
    result.signal !== null ||
    result.status !== 0 ||
    Buffer.byteLength(String(result.stdout ?? '')) +
      Buffer.byteLength(String(result.stderr ?? '')) > ResourceProbeOutputBytes ||
    result.stderr !== ''
  ) {
    fail('resource-probe-failed', 'The self-attaching governance probe did not complete.');
  }
  let decoded;
  try {
    decoded = JSON.parse(result.stdout);
  } catch (cause) {
    fail('resource-probe-invalid', 'The self-attaching governance probe returned malformed JSON.', cause);
  }
  const response = requireRecord(decoded, 'resource probe response', 'resource-probe-invalid');
  requireExactKeys(
    response,
    ['schemaVersion', 'kind', 'evidence'],
    'resource probe response',
    'resource-probe-invalid',
  );
  if (
    response.schemaVersion !== resourceGovernanceSchemaVersion ||
    response.kind !== 'probe-result'
  ) {
    fail('resource-probe-invalid', 'The self-attaching governance probe returned the wrong protocol.');
  }
  return frozen({
    ...response.evidence,
    controlLauncher: launcher === undefined
      ? frozen({ status: 'test-injected' })
      : frozen({
          status: 'authenticated',
          path: launcher.path,
          byteLength: launcher.byteLength,
          sha256: launcher.sha256,
          mode: launcher.mode,
          identity: launcher.identity,
        }),
  });
};

const defaultAnchor = () => validatedAnchor(runtimeTrustAnchor.resourceGovernance);

const retainedGovernanceLauncher = analyzerControl => {
  let control;
  try {
    control = inspectAnalyzerControl(analyzerControl);
  } catch (cause) {
    fail('analyzer-control-invalid', 'A live retained analyzer-control capability is required.', cause);
  }
  const launcher = control.files.find(file => file.path === 'resource-governance-launcher.mjs');
  if (launcher === undefined || launcher.mode !== '0444') {
    fail('analyzer-control-invalid', 'The retained standalone governance launcher is unavailable.');
  }
  return launcher;
};

/**
 * Strict readiness proof. This is intentionally Linux-only. A Darwin or
 * undelegated Linux workstation cannot report "ready" by running a weakened
 * substitute probe.
 */
export const verifyResourceGovernance = ({ cgroupRoot, analyzerControl }) => {
  assertLinux();
  const tools = defaultAnchor();
  assertSeccompPolicyAnchor(tools);
  // Authenticate every host executable before it starts the self-attaching
  // launcher. Build package provenance (including dpkg) is never consulted.
  verifyTrustedHostTool(tools.bwrap);
  verifyTrustedHostTool(tools.prlimit);
  verifyTrustedHostTool(tools.node);
  const root = canonicalCgroupRoot(cgroupRoot);
  assertDelegatedCgroupRoot(root);
  assertNoUnownedAnalysisCgroups(root);
  return probeViaSelfAttachingLauncher({
    root,
    tools,
    launcher: retainedGovernanceLauncher(analyzerControl),
  });
};

/** Test-only dependency injection; production callers must use the pinned API above. */
export const verifyResourceGovernanceForTest = ({ cgroupRoot, tools, launcherPath }) => {
  assertLinux();
  const anchor = validatedAnchor({
    schemaVersion: resourceGovernanceSchemaVersion,
    ...tools,
    seccompPolicySha256: resourceSeccompPolicySha256,
  });
  assertSeccompPolicyAnchor(anchor);
  verifyTrustedHostTool(anchor.bwrap);
  verifyTrustedHostTool(anchor.prlimit);
  verifyTrustedHostTool(anchor.node);
  const root = canonicalCgroupRoot(cgroupRoot);
  assertDelegatedCgroupRoot(root);
  assertNoUnownedAnalysisCgroups(root);
  return probeViaSelfAttachingLauncher({
    root,
    tools: anchor,
    testLauncherPath: requireAbsolutePath(launcherPath, 'test launcher path'),
  });
};

const parseProbeProtocol = input => {
  if (typeof input !== 'string' || Buffer.byteLength(input) > 16 * 1024) {
    fail('protocol-invalid', 'The probe protocol input exceeded its bounded size.');
  }
  let decoded;
  try {
    decoded = JSON.parse(input);
  } catch (cause) {
    fail('protocol-invalid', 'The probe protocol input was not JSON.', cause);
  }
  const request = requireRecord(decoded, 'probe request');
  requireExactKeys(
    request,
    ['schemaVersion', 'kind', 'cgroupRoot', 'cgroupPath', 'tools'],
    'probe request',
  );
  if (request.schemaVersion !== resourceGovernanceSchemaVersion || request.kind !== 'probe') {
    fail('protocol-invalid', 'The probe protocol input had an unsupported schema or kind.');
  }
  const root = canonicalCgroupRoot(request.cgroupRoot);
  return frozen({
    root,
    cgroupPath: validateOwnedCgroupPath(root, request.cgroupPath),
    tools: validatedAnchor(request.tools),
  });
};

export const runResourceGovernanceProbeProtocol = input => {
  assertLinux();
  const request = parseProbeProtocol(input);
  assertSeccompPolicyAnchor(request.tools);
  verifyTrustedHostTool(request.tools.bwrap);
  verifyTrustedHostTool(request.tools.prlimit);
  verifyTrustedHostTool(request.tools.node);
  return probeEvidence(request);
};

const send = message => {
  if (typeof process.send === 'function' && process.connected) process.send(message);
};

const safeError = error => frozen({
  code: error instanceof ResourceGovernanceError ? error.code : 'launcher-failed',
  message: 'The resource-governed analyzer launcher failed.',
});

export const runResourceGovernanceLaunchProtocol = async requestValue => {
  assertLinux();
  const request = validateLaunchRequest(requestValue);
  assertSeccompPolicyAnchor(request.tools);
  let child;
  let lease;
  let policy;
  let settled = false;
  let timeout;
  let terminate;
  const completed = new Promise(resolve => {
    terminate = (reason, childExitCode) => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) clearTimeout(timeout);
      let cleanupError;
      try { lease?.release(); } catch (cause) { cleanupError = cause; }
      const exitCode = cleanupError === undefined
        ? reason === 'timeout' ? 124 : reason === 'cancel' ? 130 : childExitCode ?? 1
        : 125;
      send({
        schemaVersion: resourceGovernanceSchemaVersion,
        kind: cleanupError === undefined ? 'terminated' : 'error',
        reason,
        exitCode,
        ...(cleanupError === undefined ? {} : safeError(cleanupError)),
      });
      resolve(exitCode);
    };
  });
  const cancellation = message => {
    if (
      isRecord(message) &&
      message.schemaVersion === resourceGovernanceSchemaVersion &&
      message.kind === 'cancel'
    ) {
      terminate('cancel');
    }
  };
  process.on('message', cancellation);
  // An abruptly terminated app parent closes the authenticated IPC channel.
  // Treat that exactly like cancellation so the still-live launcher kills
  // descendants and removes its owned cgroup before it exits.
  const parentDisconnected = () => terminate('cancel');
  process.once('disconnect', parentDisconnected);
  const signalHandlers = new Map();
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    const handler = () => terminate('cancel');
    signalHandlers.set(signal, handler);
    process.once(signal, handler);
  }
  try {
    verifyTrustedHostTool(request.tools.bwrap);
    verifyTrustedHostTool(request.tools.prlimit);
    verifyTrustedHostTool(request.tools.node);
    assertDelegatedCgroupRoot(request.cgroupRoot);
    lease = new AnalysisCgroupLease(request.cgroupRoot, request.cgroupPath);
    send({
      schemaVersion: resourceGovernanceSchemaVersion,
      kind: 'allocated',
      cgroupPath: lease.path,
    });
    lease.attachSelf();
    policy = createSeccompFile();
    const command = buildResourceGovernedCommandForDescriptor(
      request.bwrapArguments,
      SandboxSeccompDescriptor,
      { trustedArguments: request.mode === 'materialized' },
    );
    if (
      command.executable !== request.tools.prlimit.path ||
      command.arguments.at(requiredPrlimitArguments.length) !== request.tools.bwrap.path
    ) {
      fail('resource-governance-anchor-invalid', 'The launcher command did not match its canonical host-tool paths.');
    }
    child = spawn(
      command.executable,
      command.arguments,
      {
        cwd: request.cwd,
        detached: false,
        env: request.environment,
        shell: false,
        // Production has one fixed analyzer descriptor layout. The already
        // materialized runtime becomes FD 3, the launcher-owned seccomp
        // policy FD 4, OSV alone receives its sealed DB at FD 5, and the
        // source/request are 6/7. The shorter vector closes the trusted outer
        // launcher/addon descriptors before analyzer exec.
        stdio: request.mode === 'materialized'
          ? [
              'ignore',
              'inherit',
              'inherit',
              LauncherRuntimeRootDescriptor,
              policy.descriptor,
              isOsvAnalyzer(request.analyzerId)
                ? LauncherOsvDatabaseDescriptor
                : 'ignore',
              LauncherSourceDescriptor,
              LauncherRequestDescriptor,
            ]
          : [
              'ignore',
              'inherit',
              'inherit',
              LauncherTestSnapshotDescriptor,
              policy.descriptor,
              request.databaseDescriptor === LauncherTestDatabaseDescriptor
                ? LauncherTestDatabaseDescriptor
                : 'ignore',
            ],
        windowsHide: true,
      },
    );
    policy.release();
    policy = undefined;
    child.once('error', () => terminate('exit', 1));
    child.once('close', code => terminate('exit', code ?? 1));
    timeout = setTimeout(() => terminate('timeout'), request.timeoutMs);
    send({
      schemaVersion: resourceGovernanceSchemaVersion,
      kind: 'ready',
      evidence: frozen({
        cgroupV2: frozen({
          controllers: frozen([...requiredCgroupControllers]),
          pidsMax: requiredCgroupLimits.pidsMax,
          memoryMax: requiredCgroupLimits.memoryMax,
          memorySwapMax: requiredCgroupLimits.memorySwapMax,
          memoryOomGroup: requiredCgroupLimits.memoryOomGroup,
          cpuMax: requiredCgroupLimits.cpuMax,
          ownership: 'parent-pre-registered',
          launcherCrashCleanup: 'parent-supervised',
          staleCgroupPolicy: 'reject-unowned',
        }),
        child: frozen({
          prlimitArguments: frozen([...requiredPrlimitArguments]),
          nproc: 'not-set',
          seccompPolicySha256: resourceSeccompPolicySha256,
          network: 'blocked',
        }),
        launch: frozen({
          runtimeRootChildDescriptor: request.mode === 'materialized'
            ? SandboxRuntimeRootDescriptor
            : null,
          testSnapshotChildDescriptor: request.mode === 'test'
            ? SandboxRuntimeRootDescriptor
            : null,
          seccompChildDescriptor: SandboxSeccompDescriptor,
          osvDatabaseChildDescriptor: isOsvAnalyzer(request.analyzerId)
            ? SandboxOsvDatabaseDescriptor
            : null,
          sourceChildDescriptor: request.mode === 'materialized' ? SandboxSourceDescriptor : null,
          requestChildDescriptor: request.mode === 'materialized' ? SandboxRequestDescriptor : null,
          namespaceArguments: frozen(['--unshare-all', '--unshare-net']),
          maximumConcurrentAnalyzers: 1,
          admission: 'fifo-interruptible-deadline-bound',
        }),
        offlineOsvDatabase: frozen({
          status: isOsvAnalyzer(request.analyzerId) ? 'authenticated' : 'withheld',
          generation: requiredOfflineOsvDatabase.generation,
          bytes: requiredOfflineOsvDatabase.bytes,
          sha256: requiredOfflineOsvDatabase.sha256,
          runtimeRelativePath: requiredOfflineOsvDatabase.runtimeRelativePath,
          sandboxPath: requiredOfflineOsvDatabase.sandboxPath,
          network: 'blocked',
        }),
      }),
    });
    const exitCode = await completed;
    process.exitCode = exitCode ?? 0;
  } catch (error) {
    try { policy?.release(); } catch {}
    try { lease?.release(); } catch {}
    send({
      schemaVersion: resourceGovernanceSchemaVersion,
      kind: 'error',
      ...safeError(error),
    });
    process.exitCode = 125;
  } finally {
    process.off('message', cancellation);
    process.off('disconnect', parentDisconnected);
    for (const [signal, handler] of signalHandlers) process.off(signal, handler);
  }
};

const launcherEnvironment = () => ({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin',
});

const validateSnapshotSourceFd = value => {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('snapshot-descriptor-invalid', 'The sealed runtime snapshot descriptor is invalid.');
  }
  let metadata;
  try {
    metadata = fstatSync(value);
  } catch (cause) {
    fail('snapshot-descriptor-unavailable', 'The sealed runtime snapshot descriptor is unavailable.', cause);
  }
  if (!metadata.isFile() || metadata.size <= 0) {
    fail('snapshot-descriptor-invalid', 'The sealed runtime snapshot descriptor is not a non-empty file.');
  }
  return value;
};

const inspectRuntimeCapability = materializedRuntime => {
  try {
    return inspectMaterializedAnalyzerRuntime(materializedRuntime);
  } catch (cause) {
    fail('materialized-runtime-invalid', 'A live branded materialized runtime capability is required.', cause);
  }
};

const validateSourceFd = ({ value, label, kind, maximumBytes }) => {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('source-descriptor-invalid', `The ${label} descriptor is invalid.`);
  }
  let metadata;
  try {
    metadata = fstatSync(value);
  } catch (cause) {
    fail('source-descriptor-unavailable', `The ${label} descriptor is unavailable.`, cause);
  }
  if (
    (kind === 'directory' ? !metadata.isDirectory() : !metadata.isFile()) ||
    (kind === 'file' && (metadata.size <= 0 || metadata.size > maximumBytes))
  ) {
    fail('source-descriptor-invalid', `The ${label} descriptor has invalid metadata.`);
  }
  return value;
};

const sameDescriptorSnapshot = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

const sealAnalyzerRequest = ({ sourceFd, runtime }) => {
  let before;
  try {
    before = fstatSync(sourceFd, { bigint: true });
  } catch (cause) {
    fail('request-descriptor-unavailable', 'The analyzer request descriptor is unavailable.', cause);
  }
  if (
    !before.isFile() ||
    before.size < 1n ||
    before.size > BigInt(MaximumAnalyzerRequestBytes)
  ) {
    fail('request-descriptor-invalid', 'The analyzer request must be a bounded non-empty regular file.');
  }
  let requestFd;
  try {
    const bridge = loadRuntimeMemfdBridgeFromDescriptor({
      addonFd: runtime.addonFd,
      addonBytes: runtime.addonBytes,
      addonSha256: runtime.addonSha256,
      addonIdentity: runtime.addonIdentity,
      addonMaximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    });
    requestFd = bridge.createData();
    if (!Number.isSafeInteger(requestFd) || requestFd < 0) {
      fail('request-seal-failed', 'The runtime memfd bridge returned an invalid request descriptor.');
    }
    const byteLength = Number(before.size);
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
    let position = 0;
    while (position < byteLength) {
      const read = readSync(
        sourceFd,
        buffer,
        0,
        Math.min(buffer.byteLength, byteLength - position),
        position,
      );
      if (read <= 0) fail('request-changed', 'The analyzer request became truncated while it was sealed.');
      hash.update(buffer.subarray(0, read));
      let written = 0;
      while (written < read) {
        const count = writeSync(
          requestFd,
          buffer,
          written,
          read - written,
          position + written,
        );
        if (count <= 0) fail('request-seal-failed', 'The analyzer request memfd had a short write.');
        written += count;
      }
      position += read;
    }
    const after = fstatSync(sourceFd, { bigint: true });
    if (!sameDescriptorSnapshot(before, after)) {
      fail('request-changed', 'The analyzer request changed while its immutable snapshot was created.');
    }
    fchmodSync(requestFd, 0o444);
    fsyncSync(requestFd);
    bridge.seal(requestFd);
    const identity = serializeRuntimeDescriptorIdentity(fstatSync(requestFd, { bigint: true }));
    const sha256 = hash.digest('hex');
    const proof = assertSealedRuntimeMemfdDescriptor({
      bridge,
      fd: requestFd,
      byteLength,
      identity,
      maximumBytes: MaximumAnalyzerRequestBytes,
      sha256,
      label: 'analyzer request',
    });
    return frozen({
      fd: proof.fd,
      byteLength,
      sha256,
      identity: proof.identity,
    });
  } catch (cause) {
    if (requestFd !== undefined) {
      try { closeSync(requestFd); } catch {}
    }
    if (cause instanceof ResourceGovernanceError) throw cause;
    fail('request-seal-failed', 'The analyzer request could not be made immutable.', cause);
  }
};

const prepareResourceGovernedCapability = options => {
  const tools = defaultAnchor();
  assertSeccompPolicyAnchor(tools);
  const raw = requireRecord(options, 'launch capability options');
  requireExactKeys(
    raw,
    ['analyzerId', 'cgroupRoot', 'materializedRuntime'],
    'launch capability options',
  );
  const analyzerId = validateAnalyzerId(raw.analyzerId);
  verifyTrustedHostTool(tools.bwrap);
  verifyTrustedHostTool(tools.prlimit);
  verifyTrustedHostTool(tools.node);
  const cgroupRoot = canonicalCgroupRoot(raw.cgroupRoot);
  assertDelegatedCgroupRoot(cgroupRoot);
  assertNoUnownedAnalysisCgroups(cgroupRoot);
  const runtime = inspectRuntimeCapability(raw.materializedRuntime);
  if (
    runtime.osvDatabaseSha256 !== requiredOfflineOsvDatabase.sha256 ||
    runtime.osvDatabaseBytes !== requiredOfflineOsvDatabase.bytes ||
    runtime.osvDatabaseGeneration !== requiredOfflineOsvDatabase.generation ||
    runtime.osvDatabaseRelativePath !== requiredOfflineOsvDatabase.runtimeRelativePath ||
    runtime.nodePath !== '/runtime/bin/node' ||
    runtime.runnerPath !== '/runtime/bin/radar-semantic-analyzer.mjs' ||
    !Number.isSafeInteger(runtime.launcherFd) || runtime.launcherFd < 0 ||
    !Number.isSafeInteger(runtime.launcherBytes) || runtime.launcherBytes < 1 ||
    !sha256Pattern.test(runtime.launcherSha256) ||
    !Number.isSafeInteger(runtime.addonFd) || runtime.addonFd < 0 ||
    !Number.isSafeInteger(runtime.addonBytes) || runtime.addonBytes < 1 ||
    !sha256Pattern.test(runtime.addonSha256)
  ) {
    fail('materialized-runtime-invalid', 'The branded materialized runtime does not carry the required capabilities.');
  }
  const materializedProtocol = frozen({
    manifestSha256: runtime.manifestSha256,
    runnerSha256: runtime.runnerSha256,
    nodeSha256: runtime.nodeSha256,
    runtimeRootIdentity: runtime.runtimeRootIdentity,
    osvDatabaseSha256: runtime.osvDatabaseSha256,
    osvDatabaseBytes: runtime.osvDatabaseBytes,
    osvDatabaseGeneration: runtime.osvDatabaseGeneration,
    osvDatabaseIdentity: runtime.osvDatabaseIdentity,
    launcherBytes: runtime.launcherBytes,
    launcherSha256: runtime.launcherSha256,
    launcherIdentity: runtime.launcherIdentity,
    addonBytes: runtime.addonBytes,
    addonSha256: runtime.addonSha256,
    addonIdentity: runtime.addonIdentity,
  });
  return frozen({ analyzerId, cgroupRoot, runtime, materializedProtocol, tools });
};

export const assertResourceGovernedLaunchCapability = options => {
  assertLinux();
  const capability = prepareResourceGovernedCapability(options);
  return frozen({
    schemaVersion: 'codebase-radar.analyzer-resource-launch-capability/v1',
    analyzerId: capability.analyzerId,
    cgroupRoot: capability.cgroupRoot,
    runtime: frozen({
      schemaVersion: capability.runtime.schemaVersion,
      manifestSha256: capability.runtime.manifestSha256,
      runnerSha256: capability.runtime.runnerSha256,
      nodeSha256: capability.runtime.nodeSha256,
      runtimeRootIdentity: capability.runtime.runtimeRootIdentity,
    }),
    offlineOsvDatabase: frozen({
      status: isOsvAnalyzer(capability.analyzerId) ? 'authenticated' : 'withheld',
      generation: requiredOfflineOsvDatabase.generation,
      bytes: requiredOfflineOsvDatabase.bytes,
      sha256: requiredOfflineOsvDatabase.sha256,
      runtimeRelativePath: requiredOfflineOsvDatabase.runtimeRelativePath,
      sandboxPath: requiredOfflineOsvDatabase.sandboxPath,
      network: 'blocked',
    }),
  });
};

const launchRequest = options => {
  const raw = requireRecord(options, 'launch options');
  requireExactKeys(
    raw,
    [
      'analyzerId',
      'cgroupRoot',
      'materializedRuntime',
      'sourceFd',
      'analyzerRequestFd',
      'timeoutMs',
    ],
    'launch options',
  );
  const capability = prepareResourceGovernedCapability({
    analyzerId: raw.analyzerId,
    cgroupRoot: raw.cgroupRoot,
    materializedRuntime: raw.materializedRuntime,
  });
  const sourceFd = validateSourceFd({
    value: raw.sourceFd,
    label: 'source workspace',
    kind: 'directory',
  });
  const analyzerRequestFd = validateSourceFd({
    value: raw.analyzerRequestFd,
    label: 'analyzer request',
    kind: 'file',
    maximumBytes: MaximumAnalyzerRequestBytes,
  });
  const sealedRequest = sealAnalyzerRequest({
    sourceFd: analyzerRequestFd,
    runtime: capability.runtime,
  });
  const cgroupPath = newAnalysisCgroupPath(capability.cgroupRoot);
  return frozen({
    request: frozen({
      schemaVersion: resourceGovernanceSchemaVersion,
      kind: 'launch',
      mode: 'materialized',
      analyzerId: capability.analyzerId,
      cgroupRoot: capability.cgroupRoot,
      cgroupPath,
      cwd: '/',
      timeoutMs: raw.timeoutMs,
      runtimeRootDescriptor: LauncherRuntimeRootDescriptor,
      osvDatabaseDescriptor: isOsvAnalyzer(capability.analyzerId)
        ? LauncherOsvDatabaseDescriptor
        : null,
      sourceDescriptor: LauncherSourceDescriptor,
      requestDescriptor: LauncherRequestDescriptor,
      runtime: frozen({
        ...capability.materializedProtocol,
        analyzerRequestBytes: sealedRequest.byteLength,
        analyzerRequestSha256: sealedRequest.sha256,
        analyzerRequestIdentity: sealedRequest.identity,
      }),
      tools: capability.tools,
    }),
    inherited: frozen({
      launcherFd: capability.runtime.launcherFd,
      runtimeRootFd: capability.runtime.runtimeRootFd,
      osvDatabaseFd: isOsvAnalyzer(capability.analyzerId)
        ? capability.runtime.osvDatabaseFd
        : null,
      sourceFd,
      analyzerRequestFd: sealedRequest.fd,
      ownedAnalyzerRequestFd: sealedRequest.fd,
      addonFd: capability.runtime.addonFd,
    }),
  });
};

/**
 * Starts only the trusted short-lived launcher. The returned ChildProcess is
 * the launcher, not bwrap: callers must use cancel() so cgroup cleanup can
 * run; they must never SIGKILL it directly.
 */
const startResourceGovernedLaunch = async (request, inherited, signal) => {
  const allocatedPath = request.cgroupPath;
  activeAnalysisCgroups.add(allocatedPath);
  let child;
  let inheritedCleanupError;
  try {
    child = spawn(
      request.tools.node.path,
      [request.mode === 'materialized' ? '/proc/self/fd/4' : inherited.testLauncherPath],
      {
      cwd: '/',
      detached: false,
      env: launcherEnvironment(),
      shell: false,
      stdio: request.mode === 'materialized'
        ? [
            'ignore',
            'pipe',
            'pipe',
            'ipc',
            inherited.launcherFd,
            inherited.runtimeRootFd,
            inherited.osvDatabaseFd ?? 'ignore',
            inherited.sourceFd,
            inherited.analyzerRequestFd,
            inherited.addonFd,
          ]
        : [
            'ignore',
            'pipe',
            'pipe',
            'ipc',
            inherited.snapshotFd,
            inherited.databaseFd ?? 'ignore',
          ],
      windowsHide: true,
      },
    );
  } catch (cause) {
    activeAnalysisCgroups.delete(allocatedPath);
    fail('launcher-start-failed', 'The resource-governed launcher could not start.', cause);
  } finally {
    if (inherited.ownedAnalyzerRequestFd !== undefined) {
      try {
        closeSync(inherited.ownedAnalyzerRequestFd);
      } catch (cause) {
        inheritedCleanupError = cause;
      }
    }
  }
  if (inheritedCleanupError !== undefined) {
    if (child.connected) {
      child.send({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'cancel' });
    }
    activeAnalysisCgroups.delete(allocatedPath);
    fail(
      'request-descriptor-cleanup-failed',
      'The parent could not close its immutable analyzer request descriptor.',
      inheritedCleanupError,
    );
  }
  const cancelFromSignal = () => {
    if (child.connected) {
      child.send({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'cancel' });
    }
  };
  signal?.addEventListener('abort', cancelFromSignal, { once: true });
  const completion = new Promise(resolveCompletion => {
    let completed = false;
    let protocolFailure;
    const cleanupAfterLauncherFailure = () => {
      if (!existsSync(allocatedPath)) return 'not-needed';
      try {
        cleanupReportedCgroup(allocatedPath);
        return 'passed';
      } catch {
        return 'failed';
      }
    };
    const complete = result => {
      if (completed) return;
      completed = true;
      child.off('message', observeTerminal);
      signal?.removeEventListener('abort', cancelFromSignal);
      if (allocatedPath !== undefined) activeAnalysisCgroups.delete(allocatedPath);
      resolveCompletion(frozen(result));
    };
    const observeTerminal = message => {
      if (!isRecord(message) || message.schemaVersion !== resourceGovernanceSchemaVersion) return;
      if (message.kind === 'allocated') {
        try {
          const reportedPath = validateOwnedCgroupPath(request.cgroupRoot, message.cgroupPath);
          if (reportedPath !== allocatedPath) {
            fail('cgroup-path-invalid', 'The launcher reported a cgroup other than its pre-registered allocation.');
          }
        } catch (error) {
          protocolFailure = error instanceof ResourceGovernanceError
            ? error.code
            : 'cgroup-path-invalid';
          if (child.connected) {
            child.send({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'cancel' });
          }
        }
        return;
      }
      if (message.kind === 'terminated') {
        const cleanup = cleanupAfterLauncherFailure();
        complete({
          status: protocolFailure === undefined && cleanup !== 'failed' ? 'terminated' : 'failed',
          reason: protocolFailure === undefined ? message.reason : 'invalid-cgroup-allocation',
          exitCode: protocolFailure === undefined ? message.exitCode : 125,
          cleanup,
          ...(cleanup === 'failed'
            ? { errorCode: 'cgroup-cleanup-failed' }
            : protocolFailure === undefined
              ? {}
              : { errorCode: protocolFailure }),
        });
      } else if (message.kind === 'error') {
        const cleanup = cleanupAfterLauncherFailure();
        complete({
          status: 'failed',
          reason: message.reason ?? 'launcher-error',
          exitCode: message.exitCode ?? 125,
          cleanup,
          errorCode: cleanup === 'failed'
            ? 'cgroup-cleanup-failed'
            : message.code ?? 'launcher-failed',
        });
      }
    };
    child.on('message', observeTerminal);
    child.once('error', () => {
      const cleanup = cleanupAfterLauncherFailure();
      complete({
        status: 'failed',
        reason: 'launcher-start-failed',
        exitCode: 125,
        cleanup,
        errorCode: cleanup === 'failed' ? 'cgroup-cleanup-failed' : 'launcher-start-failed',
      });
    });
    child.once('close', (exitCode, signal) => {
      if (completed) return;
      const cleanup = cleanupAfterLauncherFailure();
      const errorCode = cleanup === 'failed'
        ? 'cgroup-cleanup-failed'
        : protocolFailure ?? 'launcher-exited-without-terminal';
      complete({
        status: 'failed',
        reason: protocolFailure === undefined
          ? 'launcher-exited-without-terminal'
          : 'invalid-cgroup-allocation',
        exitCode: exitCode ?? 125,
        signal,
        cleanup,
        errorCode,
      });
    });
  });
  let evidence;
  try {
    evidence = await new Promise((resolvePromise, reject) => {
    let settled = false;
    const finish = callback => value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off('message', onMessage);
      child.off('error', onError);
      child.off('exit', onExit);
      callback(value);
    };
    const failHandshake = finish(error => {
      if (child.connected) {
        child.send({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'cancel' });
      }
      reject(error);
    });
    const succeed = finish(value => resolvePromise(value));
    const onMessage = message => {
      if (!isRecord(message) || message.schemaVersion !== resourceGovernanceSchemaVersion) return;
      if (message.kind === 'ready') succeed(message.evidence);
      else if (message.kind === 'error') {
        failHandshake(new ResourceGovernanceError(message.code ?? 'launcher-failed', 'The resource-governed launcher rejected startup.'));
      }
    };
    const onError = () => failHandshake(new ResourceGovernanceError('launcher-start-failed', 'The resource-governed launcher could not start.'));
    const onExit = () => failHandshake(new ResourceGovernanceError('launcher-start-failed', 'The resource-governed launcher exited before readiness.'));
    const timer = setTimeout(
      () => failHandshake(new ResourceGovernanceError('launcher-handshake-timeout', 'The resource-governed launcher did not attest startup in time.')),
      LaunchHandshakeTimeoutMs,
    );
    child.on('message', onMessage);
    child.once('error', onError);
    child.once('exit', onExit);
    child.send(request, error => {
      if (error !== null && error !== undefined) onError();
    });
    if (signal?.aborted === true) cancelFromSignal();
    });
  } catch (error) {
    await completion;
    throw error;
  }
  return frozen({
    child,
    evidence,
    completion,
    cancel: () => {
      if (!child.connected) return false;
      child.send({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'cancel' });
      return true;
    },
  });
};

const startWithLaunchAdmission = async ({ timeoutMs, signal, prepare }) => {
  const validatedTimeout = validateTimeout(timeoutMs);
  const cancellationSignal = validateAbortSignal(signal);
  const deadline = Date.now() + validatedTimeout;
  const admission = await acquireLaunchAdmission({
    signal: cancellationSignal,
    timeoutMs: validatedTimeout,
  });
  let retainedThroughCompletion = false;
  try {
    if (cancellationSignal?.aborted === true) {
      fail('launch-cancelled', 'The analyzer launch was cancelled after admission.');
    }
    const remaining = deadline - Date.now();
    if (!Number.isSafeInteger(remaining) || remaining < 1) {
      fail('launch-admission-timeout', 'The analyzer launch deadline elapsed during admission.');
    }
    const launch = prepare(Math.min(remaining, validatedTimeout));
    const session = await startResourceGovernedLaunch(
      launch.request,
      launch.inherited,
      cancellationSignal,
    );
    const completion = session.completion.finally(() => admission.release());
    retainedThroughCompletion = true;
    return frozen({ ...session, completion });
  } finally {
    if (!retainedThroughCompletion) admission.release();
  }
};

export const launchResourceGovernedAnalyzer = async options => {
  assertLinux();
  const raw = requireRecord(options, 'launch options');
  const keys = [
    'analyzerId',
    'cgroupRoot',
    'materializedRuntime',
    'sourceFd',
    'analyzerRequestFd',
    'timeoutMs',
  ];
  const optionalKeys = ['signal'].filter(key => Object.hasOwn(raw, key));
  requireExactKeys(
    raw,
    [...keys, ...optionalKeys],
    'launch options',
  );
  return startWithLaunchAdmission({
    timeoutMs: raw.timeoutMs,
    signal: raw.signal,
    prepare: timeoutMs => launchRequest({
      analyzerId: raw.analyzerId,
      cgroupRoot: raw.cgroupRoot,
      materializedRuntime: raw.materializedRuntime,
      sourceFd: raw.sourceFd,
      analyzerRequestFd: raw.analyzerRequestFd,
      timeoutMs,
    }),
  });
};

/**
 * Test-only launch injection. It exists solely so an explicitly delegated
 * Linux harness can use fixture-specific raw hashes without weakening the
 * production entry point's compiled anchor.
 */
export const launchResourceGovernedAnalyzerForTest = async options => {
  assertLinux();
  const raw = requireRecord(options, 'test launch options');
  const keys = [
    'analyzerId',
    'cgroupRoot',
    'bwrapArguments',
    'environment',
    'timeoutMs',
    'snapshotFd',
    'launcherPath',
    'tools',
  ];
  const optionalKeys = ['databaseFd', 'signal'].filter(key => Object.hasOwn(raw, key));
  requireExactKeys(
    raw,
    [...keys, ...optionalKeys],
    'test launch options',
  );
  return startWithLaunchAdmission({
    timeoutMs: raw.timeoutMs,
    signal: raw.signal,
    prepare: timeoutMs => {
      const snapshotFd = validateSnapshotSourceFd(raw.snapshotFd);
      const databaseFd = raw.databaseFd === undefined
        ? null
        : validateSourceFd({
            value: raw.databaseFd,
            label: 'test database',
            kind: 'file',
            maximumBytes: 256 * 1024 * 1024,
          });
      const cgroupRoot = canonicalCgroupRoot(raw.cgroupRoot);
      assertDelegatedCgroupRoot(cgroupRoot);
      assertNoUnownedAnalysisCgroups(cgroupRoot);
      const cgroupPath = newAnalysisCgroupPath(cgroupRoot);
      const tools = validatedAnchor({
        schemaVersion: resourceGovernanceSchemaVersion,
        ...raw.tools,
        seccompPolicySha256: resourceSeccompPolicySha256,
      });
      const request = frozen({
        schemaVersion: resourceGovernanceSchemaVersion,
        kind: 'launch',
        mode: 'test',
        analyzerId: raw.analyzerId,
        cgroupRoot,
        cgroupPath,
        bwrapArguments: raw.bwrapArguments,
        environment: raw.environment,
        cwd: '/',
        timeoutMs,
        snapshotDescriptor: LauncherTestSnapshotDescriptor,
        databaseDescriptor: databaseFd === null ? null : LauncherTestDatabaseDescriptor,
        tools,
      });
      // Validate exactly the same protocol the child receives before starting it.
      const validated = validateLaunchRequest(request, { requireInheritedSnapshot: false });
      assertSeccompPolicyAnchor(validated.tools);
      return frozen({
        request: validated,
        inherited: frozen({
          snapshotFd,
          databaseFd,
          testLauncherPath: requireAbsolutePath(raw.launcherPath, 'test launcher path'),
        }),
      });
    },
  });
};
