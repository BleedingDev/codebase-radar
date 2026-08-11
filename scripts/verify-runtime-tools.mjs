import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  detectRuntimePlatform,
  getRuntimePreparationPlan,
  linuxX64Glibc,
  readRuntimeManifest,
  verifyNpmSourceIntegrityEvidence,
  verifyRuntime,
} from '../packages/analyzer-runtime/runtime-manifest.mjs';

const scriptPath = realpathSync(fileURLToPath(import.meta.url));
const workspaceRoot = realpathSync(resolve(dirname(scriptPath), '..'));
const trustedVerifierPath = realpathSync(
  resolve(workspaceRoot, 'packages/analyzer-runtime/runtime-manifest.mjs'),
);
const trustedLockPath = realpathSync(resolve(workspaceRoot, 'pnpm-lock.yaml'));
const trustedOsvValidatorRoot = realpathSync(
  resolve(workspaceRoot, 'packages/analyzer-runtime'),
);
const expectedManifestSha256 =
  '0dfb7a8f17b53dfcf75a2a8c1684cfe33b3bfc42f65798ed4695a2966a6d4c0a';
const expectedTargetVerifierSha256 =
  '37a332ea096895ad0a79c83d4f824a2c8b08df2a1c8116536c7616734e99e375';
const outerTimeoutMs = 120000;
const outerMaxOutputBytes = 131072;
const trustedOsvValidatorMaximumBytes = 4 * 1024 * 1024;
const osvValidatorSchemaVersion =
  'codebase-radar.osv-npm-snapshot-validator/v1';
const bootstrapEnvironmentKey = 'RADAR_RUNTIME_BOOTSTRAPPED';
const forbiddenEnvironmentPattern =
  /^(?:NODE_(?:OPTIONS|PATH|PRESERVE_SYMLINKS(?:_MAIN)?|COMPILE_CACHE|LOADER|REQUIRE)|LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|BUN_OPTIONS|DENO_.*|ESM_LOADER|TSX_.*|PYTHON.*|RUBYOPT)$/u;

class BootstrapError extends Error {
  constructor(code, message) {
    super('[runtime:' + code + '] ' + message);
    this.name = 'BootstrapError';
  }
}

const fail = (code, message) => {
  throw new BootstrapError(code, message);
};

const isWithin = (root, candidate) => {
  const prefix = root.endsWith(sep) ? root : root + sep;
  return candidate === root || candidate.startsWith(prefix);
};

const controlReadBounds = Object.freeze({
  fileBytes: 4 * 1024 * 1024,
  aggregateBytes: 8 * 1024 * 1024,
  chunkBytes: 64 * 1024,
  deadlineMs: 30_000,
});

const sameBigintMetadata = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

const sha256BoundedControlFile = ({ path, label, budget }) => {
  if (Date.now() - budget.startedAt > controlReadBounds.deadlineMs) {
    fail('control-read-timeout', 'Trusted control authentication exceeded its deadline.');
  }
  let before;
  try {
    before = lstatSync(path, { bigint: true });
  } catch {
    fail('control-file-missing', label + ' is missing.');
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.size < 0n ||
    before.size > BigInt(controlReadBounds.fileBytes)
  ) {
    fail('control-file-invalid', label + ' must be a bounded single-link regular non-symlink file.');
  }
  const nextAggregate = budget.bytes + before.size;
  if (nextAggregate > BigInt(controlReadBounds.aggregateBytes)) {
    fail('control-read-limit', 'Trusted control authentication exceeded its aggregate byte limit.');
  }
  budget.bytes = nextAggregate;
  let descriptor;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | constants.O_CLOEXEC | constants.O_NOFOLLOW,
    );
  } catch {
    fail('control-file-changed', label + ' could not be opened without following links.');
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (!sameBigintMetadata(before, opened)) {
      fail('control-file-changed', label + ' changed before it was opened.');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(controlReadBounds.chunkBytes);
    let offset = 0n;
    while (offset < opened.size) {
      if (Date.now() - budget.startedAt > controlReadBounds.deadlineMs) {
        fail('control-read-timeout', 'Trusted control authentication exceeded its deadline.');
      }
      const length = Number(
        opened.size - offset > BigInt(buffer.length)
          ? BigInt(buffer.length)
          : opened.size - offset,
      );
      const count = readSync(descriptor, buffer, 0, length, offset);
      if (count !== length) {
        fail('control-file-changed', label + ' changed while it was read.');
      }
      hash.update(buffer.subarray(0, count));
      offset += BigInt(count);
    }
    const afterDescriptor = fstatSync(descriptor, { bigint: true });
    let afterPath;
    try {
      afterPath = lstatSync(path, { bigint: true });
    } catch {
      fail('control-file-changed', label + ' disappeared while it was authenticated.');
    }
    if (
      !sameBigintMetadata(opened, afterDescriptor) ||
      !sameBigintMetadata(opened, afterPath)
    ) {
      fail('control-file-changed', label + ' changed while it was authenticated.');
    }
    return hash.digest('hex');
  } finally {
    closeSync(descriptor);
  }
};

const assertCleanInvocationEnvironment = () => {
  const unsafe = Object.keys(process.env).filter(key =>
    forbiddenEnvironmentPattern.test(key),
  );
  if (unsafe.length > 0) {
    fail(
      'bootstrap-environment-rejected',
      'Refusing loader/preload environment variables: ' + unsafe.sort().join(', ') + '.',
    );
  }
};

const assertBootstrapped = () => {
  if (process.env[bootstrapEnvironmentKey] !== '1') {
    fail(
      'bootstrap-required',
      'Use scripts/verify-runtime-tools.sh so loader and preload variables are cleared before Node starts.',
    );
  }
};

const parseOptions = argv => {
  const [first, ...rest] = argv;
  const command = first === undefined ? 'verify' : first;
  if (
    command !== 'verify' &&
    command !== 'prepare-plan' &&
    command !== 'validate-osv-snapshot'
  ) {
    fail(
      'cli-usage',
      'Expected command "verify", "prepare-plan", or "validate-osv-snapshot"; positional runtime roots are not accepted.',
    );
  }
  if (rest.length % 2 !== 0) fail('cli-usage', 'Expected --name value pairs.');
  const options = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (
      typeof flag !== 'string' ||
      !flag.startsWith('--') ||
      flag.length === 2 ||
      typeof value !== 'string' ||
      value.length === 0 ||
      options.has(flag)
    ) {
      fail('cli-usage', 'Expected unique non-empty --name value pairs.');
    }
    options.set(flag, value);
  }
  const supported = new Set([
    '--runtime-root',
    '--platform',
    '--architecture',
    '--libc',
    '--osv-snapshot',
  ]);
  for (const flag of options.keys()) {
    if (!supported.has(flag)) fail('cli-usage', 'Unsupported option ' + flag + '.');
  }
  if (command === 'validate-osv-snapshot') {
    if (!options.has('--osv-snapshot')) {
      fail(
        'cli-usage',
        'validate-osv-snapshot requires an explicit --osv-snapshot path.',
      );
    }
  } else if (options.has('--osv-snapshot')) {
    fail(
      'cli-usage',
      '--osv-snapshot is accepted only by validate-osv-snapshot.',
    );
  }
  return { command, options };
};

const selectTarget = options => {
  const target = {
    os: options.get('--platform') ?? linuxX64Glibc.os,
    architecture: options.get('--architecture') ?? linuxX64Glibc.architecture,
    libc: options.get('--libc') ?? linuxX64Glibc.libc,
  };
  if (
    target.os !== linuxX64Glibc.os ||
    target.architecture !== linuxX64Glibc.architecture ||
    target.libc !== linuxX64Glibc.libc
  ) {
    fail(
      'platform-unsupported',
      'Only linux/x64/glibc is supported; got ' +
        target.os +
        '/' +
        target.architecture +
        '/' +
        target.libc +
        '.',
    );
  }
  return target;
};

const validateAbsoluteRoot = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    !isAbsolute(value)
  ) {
    fail(
      'root-override-invalid',
      'RADAR_ANALYZER_ROOT and --runtime-root must be non-empty absolute paths without control characters.',
    );
  }
  let metadata;
  try {
    metadata = lstatSync(value);
  } catch {
    fail('root-missing', 'Analyzer runtime root does not exist: ' + value + '.');
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(
      'root-invalid',
      'Analyzer runtime root must be a non-symlink directory: ' + value + '.',
    );
  }
  const root = realpathSync(value);
  if (isWithin(root, trustedVerifierPath) || isWithin(root, scriptPath)) {
    fail(
      'trusted-verifier-overlap',
      'The selected runtime contains the trusted workspace verifier; select a deployed sibling runtime instead.',
    );
  }
  return root;
};

const selectRoot = options => {
  const override = process.env.RADAR_ANALYZER_ROOT;
  const explicit = options.get('--runtime-root');
  const validatedOverride = override === undefined
    ? undefined
    : validateAbsoluteRoot(override);
  const validatedExplicit = explicit === undefined
    ? undefined
    : validateAbsoluteRoot(explicit);
  if (
    validatedOverride !== undefined &&
    validatedExplicit !== undefined &&
    validatedOverride !== validatedExplicit
  ) {
    fail(
      'root-override-conflict',
      'RADAR_ANALYZER_ROOT and --runtime-root must name the same explicit runtime root.',
    );
  }
  if (validatedOverride !== undefined) return validatedOverride;
  if (validatedExplicit !== undefined) return validatedExplicit;
  fail(
    'root-required',
    'An explicit absolute freshly staged runtime root is required through RADAR_ANALYZER_ROOT or --runtime-root.',
  );
};

const controlPath = (root, path) => {
  const candidate = resolve(root, path);
  if (!isWithin(root, candidate)) {
    fail('path-escape', 'Control path ' + path + ' escapes the selected runtime root.');
  }
  const fragments = relative(root, candidate).split(sep);
  let current = root;
  for (const component of fragments) {
    current = resolve(current, component);
    let metadata;
    try {
      metadata = lstatSync(current);
    } catch {
      fail('control-file-missing', 'Control path ' + path + ' is missing.');
    }
    if (metadata.isSymbolicLink()) {
      fail('control-symlink-rejected', 'Control path ' + path + ' contains a symlink.');
    }
  }
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    fail('control-file-missing', 'Control path ' + path + ' is missing.');
  }
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1
  ) {
    fail(
      'control-file-invalid',
      'Control path ' +
        path +
        ' must be an independently linked regular non-symlink file.',
    );
  }
  const canonical = realpathSync(candidate);
  if (!isWithin(root, canonical)) {
    fail(
      'path-escape',
      'Control path ' + path + ' resolves outside the selected runtime root.',
    );
  }
  return canonical;
};

const verifyTargetControlFiles = root => {
  const manifestPath = controlPath(root, 'runtime-manifest.json');
  const targetVerifierPath = controlPath(root, 'runtime-manifest.mjs');
  const budget = { startedAt: Date.now(), bytes: 0n };
  const manifestSha256 = sha256BoundedControlFile({
    path: manifestPath,
    label: 'Target runtime manifest',
    budget,
  });
  if (manifestSha256 !== expectedManifestSha256) {
    fail(
      'manifest-authentication-failed',
      'Target manifest sha256 ' +
        manifestSha256 +
        ' does not match the reviewed runtime manifest.',
    );
  }
  const verifierSha256 = sha256BoundedControlFile({
    path: targetVerifierPath,
    label: 'Target runtime manifest verifier',
    budget,
  });
  if (verifierSha256 !== expectedTargetVerifierSha256) {
    fail(
      'target-verifier-layout-mismatch',
      'Target runtime-manifest.mjs sha256 ' +
        verifierSha256 +
        ' does not match the deployed layout.',
    );
  }
  return manifestPath;
};

const stableMetadata = metadata => ({
  device: metadata.dev,
  inode: metadata.ino,
  mode: metadata.mode,
  size: metadata.size,
  links: metadata.nlink,
});

const sameMetadata = (left, right) =>
  left.device === right.device &&
  left.inode === right.inode &&
  left.mode === right.mode &&
  left.size === right.size &&
  left.links === right.links;

const requireTrustedValidatorRecord = value => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('osv-validator-record-invalid', 'The offline OSV validator record must be an object.');
  }
  const expectedKeys = ['schemaVersion', 'path', 'byteLength', 'sha256'].sort(
    (left, right) => left.localeCompare(right),
  );
  const actualKeys = Object.keys(value).sort((left, right) =>
    left.localeCompare(right),
  );
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail('osv-validator-record-invalid', 'The offline OSV validator record has an invalid schema.');
  }
  if (value.schemaVersion !== osvValidatorSchemaVersion) {
    fail('osv-validator-record-invalid', 'The offline OSV validator record has an unsupported schema version.');
  }
  if (
    typeof value.path !== 'string' ||
    value.path.length === 0 ||
    value.path !== value.path.trim() ||
    value.path.includes('\\') ||
    value.path.startsWith('/') ||
    value.path.split('/').some(component => component === '' || component === '.' || component === '..')
  ) {
    fail('osv-validator-record-invalid', 'The offline OSV validator path is invalid.');
  }
  if (
    !Number.isSafeInteger(value.byteLength) ||
    value.byteLength < 1 ||
    value.byteLength > trustedOsvValidatorMaximumBytes
  ) {
    fail('osv-validator-record-invalid', 'The offline OSV validator byte length is invalid.');
  }
  if (typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(value.sha256)) {
    fail('osv-validator-record-invalid', 'The offline OSV validator SHA-256 is invalid.');
  }
  return value;
};

const authenticatedOsvValidatorSource = record => {
  const validator = requireTrustedValidatorRecord(record);
  const candidate = resolve(trustedOsvValidatorRoot, validator.path);
  if (!isWithin(trustedOsvValidatorRoot, candidate)) {
    fail('osv-validator-path-escape', 'The offline OSV validator path escapes its trusted source root.');
  }
  const components = relative(trustedOsvValidatorRoot, candidate).split(sep);
  let current = trustedOsvValidatorRoot;
  for (let index = 0; index < components.length; index += 1) {
    current = resolve(current, components[index]);
    let metadata;
    try {
      metadata = lstatSync(current);
    } catch {
      fail('osv-validator-missing', 'The offline OSV validator source is missing.');
    }
    if (
      metadata.isSymbolicLink() ||
      (index < components.length - 1 && !metadata.isDirectory())
    ) {
      fail('osv-validator-metadata-invalid', 'The offline OSV validator source contains an invalid path component.');
    }
  }
  let before;
  try {
    before = lstatSync(candidate);
  } catch {
    fail('osv-validator-missing', 'The offline OSV validator source is missing.');
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size !== validator.byteLength
  ) {
    fail('osv-validator-metadata-invalid', 'The offline OSV validator source metadata does not match its record.');
  }
  let descriptor;
  try {
    descriptor = openSync(
      candidate,
      constants.O_RDONLY | constants.O_CLOEXEC | constants.O_NOFOLLOW,
    );
  } catch {
    fail('osv-validator-read-failed', 'The offline OSV validator source could not be opened safely.');
  }
  try {
    const opened = fstatSync(descriptor);
    if (!sameMetadata(stableMetadata(before), stableMetadata(opened))) {
      fail('osv-validator-changed', 'The offline OSV validator source changed before it was opened.');
    }
    const source = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < source.byteLength) {
      const count = readSync(
        descriptor,
        source,
        offset,
        Math.min(64 * 1024, source.byteLength - offset),
        offset,
      );
      if (count <= 0) {
        fail('osv-validator-changed', 'The offline OSV validator source changed while it was read.');
      }
      offset += count;
    }
    let after;
    try {
      after = lstatSync(candidate);
    } catch {
      fail('osv-validator-changed', 'The offline OSV validator source disappeared while it was authenticated.');
    }
    if (
      !sameMetadata(stableMetadata(opened), stableMetadata(fstatSync(descriptor))) ||
      !sameMetadata(stableMetadata(opened), stableMetadata(after)) ||
      source.byteLength !== validator.byteLength ||
      createHash('sha256').update(source).digest('hex') !== validator.sha256
    ) {
      fail('osv-validator-authentication-failed', 'The offline OSV validator source does not match its authenticated record.');
    }
    return source;
  } finally {
    closeSync(descriptor);
  }
};

const canonicalJson = value => {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      fail('osv-evidence-invalid', 'Offline OSV evidence contains a non-finite number.');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(item => canonicalJson(item)).join(',') + ']';
  }
  if (
    typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  ) {
    return (
      '{' +
      Object.keys(value)
        .sort((left, right) => left.localeCompare(right))
        .map(key => JSON.stringify(key) + ':' + canonicalJson(value[key]))
        .join(',') +
      '}'
    );
  }
  fail('osv-evidence-invalid', 'Offline OSV evidence contains a non-JSON value.');
};

const validateOfflineOsvSnapshot = async ({ manifest, snapshot }) => {
  const database = manifest.offlineOsvDatabase;
  if (database === null || typeof database !== 'object' || Array.isArray(database)) {
    fail('osv-evidence-invalid', 'The manifest offline OSV database record is invalid.');
  }
  const expectedEvidence = database.validationEvidence;
  if (expectedEvidence === undefined) {
    fail('osv-evidence-invalid', 'The manifest does not contain pinned offline OSV validation evidence.');
  }
  const source = authenticatedOsvValidatorSource(database.validator);
  let module;
  try {
    // Import the authenticated byte snapshot, never the mutable pathname. The
    // validator imports only Node built-ins, so it has no relative dependency.
    module = await import(
      'data:text/javascript;base64,' + source.toString('base64'),
    );
  } catch {
    fail('osv-validator-import-failed', 'The authenticated offline OSV validator could not be imported.');
  }
  if (typeof module.generatePinnedOsvNpmSnapshotEvidenceFile !== 'function') {
    fail('osv-validator-api-invalid', 'The authenticated offline OSV validator has no pinned file API.');
  }
  let generated;
  try {
    generated = await module.generatePinnedOsvNpmSnapshotEvidenceFile(snapshot);
  } catch {
    fail('osv-snapshot-validation-failed', 'The downloaded offline OSV snapshot failed strict validation.');
  }
  const expectedCanonical = canonicalJson(expectedEvidence);
  const generatedCanonical = canonicalJson(generated);
  if (generatedCanonical !== expectedCanonical) {
    fail('osv-evidence-mismatch', 'The downloaded offline OSV snapshot does not match the manifest-pinned validation evidence.');
  }
  return generated;
};

const selectOsvSnapshot = options => {
  const snapshot = options.get('--osv-snapshot');
  if (
    typeof snapshot !== 'string' ||
    snapshot.length === 0 ||
    snapshot !== snapshot.trim() ||
    /[\u0000-\u001f\u007f]/u.test(snapshot) ||
    !isAbsolute(snapshot)
  ) {
    fail('osv-snapshot-path-invalid', 'The offline OSV snapshot must be an absolute path without control characters.');
  }
  let metadata;
  try {
    metadata = lstatSync(snapshot);
  } catch {
    fail('osv-snapshot-missing', 'The offline OSV snapshot is missing.');
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail('osv-snapshot-invalid', 'The offline OSV snapshot must be a single-link regular non-symlink file.');
  }
  return snapshot;
};

const cleanWorkerEnvironment = () => ({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin',
  [bootstrapEnvironmentKey]: '1',
});

const runWorker = ({ command, root, target, osvSnapshot }) => {
  const workerArgs = [
    scriptPath,
    '--worker',
    command,
    '--runtime-root',
    root,
    '--platform',
    target.os,
    '--architecture',
    target.architecture,
    '--libc',
    target.libc,
    ...(osvSnapshot === undefined ? [] : ['--osv-snapshot', osvSnapshot]),
  ];
  const result = spawnSync(process.execPath, workerArgs, {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env: cleanWorkerEnvironment(),
    killSignal: 'SIGKILL',
    maxBuffer: outerMaxOutputBytes,
    timeout: outerTimeoutMs,
    windowsHide: true,
  });
  const stdout = String(result.stdout ?? '');
  const stderr = String(result.stderr ?? '');
  if (result.error?.code === 'ETIMEDOUT') {
    fail(
      'outer-verification-timeout',
      'Trusted runtime verification exceeded ' + outerTimeoutMs + 'ms.',
    );
  }
  if (
    result.error?.code === 'ENOBUFS' ||
    Buffer.byteLength(stdout) + Buffer.byteLength(stderr) >
      outerMaxOutputBytes
  ) {
    fail(
      'outer-verification-output-limit',
      'Trusted runtime verification exceeded its output limit.',
    );
  }
  if (result.error !== undefined) {
    fail('outer-verification-failed', result.error.message);
  }
  process.stdout.write(stdout);
  process.stderr.write(stderr);
  if (result.signal !== null || result.status !== 0) process.exitCode = 1;
};

const runWorkerCommand = async argv => {
  assertBootstrapped();
  assertCleanInvocationEnvironment();
  const parsed = parseOptions(argv);
  const target = selectTarget(parsed.options);
  const root = selectRoot(parsed.options);
  const manifestPath = verifyTargetControlFiles(root);
  const manifest = readRuntimeManifest(manifestPath);
  verifyNpmSourceIntegrityEvidence(manifest, trustedLockPath);
  if (parsed.command === 'prepare-plan') {
    for (const item of getRuntimePreparationPlan(manifest, target)) {
      process.stdout.write(
        [
          item.analyzerId,
          item.url,
          item.sourceSha256,
          item.format,
          item.archiveMember,
          item.output,
          item.installedSha256,
        ].join('\t') + '\n',
      );
    }
    return;
  }
  if (parsed.command === 'validate-osv-snapshot') {
    const snapshot = selectOsvSnapshot(parsed.options);
    const evidence = await validateOfflineOsvSnapshot({ manifest, snapshot });
    process.stdout.write(canonicalJson(evidence) + '\n');
    return;
  }
  const host = detectRuntimePlatform();
  if (
    host.os !== linuxX64Glibc.os ||
    host.architecture !== linuxX64Glibc.architecture ||
    host.libc !== linuxX64Glibc.libc
  ) {
    fail(
      'linux-acceptance-required',
      'Native analyzer acceptance requires linux/x64/glibc; current host is ' +
        host.os +
        '/' +
        host.architecture +
        '/' +
        host.libc +
        '.',
    );
  }
  const result = verifyRuntime({
    root,
    target,
    lockPath: trustedLockPath,
  });
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
};

const main = async () => {
  assertBootstrapped();
  const argv = process.argv.slice(2);
  if (argv[0] === '--worker') {
    await runWorkerCommand(argv.slice(1));
    return;
  }
  assertCleanInvocationEnvironment();
  const parsed = parseOptions(argv);
  const root = selectRoot(parsed.options);
  const target = selectTarget(parsed.options);
  runWorker({
    command: parsed.command,
    root,
    target,
    osvSnapshot: parsed.options.get('--osv-snapshot'),
  });
};

try {
  await main();
} catch (error) {
  process.stderr.write(
    (error instanceof Error ? error.message : String(error)) + '\n',
  );
  process.exitCode = 1;
}
