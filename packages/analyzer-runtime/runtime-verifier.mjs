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
import { dirname, isAbsolute, join, sep } from 'node:path';
import {
  canonicalManifestPolicySha256,
  requiredHostIsolation,
  requiredSemanticRunnerPath,
  runtimeVerificationBounds,
  verifyRuntime,
} from './runtime-manifest.mjs';
import {
  AnalyzerControlVerificationError,
  verifyAnalyzerControl as verifyRetainedAnalyzerControl,
} from './runtime-control-root.mjs';
import { verifyResourceGovernance } from './resource-governance.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

// The retained descriptor capability is intentionally implemented in a leaf
// module so sealing and resource governance can consume it without a cycle.
export { verifyAnalyzerControl } from './runtime-control-root.mjs';

export class AnalyzerRuntimeVerificationError extends Error {
  constructor(code, message, cause) {
    super(`[runtime:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'AnalyzerRuntimeVerificationError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new AnalyzerRuntimeVerificationError(code, message, cause);
};

// The verifier and its trust anchor are trusted application code, never part
// of the target being authenticated. Modern bundles this module, so a source
// import.meta.url would point at the build machine. Resolve the independently
// protected absolute entrypoint's regular package root instead.
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

const isWithin = (root, candidate) => {
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  return candidate === root || candidate.startsWith(prefix);
};

const readTargetGeneration = (root, code) => {
  let metadata;
  try {
    metadata = lstatSync(root, { bigint: true });
  } catch (cause) {
    fail(code, 'Analyzer runtime root generation could not be inspected.', cause);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(code, 'Analyzer runtime root generation is not a non-symlink directory.');
  }
  return Object.freeze({
    device: metadata.dev.toString(10),
    inode: metadata.ino.toString(10),
  });
};

const sameTargetGeneration = (left, right) =>
  left.device === right.device && left.inode === right.inode;

const controlTimestamp = (metadata, field) => {
  const value = metadata[`${field}Ns`];
  if (typeof value !== 'bigint') {
    fail('trusted-control-invalid', `Trusted ${field} metadata is not a bigint.`);
  }
  return value;
};

const sameControlSnapshot = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  controlTimestamp(left, 'mtime') === controlTimestamp(right, 'mtime') &&
  controlTimestamp(left, 'ctime') === controlTimestamp(right, 'ctime');

const createControlBudget = () => ({
  deadline: process.hrtime.bigint() + BigInt(runtimeVerificationBounds.deadlineMs) * 1_000_000n,
  bytes: 0n,
});

const reserveControlBytes = (budget, bytes, label) => {
  if (process.hrtime.bigint() > budget.deadline) {
    fail('trusted-control-time-limit', `Trusted ${label} verification exceeded its deadline.`);
  }
  const next = budget.bytes + bytes;
  if (next > BigInt(runtimeVerificationBounds.aggregateBytes)) {
    fail('trusted-control-byte-limit', `Trusted ${label} verification exceeded its aggregate byte limit.`);
  }
  budget.bytes = next;
};

const assertBoundedControl = (metadata, label, maximumBytes) => {
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
    fail(
      'trusted-control-invalid',
      `${label} must be an independently linked regular non-symlink file.`,
    );
  }
  if (metadata.size < 0n || metadata.size > BigInt(maximumBytes)) {
    fail(
      'trusted-control-oversize',
      `${label} exceeds its ${maximumBytes} byte verification limit.`,
    );
  }
};

const openBoundedControl = ({ path, label, maximumBytes, budget }) => {
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (cause) {
    fail('trusted-control-missing', `${label} is missing.`, cause);
  }
  assertBoundedControl(metadata, label, maximumBytes);
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (cause) {
    fail('trusted-control-invalid', `${label} could not be opened without following links.`, cause);
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    assertBoundedControl(opened, label, maximumBytes);
    if (!sameControlSnapshot(metadata, opened)) {
      fail('trusted-control-changed', `${label} changed while it was opened.`);
    }
    reserveControlBytes(budget, opened.size, label);
    return { descriptor, metadata: opened };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
};

const canonicalRuntimeRoot = root => {
  if (
    typeof root !== 'string' ||
    root.length === 0 ||
    root !== root.trim() ||
    !isAbsolute(root) ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(root)
  ) {
    fail('root-invalid', 'Analyzer runtime root must be an absolute, trimmed path without control characters.');
  }
  let metadata;
  try {
    metadata = lstatSync(root);
  } catch (cause) {
    fail('root-missing', 'Analyzer runtime root does not exist.', cause);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('root-invalid', 'Analyzer runtime root must be a non-symlink directory.');
  }
  const canonicalRoot = realpathSync(root);
  const applicationRoot = trustedApplicationRoot();
  if (
    isWithin(canonicalRoot, applicationRoot) ||
    isWithin(applicationRoot, canonicalRoot)
  ) {
    fail(
      'root-overlap',
      'Analyzer runtime root must not overlap the trusted verifier module root.',
    );
  }
  return Object.freeze({
    root: canonicalRoot,
    targetGeneration: readTargetGeneration(canonicalRoot, 'root-invalid'),
  });
};

const authenticateControl = ({
  root,
  relativePath,
  expectedSha256,
  label,
  maximumBytes,
  budget,
}) => {
  const path = join(root, relativePath);
  const { descriptor, metadata } = openBoundedControl({
    path,
    label,
    maximumBytes,
    budget,
  });
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(runtimeVerificationBounds.chunkBytes);
  try {
    const expectedBytes = Number(metadata.size);
    let offset = 0;
    while (offset < expectedBytes) {
      if (process.hrtime.bigint() > budget.deadline) {
        fail('trusted-control-time-limit', `Trusted ${label} verification exceeded its deadline.`);
      }
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, expectedBytes - offset),
        offset,
      );
      if (bytesRead <= 0) {
        fail('trusted-control-changed', `${label} became shorter while it was hashed.`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(descriptor, extra, 0, 1, expectedBytes) !== 0) {
      fail('trusted-control-changed', `${label} grew while it was hashed.`);
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameControlSnapshot(metadata, after)) {
      fail('trusted-control-changed', `${label} changed while it was hashed.`);
    }
  } finally {
    closeSync(descriptor);
  }
  const actualSha256 = hash.digest('hex');
  if (actualSha256 !== expectedSha256) {
    fail(
      'trusted-control-mismatch',
      `${label} sha256 ${actualSha256} does not match the compiled trust anchor.`,
    );
  }
};

const assertCompiledAnchor = () => {
  if (runtimeTrustAnchor.policyDigest !== canonicalManifestPolicySha256) {
    fail('compiled-anchor-invalid', 'Compiled policy digest and trusted verifier disagree.');
  }
  if (
    runtimeTrustAnchor.sandbox.kind !== requiredHostIsolation.kind ||
    runtimeTrustAnchor.sandbox.path !== requiredHostIsolation.path ||
    runtimeTrustAnchor.sandbox.required !== requiredHostIsolation.required ||
    runtimeTrustAnchor.sandbox.packageVersion !== requiredHostIsolation.packageVersion ||
    runtimeTrustAnchor.sandbox.versionOutput !== requiredHostIsolation.versionOutput
  ) {
    fail('compiled-anchor-invalid', 'Compiled sandbox identity and trusted verifier disagree.');
  }
};

export const verifyAnalyzerRuntime = ({ root: requestedRoot, cgroupRoot, analyzerControlRoot }) => {
  assertCompiledAnchor();
  const { root, targetGeneration } = canonicalRuntimeRoot(requestedRoot);
  const controlBudget = createControlBudget();
  authenticateControl({
    root,
    relativePath: 'runtime-manifest.json',
    expectedSha256: runtimeTrustAnchor.manifestSha256,
    label: 'Analyzer runtime manifest',
    maximumBytes: runtimeVerificationBounds.manifestBytes,
    budget: controlBudget,
  });
  authenticateControl({
    root,
    relativePath: requiredSemanticRunnerPath,
    expectedSha256: runtimeTrustAnchor.runnerSha256,
    label: 'Semantic analyzer runner',
    maximumBytes: runtimeVerificationBounds.runtimeArtifactBytes,
    budget: controlBudget,
  });

  let analyzerControl;
  try {
    analyzerControl = verifyRetainedAnalyzerControl({
      controlRoot: analyzerControlRoot,
      runtimeRoot: root,
    });
  } catch (cause) {
    if (cause instanceof AnalyzerControlVerificationError) {
      fail(cause.code, cause.message, cause);
    }
    fail('analyzer-control-unavailable', 'Trusted analyzer-control verification failed.', cause);
  }

  try {
    let evidence;
    try {
      evidence = verifyRuntime({ root });
    } catch (cause) {
      fail('runtime-unavailable', 'Analyzer runtime failed trusted verification.', cause);
    }

    // verifyRuntime performs its final complete static re-authentication before
    // returning evidence. The pathname must still identify the generation that
    // was captured before verification, otherwise an atomic publisher replaced
    // the target between verification and use.
    const finalTargetGeneration = readTargetGeneration(root, 'target-generation-changed');
    if (!sameTargetGeneration(targetGeneration, finalTargetGeneration)) {
      fail('target-generation-changed', 'Analyzer runtime target generation changed during verification.');
    }

    if (
      evidence.profile !== 'dogfood:max/v1' ||
      evidence.hostIsolation.kind !== runtimeTrustAnchor.sandbox.kind ||
      evidence.hostIsolation.path !== runtimeTrustAnchor.sandbox.path ||
      evidence.hostIsolation.packageVersion !== requiredHostIsolation.packageVersion ||
      evidence.hostIsolation.version !== requiredHostIsolation.versionOutput ||
      evidence.hostIsolation.strictProbe !== 'passed'
    ) {
      fail('runtime-identity-mismatch', 'Verified runtime evidence does not match the compiled trust anchor.');
    }

    let resourceGovernance;
    try {
      resourceGovernance = verifyResourceGovernance({ cgroupRoot, analyzerControl });
    } catch (cause) {
      fail(
        'resource-governance-unavailable',
        'The required Linux child resource-governance boundary is unavailable.',
        cause,
      );
    }

    return Object.freeze({
      schemaVersion: 'codebase-radar.analyzer-runtime-identity/v1',
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      policyDigest: runtimeTrustAnchor.policyDigest,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      buildIdentity: runtimeTrustAnchor.buildIdentity,
      targetGeneration,
      analyzerControl,
      sandbox: Object.freeze({
        kind: evidence.hostIsolation.kind,
        packageVersion: evidence.hostIsolation.packageVersion,
        version: evidence.hostIsolation.version,
        strictProbe: evidence.hostIsolation.strictProbe,
      }),
      resourceGovernance,
      analyzers: Object.freeze(
        evidence.analyzers.map(item => Object.freeze({
          analyzer: item.analyzer,
          version: item.version,
        })),
      ),
    });
  } catch (cause) {
    analyzerControl.close();
    throw cause;
  }
};
