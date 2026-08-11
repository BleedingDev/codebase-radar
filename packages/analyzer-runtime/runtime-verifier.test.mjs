import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  cpSync,
  existsSync,
  fstatSync,
  ftruncateSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  canonicalManifestDigest,
  canonicalManifestPolicySha256,
  runtimeVerificationBounds,
} from './runtime-manifest.mjs';
import {
  AnalyzerRuntimeVerificationError,
  verifyAnalyzerRuntime,
} from './runtime-verifier.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const temporaryRoots = [];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

const writeStubResourceGovernance = directory => {
  writeFileSync(
    join(directory, 'resource-governance.mjs'),
    [
      "export const verifyResourceGovernance = () => Object.freeze({",
      "  schemaVersion: 'codebase-radar.analyzer-resource-governance/v1',",
      "  status: 'passed',",
      "  cgroupV2: Object.freeze({ controllers: Object.freeze(['cpu', 'memory', 'pids']), pidsMax: '128', memoryMax: '2147483648', memorySwapMax: '0', memoryOomGroup: '1', cpuMax: '200000 100000', cleanup: 'passed' }),",
      "  tools: Object.freeze({ bwrap: Object.freeze({ path: '/usr/bin/bwrap', sha256: 'a'.repeat(64), versionFirstLine: 'bubblewrap 0.9.0' }), prlimit: Object.freeze({ path: '/usr/bin/prlimit', sha256: 'b'.repeat(64), versionFirstLine: 'prlimit from util-linux 2.39.3' }), node: Object.freeze({ path: '/usr/local/bin/node', sha256: 'c'.repeat(64), versionFirstLine: 'v24.test' }) }),",
      "  child: Object.freeze({ prlimitArguments: Object.freeze(['--core=0:0', '--fsize=16777216:16777216', '--nofile=256:256', '--cpu=130:130', '--as=8589934592:8589934592']), nproc: 'not-set', seccompPolicySha256: 'd'.repeat(64), seccomp: 'passed', network: 'blocked' }),",
      '});',
      '',
    ].join('\n'),
  );
};

// Generation tests isolate runtime replacement behavior from the separately
// tested root-owned control installation. The production verifier imports the
// same leaf module, so every synthetic verifier needs this narrow capability
// stub beside its other trusted dependencies.
const writeStubAnalyzerControl = directory => {
  writeFileSync(
    join(directory, 'runtime-control-root.mjs'),
    [
      'export class AnalyzerControlVerificationError extends Error {}',
      'export const verifyAnalyzerControl = () => Object.freeze({ close: () => {} });',
      '',
    ].join('\n'),
  );
};

const temporaryRuntime = () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-runtime-verifier-'));
  temporaryRoots.push(root);
  mkdirSync(join(root, 'bin'), { recursive: true });
  cpSync(join(packageRoot, 'runtime-manifest.json'), join(root, 'runtime-manifest.json'));
  cpSync(
    join(packageRoot, 'bin/radar-semantic-analyzer.mjs'),
    join(root, 'bin/radar-semantic-analyzer.mjs'),
  );
  return root;
};

const analyzerControlFixture = async () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'radar-analyzer-control-'));
  temporaryRoots.push(fixtureRoot);
  const verifierDirectory = join(fixtureRoot, 'trusted-verifier');
  const controlRoot = join(fixtureRoot, 'control');
  const externalRoot = join(fixtureRoot, 'external');
  const files = [
    { path: 'runtime-snapshot-loader.mjs', mode: 0o444, bytes: Buffer.from('export const loader = true;\n') },
    { path: 'resource-governance-launcher.mjs', mode: 0o444, bytes: Buffer.from('export const launcher = true;\n') },
    { path: 'runtime-memfd-addon.node', mode: 0o555, bytes: Buffer.from('not-a-real-addon\n') },
  ];
  mkdirSync(verifierDirectory, { recursive: true });
  mkdirSync(controlRoot, { recursive: true });
  mkdirSync(externalRoot, { recursive: true });
  for (const file of files) {
    writeFileSync(join(controlRoot, file.path), file.bytes);
    chmodSync(join(controlRoot, file.path), file.mode);
  }
  chmodSync(controlRoot, 0o555);
  cpSync(
    join(packageRoot, 'runtime-control-root.mjs'),
    join(verifierDirectory, 'runtime-control-root.mjs'),
  );
  writeFileSync(
    join(verifierDirectory, 'runtime-manifest.mjs'),
    `export const runtimeVerificationBounds = Object.freeze(${JSON.stringify({
      textBytes: 1024 * 1024,
      runtimeArtifactBytes: 4 * 1024 * 1024,
      aggregateBytes: 8 * 1024 * 1024,
      deadlineMs: 30_000,
      chunkBytes: 64 * 1024,
    })});\n`,
  );
  writeFileSync(
    join(verifierDirectory, 'trust-anchor.mjs'),
    [
      'export const runtimeTrustAnchor = Object.freeze({',
      '  analyzerControl: Object.freeze({',
      "    schemaVersion: 'codebase-radar.analyzer-control/v1',",
      "    root: Object.freeze({ uid: 0, gid: 0, mode: '0555' }),",
      '    files: Object.freeze([',
      ...files.map(file => `      Object.freeze(${JSON.stringify({
        path: file.path,
        byteLength: file.bytes.byteLength,
        sha256: sha256(file.bytes),
        mode: file.mode.toString(8).padStart(4, '0'),
      })}),`),
      '    ]),',
      '  }),',
      '});',
      '',
    ].join('\n'),
  );
  const verifier = await import(
    pathToFileURL(join(verifierDirectory, 'runtime-control-root.mjs')).href,
  );
  return { controlRoot, externalRoot, files, verifier };
};

const canExerciseRootOwnedControl = process.getuid?.() === 0;

const temporaryStubbedVerifier = async ({ mutateTargetGeneration = false } = {}) => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'radar-runtime-generation-'));
  temporaryRoots.push(fixtureRoot);
  const verifierDirectory = join(fixtureRoot, 'trusted-verifier');
  const runtimeRoot = join(fixtureRoot, 'runtime');
  const replacementRoot = join(fixtureRoot, 'replacement');
  const retiredRoot = join(fixtureRoot, 'retired');
  const manifestBytes = Buffer.from('{"fixture":"runtime"}\n');
  const runnerBytes = Buffer.from('process.exitCode = 1;\n');
  const policyDigest = 'runtime-verifier-generation-test-policy';
  const hostIsolation = {
    kind: 'bubblewrap',
    path: '/usr/bin/bwrap',
    required: true,
    packageVersion: '0.9.0-1ubuntu0.1',
    versionOutput: 'bubblewrap 0.9.0',
  };
  mkdirSync(join(runtimeRoot, 'bin'), { recursive: true });
  writeFileSync(join(runtimeRoot, 'runtime-manifest.json'), manifestBytes);
  writeFileSync(join(runtimeRoot, 'bin/radar-semantic-analyzer.mjs'), runnerBytes);
  if (mutateTargetGeneration) mkdirSync(replacementRoot, { recursive: true });
  mkdirSync(verifierDirectory, { recursive: true });
  cpSync(
    join(packageRoot, 'runtime-verifier.mjs'),
    join(verifierDirectory, 'runtime-verifier.mjs'),
  );
  writeStubResourceGovernance(verifierDirectory);
  writeStubAnalyzerControl(verifierDirectory);
  writeFileSync(
    join(verifierDirectory, 'trust-anchor.mjs'),
    [
      'export const runtimeTrustAnchor = Object.freeze({',
      "  schemaVersion: 'codebase-radar.analyzer-runtime-trust-anchor/v1',",
      `  manifestSha256: ${JSON.stringify(sha256(manifestBytes))},`,
      `  policyDigest: ${JSON.stringify(policyDigest)},`,
      `  runnerSha256: ${JSON.stringify(sha256(runnerBytes))},`,
      "  buildIdentity: 'runtime-verifier-generation-test-anchor',",
      `  sandbox: Object.freeze(${JSON.stringify(hostIsolation)}),`,
      '});',
      '',
    ].join('\n'),
  );
  writeFileSync(
    join(verifierDirectory, 'runtime-manifest.mjs'),
    [
      ...(mutateTargetGeneration ? ["import { renameSync } from 'node:fs';"] : []),
      `export const canonicalManifestPolicySha256 = ${JSON.stringify(policyDigest)};`,
      `export const requiredHostIsolation = Object.freeze(${JSON.stringify(hostIsolation)});`,
      "export const requiredSemanticRunnerPath = 'bin/radar-semantic-analyzer.mjs';",
      `export const runtimeVerificationBounds = Object.freeze(${JSON.stringify({
        manifestBytes: 4 * 1024 * 1024,
        runtimeArtifactBytes: 256 * 1024 * 1024,
        aggregateBytes: 1024 * 1024 * 1024,
        deadlineMs: 30_000,
        chunkBytes: 64 * 1024,
      })});`,
      'export const verifyRuntime = ({ root }) => {',
      ...(mutateTargetGeneration
        ? [
          `  renameSync(root, ${JSON.stringify(retiredRoot)});`,
          `  renameSync(${JSON.stringify(replacementRoot)}, root);`,
        ]
        : []),
      '  return {',
      "    profile: 'dogfood:max/v1',",
      "    hostIsolation: { kind: 'bubblewrap', path: '/usr/bin/bwrap', packageVersion: '0.9.0-1ubuntu0.1', version: 'bubblewrap 0.9.0', strictProbe: 'passed' },",
      '    analyzers: [],',
      '  };',
      '};',
      '',
    ].join('\n'),
  );
  const verifier = await import(
    pathToFileURL(join(verifierDirectory, 'runtime-verifier.mjs')).href,
  );
  return { verifier, runtimeRoot };
};

after(() => {
  for (const root of temporaryRoots) {
    // Root-owned-control fixtures deliberately lock their directory down to
    // mode 0555; restore test-fixture deletion permission before cleanup.
    try { chmodSync(join(root, 'control'), 0o755); } catch {}
    rmSync(root, { recursive: true, force: true });
  }
});

test('pins a deeply frozen compiled runtime trust anchor', () => {
  const manifestBytes = readFileSync(join(packageRoot, 'runtime-manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const runnerBytes = readFileSync(join(packageRoot, 'bin/radar-semantic-analyzer.mjs'));

  assert.equal(Object.isFrozen(runtimeTrustAnchor), true);
  assert.equal(Object.isFrozen(runtimeTrustAnchor.sandbox), true);
  assert.equal(runtimeTrustAnchor.manifestSha256, sha256(manifestBytes));
  assert.equal(runtimeTrustAnchor.runnerSha256, sha256(runnerBytes));
  assert.equal(runtimeTrustAnchor.policyDigest, canonicalManifestPolicySha256);
  assert.equal(runtimeTrustAnchor.policyDigest, canonicalManifestDigest(manifest));
  assert.deepEqual(runtimeTrustAnchor.sandbox, {
    kind: 'bubblewrap',
    path: '/usr/bin/bwrap',
    required: true,
    packageVersion: '0.9.0-1ubuntu0.1',
    versionOutput: 'bubblewrap 0.9.0',
  });
});

test('authenticates manifest and runner before native runtime verification', () => {
  const manifestRoot = temporaryRuntime();
  writeFileSync(join(manifestRoot, 'runtime-manifest.json'), '{}\n');
  assert.throws(
    () => verifyAnalyzerRuntime({ root: manifestRoot }),
    error =>
      error instanceof AnalyzerRuntimeVerificationError &&
      error.code === 'trusted-control-mismatch',
  );

  const runnerRoot = temporaryRuntime();
  writeFileSync(join(runnerRoot, 'bin/radar-semantic-analyzer.mjs'), 'process.exitCode = 0;\n');
  assert.throws(
    () => verifyAnalyzerRuntime({ root: runnerRoot }),
    error =>
      error instanceof AnalyzerRuntimeVerificationError &&
      error.code === 'trusted-control-mismatch',
  );
});

test('rejects a hard-linked manifest before native runtime verification', () => {
  const root = temporaryRuntime();
  const control = join(root, 'runtime-manifest.json');
  linkSync(control, join(root, 'runtime-manifest.json.hardlink'));
  assert.throws(
    () => verifyAnalyzerRuntime({ root }),
    error =>
      error instanceof AnalyzerRuntimeVerificationError &&
      error.code === 'trusted-control-invalid',
  );
});

test('rejects huge sparse manifest and runner controls before target verification', async () => {
  const manifestRoot = temporaryRuntime();
  const manifestDescriptor = openSync(join(manifestRoot, 'runtime-manifest.json'), 'r+');
  try {
    ftruncateSync(manifestDescriptor, runtimeVerificationBounds.manifestBytes + 1);
  } finally {
    closeSync(manifestDescriptor);
  }
  assert.throws(
    () => verifyAnalyzerRuntime({ root: manifestRoot }),
    error => error?.code === 'trusted-control-oversize',
  );

  const { verifier, runtimeRoot } = await temporaryStubbedVerifier();
  const runnerDescriptor = openSync(join(runtimeRoot, 'bin/radar-semantic-analyzer.mjs'), 'r+');
  try {
    ftruncateSync(runnerDescriptor, runtimeVerificationBounds.runtimeArtifactBytes + 1);
  } finally {
    closeSync(runnerDescriptor);
  }
  assert.throws(
    () => verifier.verifyAnalyzerRuntime({ root: runtimeRoot }),
    error => error?.code === 'trusted-control-oversize',
  );
});

test('rejects a hard-linked runner with a locally synchronized test anchor', async () => {
  const verifierDirectory = mkdtempSync(join(tmpdir(), 'radar-runtime-verifier-module-'));
  temporaryRoots.push(verifierDirectory);
  cpSync(
    join(packageRoot, 'runtime-verifier.mjs'),
    join(verifierDirectory, 'runtime-verifier.mjs'),
  );
  cpSync(
    join(packageRoot, 'runtime-manifest.mjs'),
    join(verifierDirectory, 'runtime-manifest.mjs'),
  );
  writeStubResourceGovernance(verifierDirectory);
  writeStubAnalyzerControl(verifierDirectory);
  writeFileSync(
    join(verifierDirectory, 'trust-anchor.mjs'),
    [
      'export const runtimeTrustAnchor = Object.freeze({',
      "  schemaVersion: 'codebase-radar.analyzer-runtime-trust-anchor/v1',",
      `  manifestSha256: ${JSON.stringify(sha256(readFileSync(join(packageRoot, 'runtime-manifest.json'))))},`,
      `  policyDigest: ${JSON.stringify(canonicalManifestPolicySha256)},`,
      `  runnerSha256: ${JSON.stringify(sha256(readFileSync(join(packageRoot, 'bin/radar-semantic-analyzer.mjs'))))},`,
      "  buildIdentity: 'runtime-verifier-test-anchor',",
      "  sandbox: Object.freeze({ kind: 'bubblewrap', path: '/usr/bin/bwrap', required: true, packageVersion: '0.9.0-1ubuntu0.1', versionOutput: 'bubblewrap 0.9.0' }),",
      '});',
      '',
    ].join('\n'),
  );
  const localVerifier = await import(
    pathToFileURL(join(verifierDirectory, 'runtime-verifier.mjs')).href,
  );
  const root = temporaryRuntime();
  const runner = join(root, 'bin/radar-semantic-analyzer.mjs');
  linkSync(runner, join(root, 'runner.hardlink'));
  assert.throws(
    () => localVerifier.verifyAnalyzerRuntime({ root }),
    error => error?.code === 'trusted-control-invalid',
  );
});

test('returns the immutable generation of the fully verified target root', async () => {
  const { verifier, runtimeRoot } = await temporaryStubbedVerifier();
  const identity = verifier.verifyAnalyzerRuntime({ root: runtimeRoot });
  const metadata = lstatSync(runtimeRoot, { bigint: true });
  assert.equal(Object.isFrozen(identity.targetGeneration), true);
  assert.deepEqual(identity.targetGeneration, {
    device: metadata.dev.toString(10),
    inode: metadata.ino.toString(10),
  });
});

test('rejects an exchanged target generation after final static re-authentication', async () => {
  const { verifier, runtimeRoot } = await temporaryStubbedVerifier({
    mutateTargetGeneration: true,
  });
  assert.throws(
    () => verifier.verifyAnalyzerRuntime({ root: runtimeRoot }),
    error => error?.code === 'target-generation-changed',
  );
});

test('rejects self-importing and overlapping trusted verifier targets', () => {
  for (const root of [
    packageRoot,
    join(packageRoot, 'bin'),
    dirname(packageRoot),
    '/',
  ]) {
    assert.throws(
      () => verifyAnalyzerRuntime({ root }),
      error =>
        error instanceof AnalyzerRuntimeVerificationError &&
        error.code === 'root-overlap',
      root,
    );
  }
});

test('never imports a target-supplied verifier', () => {
  const root = temporaryRuntime();
  const marker = join(root, 'target-verifier-executed');
  writeFileSync(
    join(root, 'runtime-manifest.mjs'),
    `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'bad');\n`,
  );
  assert.throws(
    () =>
      verifyAnalyzerRuntime({
        root,
        analyzerControlRoot: join(root, 'missing-analyzer-control'),
      }),
    error =>
      error instanceof AnalyzerRuntimeVerificationError &&
      error.code === 'analyzer-control-root-invalid',
  );
  assert.equal(existsSync(marker), false);
});

test('rejects relative, control-bearing, missing, and symlink roots', () => {
  assert.throws(() => verifyAnalyzerRuntime({ root: 'relative' }), /root-invalid/u);
  assert.throws(() => verifyAnalyzerRuntime({ root: '/tmp/radar\u0080runtime' }), /root-invalid/u);
  assert.throws(
    () => verifyAnalyzerRuntime({ root: join(tmpdir(), 'radar-runtime-does-not-exist') }),
    /root-missing/u,
  );
});

test('requires an explicit absolute analyzer-control root', async () => {
  const { verifier } = await analyzerControlFixture();
  assert.throws(
    () => verifier.verifyAnalyzerControl({ controlRoot: 'relative-control-root' }),
    error => error?.code === 'analyzer-control-root-invalid',
  );
});

test('authenticates an exact root-owned analyzer-control inventory', {
  skip: !canExerciseRootOwnedControl,
}, async () => {
  const { controlRoot, verifier } = await analyzerControlFixture();
  const capability = verifier.verifyAnalyzerControl({ controlRoot });
  const inspected = verifier.inspectAnalyzerControl(capability);
  assert.equal(inspected.schemaVersion, 'codebase-radar.analyzer-control/v1');
  assert.deepEqual(
    inspected.files.map(file => [file.path, file.mode]),
    [
      ['runtime-snapshot-loader.mjs', '0444'],
      ['resource-governance-launcher.mjs', '0444'],
      ['runtime-memfd-addon.node', '0555'],
    ],
  );
  assert.ok(inspected.files.every(file => file.identity.nlink === '1'));
  assert.ok(inspected.files.every(file =>
    file.identity.mode === fstatSync(file.fd, { bigint: true }).mode.toString(10),
  ));
  capability.close();
  assert.throws(
    () => verifier.inspectAnalyzerControl(capability),
    error => error?.code === 'analyzer-control-capability-invalid',
  );
});

test('rejects analyzer-control symlinks, hard links, oversized files, and extras', {
  skip: !canExerciseRootOwnedControl,
}, async () => {
  {
    const { controlRoot, externalRoot, verifier } = await analyzerControlFixture();
    const path = join(controlRoot, 'runtime-snapshot-loader.mjs');
    const target = join(externalRoot, 'loader-target.mjs');
    writeFileSync(target, 'export const target = true;\n');
    chmodSync(controlRoot, 0o755);
    rmSync(path);
    symlinkSync(target, path);
    chmodSync(controlRoot, 0o555);
    assert.throws(
      () => verifier.verifyAnalyzerControl({ controlRoot }),
      error => error?.code === 'analyzer-control-file-invalid',
    );
  }

  {
    const { controlRoot, externalRoot, verifier, files } = await analyzerControlFixture();
    const path = join(controlRoot, 'runtime-snapshot-loader.mjs');
    const target = join(externalRoot, 'loader-hardlink.mjs');
    writeFileSync(target, files[0].bytes);
    chmodSync(target, 0o444);
    chmodSync(controlRoot, 0o755);
    rmSync(path);
    linkSync(target, path);
    chmodSync(controlRoot, 0o555);
    assert.throws(
      () => verifier.verifyAnalyzerControl({ controlRoot }),
      error => error?.code === 'analyzer-control-file-invalid',
    );
  }

  {
    const { controlRoot, verifier } = await analyzerControlFixture();
    const path = join(controlRoot, 'runtime-snapshot-loader.mjs');
    chmodSync(controlRoot, 0o755);
    const descriptor = openSync(path, 'r+');
    try {
      ftruncateSync(descriptor, 1024 * 1024 + 1);
    } finally {
      closeSync(descriptor);
    }
    chmodSync(controlRoot, 0o555);
    assert.throws(
      () => verifier.verifyAnalyzerControl({ controlRoot }),
      error => error?.code === 'analyzer-control-file-oversize',
    );
  }

  {
    const { controlRoot, verifier } = await analyzerControlFixture();
    chmodSync(controlRoot, 0o755);
    writeFileSync(join(controlRoot, 'unexpected-control-file'), 'unexpected\n');
    chmodSync(controlRoot, 0o555);
    assert.throws(
      () => verifier.verifyAnalyzerControl({ controlRoot }),
      error => error?.code === 'analyzer-control-inventory-invalid',
    );
  }
});

test('retains analyzer-control descriptors across pathname replacement and rejects overlap', {
  skip: !canExerciseRootOwnedControl,
}, async () => {
  const { controlRoot, verifier } = await analyzerControlFixture();
  const capability = verifier.verifyAnalyzerControl({ controlRoot });
  const before = verifier.inspectAnalyzerControl(capability);
  const loader = before.files.find(file => file.path === 'runtime-snapshot-loader.mjs');
  assert.ok(loader);

  chmodSync(controlRoot, 0o755);
  renameSync(
    join(controlRoot, 'runtime-snapshot-loader.mjs'),
    join(controlRoot, 'retired-runtime-snapshot-loader.mjs'),
  );
  writeFileSync(join(controlRoot, 'runtime-snapshot-loader.mjs'), 'export const replacement = true;\n');
  chmodSync(join(controlRoot, 'runtime-snapshot-loader.mjs'), 0o444);
  chmodSync(controlRoot, 0o555);

  const after = verifier.inspectAnalyzerControl(capability);
  const retainedLoader = after.files.find(file => file.path === 'runtime-snapshot-loader.mjs');
  assert.equal(retainedLoader.fd, loader.fd);
  assert.equal(retainedLoader.sha256, loader.sha256);
  capability.close();

  const overlap = await analyzerControlFixture();
  assert.throws(
    () => overlap.verifier.verifyAnalyzerControl({
      controlRoot: overlap.controlRoot,
      runtimeRoot: overlap.controlRoot,
    }),
    error => error?.code === 'analyzer-control-overlap',
  );
});
