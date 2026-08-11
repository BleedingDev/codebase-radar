import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  assertOfflineOsvDatabaseFresh,
  offlineOsvMaximumFutureClockSkewMs,
  requiredOfflineOsvDatabase,
  runtimeVerificationBounds,
} from './runtime-manifest.mjs';
import {
  AnalyzerRuntimeSnapshotError,
  assertSealedRuntimeSnapshotFd,
  requiredAnalyzerControlFiles,
} from './runtime-sealed-generation.mjs';
import { encodeSealedRuntimeSnapshotHeader } from './runtime-snapshot-codec.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const addonPath = join(packageRoot, 'runtime-memfd-addon.node');
const loaderPath = join(packageRoot, 'runtime-snapshot-loader.mjs');
const generationPath = join(packageRoot, 'runtime-sealed-generation.mjs');
const generationDeclarationPath = join(packageRoot, 'runtime-sealed-generation.d.ts');
const packageManifestPath = join(packageRoot, 'package.json');
const RequiredMemfdSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;

const closeQuietly = fd => {
  if (!Number.isSafeInteger(fd) || fd < 0) return;
  try { closeSync(fd); } catch {}
};

const identity = metadata => ({
  device: metadata.dev.toString(10),
  inode: metadata.ino.toString(10),
  mode: metadata.mode.toString(10),
  size: metadata.size.toString(10),
  nlink: metadata.nlink.toString(10),
});

const sha256File = path => createHash('sha256').update(readFileSync(path)).digest('hex');

const expectFailure = action => {
  assert.throws(action);
};

const syntheticOsvRecord = () => ({
  path: requiredOfflineOsvDatabase.path,
  url: requiredOfflineOsvDatabase.url,
  generation: requiredOfflineOsvDatabase.generation,
  sha256: requiredOfflineOsvDatabase.sha256,
  size: requiredOfflineOsvDatabase.size,
  entries: requiredOfflineOsvDatabase.entries,
  uncompressedBytes: requiredOfflineOsvDatabase.uncompressedBytes,
  signedDataDescriptorEntries: requiredOfflineOsvDatabase.signedDataDescriptorEntries,
  dataDescriptorBytes: requiredOfflineOsvDatabase.dataDescriptorBytes,
  publishedAt: requiredOfflineOsvDatabase.publishedAt,
  maxAgeDays: requiredOfflineOsvDatabase.maxAgeDays,
  validationEvidence: {
    schemaVersion: 'codebase-radar.osv-npm-snapshot-evidence/v1',
    source: {
      url: requiredOfflineOsvDatabase.url,
      generation: requiredOfflineOsvDatabase.generation,
      publishedAt: requiredOfflineOsvDatabase.publishedAt,
      maxAge: requiredOfflineOsvDatabase.maxAgeDays * 24 * 60 * 60,
    },
    archive: {
      size: requiredOfflineOsvDatabase.size,
      sha256: requiredOfflineOsvDatabase.sha256,
      format: 'zip',
      zip64: true,
      entryCount: requiredOfflineOsvDatabase.entries,
      compressedBytes: 1,
      uncompressedBytes: requiredOfflineOsvDatabase.uncompressedBytes,
      storedEntries: 0,
      deflatedEntries: requiredOfflineOsvDatabase.entries,
      signedDataDescriptorEntries: requiredOfflineOsvDatabase.signedDataDescriptorEntries,
      dataDescriptorBytes: requiredOfflineOsvDatabase.dataDescriptorBytes,
      compressionMethods: ['deflate'],
      centralDirectoryOffset: 1,
      centralDirectoryBytes: 1,
      structuralSha256: 'a'.repeat(64),
    },
  },
  validator: {
    schemaVersion: 'codebase-radar.osv-npm-snapshot-validator/v1',
    path: 'osv-npm-snapshot-validator.mjs',
    byteLength: 1,
    sha256: 'b'.repeat(64),
  },
});

test('freezes the exact three-artifact opaque control inventory', () => {
  assert.deepEqual(requiredAnalyzerControlFiles, [
    'runtime-snapshot-loader.mjs',
    'resource-governance-launcher.mjs',
    'runtime-memfd-addon.node',
  ]);
});

test('uses identical seven-day OSV freshness boundaries as the standalone loader', () => {
  const record = syntheticOsvRecord();
  const publishedAt = Date.parse(record.publishedAt);
  const expiresAt = publishedAt + record.maxAgeDays * 24 * 60 * 60 * 1000;

  assert.doesNotThrow(() => assertOfflineOsvDatabaseFresh(record, expiresAt));
  assert.throws(
    () => assertOfflineOsvDatabaseFresh(record, expiresAt + 1),
    error => error?.code === 'osv-database-stale',
  );
  assert.doesNotThrow(() =>
    assertOfflineOsvDatabaseFresh(record, publishedAt - offlineOsvMaximumFutureClockSkewMs),
  );
  assert.throws(
    () => assertOfflineOsvDatabaseFresh(record, publishedAt - offlineOsvMaximumFutureClockSkewMs - 1),
    error => error?.code === 'osv-database-stale',
  );

  const loaderSource = readFileSync(loaderPath, 'utf8');
  assert.match(loaderSource, /OfflineOsvMaximumFutureClockSkewMs\s*=\s*300_000/u);
  assert.match(loaderSource, /now\s*<\s*publishedAt\s*-\s*OfflineOsvMaximumFutureClockSkewMs/u);
});

test('keeps loader program FD 6 explicit and closes loader/addon capabilities before archive extraction', () => {
  const loaderSource = readFileSync(loaderPath, 'utf8');
  assert.match(loaderSource, /const LoaderProgramFd = 6;/u);
  assert.match(loaderSource, /closeInheritedControlFd\(LoaderProgramFd, 'materializer program'\)/u);
  assert.match(loaderSource, /closeInheritedControlFd\(LoaderAddonFd, 'memfd bridge'\)/u);
});

test('stands up an empty read-only OSV bind target without archiving database bytes', () => {
  const loaderSource = readFileSync(loaderPath, 'utf8');
  assert.match(loaderSource, /const createOfflineOsvMountPlaceholder/u);
  assert.match(loaderSource, /entries\.has\(OfflineOsvDatabase\.path\)/u);
  assert.match(loaderSource, /openSync\(destination, FileWriteFlags, 0o444\)/u);
  assert.match(loaderSource, /metadata\.size !== 0n/u);
  assert.match(loaderSource, /createOfflineOsvMountPlaceholder\(\{ entries, directories \}\)/u);
});

test('revalidates the bounded materialized tree plus its single OSV placeholder', () => {
  const generationSource = readFileSync(generationPath, 'utf8');
  assert.match(generationSource, /const validateMaterializedRuntimeTree/u);
  assert.match(generationSource, /maximumEntries: runtimeVerificationBounds\.entries \+ 1/u);
  assert.match(generationSource, /const expectedEntries = sealed\.runtimeEntries \+ 1/u);
  assert.match(generationSource, /const expectedBytes = BigInt\(sealed\.runtimeBytes\) - BigInt\(sealed\.osvDatabaseBytes\)/u);
  assert.match(generationSource, /materializedRuntimeRequiredPaths/u);
  assert.match(generationSource, /materialization-osv-placeholder-invalid/u);
});

test('publishes opaque-control-only JS and declaration entry points', () => {
  const generationSource = readFileSync(generationPath, 'utf8');
  const declarations = readFileSync(generationDeclarationPath, 'utf8');
  const packageManifest = JSON.parse(readFileSync(packageManifestPath, 'utf8'));
  assert.doesNotMatch(generationSource, /controlRoot|controlAnchors/u);
  assert.match(generationSource, /controlCapability !== identity\.analyzerControl/u);
  assert.match(declarations, /controlCapability: AnalyzerControlCapability/u);
  assert.doesNotMatch(declarations, /controlRoot|controlAnchors/u);
  assert.equal(packageManifest.exports['./runtime-sealed-generation'].types, './runtime-sealed-generation.d.ts');
  assert.equal(packageManifest.exports['./runtime-sealed-generation'].import, './runtime-sealed-generation.mjs');
  assert.equal(packageManifest.files.includes('runtime-sealed-generation.d.ts'), true);
  assert.equal(packageManifest.files.includes('runtime-snapshot-loader.mjs'), true);
  assert.equal(packageManifest.files.includes('runtime-descriptor-proofs.mjs'), true);
});

test(
  'Linux memfds prove data no-exec, executable mode, seals, write rejection, and FD-reuse resistance',
  { skip: process.platform !== 'linux' || !existsSync(addonPath) ? 'requires the built Linux memfd addon' : false },
  () => {
    const require = createRequire(import.meta.url);
    const bridge = require(addonPath);
    let addonFd;
    let snapshotFd;
    let replacementFd;
    let executableFd;
    try {
      addonFd = openSync(addonPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      const addonMetadata = fstatSync(addonFd, { bigint: true });
      const addonIdentity = identity(addonMetadata);
      const addonSha256 = sha256File(addonPath);

      snapshotFd = bridge.createData();
      fchmodSync(snapshotFd, 0o444);
      writeSync(snapshotFd, encodeSealedRuntimeSnapshotHeader({
        entryCount: 0,
        manifestSha256: runtimeTrustAnchor.manifestSha256,
        runnerSha256: runtimeTrustAnchor.runnerSha256,
        nodeSha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
        osvDatabaseSha256: requiredOfflineOsvDatabase.sha256,
      }), 0);
      const snapshotMetadataBeforeSeal = fstatSync(snapshotFd, { bigint: true });
      bridge.seal(snapshotFd);
      assert.equal((bridge.getSeals(snapshotFd) & RequiredMemfdSeals), RequiredMemfdSeals);
      expectFailure(() => writeSync(snapshotFd, Buffer.from('x'), 0, 1, null));
      expectFailure(() => fchmodSync(snapshotFd, 0o555));
      const snapshotIdentity = identity(snapshotMetadataBeforeSeal);

      const proof = assertSealedRuntimeSnapshotFd({
        fd: snapshotFd,
        archiveBytes: Number(snapshotMetadataBeforeSeal.size),
        manifestSha256: runtimeTrustAnchor.manifestSha256,
        runnerSha256: runtimeTrustAnchor.runnerSha256,
        nodeSha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
        osvDatabaseSha256: requiredOfflineOsvDatabase.sha256,
        snapshotIdentity,
        addonFd,
        addonBytes: Number(addonMetadata.size),
        addonSha256,
        addonIdentity,
      });
      assert.equal(proof.header.entryCount, 0);

      closeSync(snapshotFd);
      snapshotFd = undefined;
      replacementFd = bridge.createData();
      fchmodSync(replacementFd, 0o444);
      writeSync(replacementFd, encodeSealedRuntimeSnapshotHeader({
        entryCount: 0,
        manifestSha256: runtimeTrustAnchor.manifestSha256,
        runnerSha256: runtimeTrustAnchor.runnerSha256,
        nodeSha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
        osvDatabaseSha256: requiredOfflineOsvDatabase.sha256,
      }), 0);
      bridge.seal(replacementFd);
      assert.throws(
        () => assertSealedRuntimeSnapshotFd({
          fd: replacementFd,
          archiveBytes: Number(snapshotMetadataBeforeSeal.size),
          manifestSha256: runtimeTrustAnchor.manifestSha256,
          runnerSha256: runtimeTrustAnchor.runnerSha256,
          nodeSha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
          osvDatabaseSha256: requiredOfflineOsvDatabase.sha256,
          snapshotIdentity,
          addonFd,
          addonBytes: Number(addonMetadata.size),
          addonSha256,
          addonIdentity,
        }),
        error => error instanceof AnalyzerRuntimeSnapshotError && error.code === 'memfd-proof-invalid',
      );

      executableFd = bridge.createExecutable();
      fchmodSync(executableFd, 0o555);
      const executableMetadata = fstatSync(executableFd, { bigint: true });
      assert.equal(executableMetadata.mode & 0o7777n, 0o555n);
      writeSync(executableFd, Buffer.from('x'), 0, 1, 0);
      bridge.seal(executableFd);
      assert.equal((bridge.getSeals(executableFd) & RequiredMemfdSeals), RequiredMemfdSeals);
      expectFailure(() => writeSync(executableFd, Buffer.from('y'), 0, 1, null));
    } finally {
      closeQuietly(addonFd);
      closeQuietly(snapshotFd);
      closeQuietly(replacementFd);
      closeQuietly(executableFd);
    }
  },
);

test(
  'Linux disposable-runtime harness materializes once, then fails closed after OSV expiry',
  {
    skip:
      process.platform !== 'linux' ||
      process.env.RADAR_SEALED_RUNTIME_E2E !== '1'
        ? 'requires an explicit disposable Linux runtime/control harness'
        : false,
  },
  async () => {
    const { lstatSync } = await import('node:fs');
    const { verifyAnalyzerControl } = await import('./runtime-control-root.mjs');
    const {
      inspectMaterializedAnalyzerRuntime,
      materializeSealedAnalyzerRuntime,
      sealVerifiedAnalyzerRuntime,
    } = await import('./runtime-sealed-generation.mjs');
    const runtimeRoot = process.env.RADAR_SEALED_RUNTIME_TEST_ROOT;
    const controlRoot = process.env.RADAR_ANALYZER_CONTROL_ROOT;
    assert.ok(runtimeRoot && controlRoot, 'the explicit Linux harness requires runtime and control roots');
    const control = verifyAnalyzerControl({ controlRoot, runtimeRoot });
    const target = lstatSync(runtimeRoot, { bigint: true });
    const identityRecord = Object.freeze({
      schemaVersion: 'codebase-radar.analyzer-runtime-identity/v1',
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      policyDigest: runtimeTrustAnchor.policyDigest,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      buildIdentity: runtimeTrustAnchor.buildIdentity,
      targetGeneration: Object.freeze({ device: target.dev.toString(10), inode: target.ino.toString(10) }),
      analyzerControl: control,
    });
    const realNow = Date.now;
    const publishedAt = Date.parse(requiredOfflineOsvDatabase.publishedAt);
    const expiresAt = publishedAt + requiredOfflineOsvDatabase.maxAgeDays * 24 * 60 * 60 * 1000;
    let sealed;
    let materialized;
    try {
      Date.now = () => expiresAt;
      sealed = sealVerifiedAnalyzerRuntime({ root: runtimeRoot, identity: identityRecord, controlCapability: control });
      control.close();
      materialized = materializeSealedAnalyzerRuntime(sealed);
      const inspection = inspectMaterializedAnalyzerRuntime(materialized);
      assert.equal(inspection.osvDatabaseRelativePath, requiredOfflineOsvDatabase.path);
      const placeholder = lstatSync(
        `/proc/self/fd/${inspection.runtimeRootFd}/${requiredOfflineOsvDatabase.path}`,
        { bigint: true },
      );
      assert.equal(placeholder.isFile(), true);
      assert.equal(placeholder.isSymbolicLink(), false);
      assert.equal(placeholder.nlink, 1n);
      assert.equal(placeholder.size, 0n);
      assert.equal(placeholder.mode & 0o7777n, 0o444n);

      // A caller that tries to pass self-authenticated path/hash fields cannot
      // substitute for the verifier's retained opaque capability.
      assert.throws(
        () => sealVerifiedAnalyzerRuntime({
          root: runtimeRoot,
          identity: identityRecord,
          controlRoot,
          controlAnchors: [],
        }),
        error => error instanceof AnalyzerRuntimeSnapshotError && error.code === 'control-capability-invalid',
      );
      // The full governance handoff is deliberately an explicit Linux harness:
      // it needs a delegated cgroup root and the deployed host-tool anchors.
      // It verifies the relative runtime identity remains distinct from the
      // governance-owned absolute sandbox mount path.
      if (typeof process.env.RADAR_SEALED_RUNTIME_CGROUP_ROOT === 'string') {
        const { assertResourceGovernedLaunchCapability } = await import('./resource-governance.mjs');
        const capability = assertResourceGovernedLaunchCapability({
          analyzerId: 'OSV-Scanner',
          cgroupRoot: process.env.RADAR_SEALED_RUNTIME_CGROUP_ROOT,
          materializedRuntime: materialized,
        });
        assert.equal(capability.offlineOsvDatabase.runtimeRelativePath, requiredOfflineOsvDatabase.path);
        assert.equal(capability.offlineOsvDatabase.sandboxPath, `/runtime/${requiredOfflineOsvDatabase.path}`);
      }
      Date.now = () => expiresAt + 1;
      assert.throws(
        () => inspectMaterializedAnalyzerRuntime(materialized),
        error => error instanceof AnalyzerRuntimeSnapshotError && error.code === 'osv-database-stale',
      );
    } finally {
      Date.now = realNow;
      try { materialized?.close(); } catch {}
      sealed?.close();
      control.close();
    }
  },
);

test(
  'Linux disposable-runtime harness rejects a replaced non-runner descendant after public identity capture',
  {
    skip:
      process.platform !== 'linux' ||
      process.env.RADAR_SEALED_RUNTIME_E2E !== '1' ||
      process.env.RADAR_SEALED_RUNTIME_TEST_DISPOSABLE !== '1' ||
      typeof process.env.RADAR_SEALED_RUNTIME_E2E_NONRUNNER_PATH !== 'string'
        ? 'requires an explicit disposable Linux replacement harness'
        : false,
  },
  async () => {
    const { verifyAnalyzerControl } = await import('./runtime-control-root.mjs');
    const { sealVerifiedAnalyzerRuntime } = await import('./runtime-sealed-generation.mjs');
    const runtimeRoot = process.env.RADAR_SEALED_RUNTIME_TEST_ROOT;
    const controlRoot = process.env.RADAR_ANALYZER_CONTROL_ROOT;
    const relativeVictim = process.env.RADAR_SEALED_RUNTIME_E2E_NONRUNNER_PATH;
    assert.ok(runtimeRoot && controlRoot && relativeVictim);
    assert.ok(
      !relativeVictim.startsWith('/') &&
      !relativeVictim.includes('\\') &&
      relativeVictim.split('/').every(part => part.length > 0 && part !== '.' && part !== '..'),
      'the explicit harness descendant must be a canonical runtime-relative path',
    );
    const victim = join(runtimeRoot, relativeVictim);
    const before = lstatSync(victim, { bigint: true });
    assert.equal(before.isFile(), true, 'the harness descendant must be a regular non-runner file');
    const control = verifyAnalyzerControl({ controlRoot, runtimeRoot });
    const target = lstatSync(runtimeRoot, { bigint: true });
    const publicIdentity = Object.freeze({
      schemaVersion: 'codebase-radar.analyzer-runtime-identity/v1',
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      policyDigest: runtimeTrustAnchor.policyDigest,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      buildIdentity: runtimeTrustAnchor.buildIdentity,
      targetGeneration: Object.freeze({ device: target.dev.toString(10), inode: target.ino.toString(10) }),
      analyzerControl: control,
    });
    const backup = `${victim}.sealed-generation-test-backup-${process.pid}`;
    const corrupt = `${victim}.sealed-generation-test-corrupt-${process.pid}`;
    let moved = false;
    try {
      renameSync(victim, backup);
      moved = true;
      writeFileSync(victim, 'adversarial descendant replacement\n', { encoding: 'utf8', mode: 0o644, flag: 'wx' });
      assert.throws(
        () => sealVerifiedAnalyzerRuntime({
          root: runtimeRoot,
          identity: publicIdentity,
          controlCapability: control,
        }),
        error => error instanceof AnalyzerRuntimeSnapshotError,
      );
    } finally {
      try { renameSync(victim, corrupt); } catch {}
      if (moved) renameSync(backup, victim);
      try { rmSync(corrupt, { force: true }); } catch {}
      control.close();
    }
  },
);

test(
  'Linux disposable-runtime harness reports typed cleanup ambiguity, then safely retries exact owned cleanup',
  {
    skip:
      process.platform !== 'linux' ||
      process.env.RADAR_SEALED_RUNTIME_E2E !== '1' ||
      process.env.RADAR_SEALED_RUNTIME_TEST_DISPOSABLE !== '1'
        ? 'requires an explicit disposable Linux runtime/control harness'
        : false,
  },
  async () => {
    const { readdirSync } = await import('node:fs');
    const { verifyAnalyzerControl } = await import('./runtime-control-root.mjs');
    const {
      inspectMaterializedAnalyzerRuntime,
      materializeSealedAnalyzerRuntime,
      sealVerifiedAnalyzerRuntime,
    } = await import('./runtime-sealed-generation.mjs');
    const runtimeRoot = process.env.RADAR_SEALED_RUNTIME_TEST_ROOT;
    const controlRoot = process.env.RADAR_ANALYZER_CONTROL_ROOT;
    assert.ok(runtimeRoot && controlRoot);
    const materializationParent = '/tmp/codebase-radar-runtime-generations-v1';
    const existing = new Set(existsSync(materializationParent) ? readdirSync(materializationParent) : []);
    const control = verifyAnalyzerControl({ controlRoot, runtimeRoot });
    const target = lstatSync(runtimeRoot, { bigint: true });
    const identityRecord = Object.freeze({
      schemaVersion: 'codebase-radar.analyzer-runtime-identity/v1',
      manifestSha256: runtimeTrustAnchor.manifestSha256,
      policyDigest: runtimeTrustAnchor.policyDigest,
      runnerSha256: runtimeTrustAnchor.runnerSha256,
      buildIdentity: runtimeTrustAnchor.buildIdentity,
      targetGeneration: Object.freeze({ device: target.dev.toString(10), inode: target.ino.toString(10) }),
      analyzerControl: control,
    });
    let sealed;
    let materialized;
    let unexpectedPath;
    try {
      sealed = sealVerifiedAnalyzerRuntime({ root: runtimeRoot, identity: identityRecord, controlCapability: control });
      control.close();
      materialized = materializeSealedAnalyzerRuntime(sealed);
      const created = readdirSync(materializationParent)
        .filter(entry => !existing.has(entry) && /^generation-[0-9a-f]{32}$/u.test(entry));
      assert.equal(created.length, 1, 'the explicit harness must own exactly one newly created generation');
      unexpectedPath = join(materializationParent, created[0], 'unexpected-cleanup-entry');
      writeFileSync(unexpectedPath, 'test-only cleanup ambiguity\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      assert.throws(
        () => materialized.close(),
        error => error instanceof AnalyzerRuntimeSnapshotError && error.code === 'materialization-cleanup-ambiguous',
      );
      assert.throws(
        () => inspectMaterializedAnalyzerRuntime(materialized),
        error => error instanceof AnalyzerRuntimeSnapshotError && error.code === 'materialized-handle-invalid',
      );
      rmSync(unexpectedPath, { force: false });
      unexpectedPath = undefined;
      assert.doesNotThrow(() => materialized.close());
      assert.equal(existsSync(join(materializationParent, created[0])), false);
    } finally {
      if (unexpectedPath !== undefined) {
        try { rmSync(unexpectedPath, { force: true }); } catch {}
      }
      try { materialized?.close(); } catch {}
      sealed?.close();
      control.close();
    }
  },
);
