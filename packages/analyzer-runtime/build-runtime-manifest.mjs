import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalManifestDigest,
  packageTreeSha256,
  requiredOfflineOsvDatabase,
  requiredOsvNpmSnapshotValidator,
  requiredRuntimeNode,
  validateRuntimeManifest,
} from './runtime-manifest.mjs';
import { generatePinnedOsvNpmSnapshotEvidenceFile } from './osv-npm-snapshot-validator.mjs';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(packageRoot, '../..');
const manifestPath = join(packageRoot, 'runtime-manifest.json');
const verifierPath = join(packageRoot, 'runtime-manifest.mjs');
const expectedModes = new Set(['--check', '--write']);
const mode = process.argv[2];
const snapshotPath = process.argv[3];

if (
  !expectedModes.has(mode) ||
  (mode === '--check' && process.argv.length !== 3) ||
  (mode === '--write' && (process.argv.length !== 4 || !isAbsolute(snapshotPath)))
) {
  throw new Error('Expected --check, or --write followed by the absolute pinned OSV snapshot path.');
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

const independentBytes = relativePath => {
  const path = join(packageRoot, relativePath);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error(`Release input ${relativePath} is not an independent regular file.`);
  }
  return readFileSync(path);
};

const checksum = relativePath => ({
  path: relativePath,
  sha256: sha256(independentBytes(relativePath)),
});

const sourceArtifactBytes = relativePath => {
  const sourceRoot = [packageRoot, workspaceRoot].find(root =>
    existsSync(join(root, relativePath)),
  );
  if (sourceRoot === undefined) return undefined;
  const path = join(sourceRoot, relativePath);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error(`Release artifact ${relativePath} is not an independent regular file.`);
  }
  return readFileSync(path);
};

const controlPaths = Object.freeze([
  'package.json',
  'osv-npm-snapshot-validator.mjs',
  'licenses/osv-database/PROVENANCE.json',
  'smoke/calldiff/javascript.js',
  'smoke/calldiff/typescript.ts',
  'smoke/calldiff/typescript.tsx',
  'smoke/osv/osv-scanner.toml',
  'smoke/osv/vulnerable/package-lock.json',
  'smoke/osv/clean/package-lock.json',
]);

const clone = value => structuredClone(value);

const refreshInstalledPackageTrees = candidate => {
  const packages = [
    ...candidate.semanticRunner.bundledPackages,
    ...candidate.analyzers.flatMap(analyzer =>
      analyzer.packages.filter(packageCheck => packageCheck.source === 'npm'),
    ),
  ];
  for (const packageCheck of packages) {
    if (typeof packageCheck.packageJson !== 'string') continue;
    const sourceRoot = [packageRoot, workspaceRoot].find(root =>
      existsSync(join(root, packageCheck.packageJson)),
    );
    if (sourceRoot === undefined) continue;
    packageCheck.treeSha256 = packageTreeSha256(
      dirname(realpathSync(join(sourceRoot, packageCheck.packageJson))),
    );
  }
};

const pinNativePackageArtifact = ({ analyzer, packageName, artifactSuffix }) => {
  const packageCheck = analyzer.packages.find(
    item => item.source === 'npm' && item.name === packageName,
  );
  const artifactPath = packageCheck?.resolutionPaths.find(path => path.endsWith(artifactSuffix));
  if (artifactPath === undefined) {
    throw new Error(`${analyzer.id} has no authenticated ${packageName} artifact.`);
  }
  const platform = analyzer.platforms[0];
  const checksum = platform.checksums.find(item => item.path.endsWith(artifactSuffix));
  if (checksum === undefined) {
    throw new Error(`${analyzer.id} has no checksum for ${artifactSuffix}.`);
  }
  checksum.path = artifactPath;
  platform.nativeExecutables = platform.nativeExecutables.map(path =>
    path.endsWith(artifactSuffix) ? artifactPath : path,
  );
};

const refreshSourceArtifactChecksums = candidate => {
  for (const analyzer of candidate.analyzers) {
    for (const artifact of [
      ...analyzer.legalFiles,
      ...analyzer.platforms.flatMap(platform => platform.checksums),
    ]) {
      const bytes = sourceArtifactBytes(artifact.path);
      if (bytes !== undefined) artifact.sha256 = sha256(bytes);
    }
  }
};

const candidateManifest = ({ current, validationEvidence }) => {
  const candidate = clone(current);
  if (mode === '--write' && process.platform === 'linux' && process.arch === 'x64') {
    refreshInstalledPackageTrees(candidate);
  }
  candidate.controlFiles = controlPaths.map(checksum);
  candidate.semanticRunner.sha256 = checksum('bin/radar-semantic-analyzer.mjs').sha256;
  candidate.runtimeNode = clone(requiredRuntimeNode);
  candidate.offlineOsvDatabase = {
    ...clone(requiredOfflineOsvDatabase),
    validationEvidence: clone(validationEvidence),
    validator: {
      schemaVersion: requiredOsvNpmSnapshotValidator.schemaVersion,
      path: requiredOsvNpmSnapshotValidator.path,
      byteLength: independentBytes(requiredOsvNpmSnapshotValidator.path).byteLength,
      sha256: checksum(requiredOsvNpmSnapshotValidator.path).sha256,
    },
  };
  candidate.pnpmIntegrityEvidence.sha256 = checksum(candidate.pnpmIntegrityEvidence.path).sha256;
  const noticeSha256 = checksum('THIRD_PARTY_NOTICES.md').sha256;
  for (const analyzer of candidate.analyzers) {
    analyzer.licenseNotice.sha256 = noticeSha256;
  }
  const calldiff = candidate.analyzers.find(analyzer => analyzer.id === 'calldiff');
  if (calldiff?.platforms[0]?.smoke === null || calldiff === undefined) {
    throw new Error('The manifest has no Calldiff smoke to migrate.');
  }
  calldiff.platforms[0].smoke.kind = 'calldiff-report/v1';
  const oxlint = candidate.analyzers.find(analyzer => analyzer.id === 'oxlint-ultracite');
  if (oxlint === undefined) throw new Error('The manifest has no Oxlint + Ultracite entry.');
  pinNativePackageArtifact({
    analyzer: oxlint,
    packageName: '@oxlint/binding-linux-x64-gnu',
    artifactSuffix: '/oxlint.linux-x64-gnu.node',
  });
  const jscpd = candidate.analyzers.find(analyzer => analyzer.id === 'jscpd');
  if (jscpd === undefined) throw new Error('The manifest has no JSCPD entry.');
  pinNativePackageArtifact({
    analyzer: jscpd,
    packageName: 'jscpd-linux-x64-gnu',
    artifactSuffix: '/bin/jscpd',
  });
  refreshSourceArtifactChecksums(candidate);
  const osv = candidate.analyzers.find(analyzer => analyzer.id === 'osv-scanner');
  if (osv === undefined || osv.platforms.length !== 1) {
    throw new Error('The manifest has no canonical OSV-Scanner entry.');
  }
  osv.profileVersions = ['js-lockfiles-offline-pinned/v1'];
  const provenance = checksum('licenses/osv-database/PROVENANCE.json');
  osv.legalFiles = [
    ...osv.legalFiles.filter(file => file.path !== provenance.path),
    { kind: 'notice', ...provenance },
  ];
  osv.platforms[0].smoke = {
    kind: 'osv-offline-lockfiles/v1',
    runner: 'direct',
    path: 'bin/osv-scanner',
    fixture: 'smoke/osv',
    args: [],
    timeoutMs: 30_000,
    maxOutputBytes: 65_536,
    expectedStatus: 0,
    expectedSignal: null,
    expected: {
      analyzerVersion: '2.5.0',
      vulnerableLockfile: 'vulnerable/package-lock.json',
      cleanLockfile: 'clean/package-lock.json',
      requiredVulnerabilityId: 'GHSA-29mw-wpgm-hmr9',
    },
  };
  return candidate;
};

const current = JSON.parse(independentBytes('runtime-manifest.json').toString('utf8'));
let validationEvidence = current.offlineOsvDatabase?.validationEvidence;
if (mode === '--write') {
  const canonicalSnapshotPath = realpathSync(snapshotPath);
  if (canonicalSnapshotPath !== snapshotPath) {
    throw new Error('The pinned OSV snapshot path must already be canonical.');
  }
  validationEvidence = await generatePinnedOsvNpmSnapshotEvidenceFile(snapshotPath);
}
if (validationEvidence === undefined) {
  throw new Error('The checked manifest has no generated OSV validation evidence; run --write with the pinned snapshot.');
}
const candidate = candidateManifest({ current, validationEvidence });
const candidateBytes = Buffer.from(`${JSON.stringify(candidate, null, 2)}\n`, 'utf8');
const digest = canonicalManifestDigest(candidate);

if (mode === '--check') {
  validateRuntimeManifest(candidate);
  if (!candidateBytes.equals(independentBytes('runtime-manifest.json'))) {
    throw new Error('The checked-in runtime manifest is not reproducible from its reviewed release inputs.');
  }
  process.stdout.write(`${candidateBytes.byteLength} ${sha256(candidateBytes)} ${digest}\n`);
  process.exit(0);
}

let verifierSource = independentBytes('runtime-manifest.mjs').toString('utf8');
const policyPattern = /(export const canonicalManifestPolicySha256\s*=\s*\n\s*')[0-9a-f]{64}(';)/u;
if (!policyPattern.test(verifierSource)) {
  throw new Error('The runtime manifest policy constant could not be updated exactly once.');
}
verifierSource = verifierSource.replace(policyPattern, `$1${digest}$2`);
writeFileSync(manifestPath, candidateBytes, { mode: 0o644 });
writeFileSync(verifierPath, verifierSource, { mode: 0o644 });

const checked = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--check'], {
  cwd: packageRoot,
  encoding: 'utf8',
  env: {
    HOME: '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    PATH: '/usr/bin:/bin',
  },
  maxBuffer: 16_384,
  timeout: 30_000,
  windowsHide: true,
});
if (checked.error !== undefined || checked.status !== 0 || checked.signal !== null) {
  throw new Error(`Generated runtime manifest failed its independent check: ${checked.stderr || checked.error?.message || 'unknown failure'}`);
}
process.stdout.write(checked.stdout);
