import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(packageRoot, '../..');
const manifestPath = join(packageRoot, 'runtime-manifest.json');
const runnerPath = join(packageRoot, 'bin/radar-semantic-analyzer.mjs');
const expectedArguments = new Set(['--check', '--write']);
const mode = process.argv[2];

if (process.argv.length !== 3 || !expectedArguments.has(mode)) {
  throw new Error('Expected exactly --check or --write.');
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const manifestMetadata = lstatSync(manifestPath);
if (
  !manifestMetadata.isFile() ||
  manifestMetadata.isSymbolicLink() ||
  manifestMetadata.nlink !== 1
) {
  throw new Error('Semantic runner manifest is not an independent regular file.');
}
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const expectedPackages = new Map(
  manifest.semanticRunner.bundledPackages.map(packageEntry => [
    packageEntry.name,
    packageEntry,
  ]),
);

const packageRootFromInput = input => {
  const normalized = input.split(sep).join('/');
  const marker = '/node_modules/';
  const markerIndex = normalized.lastIndexOf(marker);
  if (markerIndex < 0) return undefined;
  const tail = normalized.slice(markerIndex + marker.length);
  const parts = tail.split('/');
  const name = parts[0]?.startsWith('@')
    ? `${parts[0]}/${parts[1] ?? ''}`
    : parts[0];
  if (name === undefined || name.endsWith('/')) return undefined;
  const relativeRoot = `${normalized.slice(0, markerIndex + marker.length)}${name}`;
  return { name, root: resolve(workspaceRoot, relativeRoot) };
};

const temporaryRoot = mkdtempSync(join(tmpdir(), 'radar-semantic-runner-build-'));
const generatedPath = join(temporaryRoot, 'radar-semantic-analyzer.mjs');
try {
  const result = buildSync({
    absWorkingDir: workspaceRoot,
    banner: {
      js: "import { createRequire as __radarCreateRequire } from 'node:module'; const require = __radarCreateRequire(import.meta.url);",
    },
    bundle: true,
    charset: 'utf8',
    entryPoints: ['apps/radar/server/semantic-runner.ts'],
    format: 'esm',
    legalComments: 'eof',
    logLevel: 'silent',
    metafile: true,
    minify: false,
    outfile: generatedPath,
    platform: 'node',
    sourcemap: false,
    target: 'node24',
    treeShaking: true,
  });

  const actualIdentities = new Set();
  const actualVersionsByName = new Map();
  for (const input of Object.keys(result.metafile.inputs)) {
    const location = packageRootFromInput(input);
    if (location === undefined) continue;
    const canonicalRoot = realpathSync(location.root);
    const packageJsonPath = join(canonicalRoot, 'package.json');
    const metadata = lstatSync(packageJsonPath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      throw new Error(`Bundled package ${location.name} metadata is not an independent regular file.`);
    }
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
    if (packageJson.name !== location.name || typeof packageJson.version !== 'string') {
      throw new Error(`Bundled package ${location.name} metadata is inconsistent.`);
    }
    const identity = `${location.name}@${packageJson.version}`;
    actualIdentities.add(identity);
    const versions = actualVersionsByName.get(location.name) ?? new Set();
    versions.add(packageJson.version);
    actualVersionsByName.set(location.name, versions);
  }

  const multipleVersions = [...actualVersionsByName.entries()]
    .filter(([, versions]) => versions.size !== 1)
    .map(([name, versions]) => `${name}: ${[...versions].sort().join(', ')}`);
  if (multipleVersions.length > 0) {
    throw new Error(
      `Semantic runner includes multiple versions of one package: ${multipleVersions.join('; ')}.`,
    );
  }

  const expectedIdentities = [...expectedPackages.values()]
    .map(packageEntry => `${packageEntry.name}@${packageEntry.version}`)
    .sort((left, right) => left.localeCompare(right));
  const sortedActualIdentities = [...actualIdentities].sort((left, right) =>
    left.localeCompare(right),
  );
  if (JSON.stringify(sortedActualIdentities) !== JSON.stringify(expectedIdentities)) {
    throw new Error(
      `Semantic runner closure mismatch: expected ${expectedIdentities.join(', ')}; got ${sortedActualIdentities.join(', ')}.`,
    );
  }

  for (const packageEntry of expectedPackages.values()) {
    const licensePath = join(packageRoot, packageEntry.licenseFile.path);
    const metadata = lstatSync(licensePath);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
      throw new Error(`Bundled package ${packageEntry.name} license is not an independent regular file.`);
    }
    const actualLicenseSha256 = sha256(readFileSync(licensePath));
    if (actualLicenseSha256 !== packageEntry.licenseFile.sha256) {
      throw new Error(`Bundled package ${packageEntry.name} license checksum mismatch.`);
    }
  }

  const generatedBytes = readFileSync(generatedPath);
  const generatedSha256 = sha256(generatedBytes);
  const smoke = spawnSync(process.execPath, [generatedPath], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env: {
      HOME: '/nonexistent',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      NO_COLOR: '1',
      PATH: '',
    },
    killSignal: 'SIGKILL',
    maxBuffer: 4_096,
    timeout: 5_000,
    windowsHide: true,
  });
  if (smoke.error !== undefined) {
    throw new Error(`Generated semantic runner smoke could not start: ${smoke.error.message}`);
  }
  if (
    smoke.status !== 1 ||
    smoke.signal !== null ||
    smoke.stdout !== '' ||
    smoke.stderr !== 'The verified semantic analyzer failed safely.\n'
  ) {
    throw new Error(
      `Generated semantic runner smoke must reject an empty clean invocation safely; got status ${String(smoke.status)}, signal ${String(smoke.signal)}, stdout ${JSON.stringify(smoke.stdout)}, stderr ${JSON.stringify(smoke.stderr)}.`,
    );
  }
  if (mode === '--write') {
    copyFileSync(generatedPath, runnerPath);
    process.stdout.write(`${generatedSha256}\n`);
  } else {
    const checkedInMetadata = lstatSync(runnerPath);
    if (
      !checkedInMetadata.isFile() ||
      checkedInMetadata.isSymbolicLink() ||
      checkedInMetadata.nlink !== 1
    ) {
      throw new Error('Checked-in semantic runner is not an independent regular file.');
    }
    const checkedInBytes = readFileSync(runnerPath);
    if (!generatedBytes.equals(checkedInBytes)) {
      throw new Error('Checked-in semantic runner is not reproducible from the pinned build inputs.');
    }
    if (generatedSha256 !== manifest.semanticRunner.sha256) {
      throw new Error('Semantic runner checksum does not match runtime-manifest.json.');
    }
  }
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
