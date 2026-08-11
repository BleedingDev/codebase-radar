import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  copyFileSync,
  cpSync,
  existsSync,
  ftruncateSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import {
  assertExactNativeMode,
  assertExactVersionOutput,
  assertPackageTreeSha256,
  buildSandboxProbeArguments,
  canonicalJsonText,
  canonicalManifestDigest,
  canonicalManifestPolicySha256,
  detectRuntimePlatform,
  evaluateProbeResult,
  getRuntimePreparationPlan,
  linuxX64Glibc,
  minimalProbeEnvironment,
  packageTreeSha256,
  readRuntimeManifest,
  requiredDogfoodAnalyzers,
  requiredHostIsolation,
  requiredManagedBinaryEntries,
  requiredOfflineOsvDatabase,
  requiredOsvNpmSnapshotValidator,
  runtimeVerificationBounds,
  validateOfflineOsvDatabase,
  validateRuntimeManifest,
  verifyBundledNpmSourceIntegrityEvidence,
  verifyNpmSourceIntegrityEvidence,
  verifyPackageClosureShadows,
  verifyPnpmResolutionGraph,
  verifyRuntime,
} from './runtime-manifest.mjs';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(packageRoot, '../..');
const deployedRuntimeRoot = join(workspaceRoot, '.zerops/analyzer-runtime');
const manifestPath = join(packageRoot, 'runtime-manifest.json');
const semanticRunnerBuildScript = join(packageRoot, 'build-semantic-runner.mjs');
const lockPath = join(workspaceRoot, 'pnpm-lock.yaml');
const verificationScript = join(workspaceRoot, 'scripts/verify-runtime-tools.mjs');
const verificationEntry = join(workspaceRoot, 'scripts/verify-runtime-tools.sh');
const preparationScript = join(workspaceRoot, 'scripts/prepare-runtime-tools.sh');
const atomicExchangeScript = join(workspaceRoot, 'scripts/runtime-atomic-exchange.py');
const managedRuntimeBinEntries = [...requiredManagedBinaryEntries];
const temporaryRoots = [];
const forbiddenEnvironment = /^(?:NODE_(?:OPTIONS|PATH|PRESERVE_SYMLINKS(?:_MAIN)?|COMPILE_CACHE|LOADER|REQUIRE)|LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|BUN_OPTIONS|DENO_.*|ESM_LOADER|TSX_.*|PYTHON.*|RUBYOPT)$/u;

const makeTemporaryRoot = prefix => {
  // macOS exposes /var as a symlink to /private/var. The preparation policy
  // deliberately rejects symlinked destination components, so test fixtures
  // must use their canonical absolute paths too.
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  temporaryRoots.push(root);
  return root;
};

const writeHugeSparseFile = (path, size) => {
  mkdirSync(dirname(path), { recursive: true });
  const descriptor = openSync(path, 'w');
  try {
    ftruncateSync(descriptor, size);
  } finally {
    closeSync(descriptor);
  }
};

after(() => {
  for (const root of temporaryRoots) {
    rmSync(root, { recursive: true, force: true });
  }
});

const canonicalManifest = () =>
  JSON.parse(readFileSync(manifestPath, 'utf8'));

const clone = value => structuredClone(value);

const sha256 = value => createHash('sha256').update(value).digest('hex');

const syntheticOsvValidationEvidence = () => ({
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
});

const syntheticOfflineOsvDatabase = () => ({
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
  validationEvidence: syntheticOsvValidationEvidence(),
  validator: {
    schemaVersion: requiredOsvNpmSnapshotValidator.schemaVersion,
    path: requiredOsvNpmSnapshotValidator.path,
    byteLength: 1,
    sha256: 'b'.repeat(64),
  },
});

const setAtPath = (value, path, replacement) => {
  let cursor = value;
  for (const part of path.slice(0, -1)) cursor = cursor[part];
  cursor[path.at(-1)] = replacement;
};

const scalarPaths = (value, path = []) => {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => scalarPaths(item, [...path, index]));
  }
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, item]) =>
      scalarPaths(item, [...path, key]),
    );
  }
  return [{ path, value }];
};

const mutateScalar = value => {
  if (typeof value === 'string') return `${value}-tampered`;
  if (typeof value === 'number') return value + 1;
  if (typeof value === 'boolean') return !value;
  if (value === null) return 'tampered';
  throw new TypeError(`Unsupported scalar ${String(value)}.`);
};

const analyzer = (manifest, id) => {
  const result = manifest.analyzers.find(candidate => candidate.id === id);
  assert.ok(result, `Missing ${id} fixture entry.`);
  return result;
};

const packageCheck = (manifest, analyzerId, name) => {
  const result = analyzer(manifest, analyzerId).packages.find(
    candidate => candidate.name === name,
  );
  assert.ok(result, `Missing ${name} package check.`);
  return result;
};

const safeEnvironment = extra => {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) =>
        !forbiddenEnvironment.test(key) &&
        key !== 'RADAR_ANALYZER_ROOT' &&
        key !== 'RADAR_RUNTIME_BOOTSTRAPPED',
    ),
  );
  return {
    HOME: environment.HOME ?? '/nonexistent',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    PATH: environment.PATH ?? '/usr/bin:/bin',
    ...extra,
  };
};

const writeAuthenticatedControlRoot = () => {
  const root = makeTemporaryRoot('radar-runtime-controls-');
  copyFileSync(manifestPath, join(root, 'runtime-manifest.json'));
  copyFileSync(
    join(packageRoot, 'runtime-manifest.mjs'),
    join(root, 'runtime-manifest.mjs'),
  );
  copyFileSync(join(packageRoot, 'package.json'), join(root, 'package.json'));
  mkdirSync(join(root, 'bin'));
  mkdirSync(join(root, 'node_modules/.bin'), { recursive: true });
  mkdirSync(join(root, 'node_modules/oxlint/bin'), { recursive: true });
  mkdirSync(join(root, 'node_modules/jscpd'), { recursive: true });
  writeFileSync(join(root, 'node_modules/oxlint/bin/oxlint'), '#!/usr/bin/env node\n');
  writeFileSync(join(root, 'node_modules/jscpd/run-jscpd.js'), '#!/usr/bin/env node\n');
  return root;
};

const runTrustedShellEntry = (
  entry,
  bootstrapVariable,
  argumentsList,
  environment = {},
) => {
  const assignments = [
    'HOME=/nonexistent',
    'LANG=C.UTF-8',
    'LC_ALL=C.UTF-8',
    'NO_COLOR=1',
    'PATH=/usr/bin:/bin',
    `${bootstrapVariable}=1`,
  ];
  if (Object.hasOwn(environment, 'RADAR_ANALYZER_ROOT')) {
    assignments.push(`RADAR_ANALYZER_ROOT=${environment.RADAR_ANALYZER_ROOT}`);
  }
  return spawnSync(
    '/usr/bin/env',
    [
      '-i',
      ...assignments,
      '/bin/bash',
      '--noprofile',
      '--norc',
      entry,
      ...argumentsList,
    ],
    {
      cwd: workspaceRoot,
      encoding: 'utf8',
      env: safeEnvironment(environment),
    },
  );
};

const runPublicVerifier = (argumentsList, environment = {}) =>
  runTrustedShellEntry(
    verificationEntry,
    'RADAR_RUNTIME_VERIFY_BOOTSTRAPPED',
    argumentsList,
    environment,
  );

const runPreparation = (entry, runtimeBin, environment = {}) =>
  runTrustedShellEntry(
    entry,
    'RADAR_RUNTIME_PREP_BOOTSTRAPPED',
    [runtimeBin],
    environment,
  );

const runPreparePlan = (root, environment = {}) =>
  runPublicVerifier(['prepare-plan', '--runtime-root', root], environment);

const markerProgram = marker => [
  "import { writeFileSync } from 'node:fs';",
  `writeFileSync(${JSON.stringify(marker)}, 'executed\\n');`,
  '',
].join('\n');

const requireMarkerProgram = marker => [
  "const { writeFileSync } = require('node:fs');",
  `writeFileSync(${JSON.stringify(marker)}, 'executed\\n');`,
  '',
].join('\n');

const executeCanary = path => {
  const result = spawnSync(process.execPath, [path], {
    encoding: 'utf8',
    env: safeEnvironment(),
  });
  assert.equal(result.status, 0, result.stderr);
};

const writePnpmPackage = ({
  root,
  snapshot,
  name,
  version,
  dependencies = [],
  packageFields = {},
}) => {
  const namespace = join(root, 'node_modules/.pnpm', snapshot, 'node_modules');
  const packageDirectory = join(namespace, name);
  mkdirSync(packageDirectory, { recursive: true });
  writeFileSync(
    join(packageDirectory, 'package.json'),
    JSON.stringify(
      {
        name,
        version,
        main: 'index.js',
        ...packageFields,
        dependencies: Object.fromEntries(dependencies.map(specifier => [specifier, '*'])),
      },
      null,
      2,
    ),
  );
  writeFileSync(join(packageDirectory, 'index.js'), 'export {};\n');
  return {
    name,
    version,
    dependencies,
    identity: `${name}@${version}`,
    namespace,
    packageDirectory,
  };
};

const makePnpmResolutionFixture = () => {
  const root = makeTemporaryRoot('radar-runtime-pnpm-graph-');
  const definitions = [
    { name: 'calldiff', version: '0.4.1', dependencies: ['tree-sitter'] },
    { name: 'tree-sitter', version: '0.25.1', dependencies: ['node-addon-api', 'node-gyp-build'] },
    {
      name: 'tree-sitter-javascript',
      version: '0.23.1',
      dependencies: ['tree-sitter', 'node-addon-api', 'node-gyp-build'],
    },
    {
      name: 'tree-sitter-typescript',
      version: '0.23.2',
      dependencies: ['tree-sitter', 'tree-sitter-javascript', 'node-addon-api', 'node-gyp-build'],
    },
    {
      name: 'node-addon-api',
      version: '8.9.1',
      packageFields: {
        type: 'module',
        exports: { '.': { import: './index.js' } },
      },
    },
    { name: 'node-gyp-build', version: '4.8.4' },
    {
      name: 'oxlint',
      version: '1.77.0',
      dependencies: ['@oxlint/binding-linux-x64-gnu'],
    },
    { name: '@oxlint/binding-linux-x64-gnu', version: '1.77.0' },
    { name: 'jscpd', version: '5.0.14', dependencies: ['jscpd-linux-x64-gnu'] },
    { name: 'jscpd-linux-x64-gnu', version: '5.0.14' },
  ];
  const nodes = new Map(
    definitions.map((definition, index) => {
      const node = writePnpmPackage({
        root,
        snapshot: `fixture-${index}-${definition.name.replaceAll(/[^A-Za-z0-9]/gu, '-')}`,
        ...definition,
      });
      return [node.identity, node];
    }),
  );
  const dependencyLinks = new Map();
  for (const node of nodes.values()) {
    for (const specifier of node.dependencies) {
      const target = [...nodes.values()].find(candidate => candidate.name === specifier);
      assert.ok(target, `Missing fixture target ${specifier}.`);
      const link = join(node.namespace, specifier);
      mkdirSync(dirname(link), { recursive: true });
      symlinkSync(target.packageDirectory, link, 'dir');
      dependencyLinks.set(`${node.identity}\u0000${specifier}`, link);
    }
  }
  const packages = [...nodes.values()].map(node => ({
    source: 'npm',
    name: node.name,
    version: node.version,
    packageJson: relative(root, join(node.packageDirectory, 'package.json')),
  }));
  const importers = [...nodes.values()].map(node => ({
    id: node.identity,
    packageJson: relative(root, join(node.packageDirectory, 'package.json')),
    namespace: relative(root, node.namespace),
    edges: node.dependencies.map(specifier => {
      const target = [...nodes.values()].find(candidate => candidate.name === specifier);
      assert.ok(target, `Missing fixture target ${specifier}.`);
      return {
        specifier,
        requested: `dependencies:${target.version}`,
        state: 'present',
        target: target.identity,
        resolver: specifier === 'node-addon-api'
          ? 'pnpm-link-import-only'
          : 'create-require',
      };
    }),
  }));
  return {
    root,
    nodes,
    dependencyLinks,
    manifest: {
      semanticRunner: { bundledPackages: [] },
      analyzers: [{ packages }],
      pnpmFallbackNamespace: {
        path: 'node_modules/.pnpm/node_modules',
        state: 'absent',
      },
      pnpmImporters: importers,
    },
    packageRoots: new Map(
      [...nodes.values()].map(node => [node.identity, node.packageDirectory]),
    ),
    expectedEdges: [...nodes.values()].flatMap(node =>
      node.dependencies.map(specifier => ({
        importer: node.identity,
        specifier,
        package: [...nodes.values()].find(candidate => candidate.name === specifier).identity,
        resolver: specifier === 'node-addon-api' ? 'pnpm-link-import-only' : 'create-require',
      })),
    ),
  };
};

const snapshotTree = root => {
  const records = [];
  const visit = (path, relativePath) => {
    const metadata = lstatSync(path);
    const mode = (metadata.mode & 0o7777).toString(8);
    if (metadata.isDirectory()) {
      records.push(`d ${relativePath} ${mode}`);
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name), `${relativePath}/${name}`);
      }
      return;
    }
    if (metadata.isSymbolicLink()) {
      records.push(`l ${relativePath} ${mode} ${readlinkSync(path)}`);
      return;
    }
    if (metadata.isFile()) {
      records.push(`f ${relativePath} ${mode} ${sha256(readFileSync(path))}`);
      return;
    }
    records.push(`other ${relativePath} ${mode}`);
  };
  visit(root, '.');
  return records.join('\n');
};

const writeTarArchive = ({ root, name, entries, transform, compression = 'gzip' }) => {
  const contents = join(root, `${name}-contents`);
  const archive = join(root, `${name}.${compression === 'gzip' ? 'tar.gz' : 'tar.xz'}`);
  mkdirSync(contents, { recursive: true });
  for (const entry of entries) {
    const path = join(contents, entry.name);
    if (entry.kind === 'file') {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, entry.contents);
      if (entry.mode !== undefined) chmodSync(path, entry.mode);
    } else if (entry.kind === 'symlink') {
      mkdirSync(dirname(path), { recursive: true });
      symlinkSync(entry.target, path);
    } else if (entry.kind === 'hardlink') {
      mkdirSync(dirname(path), { recursive: true });
      linkSync(join(contents, entry.target), path);
    }
  }
  const argumentsList = [
    '--create',
    ...(compression === 'gzip' ? ['--gzip'] : ['-J']),
    '--file',
    archive,
    ...(transform === undefined ? [] : [`--transform=${transform}`]),
    '--directory',
    contents,
    '--',
    ...entries.map(entry => entry.name),
  ];
  const result = spawnSync('/usr/bin/tar', argumentsList, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return archive;
};

const makePreparationFixture = ({
  archiveKind = 'valid',
  corruptTraceDownload = false,
  verifierBehavior = 'success',
  forceKillAfterExchange = false,
} = {}) => {
  const root = makeTemporaryRoot('radar-runtime-prepare-fixture-');
  const scripts = join(root, 'scripts');
  const downloads = join(root, 'downloads');
  const fakeBin = join(root, 'fake-bin');
  const runtime = join(root, 'runtime');
  const external = join(root, 'external');
  mkdirSync(scripts, { recursive: true });
  mkdirSync(downloads, { recursive: true });
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(external, { recursive: true });
  const fixturePreparation = join(scripts, 'prepare-runtime-tools.sh');
  copyFileSync(preparationScript, fixturePreparation);
  copyFileSync(atomicExchangeScript, join(scripts, 'runtime-atomic-exchange.py'));
  const productionPreparation = readFileSync(fixturePreparation, 'utf8');
  const curlSelection = [
    'trusted_curl="$(select_trusted_system_executable /usr/bin/curl /bin/curl /opt/homebrew/bin/curl /usr/local/bin/curl)" ||',
    "  fail 'trusted-helper-missing' 'A trusted system curl executable is required.'",
  ].join('\n');
  assert.ok(
    productionPreparation.includes(curlSelection),
    'The fixture must patch only the reviewed trusted-curl selection.',
  );
  writeFileSync(
    fixturePreparation,
    productionPreparation.replace(
      curlSelection,
      `trusted_curl=${JSON.stringify(join(fakeBin, 'curl'))}`,
    ),
  );

  const traceEntries = {
    valid: [{ name: 'tracedecay', kind: 'file', contents: 'tracedecay fixture\n' }],
    extra: [
      { name: 'tracedecay', kind: 'file', contents: 'tracedecay fixture\n' },
      { name: 'unexpected', kind: 'file', contents: 'unexpected\n' },
    ],
    option: [{ name: '-tracedecay', kind: 'file', contents: 'tracedecay fixture\n' }],
    symlink: [{ name: 'tracedecay', kind: 'symlink', target: 'outside' }],
    hardlink: [
      { name: 'payload', kind: 'file', contents: 'tracedecay fixture\n' },
      { name: 'tracedecay', kind: 'hardlink', target: 'payload' },
    ],
    traversal: [{ name: 'tracedecay', kind: 'file', contents: 'tracedecay fixture\n' }],
  }[archiveKind];
  assert.ok(traceEntries, `Unknown archive fixture ${archiveKind}.`);
  const traceArchive = writeTarArchive({
    root: downloads,
    name: 'tracedecay',
    entries: traceEntries,
  });
  const zizmorArchive = writeTarArchive({
    root: downloads,
    name: 'zizmor',
    entries: [{ name: 'zizmor', kind: 'file', contents: 'zizmor fixture\n' }],
  });
  const osvSource = join(downloads, 'osv-scanner');
  writeFileSync(osvSource, 'osv fixture\n');
  const osvDatabaseSource = join(downloads, 'osv-npm-all.zip');
  const osvDatabaseContents = 'offline osv database fixture\n';
  writeFileSync(osvDatabaseSource, osvDatabaseContents);
  const runtimeNodeContents = 'runtime node fixture\n';
  const runtimeNodeMember = 'node-v24.18.1-linux-x64/bin/node';
  const runtimeNodeArchive = writeTarArchive({
    root: downloads,
    name: 'runtime-node',
    compression: 'xz',
    entries: [{
      name: runtimeNodeMember,
      kind: 'file',
      contents: runtimeNodeContents,
      mode: 0o755,
    }],
  });
  const runtimeNodeControl = [
    "pinned_runtime_node_url='https://nodejs.org/dist/v24.18.1/node-v24.18.1-linux-x64.tar.xz'",
    "pinned_runtime_node_archive_sha256='d6c664df3f3f61458e8c277585571328522d705166723a7c7823a9253a4d15a0'",
    "pinned_runtime_node_member='node-v24.18.1-linux-x64/bin/node'",
    "pinned_runtime_node_sha256='f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a'",
  ].join('\n');
  const fixturePreparationSource = readFileSync(fixturePreparation, 'utf8');
  assert.ok(
    fixturePreparationSource.includes(runtimeNodeControl),
    'The fixture must patch only the reviewed pinned runtime Node provenance.',
  );
  writeFileSync(
    fixturePreparation,
    fixturePreparationSource.replace(
      runtimeNodeControl,
      [
        `pinned_runtime_node_url=${JSON.stringify('https://fixtures.invalid/runtime-node')}`,
        `pinned_runtime_node_archive_sha256=${JSON.stringify(sha256(readFileSync(runtimeNodeArchive)))}`,
        `pinned_runtime_node_member=${JSON.stringify(runtimeNodeMember)}`,
        `pinned_runtime_node_sha256=${JSON.stringify(sha256(runtimeNodeContents))}`,
      ].join('\n'),
    ),
  );
  const osvDatabaseControl = [
    "pinned_osv_npm_snapshot_url='https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=1786418349414076'",
    "pinned_osv_npm_snapshot_sha256='38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69'",
    'pinned_osv_npm_snapshot_bytes=218758368',
    "pinned_osv_npm_snapshot_path='databases/osv/osv-scalibr/npm/all.zip'",
  ].join('\n');
  const nodePatchedPreparationSource = readFileSync(fixturePreparation, 'utf8');
  assert.ok(
    nodePatchedPreparationSource.includes(osvDatabaseControl),
    'The fixture must patch only the reviewed pinned offline OSV provenance.',
  );
  writeFileSync(
    fixturePreparation,
    nodePatchedPreparationSource.replace(
      osvDatabaseControl,
      [
        `pinned_osv_npm_snapshot_url=${JSON.stringify('https://fixtures.invalid/osv-npm-all.zip')}`,
        `pinned_osv_npm_snapshot_sha256=${JSON.stringify(sha256(osvDatabaseContents))}`,
        `pinned_osv_npm_snapshot_bytes=${String(Buffer.byteLength(osvDatabaseContents))}`,
        "pinned_osv_npm_snapshot_path='databases/osv/osv-scalibr/npm/all.zip'",
      ].join('\n'),
    ),
  );

  const traceInstalled = sha256('tracedecay fixture\n');
  const zizmorInstalled = sha256('zizmor fixture\n');
  const osvInstalled = sha256('osv fixture\n');
  const plan = [
    [
      'tracedecay',
      'https://fixtures.invalid/tracedecay',
      sha256(readFileSync(traceArchive)),
      'tar.gz',
      archiveKind === 'traversal' ? '../tracedecay' : 'tracedecay',
      'bin/tracedecay',
      traceInstalled,
    ],
    [
      'zizmor',
      'https://fixtures.invalid/zizmor',
      sha256(readFileSync(zizmorArchive)),
      'tar.gz',
      'zizmor',
      'bin/zizmor',
      zizmorInstalled,
    ],
    [
      'osv-scanner',
      'https://fixtures.invalid/osv-scanner',
      sha256(readFileSync(osvSource)),
      'raw',
      '-',
      'bin/osv-scanner',
      osvInstalled,
    ],
  ].map(record => record.join('\t')).join('\n') + '\n';
  const verifyBehavior =
    verifierBehavior === 'late-failure'
      ? "process.stderr.write('late verifier failure\\n'); process.exit(41);"
      : verifierBehavior === 'interrupt'
        ? "process.kill(process.ppid, 'SIGTERM'); setTimeout(() => process.exit(42), 25);"
        : verifierBehavior === 'kill-before-exchange'
          ? "process.kill(process.ppid, 'SIGKILL'); setTimeout(() => process.exit(42), 25);"
        : 'process.exit(0);';
  writeFileSync(join(scripts, 'verify-runtime-tools.mjs'), [
    `const plan = ${JSON.stringify(plan)};`,
    "if (process.argv[2] === 'prepare-plan') { process.stdout.write(plan); process.exit(0); }",
    "if (process.argv[2] === 'validate-osv-snapshot') { process.stdout.write('{\"schemaVersion\":\"fixture\"}\\n'); process.exit(0); }",
    "if (process.argv[2] === 'verify') {",
    `  ${verifyBehavior}`,
    '}',
    'process.exit(64);',
    '',
  ].join('\n'));

  if (forceKillAfterExchange) {
    const helper = join(scripts, 'runtime-atomic-exchange.py');
    const source = readFileSync(helper, 'utf8');
    writeFileSync(
      helper,
      source.replace(
        'if __name__ == "__main__":\n    main()\n',
        'if __name__ == "__main__":\n    main()\n    if any(".analyzer-runtime-stage." in item for item in sys.argv[1:]):\n        os.kill(os.getppid(), 9)\n',
      ),
    );
  }

  mkdirSync(join(runtime, 'bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/.bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/oxlint/bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/jscpd'), { recursive: true });
  writeFileSync(join(runtime, 'runtime-manifest.json'), '{}\n');
  writeFileSync(join(runtime, 'runtime-manifest.mjs'), 'export {};\n');
  writeFileSync(join(runtime, 'package.json'), '{}\n');
  writeFileSync(join(runtime, 'node_modules/oxlint/bin/oxlint'), '#!/usr/bin/env node\n');
  writeFileSync(join(runtime, 'node_modules/jscpd/run-jscpd.js'), '#!/usr/bin/env node\n');
  writeFileSync(join(runtime, 'bin/radar-semantic-analyzer.mjs'), '#!/usr/bin/env node\n');
  chmodSync(join(runtime, 'bin/radar-semantic-analyzer.mjs'), 0o644);
  writeFileSync(join(runtime, 'previous-runtime-byte'), 'preserve me\n');

  const curl = join(fakeBin, 'curl');
  writeFileSync(curl, [
    '#!/bin/sh',
    'set -eu',
    'output=',
    'url=',
    'while [ "$#" -gt 0 ]; do',
    '  if [ "$1" = "--output" ]; then output="$2"; shift 2; continue; fi',
    '  if [ "$1" = "--" ]; then shift; url="$1"; break; fi',
    '  shift',
    'done',
    '[ -n "$output" ] && [ -n "$url" ]',
    `if [ "$url" = 'https://fixtures.invalid/tracedecay' ] && [ ${corruptTraceDownload ? "'yes'" : "'no'"} = 'yes' ]; then`,
    '  printf invalid > "$output"',
    '  exit 0',
    'fi',
    'case "$url" in',
    `  *tracedecay) cp -- ${JSON.stringify(traceArchive)} "$output" ;;`,
    `  *zizmor) cp -- ${JSON.stringify(zizmorArchive)} "$output" ;;`,
    `  *osv-scanner) cp -- ${JSON.stringify(osvSource)} "$output" ;;`,
    `  *osv-npm-all.zip) cp -- ${JSON.stringify(osvDatabaseSource)} "$output" ;;`,
    `  *runtime-node) cp -- ${JSON.stringify(runtimeNodeArchive)} "$output" ;;`,
    '  *) exit 64 ;;',
    'esac',
    '',
  ].join('\n'));
  chmodSync(curl, 0o755);

  return {
    root,
    runtime,
    external,
    fakeBin,
    runtimeNodeContents,
    osvDatabaseContents,
    preparation: fixturePreparation,
    before: snapshotTree(runtime),
  };
};

const runPreparationFixture = fixture =>
  runPreparation(fixture.preparation, join(fixture.runtime, 'bin'));

const waitForPath = async (path, description) => {
  const deadline = Date.now() + 30_000;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(description);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
};

const startPreparationFixture = fixture => {
  const child = spawn(
    '/usr/bin/env',
    [
      '-i',
      'HOME=/nonexistent',
      'LANG=C.UTF-8',
      'LC_ALL=C.UTF-8',
      'NO_COLOR=1',
      'PATH=/usr/bin:/bin',
      'RADAR_RUNTIME_PREP_BOOTSTRAPPED=1',
      '/bin/bash',
      '--noprofile',
      '--norc',
      fixture.preparation,
      join(fixture.runtime, 'bin'),
    ],
    {
      cwd: workspaceRoot,
      env: safeEnvironment(),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    stdout += chunk;
  });
  child.stderr.on('data', chunk => {
    stderr += chunk;
  });
  const completed = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) => {
      resolve({ status, signal, stdout, stderr });
    });
  });
  return { child, completed };
};

const assertPreparationFailurePreserved = fixture => {
  assert.equal(snapshotTree(fixture.runtime), fixture.before);
  assert.equal(existsSync(join(fixture.external, 'escaped')), false);
  assert.deepEqual(readdirSync(fixture.root).filter(
    name =>
      name.startsWith('.analyzer-runtime-')
      && name !== '.analyzer-runtime-publish.journal.lock',
  ), []);
};

const makeDestinationValidationFixture = () => {
  const root = makeTemporaryRoot('radar-runtime-destination-validation-');
  const scripts = join(root, 'scripts');
  const runtime = join(root, 'runtime');
  const marker = join(root, 'prepare-plan-reached');
  mkdirSync(scripts, { recursive: true });
  copyFileSync(preparationScript, join(scripts, 'prepare-runtime-tools.sh'));
  copyFileSync(atomicExchangeScript, join(scripts, 'runtime-atomic-exchange.py'));
  writeFileSync(join(scripts, 'verify-runtime-tools.mjs'), [
    "import { writeFileSync } from 'node:fs';",
    `const marker = ${JSON.stringify(marker)};`,
    "if (process.argv[2] === 'prepare-plan') {",
    "  writeFileSync(marker, 'reached\\n');",
    "  process.stderr.write('[runtime:manifest-plan-invalid] fixture stops after destination validation\\n');",
    '  process.exit(64);',
    '}',
    'process.exit(64);',
    '',
  ].join('\n'));
  mkdirSync(join(runtime, 'bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/.bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/oxlint/bin'), { recursive: true });
  mkdirSync(join(runtime, 'node_modules/jscpd'), { recursive: true });
  writeFileSync(join(runtime, 'runtime-manifest.json'), '{}\n');
  writeFileSync(join(runtime, 'runtime-manifest.mjs'), 'export {};\n');
  writeFileSync(join(runtime, 'package.json'), '{}\n');
  writeFileSync(join(runtime, 'node_modules/oxlint/bin/oxlint'), '#!/usr/bin/env node\n');
  writeFileSync(join(runtime, 'node_modules/jscpd/run-jscpd.js'), '#!/usr/bin/env node\n');
  writeFileSync(join(runtime, 'bin/radar-semantic-analyzer.mjs'), '#!/usr/bin/env node\n');
  chmodSync(join(runtime, 'bin/radar-semantic-analyzer.mjs'), 0o644);
  return {
    root,
    runtime,
    marker,
    preparation: join(scripts, 'prepare-runtime-tools.sh'),
    before: snapshotTree(runtime),
  };
};

test('pins the complete reviewed dogfood:max/v1 policy', () => {
  const manifest = readRuntimeManifest(manifestPath);
  assert.equal(canonicalManifestDigest(manifest), canonicalManifestPolicySha256);
  assert.equal(manifest.analyzers.length, 7);
  assert.deepEqual(
    manifest.analyzers.map(entry => entry.id).sort(),
    requiredDogfoodAnalyzers.map(entry => entry.id).sort(),
  );
  for (const entry of manifest.analyzers) {
    assert.deepEqual(entry.platforms.map(platform => ({
      os: platform.os,
      architecture: platform.architecture,
      libc: platform.libc,
    })), [linuxX64Glibc]);
    assert.ok(entry.packages.length > 0, `${entry.id} has package provenance.`);
    assert.ok(entry.platforms[0].checksums.length > 0, `${entry.id} has checksums.`);
    assert.ok(entry.legalFiles.length > 0, `${entry.id} has legal files.`);
  }
  assert.deepEqual(
    getRuntimePreparationPlan(manifest, linuxX64Glibc).map(item => item.analyzerId).sort(),
    ['osv-scanner', 'tracedecay', 'zizmor'],
  );
  verifyNpmSourceIntegrityEvidence(manifest, lockPath);
});

test('keeps trusted bootstrap hashes synchronized with the deployed controls', () => {
  const source = readFileSync(verificationScript, 'utf8');
  const manifestHash = source.match(/expectedManifestSha256\s*=\s*\n\s*'([0-9a-f]{64})'/u)?.[1];
  const verifierHash = source.match(/expectedTargetVerifierSha256\s*=\s*\n\s*'([0-9a-f]{64})'/u)?.[1];
  assert.equal(manifestHash, sha256(readFileSync(manifestPath)));
  assert.equal(
    verifierHash,
    sha256(readFileSync(join(packageRoot, 'runtime-manifest.mjs'))),
  );
  const manifest = readRuntimeManifest(manifestPath);
  for (const control of manifest.controlFiles) {
    assert.equal(
      control.sha256,
      sha256(readFileSync(join(packageRoot, control.path))),
      `Control ${control.path} must be reviewed before deployment.`,
    );
  }
});

test('pins each installed npm package tree and canonical resolution point', {
  skip:
    process.platform !== 'linux' || process.arch !== 'x64'
      ? 'package-tree identity is pinned for the production Linux x64 closure'
      : false,
}, () => {
  const manifest = readRuntimeManifest(manifestPath);
  const linuxX64OnlyPackages = new Set([
    '@oxlint/binding-linux-x64-gnu',
    '@typescript/typescript-linux-x64',
    'jscpd-linux-x64-gnu',
  ]);
  for (const entry of manifest.analyzers) {
    for (const dependency of entry.packages.filter(item => item.source === 'npm')) {
      const packageJsonRoot = [packageRoot, workspaceRoot, deployedRuntimeRoot].find(root =>
        existsSync(join(root, dependency.packageJson)),
      );
      if (
        packageJsonRoot === undefined &&
        (process.platform !== 'linux' || process.arch !== 'x64') &&
        linuxX64OnlyPackages.has(dependency.name)
      ) {
        continue;
      }
      assert.ok(packageJsonRoot, `Missing installed ${dependency.name}@${dependency.version}.`);
      const packageJson = realpathSync(join(packageJsonRoot, dependency.packageJson));
      const packageDirectory = dirname(packageJson);
      assert.equal(packageTreeSha256(packageDirectory), dependency.treeSha256);
      for (const resolutionPath of dependency.resolutionPaths) {
        const resolutionRoot = [packageRoot, workspaceRoot, deployedRuntimeRoot].find(root =>
          existsSync(join(root, resolutionPath)),
        );
        assert.ok(
          resolutionRoot,
          `Missing resolution ${resolutionPath} for ${dependency.name}@${dependency.version}.`,
        );
        const resolved = realpathSync(join(resolutionRoot, resolutionPath));
        assert.ok(
          resolved === packageDirectory || resolved.startsWith(`${packageDirectory}/`),
          `${resolutionPath} must resolve into ${dependency.name}@${dependency.version}.`,
        );
      }
    }
  }
});

test('pins every source-present artifact, notice, and legal file before runtime execution', () => {
  const manifest = readRuntimeManifest(manifestPath);
  for (const entry of manifest.analyzers) {
    for (const artifact of [
      entry.licenseNotice,
      ...entry.legalFiles,
      ...entry.platforms.flatMap(platform => platform.checksums),
    ]) {
      const candidates = artifact.path.startsWith('node_modules/')
        ? [packageRoot, workspaceRoot]
        : [packageRoot];
      const sourceRoot = candidates.find(root => existsSync(join(root, artifact.path)));
      if (sourceRoot === undefined) {
        const authenticatedPlatformPackageArtifact = entry.packages.some(
          packageCheck =>
            packageCheck.source === 'npm' &&
            packageCheck.resolutionPaths.includes(artifact.path) &&
            ![packageRoot, workspaceRoot].some(root =>
              existsSync(join(root, packageCheck.packageJson)),
            ),
        );
        assert.ok(
          artifact.path.startsWith('bin/') || authenticatedPlatformPackageArtifact,
          `Missing ${artifact.path}; only staged release binaries or authenticated absent platform-package artifacts may be absent from source.`,
        );
        continue;
      }
      const path = join(sourceRoot, artifact.path);
      assert.equal(
        sha256(readFileSync(path)),
        artifact.sha256,
        `${entry.id} ${artifact.path} must match its manifest identity.`,
      );
    }
  }
});

test('requires exact embedded OSV structural evidence and a hash-bound validator record', () => {
  const database = syntheticOfflineOsvDatabase();
  assert.equal(
    validateOfflineOsvDatabase(database).validationEvidence.archive.structuralSha256,
    'a'.repeat(64),
  );
  assert.equal(
    canonicalJsonText({ z: database.validationEvidence, a: database.validator }),
    canonicalJsonText({ a: database.validator, z: database.validationEvidence }),
  );

  for (const mutate of [
    value => { value.validationEvidence.source.maxAge += 1; },
    value => { value.validationEvidence.archive.entryCount -= 1; },
    value => { value.validationEvidence.archive.compressionMethods = ['store']; },
    value => { value.validationEvidence.archive.extra = true; },
    value => { value.validator.path = 'renamed-validator.mjs'; },
    value => { value.validator.byteLength = 0; },
    value => { value.validator.sha256 = 'A'.repeat(64); },
  ]) {
    const mutated = syntheticOfflineOsvDatabase();
    mutate(mutated);
    assert.throws(() => validateOfflineOsvDatabase(mutated), /osv-database|manifest-schema/u);
  }
});

test('rejects every reviewed scalar policy field when it is mutated', () => {
  const original = canonicalManifest();
  for (const { path, value } of scalarPaths(original)) {
    const mutated = clone(original);
    setAtPath(mutated, path, mutateScalar(value));
    assert.throws(
      () => validateRuntimeManifest(mutated),
      /\[runtime:/u,
      `Expected immutable field ${path.join('.')} to fail validation.`,
    );
  }
});

test('rejects structural and ownership mutations before accepting a policy', () => {
  const noPackages = clone(canonicalManifest());
  analyzer(noPackages, 'calldiff').packages = [];
  assert.throws(() => validateRuntimeManifest(noPackages), /manifest-schema/u);

  const noChecksums = clone(canonicalManifest());
  analyzer(noChecksums, 'calldiff').platforms[0].checksums = [];
  assert.throws(() => validateRuntimeManifest(noChecksums), /manifest-schema/u);

  const duplicateProfile = clone(canonicalManifest());
  analyzer(duplicateProfile, 'oxlint-ultracite').profileVersions.push(
    analyzer(duplicateProfile, 'strictest-comparator').profileVersions[0],
  );
  assert.throws(() => validateRuntimeManifest(duplicateProfile), /profile-duplicate/u);

  const duplicatePackage = clone(canonicalManifest());
  analyzer(duplicatePackage, 'oxlint-ultracite').packages.push(
    clone(analyzer(duplicatePackage, 'strictest-comparator').packages[0]),
  );
  assert.throws(() => validateRuntimeManifest(duplicatePackage), /package-duplicate/u);

  const duplicatePackagePath = clone(canonicalManifest());
  const aliasedPackage = clone(
    analyzer(duplicatePackagePath, 'oxlint-ultracite').packages[0],
  );
  aliasedPackage.name = 'oxlint-alias';
  aliasedPackage.packageJson = analyzer(
    duplicatePackagePath,
    'strictest-comparator',
  ).packages[0].packageJson;
  analyzer(duplicatePackagePath, 'oxlint-ultracite').packages.push(aliasedPackage);
  assert.throws(
    () => validateRuntimeManifest(duplicatePackagePath),
    /package-path-duplicate/u,
  );

  const duplicateResolutionPath = clone(canonicalManifest());
  analyzer(duplicateResolutionPath, 'oxlint-ultracite').packages[0].resolutionPaths.push(
    analyzer(duplicateResolutionPath, 'strictest-comparator').packages[0].resolutionPaths[0],
  );
  assert.throws(
    () => validateRuntimeManifest(duplicateResolutionPath),
    /resolution-path-duplicate/u,
  );

  const duplicateLegalPath = clone(canonicalManifest());
  analyzer(duplicateLegalPath, 'oxlint-ultracite').legalFiles.push(
    clone(analyzer(duplicateLegalPath, 'strictest-comparator').legalFiles[0]),
  );
  assert.throws(() => validateRuntimeManifest(duplicateLegalPath), /legal-path-duplicate/u);

  const duplicateArtifact = clone(canonicalManifest());
  analyzer(duplicateArtifact, 'oxlint-ultracite').platforms[0].checksums.push(
    clone(analyzer(duplicateArtifact, 'strictest-comparator').platforms[0].checksums[0]),
  );
  assert.throws(() => validateRuntimeManifest(duplicateArtifact), /artifact-path-duplicate/u);

  const duplicateLauncher = clone(canonicalManifest());
  analyzer(duplicateLauncher, 'jscpd').platforms[0].launchers.push(
    clone(analyzer(duplicateLauncher, 'oxlint-ultracite').platforms[0].launchers[0]),
  );
  assert.throws(() => validateRuntimeManifest(duplicateLauncher), /launcher-path-duplicate/u);

  const archiveTraversal = clone(canonicalManifest());
  analyzer(archiveTraversal, 'zizmor').platforms[0].download.archiveMember = '../zizmor';
  assert.throws(() => validateRuntimeManifest(archiveTraversal), /manifest-schema/u);

  const downloadQuery = clone(canonicalManifest());
  analyzer(downloadQuery, 'zizmor').platforms[0].download.url += '?redirect=1';
  assert.throws(() => validateRuntimeManifest(downloadQuery), /manifest-schema/u);
});

test('rejects every unsupported target class', () => {
  const manifest = canonicalManifest();
  const unsupportedTargets = [
    { os: 'darwin', architecture: 'x64', libc: 'none' },
    { os: 'darwin', architecture: 'arm64', libc: 'none' },
    { os: 'linux', architecture: 'arm64', libc: 'glibc' },
    { os: 'linux', architecture: 'x64', libc: 'musl' },
    { os: 'win32', architecture: 'x64', libc: 'none' },
  ];
  for (const target of unsupportedTargets) {
    assert.throws(
      () => getRuntimePreparationPlan(manifest, target),
      /platform-unsupported/u,
      `${target.os}/${target.architecture}/${target.libc} must be rejected.`,
    );
  }
});

test('uses exact normalized version and native-mode contracts', () => {
  assert.equal(
    assertExactVersionOutput({
      analyzer: 'fixture',
      expectedOutput: 'fixture 1.2.3',
      actualOutput: 'fixture 1.2.3\r\n',
    }),
    'fixture 1.2.3',
  );
  for (const output of [
    'fixture 1.2.3-compatible',
    'fixture 1.2.3 (compatible)',
    'fixture 1.2.3\nextra',
    'fixture 9.9.9',
  ]) {
    assert.throws(
      () =>
        assertExactVersionOutput({
          analyzer: 'fixture',
          expectedOutput: 'fixture 1.2.3',
          actualOutput: output,
        }),
      /version-mismatch/u,
    );
  }
  assert.doesNotThrow(() =>
    assertExactNativeMode({ analyzer: 'fixture', path: 'bin/fixture', mode: 0o755 }),
  );
  for (const mode of [0o777, 0o644, 0o700, 0o4755]) {
    assert.throws(
      () => assertExactNativeMode({ analyzer: 'fixture', path: 'bin/fixture', mode }),
      /native-mode-invalid/u,
    );
  }
});

test('fails bounded probes for timeout, output, status, and signals', () => {
  const contract = {
    timeoutMs: 1_000,
    maxOutputBytes: 16,
    expectedStatus: 0,
    expectedSignal: null,
  };
  const cases = [
    {
      name: 'timeout',
      result: { stdout: '', stderr: '', status: null, signal: 'SIGKILL', error: { code: 'ETIMEDOUT' } },
      pattern: /probe-timeout/u,
    },
    {
      name: 'excessive output',
      result: { stdout: 'x'.repeat(17), stderr: '', status: 0, signal: null },
      pattern: /probe-output-limit/u,
    },
    {
      name: 'nonzero exit',
      result: { stdout: '', stderr: '', status: 1, signal: null },
      pattern: /probe-status-mismatch/u,
    },
    {
      name: 'signal exit',
      result: { stdout: '', stderr: '', status: null, signal: 'SIGTERM' },
      pattern: /probe-signal-mismatch/u,
    },
  ];
  for (const item of cases) {
    assert.throws(
      () =>
        evaluateProbeResult({
          analyzer: 'fixture',
          path: 'bin/fixture',
          contract,
          result: item.result,
        }),
      item.pattern,
      item.name,
    );
  }
});

test('uses a minimal probe environment with no loader injection variables', () => {
  const environment = minimalProbeEnvironment('/tmp/radar-runtime-test-home');
  assert.deepEqual(Object.keys(environment).sort(), [
    'HOME',
    'LANG',
    'LC_ALL',
    'NO_COLOR',
    'PATH',
    'npm_config_audit',
    'npm_config_fund',
    'npm_config_ignore_scripts',
    'npm_config_offline',
    'npm_config_update_notifier',
  ].sort());
  assert.equal(environment.PATH, '');
  assert.ok(
    Object.keys(environment).every(key => !forbiddenEnvironment.test(key)),
  );
});

test('pins the production bootstrap Node and reserves host Node for Darwin development', () => {
  for (const entry of [preparationScript, verificationEntry]) {
    const source = readFileSync(entry, 'utf8');
    assert.ok(
      source.includes("trusted_node_bin='/usr/local/lib/radar-node-v24.18.1/bin/node'"),
      `${entry} must use the deployment-pinned Linux Node path.`,
    );
    assert.match(
      source,
      /\[\[ "\$trusted_node_version" != 'v24\.18\.1' \]\]/u,
      `${entry} must require the deployment-pinned Linux Node version.`,
    );
    assert.match(
      source,
      /Darwin's system\/Homebrew route below is deliberately development-only/u,
    );
    assert.match(
      source,
      /Darwin\)\n[\s\S]*?A Darwin development Node executable is required\./u,
    );
  }
});

test('models a clean runtime before the pinned Node is staged', () => {
  const fixture = makePreparationFixture();
  assert.equal(
    existsSync(join(fixture.runtime, 'bin/node')),
    false,
    'First installation must acquire Node rather than cloning a prior runtime binary.',
  );
  assert.equal(
    lstatSync(join(fixture.runtime, 'bin/radar-semantic-analyzer.mjs')).mode & 0o7777,
    0o644,
    'The source runner is normalized only in the private candidate generation.',
  );
});

test('pins the exact reviewed bubblewrap package and version output contracts', () => {
  assert.deepEqual(requiredHostIsolation, {
    kind: 'bubblewrap',
    path: '/usr/bin/bwrap',
    required: true,
    packageVersion: '0.9.0-1ubuntu0.1',
    versionOutput: 'bubblewrap 0.9.0',
  });
  assert.equal(
    assertExactVersionOutput({
      analyzer: 'bubblewrap',
      expectedOutput: requiredHostIsolation.versionOutput,
      actualOutput: `${requiredHostIsolation.versionOutput}\n`,
    }),
    requiredHostIsolation.versionOutput,
  );
  assert.throws(
    () =>
      assertExactVersionOutput({
        analyzer: 'bubblewrap',
        expectedOutput: requiredHostIsolation.versionOutput,
        actualOutput: 'bubblewrap 0.9.1',
      }),
    /version-mismatch/u,
  );
});

test('builds an exact private bubblewrap probe boundary', () => {
  const root = '/var/lib/radar/runtime';
  const arguments_ = buildSandboxProbeArguments({
    root,
    contract: {
      runner: 'direct',
      path: 'bin/fixture',
      args: [root, join(root, 'config/fixture.json'), '/workspace/unmapped.ts'],
    },
    environment: {
      ...minimalProbeEnvironment('/host/private-home'),
      CALLDIFF_GRAMMAR_CACHE: '/host/private-cache',
    },
  });
  assert.deepEqual(arguments_, [
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
    '/runtime',
    '--tmpfs',
    '/tmp',
    '--dir',
    '/tmp/home',
    '--chdir',
    '/runtime',
    '--setenv',
    'CALLDIFF_GRAMMAR_CACHE',
    '/tmp/grammar-cache',
    '--setenv',
    'HOME',
    '/tmp/home',
    '--setenv',
    'LANG',
    'C.UTF-8',
    '--setenv',
    'LC_ALL',
    'C.UTF-8',
    '--setenv',
    'NO_COLOR',
    '1',
    '--setenv',
    'npm_config_audit',
    'false',
    '--setenv',
    'npm_config_fund',
    'false',
    '--setenv',
    'npm_config_ignore_scripts',
    'true',
    '--setenv',
    'npm_config_offline',
    'true',
    '--setenv',
    'npm_config_update_notifier',
    'false',
    '--setenv',
    'PATH',
    '/runtime/bin:/usr/bin:/bin',
    '/runtime/bin/fixture',
    '/runtime',
    '/runtime/config/fixture.json',
    '/workspace/unmapped.ts',
  ]);
});

test('rewrites OSV path-valued arguments into the private runtime mount', () => {
  const root = '/var/lib/radar/runtime';
  const arguments_ = buildSandboxProbeArguments({
    root,
    contract: {
      runner: 'direct',
      path: 'bin/osv-scanner',
      args: [
        'scan',
        'source',
        '--offline',
        '--local-db-path=/runtime/databases/osv',
        '--config',
        join(root, 'smoke/osv/osv-scanner.toml'),
        '-L',
        join(root, 'smoke/osv/vulnerable/package-lock.json'),
      ],
    },
    environment: {
      ...minimalProbeEnvironment('/host/private-home'),
      OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY: '/runtime/databases/osv',
    },
  });
  assert.ok(arguments_.includes('/runtime/smoke/osv/osv-scanner.toml'));
  assert.ok(arguments_.includes('/runtime/smoke/osv/vulnerable/package-lock.json'));
  assert.deepEqual(arguments_.filter(argument => argument.includes(root)), [root]);
});

test('rejects hard-linked runtime manifests and authenticated file-tree entries', () => {
  const manifestRoot = makeTemporaryRoot('radar-runtime-hardlink-manifest-');
  const copiedManifest = join(manifestRoot, 'runtime-manifest.json');
  copyFileSync(manifestPath, copiedManifest);
  linkSync(copiedManifest, join(manifestRoot, 'manifest-alias.json'));
  assert.throws(() => readRuntimeManifest(copiedManifest), /manifest-invalid/u);

  const authenticatedPaths = [
    'pnpm-integrity-evidence.json',
    'bin/radar-semantic-analyzer.mjs',
    'config/oxlint-core.mjs',
    'THIRD_PARTY_NOTICES.md',
    'licenses/fixture/LICENSE',
    'bin/native-fixture',
  ];
  for (const relativePath of authenticatedPaths) {
    const root = makeTemporaryRoot('radar-runtime-hardlink-entry-');
    const path = join(root, relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${relativePath}\n`);
    linkSync(path, join(root, 'hardlink-alias'));
    assert.throws(
      () => packageTreeSha256(root),
      /package-tree-hardlink/u,
      relativePath,
    );
  }
});

test('rejects huge sparse runtime manifest JSON before allocation or parse', () => {
  const root = makeTemporaryRoot('radar-runtime-sparse-manifest-');
  const manifest = join(root, 'runtime-manifest.json');
  writeHugeSparseFile(manifest, runtimeVerificationBounds.manifestBytes + 1);
  assert.throws(
    () => readRuntimeManifest(manifest),
    error => error?.code === 'manifest-oversize',
  );
});

test('rejects huge sparse integrity evidence and pnpm lock text before parse', () => {
  const evidenceRoot = makeTemporaryRoot('radar-runtime-sparse-evidence-');
  const evidencePath = join(evidenceRoot, 'pnpm-integrity-evidence.json');
  writeHugeSparseFile(evidencePath, runtimeVerificationBounds.textBytes + 1);
  assert.throws(
    () => verifyBundledNpmSourceIntegrityEvidence({
      root: evidenceRoot,
      manifest: {
        pnpmIntegrityEvidence: {
          path: 'pnpm-integrity-evidence.json',
          sha256: '0'.repeat(64),
        },
      },
    }),
    error => error?.code === 'pnpm-integrity-evidence-oversize',
  );

  const lockRoot = makeTemporaryRoot('radar-runtime-sparse-lock-');
  const hugeLock = join(lockRoot, 'pnpm-lock.yaml');
  writeHugeSparseFile(hugeLock, runtimeVerificationBounds.textBytes + 1);
  assert.throws(
    () => verifyNpmSourceIntegrityEvidence(canonicalManifest(), hugeLock),
    error => error?.code === 'integrity-evidence-oversize',
  );
});

test('rejects huge sparse package metadata and package descendants before hashing', () => {
  const metadataFixture = makePnpmResolutionFixture();
  const metadata = join(
    metadataFixture.nodes.get('calldiff@0.4.1').packageDirectory,
    'package.json',
  );
  writeHugeSparseFile(metadata, runtimeVerificationBounds.textBytes + 1);
  assert.throws(
    () => verifyPnpmResolutionGraph({
      root: metadataFixture.root,
      packageRoots: metadataFixture.packageRoots,
      manifest: metadataFixture.manifest,
    }),
    error => error?.code === 'package-resolution-oversize',
  );

  const packageRoot = makeTemporaryRoot('radar-runtime-sparse-package-file-');
  writeHugeSparseFile(
    join(packageRoot, 'payload.bin'),
    runtimeVerificationBounds.packageFileBytes + 1,
  );
  assert.throws(
    () => packageTreeSha256(packageRoot),
    error => error?.code === 'package-tree-oversize',
  );
});

test('omits only generated package-local executables from source identity and rejects them at runtime', () => {
  const root = makeTemporaryRoot('radar-runtime-generated-package-bin-');
  const generatedDirectory = join(root, 'node_modules/.bin');
  mkdirSync(generatedDirectory, { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n');
  const normalizedDigest = packageTreeSha256(root);
  writeFileSync(
    join(generatedDirectory, 'fixture'),
    '#!/bin/sh\n# cmd-shim-target=/one/install/root/node_modules/.pnpm/fixture/bin.js\n',
    { mode: 0o755 },
  );
  assert.equal(packageTreeSha256(root), normalizedDigest);
  assert.throws(
    () => assertPackageTreeSha256({
      analyzer: 'fixture',
      packageName: 'fixture@1.0.0',
      packageRoot: root,
      expectedSha256: normalizedDigest,
    }),
    error => error?.code === 'package-tree-generated-bin',
  );
  rmSync(generatedDirectory, { recursive: true });
  assert.doesNotThrow(() => assertPackageTreeSha256({
    analyzer: 'fixture',
    packageName: 'fixture@1.0.0',
    packageRoot: root,
    expectedSha256: normalizedDigest,
  }));
});

test('caps package-tree directory enumeration before an unbounded entry array forms', () => {
  const root = makeTemporaryRoot('radar-runtime-package-entry-limit-');
  for (let index = 0; index <= runtimeVerificationBounds.packageTreeEntries; index += 1) {
    writeFileSync(join(root, `entry-${String(index).padStart(5, '0')}`), '');
  }
  assert.throws(
    () => packageTreeSha256(root),
    error => error?.code === 'package-tree-entry-limit',
  );
});

test('runs the reproducible semantic runner check and its clean startup smoke', () => {
  const result = spawnSync(process.execPath, [semanticRunnerBuildScript, '--check'], {
    cwd: packageRoot,
    encoding: 'utf8',
    env: safeEnvironment(),
    timeout: 30_000,
    maxBuffer: 16_384,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
});

test('staged Calldiff resolves its pinned JavaScript grammar through the direct runtime importer', () => {
  const stagedRoot = makeTemporaryRoot('radar-runtime-calldiff-stage-');
  const sourcePackages = {
    calldiff: join(
      workspaceRoot,
      'node_modules/.pnpm/calldiff@0.4.1/node_modules/calldiff',
    ),
    treeSitter: join(
      workspaceRoot,
      'node_modules/.pnpm/tree-sitter@0.25.1/node_modules/tree-sitter',
    ),
    treeSitterJavascript: join(
      workspaceRoot,
      'node_modules/.pnpm/tree-sitter-javascript@0.23.1_tree-sitter@0.25.1/node_modules/tree-sitter-javascript',
    ),
    nodeAddonApi: join(
      workspaceRoot,
      'node_modules/.pnpm/node-addon-api@8.9.1/node_modules/node-addon-api',
    ),
    nodeGypBuild: join(
      workspaceRoot,
      'node_modules/.pnpm/node-gyp-build@4.8.4/node_modules/node-gyp-build',
    ),
  };
  for (const source of Object.values(sourcePackages)) {
    assert.equal(existsSync(source), true, `Missing staged source package ${source}.`);
  }

  const namespace = join(
    stagedRoot,
    'node_modules/.pnpm/calldiff@0.4.1/node_modules',
  );
  const stagedCalldiff = join(namespace, 'calldiff');
  const stagedTreeSitter = join(
    stagedRoot,
    'node_modules/.pnpm/tree-sitter@0.25.1/node_modules/tree-sitter',
  );
  const stagedTreeSitterJavascript = join(
    stagedRoot,
    'node_modules/.pnpm/tree-sitter-javascript@0.23.1_tree-sitter@0.25.1/node_modules/tree-sitter-javascript',
  );
  const stagedNodeAddonApi = join(
    stagedRoot,
    'node_modules/.pnpm/node-addon-api@8.9.1/node_modules/node-addon-api',
  );
  const stagedNodeGypBuild = join(
    stagedRoot,
    'node_modules/.pnpm/node-gyp-build@4.8.4/node_modules/node-gyp-build',
  );
  mkdirSync(namespace, { recursive: true });
  for (const [source, destination] of [
    [sourcePackages.calldiff, stagedCalldiff],
    [sourcePackages.treeSitter, stagedTreeSitter],
    [sourcePackages.treeSitterJavascript, stagedTreeSitterJavascript],
    [sourcePackages.nodeAddonApi, stagedNodeAddonApi],
    [sourcePackages.nodeGypBuild, stagedNodeGypBuild],
  ]) {
    cpSync(source, destination, { recursive: true, dereference: true });
  }
  for (const [name, source] of [['tree-sitter', stagedTreeSitter]]) {
    symlinkSync(source, join(namespace, name), 'dir');
  }
  for (const grammarNamespace of [
    dirname(stagedTreeSitter),
    dirname(stagedTreeSitterJavascript),
  ]) {
    symlinkSync(stagedNodeAddonApi, join(grammarNamespace, 'node-addon-api'), 'dir');
    symlinkSync(stagedNodeGypBuild, join(grammarNamespace, 'node-gyp-build'), 'dir');
  }
  symlinkSync(
    stagedTreeSitter,
    join(dirname(stagedTreeSitterJavascript), 'tree-sitter'),
    'dir',
  );
  symlinkSync(stagedCalldiff, join(stagedRoot, 'node_modules/calldiff'), 'dir');
  symlinkSync(
    stagedTreeSitterJavascript,
    join(stagedRoot, 'node_modules/tree-sitter-javascript'),
    'dir',
  );
  assert.equal(
    existsSync(join(stagedRoot, 'node_modules/.pnpm/node_modules')),
    false,
    'The pnpm fallback namespace must be absent from the staged runtime.',
  );

  const grammarEntry = join(stagedCalldiff, 'dist/languages/grammars.js');
  const resolvedGrammar = realpathSync(
    createRequire(grammarEntry).resolve('tree-sitter-javascript'),
  );
  const pinnedGrammarRoot = realpathSync(stagedTreeSitterJavascript);
  assert.ok(
    resolvedGrammar === pinnedGrammarRoot ||
      resolvedGrammar.startsWith(`${pinnedGrammarRoot}/`),
    `Calldiff grammar resolved ${resolvedGrammar}; expected pinned runtime root ${pinnedGrammarRoot}.`,
  );

  const script = join(stagedRoot, 'calldiff-analyzer.mjs');
  const source = join(stagedRoot, 'source');
  copyFileSync(join(packageRoot, 'calldiff-analyzer.mjs'), script);
  mkdirSync(source, { recursive: true });
  writeFileSync(
    join(source, 'fixture.js'),
    'export function javascriptFixture() { return 1; }\n',
  );
  writeFileSync(
    join(source, 'fixture.jsx'),
    [
      'function Widget() { return null; }',
      'export function jsxFixture() { return <Widget />; }',
      '',
    ].join('\n'),
  );
  const result = spawnSync(process.execPath, [script, source], {
    cwd: stagedRoot,
    encoding: 'utf8',
    env: safeEnvironment(),
    timeout: 20_000,
    maxBuffer: 131_072,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.eligibleFiles, 2);
  assert.equal(report.analyzedFiles, 2);
  assert.deepEqual(report.failedFiles, []);
  assert.ok(report.functionCount >= 3, result.stdout);
});

test('rejects tampered Calldiff and Oxlint closure files before any canary can run', {
  skip:
    process.platform !== 'linux' || process.arch !== 'x64'
      ? 'package-tree tamper identity is pinned for the production Linux x64 closure'
      : false,
}, () => {
  const manifest = canonicalManifest();
  const cases = [
    {
      analyzerId: 'calldiff',
      name: 'calldiff',
      source: join(workspaceRoot, 'node_modules/.pnpm/calldiff@0.4.1/node_modules/calldiff'),
      paths: ['dist/extract.js', 'dist/languages/grammars.js'],
    },
    {
      analyzerId: 'oxlint-ultracite',
      name: 'oxlint',
      source: join(workspaceRoot, 'node_modules/.pnpm/oxlint@1.77.0/node_modules/oxlint'),
      paths: ['dist/cli.js'],
    },
  ];
  for (const item of cases) {
    assert.ok(existsSync(item.source), `Installed source package ${item.name} is required for this static test.`);
    const expected = packageCheck(manifest, item.analyzerId, item.name).treeSha256;
    for (const relativePath of item.paths) {
      const root = makeTemporaryRoot('radar-runtime-closure-');
      const copiedPackage = join(root, item.name);
      const copied = spawnSync('/bin/cp', ['--archive', '--', item.source, copiedPackage], {
        encoding: 'utf8',
      });
      assert.equal(copied.status, 0, copied.stderr);
      rmSync(join(copiedPackage, 'node_modules/.bin'), {
        recursive: true,
        force: true,
      });
      assert.equal(packageTreeSha256(copiedPackage), expected);
      const marker = join(root, 'canary-executed');
      const canary = join(root, 'canary.mjs');
      writeFileSync(canary, markerProgram(marker));
      const target = join(copiedPackage, relativePath);
      writeFileSync(target, `${readFileSync(target, 'utf8')}\n// tampered\n`);
      assert.throws(
        () => {
          assertPackageTreeSha256({
            analyzer: item.analyzerId,
            packageName: item.name,
            packageRoot: copiedPackage,
            expectedSha256: expected,
          });
          executeCanary(canary);
        },
        /package-tree-mismatch/u,
        relativePath,
      );
      assert.equal(existsSync(marker), false, `${relativePath} must fail before a canary executes.`);
    }
  }
});

test('authenticates every pnpm importer namespace and execution-free resolution edge', () => {
  const fixture = makePnpmResolutionFixture();
  const resolutionMarker = join(fixture.root, 'resolution-marker-executed');
  writeFileSync(
    join(fixture.nodes.get('tree-sitter@0.25.1').packageDirectory, 'index.js'),
    markerProgram(resolutionMarker),
  );
  const evidence = verifyPackageClosureShadows({
    root: fixture.root,
    packageRoots: fixture.packageRoots,
    manifest: fixture.manifest,
  });
  assert.equal(existsSync(resolutionMarker), false, 'resolution must not import package code.');
  assert.deepEqual(
    evidence
      .map(({ importer, specifier, package: packageIdentity, resolver }) =>
        `${importer}\u0000${specifier}\u0000${packageIdentity}\u0000${resolver}`,
      )
      .sort(),
    fixture.expectedEdges
      .map(({ importer, specifier, package: packageIdentity, resolver }) =>
        `${importer}\u0000${specifier}\u0000${packageIdentity}\u0000${resolver}`,
      )
      .sort(),
  );
  for (const edge of evidence) {
    const importer = fixture.nodes.get(edge.importer);
    const target = fixture.nodes.get(edge.package);
    const targetRoot = realpathSync(target.packageDirectory);
    if (edge.resolver === 'pnpm-link-import-only') {
      assert.equal(edge.resolved, targetRoot);
      assert.throws(
        () => createRequire(join(importer.packageDirectory, 'package.json')).resolve(edge.specifier),
        error => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
      );
      continue;
    }
    const resolved = realpathSync(
      createRequire(join(importer.packageDirectory, 'package.json')).resolve(
        edge.specifier,
      ),
    );
    assert.ok(
      resolved === targetRoot || resolved.startsWith(`${targetRoot}/`),
      `${edge.importer} ${edge.specifier} resolved ${resolved}; expected ${edge.package} at ${targetRoot}.`,
    );
  }
  assert.equal(existsSync(resolutionMarker), false, 'createRequire.resolve must not execute package code.');
});

test('rejects every unmodeled pnpm sibling shadow before a marker can execute', () => {
  const cases = [
    ['Calldiff tree-sitter sibling', 'calldiff@0.4.1', 'tree-sitter'],
    ['Oxlint binding', 'oxlint@1.77.0', '@oxlint/binding-linux-x64-gnu'],
    ['JSCPD Linux platform package', 'jscpd@5.0.14', 'jscpd-linux-x64-gnu'],
    ['tree-sitter TypeScript core', 'tree-sitter-typescript@0.23.2', 'tree-sitter'],
    ['tree-sitter TypeScript JavaScript grammar', 'tree-sitter-typescript@0.23.2', 'tree-sitter-javascript'],
    ['tree-sitter TypeScript node-addon-api', 'tree-sitter-typescript@0.23.2', 'node-addon-api'],
    ['tree-sitter TypeScript node-gyp-build', 'tree-sitter-typescript@0.23.2', 'node-gyp-build'],
  ];
  for (const [label, importerIdentity, specifier] of cases) {
    const fixture = makePnpmResolutionFixture();
    const marker = join(fixture.root, `${specifier.replaceAll('/', '-')}-executed`);
    const shadow = writePnpmPackage({
      root: fixture.root,
      snapshot: `shadow-${specifier.replaceAll(/[^A-Za-z0-9]/gu, '-')}`,
      name: specifier,
      version: '99.0.0',
    });
    writeFileSync(join(shadow.packageDirectory, 'index.js'), markerProgram(marker));
    const link = fixture.dependencyLinks.get(`${importerIdentity}\u0000${specifier}`);
    assert.ok(link, `Missing ${label} fixture link.`);
    rmSync(link);
    symlinkSync(shadow.packageDirectory, link, 'dir');
    const canary = join(fixture.root, 'canary.mjs');
    writeFileSync(canary, markerProgram(marker));
    assert.throws(
      () => {
        verifyPnpmResolutionGraph({
          root: fixture.root,
          packageRoots: fixture.packageRoots,
          manifest: fixture.manifest,
        });
        executeCanary(canary);
      },
      /package-(?:shadow-unmodeled|resolution-root-mismatch|specifier-mismatch)/u,
      label,
    );
    assert.equal(existsSync(marker), false, `${label} must fail before loading a shadow or canary.`);
  }
});

test('never imports a target-supplied verifier or target CLI while making a plan', () => {
  const invalidVerifierRoot = writeAuthenticatedControlRoot();
  const verifierMarker = join(invalidVerifierRoot, 'target-verifier-executed');
  writeFileSync(
    join(invalidVerifierRoot, 'runtime-manifest.mjs'),
    markerProgram(verifierMarker),
  );
  const invalidVerifier = runPreparePlan(invalidVerifierRoot);
  assert.notEqual(invalidVerifier.status, 0);
  assert.match(invalidVerifier.stderr, /target-verifier-layout-mismatch/u);
  assert.equal(existsSync(verifierMarker), false);

  const cliRoot = writeAuthenticatedControlRoot();
  const cliMarker = join(cliRoot, 'cli-executed');
  writeFileSync(join(cliRoot, 'marker.mjs'), markerProgram(cliMarker));
  mkdirSync(join(cliRoot, 'node_modules/.bin'), { recursive: true });
  rmSync(join(cliRoot, 'node_modules/.bin/oxlint'), { force: true });
  symlinkSync(join(cliRoot, 'marker.mjs'), join(cliRoot, 'node_modules/.bin/oxlint'));
  const cliPlan = runPreparePlan(cliRoot);
  assert.equal(cliPlan.status, 0, cliPlan.stderr);
  assert.equal(existsSync(cliMarker), false);

  const binaryRoot = writeAuthenticatedControlRoot();
  const binaryMarker = join(binaryRoot, 'binary-executed');
  writeFileSync(join(binaryRoot, 'marker.mjs'), markerProgram(binaryMarker));
  symlinkSync(join(binaryRoot, 'marker.mjs'), join(binaryRoot, 'bin/tracedecay'));
  const binaryPlan = runPreparePlan(binaryRoot);
  assert.equal(binaryPlan.status, 0, binaryPlan.stderr);
  assert.equal(existsSync(binaryMarker), false);
});

test('requires one explicit runtime root and rejects conflicting or malformed overrides', () => {
  const root = writeAuthenticatedControlRoot();
  const ignoredCliRoot = makeTemporaryRoot('radar-runtime-ignored-cli-');
  const authoritative = runPublicVerifier(
    ['prepare-plan', '--runtime-root', root],
    { RADAR_ANALYZER_ROOT: root },
  );
  assert.equal(authoritative.status, 0, authoritative.stderr);
  const conflict = runPublicVerifier(
    ['prepare-plan', '--runtime-root', ignoredCliRoot],
    { RADAR_ANALYZER_ROOT: root },
  );
  assert.notEqual(conflict.status, 0);
  assert.match(conflict.stderr, /root-override-conflict/u);
  for (const override of ['', 'relative-runtime-root', `${root}\n`]) {
    const result = runPreparePlan(root, { RADAR_ANALYZER_ROOT: override });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /root-override-invalid/u);
  }
});

test('rejects control symlinks and clears loader environment injection before target code can run', () => {
  const symlinkRoot = writeAuthenticatedControlRoot();
  const manifestMarker = join(symlinkRoot, 'manifest-executed');
  const manifestPayload = join(symlinkRoot, 'manifest-payload.json');
  writeFileSync(manifestPayload, markerProgram(manifestMarker));
  rmSync(join(symlinkRoot, 'runtime-manifest.json'));
  symlinkSync(manifestPayload, join(symlinkRoot, 'runtime-manifest.json'));
  const symlinkResult = runPreparePlan(symlinkRoot);
  assert.notEqual(symlinkResult.status, 0);
  assert.match(symlinkResult.stderr, /control-symlink-rejected/u);
  assert.equal(existsSync(manifestMarker), false);

  const environmentRoot = writeAuthenticatedControlRoot();
  const environmentMarker = join(environmentRoot, 'environment-executed');
  const preload = join(environmentRoot, 'preload-marker.cjs');
  writeFileSync(preload, requireMarkerProgram(environmentMarker));
  const environmentResult = runPreparePlan(environmentRoot, {
    NODE_PATH: environmentRoot,
    NODE_OPTIONS: `--require ${preload}`,
  });
  assert.equal(environmentResult.status, 0, environmentResult.stderr);
  assert.equal(existsSync(environmentMarker), false);

  const directResult = spawnSync(
    process.execPath,
    [verificationScript, 'prepare-plan', '--runtime-root', environmentRoot],
    {
      cwd: workspaceRoot,
      encoding: 'utf8',
      env: safeEnvironment(),
    },
  );
  assert.notEqual(directResult.status, 0);
  assert.match(directResult.stderr, /bootstrap-required/u);
});

test('rejects hard-linked public verifier controls before it reads target bytes', () => {
  for (const controlPath of ['runtime-manifest.json', 'runtime-manifest.mjs']) {
    const root = writeAuthenticatedControlRoot();
    const control = join(root, controlPath);
    linkSync(control, join(root, `${controlPath.replaceAll('/', '-')}.hardlink`));
    const result = runPreparePlan(root);
    assert.notEqual(result.status, 0, controlPath);
    assert.match(result.stderr, /control-file-invalid/u, controlPath);
  }
});

test('rejects oversized sparse public verifier controls before allocating their contents', () => {
  for (const controlPath of ['runtime-manifest.json', 'runtime-manifest.mjs']) {
    const root = writeAuthenticatedControlRoot();
    writeHugeSparseFile(
      join(root, controlPath),
      runtimeVerificationBounds.manifestBytes + 1,
    );
    const result = runPreparePlan(root);
    assert.notEqual(result.status, 0, controlPath);
    assert.match(result.stderr, /control-file-invalid/u, controlPath);
  }
});

test('descriptor-copies runtime sources within fixed type, link, depth, and byte bounds', () => {
  const runCopy = (source, destination) =>
    spawnSync(
      '/usr/bin/python3',
      [atomicExchangeScript, 'copy-source', source, destination],
      { cwd: workspaceRoot, encoding: 'utf8', env: safeEnvironment() },
    );

  const validRoot = makeTemporaryRoot('radar-runtime-source-copy-');
  const validSource = join(validRoot, 'source');
  const validDestination = join(validRoot, 'destination');
  mkdirSync(join(validSource, 'node_modules'), { recursive: true });
  mkdirSync(validDestination);
  writeFileSync(join(validSource, 'payload'), 'bounded payload\n');
  symlinkSync('../payload', join(validSource, 'node_modules/payload'));
  const generatedPackageBin = join(
    validSource,
    'node_modules/.pnpm/cross-spawn@7.0.6/node_modules/cross-spawn/node_modules/.bin',
  );
  mkdirSync(generatedPackageBin, { recursive: true });
  writeFileSync(
    join(generatedPackageBin, 'node-which'),
    '#!/bin/sh\n# cmd-shim-target=/absolute/build/root/node-which\n',
    { mode: 0o755 },
  );
  const packageExampleBin = join(
    validSource,
    'node_modules/.pnpm/incur@0.4.26/node_modules/incur/examples/npm/node_modules/.bin',
  );
  mkdirSync(packageExampleBin, { recursive: true });
  writeFileSync(join(packageExampleBin, 'fixture'), 'package payload\n');
  const valid = runCopy(validSource, validDestination);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(readFileSync(join(validDestination, 'payload'), 'utf8'), 'bounded payload\n');
  assert.equal(readlinkSync(join(validDestination, 'node_modules/payload')), '../payload');
  assert.equal(
    existsSync(join(
      validDestination,
      'node_modules/.pnpm/cross-spawn@7.0.6/node_modules/cross-spawn/node_modules/.bin',
    )),
    false,
  );
  assert.equal(
    readFileSync(join(
      validDestination,
      'node_modules/.pnpm/incur@0.4.26/node_modules/incur/examples/npm/node_modules/.bin/fixture',
    ), 'utf8'),
    'package payload\n',
  );

  const oversizedRoot = makeTemporaryRoot('radar-runtime-source-copy-oversized-');
  const oversizedSource = join(oversizedRoot, 'source');
  const oversizedDestination = join(oversizedRoot, 'destination');
  mkdirSync(oversizedSource);
  mkdirSync(oversizedDestination);
  writeHugeSparseFile(join(oversizedSource, 'oversized'), 256 * 1024 * 1024 + 1);
  const oversized = runCopy(oversizedSource, oversizedDestination);
  assert.notEqual(oversized.status, 0);
  assert.match(oversized.stderr, /source-copy-file-invalid/u);

  const hardlinkRoot = makeTemporaryRoot('radar-runtime-source-copy-hardlink-');
  const hardlinkSource = join(hardlinkRoot, 'source');
  const hardlinkDestination = join(hardlinkRoot, 'destination');
  mkdirSync(hardlinkSource);
  mkdirSync(hardlinkDestination);
  writeFileSync(join(hardlinkSource, 'payload'), 'linked\n');
  linkSync(join(hardlinkSource, 'payload'), join(hardlinkSource, 'alias'));
  const hardlink = runCopy(hardlinkSource, hardlinkDestination);
  assert.notEqual(hardlink.status, 0);
  assert.match(hardlink.stderr, /source-copy-file-invalid/u);

  const escapeRoot = makeTemporaryRoot('radar-runtime-source-copy-escape-');
  const escapeSource = join(escapeRoot, 'source');
  const escapeDestination = join(escapeRoot, 'destination');
  mkdirSync(escapeSource);
  mkdirSync(escapeDestination);
  symlinkSync('../outside', join(escapeSource, 'escape'));
  const escape = runCopy(escapeSource, escapeDestination);
  assert.notEqual(escape.status, 0);
  assert.match(escape.stderr, /source-copy-symlink-invalid/u);

  const depthRoot = makeTemporaryRoot('radar-runtime-source-copy-depth-');
  const depthSource = join(depthRoot, 'source');
  const depthDestination = join(depthRoot, 'destination');
  mkdirSync(depthSource);
  mkdirSync(depthDestination);
  let deepest = depthSource;
  for (let index = 0; index < 66; index += 1) {
    deepest = join(deepest, `d${String(index).padStart(2, '0')}`);
    mkdirSync(deepest);
  }
  const depth = runCopy(depthSource, depthDestination);
  assert.notEqual(depth.status, 0);
  assert.match(depth.stderr, /source-copy-depth-limit/u);

  const specialRoot = makeTemporaryRoot('radar-runtime-source-copy-special-');
  const specialSource = join(specialRoot, 'source');
  const specialDestination = join(specialRoot, 'destination');
  mkdirSync(specialSource);
  mkdirSync(specialDestination);
  const fifo = spawnSync('/usr/bin/mkfifo', [join(specialSource, 'fifo')], {
    encoding: 'utf8',
  });
  assert.equal(fifo.status, 0, fifo.stderr);
  const special = runCopy(specialSource, specialDestination);
  assert.notEqual(special.status, 0);
  assert.match(special.stderr, /source-copy-entry-invalid/u);
});

test('preflights one tar.gz member size before extraction can write destination bytes', () => {
  const writeTarGz = (path, name, declaredSize, payload = Buffer.alloc(0)) => {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'ascii');
    header.write('0000755\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write(`${declaredSize.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii');
    header.fill(0x20, 148, 156);
    header.write('0', 156, 1, 'ascii');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    const padding = Buffer.alloc((512 - (payload.byteLength % 512)) % 512);
    writeFileSync(path, gzipSync(Buffer.concat([
      header,
      payload,
      padding,
      Buffer.alloc(1024),
    ])));
  };
  const root = makeTemporaryRoot('radar-runtime-tar-preflight-');
  const validArchive = join(root, 'valid.tar.gz');
  const oversizedArchive = join(root, 'oversized.tar.gz');
  const destination = join(root, 'destination');
  mkdirSync(destination);
  writeTarGz(validArchive, 'tool', 4, Buffer.from('tool', 'ascii'));
  writeTarGz(oversizedArchive, 'tool', 256 * 1024 * 1024 + 1);
  const runValidation = archive => spawnSync(
    '/usr/bin/python3',
    [atomicExchangeScript, 'validate-tar-gz-member', archive, 'tool', String(256 * 1024 * 1024)],
    { cwd: workspaceRoot, encoding: 'utf8', env: safeEnvironment() },
  );
  const valid = runValidation(validArchive);
  assert.equal(valid.status, 0, valid.stderr);
  const oversized = runValidation(oversizedArchive);
  assert.notEqual(oversized.status, 0);
  assert.match(oversized.stderr, /archive-member-invalid/u);
  assert.deepEqual(readdirSync(destination), []);
});

test('rejects symlink and traversal destinations without mutating the live runtime', () => {
  const root = writeAuthenticatedControlRoot();
  const original = sha256(readFileSync(join(root, 'runtime-manifest.json')));
  const external = makeTemporaryRoot('radar-runtime-external-');
  rmSync(join(root, 'bin'), { recursive: true, force: true });
  symlinkSync(external, join(root, 'bin'));
  const symlinkResult = runPreparation(preparationScript, join(root, 'bin'));
  assert.notEqual(symlinkResult.status, 0);
  assert.match(symlinkResult.stderr, /destination-invalid|destination-symlink-rejected/u);
  assert.equal(sha256(readFileSync(join(root, 'runtime-manifest.json'))), original);
  assert.deepEqual(readFileSync(join(root, 'runtime-manifest.mjs')), readFileSync(join(packageRoot, 'runtime-manifest.mjs')));

  const danglingRoot = writeAuthenticatedControlRoot();
  const danglingExternal = join(danglingRoot, 'missing-external-bin');
  rmSync(join(danglingRoot, 'bin'), { recursive: true, force: true });
  symlinkSync(danglingExternal, join(danglingRoot, 'bin'));
  const danglingResult = runPreparation(
    preparationScript,
    join(danglingRoot, 'bin'),
  );
  assert.notEqual(danglingResult.status, 0);
  assert.match(danglingResult.stderr, /destination-invalid/u);
  assert.equal(existsSync(danglingExternal), false);

  const traversalRoot = writeAuthenticatedControlRoot();
  const traversalResult = runPreparation(
    preparationScript,
    `${join(traversalRoot, 'bin')}/../bin`,
  );
  assert.notEqual(traversalResult.status, 0);
  assert.match(traversalResult.stderr, /destination-invalid/u);
  assert.deepEqual(readdirSync(join(traversalRoot, 'bin')), []);
});

test('accepts an ordinary absolute bin destination and rejects representable controls before mutation', () => {
  const fixture = makeDestinationValidationFixture();
  const ordinary = runPreparation(
    fixture.preparation,
    join(fixture.runtime, 'bin'),
  );
  assert.notEqual(ordinary.status, 0);
  if (process.platform === 'darwin') {
    assert.match(ordinary.stderr, /atomic-exchange-unavailable/u);
    assert.equal(existsSync(fixture.marker), false);
  } else {
    assert.match(
      ordinary.stderr,
      /manifest-plan-invalid/u,
      JSON.stringify({
        status: ordinary.status,
        signal: ordinary.signal,
        error: ordinary.error?.message,
        stdout: ordinary.stdout,
        stderr: ordinary.stderr,
      }),
    );
    assert.equal(existsSync(fixture.marker), true, 'ordinary absolute destination must reach preparation.');
  }
  assert.equal(snapshotTree(fixture.runtime), fixture.before);

  rmSync(fixture.marker, { force: true });
  const control = runPreparation(
    fixture.preparation,
    `${join(fixture.runtime, 'bin')}\n`,
  );
  assert.notEqual(control.status, 0);
  assert.match(control.stderr, /destination-invalid/u);
  assert.equal(existsSync(fixture.marker), false, 'control-bearing destination must fail before preparation.');
  assert.equal(snapshotTree(fixture.runtime), fixture.before);
});

test('keeps a prior runtime unchanged on a checksum failure before publish', {
  skip: process.platform === 'darwin'
    ? 'Linux x64 glibc publication is exercised only by the Linux acceptance runner.'
    : false,
}, () => {
  const fixture = makePreparationFixture({ corruptTraceDownload: true });
  const result = runPreparationFixture(fixture);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /checksum-mismatch/u);
  assertPreparationFailurePreserved(fixture);
});

test('rejects hostile archives and keeps the authoritative runtime old or verified-new across crashes', {
  skip: process.platform === 'darwin'
    ? 'Linux x64 glibc renameat2 crash gate is deferred to the Linux acceptance runner.'
    : false,
}, () => {
  const archiveCases = [
    { archiveKind: 'extra', pattern: /archive-(?:member|members|member-type)-invalid/u },
    { archiveKind: 'option', pattern: /archive-(?:member|members|member-type)-invalid/u },
    { archiveKind: 'traversal', pattern: /manifest-plan-invalid/u },
    { archiveKind: 'symlink', pattern: /archive-(?:member|members|member-type)-invalid/u },
    { archiveKind: 'hardlink', pattern: /archive-(?:member|members|member-type)-invalid/u },
  ];
  for (const { archiveKind, pattern } of archiveCases) {
    const fixture = makePreparationFixture({ archiveKind });
    const result = runPreparationFixture(fixture);
    assert.notEqual(result.status, 0, `${archiveKind}: ${result.stderr}`);
    assert.match(result.stderr, pattern);
    assertPreparationFailurePreserved(fixture);
  }

  const checksumFixture = makePreparationFixture({ corruptTraceDownload: true });
  const checksumResult = runPreparationFixture(checksumFixture);
  assert.notEqual(checksumResult.status, 0, checksumResult.stderr);
  assert.match(checksumResult.stderr, /checksum-mismatch/u);
  assertPreparationFailurePreserved(checksumFixture);

  const lateFixture = makePreparationFixture({ verifierBehavior: 'late-failure' });
  const lateResult = runPreparationFixture(lateFixture);
  assert.notEqual(lateResult.status, 0, lateResult.stderr);
  assert.match(lateResult.stderr, /late verifier failure/u);
  assertPreparationFailurePreserved(lateFixture);

  const interruptionFixture = makePreparationFixture({ verifierBehavior: 'interrupt' });
  const interruptionResult = runPreparationFixture(interruptionFixture);
  assert.notEqual(interruptionResult.status, 0, interruptionResult.stderr);
  assertPreparationFailurePreserved(interruptionFixture);

  const killBeforeExchangeFixture = makePreparationFixture({
    verifierBehavior: 'kill-before-exchange',
  });
  const killBeforeExchangeResult = runPreparationFixture(killBeforeExchangeFixture);
  assert.notEqual(killBeforeExchangeResult.status, 0, killBeforeExchangeResult.stderr);
  assert.equal(snapshotTree(killBeforeExchangeFixture.runtime), killBeforeExchangeFixture.before);
  assert.equal(existsSync(join(killBeforeExchangeFixture.external, 'escaped')), false);

  const successfulFixture = makePreparationFixture();
  const successfulResult = runPreparationFixture(successfulFixture);
  assert.equal(successfulResult.status, 0, successfulResult.stderr);
  assert.deepEqual(
    readdirSync(join(successfulFixture.runtime, 'bin')).sort(),
    managedRuntimeBinEntries,
    'A published managed runtime must contain exactly the reviewed bin inventory.',
  );
  assert.equal(
    readFileSync(join(successfulFixture.runtime, 'bin/node'), 'utf8'),
    successfulFixture.runtimeNodeContents,
    'The staged runtime Node must come from the reviewed archive member.',
  );
  assert.equal(
    lstatSync(join(successfulFixture.runtime, 'bin/node')).mode & 0o7777,
    0o755,
  );
  assert.equal(
    lstatSync(join(successfulFixture.runtime, 'bin/radar-semantic-analyzer.mjs')).mode & 0o7777,
    0o755,
  );
  const publishedOsvDatabase = join(
    successfulFixture.runtime,
    'databases/osv/osv-scalibr/npm/all.zip',
  );
  assert.equal(
    readFileSync(publishedOsvDatabase, 'utf8'),
    successfulFixture.osvDatabaseContents,
    'The staged OSV database must come from the reviewed immutable snapshot.',
  );
  assert.equal(lstatSync(publishedOsvDatabase).mode & 0o7777, 0o444);
  const verifiedPublished = snapshotTree(successfulFixture.runtime);
  assert.notEqual(verifiedPublished, successfulFixture.before);

  const killAfterExchangeFixture = makePreparationFixture({
    forceKillAfterExchange: true,
  });
  const killAfterExchangeResult = runPreparationFixture(killAfterExchangeFixture);
  assert.notEqual(killAfterExchangeResult.status, 0, killAfterExchangeResult.stderr);
  const authoritative = snapshotTree(killAfterExchangeFixture.runtime);
  assert.ok(
    authoritative === killAfterExchangeFixture.before || authoritative === verifiedPublished,
    'forced kill may observe only the prior runtime or the fully verified published runtime.',
  );
  assert.equal(existsSync(join(killAfterExchangeFixture.external, 'escaped')), false);
});

test('rejects unexpected managed bin entries before publication', {
  skip: process.platform !== 'linux' || process.arch !== 'x64'
    ? 'Managed bin publication is exercised only by the Linux acceptance runner.'
    : false,
}, () => {
  const fixture = makePreparationFixture();
  const unexpected = join(fixture.runtime, 'bin/unexpected');
  writeFileSync(unexpected, '#!/bin/sh\nexit 0\n');
  chmodSync(unexpected, 0o755);
  fixture.before = snapshotTree(fixture.runtime);

  const result = runPreparationFixture(fixture);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /managed-bin-inventory-invalid/u);
  assertPreparationFailurePreserved(fixture);
});

test('removes a losing publisher stage after recovering the winning journal', {
  skip: process.platform !== 'linux' || process.arch !== 'x64'
    ? 'Atomic concurrent publisher recovery requires Linux x86_64 renameat2.'
    : false,
}, async () => {
  const fixture = makePreparationFixture();
  const ready = join(fixture.root, 'publisher-b-ready');
  const hold = join(fixture.root, 'publisher-b-hold');
  const verifier = join(fixture.root, 'scripts', 'verify-runtime-tools.mjs');
  const journal = join(fixture.root, '.analyzer-runtime-publish.journal');
  const persistentLock = '.analyzer-runtime-publish.journal.lock';
  const defaultVerify = [
    "if (process.argv[2] === 'verify') {",
    '  process.exit(0);',
    '}',
  ].join('\n');
  const source = readFileSync(verifier, 'utf8');
  assert.ok(source.includes(defaultVerify), 'Fixture must start from the reviewed success verifier.');
  writeFileSync(hold, 'hold\n');
  writeFileSync(
    verifier,
    [
      "import { existsSync, writeFileSync } from 'node:fs';",
      source.replace(
        defaultVerify,
        [
          "if (process.argv[2] === 'verify') {",
          `  writeFileSync(${JSON.stringify(ready)}, 'ready\\n');`,
          `  while (existsSync(${JSON.stringify(hold)})) {`,
          '    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);',
          '  }',
          '  process.exit(0);',
          '}',
        ].join('\n'),
      ),
    ].join('\n'),
  );

  const preparation = startPreparationFixture(fixture);
  let foreignStage;
  let result;
  try {
    await waitForPath(ready, 'Publisher B did not reach its verified staged generation.');
    assert.equal(
      readdirSync(fixture.root).filter(name => name.startsWith('.analyzer-runtime-stage.')).length,
      1,
      'Publisher B must own exactly one staged generation before it publishes.',
    );
    foreignStage = join(fixture.root, 'publisher-a-stage');
    cpSync(fixture.runtime, foreignStage, { recursive: true });
    writeFileSync(join(foreignStage, 'publisher-a-verified'), 'publisher-a\n');
    const published = spawnSync(
      '/usr/bin/python3',
      [
        join(fixture.root, 'scripts', 'runtime-atomic-exchange.py'),
        'publish',
        fixture.runtime,
        foreignStage,
        journal,
      ],
      {
        cwd: fixture.root,
        encoding: 'utf8',
        env: safeEnvironment(),
      },
    );
    assert.equal(published.status, 0, published.stderr);
    assert.equal(existsSync(journal), true);
  } finally {
    rmSync(hold, { force: true });
    result ??= await preparation.completed;
  }

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /journal-present/u);
  assert.equal(existsSync(journal), false);
  assert.equal(existsSync(foreignStage), false);
  assert.equal(readFileSync(join(fixture.runtime, 'publisher-a-verified'), 'utf8'), 'publisher-a\n');
  assert.deepEqual(
    readdirSync(fixture.root).filter(
      name => name.startsWith('.analyzer-runtime-') && name !== persistentLock,
    ),
    [],
  );
});

test('completes partial journal writes and rejects journal writes that make no progress', () => {
  const harness = String.raw`
import importlib.util
import os
import shutil
import sys
import tempfile

script_path = sys.argv[1]
specification = importlib.util.spec_from_file_location("runtime_atomic_exchange", script_path)
helper = importlib.util.module_from_spec(specification)
specification.loader.exec_module(helper)
root = tempfile.mkdtemp(prefix="runtime-atomic-journal-write-")
try:
    journal = os.path.join(root, ".analyzer-runtime-publish.journal")
    payload = helper.journal_payload(
        os.path.join(root, "runtime"),
        os.path.join(root, "stage"),
        "0" * 32,
        "prepared",
        {"device": 1, "inode": 2},
        {"device": 1, "inode": 3},
    )
    original_write = helper.os.write
    partial_writes = [0]
    def partial_write(descriptor, contents):
        partial_writes[0] += 1
        if partial_writes[0] == 1:
            return original_write(descriptor, contents[:1])
        return original_write(descriptor, contents)
    helper.os.write = partial_write
    helper.write_journal(journal, payload)
    assert partial_writes[0] >= 2
    assert helper.read_journal(journal) == payload
    os.unlink(journal)

    helper.os.write = lambda descriptor, contents: 0
    try:
        helper.write_journal(journal, payload)
    except SystemExit as error:
        assert error.code == 1
    else:
        raise AssertionError("A zero-progress journal write must fail.")
    assert not os.path.lexists(journal)
    assert not any(
        name.startswith(os.path.basename(journal) + ".new.")
        for name in os.listdir(root)
    )
finally:
    helper.os.write = original_write
    shutil.rmtree(root)
`;
  const result = spawnSync('/usr/bin/python3', ['-c', harness, atomicExchangeScript], {
    encoding: 'utf8',
    env: safeEnvironment(),
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test('serializes recovery with a persistent sibling lock that crashes free', {
  skip: process.platform === 'win32'
    ? 'Recovery locking requires a POSIX flock host.'
    : false,
}, () => {
  const harness = String.raw`
import errno
import fcntl
import importlib.util
import multiprocessing
import os
import shutil
import stat
import sys
import tempfile

script_path = sys.argv[1]
context = multiprocessing.get_context("fork")

def load_helper():
    specification = importlib.util.spec_from_file_location("runtime_atomic_exchange", script_path)
    helper = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(helper)
    return helper

def assert_lock_held(lock):
    descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                return
            raise
        raise AssertionError("Recovery did not hold the sibling lock.")
    finally:
        os.close(descriptor)

def assert_lock_released(lock):
    descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)

def hold_recovery(runtime, journal, ready, release):
    helper = load_helper()
    original_read = helper.read_journal
    def held_read(path):
        ready.set()
        assert release.wait(10), "Timed out waiting to release recovery."
        return original_read(path)
    helper.read_journal = held_read
    helper.recover(runtime, journal)

def crash_recovery(runtime, journal, ready):
    helper = load_helper()
    def crash_read(path):
        ready.set()
        os._exit(87)
    helper.read_journal = crash_read
    helper.recover(runtime, journal)

root = tempfile.mkdtemp(prefix="runtime-atomic-recovery-lock-")
runtime = os.path.join(root, "runtime")
journal = os.path.join(root, ".analyzer-runtime-publish.journal")
os.mkdir(runtime)
lock = journal + ".lock"
try:
    ready = context.Event()
    release = context.Event()
    recovery = context.Process(target=hold_recovery, args=(runtime, journal, ready, release))
    recovery.start()
    assert ready.wait(10), "Recovery did not enter its serialized operation."
    assert_lock_held(lock)
    release.set()
    recovery.join(10)
    assert recovery.exitcode == 0
    assert_lock_released(lock)

    crash_ready = context.Event()
    crashed = context.Process(target=crash_recovery, args=(runtime, journal, crash_ready))
    crashed.start()
    assert crash_ready.wait(10), "Recovery crash probe did not enter the lock."
    crashed.join(10)
    assert crashed.exitcode == 87
    assert_lock_released(lock)
    metadata = os.lstat(lock)
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert metadata.st_uid == os.lstat(root).st_uid
finally:
    shutil.rmtree(root)
`;
  const result = spawnSync('/usr/bin/python3', ['-c', harness, atomicExchangeScript], {
    encoding: 'utf8',
    env: safeEnvironment(),
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test('serializes publishers and recovers every durable journal crash point', {
  skip: process.platform !== 'linux' || process.arch !== 'x64'
    ? 'Atomic publication requires Linux x86_64 renameat2.'
    : false,
}, () => {
  const harness = String.raw`
import errno
import fcntl
import importlib.util
import multiprocessing
import os
import shutil
import stat
import sys
import tempfile

script_path = sys.argv[1]
context = multiprocessing.get_context("fork")

def load_helper():
    specification = importlib.util.spec_from_file_location("runtime_atomic_exchange", script_path)
    helper = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(helper)
    return helper

def write_generation(root, name, marker):
    generation = os.path.join(root, name)
    os.mkdir(generation)
    with open(os.path.join(generation, "verified"), "w", encoding="utf-8") as handle:
        handle.write(marker)
    return generation

def make_fixture():
    root = tempfile.mkdtemp(prefix="runtime-atomic-lock-")
    runtime = write_generation(root, "runtime", "old\\n")
    stage = write_generation(root, "stage", "new\\n")
    return root, runtime, stage, os.path.join(root, ".analyzer-runtime-publish.journal")

def assert_lock_held(lock):
    descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                return
            raise
        raise AssertionError("Publication operation did not hold the sibling lock.")
    finally:
        os.close(descriptor)

def assert_lock_released(lock):
    descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)

def crash_publish(runtime, stage, journal, point):
    helper = load_helper()
    if point in {"prepared", "exchanged"}:
        original_write = helper.write_journal
        writes = [0]
        def crash_after_write(path, payload):
            original_write(path, payload)
            writes[0] += 1
            if (point == "prepared" and writes[0] == 1) or (point == "exchanged" and writes[0] == 2):
                os._exit(91)
        helper.write_journal = crash_after_write
    elif point == "exchange":
        original_exchange = helper.rename_exchange
        def crash_after_exchange(left, right):
            original_exchange(left, right)
            os._exit(92)
        helper.rename_exchange = crash_after_exchange
    helper.publish(runtime, stage, journal)

def crash_cleanup(runtime, journal):
    helper = load_helper()
    original_remove_tree = helper.remove_tree
    def crash_after_tree(parent, candidate, label):
        original_remove_tree(parent, candidate, label)
        os._exit(93)
    helper.remove_tree = crash_after_tree
    helper.recover(runtime, journal)

def hold_publisher(runtime, stage, journal, ready, release):
    helper = load_helper()
    original_write = helper.write_journal
    writes = [0]
    def held_write(path, payload):
        original_write(path, payload)
        writes[0] += 1
        if writes[0] == 1:
            ready.set()
            assert release.wait(10), "Timed out waiting to release publisher."
    helper.write_journal = held_write
    helper.publish(runtime, stage, journal)

def competing_publisher(runtime, stage, journal, attempted):
    helper = load_helper()
    original_flock = helper.fcntl.flock
    def marked_flock(descriptor, operation):
        if operation == helper.fcntl.LOCK_EX:
            attempted.set()
        return original_flock(descriptor, operation)
    helper.fcntl.flock = marked_flock
    helper.publish(runtime, stage, journal)

def assert_recovered(root, runtime, stage, journal, expected):
    helper = load_helper()
    lock = helper.publication_lock_path(journal)
    assert_lock_released(lock)
    helper.recover(runtime, journal)
    with open(os.path.join(runtime, "verified"), encoding="utf-8") as handle:
        assert handle.read() == expected
    assert os.path.isdir(runtime)
    assert not os.path.lexists(stage)
    assert not os.path.lexists(journal)
    metadata = os.lstat(lock)
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1

for point, expected in (("prepared", "old\\n"), ("exchange", "new\\n"), ("exchanged", "new\\n")):
    root, runtime, stage, journal = make_fixture()
    try:
        publisher = context.Process(target=crash_publish, args=(runtime, stage, journal, point))
        publisher.start()
        publisher.join(10)
        assert publisher.exitcode in {91, 92}
        assert_recovered(root, runtime, stage, journal, expected)
    finally:
        shutil.rmtree(root)

root, runtime, stage, journal = make_fixture()
try:
    helper = load_helper()
    helper.publish(runtime, stage, journal)
    cleanup = context.Process(target=crash_cleanup, args=(runtime, journal))
    cleanup.start()
    cleanup.join(10)
    assert cleanup.exitcode == 93
    assert_recovered(root, runtime, stage, journal, "new\\n")
finally:
    shutil.rmtree(root)

root, runtime, stage, journal = make_fixture()
second_stage = write_generation(root, "second-stage", "second\\n")
try:
    ready = context.Event()
    release = context.Event()
    attempted = context.Event()
    first = context.Process(target=hold_publisher, args=(runtime, stage, journal, ready, release))
    first.start()
    assert ready.wait(10), "First publisher did not enter its serialized operation."
    assert_lock_held(journal + ".lock")
    second = context.Process(target=competing_publisher, args=(runtime, second_stage, journal, attempted))
    second.start()
    assert attempted.wait(10), "Second publisher did not attempt to acquire the sibling lock."
    release.set()
    first.join(10)
    second.join(10)
    assert first.exitcode == 0
    assert second.exitcode == 1
    helper = load_helper()
    helper.recover(runtime, journal)
    with open(os.path.join(runtime, "verified"), encoding="utf-8") as handle:
        assert handle.read() == "new\\n"
    assert not os.path.lexists(stage)
    assert not os.path.lexists(journal)
    helper.remove_directory(root, second_stage)
    assert not os.path.lexists(second_stage)
finally:
    shutil.rmtree(root)
`;
  const result = spawnSync('/usr/bin/python3', ['-c', harness, atomicExchangeScript], {
    encoding: 'utf8',
    env: safeEnvironment(),
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test('fails closed instead of claiming Linux native acceptance on other hosts', () => {
  const host = detectRuntimePlatform();
  if (
    host.os === linuxX64Glibc.os &&
    host.architecture === linuxX64Glibc.architecture &&
    host.libc === linuxX64Glibc.libc
  ) {
    return;
  }
  assert.throws(
    () => verifyRuntime({ root: packageRoot, target: linuxX64Glibc, lockPath }),
    /linux-acceptance-required/u,
  );
});
