import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import {
  requiredAnalyzerPrlimitArguments,
  requiredAnalyzerPrlimitPath,
  requiredOfflineOsvDatabase,
  requiredRuntimeNode,
  requiredSemanticRunnerPath,
  runtimeVerificationBounds,
} from './runtime-manifest.mjs';
import { runtimeTrustAnchor } from './trust-anchor.mjs';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(packageRoot, '../..');
const sourcePath = join(packageRoot, 'resource-governance-launcher.mjs');
const checkedInPath = join(packageRoot, 'control/resource-governance-launcher.mjs');
const expectedArguments = new Set(['--check', '--write']);
const mode = process.argv[2];

const virtualRuntimeManifest = [
  `export const requiredAnalyzerPrlimitArguments = Object.freeze(${JSON.stringify(requiredAnalyzerPrlimitArguments)});`,
  `export const requiredAnalyzerPrlimitPath = ${JSON.stringify(requiredAnalyzerPrlimitPath)};`,
  `export const requiredOfflineOsvDatabase = Object.freeze(${JSON.stringify(requiredOfflineOsvDatabase)});`,
  `export const requiredRuntimeNode = Object.freeze(${JSON.stringify(requiredRuntimeNode)});`,
  `export const requiredSemanticRunnerPath = ${JSON.stringify(requiredSemanticRunnerPath)};`,
  `export const runtimeVerificationBounds = Object.freeze(${JSON.stringify(runtimeVerificationBounds)});`,
  "export const assertOfflineOsvDatabaseFresh = () => { throw new Error('The standalone governance launcher cannot verify target manifests.'); };",
  "export const validateRuntimeManifest = () => { throw new Error('The standalone governance launcher cannot validate target manifests.'); };",
].join('\n');
const virtualTrustAnchor = `export const runtimeTrustAnchor = Object.freeze(${JSON.stringify({
  schemaVersion: runtimeTrustAnchor.schemaVersion,
  manifestSha256: runtimeTrustAnchor.manifestSha256,
  policyDigest: runtimeTrustAnchor.policyDigest,
  runnerSha256: runtimeTrustAnchor.runnerSha256,
  buildIdentity: runtimeTrustAnchor.buildIdentity,
  resourceGovernance: runtimeTrustAnchor.resourceGovernance,
})});`;

if (process.argv.length !== 3 || !expectedArguments.has(mode)) {
  throw new Error('Expected exactly --check or --write.');
}

const independentRegularFile = path => {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    throw new Error('The resource-governance launcher input is not an independent regular file.');
  }
};

independentRegularFile(sourcePath);
const temporaryRoot = mkdtempSync(join(tmpdir(), 'radar-governance-launcher-build-'));
const generatedPath = join(temporaryRoot, 'resource-governance-launcher.mjs');
try {
  const result = await build({
    absWorkingDir: workspaceRoot,
    bundle: true,
    charset: 'utf8',
    entryPoints: ['packages/analyzer-runtime/resource-governance-launcher.mjs'],
    format: 'esm',
    legalComments: 'eof',
    logLevel: 'silent',
    metafile: true,
    minify: false,
    minifySyntax: true,
    minifyWhitespace: true,
    outfile: generatedPath,
    platform: 'node',
    plugins: [{
      name: 'minimal-governance-launcher-trust',
      setup(build) {
        build.onResolve({ filter: /\/runtime-manifest\.mjs$/ }, () => ({
          path: 'runtime-manifest',
          namespace: 'radar-governance-control',
        }));
        build.onResolve({ filter: /\/trust-anchor\.mjs$/ }, () => ({
          path: 'trust-anchor',
          namespace: 'radar-governance-control',
        }));
        // The child launcher uses only the narrow Node-builtins descriptor
        // proof leaf. Parent-side opaque capability inspection must not pull
        // analyzer-control inventory (or its self-referential anchor) into
        // the independently hashed launcher artifact.
        build.onResolve({ filter: /\/runtime-sealed-generation\.mjs$/ }, () => ({
          path: 'runtime-sealed-generation',
          namespace: 'radar-governance-control',
        }));
        build.onResolve({ filter: /\/runtime-control-root\.mjs$/ }, () => ({
          path: 'runtime-control-root',
          namespace: 'radar-governance-control',
        }));
        build.onLoad(
          { filter: /^runtime-manifest$/, namespace: 'radar-governance-control' },
          () => ({ contents: virtualRuntimeManifest, loader: 'js' }),
        );
        build.onLoad(
          { filter: /^trust-anchor$/, namespace: 'radar-governance-control' },
          () => ({ contents: virtualTrustAnchor, loader: 'js' }),
        );
        build.onLoad(
          { filter: /^runtime-sealed-generation$/, namespace: 'radar-governance-control' },
          () => ({
            contents: "export const inspectMaterializedAnalyzerRuntime = () => { throw new Error('Parent-only materialized runtime inspection is unavailable in the child launcher.'); };",
            loader: 'js',
          }),
        );
        build.onLoad(
          { filter: /^runtime-control-root$/, namespace: 'radar-governance-control' },
          () => ({
            contents: "export const inspectAnalyzerControl = () => { throw new Error('Parent-only analyzer-control inspection is unavailable in the child launcher.'); };",
            loader: 'js',
          }),
        );
      },
    }],
    sourcemap: false,
    target: 'node24',
    treeShaking: true,
  });
  const output = Object.values(result.metafile.outputs)[0];
  if (
    output === undefined ||
    output.imports.some(import_ => !import_.external || !import_.path.startsWith('node:'))
  ) {
    throw new Error('The standalone launcher may import only Node builtins.');
  }
  const generatedBytes = readFileSync(generatedPath);
  const generatedSource = generatedBytes.toString('utf8');
  const analyzerIds = [
    'strictest-comparator',
    'Oxlint + Ultracite',
    'JSCPD',
    'Calldiff',
    'zizmor',
    'OSV-Scanner',
    'TraceDecay',
  ];
  if (
    /(?:from\s*|import\s*\(?)['"]\.{1,2}\//u.test(generatedSource) ||
    generatedSource.includes('packages/analyzer-runtime/resource-governance.mjs') ||
    generatedSource.includes('codebase-radar.analyzer-control/v1') ||
    [
      'runtime-snapshot-loader.mjs',
      'resource-governance-launcher.mjs',
      'runtime-memfd-addon.node',
    ].some(file => generatedSource.includes(file)) ||
    analyzerIds.some(analyzerId => !generatedSource.includes(analyzerId)) ||
    ['dependency-cruiser', 'ESLint', 'Madge', 'TypeScript'].some(
      analyzerId => generatedSource.includes(analyzerId),
    )
  ) {
    throw new Error('The standalone launcher violates its closed dependency or analyzer protocol contract.');
  }
  const smoke = spawnSync(process.execPath, [generatedPath, '--standalone-smoke'], {
    cwd: '/',
    encoding: 'utf8',
    env: {
      HOME: '/nonexistent',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      NO_COLOR: '1',
      PATH: '/usr/bin:/bin',
    },
    killSignal: 'SIGKILL',
    maxBuffer: 4_096,
    timeout: 5_000,
    windowsHide: true,
  });
  if (
    smoke.error !== undefined ||
    smoke.status !== 125 ||
    smoke.signal !== null ||
    smoke.stdout !== '' ||
    smoke.stderr !== '[resource-governance:launcher-usage] launcher failed.\n'
  ) {
    throw new Error('The standalone launcher failed its clean-root import smoke.');
  }
  const digest = createHash('sha256').update(generatedBytes).digest('hex');
  if (mode === '--write') {
    mkdirSync(dirname(checkedInPath), { recursive: true });
    copyFileSync(generatedPath, checkedInPath);
    process.stdout.write(`${generatedBytes.byteLength} ${digest}\n`);
  } else {
    independentRegularFile(checkedInPath);
    if (!generatedBytes.equals(readFileSync(checkedInPath))) {
      throw new Error('The checked-in governance launcher is not reproducible from its source inputs.');
    }
  }
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
