import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Schema } from 'effect';
import { describe, expect, it } from 'vitest';

const packageDirectory = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryDirectory = resolve(packageDirectory, '../..');
const pnpmCli = process.env.npm_execpath;

// Mirrors the deployed `/usr/bin/env -i` boundary. This is an allowlist rather
// than a filtered copy of `process.env`, so Node preload/loader search state
// from the invoking shell cannot reach the installed CLI.
const cleanEnvironment: NodeJS.ProcessEnv = {
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin',
};

const PackageArtifact = Schema.Struct({
  exports: Schema.Struct({
    '.': Schema.Struct({
      import: Schema.String,
      types: Schema.String,
    }),
  }),
  files: Schema.Array(Schema.String),
});

const isContainedBy = (root: string, candidate: string) => {
  const relativePath = relative(realpathSync(root), realpathSync(candidate));
  return relativePath.length > 0 &&
    relativePath !== '..' &&
    !relativePath.startsWith(`..${sep}`) &&
    !isAbsolute(relativePath);
};

const run = (
  command: string,
  args: ReadonlyArray<string>,
  cwd: string,
  environment: NodeJS.ProcessEnv = process.env,
) => spawnSync(command, args, {
  cwd,
  encoding: 'utf8',
  env: environment,
  timeout: 60_000,
});

describe('published CLI package', () => {
  it('imports and verifies from an arbitrary CWD using only installed package dependencies', () => {
    expect(pnpmCli).toBeDefined();
    if (pnpmCli === undefined) return;

    const temporary = mkdtempSync(join(tmpdir(), 'radar-cli-package-smoke-'));
    try {
      const deployed = join(temporary, '.zerops', 'radar-cli');
      const deployedPackage = run(
        process.execPath,
        [
          pnpmCli,
          '--filter',
          '@codebase-radar/cli',
          'deploy',
          '--prod',
          deployed,
        ],
        repositoryDirectory,
      );
      expect(deployedPackage.status).toBe(0);

      const packageJson = Schema.decodeUnknownSync(
        Schema.fromJsonString(PackageArtifact),
      )(readFileSync(join(deployed, 'package.json'), 'utf8'));
      expect(packageJson.files).toEqual(expect.arrayContaining(['bin', 'dist']));
      expect(packageJson.exports['.'].import).toBe('./dist/index.js');
      expect(packageJson.exports['.'].types).toBe('./dist/index.d.ts');
      const deployedBin = join(deployed, 'bin/radar.mjs');
      const deployedMain = join(deployed, 'dist/main.js');
      expect(existsSync(deployedBin)).toBe(true);
      expect(existsSync(deployedMain)).toBe(true);
      expect(Object.keys(cleanEnvironment).sort()).toEqual([
        'HOME',
        'LANG',
        'LC_ALL',
        'NO_COLOR',
        'PATH',
      ]);
      expect(cleanEnvironment.NODE_OPTIONS).toBeUndefined();
      expect(cleanEnvironment.NODE_PATH).toBeUndefined();

      const resolveInstalledImport = (specifier: string) => {
        const resolution = run(
          process.execPath,
          [
            '--input-type=module',
            '--eval',
            `process.stdout.write(import.meta.resolve(${JSON.stringify(specifier)}))`,
          ],
          deployed,
          cleanEnvironment,
        );
        expect(resolution.status).toBe(0);
        expect(resolution.stderr).toBe('');
        return fileURLToPath(resolution.stdout);
      };

      const deployedCore = resolveInstalledImport('@codebase-radar/core');
      const deployedContracts = resolveInstalledImport('@codebase-radar/contracts');
      const deployedEffect = resolveInstalledImport('effect');
      const deployedPlatformNode = resolveInstalledImport('@effect/platform-node');
      const deployedCorePackage = resolve(dirname(deployedCore), '../package.json');
      const deployedCoreRequire = createRequire(deployedCorePackage);
      const deployedVerifier = deployedCoreRequire.resolve(
        '@codebase-radar/analyzer-runtime/runtime-verifier',
      );
      const deployedTrustAnchor = deployedCoreRequire.resolve(
        '@codebase-radar/analyzer-runtime/trust-anchor',
      );
      const deployedClosure: ReadonlyArray<readonly [string, string]> = [
        ['CLI bin', deployedBin],
        ['CLI main', deployedMain],
        ['core', deployedCore],
        ['contracts', deployedContracts],
        ['Effect', deployedEffect],
        ['Effect Node platform', deployedPlatformNode],
        ['runtime verifier', deployedVerifier],
        ['runtime trust anchor', deployedTrustAnchor],
      ];
      for (const [name, resolvedPath] of deployedClosure) {
        expect(existsSync(resolvedPath), `${name} must exist in the deployed closure`).toBe(true);
        expect(isContainedBy(deployed, resolvedPath), `${name} must resolve below the deployed CLI root`).toBe(true);
      }

      const consumer = join(temporary, 'consumer');
      const packageLink = join(consumer, 'node_modules/@codebase-radar/cli');
      mkdirSync(join(consumer, 'node_modules/@codebase-radar'), { recursive: true });
      symlinkSync(deployed, packageLink, 'dir');

      // A caller-controlled CWD may contain lookalike packages. The bin's
      // real module location must still resolve its closure from `deployed`.
      const hostileCore = join(consumer, 'node_modules/@codebase-radar/core');
      mkdirSync(hostileCore);
      writeFileSync(
        join(hostileCore, 'package.json'),
        JSON.stringify({
          name: '@codebase-radar/core',
          type: 'module',
          exports: './index.mjs',
        }),
      );
      writeFileSync(
        join(hostileCore, 'index.mjs'),
        "process.stderr.write('HOSTILE_CWD_CORE_LOADED');\n",
      );

      const imported = run(
        process.execPath,
        [
          '--input-type=module',
          '--eval',
          "import('@codebase-radar/cli').then(value => process.stdout.write(typeof value.runRadarCli))",
        ],
        consumer,
      );
      expect(imported.status).toBe(0);
      expect(imported.stdout).toBe('function');
      expect(imported.stderr).toBe('');

      const expectedGitHubHelp = [
        'DESCRIPTION',
        '  Analyze one GitHub source with the fixed dogfood:max policy.',
        '',
        'USAGE',
        '  radar scan github [flags] <owner/repository> [<revision>]',
        '',
        'ARGUMENTS',
        '  owner/repository string  Canonical GitHub owner/repository locator.',
        '  revision string          Optional branch:<name>, tag:<name>, or commit:<sha> revision. (optional)',
        '',
        'FLAGS',
        '  --format choice      Render the accepted result as human text or strict JSON. (choices: human, json)',
        '  --baseline string    Read a prior strict successful Scan Result for comparison.',
        '  --output string      Write the complete rendered result atomically to this file.',
        '  --quiet              Suppress progress messages on stderr.',
        '  --fail-on choice     After rendering, fail when findings meet this presentation gate. (choices: never, fix-now, investigate, monitor, any)',
        '',
        'GLOBAL FLAGS',
        '  --help, -h       Show help information',
        '  --version, -v    Show version information',
        '',
      ].join('\n');
      const help = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'scan', 'github', '--help'],
        consumer,
        cleanEnvironment,
      );
      expect(help.status).toBe(0);
      expect(help.stdout).toBe(expectedGitHubHelp);
      expect(help.stderr).toBe('');
      expect(help.stderr).not.toContain('HOSTILE_CWD_CORE_LOADED');
      expect(help.stdout.replace(/\n/gu, '')).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/u);

      const hostileSyntaxes: ReadonlyArray<ReadonlyArray<string>> = [
        ['--bad\u0007token=review-secret'],
        ['--bad\u009btoken=review-secret'],
        ['--bad\u001b[2Jtoken=review-secret'],
        [`--${'x'.repeat(4096)}token=review-secret`],
        ['token=review-secret'],
        ['--help', '--help'],
        ['doctor', '--format', 'json', '--format', 'json'],
      ];
      for (const arguments_ of hostileSyntaxes) {
        const syntax = run(
          process.execPath,
          [join(packageLink, 'bin/radar.mjs'), ...arguments_],
          consumer,
          cleanEnvironment,
        );
        expect(syntax.status).toBe(64);
        expect(syntax.stdout).toBe('');
        expect(syntax.stderr).toBe('radar: Invalid command syntax.\n');
      }

      const expectUnavailableDoctor = (doctor: ReturnType<typeof run>) => {
        expect(doctor.status).toBe(69);
        expect(doctor.stderr).toBe('radar: Runtime preflight is not ready.\n');
        expect(JSON.parse(doctor.stdout)).toMatchObject({
          schemaVersion: 'codebase-radar.runtime-report/v1',
          status: 'unavailable',
        });
      };

      const unavailableDoctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        cleanEnvironment,
      );
      expectUnavailableDoctor(unavailableDoctor);

      const targetRuntime = join(temporary, 'untrusted-target');
      const workspaceParent = join(temporary, 'workspaces');
      const resourceCgroupRoot = join(temporary, 'resource-cgroup');
      const analyzerControlRoot = join(temporary, 'analyzer-control');
      mkdirSync(targetRuntime, { recursive: true });
      mkdirSync(workspaceParent, { mode: 0o700 });
      mkdirSync(resourceCgroupRoot, { mode: 0o700 });
      mkdirSync(analyzerControlRoot, { mode: 0o700 });
      writeFileSync(
        join(targetRuntime, 'runtime-verifier.mjs'),
        "process.stderr.write('TARGET_VERIFIER_LOADED'); process.exit(97);\n",
      );
      writeFileSync(
        join(targetRuntime, 'trust-anchor.mjs'),
        "process.stderr.write('TARGET_ANCHOR_LOADED'); process.exit(98);\n",
      );
      const targetRoots = {
        ...cleanEnvironment,
        RADAR_ANALYZER_ROOT: targetRuntime,
        RADAR_WORKSPACE_PARENT: workspaceParent,
      };

      const missingResourceCgroupDoctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        {
          ...targetRoots,
          RADAR_ANALYZER_CONTROL_ROOT: analyzerControlRoot,
        },
      );
      expectUnavailableDoctor(missingResourceCgroupDoctor);

      const missingAnalyzerControlDoctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        {
          ...targetRoots,
          RADAR_ANALYSIS_CGROUP_ROOT: resourceCgroupRoot,
        },
      );
      expectUnavailableDoctor(missingAnalyzerControlDoctor);

      const malformedResourceCgroupDoctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        {
          ...targetRoots,
          RADAR_ANALYSIS_CGROUP_ROOT: 'relative-cgroup-root',
          RADAR_ANALYZER_CONTROL_ROOT: analyzerControlRoot,
        },
      );
      expectUnavailableDoctor(malformedResourceCgroupDoctor);

      const malformedAnalyzerControlDoctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        {
          ...targetRoots,
          RADAR_ANALYSIS_CGROUP_ROOT: resourceCgroupRoot,
          RADAR_ANALYZER_CONTROL_ROOT: 'relative-analyzer-control-root',
        },
      );
      expectUnavailableDoctor(malformedAnalyzerControlDoctor);

      const environment = {
        ...targetRoots,
        RADAR_ANALYSIS_CGROUP_ROOT: resourceCgroupRoot,
        RADAR_ANALYZER_CONTROL_ROOT: analyzerControlRoot,
      };
      const doctor = run(
        process.execPath,
        [join(packageLink, 'bin/radar.mjs'), 'doctor', '--format', 'json'],
        consumer,
        environment,
      );

      expectUnavailableDoctor(doctor);
      expect(doctor.stderr).not.toContain('TARGET_VERIFIER_LOADED');
      expect(doctor.stderr).not.toContain('TARGET_ANCHOR_LOADED');
    } finally {
      rmSync(temporary, { force: true, recursive: true });
    }
  }, 70_000);
});
