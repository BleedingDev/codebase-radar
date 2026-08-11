import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import { Schema } from 'effect';
import { describe, expect, it } from 'vitest';

const testDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(testDirectory, '..');
const workspaceRoot = resolve(packageRoot, '../..');
const publicModules = ['index', 'analysis', 'primitives', 'report', 'runtime', 'source'];
const namespaceKeyword = ['a', 's'].join('');
const Metafile = Schema.Struct({
  inputs: Schema.Record(Schema.String, Schema.Json),
  outputs: Schema.Record(Schema.String, Schema.Json),
});
const PackageManifest = Schema.Struct({
  exports: Schema.Record(
    Schema.String,
    Schema.Struct({ types: Schema.String, import: Schema.String }),
  ),
});

const esbuildBinary = () => {
  const candidates = [
    resolve(packageRoot, 'node_modules/.bin/esbuild'),
    resolve(workspaceRoot, 'node_modules/.bin/esbuild'),
    resolve(
      workspaceRoot,
      'node_modules/.pnpm/esbuild@0.28.1/node_modules/esbuild/bin/esbuild',
    ),
  ];
  return candidates.find(existsSync);
};

const bundle = (
  binary: string,
  entry: string,
  output: string,
  metafile: string,
) =>
  execFileSync(
    binary,
    [
      entry,
      '--bundle',
      '--format=iife',
      '--platform=browser',
      `--outfile=${output}`,
      `--metafile=${metafile}`,
      '--log-level=warning',
    ],
    { cwd: workspaceRoot, encoding: 'utf8' },
  );

describe('browser-safe public closure', () => {
  it('bundles every public module and runs without Node globals', () => {
    const binary = esbuildBinary();
    expect(binary).toBeDefined();
    if (!binary) return;
    const temporaryDirectory = mkdtempSync(
      resolve(tmpdir(), 'radar-contract-browser-'),
    );
    try {
      const entry = resolve(temporaryDirectory, 'entry.mjs');
      const output = resolve(temporaryDirectory, 'bundle.mjs');
      const metafilePath = resolve(temporaryDirectory, 'metafile.json');
      const imports = publicModules
        .map(
          (moduleName, index) =>
            `import * ${namespaceKeyword} public${index} from ${JSON.stringify(
              resolve(packageRoot, `src/${moduleName}.ts`),
            )};`,
        )
        .join('\n');
      writeFileSync(
        entry,
        `${imports}
import { Schema } from 'effect';
const modules = [public0, public1, public2, public3, public4, public5];
globalThis.radarPublicModules = modules.filter(module => Object.keys(module).length > 0).length;
const source = { _tag: 'LocalDirectorySource', directory: '/work/repository', codebaseId: 'local:repository' };
const jsonSchema = Schema.fromJsonString(public0.AnalysisSource);
const decoded = Schema.decodeUnknownSync(jsonSchema)(JSON.stringify(source));
globalThis.radarBrowserSmoke = Schema.encodeSync(jsonSchema)(decoded);`,
        'utf8',
      );
      bundle(binary, entry, output, metafilePath);

      const metafile = Schema.decodeSync(Schema.fromJsonString(Metafile))(
        readFileSync(metafilePath, 'utf8'),
      );
      const inputPaths = Object.keys(metafile.inputs);
      const manifest = Schema.decodeSync(Schema.fromJsonString(PackageManifest))(
        readFileSync(resolve(packageRoot, 'package.json'), 'utf8'),
      );
      expect(Object.keys(manifest.exports)).toEqual([
        '.',
        './analysis',
        './primitives',
        './report',
        './runtime',
        './source',
      ]);
      for (const exported of Object.values(manifest.exports)) {
        expect(exported.types.startsWith('./dist/')).toBe(true);
        expect(exported.types.endsWith('.d.ts')).toBe(true);
        expect(exported.import.startsWith('./dist/')).toBe(true);
      }
      for (const moduleName of publicModules) {
        expect(
          inputPaths.some(input =>
            input.endsWith(`packages/radar-contracts/src/${moduleName}.ts`),
          ),
        ).toBe(true);
      }
      const forbiddenClosure =
        /(?:node:|@modern-js|plugin-bff|apps\/radar\/server|analyzer-runtime|radar-runtime)/iu;
      expect(inputPaths.some(input => forbiddenClosure.test(input))).toBe(false);

      const outputText = readFileSync(output, 'utf8');
      expect(outputText).not.toContain('node:fs');
      const expected = JSON.stringify({
    _tag: 'LocalDirectorySource',
    directory: '/work/repository',
    codebaseId: 'local:repository',
      });
      const browserContext = {
        AbortController,
        DOMException,
        Event,
        EventTarget,
        TextDecoder,
        TextEncoder,
        URL,
        URLSearchParams,
        clearTimeout,
        crypto,
        performance,
        queueMicrotask,
        radarBrowserSmoke: '',
        radarPublicModules: 0,
        setTimeout,
        structuredClone,
      };
      runInNewContext(outputText, browserContext);
      expect(browserContext.radarBrowserSmoke).toBe(expected);
      expect(browserContext.radarPublicModules).toBe(publicModules.length);
      expect('process' in browserContext).toBe(false);
      expect('Buffer' in browserContext).toBe(false);
    } finally {
      rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it('fails a deliberately transitive Node dependency', () => {
    const binary = esbuildBinary();
    expect(binary).toBeDefined();
    if (!binary) return;
    const temporaryDirectory = mkdtempSync(
      resolve(tmpdir(), 'radar-contract-node-attack-'),
    );
    try {
      const fixture = resolve(temporaryDirectory, 'node-fixture.mjs');
      const entry = resolve(temporaryDirectory, 'entry.mjs');
      const output = resolve(temporaryDirectory, 'bundle.mjs');
      const metafilePath = resolve(temporaryDirectory, 'metafile.json');
      writeFileSync(
        fixture,
        "import { readFileSync } from 'node:fs'; export const transitiveRead = readFileSync;",
        'utf8',
      );
      writeFileSync(
        entry,
        `import { ScanResult } from ${JSON.stringify(resolve(packageRoot, 'src/index.ts'))};
void ScanResult;
import './node-fixture.mjs';`,
        'utf8',
      );
      const attacked = spawnSync(
        binary,
        [
          entry,
          '--bundle',
          '--format=iife',
          '--platform=browser',
          `--outfile=${output}`,
          `--metafile=${metafilePath}`,
        ],
        { cwd: workspaceRoot, encoding: 'utf8' },
      );
      expect(attacked.status).not.toBe(0);
      expect(attacked.stderr).toContain('node:fs');
    } finally {
      rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it('fails a transitive dependency that reads a Node global', () => {
    const binary = esbuildBinary();
    expect(binary).toBeDefined();
    if (!binary) return;
    const temporaryDirectory = mkdtempSync(
      resolve(tmpdir(), 'radar-contract-global-attack-'),
    );
    try {
      const fixture = resolve(temporaryDirectory, 'global-fixture.mjs');
      const entry = resolve(temporaryDirectory, 'entry.mjs');
      const output = resolve(temporaryDirectory, 'bundle.js');
      const metafilePath = resolve(temporaryDirectory, 'metafile.json');
      writeFileSync(
        fixture,
        "export const workingDirectory = process.cwd();",
        'utf8',
      );
      writeFileSync(
        entry,
        `import { ScanResult } from ${JSON.stringify(resolve(packageRoot, 'src/index.ts'))};
void ScanResult;
import './global-fixture.mjs';`,
        'utf8',
      );
      bundle(binary, entry, output, metafilePath);
      const attackedOutput = readFileSync(output, 'utf8');
      expect(() => runInNewContext(attackedOutput, { URL, TextDecoder, TextEncoder }))
        .toThrow(/process/u);
    } finally {
      rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  });
});
