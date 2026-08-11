import { NodeServices } from '@effect/platform-node';
import {
  CanonicalRepositoryPathSet,
  encodeCanonicalRepositoryPathSet,
} from '@codebase-radar/contracts';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Effect, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import { RepositoryInventory } from './inventory';
import { runCalldiff } from './calldiff';

const canonicalPathSetDigest = (paths: ReadonlyArray<string>) =>
  `sha256:${createHash('sha256')
    .update(
      encodeCanonicalRepositoryPathSet(
        Schema.decodeUnknownSync(CanonicalRepositoryPathSet)(paths),
      ),
    )
    .digest('hex')}`;

const analyzerRoot = resolve(
  import.meta.dirname,
  '../../../packages/analyzer-runtime',
);

describe('Calldiff analyzer', () => {
  it('turns every repeated local call-tree node into a finding candidate', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-'));
    const source = [
      'export function coordinate(value: string) {',
      '  normalize(value);',
      '  normalize(value);',
      '}',
      'function normalize(value: string) {',
      '  return value.trim();',
      '}',
    ].join('\n');
    writeFileSync(resolve(repository, 'example.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['example.ts'],
      sourceFiles: ['example.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('complete');
        expect(output.run.profileVersion).toBe('dogfood:max/v1');
        expect(output.run.observationCount).toBe(1);
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 1,
          eligiblePathSetDigest: canonicalPathSetDigest(['example.ts']),
          analyzedPathSetDigest: canonicalPathSetDigest(['example.ts']),
        });
        expect(output.candidates).toEqual([
          expect.objectContaining({
            title: 'example.ts::normalize repeats in 1 call tree',
            tags: expect.arrayContaining([
              'calldiff',
              'call-tree-duplication',
              'local-callable',
            ]),
          }),
        ]);
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('keeps the canonical eligible proof when the runtime is unavailable', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-missing-'));
    const runtime = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-empty-runtime-'));
    const source = 'export function available() {}\n';
    writeFileSync(resolve(repository, 'available.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['available.ts'],
      sourceFiles: ['available.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, runtime).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 0,
          eligiblePathSetDigest: canonicalPathSetDigest(['available.ts']),
          analyzedPathSetDigest: canonicalPathSetDigest([]),
        });
      })
      .finally(() => {
        rmSync(repository, { recursive: true, force: true });
        rmSync(runtime, { recursive: true, force: true });
      });
  });

  it('marks ambiguous cross-file call bindings as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-ambiguous-'));
    const sources = new Map([
      ['exported.ts', 'export function shared() { return 1; }\n'],
      ['private.ts', 'function shared() { return 2; }\n'],
      ['caller.ts', 'export function caller() { return shared(); }\n'],
    ]);
    for (const [path, source] of sources) {
      writeFileSync(resolve(repository, path), source);
    }
    const inventory = new RepositoryInventory({
      files: [...sources.keys()].sort(),
      sourceFiles: [...sources.keys()].sort(),
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: [...sources.values()].reduce(
        (total, source) => total + Buffer.byteLength(source),
        0,
      ),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('call sites were not linked'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('marks a single unmodeled remote textual call as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-unmodeled-'));
    const sources = new Map([
      ['remote.ts', 'export function remote() { return 1; }\n'],
      ['caller.ts', 'export function caller() { return remote(); }\n'],
    ]);
    for (const [path, source] of sources) {
      writeFileSync(resolve(repository, path), source);
    }
    const inventory = new RepositoryInventory({
      files: [...sources.keys()].sort(),
      sourceFiles: [...sources.keys()].sort(),
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: [...sources.values()].reduce(
        (total, source) => total + Buffer.byteLength(source),
        0,
      ),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('no same-file binding could be proven'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('marks parser input budget exhaustion as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-input-'));
    const source = `export function oversized() {}\n${' '.repeat(2_097_152)}`;
    writeFileSync(resolve(repository, 'oversized.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['oversized.ts'],
      sourceFiles: ['oversized.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('skipped before parser allocation'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('marks syntax-recovery input as partial with the audited coverage denominator', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-syntax-'));
    const source = 'export function malformed( { return 1; }\n';
    writeFileSync(resolve(repository, 'malformed.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['malformed.ts'],
      sourceFiles: ['malformed.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 0,
          eligiblePathSetDigest: canonicalPathSetDigest(['malformed.ts']),
          analyzedPathSetDigest: canonicalPathSetDigest([]),
        });
        expect(output.run.coverage.eligiblePathSetDigest).not.toBe(
          output.run.coverage.analyzedPathSetDigest,
        );
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('could not read or parse 1 source files'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('marks call trees cut at the depth boundary as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-depth-'));
    const chain = Array.from({ length: 36 }, (_, index) =>
      index === 35
        ? `function f${index}() {}`
        : `function f${index}() { f${index + 1}(); }`,
    );
    const source = [
      ...chain,
      'export function root() { f0(); }',
      '',
    ].join('\n');
    writeFileSync(resolve(repository, 'depth.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['depth.ts'],
      sourceFiles: ['depth.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('call-tree branches were cut at depth'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('analyzes declaration files included by the canonical source inventory', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-dts-'));
    const source = 'export declare function declared(value: string): void;\n';
    writeFileSync(resolve(repository, 'types.d.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['types.d.ts'],
      sourceFiles: ['types.d.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('complete');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 1,
        });
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('uses the canonical denominator when an audited source path is inaccessible', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-directory-'));
    const blocked = resolve(repository, 'blocked');
    const readable = 'export function readable() {}\n';
    writeFileSync(resolve(repository, 'readable.ts'), readable);
    mkdirSync(blocked);
    writeFileSync(resolve(blocked, 'hidden.ts'), 'export function hidden() {}\n');
    chmodSync(blocked, 0o000);
    const inventory = new RepositoryInventory({
      files: ['blocked/hidden.ts', 'readable.ts'],
      sourceFiles: ['blocked/hidden.ts', 'readable.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(readable),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 2,
          analyzedFiles: 1,
        });
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('could not read or parse 1 source files'),
          ]),
        );
      })
      .finally(() => {
        chmodSync(blocked, 0o700);
        rmSync(repository, { recursive: true, force: true });
      });
  });

  it('uses an audited deep source path without independently truncating the canonical inventory', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-tree-'));
    let directory = repository;
    for (let index = 0; index < 140; index += 1) {
      directory = resolve(directory, 'd');
      mkdirSync(directory);
    }
    writeFileSync(resolve(directory, 'deep.ts'), 'export function deep() {}\n');
    const path = `${directory.slice(repository.length + 1)}/deep.ts`;
    const inventory = new RepositoryInventory({
      files: [path],
      sourceFiles: [path],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: 32,
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('complete');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 1,
        });
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });

  it('rejects a same-count analyzed path set that differs from the audited inventory', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-path-set-'));
    const runtime = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-fake-runtime-'));
    const source = 'export function audited() {}\n';
    writeFileSync(resolve(repository, 'audited.ts'), source);
    writeFileSync(resolve(repository, 'wrong.ts'), 'export function wrong() {}\n');
    mkdirSync(resolve(runtime, 'node_modules/calldiff/dist'), { recursive: true });
    writeFileSync(resolve(runtime, 'node_modules/calldiff/dist/index.js'), '');
    writeFileSync(
      resolve(runtime, 'calldiff-analyzer.mjs'),
      [
        "import { spawnSync } from 'node:child_process';",
        "import { createHash } from 'node:crypto';",
        "import { readFileSync } from 'node:fs';",
        `const adapter = ${JSON.stringify(resolve(analyzerRoot, 'calldiff-analyzer.mjs'))};`,
        "const input = readFileSync(0, 'utf8');",
        "const result = spawnSync(process.execPath, [adapter, process.argv[2], '--audited-source-files-stdin'], { encoding: 'utf8', env: process.env, input });",
        "if (result.status !== 0) { process.stderr.write(result.stderr); process.exitCode = 1; } else {",
        '  const report = JSON.parse(result.stdout);',
        "  report.analyzedPaths = ['wrong.ts'];",
        "  report.analyzedPathSetDigest = `sha256:${createHash('sha256').update(JSON.stringify(report.analyzedPaths)).digest('hex')}`;",
        '  process.stdout.write(`${JSON.stringify(report)}\\n`);',
        '}',
        '',
      ].join('\n'),
    );
    const inventory = new RepositoryInventory({
      files: ['audited.ts'],
      sourceFiles: ['audited.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, runtime).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 1,
          eligiblePathSetDigest: canonicalPathSetDigest(['audited.ts']),
          analyzedPathSetDigest: canonicalPathSetDigest(['wrong.ts']),
        });
        expect(output.run.coverage.eligiblePathSetDigest).not.toBe(
          output.run.coverage.analyzedPathSetDigest,
        );
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('source-path set different'),
          ]),
        );
      })
      .finally(() => {
        rmSync(repository, { recursive: true, force: true });
        rmSync(runtime, { recursive: true, force: true });
      });
  });

  it('marks rewrite-step budget exhaustion as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-rewrite-'));
    const source = [
      'function f() {}',
      `export function root() {${'f();'.repeat(100_001)}}`,
      '',
    ].join('\n');
    writeFileSync(resolve(repository, 'flat.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['flat.ts'],
      sourceFiles: ['flat.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('definitions were discarded'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  }, 15_000);

  it('marks bounded duplicate evidence as partial coverage', () => {
    const repository = mkdtempSync(resolve(tmpdir(), 'radar-calldiff-evidence-'));
    const groupCount = 12;
    // Forty long-label roots deterministically exhaust the shared 8 MiB
    // evidence envelope without making the consumer regression load-bound.
    const rootCount = 40;
    const label = 'x'.repeat(60);
    const groups = Array.from({ length: groupCount }, (_, group) => [
      `function group${group}Leaf${label}() {}`,
      ...Array.from({ length: 10 }, (_, index) => {
        const name = `group${group}Step${index}${label}`;
        const next = index === 9
          ? `group${group}Leaf${label}`
          : `group${group}Step${index + 1}${label}`;
        return `function ${name}() { ${next}(); }`;
      }),
    ]).flat();
    const roots = Array.from({ length: rootCount }, (_, index) => {
      const calls = Array.from(
        { length: groupCount },
        (_, group) => `group${group}Step0${label}(); group${group}Step0${label}();`,
      );
      return `export function root${index}() { ${calls.join(' ')} }`;
    });
    const source = [...groups, ...roots, ''].join('\n');
    writeFileSync(resolve(repository, 'evidence.ts'), source);
    const inventory = new RepositoryInventory({
      files: ['evidence.ts'],
      sourceFiles: ['evidence.ts'],
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: Buffer.byteLength(source),
      truncated: false,
    });

    return Effect.runPromise(
      runCalldiff(repository, inventory, analyzerRoot).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('partial');
        expect(output.run.coverage.warnings).toEqual(
          expect.arrayContaining([
            expect.stringContaining('duplicate and collision evidence exceeded'),
          ]),
        );
      })
      .finally(() => rmSync(repository, { recursive: true, force: true }));
  });
});
