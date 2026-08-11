import { NodeServices } from '@effect/platform-node';
import {
  AnalyzerRun,
  EmptyRepositoryPathSetDigest,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
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
import {
  completeAnalyzerOutput,
  incompleteAnalyzerOutput,
  runOsv,
  runOxlint,
  runStrictestComparator,
} from './analyzers';
import { RepositoryInventory } from './inventory';
import { traceDecayCountTruncationWarning } from './tracedecay';

const inventory = (sourceFiles: ReadonlyArray<string>) =>
  new RepositoryInventory({
    files: [...sourceFiles],
    sourceFiles: [...sourceFiles],
    lockfiles: [],
    tsconfigs: [],
    workflowFiles: [],
    manifests: [],
    frameworks: [],
    sourceBytes: sourceFiles.length * 32,
    truncated: false,
  });

const auditedPathSetDigest =
  'sha256:4f35a3347982cf7e2b9be7080461e55c9472d4dee20d960361d5566b1e8cce0a';
const siblingPathSetDigest =
  'sha256:ddcc11c4c4afcc56a839a2b3dda15e17c9b768bc57fc976aab9f53764552c4af';
const exactPathSetProof = {
  eligiblePathSetDigest: auditedPathSetDigest,
  analyzedPathSetDigest: auditedPathSetDigest,
};

const fakeOxlintRuntime = (root: string, exitCode: number, report: string) => {
  const command = resolve(root, 'node_modules/oxlint/bin/oxlint');
  mkdirSync(resolve(command, '..'), { recursive: true });
  writeFileSync(
    command,
    `process.stdout.write(${JSON.stringify(report)}); process.exitCode = ${String(exitCode)};\n`,
  );
};

const fakeOfflineOsvRuntime = (root: string, expectedLockfile: string) => {
  const command = resolve(root, 'bin/osv-scanner');
  mkdirSync(resolve(command, '..'), { recursive: true });
  writeFileSync(
    command,
    `#!${process.execPath}
const args = process.argv.slice(2);
const lockfileIndex = args.indexOf('-L');
const valid = args.includes('--offline') &&
  args.includes('--local-db-path=/runtime/databases/osv') &&
  args.includes('--no-resolve') &&
  args[lockfileIndex + 1] === ${JSON.stringify(expectedLockfile)} &&
  process.env.OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY === '/runtime/databases/osv';
if (valid) {
  process.stdout.write(JSON.stringify({ results: [] }));
} else {
  process.stderr.write('OSV offline invocation contract was not met.');
  process.exitCode = 2;
}
`,
  );
  chmodSync(command, 0o700);
};

describe('semantic analyzer adapters', () => {
  it('uses the one canonical policy version for exactly the required analyzers', () => {
    expect(RequiredAnalyzerIds).toEqual([
      'strictest-comparator',
      'Oxlint + Ultracite',
      'JSCPD',
      'Calldiff',
      'zizmor',
      'OSV-Scanner',
      'TraceDecay',
    ]);
    for (const analyzer of RequiredAnalyzerIds) {
      const output = completeAnalyzerOutput({
        analyzer,
        analyzerVersion: 'test',
        durationMs: 1,
        eligibleFiles: 1,
        analyzedFiles: 1,
        observationCount: 0,
        candidates: [],
        pathSetProof: exactPathSetProof,
      });
      expect(output.run).toMatchObject({
        analyzer,
        profileVersion: 'dogfood:max/v1',
        status: 'complete',
      });
    }
  });

  it('never publishes a complete Oxlint result after a nonzero process exit', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-oxlint-'));
    const repository = resolve(root, 'repository');
    mkdirSync(repository, { recursive: true });
    writeFileSync(resolve(repository, 'example.ts'), 'export const value = 1;\n');
    fakeOxlintRuntime(
      root,
      1,
      JSON.stringify({ diagnostics: [], number_of_files: 1 }),
    );

    return Effect.runPromise(
      runOxlint(repository, inventory(['example.ts']), root).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run).toMatchObject({
          status: 'failed',
          profileVersion: 'dogfood:max/v1',
          coverage: { eligibleFiles: 1, analyzedFiles: 0 },
        });
        expect(output.candidates).toEqual([]);
        expect(output.run.coverage).toMatchObject({
          eligibleFiles: 1,
          analyzedFiles: 0,
          analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        });
        expect(output.run.coverage.eligiblePathSetDigest).not.toBe(
          EmptyRepositoryPathSetDigest,
        );
        expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
          'failed',
        );
      })
      .finally(() => rmSync(root, { recursive: true, force: true }));
  });

  it('fails closed when Oxlint omits its audited file count', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-oxlint-'));
    const repository = resolve(root, 'repository');
    mkdirSync(repository, { recursive: true });
    writeFileSync(resolve(repository, 'example.ts'), 'export const value = 1;\n');
    fakeOxlintRuntime(root, 0, JSON.stringify({ diagnostics: [] }));

    return Effect.runPromise(
      runOxlint(repository, inventory(['example.ts']), root).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run).toMatchObject({
          status: 'partial',
          coverage: {
            eligibleFiles: 1,
            analyzedFiles: 0,
            analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
          },
        });
        expect(output.run.coverage.eligiblePathSetDigest).not.toBe(
          EmptyRepositoryPathSetDigest,
        );
        expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
          'partial',
        );
      })
      .finally(() => rmSync(root, { recursive: true, force: true }));
  });

  it('keeps only successfully read strictness files in partial path evidence', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-strictest-'));
    writeFileSync(
      resolve(root, 'a.json'),
      JSON.stringify({ compilerOptions: { strict: true } }),
    );
    writeFileSync(resolve(root, 'b.json'), '{ malformed');
    const strictestInventory = new RepositoryInventory({
      files: ['a.json', 'b.json'],
      sourceFiles: ['a.json', 'b.json'],
      lockfiles: [],
      tsconfigs: ['a.json', 'b.json'],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: 64,
      truncated: false,
    });

    return Effect.runPromise(
      runStrictestComparator(root, strictestInventory).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run).toMatchObject({
          status: 'partial',
          coverage: {
            eligibleFiles: 2,
            analyzedFiles: 1,
          },
        });
        expect(output.run.coverage.eligiblePathSetDigest).not.toBe(
          output.run.coverage.analyzedPathSetDigest,
        );
        expect(output.run.coverage.analyzedPathSetDigest).not.toBe(
          EmptyRepositoryPathSetDigest,
        );
        expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
          'partial',
        );
      })
      .finally(() => rmSync(root, { recursive: true, force: true }));
  });

  it('pins OSV to the mounted offline database and exact lockfile allowlist', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-osv-'));
    const repository = resolve(root, 'repository');
    const scanRoot = resolve(root, 'scan');
    const lockfile = resolve(repository, 'package-lock.json');
    mkdirSync(repository, { recursive: true });
    mkdirSync(scanRoot, { recursive: true });
    writeFileSync(lockfile, '{"lockfileVersion":3}\n');
    fakeOfflineOsvRuntime(root, lockfile);
    const osvInventory = new RepositoryInventory({
      files: ['package-lock.json'],
      sourceFiles: ['package-lock.json'],
      lockfiles: ['package-lock.json'],
      tsconfigs: [],
      workflowFiles: [],
      manifests: [],
      frameworks: [],
      sourceBytes: 20,
      truncated: false,
    });

    return Effect.runPromise(
      runOsv(scanRoot, repository, osvInventory, root).pipe(
        Effect.provide(NodeServices.layer),
      ),
    )
      .then(output => {
        expect(output.run.status).toBe('complete');
        expect(output.run.coverage.warnings).toContain(
          'Dependency coordinates are matched against the pinned offline OSV npm advisory snapshot; no advisory API request is made.',
        );
        expect(output.run.coverage.warnings).not.toContain(
          'Dependency coordinates are queried against the public OSV advisory API.',
        );
        expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
          'complete',
        );
      })
      .finally(() => rmSync(root, { recursive: true, force: true }));
  });

  it.each(RequiredAnalyzerIds)(
    'rejects %s when an equal count represents a different analyzed path set',
    analyzer => {
      const output = completeAnalyzerOutput({
        analyzer,
        analyzerVersion: 'test',
        durationMs: 1,
        eligibleFiles: 1,
        analyzedFiles: 1,
        observationCount: 0,
        candidates: [],
        pathSetProof: {
          eligiblePathSetDigest: auditedPathSetDigest,
          analyzedPathSetDigest: siblingPathSetDigest,
        },
      });
      expect(output.run).toMatchObject({
        status: 'partial',
        diagnostic: expect.stringContaining('exact audited path set'),
        coverage: {
          eligibleFiles: 1,
          analyzedFiles: 1,
          eligiblePathSetDigest: auditedPathSetDigest,
          analyzedPathSetDigest: siblingPathSetDigest,
        },
      });
      expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
        'partial',
      );
    },
  );

  it('orders coverage warnings by canonical code units, not locale', () => {
    const output = incompleteAnalyzerOutput({
      analyzer: 'JSCPD',
      analyzerVersion: 'test',
      status: 'partial',
      durationMs: 1,
      eligibleFiles: 1,
      analyzedFiles: 0,
      observationCount: 0,
      diagnostic: 'partial',
      warnings: ['ä-warning', 'zeta'],
      pathSetProof: {
        eligiblePathSetDigest: auditedPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
      },
    });
    expect(output.run.coverage.warnings).toEqual(['zeta', 'ä-warning']);
    expect(output.run.coverage).toMatchObject({
      eligibleFiles: 1,
      analyzedFiles: 0,
      eligiblePathSetDigest: auditedPathSetDigest,
      analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
    });
    expect(Schema.decodeUnknownSync(AnalyzerRun)(output.run).status).toBe(
      'partial',
    );
  });

  it.each([
    ['reported-total mismatch', { returned: 4, reported: 5, limit: 10_000 }],
    ['unreported cap', { returned: 10_000, limit: 10_000 }],
  ])('marks TraceDecay %s as incomplete evidence', (_label, counts) => {
    expect(
      traceDecayCountTruncationWarning({ tool: 'tool', ...counts }),
    ).toContain('tool:');
  });

  it('accepts reconciled TraceDecay counts below the configured cap', () => {
    expect(
      traceDecayCountTruncationWarning({
        tool: 'tool',
        returned: 4,
        reported: 4,
        limit: 10_000,
      }),
    ).toBeUndefined();
  });
});
