import { NodeServices } from '@effect/platform-node';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Effect } from 'effect';
import { describe, expect, it } from 'vitest';
import { RepositoryInventory } from './inventory';
import { runCalldiff } from './calldiff';

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
        expect(output.run.observationCount).toBe(1);
        expect(output.candidates).toEqual([
          expect.objectContaining({
            title: 'normalize repeats in 1 call tree',
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
});
