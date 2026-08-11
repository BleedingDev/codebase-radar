import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Effect } from 'effect';
import { NodeServices } from '@effect/platform-node';
import { describe, expect, it } from 'vitest';
import { materializeAuditedAnalyzerInput } from './analyzer-input';

const input = (root: string, scratch: string, entries: ReadonlyArray<{
  readonly path: string;
  readonly byteLength: number;
}>) =>
  materializeAuditedAnalyzerInput({
    sourceRoot: root,
    scratchRoot: scratch,
    entries,
    maximumFiles: 8_000,
    maximumBytes: entries.reduce((total, entry) => total + entry.byteLength, 0),
  });

const cleanup = (root: string) =>
  rm(root, {
    recursive: true,
    force: true,
    maxRetries: 8,
    retryDelay: 25,
  });

describe('audited analyzer input', () => {
  it('stages only the audited path set, not an equal-count sibling set', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-analyzer-input-'));
    const scratch = join(root, 'scratch');
    const source = join(root, 'source');
    const audited = 'src/a.ts';
    const sibling = 'src/b.ts';
    let stagedRoot = '';
    mkdirSync(join(source, 'src'), { recursive: true });
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(source, audited), 'alpha\n');
    writeFileSync(join(source, sibling), 'bravo\n');

    return Effect.runPromise(
      Effect.scoped(
        input(source, scratch, [{ path: audited, byteLength: 6 }]).pipe(
          Effect.tap(view =>
            Effect.sync(() => {
              stagedRoot = view.root;
              expect(view.stagedPaths).toEqual([audited]);
              expect(view.stagedBytes).toBe(6);
              expect(readFileSync(join(view.root, audited), 'utf8')).toBe('alpha\n');
              expect(existsSync(join(view.root, sibling))).toBe(false);
              expect(statSync(view.root).mode & 0o222).toBe(0);
            }),
          ),
        ),
      ).pipe(Effect.provide(NodeServices.layer)),
    )
      .then(() => {
        expect(existsSync(stagedRoot)).toBe(false);
      })
      .finally(() => cleanup(root));
  });

  it('rejects an equal-count wrong-path substitution', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-analyzer-input-'));
    const scratch = join(root, 'scratch');
    const source = join(root, 'source');
    mkdirSync(join(source, 'src'), { recursive: true });
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(source, 'src/b.ts'), 'bravo\n');

    return expect(
      Effect.runPromise(
        Effect.scoped(
          input(source, scratch, [{ path: 'src/a.ts', byteLength: 6 }]),
        ).pipe(Effect.provide(NodeServices.layer)),
      ),
    )
      .rejects.toMatchObject({ _tag: 'AnalyzerInputFailure' })
      .finally(() => cleanup(root));
  });

  it('rejects symbolic links in the audited input view', () => {
    const root = mkdtempSync(resolve(tmpdir(), 'radar-analyzer-input-'));
    const scratch = join(root, 'scratch');
    const source = join(root, 'source');
    mkdirSync(join(source, 'src'), { recursive: true });
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(source, 'outside.ts'), 'alpha\n');
    symlinkSync('../outside.ts', join(source, 'src/a.ts'));

    return expect(
      Effect.runPromise(
        Effect.scoped(
          input(source, scratch, [{ path: 'src/a.ts', byteLength: 6 }]),
        ).pipe(Effect.provide(NodeServices.layer)),
      ),
    )
      .rejects.toMatchObject({ _tag: 'AnalyzerInputFailure' })
      .finally(() => cleanup(root));
  });
});
