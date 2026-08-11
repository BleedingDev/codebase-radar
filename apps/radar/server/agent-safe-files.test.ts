import {
  closeSync,
  ftruncateSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Effect, Exit, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  enforceSandboxWritableQuota,
  makeAgentSafeFileCapability,
  maxAgentSandboxWritableEntries,
  readSandboxRegularFile,
} from './agent-safe-files';

const withTemporaryDirectory = <Value>(run: (root: string) => Value) => {
  const root = mkdtempSync(resolve(tmpdir(), 'radar-agent-safe-file-'));
  try {
    return run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

describe('provider result descriptor reads', () => {
  it('reads only a bounded regular file through a no-follow descriptor', () =>
    withTemporaryDirectory(root => {
      writeFileSync(resolve(root, 'priority.json'), '{"ok":true}');
      const result = Effect.runSyncExit(
        readSandboxRegularFile(root, ['priority.json'], 1_024),
      );

      expect(Exit.isSuccess(result)).toBe(true);
      if (Exit.isSuccess(result)) {
        expect(Option.isSome(result.value)).toBe(true);
      }
    }));

  it('rejects credential and result symlinks before external bytes are read', () =>
    withTemporaryDirectory(root => {
      const externalRoot = mkdtempSync(resolve(tmpdir(), 'radar-agent-sentinel-'));
      try {
        const sentinel = resolve(externalRoot, 'secret.txt');
        writeFileSync(sentinel, 'external-secret-sentinel');
        symlinkSync(sentinel, resolve(root, 'auth.json'));
        const external = Effect.runSyncExit(
          readSandboxRegularFile(root, ['auth.json'], 1_024),
        );
        rmSync(resolve(root, 'auth.json'));
        symlinkSync('/proc/self/environ', resolve(root, 'priority.json'));
        const proc = Effect.runSyncExit(
          readSandboxRegularFile(root, ['priority.json'], 1_024),
        );
        symlinkSync(externalRoot, resolve(root, '.codex'));
        const nested = Effect.runSyncExit(
          readSandboxRegularFile(root, ['.codex', 'secret.txt'], 1_024),
        );

        expect(Exit.isFailure(external)).toBe(true);
        expect(Exit.isFailure(proc)).toBe(true);
        expect(Exit.isFailure(nested)).toBe(true);
      } finally {
        rmSync(externalRoot, { recursive: true, force: true });
      }
    }));

  it('rejects hard-linked output before a retained descriptor can disclose it', () =>
    withTemporaryDirectory(root => {
      const source = resolve(root, 'private-source.json');
      const linked = resolve(root, 'priority.json');
      writeFileSync(source, '{"private":true}');
      linkSync(source, linked);

      const result = Effect.runSyncExit(
        readSandboxRegularFile(root, ['priority.json'], 1_024),
      );

      expect(Exit.isFailure(result)).toBe(true);
    }));

  it('rejects sparse and oversized files before unbounded allocation', () =>
    withTemporaryDirectory(root => {
      const sparse = resolve(root, 'sparse.json');
      const descriptor = openSync(sparse, 'w');
      ftruncateSync(descriptor, 2 * 1_024 * 1_024);
      closeSync(descriptor);
      writeFileSync(resolve(root, 'oversized.json'), 'x'.repeat(2 * 1_024 * 1_024));
      const sparseRead = Effect.runSyncExit(
        readSandboxRegularFile(root, ['sparse.json'], 1_024 * 1_024),
      );
      const oversizedRead = Effect.runSyncExit(
        readSandboxRegularFile(root, ['oversized.json'], 1_024 * 1_024),
      );
      const quota = Effect.runSyncExit(
        enforceSandboxWritableQuota(root, 1_024 * 1_024),
      );

      expect(Exit.isFailure(sparseRead)).toBe(true);
      expect(Exit.isFailure(oversizedRead)).toBe(true);
      expect(Exit.isFailure(quota)).toBe(true);
    }));

  it('retains the opened root descriptor when the root pathname is replaced', () =>
    withTemporaryDirectory(parent => {
      const root = resolve(parent, 'sandbox');
      const retained = resolve(parent, 'retained');
      const replacement = resolve(parent, 'replacement');
      mkdirSync(root);
      mkdirSync(replacement);
      writeFileSync(resolve(root, 'priority.json'), '{"source":"retained"}');
      writeFileSync(resolve(replacement, 'priority.json'), '{"source":"replacement"}');

      const result = Effect.runSyncExit(
        Effect.scoped(
          Effect.gen(function* () {
            const capability = yield* makeAgentSafeFileCapability(root);
            renameSync(root, retained);
            renameSync(replacement, root);
            const content = yield* capability.readRegularFile(['priority.json'], 1_024);

            expect(Option.isSome(content)).toBe(true);
            if (Option.isSome(content)) {
              expect(new TextDecoder().decode(content.value)).toBe('{"source":"retained"}');
            }
            yield* capability.enforceWritableQuota(1_024);
          }),
        ),
      );

      expect(Exit.isSuccess(result)).toBe(true);
    }));

  it('rejects 2,000 empty entries before accepting a writable sandbox', () =>
    withTemporaryDirectory(root => {
      for (let index = 0; index < 2_000; index += 1) {
        writeFileSync(resolve(root, `entry-${index}.json`), '');
      }
      const quota = Effect.runSyncExit(
        enforceSandboxWritableQuota(root, 1_024, maxAgentSandboxWritableEntries),
      );

      expect(Exit.isFailure(quota)).toBe(true);
    }));
});
