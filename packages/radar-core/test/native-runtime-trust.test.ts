import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Effect } from 'effect';
import { describe, expect, it } from 'vitest';
import { makeNodeLinuxDescriptorWorkspaceBindingForTest } from '../src/internal/linux-descriptor-host.js';
import {
  WorkspaceQuota,
  WorkspaceRelativePath,
} from '../src/internal/workspace.js';

const linuxIt = process.platform === 'linux' ? it : it.skip;

const workspaceQuota = (maximumEntries = 8, maximumFiles = 8) => new WorkspaceQuota({
  maximumEntries,
  maximumFiles,
  maximumBytes: 8 * 1024,
});

const workspacePath = (...segments: ReadonlyArray<string>) =>
  new WorkspaceRelativePath({ segments: [...segments] });

describe('native descriptor workspace lifecycle', () => {
  linuxIt('keeps the binding parent live per lease and recursively removes populated workspaces', () => {
    const fixture = mkdtempSync(join(tmpdir(), 'radar-workspace-lifecycle-'));
    const workspaceParent = join(fixture, 'workspaces');
    mkdirSync(workspaceParent, { mode: 0o700 });
    chmodSync(workspaceParent, 0o700);
    const program = Effect.scoped(
      makeNodeLinuxDescriptorWorkspaceBindingForTest({ workspaceParent }).pipe(
        Effect.flatMap(binding => Effect.gen(function* () {
          const first = yield* binding.allocateScratch(workspaceQuota());
          yield* first.scratch.makeDirectory(workspacePath('nested'));
          const writer = yield* first.scratch.openFileWriter(workspacePath('nested', 'result.txt'));
          yield* writer.write(new TextEncoder().encode('owned result'));
          yield* writer.close(true);
          yield* first.close;
          expect(readdirSync(workspaceParent)).toEqual([]);

          // Every lease owns a duplicate parent descriptor. Closing the first
          // populated scratch must not invalidate the retained binding parent.
          const second = yield* binding.allocateScratch(workspaceQuota());
          yield* second.close;
          expect(readdirSync(workspaceParent)).toEqual([]);
        })),
      ),
    );
    return Effect.runPromise(program).finally(() => {
      rmSync(fixture, { force: true, recursive: true });
    });
  });

  linuxIt('rolls back a newly created workspace when its first descriptor open fails', () => {
    const fixture = mkdtempSync(join(tmpdir(), 'radar-workspace-rollback-'));
    const workspaceParent = join(fixture, 'workspaces');
    mkdirSync(workspaceParent, { mode: 0o700 });
    chmodSync(workspaceParent, 0o700);
    const program = Effect.scoped(
      makeNodeLinuxDescriptorWorkspaceBindingForTest({ workspaceParent }).pipe(
        Effect.flatMap(binding => Effect.acquireUseRelease(
          Effect.sync(() => process.umask(0o777)),
          previous => Effect.flip(binding.allocateScratch(workspaceQuota())).pipe(
            Effect.tap(rejected => Effect.sync(() => {
              expect(rejected.reason).toBe('workspace-quota-unenforced');
              expect(readdirSync(workspaceParent)).toEqual([]);
            })),
            Effect.ensuring(Effect.sync(() => {
              process.umask(previous);
            })),
          ),
          previous => Effect.sync(() => {
            process.umask(previous);
          }),
        )),
      ),
    );
    return Effect.runPromise(program).finally(() => {
      rmSync(fixture, { force: true, recursive: true });
    });
  });

  linuxIt('does not refund a failed writer abort and later removes its partial tree', () => {
    const fixture = mkdtempSync(join(tmpdir(), 'radar-writer-abort-'));
    const workspaceParent = join(fixture, 'workspaces');
    mkdirSync(workspaceParent, { mode: 0o700 });
    chmodSync(workspaceParent, 0o700);
    const program = Effect.scoped(
      makeNodeLinuxDescriptorWorkspaceBindingForTest({ workspaceParent }).pipe(
        Effect.flatMap(binding => Effect.gen(function* () {
          const lease = yield* binding.allocateScratch(workspaceQuota(2, 1));
          const writer = yield* lease.scratch.openFileWriter(workspacePath('partial.txt'));
          yield* writer.write(new TextEncoder().encode('partial result'));
          yield* Effect.sync(() => {
            const workspace = readdirSync(workspaceParent)[0];
            expect(workspace).toBeDefined();
            if (workspace === undefined) return;
            renameSync(
              join(workspaceParent, workspace, 'partial.txt'),
              join(workspaceParent, workspace, 'retained.txt'),
            );
            mkdirSync(join(workspaceParent, workspace, 'partial.txt'), { mode: 0o700 });
          });
          const abortFailure = yield* Effect.flip(writer.close(false));
          expect(abortFailure.reason).toBe('cleanup-failed');
          const quotaFailure = yield* Effect.flip(
            lease.scratch.openFileWriter(workspacePath('replacement.txt')),
          );
          expect(quotaFailure.reason).toBe('workspace-quota-exceeded');
          yield* lease.close;
          expect(readdirSync(workspaceParent)).toEqual([]);
        })),
      ),
    );
    return Effect.runPromise(program).finally(() => {
      rmSync(fixture, { force: true, recursive: true });
    });
  });
});
