import { spawnSync } from 'node:child_process';
import { linkSync, lstatSync, mkdirSync, symlinkSync } from 'node:fs';
import { Effect, Exit, FileSystem, Path, Result } from 'effect';
import { NodeServices } from '@effect/platform-node';
import { describe, expect, it } from 'vitest';
import { writeFileAtomically } from '../src/io.js';

describe('atomic result output', () => {
  it('replaces the destination through a same-directory temporary file without leftovers', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const paths = yield* Path.Path;
        const directory = yield* filesystem.makeTempDirectory({ prefix: 'radar-cli-test-' });
        const destination = paths.join(directory, 'result.json');
        const check = Effect.gen(function* () {
          yield* filesystem.writeFileString(destination, 'old result');
          yield* writeFileAtomically(destination, 'new result');
          expect(yield* filesystem.readFileString(destination)).toBe('new result');
          expect((yield* filesystem.readDirectory(directory)).filter(name => (
            name.startsWith('.radar-')
          ))).toHaveLength(0);
        });
        yield* check.pipe(
          Effect.ensuring(filesystem.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore)),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    ));

  it('rejects a final symbolic-link output target without changing its referent', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const paths = yield* Path.Path;
        const directory = yield* filesystem.makeTempDirectory({ prefix: 'radar-cli-link-test-' });
        const referent = paths.join(directory, 'protected.json');
        const destination = paths.join(directory, 'result.json');
        const check = Effect.gen(function* () {
          yield* filesystem.writeFileString(referent, 'protected result');
          symlinkSync(referent, destination);
          const exit = yield* Effect.exit(writeFileAtomically(destination, 'new result'));

          expect(Exit.isFailure(exit)).toBe(true);
          expect(lstatSync(destination).isSymbolicLink()).toBe(true);
          expect(yield* filesystem.readFileString(referent)).toBe('protected result');
          expect((yield* filesystem.readDirectory(directory)).filter(name => (
            name.startsWith('.radar-')
          ))).toHaveLength(0);
        });
        yield* check.pipe(
          Effect.ensuring(filesystem.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore)),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    ));

  it('rejects directory and hard-linked final output targets without replacing them', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const paths = yield* Path.Path;
        const directory = yield* filesystem.makeTempDirectory({ prefix: 'radar-cli-target-test-' });
        const directoryTarget = paths.join(directory, 'directory-target');
        const referent = paths.join(directory, 'referent.json');
        const hardLinkTarget = paths.join(directory, 'hard-link-target.json');
        const check = Effect.gen(function* () {
          mkdirSync(directoryTarget);
          yield* filesystem.writeFileString(referent, 'protected result');
          linkSync(referent, hardLinkTarget);

          const directoryResult = yield* Effect.exit(
            writeFileAtomically(directoryTarget, 'new result'),
          );
          const directoryError = Exit.findError(directoryResult);
          expect(Result.isSuccess(directoryError)).toBe(true);
          if (Result.isSuccess(directoryError)) {
            expect(directoryError.success.message).toBe(
              'Output target must be absent or a single-link regular file.',
            );
          }
          expect(lstatSync(directoryTarget).isDirectory()).toBe(true);

          const hardLinkResult = yield* Effect.exit(
            writeFileAtomically(hardLinkTarget, 'new result'),
          );
          const hardLinkError = Exit.findError(hardLinkResult);
          expect(Result.isSuccess(hardLinkError)).toBe(true);
          if (Result.isSuccess(hardLinkError)) {
            expect(hardLinkError.success.message).toBe(
              'Output target must be absent or a single-link regular file.',
            );
          }
          expect(lstatSync(hardLinkTarget).ino).toBe(lstatSync(referent).ino);
          expect(yield* filesystem.readFileString(referent)).toBe('protected result');
          expect((yield* filesystem.readDirectory(directory)).filter(name => (
            name.startsWith('.radar-')
          ))).toHaveLength(0);
        });
        yield* check.pipe(
          Effect.ensuring(filesystem.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore)),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    ));

  it('rejects a final FIFO output target on POSIX platforms', () => {
    if (process.platform === 'win32') return;
    return Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const paths = yield* Path.Path;
        const directory = yield* filesystem.makeTempDirectory({ prefix: 'radar-cli-fifo-test-' });
        const destination = paths.join(directory, 'result.fifo');
        const check = Effect.gen(function* () {
          const created = spawnSync('mkfifo', [destination], { encoding: 'utf8' });
          expect(created.error).toBeUndefined();
          expect(created.status).toBe(0);
          expect(lstatSync(destination).isFIFO()).toBe(true);

          const result = yield* Effect.exit(writeFileAtomically(destination, 'new result'));
          const error = Exit.findError(result);
          expect(Result.isSuccess(error)).toBe(true);
          if (Result.isSuccess(error)) {
            expect(error.success.message).toBe(
              'Output target must be absent or a single-link regular file.',
            );
          }
          expect(lstatSync(destination).isFIFO()).toBe(true);
          expect((yield* filesystem.readDirectory(directory)).filter(name => (
            name.startsWith('.radar-')
          ))).toHaveLength(0);
        });
        yield* check.pipe(
          Effect.ensuring(filesystem.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore)),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    );
  });
});
