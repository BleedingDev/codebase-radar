import { lstatSync, renameSync } from 'node:fs';
import { Effect, FileSystem, Path, Stdio, Stream } from 'effect';
import { CliOutputError } from './errors.js';

const writeToSink = (
  contents: string,
  sink: ReturnType<Stdio.Stdio['stdout']>,
) =>
  Stream.run(Stream.succeed(contents), sink).pipe(
    Effect.mapError(
      () => new CliOutputError({ message: 'Unable to write CLI output.' }),
    ),
  );

export const writeStdout = (contents: string) =>
  Stdio.Stdio.use(stdio => writeToSink(contents, stdio.stdout()));

export const writeStderr = (contents: string) =>
  Stdio.Stdio.use(stdio => writeToSink(contents, stdio.stderr()));

const replaceWithoutFollowingFinalSymlink = (temporary: string, destination: string) =>
  Effect.try({
    try: () => {
      const existing = lstatSync(destination, { throwIfNoEntry: false });
      if (existing?.isSymbolicLink()) {
        return 'Output target must not be a symbolic link.';
      }
      if (existing !== undefined && (!existing.isFile() || existing.nlink !== 1)) {
        return 'Output target must be absent or a single-link regular file.';
      }
      renameSync(temporary, destination);
      return undefined;
    },
    catch: () => new CliOutputError({ message: 'Unable to write the output file.' }),
  }).pipe(
    Effect.flatMap(rejection =>
      rejection === undefined
        ? Effect.void
        : Effect.fail(new CliOutputError({ message: rejection })),
    ),
  );

export const writeFileAtomically = Effect.fn('writeFileAtomically')(function* (
  target: string,
  contents: string,
) {
  const filesystem = yield* FileSystem.FileSystem;
  const paths = yield* Path.Path;
  const destination = paths.resolve(target);
  const temporary = yield* filesystem.makeTempFile({
    directory: paths.dirname(destination),
    prefix: '.radar-',
    suffix: '.tmp',
  }).pipe(
    Effect.mapError(
      () => new CliOutputError({ message: 'Unable to prepare the output file.' }),
    ),
  );
  const temporaryDirectory = paths.dirname(temporary);
  yield* Effect.gen(function* () {
    yield* filesystem.writeFileString(temporary, contents).pipe(
      Effect.mapError(() => new CliOutputError({ message: 'Unable to write the output file.' })),
    );
    yield* replaceWithoutFollowingFinalSymlink(temporary, destination);
  }).pipe(
    Effect.ensuring(
      filesystem.remove(temporaryDirectory, { recursive: true, force: true }).pipe(Effect.ignore),
    ),
  );
});

export const writeResult = (contents: string, output: string | undefined) =>
  output === undefined ? writeStdout(contents) : writeFileAtomically(output, contents);
