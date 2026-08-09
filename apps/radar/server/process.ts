import {
  Clock,
  Effect,
  Option,
  Schema,
  Stream,
} from 'effect';
import { ChildProcess } from 'effect/unstable/process';

export class CommandFailure extends Schema.TaggedErrorClass<CommandFailure>()(
  'CommandFailure',
  { message: Schema.String },
) {}

export const runCommand = Effect.fn('runCommand')(function* (input: {
  readonly command: string;
  readonly args: ReadonlyArray<string>;
  readonly cwd: string;
  readonly env?: Record<string, string | undefined>;
  readonly stdin?: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes?: number;
}) {
  const startedAt = yield* Clock.currentTimeMillis;
  const maxOutputBytes = input.maxOutputBytes ?? 4 * 1024 * 1024;
  const command = ChildProcess.make(input.command, input.args, {
    cwd: input.cwd,
    env: input.env,
    extendEnv: false,
    shell: false,
    detached: true,
    stdin:
      input.stdin === undefined
        ? 'ignore'
        : Stream.make(new TextEncoder().encode(input.stdin)),
    stdout: 'pipe',
    stderr: 'pipe',
    forceKillAfter: '2 seconds',
  });

  const completed = yield* Effect.scoped(
    Effect.gen(function* () {
      const handle = yield* command;
      const collect = <OutputError>(
        stream: Stream.Stream<Uint8Array, OutputError>,
      ) =>
        stream.pipe(
          Stream.runFold(
            () => ({
              chunks: new Array<Uint8Array>(),
              bytes: 0,
              truncated: false,
            }),
            (state, chunk) => {
              const remaining = Math.max(0, maxOutputBytes - state.bytes);
              if (remaining === 0) return { ...state, truncated: true };
              const accepted = chunk.subarray(0, remaining);
              return {
                chunks: [...state.chunks, accepted],
                bytes: state.bytes + accepted.byteLength,
                truncated: state.truncated || accepted.byteLength < chunk.byteLength,
              };
            },
          ),
          Effect.map(({ chunks, truncated }) => ({
            value: new TextDecoder().decode(
              Uint8Array.from(chunks.flatMap(chunk => [...chunk])),
            ),
            truncated,
          })),
        );
      const [stdout, stderr, exitCode] = yield* Effect.all(
        [collect(handle.stdout), collect(handle.stderr), handle.exitCode],
        { concurrency: 'unbounded' },
      );
      return { stdout, stderr, exitCode: Number(exitCode) };
    }),
  ).pipe(
    Effect.timeoutOption(input.timeoutMs),
    Effect.mapError(
      cause =>
        new CommandFailure({
          message: cause instanceof Error ? cause.message : String(cause),
        }),
    ),
  );
  const durationMs = (yield* Clock.currentTimeMillis) - startedAt;
  if (Option.isNone(completed)) {
    return {
      exitCode: null,
      stdout: '',
      stderr: '',
      durationMs,
      timedOut: true,
      truncated: false,
    };
  }
  return {
    exitCode: completed.value.exitCode,
    stdout: completed.value.stdout.value,
    stderr: completed.value.stderr.value,
    durationMs,
    timedOut: false,
    truncated:
      completed.value.stdout.truncated || completed.value.stderr.truncated,
  };
});

export const boundedDiagnostic = (value: string, max = 500) =>
  value.replace(/\s+/gu, ' ').trim().slice(0, max);
