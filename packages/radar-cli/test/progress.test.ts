import {
  Effect,
  Ref,
  Sink,
  Stdio,
} from 'effect';
import { AnalysisProgressUpdate } from '@codebase-radar/contracts';
import { describe, expect, it } from 'vitest';
import { presentProgress } from '../src/progress.js';

const capture = () =>
  Effect.gen(function* () {
    const stdout = yield* Ref.make('');
    const stderr = yield* Ref.make('');
    const layer = Stdio.layerTest({
      stdout: () => Sink.forEach((chunk: string | Uint8Array) => Ref.update(
        stdout,
        text => `${text}${typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk)}`,
      )),
      stderr: () => Sink.forEach((chunk: string | Uint8Array) => Ref.update(
        stderr,
        text => `${text}${typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk)}`,
      )),
    });
    return { layer, stdout, stderr };
  });

const update = new AnalysisProgressUpdate({
  scanId: 'scan-progress-001',
  sequence: 0,
  timestamp: '2026-08-11T00:00:00.000Z',
  completedWork: 1,
  totalWork: 2,
  percent: 50,
  stage: 'analyzing',
  terminal: false,
});

describe('stderr progress presentation', () => {
  it('keeps progress off stdout and switches between non-TTY and TTY framing', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const nonTty = yield* capture();
        yield* presentProgress({ quiet: false, isTty: false }, update).pipe(
          Effect.provide(nonTty.layer),
        );
        expect(yield* Ref.get(nonTty.stdout)).toBe('');
        expect(yield* Ref.get(nonTty.stderr)).toBe('analyzing 1/2 (50%)\n');

        const tty = yield* capture();
        yield* presentProgress({ quiet: false, isTty: true }, update).pipe(
          Effect.provide(tty.layer),
        );
        expect(yield* Ref.get(tty.stdout)).toBe('');
        expect(yield* Ref.get(tty.stderr)).toBe('\ranalyzing 1/2 (50%)\r');

        const quiet = yield* capture();
        yield* presentProgress({ quiet: true, isTty: false }, update).pipe(
          Effect.provide(quiet.layer),
        );
        expect(yield* Ref.get(quiet.stderr)).toBe('');
      }),
    ));
});
