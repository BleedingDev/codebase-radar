import { Effect, Exit, Fiber } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  DuplicateAnalyzerRunError,
  DuplicateProcessScriptUseError,
  ScriptedAnalyzerRuntime,
  ScriptedProcessAdapter,
  type ScriptedCommandRequest,
} from './index.js';

const request = (
  command: string,
  overrides: Partial<ScriptedCommandRequest> = {},
): ScriptedCommandRequest => ({
  command,
  args: ['--format', 'json'],
  cwd: '/deterministic/repository',
  timeoutMs: 250,
  ...overrides,
});

describe('ScriptedProcessAdapter', () => {
  it('injects every child-process boundary failure without starting a process', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const controller = new AbortController();
        controller.abort('caller cancelled');
        const nonStringReasonController = new AbortController();
        nonStringReasonController.abort({ cancelled: true });
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'success',
            outcome: {
              kind: 'exit',
              exitCode: 0,
              stdout: '{"findings":[]}',
              durationMs: 7,
            },
          },
          { id: 'missing', outcome: { kind: 'missing-binary' } },
          {
            id: 'malformed',
            outcome: { kind: 'exit', exitCode: 0, stdout: '{not-json' },
          },
          {
            id: 'nonzero',
            outcome: { kind: 'exit', exitCode: 23, stderr: 'analyzer failed' },
          },
          { id: 'timeout', outcome: { kind: 'timeout', stdout: 'partial' } },
          {
            id: 'truncated',
            outcome: { kind: 'exit', exitCode: 0, stdout: 'abcdef' },
          },
          { id: 'interrupted', outcome: { kind: 'exit', exitCode: 0 } },
          {
            id: 'interrupted-nonstring',
            outcome: { kind: 'exit', exitCode: 0 },
          },
        ]);

        const outcomes = yield* Effect.all(
          [
            adapter.execute('success', request('analyzer-ok')),
            adapter.execute('missing', request('missing-analyzer')),
            adapter.execute('malformed', request('bad-json-analyzer')),
            adapter.execute('nonzero', request('failing-analyzer')),
            adapter.execute('timeout', request('slow-analyzer')),
            adapter.execute(
              'truncated',
              request('noisy-analyzer', { maxOutputBytes: 4 }),
            ),
            adapter.execute(
              'interrupted',
              request('cancelled-analyzer', { signal: controller.signal }),
            ),
            adapter.execute(
              'interrupted-nonstring',
              request('cancelled-analyzer', {
                signal: nonStringReasonController.signal,
              }),
            ),
          ],
          { concurrency: 'unbounded' },
        );

        expect(outcomes).toMatchObject([
          {
            status: 'exited',
            exitCode: 0,
            stdout: '{"findings":[]}',
            durationMs: 7,
            truncated: false,
          },
          {
            status: 'missing-binary',
            binary: 'missing-analyzer',
          },
          { status: 'exited', stdout: '{not-json' },
          {
            status: 'exited',
            exitCode: 23,
            stderr: 'analyzer failed',
          },
          {
            status: 'timed-out',
            timeoutMs: 250,
            durationMs: 250,
            stdout: 'partial',
          },
          {
            status: 'exited',
            stdout: 'abcd',
            truncated: true,
          },
          {
            status: 'interrupted',
            reason: 'caller cancelled',
          },
          {
            status: 'interrupted',
            reason: 'aborted',
          },
        ]);

        const snapshot = yield* adapter.snapshot();
        expect(snapshot.invocations.map(call => call.scriptId)).toEqual([
          'success',
          'missing',
          'malformed',
          'nonzero',
          'timeout',
          'truncated',
          'interrupted',
          'interrupted-nonstring',
        ]);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('finalizes claimed executions when request decoding fails', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'invalid-limit',
            outcome: { kind: 'exit', exitCode: 0, stdout: 'output' },
          },
        ]);

        const invalidLimit = yield* Effect.exit(
          adapter.execute(
            'invalid-limit',
            request('analyzer', { maxOutputBytes: -1 }),
          ),
        );
        expect(Exit.isFailure(invalidLimit)).toBe(true);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('rejects empty process script ids at the execution schema boundary', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'present-script',
            outcome: { kind: 'exit', exitCode: 0 },
          },
        ]);

        const emptyId = yield* Effect.exit(
          adapter.execute('', request('analyzer')),
        );
        expect(Exit.isFailure(emptyId)).toBe(true);
        expect(yield* adapter.snapshot()).toEqual({
          invocations: [],
          activeScriptIds: [],
          finalizedScriptIds: [],
          remainingScriptIds: ['present-script'],
        });
      }),
    ));

  it('truncates UTF-8 output only at complete code point boundaries', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'inside-code-point',
            outcome: { kind: 'exit', exitCode: 0, stdout: 'A€B' },
          },
          {
            id: 'at-code-point',
            outcome: { kind: 'exit', exitCode: 0, stdout: 'A€B' },
          },
        ]);

        const outcomes = yield* Effect.all(
          [
            adapter.execute(
              'inside-code-point',
              request('analyzer', { maxOutputBytes: 2 }),
            ),
            adapter.execute(
              'at-code-point',
              request('analyzer', { maxOutputBytes: 4 }),
            ),
          ],
          { concurrency: 'unbounded' },
        );
        const outputEncoder = new TextEncoder();

        expect(outcomes).toMatchObject([
          { status: 'exited', stdout: 'A', truncated: true },
          { status: 'exited', stdout: 'A€', truncated: true },
        ]);
        expect(
          outcomes.map(outcome => outputEncoder.encode(outcome.stdout).byteLength),
        ).toEqual([1, 4]);
        expect(outcomes.map(outcome => outcome.stdout.includes('�'))).toEqual([
          false,
          false,
        ]);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('rejects duplicate process scripts and preserves single finalization', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'duplication',
            outcome: { kind: 'exit', exitCode: 0 },
          },
        ]);

        yield* adapter.execute('duplication', request('analyzer'));
        const duplicate = yield* adapter
          .execute('duplication', request('analyzer'))
          .pipe(Effect.flip);
        expect(duplicate).toBeInstanceOf(DuplicateProcessScriptUseError);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('does not finalize an active process claim when a concurrent duplicate fails', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'duplication',
            outcome: { kind: 'exit', exitCode: 0 },
          },
        ]);

        const first = yield* adapter
          .execute('duplication', request('analyzer'))
          .pipe(Effect.forkChild);
        yield* Effect.yieldNow;
        expect((yield* adapter.snapshot()).activeScriptIds).toEqual([
          'duplication',
        ]);

        const duplicate = yield* adapter
          .execute('duplication', request('analyzer'))
          .pipe(Effect.flip);
        expect(duplicate).toBeInstanceOf(DuplicateProcessScriptUseError);

        const afterDuplicate = yield* adapter.snapshot();
        expect(afterDuplicate.activeScriptIds).toEqual(['duplication']);
        expect(afterDuplicate.finalizedScriptIds).toEqual([]);

        yield* Fiber.join(first);
        const completed = yield* adapter.snapshot();
        expect(completed.activeScriptIds).toEqual([]);
        expect(completed.finalizedScriptIds).toEqual(['duplication']);
        expect(completed.finalizedScriptIds).toHaveLength(1);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('observes cancellation that arrives after a process claim starts', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const controller = new AbortController();
        const adapter = yield* ScriptedProcessAdapter.make([
          {
            id: 'post-start-abort',
            outcome: { kind: 'exit', exitCode: 0 },
          },
        ]);

        const running = yield* adapter
          .execute('post-start-abort', request('analyzer', { signal: controller.signal }))
          .pipe(Effect.forkChild);
        yield* Effect.yieldNow;
        const claimedSnapshot = yield* adapter.snapshot();
        expect(claimedSnapshot.activeScriptIds).toEqual([
          'post-start-abort',
        ]);
        expect(claimedSnapshot.invocations).toEqual([
          {
            sequence: 0,
            scriptId: 'post-start-abort',
            request: {
              command: 'analyzer',
              args: ['--format', 'json'],
              cwd: '/deterministic/repository',
              timeoutMs: 250,
            },
          },
        ]);

        controller.abort('cancelled after claim');
        expect(claimedSnapshot.invocations).toEqual([
          {
            sequence: 0,
            scriptId: 'post-start-abort',
            request: {
              command: 'analyzer',
              args: ['--format', 'json'],
              cwd: '/deterministic/repository',
              timeoutMs: 250,
            },
          },
        ]);
        expect(yield* Fiber.join(running)).toMatchObject({
          status: 'interrupted',
          reason: 'cancelled after claim',
        });
        const completed = yield* adapter.snapshot();
        expect(completed.finalizedScriptIds).toEqual(['post-start-abort']);
        yield* adapter.assertClean();
        yield* adapter.assertExhausted();
      }),
    ));

  it('canonicalizes process snapshots after reversed concurrent launch order', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const forward = yield* ScriptedProcessAdapter.make([
          { id: 'first', outcome: { kind: 'exit', exitCode: 0 } },
          { id: 'second', outcome: { kind: 'exit', exitCode: 0 } },
          { id: 'third', outcome: { kind: 'exit', exitCode: 0 } },
        ]);
        const reversed = yield* ScriptedProcessAdapter.make([
          { id: 'first', outcome: { kind: 'exit', exitCode: 0 } },
          { id: 'second', outcome: { kind: 'exit', exitCode: 0 } },
          { id: 'third', outcome: { kind: 'exit', exitCode: 0 } },
        ]);

        yield* Effect.all(
          [
            forward.execute('first', request('analyzer')),
            forward.execute('second', request('analyzer')),
            forward.execute('third', request('analyzer')),
          ],
          { concurrency: 'unbounded' },
        );
        yield* Effect.all(
          [
            reversed.execute('third', request('analyzer')),
            reversed.execute('second', request('analyzer')),
            reversed.execute('first', request('analyzer')),
          ],
          { concurrency: 'unbounded' },
        );

        expect(yield* reversed.snapshot()).toEqual(
          yield* forward.snapshot(),
        );
        yield* forward.assertClean();
        yield* forward.assertExhausted();
        yield* reversed.assertClean();
        yield* reversed.assertExhausted();
      }),
    ));
});

describe('ScriptedAnalyzerRuntime', () => {
  it('scripts typed analyzer failures and reports partial coverage', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const scanId = 'scan-fixed';
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId,
            analyzerId: 'complete',
            outcome: {
              status: 'complete',
              payload: { candidates: [] },
              observationCount: 3,
            },
          },
          {
            scanId,
            analyzerId: 'missing',
            outcome: { status: 'missing-binary', binary: 'missing-tool' },
          },
          {
            scanId,
            analyzerId: 'malformed',
            outcome: {
              status: 'malformed-output',
              rawOutput: '{',
              diagnostic: 'unexpected end of JSON input',
            },
          },
          {
            scanId,
            analyzerId: 'nonzero',
            outcome: { status: 'nonzero-exit', exitCode: 2, stderr: 'failed' },
          },
          {
            scanId,
            analyzerId: 'timeout',
            outcome: { status: 'timed-out', timeoutMs: 500 },
          },
          {
            scanId,
            analyzerId: 'truncated',
            outcome: {
              status: 'truncated',
              stream: 'stdout',
              captured: 'abcd',
              maxOutputBytes: 4,
            },
          },
          {
            scanId,
            analyzerId: 'interrupted',
            outcome: { status: 'interrupted', reason: 'scan cancelled' },
          },
        ]);
        const analyzerIds = [
          'complete',
          'missing',
          'malformed',
          'nonzero',
          'timeout',
          'truncated',
          'interrupted',
        ];

        const outcomes = yield* Effect.all(
          analyzerIds.map(analyzerId => runtime.run({ scanId, analyzerId })),
          { concurrency: 'unbounded' },
        );

        expect(outcomes.map(outcome => outcome.status)).toEqual([
          'complete',
          'missing-binary',
          'malformed-output',
          'nonzero-exit',
          'timed-out',
          'truncated',
          'interrupted',
        ]);
        expect(
          yield* runtime.coverage(scanId, [...analyzerIds, 'not-attempted']),
        ).toEqual({
          status: 'partial',
          expectedAnalyzerIds: [...analyzerIds, 'not-attempted'],
          attemptedAnalyzerIds: analyzerIds,
          completeAnalyzerIds: ['complete'],
          incompleteAnalyzerIds: analyzerIds.filter(
            analyzerId => analyzerId !== 'complete',
          ),
          missingAnalyzerIds: ['not-attempted'],
          unexpectedAnalyzerIds: [],
        });
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('rejects a duplicate analyzer run and preserves single finalization', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'duplication',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        yield* runtime.run({ scanId: 'scan-fixed', analyzerId: 'duplication' });
        const duplicate = yield* runtime
          .run({ scanId: 'scan-fixed', analyzerId: 'duplication' })
          .pipe(Effect.flip);
        expect(duplicate).toBeInstanceOf(DuplicateAnalyzerRunError);

        expect(yield* runtime.snapshot()).toEqual({
          attemptedRuns: [{ scanId: 'scan-fixed', analyzerId: 'duplication' }],
          activeRuns: [],
          finalizedRuns: [{ scanId: 'scan-fixed', analyzerId: 'duplication' }],
          remainingRuns: [],
        });
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('does not expose remaining analyzer cases through a snapshot', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'original-case',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        const priorSnapshot = yield* runtime.snapshot();
        expect(priorSnapshot.remainingRuns).toHaveLength(1);
        priorSnapshot.remainingRuns.forEach((remainingRun, index) => {
          if (index === 0) {
            Object.assign(remainingRun, { scanId: 'mutated-snapshot' });
          }
        });

        expect(yield* runtime.snapshot()).toEqual({
          attemptedRuns: [],
          activeRuns: [],
          finalizedRuns: [],
          remainingRuns: [
            { scanId: 'scan-fixed', analyzerId: 'original-case' },
          ],
        });
        expect(
          yield* runtime.run({
            scanId: 'scan-fixed',
            analyzerId: 'original-case',
          }),
        ).toMatchObject({ status: 'complete' });
        expect(yield* runtime.snapshot()).toEqual({
          attemptedRuns: [
            { scanId: 'scan-fixed', analyzerId: 'original-case' },
          ],
          activeRuns: [],
          finalizedRuns: [
            { scanId: 'scan-fixed', analyzerId: 'original-case' },
          ],
          remainingRuns: [],
        });
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('does not publish completion for interrupted active analyzer work', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'interrupted',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        const running = yield* runtime
          .run({ scanId: 'scan-fixed', analyzerId: 'interrupted' })
          .pipe(Effect.forkChild);
        yield* Effect.yieldNow;
        expect((yield* runtime.snapshot()).activeRuns).toEqual([
          { scanId: 'scan-fixed', analyzerId: 'interrupted' },
        ]);

        yield* Fiber.interrupt(running);
        expect(yield* runtime.snapshot()).toEqual({
          attemptedRuns: [
            { scanId: 'scan-fixed', analyzerId: 'interrupted' },
          ],
          activeRuns: [],
          finalizedRuns: [
            { scanId: 'scan-fixed', analyzerId: 'interrupted' },
          ],
          remainingRuns: [],
        });
        expect(
          yield* runtime.coverage('scan-fixed', ['interrupted']),
        ).toEqual({
          status: 'partial',
          expectedAnalyzerIds: ['interrupted'],
          attemptedAnalyzerIds: ['interrupted'],
          completeAnalyzerIds: [],
          incompleteAnalyzerIds: ['interrupted'],
          missingAnalyzerIds: [],
          unexpectedAnalyzerIds: [],
        });
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('does not finalize an active analyzer claim when a concurrent duplicate fails', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'duplication',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        const first = yield* runtime
          .run({ scanId: 'scan-fixed', analyzerId: 'duplication' })
          .pipe(Effect.forkChild);
        yield* Effect.yieldNow;
        expect((yield* runtime.snapshot()).activeRuns).toEqual([
          { scanId: 'scan-fixed', analyzerId: 'duplication' },
        ]);

        const duplicate = yield* runtime
          .run({ scanId: 'scan-fixed', analyzerId: 'duplication' })
          .pipe(Effect.flip);
        expect(duplicate).toBeInstanceOf(DuplicateAnalyzerRunError);

        const afterDuplicate = yield* runtime.snapshot();
        expect(afterDuplicate.activeRuns).toEqual([
          { scanId: 'scan-fixed', analyzerId: 'duplication' },
        ]);
        expect(afterDuplicate.finalizedRuns).toEqual([]);

        yield* Fiber.join(first);
        const completed = yield* runtime.snapshot();
        expect(completed.activeRuns).toEqual([]);
        expect(completed.finalizedRuns).toEqual([
          { scanId: 'scan-fixed', analyzerId: 'duplication' },
        ]);
        expect(completed.finalizedRuns).toHaveLength(1);
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('isolates delimiter-bearing pairs and reports unexpected-only coverage', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const runtime = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan:tool',
            analyzerId: 'alpha',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'scan',
            analyzerId: 'tool:alpha',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'unexpected-only',
            analyzerId: 'actual',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        yield* Effect.all(
          [
            runtime.run({ scanId: 'scan:tool', analyzerId: 'alpha' }),
            runtime.run({ scanId: 'scan', analyzerId: 'tool:alpha' }),
            runtime.run({ scanId: 'unexpected-only', analyzerId: 'actual' }),
          ],
          { concurrency: 'unbounded' },
        );

        expect(yield* runtime.coverage('scan:tool', ['alpha'])).toEqual({
          status: 'complete',
          expectedAnalyzerIds: ['alpha'],
          attemptedAnalyzerIds: ['alpha'],
          completeAnalyzerIds: ['alpha'],
          incompleteAnalyzerIds: [],
          missingAnalyzerIds: [],
          unexpectedAnalyzerIds: [],
        });
        expect(yield* runtime.coverage('scan', ['tool:alpha'])).toEqual({
          status: 'complete',
          expectedAnalyzerIds: ['tool:alpha'],
          attemptedAnalyzerIds: ['tool:alpha'],
          completeAnalyzerIds: ['tool:alpha'],
          incompleteAnalyzerIds: [],
          missingAnalyzerIds: [],
          unexpectedAnalyzerIds: [],
        });
        expect(yield* runtime.coverage('unexpected-only', [])).toEqual({
          status: 'partial',
          expectedAnalyzerIds: [],
          attemptedAnalyzerIds: ['actual'],
          completeAnalyzerIds: [],
          incompleteAnalyzerIds: [],
          missingAnalyzerIds: [],
          unexpectedAnalyzerIds: ['actual'],
        });
        yield* runtime.assertClean();
        yield* runtime.assertExhausted();
      }),
    ));

  it('canonicalizes analyzer snapshots and coverage after reversed concurrent launch order', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const forward = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'first',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'scan-fixed',
            analyzerId: 'second',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'scan-fixed',
            analyzerId: 'third',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);
        const reversed = yield* ScriptedAnalyzerRuntime.make([
          {
            scanId: 'scan-fixed',
            analyzerId: 'first',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'scan-fixed',
            analyzerId: 'second',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
          {
            scanId: 'scan-fixed',
            analyzerId: 'third',
            outcome: {
              status: 'complete',
              payload: null,
              observationCount: 1,
            },
          },
        ]);

        yield* Effect.all(
          [
            forward.run({ scanId: 'scan-fixed', analyzerId: 'first' }),
            forward.run({ scanId: 'scan-fixed', analyzerId: 'second' }),
            forward.run({ scanId: 'scan-fixed', analyzerId: 'third' }),
          ],
          { concurrency: 'unbounded' },
        );
        yield* Effect.all(
          [
            reversed.run({ scanId: 'scan-fixed', analyzerId: 'third' }),
            reversed.run({ scanId: 'scan-fixed', analyzerId: 'second' }),
            reversed.run({ scanId: 'scan-fixed', analyzerId: 'first' }),
          ],
          { concurrency: 'unbounded' },
        );

        expect(yield* reversed.snapshot()).toEqual(
          yield* forward.snapshot(),
        );
        expect(
          yield* reversed.coverage('scan-fixed', ['third', 'second', 'first']),
        ).toEqual(
          yield* forward.coverage('scan-fixed', ['first', 'second', 'third']),
        );
        yield* forward.assertClean();
        yield* forward.assertExhausted();
        yield* reversed.assertClean();
        yield* reversed.assertExhausted();
      }),
    ));
});
