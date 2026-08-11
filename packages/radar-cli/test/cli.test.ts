import { readFileSync, symlinkSync } from 'node:fs';
import {
  Cause,
  Effect,
  Exit,
  FileSystem,
  Option,
  Path,
  Ref,
  Runtime,
  Sink,
  Stdio,
} from 'effect';
import { NodeServices } from '@effect/platform-node';
import {
  AnalysisInterrupted,
  AnalysisProgressUpdate,
  AnalysisRuntimeUnavailable,
  decodeScanResultJson,
  encodeScanResultJson,
  RequiredAnalyzerIds,
  SuccessfulScanResult,
} from '@codebase-radar/contracts';
import type { AnalysisRequest } from '@codebase-radar/contracts';
import {
  AnalysisObserver,
  makeUnavailableRadarRuntimePreflight,
  RadarAnalysis,
  RadarRuntimeEvidence,
  RadarRuntimeReport,
} from '@codebase-radar/core';
import { TestConsole } from 'effect/testing';
import { describe, expect, it } from 'vitest';
import { runRadarCli } from '../src/cli.js';
import {
  RadarDoctor,
  decodeDoctorReport,
  encodeDoctorReportJson,
} from '../src/doctor.js';
import { safeDiagnosticText } from '../src/text.js';

const artifact = (name: string) =>
  readFileSync(
    new URL(`../../radar-testkit/golden/artifacts/${name}`, import.meta.url),
    'utf8',
  );

const appendChunk = (target: Ref.Ref<string>, chunk: string | Uint8Array) =>
  Ref.update(
    target,
    current => `${current}${typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk)}`,
  );

const captureStdio = (arguments_: ReadonlyArray<string>) =>
  Effect.gen(function* () {
    const stdout = yield* Ref.make('');
    const stderr = yield* Ref.make('');
    return {
      stdout,
      stderr,
      layer: Stdio.layerTest({
        args: Effect.succeed(arguments_),
        stdout: () => Sink.forEach(chunk => appendChunk(stdout, chunk)),
        stderr: () => Sink.forEach(chunk => appendChunk(stderr, chunk)),
      }),
    };
  });

const unavailableRuntimeReport = Effect.runSync(
  makeUnavailableRadarRuntimePreflight().report(),
);

const readyRuntimeReport = new RadarRuntimeReport({
  ...unavailableRuntimeReport,
  status: 'ready',
  evidence: unavailableRuntimeReport.evidence.map(evidence => new RadarRuntimeEvidence({
    ...evidence,
    status: 'ready',
  })),
});

const degradedRuntimeReport = new RadarRuntimeReport({
  ...unavailableRuntimeReport,
  status: 'degraded',
  evidence: unavailableRuntimeReport.evidence.map((evidence, index) => new RadarRuntimeEvidence({
    ...evidence,
    status: index === 0 ? 'ready' : 'unavailable',
  })),
});

const doctor = RadarDoctor.of({ inspect: Effect.succeed(readyRuntimeReport) });

const run = (
  arguments_: ReadonlyArray<string>,
  analysis: ReturnType<typeof RadarAnalysis.of>,
  isTty = false,
  doctorService: ReturnType<typeof RadarDoctor.of> = doctor,
) =>
  Effect.gen(function* () {
    const captured = yield* captureStdio(arguments_);
    const exit = yield* Effect.exit(
      runRadarCli({ isTty }).pipe(
        Effect.provideService(RadarAnalysis, analysis),
        Effect.provideService(RadarDoctor, doctorService),
        Effect.provide(captured.layer),
        Effect.provide(NodeServices.layer),
      ),
    );
    return {
      exit,
      stdout: yield* Ref.get(captured.stdout),
      stderr: yield* Ref.get(captured.stderr),
    };
  });

const successfulAnalysis = (result: ReturnType<typeof RadarAnalysis.of>) => result;

describe('radar command adapter', () => {
  it('renders strict JSON and complete human output from the same canonical findings', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const decoded = yield* decodeScanResultJson(artifact('complete-scan-result.json'));
        expect(decoded.resultKind).toBe('complete');
        if (decoded.resultKind !== 'complete') return;
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.succeed(decoded),
        }));

        const json = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--format', 'json', '--quiet'],
          analysis,
        );
        const human = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--format', 'human', '--quiet'],
          analysis,
        );

        expect(Exit.isSuccess(json.exit)).toBe(true);
        expect(Exit.isSuccess(human.exit)).toBe(true);
        expect(json.stderr).toBe('');
        expect(human.stderr).toBe('');
        expect(yield* decodeScanResultJson(json.stdout)).toEqual(decoded);
        expect(json.stdout.endsWith('\n')).toBe(true);
        expect(human.stdout.split('\n').filter(line => /^\d+\. /.test(line))).toHaveLength(
          decoded.findings.length,
        );
        for (const finding of decoded.findings) {
          expect(human.stdout).toContain(finding.id);
          expect(human.stdout).toContain(finding.mechanism);
        }
      }),
    ));

  it('provides a fresh stderr/noop AnalysisObserver around each parsed scan invocation', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const decoded = yield* decodeScanResultJson(artifact('complete-scan-result.json'));
        expect(decoded.resultKind).toBe('complete');
        if (decoded.resultKind !== 'complete') return;
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.gen(function* () {
            const observer = yield* AnalysisObserver;
            yield* observer.observe(new AnalysisProgressUpdate({
              scanId: 'scan-observer-001',
              sequence: 0,
              timestamp: '2026-08-11T00:00:00.000Z',
              completedWork: 1,
              totalWork: 2,
              percent: 50,
              stage: 'analyzing',
              terminal: false,
            }));
            return decoded;
          }),
        }));

        const visible = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--format', 'json'],
          analysis,
        );
        const quiet = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--format', 'json', '--quiet'],
          analysis,
        );

        expect(Exit.isSuccess(visible.exit)).toBe(true);
        expect(visible.stderr).toBe('analyzing 1/2 (50%)\n');
        expect(yield* decodeScanResultJson(visible.stdout)).toEqual(decoded);
        expect(Exit.isSuccess(quiet.exit)).toBe(true);
        expect(quiet.stderr).toBe('');
        expect(yield* decodeScanResultJson(quiet.stdout)).toEqual(decoded);
      }),
    ));

  it('rejects GitHub/path confusion and forbidden analysis controls with a usage exit code', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisInterrupted({
            message: 'The analysis service must not be called for invalid source syntax.',
          })),
        }));

        const confused = yield* run(['scan', 'github', '/tmp/not-a-repository'], analysis);
        const pathConfused = yield* run(
          ['scan', 'path', 'https://github.com/Acme/radar-sample'],
          analysis,
        );
        const forbidden = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--profile', 'fast'],
          analysis,
        );
        const hostile = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--bad\u001b[2J'],
          analysis,
        );
        const hostileC1 = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--bad\u009b2J'],
          analysis,
        );

        expect(Exit.isFailure(confused.exit)).toBe(true);
        if (Exit.isSuccess(confused.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(confused.exit.cause))).toBe(64);
        expect(confused.stdout).toBe('');
        expect(confused.stderr).toContain('owner/repository');

        expect(Exit.isFailure(pathConfused.exit)).toBe(true);
        if (Exit.isSuccess(pathConfused.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(pathConfused.exit.cause))).toBe(64);
        expect(pathConfused.stdout).toBe('');
        expect(pathConfused.stderr).toContain('Scan path');

        expect(Exit.isFailure(forbidden.exit)).toBe(true);
        if (Exit.isSuccess(forbidden.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(forbidden.exit.cause))).toBe(64);
        expect(forbidden.stdout).toBe('');
        expect(forbidden.stderr).toBe('radar: Invalid command syntax.\n');

        expect(Exit.isFailure(hostile.exit)).toBe(true);
        expect(hostile.stdout).toBe('');
        expect(hostile.stderr).toBe('radar: Invalid command syntax.\n');
        expect(hostile.stderr).not.toContain('\u001b');

        expect(Exit.isFailure(hostileC1.exit)).toBe(true);
        expect(hostileC1.stdout).toBe('');
        expect(hostileC1.stderr).toBe('radar: Invalid command syntax.\n');
        expect(hostileC1.stderr).not.toContain('\u009b');
      }),
    ));

  it('rejects every duplicated option instead of accepting the first value', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisInterrupted({ message: 'must not run' })),
        }));
        const duplicatedArguments = [
          ['scan', 'github', 'Acme/radar-sample', '--format', 'human', '--format', 'json'],
          ['scan', 'github', 'Acme/radar-sample', '--baseline', 'first', '--baseline', 'second'],
          ['scan', 'github', 'Acme/radar-sample', '--output', 'first', '--output', 'second'],
          ['scan', 'github', 'Acme/radar-sample', '--quiet', '--quiet'],
          ['scan', 'github', 'Acme/radar-sample', '--fail-on', 'never', '--fail-on', 'any'],
          ['doctor', '--format', 'human', '--format', 'json'],
          ['doctor', '--output', 'first', '--output', 'second'],
          ['--help', '--help'],
          ['--version', '--version'],
        ];
        const executions = yield* Effect.forEach(
          duplicatedArguments,
          arguments_ => run(arguments_, analysis),
        );

        for (const execution of executions) {
          expect(Exit.isFailure(execution.exit)).toBe(true);
          if (Exit.isSuccess(execution.exit)) continue;
          expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(64);
          expect(execution.stdout).toBe('');
          expect(execution.stderr).toBe('radar: Invalid command syntax.\n');
        }
      }),
    ));

  it('escapes C1 controls before diagnostics can reach stderr', () => {
    const rendered = safeDiagnosticText('bad\u009b31m token=very-secret-value');
    expect(rendered).toContain('\\u009b');
    expect(rendered).not.toContain('\u009b');
    expect(rendered).toContain('<redacted>');
  });

  it('writes a completed result before applying an explicit fail-on gate', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const decoded = yield* decodeScanResultJson(artifact('complete-scan-result.json'));
        expect(decoded.resultKind).toBe('complete');
        if (decoded.resultKind !== 'complete') return;
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.succeed(decoded),
        }));
        const execution = yield* run(
          [
            'scan',
            'github',
            'Acme/radar-sample',
            '--format',
            'json',
            '--quiet',
            '--fail-on',
            'any',
          ],
          analysis,
        );

        expect(Exit.isFailure(execution.exit)).toBe(true);
        if (Exit.isSuccess(execution.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(2);
        expect(yield* decodeScanResultJson(execution.stdout)).toEqual(decoded);
        expect(execution.stderr).toContain('--fail-on any');
      }),
    ));

  it('renders the canonical ready runtime report through the injected doctor port', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisInterrupted({ message: 'unused' })),
        }));
        const execution = yield* run(
          ['doctor', '--format', 'json'],
          analysis,
        );

        expect(Exit.isSuccess(execution.exit)).toBe(true);
        expect(execution.stderr).toBe('');
        expect(execution.stdout).toBe(`${yield* encodeDoctorReportJson(readyRuntimeReport)}\n`);
        expect(readyRuntimeReport.evidence).toHaveLength(RequiredAnalyzerIds.length);
      }),
    ));

  it('renders canonical non-ready evidence before exiting with the runtime code', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisInterrupted({ message: 'unused' })),
        }));
        const doctorService = RadarDoctor.of({
          inspect: Effect.succeed(degradedRuntimeReport),
        });
        const execution = yield* run(
          ['doctor', '--format', 'json'],
          analysis,
          false,
          doctorService,
        );

        expect(Exit.isFailure(execution.exit)).toBe(true);
        if (Exit.isSuccess(execution.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(69);
        expect(execution.stdout).toBe(`${yield* encodeDoctorReportJson(degradedRuntimeReport)}\n`);
        expect(execution.stderr).toBe('radar: Runtime preflight is not ready.\n');
      }),
    ));

  it('maps typed analysis interruption to exit code 130', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisInterrupted({ message: 'Cancelled.' })),
        }));
        const execution = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--quiet'],
          analysis,
        );

        expect(Exit.isFailure(execution.exit)).toBe(true);
        if (Exit.isSuccess(execution.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(130);
      }),
    ));

  it('maps unavailable analysis runtime failures to a stable runtime exit code', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.fail(new AnalysisRuntimeUnavailable({
            message: 'Runtime preflight was unavailable.',
          })),
        }));
        const execution = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--quiet'],
          analysis,
        );

        expect(Exit.isFailure(execution.exit)).toBe(true);
        if (Exit.isSuccess(execution.exit)) return;
        expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(69);
        expect(execution.stdout).toBe('');
        expect(execution.stderr).toContain('Runtime preflight was unavailable.');
      }),
    ));

  it('accepts a strict baseline and keeps result output out of stdout when --output is used', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const baselinePath = yield* filesystem.makeTempFile({ prefix: 'radar-baseline-' });
        const outputPath = yield* filesystem.makeTempFile({ prefix: 'radar-output-' });
        const check = Effect.gen(function* () {
          const decoded = yield* decodeScanResultJson(artifact('complete-scan-result.json'));
          expect(decoded.resultKind).toBe('complete');
          if (decoded.resultKind !== 'complete') return;
          const baseline = new SuccessfulScanResult({
            ...decoded,
            scanId: 'scan-baseline-001',
            createdAt: '2026-08-01T00:00:00.000Z',
            completedAt: '2026-08-01T00:07:00.000Z',
          });
          yield* filesystem.writeFileString(
            baselinePath,
            yield* encodeScanResultJson(baseline),
          );
          const request = yield* Ref.make<Option.Option<AnalysisRequest>>(Option.none());
          const analysis = successfulAnalysis(RadarAnalysis.of({
            analyze: next => Ref.set(request, Option.some(next)).pipe(Effect.as(decoded)),
          }));
          const execution = yield* run(
            [
              'scan',
              'github',
              'Acme/radar-sample',
              '--baseline',
              baselinePath,
              '--output',
              outputPath,
              '--format',
              'json',
              '--quiet',
            ],
            analysis,
          );

          expect(Exit.isSuccess(execution.exit)).toBe(true);
          expect(execution.stdout).toBe('');
          expect(execution.stderr).toBe('');
          expect(yield* decodeScanResultJson(yield* filesystem.readFileString(outputPath))).toEqual(decoded);
          const captured = yield* Ref.get(request);
          expect(Option.isSome(captured)).toBe(true);
          if (Option.isNone(captured)) return;
          expect(captured.value.baseline?.scanId).toBe('scan-baseline-001');
        });
        yield* check.pipe(
          Effect.ensuring(
            filesystem.remove(baselinePath, { force: true }).pipe(
              Effect.andThen(filesystem.remove(outputPath, { force: true })),
              Effect.ignore,
            ),
          ),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    ));

  it('rejects a symbolic-link baseline before reading its target', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const filesystem = yield* FileSystem.FileSystem;
        const paths = yield* Path.Path;
        const directory = yield* filesystem.makeTempDirectory({ prefix: 'radar-baseline-link-' });
        const baselinePath = paths.join(directory, 'baseline.json');
        const symlinkPath = paths.join(directory, 'baseline-link.json');
        const check = Effect.gen(function* () {
          yield* filesystem.writeFileString(
            baselinePath,
            artifact('complete-scan-result.json'),
          );
          symlinkSync(baselinePath, symlinkPath);
          const analysis = successfulAnalysis(RadarAnalysis.of({
            analyze: () => Effect.fail(new AnalysisInterrupted({
              message: 'Analysis must not run for a symbolic-link baseline.',
            })),
          }));
          const execution = yield* run(
            [
              'scan',
              'github',
              'Acme/radar-sample',
              '--baseline',
              symlinkPath,
              '--quiet',
            ],
            analysis,
          );

          expect(Exit.isFailure(execution.exit)).toBe(true);
          if (Exit.isSuccess(execution.exit)) return;
          expect(Runtime.getErrorExitCode(Cause.squash(execution.exit.cause))).toBe(64);
          expect(execution.stdout).toBe('');
          expect(execution.stderr).toBe(
            'radar: Baseline must be a bounded regular non-symlink file.\n',
          );
        });
        yield* check.pipe(
          Effect.ensuring(
            filesystem.remove(directory, { recursive: true, force: true }).pipe(Effect.ignore),
          ),
        );
      }).pipe(Effect.provide(NodeServices.layer)),
    ));

  it('uses Command.runWith built-in help while preserving a zero help exit code', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const decoded = yield* decodeScanResultJson(artifact('complete-scan-result.json'));
        expect(decoded.resultKind).toBe('complete');
        if (decoded.resultKind !== 'complete') return;
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.succeed(decoded),
        }));
        const captured = yield* captureStdio(['scan', 'github', '--help']);
        const exit = yield* Effect.exit(
          runRadarCli({ isTty: false }).pipe(
            Effect.provideService(RadarAnalysis, analysis),
            Effect.provideService(RadarDoctor, doctor),
            Effect.provide(captured.layer),
          ),
        );
        const lines = yield* TestConsole.logLines;

        expect(Exit.isSuccess(exit)).toBe(true);
        expect(lines).toEqual([]);
        expect(yield* Ref.get(captured.stdout)).toContain('GitHub source');
        expect(yield* Ref.get(captured.stderr)).toBe('');
      }).pipe(
        Effect.provide(TestConsole.layer),
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('preserves an external cancellation as an interruption-only exit code', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const analysis = successfulAnalysis(RadarAnalysis.of({
          analyze: () => Effect.interrupt,
        }));
        const execution = yield* run(
          ['scan', 'github', 'Acme/radar-sample', '--quiet'],
          analysis,
        );

        expect(Exit.isFailure(execution.exit)).toBe(true);
        let exitCode = -1;
        Runtime.defaultTeardown(execution.exit, code => {
          exitCode = code;
        });
        expect(exitCode).toBe(130);
      }),
    ));

  it('rejects a report that violates the canonical runtime invariants', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const hostile = new RadarRuntimeReport({
          ...readyRuntimeReport,
          evidence: readyRuntimeReport.evidence.map((evidence, index) =>
            new RadarRuntimeEvidence({
              ...evidence,
              status: index === 0 ? 'unavailable' : 'ready',
            })),
        });
        const exit = yield* Effect.exit(
          decodeDoctorReport(hostile),
        );

        expect(Exit.isFailure(exit)).toBe(true);
      }),
    ));
});
