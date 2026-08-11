import {
  Console,
  Crypto,
  Effect,
  FileSystem,
  Layer,
  Option,
  Path,
  Ref,
  Stdio,
} from 'effect';
import {
  Argument,
  CliConfig,
  CliError,
  Command,
  Flag,
  GlobalFlag,
} from 'effect/unstable/cli';
import {
  AnalysisObserver,
  AnalysisObserverNoop,
  RadarAnalysis,
} from '@codebase-radar/core';
import type { AnalysisFailure, AnalysisSource } from '@codebase-radar/contracts';
import {
  RadarDoctor,
  decodeDoctorReport,
  encodeDoctorReportJson,
} from './doctor.js';
import {
  CliAnalysisError,
  CliCommandError,
  CliFailOnError,
  CliInterruptedError,
  CliOutputError,
  CliRuntimeError,
  CliUsageError,
} from './errors.js';
import {
  makeAnalysisRequest,
  makeGitHubSource,
  makeLocalDirectorySource,
  readBaseline,
} from './input.js';
import { writeResult, writeStderr, writeStdout } from './io.js';
import { presentProgress } from './progress.js';
import {
  applyFailOn,
  encodeScanOutput,
} from './result.js';
import type { FailOn, OutputFormat } from './result.js';
import {
  renderHumanDoctorReport,
} from './render.js';
import { safeDiagnosticText, safeHumanText } from './text.js';

const version = '0.1.0';

export interface RadarCliOptions {
  readonly isTty: boolean;
}

interface ScanSettings {
  readonly format: OutputFormat;
  readonly baseline: Option.Option<string>;
  readonly output: Option.Option<string>;
  readonly quiet: boolean;
  readonly failOn: FailOn;
}

interface DoctorSettings {
  readonly format: OutputFormat;
  readonly output: Option.Option<string>;
}

const singleFlag = <A>(flag: Flag.Flag<A>, fallback: A) =>
  flag.pipe(
    Flag.atMost(1),
    Flag.map(values => values.at(0) ?? fallback),
  );

const optionalStringFlag = (name: string, description: string) =>
  Flag.string(name).pipe(
    Flag.atMost(1),
    Flag.map(values => Option.fromUndefinedOr(values.at(0))),
    Flag.withDescription(description),
  );

const strictGlobalFlag = (flag: GlobalFlag.Action<boolean>) =>
  GlobalFlag.action({
    flag: singleFlag(flag.flag, false),
    run: flag.run,
  });

const cliConfig = CliConfig.layer({
  builtIns: [
    strictGlobalFlag(GlobalFlag.Help),
    strictGlobalFlag(GlobalFlag.Version),
  ],
});

const scanFlags = () => ({
  format: singleFlag(Flag.choice('format', ['human', 'json']), 'human').pipe(
    Flag.withDescription('Render the accepted result as human text or strict JSON.'),
  ),
  baseline: optionalStringFlag(
    'baseline',
    'Read a prior strict successful Scan Result for comparison.',
  ),
  output: optionalStringFlag(
    'output',
    'Write the complete rendered result atomically to this file.',
  ),
  quiet: singleFlag(Flag.boolean('quiet'), false).pipe(
    Flag.withDescription('Suppress progress messages on stderr.'),
  ),
  failOn: singleFlag(Flag.choice('fail-on', [
    'never',
    'fix-now',
    'investigate',
    'monitor',
    'any',
  ]), 'never').pipe(
    Flag.withDescription('After rendering, fail when findings meet this presentation gate.'),
  ),
});

const doctorFlags = () => ({
  format: singleFlag(Flag.choice('format', ['human', 'json']), 'human').pipe(
    Flag.withDescription('Render runtime-preflight evidence as human text or strict JSON.'),
  ),
  output: optionalStringFlag(
    'output',
    'Write the complete rendered doctor report atomically to this file.',
  ),
});

const analysisFailureToCliFailure = (failure: AnalysisFailure) => {
  if (failure._tag === 'AnalysisSourceRejected') {
    return new CliUsageError({ message: safeDiagnosticText(failure.message) });
  }
  if (failure._tag === 'AnalysisSourceUnavailable') {
    return new CliRuntimeError({ message: safeDiagnosticText(failure.message) });
  }
  if (failure._tag === 'AnalysisRuntimeUnavailable') {
    return new CliRuntimeError({ message: safeDiagnosticText(failure.message) });
  }
  if (failure._tag === 'AnalysisInterrupted') {
    return new CliInterruptedError({ message: safeDiagnosticText(failure.message) });
  }
  return new CliAnalysisError({
    message: `Analysis is incomplete: ${failure.violations.map(violation => (
      violation.analyzer === undefined ? violation.code : `${violation.analyzer}:${violation.code}`
    )).join(', ')}.`,
  });
};

const observerLayer = (
  options: RadarCliOptions,
  quiet: boolean,
  stdio: Stdio.Stdio,
  progressFailure: Ref.Ref<Option.Option<CliOutputError>>,
) =>
  quiet
    ? AnalysisObserverNoop
    : Layer.succeed(
      AnalysisObserver,
      AnalysisObserver.of({
        observe: progress => presentProgress({ quiet, isTty: options.isTty }, progress).pipe(
          Effect.catchTag('CliOutputError', error => Ref.set(progressFailure, Option.some(error))),
          Effect.provideService(Stdio.Stdio, stdio),
        ),
      }),
    );

const runScan = (
  options: RadarCliOptions,
  source: Effect.Effect<
    AnalysisSource,
    CliRuntimeError | CliUsageError,
    Crypto.Crypto | FileSystem.FileSystem | Path.Path
  >,
  settings: ScanSettings,
) =>
  Effect.gen(function* () {
    const stdio = yield* Stdio.Stdio;
    const progressFailure = yield* Ref.make<Option.Option<CliOutputError>>(Option.none());
    const requestedSource = yield* source;
    const baseline = yield* readBaseline(Option.getOrUndefined(settings.baseline));
    const request = yield* makeAnalysisRequest(requestedSource, baseline);
    const analysis = yield* RadarAnalysis;
    const result = yield* analysis.analyze(request).pipe(
      Effect.provide(observerLayer(options, settings.quiet, stdio, progressFailure)),
      Effect.mapError(analysisFailureToCliFailure),
    );
    const reportedProgressFailure = yield* Ref.get(progressFailure);
    if (Option.isSome(reportedProgressFailure)) {
      return yield* Effect.fail(reportedProgressFailure.value);
    }
    const contents = yield* encodeScanOutput(result, settings.format);
    yield* writeResult(contents, Option.getOrUndefined(settings.output));
    yield* applyFailOn(result, settings.failOn);
  });

const makePathCommand = (options: RadarCliOptions) =>
  Command.make(
    'path',
    {
      directory: Argument.string('directory').pipe(
        Argument.withDescription('Local directory to analyze.'),
      ),
      ...scanFlags(),
    },
    settings => runScan(options, makeLocalDirectorySource(settings.directory), settings),
  ).pipe(
    Command.withDescription('Analyze one local directory with the fixed dogfood:max policy.'),
  );

const makeGitHubCommand = (options: RadarCliOptions) =>
  Command.make(
    'github',
    {
      locator: Argument.string('owner/repository').pipe(
        Argument.withDescription('Canonical GitHub owner/repository locator.'),
      ),
      revision: Argument.string('revision').pipe(
        Argument.optional,
        Argument.withDescription('Optional branch:<name>, tag:<name>, or commit:<sha> revision.'),
      ),
      ...scanFlags(),
    },
    settings => runScan(
      options,
      makeGitHubSource(settings.locator, Option.getOrUndefined(settings.revision)),
      settings,
    ),
  ).pipe(
    Command.withDescription('Analyze one GitHub source with the fixed dogfood:max policy.'),
  );

const makeDoctorCommand = () =>
  Command.make(
    'doctor',
    doctorFlags(),
    settings => Effect.gen(function* () {
      const doctor = yield* RadarDoctor;
      const report = yield* doctor.inspect.pipe(
        Effect.mapError(error => new CliRuntimeError({ message: safeDiagnosticText(error.message) })),
      );
      const validatedReport = yield* decodeDoctorReport(report).pipe(
        Effect.mapError(() => new CliRuntimeError({
          message: 'Runtime preflight returned an invalid doctor report.',
        })),
      );
      const contents = settings.format === 'human'
        ? renderHumanDoctorReport(validatedReport)
        : `${yield* encodeDoctorReportJson(validatedReport).pipe(
          Effect.mapError(() => new CliRuntimeError({
            message: 'Runtime preflight returned an invalid doctor report.',
          })),
        )}\n`;
      yield* writeResult(contents, Option.getOrUndefined(settings.output));
      if (validatedReport.status !== 'ready') {
        return yield* Effect.fail(new CliRuntimeError({
          message: 'Runtime preflight is not ready.',
        }));
      }
    }),
  ).pipe(
    Command.withDescription('Inspect runtime-preflight evidence without running an analysis.'),
  );

export const makeRadarCommand = (options: RadarCliOptions) => {
  const scan = Command.make('scan').pipe(
    Command.withDescription('Run the fixed, complete codebase analysis.'),
    Command.withSubcommands([
      makePathCommand(options),
      makeGitHubCommand(options),
    ]),
  );
  return Command.make('radar').pipe(
    Command.withDescription('Codebase Radar command line interface.'),
    Command.withSubcommands([
      scan,
      makeDoctorCommand(),
    ]),
  );
};

const reportFailure = (
  failure:
    | CliUsageError
    | CliRuntimeError
    | CliAnalysisError
    | CliCommandError
    | CliOutputError
    | CliFailOnError,
) =>
  writeStderr(`radar: ${safeDiagnosticText(failure.message)}\n`).pipe(
    Effect.andThen(Effect.fail(failure)),
    Effect.catchTag('CliOutputError', () => Effect.fail(failure)),
  );

const handleShowHelp = (error: CliError.ShowHelp, renderedHelp: string): Effect.Effect<
  never,
  CliCommandError | CliOutputError | CliError.ShowHelp,
  Stdio.Stdio
> =>
  error.errors.length === 0
    ? writeStdout(renderedHelp).pipe(Effect.andThen(Effect.fail(error)))
    : Effect.fail(new CliCommandError({ message: 'Invalid command syntax.' }));

export const runRadarCli = (options: RadarCliOptions) =>
  Effect.gen(function* () {
    const stdio = yield* Stdio.Stdio;
    const arguments_ = yield* stdio.args.pipe(
      Effect.mapError(() => new CliRuntimeError({ message: 'Unable to read command line arguments.' })),
    );
    const consoleOutput = new Array<string>();
    const capturedConsole: Console.Console = {
      ...globalThis.console,
      log: (...values) => {
        consoleOutput.push(values.map(value => String(value)).join(' '));
      },
      error: () => undefined,
    };
    const renderedHelp = () => {
      const contents = consoleOutput
        .map(value => value.split('\n').map(safeHumanText).join('\n'))
        .join('\n')
        .trimEnd();
      return contents.length === 0 ? '' : `${contents}\n`;
    };
    return yield* Command.runWith(makeRadarCommand(options), { version })(arguments_).pipe(
      Effect.provide(cliConfig),
      Effect.provideService(Console.Console, capturedConsole),
      Effect.catchTag('DuplicateOption', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('InvalidValue', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('MissingArgument', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('MissingOption', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('UnexpectedArgument', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('UnknownSubcomand', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('UnrecognizedOption', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('UserError', () => Effect.fail(
        new CliCommandError({ message: 'Invalid command syntax.' }),
      )),
      Effect.catchTag('ShowHelp', error => handleShowHelp(error, renderedHelp())),
      Effect.tap(() => {
        const output = renderedHelp();
        return output.length === 0 ? Effect.void : writeStdout(output);
      }),
    );
  }).pipe(
    Effect.catchTag('CliUsageError', reportFailure),
    Effect.catchTag('CliRuntimeError', reportFailure),
    Effect.catchTag('CliAnalysisError', reportFailure),
    Effect.catchTag('CliOutputError', reportFailure),
    Effect.catchTag('CliFailOnError', reportFailure),
    Effect.catchTag('CliInterruptedError', failure => Effect.fail(failure)),
    Effect.catchTag('CliCommandError', reportFailure),
  );
