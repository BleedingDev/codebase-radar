import { Runtime, Schema } from 'effect';

export class CliUsageError extends Schema.TaggedErrorClass<CliUsageError>()(
  'CliUsageError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 64;
  override readonly [Runtime.errorReported] = false;
}

export class CliCommandError extends Schema.TaggedErrorClass<CliCommandError>()(
  'CliCommandError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 64;
  override readonly [Runtime.errorReported] = false;
}

export class CliRuntimeError extends Schema.TaggedErrorClass<CliRuntimeError>()(
  'CliRuntimeError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 69;
  override readonly [Runtime.errorReported] = false;
}

export class CliAnalysisError extends Schema.TaggedErrorClass<CliAnalysisError>()(
  'CliAnalysisError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 70;
  override readonly [Runtime.errorReported] = false;
}

export class CliOutputError extends Schema.TaggedErrorClass<CliOutputError>()(
  'CliOutputError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 74;
  override readonly [Runtime.errorReported] = false;
}

export class CliFailOnError extends Schema.TaggedErrorClass<CliFailOnError>()(
  'CliFailOnError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 2;
  override readonly [Runtime.errorReported] = false;
}

export class CliInterruptedError extends Schema.TaggedErrorClass<CliInterruptedError>()(
  'CliInterruptedError',
  { message: Schema.String },
) {
  override readonly [Runtime.errorExitCode] = 130;
  override readonly [Runtime.errorReported] = false;
}

export type RadarCliFailure =
  | CliUsageError
  | CliCommandError
  | CliRuntimeError
  | CliAnalysisError
  | CliOutputError
  | CliFailOnError
  | CliInterruptedError;
