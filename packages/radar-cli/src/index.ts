export {
  makeRadarCommand,
  runRadarCli,
} from './cli.js';
export type { RadarCliOptions } from './cli.js';
export {
  DoctorUnavailable,
  RadarDoctor,
  decodeDoctorReport,
  decodeDoctorReportJson,
  encodeDoctorReportJson,
} from './doctor.js';
export type { DoctorReport } from './doctor.js';
export {
  CliAnalysisError,
  CliCommandError,
  CliFailOnError,
  CliInterruptedError,
  CliOutputError,
  CliRuntimeError,
  CliUsageError,
} from './errors.js';
export type { RadarCliFailure } from './errors.js';
export {
  applyFailOn,
  encodeScanOutput,
} from './result.js';
export type { FailOn, OutputFormat } from './result.js';
export {
  renderHumanDoctorReport,
  renderHumanScanResult,
  safeHumanText,
} from './render.js';
