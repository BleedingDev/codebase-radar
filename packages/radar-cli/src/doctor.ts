import { decodeRadarRuntimeReport, RadarRuntimeReportSchema } from '@codebase-radar/core';
import type { RadarRuntimeReport } from '@codebase-radar/core';
import { Context, Effect, Schema } from 'effect';

/** The doctor protocol is the core runtime report, not a CLI-local shadow. */
export type DoctorReport = RadarRuntimeReport;

const parseDoctorReportJson = Schema.decodeUnknownEffect(
  Schema.fromJsonString(Schema.Json),
);
export const decodeDoctorReport = decodeRadarRuntimeReport;

export const decodeDoctorReportJson = (contents: string) =>
  parseDoctorReportJson(contents).pipe(Effect.flatMap(decodeDoctorReport));

export const encodeDoctorReportJson = (report: DoctorReport) =>
  Schema.encodeEffect(RadarRuntimeReportSchema)(report).pipe(
    Effect.map(value => JSON.stringify(value)),
  );

export class DoctorUnavailable extends Schema.TaggedErrorClass<DoctorUnavailable>()(
  'DoctorUnavailable',
  { message: Schema.String },
) {}

export class RadarDoctor extends Context.Service<RadarDoctor, {
  readonly inspect: Effect.Effect<DoctorReport, DoctorUnavailable>;
}>()('RadarDoctor') {}
