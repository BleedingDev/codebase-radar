import {
  type AnalysisFailure,
  type AnalysisProgress,
  type AnalysisRequest,
  SuccessfulScanResult,
} from '@codebase-radar/contracts';
import { Context, Effect, Layer } from 'effect';

export class AnalysisObserver extends Context.Service<AnalysisObserver, {
  readonly observe: (progress: AnalysisProgress) => Effect.Effect<void>;
}>()('@codebase-radar/core/AnalysisObserver') {}

export const AnalysisObserverNoop = Layer.succeed(
  AnalysisObserver,
  AnalysisObserver.of({ observe: () => Effect.void }),
);

export class RadarAnalysis extends Context.Service<RadarAnalysis, {
  readonly analyze: (
    request: AnalysisRequest,
  ) => Effect.Effect<SuccessfulScanResult, AnalysisFailure, AnalysisObserver>;
}>()('@codebase-radar/core/RadarAnalysis') {}
