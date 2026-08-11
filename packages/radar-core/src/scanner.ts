import { Context, Layer } from 'effect';
import { RadarAnalysis } from './scanner-service.js';

/**
 * An explicit public wrapper for an already constructed analysis implementation.
 * It does not install an unavailable source, runtime, workspace, or observer
 * adapter. Integrations must supply a verified implementation deliberately.
 */
export const RadarAnalysisLive = (
  implementation: Context.Service.Shape<typeof RadarAnalysis>,
) => Layer.succeed(RadarAnalysis, implementation);

export {
  AnalysisObserver,
  AnalysisObserverNoop,
  RadarAnalysis,
} from './scanner-service.js';
