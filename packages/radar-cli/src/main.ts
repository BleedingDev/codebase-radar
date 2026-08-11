import { Effect, Layer } from 'effect';
import { NodeRuntime, NodeServices } from '@effect/platform-node';
import { isAbsolute } from 'node:path';
import {
  makeRadarProductionLayer,
  makeUnavailableRadarRuntimePreflight,
  RadarAnalysis,
  RadarRuntimePreflight,
} from '@codebase-radar/core';
import { AnalysisRuntimeUnavailable } from '@codebase-radar/contracts';
import { runRadarCli } from './cli.js';
import { DoctorUnavailable, RadarDoctor } from './doctor.js';

const unavailableAnalysis = Layer.succeed(
  RadarAnalysis,
  RadarAnalysis.of({
    analyze: () => Effect.fail(new AnalysisRuntimeUnavailable({
      message: 'No RadarAnalysis live layer has been installed for this CLI runtime.',
    })),
  }),
);

/**
 * There are deliberately no working-directory fallbacks for any host root:
 * a package-installed CLI must not mistake its caller's directory for a
 * verified analyzer runtime, private workspace, delegated cgroup, or trusted
 * independently deployed analyzer-control package.
 */
const isExplicitAbsolutePath = (value: string | undefined): value is string =>
  value !== undefined && isAbsolute(value);

const makeCoreRuntimeLayer = () => {
  const runtimeRoot = process.env.RADAR_ANALYZER_ROOT;
  const workspaceParent = process.env.RADAR_WORKSPACE_PARENT;
  const resourceCgroupRoot = process.env.RADAR_ANALYSIS_CGROUP_ROOT;
  const analyzerControlRoot = process.env.RADAR_ANALYZER_CONTROL_ROOT;
  if (
    !isExplicitAbsolutePath(runtimeRoot) ||
    !isExplicitAbsolutePath(workspaceParent) ||
    !isExplicitAbsolutePath(resourceCgroupRoot) ||
    !isExplicitAbsolutePath(analyzerControlRoot)
  ) {
    return Layer.mergeAll(
      unavailableAnalysis,
      Layer.succeed(RadarRuntimePreflight, makeUnavailableRadarRuntimePreflight()),
    );
  }
  return makeRadarProductionLayer({
    runtimeRoot,
    workspaceParent,
    resourceCgroupRoot,
    analyzerControlRoot,
  });
};

const doctorLayer = Layer.effect(
  RadarDoctor,
  Effect.gen(function* () {
    const preflight = yield* RadarRuntimePreflight;
    return RadarDoctor.of({
      inspect: preflight.report().pipe(
        Effect.mapError(() => new DoctorUnavailable({
          message: 'Runtime preflight could not produce verification evidence.',
        })),
      ),
    });
  }),
);

const coreRuntime = makeCoreRuntimeLayer();

NodeRuntime.runMain(
  runRadarCli({ isTty: process.stderr.isTTY === true }).pipe(
    Effect.provide(doctorLayer),
    Effect.provide(coreRuntime),
    Effect.provide(NodeServices.layer),
  ),
);
