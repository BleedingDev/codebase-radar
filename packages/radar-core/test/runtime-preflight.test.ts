import {
  AnalysisRuntimeUnavailable,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
import { runtimeTrustAnchor } from '@codebase-radar/analyzer-runtime/trust-anchor';
import { Effect, Exit } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  RadarRuntimeEvidence,
  RadarRuntimeManifest,
  RadarRuntimeReport,
  decodeRadarRuntimeReport,
  makeRadarRuntimePreflight,
} from '../src/runtime-preflight.js';

const manifest = new RadarRuntimeManifest({
  policyDigest: `sha256:${runtimeTrustAnchor.policyDigest}`,
  buildIdentity: runtimeTrustAnchor.buildIdentity,
});

const report = (status: 'ready' | 'degraded' | 'unavailable') => {
  const readyCount = status === 'ready'
    ? RequiredAnalyzerIds.length
    : status === 'degraded'
      ? 1
      : 0;
  return new RadarRuntimeReport({
    schemaVersion: 'codebase-radar.runtime-report/v1',
    status,
    manifest,
    evidence: RequiredAnalyzerIds.map((analyzer, index) => new RadarRuntimeEvidence({
      analyzer,
      status: index < readyCount ? 'ready' : 'unavailable',
    })),
  });
};

describe('RadarRuntimeReport', () => {
  it('requires the exact ordered seven analyzer evidence rows and derived aggregate', () => {
    const malformed = {
      schemaVersion: 'codebase-radar.runtime-report/v1',
      status: 'ready',
      manifest: {
        policyDigest: `sha256:${runtimeTrustAnchor.policyDigest}`,
        buildIdentity: runtimeTrustAnchor.buildIdentity,
      },
      evidence: RequiredAnalyzerIds.map((analyzer, index) => ({
        analyzer: index === 1 ? RequiredAnalyzerIds[0] : analyzer,
        status: 'ready',
      })),
    };
    const exit = Effect.runSync(Effect.exit(decodeRadarRuntimeReport(malformed)));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('rejects a structurally valid report from a different policy or build', () => {
    const foreign = {
      schemaVersion: 'codebase-radar.runtime-report/v1',
      status: 'ready',
      manifest: {
        policyDigest: `sha256:${'f'.repeat(64)}`,
        buildIdentity: 'other-runtime-build@v1',
      },
      evidence: RequiredAnalyzerIds.map(analyzer => ({ analyzer, status: 'ready' })),
    };
    const exit = Effect.runSync(Effect.exit(decodeRadarRuntimeReport(foreign)));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('fails check for unavailable or degraded evidence while report remains diagnostic', () => {
    const preflight = makeRadarRuntimePreflight({
      inspect: () => Effect.succeed(report('unavailable')),
    });
    const diagnostic = Effect.runSync(preflight.report());
    const rejected = Effect.runSync(Effect.flip(preflight.check()));
    expect(diagnostic.status).toBe('unavailable');
    expect(rejected).toBeInstanceOf(AnalysisRuntimeUnavailable);
  });

  it('accepts check only when every exact analyzer row is ready', () => {
    const preflight = makeRadarRuntimePreflight({
      inspect: () => Effect.succeed(report('ready')),
    });
    expect(Effect.runSync(preflight.check()).status).toBe('ready');
  });
});
