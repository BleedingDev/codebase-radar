import {
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AnalysisRequest,
  AnalysisRuntimeUnavailable,
  LocalDirectorySource,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
import { runtimeTrustAnchor } from '@codebase-radar/analyzer-runtime/trust-anchor';
import { Effect } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalysisObserverNoop,
  makeRadarProductionLayer,
  makeUnavailableRadarRuntimePreflight,
  RadarAnalysis,
  verifyTrustedRadarAnalyzerRuntime,
} from '../src/index.js';

const request = new AnalysisRequest({
  scanId: 'scan-production-preflight',
  source: new LocalDirectorySource({
    directory: '/source-must-not-be-materialized',
    codebaseId: 'local:source-must-not-be-materialized',
  }),
  createdAt: '2026-08-11T00:00:00.000Z',
});

describe('supported production composition', () => {
  it('returns the canonical exact unavailable report without fabricated readiness', () => {
    const preflight = makeUnavailableRadarRuntimePreflight();
    const report = Effect.runSync(preflight.report());
    expect(report.status).toBe('unavailable');
    expect(report.evidence.map(evidence => evidence.analyzer)).toEqual(RequiredAnalyzerIds);
    expect(report.evidence.every(evidence => evidence.status === 'unavailable')).toBe(true);
    expect(report.manifest).toMatchObject({
      policyDigest: `sha256:${runtimeTrustAnchor.policyDigest}`,
      buildIdentity: runtimeTrustAnchor.buildIdentity,
    });
    expect(Effect.runSync(Effect.flip(preflight.check()))).toBeInstanceOf(
      AnalysisRuntimeUnavailable,
    );
  });

  it('uses the core-installed verifier rather than target verifier or anchor modules', () => {
    const runtimeRoot = mkdtempSync(join(tmpdir(), 'radar-target-verifier-'));
    const marker = join(runtimeRoot, 'target-module-imported');
    try {
      writeFileSync(
        join(runtimeRoot, 'runtime-verifier.mjs'),
        `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'bad');`,
      );
      writeFileSync(
        join(runtimeRoot, 'trust-anchor.mjs'),
        `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'bad');`,
      );

      expect(Effect.runSync(Effect.flip(
        verifyTrustedRadarAnalyzerRuntime({
          runtimeRoot,
          resourceCgroupRoot: runtimeRoot,
          analyzerControlRoot: runtimeRoot,
        }),
      ))).toBeInstanceOf(AnalysisRuntimeUnavailable);
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(runtimeRoot, { force: true, recursive: true });
    }
  });

  it('checks the runtime before any source materialization path can run', () => {
    const runtimeRoot = mkdtempSync(join(tmpdir(), 'radar-untrusted-runtime-'));
    try {
      const rejected = Effect.runSync(
        Effect.gen(function* () {
          const analysis = yield* RadarAnalysis;
          return yield* Effect.flip(analysis.analyze(request));
        }).pipe(
          Effect.provide(AnalysisObserverNoop),
          Effect.provide(makeRadarProductionLayer({
            runtimeRoot,
            workspaceParent: runtimeRoot,
            resourceCgroupRoot: runtimeRoot,
            analyzerControlRoot: runtimeRoot,
          })),
        ),
      );
      expect(rejected).toBeInstanceOf(AnalysisRuntimeUnavailable);
    } finally {
      rmSync(runtimeRoot, { force: true, recursive: true });
    }
  });
});
