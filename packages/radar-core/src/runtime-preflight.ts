import {
  AnalysisRuntimeUnavailable,
  RequiredAnalyzer,
  RequiredAnalyzerIds,
} from '@codebase-radar/contracts';
import { runtimeTrustAnchor } from '@codebase-radar/analyzer-runtime/trust-anchor';
import { Context, Effect, Schema } from 'effect';

/**
 * The report is intentionally anchored to the runtime package compiled into
 * this build. A structurally plausible manifest must never make a different
 * analyzer image appear ready.
 */
const TrustedPolicyDigest = `sha256:${runtimeTrustAnchor.policyDigest}`;
const TrustedBuildIdentity = runtimeTrustAnchor.buildIdentity;
const RequiredRuntimeAnalyzerCount = 7;

const RuntimeIdentityToken = Schema.String.check(
  Schema.isTrimmed(),
  Schema.isMinLength(1),
  Schema.isMaxLength(256),
  Schema.makeFilter(value =>
    /^[A-Za-z0-9][A-Za-z0-9@._:+-]*$/u.test(value)
      ? undefined
      : 'runtime identities must be bounded safe tokens',
  ),
);

const PolicyDigest = Schema.String.check(
  Schema.makeFilter(value =>
    /^sha256:[0-9a-f]{64}$/u.test(value)
      ? undefined
      : 'policy digest must be a complete lowercase SHA-256 digest',
  ),
);

export const RadarRuntimeStatus = Schema.Literals([
  'ready',
  'degraded',
  'unavailable',
]);

export const RadarRuntimeEvidenceStatus = Schema.Literals([
  'ready',
  'unavailable',
]);

export class RadarRuntimeManifest extends Schema.Class<RadarRuntimeManifest>(
  'RadarRuntimeManifest',
)({
  policyDigest: PolicyDigest,
  buildIdentity: RuntimeIdentityToken,
}) {}

export class RadarRuntimeEvidence extends Schema.Class<RadarRuntimeEvidence>(
  'RadarRuntimeEvidence',
)({
  analyzer: RequiredAnalyzer,
  status: RadarRuntimeEvidenceStatus,
}) {}

export class RadarRuntimeReport extends Schema.Class<RadarRuntimeReport>(
  'RadarRuntimeReport',
)({
  schemaVersion: Schema.Literal('codebase-radar.runtime-report/v1'),
  status: RadarRuntimeStatus,
  manifest: RadarRuntimeManifest,
  evidence: Schema.Array(RadarRuntimeEvidence).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(RequiredAnalyzerIds.length),
  ),
}) {}

export const RadarRuntimeReportSchema = RadarRuntimeReport.check(
  Schema.makeFilter(report => {
    const issues = new Array<Schema.FilterIssue>();
    if (
      RequiredAnalyzerIds.length !== RequiredRuntimeAnalyzerCount ||
      report.evidence.length !== RequiredRuntimeAnalyzerCount ||
      report.evidence.some((evidence, index) =>
        evidence.analyzer !== RequiredAnalyzerIds[index])
    ) {
      issues.push({
        path: ['evidence'],
        issue: 'runtime evidence must contain the exact ordered seven required analyzers',
      });
    }
    if (
      report.manifest.policyDigest !== TrustedPolicyDigest ||
      report.manifest.buildIdentity !== TrustedBuildIdentity
    ) {
      issues.push({
        path: ['manifest'],
        issue: 'runtime manifest must match the compiled trust anchor policy and build identity',
      });
    }
    const readyCount = report.evidence.filter(evidence => evidence.status === 'ready').length;
    const expectedStatus = readyCount === RequiredRuntimeAnalyzerCount
      ? 'ready'
      : readyCount === 0
        ? 'unavailable'
        : 'degraded';
    if (report.status !== expectedStatus) {
      issues.push({
        path: ['status'],
        issue: 'runtime status must be derived from canonical evidence',
      });
    }
    return issues;
  }),
);

export const decodeRadarRuntimeReport = Schema.decodeUnknownEffect(
  RadarRuntimeReportSchema,
  { onExcessProperty: 'error' },
);

const invalidPreflight = () => new AnalysisRuntimeUnavailable({
  message: 'Runtime preflight returned invalid verification evidence.',
});

export interface RadarRuntimePreflightSource {
  readonly inspect: () => Effect.Effect<RadarRuntimeReport, AnalysisRuntimeUnavailable>;
}

export class RadarRuntimePreflight extends Context.Service<RadarRuntimePreflight, {
  readonly check: () => Effect.Effect<RadarRuntimeReport, AnalysisRuntimeUnavailable>;
  readonly report: () => Effect.Effect<RadarRuntimeReport, AnalysisRuntimeUnavailable>;
}>()('@codebase-radar/core/RadarRuntimePreflight') {}

export const makeRadarRuntimePreflight = (
  source: RadarRuntimePreflightSource,
) => {
  const report = () => source.inspect().pipe(
    Effect.flatMap(decodeRadarRuntimeReport),
    Effect.mapError(invalidPreflight),
  );
  return RadarRuntimePreflight.of({
    report,
    check: () => report().pipe(
      Effect.flatMap(value => value.status === 'ready'
        ? Effect.succeed(value)
        : Effect.fail(new AnalysisRuntimeUnavailable({
          message: 'The verified analyzer runtime is not ready.',
        }))),
    ),
  });
};
