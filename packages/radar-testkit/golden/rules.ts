import { Exit, Schema } from "effect";
import {
  AnalysisPolicyIdentity,
  AnalysisFailure,
  AnalysisProgressStream,
  CodebaseId,
  ContractLimits,
  OpaqueId,
  PathFreeText,
  RequiredAnalyzerIds,
  sanitizeContractText,
  SuccessfulScanResultSchema,
} from "../../radar-contracts/src/index.js";
import {
  defineNormalizationSchema,
  type NormalizationRule,
} from "../src/index.js";
import {
  ScriptedAnalyzerRun,
  ScriptedAnalyzerSnapshot,
} from "../src/runtime/scripted-analyzer-runtime.js";

const strictCompleteResult = Schema.decodeUnknownExit(
  SuccessfulScanResultSchema,
  { onExcessProperty: "error" },
);

const strictProgressStream = Schema.decodeUnknownExit(AnalysisProgressStream, {
  onExcessProperty: "error",
});

const strictAnalysisPolicyIdentity = Schema.decodeUnknownExit(
  AnalysisPolicyIdentity,
);

const strictCodebaseId = Schema.decodeUnknownExit(CodebaseId);

const CanonicalScanResult = Schema.Json.check(
  Schema.makeFilter(value =>
    Exit.isSuccess(strictCompleteResult(value))
      ? undefined
      : "Expected a strict canonical complete Scan Result.",
  ),
);

const StrictProgressStream = Schema.Json.check(
  Schema.makeFilter(value =>
    Exit.isSuccess(strictProgressStream(value))
      ? undefined
      : "Expected a strict monotonic AnalysisProgress stream.",
  ),
);

const scanResultRules = [
  { path: ["scanId"], kind: "run-id" },
  { path: ["createdAt"], kind: "timestamp" },
  { path: ["completedAt"], kind: "timestamp" },
  { path: ["analyzerRuns", "*", "durationMs"], kind: "duration" },
] satisfies readonly NormalizationRule[];

/**
 * The only normalized Scan Result values are explicitly typed run metadata.
 * Source identity, manifest-tied analyzer tuples, findings, evidence,
 * comparison, and ordering remain semantic and are deliberately not rewritten.
 */
export const completeScanResultNormalization = defineNormalizationSchema(
  CanonicalScanResult,
  scanResultRules,
);

export const cliJsonResultNormalization = defineNormalizationSchema(
  CanonicalScanResult,
  scanResultRules,
);

export const humanBacklogResultNormalization = defineNormalizationSchema(
  CanonicalScanResult,
  scanResultRules,
);

/**
 * HTTP envelopes are frozen app-owned ScanRecord data. Golden normalization
 * applies only to the strict public result inside that envelope.
 */
export const httpPersistedResultNormalization = defineNormalizationSchema(
  CanonicalScanResult,
  scanResultRules,
);

export const monotonicProgressNormalization = defineNormalizationSchema(
  StrictProgressStream,
  [
    { path: ["*", "scanId"], kind: "run-id" },
    { path: ["*", "timestamp"], kind: "timestamp" },
  ],
);

const RuntimeManifestAnalyzer = Schema.Struct({
  id: Schema.String,
  analyzer: Schema.String,
  version: Schema.String,
  profileVersions: Schema.Array(Schema.String),
});

export const runtimeManifestIdentity = {
  schemaVersion: "codebase-radar.analyzer-runtime/v1",
  manifestVersion: 1,
  analysisPolicy: "dogfood:max/v1",
  digest: "da777485716f9409b819e5d125d1836d0f2b92318428febf667a878e40780f3d",
};

const runtimeManifestIdentityFields = {
  schemaVersion: Schema.Literal(runtimeManifestIdentity.schemaVersion),
  manifestVersion: Schema.Literal(runtimeManifestIdentity.manifestVersion),
  analysisPolicy: Schema.Literal(runtimeManifestIdentity.analysisPolicy),
  digest: Schema.Literal(runtimeManifestIdentity.digest),
};

const RuntimeManifestIdentitySchema = Schema.Struct(
  runtimeManifestIdentityFields,
);

export const runtimeManifestAnalyzerTuples = [
  {
    id: "strictest-comparator",
    analyzer: "strictest-comparator",
    version: "@tsconfig/strictest 2.0.8",
    profileVersions: ["radar.tsconfig-gap/v1"],
  },
  {
    id: "oxlint-ultracite",
    analyzer: "Oxlint + Ultracite",
    version: "1.77.0 + 7.10.2",
    profileVersions: [
      "radar/oxlint-core.mjs",
      "radar/oxlint-react.mjs",
      "radar/oxlint-vue.mjs",
      "radar/oxlint-react-vue.mjs",
    ],
  },
  {
    id: "jscpd",
    analyzer: "JSCPD",
    version: "5.0.14",
    profileVersions: ["radar-duplicates-max/v2"],
  },
  {
    id: "calldiff",
    analyzer: "Calldiff",
    version: "0.4.1",
    profileVersions: ["all-root-call-trees-max/v2"],
  },
  {
    id: "zizmor",
    analyzer: "zizmor",
    version: "1.29.0",
    profileVersions: ["offline-regular/v1"],
  },
  {
    id: "osv-scanner",
    analyzer: "OSV-Scanner",
    version: "2.5.0",
    profileVersions: ["js-lockfiles-offline-pinned/v1"],
  },
  {
    id: "tracedecay",
    analyzer: "TraceDecay",
    version: "0.0.73",
    profileVersions: ["structural-max/v2"],
  },
];

const sameStrings = (
  left: ReadonlyArray<string>,
  right: ReadonlyArray<string>,
) =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const hasExactManifestTuples = (
  analyzers: ReadonlyArray<typeof RuntimeManifestAnalyzer.Type>,
) =>
  analyzers.length === runtimeManifestAnalyzerTuples.length &&
  analyzers.every((analyzer, index) => {
    const expected = runtimeManifestAnalyzerTuples[index];
    return expected !== undefined &&
      analyzer.id === expected.id &&
      analyzer.analyzer === expected.analyzer &&
      analyzer.version === expected.version &&
      sameStrings(analyzer.profileVersions, expected.profileVersions);
  });

/** Golden-only provenance metadata; it is not a runtime transport contract. */
export const RuntimeManifestProvenance = Schema.Struct({
  ...runtimeManifestIdentityFields,
  analyzers: Schema.Array(RuntimeManifestAnalyzer).check(
    Schema.makeFilter(analyzers =>
      hasExactManifestTuples(analyzers)
        ? undefined
        : "Expected the exact immutable seven-analyzer runtime manifest.",
    ),
  ),
});

/**
 * Full-root artifact schema: the manifest identity and every failure are
 * decoded together, so strict excess-property handling reaches every level.
 */
export const AnalysisFailuresArtifact = Schema.Struct({
  runtimeManifest: RuntimeManifestIdentitySchema,
  failures: Schema.Array(AnalysisFailure).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(ContractLimits.violations),
  ),
});

export const decodeAnalysisFailuresArtifact = Schema.decodeUnknownEffect(
  AnalysisFailuresArtifact,
  { onExcessProperty: "error" },
);

const strictAnalysisFailuresArtifact = Schema.decodeUnknownExit(
  AnalysisFailuresArtifact,
  { onExcessProperty: "error" },
);

const StrictAnalysisFailuresArtifact = Schema.Json.check(
  Schema.makeFilter(value =>
    Exit.isSuccess(strictAnalysisFailuresArtifact(value))
      ? undefined
      : "Expected a strict full-root AnalysisFailures artifact.",
  ),
);

export const analysisFailureNormalization = defineNormalizationSchema(
  StrictAnalysisFailuresArtifact,
  [
    {
      path: ["failures", "*", "analyzerRuns", "*", "durationMs"],
      kind: "duration",
    },
  ],
);

const GoldenTimestamp = Schema.NonEmptyString.check(
  Schema.makeFilter(value => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
      return "timestamp must be a millisecond-precision UTC ISO-8601 string";
    }
    const instant = new Date(value);
    return Number.isNaN(instant.getTime()) || instant.toISOString() !== value
      ? "timestamp must identify a real calendar instant"
      : undefined;
  }),
);

const NonNegativeInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
);

export const FixtureRelativePath = Schema.NonEmptyString.check(
  Schema.isTrimmed(),
  Schema.isMaxLength(ContractLimits.pathCharacters),
  Schema.makeFilter(value =>
    /^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(value) &&
    !value.includes("..") &&
    !value.startsWith("/")
      ? undefined
      : "fixture paths must be portable, relative, and traversal-free",
  ),
);

const LocaleTag = Schema.NonEmptyString.check(
  Schema.makeFilter(value =>
    /^[a-z]{2,3}(?:-[A-Z]{2})?$/u.test(value)
      ? undefined
      : "locale must use a deterministic language or language-region tag",
  ),
);

const hasExactRuns = (
  runs: ReadonlyArray<typeof ScriptedAnalyzerRun.Type>,
  scanId: string,
) =>
  runs.length === RequiredAnalyzerIds.length &&
  runs.every((run, index) =>
    run.scanId === scanId && run.analyzerId === RequiredAnalyzerIds[index]);

/**
 * Private scripted-adapter evidence, intentionally exact rather than a
 * permissive mirror. Its snapshot comes from ScriptedAnalyzerRuntime itself.
 */
export const ScriptedRuntimeTranscript = Schema.Struct({
  schemaVersion: Schema.Literal("codebase-radar.golden-scripted-transcript/v1"),
  manifest: RuntimeManifestProvenance,
  execution: Schema.Struct({
    scanId: OpaqueId,
    startedAt: GoldenTimestamp,
    completedAt: GoldenTimestamp,
    durationMs: NonNegativeInteger,
    status: Schema.Literal("complete"),
    metadata: Schema.Struct({
      locale: LocaleTag,
      temporaryDirectory: FixtureRelativePath,
      workspace: FixtureRelativePath,
    }),
  }),
  snapshot: ScriptedAnalyzerSnapshot,
}).check(
  Schema.makeFilter(transcript =>
    transcript.execution.completedAt >= transcript.execution.startedAt &&
    hasExactRuns(transcript.snapshot.attemptedRuns, transcript.execution.scanId) &&
    transcript.snapshot.activeRuns.length === 0 &&
    hasExactRuns(transcript.snapshot.finalizedRuns, transcript.execution.scanId) &&
    transcript.snapshot.remainingRuns.length === 0
      ? undefined
      : "Expected one completed canonical seven-analyzer scripted adapter snapshot.",
  ),
);

const StrictScriptedRuntimeTranscript = Schema.Json.check(
  Schema.makeFilter(value =>
    Exit.isSuccess(
      Schema.decodeUnknownExit(ScriptedRuntimeTranscript, {
        onExcessProperty: "error",
      })(value),
    )
      ? undefined
      : "Expected a strict scripted runtime transcript.",
  ),
);

export const scriptedRuntimeTranscriptNormalization = defineNormalizationSchema(
  StrictScriptedRuntimeTranscript,
  [
    { path: ["execution", "scanId"], kind: "run-id" },
    { path: ["snapshot", "attemptedRuns", "*", "scanId"], kind: "run-id" },
    { path: ["snapshot", "finalizedRuns", "*", "scanId"], kind: "run-id" },
    { path: ["execution", "startedAt"], kind: "timestamp" },
    { path: ["execution", "completedAt"], kind: "timestamp" },
    { path: ["execution", "durationMs"], kind: "duration" },
    {
      path: ["execution", "metadata", "locale"],
      kind: "replace",
      replacement: "<locale>",
    },
    { path: ["execution", "metadata", "temporaryDirectory"], kind: "path" },
    { path: ["execution", "metadata", "workspace"], kind: "path" },
  ],
);

const artifactUriMaterial = /\b[A-Za-z][A-Za-z0-9+.-]*(?::|%(?:25){0,3}3A)(?=[^\s)\]}>,;]*(?:[\\/@?]|%(?:25){0,3}2F))[^\s)\]}>,;]*/giu;
const publicArtifactUriProtocol = /^https?:$/iu;
const unrenderedNormalizationMarker = /<(?:locale|local-path|run-id|timestamp|tmp|workspace)>/u;
const credentialQuerySuffix = /(?:apikey|authorization|credential|password|privatekey|secret|signature|token|sig)$/u;

const isCredentialQueryParameter = (parameter: string) => {
  const normalized = parameter.replaceAll(/[^A-Za-z0-9]/gu, "").toLowerCase();
  return normalized === "key" ||
    credentialQuerySuffix.test(normalized) ||
    normalized.includes("accesskey");
};

const hasForbiddenArtifactUri = (value: string) => {
  for (const match of value.matchAll(artifactUriMaterial)) {
    let uriMaterial = match[0];
    if (
      Exit.isSuccess(strictAnalysisPolicyIdentity(uriMaterial)) ||
      Exit.isSuccess(strictCodebaseId(uriMaterial))
    ) {
      continue;
    }
    for (let decodeDepth = 0; decodeDepth < 4; decodeDepth += 1) {
      try {
        const decoded = decodeURIComponent(uriMaterial);
        if (decoded === uriMaterial) break;
        uriMaterial = decoded;
      } catch {
        return true;
      }
    }
    try {
      const uri = new URL(uriMaterial);
      if (!publicArtifactUriProtocol.test(uri.protocol)) return true;
      if (uri.username.length > 0 || uri.password.length > 0) return true;
      if (
        Array.from(uri.searchParams.keys()).some(parameter =>
          isCredentialQueryParameter(parameter),
        )
      ) {
        return true;
      }
    } catch {
      return true;
    }
  }
  return false;
};

/**
 * Each individual golden text field must already be safe for publication.
 * Reusing the contract sanitizer makes a newly detected local-path family
 * fail this guard without adding another hand-maintained path list here.
 */
export const GoldenArtifactText = PathFreeText.check(
  Schema.makeFilter(value =>
    sanitizeContractText([], value) !== value
      ? "artifact text must not require local-path sanitization"
      : hasForbiddenArtifactUri(value)
        ? "artifact text must use public HTTP(S) URLs without credentials or secret query parameters"
        : unrenderedNormalizationMarker.test(value)
          ? "artifact text must not contain normalization placeholders"
          : undefined,
  ),
);
