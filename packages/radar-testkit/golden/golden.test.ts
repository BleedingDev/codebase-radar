import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Effect, Exit, Schema } from "effect";
import { describe, expect, it } from "vitest";
import { ScanRecord } from "../../../apps/radar/shared/domain.js";
import { runtimeTrustAnchor } from "../../analyzer-runtime/trust-anchor.mjs";
import {
  AnalysisProgressStream,
  ContractLimits,
  decodeScanResult,
  decodeScanResultJson,
  encodeScanResult,
  encodeScanResultJson,
  Finding,
  PathFreeText,
  RequiredAnalyzerIds,
  sanitizeAndDecodeContractText,
  sanitizeContractText,
  SuccessfulScanResult,
  SuccessfulScanResultSchema,
} from "../../radar-contracts/src/index.js";
import {
  decodeRadarRuntimeReport,
} from "../../radar-core/src/index.js";
import {
  createSchemaNormalizer,
  stableStringify,
} from "../src/index.js";
import {
  ScriptedProcessAdapter,
} from "../src/runtime/index.js";
import {
  ScriptedAnalyzerCase,
  ScriptedAnalyzerRuntime,
} from "../src/runtime/scripted-analyzer-runtime.js";
import { renderHumanBacklog } from "./render.js";
import {
  analysisFailureNormalization,
  cliJsonResultNormalization,
  completeScanResultNormalization,
  decodeAnalysisFailuresArtifact,
  FixtureRelativePath,
  GoldenArtifactText,
  httpPersistedResultNormalization,
  humanBacklogResultNormalization,
  monotonicProgressNormalization,
  RuntimeManifestProvenance,
  runtimeManifestAnalyzerTuples,
  runtimeManifestIdentity,
  ScriptedRuntimeTranscript,
  scriptedRuntimeTranscriptNormalization,
} from "./rules.js";

const JsonText = Schema.fromJsonString(Schema.Json);
const JsonArray = Schema.Array(Schema.Json);
const JsonObject = Schema.Record(Schema.String, Schema.Json);
const JsonObjects = Schema.Array(JsonObject);
const RuntimeManifestAnalyzerProjection = Schema.Struct({
  id: Schema.String,
  analyzer: Schema.String,
  version: Schema.String,
  profileVersions: Schema.Array(Schema.String),
});
const RuntimeManifestProjection = Schema.Struct({
  schemaVersion: Schema.String,
  manifestVersion: Schema.Number,
  profile: Schema.String,
  analyzers: Schema.Array(RuntimeManifestAnalyzerProjection),
});
const decodeJsonText = Schema.decodeUnknownEffect(JsonText);
const decodeJson = Schema.decodeUnknownEffect(Schema.Json);
const decodeJsonObject = Schema.decodeUnknownEffect(JsonObject);
const decodeJsonObjects = Schema.decodeUnknownEffect(JsonObjects);
const decodeCompleteResult = Schema.decodeUnknownEffect(
  SuccessfulScanResultSchema,
  { onExcessProperty: "error" },
);
const decodeProgressStream = Schema.decodeUnknownEffect(AnalysisProgressStream, {
  onExcessProperty: "error",
});
const decodeScanRecord = Schema.decodeUnknownEffect(ScanRecord, {
  onExcessProperty: "error",
});
const decodeManifestProvenance = Schema.decodeUnknownEffect(
  RuntimeManifestProvenance,
  { onExcessProperty: "error" },
);
const decodeTranscript = Schema.decodeUnknownEffect(ScriptedRuntimeTranscript, {
  onExcessProperty: "error",
});
const decodeScriptedAnalyzerCase = Schema.decodeUnknownEffect(
  ScriptedAnalyzerCase,
  { onExcessProperty: "error" },
);
const decodeFixtureRelativePath = Schema.decodeUnknownEffect(
  FixtureRelativePath,
);
const decodePathFreeText = Schema.decodeUnknownExit(PathFreeText);
const decodeGoldenArtifactText = Schema.decodeUnknownExit(GoldenArtifactText);
const runtimeReportInput = {
  schemaVersion: "codebase-radar.runtime-report/v1",
  status: "ready",
  manifest: {
    policyDigest: `sha256:${runtimeTrustAnchor.policyDigest}`,
    buildIdentity: runtimeTrustAnchor.buildIdentity,
  },
  evidence: RequiredAnalyzerIds.map(analyzer => ({ analyzer, status: "ready" })),
};
const decodeRuntimeManifestProjection = Schema.decodeUnknownEffect(
  RuntimeManifestProjection,
  { onExcessProperty: "ignore" },
);

const artifactNames = [
  "analysis-failures.json",
  "cli-json.json",
  "complete-scan-result.json",
  "http-persisted-completed.json",
  "http-persisted-legacy-v1.json",
  "human-backlog.txt",
  "monotonic-progress.json",
  "runtime-doctor-failures.json",
  "runtime-doctor-ready.json",
  "runtime-manifest-provenance.json",
  "scripted-runtime-transcript.json",
];

const readGoldenText = (name: string): Effect.Effect<string, string> =>
  Effect.try({
    try: () => readFileSync(new URL(`./artifacts/${name}`, import.meta.url), "utf8"),
    catch: cause => `Unable to read golden artifact ${name}: ${String(cause)}`,
  });

const readGoldenJson = (name: string) =>
  readGoldenText(name).pipe(Effect.flatMap(decodeJsonText));

const readGoldenObject = (name: string) =>
  readGoldenJson(name).pipe(Effect.flatMap(decodeJsonObject));

const readAcceptedRuntimeManifestText = (): Effect.Effect<string, string> =>
  Effect.try({
    try: () => readFileSync(
      new URL("../../analyzer-runtime/runtime-manifest.json", import.meta.url),
      "utf8",
    ),
    catch: cause => `Unable to read accepted runtime manifest: ${String(cause)}`,
  });

const readAcceptedRuntimeManifestJson = () =>
  readAcceptedRuntimeManifestText().pipe(Effect.flatMap(decodeJsonText));

const readAcceptedRuntimeManifest = () =>
  readAcceptedRuntimeManifestJson().pipe(
    Effect.flatMap(decodeRuntimeManifestProjection),
  );

const compareCodeUnits = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const canonicalRuntimeManifestJson = (value: Schema.Json): string => {
  if (Schema.is(JsonArray)(value)) {
    return `[${value.map(canonicalRuntimeManifestJson).join(",")}]`;
  }
  if (Schema.is(JsonObject)(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, nested]) =>
        `${JSON.stringify(key)}:${canonicalRuntimeManifestJson(nested)}`)
      .join(",")}}`;
  }
  return value === null ? "null" : JSON.stringify(value);
};

const acceptedRuntimeManifestDigest = (value: Schema.Json) =>
  createHash("sha256").update(canonicalRuntimeManifestJson(value)).digest("hex");

const decodeComplete = () =>
  readGoldenJson("complete-scan-result.json").pipe(
    Effect.flatMap(decodeCompleteResult),
  );

const canonicalBytes = (result: Parameters<typeof encodeScanResult>[0]) =>
  encodeScanResult(result).pipe(
    Effect.flatMap(decodeJson),
    Effect.flatMap(stableStringify),
  );

const exactCliDocument = (value: string) =>
  value.endsWith("\n") &&
  !value.endsWith("\n\n") &&
  !value.slice(0, -1).includes("\n");

const jsonTextFields = (value: Schema.Json): ReadonlyArray<string> => {
  if (typeof value === "string") return [value];
  if (Schema.is(JsonArray)(value)) return value.flatMap(jsonTextFields);
  if (Schema.is(JsonObject)(value)) {
    return Object.entries(value).flatMap(([key, nested]) => [
      key,
      ...jsonTextFields(nested),
    ]);
  }
  return [];
};

const humanRecordHeading = "## Complete canonical record\n\n";

const decodeHumanRecord = (human: string) => {
  const record = human.split(humanRecordHeading).at(-1);
  return record === undefined
    ? Effect.fail("Human golden is missing its complete canonical record.")
    : decodeScanResultJson(record.trim());
};

const expectedFindingIds = [
  "finding-001",
  "finding-002",
  "finding-003",
  "finding-004",
  "finding-005",
  "finding-006",
  "finding-007",
];

const expectedMechanisms = [
  "A known vulnerable dependency remains reachable through the production lockfile.",
  "A workflow permission grants a token broader authority than the job requires.",
  "The configured TypeScript strictness leaves unsafe indexed access unchecked.",
  "A request handler suppresses a lint rule that protects an awaited error boundary.",
  "Two domain modules depend on each other across a boundary intended to remain one-way.",
  "Two request mappers duplicate the same validation and normalization sequence.",
  "A public call path increased fan-out across an API boundary.",
];

const expectedEvidence = [
  {
    analyzer: "OSV-Scanner",
    kind: "direct",
    message: "Resolved dependency matches a published vulnerability advisory.",
    ruleId: "OSV-2026-0001",
    path: "package-lock.json",
    line: 128,
    excerpt: "\"version\": \"1.2.3\"",
  },
  {
    analyzer: "zizmor",
    kind: "direct",
    message: "Workflow job declares write permissions for an otherwise read-only task.",
    ruleId: "zizmor:excessive-permissions",
    path: ".github/workflows/release.yml",
    line: 14,
    excerpt: "permissions: write-all",
  },
  {
    analyzer: "strictest-comparator",
    kind: "direct",
    message: "The strict comparator found an unchecked indexed access gap.",
    ruleId: "noUncheckedIndexedAccess",
    path: "tsconfig.json",
    line: 9,
    excerpt: "\"noUncheckedIndexedAccess\": false",
  },
  {
    analyzer: "Oxlint + Ultracite",
    kind: "direct",
    message: "Suppression hides an asynchronous error-boundary rule violation.",
    ruleId: "promise-function-async",
    path: "src/server/submit-review.ts",
    line: 47,
    excerpt: "eslint-disable-next-line",
  },
  {
    analyzer: "TraceDecay",
    kind: "direct",
    message: "A cycle crosses the billing and reporting domain boundary.",
    ruleId: "dependency-cycle",
    path: "src/domain/billing.ts",
    line: 3,
    excerpt: "import { report } from \"../reporting/report\"",
  },
  {
    analyzer: "JSCPD",
    kind: "direct",
    message: "A duplicate block matches the mapper in the adjacent request module.",
    ruleId: "jscpd:clone",
    path: "src/http/map-review-request.ts",
    line: 22,
    excerpt: "const normalized = normalizeInput(request)",
  },
  {
    analyzer: "Calldiff",
    kind: "direct",
    message: "The public endpoint reaches two additional downstream calls.",
    ruleId: "calldiff:fanout",
    path: "src/api/get-review.ts",
    line: 31,
    excerpt: "return loadReviewWithMetadata(id)",
  },
];

const expectedAnalyzerRunTuples = [
  {
    analyzer: "strictest-comparator",
    analyzerVersion: "@tsconfig/strictest 2.0.8",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "Oxlint + Ultracite",
    analyzerVersion: "1.77.0 + 7.10.2",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "JSCPD",
    analyzerVersion: "5.0.14",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "Calldiff",
    analyzerVersion: "0.4.1",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "zizmor",
    analyzerVersion: "1.29.0",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "OSV-Scanner",
    analyzerVersion: "2.5.0",
    profileVersion: "dogfood:max/v1",
  },
  {
    analyzer: "TraceDecay",
    analyzerVersion: "0.0.73",
    profileVersion: "dogfood:max/v1",
  },
];

const completeScripts = (scanId: string) =>
  Effect.forEach(
    RequiredAnalyzerIds,
    analyzerId =>
      decodeScriptedAnalyzerCase({
        scanId,
        analyzerId,
        outcome: {
          status: "complete",
          payload: { analyzerId, fixture: "golden" },
          observationCount: 1,
        },
      }),
  );

const transcriptFromSchedule = (
  scanId: string,
  schedule: ReadonlyArray<string>,
  startedAt: string,
  completedAt: string,
  durationMs: number,
  locale: string,
  temporaryDirectory: string,
  workspace: string,
) =>
  Effect.gen(function* () {
    const runtime = yield* ScriptedAnalyzerRuntime.make(
      yield* completeScripts(scanId),
    );
    yield* Effect.all(
      schedule.map(analyzerId => runtime.run({ scanId, analyzerId })),
      { concurrency: "unbounded" },
    );
    const snapshot = yield* runtime.snapshot();
    yield* runtime.assertClean();
    yield* runtime.assertExhausted();
    return yield* decodeTranscript({
      schemaVersion: "codebase-radar.golden-scripted-transcript/v1",
      manifest: {
        ...runtimeManifestIdentity,
        analyzers: runtimeManifestAnalyzerTuples,
      },
      execution: {
        scanId,
        startedAt,
        completedAt,
        durationMs,
        status: "complete",
        metadata: { locale, temporaryDirectory, workspace },
      },
      snapshot,
    });
  });

describe("radar golden artifacts", () => {
  it("decodes every result surface through strict public codecs with semantic identity", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const complete = yield* decodeComplete();
        const cliText = yield* readGoldenText("cli-json.json");
        const cli = yield* decodeScanResultJson(cliText);
        expect(exactCliDocument(cliText)).toBe(true);
        expect(cli.resultKind).toBe("complete");
        if (cli.resultKind !== "complete") return;
        const encodedCli = yield* encodeScanResultJson(complete);
        expect(cliText).toBe(`${encodedCli}\n`);
        expect(exactCliDocument(`${encodedCli}\n\n`)).toBe(false);

        const persistedRaw = yield* readGoldenObject("http-persisted-completed.json");
        const persisted = yield* decodeScanRecord(persistedRaw);
        const persistedResult = persisted.result;
        expect(persisted.id).toBe("scan-golden-001");
        expect(persisted.status).toBe("completed");
        expect(persisted.progress).toBe(100);
        expect(persistedResult).toBeDefined();
        if (persistedResult === undefined) return;
        expect(persistedResult.resultKind).toBe("complete");
        if (persistedResult.resultKind !== "complete") return;

        const legacyRaw = yield* readGoldenObject("http-persisted-legacy-v1.json");
        const legacy = yield* decodeScanRecord(legacyRaw);
        const legacyResult = legacy.result;
        expect(legacy.id).toBe("scan-golden-001");
        expect(legacy.status).toBe("completed");
        expect(legacyResult).toBeDefined();
        if (legacyResult === undefined) return;
        expect(legacyResult.resultKind).toBe("legacy-noncanonical");

        const human = yield* readGoldenText("human-backlog.txt");
        const humanResult = yield* decodeHumanRecord(human);
        expect(humanResult.resultKind).toBe("complete");
        if (humanResult.resultKind !== "complete") return;

        const expectedBytes = yield* canonicalBytes(complete);
        expect(yield* canonicalBytes(cli)).toBe(expectedBytes);
        expect(yield* canonicalBytes(persistedResult)).toBe(expectedBytes);
        expect(yield* canonicalBytes(humanResult)).toBe(expectedBytes);
        expect(yield* renderHumanBacklog(complete)).toBe(human);
        expect(yield* renderHumanBacklog(cli)).toBe(human);
        expect(yield* renderHumanBacklog(persistedResult)).toBe(human);

        const normalizeComplete = createSchemaNormalizer(
          completeScanResultNormalization,
        );
        const normalizeCli = createSchemaNormalizer(cliJsonResultNormalization);
        const normalizeHuman = createSchemaNormalizer(
          humanBacklogResultNormalization,
        );
        const normalizeHttp = createSchemaNormalizer(
          httpPersistedResultNormalization,
        );
        const normalizedComplete = yield* normalizeComplete(
          yield* encodeScanResult(complete),
        );
        const normalizedBytes = yield* stableStringify(normalizedComplete);
        expect(yield* stableStringify(yield* normalizeCli(
          yield* encodeScanResult(cli),
        ))).toBe(normalizedBytes);
        expect(yield* stableStringify(yield* normalizeHuman(
          yield* encodeScanResult(persistedResult),
        ))).toBe(normalizedBytes);
        expect(yield* stableStringify(yield* normalizeHttp(
          yield* encodeScanResult(persistedResult),
        ))).toBe(normalizedBytes);
      }),
    ));

  it("freezes every committed artifact with exactly one terminal LF", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        for (const name of artifactNames) {
          const artifact = yield* readGoldenText(name);
          expect(artifact.endsWith("\n"), name).toBe(true);
          expect(artifact.endsWith("\n\n"), name).toBe(false);
          expect(artifact.endsWith("\r\n"), name).toBe(false);
        }
      }),
    ));

  it("pins the immutable manifest tuples, ranked inventory, mechanisms, and complete evidence", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const acceptedRuntimeManifestJson = yield* readAcceptedRuntimeManifestJson();
        const acceptedRuntimeManifest = yield* readAcceptedRuntimeManifest();
        expect(acceptedRuntimeManifest.schemaVersion).toBe(
          runtimeManifestIdentity.schemaVersion,
        );
        expect(acceptedRuntimeManifest.manifestVersion).toBe(
          runtimeManifestIdentity.manifestVersion,
        );
        expect(acceptedRuntimeManifest.profile).toBe(
          runtimeManifestIdentity.analysisPolicy,
        );
        expect(acceptedRuntimeManifest.analyzers).toEqual(
          runtimeManifestAnalyzerTuples,
        );
        expect(acceptedRuntimeManifestDigest(acceptedRuntimeManifestJson)).toBe(
          runtimeManifestIdentity.digest,
        );

        const manifest = yield* readGoldenJson("runtime-manifest-provenance.json").pipe(
          Effect.flatMap(decodeManifestProvenance),
        );
        expect(manifest.schemaVersion).toBe(runtimeManifestIdentity.schemaVersion);
        expect(manifest.manifestVersion).toBe(runtimeManifestIdentity.manifestVersion);
        expect(manifest.analysisPolicy).toBe(runtimeManifestIdentity.analysisPolicy);
        expect(manifest.digest).toBe(runtimeManifestIdentity.digest);
        expect(manifest.analyzers).toEqual(runtimeManifestAnalyzerTuples);
        expect(manifest.analyzers.map(analyzer => analyzer.analyzer)).toEqual(
          RequiredAnalyzerIds,
        );

        const complete = yield* decodeComplete();
        expect(complete.profile.limitations).toContain(
          `Immutable analyzer runtime manifest: ${runtimeManifestIdentity.schemaVersion} sha256:${runtimeManifestIdentity.digest}`,
        );
        expect(complete.analyzerRuns).toHaveLength(7);
        expect(complete.analyzerRuns.map(run => ({
          analyzer: run.analyzer,
          analyzerVersion: run.analyzerVersion,
          profileVersion: run.profileVersion,
        }))).toEqual(expectedAnalyzerRunTuples);
        expect(complete.analyzerRuns.map(run => run.status)).toEqual([
          "complete",
          "complete",
          "complete",
          "complete",
          "complete",
          "complete",
          "complete",
        ]);
        expect(complete.analyzerRuns.map(run => run.observationCount)).toEqual([
          14,
          18,
          7,
          5,
          3,
          2,
          9,
        ]);
        expect(complete.findings.map(finding => finding.id)).toEqual(
          expectedFindingIds,
        );
        expect(complete.findings.map(finding => finding.mechanism)).toEqual(
          expectedMechanisms,
        );
        expect(complete.findings.map(finding => finding.evidence[0])).toEqual(
          expectedEvidence,
        );
        expect(complete.findings.map(finding => finding.externalReferences.length)).toEqual([
          1,
          1,
          1,
          1,
          1,
          1,
          1,
        ]);
        expect(complete.summary).toEqual({
          headline: "Two urgent fixes lead a complete seven-analyzer improvement backlog.",
          healthScore: 71,
          fixNow: 2,
          investigate: 2,
          monitor: 2,
          doNotFix: 1,
        });
        expect(complete.comparison).toEqual({
          basisCodebaseId: "github:acme/radar-sample",
          basisPolicyId: "dogfood:max/v1",
          previousScanId: "scan-golden-000",
          newFingerprints: ["fingerprint-001", "fingerprint-002", "fingerprint-007"],
          resolvedFingerprints: ["fingerprint-000"],
          persistentFingerprints: [
            "fingerprint-003",
            "fingerprint-004",
            "fingerprint-005",
            "fingerprint-006",
          ],
          priorityDelta: 7,
        });

        const failureDocument = yield* readGoldenJson("analysis-failures.json").pipe(
          Effect.flatMap(decodeAnalysisFailuresArtifact),
        );
        expect(failureDocument.runtimeManifest).toEqual(runtimeManifestIdentity);
        const failures = failureDocument.failures;
        const incomplete = failures.find(failure => failure._tag === "AnalysisIncomplete");
        expect(incomplete).toBeDefined();
        if (incomplete === undefined) return;
        expect(incomplete.analyzerRuns.map(run => ({
          analyzer: run.analyzer,
          analyzerVersion: run.analyzerVersion,
          profileVersion: run.profileVersion,
        }))).toEqual(expectedAnalyzerRunTuples);
      }),
    ));

  it("decodes monotonic progress and typed failures", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const progressJson = yield* readGoldenJson("monotonic-progress.json");
        const progress = yield* decodeProgressStream(progressJson);
        expect(progress.map(event => event.sequence)).toEqual([
          0,
          1,
          2,
          3,
          4,
          5,
          6,
          7,
        ]);
        expect(progress.map(event => event.stage)).toEqual([
          "preflight",
          "materializing",
          "inventory",
          "analyzing",
          "analyzing",
          "prioritizing",
          "comparing",
          "terminal",
        ]);
        const terminal = progress.at(-1);
        expect(terminal?._tag).toBe("AnalysisProgressTerminal");
        if (terminal?._tag !== "AnalysisProgressTerminal") return;
        expect(terminal.outcome).toBe("succeeded");
        const normalizeProgress = createSchemaNormalizer(
          monotonicProgressNormalization,
        );
        expect(yield* stableStringify(yield* normalizeProgress(progressJson))).toContain(
          "<timestamp>",
        );

        const failureDocument = yield* readGoldenJson("analysis-failures.json").pipe(
          Effect.flatMap(decodeAnalysisFailuresArtifact),
        );
        const failures = failureDocument.failures;
        expect(failures.map(failure => failure._tag)).toEqual([
          "AnalysisSourceRejected",
          "AnalysisSourceUnavailable",
          "AnalysisRuntimeUnavailable",
          "AnalysisIncomplete",
          "AnalysisInterrupted",
        ]);
        const incomplete = failures.find(failure => failure._tag === "AnalysisIncomplete");
        expect(incomplete).toBeDefined();
        if (incomplete === undefined) return;
        expect(incomplete.violations).toEqual([
          { code: "analyzer_timed_out", analyzer: "TraceDecay" },
        ]);
        expect(incomplete.analyzerRuns).toHaveLength(7);
        expect(incomplete.analyzerRuns.map(run => run.analyzer)).toEqual(
          RequiredAnalyzerIds,
        );
        expect(incomplete.analyzerRuns.at(-1)?.status).toBe("timed_out");
        const normalizeFailures = createSchemaNormalizer(
          analysisFailureNormalization,
        );
        expect(yield* stableStringify(yield* normalizeFailures(
          yield* readGoldenJson("analysis-failures.json"),
        ))).toContain(
          "\"durationMs\": 0",
        );

        const doctor = yield* ScriptedProcessAdapter.make([
          { id: "ready", outcome: { kind: "exit", exitCode: 0, stdout: "ready" } },
          { id: "missing", outcome: { kind: "missing-binary" } },
          { id: "timeout", outcome: { kind: "timeout" } },
        ]);
        const outcomes = yield* Effect.all([
          doctor.execute("ready", {
            command: "runtime-doctor",
            args: ["--check", "strictest-comparator"],
            cwd: "golden-workspace",
            timeoutMs: 1000,
          }),
          doctor.execute("missing", {
            command: "runtime-doctor",
            args: ["--check", "JSCPD"],
            cwd: "golden-workspace",
            timeoutMs: 1000,
          }),
          doctor.execute("timeout", {
            command: "runtime-doctor",
            args: ["--check", "OSV-Scanner"],
            cwd: "golden-workspace",
            timeoutMs: 1000,
          }),
        ], { concurrency: "unbounded" });
        expect(outcomes.map(outcome => outcome.status)).toEqual([
          "exited",
          "missing-binary",
          "timed-out",
        ]);
        yield* doctor.assertClean();
        yield* doctor.assertExhausted();
      }),
    ));

  it("uses the canonical runtime-report decoder", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const ready = yield* decodeRadarRuntimeReport(runtimeReportInput);
        expect(ready.schemaVersion).toBe("codebase-radar.runtime-report/v1");
        expect(ready.status).toBe("ready");
        expect(ready.evidence.map(evidence => evidence.analyzer)).toEqual(
          RequiredAnalyzerIds,
        );
        const unavailable = yield* decodeRadarRuntimeReport({
          ...runtimeReportInput,
          status: "unavailable",
          evidence: runtimeReportInput.evidence.map(evidence => ({
            ...evidence,
            status: "unavailable",
          })),
        });
        expect(unavailable.status).toBe("unavailable");
      }),
    ));

  it("rejects outer, nested, malformed, private-path, and credential attacks at every strict boundary", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const completeRaw = yield* readGoldenObject("complete-scan-result.json");
        const source = completeRaw.source;
        expect(source).toBeDefined();
        if (source === undefined) return;
        const sourceObject = yield* decodeJsonObject(source);
        expect(Exit.isFailure(yield* Effect.exit(decodeCompleteResult({
          ...completeRaw,
          implementationPrivate: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeCompleteResult({
          ...completeRaw,
          source: { ...sourceObject, checkoutDirectory: "private/repository" },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeCompleteResult({
          ...completeRaw,
          source: { ...sourceObject, url: "https://token:secret@github.com/Acme/radar-sample" },
        })))).toBe(true);

        const findingsValue = completeRaw.findings;
        expect(findingsValue).toBeDefined();
        if (findingsValue === undefined) return;
        const findings = yield* decodeJsonObjects(findingsValue);
        const firstFinding = findings[0];
        expect(firstFinding).toBeDefined();
        if (firstFinding === undefined) return;
        const findingEvidenceValue = firstFinding.evidence;
        expect(findingEvidenceValue).toBeDefined();
        if (findingEvidenceValue === undefined) return;
        const findingEvidence = yield* decodeJsonObjects(findingEvidenceValue);
        const firstEvidence = findingEvidence[0];
        expect(firstEvidence).toBeDefined();
        if (firstEvidence === undefined) return;
        expect(Exit.isFailure(yield* Effect.exit(decodeCompleteResult({
          ...completeRaw,
          findings: [
            {
              ...firstFinding,
              evidence: [
                {
                  ...firstEvidence,
                  message: "The analyzer read /Users/alice/private/repository.",
                },
              ],
            },
            ...findings.slice(1),
          ],
        })))).toBe(true);
        const normalizeComplete = createSchemaNormalizer(
          completeScanResultNormalization,
        );
        expect(Exit.isFailure(yield* Effect.exit(normalizeComplete({
          ...completeRaw,
          implementationPrivate: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(normalizeComplete({
          ...completeRaw,
          source: { ...sourceObject, url: "https://token:secret@github.com/Acme/radar-sample" },
        })))).toBe(true);

        const progressRaw = yield* readGoldenJson("monotonic-progress.json");
        const progress = yield* decodeJsonObjects(progressRaw);
        const firstProgress = progress[0];
        expect(firstProgress).toBeDefined();
        if (firstProgress === undefined) return;
        expect(Exit.isFailure(yield* Effect.exit(decodeProgressStream([
          { ...firstProgress, privateField: "forbidden" },
          ...progress.slice(1),
        ])))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeProgressStream([
          { ...firstProgress, timestamp: 0 },
          ...progress.slice(1),
        ])))).toBe(true);
        const normalizeProgress = createSchemaNormalizer(
          monotonicProgressNormalization,
        );
        expect(Exit.isFailure(yield* Effect.exit(normalizeProgress([
          { ...firstProgress, privateField: "forbidden" },
          ...progress.slice(1),
        ])))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(normalizeProgress([
          { ...firstProgress, timestamp: 0 },
          ...progress.slice(1),
        ])))).toBe(true);

        const failureDocument = yield* readGoldenObject("analysis-failures.json");
        const failureManifestValue = failureDocument.runtimeManifest;
        const failureValues = failureDocument.failures;
        expect(failureManifestValue).toBeDefined();
        expect(failureValues).toBeDefined();
        if (failureManifestValue === undefined || failureValues === undefined) return;
        const failureManifest = yield* decodeJsonObject(failureManifestValue);
        const failures = yield* decodeJsonObjects(failureValues);
        const firstFailure = failures[0];
        expect(firstFailure).toBeDefined();
        if (firstFailure === undefined) return;
        const incomplete = failures.at(3);
        expect(incomplete).toBeDefined();
        if (incomplete === undefined) return;
        const attemptsValue = incomplete.analyzerRuns;
        expect(attemptsValue).toBeDefined();
        if (attemptsValue === undefined) return;
        const attempts = yield* decodeJsonObjects(attemptsValue);
        const firstAttempt = attempts[0];
        expect(firstAttempt).toBeDefined();
        if (firstAttempt === undefined) return;
        const maximumFailures = Array.from(
          { length: ContractLimits.violations },
          () => firstFailure,
        );
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: [],
        })))).toBe(true);
        expect(Exit.isSuccess(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: maximumFailures,
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: [...maximumFailures, firstFailure],
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          implementationPrivate: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          runtimeManifest: { ...failureManifest, implementationPrivate: "forbidden" },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: [
            { ...firstFailure, privateField: "forbidden" },
            ...failures.slice(1),
          ],
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: [
            ...failures.slice(0, 3),
            {
              ...incomplete,
              analyzerRuns: [
                { ...firstAttempt, privateField: "forbidden" },
                ...attempts.slice(1),
              ],
            },
            ...failures.slice(4),
          ],
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeAnalysisFailuresArtifact({
          ...failureDocument,
          failures: [
            ...failures.slice(0, 3),
            {
              ...incomplete,
              analyzerRuns: [
                { ...firstAttempt, durationMs: "zero" },
                ...attempts.slice(1),
              ],
            },
            ...failures.slice(4),
          ],
        })))).toBe(true);
        const normalizeFailures = createSchemaNormalizer(
          analysisFailureNormalization,
        );
        expect(Exit.isFailure(yield* Effect.exit(normalizeFailures({
          ...failureDocument,
          implementationPrivate: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(normalizeFailures({
          ...failureDocument,
          runtimeManifest: { ...failureManifest, implementationPrivate: "forbidden" },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(normalizeFailures({
          ...failureDocument,
          failures: [
            ...failures.slice(0, 3),
            {
              ...incomplete,
              analyzerRuns: [
                { ...firstAttempt, durationMs: "zero" },
                ...attempts.slice(1),
              ],
            },
            ...failures.slice(4),
          ],
        })))).toBe(true);

        const persisted = yield* readGoldenObject("http-persisted-completed.json");
        const persistedResult = persisted.result;
        expect(persistedResult).toBeDefined();
        if (persistedResult === undefined) return;
        const persistedResultObject = yield* decodeJsonObject(persistedResult);
        expect(Exit.isFailure(yield* Effect.exit(decodeScanRecord({
          ...persisted,
          privateField: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeScanRecord({
          ...persisted,
          result: { ...persistedResultObject, privateField: "forbidden" },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeScanRecord({
          ...persisted,
          result: { ...persistedResultObject, scanId: 1 },
        })))).toBe(true);

        const firstRuntimeEvidence = runtimeReportInput.evidence[0];
        expect(firstRuntimeEvidence).toBeDefined();
        if (firstRuntimeEvidence === undefined) return;
        expect(Exit.isFailure(yield* Effect.exit(decodeRadarRuntimeReport({
          ...runtimeReportInput,
          privateField: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeRadarRuntimeReport({
          ...runtimeReportInput,
          manifest: { ...runtimeReportInput.manifest, privateField: "forbidden" },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeRadarRuntimeReport({
          ...runtimeReportInput,
          evidence: [
            { ...firstRuntimeEvidence, privateField: "forbidden" },
            ...runtimeReportInput.evidence.slice(1),
          ],
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeRadarRuntimeReport({
          ...runtimeReportInput,
          evidence: [
            { ...firstRuntimeEvidence, status: "unavailable" },
            ...runtimeReportInput.evidence.slice(1),
          ],
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeRadarRuntimeReport({
          ...runtimeReportInput,
          evidence: [
            ...runtimeReportInput.evidence.slice(1),
            firstRuntimeEvidence,
          ],
        })))).toBe(true);

        const transcript = yield* readGoldenObject("scripted-runtime-transcript.json");
        const executionValue = transcript.execution;
        const snapshotValue = transcript.snapshot;
        expect(executionValue).toBeDefined();
        expect(snapshotValue).toBeDefined();
        if (executionValue === undefined || snapshotValue === undefined) return;
        const execution = yield* decodeJsonObject(executionValue);
        const snapshot = yield* decodeJsonObject(snapshotValue);
        const attemptedValue = snapshot.attemptedRuns;
        expect(attemptedValue).toBeDefined();
        if (attemptedValue === undefined) return;
        const attempted = yield* decodeJsonObjects(attemptedValue);
        const firstRun = attempted[0];
        expect(firstRun).toBeDefined();
        if (firstRun === undefined) return;
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcript,
          privateField: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcript,
          snapshot: {
            ...snapshot,
            attemptedRuns: [{ ...firstRun, privateField: "forbidden" }, ...attempted.slice(1)],
          },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcript,
          execution: { ...execution, durationMs: "zero" },
        })))).toBe(true);
        const normalizeTranscript = createSchemaNormalizer(
          scriptedRuntimeTranscriptNormalization,
        );
        expect(Exit.isFailure(yield* Effect.exit(normalizeTranscript({
          ...transcript,
          privateField: "forbidden",
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(normalizeTranscript({
          ...transcript,
          execution: { ...execution, durationMs: "zero" },
        })))).toBe(true);
      }),
    ));

  it("bounds fixture, workspace, and temporary paths at the shared path limit", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const exactLimit = "a".repeat(ContractLimits.pathCharacters);
        const onePastLimit = `${exactLimit}a`;
        expect(yield* decodeFixtureRelativePath(exactLimit)).toBe(exactLimit);
        expect(Exit.isFailure(yield* Effect.exit(
          decodeFixtureRelativePath(onePastLimit),
        ))).toBe(true);

        const transcript = yield* readGoldenObject(
          "scripted-runtime-transcript.json",
        );
        const executionValue = transcript.execution;
        expect(executionValue).toBeDefined();
        if (executionValue === undefined) return;
        const execution = yield* decodeJsonObject(executionValue);
        const metadataValue = execution.metadata;
        expect(metadataValue).toBeDefined();
        if (metadataValue === undefined) return;
        const metadata = yield* decodeJsonObject(metadataValue);
        expect(Exit.isSuccess(yield* Effect.exit(decodeTranscript({
          ...transcript,
          execution: {
            ...execution,
            metadata: {
              ...metadata,
              temporaryDirectory: exactLimit,
              workspace: exactLimit,
            },
          },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcript,
          execution: {
            ...execution,
            metadata: { ...metadata, temporaryDirectory: onePastLimit },
          },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcript,
          execution: {
            ...execution,
            metadata: { ...metadata, workspace: onePastLimit },
          },
        })))).toBe(true);
      }),
    ));

  it("keeps semantic mutations visible in the normalized golden diff", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const complete = yield* decodeComplete();
        const firstFinding = complete.findings[0];
        expect(firstFinding).toBeDefined();
        if (firstFinding === undefined) return;
        const normalize = createSchemaNormalizer(completeScanResultNormalization);
        const baseline = yield* stableStringify(yield* normalize(
          yield* encodeScanResult(complete),
        ));
        const mutation = new SuccessfulScanResult({
          ...complete,
          findings: [
            new Finding({
              ...firstFinding,
              title: "Reachable dependency advisory requires an upgrade",
            }),
            ...complete.findings.slice(1),
          ],
        });
        const changed = yield* stableStringify(yield* normalize(
          yield* encodeScanResult(mutation),
        ));
        expect(changed).not.toBe(baseline);
      }),
    ));

  it("derives exact transcript bytes from scripted snapshots and normalizes only operational metadata", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const transcriptRaw = yield* readGoldenJson("scripted-runtime-transcript.json");
        const transcript = yield* decodeTranscript(transcriptRaw);
        const expectedBytes = yield* stableStringify(transcriptRaw);
        const forward = yield* transcriptFromSchedule(
          "scan-golden-001",
          RequiredAnalyzerIds,
          "2026-08-11T10:00:00.000Z",
          "2026-08-11T10:00:00.000Z",
          0,
          "en-US",
          "golden-workspace/tmp",
          "golden-workspace/repository",
        );
        const reversed = yield* transcriptFromSchedule(
          "scan-golden-001",
          [...RequiredAnalyzerIds].toReversed(),
          "2026-08-11T10:00:00.000Z",
          "2026-08-11T10:00:00.000Z",
          0,
          "en-US",
          "golden-workspace/tmp",
          "golden-workspace/repository",
        );
        expect(yield* stableStringify(forward)).toBe(expectedBytes);
        expect(yield* stableStringify(reversed)).toBe(expectedBytes);

        const normalizeExpected = createSchemaNormalizer(
          scriptedRuntimeTranscriptNormalization,
          {
            workspaceRoot: "golden-workspace",
            temporaryRoots: ["golden-workspace/tmp"],
          },
        );
        const expectedNormalized = yield* stableStringify(
          yield* normalizeExpected(transcriptRaw),
        );
        const variants = [
          {
            scanId: "scan-locale-en",
            schedule: [...RequiredAnalyzerIds],
            startedAt: "2030-03-03T03:03:03.000Z",
            completedAt: "2030-03-03T03:03:03.000Z",
            durationMs: 7,
            locale: "en-US",
            temporaryDirectory: "volatile-en/tmp",
            workspace: "volatile-en/repository",
            workspaceRoot: "volatile-en",
            temporaryRoot: "volatile-en/tmp",
          },
          {
            scanId: "scan-locale-cs",
            schedule: [...RequiredAnalyzerIds].toReversed(),
            startedAt: "2031-04-04T04:04:04.000Z",
            completedAt: "2031-04-04T04:04:04.000Z",
            durationMs: 12,
            locale: "cs-CZ",
            temporaryDirectory: "volatile-cs/tmp",
            workspace: "volatile-cs/repository",
            workspaceRoot: "volatile-cs",
            temporaryRoot: "volatile-cs/tmp",
          },
          {
            scanId: "scan-locale-tr",
            schedule: [
              "TraceDecay",
              "OSV-Scanner",
              "zizmor",
              "Calldiff",
              "JSCPD",
              "Oxlint + Ultracite",
              "strictest-comparator",
            ],
            startedAt: "2032-05-05T05:05:05.000Z",
            completedAt: "2032-05-05T05:05:05.000Z",
            durationMs: 21,
            locale: "tr-TR",
            temporaryDirectory: "volatile-tr/tmp",
            workspace: "volatile-tr/repository",
            workspaceRoot: "volatile-tr",
            temporaryRoot: "volatile-tr/tmp",
          },
        ];
        const variantBytes = yield* Effect.forEach(variants, variant =>
          transcriptFromSchedule(
            variant.scanId,
            variant.schedule,
            variant.startedAt,
            variant.completedAt,
            variant.durationMs,
            variant.locale,
            variant.temporaryDirectory,
            variant.workspace,
          ).pipe(
            Effect.flatMap(value =>
              createSchemaNormalizer(scriptedRuntimeTranscriptNormalization, {
                workspaceRoot: variant.workspaceRoot,
                temporaryRoots: [variant.temporaryRoot],
              })(value),
            ),
            Effect.flatMap(stableStringify),
          ),
        );
        expect(variantBytes).toEqual([
          expectedNormalized,
          expectedNormalized,
          expectedNormalized,
        ]);

        const transcriptObject = yield* readGoldenObject(
          "scripted-runtime-transcript.json",
        );
        const snapshotValue = transcriptObject.snapshot;
        expect(snapshotValue).toBeDefined();
        if (snapshotValue === undefined) return;
        const snapshot = yield* decodeJsonObject(snapshotValue);
        const attemptedValue = snapshot.attemptedRuns;
        expect(attemptedValue).toBeDefined();
        if (attemptedValue === undefined) return;
        const attempted = yield* decodeJsonObjects(attemptedValue);
        const firstRun = attempted[0];
        expect(firstRun).toBeDefined();
        if (firstRun === undefined) return;
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcriptObject,
          snapshot: { ...snapshot, attemptedRuns: attempted.slice(1) },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcriptObject,
          snapshot: { ...snapshot, attemptedRuns: [...attempted, firstRun] },
        })))).toBe(true);
        expect(Exit.isFailure(yield* Effect.exit(decodeTranscript({
          ...transcriptObject,
          snapshot: {
            ...snapshot,
            attemptedRuns: [{ ...firstRun, analyzerId: "unexpected-analyzer" }, ...attempted.slice(1)],
          },
        })))).toBe(true);
        expect(transcript.snapshot.finalizedRuns.map(run => run.analyzerId)).toEqual(
          RequiredAnalyzerIds,
        );
      }),
    ));

  it("keeps every committed artifact field private under shared sanitizer codecs", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const jsonArtifactNames = artifactNames.filter(name => name.endsWith(".json"));
        const jsonArtifactFields = yield* Effect.forEach(
          jsonArtifactNames,
          name => readGoldenJson(name).pipe(Effect.map(jsonTextFields)),
        );
        const human = yield* readGoldenText("human-backlog.txt");
        const humanHeader = human.split(humanRecordHeading)[0];
        expect(humanHeader).toBeDefined();
        if (humanHeader === undefined) return;
        const humanRecordJson = human.split(humanRecordHeading).at(-1);
        expect(humanRecordJson).toBeDefined();
        if (humanRecordJson === undefined) return;
        const humanRecordFields = jsonTextFields(
          yield* decodeJsonText(humanRecordJson.trim()),
        );
        const artifactFields = [
          ...jsonArtifactFields.flat(),
          ...humanHeader.split("\n").filter(field => field.length > 0),
          humanRecordHeading.trim(),
          ...humanRecordFields,
        ];
        expect(artifactFields.length).toBeGreaterThan(0);
        for (const field of artifactFields) {
          expect(Exit.isSuccess(decodeGoldenArtifactText(field)), field).toBe(true);
          expect(sanitizeContractText([], field)).toBe(field);
        }

        const localPathAdversaries = [
          "failure=/home/alice/private/repository.ts",
          "failure=/Users/alice/private/repository.ts",
          "failure=/custom/build/checkout/private.ts",
          "failure=/nix/store/abc-private/source.ts",
          "failure=/github/workspace/src/private.ts",
          "failure=\\\\server\\share\\private.ts",
          "failure=//server/share/private.ts",
          "failure=~/private/repository.ts",
          "failure=~\\private\\repository.ts",
          ...Array.from(
            { length: 26 },
            (_, offset) => {
              const drive = String.fromCharCode("A".charCodeAt(0) + offset);
              return [
                `failure=${drive}:\\Users\\alice\\private.ts`,
                `failure=${drive}:/Users/alice/private.ts`,
              ];
            },
          ).flat(),
        ];
        for (const attack of localPathAdversaries) {
          expect(sanitizeContractText([], attack)).not.toBe(attack);
          expect(Exit.isFailure(decodePathFreeText(attack))).toBe(true);
          expect(Exit.isSuccess(yield* Effect.exit(
            sanitizeAndDecodeContractText([], attack),
          ))).toBe(true);
          expect(Exit.isFailure(decodeGoldenArtifactText(attack))).toBe(true);
        }

        const controlCharacterAdversaries = [
          "failure=\u0000private",
          "failure=\u001Fprivate",
          "failure=\u007Fprivate",
          ...Array.from(
            { length: 0x20 },
            (_, offset) => `failure=${String.fromCharCode(0x80 + offset)}private`,
          ),
          "https://token:\u0000secret@github.com/Acme/radar-sample",
        ];
        for (const attack of controlCharacterAdversaries) {
          expect(Exit.isFailure(decodePathFreeText(attack))).toBe(true);
          expect(Exit.isFailure(decodeGoldenArtifactText(attack))).toBe(true);
        }

        const credentialQueryParameterFamilies = [
          "access_token",
          "api_key",
          "client_secret",
          "refresh_token",
          "id_token",
          "session_token",
          "private_token",
        ];
        const credentialQueryParameterVariants = [
          ...credentialQueryParameterFamilies.flatMap(parameter => [
            parameter,
            parameter.toUpperCase(),
            parameter.replaceAll("_", "-"),
            parameter.replaceAll("_", "."),
          ]),
          "x-api-key",
          "x_api_key",
          "X-API-KEY",
          "AWSAccessKeyId",
          "aws_access_key_id",
          "aws-access-key-id",
          "Signature",
          "X-Amz-Signature",
          "x_amz_signature",
          "sig",
          "SIG",
          "x-ms-sig",
          "client%5Fsecret",
        ];
        const credentialedUrlAdversaries = [
          "https://token:secret@github.com/Acme/radar-sample",
          "https://token@github.com/Acme/radar-sample",
          "https:token:secret@github.com/Acme/radar-sample",
          "ssh://token:secret@example.test/repository.git",
          "https://token%00:secret@github.com/Acme/radar-sample",
          "https://token%0Asecret@github.com/Acme/radar-sample",
          "https://storage.example.test/container?sv=2026-01-01&sig=secret",
          ...credentialQueryParameterVariants.map(
            parameter => `https://example.test/?${parameter}=secret`,
          ),
        ];
        const localUriAdversaries = [
          "file:///Users/alice/private.ts",
          "file://localhost/Users/alice/private.ts",
          "file://host/home/alice/private.ts",
          "smb://server/share/private.ts",
          "vscode://file/Users/alice/private.ts",
          "vscode:file/Users/alice/private.ts",
          "file:%2F%2Flocalhost%2FUsers%2Falice%2Fprivate.ts",
          "file%3A%2F%2Flocalhost%2FUsers%2Falice%2Fprivate.ts",
          "file%253A%252F%252Flocalhost%252FUsers%252Falice%252Fprivate.ts",
          "smb:server/share/private.ts",
          "VSCODE://file/Users/alice/private.ts",
          "vscode-insiders://file/Users/alice/private.ts",
          "git+ssh://host/home/alice/private.ts",
        ];
        for (const attack of credentialedUrlAdversaries) {
          expect(Exit.isFailure(decodeGoldenArtifactText(attack))).toBe(true);
        }
        for (const attack of localUriAdversaries) {
          expect(Exit.isFailure(decodeGoldenArtifactText(attack))).toBe(true);
        }
        for (const safePublicUrl of [
          "https://github.com/Acme/radar-sample?view=tree",
          "https://docs.example.test/routes/v1/overview",
        ]) {
          expect(Exit.isSuccess(decodeGoldenArtifactText(safePublicUrl))).toBe(true);
        }

        const complete = yield* readGoldenObject("complete-scan-result.json");
        const sourceValue = complete.source;
        expect(sourceValue).toBeDefined();
        if (sourceValue === undefined) return;
        const source = yield* decodeJsonObject(sourceValue);
        for (const credentialedUrl of [...credentialedUrlAdversaries, ...localUriAdversaries]) {
          expect(Exit.isFailure(yield* Effect.exit(decodeCompleteResult({
            ...complete,
            source: { ...source, url: credentialedUrl },
          })))).toBe(true);
        }
      }),
    ));
});
