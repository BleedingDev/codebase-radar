import { createHash } from "node:crypto";
import { Effect, Exit, Schema } from "effect";
import { describe, expect, it } from "vitest";
import {
  CanonicalRepositoryPathSet,
  CompleteAnalyzerRunSchema,
  encodeCanonicalRepositoryPathSet,
} from "../../radar-contracts/src/index.js";

const digestRepositoryPathSet = (paths: CanonicalRepositoryPathSet) =>
  `sha256:${createHash("sha256")
    .update(encodeCanonicalRepositoryPathSet(paths))
    .digest("hex")}`;

const decodeCanonicalRepositoryPathSet = Schema.decodeUnknownEffect(
  CanonicalRepositoryPathSet,
  { onExcessProperty: "error" },
);

const decodeCompleteAnalyzerRun = Schema.decodeUnknownExit(
  CompleteAnalyzerRunSchema,
  { onExcessProperty: "error" },
);

describe("AnalyzerCoverage path-set digests", () => {
  it("uses only validated UTF-8-canonical repository paths for digest bytes", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const paths = yield* decodeCanonicalRepositoryPathSet([
          "src/\uE000.ts",
          "src/\u{10000}.ts",
        ]);

        expect(digestRepositoryPathSet(paths)).toBe(
          "sha256:e1896bcc1f0552576966bf9128cd5d5e77ce8bbe424bf099056d257166e8b563",
        );
        const reversed = yield* Effect.exit(
          decodeCanonicalRepositoryPathSet(["src/\u{10000}.ts", "src/\uE000.ts"]),
        );
        const duplicate = yield* Effect.exit(
          decodeCanonicalRepositoryPathSet(["src/a.ts", "src/a.ts"]),
        );
        expect(Exit.isFailure(reversed)).toBe(true);
        expect(Exit.isFailure(duplicate)).toBe(true);
      }),
    ));

  it("rejects complete coverage with equal counts for different path sets", () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const eligiblePaths = yield* decodeCanonicalRepositoryPathSet([
          "src/a.ts",
          "src/b.ts",
        ]);
        const analyzedPaths = yield* decodeCanonicalRepositoryPathSet([
          "src/a.ts",
          "src/c.ts",
        ]);
        const completeRun = {
          _tag: "CompleteAnalyzerRun",
          status: "complete",
          analyzer: "strictest-comparator",
          analyzerVersion: "@tsconfig/strictest 2.0.8",
          profileVersion: "dogfood:max/v1",
          durationMs: 0,
          coverage: {
            eligibleFiles: eligiblePaths.length,
            analyzedFiles: analyzedPaths.length,
            eligiblePathSetDigest: digestRepositoryPathSet(eligiblePaths),
            analyzedPathSetDigest: digestRepositoryPathSet(eligiblePaths),
            omittedCapabilities: [],
            warnings: [],
          },
          observationCount: 1,
        };

        expect(Exit.isSuccess(decodeCompleteAnalyzerRun(completeRun))).toBe(true);
        expect(Exit.isFailure(decodeCompleteAnalyzerRun({
          ...completeRun,
          coverage: {
            ...completeRun.coverage,
            analyzedPathSetDigest: digestRepositoryPathSet(analyzedPaths),
          },
        }))).toBe(true);
      }),
    ));
});
