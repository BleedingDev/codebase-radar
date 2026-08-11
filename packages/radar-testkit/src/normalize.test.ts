import { Effect, Schema } from "effect";
import { describe, expect, it } from "vitest";
import {
  createSchemaNormalizer,
  defineNormalizationSchema,
  stableStringify,
} from "./normalize.js";

const Result = Schema.Struct({
  runId: Schema.String,
  startedAt: Schema.String,
  durationMs: Schema.Number,
  findings: Schema.Array(Schema.Struct({
    severity: Schema.String,
    file: Schema.String,
  })),
});

const resultNormalization = defineNormalizationSchema(Result, [
  { path: ["runId"], kind: "run-id" },
  { path: ["startedAt"], kind: "timestamp" },
  { path: ["durationMs"], kind: "duration" },
  { path: ["findings", "*", "file"], kind: "path" },
  { path: ["findings"], kind: "sort-array" },
]);

describe("createSchemaNormalizer", () => {
  it("decodes and normalizes declared volatile fields", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalize = createSchemaNormalizer(resultNormalization, {
        workspaceRoot: "/work",
        temporaryRoots: ["/tmp/radar-a"],
      });
      const normalized = yield* normalize({
        startedAt: "2026-08-11T00:00:00.000Z",
        runId: "real-123",
        durationMs: 418,
        findings: [
          { severity: "warn", file: "/work/src/z.ts" },
          { severity: "error", file: "/tmp/radar-a/src/a.ts" },
        ],
      });

      expect(normalized).toEqual({
        durationMs: 0,
        findings: [
          { file: "<tmp>/src/a.ts", severity: "error" },
          { file: "<workspace>/src/z.ts", severity: "warn" },
        ],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("rejects external values that drift from the concrete result schema", () => Effect.runPromise(
    Effect.gen(function* () {
      const error = yield* Effect.flip(
        createSchemaNormalizer(resultNormalization)({
          runId: "run",
          startedAt: "2026-08-11T00:00:00.000Z",
          durationMs: "slow",
          findings: [],
        }),
      );
      expect(Schema.isSchemaError(error)).toBe(true);
    }),
  ));

  it("normalizes Windows paths independently of the host platform", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalized = yield* createSchemaNormalizer(
        resultNormalization,
        { workspaceRoot: "C:\\repo" },
      )({
        runId: "run",
        startedAt: "2026-08-11T00:00:00.000Z",
        durationMs: 1,
        findings: [{ severity: "warn", file: "C:\\repo\\src\\index.ts" }],
      });
      expect(normalized).toEqual({
        durationMs: 0,
        findings: [{ file: "<workspace>/src/index.ts", severity: "warn" }],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("chooses the most-specific containing root", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalized = yield* createSchemaNormalizer(resultNormalization, {
        workspaceRoot: "/work",
        temporaryRoots: ["/work/.tmp", "/work/.tmp/runs/current"],
      })({
        runId: "run",
        startedAt: "2026-08-11T00:00:00.000Z",
        durationMs: 1,
        findings: [{
          severity: "warn",
          file: "/work/.tmp/runs/current/src/index.ts",
        }],
      });

      expect(normalized).toEqual({
        durationMs: 0,
        findings: [{ file: "<tmp>/src/index.ts", severity: "warn" }],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("normalizes UNC workspace paths without retaining volatile roots", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalized = yield* createSchemaNormalizer(
        resultNormalization,
        { workspaceRoot: "\\\\server\\share\\volatile-run" },
      )({
        runId: "run",
        startedAt: "2026-08-11T00:00:00.000Z",
        durationMs: 1,
        findings: [{
          severity: "warn",
          file: "\\\\server\\share\\volatile-run\\src\\index.ts",
        }],
      });

      expect(normalized).toEqual({
        durationMs: 0,
        findings: [{ file: "<workspace>/src/index.ts", severity: "warn" }],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("does not compare POSIX roots with forward-slash UNC values", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalized = yield* createSchemaNormalizer(
        resultNormalization,
        {
          workspaceRoot: "/server/share/root/deep",
          temporaryRoots: ["\\\\server\\share\\root"],
        },
      )({
        runId: "run",
        startedAt: "2026-08-11T00:00:00.000Z",
        durationMs: 1,
        findings: [{
          severity: "warn",
          file: "//server/share/root/deep/file.ts",
        }],
      });

      expect(normalized).toEqual({
        durationMs: 0,
        findings: [{ file: "<tmp>/deep/file.ts", severity: "warn" }],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("ranks compatible mixed-separator UNC roots by segment depth", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalized = yield* createSchemaNormalizer(
        resultNormalization,
        {
          workspaceRoot: "\\\\server\\share\\root",
          temporaryRoots: ["//server/share/root/deep"],
        },
      )({
        runId: "run",
        startedAt: "2026-08-11T00:00:00.000Z",
        durationMs: 1,
        findings: [{
          severity: "warn",
          file: "\\\\server/share/root/deep/file.ts",
        }],
      });

      expect(normalized).toEqual({
        durationMs: 0,
        findings: [{ file: "<tmp>/file.ts", severity: "warn" }],
        runId: "<run-id>",
        startedAt: "<timestamp>",
      });
    }),
  ));

  it("preserves decoded JSON keys that shadow object internals", () => Effect.runPromise(
    Effect.gen(function* () {
      const normalize = createSchemaNormalizer(
        defineNormalizationSchema(Schema.Record(Schema.String, Schema.Json), []),
      );
      const normalized = yield* normalize(
        JSON.parse('{"__proto__":{"retained":true},"constructor":"still-data","name":"value"}'),
      );

      expect(yield* stableStringify(normalized)).toBe(
        '{\n  "__proto__": {\n    "retained": true\n  },\n  "constructor": "still-data",\n  "name": "value"\n}',
      );
    }),
  ));

  it("produces stable JSON for differently ordered object keys", () => Effect.runPromise(
    Effect.gen(function* () {
      const left = yield* stableStringify({ "ä": 4, z: 3, b: 2, A: 1 });
      const right = yield* stableStringify({ A: 1, b: 2, z: 3, "ä": 4 });
      expect(left).toBe(right);
      expect(left).toBe('{\n  "A": 1,\n  "b": 2,\n  "z": 3,\n  "ä": 4\n}');
    }),
  ));
});
