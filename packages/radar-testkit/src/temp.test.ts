import { access, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Fiber, Option, Schema } from "effect";
import { describe, expect, it } from "vitest";
import {
  createTemporaryWorkspace,
  TemporaryWorkspaceCapabilityError,
  TemporaryWorkspaceError,
  type DescriptorRelativeWorkspace,
  type TemporaryWorkspaceFilesystem,
  withTemporaryWorkspace,
} from "./temp.js";

const ExternalFileFailure = Schema.Struct({
  code: Schema.optional(Schema.String),
  message: Schema.optional(Schema.String),
});
const decodeExternalFileFailure = Schema.decodeUnknownOption(ExternalFileFailure);

class TestFileOperationError extends Schema.TaggedErrorClass<TestFileOperationError>()(
  "TestFileOperationError",
  { reason: Schema.String },
) {}

class ExpectedTestFailure extends Schema.TaggedErrorClass<ExpectedTestFailure>()(
  "ExpectedTestFailure",
  {},
) {}

const pathIsMissing = (target: string): Effect.Effect<boolean> => Effect.tryPromise({
  try: () => access(target),
  catch: cause => decodeExternalFileFailure(cause),
}).pipe(
  Effect.match({
    onFailure: details => Option.exists(details, detail => detail.code === "ENOENT"),
    onSuccess: () => false,
  }),
);

function externalFailure(): TestFileOperationError {
  return new TestFileOperationError({ reason: "test file operation failed" });
}

function makeTemporaryDirectory(
  prefix: string,
): Effect.Effect<string, TestFileOperationError> {
  return Effect.tryPromise({
    try: () => mkdtemp(join(tmpdir(), prefix)),
    catch: externalFailure,
  });
}

function removeDirectory(target: string): Effect.Effect<void, TestFileOperationError> {
  return Effect.tryPromise({
    try: () => rm(target, { force: true, recursive: true }),
    catch: externalFailure,
  });
}

function waitUntil(condition: () => boolean): Effect.Effect<void> {
  return Effect.suspend(() => condition()
    ? Effect.void
    : Effect.yieldNow.pipe(Effect.andThen(waitUntil(condition))));
}

function descriptorFilesystem(
  label: string,
  afterDescriptorValidation: () => Effect.Effect<void, TestFileOperationError>,
  onCleanup: () => void = () => undefined,
  writeStrategy?: (
    segments: readonly string[],
    content: string | Uint8Array,
  ) => Effect.Effect<void, TemporaryWorkspaceError>,
): TemporaryWorkspaceFilesystem {
  const files = new Set<string>();
  let cleaned = false;
  const active = (
    operation: "access" | "mkdir" | "write",
  ): Effect.Effect<void, TemporaryWorkspaceError> => cleaned
    ? Effect.fail(new TemporaryWorkspaceError({
      operation,
      path: label,
      reason: "workspace has already been cleaned up",
    }))
    : Effect.void;
  const key = (segments: readonly string[]): string => segments.join("/");
  const write = writeStrategy ?? (segments => Effect.sync(() => {
    files.add(key(segments));
  }));
  const descriptor: DescriptorRelativeWorkspace = {
    root: label,
    cleanup: Effect.sync(() => {
      cleaned = true;
      files.clear();
      onCleanup();
    }),
    exists: segments => active("access").pipe(Effect.map(() => {
      const path = key(segments);
      return path.length === 0 || files.has(path);
    })),
    mkdir: _segments => active("mkdir"),
    write: (segments, content) => active("write").pipe(
      Effect.andThen(write(segments, content)),
      Effect.asVoid,
    ),
  };

  return {
    acquireDescriptorWorkspace: () => afterDescriptorValidation().pipe(
      Effect.mapError(() => new TemporaryWorkspaceError({
        operation: "create",
        path: label,
        reason: "test descriptor acquisition failed",
      })),
      Effect.as(descriptor),
    ),
  };
}

describe("temporary workspaces", () => {
  it("fails closed before mutation when no descriptor-relative capability is available", () => Effect.runPromise(
    Effect.gen(function* () {
      const error = yield* Effect.flip(createTemporaryWorkspace());
      expect(error).toBeInstanceOf(TemporaryWorkspaceCapabilityError);
      if (!(error instanceof TemporaryWorkspaceCapabilityError)) return;
      expect(error.reason).toBe("descriptor-relative-no-follow-unavailable");
    }),
  ));

  it("keeps lexical containment and Effect resource release in the capability boundary", () => Effect.runPromise(
    Effect.gen(function* () {
      let cleanupCount = 0;
      const filesystem = descriptorFilesystem(
        "descriptor://workspace",
        () => Effect.void,
        () => {
          cleanupCount += 1;
        },
      );
      const workspace = yield* createTemporaryWorkspace({ filesystem });
      const escapeError = yield* Effect.flip(workspace.resolve("../escape"));
      expect(escapeError).toBeInstanceOf(TemporaryWorkspaceError);
      if (!(escapeError instanceof TemporaryWorkspaceError)) return;
      expect(escapeError.reason).toContain("escapes");
      expect(yield* workspace.write("src/index.ts", "export {};\n"))
        .toBe("descriptor://workspace/src/index.ts");
      expect(yield* workspace.exists("src/index.ts")).toBe(true);
      yield* workspace.cleanup;

      const failed = yield* Effect.exit(withTemporaryWorkspace(
        () => Effect.fail(new ExpectedTestFailure()),
        { filesystem },
      ));
      expect(failed._tag).toBe("Failure");
      expect(cleanupCount).toBe(2);
    }),
  ));

  it("releases a retained capability when an operation is interrupted", () => Effect.runPromise(
    Effect.gen(function* () {
      let cleanupCount = 0;
      const filesystem = descriptorFilesystem(
        "descriptor://interrupted-workspace",
        () => Effect.void,
        () => {
          cleanupCount += 1;
        },
      );
      const running = yield* withTemporaryWorkspace(
        () => Effect.never,
        { filesystem },
      ).pipe(Effect.forkChild);
      yield* Effect.yieldNow;
      yield* Fiber.interrupt(running);
      expect(cleanupCount).toBe(1);
    }),
  ));

  it("does not write outside or remove a replacement when a descriptor barrier swaps root", () => Effect.runPromise(
    Effect.acquireUseRelease(
      makeTemporaryDirectory("radar-descriptor-parent-"),
      parent => Effect.acquireUseRelease(
        makeTemporaryDirectory("radar-descriptor-outside-"),
        outside => Effect.gen(function* () {
          const physicalRoot = join(parent, "workspace");
          yield* Effect.tryPromise({
            try: () => mkdir(physicalRoot),
            catch: externalFailure,
          });
          const filesystem = descriptorFilesystem(
            "descriptor://retained-workspace",
            () => Effect.tryPromise({
              try: () => rm(physicalRoot, { force: true, recursive: true })
                .then(() => symlink(outside, physicalRoot)),
              catch: externalFailure,
            }),
          );
          const workspace = yield* createTemporaryWorkspace({
            filesystem,
            parentDirectory: parent,
          });
          expect(yield* workspace.write("owned.txt", "nope")).toBe(
            "descriptor://retained-workspace/owned.txt",
          );
          yield* workspace.cleanup;

          expect(yield* pathIsMissing(join(outside, "owned.txt"))).toBe(true);
          expect(yield* pathIsMissing(physicalRoot)).toBe(false);
        }),
        removeDirectory,
      ),
      removeDirectory,
    ),
  ));

  it("interrupts an in-flight descriptor write, releases its permit, and cleans up once", () => Effect.runPromise(
    Effect.acquireUseRelease(
      makeTemporaryDirectory("radar-descriptor-interrupt-parent-"),
      parent => Effect.acquireUseRelease(
        makeTemporaryDirectory("radar-descriptor-interrupt-outside-"),
        outside => Effect.gen(function* () {
          const physicalRoot = join(parent, "workspace");
          yield* Effect.tryPromise({
            try: () => mkdir(physicalRoot),
            catch: externalFailure,
          });
          let writeStarted = false;
          let cleanupCount = 0;
          const filesystem = descriptorFilesystem(
            "descriptor://interrupted-write",
            () => Effect.tryPromise({
              try: () => rm(physicalRoot, { force: true, recursive: true })
                .then(() => symlink(outside, physicalRoot)),
              catch: externalFailure,
            }),
            () => {
              cleanupCount += 1;
            },
            (_segments, _content) => Effect.sync(() => {
              writeStarted = true;
            }).pipe(Effect.andThen(Effect.never)),
          );
          const running = yield* withTemporaryWorkspace(
            workspace => workspace.write("owned.txt", "must not reach the replacement"),
            { filesystem, parentDirectory: parent },
          ).pipe(Effect.forkChild);

          yield* waitUntil(() => writeStarted);
          yield* Fiber.interrupt(running);

          expect(cleanupCount).toBe(1);
          expect(yield* pathIsMissing(join(outside, "owned.txt"))).toBe(true);
          expect(yield* pathIsMissing(physicalRoot)).toBe(false);
        }),
        removeDirectory,
      ),
      removeDirectory,
    ),
  ));
});
