import { tmpdir } from "node:os";
import { isAbsolute, win32 } from "node:path";
import { Effect, Schema, Semaphore } from "effect";

export const TemporaryWorkspaceOperation = Schema.Literals([
  "access",
  "cleanup",
  "create",
  "mkdir",
  "resolve",
  "write",
]);

export class TemporaryWorkspaceError extends Schema.TaggedErrorClass<TemporaryWorkspaceError>()(
  "TemporaryWorkspaceError",
  {
    operation: TemporaryWorkspaceOperation,
    path: Schema.String,
    reason: Schema.String,
  },
) {}

export const TemporaryWorkspaceCapabilityReason = Schema.Literals([
  "descriptor-relative-no-follow-unavailable",
]);

export class TemporaryWorkspaceCapabilityError extends Schema.TaggedErrorClass<
  TemporaryWorkspaceCapabilityError
>()(
  "TemporaryWorkspaceCapabilityError",
  {
    platform: Schema.String,
    reason: TemporaryWorkspaceCapabilityReason,
  },
) {}

export type TemporaryWorkspaceFailure =
  | TemporaryWorkspaceCapabilityError
  | TemporaryWorkspaceError;

/**
 * An opaque, descriptor-backed directory supplied by a host filesystem
 * capability. `root` is a display label, never a pathname for direct I/O.
 */
export interface DescriptorRelativeWorkspace {
  readonly root: string;
  readonly cleanup: Effect.Effect<void, TemporaryWorkspaceError>;
  readonly exists: (
    segments: readonly string[],
  ) => Effect.Effect<boolean, TemporaryWorkspaceError>;
  readonly mkdir: (
    segments: readonly string[],
  ) => Effect.Effect<void, TemporaryWorkspaceError>;
  readonly write: (
    segments: readonly string[],
    content: string | Uint8Array,
  ) => Effect.Effect<void, TemporaryWorkspaceError>;
}

export interface TemporaryWorkspaceRequest {
  readonly parentDirectory: string;
  readonly prefix: string;
}

/**
 * Hosts may inject a filesystem capability only when it anchors every
 * operation and cleanup to retained directory descriptors with no-follow
 * semantics. Node's portable filesystem API cannot provide that invariant.
 */
export interface TemporaryWorkspaceFilesystem {
  readonly acquireDescriptorWorkspace: (
    request: TemporaryWorkspaceRequest,
  ) => Effect.Effect<DescriptorRelativeWorkspace, TemporaryWorkspaceFailure>;
}

export interface TemporaryWorkspace {
  readonly root: string;
  readonly cleanup: Effect.Effect<void, TemporaryWorkspaceError>;
  readonly exists: (relativePath?: string) => Effect.Effect<boolean, TemporaryWorkspaceError>;
  readonly mkdir: (relativePath: string) => Effect.Effect<string, TemporaryWorkspaceError>;
  readonly resolve: (relativePath?: string) => Effect.Effect<string, TemporaryWorkspaceError>;
  readonly write: (
    relativePath: string,
    content: string | Uint8Array,
  ) => Effect.Effect<string, TemporaryWorkspaceError>;
}

export interface TemporaryWorkspaceOptions {
  readonly filesystem?: TemporaryWorkspaceFilesystem;
  readonly parentDirectory?: string;
  readonly prefix?: string;
}

const unavailableFilesystem: TemporaryWorkspaceFilesystem = {
  acquireDescriptorWorkspace: () => Effect.fail(new TemporaryWorkspaceCapabilityError({
    platform: process.platform,
    reason: "descriptor-relative-no-follow-unavailable",
  })),
};

function workspaceError(
  operation: typeof TemporaryWorkspaceOperation.Type,
  path: string,
  reason: string,
): TemporaryWorkspaceError {
  return new TemporaryWorkspaceError({ operation, path, reason });
}

function workspaceSegments(
  relativePath: string,
  operation: typeof TemporaryWorkspaceOperation.Type,
): Effect.Effect<readonly string[], TemporaryWorkspaceError> {
  if (relativePath.includes("\0")) {
    return Effect.fail(workspaceError(operation, relativePath, "path contains a null byte"));
  }
  if (isAbsolute(relativePath) || win32.isAbsolute(relativePath)) {
    return Effect.fail(workspaceError(operation, relativePath, "path must be relative"));
  }

  const segments: string[] = [];
  for (const part of relativePath.replaceAll("\\", "/").split("/")) {
    if (part.length === 0 || part === ".") continue;
    if (part === "..") {
      return Effect.fail(workspaceError(
        operation,
        relativePath,
        "path escapes the workspace root",
      ));
    }
    segments.push(part);
  }
  return Effect.succeed(segments);
}

function displayPath(root: string, segments: readonly string[]): string {
  return segments.length === 0 ? root : `${root}/${segments.join("/")}`;
}

/**
 * Creates a test workspace only through a descriptor-relative host capability.
 * Without one, this fails before creating, opening, writing, or cleaning a
 * pathname so portable Node runtimes cannot falsely claim hostile-race safety.
 */
export function createTemporaryWorkspace(
  options: TemporaryWorkspaceOptions = {},
): Effect.Effect<TemporaryWorkspace, TemporaryWorkspaceFailure> {
  const prefix = options.prefix ?? "codebase-radar-test-";
  if (prefix.length === 0 || prefix.includes("/") || prefix.includes("\\")) {
    return Effect.fail(workspaceError(
      "create",
      prefix,
      "prefix must be a non-empty file name prefix",
    ));
  }

  const filesystem = options.filesystem ?? unavailableFilesystem;
  return filesystem.acquireDescriptorWorkspace({
    parentDirectory: options.parentDirectory ?? tmpdir(),
    prefix,
  }).pipe(Effect.flatMap(descriptor => Effect.gen(function* () {
    const lock = yield* Semaphore.make(1);
    let cleaned = false;
    const exclusively = <A>(
      operation: typeof TemporaryWorkspaceOperation.Type,
      effect: Effect.Effect<A, TemporaryWorkspaceError>,
    ): Effect.Effect<A, TemporaryWorkspaceError> => lock.withPermit(
      Effect.suspend(() => cleaned
        ? Effect.fail(workspaceError(operation, descriptor.root, "workspace has already been cleaned up"))
        : effect),
    );

    const resolvePath = (
      relativePath = ".",
    ): Effect.Effect<string, TemporaryWorkspaceError> => exclusively(
      "resolve",
      workspaceSegments(relativePath, "resolve").pipe(
        Effect.map(segments => displayPath(descriptor.root, segments)),
      ),
    );

    const cleanup = lock.withPermit(Effect.suspend(() => cleaned
      ? Effect.void
      : descriptor.cleanup.pipe(Effect.tap(() => Effect.sync(() => {
        cleaned = true;
      })), Effect.asVoid)));

    return {
      root: descriptor.root,
      cleanup,
      resolve: resolvePath,
      exists: (relativePath = ".") => exclusively(
        "access",
        workspaceSegments(relativePath, "access").pipe(
          Effect.flatMap(descriptor.exists),
        ),
      ),
      mkdir: relativePath => exclusively(
        "mkdir",
        workspaceSegments(relativePath, "mkdir").pipe(
          Effect.flatMap(segments => descriptor.mkdir(segments).pipe(
            Effect.as(displayPath(descriptor.root, segments)),
          )),
        ),
      ),
      write: (relativePath, content) => exclusively(
        "write",
        workspaceSegments(relativePath, "write").pipe(
          Effect.flatMap(segments => segments.length === 0
            ? Effect.fail(workspaceError("write", descriptor.root, "cannot write to the root directory"))
            : descriptor.write(segments, content).pipe(
              Effect.as(displayPath(descriptor.root, segments)),
            )),
        ),
      ),
    };
  })));
}

export function withTemporaryWorkspace<A, E, R>(
  operation: (workspace: TemporaryWorkspace) => Effect.Effect<A, E, R>,
  options: TemporaryWorkspaceOptions = {},
): Effect.Effect<A, E | TemporaryWorkspaceFailure, R> {
  return Effect.acquireUseRelease(
    createTemporaryWorkspace(options),
    operation,
    workspace => workspace.cleanup,
  );
}
