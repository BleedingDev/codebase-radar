import { Context, Effect, Layer, Schema, Scope, Semaphore } from 'effect';
import {
  ProcessOutput,
  ProcessRequest,
} from './process/index.js';

const PositiveBoundedInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
);

const NonNegativeBoundedInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
  Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
);

const WorkspacePathSegment = Schema.NonEmptyString.check(
  Schema.isMaxLength(255),
  Schema.makeFilter(value =>
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    value.includes('\0') ||
    /[\u0000-\u001f\u007f]/u.test(value)
      ? 'workspace path segments must be safe file names'
      : undefined,
  ),
);

const WorkspacePathSegments = Schema.Array(WorkspacePathSegment).check(
  Schema.isMaxLength(512),
);

const WorkspaceContentDigest = Schema.String.check(
  Schema.makeFilter(value =>
    /^sha256:[0-9a-f]{64}$/u.test(value)
      ? undefined
      : 'workspace content digests must be complete SHA-256 values',
  ),
);

const GitResolverArgument = Schema.NonEmptyString.check(Schema.isMaxLength(4_096));

export class WorkspaceQuota extends Schema.Class<WorkspaceQuota>('WorkspaceQuota')({
  maximumEntries: PositiveBoundedInteger,
  maximumFiles: PositiveBoundedInteger,
  maximumBytes: PositiveBoundedInteger,
}) {}

export class SourceSnapshot extends Schema.Class<SourceSnapshot>('SourceSnapshot')({
  snapshotDigest: WorkspaceContentDigest,
  fileCount: Schema.Natural,
  totalBytes: Schema.Natural,
}) {}

export class WorkspaceRelativePath extends Schema.Class<WorkspaceRelativePath>(
  'WorkspaceRelativePath',
)({
  segments: WorkspacePathSegments,
}) {}

export const WorkspaceRoot = new WorkspaceRelativePath({ segments: [] });

export const WorkspaceEntryKind = Schema.Literals([
  'file',
  'directory',
  'symlink',
  'block-device',
  'character-device',
  'fifo',
  'socket',
  'unsupported',
]);

export class WorkspaceDirectoryEntry extends Schema.Class<WorkspaceDirectoryEntry>(
  'WorkspaceDirectoryEntry',
)({
  name: WorkspacePathSegment,
  kind: WorkspaceEntryKind,
}) {}

export class WorkspaceDirectoryBatch extends Schema.Class<WorkspaceDirectoryBatch>(
  'WorkspaceDirectoryBatch',
)({
  entries: Schema.Array(WorkspaceDirectoryEntry),
  truncated: Schema.Boolean,
}) {}

export class WorkspaceEntryStat extends Schema.Class<WorkspaceEntryStat>('WorkspaceEntryStat')({
  kind: WorkspaceEntryKind,
  byteLength: Schema.Natural,
}) {}

export class WorkspaceFileDigest extends Schema.Class<WorkspaceFileDigest>(
  'WorkspaceFileDigest',
)({
  contentDigest: WorkspaceContentDigest,
  byteLength: Schema.Natural,
}) {}

/**
 * The descriptor host, not the caller, supplies the fixed no-shell,
 * ignored-stdin, scrubbed-environment Git resolver sandbox. The host must reject
 * anything outside its canonical GitHub resolution policy before spawning.
 */
export class GitResolverCommand extends Schema.Class<GitResolverCommand>(
  'GitResolverCommand',
)({
  executable: Schema.Literal('git'),
  args: Schema.Array(GitResolverArgument).check(Schema.isMaxLength(64)),
  timeoutMs: PositiveBoundedInteger,
  maxOutputBytes: PositiveBoundedInteger,
}) {}

export const WorkspaceOperation = Schema.Literals([
  'allocate',
  'allocate-scratch',
  'seal',
  'close',
  'open-external-source',
  'read-directory',
  'stat',
  'read-text',
  'digest-regular-file',
  'copy-regular-file',
  'make-directory',
  'write-file',
  'run',
  'run-analyzer',
]);

export const WorkspaceFailureReason = Schema.Literals([
  'capability-unavailable',
  'unsupported-platform',
  'procfs-unavailable',
  'workspace-quota-unenforced',
  'workspace-quota-exceeded',
  'bound-exceeded',
  'unsafe-path',
  'unsafe-entry',
  'unrecognized-handle',
  'cross-host-handle',
  'workspace-closing',
  'workspace-closed',
  'staging-sealed',
  'read-only',
  'process-rejected',
  'process-failed',
  'process-timed-out',
  'process-output-truncated',
  'cleanup-failed',
]);

export class WorkspaceAccessError extends Schema.TaggedErrorClass<WorkspaceAccessError>()(
  'WorkspaceAccessError',
  {
    operation: WorkspaceOperation,
    reason: WorkspaceFailureReason,
  },
) {}

export class WorkspaceAllocationError extends Schema.TaggedErrorClass<WorkspaceAllocationError>()(
  'WorkspaceAllocationError',
  { reason: WorkspaceFailureReason },
) {}

const decodeQuota = Schema.decodeUnknownEffect(WorkspaceQuota, {
  onExcessProperty: 'error',
});

const decodePath = Schema.decodeUnknownEffect(WorkspaceRelativePath, {
  onExcessProperty: 'error',
});

const decodeBound = Schema.decodeUnknownEffect(NonNegativeBoundedInteger, {
  onExcessProperty: 'error',
});

const decodeDirectoryBatch = Schema.decodeUnknownEffect(WorkspaceDirectoryBatch, {
  onExcessProperty: 'error',
});

const decodeEntryStat = Schema.decodeUnknownEffect(WorkspaceEntryStat, {
  onExcessProperty: 'error',
});

const decodeFileDigest = Schema.decodeUnknownEffect(WorkspaceFileDigest, {
  onExcessProperty: 'error',
});

const decodeProcessRequest = Schema.decodeUnknownEffect(ProcessRequest, {
  onExcessProperty: 'error',
});

const decodeProcessOutput = Schema.decodeUnknownEffect(ProcessOutput, {
  onExcessProperty: 'error',
});

const decodeGitResolverCommand = Schema.decodeUnknownEffect(GitResolverCommand, {
  onExcessProperty: 'error',
});

const accessError = (
  operation: typeof WorkspaceOperation.Type,
  reason: typeof WorkspaceFailureReason.Type,
) => new WorkspaceAccessError({ operation, reason });

const allocationError = (reason: typeof WorkspaceFailureReason.Type) =>
  new WorkspaceAllocationError({ reason });

const LocalSourceInputDirectoryBrand: unique symbol = Symbol(
  'codebase-radar-local-source-input-directory',
);
const StagingWorkspaceHandleBrand: unique symbol = Symbol(
  'codebase-radar-staging-workspace-handle',
);
const SourceWorkspaceHandleBrand: unique symbol = Symbol(
  'codebase-radar-source-workspace-handle',
);
const AnalyzerScratchHandleBrand: unique symbol = Symbol(
  'codebase-radar-analyzer-scratch-handle',
);

/**
 * Host-issued opaque capabilities. The hidden unique-symbol members make them
 * nominal to TypeScript callers; the corresponding WeakMaps authenticate every
 * use at runtime. Neither a pathname nor a structural lookalike can be used as
 * a workspace capability.
 */
export interface LocalSourceInputDirectory {
  readonly [LocalSourceInputDirectoryBrand]: typeof LocalSourceInputDirectoryBrand;
}

export interface StagingWorkspaceHandle {
  readonly [StagingWorkspaceHandleBrand]: typeof StagingWorkspaceHandleBrand;
}

export interface SourceWorkspaceHandle {
  readonly [SourceWorkspaceHandleBrand]: typeof SourceWorkspaceHandleBrand;
}

export interface AnalyzerScratchHandle {
  readonly [AnalyzerScratchHandleBrand]: typeof AnalyzerScratchHandleBrand;
}

class LocalSourceInputDirectoryToken implements LocalSourceInputDirectory {
  readonly [LocalSourceInputDirectoryBrand]: typeof LocalSourceInputDirectoryBrand =
    LocalSourceInputDirectoryBrand;
}

class StagingWorkspaceHandleToken implements StagingWorkspaceHandle {
  readonly [StagingWorkspaceHandleBrand]: typeof StagingWorkspaceHandleBrand =
    StagingWorkspaceHandleBrand;
}

class SourceWorkspaceHandleToken implements SourceWorkspaceHandle {
  readonly [SourceWorkspaceHandleBrand]: typeof SourceWorkspaceHandleBrand =
    SourceWorkspaceHandleBrand;
}

class AnalyzerScratchHandleToken implements AnalyzerScratchHandle {
  readonly [AnalyzerScratchHandleBrand]: typeof AnalyzerScratchHandleBrand =
    AnalyzerScratchHandleBrand;
}

const LocalSourceInputDirectorySchema = Schema.NonEmptyString.check(
  Schema.isMaxLength(4_096),
  Schema.makeFilter(value =>
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.includes('\\') &&
    !value.includes('\0') &&
    !/[\u0000-\u001f\u007f]/u.test(value)
      ? undefined
      : 'local source directories must be safe absolute POSIX paths',
  ),
);

const decodeLocalSourceDirectory = Schema.decodeUnknownEffect(
  LocalSourceInputDirectorySchema,
  { onExcessProperty: 'error' },
);

const localSourceDirectories = new WeakMap<LocalSourceInputDirectory, string>();

/**
 * Converts a contract-validated local source string into an opaque input token.
 * The only consumer of its pathname is a Linux descriptor host during a no-follow
 * open; the string is never exposed through a workspace callback.
 */
export const decodeLocalSourceInputDirectory = (directory: string) =>
  decodeLocalSourceDirectory(directory).pipe(
    Effect.mapError(() => accessError('open-external-source', 'unsafe-path')),
    Effect.flatMap(value =>
      Effect.sync(() => {
        const token = new LocalSourceInputDirectoryToken();
        localSourceDirectories.set(token, value);
        return token;
      }),
    ),
  );

export interface DescriptorFileWriter {
  readonly write: (chunk: Uint8Array) => Effect.Effect<void, WorkspaceAccessError>;
}

export interface DescriptorReadOperations {
  /** The host rejects over-budget entries before allocating this batch. */
  readonly readDirectory: (
    path: WorkspaceRelativePath,
    remainingEntries: number,
  ) => Effect.Effect<WorkspaceDirectoryBatch, WorkspaceAccessError>;
  readonly stat: (
    path: WorkspaceRelativePath,
  ) => Effect.Effect<WorkspaceEntryStat, WorkspaceAccessError>;
  readonly readText: (
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<string, WorkspaceAccessError>;
  /** A zero remaining-byte budget may read only an empty regular file. */
  readonly digestRegularFile: (
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError>;
}

export interface DescriptorStagingOperations extends DescriptorReadOperations {
  readonly makeDirectory: (
    path: WorkspaceRelativePath,
  ) => Effect.Effect<void, WorkspaceAccessError>;
  readonly withFileWriter: <A, E, R>(
    path: WorkspaceRelativePath,
    write: (writer: DescriptorFileWriter) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>;
  readonly runGitResolver: (
    command: GitResolverCommand,
  ) => Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope>;
}

export interface DescriptorExternalSourceOperations extends DescriptorReadOperations {
  readonly copyRegularFileTo: (
    sourcePath: WorkspaceRelativePath,
    destination: StagingWorkspaceHandle,
    destinationPath: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError>;
}

export interface LinuxDescriptorFileWriter {
  readonly write: (chunk: Uint8Array) => Effect.Effect<void, WorkspaceAccessError>;
  /** Abort retains quota unless descriptor-relative removal succeeds. */
  readonly close: (commit: boolean) => Effect.Effect<void, WorkspaceAccessError>;
}

export interface LinuxDescriptorReadOperations {
  /** Must enforce the entry budget during enumeration, before batch allocation. */
  readonly readDirectory: (
    path: WorkspaceRelativePath,
    remainingEntries: number,
  ) => Effect.Effect<WorkspaceDirectoryBatch, WorkspaceAccessError>;
  readonly stat: (
    path: WorkspaceRelativePath,
  ) => Effect.Effect<WorkspaceEntryStat, WorkspaceAccessError>;
  readonly readText: (
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<string, WorkspaceAccessError>;
  /** Must stream and stop at the byte budget; zero permits only an empty file. */
  readonly digestRegularFile: (
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError>;
}

export interface LinuxDescriptorStagingOperations extends LinuxDescriptorReadOperations {
  readonly makeDirectory: (
    path: WorkspaceRelativePath,
  ) => Effect.Effect<void, WorkspaceAccessError>;
  readonly openFileWriter: (
    path: WorkspaceRelativePath,
  ) => Effect.Effect<LinuxDescriptorFileWriter, WorkspaceAccessError>;
  /**
   * The binding must reject this before spawn unless this lease has a concrete
   * kernel-enforced total quota and a GitHub-resolution-only sandbox. The host
   * owns a fixed no-shell invocation with ignored stdin, a fixed executable
   * path, and no inherited configuration. Its environment must set
   * `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
   * `HOME=/nonexistent`, `XDG_CONFIG_HOME=/nonexistent`,
   * `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/false`,
   * `GIT_SSH_COMMAND=/bin/false`, `GIT_LFS_SKIP_SMUDGE=1`, and
   * `GIT_OPTIONAL_LOCKS=0`. It must reject protocol or network destinations
   * outside its canonical GitHub resolver policy before spawning.
   */
  readonly runGitResolver: (
    command: GitResolverCommand,
  ) => Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope>;
}

export interface LinuxDescriptorExternalSourceOperations extends LinuxDescriptorReadOperations {
  readonly copyRegularFileTo: (
    sourcePath: WorkspaceRelativePath,
    destination: LinuxDescriptorStagingOperations,
    destinationPath: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError>;
  readonly close: Effect.Effect<void>;
}

export interface LinuxDescriptorWorkspaceLease {
  readonly staging: LinuxDescriptorStagingOperations;
  readonly source: LinuxDescriptorReadOperations;
  /** The binding changes the source view to read-only before resolving. */
  readonly seal: Effect.Effect<void, WorkspaceAccessError>;
  /** Must be uninterruptible and idempotent inside the supplied native binding. */
  readonly close: Effect.Effect<void>;
}

export interface LinuxDescriptorScratchLease {
  readonly scratch: LinuxDescriptorStagingOperations;
  /** Must be uninterruptible and idempotent inside the supplied native binding. */
  readonly close: Effect.Effect<void>;
}

/**
 * A production implementation is Linux-only. It must retain directory
 * descriptors, use component-wise no-follow operations, establish quota before
 * returning a lease, and use descriptor-relative cleanup. Portable Node pathname
 * APIs are deliberately not a valid implementation.
 */
export interface LinuxDescriptorWorkspaceBinding {
  readonly allocate: (
    quota: WorkspaceQuota,
  ) => Effect.Effect<LinuxDescriptorWorkspaceLease, WorkspaceAllocationError>;
  readonly allocateScratch: (
    quota: WorkspaceQuota,
  ) => Effect.Effect<LinuxDescriptorScratchLease, WorkspaceAllocationError>;
  readonly openExternalSource: (
    directory: string,
  ) => Effect.Effect<LinuxDescriptorExternalSourceOperations, WorkspaceAccessError>;
  readonly runAnalyzer: (
    source: LinuxDescriptorReadOperations,
    scratch: LinuxDescriptorStagingOperations,
    request: ProcessRequest,
  ) => Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope>;
}

type WorkspaceLifecycle = 'active' | 'closing' | 'closed';

interface StagingWorkspaceState {
  readonly hostId: symbol;
  readonly lease: LinuxDescriptorWorkspaceLease;
  lifecycle: WorkspaceLifecycle;
  sealed: boolean;
}

interface ScratchWorkspaceState {
  readonly hostId: symbol;
  readonly lease: LinuxDescriptorScratchLease;
  lifecycle: WorkspaceLifecycle;
}

interface ExternalSourceState {
  lifecycle: WorkspaceLifecycle;
  readonly lease: LinuxDescriptorExternalSourceOperations;
}

interface HostInternals {
  readonly binding: LinuxDescriptorWorkspaceBinding;
  readonly gate: Semaphore.Semaphore;
  readonly hostId: symbol;
}

const stagingHandles = new WeakMap<StagingWorkspaceHandleToken, StagingWorkspaceState>();
const sourceHandles = new WeakMap<SourceWorkspaceHandleToken, StagingWorkspaceState>();
const scratchHandles = new WeakMap<AnalyzerScratchHandleToken, ScratchWorkspaceState>();

export interface StagingWorkspace {
  readonly withHandle: <A, E, R>(
    use: (handle: StagingWorkspaceHandle) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>;
  readonly seal: Effect.Effect<SourceWorkspaceHandle, WorkspaceAccessError>;
}

export class WorkspaceDescriptorHost extends Context.Service<WorkspaceDescriptorHost, {
  readonly withStaging: <A, E, R>(
    handle: StagingWorkspaceHandle,
    use: (operations: DescriptorStagingOperations) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>;
  readonly withSource: <A, E, R>(
    handle: SourceWorkspaceHandle,
    use: (operations: DescriptorReadOperations) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>;
  readonly withExternalSource: <A, E, R>(
    input: LocalSourceInputDirectory,
    use: (operations: DescriptorExternalSourceOperations) => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>;
  readonly runAnalyzer: (
    source: SourceWorkspaceHandle,
    scratch: AnalyzerScratchHandle,
    request: ProcessRequest,
  ) => Effect.Effect<ProcessOutput, WorkspaceAccessError, Scope.Scope>;
}>()('@codebase-radar/core/internal/WorkspaceDescriptorHost') {}

type WorkspaceDescriptorHostService = Context.Service.Shape<typeof WorkspaceDescriptorHost>;

/**
 * An explicit, typed fail-closed host for callers that deliberately choose not
 * to install a verified Linux descriptor capability. It is never composed by
 * the public RadarAnalysis layer.
 */
export const WorkspaceDescriptorHostUnavailableLive = Layer.succeed(
  WorkspaceDescriptorHost,
  WorkspaceDescriptorHost.of({
    withStaging: () => hostUnavailable('allocate'),
    withSource: () => hostUnavailable('read-directory'),
    withExternalSource: () => hostUnavailable('open-external-source'),
    runAnalyzer: () => hostUnavailable('run-analyzer'),
  }),
);

const hostInternals = new WeakMap<WorkspaceDescriptorHostService, HostInternals>();

const hostUnavailable = <A>(
  operation: typeof WorkspaceOperation.Type,
): Effect.Effect<A, WorkspaceAccessError> =>
  Effect.fail(accessError(operation, 'capability-unavailable'));

const getInternals = (
  host: WorkspaceDescriptorHostService,
  operation: typeof WorkspaceOperation.Type,
): Effect.Effect<HostInternals, WorkspaceAccessError> => {
  const internals = hostInternals.get(host);
  return internals === undefined
    ? hostUnavailable(operation)
    : Effect.succeed(internals);
};

const checkBound = (
  value: number,
  operation: typeof WorkspaceOperation.Type,
) => decodeBound(value).pipe(
  Effect.mapError(() => accessError(operation, 'bound-exceeded')),
);

const checkPath = (
  value: WorkspaceRelativePath,
  operation: typeof WorkspaceOperation.Type,
) => decodePath(value).pipe(
  Effect.mapError(() => accessError(operation, 'unsafe-path')),
);

const checkDirectoryBatch = (
  batch: WorkspaceDirectoryBatch,
  remainingEntries: number,
) => decodeDirectoryBatch(batch).pipe(
  Effect.mapError(() => accessError('read-directory', 'unsafe-entry')),
  Effect.flatMap(decoded => decoded.entries.length > remainingEntries
    ? Effect.fail(accessError('read-directory', 'bound-exceeded'))
    : Effect.succeed(decoded)),
);

const checkEntryStat = (stat: WorkspaceEntryStat) => decodeEntryStat(stat).pipe(
  Effect.mapError(() => accessError('stat', 'unsafe-entry')),
);

const checkFileDigest = (
  digest: WorkspaceFileDigest,
  remainingBytes: number,
  operation: 'copy-regular-file' | 'digest-regular-file',
) => decodeFileDigest(digest).pipe(
  Effect.mapError(() => accessError(operation, 'unsafe-entry')),
  Effect.flatMap(decoded => decoded.byteLength > remainingBytes
    ? Effect.fail(accessError(operation, 'bound-exceeded'))
    : Effect.succeed(decoded)),
);

const checkProcessRequest = (
  request: ProcessRequest,
  operation: 'run' | 'run-analyzer',
) => decodeProcessRequest(request).pipe(
  Effect.mapError(() => accessError(operation, 'process-rejected')),
);

const checkGitResolverCommand = (command: GitResolverCommand) =>
  decodeGitResolverCommand(command).pipe(
    Effect.mapError(() => accessError('run', 'process-rejected')),
  );

const checkProcessOutput = (
  output: ProcessOutput,
  operation: 'run' | 'run-analyzer',
  timeoutMs: number,
  maxOutputBytes: number,
) => decodeProcessOutput(output).pipe(
  Effect.mapError(() => accessError(operation, 'process-failed')),
  Effect.flatMap(decoded => {
    const outputBytes = utf8ByteLength(decoded.stdout) + utf8ByteLength(decoded.stderr);
    return outputBytes > maxOutputBytes || decoded.truncated
      ? Effect.fail(accessError(operation, 'process-output-truncated'))
      : decoded.durationMs > timeoutMs || decoded.timedOut
        ? Effect.fail(accessError(operation, 'process-timed-out'))
        : Effect.succeed(decoded);
  }),
);

const utf8ByteLength = (value: string) => new TextEncoder().encode(value).byteLength;

const workspaceStateError = (
  lifecycle: WorkspaceLifecycle,
  sealed: boolean,
  required: 'staging' | 'source',
  operation: typeof WorkspaceOperation.Type,
) => lifecycle === 'closed'
  ? accessError(operation, 'workspace-closed')
  : lifecycle === 'closing'
    ? accessError(operation, 'workspace-closing')
    : required === 'staging' && sealed
      ? accessError(operation, 'staging-sealed')
      : required === 'source' && !sealed
        ? accessError(operation, 'read-only')
        : undefined;

const scratchStateError = (
  lifecycle: WorkspaceLifecycle,
  operation: typeof WorkspaceOperation.Type,
) => lifecycle === 'closed'
  ? accessError(operation, 'workspace-closed')
  : lifecycle === 'closing'
    ? accessError(operation, 'workspace-closing')
    : undefined;

const accessStaging = <A, E, R>(
  internals: HostInternals,
  state: StagingWorkspaceState,
  operation: typeof WorkspaceOperation.Type,
  use: () => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | WorkspaceAccessError, R> => internals.gate.withPermit(
  Effect.suspend<A, E | WorkspaceAccessError, R>(() => {
    const failure = workspaceStateError(state.lifecycle, state.sealed, 'staging', operation);
    return failure === undefined ? use() : Effect.fail(failure);
  }),
);

const accessSource = <A, E, R>(
  internals: HostInternals,
  state: StagingWorkspaceState,
  operation: typeof WorkspaceOperation.Type,
  use: () => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | WorkspaceAccessError, R> => internals.gate.withPermit(
  Effect.suspend<A, E | WorkspaceAccessError, R>(() => {
    const failure = workspaceStateError(state.lifecycle, state.sealed, 'source', operation);
    return failure === undefined ? use() : Effect.fail(failure);
  }),
);

const accessScratch = <A, E, R>(
  internals: HostInternals,
  state: ScratchWorkspaceState,
  operation: typeof WorkspaceOperation.Type,
  use: () => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | WorkspaceAccessError, R> => internals.gate.withPermit(
  Effect.suspend<A, E | WorkspaceAccessError, R>(() => {
    const failure = scratchStateError(state.lifecycle, operation);
    return failure === undefined ? use() : Effect.fail(failure);
  }),
);

const accessExternal = <A, E, R>(
  internals: HostInternals,
  state: ExternalSourceState,
  operation: typeof WorkspaceOperation.Type,
  use: () => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | WorkspaceAccessError, R> => internals.gate.withPermit(
  Effect.suspend<A, E | WorkspaceAccessError, R>(() => {
    const failure = state.lifecycle === 'closed'
      ? accessError(operation, 'workspace-closed')
      : state.lifecycle === 'closing'
        ? accessError(operation, 'workspace-closing')
        : undefined;
    return failure === undefined ? use() : Effect.fail(failure);
  }),
);

const createReadOperations = (
  internals: HostInternals,
  access: <A, E, R>(
    operation: typeof WorkspaceOperation.Type,
    use: () => Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E | WorkspaceAccessError, R>,
  native: LinuxDescriptorReadOperations,
): DescriptorReadOperations => ({
  readDirectory: (path, remainingEntries) => checkPath(path, 'read-directory').pipe(
    Effect.flatMap(validPath => checkBound(remainingEntries, 'read-directory').pipe(
      Effect.flatMap(validBound => access(
        'read-directory',
        () => native.readDirectory(validPath, validBound).pipe(
          Effect.flatMap(batch => checkDirectoryBatch(batch, validBound)),
        ),
      )),
    )),
  ),
  stat: path => checkPath(path, 'stat').pipe(
    Effect.flatMap(validPath => access(
      'stat',
      () => native.stat(validPath).pipe(Effect.flatMap(checkEntryStat)),
    )),
  ),
  readText: (path, remainingBytes) => checkPath(path, 'read-text').pipe(
    Effect.flatMap(validPath => checkBound(remainingBytes, 'read-text').pipe(
      Effect.flatMap(validBound => access(
        'read-text',
        () => native.readText(validPath, validBound).pipe(
          Effect.flatMap(value => utf8ByteLength(value) > validBound
            ? Effect.fail(accessError('read-text', 'bound-exceeded'))
            : Effect.succeed(value)),
        ),
      )),
    )),
  ),
  digestRegularFile: (path, remainingBytes) => checkPath(path, 'digest-regular-file').pipe(
    Effect.flatMap(validPath => checkBound(remainingBytes, 'digest-regular-file').pipe(
      Effect.flatMap(validBound => access(
        'digest-regular-file',
        () => native.digestRegularFile(validPath, validBound).pipe(
          Effect.flatMap(digest => checkFileDigest(
            digest,
            validBound,
            'digest-regular-file',
          )),
        ),
      )),
    )),
  ),
});

const resolveStaging = (
  handle: StagingWorkspaceHandle,
  internals: HostInternals,
  operation: typeof WorkspaceOperation.Type,
): Effect.Effect<StagingWorkspaceState, WorkspaceAccessError> => {
  const state = stagingHandles.get(handle);
  return state === undefined
    ? Effect.fail(accessError(operation, 'unrecognized-handle'))
    : state.hostId !== internals.hostId
      ? Effect.fail(accessError(operation, 'cross-host-handle'))
      : Effect.succeed(state);
};

const resolveSource = (
  handle: SourceWorkspaceHandle,
  internals: HostInternals,
  operation: typeof WorkspaceOperation.Type,
): Effect.Effect<StagingWorkspaceState, WorkspaceAccessError> => {
  const state = sourceHandles.get(handle);
  return state === undefined
    ? Effect.fail(accessError(operation, 'unrecognized-handle'))
    : state.hostId !== internals.hostId
      ? Effect.fail(accessError(operation, 'cross-host-handle'))
      : Effect.succeed(state);
};

const resolveScratch = (
  handle: AnalyzerScratchHandle,
  internals: HostInternals,
  operation: typeof WorkspaceOperation.Type,
): Effect.Effect<ScratchWorkspaceState, WorkspaceAccessError> => {
  const state = scratchHandles.get(handle);
  return state === undefined
    ? Effect.fail(accessError(operation, 'unrecognized-handle'))
    : state.hostId !== internals.hostId
      ? Effect.fail(accessError(operation, 'cross-host-handle'))
      : Effect.succeed(state);
};

const stagingOperations = (
  internals: HostInternals,
  state: StagingWorkspaceState,
): DescriptorStagingOperations => {
  const access = <A, E, R>(
    operation: typeof WorkspaceOperation.Type,
    use: () => Effect.Effect<A, E, R>,
  ) => accessStaging(internals, state, operation, use);
  const read = createReadOperations(internals, access, state.lease.staging);
  return {
    ...read,
    makeDirectory: path => checkPath(path, 'make-directory').pipe(
      Effect.flatMap(validPath => access(
        'make-directory',
        () => state.lease.staging.makeDirectory(validPath),
      )),
    ),
    withFileWriter: (path, write) => checkPath(path, 'write-file').pipe(
      Effect.flatMap(validPath => Effect.acquireUseRelease(
        access('write-file', () => state.lease.staging.openFileWriter(validPath)),
        nativeWriter => {
          let closed = false;
          const writer: DescriptorFileWriter = {
            write: chunk => access('write-file', () => closed
              ? Effect.fail(accessError('write-file', 'workspace-closed'))
              : nativeWriter.write(chunk)),
          };
          return write(writer).pipe(
            Effect.ensuring(Effect.sync(() => {
              closed = true;
            })),
          );
        },
        (nativeWriter, exit) => internals.gate.withPermit(
            nativeWriter.close(exit._tag === 'Success').pipe(Effect.orDie),
        ),
      )),
    ),
    runGitResolver: command => checkGitResolverCommand(command).pipe(
      Effect.flatMap(validCommand => access(
        'run',
        () => state.lease.staging.runGitResolver(validCommand).pipe(
          Effect.flatMap(output => checkProcessOutput(
            output,
            'run',
            validCommand.timeoutMs,
            validCommand.maxOutputBytes,
          )),
        ),
      )),
    ),
  };
};

const sourceOperations = (
  internals: HostInternals,
  state: StagingWorkspaceState,
): DescriptorReadOperations => createReadOperations(
  internals,
  (operation, use) => accessSource(internals, state, operation, use),
  state.lease.source,
);

const externalOperations = (
  internals: HostInternals,
  state: ExternalSourceState,
): DescriptorExternalSourceOperations => {
  const access = <A, E, R>(
    operation: typeof WorkspaceOperation.Type,
    use: () => Effect.Effect<A, E, R>,
  ) => accessExternal(internals, state, operation, use);
  const read = createReadOperations(internals, access, state.lease);
  return {
    ...read,
    copyRegularFileTo: (sourcePath, destination, destinationPath, remainingBytes) =>
      checkPath(sourcePath, 'copy-regular-file').pipe(
        Effect.flatMap(validSourcePath => checkPath(destinationPath, 'copy-regular-file').pipe(
          Effect.flatMap(validDestinationPath => checkBound(
            remainingBytes,
            'copy-regular-file',
          ).pipe(
            Effect.flatMap(validBound => resolveStaging(
              destination,
              internals,
              'copy-regular-file',
            ).pipe(
              Effect.flatMap(destinationState => internals.gate.withPermit(
                Effect.suspend(() => {
                  const externalFailure = state.lifecycle === 'closed'
                    ? accessError('copy-regular-file', 'workspace-closed')
                    : state.lifecycle === 'closing'
                      ? accessError('copy-regular-file', 'workspace-closing')
                      : undefined;
                  const destinationFailure = workspaceStateError(
                    destinationState.lifecycle,
                    destinationState.sealed,
                    'staging',
                    'copy-regular-file',
                  );
                  if (externalFailure !== undefined) return Effect.fail(externalFailure);
                  if (destinationFailure !== undefined) return Effect.fail(destinationFailure);
                  return state.lease.copyRegularFileTo(
                    validSourcePath,
                    destinationState.lease.staging,
                    validDestinationPath,
                    validBound,
                  ).pipe(
                    Effect.flatMap(digest => checkFileDigest(
                      digest,
                      validBound,
                      'copy-regular-file',
                    )),
                  );
                }),
              )),
            )),
          )),
        )),
      ),
  };
};

const releaseStaging = (
  internals: HostInternals,
  state: StagingWorkspaceState,
) => internals.gate.withPermit(
  Effect.uninterruptible(
    Effect.suspend(() => {
      if (state.lifecycle !== 'active') return Effect.void;
      state.lifecycle = 'closing';
      return state.lease.close.pipe(
        Effect.ensuring(Effect.sync(() => {
          state.lifecycle = 'closed';
        })),
      );
    }),
  ),
);

const releaseScratch = (
  internals: HostInternals,
  state: ScratchWorkspaceState,
) => internals.gate.withPermit(
  Effect.uninterruptible(
    Effect.suspend(() => {
      if (state.lifecycle !== 'active') return Effect.void;
      state.lifecycle = 'closing';
      return state.lease.close.pipe(
        Effect.ensuring(Effect.sync(() => {
          state.lifecycle = 'closed';
        })),
      );
    }),
  ),
);

const releaseExternalSource = (
  internals: HostInternals,
  state: ExternalSourceState,
) => internals.gate.withPermit(
  Effect.uninterruptible(
    Effect.suspend(() => {
      if (state.lifecycle !== 'active') return Effect.void;
      state.lifecycle = 'closing';
      return state.lease.close.pipe(
        Effect.ensuring(Effect.sync(() => {
          state.lifecycle = 'closed';
        })),
      );
    }),
  ),
);

const makeStagingState = (
  hostId: symbol,
  lease: LinuxDescriptorWorkspaceLease,
): StagingWorkspaceState => ({
  hostId,
  lease,
  lifecycle: 'active',
  sealed: false,
});

const makeScratchState = (
  hostId: symbol,
  lease: LinuxDescriptorScratchLease,
): ScratchWorkspaceState => ({
  hostId,
  lease,
  lifecycle: 'active',
});

const makeExternalSourceState = (
  lease: LinuxDescriptorExternalSourceOperations,
): ExternalSourceState => ({
  lifecycle: 'active',
  lease,
});

const allocateStaging = (
  host: WorkspaceDescriptorHostService,
  quota: WorkspaceQuota,
): Effect.Effect<StagingWorkspace, WorkspaceAllocationError, Scope.Scope> =>
  getInternals(host, 'allocate').pipe(
    Effect.mapError(error => allocationError(error.reason)),
    Effect.flatMap(internals => decodeQuota(quota).pipe(
      Effect.mapError(() => allocationError('bound-exceeded')),
      // acquireRelease masks the native acquisition until its finalizer is
      // registered, then releases the exact lease on every scope exit.
      Effect.flatMap(validQuota => Effect.acquireRelease(
        internals.binding.allocate(validQuota).pipe(
          Effect.map(lease => makeStagingState(internals.hostId, lease)),
        ),
        state => releaseStaging(internals, state),
      )),
      Effect.map(state => {
        const stagingHandle = new StagingWorkspaceHandleToken();
        stagingHandles.set(stagingHandle, state);
        return {
          withHandle: use => accessStaging(
            internals,
            state,
            'allocate',
            () => Effect.void,
          ).pipe(Effect.andThen(use(stagingHandle))),
          seal: accessStaging(
            internals,
            state,
            'seal',
            () => state.lease.seal.pipe(
              Effect.andThen(Effect.sync(() => {
                state.sealed = true;
                const sourceHandle = new SourceWorkspaceHandleToken();
                sourceHandles.set(sourceHandle, state);
                return sourceHandle;
              })),
            ),
          ),
        };
      }),
    )),
  );

const allocateScratch = (
  host: WorkspaceDescriptorHostService,
  quota: WorkspaceQuota,
): Effect.Effect<AnalyzerScratchHandle, WorkspaceAllocationError, Scope.Scope> =>
  getInternals(host, 'allocate-scratch').pipe(
    Effect.mapError(error => allocationError(error.reason)),
    Effect.flatMap(internals => decodeQuota(quota).pipe(
      Effect.mapError(() => allocationError('bound-exceeded')),
      // See staging allocation: this is the cancellation-safe native bracket
      // for one analyzer's short-lived scratch lease.
      Effect.flatMap(validQuota => Effect.acquireRelease(
        internals.binding.allocateScratch(validQuota).pipe(
          Effect.map(lease => makeScratchState(internals.hostId, lease)),
        ),
        state => releaseScratch(internals, state),
      )),
      Effect.map(state => {
        const handle = new AnalyzerScratchHandleToken();
        scratchHandles.set(handle, state);
        return handle;
      }),
    )),
  );

export const makeLinuxDescriptorWorkspaceHost = (
  binding: LinuxDescriptorWorkspaceBinding,
): Effect.Effect<WorkspaceDescriptorHostService> =>
  Effect.gen(function* () {
    const gate = yield* Semaphore.make(1);
    const hostId = Symbol('codebase-radar-linux-descriptor-workspace');
    const internals: HostInternals = { binding, gate, hostId };
    const service = WorkspaceDescriptorHost.of({
      withStaging: (handle, use) => resolveStaging(handle, internals, 'allocate').pipe(
        Effect.flatMap(state => accessStaging(
          internals,
          state,
          'allocate',
          () => Effect.void,
        ).pipe(Effect.andThen(use(stagingOperations(internals, state))))),
      ),
      withSource: (handle, use) => resolveSource(handle, internals, 'read-directory').pipe(
        Effect.flatMap(state => accessSource(
          internals,
          state,
          'read-directory',
          () => Effect.void,
        ).pipe(Effect.andThen(use(sourceOperations(internals, state))))),
      ),
      withExternalSource: (input, use) => {
        const directory = localSourceDirectories.get(input);
        return directory === undefined
          ? Effect.fail(accessError('open-external-source', 'unrecognized-handle'))
          : Effect.acquireUseRelease(
            internals.binding.openExternalSource(directory).pipe(
              Effect.map(lease => ({
                lease,
                state: makeExternalSourceState(lease),
              })),
            ),
            resource => use(externalOperations(internals, resource.state)),
            resource => releaseExternalSource(internals, resource.state),
          );
      },
      runAnalyzer: (source, scratch, request) => checkProcessRequest(
        request,
        'run-analyzer',
      ).pipe(
        Effect.flatMap(validRequest => resolveSource(
          source,
          internals,
          'run-analyzer',
        ).pipe(
          Effect.flatMap(sourceState => resolveScratch(
            scratch,
            internals,
            'run-analyzer',
          ).pipe(
            Effect.flatMap(scratchState => internals.gate.withPermit(
              Effect.suspend(() => {
                const sourceFailure = workspaceStateError(
                  sourceState.lifecycle,
                  sourceState.sealed,
                  'source',
                  'run-analyzer',
                );
                const scratchFailure = scratchStateError(
                  scratchState.lifecycle,
                  'run-analyzer',
                );
                if (sourceFailure !== undefined) return Effect.fail(sourceFailure);
                if (scratchFailure !== undefined) return Effect.fail(scratchFailure);
                return internals.binding.runAnalyzer(
                  sourceState.lease.source,
                  scratchState.lease.scratch,
                  validRequest,
                ).pipe(
                  Effect.flatMap(output => checkProcessOutput(
                    output,
                    'run-analyzer',
                    validRequest.timeoutMs,
                    validRequest.maxOutputBytes,
                  )),
                );
              }),
            )),
          )),
        )),
      ),
    });
    hostInternals.set(service, internals);
    return service;
  });

/**
 * Test and integration construction route. A caller must supply the native
 * descriptor capability; there is intentionally no pathname-based fallback.
 */
export const makeLinuxDescriptorWorkspaceHostLayer = (
  binding: LinuxDescriptorWorkspaceBinding,
) => Layer.effect(WorkspaceDescriptorHost, makeLinuxDescriptorWorkspaceHost(binding));

export class WorkspaceAllocator extends Context.Service<WorkspaceAllocator, {
  readonly allocate: (
    quota: WorkspaceQuota,
  ) => Effect.Effect<StagingWorkspace, WorkspaceAllocationError, Scope.Scope>;
  readonly allocateScratch: (
    quota: WorkspaceQuota,
  ) => Effect.Effect<AnalyzerScratchHandle, WorkspaceAllocationError, Scope.Scope>;
}>()('@codebase-radar/core/internal/WorkspaceAllocator') {}

/**
 * This layer has an explicit native descriptor-host requirement. It cannot
 * allocate through ordinary pathname-based temporary directories or a fail-open
 * fallback.
 */
export const WorkspaceAllocatorLive = Layer.effect(
  WorkspaceAllocator,
  Effect.gen(function* () {
    const host = yield* WorkspaceDescriptorHost;
    return WorkspaceAllocator.of({
      allocate: quota => allocateStaging(host, quota),
      allocateScratch: quota => allocateScratch(host, quota),
    });
  }),
);

export class WorkspaceReader extends Context.Service<WorkspaceReader, {
  readonly readDirectory: (
    workspace: SourceWorkspaceHandle,
    path: WorkspaceRelativePath,
    remainingEntries: number,
  ) => Effect.Effect<WorkspaceDirectoryBatch, WorkspaceAccessError>;
  readonly stat: (
    workspace: SourceWorkspaceHandle,
    path: WorkspaceRelativePath,
  ) => Effect.Effect<WorkspaceEntryStat, WorkspaceAccessError>;
  readonly readText: (
    workspace: SourceWorkspaceHandle,
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<string, WorkspaceAccessError>;
  readonly digestRegularFile: (
    workspace: SourceWorkspaceHandle,
    path: WorkspaceRelativePath,
    remainingBytes: number,
  ) => Effect.Effect<WorkspaceFileDigest, WorkspaceAccessError>;
}>()('@codebase-radar/core/internal/WorkspaceReader') {}

export const WorkspaceReaderLive = Layer.effect(
  WorkspaceReader,
  Effect.gen(function* () {
    const host = yield* WorkspaceDescriptorHost;
    return WorkspaceReader.of({
      readDirectory: (workspace, path, remainingEntries) => host.withSource(
        workspace,
        operations => operations.readDirectory(path, remainingEntries),
      ),
      stat: (workspace, path) => host.withSource(
        workspace,
        operations => operations.stat(path),
      ),
      readText: (workspace, path, remainingBytes) => host.withSource(
        workspace,
        operations => operations.readText(path, remainingBytes),
      ),
      digestRegularFile: (workspace, path, remainingBytes) => host.withSource(
        workspace,
        operations => operations.digestRegularFile(path, remainingBytes),
      ),
    });
  }),
);

export const DefaultAnalyzerScratchQuota = new WorkspaceQuota({
  maximumEntries: 256,
  maximumFiles: 128,
  maximumBytes: 16 * 1024 * 1024,
});
