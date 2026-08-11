import { createHash } from 'node:crypto';
import { Context, Effect, Layer, Schema, Scope } from 'effect';
import {
  AnalysisSource,
  SourceIdentity,
  type GitHubSource,
  type LocalDirectorySource,
} from '@codebase-radar/contracts/source';
import {
  decodeLocalSourceInputDirectory,
  SourceSnapshot,
  type DescriptorExternalSourceOperations,
  type DescriptorReadOperations,
  type DescriptorStagingOperations,
  type SourceWorkspaceHandle,
  type StagingWorkspaceHandle,
  type StagingWorkspace,
  WorkspaceAllocator,
  type WorkspaceAccessError,
  type WorkspaceAllocationError,
  WorkspaceDescriptorHost,
  WorkspaceQuota,
  WorkspaceRelativePath,
  WorkspaceRoot,
} from '../workspace.js';
import {
  decodeSourceMaterializationLimits,
  defaultSourceMaterializationLimits,
  GitHubCodeloadArchiveError,
  GitHubCodeloadArchiveReceipt,
  GitHubCodeloadArchiveRequest,
  GitHubCodeloadArchiveTransport,
  GitHubRevisionResolution,
  GitHubRevisionResolver,
  GitHubRevisionResolverError,
  type SourceMaterializationLimits,
  SourceMaterializationError,
} from './ports.js';

export interface MaterializedSource {
  readonly identity: typeof SourceIdentity.Type;
  readonly snapshot: SourceSnapshot;
  readonly workspace: SourceWorkspaceHandle;
}

export interface SourceMaterializerService {
  readonly materialize: (
    source: AnalysisSource,
  ) => Effect.Effect<MaterializedSource, SourceMaterializationError, Scope.Scope>;
}

export interface SourceMaterializerHost {
  readonly workspace: {
    readonly allocate: (
      quota: WorkspaceQuota,
    ) => Effect.Effect<StagingWorkspace, WorkspaceAllocationError, Scope.Scope>;
  };
  readonly descriptor: Context.Service.Shape<typeof WorkspaceDescriptorHost>;
  readonly resolver: Context.Service.Shape<typeof GitHubRevisionResolver>;
  readonly archives: Context.Service.Shape<typeof GitHubCodeloadArchiveTransport>;
  readonly limits?: SourceMaterializationLimits;
}

export class SourceMaterializer extends Context.Service<SourceMaterializer, SourceMaterializerService>()(
  '@codebase-radar/core/internal/SourceMaterializer',
) {}

const sourceError = (
  source: 'github' | 'local',
  stage:
    | 'workspace'
    | 'local-capture'
    | 'github-resolve'
    | 'github-stage'
    | 'snapshot'
    | 'identity',
  reason:
    | 'capability-unavailable'
    | 'transport-failed'
    | 'invalid-response'
    | 'missing-revision'
    | 'ambiguous-revision'
    | 'revision-changed'
    | 'unsafe-entry'
    | 'nested-repository'
    | 'source-limit-exceeded'
    | 'invalid-identity',
): SourceMaterializationError => new SourceMaterializationError({ source, stage, reason });

const githubIdentityUrl = (owner: string, repository: string): string =>
  `https://github.com/${owner}/${repository}`;

const githubCodebaseId = (owner: string, repository: string): string =>
  `github:${owner.toLowerCase()}/${repository.toLowerCase()}`;

const compareCodeUnits = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const maximumAuditedPathCharacters = 1_024;

const pathText = (path: WorkspaceRelativePath): string => path.segments.join('/');

const childPath = (
  parent: WorkspaceRelativePath,
  name: string,
): WorkspaceRelativePath => new WorkspaceRelativePath({
  segments: [...parent.segments, name],
});

interface AuditedRegularFile {
  readonly path: WorkspaceRelativePath;
  readonly text: string;
  readonly byteLength: number;
  readonly contentDigest: string;
}

interface AuditedTree {
  readonly directories: ReadonlyArray<WorkspaceRelativePath>;
  readonly files: ReadonlyArray<AuditedRegularFile>;
  readonly entryCount: number;
  readonly fileCount: number;
  readonly totalBytes: number;
  readonly contentDigest: string;
}

interface SnapshotTotals {
  readonly fileCount: number;
  readonly totalBytes: number;
}

const mapWorkspaceError = (
  source: 'github' | 'local',
  stage:
    | 'workspace'
    | 'local-capture'
    | 'github-resolve'
    | 'github-stage'
    | 'snapshot',
) => (error: WorkspaceAccessError | WorkspaceAllocationError): SourceMaterializationError => {
  switch (error.reason) {
    case 'workspace-quota-exceeded':
    case 'bound-exceeded':
      return sourceError(source, stage, 'source-limit-exceeded');
    case 'capability-unavailable':
    case 'unsupported-platform':
    case 'procfs-unavailable':
    case 'workspace-quota-unenforced':
      return sourceError(source, stage, 'capability-unavailable');
    case 'unsafe-entry':
    case 'unsafe-path':
      return sourceError(source, stage, 'unsafe-entry');
    default:
      return sourceError(source, stage, 'transport-failed');
  }
};

const mapArchiveError = (error: GitHubCodeloadArchiveError): SourceMaterializationError =>
  error.code === 'source-limit-exceeded'
    ? sourceError('github', 'github-stage', 'source-limit-exceeded')
    : error.code === 'missing-revision'
      ? sourceError('github', 'github-stage', 'missing-revision')
      : error.code === 'revision-changed'
        ? sourceError('github', 'github-stage', 'revision-changed')
        : error.code === 'capability-unavailable'
          ? sourceError('github', 'github-stage', 'capability-unavailable')
          : error.code === 'archive-invalid'
            ? sourceError('github', 'github-stage', 'unsafe-entry')
            : sourceError('github', 'github-stage', 'transport-failed');

const mapResolverError = (error: GitHubRevisionResolverError): SourceMaterializationError =>
  error.code === 'source-limit-exceeded'
    ? sourceError('github', 'github-resolve', 'source-limit-exceeded')
    : error.code === 'missing-revision'
      ? sourceError('github', 'github-resolve', 'missing-revision')
      : error.code === 'ambiguous-revision'
        ? sourceError('github', 'github-resolve', 'ambiguous-revision')
        : error.code === 'capability-unavailable'
          ? sourceError('github', 'github-resolve', 'capability-unavailable')
          : error.code === 'invalid-response'
            ? sourceError('github', 'github-resolve', 'invalid-response')
            : sourceError('github', 'github-resolve', 'transport-failed');

const mapSourceOrWorkspaceError = (
  source: 'github' | 'local',
  stage:
    | 'workspace'
    | 'local-capture'
    | 'github-resolve'
    | 'github-stage'
    | 'snapshot',
) => (error: SourceMaterializationError | WorkspaceAccessError): SourceMaterializationError =>
  error instanceof SourceMaterializationError
    ? error
    : mapWorkspaceError(source, stage)(error);

const treeDigest = (
  files: ReadonlyArray<AuditedRegularFile>,
  source: 'github' | 'local',
): Effect.Effect<string, SourceMaterializationError> => Effect.try({
  try: () => {
    const digest = createHash('sha256');
    const ordered = [...files].toSorted((left, right) => compareCodeUnits(left.text, right.text));
    for (const file of ordered) {
      digest.update(
        `f${file.text.length}:${file.text}${file.byteLength}:${file.byteLength}${file.contentDigest.length}:${file.contentDigest}`,
        'utf8',
      );
    }
    return `sha256:${digest.digest('hex')}`;
  },
  catch: () => sourceError(source, 'snapshot', 'invalid-response'),
});

const isNestedGitMetadata = (path: WorkspaceRelativePath): boolean =>
  path.segments.some(segment => segment === '.git');

function auditTree(
  source: 'github' | 'local',
  stage: 'local-capture' | 'github-stage' | 'snapshot',
  operations: DescriptorReadOperations,
  limits: SourceMaterializationLimits,
  skipRootGitDirectory: boolean,
): Effect.Effect<AuditedTree, SourceMaterializationError> {
  return Effect.gen(function* () {
    const directories = new Array<WorkspaceRelativePath>();
    const files = new Array<AuditedRegularFile>();
    const seenPaths = new Set<string>();
    let entryCount = 0;
    let fileCount = 0;
    let totalBytes = 0;

    const visit = (parent: WorkspaceRelativePath): Effect.Effect<void, SourceMaterializationError> =>
      Effect.gen(function* () {
        // At the exact entry limit, ask the descriptor host for a zero-sized
        // batch. Its truncation bit distinguishes an empty directory from one
        // more entry without trusting a second, unbounded listing.
        const remainingEntries = Math.max(0, limits.maximumEntries - entryCount);
        const batch = yield* operations.readDirectory(parent, remainingEntries).pipe(
          Effect.mapError(mapWorkspaceError(source, stage)),
        );
        if (batch.truncated) {
          return yield* Effect.fail(sourceError(source, stage, 'source-limit-exceeded'));
        }
        const names = new Set<string>();
        for (const entry of batch.entries.toSorted((left, right) => compareCodeUnits(left.name, right.name))) {
          if (names.has(entry.name)) {
            return yield* Effect.fail(sourceError(source, stage, 'invalid-response'));
          }
          names.add(entry.name);
          const child = childPath(parent, entry.name);
          const stat = yield* operations.stat(child).pipe(
            Effect.mapError(mapWorkspaceError(source, stage)),
          );
          if (stat.kind !== entry.kind) {
            return yield* Effect.fail(sourceError(source, stage, 'transport-failed'));
          }
          const rootGitDirectory = skipRootGitDirectory &&
            parent.segments.length === 0 &&
            entry.name === '.git' &&
            stat.kind === 'directory';
          if (rootGitDirectory) continue;
          if (isNestedGitMetadata(child)) {
            return yield* Effect.fail(sourceError(source, stage, 'nested-repository'));
          }
          const text = pathText(child);
          if (text.length > maximumAuditedPathCharacters) {
            return yield* Effect.fail(sourceError(source, stage, 'source-limit-exceeded'));
          }
          if (seenPaths.has(text)) {
            return yield* Effect.fail(sourceError(source, stage, 'invalid-response'));
          }
          seenPaths.add(text);
          const nextEntryCount = entryCount + 1;
          if (nextEntryCount > limits.maximumEntries) {
            return yield* Effect.fail(sourceError(source, stage, 'source-limit-exceeded'));
          }
          entryCount = nextEntryCount;
          if (stat.kind === 'directory') {
            directories.push(child);
            yield* visit(child);
            continue;
          }
          if (stat.kind !== 'file') {
            return yield* Effect.fail(sourceError(source, stage, 'unsafe-entry'));
          }
          const nextFileCount = fileCount + 1;
          if (nextFileCount > limits.maximumFiles) {
            return yield* Effect.fail(sourceError(source, stage, 'source-limit-exceeded'));
          }
          const remainingBytes = limits.maximumBytes - totalBytes;
          const digest = yield* operations.digestRegularFile(child, remainingBytes).pipe(
            Effect.mapError(mapWorkspaceError(source, stage)),
          );
          if (digest.byteLength !== stat.byteLength) {
            return yield* Effect.fail(sourceError(source, stage, 'transport-failed'));
          }
          const nextTotalBytes = totalBytes + digest.byteLength;
          if (!Number.isSafeInteger(nextTotalBytes) || nextTotalBytes > limits.maximumBytes) {
            return yield* Effect.fail(sourceError(source, stage, 'source-limit-exceeded'));
          }
          fileCount = nextFileCount;
          totalBytes = nextTotalBytes;
          files.push({
            path: child,
            text,
            byteLength: digest.byteLength,
            contentDigest: digest.contentDigest,
          });
        }
      });

    yield* visit(WorkspaceRoot);
    const orderedFiles = files.toSorted((left, right) => compareCodeUnits(left.text, right.text));
    for (let index = 1; index < orderedFiles.length; index += 1) {
      const previous = orderedFiles.at(index - 1);
      const current = orderedFiles.at(index);
      if (previous === undefined || current === undefined) {
        return yield* Effect.fail(sourceError(source, stage, 'invalid-response'));
      }
      if (current.text.startsWith(`${previous.text}/`)) {
        return yield* Effect.fail(sourceError(source, stage, 'invalid-response'));
      }
    }
    const contentDigest = yield* treeDigest(orderedFiles, source);
    return {
      directories: directories.toSorted((left, right) => compareCodeUnits(pathText(left), pathText(right))),
      files: orderedFiles,
      entryCount,
      fileCount,
      totalBytes,
      contentDigest,
    };
  });
}

const sameTree = (left: AuditedTree, right: AuditedTree): boolean =>
  left.fileCount === right.fileCount &&
  left.totalBytes === right.totalBytes &&
  left.contentDigest === right.contentDigest;

function copyAuditedTree(
  source: DescriptorExternalSourceOperations,
  destination: DescriptorStagingOperations,
  staging: StagingWorkspaceHandle,
  tree: AuditedTree,
  limits: SourceMaterializationLimits,
): Effect.Effect<void, SourceMaterializationError> {
  return Effect.gen(function* () {
    for (const directory of tree.directories) {
      yield* destination.makeDirectory(directory).pipe(
        Effect.mapError(mapWorkspaceError('local', 'local-capture')),
      );
    }
    let copiedBytes = 0;
    for (const file of tree.files) {
      const remainingBytes = limits.maximumBytes - copiedBytes;
      const copied = yield* source.copyRegularFileTo(
        file.path,
        staging,
        file.path,
        remainingBytes,
      ).pipe(Effect.mapError(mapWorkspaceError('local', 'local-capture')));
      if (copied.byteLength !== file.byteLength || copied.contentDigest !== file.contentDigest) {
        return yield* Effect.fail(sourceError('local', 'local-capture', 'transport-failed'));
      }
      const nextCopiedBytes = copiedBytes + copied.byteLength;
      if (!Number.isSafeInteger(nextCopiedBytes) || nextCopiedBytes > limits.maximumBytes) {
        return yield* Effect.fail(sourceError('local', 'local-capture', 'source-limit-exceeded'));
      }
      copiedBytes = nextCopiedBytes;
    }
  });
}

const sourceSnapshot = (
  digest: string,
  totals: SnapshotTotals,
): SourceSnapshot => new SourceSnapshot({
  snapshotDigest: digest,
  fileCount: totals.fileCount,
  totalBytes: totals.totalBytes,
});

function decodedIdentity(
  value: {
    readonly _tag: 'LocalSourceIdentity';
    readonly codebaseId: string;
    readonly repository: string;
    readonly snapshotDigest: string;
    readonly dirty: boolean;
  } | {
    readonly _tag: 'GitHubSourceIdentity';
    readonly codebaseId: string;
    readonly owner: string;
    readonly repository: string;
    readonly url: string;
    readonly commitSha: string;
    readonly defaultBranch: string;
    readonly snapshotDigest: string;
  },
  source: 'github' | 'local',
): Effect.Effect<typeof SourceIdentity.Type, SourceMaterializationError> {
  return Schema.decodeEffect(SourceIdentity, {
    onExcessProperty: 'error',
  })(value).pipe(Effect.mapError(() => sourceError(source, 'identity', 'invalid-identity')));
}

const quotaFor = (limits: SourceMaterializationLimits): WorkspaceQuota => new WorkspaceQuota({
  maximumEntries: limits.maximumEntries,
  maximumFiles: limits.maximumFiles,
  maximumBytes: limits.maximumBytes,
});

function checkedLimits(
  source: 'github' | 'local',
  value: SourceMaterializationLimits,
): Effect.Effect<SourceMaterializationLimits, SourceMaterializationError> {
  return decodeSourceMaterializationLimits(value).pipe(
    Effect.mapError(() => sourceError(source, 'workspace', 'invalid-response')),
    Effect.flatMap(limits => limits.maximumFiles > limits.maximumEntries
      ? Effect.fail(sourceError(source, 'workspace', 'invalid-response'))
      : Effect.succeed(limits)),
  );
}

function materializeLocal(
  source: LocalDirectorySource,
  host: SourceMaterializerHost,
  limits: SourceMaterializationLimits,
): Effect.Effect<MaterializedSource, SourceMaterializationError, Scope.Scope> {
  return Effect.gen(function* () {
    const input = yield* decodeLocalSourceInputDirectory(source.directory).pipe(
      Effect.mapError(mapWorkspaceError('local', 'local-capture')),
    );
    const staging = yield* host.workspace.allocate(quotaFor(limits)).pipe(
      Effect.mapError(mapWorkspaceError('local', 'workspace')),
    );
    const captured = yield* host.descriptor.withExternalSource(input, external => staging.withHandle(
      handle => host.descriptor.withStaging(handle, destination => Effect.gen(function* () {
        const before = yield* auditTree('local', 'local-capture', external, limits, true);
        yield* copyAuditedTree(external, destination, handle, before, limits);
        const after = yield* auditTree('local', 'local-capture', external, limits, true);
        const staged = yield* auditTree('local', 'snapshot', destination, limits, false);
        if (!sameTree(before, after) || !sameTree(before, staged)) {
          return yield* Effect.fail(sourceError('local', 'local-capture', 'transport-failed'));
        }
        return staged;
      })),
    )).pipe(Effect.mapError(mapSourceOrWorkspaceError('local', 'local-capture')));
    const workspace = yield* staging.seal.pipe(
      Effect.mapError(mapWorkspaceError('local', 'workspace')),
    );
    const repository = `local-${captured.contentDigest.slice('sha256:'.length, 'sha256:'.length + 16)}`;
    const identity = yield* decodedIdentity({
      _tag: 'LocalSourceIdentity',
      codebaseId: source.codebaseId,
      repository,
      snapshotDigest: captured.contentDigest,
      dirty: true,
    }, 'local');
    return {
      identity,
      snapshot: sourceSnapshot(captured.contentDigest, captured),
      workspace,
    };
  });
}

function materializeGitHub(
  source: GitHubSource,
  host: SourceMaterializerHost,
  limits: SourceMaterializationLimits,
): Effect.Effect<MaterializedSource, SourceMaterializationError, Scope.Scope> {
  return Effect.gen(function* () {
    const resolved = yield* host.resolver.resolve(source, limits).pipe(
      Effect.catchTag(
        'GitHubRevisionResolverError',
        error => Effect.fail(mapResolverError(error)),
      ),
    );
    const resolution = yield* Schema.decodeEffect(GitHubRevisionResolution, {
      onExcessProperty: 'error',
    })(resolved).pipe(
      Effect.mapError(() => sourceError('github', 'github-resolve', 'invalid-response')),
    );
    if (resolution.owner.toLowerCase() !== source.owner.toLowerCase() ||
      resolution.repository.toLowerCase() !== source.repository.toLowerCase()) {
      return yield* Effect.fail(sourceError('github', 'github-resolve', 'invalid-response'));
    }
    const staging = yield* host.workspace.allocate(quotaFor(limits)).pipe(
      Effect.mapError(mapWorkspaceError('github', 'workspace')),
    );
    const staged = yield* staging.withHandle(handle => host.descriptor.withStaging(
      handle,
      operations => Effect.gen(function* () {
        const receipt = yield* host.archives.stage(
          new GitHubCodeloadArchiveRequest({
            owner: resolution.owner,
            repository: resolution.repository,
            commitSha: resolution.commitSha,
            maximumEntries: limits.maximumEntries,
            maximumFiles: limits.maximumFiles,
            maximumBytes: limits.maximumBytes,
            maximumArchiveBytes: limits.maximumArchiveBytes,
            timeoutMs: limits.archiveTimeoutMs,
          }),
          operations,
        ).pipe(
          Effect.catchTag(
            'GitHubCodeloadArchiveError',
            error => Effect.fail(mapArchiveError(error)),
          ),
        );
        const decodedReceipt = yield* Schema.decodeEffect(GitHubCodeloadArchiveReceipt, {
          onExcessProperty: 'error',
        })(receipt).pipe(
          Effect.mapError(() => sourceError('github', 'github-stage', 'invalid-response')),
        );
        if (decodedReceipt.commitSha !== resolution.commitSha) {
          return yield* Effect.fail(sourceError('github', 'github-stage', 'revision-changed'));
        }
        const tree = yield* auditTree('github', 'github-stage', operations, limits, false);
        return {
          defaultBranch: resolution.defaultBranch,
          commitSha: resolution.commitSha,
          tree,
        };
      }),
    )).pipe(Effect.mapError(mapSourceOrWorkspaceError('github', 'github-stage')));
    const workspace = yield* staging.seal.pipe(
      Effect.mapError(mapWorkspaceError('github', 'workspace')),
    );
    const digest = `git:${staged.commitSha}`;
    const identity = yield* decodedIdentity({
      _tag: 'GitHubSourceIdentity',
      codebaseId: githubCodebaseId(resolution.owner, resolution.repository),
      owner: resolution.owner,
      repository: resolution.repository,
      url: githubIdentityUrl(resolution.owner, resolution.repository),
      commitSha: staged.commitSha,
      defaultBranch: staged.defaultBranch,
      snapshotDigest: digest,
    }, 'github');
    return {
      identity,
      snapshot: sourceSnapshot(staged.tree.contentDigest, staged.tree),
      workspace,
    };
  });
}

export function makeSourceMaterializer(host: SourceMaterializerHost): SourceMaterializerService {
  const configuredLimits = host.limits ?? defaultSourceMaterializationLimits;
  return {
    materialize: source => Schema.decodeEffect(AnalysisSource, {
      onExcessProperty: 'error',
    })(source).pipe(
      Effect.mapError(() => sourceError('local', 'identity', 'invalid-identity')),
      Effect.flatMap(accepted => checkedLimits(
        accepted._tag === 'LocalDirectorySource' ? 'local' : 'github',
        configuredLimits,
      ).pipe(
        Effect.flatMap(limits => accepted._tag === 'LocalDirectorySource'
          ? materializeLocal(accepted, host, limits)
          : materializeGitHub(accepted, host, limits)),
      )),
    ),
  };
}

export const SourceMaterializerLive = Layer.effect(
  SourceMaterializer,
  Effect.gen(function* () {
    const workspace = yield* WorkspaceAllocator;
    const descriptor = yield* WorkspaceDescriptorHost;
    const resolver = yield* GitHubRevisionResolver;
    const archives = yield* GitHubCodeloadArchiveTransport;
    return SourceMaterializer.of(makeSourceMaterializer({
      workspace,
      descriptor,
      resolver,
      archives,
    }));
  }),
);

export const makeSourceMaterializerLayer = (
  resolver: Context.Service.Shape<typeof GitHubRevisionResolver>,
  archives: Context.Service.Shape<typeof GitHubCodeloadArchiveTransport>,
  limits?: SourceMaterializationLimits,
) => Layer.effect(
  SourceMaterializer,
  Effect.gen(function* () {
    const workspace = yield* WorkspaceAllocator;
    const descriptor = yield* WorkspaceDescriptorHost;
    return SourceMaterializer.of(makeSourceMaterializer({
      workspace,
      descriptor,
      resolver,
      archives,
      ...(limits === undefined ? {} : { limits }),
    }));
  }),
);
