import { Context, Effect, Schema, Scope } from 'effect';
import type { GitHubSource } from '@codebase-radar/contracts/source';
import type { DescriptorStagingOperations } from '../workspace.js';

const GitHubOwner = Schema.NonEmptyString.check(
  Schema.isMaxLength(39),
  Schema.makeFilter(value =>
    !value.includes('--') && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(value)
      ? undefined
      : 'GitHub owners must use canonical account-name syntax',
  ),
);

const GitHubRepository = Schema.NonEmptyString.check(
  Schema.isMaxLength(100),
  Schema.makeFilter(value =>
    value !== '.' &&
    value !== '..' &&
    !value.toLowerCase().endsWith('.git') &&
    /^[A-Za-z0-9_.-]+$/u.test(value)
      ? undefined
      : 'GitHub repositories must use canonical repository-name syntax',
  ),
);

const CommitSha = Schema.NonEmptyString.check(
  Schema.makeFilter(value =>
    /^[0-9a-f]{40}$/u.test(value)
      ? undefined
      : 'commit ids must be complete lowercase GitHub object ids',
  ),
);

const PositiveMaximumEntries = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(100_000),
);

const PositiveMaximumFiles = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(100_000),
);

const PositiveMaximumBytes = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(512 * 1024 * 1024),
);

const PositiveMaximumArchiveBytes = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(1024 * 1024 * 1024),
);

const PositiveGitTimeoutMilliseconds = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(60_000),
);

const PositiveGitOutputBytes = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(1024 * 1024),
);

/**
 * All values are decoded before allocation. The limits are deliberately capped
 * by this package so an injected host cannot be asked to accept Infinity,
 * negative numbers, or an application-sized unbounded source.
 */
export class SourceMaterializationLimits extends Schema.Class<SourceMaterializationLimits>(
  'SourceMaterializationLimits',
)({
  maximumEntries: PositiveMaximumEntries,
  maximumFiles: PositiveMaximumFiles,
  maximumBytes: PositiveMaximumBytes,
  maximumArchiveBytes: PositiveMaximumArchiveBytes,
  archiveTimeoutMs: PositiveGitTimeoutMilliseconds,
  gitTimeoutMs: PositiveGitTimeoutMilliseconds,
  gitOutputBytes: PositiveGitOutputBytes,
}) {}

export const defaultSourceMaterializationLimits = new SourceMaterializationLimits({
  maximumEntries: 100_000,
  maximumFiles: 100_000,
  maximumBytes: 512 * 1024 * 1024,
  maximumArchiveBytes: 512 * 1024 * 1024,
  archiveTimeoutMs: 60_000,
  gitTimeoutMs: 60_000,
  gitOutputBytes: 64 * 1024,
});

export const decodeSourceMaterializationLimits = Schema.decodeUnknownEffect(
  SourceMaterializationLimits,
  { onExcessProperty: 'error' },
);

export const SourceMaterializationSource = Schema.Literals(['github', 'local']);

export const SourceMaterializationStage = Schema.Literals([
  'workspace',
  'local-capture',
  'github-resolve',
  'github-stage',
  'snapshot',
  'identity',
]);

export const SourceMaterializationReason = Schema.Literals([
  'capability-unavailable',
  'transport-failed',
  'invalid-response',
  'missing-revision',
  'ambiguous-revision',
  'revision-changed',
  'unsafe-entry',
  'nested-repository',
  'source-limit-exceeded',
  'invalid-identity',
]);

/**
 * Intentionally contains only stable reason codes. Paths, URLs, credentials,
 * Git stderr, archive headers, and host-process details never cross this error
 * boundary.
 */
export class SourceMaterializationError extends Schema.TaggedErrorClass<SourceMaterializationError>()(
  'SourceMaterializationError',
  {
    source: SourceMaterializationSource,
    stage: SourceMaterializationStage,
    reason: SourceMaterializationReason,
  },
) {}

const GitHubDefaultBranch = Schema.NonEmptyString.check(
  Schema.isMaxLength(1_024),
  Schema.makeFilter(value => {
    const segments = value.split('/');
    return value === '@' ||
      value.startsWith('-') ||
      value.startsWith('/') ||
      value.endsWith('/') ||
      value.endsWith('.') ||
      value.includes('..') ||
      value.includes('//') ||
      value.includes('@{') ||
      /[\u0000-\u0020\u007f~^:?*[\\]/u.test(value) ||
      segments.some(segment => segment.startsWith('.') || segment.endsWith('.lock'))
      ? 'default branches must use safe Git reference syntax'
      : undefined;
  }),
);

/**
 * The immutable response from the fixed-origin GitHub resolver. It carries
 * the canonical repository spelling returned by GitHub, and the archive
 * transport receives only that identity plus a pinned commit SHA.
 */
export class GitHubRevisionResolution extends Schema.Class<GitHubRevisionResolution>(
  'GitHubRevisionResolution',
)({
  owner: GitHubOwner,
  repository: GitHubRepository,
  defaultBranch: GitHubDefaultBranch,
  commitSha: CommitSha,
}) {}

export const GitHubRevisionResolverOperation = Schema.Literals(['resolve']);

export const GitHubRevisionResolverFailureCode = Schema.Literals([
  'capability-unavailable',
  'missing-revision',
  'ambiguous-revision',
  'invalid-response',
  'source-limit-exceeded',
  'transport-failed',
]);

/** Contains only stable diagnostic codes; never a URL, header, or response body. */
export class GitHubRevisionResolverError extends Schema.TaggedErrorClass<GitHubRevisionResolverError>()(
  'GitHubRevisionResolverError',
  {
    operation: GitHubRevisionResolverOperation,
    code: GitHubRevisionResolverFailureCode,
  },
) {}

/**
 * Resolves an accepted GitHub source against api.github.com. Implementations
 * must use a fixed credential-free origin and return a complete immutable SHA.
 */
export class GitHubRevisionResolver extends Context.Service<
  GitHubRevisionResolver,
  {
    readonly resolve: (
      source: GitHubSource,
      limits: SourceMaterializationLimits,
    ) => Effect.Effect<
      GitHubRevisionResolution,
      GitHubRevisionResolverError,
      Scope.Scope
    >;
  }
>()('@codebase-radar/core/internal/source/GitHubRevisionResolver') {}

/**
 * The transport receives no URL, cwd, pathname, environment, or credential.
 * It must construct only `https://codeload.github.com/{owner}/{repository}/tar.gz/{commitSha}`
 * from these canonical identifiers, stream the compressed response within
 * maximumArchiveBytes and timeoutMs, abort its stream on Scope interruption,
 * and extract only regular files/directories through the supplied staging writer.
 */
export class GitHubCodeloadArchiveRequest extends Schema.Class<GitHubCodeloadArchiveRequest>(
  'GitHubCodeloadArchiveRequest',
)({
  owner: GitHubOwner,
  repository: GitHubRepository,
  commitSha: CommitSha,
  maximumEntries: PositiveMaximumEntries,
  maximumFiles: PositiveMaximumFiles,
  maximumBytes: PositiveMaximumBytes,
  maximumArchiveBytes: PositiveMaximumArchiveBytes,
  timeoutMs: PositiveGitTimeoutMilliseconds,
}) {}

/**
 * The transport can only report the immutable revision it was asked to stage;
 * all tree sizes, entry kinds, and content digests are recomputed afterward
 * through the retained descriptor workspace.
 */
export class GitHubCodeloadArchiveReceipt extends Schema.Class<GitHubCodeloadArchiveReceipt>(
  'GitHubCodeloadArchiveReceipt',
)({
  commitSha: CommitSha,
}) {}

export const GitHubCodeloadArchiveOperation = Schema.Literals(['stage']);

export const GitHubCodeloadArchiveFailureCode = Schema.Literals([
  'capability-unavailable',
  'missing-revision',
  'revision-changed',
  'source-limit-exceeded',
  'archive-invalid',
  'transport-failed',
]);

export class GitHubCodeloadArchiveError extends Schema.TaggedErrorClass<GitHubCodeloadArchiveError>()(
  'GitHubCodeloadArchiveError',
  {
    operation: GitHubCodeloadArchiveOperation,
    code: GitHubCodeloadArchiveFailureCode,
  },
) {}

export class GitHubCodeloadArchiveTransport extends Context.Service<
  GitHubCodeloadArchiveTransport,
  {
    readonly stage: (
      request: GitHubCodeloadArchiveRequest,
      staging: DescriptorStagingOperations,
    ) => Effect.Effect<
      GitHubCodeloadArchiveReceipt,
      GitHubCodeloadArchiveError,
      Scope.Scope
    >;
  }
>()('@codebase-radar/core/internal/source/GitHubCodeloadArchiveTransport') {}
