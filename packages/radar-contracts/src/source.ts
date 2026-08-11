import { Schema } from 'effect';
import {
  containsCredentialMaterial,
  containsControlCharacter,
  containsEncodedControlCharacter,
  ContractLimits,
} from './primitives.js';

const NonEmptyString = Schema.String.check(
  Schema.isTrimmed(),
  Schema.isMinLength(1),
);

const LocalRepositoryLabel = NonEmptyString.check(
  Schema.isMaxLength(100),
  Schema.makeFilter(value =>
    value !== '.' && value !== '..' && /^[A-Za-z0-9_.-]+$/u.test(value)
      ? undefined
      : 'repository segments may contain only letters, digits, underscore, dot, and dash and may not be dot segments',
  ),
);

const GitHubOwner = NonEmptyString.check(
  Schema.isMaxLength(39),
  Schema.makeFilter(value =>
    !value.includes('--') &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(value)
      ? undefined
      : 'GitHub owner must use canonical account-name syntax',
  ),
);

const GitHubRepository = NonEmptyString.check(
  Schema.isMaxLength(100),
  Schema.makeFilter(value =>
    value !== '.' &&
    value !== '..' &&
    !value.toLowerCase().endsWith('.git') &&
    /^[A-Za-z0-9_.-]+$/u.test(value)
      ? undefined
      : 'GitHub repository must be a canonical name without a Git suffix',
  ),
);

const AbsoluteDirectory = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.pathCharacters),
  Schema.makeFilter(value => {
    if (containsControlCharacter(value)) {
      return 'directory must not contain control characters';
    }
    if (/^\/(?!\/)/u.test(value)) return undefined;
    if (/^[A-Za-z]:[\\/]/u.test(value)) return undefined;
    if (/^\\\\[^\\/]+[\\/][^\\/]+/u.test(value)) return undefined;
    return 'directory must be an absolute path';
  }),
);

const ReservedSymbolicRef =
  /^(?:head|fetch_head|orig_head|merge_head|cherry_pick_head|revert_head|bisect_head|auto_merge)$/iu;

const BranchOrTag = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.pathCharacters),
  Schema.makeFilter(value => {
    const segments = value.split('/');
    return value === '@' ||
      ReservedSymbolicRef.test(value) ||
      value.startsWith('-') ||
      value.startsWith('/') ||
      value.endsWith('/') ||
      value.endsWith('.') ||
      value.includes('..') ||
      value.includes('//') ||
      value.includes('@{') ||
      /[\u0000-\u0020\u007f-\u009f~^:?*[\\]/u.test(value) ||
      segments.some(segment => segment.startsWith('.') || segment.endsWith('.lock'))
      ? 'revision does not satisfy safe Git reference syntax'
      : undefined;
  }),
);

const CommitSha = NonEmptyString.check(
  Schema.makeFilter(value =>
    /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value)
      ? undefined
      : 'commit must be a complete lowercase hexadecimal object id',
  ),
);

export const CodebaseId = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.identifierCharacters),
  Schema.makeFilter(value => {
    if (/^local:[a-z0-9][a-z0-9._:-]*$/u.test(value)) return undefined;
    const github = /^github:([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)\/([a-z0-9_.-]{1,100})$/u.exec(
      value,
    );
    const owner = github?.[1];
    const repository = github?.[2];
    return owner !== undefined &&
      !owner.includes('--') &&
      repository !== undefined &&
      repository !== '.' &&
      repository !== '..' &&
      !repository.endsWith('.git')
      ? undefined
      : 'codebase identity must be an opaque local id or canonical lowercase GitHub id';
  }),
);

const SnapshotDigest = NonEmptyString.check(
  Schema.makeFilter(value =>
    /^(?:git:(?:[0-9a-f]{40}|[0-9a-f]{64})|sha256:[0-9a-f]{64})$/u.test(
      value,
    )
      ? undefined
      : 'snapshot digest must be a complete Git object id or SHA-256 digest',
  ),
);

const GitHubUrl = NonEmptyString.check(
  Schema.isMaxLength(256),
  Schema.makeFilter(value => {
    if (containsControlCharacter(value) || containsEncodedControlCharacter(value)) {
      return 'GitHub identity URL must not contain control characters';
    }
    if (containsCredentialMaterial(value)) {
      return 'GitHub identity URL must not contain credentials';
    }
    try {
      const url = new URL(value);
      return url.protocol === 'https:' &&
        url.hostname === 'github.com' &&
        url.username === '' &&
        url.password === ''
        ? undefined
        : 'GitHub identity URL must be a safe canonical HTTPS URL';
    } catch {
      return 'GitHub identity URL must be a valid canonical URL';
    }
  }),
);

export class DefaultBranchRevision extends Schema.TaggedClass<DefaultBranchRevision>()(
  'DefaultBranchRevision',
  {},
) {}

export class BranchRevision extends Schema.TaggedClass<BranchRevision>()(
  'BranchRevision',
  { branch: BranchOrTag },
) {}

export class TagRevision extends Schema.TaggedClass<TagRevision>()('TagRevision', {
  tag: BranchOrTag,
}) {}

export class CommitRevision extends Schema.TaggedClass<CommitRevision>()(
  'CommitRevision',
  { commitSha: CommitSha },
) {}

export const GitHubRevision = Schema.Union([
  DefaultBranchRevision,
  BranchRevision,
  TagRevision,
  CommitRevision,
]);
export type GitHubRevision = typeof GitHubRevision.Type;

export class LocalDirectorySource extends Schema.TaggedClass<LocalDirectorySource>()(
  'LocalDirectorySource',
  {
    directory: AbsoluteDirectory,
    codebaseId: CodebaseId,
  },
) {}

export class GitHubSource extends Schema.TaggedClass<GitHubSource>()(
  'GitHubSource',
  {
    owner: GitHubOwner,
    repository: GitHubRepository,
    revision: GitHubRevision,
  },
) {}

export const AnalysisSource = Schema.Union([LocalDirectorySource, GitHubSource]).check(
  Schema.makeFilter(source =>
    source._tag === 'LocalDirectorySource' && !source.codebaseId.startsWith('local:')
      ? { path: ['codebaseId'], issue: 'local sources require an opaque local codebase id' }
      : undefined,
  ),
);
export type AnalysisSource = typeof AnalysisSource.Type;

export const decodeAnalysisSource = Schema.decodeUnknownEffect(AnalysisSource, {
  onExcessProperty: 'error',
});

export class LocalSourceIdentity extends Schema.TaggedClass<LocalSourceIdentity>()(
  'LocalSourceIdentity',
  {
    codebaseId: CodebaseId,
    repository: LocalRepositoryLabel,
    snapshotDigest: SnapshotDigest,
    commitSha: Schema.optional(CommitSha),
    branch: Schema.optional(BranchOrTag),
    dirty: Schema.Boolean,
  },
) {}

export class GitHubSourceIdentity extends Schema.TaggedClass<GitHubSourceIdentity>()(
  'GitHubSourceIdentity',
  {
    codebaseId: CodebaseId,
    owner: GitHubOwner,
    repository: GitHubRepository,
    url: GitHubUrl,
    commitSha: CommitSha,
    defaultBranch: BranchOrTag,
    snapshotDigest: SnapshotDigest,
  },
) {}

export const SourceIdentity = Schema.Union([
  LocalSourceIdentity,
  GitHubSourceIdentity,
]).check(
  Schema.makeFilter(source => {
    if (source._tag === 'LocalSourceIdentity') {
      const issues = new Array<Schema.FilterIssue>();
      if (!source.codebaseId.startsWith('local:')) {
        issues.push({
          path: ['codebaseId'],
          issue: 'local identity requires an opaque local id',
        });
      }
      if (source.branch !== undefined && source.commitSha === undefined) {
        issues.push({
          path: ['branch'],
          issue: 'a resolved local branch requires a resolved commit',
        });
      }
      if (source.dirty && !source.snapshotDigest.startsWith('sha256:')) {
        issues.push({
          path: ['snapshotDigest'],
          issue: 'a dirty local snapshot requires a content digest',
        });
      }
      if (
        !source.dirty &&
        source.commitSha !== undefined &&
        source.snapshotDigest !== `git:${source.commitSha}`
      ) {
        issues.push({
          path: ['snapshotDigest'],
          issue: 'a clean committed local snapshot must identify its exact commit',
        });
      }
      if (
        source.snapshotDigest.startsWith('git:') &&
        source.snapshotDigest !== `git:${source.commitSha ?? ''}`
      ) {
        issues.push({
          path: ['commitSha'],
          issue: 'a Git snapshot digest requires the matching resolved commit',
        });
      }
      return issues;
    }
    const codebaseId = `github:${source.owner.toLowerCase()}/${source.repository.toLowerCase()}`;
    const url = `https://github.com/${source.owner}/${source.repository}`;
    if (source.codebaseId !== codebaseId) {
      return { path: ['codebaseId'], issue: `GitHub codebase id must equal ${codebaseId}` };
    }
    if (source.url !== url) {
      return { path: ['url'], issue: `GitHub URL must equal ${url}` };
    }
    return source.snapshotDigest === `git:${source.commitSha}`
      ? undefined
      : {
          path: ['snapshotDigest'],
          issue: 'GitHub snapshot digest must identify the exact commit',
        };
  }),
);
export type SourceIdentity = typeof SourceIdentity.Type;
