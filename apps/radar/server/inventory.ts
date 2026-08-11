import { Path, Schema } from 'effect';
import { Framework, RepositoryPathSetDigest } from '@codebase-radar/contracts';

export class RepositoryManifest extends Schema.Class<RepositoryManifest>(
  'RepositoryManifest',
)({
  path: Schema.String,
  dependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  devDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  peerDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
}) {}

export class RepositoryInventory extends Schema.Class<RepositoryInventory>(
  'RepositoryInventory',
)({
  files: Schema.Array(Schema.String),
  sourceFiles: Schema.Array(Schema.String),
  lockfiles: Schema.Array(Schema.String),
  tsconfigs: Schema.Array(Schema.String),
  workflowFiles: Schema.Array(Schema.String),
  manifests: Schema.Array(RepositoryManifest),
  frameworks: Schema.Array(Framework),
  sourceBytes: Schema.Number,
  truncated: Schema.Boolean,
  /** The semantic runner derives this from its audited request, never a caller digest. */
  eligiblePathSetDigest: Schema.optional(RepositoryPathSetDigest),
}) {}

export const repositoryRelative = (
  pathService: Path.Path,
  root: string,
  absolute: string,
) => {
  const rootName = pathService.basename(root);
  const resolved = pathService.isAbsolute(absolute)
    ? pathService.resolve(absolute)
    : absolute === rootName || absolute.startsWith(`${rootName}${pathService.sep}`)
      ? pathService.resolve(pathService.dirname(root), absolute)
      : pathService.resolve(root, absolute);
  const value = pathService.relative(root, resolved);
  return !value || value === '..' || value.startsWith(`..${pathService.sep}`)
    ? undefined
    : value.split(pathService.sep).join('/');
};
