import { Effect, FileSystem, Option, Path, PlatformError, Schema } from 'effect';
import { Framework } from '../shared/domain';

const sourceExtensions = new Set([
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
  '.vue',
  '.svelte',
]);
const ignoredDirectories = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'vendor',
]);

export class RepositoryManifest extends Schema.Class<RepositoryManifest>(
  'RepositoryManifest',
)({
  path: Schema.String,
  dependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  devDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  peerDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
}) {}

class PackageManifest extends Schema.Class<PackageManifest>('PackageManifest')({
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
}) {}

export const repositoryRelative = (
  pathService: Path.Path,
  root: string,
  absolute: string,
) => {
  const resolved = pathService.isAbsolute(absolute)
    ? pathService.resolve(absolute)
    : pathService.resolve(root, absolute);
  const value = pathService.relative(root, resolved);
  return !value || value === '..' || value.startsWith(`..${pathService.sep}`)
    ? undefined
    : value.split(pathService.sep).join('/');
};

export const inventoryRepository = Effect.fn('inventoryRepository')(
  function* (root: string) {
    const fs = yield* FileSystem.FileSystem;
    const pathService = yield* Path.Path;
    const files: Array<string> = [];
    const sourceFiles: Array<string> = [];
    const lockfiles: Array<string> = [];
    const tsconfigs: Array<string> = [];
    const workflowFiles: Array<string> = [];
    const manifests: Array<RepositoryManifest> = [];
    let sourceBytes = 0;
    let truncated = false;

    const visit = (directory: string): Effect.Effect<void, PlatformError.PlatformError> =>
      Effect.gen(function* () {
      if (files.length >= 8_000) {
        truncated = true;
        return;
      }
      const entries = yield* fs.readDirectory(directory);
      yield* Effect.forEach(
        entries,
        Effect.fn(function* (name) {
          if (files.length >= 8_000) {
            truncated = true;
            return;
          }
          const absolute = pathService.resolve(directory, name);
          const repositoryPath = repositoryRelative(pathService, root, absolute);
          if (!repositoryPath) return;
          if (Option.isSome(yield* Effect.option(fs.readLink(absolute)))) return;
          const info = yield* fs.stat(absolute);
          if (info.type === 'Directory') {
            if (!ignoredDirectories.has(name)) yield* visit(absolute);
            return;
          }
          if (info.type !== 'File' || info.size > BigInt(2 * 1024 * 1024)) return;
          files.push(repositoryPath);
          if (sourceExtensions.has(pathService.extname(repositoryPath).toLowerCase())) {
            sourceFiles.push(repositoryPath);
            sourceBytes += Number(info.size);
          }
          if (
            ['bun.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(
              name,
            )
          ) {
            lockfiles.push(repositoryPath);
          }
          if (/^tsconfig(?:\.[\w-]+)?\.json$/iu.test(name)) {
            tsconfigs.push(repositoryPath);
          }
          if (/^\.github\/(workflows\/.*\.ya?ml|actions\/)/u.test(repositoryPath)) {
            workflowFiles.push(repositoryPath);
          }
          if (name === 'package.json' && info.size <= BigInt(512 * 1024)) {
            const parsed = yield* Effect.option(
              fs.readFileString(absolute).pipe(
                Effect.flatMap(content =>
                  Schema.decodeEffect(Schema.fromJsonString(PackageManifest))(content),
                ),
              ),
            );
            if (Option.isSome(parsed)) {
              manifests.push(
                new RepositoryManifest({ path: repositoryPath, ...parsed.value }),
              );
            }
          }
        }),
        { concurrency: 1, discard: true },
      );
      });

    yield* visit(root);
    const packageNames = new Set<string>();
    for (const manifest of manifests) {
      const sections = [
        manifest.dependencies,
        manifest.devDependencies,
        manifest.peerDependencies,
      ];
      for (const dependencies of sections) {
        if (!dependencies) continue;
        for (const name of Object.keys(dependencies)) packageNames.add(name);
      }
    }
    const frameworks: Array<typeof Framework.Type> = [];
    if (packageNames.has('react') || packageNames.has('next')) frameworks.push('react');
    if (packageNames.has('@angular/core') || files.includes('angular.json')) {
      frameworks.push('angular');
    }
    if (packageNames.has('vue') || packageNames.has('nuxt')) frameworks.push('vue');
    if (packageNames.has('svelte') || packageNames.has('@sveltejs/kit')) {
      frameworks.push('svelte');
    }
    if (packageNames.has('solid-js') || packageNames.has('@solidjs/start')) {
      frameworks.push('solid');
    }

    return new RepositoryInventory({
      files,
      sourceFiles,
      lockfiles,
      tsconfigs,
      workflowFiles,
      manifests,
      frameworks,
      sourceBytes,
      truncated,
    });
  },
);
