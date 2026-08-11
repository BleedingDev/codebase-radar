import {
  ContractLimits,
  compareCanonicalRepositoryPaths,
  Framework,
  RepositoryPath,
  RequiredAnalyzerIds,
  SemanticAnalyzerInventory,
  SemanticAnalyzerInventoryEntry,
  SemanticAnalyzerInventoryValue,
} from '@codebase-radar/contracts';
import { Effect, Option, Schema } from 'effect';
import {
  WorkspaceReader,
  WorkspaceRelativePath,
  WorkspaceRoot,
} from '../workspace.js';
import type { SourceWorkspaceHandle } from '../workspace.js';

const MaximumInventoryFiles = ContractLimits.semanticAnalyzerInventoryEntries;
const MaximumSourceFileBytes = ContractLimits.semanticAnalyzerFileBytes;
const MaximumManifestBytes = 512 * 1024;

const PackageManifest = Schema.Struct({
  dependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  devDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  peerDependencies: Schema.optional(Schema.Record(Schema.String, Schema.String)),
});

export class RepositoryInventory extends Schema.Class<RepositoryInventory>(
  'RepositoryInventory',
)({
  files: Schema.Array(RepositoryPath),
  sourceFiles: Schema.Array(RepositoryPath),
  lockfiles: Schema.Array(RepositoryPath),
  tsconfigs: Schema.Array(RepositoryPath),
  workflowFiles: Schema.Array(RepositoryPath),
  packageNames: Schema.Array(Schema.NonEmptyString),
  frameworks: Schema.Array(Framework),
  sourceBytes: Schema.Natural,
  truncated: Schema.Boolean,
  analyzerInventory: SemanticAnalyzerInventory,
  /** Oversized non-source files are intentionally omitted without invalidating analysis. */
  skippedOversizedNonSourceFiles: Schema.optional(
    Schema.Array(RepositoryPath).check(Schema.isMaxLength(1_000)),
  ),
}) {}

export class InventoryFailure extends Schema.TaggedErrorClass<InventoryFailure>()(
  'InventoryFailure',
  { message: Schema.NonEmptyString },
) {}

const programExtensions = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
]);

const singleFileComponentExtensions = new Set(['.vue', '.svelte']);

const semanticSourceExtensions = new Set([
  ...programExtensions,
  ...singleFileComponentExtensions,
]);

const ignoredDirectories = new Set([
  '.git',
  '.hg',
  '.svn',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.cache',
  'coverage',
  'dist',
  'build',
  'node_modules',
  'vendor',
]);

const sourceExtension = (path: string) => {
  const index = path.lastIndexOf('.');
  return index < 0 ? '' : path.slice(index).toLowerCase();
};

const isLockfile = (name: string) =>
  name === 'bun.lock' ||
  name === 'package-lock.json' ||
  name === 'pnpm-lock.yaml' ||
  name === 'yarn.lock';

const isTsconfig = (name: string) => /^tsconfig(?:\.[\w-]+)?\.json$/u.test(name);

const isWorkflowFile = (path: string) => /^\.github\/workflows\/.*\.ya?ml$/u.test(path);

const isAnalyzerInput = (name: string, path: string, extension: string) =>
  semanticSourceExtensions.has(extension) ||
  isLockfile(name) ||
  isTsconfig(name) ||
  isWorkflowFile(path);

const ordered = (values: ReadonlyArray<string>) =>
  [...new Set(values)].sort(compareCanonicalRepositoryPaths);

const frameworkNames = (packageNames: ReadonlySet<string>, files: ReadonlyArray<string>) => {
  const frameworks = new Array<typeof Framework.Type>();
  if (packageNames.has('react') || packageNames.has('next')) frameworks.push('react');
  if (packageNames.has('@angular/core') || files.includes('angular.json')) {
    frameworks.push('angular');
  }
  if (packageNames.has('vue') || files.includes('nuxt.config.ts')) frameworks.push('vue');
  if (packageNames.has('svelte') || packageNames.has('@sveltejs/kit')) {
    frameworks.push('svelte');
  }
  if (packageNames.has('solid-js') || packageNames.has('@solidjs/start')) {
    frameworks.push('solid');
  }
  return frameworks;
};

const analyzerInventory = (
  fileBytes: ReadonlyMap<string, number>,
  programFiles: ReadonlyArray<string>,
  singleFileComponentFiles: ReadonlyArray<string>,
  tsconfigs: ReadonlyArray<string>,
  workflowFiles: ReadonlyArray<string>,
  lockfiles: ReadonlyArray<string>,
  frameworks: ReadonlyArray<typeof Framework.Type>,
  truncated: boolean,
) => {
  const eligible = new Map<string, Set<typeof RequiredAnalyzerIds[number]>>();
  const include = (
    analyzer: typeof RequiredAnalyzerIds[number],
    paths: ReadonlyArray<string>,
  ) => {
    for (const path of paths) {
      const current = eligible.get(path) ?? new Set<typeof RequiredAnalyzerIds[number]>();
      current.add(analyzer);
      eligible.set(path, current);
    }
  };
  const sourceLikeFiles = ordered([...programFiles, ...singleFileComponentFiles]);
  include('strictest-comparator', tsconfigs);
  include('Oxlint + Ultracite', sourceLikeFiles);
  include('JSCPD', sourceLikeFiles);
  include('Calldiff', programFiles);
  include('zizmor', workflowFiles);
  include('OSV-Scanner', lockfiles);
  include('TraceDecay', programFiles);
  return new SemanticAnalyzerInventoryValue({
    entries: [...eligible.entries()]
      .toSorted(([left], [right]) => compareCanonicalRepositoryPaths(left, right))
      .map(([path, analyzers]) => new SemanticAnalyzerInventoryEntry({
        path,
        byteLength: fileBytes.get(path) ?? 0,
        analyzers: RequiredAnalyzerIds.filter(analyzer => analyzers.has(analyzer)),
      })),
    frameworks: [...frameworks],
    truncated,
  });
};

const inventoryFailure = (message: string) => new InventoryFailure({ message });

const workspacePath = (segments: ReadonlyArray<string>) =>
  new WorkspaceRelativePath({ segments: [...segments] });

const repositoryPath = (segments: ReadonlyArray<string>) => segments.join('/');

export const inventoryRepository = Effect.fn('inventoryRepository')(function* (
  workspace: SourceWorkspaceHandle,
) {
  const reader = yield* WorkspaceReader;
  const files = new Array<string>();
  const sourceFiles = new Array<string>();
  const programFiles = new Array<string>();
  const singleFileComponentFiles = new Array<string>();
  const lockfiles = new Array<string>();
  const tsconfigs = new Array<string>();
  const workflowFiles = new Array<string>();
  const fileBytes = new Map<string, number>();
  const packageNames = new Set<string>();
  let sourceBytes = 0;
  let analyzerInputBytes = 0;
  let entriesSeen = 0;
  let truncated = false;
  const skippedOversizedNonSourceFiles = new Array<string>();

  const visit = (segments: ReadonlyArray<string>): Effect.Effect<void, InventoryFailure> =>
    Effect.gen(function* () {
      if (truncated || entriesSeen >= MaximumInventoryFiles) {
        truncated = true;
        return;
      }
      const batch = yield* reader.readDirectory(
        workspace,
        segments.length === 0 ? WorkspaceRoot : workspacePath(segments),
        MaximumInventoryFiles - entriesSeen,
      ).pipe(
        Effect.mapError(() => inventoryFailure(
          'The isolated source workspace could not be inventoried.',
        )),
      );
      if (batch.truncated) {
        truncated = true;
        return;
      }
      yield* Effect.forEach(
        [...batch.entries].sort((left, right) => compareCanonicalRepositoryPaths(left.name, right.name)),
        entry =>
          Effect.gen(function* () {
            if (truncated || entriesSeen >= MaximumInventoryFiles) {
              truncated = true;
              return;
            }
            entriesSeen += 1;
            const childSegments = [...segments, entry.name];
            const path = workspacePath(childSegments);
            const pathText = repositoryPath(childSegments);
            const details = yield* reader.stat(workspace, path).pipe(
              Effect.mapError(() => inventoryFailure(
                'The isolated source workspace changed during inventory.',
              )),
            );
            if (details.kind === 'directory') {
              if (!ignoredDirectories.has(entry.name)) yield* visit(childSegments);
              return;
            }
            if (details.kind !== 'file') {
              truncated = true;
              return;
            }
            const extension = sourceExtension(pathText);
            if (details.byteLength > MaximumSourceFileBytes) {
              if (isAnalyzerInput(entry.name, pathText, extension)) {
                truncated = true;
              } else {
                skippedOversizedNonSourceFiles.push(pathText);
              }
              return;
            }
            const analyzerInput = isAnalyzerInput(entry.name, pathText, extension);
            if (analyzerInput && analyzerInputBytes + details.byteLength > ContractLimits.semanticAnalyzerSourceBytes) {
              truncated = true;
              return;
            }
            const semanticSource = semanticSourceExtensions.has(extension);
            files.push(pathText);
            fileBytes.set(pathText, details.byteLength);
            if (analyzerInput) analyzerInputBytes += details.byteLength;
            if (semanticSource) {
              sourceFiles.push(pathText);
              sourceBytes += details.byteLength;
            }
            if (programExtensions.has(extension)) programFiles.push(pathText);
            if (singleFileComponentExtensions.has(extension)) singleFileComponentFiles.push(pathText);
            if (isLockfile(entry.name)) {
              lockfiles.push(pathText);
            }
            if (isTsconfig(entry.name)) {
              tsconfigs.push(pathText);
            }
            if (isWorkflowFile(pathText)) {
              workflowFiles.push(pathText);
            }
            if (entry.name !== 'package.json') return;
            if (details.byteLength > MaximumManifestBytes) {
              truncated = true;
              return;
            }
            const text = yield* reader.readText(
              workspace,
              path,
              MaximumManifestBytes,
            ).pipe(
              Effect.mapError(() => inventoryFailure(
                'The isolated source workspace could not read a package manifest.',
              )),
            );
            const manifest = yield* Effect.option(
              Schema.decodeEffect(Schema.fromJsonString(PackageManifest))(text),
            );
            if (Option.isNone(manifest)) return;
            const sections = [
              manifest.value.dependencies,
              manifest.value.devDependencies,
              manifest.value.peerDependencies,
            ];
            for (const dependencies of sections) {
              if (dependencies === undefined) continue;
              for (const packageName of Object.keys(dependencies)) {
                packageNames.add(packageName);
              }
            }
          }),
        { concurrency: 1, discard: true },
      );
    });

  yield* visit([]);
  const orderedFiles = ordered(files);
  const orderedSourceFiles = ordered(sourceFiles);
  const orderedProgramFiles = ordered(programFiles);
  const orderedSingleFileComponentFiles = ordered(singleFileComponentFiles);
  const orderedLockfiles = ordered(lockfiles);
  const orderedTsconfigs = ordered(tsconfigs);
  const orderedWorkflowFiles = ordered(workflowFiles);
  const orderedPackageNames = ordered([...packageNames]);
  const orderedFrameworks = frameworkNames(packageNames, orderedFiles);
  return new RepositoryInventory({
    files: orderedFiles,
    sourceFiles: orderedSourceFiles,
    lockfiles: orderedLockfiles,
    tsconfigs: orderedTsconfigs,
    workflowFiles: orderedWorkflowFiles,
    packageNames: orderedPackageNames,
    frameworks: orderedFrameworks,
    sourceBytes,
    truncated,
    analyzerInventory: analyzerInventory(
      fileBytes,
      orderedProgramFiles,
      orderedSingleFileComponentFiles,
      orderedTsconfigs,
      orderedWorkflowFiles,
      orderedLockfiles,
      orderedFrameworks,
      truncated,
    ),
    skippedOversizedNonSourceFiles: ordered(skippedOversizedNonSourceFiles),
  });
});
