import type { AnalyzerControlCapability, AnalyzerRuntimeIdentity } from './runtime-verifier.mjs';

declare const sealedAnalyzerRuntimeBrand: unique symbol;
declare const materializedAnalyzerRuntimeBrand: unique symbol;

export interface DescriptorIdentity {
  readonly device: string;
  readonly inode: string;
  readonly mode: string;
  readonly size: string;
  readonly nlink: string;
}

export interface TrustedRuntimeControlArtifact {
  readonly path: 'runtime-snapshot-loader.mjs' | 'resource-governance-launcher.mjs' | 'runtime-memfd-addon.node';
  readonly byteLength: number;
  readonly sha256: string;
  readonly mode: '0444' | '0555';
  readonly identity: DescriptorIdentity;
}

export interface OfflineOsvDatabaseMetadata {
  readonly path: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly url: string;
  readonly generation: string;
  readonly sha256: string;
  readonly size: number;
  readonly entries: number;
  readonly uncompressedBytes: number;
  readonly signedDataDescriptorEntries: number;
  readonly dataDescriptorBytes: number;
  readonly publishedAt: string;
  readonly maxAgeDays: number;
  readonly validationEvidence: Readonly<{
    readonly schemaVersion: 'codebase-radar.osv-npm-snapshot-evidence/v1';
    readonly source: Readonly<{
      readonly url: string;
      readonly generation: string;
      readonly publishedAt: string;
      readonly maxAge: number;
    }>;
    readonly archive: Readonly<{
      readonly size: number;
      readonly sha256: string;
      readonly format: 'zip';
      readonly zip64: boolean;
      readonly entryCount: number;
      readonly compressedBytes: number;
      readonly uncompressedBytes: number;
      readonly storedEntries: number;
      readonly deflatedEntries: number;
      readonly signedDataDescriptorEntries: number;
      readonly dataDescriptorBytes: number;
      readonly compressionMethods: readonly string[];
      readonly centralDirectoryOffset: number;
      readonly centralDirectoryBytes: number;
      readonly structuralSha256: string;
    }>;
  }>;
  readonly validator: Readonly<{
    readonly schemaVersion: 'codebase-radar.osv-npm-snapshot-validator/v1';
    readonly path: 'osv-npm-snapshot-validator.mjs';
    readonly byteLength: number;
    readonly sha256: string;
  }>;
}

export interface SealedAnalyzerRuntimeGeneration {
  readonly [sealedAnalyzerRuntimeBrand]: 'codebase-radar.sealed-analyzer-runtime-generation/v1';
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-sealed-generation/v1';
  readonly sealing: 'linux-memfd-seals/v1';
  readonly seals: number;
  readonly manifestSha256: string;
  readonly runnerSha256: string;
  readonly nodeSha256: string;
  readonly osvDatabaseSha256: string;
  /** Manifest-relative. Governance owns the absolute /runtime mount path. */
  readonly osvDatabaseRelativePath: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly osvDatabaseBytes: number;
  readonly osvDatabaseGeneration: string;
  readonly osvDatabaseIdentity: DescriptorIdentity;
  readonly runtimeBytes: number;
  readonly runtimeEntries: number;
  readonly archiveBytes: number;
  readonly snapshotIdentity: DescriptorIdentity;
  close(): void;
}

/**
 * A production-layer lifetime capability. It has no public backing pathname
 * or descriptor; use it only with the trusted resource-governance module.
 */
export interface MaterializedAnalyzerRuntime {
  readonly [materializedAnalyzerRuntimeBrand]: 'codebase-radar.materialized-analyzer-runtime/v1';
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-materialized/v1';
  readonly manifestSha256: string;
  readonly runnerSha256: string;
  readonly nodeSha256: string;
  readonly osvDatabaseSha256: string;
  /** Manifest-relative. Governance owns the absolute /runtime mount path. */
  readonly osvDatabaseRelativePath: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly osvDatabaseBytes: number;
  readonly osvDatabaseGeneration: string;
  readonly runtimeRootIdentity: DescriptorIdentity;
  /** May throw AnalyzerRuntimeSnapshotError if strict owned-generation cleanup fails. */
  close(): void;
}

export interface SealedMemfdProof {
  readonly fd: number;
  readonly byteLength: number;
  readonly seals: number;
  readonly identity: DescriptorIdentity;
}

export interface RuntimeMemfdBridge {
  createData(): number;
  createExecutable(): number;
  seal(fd: number): number;
  getSeals(fd: number): number;
}

export interface SealedAnalyzerRuntimeInspection {
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-sealed-generation/v1';
  readonly sealing: 'linux-memfd-seals/v1';
  readonly seals: number;
  readonly snapshotFd: number;
  readonly snapshotIdentity: DescriptorIdentity;
  readonly archiveBytes: number;
  readonly nodeFd: number;
  readonly nodeSeals: number;
  readonly nodeBytes: number;
  readonly nodeIdentity: DescriptorIdentity;
  readonly osvDatabaseFd: number;
  readonly osvDatabaseSeals: number;
  readonly osvDatabaseIdentity: DescriptorIdentity;
  readonly loaderFd: number;
  readonly loaderBytes: number;
  readonly loaderSha256: string;
  readonly loaderIdentity: DescriptorIdentity;
  readonly launcherFd: number;
  readonly launcherBytes: number;
  readonly launcherSha256: string;
  readonly launcherIdentity: DescriptorIdentity;
  readonly addonFd: number;
  readonly addonBytes: number;
  readonly addonSha256: string;
  readonly addonIdentity: DescriptorIdentity;
  readonly controlArtifacts: readonly TrustedRuntimeControlArtifact[];
  readonly manifestSha256: string;
  readonly runnerSha256: string;
  readonly nodeSha256: string;
  readonly osvDatabaseSha256: string;
  readonly osvDatabaseRelativePath: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly osvDatabaseBytes: number;
  readonly osvDatabaseGeneration: string;
  readonly osvDatabaseMetadata: OfflineOsvDatabaseMetadata;
  readonly runtimeBytes: number;
  readonly runtimeEntries: number;
}

export interface MaterializedAnalyzerRuntimeInspection {
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-materialized/v1';
  readonly runtimeRootFd: number;
  readonly runtimeRootIdentity: DescriptorIdentity;
  readonly runnerPath: '/runtime/bin/radar-semantic-analyzer.mjs';
  readonly nodePath: '/runtime/bin/node';
  readonly manifestSha256: string;
  readonly runnerSha256: string;
  readonly nodeSha256: string;
  readonly osvDatabaseFd: number;
  readonly osvDatabaseIdentity: DescriptorIdentity;
  readonly osvDatabaseSha256: string;
  readonly osvDatabaseRelativePath: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly osvDatabaseBytes: number;
  readonly osvDatabaseGeneration: string;
  readonly launcherFd: number;
  readonly launcherBytes: number;
  readonly launcherSha256: string;
  readonly launcherIdentity: DescriptorIdentity;
  readonly addonFd: number;
  readonly addonBytes: number;
  readonly addonSha256: string;
  readonly addonIdentity: DescriptorIdentity;
  readonly controlArtifacts: readonly TrustedRuntimeControlArtifact[];
}

export declare class AnalyzerRuntimeSnapshotError extends Error {
  readonly code: string;
  constructor(code: string, message: string, cause?: Error);
}

export declare const requiredAnalyzerControlFiles: readonly [
  'runtime-snapshot-loader.mjs',
  'resource-governance-launcher.mjs',
  'runtime-memfd-addon.node',
];

/**
 * Re-authenticates and streams the complete manifest closure into sealed
 * anonymous descriptors. `controlCapability` must be the exact opaque object
 * returned in this verified identity; raw control paths are intentionally not
 * accepted.
 */
export declare const sealVerifiedAnalyzerRuntime: (options: Readonly<{
  root: string;
  identity: AnalyzerRuntimeIdentity;
  controlCapability: AnalyzerControlCapability;
}>) => SealedAnalyzerRuntimeGeneration;

export declare const inspectSealedAnalyzerRuntime: (
  sealedRuntime: SealedAnalyzerRuntimeGeneration,
) => SealedAnalyzerRuntimeInspection;

export declare const materializeSealedAnalyzerRuntime: (
  sealedRuntime: SealedAnalyzerRuntimeGeneration,
) => MaterializedAnalyzerRuntime;

export declare const inspectMaterializedAnalyzerRuntime: (
  materializedRuntime: MaterializedAnalyzerRuntime,
) => MaterializedAnalyzerRuntimeInspection;

export declare const assertTrustedRuntimeControlFd: (options: Readonly<{
  fd: number;
  byteLength: number;
  sha256: string;
  identity: DescriptorIdentity;
}>) => Readonly<{
  fd: number;
  byteLength: number;
  sha256: string;
  identity: DescriptorIdentity;
}>;

/** Load the retained native bridge only after identity and byte re-proof. */
export declare const loadRuntimeMemfdBridgeFromFd: (options: Readonly<{
  addonFd: number;
  addonBytes: number;
  addonSha256: string;
  addonIdentity: DescriptorIdentity;
}>) => RuntimeMemfdBridge;

export declare const assertSealedRuntimeSnapshotFd: (options: Readonly<{
  fd: number;
  archiveBytes: number;
  manifestSha256: string;
  runnerSha256: string;
  nodeSha256: string;
  osvDatabaseSha256: string;
  snapshotIdentity: DescriptorIdentity;
  addonFd: number;
  addonBytes: number;
  addonSha256: string;
  addonIdentity: DescriptorIdentity;
}>) => SealedMemfdProof & Readonly<{
  header: Readonly<{
    entryCount: number;
    manifestSha256: string;
    runnerSha256: string;
    nodeSha256: string;
    osvDatabaseSha256: string;
  }>;
}>;

export declare const assertSealedRuntimeNodeFd: (options: Readonly<{
  nodeFd: number;
  nodeSha256: string;
  nodeBytes: number;
  nodeIdentity: DescriptorIdentity;
  addonFd: number;
  addonBytes: number;
  addonSha256: string;
  addonIdentity: DescriptorIdentity;
}>) => SealedMemfdProof;

export declare const assertSealedOfflineOsvDatabaseFd: (options: Readonly<{
  osvDatabaseFd: number;
  osvDatabaseSha256: string;
  osvDatabaseBytes: number;
  osvDatabaseGeneration: string;
  osvDatabaseIdentity: DescriptorIdentity;
  addonFd: number;
  addonBytes: number;
  addonSha256: string;
  addonIdentity: DescriptorIdentity;
  verifyContent?: boolean;
}>) => SealedMemfdProof;

export declare const assertMaterializedAnalyzerRuntimeRootFd: (options: Readonly<{
  runtimeRootFd: number;
  runtimeRootIdentity: DescriptorIdentity;
  manifestSha256: string;
  runnerSha256: string;
  nodeSha256: string;
}>) => Readonly<{
  runtimeRootFd: number;
  runtimeRootIdentity: DescriptorIdentity;
}>;
