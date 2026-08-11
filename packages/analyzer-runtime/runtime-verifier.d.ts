import type { ResourceGovernanceEvidence } from './resource-governance.mjs';

declare const analyzerControlCapabilityBrand: unique symbol;

/**
 * A live descriptor-backed capability. Its private brand and the runtime
 * WeakMap make a structurally similar object unusable by trusted consumers.
 */
export interface AnalyzerControlCapability {
  readonly [analyzerControlCapabilityBrand]: 'codebase-radar.analyzer-control-capability/v1';
  close(): void;
}

export interface AnalyzerRuntimeIdentity {
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-identity/v1';
  readonly manifestSha256: string;
  readonly policyDigest: string;
  readonly runnerSha256: string;
  readonly buildIdentity: string;
  /** Opaque decimal device/inode identity of the verified target generation. */
  readonly targetGeneration: Readonly<{
    readonly device: string;
    readonly inode: string;
  }>;
  /** Retained, verified control descriptors; close after sealing transfers them. */
  readonly analyzerControl: AnalyzerControlCapability;
  readonly sandbox: Readonly<{
    kind: 'bubblewrap';
    packageVersion: '0.9.0-1ubuntu0.1';
    version: 'bubblewrap 0.9.0';
    strictProbe: 'passed';
  }>;
  readonly resourceGovernance: ResourceGovernanceEvidence;
  readonly analyzers: ReadonlyArray<Readonly<{
    analyzer: string;
    version: string;
  }>>;
}

export declare class AnalyzerRuntimeVerificationError extends Error {
  readonly code: string;
  constructor(code: string, message: string, cause?: Error);
}

export declare const verifyAnalyzerRuntime: (options: Readonly<{
  root: string;
  /** Explicit service-instance delegated cgroup-v2 root. */
  cgroupRoot: string;
  /** Explicit root-owned immutable analyzer-control installation. */
  analyzerControlRoot: string;
}>) => Readonly<AnalyzerRuntimeIdentity>;

/**
 * Authenticate the standalone analyzer-control installation. Consumers need
 * only the opaque capability; descriptor inspection is reserved for trusted
 * runtime sibling modules.
 */
export declare const verifyAnalyzerControl: (options: Readonly<{
  controlRoot: string;
  /** When provided, the control root must not overlap this target runtime. */
  runtimeRoot?: string;
}>) => AnalyzerControlCapability;
