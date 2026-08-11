import type { ChildProcess } from 'node:child_process';
import type {
  DescriptorIdentity,
  MaterializedAnalyzerRuntime,
} from './runtime-sealed-generation.mjs';
import type { AnalyzerControlCapability } from './runtime-verifier.mjs';

export type AnalyzerId =
  | 'strictest-comparator'
  | 'Oxlint + Ultracite'
  | 'JSCPD'
  | 'Calldiff'
  | 'zizmor'
  | 'OSV-Scanner'
  | 'TraceDecay';

export declare const resourceGovernanceSchemaVersion: 'codebase-radar.analyzer-resource-governance/v1';

export declare const requiredCgroupControllers: readonly ['cpu', 'memory', 'pids'];

export declare const requiredCgroupLimits: Readonly<{
  pidsMax: '128';
  memoryMax: '2147483648';
  memorySwapMax: '0';
  memoryOomGroup: '1';
  cpuMax: '200000 100000';
}>;

/** RLIMIT_NPROC is deliberately absent; pids.max is the per-analysis PID cap. */
export declare const requiredPrlimitArguments: readonly [
  '--core=0:0',
  '--fsize=16777216:16777216',
  '--nofile=256:256',
  '--cpu=130:130',
  '--as=8589934592:8589934592',
];

export declare const requiredChildLimits: Readonly<Record<
  'core' | 'fsize' | 'nofile' | 'cpu' | 'as',
  Readonly<{ soft: string; hard: string; unit: string }>
>>;

export declare const requiredOfflineOsvDatabase: Readonly<{
  readonly generation: '1786418349414076';
  readonly bytes: 218758368;
  readonly sha256: '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69';
  readonly runtimeRelativePath: 'databases/osv/osv-scalibr/npm/all.zip';
  readonly sandboxPath: '/runtime/databases/osv/osv-scalibr/npm/all.zip';
  readonly scannerArguments: readonly [
    '--offline',
    '--local-db-path=/runtime/databases/osv',
    '--no-resolve',
  ];
  readonly environment: Readonly<{
    readonly OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY: '/runtime/databases/osv';
  }>;
}>;

export declare const resourceSeccompPolicyArchitecture: 'x86_64';
export declare const resourceSeccompPolicySha256: string;
export declare const buildResourceSeccompPolicy: () => Buffer;

export declare class ResourceGovernanceError extends Error {
  readonly code: string;
  constructor(code: string, message: string, cause?: Error);
}

export interface HostToolIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly versionFirstLine: string;
}

export interface HostToolEvidence extends HostToolIdentity {
  readonly metadata: Readonly<{
    readonly device: string;
    readonly inode: string;
    readonly size: number;
    readonly mode: '0755';
    readonly uid: 0;
    readonly gid: 0;
  }>;
}

export declare const verifyTrustedHostTool: (tool: HostToolIdentity) => HostToolEvidence;

export declare const buildResourceGovernedCommand: (bwrapArguments: readonly string[]) => Readonly<{
  readonly executable: '/usr/bin/prlimit';
  readonly arguments: readonly string[];
}>;

export declare const buildPrlimitedAnalyzerCommand: (
  executable: string,
  analyzerArguments: readonly string[],
) => Readonly<{
  readonly executable: '/usr/bin/prlimit';
  readonly arguments: readonly string[];
}>;

/** Exact production Bubblewrap argv; materialization has already completed. */
export declare const buildMaterializedAnalyzerBwrapArguments: (
  analyzerId: AnalyzerId,
) => readonly string[];

export interface ResourceGovernanceCgroupEvidence {
  readonly controllers: readonly ['cpu', 'memory', 'pids'];
  readonly pidsMax: '128';
  readonly memoryMax: '2147483648';
  readonly memorySwapMax: '0';
  readonly memoryOomGroup: '1';
  readonly cpuMax: '200000 100000';
  readonly ownership: 'parent-pre-registered';
  readonly launcherCrashCleanup: 'parent-supervised';
  readonly staleCgroupPolicy: 'reject-unowned';
  readonly cleanup: 'passed';
}

export interface ResourceGovernanceLaunchEvidence {
  readonly runtimeRootChildDescriptor: 3;
  readonly seccompChildDescriptor: 4;
  readonly osvDatabaseChildDescriptor: 5;
  readonly osvDatabaseScope: 'OSV-Scanner-only';
  readonly sourceChildDescriptor: 6;
  readonly requestChildDescriptor: 7;
  readonly namespaceArguments: readonly ['--unshare-all', '--unshare-net'];
  readonly maximumConcurrentAnalyzers: 1;
  readonly admission: 'fifo-interruptible-deadline-bound';
}

export interface ResourceGovernanceOfflineOsvEvidence {
  readonly status: 'sealed-capability-required';
  readonly generation: typeof requiredOfflineOsvDatabase.generation;
  readonly bytes: typeof requiredOfflineOsvDatabase.bytes;
  readonly sha256: typeof requiredOfflineOsvDatabase.sha256;
  readonly runtimeRelativePath: typeof requiredOfflineOsvDatabase.runtimeRelativePath;
  readonly sandboxPath: typeof requiredOfflineOsvDatabase.sandboxPath;
  readonly scannerArguments: typeof requiredOfflineOsvDatabase.scannerArguments;
  readonly environment: typeof requiredOfflineOsvDatabase.environment;
  readonly network: 'blocked';
}

export interface ResourceGovernanceEvidence {
  readonly schemaVersion: 'codebase-radar.analyzer-resource-governance/v1';
  readonly status: 'passed';
  readonly cgroupV2: ResourceGovernanceCgroupEvidence;
  readonly tools: Readonly<{
    readonly bwrap: HostToolEvidence;
    readonly prlimit: HostToolEvidence;
    readonly node: HostToolEvidence;
  }>;
  readonly launch: ResourceGovernanceLaunchEvidence;
  readonly offlineOsvDatabase: ResourceGovernanceOfflineOsvEvidence;
  readonly child: Readonly<{
    readonly prlimitArguments: typeof requiredPrlimitArguments;
    readonly nproc: 'not-set';
    readonly limits: typeof requiredChildLimits;
    readonly seccompPolicySha256: string;
    readonly seccomp: 'passed';
    readonly network: 'blocked';
  }>;
  readonly controlLauncher: Readonly<{
    readonly status: 'authenticated';
    readonly path: 'resource-governance-launcher.mjs';
    readonly byteLength: number;
    readonly sha256: string;
    readonly mode: '0444';
    readonly identity: DescriptorIdentity;
  }> | Readonly<{
    readonly status: 'test-injected';
  }>;
}

/** Production readiness consumes only the retained opaque control capability. */
export declare const verifyResourceGovernance: (options: Readonly<{
  readonly cgroupRoot: string;
  readonly analyzerControl: AnalyzerControlCapability;
}>) => ResourceGovernanceEvidence;

/** Test-only injectable identities for an explicitly delegated Linux harness. */
export declare const verifyResourceGovernanceForTest: (options: Readonly<{
  readonly cgroupRoot: string;
  readonly launcherPath: string;
  readonly tools: Readonly<{
    readonly bwrap: HostToolIdentity;
    readonly prlimit: HostToolIdentity;
    readonly node: HostToolIdentity;
  }>;
}>) => ResourceGovernanceEvidence;

export type ResourceGovernedAnalyzerCompletion = Readonly<{
  readonly status: 'terminated';
  readonly reason: 'exit' | 'timeout' | 'cancel';
  readonly exitCode: number;
  readonly cleanup: 'not-needed' | 'passed';
}> | Readonly<{
  readonly status: 'failed';
  readonly reason: string;
  readonly exitCode: number;
  readonly cleanup: 'not-needed' | 'passed' | 'failed';
  readonly errorCode: string;
  readonly signal?: NodeJS.Signals | null;
}>;

export interface ResourceGovernedLaunchCapabilityEvidence {
  readonly schemaVersion: 'codebase-radar.analyzer-resource-launch-capability/v1';
  readonly analyzerId: AnalyzerId;
  readonly cgroupRoot: string;
  readonly runtime: Readonly<{
    readonly schemaVersion: 'codebase-radar.analyzer-runtime-materialized/v1';
    readonly manifestSha256: string;
    readonly runnerSha256: string;
    readonly nodeSha256: string;
    readonly runtimeRootIdentity: DescriptorIdentity;
  }>;
  readonly offlineOsvDatabase: Readonly<{
    readonly status: 'authenticated' | 'withheld';
    readonly generation: typeof requiredOfflineOsvDatabase.generation;
    readonly bytes: typeof requiredOfflineOsvDatabase.bytes;
    readonly sha256: typeof requiredOfflineOsvDatabase.sha256;
    readonly runtimeRelativePath: typeof requiredOfflineOsvDatabase.runtimeRelativePath;
    readonly sandboxPath: typeof requiredOfflineOsvDatabase.sandboxPath;
    readonly network: 'blocked';
  }>;
}

/** Re-proves the reusable materialized runtime immediately before launch. */
export declare const assertResourceGovernedLaunchCapability: (options: Readonly<{
  readonly analyzerId: AnalyzerId;
  readonly cgroupRoot: string;
  readonly materializedRuntime: MaterializedAnalyzerRuntime;
}>) => ResourceGovernedLaunchCapabilityEvidence;

export interface ResourceGovernedAnalyzerSession {
  /** The short-lived trusted launcher, not the analyzer or Bubblewrap child. */
  readonly child: ChildProcess;
  readonly evidence: Readonly<{
    readonly cgroupV2: Omit<ResourceGovernanceCgroupEvidence, 'cleanup'>;
    readonly child: Readonly<{
      readonly prlimitArguments: typeof requiredPrlimitArguments;
      readonly nproc: 'not-set';
      readonly seccompPolicySha256: string;
      readonly network: 'blocked';
    }>;
    readonly launch: Readonly<{
      readonly runtimeRootChildDescriptor: 3 | null;
      readonly testSnapshotChildDescriptor: 3 | null;
      readonly seccompChildDescriptor: 4;
      readonly osvDatabaseChildDescriptor: 5 | null;
      readonly sourceChildDescriptor: 6 | null;
      readonly requestChildDescriptor: 7 | null;
      readonly namespaceArguments: readonly ['--unshare-all', '--unshare-net'];
      readonly maximumConcurrentAnalyzers: 1;
      readonly admission: 'fifo-interruptible-deadline-bound';
    }>;
    readonly offlineOsvDatabase: Readonly<{
      readonly status: 'authenticated' | 'withheld';
      readonly generation: typeof requiredOfflineOsvDatabase.generation;
      readonly bytes: typeof requiredOfflineOsvDatabase.bytes;
      readonly sha256: typeof requiredOfflineOsvDatabase.sha256;
      readonly runtimeRelativePath: typeof requiredOfflineOsvDatabase.runtimeRelativePath;
      readonly sandboxPath: typeof requiredOfflineOsvDatabase.sandboxPath;
      readonly network: 'blocked';
    }>;
  }>;
  /** Installed before request dispatch and held through cgroup cleanup. */
  readonly completion: Promise<ResourceGovernedAnalyzerCompletion>;
  /** Cooperative cancellation is the only supported termination operation. */
  readonly cancel: () => boolean;
}

export declare const launchResourceGovernedAnalyzer: (options: Readonly<{
  readonly analyzerId: AnalyzerId;
  readonly cgroupRoot: string;
  readonly materializedRuntime: MaterializedAnalyzerRuntime;
  /** Retained descriptor-relative source directory; mounted read-only at /workspace. */
  readonly sourceFd: number;
  /** Bounded request source; governance seals a private immutable memfd before launch. */
  readonly analyzerRequestFd: number;
  /** Total admission plus execution deadline. */
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}>) => Promise<ResourceGovernedAnalyzerSession>;

/** Test-only raw-descriptor injection for an explicit delegated Linux harness. */
export declare const launchResourceGovernedAnalyzerForTest: (options: Readonly<{
  readonly analyzerId: AnalyzerId;
  readonly cgroupRoot: string;
  readonly bwrapArguments: readonly string[];
  readonly environment: Readonly<Record<string, string>>;
  readonly launcherPath: string;
  readonly snapshotFd: number;
  readonly databaseFd?: number;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly tools: Readonly<{
    readonly bwrap: HostToolIdentity;
    readonly prlimit: HostToolIdentity;
    readonly node: HostToolIdentity;
  }>;
}>) => Promise<ResourceGovernedAnalyzerSession>;

export declare const parseChildLimits: (
  text: string,
) => ResourceGovernanceEvidence['child']['limits'];

/** Standalone-launcher protocol entry points; not application launch APIs. */
export declare const runResourceGovernanceProbeProtocol: (
  input: string,
) => Omit<ResourceGovernanceEvidence, 'controlLauncher'>;
export declare const runResourceGovernanceLaunchProtocol: (request: unknown) => Promise<void>;
