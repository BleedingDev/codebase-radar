import {
  AnalysisRuntimeUnavailable,
  RequiredAnalyzerIds,
  type AnalysisRequest,
} from '@codebase-radar/contracts';
import {
  assertResourceGovernedLaunchCapability,
} from '@codebase-radar/analyzer-runtime/resource-governance';
import {
  materializeSealedAnalyzerRuntime,
  sealVerifiedAnalyzerRuntime,
  type MaterializedAnalyzerRuntime,
} from '@codebase-radar/analyzer-runtime/runtime-sealed-generation';
import {
  type AnalyzerRuntimeIdentity,
  verifyAnalyzerRuntime,
} from '@codebase-radar/analyzer-runtime/runtime-verifier';
import { runtimeTrustAnchor } from '@codebase-radar/analyzer-runtime/trust-anchor';
import { Context, Effect, Exit, Layer, Scope } from 'effect';
import { AnalyzerRuntime } from './internal/analyzers/index.js';
import { makeWorkspaceDescriptorAnalyzerRuntime } from './internal/analyzers/workspace-runtime.js';
import {
  makeNodeLinuxDescriptorWorkspaceBinding,
  probeNodeLinuxDescriptorHost,
} from './internal/linux-descriptor-host.js';
import {
  makeNodeGitHubSourceTransport,
  makeSourceMaterializerLayer,
} from './internal/source/index.js';
import {
  makeLinuxDescriptorWorkspaceHost,
  WorkspaceAllocatorLive,
  WorkspaceDescriptorHost,
  WorkspaceReaderLive,
} from './internal/workspace.js';
import { makeRadarAnalysisPrivateLive } from './scanner-private.js';
import { RadarAnalysis } from './scanner-service.js';
import {
  makeRadarRuntimePreflight,
  RadarRuntimeEvidence,
  RadarRuntimeManifest,
  RadarRuntimePreflight,
  RadarRuntimeReport,
} from './runtime-preflight.js';

/**
 * The only host-controlled locations accepted by the supported Linux
 * composition. Each value is explicit and absolute; no production default can
 * redirect a verifier, control bundle, cgroup, source workspace, or runner.
 */
export interface RadarProductionOptions {
  /** Absolute target runtime root verified against the compiled trust anchor. */
  readonly runtimeRoot: string;
  /** Existing private (0700) directory owned by the Radar service account. */
  readonly workspaceParent: string;
  /** Explicit delegated cgroup-v2 parent for resource-governed analyzer children. */
  readonly resourceCgroupRoot: string;
  /** Explicit independently deployed immutable analyzer-control installation. */
  readonly analyzerControlRoot: string;
}

interface PreparedProductionRuntime {
  readonly materializedRuntime: MaterializedAnalyzerRuntime;
}

const runtimeUnavailable = (message: string) => new AnalysisRuntimeUnavailable({ message });

const trustedManifest = () => new RadarRuntimeManifest({
  policyDigest: `sha256:${runtimeTrustAnchor.policyDigest}`,
  buildIdentity: runtimeTrustAnchor.buildIdentity,
});

const reportFor = (status: 'ready' | 'unavailable') => new RadarRuntimeReport({
  schemaVersion: 'codebase-radar.runtime-report/v1',
  status,
  manifest: trustedManifest(),
  evidence: RequiredAnalyzerIds.map(analyzer => new RadarRuntimeEvidence({
    analyzer,
    status,
  })),
});

const isCanonicalGenerationPart = (value: string) =>
  /^(?:0|[1-9][0-9]*)$/u.test(value);

const isDigest = (value: string) => /^[0-9a-f]{64}$/u.test(value);

const isTrustedHostTool = (
  tool: AnalyzerRuntimeIdentity['resourceGovernance']['tools']['bwrap'],
  anchor:
    | typeof runtimeTrustAnchor.resourceGovernance.bwrap
    | typeof runtimeTrustAnchor.resourceGovernance.prlimit
    | typeof runtimeTrustAnchor.resourceGovernance.node,
) =>
  tool.path === anchor.path &&
  tool.sha256 === anchor.sha256 &&
  tool.versionFirstLine === anchor.versionFirstLine &&
  isCanonicalGenerationPart(tool.metadata.device) &&
  isCanonicalGenerationPart(tool.metadata.inode) &&
  Number.isSafeInteger(tool.metadata.size) &&
  tool.metadata.size > 0 &&
  tool.metadata.mode === '0755' &&
  tool.metadata.uid === 0 &&
  tool.metadata.gid === 0;

const isTrustedResourceGovernance = (identity: AnalyzerRuntimeIdentity): boolean => {
  const evidence = identity.resourceGovernance;
  const anchor = runtimeTrustAnchor.resourceGovernance;
  return evidence.schemaVersion === anchor.schemaVersion &&
    evidence.status === 'passed' &&
    evidence.cgroupV2.controllers.length === 3 &&
    evidence.cgroupV2.controllers[0] === 'cpu' &&
    evidence.cgroupV2.controllers[1] === 'memory' &&
    evidence.cgroupV2.controllers[2] === 'pids' &&
    evidence.cgroupV2.pidsMax === '128' &&
    evidence.cgroupV2.memoryMax === '2147483648' &&
    evidence.cgroupV2.memorySwapMax === '0' &&
    evidence.cgroupV2.memoryOomGroup === '1' &&
    evidence.cgroupV2.cpuMax === '200000 100000' &&
    evidence.cgroupV2.ownership === 'parent-pre-registered' &&
    evidence.cgroupV2.launcherCrashCleanup === 'parent-supervised' &&
    evidence.cgroupV2.staleCgroupPolicy === 'reject-unowned' &&
    evidence.cgroupV2.cleanup === 'passed' &&
    isTrustedHostTool(evidence.tools.bwrap, anchor.bwrap) &&
    isTrustedHostTool(evidence.tools.prlimit, anchor.prlimit) &&
    isTrustedHostTool(evidence.tools.node, anchor.node) &&
    evidence.launch.runtimeRootChildDescriptor === 3 &&
    evidence.launch.seccompChildDescriptor === 4 &&
    evidence.launch.osvDatabaseChildDescriptor === 5 &&
    evidence.launch.osvDatabaseScope === 'OSV-Scanner-only' &&
    evidence.launch.sourceChildDescriptor === 6 &&
    evidence.launch.requestChildDescriptor === 7 &&
    evidence.launch.namespaceArguments.length === 2 &&
    evidence.launch.namespaceArguments[0] === '--unshare-all' &&
    evidence.launch.namespaceArguments[1] === '--unshare-net' &&
    evidence.launch.maximumConcurrentAnalyzers === 1 &&
    evidence.launch.admission === 'fifo-interruptible-deadline-bound' &&
    evidence.offlineOsvDatabase.status === 'sealed-capability-required' &&
    evidence.offlineOsvDatabase.generation === '1786418349414076' &&
    evidence.offlineOsvDatabase.bytes === 218758368 &&
    evidence.offlineOsvDatabase.sha256 ===
      '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69' &&
    evidence.offlineOsvDatabase.runtimeRelativePath ===
      'databases/osv/osv-scalibr/npm/all.zip' &&
    evidence.offlineOsvDatabase.sandboxPath ===
      '/runtime/databases/osv/osv-scalibr/npm/all.zip' &&
    evidence.offlineOsvDatabase.scannerArguments.length === 3 &&
    evidence.offlineOsvDatabase.scannerArguments[0] === '--offline' &&
    evidence.offlineOsvDatabase.scannerArguments[1] ===
      '--local-db-path=/runtime/databases/osv' &&
    evidence.offlineOsvDatabase.scannerArguments[2] === '--no-resolve' &&
    evidence.offlineOsvDatabase.environment.OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY ===
      '/runtime/databases/osv' &&
    evidence.offlineOsvDatabase.network === 'blocked' &&
    evidence.child.prlimitArguments.length === 5 &&
    evidence.child.prlimitArguments[0] === '--core=0:0' &&
    evidence.child.prlimitArguments[1] === '--fsize=16777216:16777216' &&
    evidence.child.prlimitArguments[2] === '--nofile=256:256' &&
    evidence.child.prlimitArguments[3] === '--cpu=130:130' &&
    evidence.child.prlimitArguments[4] === '--as=8589934592:8589934592' &&
    evidence.child.nproc === 'not-set' &&
    evidence.child.limits.core.soft === '0' &&
    evidence.child.limits.core.hard === '0' &&
    evidence.child.limits.core.unit === 'bytes' &&
    evidence.child.limits.fsize.soft === '16777216' &&
    evidence.child.limits.fsize.hard === '16777216' &&
    evidence.child.limits.fsize.unit === 'bytes' &&
    evidence.child.limits.nofile.soft === '256' &&
    evidence.child.limits.nofile.hard === '256' &&
    evidence.child.limits.nofile.unit === 'files' &&
    evidence.child.limits.cpu.soft === '130' &&
    evidence.child.limits.cpu.hard === '130' &&
    evidence.child.limits.cpu.unit === 'seconds' &&
    evidence.child.limits.as.soft === '8589934592' &&
    evidence.child.limits.as.hard === '8589934592' &&
    evidence.child.limits.as.unit === 'bytes' &&
    evidence.child.seccompPolicySha256 === anchor.seccompPolicySha256 &&
    evidence.child.seccomp === 'passed' &&
    evidence.child.network === 'blocked' &&
    evidence.controlLauncher.status === 'authenticated' &&
    evidence.controlLauncher.path === 'resource-governance-launcher.mjs' &&
    isDigest(evidence.controlLauncher.sha256) &&
    Number.isSafeInteger(evidence.controlLauncher.byteLength) &&
    evidence.controlLauncher.byteLength > 0 &&
    evidence.controlLauncher.mode === '0444' &&
    isCanonicalGenerationPart(evidence.controlLauncher.identity.device) &&
    isCanonicalGenerationPart(evidence.controlLauncher.identity.inode);
};

const isTrustedIdentity = (identity: AnalyzerRuntimeIdentity): boolean =>
  identity.schemaVersion === 'codebase-radar.analyzer-runtime-identity/v1' &&
  identity.manifestSha256 === runtimeTrustAnchor.manifestSha256 &&
  identity.policyDigest === runtimeTrustAnchor.policyDigest &&
  identity.runnerSha256 === runtimeTrustAnchor.runnerSha256 &&
  identity.buildIdentity === runtimeTrustAnchor.buildIdentity &&
  identity.sandbox.kind === runtimeTrustAnchor.sandbox.kind &&
  identity.sandbox.packageVersion === runtimeTrustAnchor.sandbox.packageVersion &&
  identity.sandbox.strictProbe === 'passed' &&
  identity.sandbox.version === runtimeTrustAnchor.sandbox.versionOutput &&
  identity.analyzers.length === RequiredAnalyzerIds.length &&
  identity.analyzers.every((item, index) =>
    item.analyzer === RequiredAnalyzerIds[index] && item.version.length > 0,
  ) &&
  isTrustedResourceGovernance(identity) &&
  isCanonicalGenerationPart(identity.targetGeneration.device) &&
  isCanonicalGenerationPart(identity.targetGeneration.inode);

const closeAnalyzerControl = (identity: AnalyzerRuntimeIdentity) => Effect.try({
  try: () => identity.analyzerControl.close(),
  catch: () => runtimeUnavailable('The verified analyzer-control capability could not be released.'),
});

const verifyTrustedRuntimeIdentity = (
  options: Pick<
    RadarProductionOptions,
    'runtimeRoot' | 'resourceCgroupRoot' | 'analyzerControlRoot'
  >,
): Effect.Effect<AnalyzerRuntimeIdentity, AnalysisRuntimeUnavailable> =>
  Effect.try({
    try: () => verifyAnalyzerRuntime({
      root: options.runtimeRoot,
      cgroupRoot: options.resourceCgroupRoot,
      analyzerControlRoot: options.analyzerControlRoot,
    }),
    catch: () => runtimeUnavailable('The analyzer runtime could not be verified.'),
  }).pipe(
    Effect.flatMap(identity => isTrustedIdentity(identity)
      ? Effect.succeed(identity)
      : closeAnalyzerControl(identity).pipe(
        Effect.andThen(Effect.fail(
          runtimeUnavailable('The verified runtime did not match its trust anchor.'),
        )),
      )),
  );

const sealTrustedRuntime = (
  options: Pick<RadarProductionOptions, 'runtimeRoot'>,
  identity: AnalyzerRuntimeIdentity,
): Effect.Effect<ReturnType<typeof sealVerifiedAnalyzerRuntime>, AnalysisRuntimeUnavailable> =>
  Effect.sync(() => {
    let sealed: ReturnType<typeof sealVerifiedAnalyzerRuntime> | undefined;
    try {
      sealed = sealVerifiedAnalyzerRuntime({
        root: options.runtimeRoot,
        identity,
        controlCapability: identity.analyzerControl,
      });
      identity.analyzerControl.close();
      return sealed;
    } catch {
      try {
        sealed?.close();
      } catch {
        // The failed setup scope remains unavailable even if its emergency close also fails.
      }
      try {
        identity.analyzerControl.close();
      } catch {
        // The verifier capability is best-effort closed on an already failed acquisition.
      }
      return undefined;
    }
  }).pipe(
    Effect.flatMap(sealed => sealed === undefined
      ? Effect.fail(runtimeUnavailable('The verified analyzer runtime could not be sealed.'))
      : Effect.succeed(sealed)),
  );

const isTrustedMaterializedRuntime = (runtime: MaterializedAnalyzerRuntime) =>
  runtime.schemaVersion === 'codebase-radar.analyzer-runtime-materialized/v1' &&
  runtime.manifestSha256 === runtimeTrustAnchor.manifestSha256 &&
  runtime.runnerSha256 === runtimeTrustAnchor.runnerSha256 &&
  isDigest(runtime.nodeSha256) &&
  runtime.osvDatabaseSha256 ===
    '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69' &&
  runtime.osvDatabaseRelativePath === 'databases/osv/osv-scalibr/npm/all.zip' &&
  runtime.osvDatabaseBytes === 218758368 &&
  runtime.osvDatabaseGeneration === '1786418349414076' &&
  isCanonicalGenerationPart(runtime.runtimeRootIdentity.device) &&
  isCanonicalGenerationPart(runtime.runtimeRootIdentity.inode);

const assertRetainedRuntimeCapabilities = (
  options: Pick<RadarProductionOptions, 'resourceCgroupRoot'>,
  materializedRuntime: MaterializedAnalyzerRuntime,
): Effect.Effect<void, AnalysisRuntimeUnavailable> =>
  Effect.try({
    try: () => RequiredAnalyzerIds.map(analyzer =>
      assertResourceGovernedLaunchCapability({
        analyzerId: analyzer,
        cgroupRoot: options.resourceCgroupRoot,
        materializedRuntime,
      })),
    catch: () => runtimeUnavailable('The sealed analyzer runtime cannot satisfy resource governance.'),
  }).pipe(
    Effect.flatMap(capabilities => {
      const valid = isTrustedMaterializedRuntime(materializedRuntime) &&
        capabilities.length === RequiredAnalyzerIds.length &&
        capabilities.every((capability, index) => {
          const analyzer = RequiredAnalyzerIds[index];
          const osvRequired = analyzer === 'OSV-Scanner';
          return analyzer !== undefined &&
            capability.schemaVersion === 'codebase-radar.analyzer-resource-launch-capability/v1' &&
            capability.analyzerId === analyzer &&
            capability.cgroupRoot === options.resourceCgroupRoot &&
            capability.runtime.schemaVersion ===
              'codebase-radar.analyzer-runtime-materialized/v1' &&
            capability.runtime.manifestSha256 === runtimeTrustAnchor.manifestSha256 &&
            capability.runtime.runnerSha256 === runtimeTrustAnchor.runnerSha256 &&
            isDigest(capability.runtime.nodeSha256) &&
            isCanonicalGenerationPart(capability.runtime.runtimeRootIdentity.device) &&
            isCanonicalGenerationPart(capability.runtime.runtimeRootIdentity.inode) &&
            capability.offlineOsvDatabase.generation === '1786418349414076' &&
            capability.offlineOsvDatabase.bytes === 218758368 &&
            capability.offlineOsvDatabase.sha256 ===
              '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69' &&
            capability.offlineOsvDatabase.runtimeRelativePath ===
              'databases/osv/osv-scalibr/npm/all.zip' &&
            capability.offlineOsvDatabase.sandboxPath ===
              '/runtime/databases/osv/osv-scalibr/npm/all.zip' &&
            capability.offlineOsvDatabase.network === 'blocked' &&
            capability.offlineOsvDatabase.status ===
              (osvRequired ? 'authenticated' : 'withheld');
        });
      return valid
        ? Effect.void
        : Effect.fail(runtimeUnavailable(
          'The sealed analyzer runtime did not retain its governed capabilities.',
        ));
    }),
  );

const acquirePreparedProductionRuntime = (
  options: RadarProductionOptions,
): Effect.Effect<PreparedProductionRuntime, AnalysisRuntimeUnavailable, Scope.Scope> =>
  Effect.gen(function* () {
    const identity = yield* verifyTrustedRuntimeIdentity(options);
    const sealedRuntime = yield* Effect.acquireRelease(
      sealTrustedRuntime(options, identity),
      runtime => Effect.sync(() => runtime.close()),
    );
    const materializedRuntime = yield* Effect.acquireRelease(
      Effect.try({
        try: () => materializeSealedAnalyzerRuntime(sealedRuntime),
        catch: () => runtimeUnavailable('The verified analyzer runtime could not be materialized.'),
      }),
      runtime => Effect.sync(() => runtime.close()),
    );
    return { materializedRuntime };
  });

/**
 * Verifies a target runtime using this installation's static verifier/trust
 * anchor. The returned manifest owns no target or control descriptor: the
 * opaque verifier capability is always released before the Effect completes.
 */
export const verifyTrustedRadarAnalyzerRuntime = (
  options: Pick<
    RadarProductionOptions,
    'runtimeRoot' | 'resourceCgroupRoot' | 'analyzerControlRoot'
  >,
): Effect.Effect<RadarRuntimeManifest, AnalysisRuntimeUnavailable> =>
  Effect.scoped(Effect.acquireUseRelease(
    verifyTrustedRuntimeIdentity(options),
    () => Effect.succeed(trustedManifest()),
    closeAnalyzerControl,
  ));

const inspectRetainedProductionRuntime = (
  options: RadarProductionOptions,
  prepared: PreparedProductionRuntime,
) => Effect.all([
  probeNodeLinuxDescriptorHost({ workspaceParent: options.workspaceParent }),
  makeNodeGitHubSourceTransport({ allowInsecureTestOrigins: false }),
  assertRetainedRuntimeCapabilities(options, prepared.materializedRuntime),
]).pipe(
  Effect.as(reportFor('ready')),
  Effect.catch(() => Effect.succeed(reportFor('unavailable'))),
);

/**
 * Performs an ephemeral verify/seal/materialize diagnostic. It never reports
 * ready from a verifier-only result and it releases every opaque capability
 * before returning its report.
 */
const inspectProductionRuntime = (options: RadarProductionOptions) =>
  Effect.scoped(
    acquirePreparedProductionRuntime(options).pipe(
      Effect.flatMap(prepared => inspectRetainedProductionRuntime(options, prepared)),
    ),
  ).pipe(Effect.catch(() => Effect.succeed(reportFor('unavailable'))));

/** Strict diagnostic/readiness service for the supported production runtime. */
export const makeProductionRadarRuntimePreflight = (
  options: RadarProductionOptions,
) => makeRadarRuntimePreflight({
  inspect: () => inspectProductionRuntime(options),
});

/**
 * Lets hosts report a canonical fail-closed diagnostic when required explicit
 * production configuration is absent, without inventing paths or readiness.
 */
export const makeUnavailableRadarRuntimePreflight = () => makeRadarRuntimePreflight({
  inspect: () => Effect.succeed(reportFor('unavailable')),
});

const unavailableProductionContext = () => {
  const preflight = makeUnavailableRadarRuntimePreflight();
  const analysis = RadarAnalysis.of({
    analyze: () => preflight.check().pipe(
      Effect.andThen(Effect.fail(runtimeUnavailable('The production runtime is unavailable.'))),
    ),
  });
  return Context.empty().pipe(
    Context.add(RadarRuntimePreflight, preflight),
    Context.add(RadarAnalysis, analysis),
  );
};

const makeReadyProductionContext = (
  options: RadarProductionOptions,
) => Effect.gen(function* () {
  const prepared = yield* acquirePreparedProductionRuntime(options);
  const preflight = makeRadarRuntimePreflight({
    inspect: () => inspectRetainedProductionRuntime(options, prepared),
  });
  yield* preflight.check();
  const binding = yield* makeNodeLinuxDescriptorWorkspaceBinding({
    workspaceParent: options.workspaceParent,
    resourceCgroupRoot: options.resourceCgroupRoot,
    materializedRuntime: prepared.materializedRuntime,
  }).pipe(Effect.mapError(() => runtimeUnavailable(
    'The required native descriptor host is unavailable.',
  )));
  const host = yield* makeLinuxDescriptorWorkspaceHost(binding);
  const transport = yield* makeNodeGitHubSourceTransport({
    allowInsecureTestOrigins: false,
  }).pipe(Effect.mapError(() => runtimeUnavailable(
    'The required source transport is unavailable.',
  )));
  const workspace = Layer.mergeAll(
    WorkspaceAllocatorLive,
    WorkspaceReaderLive,
  ).pipe(Layer.provide(Layer.succeed(WorkspaceDescriptorHost, host)));
  const source = makeSourceMaterializerLayer(
    transport.resolver,
    transport.archives,
  ).pipe(Layer.provide(Layer.mergeAll(
    workspace,
    Layer.succeed(WorkspaceDescriptorHost, host),
  )));
  const dependencies = Layer.mergeAll(
    source,
    workspace,
    Layer.succeed(AnalyzerRuntime, makeWorkspaceDescriptorAnalyzerRuntime(host)),
  );
  const live = makeRadarAnalysisPrivateLive().pipe(Layer.provide(dependencies));
  const privateAnalysis = yield* RadarAnalysis.pipe(Effect.provide(live));
  const analysis = RadarAnalysis.of({
    analyze: (request: AnalysisRequest) => preflight.check().pipe(
      Effect.andThen(privateAnalysis.analyze(request)),
    ),
  });
  return Context.empty().pipe(
    Context.add(RadarRuntimePreflight, preflight),
    Context.add(RadarAnalysis, analysis),
  );
});

const makeProductionContext = (options: RadarProductionOptions) => Effect.gen(function* () {
  const applicationScope = yield* Scope.Scope;
  const setupScope = yield* Scope.fork(applicationScope);
  const ready = yield* Effect.exit(
    makeReadyProductionContext(options).pipe(
      Effect.provideService(Scope.Scope, setupScope),
    ),
  );
  if (Exit.isSuccess(ready)) return ready.value;
  yield* Scope.close(setupScope, Exit.void).pipe(Effect.ignore);
  return unavailableProductionContext();
});

/**
 * Truthful supported production composition. The layer owns one verified,
 * sealed and materialized runtime generation for its whole lifetime. Scan
 * calls receive only its opaque materialized capability through governance;
 * target runtime and analyzer-control paths are never reopened or mounted by
 * core execution code.
 */
export const makeRadarProductionLayer = (options: RadarProductionOptions) =>
  Layer.effectContext(makeProductionContext(options));
