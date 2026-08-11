import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Config, Context } from 'effect';
import {
  defineEffectBff,
  Effect,
  HttpApiBuilder,
  Layer,
  Option,
  Schema,
} from '@modern-js/plugin-bff/effect-edge';
import type {
  EffectBffDefinition,
  EffectBffRuntime,
  EffectRuntimeLayer,
} from '@modern-js/plugin-bff/effect-edge';
import { McpServer, Tool, Toolkit } from 'effect/unstable/ai';
import {
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from 'effect/unstable/http';
import {
  AnalysisRuntimeUnavailable,
  DefaultBranchRevision,
  decodeAnalysisSource,
} from '@codebase-radar/contracts';
import {
  makeRadarProductionLayer,
  makeUnavailableRadarRuntimePreflight,
  RadarAnalysis,
  RadarAnalysisLive,
  RadarRuntimePreflight,
  type RadarProductionOptions,
} from '@codebase-radar/core';
import {
  AgentPriorityCapability,
  ApiFailure,
  CapabilityUnavailable,
  HealthResponse,
  InvalidInput,
  NotFound,
  RadarApi,
  ReadyResponse,
  ScanListResponse,
  SessionCookie,
} from '../shared/api';
import { parseGithubRepository } from '../shared/contracts';
import {
  Audience,
  AgentProfileList,
  BrowserSession,
  FindingTaskpack,
  PrioritizationBrief,
  ScanRecord,
  ScanResult,
} from '../shared/domain';
import {
  AgentCoordinator,
  AgentCoordinatorError,
  AgentCoordinatorLive,
} from '../server/agent-coordinator';
import {
  AgentRuntime,
  AgentRuntimeError,
  AgentRuntimeLive,
} from '../server/agent-runtime';
import {
  AgentScanVisibilityGate,
  AgentScanVisibilityGateLive,
  AgentVisibilityRejected,
} from '../server/agent-visibility-gate';
import {
  AgentStore,
  AgentStoreLive,
  grantVisibleScanAccess,
} from '../server/agent-store';
import {
  persistAndAttachScan,
  ScanCoordinator,
  ScanCoordinatorLive,
} from '../server/scan-runner';
import {
  buildFindingTaskpack,
  buildPrioritizationBrief,
  listImprovementBacklog,
} from '../server/mcp-read-model';
import { RadarStore, RadarStoreLive } from '../server/store';

class ToolFailure extends Schema.TaggedErrorClass<ToolFailure>()('ToolFailure', {
  message: Schema.String,
}) {}

const ListScans = Tool.make('list_scans', {
  description:
    'List recent immutable Codebase Radar scan snapshots and their current status.',
  parameters: Schema.Struct({
    limit: Schema.optional(Schema.Number),
  }),
  success: Schema.Struct({ scans: Schema.Array(ScanRecord) }),
  failure: ToolFailure,
  failureMode: 'return',
})
  .annotate(Tool.Readonly, true)
  .annotate(Tool.Destructive, false)
  .annotate(Tool.Idempotent, true)
  .annotate(Tool.OpenWorld, false);

const GetScan = Tool.make('get_scan', {
  description:
    'Get one immutable repository scan snapshot including analyzer coverage and comparison data.',
  parameters: Schema.Struct({ scanId: Schema.String }),
  success: ScanRecord,
  failure: ToolFailure,
  failureMode: 'return',
})
  .annotate(Tool.Readonly, true)
  .annotate(Tool.Destructive, false)
  .annotate(Tool.Idempotent, true)
  .annotate(Tool.OpenWorld, false);

const GetImprovementBacklog = Tool.make('get_improvement_backlog', {
  description:
    'Return every scored Finding in the single ranked evidence-backed backlog for a completed scan, including its analyzer mechanism. Audience affects communication, never ranking or evidence.',
  parameters: Schema.Struct({
    scanId: Schema.String,
    audience: Schema.optional(Audience),
  }),
  success: ScanResult,
  failure: ToolFailure,
  failureMode: 'return',
})
  .annotate(Tool.Readonly, true)
  .annotate(Tool.Destructive, false)
  .annotate(Tool.Idempotent, true)
  .annotate(Tool.OpenWorld, false);

const GetFindingTaskpack = Tool.make('get_finding_taskpack', {
  description:
    'Create an agent-ready, read-only taskpack for one selected finding without modifying the repository.',
  parameters: Schema.Struct({
    scanId: Schema.String,
    findingId: Schema.String,
  }),
  success: FindingTaskpack,
  failure: ToolFailure,
  failureMode: 'return',
})
  .annotate(Tool.Readonly, true)
  .annotate(Tool.Destructive, false)
  .annotate(Tool.Idempotent, true)
  .annotate(Tool.OpenWorld, false);

const GetPrioritizationBrief = Tool.make('get_prioritization_brief', {
  description:
    'Give Codex or Claude Code the complete scored Finding catalog for reviewing the next decisions. Designed to work alongside the official Zerops ZCP workspace.',
  parameters: Schema.Struct({ scanId: Schema.String }),
  success: PrioritizationBrief,
  failure: ToolFailure,
  failureMode: 'return',
})
  .annotate(Tool.Readonly, true)
  .annotate(Tool.Destructive, false)
  .annotate(Tool.Idempotent, true)
  .annotate(Tool.OpenWorld, false);

const RadarToolkit = Toolkit.make(
  ListScans,
  GetScan,
  GetImprovementBacklog,
  GetPrioritizationBrief,
  GetFindingTaskpack,
);

const ToolHandlersLive = RadarToolkit.toLayer(
  Effect.gen(function* () {
    const store = yield* RadarStore;
    const toolFailure = (message: string) => new ToolFailure({ message });
    return RadarToolkit.of({
      list_scans: ({ limit }) =>
        store.listRecentScans(limit).pipe(
          Effect.map(scans => ({ scans })),
          Effect.mapError(error => toolFailure(error.message)),
        ),
      get_scan: ({ scanId }) =>
        store.getScan(scanId).pipe(
          Effect.flatMap(
            Option.match({
              onNone: () => Effect.fail(toolFailure(`Scan ${scanId} was not found.`)),
              onSome: Effect.succeed,
            }),
          ),
          Effect.mapError(error =>
            error._tag === 'ToolFailure' ? error : toolFailure(error.message),
          ),
        ),
      get_improvement_backlog: ({ scanId }) =>
        store.getScan(scanId).pipe(
          Effect.flatMap(
            Option.match({
              onNone: () => Effect.fail(toolFailure(`Scan ${scanId} was not found.`)),
              onSome: scan =>
                listImprovementBacklog(scan).pipe(
                  Effect.mapError(error => toolFailure(error.message)),
                ),
            }),
          ),
          Effect.mapError(error =>
            error._tag === 'ToolFailure' ? error : toolFailure(error.message),
          ),
        ),
      get_prioritization_brief: ({ scanId }) =>
        store.getScan(scanId).pipe(
          Effect.flatMap(
            Option.match({
              onNone: () => Effect.fail(toolFailure(`Scan ${scanId} was not found.`)),
              onSome: scan =>
                buildPrioritizationBrief(scan).pipe(
                  Effect.mapError(error => toolFailure(error.message)),
                ),
            }),
          ),
          Effect.mapError(error =>
            error._tag === 'ToolFailure' ? error : toolFailure(error.message),
          ),
        ),
      get_finding_taskpack: ({ findingId, scanId }) =>
        store.getScan(scanId).pipe(
          Effect.flatMap(
            Option.match({
              onNone: () => Effect.fail(toolFailure(`Scan ${scanId} was not found.`)),
              onSome: scan =>
                buildFindingTaskpack(scan, findingId).pipe(
                  Effect.mapError(error => toolFailure(error.message)),
                ),
            }),
          ),
          Effect.mapError(error =>
            error._tag === 'ToolFailure' ? error : toolFailure(error.message),
          ),
        ),
    });
  }),
);

const currentOwner = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const store = yield* AgentStore;
  const candidate = request.cookies['radar_session'];
  const ownerId = yield* store.getOrCreateSession(candidate).pipe(
    Effect.mapError(error => new ApiFailure({ message: error.message })),
  );
  if (candidate !== ownerId) {
    const forwardedProtocol = request.headers['x-forwarded-proto']
      ?.split(',')[0]
      ?.trim();
    yield* HttpApiBuilder.securitySetCookie(SessionCookie, ownerId, {
      httpOnly: true,
      path: '/',
      sameSite: 'lax',
      secure: forwardedProtocol === 'https',
      maxAge: '365 days',
    });
  }
  return ownerId;
});

const agentPriorityUnavailableMessage =
  'Agent Priority is unavailable in this deployment.';

const agentPriorityUnavailable = () =>
  new CapabilityUnavailable({
    capability: 'agent-priority',
    message: agentPriorityUnavailableMessage,
  });

/** Converts an optional capability probe into an explicit public state. */
export const reportAgentPriorityCapability = <Failure, Requirements>(
  ready: Effect.Effect<void, Failure, Requirements>,
) =>
  ready.pipe(
    Effect.as(new AgentPriorityCapability({ status: 'ready' })),
    Effect.catch(() =>
      Effect.succeed(new AgentPriorityCapability({ status: 'unavailable' })),
    ),
  );

class AgentPriorityAvailability extends Context.Service<AgentPriorityAvailability, {
  readonly status: Effect.Effect<AgentPriorityCapability>;
  readonly require: Effect.Effect<void, CapabilityUnavailable>;
}>()('AgentPriorityAvailability') {}

const requireAgentPriority = AgentPriorityAvailability.use(availability =>
  availability.require,
);

const requiredAgentProfile = Effect.fn('requiredAgentProfile')(function* (
  ownerId: string,
  profileId: string,
) {
  yield* requireAgentPriority;
  const store = yield* AgentStore;
  return yield* store.getProfile(ownerId, profileId).pipe(
    Effect.mapError(error => new ApiFailure({ message: error.message })),
    Effect.flatMap(
      Option.match({
        onNone: () =>
          Effect.fail(new NotFound({ resource: 'provider profile', id: profileId })),
        onSome: Effect.succeed,
      }),
    ),
  );
});

/**
 * The HTTP boundary accepts only a credential-free public GitHub repository,
 * then lets the canonical source schema validate the stored identity.
 */
export const approvedGithubRepository = Effect.fn('approvedGithubRepository')(
  function* (input: string) {
    const trimmed = input.trim();
    const isGithubUrlInput = trimmed.includes('://');
    if (
      /[\u0000-\u001f\u007f]/u.test(input) ||
      trimmed.startsWith('/') ||
      trimmed.startsWith('\\\\') ||
      /^[A-Za-z]:[\\/]/u.test(trimmed) ||
      trimmed.includes('?') ||
      trimmed.includes('#') ||
      (isGithubUrlInput &&
        !/^https:\/\/github\.com(?:\/|$)/iu.test(trimmed))
    ) {
      return yield* new InvalidInput({
        message: 'Only credential-free public GitHub repositories are accepted.',
      });
    }
    const repository = yield* parseGithubRepository(trimmed).pipe(
      Effect.mapError(
        error => new InvalidInput({ message: error.message }),
      ),
    );
    if (isGithubUrlInput) {
      const pathname = yield* Effect.try({
        try: () => new URL(trimmed).pathname,
        catch: () =>
          new InvalidInput({
            message: 'Only credential-free public GitHub repositories are accepted.',
          }),
      });
      const repositoryPath = `/${repository.owner}/${repository.repository}`;
      if (
        pathname !== repositoryPath &&
        pathname !== `${repositoryPath}.git`
      ) {
        return yield* new InvalidInput({
          message: 'Only credential-free public GitHub repositories are accepted.',
        });
      }
    }
    const source = yield* decodeAnalysisSource({
      _tag: 'GitHubSource',
      owner: repository.owner,
      repository: repository.repository,
      revision: new DefaultBranchRevision({}),
    }).pipe(
      Effect.mapError(
        () =>
          new InvalidInput({
            message: 'Only credential-free public GitHub repositories are accepted.',
          }),
      ),
    );
    if (source._tag !== 'GitHubSource') {
      return yield* new InvalidInput({
        message: 'Only credential-free public GitHub repositories are accepted.',
      });
    }
    const owner = source.owner.toLowerCase();
    const name = source.repository.toLowerCase();
    return {
      owner,
      repository: name,
      url: `https://github.com/${owner}/${name}`,
    };
  },
);

class RuntimeReadiness extends Context.Service<RuntimeReadiness, {
  readonly check: Effect.Effect<void, ApiFailure>;
  readonly agentPriority: Effect.Effect<AgentPriorityCapability>;
}>()('RuntimeReadiness') {}

const RuntimeReadinessLive = Layer.effect(
  RuntimeReadiness,
  Effect.gen(function* () {
    const radarStore = yield* RadarStore;
    const agentStore = yield* AgentStore;
    const agentPriority = yield* AgentPriorityAvailability;
    const runtimePreflight = yield* RadarRuntimePreflight;
    const check = Effect.gen(function* () {
      yield* Effect.all([
        radarStore.ready,
        agentStore.ready,
      ]);
      yield* runtimePreflight.check().pipe(Effect.asVoid);
    }).pipe(
      Effect.mapError(error =>
        error instanceof ApiFailure
          ? error
          : new ApiFailure({
              message: 'A required Radar service is unavailable.',
          }),
      ),
    );
    return RuntimeReadiness.of({ check, agentPriority: agentPriority.status });
  }),
);

const RadarGroupLive = HttpApiBuilder.group(RadarApi, 'radar', handlers =>
  handlers
    .handle('health', () =>
      Effect.succeed(
        new HealthResponse({
          status: 'ok',
          service: 'codebase-radar',
          runtime: 'ultramodern-effect',
        }),
      ),
    )
    .handle('ready', () =>
      Effect.gen(function* () {
        const radarStore = yield* RadarStore;
        const readiness = yield* RuntimeReadiness;
        yield* readiness.check;
        const agentPriority = yield* readiness.agentPriority;
        return new ReadyResponse({
          status: 'ready',
          storage: radarStore.storage,
          agentPriority,
        });
      }),
    )
    .handle('getSession', () =>
      currentOwner.pipe(
        Effect.map(() => new BrowserSession({ status: 'ready' })),
      ),
    )
    .handle('listAgentProfiles', () =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const store = yield* AgentStore;
        const items = yield* store.listProfiles(ownerId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        return new AgentProfileList({ items });
      }),
    )
    .handle('createAgentProfile', ({ payload }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const store = yield* AgentStore;
        const profiles = yield* store.listProfiles(ownerId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        const existing = profiles.find(profile => profile.provider === payload.provider);
        if (existing) return existing;
        return yield* store.createProfile(ownerId, payload.provider).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('beginAgentLogin', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const profile = yield* requiredAgentProfile(ownerId, params.profileId);
        const runtime = yield* AgentRuntime;
        return yield* runtime.beginLogin(ownerId, profile).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('pollAgentLogin', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const runtime = yield* AgentRuntime;
        return yield* runtime.pollLogin(ownerId, params.challengeId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('submitAgentLoginInput', ({ params, payload }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const runtime = yield* AgentRuntime;
        return yield* runtime.submitLoginInput(
          ownerId,
          params.challengeId,
          payload.value,
        ).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('cancelAgentLogin', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const runtime = yield* AgentRuntime;
        yield* runtime.cancelLogin(ownerId, params.challengeId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('refreshAgentProfile', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const profile = yield* requiredAgentProfile(ownerId, params.profileId);
        const runtime = yield* AgentRuntime;
        return yield* runtime.refreshStatus(ownerId, profile).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('disconnectAgentProfile', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const profile = yield* requiredAgentProfile(ownerId, params.profileId);
        const runtime = yield* AgentRuntime;
        yield* runtime.disconnect(ownerId, profile).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('createPriorityReview', ({ params, payload }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const agentStore = yield* AgentStore;
        const radarStore = yield* RadarStore;
        const coordinator = yield* AgentCoordinator;
        const profile = yield* requiredAgentProfile(ownerId, payload.profileId);
        if (profile.state !== 'connected') {
          return yield* new InvalidInput({
            message: 'Sign in before requesting agent prioritization.',
          });
        }
        const scan = yield* radarStore.getScan(params.scanId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        if (Option.isNone(scan)) {
          return yield* new NotFound({ resource: 'scan', id: params.scanId });
        }
        const result = yield* listImprovementBacklog(scan.value).pipe(
          Effect.mapError(error => new InvalidInput({ message: error.message })),
        );
        if (result.scanId !== scan.value.id) {
          return yield* new ApiFailure({
            message: 'The completed scan record could not be verified.',
          });
        }
        const review = yield* agentStore.createReview(
          ownerId,
          profile.id,
          grantVisibleScanAccess(ownerId, result),
        ).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        yield* coordinator.enqueue(ownerId, review).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        return review;
      }),
    )
    .handle('getPriorityReview', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const store = yield* AgentStore;
        return yield* store.getReview(ownerId, params.reviewId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
          Effect.flatMap(
            Option.match({
              onNone: () =>
                Effect.fail(
                  new NotFound({ resource: 'priority review', id: params.reviewId }),
                ),
              onSome: Effect.succeed,
            }),
          ),
        );
      }),
    )
    .handle('cancelPriorityReview', ({ params }) =>
      Effect.gen(function* () {
        yield* requireAgentPriority;
        const ownerId = yield* currentOwner;
        const coordinator = yield* AgentCoordinator;
        yield* coordinator.cancel(ownerId, params.reviewId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('createProfile', ({ payload }) =>
      RadarStore.use(store =>
        store.createProfile({
          audience: payload.audience,
          ...(payload.displayName === undefined
            ? {}
            : { displayName: payload.displayName }),
        }).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        ),
      ),
    )
    .handle('createScan', ({ payload }) =>
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const coordinator = yield* ScanCoordinator;
        const repository = yield* approvedGithubRepository(payload.repository);
        const scan = yield* Effect.acquireUseRelease(
          coordinator.reserve(repository.owner, repository.repository).pipe(
            Effect.catchTags({
              RepositoryScanAlreadyActive: error =>
                Effect.fail(new InvalidInput({ message: error.message })),
              ScanCapacityUnavailable: error =>
                Effect.fail(new ApiFailure({ message: error.message })),
            }),
          ),
          admission =>
            persistAndAttachScan(
              store
                .createScan({
                  githubUrl: repository.url,
                  owner: repository.owner,
                  repository: repository.repository,
                  audience: payload.audience,
                })
                .pipe(
                  Effect.mapError(
                    error => new ApiFailure({ message: error.message }),
                  ),
                ),
              created =>
                admission.enqueue(created).pipe(
                  Effect.onError(() =>
                    store
                      .failScanIfActive(created.id, {
                        stage: 'Scan could not be queued',
                        error: 'The scan could not be attached to a worker. Submit a new scan.',
                      })
                      .pipe(Effect.ignore),
                  ),
                ),
            ).pipe(
              Effect.mapError(
                error => new ApiFailure({ message: error.message }),
              ),
            ),
          admission => admission.release,
        );
        return scan;
      }),
    )
    .handle('getScan', ({ params }) =>
      RadarStore.use(store =>
        store.getScan(params.scanId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
          Effect.flatMap(
            Option.match({
              onNone: () =>
                Effect.fail(
                  new NotFound({ resource: 'scan', id: params.scanId }),
                ),
              onSome: Effect.succeed,
            }),
          ),
        ),
      ),
    )
    .handle('listScans', ({ query }) =>
      RadarStore.use(store =>
        store.listRecentScans(query.limit).pipe(
          Effect.map(items => new ScanListResponse({ items })),
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        ),
      ),
    )
    .handle('listRepositories', ({ query }) =>
      RadarStore.use(store =>
        store.listRecentRepositories(query.limit).pipe(
          Effect.map(items => new ScanListResponse({ items })),
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        ),
      ),
    )
    .handle('listRepositoryScans', ({ params }) =>
      RadarStore.use(store =>
        store.listRepositoryScans(params.owner, params.repository).pipe(
          Effect.map(items => new ScanListResponse({ items })),
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        ),
      ),
    ),
);

const PlatformLive = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);
const StoresLive = Layer.merge(RadarStoreLive, AgentStoreLive).pipe(
  Layer.provideMerge(PlatformLive),
);
const unavailableProductionPath = (value: string | undefined) =>
  value !== undefined &&
    value !== '/' &&
    value.trim() === value &&
    value.startsWith('/') &&
    !/[\u0000-\u001f\u007f]/u.test(value)
    ? value
    : undefined;

/**
 * Accept only explicit host-owned roots. The core factory performs the
 * descriptor-relative metadata and trust-anchor verification; this boundary
 * deliberately supplies no inferred paths or analyzer-target fallback.
 */
export const productionRuntimeOptionsFromEnvironment = (environment: {
  readonly runtimeRoot: string | undefined;
  readonly workspaceParent: string | undefined;
  readonly resourceCgroupRoot: string | undefined;
  readonly analyzerControlRoot: string | undefined;
}) => {
  const runtimeRoot = unavailableProductionPath(environment.runtimeRoot);
  const workspaceParent = unavailableProductionPath(environment.workspaceParent);
  const resourceCgroupRoot = unavailableProductionPath(
    environment.resourceCgroupRoot,
  );
  const analyzerControlRoot = unavailableProductionPath(
    environment.analyzerControlRoot,
  );
  return runtimeRoot === undefined ||
    workspaceParent === undefined ||
    resourceCgroupRoot === undefined ||
    analyzerControlRoot === undefined ||
    analyzerControlRoot === runtimeRoot
    ? undefined
    : {
        runtimeRoot,
        workspaceParent,
        resourceCgroupRoot,
        analyzerControlRoot,
      } satisfies RadarProductionOptions;
};
const MissingProductionRuntimeLive = Layer.merge(
  Layer.succeed(RadarRuntimePreflight, makeUnavailableRadarRuntimePreflight()),
  RadarAnalysisLive(
    RadarAnalysis.of({
      analyze: () =>
        Effect.fail(
          new AnalysisRuntimeUnavailable({
            message: 'The verified analyzer runtime is unavailable.',
          }),
        ),
    }),
  ),
);
/**
 * Select the only production composition from explicit host configuration.
 * Missing or malformed values deliberately retain the canonical unavailable
 * preflight, so `/ready` cannot turn a partial configuration into readiness.
 */
export const productionRuntimeLayerFromEnvironment = (
  environment: Parameters<typeof productionRuntimeOptionsFromEnvironment>[0],
) => {
  const options = productionRuntimeOptionsFromEnvironment(environment);
  return options === undefined
    ? MissingProductionRuntimeLive
    : makeRadarProductionLayer(options);
};
const ProductionRuntimeLive = Layer.unwrap(
  Effect.all({
    runtimeRoot: Config.option(Config.string('RADAR_ANALYZER_ROOT')),
    workspaceParent: Config.option(Config.string('RADAR_WORKSPACE_PARENT')),
    resourceCgroupRoot: Config.option(Config.string('RADAR_ANALYSIS_CGROUP_ROOT')),
    analyzerControlRoot: Config.option(Config.string('RADAR_ANALYZER_CONTROL_ROOT')),
  }).pipe(
    Effect.map(config =>
      productionRuntimeLayerFromEnvironment({
        runtimeRoot: Option.getOrUndefined(config.runtimeRoot),
        workspaceParent: Option.getOrUndefined(config.workspaceParent),
        resourceCgroupRoot: Option.getOrUndefined(config.resourceCgroupRoot),
        analyzerControlRoot: Option.getOrUndefined(config.analyzerControlRoot),
      }),
    ),
  ),
);
const CoreRuntimeLive = ScanCoordinatorLive.pipe(
  Layer.provideMerge(ProductionRuntimeLive),
  Layer.provideMerge(StoresLive),
);
const VisibilityLive = AgentScanVisibilityGateLive.pipe(
  Layer.provide(PlatformLive),
);
const unavailableAgentRuntime = () => new AgentRuntimeError({
  message: agentPriorityUnavailableMessage,
});
const UnavailableAgentRuntimeLive = Layer.succeed(
  AgentRuntime,
  AgentRuntime.of({
    ready: Effect.fail(unavailableAgentRuntime()),
    beginLogin: () => Effect.fail(unavailableAgentRuntime()),
    pollLogin: () => Effect.fail(unavailableAgentRuntime()),
    submitLoginInput: () => Effect.fail(unavailableAgentRuntime()),
    cancelLogin: () => Effect.fail(unavailableAgentRuntime()),
    refreshStatus: () => Effect.fail(unavailableAgentRuntime()),
    disconnect: () => Effect.fail(unavailableAgentRuntime()),
    prioritizeChunk: () => Effect.fail(unavailableAgentRuntime()),
    prioritizeMerge: () => Effect.fail(unavailableAgentRuntime()),
  }),
);
const UnavailableAgentVisibilityLive = Layer.succeed(
  AgentScanVisibilityGate,
  AgentScanVisibilityGate.of({
    verify: () =>
      Effect.fail(new AgentVisibilityRejected({ code: 'scan-access-revoked' })),
  }),
);
const unavailableAgentCoordinator = () => new AgentCoordinatorError({
  message: agentPriorityUnavailableMessage,
});
const UnavailableAgentCoordinatorLive = Layer.succeed(
  AgentCoordinator,
  AgentCoordinator.of({
    enqueue: () => Effect.fail(unavailableAgentCoordinator()),
    cancel: () => Effect.fail(unavailableAgentCoordinator()),
  }),
);
const UnavailableAgentPriorityAvailabilityLive = Layer.succeed(
  AgentPriorityAvailability,
  AgentPriorityAvailability.of({
    status: Effect.succeed(new AgentPriorityCapability({ status: 'unavailable' })),
    require: Effect.fail(agentPriorityUnavailable()),
  }),
);
const UnavailableAgentFeatureLive = Layer.mergeAll(
  UnavailableAgentRuntimeLive,
  UnavailableAgentVisibilityLive,
  UnavailableAgentCoordinatorLive,
  UnavailableAgentPriorityAvailabilityLive,
);
const ActiveAgentPriorityAvailabilityLive = Layer.effect(
  AgentPriorityAvailability,
  Effect.gen(function* () {
    const store = yield* AgentStore;
    const runtime = yield* AgentRuntime;
    const ready = Effect.all([store.ready, runtime.ready]).pipe(Effect.asVoid);
    // Construct the coordinator only after its provider runtime is attested.
    // A failure selects the fail-closed optional feature bundle below.
    yield* ready;
    const status = reportAgentPriorityCapability(ready);
    return AgentPriorityAvailability.of({
      status,
      require: status.pipe(
        Effect.flatMap(capability =>
          capability.status === 'ready'
            ? Effect.void
            : Effect.fail(agentPriorityUnavailable()),
        ),
      ),
    });
  }),
);
const AgentRuntimeAndVisibilityLive = Layer.merge(
  AgentRuntimeLive,
  VisibilityLive,
);
const VerifiedAgentPriorityLive = ActiveAgentPriorityAvailabilityLive.pipe(
  Layer.provideMerge(AgentRuntimeAndVisibilityLive),
);
const ActiveAgentFeatureLive = AgentCoordinatorLive.pipe(
  Layer.provideMerge(VerifiedAgentPriorityLive),
);
const AgentFeatureLive = ActiveAgentFeatureLive.pipe(
  Layer.catchCause(() => UnavailableAgentFeatureLive),
);
const ServicesLive = RuntimeReadinessLive.pipe(
  Layer.provideMerge(AgentFeatureLive),
  Layer.provideMerge(CoreRuntimeLive),
);
const canonicalConfiguredOrigin = (value: string): string | undefined => {
  try {
    const parsed = new URL(value);
    return value.trim() === value &&
      !value.includes('?') &&
      !value.includes('#') &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.pathname === '/' &&
      parsed.search === '' &&
      parsed.hash === ''
      ? parsed.origin
      : undefined;
  } catch {
    return undefined;
  }
};

export const isMcpRequestPath = (requestUrl: string) => {
  try {
    return new URL(requestUrl, 'https://radar.invalid').pathname === '/mcp';
  } catch {
    return false;
  }
};

export const isMcpOriginAllowed = (
  requestUrl: string,
  requestOrigin: string | undefined,
  configuredOrigin: string | undefined,
) => {
  if (!isMcpRequestPath(requestUrl)) return true;
  if (requestOrigin === undefined || configuredOrigin === undefined) return false;
  const expectedOrigin = canonicalConfiguredOrigin(configuredOrigin);
  return expectedOrigin !== undefined && requestOrigin === expectedOrigin;
};

const McpOriginGuardLive = HttpRouter.middleware(
  Effect.gen(function* () {
    const configuredOrigin = yield* Config.option(Config.string('RADAR_PUBLIC_ORIGIN'));
    return httpEffect =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const origin = request.headers['origin'];
        const expectedOrigin = Option.getOrUndefined(configuredOrigin);
        if (!isMcpOriginAllowed(request.url, origin, expectedOrigin)) {
          return HttpServerResponse.empty({ status: 403 });
        }
        return yield* httpEffect;
      });
  }),
  { global: true },
);
const McpToolsLive = Layer.effectDiscard(
  McpServer.registerToolkit(RadarToolkit),
).pipe(Layer.provide(ToolHandlersLive));
const McpRoutesLive = Layer.merge(McpToolsLive, McpOriginGuardLive).pipe(
  Layer.provide(
    McpServer.layerHttp({
      name: 'codebase-radar',
      version: '0.1.0',
      path: '/mcp',
    }),
  ),
);
const layer = Layer.mergeAll(
  HttpApiBuilder.layer(RadarApi).pipe(Layer.provide(RadarGroupLive)),
  McpRoutesLive,
).pipe(
  Layer.provide(ServicesLive),
  Layer.orDie,
) satisfies EffectRuntimeLayer;

const runtime: EffectBffDefinition<typeof RadarApi, EffectRuntimeLayer> &
  EffectBffRuntime<typeof RadarApi, EffectRuntimeLayer> = defineEffectBff({
  api: RadarApi,
  layer,
});

export default runtime;
