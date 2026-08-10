import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Config, Context, FileSystem, Path } from 'effect';
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
  ApiFailure,
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
  AgentCoordinatorLive,
} from '../server/agent-coordinator';
import { AgentRuntime, AgentRuntimeLive } from '../server/agent-runtime';
import { AgentStore, AgentStoreLive } from '../server/agent-store';
import {
  persistAndAttachScan,
  ScanCoordinator,
  ScanCoordinatorLive,
} from '../server/scan-runner';
import { prioritizationBrief } from '../server/prioritization-brief';
import { analyzerRoot } from '../server/analyzers';
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
                scan.result
                  ? Effect.succeed(scan.result)
                  : Effect.fail(
                      toolFailure(`Scan ${scanId} has no completed backlog yet.`),
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
                scan.result
                  ? Effect.succeed(prioritizationBrief(scan)).pipe(
                      Effect.filterOrFail(
                        brief => brief !== undefined,
                        () => toolFailure(`Scan ${scanId} has no completed backlog yet.`),
                      ),
                    )
                  : Effect.fail(toolFailure(`Scan ${scanId} has no completed backlog yet.`)),
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
              onSome: scan => {
                const finding = scan.result?.findings.find(item => item.id === findingId);
                if (!scan.result || !finding) {
                  return Effect.fail(
                    toolFailure(`Finding ${findingId} was not found in scan ${scanId}.`),
                  );
                }
                return Effect.succeed(
                  new FindingTaskpack({
                    schemaVersion: 'codebase-radar.taskpack/v1',
                    scanId,
                    repository: scan.result.repository,
                    finding,
                    objective: finding.recommendation,
                    acceptanceCriteria: [
                      `Address the evidence represented by ${finding.fingerprint}.`,
                      'Preserve or improve existing behavior and attributed test coverage.',
                      'Run focused verification and report before/after evidence.',
                    ],
                    guardrails: [
                      'Inference and advisory links provide context; they do not verify runtime impact.',
                      'Inspect callers, blast radius, and affected tests before editing.',
                      'Do not broaden the change beyond this finding without maintainer approval.',
                    ],
                    suggestedInvestigation: [
                      ...finding.evidence.map(evidence =>
                        evidence.path
                          ? `${evidence.path}${evidence.line ? `:${evidence.line}` : ''} — ${evidence.message}`
                          : evidence.message,
                      ),
                    ],
                  }),
                );
              },
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

const requiredAgentProfile = Effect.fn('requiredAgentProfile')(function* (
  ownerId: string,
  profileId: string,
) {
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

class RuntimeReadiness extends Context.Service<RuntimeReadiness, {
  readonly check: Effect.Effect<void, ApiFailure>;
}>()('RuntimeReadiness') {}

const RuntimeReadinessLive = Layer.effect(
  RuntimeReadiness,
  Effect.gen(function* () {
    const radarStore = yield* RadarStore;
    const agentStore = yield* AgentStore;
    const agentRuntime = yield* AgentRuntime;
    const fs = yield* FileSystem.FileSystem;
    const pathService = yield* Path.Path;
    const root = yield* analyzerRoot();
    const essentials = [
      'calldiff-analyzer.mjs',
      'node_modules/.bin/calldiff',
      'node_modules/.bin/oxlint',
      'node_modules/.bin/jscpd',
      'bin/tracedecay',
      'bin/zizmor',
      'bin/osv-scanner',
      'config/jscpd.json',
    ];
    const check = Effect.gen(function* () {
      yield* Effect.all([
        radarStore.ready,
        agentStore.ready,
        agentRuntime.ready,
      ]);
      for (const relative of essentials) {
        const available = yield* fs.exists(pathService.resolve(root, relative));
        if (!available) {
          return yield* new ApiFailure({
            message: `Analyzer runtime is missing ${relative}.`,
          });
        }
      }
    }).pipe(
      Effect.mapError(error =>
        error instanceof ApiFailure
          ? error
          : new ApiFailure({
              message: error instanceof Error ? error.message : String(error),
            }),
      ),
    );
    const cached = yield* Effect.cachedWithTTL(check, '30 seconds');
    return RuntimeReadiness.of({ check: cached });
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
        return new ReadyResponse({
          status: 'ready',
          storage: radarStore.storage,
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
        const ownerId = yield* currentOwner;
        const runtime = yield* AgentRuntime;
        return yield* runtime.pollLogin(ownerId, params.challengeId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('submitAgentLoginInput', ({ params, payload }) =>
      Effect.gen(function* () {
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
        const ownerId = yield* currentOwner;
        const runtime = yield* AgentRuntime;
        yield* runtime.cancelLogin(ownerId, params.challengeId).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
      }),
    )
    .handle('refreshAgentProfile', ({ params }) =>
      Effect.gen(function* () {
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
        if (!scan.value.result) {
          return yield* new InvalidInput({
            message: 'The codebase review is not ready yet.',
          });
        }
        const review = yield* agentStore.createReview(
          ownerId,
          profile.id,
          scan.value.id,
        ).pipe(
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        );
        yield* coordinator.enqueue(ownerId, review);
        return review;
      }),
    )
    .handle('getPriorityReview', ({ params }) =>
      Effect.gen(function* () {
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
        const repository = yield* parseGithubRepository(payload.repository).pipe(
          Effect.mapError(error => new InvalidInput({ message: error.message })),
        );
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
const RuntimeLive = Layer.merge(ScanCoordinatorLive, AgentRuntimeLive).pipe(
  Layer.provideMerge(StoresLive),
);
const ServicesLive = Layer.merge(AgentCoordinatorLive, RuntimeReadinessLive).pipe(
  Layer.provideMerge(RuntimeLive),
);
const McpOriginGuardLive = HttpRouter.middleware(
  Effect.gen(function* () {
    const configuredOrigin = yield* Config.option(Config.string('RADAR_PUBLIC_ORIGIN'));
    return httpEffect =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const origin = request.headers['origin'];
        if (request.url === '/mcp' && origin) {
          const forwardedProtocol = request.headers['x-forwarded-proto']
            ?.split(',')[0]
            ?.trim();
          const expectedOrigin = Option.getOrElse(
            configuredOrigin,
            () => `${forwardedProtocol || 'http'}://${request.headers['host'] || ''}`,
          );
          if (origin !== expectedOrigin) {
            return HttpServerResponse.empty({ status: 403 });
          }
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
