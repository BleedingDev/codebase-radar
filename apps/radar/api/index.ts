import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Config } from 'effect';
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
} from '../shared/api';
import { parseGithubRepository } from '../shared/contracts';
import {
  Audience,
  FindingTaskpack,
  ScanRecord,
  ScanResult,
} from '../shared/domain';
import { ScanCoordinator, ScanCoordinatorLive } from '../server/scan-runner';
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
    'Return the single ranked evidence-backed backlog for a completed scan. Audience affects communication, never ranking or evidence.',
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

const RadarToolkit = Toolkit.make(
  ListScans,
  GetScan,
  GetImprovementBacklog,
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
      RadarStore.use(store =>
        store.ready.pipe(
          Effect.map(
            () => new ReadyResponse({ status: 'ready', storage: store.storage }),
          ),
          Effect.mapError(error => new ApiFailure({ message: error.message })),
        ),
      ),
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
        const repository = yield* parseGithubRepository(payload.githubUrl).pipe(
          Effect.mapError(error => new InvalidInput({ message: error.message })),
        );
        const scan = yield* store
          .createScan({
            githubUrl: repository.url,
            owner: repository.owner,
            repository: repository.repository,
            audience: payload.audience,
          })
          .pipe(
            Effect.mapError(error => new ApiFailure({ message: error.message })),
          );
        yield* coordinator.enqueue(scan);
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
    ),
);

const PlatformLive = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);
const ServicesLive = ScanCoordinatorLive.pipe(
  Layer.provideMerge(RadarStoreLive),
  Layer.provideMerge(PlatformLive),
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
