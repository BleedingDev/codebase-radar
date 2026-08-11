import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiSchema,
  Schema,
} from '@modern-js/plugin-bff/effect-client';
import { HttpApiSecurity } from 'effect/unstable/httpapi';
import {
  AgentLoginChallenge,
  AgentPriorityReview,
  AgentProfile,
  AgentProfileList,
  AgentProvider,
  Audience,
  AudienceProfile,
  BrowserSession,
  ScanRecord,
} from './domain';

export const SessionCookie = HttpApiSecurity.apiKey({
  key: 'radar_session',
  in: 'cookie',
});

export class ApiFailure extends Schema.TaggedErrorClass<ApiFailure>()(
  'ApiFailure',
  {
    message: Schema.String,
  },
) {}

/** A deliberately disabled optional product capability, never a core outage. */
export class CapabilityUnavailable extends Schema.TaggedErrorClass<CapabilityUnavailable>()(
  'CapabilityUnavailable',
  {
    capability: Schema.Literal('agent-priority'),
    message: Schema.String,
  },
) {}

export class InvalidInput extends Schema.TaggedErrorClass<InvalidInput>()(
  'InvalidInput',
  {
    message: Schema.String,
  },
) {}

export class NotFound extends Schema.TaggedErrorClass<NotFound>()('NotFound', {
  resource: Schema.String,
  id: Schema.String,
}) {}

export class HealthResponse extends Schema.Class<HealthResponse>('HealthResponse')({
  status: Schema.Literal('ok'),
  service: Schema.Literal('codebase-radar'),
  runtime: Schema.Literal('ultramodern-effect'),
}) {}

export const AgentPriorityCapabilityStatus = Schema.Literals([
  'ready',
  'unavailable',
]);

/** Always present so a core-ready deployment cannot hide Agent Priority state. */
export class AgentPriorityCapability extends Schema.Class<AgentPriorityCapability>(
  'AgentPriorityCapability',
)({
  status: AgentPriorityCapabilityStatus,
}) {}

export class ReadyResponse extends Schema.Class<ReadyResponse>('ReadyResponse')({
  status: Schema.Literal('ready'),
  storage: Schema.Literals(['memory', 'postgres']),
  agentPriority: AgentPriorityCapability,
}) {}

export class ScanListResponse extends Schema.Class<ScanListResponse>(
  'ScanListResponse',
)({
  items: Schema.Array(ScanRecord),
}) {}

const ApiFailureHttp = ApiFailure.pipe(HttpApiSchema.status(500));
const CapabilityUnavailableHttp = CapabilityUnavailable.pipe(HttpApiSchema.status(503));
const InvalidInputHttp = InvalidInput.pipe(HttpApiSchema.status(400));
const NotFoundHttp = NotFound.pipe(HttpApiSchema.status(404));

export const RadarApi = HttpApi.make('RadarApi').add(
  HttpApiGroup.make('radar')
    .add(
      HttpApiEndpoint.get('health', '/health', {
        success: HealthResponse,
      }),
    )
    .add(
      HttpApiEndpoint.get('ready', '/ready', {
        error: ApiFailureHttp,
        success: ReadyResponse,
      }),
    )
    .add(
      HttpApiEndpoint.get('getSession', '/session', {
        error: ApiFailureHttp,
        success: BrowserSession,
      }),
    )
    .add(
      HttpApiEndpoint.get('listAgentProfiles', '/agent-profiles', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        success: AgentProfileList,
      }),
    )
    .add(
      HttpApiEndpoint.post('createAgentProfile', '/agent-profiles', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        payload: Schema.Struct({ provider: AgentProvider }),
        success: AgentProfile,
      }),
    )
    .add(
      HttpApiEndpoint.post('beginAgentLogin', '/agent-profiles/:profileId/login', {
        error: Schema.Union([
          NotFoundHttp,
          ApiFailureHttp,
          CapabilityUnavailableHttp,
        ]),
        params: { profileId: Schema.String },
        success: AgentLoginChallenge,
      }),
    )
    .add(
      HttpApiEndpoint.get('pollAgentLogin', '/agent-logins/:challengeId', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        params: { challengeId: Schema.String },
        success: AgentLoginChallenge,
      }),
    )
    .add(
      HttpApiEndpoint.post('submitAgentLoginInput', '/agent-logins/:challengeId/input', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        params: { challengeId: Schema.String },
        payload: Schema.Struct({ value: Schema.String }),
        success: AgentLoginChallenge,
      }),
    )
    .add(
      HttpApiEndpoint.delete('cancelAgentLogin', '/agent-logins/:challengeId', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        params: { challengeId: Schema.String },
        success: Schema.Void,
      }),
    )
    .add(
      HttpApiEndpoint.post('refreshAgentProfile', '/agent-profiles/:profileId/status', {
        error: Schema.Union([
          NotFoundHttp,
          ApiFailureHttp,
          CapabilityUnavailableHttp,
        ]),
        params: { profileId: Schema.String },
        success: AgentProfile,
      }),
    )
    .add(
      HttpApiEndpoint.delete('disconnectAgentProfile', '/agent-profiles/:profileId', {
        error: Schema.Union([
          NotFoundHttp,
          ApiFailureHttp,
          CapabilityUnavailableHttp,
        ]),
        params: { profileId: Schema.String },
        success: Schema.Void,
      }),
    )
    .add(
      HttpApiEndpoint.post('createPriorityReview', '/scans/:scanId/priority-reviews', {
        error: Schema.Union([
          InvalidInputHttp,
          NotFoundHttp,
          ApiFailureHttp,
          CapabilityUnavailableHttp,
        ]),
        params: { scanId: Schema.String },
        payload: Schema.Struct({ profileId: Schema.String }),
        success: AgentPriorityReview,
      }),
    )
    .add(
      HttpApiEndpoint.get('getPriorityReview', '/priority-reviews/:reviewId', {
        error: Schema.Union([
          NotFoundHttp,
          ApiFailureHttp,
          CapabilityUnavailableHttp,
        ]),
        params: { reviewId: Schema.String },
        success: AgentPriorityReview,
      }),
    )
    .add(
      HttpApiEndpoint.delete('cancelPriorityReview', '/priority-reviews/:reviewId', {
        error: Schema.Union([ApiFailureHttp, CapabilityUnavailableHttp]),
        params: { reviewId: Schema.String },
        success: Schema.Void,
      }),
    )
    .add(
      HttpApiEndpoint.post('createProfile', '/profiles', {
        error: ApiFailureHttp,
        payload: Schema.Struct({
          audience: Audience,
          displayName: Schema.optional(Schema.String),
        }),
        success: AudienceProfile,
      }),
    )
    .add(
      HttpApiEndpoint.post('createScan', '/scans', {
        error: Schema.Union([InvalidInputHttp, ApiFailureHttp]),
        payload: Schema.Struct({
          repository: Schema.String,
          audience: Audience,
        }),
        success: ScanRecord,
      }),
    )
    .add(
      HttpApiEndpoint.get('getScan', '/scans/:scanId', {
        error: Schema.Union([NotFoundHttp, ApiFailureHttp]),
        params: { scanId: Schema.String },
        success: ScanRecord,
      }),
    )
    .add(
      HttpApiEndpoint.get('listScans', '/scans', {
        error: ApiFailureHttp,
        query: { limit: Schema.optional(Schema.FiniteFromString) },
        success: ScanListResponse,
      }),
    )
    .add(
      HttpApiEndpoint.get('listRepositories', '/repositories', {
        error: ApiFailureHttp,
        query: { limit: Schema.optional(Schema.FiniteFromString) },
        success: ScanListResponse,
      }),
    )
    .add(
      HttpApiEndpoint.get(
        'listRepositoryScans',
        '/repositories/:owner/:repository/scans',
        {
          error: ApiFailureHttp,
          params: {
            owner: Schema.String,
            repository: Schema.String,
          },
          success: ScanListResponse,
        },
      ),
    ),
);
