import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiSchema,
  Schema,
} from '@modern-js/plugin-bff/effect-client';
import { Audience, AudienceProfile, ScanRecord } from './domain';

export class ApiFailure extends Schema.TaggedErrorClass<ApiFailure>()(
  'ApiFailure',
  {
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

export class ReadyResponse extends Schema.Class<ReadyResponse>('ReadyResponse')({
  status: Schema.Literal('ready'),
  storage: Schema.Literals(['memory', 'postgres']),
}) {}

export class ScanListResponse extends Schema.Class<ScanListResponse>(
  'ScanListResponse',
)({
  items: Schema.Array(ScanRecord),
}) {}

const ApiFailureHttp = ApiFailure.pipe(HttpApiSchema.status(500));
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
          githubUrl: Schema.String,
          audience: Audience,
          profileId: Schema.optional(Schema.String),
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
    ),
);
