import {
  Config,
  Context,
  Effect,
  Layer,
  Option,
  Redacted,
  Ref,
  Schema,
  Stream,
} from 'effect';
import { HttpClient, HttpClientResponse } from 'effect/unstable/http';
import {
  makeScanAccessVisibilityAttestation,
  publicGitHubVisibilityPolicyVersion,
  ScanAccessGrant,
} from './agent-store';

export class AgentVisibilityRejected extends Schema.TaggedErrorClass<AgentVisibilityRejected>()(
  'AgentVisibilityRejected',
  {
    code: Schema.Literal('scan-access-revoked'),
  },
) {}

export class AgentScanVisibilityGate extends Context.Service<AgentScanVisibilityGate, {
  readonly verify: (
    grant: ScanAccessGrant,
  ) => Effect.Effect<void, AgentVisibilityRejected>;
}>()('AgentScanVisibilityGate') {}

const MaximumVisibilityResponseBytes = 256 * 1024;
const VisibilityRequestTimeout = '10 seconds';
export const visibilityAttestationCacheTtlMs = 30_000;
export const maximumVisibilityAttestationCacheEntries = 128;
const GitHubVisibilityResponse = Schema.Struct({
  private: Schema.Boolean,
  full_name: Schema.String,
});

interface BodyAccumulator {
  readonly chunks: ReadonlyArray<Uint8Array>;
  readonly byteLength: number;
}

interface CachedVisibilityAttestation {
  readonly expiresAt: number;
  readonly etag?: string;
}

const rejected = () => new AgentVisibilityRejected({
  code: 'scan-access-revoked',
});

export const visibilityAttestationCacheKey = (grant: ScanAccessGrant) => JSON.stringify({
  policyVersion: grant.visibilityPolicyVersion,
  attestation: grant.visibilityAttestation,
  source: grant.source,
  canonicalResultDigest: grant.canonicalResultDigest,
  findingInventoryDigest: grant.findingInventoryDigest,
});

const boundedEtag = (value: string | undefined) =>
  value !== undefined && value.length > 0 && value.length <= 512
    ? value
    : undefined;

const boundedResponseText = (
  response: HttpClientResponse.HttpClientResponse,
): Effect.Effect<string, AgentVisibilityRejected> => response.stream.pipe(
  Stream.runFoldEffect(
    (): BodyAccumulator => ({ chunks: [], byteLength: 0 }),
    (state, chunk) => {
      const byteLength = state.byteLength + chunk.byteLength;
      return Number.isSafeInteger(byteLength) &&
        byteLength <= MaximumVisibilityResponseBytes
        ? Effect.succeed({ chunks: [...state.chunks, chunk], byteLength })
        : Effect.fail(rejected());
    },
  ),
  Effect.flatMap(state => Effect.try({
    try: () => {
      const bytes = new Uint8Array(state.byteLength);
      let offset = 0;
      for (const chunk of state.chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    },
    catch: rejected,
  })),
  Effect.mapError(rejected),
);

export const verifyVisibilityRemotely = (
  client: HttpClient.HttpClient,
  token: string,
  grant: ScanAccessGrant,
  cached: CachedVisibilityAttestation | undefined,
): Effect.Effect<CachedVisibilityAttestation, AgentVisibilityRejected> => {
  const source = grant.source;
  if (
    source._tag !== 'GitHubSourceIdentity' ||
    grant.visibilityPolicyVersion !== publicGitHubVisibilityPolicyVersion
  ) {
    return Effect.fail(rejected());
  }
  const expectedAttestation = makeScanAccessVisibilityAttestation(
    grant.visibilityPolicyVersion,
    grant.source,
    grant.canonicalResultDigest,
    grant.findingInventoryDigest,
  );
  if (expectedAttestation.attestation !== grant.visibilityAttestation) {
    return Effect.fail(rejected());
  }
  const expectedFullName = `${source.owner}/${source.repository}`.toLocaleLowerCase('en-US');
  const url = `https://api.github.com/repos/${encodeURIComponent(source.owner)}/${encodeURIComponent(source.repository)}`;
  const program = client.get(url, {
    accept: 'application/vnd.github+json',
    headers: {
      authorization: `Bearer ${token}`,
      'user-agent': 'codebase-radar/0.1',
      'x-github-api-version': '2022-11-28',
      ...(cached?.etag === undefined ? {} : { 'if-none-match': cached.etag }),
    },
  }).pipe(
    Effect.mapError(rejected),
    Effect.flatMap(httpResponse => {
      if (httpResponse.status === 304 && cached !== undefined) {
        return Effect.succeed({
          expiresAt: Date.now() + visibilityAttestationCacheTtlMs,
          ...(cached.etag === undefined ? {} : { etag: cached.etag }),
        } satisfies CachedVisibilityAttestation);
      }
      const contentType = httpResponse.headers['content-type'] ?? '';
      const etag = boundedEtag(httpResponse.headers['etag']);
      return httpResponse.status === 200 &&
        /^(?:application\/json|application\/vnd\.github\+json)(?:;|$)/iu.test(contentType)
        ? boundedResponseText(httpResponse).pipe(
            Effect.flatMap(text => Schema.decodeUnknownEffect(
              Schema.fromJsonString(GitHubVisibilityResponse),
            )(text).pipe(Effect.mapError(rejected))),
            Effect.flatMap(decodedBody =>
              !decodedBody.private &&
              decodedBody.full_name.toLocaleLowerCase('en-US') === expectedFullName
                  ? Effect.succeed({
                    expiresAt: Date.now() + visibilityAttestationCacheTtlMs,
                    ...(etag === undefined
                      ? {}
                      : { etag }),
                  } satisfies CachedVisibilityAttestation)
                : Effect.fail(rejected()),
            ),
          )
        : Effect.fail(rejected());
    }),
  );
  return program.pipe(
    Effect.timeoutOption(VisibilityRequestTimeout),
    Effect.flatMap(Option.match({
      onNone: () => Effect.fail(rejected()),
      onSome: Effect.succeed,
    })),
  );
};

export const AgentScanVisibilityGateLive = Layer.effect(
  AgentScanVisibilityGate,
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const configuredToken = yield* Config.redacted('RADAR_GITHUB_VISIBILITY_TOKEN');
    const token = Redacted.value(configuredToken).trim();
    if (token.length === 0) return yield* rejected();
    const cache = yield* Ref.make<ReadonlyMap<string, CachedVisibilityAttestation>>(new Map());
    return AgentScanVisibilityGate.of({
      verify: grant =>
        Effect.gen(function* () {
          const source = grant.source;
          const expectedAttestation = makeScanAccessVisibilityAttestation(
            grant.visibilityPolicyVersion,
            grant.source,
            grant.canonicalResultDigest,
            grant.findingInventoryDigest,
          );
          if (
            source._tag !== 'GitHubSourceIdentity' ||
            grant.visibilityPolicyVersion !== publicGitHubVisibilityPolicyVersion ||
            expectedAttestation.attestation !== grant.visibilityAttestation
          ) {
            return yield* rejected();
          }
          const key = visibilityAttestationCacheKey(grant);
          const currentTime = Date.now();
          const cached = (yield* Ref.get(cache)).get(key);
          if (cached !== undefined && cached.expiresAt > currentTime) return;
          const attestation = yield* verifyVisibilityRemotely(client, token, grant, cached);
          yield* Ref.update(cache, current => {
            const next = new Map(
              [...current].filter(([, value]) => value.expiresAt > currentTime),
            );
            next.set(key, attestation);
            while (next.size > maximumVisibilityAttestationCacheEntries) {
              const oldest = next.keys().next().value;
              if (oldest === undefined) break;
              next.delete(oldest);
            }
            return next;
          });
        }),
    });
  }),
);
