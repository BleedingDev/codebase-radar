import { Effect, Layer, Option, Schema } from 'effect';
import type { GitHubSource } from '@codebase-radar/contracts/source';
import {
  type DescriptorFileWriter,
  type DescriptorStagingOperations,
  WorkspaceRelativePath,
} from '../workspace.js';
import {
  GitHubCodeloadArchiveError,
  GitHubCodeloadArchiveReceipt,
  GitHubCodeloadArchiveRequest,
  GitHubCodeloadArchiveTransport,
  GitHubRevisionResolution,
  GitHubRevisionResolver,
  GitHubRevisionResolverError,
  type SourceMaterializationLimits,
} from './ports.js';

const apiJsonContentTypes = new Set(['application/json', 'application/vnd.github+json']);
const gzipContentTypes = new Set(['application/gzip', 'application/x-gzip']);
const apiProductionOrigin = 'https://api.github.com';
const codeloadProductionOrigin = 'https://codeload.github.com';
const utf8 = new TextEncoder();
const maximumArchivePathBytes = 1_024;
const maximumArchivePathSegmentBytes = 255;
const maximumArchiveDepth = 32;
const maximumTagDereferenceDepth = 8;
const tarBlockBytes = 512;
const tarChecksumOffset = 148;
const tarChecksumLength = 8;
const tarTypeOffset = 156;
const tarNameLength = 100;
const tarSizeOffset = 124;
const tarSizeLength = 12;
const tarPrefixOffset = 345;
const tarPrefixLength = 155;
const symbolicGitReferences = new Set([
  'head',
  'fetch_head',
  'orig_head',
  'merge_head',
  'cherry_pick_head',
  'revert_head',
  'bisect_head',
  'auto_merge',
]);

type ArchiveFailureCode = typeof GitHubCodeloadArchiveError.Type['code'];
type ResolverFailureCode = typeof GitHubRevisionResolverError.Type['code'];

interface FixedOrigin {
  readonly url: URL;
  readonly value: string;
}

interface FixedOrigins {
  readonly api: FixedOrigin;
  readonly codeload: FixedOrigin;
}

interface CanonicalRepository {
  readonly owner: string;
  readonly repository: string;
}

export interface NodeGitHubSourceTransportOptions {
  /** Defaults to the production api.github.com origin. Test-only callers may opt into local HTTP. */
  readonly apiOrigin?: string;
  /** Defaults to the production codeload.github.com origin. Test-only callers may opt into local HTTP. */
  readonly codeloadOrigin?: string;
  /** This must never be enabled by production composition. */
  readonly allowInsecureTestOrigins?: boolean;
}

export interface GitHubSourceTransportServices {
  readonly resolver: ReturnType<typeof GitHubRevisionResolver.of>;
  readonly archives: ReturnType<typeof GitHubCodeloadArchiveTransport.of>;
}

/** Invalid endpoint configuration is deliberately path-free and credential-free. */
export class GitHubSourceTransportConfigurationError extends Schema.TaggedErrorClass<GitHubSourceTransportConfigurationError>()(
  'GitHubSourceTransportConfigurationError',
  { reason: Schema.Literal('invalid-origin') },
) {}

const archiveError = (code: ArchiveFailureCode): GitHubCodeloadArchiveError =>
  new GitHubCodeloadArchiveError({ operation: 'stage', code });

const resolverError = (code: ResolverFailureCode): GitHubRevisionResolverError =>
  new GitHubRevisionResolverError({ operation: 'resolve', code });

const isCompleteSha = (value: string): boolean => /^[0-9a-f]{40}$/u.test(value);

const isCanonicalOwner = (value: string): boolean =>
  value.length >= 1 &&
  value.length <= 39 &&
  !value.includes('--') &&
  /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(value);

const isCanonicalRepository = (value: string): boolean =>
  value.length >= 1 &&
  value.length <= 100 &&
  value !== '.' &&
  value !== '..' &&
  !value.toLowerCase().endsWith('.git') &&
  /^[A-Za-z0-9_.-]+$/u.test(value);

const isSafeReference = (value: string): boolean => {
  const segments = value.split('/');
  return value.length > 0 &&
    value !== '@' &&
    !symbolicGitReferences.has(value.toLowerCase()) &&
    !value.startsWith('-') &&
    !value.startsWith('/') &&
    !value.endsWith('/') &&
    !value.endsWith('.') &&
    !value.includes('..') &&
    !value.includes('//') &&
    !value.includes('@{') &&
    !/[\u0000-\u0020\u007f~^:?*[\\]/u.test(value) &&
    !segments.some(segment => segment.startsWith('.') || segment.endsWith('.lock'));
};

const contentType = (response: Response): string | undefined => {
  const raw = response.headers.get('content-type');
  if (raw === null) return undefined;
  const value = raw.split(';', 1).at(0)?.trim().toLowerCase();
  return value === '' || value === undefined ? undefined : value;
};

const validContentLength = (response: Response, maximumBytes: number): boolean => {
  const raw = response.headers.get('content-length');
  if (raw === null) return true;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(raw)) return false;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed <= maximumBytes;
};

const isExactOriginInput = (value: string, origin: string): boolean =>
  value === origin || value === `${origin}/`;

const isLoopbackHostname = (hostname: string): boolean =>
  hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';

const fixedOrigin = (
  value: string,
  productionOrigin: string,
  allowInsecureTestOrigins: boolean,
): Effect.Effect<FixedOrigin, GitHubSourceTransportConfigurationError> =>
  Effect.try({
    try: () => new URL(value),
    catch: () => new GitHubSourceTransportConfigurationError({ reason: 'invalid-origin' }),
  }).pipe(
    Effect.flatMap(url => {
      const credentialsFreeRoot = url.username === '' &&
        url.password === '' &&
        url.pathname === '/' &&
        url.search === '' &&
        url.hash === '';
      const production = url.protocol === 'https:' &&
        url.origin === productionOrigin &&
        isExactOriginInput(value, productionOrigin);
      const test = allowInsecureTestOrigins &&
        url.protocol === 'http:' &&
        isLoopbackHostname(url.hostname) &&
        url.port !== '' &&
        isExactOriginInput(value, url.origin);
      return credentialsFreeRoot && (production || test)
        ? Effect.succeed({ url, value: url.origin })
        : Effect.fail(new GitHubSourceTransportConfigurationError({ reason: 'invalid-origin' }));
    }),
  );

const requestUrl = (origin: FixedOrigin, path: string): URL => new URL(path, origin.url);

const responseIsFixed = (response: Response, origin: FixedOrigin): boolean => {
  try {
    const url = new URL(response.url);
    return !response.redirected &&
      url.username === '' &&
      url.password === '' &&
      url.origin === origin.value;
  } catch {
    return false;
  }
};

const cancelResponse = (response: Response): Effect.Effect<void> => {
  const body = response.body;
  return body === null
    ? Effect.void
    : Effect.tryPromise({
      try: () => body.cancel(),
      catch: () => undefined,
    }).pipe(Effect.ignore);
};

const fetchFixed = <E>(
  url: URL,
  origin: FixedOrigin,
  acceptedContentTypes: ReadonlySet<string>,
  maximumBytes: number,
  onFailure: () => E,
  onMissing: () => E,
): Effect.Effect<Response, E> => Effect.tryPromise({
  try: signal => globalThis.fetch(url, {
    method: 'GET',
    redirect: 'error',
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    signal,
    headers: {
      accept: [...acceptedContentTypes].join(', '),
    },
  }),
  catch: onFailure,
}).pipe(
  Effect.flatMap(response => {
    if (!responseIsFixed(response, origin)) {
      return cancelResponse(response).pipe(Effect.andThen(Effect.fail(onFailure())));
    }
    // Response media type and length are success-only constraints. GitHub's
    // authenticated 404 body is normally text/plain, but it still means the
    // immutable revision is absent rather than that codeload misbehaved.
    if (response.status === 404) {
      return cancelResponse(response).pipe(Effect.andThen(Effect.fail(onMissing())));
    }
    if (response.status !== 200 || !validContentLength(response, maximumBytes)) {
      return cancelResponse(response).pipe(Effect.andThen(Effect.fail(onFailure())));
    }
    const mediaType = contentType(response);
    return mediaType === undefined || !acceptedContentTypes.has(mediaType)
      ? cancelResponse(response).pipe(Effect.andThen(Effect.fail(onFailure())))
      : Effect.succeed(response);
  }),
);

const withResponseReader = <A, E, R>(
  response: Response,
  onFailure: () => E,
  use: (reader: ReadableStreamDefaultReader<Uint8Array>) => Effect.Effect<A, E, R>,
): Effect.Effect<A, E, R> => {
  const body = response.body;
  if (body === null) return Effect.fail(onFailure());
  return Effect.try({
    try: () => body.getReader(),
    catch: onFailure,
  }).pipe(
    Effect.flatMap(reader => Effect.acquireUseRelease(
      Effect.succeed(reader),
      use,
      acquired => Effect.tryPromise({
        try: () => acquired.cancel(),
        catch: () => undefined,
      }).pipe(Effect.ignore),
    )),
    Effect.ensuring(cancelResponse(response)),
  );
};

const readReader = <E>(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  onFailure: () => E,
): Effect.Effect<ReadableStreamReadResult<Uint8Array>, E> => Effect.tryPromise({
  try: () => reader.read(),
  catch: onFailure,
});

const concatenate = (chunks: ReadonlyArray<Uint8Array>, byteLength: number): Uint8Array => {
  const output = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
};

const readBoundedBody = <E>(
  response: Response,
  maximumBytes: number,
  onFailure: () => E,
  onLimit: () => E,
): Effect.Effect<Uint8Array, E> => withResponseReader(response, onFailure, reader =>
  Effect.gen(function* () {
    const chunks = new Array<Uint8Array>();
    let byteLength = 0;
    let complete = false;
    yield* Effect.whileLoop({
      while: () => !complete,
      body: () => readReader(reader, onFailure).pipe(
        Effect.flatMap(result => {
          if (result.done) {
            complete = true;
            return Effect.void;
          }
          const nextLength = byteLength + result.value.byteLength;
          if (!Number.isSafeInteger(nextLength) || nextLength > maximumBytes) {
            return Effect.fail(onLimit());
          }
          byteLength = nextLength;
          chunks.push(result.value);
          return Effect.void;
        }),
      ),
      step: () => undefined,
    });
    return concatenate(chunks, byteLength);
  }),
);

const RepositoryMetadata = Schema.Struct({
  default_branch: Schema.String,
  name: Schema.String,
  full_name: Schema.String,
  owner: Schema.Struct({ login: Schema.String }),
});
const GitReferenceObject = Schema.Struct({
  object: Schema.Struct({ sha: Schema.String, type: Schema.String }),
});
const GitTagObject = Schema.Struct({
  object: Schema.Struct({ sha: Schema.String, type: Schema.String }),
});
const GitCommitObject = Schema.Struct({ sha: Schema.String });

const parseJson = (body: Uint8Array) => Effect.try({
  try: () => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)),
  catch: () => resolverError('invalid-response'),
});

const decodeRepositoryMetadata = (body: Uint8Array) => parseJson(body).pipe(
  Effect.flatMap(value => Schema.decodeUnknownEffect(RepositoryMetadata)(value).pipe(
    Effect.mapError(() => resolverError('invalid-response')),
  )),
);

const canonicalRepositoryIdentity = (
  source: GitHubSource,
  repository: typeof RepositoryMetadata.Type,
): Effect.Effect<CanonicalRepository, GitHubRevisionResolverError> => {
  const owner = repository.owner.login;
  const name = repository.name;
  return isCanonicalOwner(source.owner) &&
    isCanonicalRepository(source.repository) &&
    isCanonicalOwner(owner) &&
    isCanonicalRepository(name) &&
    owner.toLowerCase() === source.owner.toLowerCase() &&
    name.toLowerCase() === source.repository.toLowerCase() &&
    repository.full_name === `${owner}/${name}`
    ? Effect.succeed({ owner, repository: name })
    : Effect.fail(resolverError('invalid-response'));
};

const decodeGitReferenceObject = (body: Uint8Array) => parseJson(body).pipe(
  Effect.flatMap(value => Array.isArray(value)
    ? Effect.fail(resolverError('ambiguous-revision'))
    : Schema.decodeUnknownEffect(GitReferenceObject)(value).pipe(
      Effect.mapError(() => resolverError('invalid-response')),
    )),
);

const decodeGitTagObject = (body: Uint8Array) => parseJson(body).pipe(
  Effect.flatMap(value => Schema.decodeUnknownEffect(GitTagObject)(value).pipe(
    Effect.mapError(() => resolverError('invalid-response')),
  )),
);

const decodeGitCommitObject = (body: Uint8Array) => parseJson(body).pipe(
  Effect.flatMap(value => Schema.decodeUnknownEffect(GitCommitObject)(value).pipe(
    Effect.mapError(() => resolverError('invalid-response')),
  )),
);

const resolverRequest = (
  origins: FixedOrigins,
  path: string,
  limits: SourceMaterializationLimits,
): Effect.Effect<Uint8Array, GitHubRevisionResolverError> => {
  const url = requestUrl(origins.api, path);
  return fetchFixed(
    url,
    origins.api,
    apiJsonContentTypes,
    limits.gitOutputBytes,
    () => resolverError('transport-failed'),
    () => resolverError('missing-revision'),
  ).pipe(Effect.flatMap(response => readBoundedBody(
    response,
    limits.gitOutputBytes,
    () => resolverError('transport-failed'),
    () => resolverError('source-limit-exceeded'),
  )));
};

const apiRepositoryPath = (source: CanonicalRepository): string =>
  `/repos/${encodeURIComponent(source.owner)}/${encodeURIComponent(source.repository)}`;

const resolvedRef = (source: GitHubSource, defaultBranch: string): string => {
  switch (source.revision._tag) {
    case 'DefaultBranchRevision':
      return defaultBranch;
    case 'BranchRevision':
      return source.revision.branch;
    case 'TagRevision':
      return source.revision.tag;
    case 'CommitRevision':
      return source.revision.commitSha;
  }
};

const resolveAnnotatedTag = (
  origins: FixedOrigins,
  repositoryPath: string,
  objectSha: string,
  limits: SourceMaterializationLimits,
  depth: number,
): Effect.Effect<string, GitHubRevisionResolverError> => {
  if (!isCompleteSha(objectSha) || depth > maximumTagDereferenceDepth) {
    return Effect.fail(resolverError('invalid-response'));
  }
  return resolverRequest(
    origins,
    `${repositoryPath}/git/tags/${encodeURIComponent(objectSha)}`,
    limits,
  ).pipe(
    Effect.flatMap(decodeGitTagObject),
    Effect.flatMap(tag => {
      const object = tag.object;
      if (!isCompleteSha(object.sha)) return Effect.fail(resolverError('invalid-response'));
      if (object.type === 'commit') return Effect.succeed(object.sha);
      return object.type === 'tag'
        ? resolveAnnotatedTag(origins, repositoryPath, object.sha, limits, depth + 1)
        : Effect.fail(resolverError('invalid-response'));
    }),
  );
};

const resolveReference = (
  origins: FixedOrigins,
  repositoryPath: string,
  source: GitHubSource,
  defaultBranch: string,
  limits: SourceMaterializationLimits,
): Effect.Effect<string, GitHubRevisionResolverError> => {
  const reference = resolvedRef(source, defaultBranch);
  if (source.revision._tag === 'CommitRevision') {
    return isCompleteSha(reference)
      ? Effect.succeed(reference)
      : Effect.fail(resolverError('ambiguous-revision'));
  }
  if (!isSafeReference(reference)) return Effect.fail(resolverError('ambiguous-revision'));
  switch (source.revision._tag) {
    case 'DefaultBranchRevision':
    case 'BranchRevision':
      return resolverRequest(
        origins,
        `${repositoryPath}/git/ref/heads/${encodeURIComponent(reference)}`,
        limits,
      ).pipe(
        Effect.flatMap(decodeGitReferenceObject),
        Effect.flatMap(referenceObject =>
          referenceObject.object.type === 'commit' && isCompleteSha(referenceObject.object.sha)
            ? Effect.succeed(referenceObject.object.sha)
            : Effect.fail(resolverError('invalid-response')),
        ),
      );
    case 'TagRevision':
      return resolverRequest(
        origins,
        `${repositoryPath}/git/ref/tags/${encodeURIComponent(reference)}`,
        limits,
      ).pipe(
        Effect.flatMap(decodeGitReferenceObject),
        Effect.flatMap(referenceObject => {
          const object = referenceObject.object;
          if (!isCompleteSha(object.sha)) return Effect.fail(resolverError('invalid-response'));
          if (object.type === 'commit') return Effect.succeed(object.sha);
          return object.type === 'tag'
            ? resolveAnnotatedTag(origins, repositoryPath, object.sha, limits, 1)
            : Effect.fail(resolverError('invalid-response'));
        }),
      );
  }
};

const authenticateCommit = (
  origins: FixedOrigins,
  repositoryPath: string,
  commitSha: string,
  limits: SourceMaterializationLimits,
): Effect.Effect<string, GitHubRevisionResolverError> => {
  if (!isCompleteSha(commitSha)) return Effect.fail(resolverError('invalid-response'));
  return resolverRequest(
    origins,
    `${repositoryPath}/git/commits/${encodeURIComponent(commitSha)}`,
    limits,
  ).pipe(
    Effect.flatMap(decodeGitCommitObject),
    Effect.flatMap(commit =>
      isCompleteSha(commit.sha) && commit.sha === commitSha
        ? Effect.succeed(commitSha)
        : Effect.fail(resolverError('invalid-response')),
    ),
  );
};

const resolveGitHubRevision = (
  origins: FixedOrigins,
  source: GitHubSource,
  limits: SourceMaterializationLimits,
): Effect.Effect<GitHubRevisionResolution, GitHubRevisionResolverError> => Effect.gen(function* () {
  if (!isCanonicalOwner(source.owner) || !isCanonicalRepository(source.repository)) {
    return yield* Effect.fail(resolverError('invalid-response'));
  }
  const repository = yield* resolverRequest(origins, apiRepositoryPath(source), limits).pipe(
    Effect.flatMap(decodeRepositoryMetadata),
  );
  if (!isSafeReference(repository.default_branch)) {
    return yield* Effect.fail(resolverError('invalid-response'));
  }
  const canonical = yield* canonicalRepositoryIdentity(source, repository);
  const repositoryPath = apiRepositoryPath(canonical);
  const candidateSha = yield* resolveReference(
    origins,
    repositoryPath,
    source,
    repository.default_branch,
    limits,
  );
  const commitSha = yield* authenticateCommit(origins, repositoryPath, candidateSha, limits);
  return new GitHubRevisionResolution({
    owner: canonical.owner,
    repository: canonical.repository,
    defaultBranch: repository.default_branch,
    commitSha,
  });
});

interface TarCursor {
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly maximumExpandedBytes: number;
  pending: Uint8Array | undefined;
  pendingOffset: number;
  expandedBytes: number;
}

interface TarHeader {
  readonly kind: 'directory' | 'file';
  readonly path: string;
  readonly byteLength: number;
}

const allZero = (bytes: Uint8Array): boolean => {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
};

const tarOctal = (bytes: Uint8Array): number | undefined => {
  let value = 0;
  let sawDigit = false;
  let terminated = false;
  for (const byte of bytes) {
    if (byte === 0 || byte === 32) {
      if (sawDigit) terminated = true;
      continue;
    }
    if (terminated || byte < 48 || byte > 55) return undefined;
    sawDigit = true;
    value = value * 8 + (byte - 48);
    if (!Number.isSafeInteger(value)) return undefined;
  }
  return sawDigit ? value : 0;
};

const tarText = (bytes: Uint8Array): Effect.Effect<string, GitHubCodeloadArchiveError> => {
  let end = bytes.length;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === 0) {
      end = index;
      break;
    }
  }
  for (let index = end; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) return Effect.fail(archiveError('archive-invalid'));
  }
  return Effect.try({
    try: () => new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, end)),
    catch: () => archiveError('archive-invalid'),
  });
};

const validTarChecksum = (header: Uint8Array): boolean => {
  const expected = tarOctal(header.subarray(tarChecksumOffset, tarChecksumOffset + tarChecksumLength));
  if (expected === undefined) return false;
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= tarChecksumOffset && index < tarChecksumOffset + tarChecksumLength
      ? 32
      : header[index] ?? 0;
  }
  return actual === expected;
};

const decodeTarHeader = (header: Uint8Array): Effect.Effect<TarHeader, GitHubCodeloadArchiveError> => {
  if (header.length !== tarBlockBytes || !validTarChecksum(header)) {
    return Effect.fail(archiveError('archive-invalid'));
  }
  const size = tarOctal(header.subarray(tarSizeOffset, tarSizeOffset + tarSizeLength));
  if (size === undefined) return Effect.fail(archiveError('archive-invalid'));
  const type = header[tarTypeOffset] ?? -1;
  if (type !== 0 && type !== 48 && type !== 53) {
    return Effect.fail(archiveError('archive-invalid'));
  }
  return Effect.all([
    tarText(header.subarray(0, tarNameLength)),
    tarText(header.subarray(tarPrefixOffset, tarPrefixOffset + tarPrefixLength)),
  ]).pipe(
    Effect.flatMap(([name, prefix]) => {
      if (name === '') return Effect.fail(archiveError('archive-invalid'));
      const combined = prefix === '' ? name : `${prefix}/${name}`;
      const directory = type === 53;
      if (!directory && combined.endsWith('/')) return Effect.fail(archiveError('archive-invalid'));
      const path = directory && combined.endsWith('/') ? combined.slice(0, -1) : combined;
      return path === ''
        ? Effect.fail(archiveError('archive-invalid'))
        : Effect.succeed({ kind: directory ? 'directory' : 'file', path, byteLength: size });
    }),
  );
};

const archiveExpandedLimit = (maximumBytes: number, maximumEntries: number): number => {
  // maximumEntries counts staged source members, not codeload's mandatory
  // synthetic root directory. Reserve its header plus the two tar terminator
  // blocks in addition to a header/padding allowance for every source member.
  const computed = maximumBytes + maximumEntries * (tarBlockBytes * 2) + tarBlockBytes * 3;
  return Number.isSafeInteger(computed) ? computed : 0;
};

const nextTarChunk = (
  cursor: TarCursor,
): Effect.Effect<Uint8Array | undefined, GitHubCodeloadArchiveError> => Effect.suspend(() => {
  const pending = cursor.pending;
  if (pending !== undefined) {
    const chunk = pending.subarray(cursor.pendingOffset);
    cursor.pending = undefined;
    cursor.pendingOffset = 0;
    return Effect.succeed(chunk);
  }
  return readReader(cursor.reader, () => archiveError('archive-invalid')).pipe(
    Effect.flatMap(result => {
      if (result.done) return Effect.succeed(undefined);
      const nextExpandedBytes = cursor.expandedBytes + result.value.byteLength;
      if (!Number.isSafeInteger(nextExpandedBytes) || nextExpandedBytes > cursor.maximumExpandedBytes) {
        return Effect.fail(archiveError('source-limit-exceeded'));
      }
      cursor.expandedBytes = nextExpandedBytes;
      return result.value.byteLength === 0
        ? nextTarChunk(cursor)
        : Effect.succeed(result.value);
    }),
  );
});

const takeTarBytes = (
  cursor: TarCursor,
  maximumBytes: number,
): Effect.Effect<Uint8Array, GitHubCodeloadArchiveError> => Effect.suspend(() => {
  const pending = cursor.pending;
  if (pending !== undefined) {
    const available = pending.byteLength - cursor.pendingOffset;
    const length = Math.min(available, maximumBytes);
    const chunk = pending.subarray(cursor.pendingOffset, cursor.pendingOffset + length);
    cursor.pendingOffset += length;
    if (cursor.pendingOffset === pending.byteLength) {
      cursor.pending = undefined;
      cursor.pendingOffset = 0;
    }
    return Effect.succeed(chunk);
  }
  return nextTarChunk(cursor).pipe(
    Effect.flatMap(chunk => {
      if (chunk === undefined) return Effect.fail(archiveError('archive-invalid'));
      cursor.pending = chunk;
      cursor.pendingOffset = 0;
      return takeTarBytes(cursor, maximumBytes);
    }),
  );
});

const takeTarExactly = (
  cursor: TarCursor,
  byteLength: number,
): Effect.Effect<Uint8Array, GitHubCodeloadArchiveError> => Effect.gen(function* () {
  const chunks = new Array<Uint8Array>();
  let remaining = byteLength;
  yield* Effect.whileLoop({
    while: () => remaining > 0,
    body: () => takeTarBytes(cursor, remaining).pipe(Effect.map(chunk => {
      remaining -= chunk.byteLength;
      chunks.push(chunk);
    })),
    step: () => undefined,
  });
  return concatenate(chunks, byteLength);
});

const writeTarFile = (
  cursor: TarCursor,
  writer: DescriptorFileWriter,
  byteLength: number,
): Effect.Effect<void, GitHubCodeloadArchiveError> => {
  let remaining = byteLength;
  return Effect.whileLoop({
    while: () => remaining > 0,
    body: () => takeTarBytes(cursor, Math.min(remaining, 64 * 1024)).pipe(
      Effect.flatMap(chunk => writer.write(chunk).pipe(
        Effect.mapError(() => archiveError('transport-failed')),
        Effect.tap(() => Effect.sync(() => {
          remaining -= chunk.byteLength;
        })),
      )),
    ),
    step: () => undefined,
  });
};

const consumeTarPadding = (
  cursor: TarCursor,
  byteLength: number,
): Effect.Effect<void, GitHubCodeloadArchiveError> => {
  let remaining = (tarBlockBytes - (byteLength % tarBlockBytes)) % tarBlockBytes;
  return Effect.whileLoop({
    while: () => remaining > 0,
    body: () => takeTarBytes(cursor, remaining).pipe(
      Effect.flatMap(chunk => {
        if (!allZero(chunk)) return Effect.fail(archiveError('archive-invalid'));
        remaining -= chunk.byteLength;
        return Effect.void;
      }),
    ),
    step: () => undefined,
  });
};

const consumeTrailingZeroes = (
  cursor: TarCursor,
): Effect.Effect<void, GitHubCodeloadArchiveError> => {
  let complete = false;
  return Effect.whileLoop({
    while: () => !complete,
    body: () => nextTarChunk(cursor).pipe(
      Effect.flatMap(chunk => {
        if (chunk === undefined) {
          complete = true;
          return Effect.void;
        }
        return allZero(chunk)
          ? Effect.void
          : Effect.fail(archiveError('archive-invalid'));
      }),
    ),
    step: () => undefined,
  });
};

const validArchivePath = (path: string): boolean => {
  const segments = path.split('/');
  return utf8.encode(path).byteLength <= maximumArchivePathBytes &&
    segments.length <= maximumArchiveDepth &&
    !path.startsWith('//') &&
    !path.startsWith('/') &&
    !/^[A-Za-z]:/u.test(path) &&
    !path.includes(':') &&
    !path.includes('%') &&
    !path.includes('\\') &&
    !/[\u0000-\u001f\u007f]/u.test(path) &&
    segments.every(segment =>
      segment !== '' &&
      segment !== '.' &&
      segment !== '..' &&
      utf8.encode(segment).byteLength <= maximumArchivePathSegmentBytes,
    );
};

const archivePathKey = (path: string): string => path.normalize('NFC').toLowerCase();

const parentDirectoriesExist = (
  entries: ReadonlyMap<string, 'directory' | 'file'>,
  path: string,
): boolean => {
  const segments = path.split('/');
  let parent = '';
  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index];
    if (segment === undefined) return false;
    parent = parent === '' ? segment : `${parent}/${segment}`;
    if (entries.get(parent) !== 'directory') return false;
  }
  return true;
};

const canAddArchiveEntry = (
  entries: ReadonlyMap<string, 'directory' | 'file'>,
  entryKeys: ReadonlyMap<string, string>,
  path: string,
): boolean => {
  if (entries.has(path) || entryKeys.has(archivePathKey(path)) || !parentDirectoriesExist(entries, path)) {
    return false;
  }
  for (const existing of entries.keys()) {
    if (existing.startsWith(`${path}/`)) return false;
  }
  return true;
};

const archiveRoot = (repository: string, commitSha: string): string => `${repository}-${commitSha}`;

const isPositiveBoundedInteger = (value: number, maximum: number): boolean =>
  Number.isSafeInteger(value) && value >= 1 && value <= maximum;

const validArchiveRequest = (request: GitHubCodeloadArchiveRequest): boolean =>
  isCanonicalOwner(request.owner) &&
  isCanonicalRepository(request.repository) &&
  isCompleteSha(request.commitSha) &&
  isPositiveBoundedInteger(request.maximumEntries, 100_000) &&
  isPositiveBoundedInteger(request.maximumFiles, 100_000) &&
  isPositiveBoundedInteger(request.maximumBytes, 512 * 1024 * 1024) &&
  isPositiveBoundedInteger(request.maximumArchiveBytes, 1024 * 1024 * 1024) &&
  isPositiveBoundedInteger(request.timeoutMs, 60_000);

const withArchiveCursor = <A>(
  response: Response,
  maximumCompressedBytes: number,
  maximumExpandedBytes: number,
  use: (cursor: TarCursor) => Effect.Effect<A, GitHubCodeloadArchiveError>,
): Effect.Effect<A, GitHubCodeloadArchiveError> => {
  const body = response.body;
  if (body === null || maximumExpandedBytes < 1) {
    return Effect.fail(archiveError('archive-invalid'));
  }
  let compressedBytes = 0;
  let compressedLimitExceeded = false;
  return Effect.try({
    try: () => {
      const counted = body.pipeThrough(new TransformStream<Uint8Array, BufferSource>({
        transform(chunk, controller) {
          const next = compressedBytes + chunk.byteLength;
          if (!Number.isSafeInteger(next) || next > maximumCompressedBytes) {
            compressedLimitExceeded = true;
            controller.error(archiveError('source-limit-exceeded'));
            return;
          }
          compressedBytes = next;
          controller.enqueue(new Uint8Array(chunk));
        },
      }));
      return counted.pipeThrough(new DecompressionStream('gzip')).getReader();
    },
    catch: () => archiveError('capability-unavailable'),
  }).pipe(
    Effect.flatMap(reader => Effect.acquireUseRelease(
      Effect.succeed(reader),
      acquired => use({
        reader: acquired,
        maximumExpandedBytes,
        pending: undefined,
        pendingOffset: 0,
        expandedBytes: 0,
      }).pipe(Effect.catchTag('GitHubCodeloadArchiveError', error =>
        compressedLimitExceeded
          ? Effect.fail(archiveError('source-limit-exceeded'))
          : Effect.fail(error),
      )),
      acquired => Effect.tryPromise({
        try: () => acquired.cancel(),
        catch: () => undefined,
      }).pipe(Effect.ignore),
    )),
    Effect.ensuring(cancelResponse(response)),
  );
};

const stageArchive = (
  origins: FixedOrigins,
  request: GitHubCodeloadArchiveRequest,
  staging: DescriptorStagingOperations,
): Effect.Effect<GitHubCodeloadArchiveReceipt, GitHubCodeloadArchiveError> => {
  if (!validArchiveRequest(request)) return Effect.fail(archiveError('archive-invalid'));
  const url = requestUrl(
    origins.codeload,
    `/${encodeURIComponent(request.owner)}/${encodeURIComponent(request.repository)}/tar.gz/${encodeURIComponent(request.commitSha)}`,
  );
  return fetchFixed(
    url,
    origins.codeload,
    gzipContentTypes,
    request.maximumArchiveBytes,
    () => archiveError('transport-failed'),
    () => archiveError('missing-revision'),
  ).pipe(
    Effect.flatMap(response => {
      const expandedLimit = archiveExpandedLimit(request.maximumBytes, request.maximumEntries);
      return withArchiveCursor(response, request.maximumArchiveBytes, expandedLimit, cursor => Effect.gen(function* () {
        const expectedRoot = archiveRoot(request.repository, request.commitSha);
        const entries = new Map<string, 'directory' | 'file'>();
        const entryKeys = new Map<string, string>();
        let rootSeen = false;
        let entryCount = 0;
        let fileCount = 0;
        let totalFileBytes = 0;
        let complete = false;
        yield* Effect.whileLoop({
          while: () => !complete,
          body: () => Effect.gen(function* () {
            const header = yield* takeTarExactly(cursor, tarBlockBytes);
            if (allZero(header)) {
              const terminal = yield* takeTarExactly(cursor, tarBlockBytes);
              if (!allZero(terminal)) return yield* Effect.fail(archiveError('archive-invalid'));
              yield* consumeTrailingZeroes(cursor);
              complete = true;
              return;
            }
            const entry = yield* decodeTarHeader(header);
            if (!rootSeen) {
              if (entry.kind !== 'directory' || entry.path !== expectedRoot || entry.byteLength !== 0) {
                return yield* Effect.fail(archiveError('archive-invalid'));
              }
              rootSeen = true;
              return;
            }
            const nextEntryCount = entryCount + 1;
            if (nextEntryCount > request.maximumEntries) {
              return yield* Effect.fail(archiveError('source-limit-exceeded'));
            }
            entryCount = nextEntryCount;
            const rootPrefix = `${expectedRoot}/`;
            if (!entry.path.startsWith(rootPrefix)) {
              return yield* Effect.fail(archiveError('archive-invalid'));
            }
            const relative = entry.path.slice(rootPrefix.length);
            if (!validArchivePath(relative) || !canAddArchiveEntry(entries, entryKeys, relative)) {
              return yield* Effect.fail(archiveError('archive-invalid'));
            }
            const path = new WorkspaceRelativePath({ segments: relative.split('/') });
            if (entry.kind === 'directory') {
              if (entry.byteLength !== 0) return yield* Effect.fail(archiveError('archive-invalid'));
              entries.set(relative, 'directory');
              entryKeys.set(archivePathKey(relative), relative);
              yield* staging.makeDirectory(path).pipe(
                Effect.mapError(() => archiveError('transport-failed')),
              );
              return;
            }
            const nextFileCount = fileCount + 1;
            const nextTotalFileBytes = totalFileBytes + entry.byteLength;
            if (!Number.isSafeInteger(nextTotalFileBytes) ||
              nextFileCount > request.maximumFiles ||
              entry.byteLength > request.maximumBytes ||
              nextTotalFileBytes > request.maximumBytes) {
              return yield* Effect.fail(archiveError('source-limit-exceeded'));
            }
            entries.set(relative, 'file');
            entryKeys.set(archivePathKey(relative), relative);
            fileCount = nextFileCount;
            totalFileBytes = nextTotalFileBytes;
            yield* staging.withFileWriter(
              path,
              writer => writeTarFile(cursor, writer, entry.byteLength),
            ).pipe(Effect.mapError(() => archiveError('transport-failed')));
            yield* consumeTarPadding(cursor, entry.byteLength);
          }),
          step: () => undefined,
        });
        return rootSeen
          ? new GitHubCodeloadArchiveReceipt({ commitSha: request.commitSha })
          : yield* Effect.fail(archiveError('archive-invalid'));
      }));
    }),
    Effect.timeoutOption(request.timeoutMs),
    Effect.flatMap(Option.match({
      onNone: () => Effect.fail(archiveError('transport-failed')),
      onSome: Effect.succeed,
    })),
  );
};

const makeServices = (origins: FixedOrigins): GitHubSourceTransportServices => ({
  resolver: GitHubRevisionResolver.of({
    resolve: (source, limits) => resolveGitHubRevision(origins, source, limits).pipe(
      Effect.timeoutOption(limits.gitTimeoutMs),
      Effect.flatMap(Option.match({
        onNone: () => Effect.fail(resolverError('transport-failed')),
        onSome: Effect.succeed,
      })),
    ),
  }),
  archives: GitHubCodeloadArchiveTransport.of({
    stage: (request, staging) => stageArchive(origins, request, staging),
  }),
});

const productionOrigins: FixedOrigins = {
  api: {
    url: new URL(apiProductionOrigin),
    value: apiProductionOrigin,
  },
  codeload: {
    url: new URL(codeloadProductionOrigin),
    value: codeloadProductionOrigin,
  },
};

/**
 * Builds a strict Node fetch transport. The only test escape hatch is an
 * explicitly opt-in local HTTP origin; production callers should use the live
 * layer below, whose origins are constants.
 */
export const makeNodeGitHubSourceTransport = (
  options: NodeGitHubSourceTransportOptions = {},
): Effect.Effect<GitHubSourceTransportServices, GitHubSourceTransportConfigurationError> =>
  Effect.all([
    fixedOrigin(
      options.apiOrigin ?? productionOrigins.api.value,
      apiProductionOrigin,
      options.allowInsecureTestOrigins ?? false,
    ),
    fixedOrigin(
      options.codeloadOrigin ?? productionOrigins.codeload.value,
      codeloadProductionOrigin,
      options.allowInsecureTestOrigins ?? false,
    ),
  ]).pipe(Effect.map(([api, codeload]) => makeServices({ api, codeload })));

export const GitHubSourceTransportLive = Layer.mergeAll(
  Layer.succeed(GitHubRevisionResolver, makeServices(productionOrigins).resolver),
  Layer.succeed(GitHubCodeloadArchiveTransport, makeServices(productionOrigins).archives),
);
