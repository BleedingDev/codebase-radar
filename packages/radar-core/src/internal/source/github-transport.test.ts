import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { gzipSync } from 'node:zlib';
import { Effect } from 'effect';
import {
  CommitRevision,
  DefaultBranchRevision,
  GitHubSource,
} from '@codebase-radar/contracts/source';
import { describe, expect, it } from 'vitest';
import {
  WorkspaceAccessError,
  WorkspaceFileDigest,
  WorkspaceRelativePath,
} from '../workspace.js';
import type {
  DescriptorStagingOperations,
} from '../workspace.js';
import {
  GitHubCodeloadArchiveRequest,
  SourceMaterializationLimits,
  makeNodeGitHubSourceTransport,
} from './index.js';

const commitSha = 'a'.repeat(40);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const tarBlockBytes = 512;

interface TarMember {
  readonly path: string;
  readonly kind:
    | 'block-device'
    | 'character-device'
    | 'directory'
    | 'fifo'
    | 'file'
    | 'hardlink'
    | 'pax'
    | 'socket'
    | 'symlink';
  readonly body?: Uint8Array;
}

interface InertReply {
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly delayMs?: number;
  readonly redirect?: string;
  readonly status?: number;
}

interface SeenRequest {
  readonly authorization: string | undefined;
  readonly cookie: string | undefined;
  readonly proxyAuthorization: string | undefined;
  readonly url: string;
}

interface InertServer {
  readonly close: Effect.Effect<void>;
  readonly origin: string;
  readonly requests: ReadonlyArray<SeenRequest>;
  readonly closedRequests: () => number;
  readonly openRequests: () => number;
  readonly setReply: (reply: InertReply) => void;
  readonly setReplyFor: (url: string, reply: InertReply) => void;
}

const archiveFailure = () => new WorkspaceAccessError({
  operation: 'write-file',
  reason: 'unsafe-entry',
});

const pathText = (path: WorkspaceRelativePath): string => path.segments.join('/');

const concat = (chunks: ReadonlyArray<Uint8Array>): Uint8Array => {
  const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
};

const putText = (target: Uint8Array, offset: number, width: number, text: string): void => {
  const bytes = encoder.encode(text);
  target.set(bytes.subarray(0, width), offset);
};

const putOctal = (target: Uint8Array, offset: number, width: number, value: number): void => {
  const text = value.toString(8).padStart(width - 1, '0');
  putText(target, offset, width - 1, text);
  target[offset + width - 1] = 0;
};

const tarType = (kind: TarMember['kind']): number => {
  switch (kind) {
    case 'block-device': return 52;
    case 'character-device': return 51;
    case 'directory': return 53;
    case 'file': return 48;
    case 'fifo': return 54;
    case 'hardlink': return 49;
    case 'pax': return 120;
    case 'socket': return 115;
    case 'symlink': return 50;
  }
};

const tarHeader = (member: TarMember): Uint8Array => {
  const header = new Uint8Array(tarBlockBytes);
  const body = member.body ?? new Uint8Array();
  putText(header, 0, 100, member.path);
  putOctal(header, 100, 8, member.kind === 'directory' ? 0o755 : 0o644);
  putOctal(header, 124, 12, body.byteLength);
  putOctal(header, 136, 12, 0);
  header.fill(32, 148, 156);
  header[156] = tarType(member.kind);
  putText(header, 257, 6, 'ustar');
  putText(header, 263, 2, '00');
  const checksum = header.reduce((total, byte) => total + byte, 0);
  putOctal(header, 148, 8, checksum);
  return header;
};

const tar = (...members: ReadonlyArray<TarMember>): Uint8Array => {
  const chunks = new Array<Uint8Array>();
  for (const member of members) {
    const body = member.body ?? new Uint8Array();
    chunks.push(tarHeader(member));
    if (member.kind !== 'directory') {
      chunks.push(body);
      const padding = (tarBlockBytes - (body.byteLength % tarBlockBytes)) % tarBlockBytes;
      if (padding > 0) chunks.push(new Uint8Array(padding));
    }
  }
  chunks.push(new Uint8Array(tarBlockBytes), new Uint8Array(tarBlockBytes));
  return concat(chunks);
};

const responseBody = (value: string): Uint8Array => encoder.encode(value);

const jsonReply = (value: string): InertReply => ({
  body: responseBody(value),
  contentType: 'application/json; charset=utf-8',
});

const repositoryReply = (
  owner = 'RadarOwner',
  repository = 'Fixture.Repository',
  defaultBranch = 'main',
  fullName = `${owner}/${repository}`,
): InertReply => jsonReply(JSON.stringify({
  default_branch: defaultBranch,
  full_name: fullName,
  name: repository,
  owner: { login: owner },
}));

const closeServer = (server: Server) => Effect.tryPromise({
  try: () => new Promise<void>((resolve, reject) => {
    server.close(error => error === undefined ? resolve() : reject(error));
  }),
  catch: archiveFailure,
}).pipe(Effect.ignore);

const startInertServer = (): Effect.Effect<InertServer, WorkspaceAccessError> =>
  Effect.callback((resume) => {
    const seen = new Array<SeenRequest>();
    let closed = 0;
    let open = 0;
    let reply: InertReply = jsonReply('{}');
    const routedReplies = new Map<string, InertReply>();
    const handler = (request: IncomingMessage, response: ServerResponse): void => {
      const url = request.url ?? '';
      const active = routedReplies.get(url) ?? reply;
      seen.push({
        authorization: request.headers.authorization,
        cookie: request.headers.cookie,
        proxyAuthorization: request.headers['proxy-authorization'],
        url,
      });
      open += 1;
      request.once('close', () => {
        closed += 1;
        open -= 1;
      });
      if (active.redirect !== undefined) {
        response.writeHead(302, { location: active.redirect });
        response.end();
        return;
      }
      const send = (): void => {
        response.writeHead(active.status ?? 200, { 'content-type': active.contentType });
        response.write(active.body);
        response.end();
      };
      if (active.delayMs === undefined) {
        send();
        return;
      }
      const timeout = setTimeout(send, active.delayMs);
      timeout.unref();
    };
    const server = createServer(handler);
    const failed = (): void => resume(Effect.fail(archiveFailure()));
    server.once('error', failed);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', failed);
      const address = server.address();
      if (address === null || typeof address === 'string') {
        void closeServer(server);
        resume(Effect.fail(archiveFailure()));
        return;
      }
      resume(Effect.succeed({
        close: closeServer(server),
        origin: `http://127.0.0.1:${address.port}`,
        requests: seen,
        closedRequests: () => closed,
        openRequests: () => open,
        setReply: next => {
          reply = next;
        },
        setReplyFor: (url, next) => {
          routedReplies.set(url, next);
        },
      }));
    });
    return closeServer(server);
  });

const withInertServer = <A, E, R>(
  use: (server: InertServer) => Effect.Effect<A, E, R>,
): Effect.Effect<A, E | WorkspaceAccessError, R> => Effect.acquireUseRelease(
  startInertServer(),
  use,
  server => server.close,
);

const source = () => new GitHubSource({
  owner: 'RadarOwner',
  repository: 'Fixture.Repository',
  revision: new DefaultBranchRevision({}),
});

const limits = (overrides: Partial<ConstructorParameters<typeof SourceMaterializationLimits>[0]> = {}) =>
  new SourceMaterializationLimits({
    maximumEntries: 16,
    maximumFiles: 8,
    maximumBytes: 8 * 1024,
    maximumArchiveBytes: 8 * 1024,
    archiveTimeoutMs: 500,
    gitTimeoutMs: 500,
    gitOutputBytes: 8 * 1024,
    ...overrides,
  });

const request = (overrides: Partial<ConstructorParameters<typeof GitHubCodeloadArchiveRequest>[0]> = {}) =>
  new GitHubCodeloadArchiveRequest({
    owner: 'RadarOwner',
    repository: 'Fixture.Repository',
    commitSha,
    maximumEntries: 16,
    maximumFiles: 8,
    maximumBytes: 8 * 1024,
    maximumArchiveBytes: 8 * 1024,
    timeoutMs: 500,
    ...overrides,
  });

interface MemoryStaging {
  readonly directories: ReadonlyArray<string>;
  readonly files: ReadonlyMap<string, Uint8Array>;
  readonly operations: DescriptorStagingOperations;
}

const memoryStaging = (): MemoryStaging => {
  const directories = new Array<string>();
  const files = new Map<string, Uint8Array>();
  const operations: DescriptorStagingOperations = {
    readDirectory: () => Effect.fail(archiveFailure()),
    stat: () => Effect.fail(archiveFailure()),
    readText: () => Effect.fail(archiveFailure()),
    digestRegularFile: () => Effect.fail(archiveFailure()),
    makeDirectory: path => Effect.sync(() => {
      directories.push(pathText(path));
    }),
    withFileWriter: (path, write) => {
      const chunks = new Array<Uint8Array>();
      return write({
        write: chunk => Effect.sync(() => {
          chunks.push(new Uint8Array(chunk));
        }),
      }).pipe(Effect.tap(() => Effect.sync(() => {
        files.set(pathText(path), concat(chunks));
      })));
    },
    runGitResolver: () => Effect.fail(archiveFailure()),
  };
  return { directories, files, operations };
};

const serviceFor = (server: InertServer) => makeNodeGitHubSourceTransport({
  apiOrigin: server.origin,
  codeloadOrigin: server.origin,
  allowInsecureTestOrigins: true,
});

describe('Node GitHub source transport', () => {
  it('normalizes the canonical repository identity and authenticates a full immutable SHA on the fixed credential-free API origin', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      server.setReplyFor('/repos/RadarOwner/Fixture.Repository', repositoryReply(
        'radarowner',
        'fixture.repository',
      ));
      server.setReplyFor(
        '/repos/radarowner/fixture.repository/git/ref/heads/main',
        jsonReply(`{"object":{"sha":"${commitSha}","type":"commit"}}`),
      );
      server.setReplyFor(
        `/repos/radarowner/fixture.repository/git/commits/${commitSha}`,
        jsonReply(`{"sha":"${commitSha}"}`),
      );
      const resolution = yield* services.resolver.resolve(source(), limits());
      expect(resolution.commitSha).toBe(commitSha);
      expect(resolution.defaultBranch).toBe('main');
      expect(resolution.owner).toBe('radarowner');
      expect(resolution.repository).toBe('fixture.repository');
      expect(server.requests.map(item => item.url)).toEqual([
        '/repos/RadarOwner/Fixture.Repository',
        '/repos/radarowner/fixture.repository/git/ref/heads/main',
        `/repos/radarowner/fixture.repository/git/commits/${commitSha}`,
      ]);
      expect(server.requests.every(item =>
        item.authorization === undefined &&
        item.cookie === undefined &&
        item.proxyAuthorization === undefined,
      )).toBe(true);
    })))),
  );

  it('rejects origin smuggling before any network request is made', () =>
    Effect.runPromise(Effect.gen(function* () {
      for (const apiOrigin of [
        'https://api.github.com:443',
        'https://api.github.com:8443',
        'https://api.github.com./',
        'https://api.github.com/?next=https://elsewhere.invalid',
        'https://user:secret@api.github.com/',
        'https://api.github.com/#fragment',
      ]) {
        const failure = yield* Effect.flip(makeNodeGitHubSourceTransport({ apiOrigin }));
        expect(failure.reason).toBe('invalid-origin');
      }
      const codeloadFailure = yield* Effect.flip(makeNodeGitHubSourceTransport({
        codeloadOrigin: 'https://codeload.github.com:443',
      }));
      expect(codeloadFailure.reason).toBe('invalid-origin');
    })),
  );

  it('rejects symbolic, spoofed, and mismatched GitHub revision responses', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      const repositoryPath = '/repos/RadarOwner/Fixture.Repository';
      server.setReplyFor(repositoryPath, repositoryReply('RadarOwner', 'Fixture.Repository', 'HEAD'));
      const symbolicDefault = yield* Effect.flip(services.resolver.resolve(source(), limits()));
      expect(symbolicDefault.code).toBe('invalid-response');

      server.setReplyFor(repositoryPath, repositoryReply('Elsewhere', 'Fixture.Repository'));
      const spoofedRepository = yield* Effect.flip(services.resolver.resolve(source(), limits()));
      expect(spoofedRepository.code).toBe('invalid-response');

      server.setReplyFor(repositoryPath, repositoryReply());
      const sha256LikeRevision = new GitHubSource({
        owner: 'RadarOwner',
        repository: 'Fixture.Repository',
        revision: new CommitRevision({ commitSha: 'c'.repeat(64) }),
      });
      const nonGitHubObject = yield* Effect.flip(services.resolver.resolve(sha256LikeRevision, limits()));
      expect(nonGitHubObject.code).toBe('ambiguous-revision');

      server.setReplyFor(
        `${repositoryPath}/git/ref/heads/main`,
        jsonReply(`{"object":{"sha":"${commitSha}","type":"commit"}}`),
      );
      server.setReplyFor(
        `${repositoryPath}/git/commits/${commitSha}`,
        jsonReply(`{"sha":"${'b'.repeat(40)}"}`),
      );
      const mismatch = yield* Effect.flip(services.resolver.resolve(source(), limits()));
      expect(mismatch.code).toBe('invalid-response');

      server.setReplyFor(
        `${repositoryPath}/git/ref/heads/main`,
        jsonReply(`[{"object":{"sha":"${commitSha}","type":"commit"}}]`),
      );
      const ambiguous = yield* Effect.flip(services.resolver.resolve(source(), limits()));
      expect(ambiguous.code).toBe('ambiguous-revision');
    })))),
  );

  it('rejects redirects, unexpected content types, and slow API responses without leaving a request open', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      for (const reply of [
        { ...jsonReply('{}'), redirect: 'http://127.0.0.1/elsewhere' },
        { body: responseBody('{}'), contentType: 'text/html' },
        { ...jsonReply('{}'), delayMs: 100 },
      ]) {
        server.setReply(reply);
        const failure = yield* Effect.flip(services.resolver.resolve(
          source(),
          limits({ gitTimeoutMs: 5 }),
        ));
        expect(failure.code).toBe('transport-failed');
      }
    })))),
  );

  it('classifies a fixed-origin codeload 404 before applying success-only gzip checks', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      server.setReply({
        body: responseBody('not found'),
        contentType: 'text/plain; charset=utf-8',
        status: 404,
      });
      const missing = yield* Effect.flip(services.archives.stage(request(), memoryStaging().operations));
      expect(missing.code).toBe('missing-revision');

      server.setReply({
        body: responseBody('not an archive'),
        contentType: 'text/plain; charset=utf-8',
      });
      const wrongSuccessType = yield* Effect.flip(services.archives.stage(request(), memoryStaging().operations));
      expect(wrongSuccessType.code).toBe('transport-failed');
    })))),
  );

  it('streams only a canonical pinned root and rejects hostile tar members before descriptor writes', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      const root = `Fixture.Repository-${commitSha}`;
      const safeArchive = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/src/`, kind: 'directory' },
        { path: `${root}/src/index.ts`, kind: 'file', body: responseBody('safe') },
      ));
      server.setReply({ body: safeArchive, contentType: 'application/x-gzip' });
      const safe = memoryStaging();
      const receipt = yield* services.archives.stage(request(), safe.operations);
      expect(receipt.commitSha).toBe(commitSha);
      expect(safe.directories).toEqual(['src']);
      const written = safe.files.get('src/index.ts');
      expect(written).toBeDefined();
      if (written !== undefined) {
        expect(decoder.decode(written)).toBe('safe');
      }

      const hostile = [
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/link`, kind: 'symlink' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/hard-link`, kind: 'hardlink' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/pipe`, kind: 'fifo' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/socket`, kind: 'socket' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/block-device`, kind: 'block-device' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/character-device`, kind: 'character-device' },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/pax`, kind: 'pax', body: responseBody('path=../escape') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/a`, kind: 'file', body: responseBody('a') },
          { path: `${root}/a`, kind: 'file', body: responseBody('b') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/a`, kind: 'file', body: responseBody('a') },
          { path: `${root}/a/child`, kind: 'file', body: responseBody('b') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/../escape`, kind: 'file', body: responseBody('x') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/%2e%2e`, kind: 'file', body: responseBody('x') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/A`, kind: 'file', body: responseBody('a') },
          { path: `${root}/a`, kind: 'file', body: responseBody('b') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}-prefix/escape`, kind: 'file', body: responseBody('x') },
        ),
        tar(
          { path: `${root}/`, kind: 'directory' },
          { path: `${root}/`, kind: 'directory' },
        ),
      ];
      for (const bytes of hostile) {
        server.setReply({ body: gzipSync(bytes), contentType: 'application/x-gzip' });
        const staged = memoryStaging();
        const failure = yield* Effect.flip(services.archives.stage(request(), staged.operations));
        expect(failure.code).toBe('archive-invalid');
        // A bounded regular member may have been staged before a later corrupt
        // member is discovered, but no hostile path is ever written and the
        // enclosing materialization scope discards this unsealed workspace.
        expect([...staged.files.keys()].every(path => path === 'a' || path === 'A')).toBe(true);
      }
    })))),
  );

  it('enforces compressed, expanded, entry, file, and time bounds before retaining a hostile archive', () =>
    Effect.runPromise(Effect.scoped(withInertServer(server => Effect.gen(function* () {
      const services = yield* serviceFor(server);
      const root = `Fixture.Repository-${commitSha}`;
      const exactOneByte = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/one-byte.txt`, kind: 'file', body: responseBody('x') },
      ));
      server.setReply({ body: exactOneByte, contentType: 'application/x-gzip' });
      const exactOneByteStaging = memoryStaging();
      const exactOneByteReceipt = yield* services.archives.stage(request({
        maximumEntries: 1,
        maximumFiles: 1,
        maximumBytes: 1,
      }), exactOneByteStaging.operations);
      expect(exactOneByteReceipt.commitSha).toBe(commitSha);
      expect(exactOneByteStaging.files.get('one-byte.txt')).toEqual(responseBody('x'));

      const oversizedFile = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/one.txt`, kind: 'file', body: new Uint8Array(5) },
      ));
      server.setReply({ body: oversizedFile, contentType: 'application/x-gzip' });
      const fileFailure = yield* Effect.flip(services.archives.stage(request({ maximumBytes: 4 }), memoryStaging().operations));
      expect(fileFailure.code).toBe('source-limit-exceeded');
      const compressedFailure = yield* Effect.flip(services.archives.stage(request({
        maximumArchiveBytes: oversizedFile.byteLength - 1,
      }), memoryStaging().operations));
      expect(compressedFailure.code).toBe('source-limit-exceeded');

      const extraFile = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/one.txt`, kind: 'file', body: responseBody('one') },
        { path: `${root}/two.txt`, kind: 'file', body: responseBody('two') },
      ));
      server.setReply({ body: extraFile, contentType: 'application/x-gzip' });
      const countFailure = yield* Effect.flip(services.archives.stage(request({ maximumFiles: 1 }), memoryStaging().operations));
      expect(countFailure.code).toBe('source-limit-exceeded');

      const exactEntries = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/a/`, kind: 'directory' },
        { path: `${root}/a/file`, kind: 'file', body: responseBody('a') },
      ));
      server.setReply({ body: exactEntries, contentType: 'application/x-gzip' });
      const exactEntriesStaging = memoryStaging();
      const exactEntriesReceipt = yield* services.archives.stage(request({ maximumEntries: 2 }), exactEntriesStaging.operations);
      expect(exactEntriesReceipt.commitSha).toBe(commitSha);
      expect(exactEntriesStaging.directories).toEqual(['a']);
      expect(exactEntriesStaging.files.get('a/file')).toEqual(responseBody('a'));

      const extraEntry = gzipSync(tar(
        { path: `${root}/`, kind: 'directory' },
        { path: `${root}/a/`, kind: 'directory' },
        { path: `${root}/a/file`, kind: 'file', body: responseBody('a') },
        { path: `${root}/extra.txt`, kind: 'file', body: responseBody('b') },
      ));
      server.setReply({ body: extraEntry, contentType: 'application/x-gzip' });
      const entryFailure = yield* Effect.flip(services.archives.stage(request({ maximumEntries: 2 }), memoryStaging().operations));
      expect(entryFailure.code).toBe('source-limit-exceeded');

      const bomb = gzipSync(new Uint8Array(8 * 1024));
      server.setReply({ body: bomb, contentType: 'application/x-gzip' });
      const bombFailure = yield* Effect.flip(services.archives.stage(request({
        maximumEntries: 1,
        maximumBytes: 1,
        maximumArchiveBytes: bomb.byteLength,
      }), memoryStaging().operations));
      expect(bombFailure.code).toBe('source-limit-exceeded');

      server.setReply({
        body: oversizedFile,
        contentType: 'application/x-gzip',
        delayMs: 100,
      });
      const slowFailure = yield* Effect.flip(services.archives.stage(request({ timeoutMs: 5 }), memoryStaging().operations));
      expect(slowFailure.code).toBe('transport-failed');
      yield* Effect.sleep('10 millis');
      expect(server.openRequests()).toBe(0);
    })))),
  );
});
