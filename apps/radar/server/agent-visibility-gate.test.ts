import { readFileSync } from 'node:fs';
import { Effect } from 'effect';
import { HttpClient, HttpClientResponse } from 'effect/unstable/http';
import { describe, expect, it } from 'vitest';
import { GitHubSourceIdentity } from '../shared/domain';
import {
  makeScanAccessVisibilityAttestation,
  publicGitHubVisibilityPolicyVersion,
  ScanAccessGrant,
} from './agent-store';
import {
  maximumVisibilityAttestationCacheEntries,
  verifyVisibilityRemotely,
  visibilityAttestationCacheKey,
  visibilityAttestationCacheTtlMs,
} from './agent-visibility-gate';

const source = (repository = 'repository') =>
  new GitHubSourceIdentity({
    codebaseId: `github:owner/${repository}`,
    owner: 'owner',
    repository,
    url: `https://github.com/owner/${repository}`,
    commitSha: 'a'.repeat(40),
    defaultBranch: 'main',
    snapshotDigest: `git:${'a'.repeat(40)}`,
  });

const grant = (repository = 'repository', inventory = 'b'.repeat(64)) => {
  const identity = source(repository);
  const visibility = makeScanAccessVisibilityAttestation(
    publicGitHubVisibilityPolicyVersion,
    identity,
    'a'.repeat(64),
    inventory,
  );
  return new ScanAccessGrant({
    reviewOwnerId: 'owner-id',
    scanId: 'scan-id',
    canonicalResultDigest: 'a'.repeat(64),
    source: identity,
    findingInventoryDigest: inventory,
    visibilityPolicyVersion: visibility.policyVersion,
    visibilityAttestation: visibility.attestation,
  });
};

describe('authenticated GitHub visibility attestation', () => {
  it('binds the bounded cache key to the exact source and inventory', () => {
    expect(visibilityAttestationCacheKey(grant())).not.toBe(
      visibilityAttestationCacheKey(grant('other-repository')),
    );
    expect(visibilityAttestationCacheKey(grant())).not.toBe(
      visibilityAttestationCacheKey(grant('repository', 'c'.repeat(64))),
    );
    expect(visibilityAttestationCacheTtlMs).toBeGreaterThan(0);
    expect(visibilityAttestationCacheTtlMs).toBeLessThanOrEqual(60_000);
    expect(maximumVisibilityAttestationCacheEntries).toBeGreaterThan(0);
  });

  it('sends authenticated revalidation and uses conditional bounded cache refreshes', () => {
    const implementation = readFileSync(
      new URL('./agent-visibility-gate.ts', import.meta.url),
      'utf8',
    );

    expect(implementation).toContain('authorization: `Bearer ${token}`,');
    expect(implementation).toContain("'if-none-match': cached.etag");
    expect(implementation).toContain('httpResponse.status === 304 && cached !== undefined');
    expect(implementation).toContain('while (next.size > maximumVisibilityAttestationCacheEntries)');
  });

  it('retains the transport ETag after decoding a successful response body', () => {
    let callCount = 0;
    let authorization: string | undefined;
    let conditionalEtag: string | undefined;
    const client = HttpClient.make(request => {
      callCount += 1;
      authorization = request.headers['authorization'];
      conditionalEtag = request.headers['if-none-match'];
      return Effect.succeed(HttpClientResponse.fromWeb(
        request,
        callCount === 1
          ? new Response(JSON.stringify({ private: false, full_name: 'owner/repository' }), {
              status: 200,
              headers: {
                'content-type': 'application/vnd.github+json',
                etag: '"visibility-v1"',
              },
            })
          : new Response(null, { status: 304 }),
      ));
    });

    return Effect.runPromise(Effect.gen(function* () {
      const first = yield* verifyVisibilityRemotely(client, 'visibility-token', grant(), undefined);
      expect(first.etag).toBe('"visibility-v1"');
      expect(authorization).toBe('Bearer visibility-token');

      yield* verifyVisibilityRemotely(client, 'visibility-token', grant(), first);
      expect(callCount).toBe(2);
      expect(conditionalEtag).toBe('"visibility-v1"');
    }));
  });
});
