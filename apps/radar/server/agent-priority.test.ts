import { createHash } from 'node:crypto';
import { Effect, Exit, Ref, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalyzerCoverage,
  CanonicalRepositoryPathSet,
  CompleteAnalyzerRun,
  encodeCanonicalRepositoryPathSet,
  Evidence,
  ExternalReference,
  Finding,
  FindingScores,
  GitHubSourceIdentity,
  RequiredAnalyzerIds,
  RepositoryPathSetDigest,
  ScanComparison,
  ScanProfile,
  ScanSummary,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  agentPriorityMergeRoundCount,
  AgentPriorityChunkItem,
  AgentPriorityChunkOutput,
  AgentPriorityMergeOrderItem,
  AgentPriorityMergeOutput,
  AgentPriorityModelHistoryEntry,
  AgentPriorityOverlayError,
  aggregateAgentPriorityTournament,
  buildAgentPriorityChunkRequests,
  buildAgentPriorityMergeRoundRequests,
  canonicalFindingDigest,
  canonicalFindingInventoryDigest,
  canonicalResultDigest,
  compareAgentPriorityModelHistories,
  CompleteAgentPriorityOverlay,
  encodedAgentPriorityMergeRequestBytes,
  encodedAgentPriorityRequestBytes,
  isExactCanonicalSource,
  legacyPriorityOutput,
  maxAgentPriorityOutputBytes,
  maxAgentPriorityPromptBytes,
  retryAgentPriorityChunk,
  retryAgentPriorityMerge,
} from './agent-priority-overlay';
import {
  agentPriorityMergeOutputSchemaJson,
  agentPriorityOutputSchemaJson,
  encodedAgentPriorityModelInputBytes,
  priorityMergePrompt,
  priorityPrompt,
} from './agent-runtime';

const canonicalPathSetDigest = (paths: ReadonlyArray<string>) =>
  Schema.decodeUnknownSync(RepositoryPathSetDigest)(
    `sha256:${createHash('sha256')
      .update(
        encodeCanonicalRepositoryPathSet(
          Schema.decodeUnknownSync(CanonicalRepositoryPathSet)(paths),
        ),
      )
      .digest('hex')}`,
  );

const completeAnalyzerPathSetDigest = canonicalPathSetDigest(['src/fixture.ts']);

const commitSha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

const source = () =>
  new GitHubSourceIdentity({
    codebaseId: 'github:owner/repository',
    owner: 'Owner',
    repository: 'Repository',
    url: 'https://github.com/Owner/Repository',
    commitSha,
    defaultBranch: 'main',
    snapshotDigest: `git:${commitSha}`,
  });

const finding = (index: number, prefix = 'finding', opaqueIdIndex = index) =>
  new Finding({
    id: `${prefix}-${String(opaqueIdIndex).padStart(4, '0')}`,
    fingerprint: `fingerprint-${String(index).padStart(4, '0')}`,
    mechanism: 'structural dependency cycle',
    title: `Finding ${index}`,
    category: 'architecture',
    action: 'investigate',
    summary: `Inspect finding ${index}.`,
    technicalSummary: `Canonical technical summary for finding ${index}.`,
    recommendation: `Inspect the canonical evidence for finding ${index}.`,
    scores: new FindingScores({
      consequence: 70,
      blastRadius: 60,
      confidence: 80,
      effort: 40,
      changeExposure: 50,
      priority: 68,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: `Canonical evidence for finding ${index}.`,
        path: `src/${index}.ts`,
        line: 1,
      }),
    ],
    externalReferences: [
      new ExternalReference({
        label: 'Canonical advisory',
        url: `https://example.test/findings/${index}`,
        relationship: 'advisory',
        applicability: 'established',
      }),
    ],
    tags: ['architecture', 'evidence-complete'],
    statusComparedToPrevious: 'new',
  });

const runs = () =>
  RequiredAnalyzerIds.map(
    analyzer =>
      new CompleteAnalyzerRun({
        analyzer,
        analyzerVersion: '1.0.0',
        profileVersion: 'dogfood:max/v1',
        status: 'complete',
        durationMs: 1,
        coverage: new AnalyzerCoverage({
          eligibleFiles: 1,
          analyzedFiles: 1,
          eligiblePathSetDigest: completeAnalyzerPathSetDigest,
          analyzedPathSetDigest: completeAnalyzerPathSetDigest,
          omittedCapabilities: [],
          warnings: [],
        }),
        observationCount: 1,
      }),
  );

const successfulScan = (
  count: number,
  prefix = 'finding',
  opaqueIdIndex: (index: number, count: number) => number = index => index,
) => {
  const findings = Array.from({ length: count }, (_, index) =>
    finding(index, prefix, opaqueIdIndex(index, count)),
  );
  const identity = source();
  return new SuccessfulScanResult({
    schemaVersion: 'codebase-radar.scan-result/v2',
    resultKind: 'complete',
    analysisPolicy: 'dogfood:max/v1',
    scanId: 'scan-current',
    source: identity,
    createdAt: '2026-08-11T10:00:00.000Z',
    completedAt: '2026-08-11T10:01:00.000Z',
    profile: new ScanProfile({
      frameworks: ['react'],
      languageCoverage: ['TypeScript'],
      limitations: [],
    }),
    summary: new ScanSummary({
      headline: 'Canonical review ready.',
      healthScore: 80,
      fixNow: 0,
      investigate: count,
      monitor: 0,
      doNotFix: 0,
    }),
    findings,
    analyzerRuns: runs(),
    comparison: new ScanComparison({
      basisCodebaseId: identity.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      newFingerprints: findings.map(item => item.fingerprint),
      resolvedFingerprints: [],
      persistentFingerprints: [],
      priorityDelta: 0,
    }),
  });
};

const requestsFor = (scan: SuccessfulScanResult) =>
  Effect.runSync(buildAgentPriorityChunkRequests(scan));

const chunkOutput = (
  request: ReturnType<typeof requestsFor>[number],
) =>
  new AgentPriorityChunkOutput({
    schemaVersion: 'codebase-radar.agent-priority-chunk-output/v3',
    scanId: request.scanId,
    canonicalResultDigest: request.canonicalResultDigest,
    source: request.source,
    findingInventoryDigest: request.findingInventoryDigest,
    chunkIndex: request.chunkIndex,
    chunkCount: request.chunkCount,
    totalFindingCount: request.totalFindingCount,
    items: request.candidates.map(candidate =>
      new AgentPriorityChunkItem({
        findingId: candidate.findingId,
        canonicalFindingDigest: candidate.canonicalFindingDigest,
        action: candidate.canonicalFinding.action,
        opinionKind: 'unverified-model-opinion',
        rationale: `Model ordering opinion for ${candidate.findingId}.`,
        nextMove: `Inspect canonical evidence for ${candidate.findingId}.`,
      })),
    unsupportedClaims: [],
  });

const mergeOutput = (
  request: ReturnType<typeof mergeRequestsFor>[number],
  reverse = false,
) => {
  const candidates = reverse
    ? request.candidates.slice().reverse()
    : request.candidates;
  return new AgentPriorityMergeOutput({
    schemaVersion: 'codebase-radar.agent-priority-merge-output/v3',
    scanId: request.scanId,
    canonicalResultDigest: request.canonicalResultDigest,
    source: request.source,
    findingInventoryDigest: request.findingInventoryDigest,
    roundIndex: request.roundIndex,
    roundCount: request.roundCount,
    windowIndex: request.windowIndex,
    windowCount: request.windowCount,
    totalFindingCount: request.totalFindingCount,
    orderedItems: candidates.map(candidate =>
      new AgentPriorityMergeOrderItem({
        findingId: candidate.findingId,
        canonicalFindingDigest: candidate.canonicalFindingDigest,
      })),
  });
};

const mergeRequestsFor = (
  scan: SuccessfulScanResult,
  chunks: ReadonlyArray<AgentPriorityChunkOutput>,
  rounds: ReadonlyArray<ReadonlyArray<AgentPriorityMergeOutput>>,
  roundIndex: number,
) =>
  Effect.runSync(
    buildAgentPriorityMergeRoundRequests(
      scan,
      requestsFor(scan),
      chunks,
      rounds,
      roundIndex,
    ),
  );

const completeTournament = (
  scan: SuccessfulScanResult,
  reverseMerges = false,
) => {
  const requests = requestsFor(scan);
  const chunks = requests.map(request => chunkOutput(request));
  const rounds = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
  for (let roundIndex = 0; roundIndex < agentPriorityMergeRoundCount; roundIndex += 1) {
    const mergeRequests = mergeRequestsFor(scan, chunks, rounds, roundIndex);
    rounds.push(mergeRequests.map(request => mergeOutput(request, reverseMerges)));
  }
  return {
    requests,
    chunks,
    rounds,
    exit: Effect.runSyncExit(
      aggregateAgentPriorityTournament(scan, 'codex', requests, chunks, rounds),
    ),
  };
};

const canonicalIndexes = (
  scan: SuccessfulScanResult,
  overlay: CompleteAgentPriorityOverlay,
) =>
  overlay.orderedItems.map(item =>
    scan.findings.findIndex(findingItem => findingItem.id === item.findingId),
  );

describe('complete Coding Agent priority tournament', () => {
  it('keeps every 1,000-finding model call bounded without a full catalog', () => {
    const scan = successfulScan(1_000);
    const requests = requestsFor(scan);
    const chunks = requests.map(request => chunkOutput(request));
    const mergeRequests = new Array<
      ReadonlyArray<ReturnType<typeof mergeRequestsFor>[number]>
    >();
    const mergeOutputs = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
    for (let roundIndex = 0; roundIndex < agentPriorityMergeRoundCount; roundIndex += 1) {
      const round = mergeRequestsFor(scan, chunks, mergeOutputs, roundIndex);
      mergeRequests.push(round);
      mergeOutputs.push(round.map(request => mergeOutput(request)));
    }
    const allMergeRequests = mergeRequests.flatMap(round => round);
    const chunkSchema = agentPriorityOutputSchemaJson();
    const mergeSchema = agentPriorityMergeOutputSchemaJson();
    const resultDigest = canonicalResultDigest(scan);
    const findingInventoryDigest = canonicalFindingInventoryDigest(scan);

    expect(requests).toHaveLength(40);
    expect(requests.every(request => request.candidates.length <= 25)).toBe(true);
    expect(allMergeRequests.every(request => request.candidates.length <= 25)).toBe(true);
    expect(requests.every(request => request.candidates.length < 1_000)).toBe(true);
    expect(allMergeRequests.every(request => request.candidates.length < 1_000)).toBe(true);
    expect(requests.every(request => !Reflect.has(request, 'catalog'))).toBe(true);
    expect(allMergeRequests.every(request => !Reflect.has(request, 'catalog'))).toBe(true);
    const firstCandidate = requests[0]?.candidates[0];
    const firstFinding = scan.findings[0];
    expect(firstCandidate?.canonicalFinding).toEqual(firstFinding);
    expect(firstCandidate?.canonicalFinding.evidence).toHaveLength(1);
    expect(firstCandidate?.canonicalFinding.tags).toEqual([
      'architecture',
      'evidence-complete',
    ]);
    expect(firstCandidate?.canonicalFinding.externalReferences).toHaveLength(1);
    expect(
      requests.every(
        request =>
          request.schemaVersion === 'codebase-radar.agent-priority-chunk/v3' &&
          request.canonicalResultDigest === resultDigest &&
          request.findingInventoryDigest === findingInventoryDigest &&
          isExactCanonicalSource(request.source, scan.source),
      ),
    ).toBe(true);
    expect(
      chunks.every(
        output =>
          output.schemaVersion === 'codebase-radar.agent-priority-chunk-output/v3' &&
          output.canonicalResultDigest === resultDigest &&
          output.findingInventoryDigest === findingInventoryDigest &&
          isExactCanonicalSource(output.source, scan.source),
      ),
    ).toBe(true);
    expect(
      allMergeRequests.every(
        request =>
          request.schemaVersion === 'codebase-radar.agent-priority-merge/v3' &&
          request.canonicalResultDigest === resultDigest &&
          request.findingInventoryDigest === findingInventoryDigest &&
          isExactCanonicalSource(request.source, scan.source),
      ),
    ).toBe(true);
    expect(
      requests.every(request =>
        encodedAgentPriorityRequestBytes(request) <= maxAgentPriorityPromptBytes &&
        encodedAgentPriorityModelInputBytes(priorityPrompt(request), chunkSchema) <=
          maxAgentPriorityPromptBytes),
    ).toBe(true);
    expect(
      allMergeRequests.every(request =>
        encodedAgentPriorityMergeRequestBytes(request) <= maxAgentPriorityPromptBytes &&
        encodedAgentPriorityModelInputBytes(priorityMergePrompt(request), mergeSchema) <=
          maxAgentPriorityPromptBytes),
    ).toBe(true);
  }, 60_000);

  it('produces one exact global permutation from every bounded tournament round', () => {
    const scan = successfulScan(1_000);
    const tournament = completeTournament(scan, true);

    expect(Exit.isSuccess(tournament.exit)).toBe(true);
    if (Exit.isSuccess(tournament.exit)) {
      expect(tournament.exit.value.orderedItems).toHaveLength(1_000);
      expect(new Set(tournament.exit.value.orderedItems.map(item => item.findingId)).size).toBe(1_000);
      expect(canonicalIndexes(scan, tournament.exit.value).every(index => index >= 0)).toBe(
        true,
      );
      expect(tournament.exit.value.schemaVersion).toBe(
        'codebase-radar.complete-agent-priority-overlay/v3',
      );
      expect(tournament.exit.value.canonicalResultDigest).toBe(canonicalResultDigest(scan));
      expect(tournament.exit.value.findingInventoryDigest).toBe(
        canonicalFindingInventoryDigest(scan),
      );
      expect(isExactCanonicalSource(tournament.exit.value.source, scan.source)).toBe(true);
      expect(tournament.exit.value.opinionKind).toBe('unverified-model-opinion');
      const publicOutput = Effect.runSyncExit(
        legacyPriorityOutput(tournament.exit.value),
      );
      expect(Exit.isSuccess(publicOutput)).toBe(true);
      if (Exit.isSuccess(publicOutput)) {
        expect(publicOutput.value.opinionKind).toBe('unverified-model-opinion');
        expect(publicOutput.value.orderedItems).toHaveLength(1_000);
        expect(
          publicOutput.value.orderedItems.every(
            item => item.opinionKind === 'unverified-model-opinion',
          ),
        ).toBe(true);
        expect(publicOutput.value.notNowFindingIds).toEqual([]);
      }
      expect(
        tournament.exit.value.orderedItems.every(
          item =>
            item.opinionKind === 'unverified-model-opinion' &&
            item.modelHistory.length > 0 &&
            item.modelHistory[0]?.phase === 'local',
        ),
      ).toBe(true);
      const orderedItems = tournament.exit.value.orderedItems;
      const hasUnresolvedAdjacentTie = orderedItems
        .slice(1)
        .some((item, index) => {
          const previous = orderedItems[index];
          if (previous === undefined) return true;
          const historyLength = Math.max(
            previous.modelHistory.length,
            item.modelHistory.length,
          );
          for (let historyIndex = historyLength - 1; historyIndex >= 0; historyIndex -= 1) {
            const previousPosition = previous.modelHistory[historyIndex];
            const currentPosition = item.modelHistory[historyIndex];
            if (previousPosition === undefined || currentPosition === undefined) continue;
            if (
              previousPosition.rank * currentPosition.windowSize !==
              currentPosition.rank * previousPosition.windowSize
            ) {
              return false;
            }
          }
          return true;
        });
      expect(hasUnresolvedAdjacentTie).toBe(false);
      expect(Effect.runSync(legacyPriorityOutput(tournament.exit.value)).orderedItems)
        .toHaveLength(1_000);
    }
  }, 60_000);

  it('preserves every bounded unsupported claim in the public projection', () => {
    const scan = successfulScan(25);
    const tournament = completeTournament(scan, true).exit;

    expect(Exit.isSuccess(tournament)).toBe(true);
    if (Exit.isSuccess(tournament)) {
      const claims = Array.from(
        { length: 400 },
        (_, index) => `Unsupported model claim ${index}.`,
      );
      const overlay = new CompleteAgentPriorityOverlay({
        ...tournament.value,
        unsupportedClaims: claims,
      });

      expect(Effect.runSync(legacyPriorityOutput(overlay)).unsupportedClaims).toEqual(claims);
    }
  });

  it('does not use opaque finding-ID spelling to decide rank', () => {
    const first = successfulScan(26, 'opaque-first');
    const second = successfulScan(
      26,
      'opaque-second',
      (index, count) => count - index - 1,
    );
    const firstTournament = completeTournament(first, true);
    const secondTournament = completeTournament(second, true);
    const firstExit = firstTournament.exit;
    const secondExit = secondTournament.exit;

    expect(firstTournament.requests.length).toBeGreaterThan(1);
    expect(secondTournament.requests.length).toBeGreaterThan(1);
    expect(Exit.isSuccess(firstExit)).toBe(true);
    expect(Exit.isSuccess(secondExit)).toBe(true);
    if (Exit.isSuccess(firstExit) && Exit.isSuccess(secondExit)) {
      expect(canonicalIndexes(first, firstExit.value)).toEqual(
        canonicalIndexes(second, secondExit.value),
      );
    }
  });

  it('uses a transitive model-history order when local and merge histories are mixed', () => {
    const local = (rank: number) => new AgentPriorityModelHistoryEntry({
      phase: 'local',
      roundIndex: 0,
      windowIndex: 0,
      rank,
      windowSize: 3,
    });
    const merge = (rank: number) => new AgentPriorityModelHistoryEntry({
      phase: 'merge',
      roundIndex: 0,
      windowIndex: 0,
      rank,
      windowSize: 3,
    });
    const first = [local(1)];
    const second = [local(2), merge(0)];
    const third = [local(0), merge(1)];

    expect(compareAgentPriorityModelHistories(first, second)).toBeLessThan(0);
    expect(compareAgentPriorityModelHistories(second, third)).toBeGreaterThan(0);
    expect(compareAgentPriorityModelHistories(third, first)).toBeLessThan(0);
  });

  it('changes final rank when a validated merge comparison changes', () => {
    const scan = successfulScan(50);
    const normal = completeTournament(scan, false).exit;
    const reversed = completeTournament(scan, true).exit;

    expect(Exit.isSuccess(normal)).toBe(true);
    expect(Exit.isSuccess(reversed)).toBe(true);
    if (Exit.isSuccess(normal) && Exit.isSuccess(reversed)) {
      expect(canonicalIndexes(scan, normal.value)).not.toEqual(
        canonicalIndexes(scan, reversed.value),
      );
    }
  });

  it('uses one bounded merge comparison even when every other window remains unchanged', () => {
    const scan = successfulScan(50);
    const requests = requestsFor(scan);
    const chunks = requests.map(request => chunkOutput(request));
    const normalRounds = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
    const changedRounds = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
    for (let roundIndex = 0; roundIndex < agentPriorityMergeRoundCount; roundIndex += 1) {
      const normalRequests = mergeRequestsFor(scan, chunks, normalRounds, roundIndex);
      normalRounds.push(normalRequests.map(request => mergeOutput(request)));
      const changedRequests = mergeRequestsFor(scan, chunks, changedRounds, roundIndex);
      const outputs = changedRequests.map(request => mergeOutput(request));
      if (roundIndex === 0) {
        const first = outputs[0];
        const one = first?.orderedItems[0];
        const two = first?.orderedItems[1];
        if (first !== undefined && one !== undefined && two !== undefined) {
          outputs[0] = new AgentPriorityMergeOutput({
            ...first,
            orderedItems: [two, one, ...first.orderedItems.slice(2)],
          });
        }
      }
      changedRounds.push(outputs);
    }
    const normal = Effect.runSync(
      aggregateAgentPriorityTournament(scan, 'codex', requests, chunks, normalRounds),
    );
    const changed = Effect.runSync(
      aggregateAgentPriorityTournament(scan, 'codex', requests, chunks, changedRounds),
    );

    expect(canonicalIndexes(scan, changed)).not.toEqual(canonicalIndexes(scan, normal));
  });

  it('rejects malformed, missing, repeated, invented, cross-scan, and source-mutated output', () => {
    const scan = successfulScan(50);
    const requests = requestsFor(scan);
    const first = requests[0];
    const second = requests[1];
    if (first === undefined || second === undefined) return;
    const output = chunkOutput(first);
    const secondOutput = chunkOutput(second);
    const item = output.items[0];
    if (item === undefined) return;
    const repeated = new AgentPriorityChunkOutput({
      ...output,
      items: [item, item],
    });
    const missing = new AgentPriorityChunkOutput({
      ...output,
      items: output.items.slice(1),
    });
    const invented = new AgentPriorityChunkOutput({
      ...output,
      items: [
        new AgentPriorityChunkItem({ ...item, findingId: 'invented-finding' }),
        ...output.items.slice(1),
      ],
    });
    const crossScan = new AgentPriorityChunkOutput({ ...output, scanId: 'other-scan' });
    const malformedResultBinding = new AgentPriorityChunkOutput({
      ...output,
      canonicalResultDigest: 'b'.repeat(64),
    });
    const malformedInventoryBinding = new AgentPriorityChunkOutput({
      ...output,
      findingInventoryDigest: 'c'.repeat(64),
    });
    const changedSources = [
      new GitHubSourceIdentity({ ...output.source, codebaseId: 'github:other/repository' }),
      new GitHubSourceIdentity({ ...output.source, owner: 'Other' }),
      new GitHubSourceIdentity({ ...output.source, repository: 'Different' }),
      new GitHubSourceIdentity({ ...output.source, url: 'https://github.com/Other/Different' }),
      new GitHubSourceIdentity({ ...output.source, commitSha: 'b'.repeat(40) }),
      new GitHubSourceIdentity({ ...output.source, defaultBranch: 'trunk' }),
      new GitHubSourceIdentity({ ...output.source, snapshotDigest: `git:${'b'.repeat(40)}` }),
    ].map(sourceValue => new AgentPriorityChunkOutput({ ...output, source: sourceValue }));

    for (const candidate of [
      repeated,
      missing,
      invented,
      crossScan,
      malformedResultBinding,
      malformedInventoryBinding,
      ...changedSources,
    ]) {
      expect(
        Exit.isFailure(
          Effect.runSyncExit(
            aggregateAgentPriorityTournament(
              scan,
              'codex',
              requests,
              [candidate, secondOutput],
              [],
            ),
          ),
        ),
      ).toBe(true);
    }
  });

  it('rejects canonical field and digest mutation from model output', () => {
    const scan = successfulScan(25);
    const request = requestsFor(scan)[0];
    if (request === undefined) return;
    const output = chunkOutput(request);
    const item = output.items[0];
    if (item === undefined) return;
    const changedAction = new AgentPriorityChunkOutput({
      ...output,
      items: [
        new AgentPriorityChunkItem({ ...item, action: 'fix now' }),
        ...output.items.slice(1),
      ],
    });
    const changedDigest = new AgentPriorityChunkOutput({
      ...output,
      items: [
        new AgentPriorityChunkItem({
          ...item,
          canonicalFindingDigest: 'b'.repeat(64),
        }),
        ...output.items.slice(1),
      ],
    });

    for (const candidate of [changedAction, changedDigest]) {
      expect(
        Exit.isFailure(
          Effect.runSyncExit(
            aggregateAgentPriorityTournament(scan, 'codex', [request], [candidate], []),
          ),
        ),
      ).toBe(true);
    }
  });

  it('requires unverified model-opinion markers and 1,000-character presentation fields', () => {
    const scan = successfulScan(1);
    const request = requestsFor(scan)[0];
    if (request === undefined) return;
    const candidate = request.candidates[0];
    if (candidate === undefined) return;
    const base = {
      findingId: candidate.findingId,
      canonicalFindingDigest: candidate.canonicalFindingDigest,
      action: candidate.canonicalFinding.action,
      opinionKind: 'unverified-model-opinion',
      rationale: 'r'.repeat(1_000),
      nextMove: 'n'.repeat(1_000),
    };
    expect(Exit.isSuccess(Schema.decodeUnknownExit(AgentPriorityChunkItem)(base))).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AgentPriorityChunkItem)({
          ...base,
          rationale: 'r'.repeat(1_001),
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AgentPriorityChunkItem)({
          ...base,
          nextMove: 'n'.repeat(1_200),
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AgentPriorityChunkItem)({
          ...base,
          opinionKind: 'supported-canonical-claim',
        }),
      ),
    ).toBe(true);
  });

  it('reserves enough bytes for every schema-valid Unicode chunk output', () => {
    const scan = successfulScan(25);
    const request = requestsFor(scan)[0];
    if (request === undefined) return;
    const prose = '\u0800'.repeat(1_000);
    const output = new AgentPriorityChunkOutput({
      schemaVersion: 'codebase-radar.agent-priority-chunk-output/v3',
      scanId: request.scanId,
      canonicalResultDigest: request.canonicalResultDigest,
      source: request.source,
      findingInventoryDigest: request.findingInventoryDigest,
      chunkIndex: request.chunkIndex,
      chunkCount: request.chunkCount,
      totalFindingCount: request.totalFindingCount,
      items: request.candidates.map(candidate =>
        new AgentPriorityChunkItem({
          findingId: candidate.findingId,
          canonicalFindingDigest: candidate.canonicalFindingDigest,
          action: candidate.canonicalFinding.action,
          opinionKind: 'unverified-model-opinion',
          rationale: prose,
          nextMove: prose,
        })),
      unsupportedClaims: Array.from({ length: 10 }, () => prose),
    });

    expect(new TextEncoder().encode(JSON.stringify(output)).byteLength)
      .toBeLessThanOrEqual(maxAgentPriorityOutputBytes);
  });

  it('rejects a 1,000-finding Unicode aggregate before it can exceed storage bounds', () => {
    const scan = successfulScan(1_000);
    const requests = requestsFor(scan);
    const prose = '\u0800'.repeat(1_000);
    const chunks = requests.map(request =>
      new AgentPriorityChunkOutput({
        ...chunkOutput(request),
        items: request.candidates.map(candidate =>
          new AgentPriorityChunkItem({
            findingId: candidate.findingId,
            canonicalFindingDigest: candidate.canonicalFindingDigest,
            action: candidate.canonicalFinding.action,
            opinionKind: 'unverified-model-opinion',
            rationale: prose,
            nextMove: prose,
          }),
        ),
        unsupportedClaims: Array.from({ length: 10 }, () => prose),
      }),
    );
    const rounds = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
    for (let roundIndex = 0; roundIndex < agentPriorityMergeRoundCount; roundIndex += 1) {
      const requestsForRound = mergeRequestsFor(scan, chunks, rounds, roundIndex);
      rounds.push(requestsForRound.map(request => mergeOutput(request)));
    }

    expect(
      Exit.isFailure(
        Effect.runSyncExit(
          aggregateAgentPriorityTournament(scan, 'codex', requests, chunks, rounds),
        ),
      ),
    ).toBe(true);
  }, 60_000);

  it('retries bounded local work and still covers all 1,000 findings', () => {
    const scan = successfulScan(1_000);
    const requests = requestsFor(scan);
    const exit = Effect.runSyncExit(
      Effect.gen(function* () {
        const outputs = yield* Effect.forEach(
          requests,
          request =>
            Effect.gen(function* () {
              const attempts = yield* Ref.make(0);
              return yield* retryAgentPriorityChunk(() =>
                Ref.updateAndGet(attempts, count => count + 1).pipe(
                  Effect.flatMap(count =>
                    count === 1
                      ? Effect.fail(
                          new AgentPriorityOverlayError({
                            code: 'missing-chunk',
                            message: 'retry',
                          }),
                        )
                      : Effect.succeed(chunkOutput(request)),
                  ),
                ),
              );
            }),
          { concurrency: 8 },
        );
        return new Set(outputs.flatMap(output => output.items.map(item => item.findingId))).size;
      }),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) expect(exit.value).toBe(1_000);
  });

  it('retries concurrent bounded merge work without losing 1,000-ID coverage', () => {
    const scan = successfulScan(1_000);
    const requests = requestsFor(scan);
    const chunks = requests.map(request => chunkOutput(request));
    const firstRound = mergeRequestsFor(scan, chunks, [], 0);
    const exit = Effect.runSyncExit(
      Effect.gen(function* () {
        const outputs = yield* Effect.forEach(
          firstRound,
          request =>
            Effect.gen(function* () {
              const attempts = yield* Ref.make(0);
              return yield* retryAgentPriorityMerge(() =>
                Ref.updateAndGet(attempts, count => count + 1).pipe(
                  Effect.flatMap(count =>
                    count === 1
                      ? Effect.fail(
                          new AgentPriorityOverlayError({
                            code: 'missing-chunk',
                            message: 'retry',
                          }),
                        )
                      : Effect.succeed(mergeOutput(request)),
                  ),
                ),
              );
            }),
          { concurrency: 8 },
        );
        return new Set(
          outputs.flatMap(output => output.orderedItems.map(item => item.findingId)),
        ).size;
      }),
    );

    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) expect(exit.value).toBe(1_000);
  }, 15_000);

  it('echoes a full canonical finding digest that changes with canonical fields', () => {
    const scan = successfulScan(1);
    const item = scan.findings[0];
    if (item === undefined) return;
    const changed = new Finding({ ...item, mechanism: 'changed mechanism' });
    expect(canonicalFindingDigest(item)).not.toBe(canonicalFindingDigest(changed));
  });
});
