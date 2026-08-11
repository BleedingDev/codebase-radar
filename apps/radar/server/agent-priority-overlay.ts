import { createHash } from 'node:crypto';
import { Effect, Schema } from 'effect';
import {
  ActionClass,
  AgentPriorityItem,
  AgentPriorityOutput,
  AgentProvider,
  Finding,
  GitHubSourceIdentity,
  OpaqueId,
  PathFreeText,
  SuccessfulScanResult,
} from '../shared/domain';
import type { SourceIdentity } from '../shared/domain';

const PositiveInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
);
const NonNegativeInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
);

export const agentPriorityLegacyUnsupportedClaimLimit = 10;
export const agentPriorityLegacyProseCharacterLimit = 1_000;
export const agentPriorityLegacySummaryCharacterLimit = 1_200;
export const agentPriorityMaximumFindingCount = 1_000;
export const agentPriorityChunkSize = 25;
export const agentPriorityMergeWindowSize = 25;
export const agentPriorityMergeRoundCount = Math.ceil(
  Math.log2(agentPriorityMaximumFindingCount),
);
export const maxAgentPriorityPromptBytes = 128_000;
export const maxAgentPriorityProtocolEnvelopeBytes = 16 * 1_024;
export const maxAgentPriorityRequestPayloadBytes =
  maxAgentPriorityPromptBytes - maxAgentPriorityProtocolEnvelopeBytes;
// The schemas bound Unicode by characters. Reserve four UTF-8 bytes per code
// point for every legal prose field plus the JSON envelope so a valid result
// can never be rejected merely because it used non-ASCII text.
export const maxAgentPriorityOutputBytes = 512 * 1_024;
/**
 * A completed tournament is stored twice: once as the complete overlay and
 * once as the user-facing presentation on the review record. Keep the
 * largest representation comfortably below the database JSON guardrail.
 *
 * This is deliberately an encoded UTF-8 bound, not a JavaScript character
 * count. The provider schemas permit multi-byte prose and a 1,000-finding
 * result can otherwise pass schema validation but fail only after a provider
 * has already disclosed it.
 */
export const maxAgentPriorityAggregateBytes = 7 * 1_024 * 1_024;
export const agentPriorityCompleteUnsupportedClaimLimit =
  Math.ceil(agentPriorityMaximumFindingCount / agentPriorityChunkSize) *
  agentPriorityLegacyUnsupportedClaimLimit;

const BoundedRationale = PathFreeText.check(
  Schema.isMaxLength(agentPriorityLegacyProseCharacterLimit),
);
const BoundedNextMove = PathFreeText.check(
  Schema.isMaxLength(agentPriorityLegacyProseCharacterLimit),
);
const BoundedUnsupportedClaim = PathFreeText.check(
  Schema.isMaxLength(agentPriorityLegacyProseCharacterLimit),
);
const CanonicalDigest = Schema.String.check(
  Schema.isMinLength(64),
  Schema.isMaxLength(64),
);

export const AgentPriorityOverlayErrorCode = Schema.Literals([
  'chunk-metadata-mismatch',
  'chunk-finding-set-mismatch',
  'merge-metadata-mismatch',
  'merge-finding-set-mismatch',
  'canonical-action-mismatch',
  'canonical-digest-mismatch',
  'finding-inventory-mismatch',
  'duplicate-chunk',
  'missing-chunk',
  'unexpected-chunk',
  'global-ordering-mismatch',
  'model-history-incomplete',
  'context-limit-exceeded',
  'aggregate-output-too-large',
]);

export class AgentPriorityOverlayError extends Schema.TaggedErrorClass<AgentPriorityOverlayError>()(
  'AgentPriorityOverlayError',
  {
    code: AgentPriorityOverlayErrorCode,
    message: Schema.String,
  },
) {}

export class AgentSourceUnsupported extends Schema.TaggedErrorClass<AgentSourceUnsupported>()(
  'AgentSourceUnsupported',
  { message: Schema.String },
) {}

export const AgentPriorityOpinionKind = Schema.Literal(
  'unverified-model-opinion',
);

export class AgentPriorityCandidateContext extends Schema.Class<AgentPriorityCandidateContext>(
  'AgentPriorityCandidateContext',
)({
  findingId: OpaqueId,
  canonicalFindingDigest: CanonicalDigest,
  canonicalFinding: Finding,
}) {}

export class AgentPriorityChunkRequest extends Schema.Class<AgentPriorityChunkRequest>(
  'AgentPriorityChunkRequest',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-priority-chunk/v3'),
  scanId: OpaqueId,
  canonicalResultDigest: CanonicalDigest,
  source: GitHubSourceIdentity,
  findingInventoryDigest: CanonicalDigest,
  chunkIndex: NonNegativeInteger,
  chunkCount: PositiveInteger,
  totalFindingCount: NonNegativeInteger,
  candidates: Schema.Array(AgentPriorityCandidateContext).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(agentPriorityChunkSize),
  ),
}) {}

export class AgentPriorityChunkItem extends Schema.Class<AgentPriorityChunkItem>(
  'AgentPriorityChunkItem',
)({
  findingId: OpaqueId,
  canonicalFindingDigest: CanonicalDigest,
  action: ActionClass,
  opinionKind: AgentPriorityOpinionKind,
  rationale: BoundedRationale,
  nextMove: BoundedNextMove,
}) {}

export class AgentPriorityChunkOutput extends Schema.Class<AgentPriorityChunkOutput>(
  'AgentPriorityChunkOutput',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-priority-chunk-output/v3'),
  scanId: OpaqueId,
  canonicalResultDigest: CanonicalDigest,
  source: GitHubSourceIdentity,
  findingInventoryDigest: CanonicalDigest,
  chunkIndex: NonNegativeInteger,
  chunkCount: PositiveInteger,
  totalFindingCount: NonNegativeInteger,
  items: Schema.Array(AgentPriorityChunkItem).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(agentPriorityChunkSize),
  ),
  unsupportedClaims: Schema.Array(BoundedUnsupportedClaim).check(
    Schema.isMaxLength(agentPriorityLegacyUnsupportedClaimLimit),
  ),
}) {}

export class AgentPriorityMergeRequest extends Schema.Class<AgentPriorityMergeRequest>(
  'AgentPriorityMergeRequest',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-priority-merge/v3'),
  scanId: OpaqueId,
  canonicalResultDigest: CanonicalDigest,
  source: GitHubSourceIdentity,
  findingInventoryDigest: CanonicalDigest,
  roundIndex: NonNegativeInteger,
  roundCount: PositiveInteger,
  windowIndex: NonNegativeInteger,
  windowCount: PositiveInteger,
  totalFindingCount: NonNegativeInteger,
  candidates: Schema.Array(AgentPriorityCandidateContext).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(agentPriorityMergeWindowSize),
  ),
}) {}

export class AgentPriorityMergeOrderItem extends Schema.Class<AgentPriorityMergeOrderItem>(
  'AgentPriorityMergeOrderItem',
)({
  findingId: OpaqueId,
  canonicalFindingDigest: CanonicalDigest,
}) {}

export class AgentPriorityMergeOutput extends Schema.Class<AgentPriorityMergeOutput>(
  'AgentPriorityMergeOutput',
)({
  schemaVersion: Schema.Literal('codebase-radar.agent-priority-merge-output/v3'),
  scanId: OpaqueId,
  canonicalResultDigest: CanonicalDigest,
  source: GitHubSourceIdentity,
  findingInventoryDigest: CanonicalDigest,
  roundIndex: NonNegativeInteger,
  roundCount: PositiveInteger,
  windowIndex: NonNegativeInteger,
  windowCount: PositiveInteger,
  totalFindingCount: NonNegativeInteger,
  orderedItems: Schema.Array(AgentPriorityMergeOrderItem).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(agentPriorityMergeWindowSize),
  ),
}) {}

export class AgentPriorityModelHistoryEntry extends Schema.Class<AgentPriorityModelHistoryEntry>(
  'AgentPriorityModelHistoryEntry',
)({
  phase: Schema.Literals(['local', 'merge']),
  roundIndex: NonNegativeInteger,
  windowIndex: NonNegativeInteger,
  rank: NonNegativeInteger,
  windowSize: PositiveInteger,
}) {}

export class AgentPriorityOverlayItem extends Schema.Class<AgentPriorityOverlayItem>(
  'AgentPriorityOverlayItem',
)({
  findingId: OpaqueId,
  canonicalFindingDigest: CanonicalDigest,
  action: ActionClass,
  opinionKind: AgentPriorityOpinionKind,
  rationale: BoundedRationale,
  nextMove: BoundedNextMove,
  modelHistory: Schema.Array(AgentPriorityModelHistoryEntry).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(agentPriorityMergeRoundCount + 1),
  ),
}) {}

export class CompleteAgentPriorityOverlay extends Schema.Class<CompleteAgentPriorityOverlay>(
  'CompleteAgentPriorityOverlay',
)({
  schemaVersion: Schema.Literal('codebase-radar.complete-agent-priority-overlay/v3'),
  scanId: OpaqueId,
  canonicalResultDigest: CanonicalDigest,
  source: GitHubSourceIdentity,
  findingInventoryDigest: CanonicalDigest,
  provider: AgentProvider,
  opinionKind: AgentPriorityOpinionKind,
  orderedItems: Schema.Array(AgentPriorityOverlayItem).check(
    Schema.isMaxLength(agentPriorityMaximumFindingCount),
  ),
  unsupportedClaims: Schema.Array(BoundedUnsupportedClaim).check(
    Schema.isMaxLength(agentPriorityCompleteUnsupportedClaimLimit),
  ),
}) {}

interface TournamentEntry {
  readonly findingId: string;
  readonly modelHistory: ReadonlyArray<AgentPriorityModelHistoryEntry>;
}

interface ValidatedLocalProtocol {
  readonly source: GitHubSourceIdentity;
  readonly canonicalResultDigest: string;
  readonly findingInventoryDigest: string;
  readonly candidateById: ReadonlyMap<string, AgentPriorityCandidateContext>;
  readonly itemById: ReadonlyMap<string, AgentPriorityChunkItem>;
  readonly entries: ReadonlyArray<TournamentEntry>;
}

interface FindingInventoryEntry {
  readonly findingId: string;
  readonly canonicalFindingDigest: string;
}

const overlayError = (
  code: typeof AgentPriorityOverlayErrorCode.Type,
  message: string,
) => new AgentPriorityOverlayError({ code, message });

export const isExactCanonicalSource = (
  left: SourceIdentity,
  right: SourceIdentity,
) => {
  if (left._tag !== right._tag) return false;
  if (left._tag === 'GitHubSourceIdentity') {
    if (right._tag !== 'GitHubSourceIdentity') return false;
    return (
      left.codebaseId === right.codebaseId &&
      left.owner === right.owner &&
      left.repository === right.repository &&
      left.url === right.url &&
      left.commitSha === right.commitSha &&
      left.defaultBranch === right.defaultBranch &&
      left.snapshotDigest === right.snapshotDigest
    );
  }
  if (right._tag !== 'LocalSourceIdentity') return false;
  return (
    left.codebaseId === right.codebaseId &&
    left.repository === right.repository &&
    left.snapshotDigest === right.snapshotDigest &&
    left.commitSha === right.commitSha &&
    left.branch === right.branch &&
    left.dirty === right.dirty
  );
};

const githubSource = (
  scan: SuccessfulScanResult,
): Effect.Effect<GitHubSourceIdentity, AgentSourceUnsupported> =>
  Effect.gen(function* () {
    if (scan.source._tag === 'GitHubSourceIdentity') return scan.source;
    return yield* new AgentSourceUnsupported({
      message:
        'Coding Agent prioritization is available only for hosted GitHub scan snapshots.',
    });
  });

const digest = (value: string) =>
  createHash('sha256').update(value).digest('hex');

export const canonicalFindingDigest = (
  finding: SuccessfulScanResult['findings'][number],
) => digest(JSON.stringify(finding) ?? '');

export const canonicalResultDigest = (scan: SuccessfulScanResult) =>
  digest(JSON.stringify(scan) ?? '');

const canonicalInventoryDigest = (
  entries: ReadonlyArray<FindingInventoryEntry>,
) =>
  digest(
    JSON.stringify(
      entries
        .map(entry => ({
          findingId: entry.findingId,
          canonicalFindingDigest: entry.canonicalFindingDigest,
        }))
        .sort(
          (left, right) =>
            left.findingId.localeCompare(right.findingId) ||
            left.canonicalFindingDigest.localeCompare(right.canonicalFindingDigest),
        ),
    ) ?? '',
  );

export const canonicalFindingInventoryDigest = (scan: SuccessfulScanResult) =>
  canonicalInventoryDigest(
    scan.findings.map(finding => ({
      findingId: finding.id,
      canonicalFindingDigest: canonicalFindingDigest(finding),
    })),
  );

export const canonicalOverlayFindingInventoryDigest = (
  items: ReadonlyArray<AgentPriorityOverlayItem>,
) =>
  canonicalInventoryDigest(
    items.map(item => ({
      findingId: item.findingId,
      canonicalFindingDigest: item.canonicalFindingDigest,
    })),
  );

const candidateContext = (
  finding: SuccessfulScanResult['findings'][number],
) =>
  new AgentPriorityCandidateContext({
    findingId: finding.id,
    canonicalFindingDigest: canonicalFindingDigest(finding),
    canonicalFinding: finding,
  });

const encodedBytes = (value: object) =>
  new TextEncoder().encode(JSON.stringify(value)).byteLength;

export const encodedAgentPriorityRequestBytes = (
  request: AgentPriorityChunkRequest,
) => encodedBytes(request);

export const encodedAgentPriorityMergeRequestBytes = (
  request: AgentPriorityMergeRequest,
) => encodedBytes(request);

export const encodedAgentPriorityAggregateBytes = (
  overlay: CompleteAgentPriorityOverlay,
) => encodedBytes(overlay);

export const encodedAgentPriorityPresentationBytes = (
  output: AgentPriorityOutput,
) => encodedBytes(output);

const scanInventoryIssue = (scan: SuccessfulScanResult) => {
  const findingIds = new Set<string>();
  for (const finding of scan.findings) {
    if (findingIds.has(finding.id)) {
      return overlayError(
        'finding-inventory-mismatch',
        'The immutable scan snapshot contains a duplicate canonical finding ID.',
      );
    }
    findingIds.add(finding.id);
  }
  return undefined;
};

const candidateSetIssue = (
  scan: SuccessfulScanResult,
  candidates: ReadonlyArray<AgentPriorityCandidateContext>,
  message: string,
) => {
  const expectedById = new Map<string, SuccessfulScanResult['findings'][number]>();
  for (const finding of scan.findings) expectedById.set(finding.id, finding);
  const actualIds = new Set<string>();
  for (const candidate of candidates) {
    if (actualIds.has(candidate.findingId)) {
      return overlayError('chunk-finding-set-mismatch', message);
    }
    actualIds.add(candidate.findingId);
    const canonicalFinding = expectedById.get(candidate.findingId);
    if (
      canonicalFinding === undefined ||
      candidate.canonicalFinding.id !== candidate.findingId ||
      canonicalFindingDigest(candidate.canonicalFinding) !==
        candidate.canonicalFindingDigest ||
      canonicalFindingDigest(canonicalFinding) !== candidate.canonicalFindingDigest
    ) {
      return overlayError(
        'canonical-digest-mismatch',
        'The priority protocol request must contain the exact complete canonical Finding.',
      );
    }
  }
  return undefined;
};

const packCandidateWindows = (
  candidates: ReadonlyArray<AgentPriorityCandidateContext>,
  maximumCandidates: number,
  fits: (window: ReadonlyArray<AgentPriorityCandidateContext>) => boolean,
  limitMessage: string,
) => {
  const windows = new Array<Array<AgentPriorityCandidateContext>>();
  let current = new Array<AgentPriorityCandidateContext>();
  for (const candidate of candidates) {
    const next = [...current, candidate];
    if (next.length <= maximumCandidates && fits(next)) {
      current.push(candidate);
      continue;
    }
    if (current.length === 0 || !fits([candidate])) {
      return Effect.fail(overlayError('context-limit-exceeded', limitMessage));
    }
    windows.push(current);
    current = [candidate];
  }
  if (current.length > 0) windows.push(current);
  return Effect.succeed(windows);
};

const chunkRequestFits = (
  scan: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  canonicalResult: string,
  findingInventory: string,
  candidates: ReadonlyArray<AgentPriorityCandidateContext>,
) =>
  encodedBytes({
    schemaVersion: 'codebase-radar.agent-priority-chunk/v3',
    scanId: scan.scanId,
    canonicalResultDigest: canonicalResult,
    source,
    findingInventoryDigest: findingInventory,
    chunkIndex: agentPriorityMaximumFindingCount - 1,
    chunkCount: agentPriorityMaximumFindingCount,
    totalFindingCount: scan.findings.length,
    candidates,
  }) <= maxAgentPriorityRequestPayloadBytes;

export const buildAgentPriorityChunkRequests = (
  scan: SuccessfulScanResult,
) =>
  githubSource(scan).pipe(
    Effect.flatMap(source => Effect.gen(function* () {
      const inventoryIssue = scanInventoryIssue(scan);
      if (inventoryIssue !== undefined) return yield* inventoryIssue;
      if (scan.findings.length === 0) {
        return new Array<AgentPriorityChunkRequest>();
      }
      const canonicalResult = canonicalResultDigest(scan);
      const findingInventory = canonicalFindingInventoryDigest(scan);
      const candidates = scan.findings.map(candidateContext);
      const windows = yield* packCandidateWindows(
        candidates,
        agentPriorityChunkSize,
        window => chunkRequestFits(
          scan,
          source,
          canonicalResult,
          findingInventory,
          window,
        ),
        'One complete canonical Finding exceeds the bounded Coding Agent prompt context.',
      );
      const chunkCount = windows.length;
      const requests = new Array<AgentPriorityChunkRequest>();
      for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const chunkCandidates = windows[chunkIndex];
        if (chunkCandidates === undefined) {
          return yield* overlayError(
            'global-ordering-mismatch',
            'A byte-packed priority chunk is incomplete.',
          );
        }
        const request = new AgentPriorityChunkRequest({
          schemaVersion: 'codebase-radar.agent-priority-chunk/v3',
          scanId: scan.scanId,
          canonicalResultDigest: canonicalResult,
          source,
          findingInventoryDigest: findingInventory,
          chunkIndex,
          chunkCount,
          totalFindingCount: scan.findings.length,
          candidates: chunkCandidates,
        });
        if (encodedAgentPriorityRequestBytes(request) > maxAgentPriorityRequestPayloadBytes) {
          return yield* overlayError(
            'context-limit-exceeded',
            'A byte-packed priority chunk exceeded the provider prompt context limit.',
          );
        }
        requests.push(request);
      }
      return requests;
    })),
  );

export const retryAgentPriorityChunk = <Failure, Requirements>(
  run: () => Effect.Effect<AgentPriorityChunkOutput, Failure, Requirements>,
) => run().pipe(Effect.catch(run));

export const retryAgentPriorityMerge = <Failure, Requirements>(
  run: () => Effect.Effect<AgentPriorityMergeOutput, Failure, Requirements>,
) => run().pipe(Effect.catch(run));

const requestIssue = (
  scan: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  request: AgentPriorityChunkRequest,
  expectedChunkCount: number,
) => {
  if (
    request.scanId !== scan.scanId ||
    request.canonicalResultDigest !== canonicalResultDigest(scan) ||
    !isExactCanonicalSource(request.source, source) ||
    request.findingInventoryDigest !== canonicalFindingInventoryDigest(scan) ||
    request.chunkCount !== expectedChunkCount ||
    request.totalFindingCount !== scan.findings.length
  ) {
    return overlayError(
      'chunk-metadata-mismatch',
      'The priority protocol request does not match this immutable scan snapshot.',
    );
  }
  return undefined;
};

const localOutputIssue = (
  scan: SuccessfulScanResult,
  request: AgentPriorityChunkRequest,
  output: AgentPriorityChunkOutput,
) => {
  if (
    output.scanId !== scan.scanId ||
    output.canonicalResultDigest !== request.canonicalResultDigest ||
    !isExactCanonicalSource(output.source, request.source) ||
    output.findingInventoryDigest !== request.findingInventoryDigest ||
    output.chunkIndex !== request.chunkIndex ||
    output.chunkCount !== request.chunkCount ||
    output.totalFindingCount !== request.totalFindingCount
  ) {
    return overlayError(
      'chunk-metadata-mismatch',
      'The provider returned a chunk for a different immutable scan snapshot.',
    );
  }
  const expectedById = new Map<string, AgentPriorityCandidateContext>();
  for (const candidate of request.candidates) {
    expectedById.set(candidate.findingId, candidate);
  }
  const actualIds = new Set(output.items.map(item => item.findingId));
  if (
    output.items.length !== request.candidates.length ||
    actualIds.size !== output.items.length ||
    actualIds.size !== expectedById.size ||
    [...actualIds].some(findingId => !expectedById.has(findingId))
  ) {
    return overlayError(
      'chunk-finding-set-mismatch',
      'The provider must return every finding ID from exactly one requested chunk.',
    );
  }
  for (const item of output.items) {
    const candidate = expectedById.get(item.findingId);
    if (
      candidate === undefined ||
      candidate.canonicalFinding.action !== item.action
    ) {
      return overlayError(
        'canonical-action-mismatch',
        'The provider may rank finding IDs but may not alter a canonical action class.',
      );
    }
    if (candidate.canonicalFindingDigest !== item.canonicalFindingDigest) {
      return overlayError(
        'canonical-digest-mismatch',
        'The provider must echo the canonical finding digest without modification.',
      );
    }
  }
  return undefined;
};

const validateLocalProtocol = (
  scan: SuccessfulScanResult,
  requests: ReadonlyArray<AgentPriorityChunkRequest>,
  outputs: ReadonlyArray<AgentPriorityChunkOutput>,
) =>
  githubSource(scan).pipe(
    Effect.flatMap(source => {
      const inventoryIssue = scanInventoryIssue(scan);
      if (inventoryIssue !== undefined) return Effect.fail(inventoryIssue);
      if (requests.length !== outputs.length) {
        return Effect.fail(
          overlayError(
            'missing-chunk',
            'Every requested priority chunk must complete before an overlay can be accepted.',
          ),
        );
      }
      if (scan.findings.length === 0 && requests.length !== 0) {
        return Effect.fail(
          overlayError(
            'unexpected-chunk',
            'The empty immutable scan snapshot must not request priority chunks.',
          ),
        );
      }
      if (scan.findings.length > 0 && requests.length === 0) {
        return Effect.fail(
          overlayError(
            'missing-chunk',
            'The priority protocol did not request every canonical Finding.',
          ),
        );
      }
      const expectedChunkCount = requests.length;
      const requestsByIndex = new Map<number, AgentPriorityChunkRequest>();
      const requestedIds = new Set<string>();
      for (const request of requests) {
        const issue = requestIssue(scan, source, request, expectedChunkCount);
        if (issue !== undefined) return Effect.fail(issue);
        if (request.chunkIndex >= expectedChunkCount) {
          return Effect.fail(
            overlayError(
              'unexpected-chunk',
              'The priority protocol request has an invalid chunk index.',
            ),
          );
        }
        if (requestsByIndex.has(request.chunkIndex)) {
          return Effect.fail(
            overlayError('duplicate-chunk', 'The priority protocol contains a duplicate chunk.'),
          );
        }
        const candidateIssue = candidateSetIssue(
          scan,
          request.candidates,
          'The priority protocol request must contain each canonical Finding exactly once.',
        );
        if (candidateIssue !== undefined) return Effect.fail(candidateIssue);
        for (const candidate of request.candidates) {
          if (requestedIds.has(candidate.findingId)) {
            return Effect.fail(
              overlayError(
                'chunk-finding-set-mismatch',
                'The priority protocol requested a canonical Finding more than once.',
              ),
            );
          }
          requestedIds.add(candidate.findingId);
        }
        requestsByIndex.set(request.chunkIndex, request);
      }
      for (let chunkIndex = 0; chunkIndex < expectedChunkCount; chunkIndex += 1) {
        if (!requestsByIndex.has(chunkIndex)) {
          return Effect.fail(
            overlayError(
              'missing-chunk',
              'The priority protocol omitted a byte-packed finding chunk.',
            ),
          );
        }
      }
      if (
        requestedIds.size !== scan.findings.length ||
        scan.findings.some(finding => !requestedIds.has(finding.id))
      ) {
        return Effect.fail(
          overlayError(
            'finding-inventory-mismatch',
            'The priority protocol request inventory does not equal the immutable scan inventory.',
          ),
        );
      }
      const outputsByIndex = new Map<number, AgentPriorityChunkOutput>();
      for (const output of outputs) {
        if (!requestsByIndex.has(output.chunkIndex)) {
          return Effect.fail(
            overlayError('unexpected-chunk', 'The provider returned an unrequested priority chunk.'),
          );
        }
        if (outputsByIndex.has(output.chunkIndex)) {
          return Effect.fail(
            overlayError('duplicate-chunk', 'The provider returned a priority chunk twice.'),
          );
        }
        outputsByIndex.set(output.chunkIndex, output);
      }
      const candidateById = new Map<string, AgentPriorityCandidateContext>();
      const itemById = new Map<string, AgentPriorityChunkItem>();
      const entries = new Array<TournamentEntry>();
      for (let chunkIndex = 0; chunkIndex < expectedChunkCount; chunkIndex += 1) {
        const request = requestsByIndex.get(chunkIndex);
        const output = outputsByIndex.get(chunkIndex);
        if (request === undefined || output === undefined) {
          return Effect.fail(
            overlayError('missing-chunk', 'The provider omitted a requested priority chunk.'),
          );
        }
        const issue = localOutputIssue(scan, request, output);
        if (issue !== undefined) return Effect.fail(issue);
        for (const candidate of request.candidates) {
          candidateById.set(candidate.findingId, candidate);
        }
        for (let rank = 0; rank < output.items.length; rank += 1) {
          const item = output.items[rank];
          if (item === undefined) {
            return Effect.fail(
              overlayError('global-ordering-mismatch', 'A priority chunk is incomplete.'),
            );
          }
          itemById.set(item.findingId, item);
          entries.push({
            findingId: item.findingId,
            modelHistory: [
              new AgentPriorityModelHistoryEntry({
                phase: 'local',
                roundIndex: 0,
                windowIndex: chunkIndex,
                rank,
                windowSize: output.items.length,
              }),
            ],
          });
        }
      }
      const allIds = new Set(entries.map(entry => entry.findingId));
      if (
        entries.length !== scan.findings.length ||
        allIds.size !== scan.findings.length ||
        scan.findings.some(finding => !allIds.has(finding.id))
      ) {
        return Effect.fail(
          overlayError(
            'global-ordering-mismatch',
            'The complete overlay must contain every canonical finding ID exactly once.',
          ),
        );
      }
      return Effect.succeed({
        source,
        canonicalResultDigest: canonicalResultDigest(scan),
        findingInventoryDigest: canonicalFindingInventoryDigest(scan),
        candidateById,
        itemById,
        entries,
      } satisfies ValidatedLocalProtocol);
    }),
  );

const greatestCommonDivisor = (left: number, right: number) => {
  let dividend = Math.abs(left);
  let divisor = Math.abs(right);
  while (divisor !== 0) {
    const remainder = dividend % divisor;
    dividend = divisor;
    divisor = remainder;
  }
  return dividend === 0 ? 1 : dividend;
};

const comparePosition = (
  left: AgentPriorityModelHistoryEntry,
  right: AgentPriorityModelHistoryEntry,
) => left.rank * right.windowSize - right.rank * left.windowSize;

const positionKey = (position: AgentPriorityModelHistoryEntry) => {
  const divisor = greatestCommonDivisor(position.rank, position.windowSize);
  return `${position.rank / divisor}/${position.windowSize / divisor}`;
};

const modelHistoryKey = (entry: TournamentEntry) =>
  entry.modelHistory.map(positionKey).join('|');

export const compareAgentPriorityModelHistories = (
  left: ReadonlyArray<AgentPriorityModelHistoryEntry>,
  right: ReadonlyArray<AgentPriorityModelHistoryEntry>,
) => {
  const greatest = Math.max(left.length, right.length);
  /*
   * A later merge only resolves a tie from an earlier model comparison. Walk
   * history from the local model position forward, so every comparison is a
   * lexicographic comparison of model-derived positions. The old
   * newest-first comparator skipped missing positions, which can make
   * A < B, B < C, and C < A for mixed local/merge histories.
   *
   * A missing later position is itself a protocol fact (the entry did not
   * participate in that model tie-break), not a canonical-ID escape hatch.
   * `hasCompleteModelHistory` rejects any remaining indistinguishable pair.
  */
  for (let index = 0; index < greatest; index += 1) {
    const leftPosition = left[index];
    const rightPosition = right[index];
    if (leftPosition === undefined || rightPosition === undefined) {
      if (leftPosition === rightPosition) continue;
      return leftPosition === undefined ? 1 : -1;
    }
    const comparison = comparePosition(leftPosition, rightPosition);
    if (comparison !== 0) return comparison;
  }
  return 0;
};

const compareTournamentEntries = (
  left: TournamentEntry,
  right: TournamentEntry,
) => compareAgentPriorityModelHistories(left.modelHistory, right.modelHistory);

const sortedTournamentEntries = (entries: ReadonlyArray<TournamentEntry>) =>
  entries.slice().sort(compareTournamentEntries);

const mergeRequestFits = (
  scan: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  canonicalResult: string,
  findingInventory: string,
  candidates: ReadonlyArray<AgentPriorityCandidateContext>,
) =>
  encodedBytes({
    schemaVersion: 'codebase-radar.agent-priority-merge/v3',
    scanId: scan.scanId,
    canonicalResultDigest: canonicalResult,
    source,
    findingInventoryDigest: findingInventory,
    roundIndex: agentPriorityMergeRoundCount - 1,
    roundCount: agentPriorityMergeRoundCount,
    windowIndex: agentPriorityMaximumFindingCount - 1,
    windowCount: agentPriorityMaximumFindingCount,
    totalFindingCount: scan.findings.length,
    candidates,
  }) <= maxAgentPriorityRequestPayloadBytes;

const makeMergeRequests = (
  scan: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  candidateById: ReadonlyMap<string, AgentPriorityCandidateContext>,
  entries: ReadonlyArray<TournamentEntry>,
  roundIndex: number,
): Effect.Effect<ReadonlyArray<AgentPriorityMergeRequest>, AgentPriorityOverlayError> =>
  Effect.gen(function* () {
    const canonicalResult = canonicalResultDigest(scan);
    const findingInventory = canonicalFindingInventoryDigest(scan);
    const groups = new Map<string, Array<AgentPriorityCandidateContext>>();
    for (const entry of entries) {
      const candidate = candidateById.get(entry.findingId);
      if (candidate === undefined) {
        return yield* overlayError(
          'global-ordering-mismatch',
          'The tournament lost complete canonical Finding context.',
        );
      }
      const key = modelHistoryKey(entry);
      const group = groups.get(key);
      if (group === undefined) {
        groups.set(key, [candidate]);
      } else {
        group.push(candidate);
      }
    }
    const windows = new Array<Array<AgentPriorityCandidateContext>>();
    for (const group of groups.values()) {
      if (group.length < 2) continue;
      const packed = yield* packCandidateWindows(
        group,
        agentPriorityMergeWindowSize,
        window => mergeRequestFits(
          scan,
          source,
          canonicalResult,
          findingInventory,
          window,
        ),
        'A complete canonical Finding cannot participate in a bounded merge comparison.',
      );
      windows.push(...packed);
    }
    const requests = new Array<AgentPriorityMergeRequest>();
    for (let windowIndex = 0; windowIndex < windows.length; windowIndex += 1) {
      const candidates = windows[windowIndex];
      if (candidates === undefined || candidates.length === 0) {
        return yield* overlayError(
          'global-ordering-mismatch',
          'The priority tournament merge window is incomplete.',
        );
      }
      const request = new AgentPriorityMergeRequest({
        schemaVersion: 'codebase-radar.agent-priority-merge/v3',
        scanId: scan.scanId,
        canonicalResultDigest: canonicalResult,
        source,
        findingInventoryDigest: findingInventory,
        roundIndex,
        roundCount: agentPriorityMergeRoundCount,
        windowIndex,
        windowCount: windows.length,
        totalFindingCount: scan.findings.length,
        candidates,
      });
      if (encodedAgentPriorityMergeRequestBytes(request) > maxAgentPriorityRequestPayloadBytes) {
        return yield* overlayError(
          'context-limit-exceeded',
          'A byte-packed priority merge window exceeded the provider prompt context limit.',
        );
      }
      requests.push(request);
    }
    return requests;
  });

const mergeOutputIssue = (
  scan: SuccessfulScanResult,
  request: AgentPriorityMergeRequest,
  output: AgentPriorityMergeOutput,
) => {
  if (
    output.scanId !== scan.scanId ||
    output.canonicalResultDigest !== request.canonicalResultDigest ||
    !isExactCanonicalSource(output.source, request.source) ||
    output.findingInventoryDigest !== request.findingInventoryDigest ||
    output.roundIndex !== request.roundIndex ||
    output.roundCount !== request.roundCount ||
    output.windowIndex !== request.windowIndex ||
    output.windowCount !== request.windowCount ||
    output.totalFindingCount !== request.totalFindingCount
  ) {
    return overlayError(
      'merge-metadata-mismatch',
      'The provider returned a merge window for a different immutable scan snapshot.',
    );
  }
  const expectedById = new Map<string, AgentPriorityCandidateContext>();
  for (const candidate of request.candidates) {
    expectedById.set(candidate.findingId, candidate);
  }
  const actualIds = new Set(output.orderedItems.map(item => item.findingId));
  if (
    output.orderedItems.length !== request.candidates.length ||
    actualIds.size !== output.orderedItems.length ||
    actualIds.size !== expectedById.size ||
    [...actualIds].some(findingId => !expectedById.has(findingId))
  ) {
    return overlayError(
      'merge-finding-set-mismatch',
      'The provider must rank every finding ID from exactly one requested merge window.',
    );
  }
  for (const item of output.orderedItems) {
    const candidate = expectedById.get(item.findingId);
    if (
      candidate === undefined ||
      candidate.canonicalFindingDigest !== item.canonicalFindingDigest
    ) {
      return overlayError(
        'canonical-digest-mismatch',
        'The provider must echo the canonical finding digest without modification.',
      );
    }
  }
  return undefined;
};

const applyMergeRound = (
  scan: SuccessfulScanResult,
  source: GitHubSourceIdentity,
  candidateById: ReadonlyMap<string, AgentPriorityCandidateContext>,
  entries: ReadonlyArray<TournamentEntry>,
  roundIndex: number,
  outputs: ReadonlyArray<AgentPriorityMergeOutput>,
) =>
  makeMergeRequests(scan, source, candidateById, entries, roundIndex).pipe(
    Effect.flatMap(requests => {
      if (requests.length !== outputs.length) {
        return Effect.fail(
          overlayError(
            'missing-chunk',
            'Every bounded merge window must complete before an overlay can be accepted.',
          ),
        );
      }
      const requestsByIndex = new Map<number, AgentPriorityMergeRequest>();
      for (const request of requests) {
        if (requestsByIndex.has(request.windowIndex)) {
          return Effect.fail(
            overlayError('duplicate-chunk', 'The merge protocol contains a duplicate window.'),
          );
        }
        requestsByIndex.set(request.windowIndex, request);
      }
      const outputsByIndex = new Map<number, AgentPriorityMergeOutput>();
      for (const output of outputs) {
        if (!requestsByIndex.has(output.windowIndex)) {
          return Effect.fail(
            overlayError('unexpected-chunk', 'The provider returned an unrequested merge window.'),
          );
        }
        if (outputsByIndex.has(output.windowIndex)) {
          return Effect.fail(
            overlayError('duplicate-chunk', 'The provider returned a merge window twice.'),
          );
        }
        outputsByIndex.set(output.windowIndex, output);
      }
      const positionsById = new Map<string, AgentPriorityModelHistoryEntry>();
      for (const request of requests) {
        const output = outputsByIndex.get(request.windowIndex);
        if (output === undefined) {
          return Effect.fail(
            overlayError('missing-chunk', 'The provider omitted a merge window.'),
          );
        }
        const issue = mergeOutputIssue(scan, request, output);
        if (issue !== undefined) return Effect.fail(issue);
        for (let rank = 0; rank < output.orderedItems.length; rank += 1) {
          const item = output.orderedItems[rank];
          if (item === undefined) {
            return Effect.fail(
              overlayError('global-ordering-mismatch', 'A merge window is incomplete.'),
            );
          }
          positionsById.set(
            item.findingId,
            new AgentPriorityModelHistoryEntry({
              phase: 'merge',
              roundIndex,
              windowIndex: request.windowIndex,
              rank,
              windowSize: output.orderedItems.length,
            }),
          );
        }
      }
      const next = new Array<TournamentEntry>();
      for (const entry of entries) {
        const position = positionsById.get(entry.findingId);
        next.push(
          position === undefined
            ? entry
            : { ...entry, modelHistory: [...entry.modelHistory, position] },
        );
      }
      return Effect.succeed(next);
    }),
  );

export const buildAgentPriorityMergeRoundRequests = (
  scan: SuccessfulScanResult,
  requests: ReadonlyArray<AgentPriorityChunkRequest>,
  outputs: ReadonlyArray<AgentPriorityChunkOutput>,
  priorRounds: ReadonlyArray<ReadonlyArray<AgentPriorityMergeOutput>>,
  roundIndex: number,
) =>
  validateLocalProtocol(scan, requests, outputs).pipe(
    Effect.flatMap(protocol => Effect.gen(function* () {
      if (
        !Number.isInteger(roundIndex) ||
        roundIndex < 0 ||
        roundIndex >= agentPriorityMergeRoundCount
      ) {
        return yield* overlayError(
          'merge-metadata-mismatch',
          'The priority tournament requested an invalid merge round.',
        );
      }
      if (priorRounds.length !== roundIndex) {
        return yield* overlayError(
          'merge-metadata-mismatch',
          'The priority tournament merge sequence is incomplete.',
        );
      }
      let entries = protocol.entries;
      for (let index = 0; index < priorRounds.length; index += 1) {
        const prior = priorRounds[index];
        if (prior === undefined) {
          return yield* overlayError(
            'merge-metadata-mismatch',
            'The priority tournament omitted a prior merge round.',
          );
        }
        entries = yield* applyMergeRound(
          scan,
          protocol.source,
          protocol.candidateById,
          entries,
          index,
          prior,
        );
      }
      return yield* makeMergeRequests(
        scan,
        protocol.source,
        protocol.candidateById,
        entries,
        roundIndex,
      );
    })),
  );

const hasCompleteModelHistory = (entries: ReadonlyArray<TournamentEntry>) => {
  const ordered = sortedTournamentEntries(entries);
  for (let index = 1; index < ordered.length; index += 1) {
    const previous = ordered[index - 1];
    const current = ordered[index];
    if (
      previous === undefined ||
      current === undefined ||
      compareTournamentEntries(previous, current) === 0
    ) {
      return false;
    }
  }
  return ordered.every(entry => entry.modelHistory.length > 0);
};

export const aggregateAgentPriorityTournament = (
  scan: SuccessfulScanResult,
  provider: typeof AgentProvider.Type,
  requests: ReadonlyArray<AgentPriorityChunkRequest>,
  outputs: ReadonlyArray<AgentPriorityChunkOutput>,
  mergeRounds: ReadonlyArray<ReadonlyArray<AgentPriorityMergeOutput>>,
) =>
  validateLocalProtocol(scan, requests, outputs).pipe(
    Effect.flatMap(protocol => Effect.gen(function* () {
      if (mergeRounds.length !== agentPriorityMergeRoundCount) {
        return yield* overlayError(
          'missing-chunk',
          'Every bounded merge round must complete before an overlay can be accepted.',
        );
      }
      let entries = protocol.entries;
      for (let index = 0; index < mergeRounds.length; index += 1) {
        const round = mergeRounds[index];
        if (round === undefined) {
          return yield* overlayError(
            'missing-chunk',
            'The priority tournament omitted a bounded merge round.',
          );
        }
        entries = yield* applyMergeRound(
          scan,
          protocol.source,
          protocol.candidateById,
          entries,
          index,
          round,
        );
      }
      if (!hasCompleteModelHistory(entries)) {
        return yield* overlayError(
          'model-history-incomplete',
          'Every canonical Finding needs a complete model-derived history that resolves one total order.',
        );
      }
      const orderedItems = sortedTournamentEntries(entries).map(entry => {
        const item = protocol.itemById.get(entry.findingId);
        const candidate = protocol.candidateById.get(entry.findingId);
        if (item === undefined || candidate === undefined) {
          return undefined;
        }
        return new AgentPriorityOverlayItem({
          findingId: item.findingId,
          canonicalFindingDigest: candidate.canonicalFindingDigest,
          action: item.action,
          opinionKind: item.opinionKind,
          rationale: item.rationale,
          nextMove: item.nextMove,
          modelHistory: entry.modelHistory,
        });
      });
      if (orderedItems.some(item => item === undefined)) {
        return yield* overlayError(
          'global-ordering-mismatch',
          'The validated tournament lost a canonical finding.',
        );
      }
      const completeItems = orderedItems.filter(
        (item): item is AgentPriorityOverlayItem => item !== undefined,
      );
      const completeIds = new Set(completeItems.map(item => item.findingId));
      if (
        completeItems.length !== scan.findings.length ||
        completeIds.size !== scan.findings.length ||
        scan.findings.some(finding => !completeIds.has(finding.id)) ||
        canonicalOverlayFindingInventoryDigest(completeItems) !== protocol.findingInventoryDigest
      ) {
        return yield* overlayError(
          'finding-inventory-mismatch',
          'The complete overlay inventory does not equal the immutable scan inventory.',
        );
      }
      const unsupportedClaims = outputs
        .slice()
        .sort((left, right) => left.chunkIndex - right.chunkIndex)
        .flatMap(output => output.unsupportedClaims);
      if (unsupportedClaims.length > agentPriorityCompleteUnsupportedClaimLimit) {
        return yield* overlayError(
          'global-ordering-mismatch',
          'The provider reported too many unsupported claims for one complete overlay.',
        );
      }
      const overlay = new CompleteAgentPriorityOverlay({
        schemaVersion: 'codebase-radar.complete-agent-priority-overlay/v3',
        scanId: scan.scanId,
        canonicalResultDigest: protocol.canonicalResultDigest,
        source: protocol.source,
        findingInventoryDigest: protocol.findingInventoryDigest,
        provider,
        opinionKind: 'unverified-model-opinion',
        orderedItems: completeItems,
        unsupportedClaims,
      });
      if (encodedAgentPriorityAggregateBytes(overlay) > maxAgentPriorityAggregateBytes) {
        return yield* overlayError(
          'aggregate-output-too-large',
          'The complete priority overlay exceeds the safe UTF-8 storage limit.',
        );
      }
      return overlay;
    })),
  );

export const legacyPriorityOutput = (
  overlay: CompleteAgentPriorityOverlay,
) =>
  encodedAgentPriorityAggregateBytes(overlay) > maxAgentPriorityAggregateBytes
    ? Effect.fail(
        overlayError(
          'aggregate-output-too-large',
          'The complete priority overlay exceeds the safe UTF-8 storage limit.',
        ),
      )
    : Schema.decodeEffect(AgentPriorityOutput, { onExcessProperty: 'error' })({
        opinionKind: 'unverified-model-opinion',
        summary: `An unverified Coding Agent opinion ranked all ${overlay.orderedItems.length} canonical findings; this view includes the complete ordering.`,
        orderedItems: overlay.orderedItems
          .map(
            item =>
              new AgentPriorityItem({
                findingId: item.findingId,
                action: item.action,
                opinionKind: item.opinionKind,
                reason: item.rationale,
                nextMove: item.nextMove,
              }),
        ),
        notNowFindingIds: [],
        unsupportedClaims: overlay.unsupportedClaims,
      }).pipe(
        Effect.flatMap(output =>
          encodedAgentPriorityPresentationBytes(output) <= maxAgentPriorityAggregateBytes
            ? Effect.succeed(output)
            : Effect.fail(
                overlayError(
                  'aggregate-output-too-large',
                  'The priority presentation exceeds the safe UTF-8 storage limit.',
                ),
              ),
        ),
        Effect.mapError(error =>
          error instanceof AgentPriorityOverlayError
            ? error
            : overlayError(
                'global-ordering-mismatch',
                'The validated overlay cannot be converted to the legacy presentation.',
              ),
        ),
      );
