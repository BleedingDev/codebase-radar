import { Effect, Schema } from 'effect';
import {
  FindingTaskpack,
  GitHubSourceIdentity,
  RepositorySnapshot,
  ScanRecord,
  ScanResult,
  SuccessfulScanResult,
} from '../shared/domain';
import { AgentSourceUnsupported } from './agent-priority-overlay';
import { prioritizationBrief } from './prioritization-brief';

export class AgentScanUnavailable extends Schema.TaggedErrorClass<AgentScanUnavailable>()(
  'AgentScanUnavailable',
  { message: Schema.String },
) {}

export class AgentScanNotComplete extends Schema.TaggedErrorClass<AgentScanNotComplete>()(
  'AgentScanNotComplete',
  { message: Schema.String },
) {}

export class AgentFindingUnavailable extends Schema.TaggedErrorClass<AgentFindingUnavailable>()(
  'AgentFindingUnavailable',
  { message: Schema.String },
) {}

class HostedGitHubResult extends Schema.Class<HostedGitHubResult>(
  'HostedGitHubResult',
)({
  result: SuccessfulScanResult,
  source: GitHubSourceIdentity,
}) {}

type AgentReadFailure =
  | AgentScanUnavailable
  | AgentScanNotComplete
  | AgentSourceUnsupported;

export const requireCompleteScanResult = (
  result: ScanResult,
): Effect.Effect<SuccessfulScanResult, AgentScanNotComplete> =>
  Effect.gen(function* () {
    if (result.resultKind === 'complete') return result;
    return yield* new AgentScanNotComplete({
      message:
        'This legacy-noncanonical scan cannot provide a complete improvement backlog.',
    });
  });

const requireHostedGitHubResult = (
  record: ScanRecord,
): Effect.Effect<HostedGitHubResult, AgentReadFailure> =>
  Effect.gen(function* () {
    if (record.result === undefined) {
      return yield* new AgentScanUnavailable({
        message: 'The requested scan has no completed improvement backlog.',
      });
    }
    const result = yield* requireCompleteScanResult(record.result);
    if (result.source._tag !== 'GitHubSourceIdentity') {
      return yield* new AgentSourceUnsupported({
        message:
          'Hosted MCP and Coding Agent views support GitHub source identities only.',
      });
    }
    return new HostedGitHubResult({ result, source: result.source });
  });

const repositorySnapshot = (source: GitHubSourceIdentity) =>
  new RepositorySnapshot({
    owner: source.owner,
    name: source.repository,
    url: source.url,
    commitSha: source.commitSha,
    defaultBranch: source.defaultBranch,
  });

/**
 * The complete canonical scan is the MCP backlog read model. It returns every
 * Finding unchanged, including canonical mechanism and score information.
 */
export const listImprovementBacklog = (record: ScanRecord) =>
  requireHostedGitHubResult(record).pipe(Effect.map(hosted => hosted.result));

/**
 * A taskpack is derived from one immutable canonical Finding. It does not
 * allow model output to change evidence, scoring, action, or coverage.
 */
export const buildFindingTaskpack = (
  record: ScanRecord,
  findingId: string,
) =>
  requireHostedGitHubResult(record).pipe(
    Effect.flatMap(result =>
      Effect.gen(function* () {
        const finding = result.result.findings.find(
          item => item.id === findingId,
        );
        if (finding === undefined) {
          return yield* new AgentFindingUnavailable({
            message: 'The requested finding is unavailable for this scan.',
          });
        }
        return new FindingTaskpack({
          schemaVersion: 'codebase-radar.taskpack/v1',
          scanId: result.result.scanId,
          repository: repositorySnapshot(result.source),
          finding,
          objective: finding.recommendation,
          acceptanceCriteria: [
            `Address the evidence represented by ${finding.fingerprint}.`,
            'Preserve or improve existing behavior and attributed test coverage.',
            'Run focused verification and report before-and-after evidence.',
          ],
          guardrails: [
            'Inference and advisory links provide context; they do not verify runtime impact.',
            'Inspect callers, blast radius, and affected tests before editing.',
            'Do not broaden the change beyond this finding without maintainer approval.',
          ],
          suggestedInvestigation: finding.evidence.map(evidence =>
            evidence.path
              ? `${evidence.path}${evidence.line === undefined ? '' : `:${evidence.line}`} — ${evidence.message}`
              : evidence.message,
          ),
        });
      }),
    ),
  );

/**
 * Reuses the single presentation builder so MCP and the provider receive the
 * same complete canonical Finding catalog for hosted GitHub scans.
 */
export const buildPrioritizationBrief = (record: ScanRecord) =>
  requireHostedGitHubResult(record).pipe(
    Effect.flatMap(() => {
      const brief = prioritizationBrief(record);
      return brief === undefined
        ? Effect.fail(
            new AgentScanUnavailable({
              message: 'The requested scan has no hosted priority brief.',
            }),
          )
        : Effect.succeed(brief);
    }),
  );

export const completeResultForAgent = (
  result: ScanResult,
): Effect.Effect<SuccessfulScanResult, AgentScanNotComplete> =>
  requireCompleteScanResult(result);
