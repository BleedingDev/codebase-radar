import {
  PrioritizationBrief,
  RepositorySnapshot,
  ScanRecord,
  SuccessfulScanResult,
} from '../shared/domain';

const hostedCompleteResult = (scan: ScanRecord) => {
  const result = scan.result;
  return result === undefined ||
    result.resultKind !== 'complete' ||
    result.source._tag !== 'GitHubSourceIdentity'
    ? undefined
    : result;
};

const repositorySnapshot = (scan: SuccessfulScanResult) => {
  const source = scan.source;
  return source._tag !== 'GitHubSourceIdentity'
    ? undefined
    : new RepositorySnapshot({
        owner: source.owner,
        name: source.repository,
        url: source.url,
        commitSha: source.commitSha,
        defaultBranch: source.defaultBranch,
      });
};

export const prioritizationBrief = (scan: ScanRecord) => {
  const result = hostedCompleteResult(scan);
  if (result === undefined) return undefined;
  const repository = repositorySnapshot(result);
  if (repository === undefined) return undefined;
  return new PrioritizationBrief({
    schemaVersion: 'codebase-radar.prioritization-brief/v1',
    scanId: result.scanId,
    repository,
    audience: scan.audience,
    objective:
      'Review the complete canonical Finding catalog. The Coding Agent may create only a validated ordering overlay and bounded rationale; it may not change the deterministic improvement backlog.',
    decisionRules: [
      'Prefer direct, corroborated evidence over inference or raw volume.',
      'Keep consequence, reach, confidence, effort, and change risk separate; no composite score proves codebase health.',
      'Do not change a canonical mechanism, score, action class, evidence record, or analyzer coverage.',
      'Use existing finding IDs only. Do not invent, remove, duplicate, or cross-reference findings from another scan.',
      'When evidence is insufficient, record it under unsupported claims instead of inventing impact.',
      'Audience changes wording, never canonical findings or deterministic ordering.',
    ],
    candidates: result.findings,
    requiredOutput: [
      'The chunk protocol must return every requested finding ID exactly once.',
      'A complete overlay is an exact permutation of all canonical finding IDs.',
      'Every item must echo its canonical action class and include bounded rationale and next move.',
      'Unsupported claims must be explicitly marked and never alter canonical findings.',
    ],
  });
};
