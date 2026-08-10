import {
  AgentPriorityOutput,
  PrioritizationBrief,
  ScanRecord,
  ScanResult,
} from '../shared/domain';

export const prioritizationBrief = (scan: ScanRecord) =>
  scan.result
    ? new PrioritizationBrief({
        schemaVersion: 'codebase-radar.prioritization-brief/v1',
        scanId: scan.id,
        repository: scan.result.repository,
        audience: scan.audience,
        objective:
          'Review every candidate, choose no more than five next decisions, and explain why each deserves attention before the remaining findings.',
        decisionRules: [
          'Prefer direct, corroborated evidence over inference or raw volume.',
          'Keep consequence, reach, confidence, effort, and change risk separate; no composite score proves codebase health.',
          'Use fix now only for a concrete, consequential, high-confidence problem.',
          'Do not let style preferences or duplication counts displace security, reliability, or structural risk.',
          'When evidence is insufficient, ask for investigation instead of inventing impact.',
          'Audience changes wording, never the evidence or ordered decisions.',
        ],
        candidates: scan.result.findings,
        requiredOutput: [
          'An ordered list of finding IDs with fix now, investigate, monitor, or do not fix.',
          'One plain-language reason and one concrete next move for every selected finding.',
          'An explicit list of tempting findings that should not be scheduled now.',
          'Claims the available evidence cannot support.',
        ],
      })
    : undefined;

export const isValidPriorityOutput = (
  scan: ScanResult,
  output: AgentPriorityOutput,
) => {
  const allowed = new Set(scan.findings.map(finding => finding.id));
  const referenced = [
    ...output.orderedItems.map(priority => priority.findingId),
    ...output.notNowFindingIds,
  ];
  return referenced.every(findingId => allowed.has(findingId))
    && new Set(referenced).size === referenced.length;
};
