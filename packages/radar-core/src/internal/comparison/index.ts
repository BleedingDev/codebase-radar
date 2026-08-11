import {
  Finding,
  ScanComparison,
  type SuccessfulScanResult,
} from '@codebase-radar/contracts';

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const ordered = (values: ReadonlyArray<string>) => [...new Set(values)].sort(compareText);

const statusFor = (
  finding: Finding,
  previous: ReadonlyMap<string, Finding>,
): Finding['statusComparedToPrevious'] => {
  const earlier = previous.get(finding.fingerprint);
  if (earlier === undefined) return 'new';
  if (finding.scores.priority > earlier.scores.priority + 4) return 'regressed';
  if (finding.scores.priority < earlier.scores.priority - 4) return 'improved';
  return 'persistent';
};

export const compareFindings = (input: {
  readonly findings: ReadonlyArray<Finding>;
  readonly source: SuccessfulScanResult['source'];
  readonly baseline?: SuccessfulScanResult;
}) => {
  const previous = new Map<string, Finding>();
  for (const finding of input.baseline?.findings ?? []) {
    previous.set(finding.fingerprint, finding);
  }
  const findings = input.findings.map(
    finding =>
      new Finding({
        ...finding,
        statusComparedToPrevious: statusFor(finding, previous),
      }),
  );
  const fingerprints = new Set(findings.map(finding => finding.fingerprint));
  const currentPriority = findings.reduce(
    (total, finding) => total + finding.scores.priority,
    0,
  );
  const previousPriority = (input.baseline?.findings ?? []).reduce(
    (total, finding) => total + finding.scores.priority,
    0,
  );
  return {
    findings,
    comparison: new ScanComparison({
      basisCodebaseId: input.source.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      ...(input.baseline === undefined ? {} : { previousScanId: input.baseline.scanId }),
      newFingerprints: ordered(
        findings
          .filter(finding => finding.statusComparedToPrevious === 'new')
          .map(finding => finding.fingerprint),
      ),
      resolvedFingerprints: ordered(
        (input.baseline?.findings ?? [])
          .filter(finding => !fingerprints.has(finding.fingerprint))
          .map(finding => finding.fingerprint),
      ),
      persistentFingerprints: ordered(
        findings
          .filter(finding => finding.statusComparedToPrevious !== 'new')
          .map(finding => finding.fingerprint),
      ),
      priorityDelta:
        input.baseline === undefined ? 0 : currentPriority - previousPriority,
    }),
  };
};
