import { AnalyzerRun } from '../shared/domain';

export const maximalAnalysisProfile = 'dogfood:max/v1';

export const requiredAnalyzers = [
  'strictest-comparator',
  'Oxlint + Ultracite',
  'JSCPD',
  'Calldiff',
  'zizmor',
  'OSV-Scanner',
  'TraceDecay',
];

export const maximalAnalysisViolations = (input: {
  readonly inventoryTruncated: boolean;
  readonly analyzerRuns: ReadonlyArray<AnalyzerRun>;
}) => {
  const violations = new Array<string>();
  if (input.inventoryTruncated) {
    violations.push('repository inventory reached its hard file limit');
  }

  const counts = new Map<string, number>();
  for (const run of input.analyzerRuns) {
    counts.set(run.analyzer, (counts.get(run.analyzer) ?? 0) + 1);
  }

  for (const analyzer of requiredAnalyzers) {
    const matching = input.analyzerRuns.filter(run => run.analyzer === analyzer);
    if (matching.length === 0) {
      violations.push(`${analyzer}: required analyzer did not run`);
      continue;
    }
    if (matching.length > 1) {
      violations.push(`${analyzer}: analyzer ran ${matching.length} times`);
      continue;
    }

    const run = matching.at(0);
    if (run === undefined) continue;
    if (run.status !== 'complete' && run.status !== 'not_applicable') {
      violations.push(`${analyzer}: ${run.status}${run.diagnostic ? ` (${run.diagnostic})` : ''}`);
      continue;
    }
    if (
      run.status === 'complete' &&
      run.coverage.analyzedFiles < run.coverage.eligibleFiles
    ) {
      violations.push(
        `${analyzer}: analyzed ${run.coverage.analyzedFiles}/${run.coverage.eligibleFiles} eligible files`,
      );
    }
  }

  for (const [analyzer, count] of counts) {
    if (count > 1 && !requiredAnalyzers.includes(analyzer)) {
      violations.push(`${analyzer}: analyzer ran ${count} times`);
    }
  }

  return violations;
};
