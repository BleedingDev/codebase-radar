import { describe, expect, it } from 'vitest';
import { AnalyzerCoverage, AnalyzerRun } from '../shared/domain';
import {
  maximalAnalysisViolations,
  requiredAnalyzers,
} from './analysis-policy';

const analyzerRun = (
  analyzer: string,
  overrides: Partial<ConstructorParameters<typeof AnalyzerRun>[0]> = {},
) =>
  new AnalyzerRun({
    analyzer,
    analyzerVersion: '1.0.0',
    profileVersion: 'max/v1',
    status: 'complete',
    durationMs: 1,
    coverage: new AnalyzerCoverage({
      eligibleFiles: 3,
      analyzedFiles: 3,
      omittedCapabilities: [],
      warnings: [],
    }),
    observationCount: 0,
    ...overrides,
  });

const completeRuns = () => requiredAnalyzers.map(analyzer => analyzerRun(analyzer));

describe('dogfood:max analysis policy', () => {
  it('accepts exactly one complete or inapplicable run for every required analyzer', () => {
    const runs = completeRuns();
    runs[0] = analyzerRun('strictest-comparator', {
      status: 'not_applicable',
      coverage: new AnalyzerCoverage({
        eligibleFiles: 0,
        analyzedFiles: 0,
        omittedCapabilities: ['No TypeScript configuration found.'],
        warnings: [],
      }),
    });

    expect(
      maximalAnalysisViolations({
        inventoryTruncated: false,
        analyzerRuns: runs,
      }),
    ).toEqual([]);
  });

  const incompleteStatuses: ReadonlyArray<AnalyzerRun['status']> = [
    'partial',
    'failed',
    'timed_out',
    'truncated',
  ];

  it.each(incompleteStatuses)(
    'rejects a %s required analyzer',
    status => {
      const runs = completeRuns();
      runs[1] = analyzerRun('Oxlint + Ultracite', {
        status,
        diagnostic: 'bounded failure',
      });

      expect(
        maximalAnalysisViolations({
          inventoryTruncated: false,
          analyzerRuns: runs,
        }),
      ).toContain(`${requiredAnalyzers[1]}: ${status} (bounded failure)`);
    },
  );

  it('rejects missing, duplicate, incomplete-coverage, and inventory-truncated scans', () => {
    const runs = completeRuns().slice(1);
    runs[runs.length - 1] = analyzerRun('TraceDecay', {
      coverage: new AnalyzerCoverage({
        eligibleFiles: 3,
        analyzedFiles: 2,
        omittedCapabilities: [],
        warnings: [],
      }),
    });
    runs.push(analyzerRun('Oxlint + Ultracite'));

    expect(
      maximalAnalysisViolations({
        inventoryTruncated: true,
        analyzerRuns: runs,
      }),
    ).toEqual([
      'repository inventory reached its hard file limit',
      'strictest-comparator: required analyzer did not run',
      'Oxlint + Ultracite: analyzer ran 2 times',
      'TraceDecay: analyzed 2/3 eligible files',
    ]);
  });
});
