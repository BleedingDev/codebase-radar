import {
  AnalysisIncompleteValue,
  AnalysisViolation,
  CanonicalRepositoryPathSet,
  CompleteAnalyzerRun,
  encodeCanonicalRepositoryPathSet,
  NotApplicableAnalyzerRun,
  RequiredAnalyzerIds,
  type AttemptedAnalyzerRun,
  type SuccessfulAnalyzerRun,
} from '@codebase-radar/contracts';
import { createHash } from 'node:crypto';
import { Schema } from 'effect';
import type { AnalyzerExecution, FindingCandidate } from '../analyzers/index.js';
import { eligiblePathsForAnalyzer } from '../analyzers/applicability.js';
import type { RepositoryInventory } from '../inventory/index.js';

const ViolationCodeOrder = [
  'inventory_truncated',
  'analyzer_missing',
  'analyzer_duplicate',
  'analyzer_partial',
  'analyzer_failed',
  'analyzer_timed_out',
  'analyzer_truncated',
  'coverage_incomplete',
  'finding_inventory_exceeded',
  'runtime_mismatch',
];

const violationForStatus = (status: AttemptedAnalyzerRun['status']) => {
  if (status === 'partial') return 'analyzer_partial';
  if (status === 'failed') return 'analyzer_failed';
  if (status === 'timed_out') return 'analyzer_timed_out';
  if (status === 'truncated') return 'analyzer_truncated';
  return undefined;
};

const compareViolation = (left: AnalysisViolation, right: AnalysisViolation) => {
  const leftAnalyzer =
    left.analyzer === undefined ? -1 : RequiredAnalyzerIds.indexOf(left.analyzer);
  const rightAnalyzer =
    right.analyzer === undefined ? -1 : RequiredAnalyzerIds.indexOf(right.analyzer);
  return (
    leftAnalyzer - rightAnalyzer ||
    ViolationCodeOrder.indexOf(left.code) - ViolationCodeOrder.indexOf(right.code)
  );
};

const selectedAttempts = (executions: ReadonlyArray<AnalyzerExecution>) =>
  RequiredAnalyzerIds.flatMap(analyzer => {
    const attempt = executions.find(execution => execution.run.analyzer === analyzer);
    return attempt === undefined ? [] : [attempt.run];
  });

const pathSetDigest = (paths: ReadonlyArray<string>): string | undefined =>
  Schema.is(CanonicalRepositoryPathSet)(paths)
    ? `sha256:${createHash('sha256').update(encodeCanonicalRepositoryPathSet(paths)).digest('hex')}`
    : undefined;

const asSuccessfulRun = (attempt: AttemptedAnalyzerRun): SuccessfulAnalyzerRun | undefined => {
  if (attempt.status === 'complete') {
    return new CompleteAnalyzerRun({
      analyzer: attempt.analyzer,
      analyzerVersion: attempt.analyzerVersion,
      profileVersion: 'dogfood:max/v1',
      durationMs: attempt.durationMs,
      coverage: attempt.coverage,
      observationCount: attempt.observationCount,
      status: 'complete',
    });
  }
  if (attempt.status === 'not_applicable' && attempt.reason !== undefined) {
    return new NotApplicableAnalyzerRun({
      analyzer: attempt.analyzer,
      analyzerVersion: attempt.analyzerVersion,
      profileVersion: 'dogfood:max/v1',
      durationMs: attempt.durationMs,
      coverage: attempt.coverage,
      observationCount: attempt.observationCount,
      status: 'not_applicable',
      reason: attempt.reason,
    });
  }
  return undefined;
};

export interface PolicyComplete {
  readonly _tag: 'PolicyComplete';
  readonly attempts: ReadonlyArray<AttemptedAnalyzerRun>;
  readonly analyzerRuns: ReadonlyArray<SuccessfulAnalyzerRun>;
  readonly candidates: ReadonlyArray<FindingCandidate>;
}

export interface PolicyIncomplete {
  readonly _tag: 'PolicyIncomplete';
  readonly failure: AnalysisIncompleteValue;
}

export type PolicyDecision = PolicyComplete | PolicyIncomplete;

export const evaluatePolicy = (input: {
  readonly inventory: RepositoryInventory;
  readonly executions: ReadonlyArray<AnalyzerExecution>;
}): PolicyDecision => {
  const attempts = selectedAttempts(input.executions);
  const violations = new Array<AnalysisViolation>();
  if (input.inventory.truncated) {
    violations.push(new AnalysisViolation({ code: 'inventory_truncated' }));
  }
  if (attempts.some(attempt => attempt.profileVersion !== 'dogfood:max/v1')) {
    violations.push(new AnalysisViolation({ code: 'runtime_mismatch' }));
  }
  for (const analyzer of RequiredAnalyzerIds) {
    const matching = input.executions.filter(execution => execution.run.analyzer === analyzer);
    if (matching.length === 0) {
      violations.push(new AnalysisViolation({ code: 'analyzer_missing', analyzer }));
      continue;
    }
    if (matching.length > 1) {
      violations.push(new AnalysisViolation({ code: 'analyzer_duplicate', analyzer }));
    }
    const execution = matching[0];
    if (execution === undefined) continue;
    const attempt = execution.run;
    const expectedEligiblePaths = eligiblePathsForAnalyzer(analyzer, input.inventory);
    const expectedEligibleFiles = expectedEligiblePaths.length;
    const expectedEligiblePathSetDigest = pathSetDigest(expectedEligiblePaths);
    const exactInventoryCoverage =
      attempt.coverage.eligibleFiles === expectedEligibleFiles &&
      attempt.coverage.analyzedFiles === expectedEligibleFiles &&
      expectedEligiblePathSetDigest !== undefined &&
      attempt.coverage.eligiblePathSetDigest === expectedEligiblePathSetDigest &&
      attempt.coverage.analyzedPathSetDigest === expectedEligiblePathSetDigest &&
      attempt.coverage.omittedCapabilities.length === 0;
    const statusViolation = violationForStatus(attempt.status);
    if (statusViolation !== undefined) {
      violations.push(new AnalysisViolation({ code: statusViolation, analyzer }));
      continue;
    }
    if (
      attempt.status === 'complete' &&
      (expectedEligibleFiles === 0 ||
        !exactInventoryCoverage)
    ) {
      violations.push(new AnalysisViolation({ code: 'coverage_incomplete', analyzer }));
    }
    if (
      attempt.status === 'not_applicable' &&
      (expectedEligibleFiles !== 0 ||
        !exactInventoryCoverage ||
        execution.candidates.length > 0 ||
        attempt.observationCount !== 0)
    ) {
      violations.push(new AnalysisViolation({ code: 'coverage_incomplete', analyzer }));
    }
    if (execution.candidates.length > 0 && attempt.observationCount === 0) {
      violations.push(new AnalysisViolation({ code: 'coverage_incomplete', analyzer }));
    }
  }
  if (violations.length > 0) {
    return {
      _tag: 'PolicyIncomplete',
      failure: new AnalysisIncompleteValue({
        analyzerRuns: attempts,
        violations: [...violations].sort(compareViolation),
      }),
    };
  }
  const analyzerRuns = attempts.flatMap(attempt => {
    const successful = asSuccessfulRun(attempt);
    return successful === undefined ? [] : [successful];
  });
  if (analyzerRuns.length !== RequiredAnalyzerIds.length) {
    return {
      _tag: 'PolicyIncomplete',
      failure: new AnalysisIncompleteValue({
        analyzerRuns: attempts,
        violations: RequiredAnalyzerIds.flatMap(analyzer =>
          attempts.some(attempt => attempt.analyzer === analyzer)
            ? []
            : [new AnalysisViolation({ code: 'analyzer_missing', analyzer })],
        ).sort(compareViolation),
      }),
    };
  }
  return {
    _tag: 'PolicyComplete',
    attempts,
    analyzerRuns,
    candidates: input.executions.flatMap(execution => execution.candidates),
  };
};
