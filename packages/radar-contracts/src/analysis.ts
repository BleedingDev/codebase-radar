import { Schema } from 'effect';
import { ContractLimits, OpaqueId } from './primitives.js';
import { AnalysisSource } from './source.js';
import {
  AttemptedAnalyzerRun,
  EmptyRepositoryPathSetDigest,
  PathFreeText,
  RequiredAnalyzer,
  RequiredAnalyzerIds,
  SuccessfulScanResultSchema,
} from './report.js';

const NonEmptyString = Schema.String.check(
  Schema.isTrimmed(),
  Schema.isMinLength(1),
);
const NonNegativeInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
);
const PositiveInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
);
const Percentage = Schema.Finite.check(
  Schema.isBetween({ minimum: 0, maximum: 100 }),
);
const IsoTimestamp = NonEmptyString.check(
  Schema.makeFilter(value => {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
      return 'timestamp must be a millisecond-precision UTC ISO-8601 string';
    }
    const instant = new Date(value);
    return Number.isNaN(instant.getTime()) || instant.toISOString() !== value
      ? 'timestamp must identify a real calendar instant'
      : undefined;
  }),
);

export class AnalysisRequest extends Schema.Class<AnalysisRequest>('AnalysisRequest')({
  scanId: OpaqueId,
  source: AnalysisSource,
  createdAt: IsoTimestamp,
  baseline: Schema.optional(SuccessfulScanResultSchema),
}) {}

export const AnalysisRequestSchema = AnalysisRequest.check(
  Schema.makeFilter(request => {
    if (request.baseline === undefined) return undefined;
    const issues = new Array<Schema.FilterIssue>();
    const codebaseId =
      request.source._tag === 'LocalDirectorySource'
        ? request.source.codebaseId
        : `github:${request.source.owner.toLowerCase()}/${request.source.repository.toLowerCase()}`;
    if (request.baseline.source.codebaseId !== codebaseId) {
      issues.push({
        path: ['baseline', 'source', 'codebaseId'],
        issue: 'baseline must belong to the requested codebase',
      });
    }
    if (request.baseline.scanId === request.scanId) {
      issues.push({
        path: ['baseline', 'scanId'],
        issue: 'a scan may not use itself for its baseline',
      });
    }
    if (request.baseline.completedAt >= request.createdAt) {
      issues.push({
        path: ['baseline', 'completedAt'],
        issue: 'baseline must complete before the requested scan starts',
      });
    }
    return issues;
  }),
);

export const decodeAnalysisRequest = Schema.decodeUnknownEffect(AnalysisRequestSchema, {
  onExcessProperty: 'error',
});

export const AnalysisProgressStage = Schema.Literals([
  'preflight',
  'materializing',
  'inventory',
  'analyzing',
  'prioritizing',
  'comparing',
]);

const ProgressStageOrder: ReadonlyArray<typeof AnalysisProgressStage.Type> = [
  'preflight',
  'materializing',
  'inventory',
  'analyzing',
  'prioritizing',
  'comparing',
];

const progressFields = {
  scanId: OpaqueId,
  sequence: NonNegativeInteger,
  timestamp: IsoTimestamp,
  completedWork: NonNegativeInteger,
  totalWork: PositiveInteger,
  percent: Percentage,
};
const progressPercent = (completedWork: number, totalWork: number) =>
  Math.floor((completedWork / totalWork) * 100);

export class AnalysisProgressUpdate extends Schema.TaggedClass<AnalysisProgressUpdate>()(
  'AnalysisProgressUpdate',
  {
    ...progressFields,
    stage: AnalysisProgressStage,
    terminal: Schema.Literal(false),
  },
) {}

export const AnalysisProgressUpdateSchema = AnalysisProgressUpdate.check(
  Schema.makeFilter(progress => {
    const expectedPercent = progressPercent(
      progress.completedWork,
      progress.totalWork,
    );
    if (progress.completedWork >= progress.totalWork) {
      return {
        path: ['completedWork'],
        issue: 'nonterminal progress must leave work remaining',
      };
    }
    return progress.percent === expectedPercent
      ? undefined
      : {
          path: ['percent'],
          issue: 'percent must be derived from completed and total work',
        };
  }),
);

export class AnalysisProgressTerminal extends Schema.TaggedClass<AnalysisProgressTerminal>()(
  'AnalysisProgressTerminal',
  {
    ...progressFields,
    stage: Schema.Literal('terminal'),
    terminal: Schema.Literal(true),
    outcome: Schema.Literals(['succeeded', 'failed', 'interrupted']),
  },
) {}

export const AnalysisProgressTerminalSchema = AnalysisProgressTerminal.check(
  Schema.makeFilter(progress => {
    if (progress.completedWork > progress.totalWork) {
      return {
        path: ['completedWork'],
        issue: 'completed work must not exceed total work',
      };
    }
    const expectedPercent = progressPercent(
      progress.completedWork,
      progress.totalWork,
    );
    if (progress.percent !== expectedPercent) {
      return {
        path: ['percent'],
        issue: 'percent must be derived from completed and total work',
      };
    }
    if (
      progress.outcome === 'succeeded' &&
      (progress.completedWork !== progress.totalWork || progress.percent !== 100)
    ) {
      return {
          path: ['outcome'],
          issue: 'successful terminal progress must report all work complete',
        };
    }
    return progress.outcome !== 'succeeded' && progress.percent === 100
      ? {
          path: ['percent'],
          issue: 'only successful terminal progress may report one hundred percent',
        }
      : undefined;
  }),
);

export const AnalysisProgress = Schema.Union([
  AnalysisProgressUpdateSchema,
  AnalysisProgressTerminalSchema,
]);
export type AnalysisProgress = typeof AnalysisProgress.Type;

export const isMonotonicProgress = (
  previous: AnalysisProgress,
  next: AnalysisProgress,
) => {
  if (previous._tag === 'AnalysisProgressTerminal') return false;
  const previousStage = ProgressStageOrder.indexOf(previous.stage);
  const nextStage =
    next._tag === 'AnalysisProgressTerminal'
      ? ProgressStageOrder.length
      : ProgressStageOrder.indexOf(next.stage);
  return (
    previous.scanId === next.scanId &&
    next.sequence === previous.sequence + 1 &&
    next.timestamp >= previous.timestamp &&
    next.completedWork >= previous.completedWork &&
    next.totalWork === previous.totalWork &&
    next.percent >= previous.percent &&
    nextStage >= previousStage
  );
};

export const AnalysisProgressStream = Schema.Array(AnalysisProgress).check(
  Schema.isMinLength(1),
  Schema.isMaxLength(ContractLimits.progressEvents),
  Schema.makeFilter(events => {
    const terminals = events.filter(event => event.terminal);
    if (events[0]?.sequence !== 0) {
      return { path: [0, 'sequence'], issue: 'progress sequence must begin at zero' };
    }
    if (terminals.length !== 1 || events.at(-1)?.terminal !== true) {
      return 'progress stream must end with exactly one terminal event';
    }
    for (let index = 1; index < events.length; index += 1) {
      const previous = events[index - 1];
      const next = events[index];
      if (!previous || !next || !isMonotonicProgress(previous, next)) {
        return {
          path: [index],
          issue: 'progress events must be contiguous, monotonic, correlated, and post-terminal free',
        };
      }
    }
    return undefined;
  }),
);

export const decodeAnalysisProgressStream = Schema.decodeUnknownEffect(
  AnalysisProgressStream,
  { onExcessProperty: 'error' },
);

export class AnalysisSourceRejected extends Schema.TaggedErrorClass<AnalysisSourceRejected>()(
  'AnalysisSourceRejected',
  { message: PathFreeText },
) {}

export class AnalysisSourceUnavailable extends Schema.TaggedErrorClass<AnalysisSourceUnavailable>()(
  'AnalysisSourceUnavailable',
  { message: PathFreeText },
) {}

export class AnalysisRuntimeUnavailable extends Schema.TaggedErrorClass<AnalysisRuntimeUnavailable>()(
  'AnalysisRuntimeUnavailable',
  { message: PathFreeText },
) {}

export const AnalysisViolationCode = Schema.Literals([
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
]);

export class AnalysisViolation extends Schema.Class<AnalysisViolation>(
  'AnalysisViolation',
)({
  code: AnalysisViolationCode,
  analyzer: Schema.optional(RequiredAnalyzer),
}) {}

export class AnalysisIncompleteValue extends Schema.TaggedErrorClass<AnalysisIncompleteValue>()(
  'AnalysisIncomplete',
  {
    violations: Schema.Array(AnalysisViolation).check(
      Schema.isMinLength(1),
      Schema.isMaxLength(ContractLimits.violations),
    ),
    analyzerRuns: Schema.Array(AttemptedAnalyzerRun).check(
      Schema.isMaxLength(RequiredAnalyzerIds.length),
    ),
  },
) {}

const ViolationCodeOrder: ReadonlyArray<typeof AnalysisViolationCode.Type> =
  Object.freeze([
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
  ]);

const compareAttempts = (
  left: AttemptedAnalyzerRun,
  right: AttemptedAnalyzerRun,
) => RequiredAnalyzerIds.indexOf(left.analyzer) - RequiredAnalyzerIds.indexOf(right.analyzer);

const compareViolations = (left: AnalysisViolation, right: AnalysisViolation) => {
  const leftAnalyzer = left.analyzer === undefined
    ? -1
    : RequiredAnalyzerIds.indexOf(left.analyzer);
  const rightAnalyzer = right.analyzer === undefined
    ? -1
    : RequiredAnalyzerIds.indexOf(right.analyzer);
  return leftAnalyzer - rightAnalyzer ||
    ViolationCodeOrder.indexOf(left.code) - ViolationCodeOrder.indexOf(right.code);
};

const containsOrderedUniqueValues = <T>(
  values: ReadonlyArray<T>,
  compare: (left: T, right: T) => number,
) => values.every((value, index) => {
  if (index === 0) return true;
  const previous = values[index - 1];
  return previous !== undefined && compare(previous, value) < 0;
});

const violationForStatus = (status: AttemptedAnalyzerRun['status']) => {
  if (status === 'partial') return 'analyzer_partial';
  if (status === 'failed') return 'analyzer_failed';
  if (status === 'timed_out') return 'analyzer_timed_out';
  if (status === 'truncated') return 'analyzer_truncated';
  return undefined;
};

const hasViolation = (
  violations: ReadonlyArray<AnalysisViolation>,
  analyzer: typeof RequiredAnalyzer.Type,
  code: typeof AnalysisViolationCode.Type,
) => violations.some(violation => violation.analyzer === analyzer && violation.code === code);

const hasLocallyIncompleteCoverage = (run: AttemptedAnalyzerRun) => {
  if (run.status === 'complete') {
    return run.coverage.eligibleFiles === 0 ||
      run.coverage.analyzedFiles !== run.coverage.eligibleFiles ||
      run.coverage.omittedCapabilities.length > 0 ||
      run.coverage.eligiblePathSetDigest === EmptyRepositoryPathSetDigest ||
      run.coverage.analyzedPathSetDigest === EmptyRepositoryPathSetDigest ||
      run.coverage.eligiblePathSetDigest !== run.coverage.analyzedPathSetDigest;
  }
  return run.status === 'not_applicable' &&
    (run.coverage.eligibleFiles !== 0 ||
      run.coverage.analyzedFiles !== 0 ||
      run.coverage.eligiblePathSetDigest !== EmptyRepositoryPathSetDigest ||
      run.coverage.analyzedPathSetDigest !== EmptyRepositoryPathSetDigest ||
      run.coverage.omittedCapabilities.length > 0 ||
      run.observationCount !== 0);
};

const canCarryCoverageViolation = (run: AttemptedAnalyzerRun | undefined) =>
  run !== undefined &&
  (run.status === 'complete' || run.status === 'not_applicable');

export const AnalysisIncomplete = AnalysisIncompleteValue.check(
  Schema.makeFilter(incomplete => {
    const issues = new Array<Schema.FilterIssue>();
    const hasRuntimeMismatch = incomplete.violations.some(
      violation => violation.code === 'runtime_mismatch',
    );
    const hasMismatchedAttempt = incomplete.analyzerRuns.some(
      run => run.profileVersion !== 'dogfood:max/v1',
    );
    if (hasRuntimeMismatch !== hasMismatchedAttempt) {
      issues.push({
        path: ['violations'],
        issue: 'runtime mismatch evidence must exactly track attempted policy identity',
      });
    }
    if (!containsOrderedUniqueValues(incomplete.analyzerRuns, compareAttempts)) {
      issues.push({
        path: ['analyzerRuns'],
        issue: 'attempted analyzer evidence must be unique and canonically ordered',
      });
    }
    if (!containsOrderedUniqueValues(incomplete.violations, compareViolations)) {
      issues.push({
        path: ['violations'],
        issue: 'analysis violations must be unique and canonically ordered',
      });
    }

    for (const [index, violation] of incomplete.violations.entries()) {
      const globalViolation =
        violation.code === 'inventory_truncated' ||
        violation.code === 'finding_inventory_exceeded' ||
        violation.code === 'runtime_mismatch';
      if (globalViolation !== (violation.analyzer === undefined)) {
        issues.push({
          path: ['violations', index, 'analyzer'],
          issue: 'violation attribution must match its stable code',
        });
        continue;
      }
      if (violation.analyzer === undefined) continue;
      const run = incomplete.analyzerRuns.find(
        candidate => candidate.analyzer === violation.analyzer,
      );
      if (violation.code === 'analyzer_missing') {
        if (run !== undefined) {
          issues.push({
            path: ['violations', index],
            issue: 'a missing-analyzer violation may not reference an attempted run',
          });
        }
        continue;
      }
      if (violation.code === 'analyzer_duplicate') {
        if (run === undefined) {
          issues.push({
            path: ['violations', index],
            issue: 'a duplicate-analyzer violation requires retained attempt evidence',
          });
        }
        continue;
      }
      const expectedCode = run === undefined ? undefined : violationForStatus(run.status);
      if (violation.code === 'coverage_incomplete') {
        if (!canCarryCoverageViolation(run)) {
          issues.push({
            path: ['violations', index],
            issue: 'coverage violation must reference a complete or not-applicable attempt',
          });
        }
      } else if (expectedCode !== violation.code) {
        issues.push({
          path: ['violations', index],
          issue: 'violation code must match the attributed attempt status',
        });
      }
    }

    for (const [index, run] of incomplete.analyzerRuns.entries()) {
      const statusViolation = violationForStatus(run.status);
      if (
        statusViolation !== undefined &&
        !hasViolation(incomplete.violations, run.analyzer, statusViolation)
      ) {
        issues.push({
          path: ['analyzerRuns', index, 'status'],
          issue: 'an incomplete attempt requires its matching violation',
        });
      }
      const incompleteCoverage = hasLocallyIncompleteCoverage(run);
      if (
        incompleteCoverage &&
        !hasViolation(incomplete.violations, run.analyzer, 'coverage_incomplete')
      ) {
        issues.push({
          path: ['analyzerRuns', index, 'coverage'],
          issue: 'incomplete coverage evidence requires its matching violation',
        });
      }
    }
    for (const analyzer of RequiredAnalyzerIds) {
      const run = incomplete.analyzerRuns.find(candidate => candidate.analyzer === analyzer);
      if (
        run === undefined &&
        !hasViolation(incomplete.violations, analyzer, 'analyzer_missing')
      ) {
        issues.push({
          path: ['analyzerRuns'],
          issue: `missing ${analyzer} attempt requires an attributed violation`,
        });
      }
    }
    return issues;
  }),
);
export type AnalysisIncomplete = typeof AnalysisIncomplete.Type;

export class AnalysisInterrupted extends Schema.TaggedErrorClass<AnalysisInterrupted>()(
  'AnalysisInterrupted',
  { message: PathFreeText },
) {}

export const AnalysisFailure = Schema.Union([
  AnalysisSourceRejected,
  AnalysisSourceUnavailable,
  AnalysisRuntimeUnavailable,
  AnalysisIncomplete,
  AnalysisInterrupted,
]);
export type AnalysisFailure = typeof AnalysisFailure.Type;
