import { Effect, Schema, SchemaParser, SchemaTransformation } from 'effect';
import {
  BoundedTag,
  containsCredentialMaterial,
  containsControlCharacter,
  containsEncodedControlCharacter,
  ContractLimits,
  OpaqueId,
  PathFreeText,
} from './primitives.js';
import {
  CodebaseId,
  SourceIdentity,
} from './source.js';

const NonEmptyString = Schema.String.check(
  Schema.isTrimmed(),
  Schema.isMinLength(1),
);
export { PathFreeText } from './primitives.js';
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
const encodedByteLength = (value: string) => new TextEncoder().encode(value).byteLength;
const encodedResultExceedsLimit = <A>(value: A) => {
  try {
    const serialized = JSON.stringify(value);
    return (
      serialized === undefined ||
      encodedByteLength(serialized) > ContractLimits.encodedResultBytes
    );
  } catch {
    return true;
  }
};

const containsUnpairedSurrogate = (value: string) => {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
};

export const RepositoryPath = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.pathCharacters),
  Schema.makeFilter(value => {
    if (
      containsControlCharacter(value) ||
      containsUnpairedSurrogate(value) ||
      value.includes('\\')
    ) {
      return 'evidence path must use repository-relative forward-slash syntax';
    }
    if (
      value.startsWith('/') ||
      value.startsWith('~/') ||
      /^[A-Za-z]:\//u.test(value)
    ) {
      return 'evidence path must be repository-relative';
    }
    const segments = value.split('/');
    return segments.some(segment => segment === '' || segment === '.' || segment === '..')
      ? 'evidence path contains an unsafe segment'
      : undefined;
  }),
);
const SafeHttpUrl = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.webUrlCharacters),
  Schema.makeFilter(value => {
    if (containsControlCharacter(value) || containsEncodedControlCharacter(value)) {
      return 'external reference URL must not contain control characters';
    }
    if (containsCredentialMaterial(value)) {
      return 'external reference must not contain credentials';
    }
    try {
      const url = new URL(value);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return 'external reference must use HTTP or HTTPS';
      }
      if (url.username || url.password) {
        return 'external reference must not contain credentials';
      }
      return url.href === value
        ? undefined
        : 'external reference URL must already use canonical serialization';
    } catch {
      return 'external reference must be a valid URL';
    }
  }),
);
const CommitSha = NonEmptyString.check(
  Schema.makeFilter(value =>
    /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value)
      ? undefined
      : 'commit must be a complete lowercase hexadecimal object id',
  ),
);

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const utf8 = new TextEncoder();

export const compareCanonicalRepositoryPaths = (left: string, right: string) => {
  const leftBytes = utf8.encode(left);
  const rightBytes = utf8.encode(right);
  const sharedLength = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
};

export const CanonicalRepositoryPathSet = Schema.brand('CanonicalRepositoryPathSet')(
  Schema.Array(RepositoryPath).check(
    Schema.isMaxLength(ContractLimits.semanticAnalyzerInventoryEntries),
    Schema.makeFilter(paths =>
      utf8.encode(JSON.stringify(paths)).byteLength <=
          ContractLimits.semanticAnalyzerRequestBytes
        ? undefined
        : 'canonical repository path-set JSON exceeds the semantic analyzer request byte limit',
    ),
    Schema.makeFilter(paths =>
      paths.every((path, index) => {
        const previous = paths[index - 1];
        return previous === undefined || compareCanonicalRepositoryPaths(previous, path) < 0;
      })
        ? undefined
        : 'repository paths must be unique and in canonical UTF-8 byte order',
    ),
  ),
);
export type CanonicalRepositoryPathSet = typeof CanonicalRepositoryPathSet.Type;

export const encodeCanonicalRepositoryPathSet = (
  paths: CanonicalRepositoryPathSet,
) => utf8.encode(JSON.stringify(paths));

export const RepositoryPathSetDigest = NonEmptyString.check(
  Schema.makeFilter(value =>
    /^sha256:[0-9a-f]{64}$/u.test(value)
      ? undefined
      : 'path-set digest must use canonical lowercase SHA-256 syntax',
  ),
);
export type RepositoryPathSetDigest = typeof RepositoryPathSetDigest.Type;

export const EmptyRepositoryPathSetDigest =
  'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945';

const isCanonicalOrder = <T>(
  values: ReadonlyArray<T>,
  compare: (left: T, right: T) => number,
) =>
  values.every((value, index) => {
    if (index === 0) return true;
    const previous = values[index - 1];
    return previous !== undefined && compare(previous, value) < 0;
  });

const canonicalStrings = (values: ReadonlyArray<string>) =>
  isCanonicalOrder(values, compareText);
const equalStrings = (
  left: ReadonlyArray<string>,
  right: ReadonlyArray<string>,
) =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

export const ScanResultSchemaVersion = 'codebase-radar.scan-result/v2';
const LegacyScanResultSchemaVersion = 'codebase-radar.scan-result/v1';

export const CanonicalAnalysisPolicy = 'dogfood:max/v1';
export const AnalysisPolicyIdentity = Schema.Literal(CanonicalAnalysisPolicy);
export type AnalysisPolicyIdentity = typeof AnalysisPolicyIdentity.Type;

export const RequiredAnalyzer = Schema.Literals([
  'strictest-comparator',
  'Oxlint + Ultracite',
  'JSCPD',
  'Calldiff',
  'zizmor',
  'OSV-Scanner',
  'TraceDecay',
]);

export const RequiredAnalyzerIds: ReadonlyArray<typeof RequiredAnalyzer.Type> =
  Object.freeze([
    'strictest-comparator',
    'Oxlint + Ultracite',
    'JSCPD',
    'Calldiff',
    'zizmor',
    'OSV-Scanner',
    'TraceDecay',
  ]);

export const ActionClass = Schema.Literals([
  'fix now',
  'investigate',
  'monitor',
  'do not fix',
]);
export const AnalyzerStatus = Schema.Literals([
  'complete',
  'partial',
  'not_applicable',
  'failed',
  'timed_out',
  'truncated',
]);
export const Framework = Schema.Literals([
  'react',
  'angular',
  'vue',
  'svelte',
  'solid',
]);
export const FindingCategory = Schema.Literals([
  'security',
  'reliability',
  'maintainability',
  'performance',
  'architecture',
  'configuration',
]);

export class Evidence extends Schema.Class<Evidence>('Evidence')({
  analyzer: RequiredAnalyzer,
  kind: Schema.Literals(['direct', 'strong_proxy', 'context', 'inference']),
  message: PathFreeText,
  ruleId: Schema.optional(PathFreeText),
  path: Schema.optional(RepositoryPath),
  line: Schema.optional(PositiveInteger),
  excerpt: Schema.optional(PathFreeText),
}) {}

export const EvidenceSchema = Evidence.check(
  Schema.makeFilter(evidence =>
    evidence.line !== undefined && evidence.path === undefined
      ? { path: ['line'], issue: 'an evidence line requires a repository path' }
      : undefined,
  ),
);

export const compareEvidence = (left: Evidence, right: Evidence) =>
  compareText(left.analyzer, right.analyzer) ||
  compareText(left.kind, right.kind) ||
  compareCanonicalRepositoryPaths(left.path ?? '', right.path ?? '') ||
  (left.line ?? 0) - (right.line ?? 0) ||
  compareText(left.ruleId ?? '', right.ruleId ?? '') ||
  compareText(left.message, right.message) ||
  compareText(left.excerpt ?? '', right.excerpt ?? '');

export class ExternalReference extends Schema.Class<ExternalReference>(
  'ExternalReference',
)({
  label: PathFreeText,
  url: SafeHttpUrl,
  relationship: Schema.Literals(['advisory', 'background', 'similar_case']),
  applicability: Schema.Literals(['established', 'unverified']),
}) {}

export const compareExternalReferences = (
  left: ExternalReference,
  right: ExternalReference,
) =>
  compareText(left.url, right.url) ||
  compareText(left.label, right.label) ||
  compareText(left.relationship, right.relationship) ||
  compareText(left.applicability, right.applicability);

export class FindingScores extends Schema.Class<FindingScores>('FindingScores')({
  consequence: Percentage,
  blastRadius: Percentage,
  confidence: Percentage,
  effort: Percentage,
  changeExposure: Percentage,
  priority: Percentage,
}) {}

export class Finding extends Schema.Class<Finding>('Finding')({
  id: OpaqueId,
  fingerprint: OpaqueId,
  mechanism: PathFreeText,
  title: PathFreeText,
  category: FindingCategory,
  action: ActionClass,
  summary: PathFreeText,
  technicalSummary: PathFreeText,
  recommendation: PathFreeText,
  scores: FindingScores,
  evidence: Schema.Array(EvidenceSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(ContractLimits.evidencePerFinding),
  ),
  externalReferences: Schema.Array(ExternalReference).check(
    Schema.isMaxLength(ContractLimits.externalReferencesPerFinding),
  ),
  tags: Schema.Array(BoundedTag).check(
    Schema.isMaxLength(ContractLimits.tagsPerFinding),
  ),
  statusComparedToPrevious: Schema.Literals([
    'new',
    'persistent',
    'improved',
    'regressed',
  ]),
}) {}

export const FindingSchema = Finding.check(
  Schema.makeFilter(finding => {
    const issues = new Array<Schema.FilterIssue>();
    if (!isCanonicalOrder(finding.evidence, compareEvidence)) {
      issues.push({ path: ['evidence'], issue: 'evidence must be unique and canonically ordered' });
    }
    if (!isCanonicalOrder(finding.externalReferences, compareExternalReferences)) {
      issues.push({
        path: ['externalReferences'],
        issue: 'external references must be unique and canonically ordered',
      });
    }
    if (!canonicalStrings(finding.tags)) {
      issues.push({ path: ['tags'], issue: 'tags must be unique and canonically ordered' });
    }
    return issues;
  }),
);

export const compareFindings = (left: Finding, right: Finding) =>
  right.scores.priority - left.scores.priority ||
  right.scores.confidence - left.scores.confidence ||
  compareText(left.fingerprint, right.fingerprint);

export class AnalyzerCoverage extends Schema.Class<AnalyzerCoverage>(
  'AnalyzerCoverage',
)({
  eligibleFiles: NonNegativeInteger,
  analyzedFiles: NonNegativeInteger,
  eligiblePathSetDigest: RepositoryPathSetDigest,
  analyzedPathSetDigest: RepositoryPathSetDigest,
  omittedCapabilities: Schema.Array(BoundedTag).check(
    Schema.isMaxLength(ContractLimits.warningsPerAnalyzer),
  ),
  warnings: Schema.Array(PathFreeText).check(
    Schema.isMaxLength(ContractLimits.warningsPerAnalyzer),
  ),
}) {}

const AttemptedAnalyzerCoverageSchema = AnalyzerCoverage.check(
  Schema.makeFilter(coverage => {
    const issues = new Array<Schema.FilterIssue>();
    if (coverage.analyzedFiles > coverage.eligibleFiles) {
      issues.push({
        path: ['analyzedFiles'],
        issue: 'analyzed files must not exceed eligible files',
      });
    }
    if (!canonicalStrings(coverage.omittedCapabilities)) {
      issues.push({
        path: ['omittedCapabilities'],
        issue: 'omitted capabilities must be unique and canonically ordered',
      });
    }
    if (!canonicalStrings(coverage.warnings)) {
      issues.push({ path: ['warnings'], issue: 'warnings must be unique and canonically ordered' });
    }
    return issues;
  }),
);

export const AnalyzerCoverageSchema = AttemptedAnalyzerCoverageSchema.check(
  Schema.makeFilter(coverage => {
    const issues = new Array<Schema.FilterIssue>();
    if (
      (coverage.eligibleFiles === 0) !==
      (coverage.eligiblePathSetDigest === EmptyRepositoryPathSetDigest)
    ) {
      issues.push({
        path: ['eligiblePathSetDigest'],
        issue: 'the eligible path-set digest must prove an empty set exactly when no files are eligible',
      });
    }
    if (
      (coverage.analyzedFiles === 0) !==
      (coverage.analyzedPathSetDigest === EmptyRepositoryPathSetDigest)
    ) {
      issues.push({
        path: ['analyzedPathSetDigest'],
        issue: 'the analyzed path-set digest must prove an empty set exactly when no files were analyzed',
      });
    }
    return issues;
  }),
);

const analyzerRunFields = {
  analyzer: RequiredAnalyzer,
  analyzerVersion: PathFreeText,
  profileVersion: AnalysisPolicyIdentity,
  durationMs: NonNegativeInteger,
  coverage: AnalyzerCoverageSchema,
  observationCount: NonNegativeInteger,
};

export class CompleteAnalyzerRun extends Schema.TaggedClass<CompleteAnalyzerRun>()(
  'CompleteAnalyzerRun',
  {
    status: Schema.Literal('complete'),
    ...analyzerRunFields,
  },
) {}

export const CompleteAnalyzerRunSchema = CompleteAnalyzerRun.check(
  Schema.makeFilter(run => {
    const issues = new Array<Schema.FilterIssue>();
    if (
      run.coverage.eligibleFiles === 0 ||
      run.coverage.analyzedFiles !== run.coverage.eligibleFiles
    ) {
      issues.push({
          path: ['coverage', 'analyzedFiles'],
          issue: 'complete analyzer coverage must include every eligible file and may not be zero',
        });
    }
    if (run.coverage.omittedCapabilities.length > 0) {
      issues.push({
        path: ['coverage', 'omittedCapabilities'],
        issue: 'complete analyzer coverage may not omit capabilities',
      });
    }
    if (
      run.coverage.eligiblePathSetDigest !== run.coverage.analyzedPathSetDigest
    ) {
      issues.push({
        path: ['coverage', 'analyzedPathSetDigest'],
        issue: 'complete analyzer coverage must prove the audited eligible and analyzed path sets are identical',
      });
    }
    if (run.coverage.eligiblePathSetDigest === EmptyRepositoryPathSetDigest) {
      issues.push({
        path: ['coverage', 'eligiblePathSetDigest'],
        issue: 'complete analyzer coverage with eligible files must not prove the empty path set',
      });
    }
    return issues;
  }),
);

export class NotApplicableReason extends Schema.Class<NotApplicableReason>(
  'NotApplicableReason',
)({
  code: Schema.Literals(['no-eligible-input', 'source-not-applicable']),
  message: PathFreeText,
}) {}

export class NotApplicableAnalyzerRun extends Schema.TaggedClass<NotApplicableAnalyzerRun>()(
  'NotApplicableAnalyzerRun',
  {
    status: Schema.Literal('not_applicable'),
    reason: NotApplicableReason,
    ...analyzerRunFields,
  },
) {}

export const NotApplicableAnalyzerRunSchema = NotApplicableAnalyzerRun.check(
  Schema.makeFilter(run =>
    run.coverage.eligibleFiles === 0 &&
    run.coverage.analyzedFiles === 0 &&
    run.coverage.eligiblePathSetDigest === EmptyRepositoryPathSetDigest &&
    run.coverage.analyzedPathSetDigest === EmptyRepositoryPathSetDigest &&
    run.coverage.omittedCapabilities.length === 0 &&
    run.observationCount === 0
      ? undefined
      : {
          path: ['coverage'],
          issue: 'not-applicable analyzer coverage must prove the empty path set with zero observations and omissions',
        },
  ),
);

export const SuccessfulAnalyzerRun = Schema.Union([
  CompleteAnalyzerRunSchema,
  NotApplicableAnalyzerRunSchema,
]);
export type SuccessfulAnalyzerRun = typeof SuccessfulAnalyzerRun.Type;

export class IncompleteAnalyzerRun extends Schema.TaggedClass<IncompleteAnalyzerRun>()(
  'IncompleteAnalyzerRun',
  {
    analyzer: RequiredAnalyzer,
    analyzerVersion: PathFreeText,
    profileVersion: PathFreeText,
    status: Schema.Literals(['partial', 'failed', 'timed_out', 'truncated']),
    durationMs: NonNegativeInteger,
    coverage: AnalyzerCoverageSchema,
    observationCount: NonNegativeInteger,
    diagnostic: PathFreeText,
  },
) {}

export const AnalyzerRun = Schema.Union([
  SuccessfulAnalyzerRun,
  IncompleteAnalyzerRun,
]);
export type AnalyzerRun = typeof AnalyzerRun.Type;

export class AttemptedAnalyzerRunValue extends Schema.TaggedClass<AttemptedAnalyzerRunValue>()(
  'AttemptedAnalyzerRun',
  {
    analyzer: RequiredAnalyzer,
    analyzerVersion: PathFreeText,
    profileVersion: PathFreeText,
    status: AnalyzerStatus,
    durationMs: NonNegativeInteger,
    coverage: AttemptedAnalyzerCoverageSchema,
    observationCount: NonNegativeInteger,
    diagnostic: Schema.optional(PathFreeText),
    reason: Schema.optional(NotApplicableReason),
  },
) {}

export const AttemptedAnalyzerRun = AttemptedAnalyzerRunValue.check(
  Schema.makeFilter(run => {
    const issues = new Array<Schema.FilterIssue>();
    if (run.status === 'not_applicable') {
      if (run.reason === undefined) {
        issues.push({
          path: ['reason'],
          issue: 'a not-applicable attempt requires a structured reason',
        });
      }
    } else if (run.reason !== undefined) {
      issues.push({
        path: ['reason'],
        issue: 'only a not-applicable attempt may carry a not-applicable reason',
      });
    }
    return issues;
  }),
);
export type AttemptedAnalyzerRun = typeof AttemptedAnalyzerRun.Type;

export class ScanComparison extends Schema.Class<ScanComparison>('ScanComparison')({
  basisCodebaseId: CodebaseId,
  basisPolicyId: AnalysisPolicyIdentity,
  previousScanId: Schema.optional(OpaqueId),
  newFingerprints: Schema.Array(OpaqueId).check(
    Schema.isMaxLength(ContractLimits.referencesPerComparisonSet),
  ),
  resolvedFingerprints: Schema.Array(OpaqueId).check(
    Schema.isMaxLength(ContractLimits.referencesPerComparisonSet),
  ),
  persistentFingerprints: Schema.Array(OpaqueId).check(
    Schema.isMaxLength(ContractLimits.referencesPerComparisonSet),
  ),
  priorityDelta: Schema.Finite,
}) {}

export const ScanComparisonSchema = ScanComparison.check(
  Schema.makeFilter(comparison => {
    const issues = new Array<Schema.FilterIssue>();
    if (!canonicalStrings(comparison.newFingerprints)) {
      issues.push({
        path: ['newFingerprints'],
        issue: 'new fingerprints must be unique and canonically ordered',
      });
    }
    if (!canonicalStrings(comparison.resolvedFingerprints)) {
      issues.push({
        path: ['resolvedFingerprints'],
        issue: 'resolved fingerprints must be unique and canonically ordered',
      });
    }
    if (!canonicalStrings(comparison.persistentFingerprints)) {
      issues.push({
        path: ['persistentFingerprints'],
        issue: 'persistent fingerprints must be unique and canonically ordered',
      });
    }
    return issues;
  }),
);

export class RepositorySnapshot extends Schema.Class<RepositorySnapshot>(
  'RepositorySnapshot',
)({
  owner: PathFreeText,
  name: PathFreeText,
  url: SafeHttpUrl,
  commitSha: CommitSha,
  defaultBranch: PathFreeText,
}) {}

export class ScanProfile extends Schema.Class<ScanProfile>('ScanProfile')({
  frameworks: Schema.Array(Framework),
  languageCoverage: Schema.Array(BoundedTag).check(
    Schema.isMaxLength(ContractLimits.languageCoverageEntries),
  ),
  limitations: Schema.Array(PathFreeText).check(
    Schema.isMaxLength(ContractLimits.limitations),
  ),
}) {}

const FrameworkOrder: ReadonlyArray<typeof Framework.Type> = [
  'react',
  'angular',
  'vue',
  'svelte',
  'solid',
];

export const ScanProfileSchema = ScanProfile.check(
  Schema.makeFilter(profile => {
    const issues = new Array<Schema.FilterIssue>();
    if (
      !isCanonicalOrder(
        profile.frameworks,
        (left, right) => FrameworkOrder.indexOf(left) - FrameworkOrder.indexOf(right),
      )
    ) {
      issues.push({ path: ['frameworks'], issue: 'frameworks must be unique and canonically ordered' });
    }
    if (!canonicalStrings(profile.languageCoverage)) {
      issues.push({
        path: ['languageCoverage'],
        issue: 'language coverage must be unique and canonically ordered',
      });
    }
    if (!canonicalStrings(profile.limitations)) {
      issues.push({
        path: ['limitations'],
        issue: 'limitations must be unique and canonically ordered',
      });
    }
    return issues;
  }),
);

export class ScanSummary extends Schema.Class<ScanSummary>('ScanSummary')({
  headline: PathFreeText,
  healthScore: Percentage,
  fixNow: NonNegativeInteger,
  investigate: NonNegativeInteger,
  monitor: NonNegativeInteger,
  doNotFix: NonNegativeInteger,
}) {}

export class SuccessfulScanResult extends Schema.Class<SuccessfulScanResult>(
  'SuccessfulScanResult',
)({
  schemaVersion: Schema.Literal(ScanResultSchemaVersion),
  resultKind: Schema.Literal('complete'),
  analysisPolicy: AnalysisPolicyIdentity,
  scanId: OpaqueId,
  source: SourceIdentity,
  createdAt: IsoTimestamp,
  completedAt: IsoTimestamp,
  profile: ScanProfileSchema,
  summary: ScanSummary,
  findings: Schema.Array(FindingSchema).check(
    Schema.isMaxLength(ContractLimits.findings),
  ),
  analyzerRuns: Schema.Array(SuccessfulAnalyzerRun).check(
    Schema.isMaxLength(RequiredAnalyzerIds.length),
  ),
  comparison: ScanComparisonSchema,
}) {}

const successfulScanResultFilter = Schema.makeFilter<SuccessfulScanResult>(result => {
  const issues = new Array<Schema.FilterIssue>();
  const findingIds = new Set(result.findings.map(finding => finding.id));
  const fingerprints = new Set(result.findings.map(finding => finding.fingerprint));
  if (findingIds.size !== result.findings.length) {
    issues.push({ path: ['findings'], issue: 'finding ids must be unique' });
  }
  if (fingerprints.size !== result.findings.length) {
    issues.push({ path: ['findings'], issue: 'finding fingerprints must be unique' });
  }
  if (!isCanonicalOrder(result.findings, compareFindings)) {
    issues.push({ path: ['findings'], issue: 'findings must use deterministic priority ordering' });
  }

  const counts = {
    fixNow: result.findings.filter(finding => finding.action === 'fix now').length,
    investigate: result.findings.filter(finding => finding.action === 'investigate').length,
    monitor: result.findings.filter(finding => finding.action === 'monitor').length,
    doNotFix: result.findings.filter(finding => finding.action === 'do not fix').length,
  };
  if (
    result.summary.fixNow !== counts.fixNow ||
    result.summary.investigate !== counts.investigate ||
    result.summary.monitor !== counts.monitor ||
    result.summary.doNotFix !== counts.doNotFix
  ) {
    issues.push({ path: ['summary'], issue: 'summary action counts must match findings' });
  }

  const newFingerprints = result.findings
    .filter(finding => finding.statusComparedToPrevious === 'new')
    .map(finding => finding.fingerprint)
    .sort(compareText);
  const persistentFingerprints = result.findings
    .filter(finding => finding.statusComparedToPrevious !== 'new')
    .map(finding => finding.fingerprint)
    .sort(compareText);
  if (!equalStrings(newFingerprints, result.comparison.newFingerprints)) {
    issues.push({
      path: ['comparison', 'newFingerprints'],
      issue: 'new fingerprints must exactly match current finding status',
    });
  }
  if (!equalStrings(persistentFingerprints, result.comparison.persistentFingerprints)) {
    issues.push({
      path: ['comparison', 'persistentFingerprints'],
      issue: 'persistent fingerprints must exactly match current finding status',
    });
  }
  if (result.comparison.resolvedFingerprints.some(fingerprint => fingerprints.has(fingerprint))) {
    issues.push({
      path: ['comparison', 'resolvedFingerprints'],
      issue: 'resolved fingerprints must not occur in current findings',
    });
  }
  if (result.comparison.previousScanId === undefined) {
    if (
      result.comparison.persistentFingerprints.length > 0 ||
      result.comparison.resolvedFingerprints.length > 0 ||
      result.comparison.newFingerprints.length !== result.findings.length
    ) {
      issues.push({
        path: ['comparison'],
        issue: 'a result without a baseline must place every current fingerprint in the new set',
      });
    }
    if (result.comparison.priorityDelta !== 0) {
      issues.push({
        path: ['comparison', 'priorityDelta'],
        issue: 'a result without a baseline must report zero priority delta',
      });
    }
  }
  if (result.comparison.previousScanId === result.scanId) {
    issues.push({
      path: ['comparison', 'previousScanId'],
      issue: 'a result may not compare itself with itself',
    });
  }
  if (result.comparison.basisCodebaseId !== result.source.codebaseId) {
    issues.push({
      path: ['comparison', 'basisCodebaseId'],
      issue: 'comparison codebase must match result source',
    });
  }
  if (result.comparison.basisPolicyId !== result.analysisPolicy) {
    issues.push({
      path: ['comparison', 'basisPolicyId'],
      issue: 'comparison policy must match result policy',
    });
  }
  if (result.completedAt < result.createdAt) {
    issues.push({ path: ['completedAt'], issue: 'completion must not precede creation' });
  }
  if (result.analysisPolicy !== CanonicalAnalysisPolicy) {
    issues.push({
      path: ['analysisPolicy'],
      issue: 'successful results must identify the canonical dogfood:max/v1 policy',
    });
  }
  const analyzerIds = result.analyzerRuns.map(run => run.analyzer);
  if (
    analyzerIds.length !== RequiredAnalyzerIds.length ||
    analyzerIds.some((analyzer, index) => analyzer !== RequiredAnalyzerIds[index])
  ) {
    issues.push({
      path: ['analyzerRuns'],
      issue: 'successful analyzer runs must contain the exact policy set in canonical order',
    });
  }
  for (const [runIndex, run] of result.analyzerRuns.entries()) {
    if (
      run.profileVersion !== CanonicalAnalysisPolicy ||
      run.profileVersion !== result.analysisPolicy
    ) {
      issues.push({
        path: ['analyzerRuns', runIndex, 'profileVersion'],
        issue: 'every successful analyzer run must identify the canonical dogfood:max/v1 policy',
      });
    }
  }
  for (const [findingIndex, finding] of result.findings.entries()) {
    for (const [evidenceIndex, evidence] of finding.evidence.entries()) {
      const run = result.analyzerRuns.find(
        candidate => candidate.analyzer === evidence.analyzer,
      );
      if (
        run === undefined ||
        run.status !== 'complete' ||
        run.observationCount === 0
      ) {
        issues.push({
          path: ['findings', findingIndex, 'evidence', evidenceIndex, 'analyzer'],
          issue: 'finding evidence requires a complete observation-bearing analyzer run',
        });
      }
    }
  }
  if (encodedResultExceedsLimit(result)) {
    issues.push({
      path: [],
      issue: 'encoded scan result exceeds the contract byte limit',
    });
  }
  return issues;
});

export const SuccessfulScanResultSchema = SuccessfulScanResult.check(
  successfulScanResultFilter,
);
export const ScanResultV2 = SuccessfulScanResultSchema;
export type ScanResultV2 = typeof ScanResultV2.Type;

class LegacyEvidenceV1 extends Schema.Class<LegacyEvidenceV1>('LegacyEvidenceV1')({
  analyzer: Schema.String,
  kind: Schema.Literals(['direct', 'strong_proxy', 'context', 'inference']),
  message: Schema.String,
  ruleId: Schema.optional(Schema.String),
  path: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  excerpt: Schema.optional(Schema.String),
}) {}

class LegacyExternalReferenceV1 extends Schema.Class<LegacyExternalReferenceV1>(
  'LegacyExternalReferenceV1',
)({
  label: Schema.String,
  url: Schema.String,
  relationship: Schema.Literals(['advisory', 'background', 'similar_case']),
  applicability: Schema.Literals(['established', 'unverified']),
}) {}

class LegacyFindingScoresV1 extends Schema.Class<LegacyFindingScoresV1>(
  'LegacyFindingScoresV1',
)({
  consequence: Schema.Number,
  blastRadius: Schema.Number,
  confidence: Schema.Number,
  effort: Schema.Number,
  changeExposure: Schema.Number,
  priority: Schema.Number,
}) {}

class LegacyFindingV1 extends Schema.Class<LegacyFindingV1>('LegacyFindingV1')({
  id: Schema.String,
  fingerprint: Schema.String,
  mechanism: Schema.optional(Schema.String),
  title: Schema.String,
  category: FindingCategory,
  action: ActionClass,
  summary: Schema.String,
  technicalSummary: Schema.String,
  recommendation: Schema.String,
  scores: LegacyFindingScoresV1,
  evidence: Schema.Array(LegacyEvidenceV1),
  externalReferences: Schema.Array(LegacyExternalReferenceV1),
  tags: Schema.Array(Schema.String),
  statusComparedToPrevious: Schema.Literals([
    'new',
    'persistent',
    'improved',
    'regressed',
  ]),
}) {}

class LegacyAnalyzerCoverageV1 extends Schema.Class<LegacyAnalyzerCoverageV1>(
  'LegacyAnalyzerCoverageV1',
)({
  eligibleFiles: Schema.Number,
  analyzedFiles: Schema.Number,
  omittedCapabilities: Schema.Array(Schema.String),
  warnings: Schema.Array(Schema.String),
}) {}

class LegacyAnalyzerRunV1 extends Schema.Class<LegacyAnalyzerRunV1>(
  'LegacyAnalyzerRunV1',
)({
  analyzer: Schema.String,
  analyzerVersion: Schema.String,
  profileVersion: Schema.String,
  status: AnalyzerStatus,
  durationMs: Schema.Number,
  coverage: LegacyAnalyzerCoverageV1,
  observationCount: Schema.Number,
  diagnostic: Schema.optional(Schema.String),
}) {}

class LegacyScanComparisonV1 extends Schema.Class<LegacyScanComparisonV1>(
  'LegacyScanComparisonV1',
)({
  previousScanId: Schema.optional(Schema.String),
  newFindingIds: Schema.Array(Schema.String),
  resolvedFingerprints: Schema.Array(Schema.String),
  persistentFindingIds: Schema.Array(Schema.String),
  priorityDelta: Schema.Number,
}) {}

class LegacyScanProfileV1 extends Schema.Class<LegacyScanProfileV1>(
  'LegacyScanProfileV1',
)({
  version: Schema.String,
  frameworks: Schema.Array(Framework),
  languageCoverage: Schema.Array(Schema.String),
  limitations: Schema.Array(Schema.String),
}) {}

class LegacyRepositorySnapshotV1 extends Schema.Class<LegacyRepositorySnapshotV1>(
  'LegacyRepositorySnapshotV1',
)({
  owner: Schema.String,
  name: Schema.String,
  url: Schema.String,
  commitSha: Schema.String,
  defaultBranch: Schema.String,
}) {}

class LegacyScanSummaryV1 extends Schema.Class<LegacyScanSummaryV1>(
  'LegacyScanSummaryV1',
)({
  headline: Schema.String,
  healthScore: Schema.Number,
  fixNow: Schema.Number,
  investigate: Schema.Number,
  monitor: Schema.Number,
  doNotFix: Schema.Number,
}) {}

class LegacyScanResultV1 extends Schema.Class<LegacyScanResultV1>(
  'LegacyScanResultV1',
)({
  schemaVersion: Schema.Literal(LegacyScanResultSchemaVersion),
  scanId: Schema.String,
  repository: LegacyRepositorySnapshotV1,
  createdAt: Schema.String,
  completedAt: Schema.String,
  profile: LegacyScanProfileV1,
  summary: LegacyScanSummaryV1,
  findings: Schema.Array(LegacyFindingV1),
  analyzerRuns: Schema.Array(LegacyAnalyzerRunV1),
  comparison: LegacyScanComparisonV1,
}) {}

class LegacyGitHubSourceIdentity extends Schema.TaggedClass<LegacyGitHubSourceIdentity>()(
  'LegacyGitHubSourceIdentity',
  {
    codebaseId: NonEmptyString,
    owner: NonEmptyString,
    repository: NonEmptyString,
    url: NonEmptyString,
    commitSha: NonEmptyString,
    defaultBranch: NonEmptyString,
    snapshotDigest: NonEmptyString,
  },
) {}

export class LegacyScanResult extends Schema.Class<LegacyScanResult>(
  'LegacyScanResult',
)({
  schemaVersion: Schema.Literal(ScanResultSchemaVersion),
  resultKind: Schema.Literal('legacy-noncanonical'),
  legacyProfileVersion: Schema.String,
  legacyReason: NonEmptyString,
  scanId: Schema.String,
  source: LegacyGitHubSourceIdentity,
  createdAt: Schema.String,
  completedAt: Schema.String,
  profile: LegacyScanProfileV1,
  summary: LegacyScanSummaryV1,
  findings: Schema.Array(LegacyFindingV1),
  analyzerRuns: Schema.Array(LegacyAnalyzerRunV1),
  comparison: LegacyScanComparisonV1,
}) {}

export const ScanResult = Schema.Union([
  SuccessfulScanResultSchema,
  LegacyScanResult,
]).check(
  Schema.makeFilter(result =>
    encodedResultExceedsLimit(result)
      ? {
          path: [],
          issue: 'encoded scan result exceeds the contract byte limit',
        }
      : undefined,
  ),
);
export type ScanResult = typeof ScanResult.Type;

const migrateLegacyScanResult = (legacy: LegacyScanResultV1): ScanResult => {
  const codebaseId = `github:${legacy.repository.owner.toLowerCase()}/${legacy.repository.name.toLowerCase()}`;
  const legacySource = new LegacyGitHubSourceIdentity({
    codebaseId,
    owner: legacy.repository.owner,
    repository: legacy.repository.name,
    url: legacy.repository.url,
    commitSha: legacy.repository.commitSha,
    defaultBranch: legacy.repository.defaultBranch,
    snapshotDigest: `legacy:${legacy.repository.commitSha}`,
  });
  const legacyResult = new LegacyScanResult({
    schemaVersion: ScanResultSchemaVersion,
    resultKind: 'legacy-noncanonical',
    legacyProfileVersion: legacy.profile.version,
    legacyReason:
      'The v1 record does not prove canonical eligible and analyzed repository path-set identity.',
    scanId: legacy.scanId,
    source: legacySource,
    createdAt: legacy.createdAt,
    completedAt: legacy.completedAt,
    profile: legacy.profile,
    summary: legacy.summary,
    findings: legacy.findings,
    analyzerRuns: legacy.analyzerRuns,
    comparison: new LegacyScanComparisonV1({
      newFindingIds: legacy.comparison.newFindingIds,
      resolvedFingerprints: legacy.comparison.resolvedFingerprints,
      persistentFindingIds: legacy.comparison.persistentFindingIds,
      priorityDelta: legacy.comparison.priorityDelta,
    }),
  });
  return legacyResult;
};

const ScanResultWire = Schema.Union([
  LegacyScanResultV1,
  Schema.toEncoded(ScanResult),
]);

export const ScanResultFromV1 = ScanResultWire.pipe(
  Schema.decodeTo(
    ScanResult,
    SchemaTransformation.transform({
      decode: value =>
        value.schemaVersion === LegacyScanResultSchemaVersion
          ? migrateLegacyScanResult(value)
          : value,
      encode: value => value,
    }),
  ),
);

export const decodeScanResult = Schema.decodeUnknownEffect(ScanResultFromV1, {
  onExcessProperty: 'error',
});
export const encodeScanResult = Schema.encodeEffect(ScanResultFromV1, {
  onExcessProperty: 'error',
});
const BoundedScanResultJson = Schema.String.check(
  Schema.makeFilter(value =>
    encodedByteLength(value) <= ContractLimits.encodedResultBytes
      ? undefined
      : 'encoded scan result JSON exceeds the contract byte limit',
  ),
);
const ScanResultJsonValue = BoundedScanResultJson.pipe(
  Schema.decodeTo(Schema.fromJsonString(Schema.Json)),
);
const decodeStrictScanResult = SchemaParser.decodeUnknownEffect(ScanResultFromV1, {
  onExcessProperty: 'error',
});
const validateEncodedScanResult = SchemaParser.decodeUnknownEffect(
  Schema.toEncoded(ScanResult),
  {
  onExcessProperty: 'error',
  },
);
const decodeJsonValue = SchemaParser.decodeUnknownEffect(Schema.Json);
const decodeScanResultJsonValue = (value: Schema.Json) =>
  decodeStrictScanResult(value);
const encodeScanResultJsonValue = (value: ScanResult) =>
  validateEncodedScanResult(value).pipe(Effect.flatMap(decodeJsonValue));
export const ScanResultJson = ScanResultJsonValue.pipe(
  Schema.decodeTo(
    ScanResult,
    SchemaTransformation.transformOrFail({
      decode: decodeScanResultJsonValue,
      encode: encodeScanResultJsonValue,
    }),
  ),
);
export const decodeScanResultJson = Schema.decodeUnknownEffect(ScanResultJson, {
  onExcessProperty: 'error',
});
export const encodeScanResultJson = Schema.encodeEffect(ScanResultJson, {
  onExcessProperty: 'error',
});
