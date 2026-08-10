import { Schema } from '@modern-js/plugin-bff/effect-client';

export const Audience = Schema.Literals(['technical', 'executive', 'security']);
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
  analyzer: Schema.String,
  kind: Schema.Literals(['direct', 'strong_proxy', 'context', 'inference']),
  message: Schema.String,
  ruleId: Schema.optional(Schema.String),
  path: Schema.optional(Schema.String),
  line: Schema.optional(Schema.Number),
  excerpt: Schema.optional(Schema.String),
}) {}

export class ExternalReference extends Schema.Class<ExternalReference>(
  'ExternalReference',
)({
  label: Schema.String,
  url: Schema.String,
  relationship: Schema.Literals(['advisory', 'background', 'similar_case']),
  applicability: Schema.Literals(['established', 'unverified']),
}) {}

export class FindingScores extends Schema.Class<FindingScores>('FindingScores')({
  consequence: Schema.Number,
  blastRadius: Schema.Number,
  confidence: Schema.Number,
  effort: Schema.Number,
  changeExposure: Schema.Number,
  priority: Schema.Number,
}) {}

export class Finding extends Schema.Class<Finding>('Finding')({
  id: Schema.String,
  fingerprint: Schema.String,
  mechanism: Schema.optional(Schema.String),
  title: Schema.String,
  category: FindingCategory,
  action: ActionClass,
  summary: Schema.String,
  technicalSummary: Schema.String,
  recommendation: Schema.String,
  scores: FindingScores,
  evidence: Schema.Array(Evidence),
  externalReferences: Schema.Array(ExternalReference),
  tags: Schema.Array(Schema.String),
  statusComparedToPrevious: Schema.Literals([
    'new',
    'persistent',
    'improved',
    'regressed',
  ]),
}) {}

export class AnalyzerCoverage extends Schema.Class<AnalyzerCoverage>(
  'AnalyzerCoverage',
)({
  eligibleFiles: Schema.Number,
  analyzedFiles: Schema.Number,
  omittedCapabilities: Schema.Array(Schema.String),
  warnings: Schema.Array(Schema.String),
}) {}

export class AnalyzerRun extends Schema.Class<AnalyzerRun>('AnalyzerRun')({
  analyzer: Schema.String,
  analyzerVersion: Schema.String,
  profileVersion: Schema.String,
  status: AnalyzerStatus,
  durationMs: Schema.Number,
  coverage: AnalyzerCoverage,
  observationCount: Schema.Number,
  diagnostic: Schema.optional(Schema.String),
}) {}

export class ScanComparison extends Schema.Class<ScanComparison>('ScanComparison')({
  previousScanId: Schema.optional(Schema.String),
  newFindingIds: Schema.Array(Schema.String),
  resolvedFingerprints: Schema.Array(Schema.String),
  persistentFindingIds: Schema.Array(Schema.String),
  priorityDelta: Schema.Number,
}) {}

export class RepositorySnapshot extends Schema.Class<RepositorySnapshot>(
  'RepositorySnapshot',
)({
  owner: Schema.String,
  name: Schema.String,
  url: Schema.String,
  commitSha: Schema.String,
  defaultBranch: Schema.String,
}) {}

export class ScanProfile extends Schema.Class<ScanProfile>('ScanProfile')({
  version: Schema.Literals(['2026-08-09', 'dogfood:max/v1']),
  frameworks: Schema.Array(Framework),
  languageCoverage: Schema.Array(Schema.String),
  limitations: Schema.Array(Schema.String),
}) {}

export class ScanSummary extends Schema.Class<ScanSummary>('ScanSummary')({
  headline: Schema.String,
  healthScore: Schema.Number,
  fixNow: Schema.Number,
  investigate: Schema.Number,
  monitor: Schema.Number,
  doNotFix: Schema.Number,
}) {}

export class ScanResult extends Schema.Class<ScanResult>('ScanResult')({
  schemaVersion: Schema.Literal('codebase-radar.scan-result/v1'),
  scanId: Schema.String,
  repository: RepositorySnapshot,
  createdAt: Schema.String,
  completedAt: Schema.String,
  profile: ScanProfile,
  summary: ScanSummary,
  findings: Schema.Array(Finding),
  analyzerRuns: Schema.Array(AnalyzerRun),
  comparison: ScanComparison,
}) {}

export class ScanRecord extends Schema.Class<ScanRecord>('ScanRecord')({
  id: Schema.String,
  githubUrl: Schema.String,
  owner: Schema.String,
  repository: Schema.String,
  audience: Audience,
  status: Schema.Literals(['queued', 'running', 'completed', 'failed']),
  progress: Schema.Number,
  stage: Schema.String,
  createdAt: Schema.String,
  updatedAt: Schema.String,
  error: Schema.optional(Schema.String),
  result: Schema.optional(ScanResult),
}) {}

export class AudienceProfile extends Schema.Class<AudienceProfile>(
  'AudienceProfile',
)({
  id: Schema.String,
  audience: Audience,
  displayName: Schema.optional(Schema.String),
  createdAt: Schema.String,
}) {}

export class FindingTaskpack extends Schema.Class<FindingTaskpack>(
  'FindingTaskpack',
)({
  schemaVersion: Schema.Literal('codebase-radar.taskpack/v1'),
  scanId: Schema.String,
  repository: RepositorySnapshot,
  finding: Finding,
  objective: Schema.String,
  acceptanceCriteria: Schema.Array(Schema.String),
  guardrails: Schema.Array(Schema.String),
  suggestedInvestigation: Schema.Array(Schema.String),
}) {}

export class PrioritizationBrief extends Schema.Class<PrioritizationBrief>(
  'PrioritizationBrief',
)({
  schemaVersion: Schema.Literal('codebase-radar.prioritization-brief/v1'),
  scanId: Schema.String,
  repository: RepositorySnapshot,
  audience: Audience,
  objective: Schema.String,
  decisionRules: Schema.Array(Schema.String),
  candidates: Schema.Array(Finding),
  requiredOutput: Schema.Array(Schema.String),
}) {}

export const AgentProvider = Schema.Literals(['codex', 'claude']);
export const AgentConnectionState = Schema.Literals([
  'disconnected',
  'connecting',
  'connected',
  'failed',
  'deleting',
]);

export class BrowserSession extends Schema.Class<BrowserSession>('BrowserSession')({
  status: Schema.Literal('ready'),
}) {}

export class AgentProfile extends Schema.Class<AgentProfile>('AgentProfile')({
  id: Schema.String,
  provider: AgentProvider,
  state: AgentConnectionState,
  accountLabel: Schema.optional(Schema.String),
  diagnostic: Schema.optional(Schema.String),
  createdAt: Schema.String,
  updatedAt: Schema.String,
}) {}

export class AgentProfileList extends Schema.Class<AgentProfileList>(
  'AgentProfileList',
)({
  items: Schema.Array(AgentProfile),
}) {}

export class AgentLoginChallenge extends Schema.Class<AgentLoginChallenge>(
  'AgentLoginChallenge',
)({
  id: Schema.String,
  profileId: Schema.String,
  provider: AgentProvider,
  status: Schema.Literals(['starting', 'waiting', 'completed', 'failed']),
  verificationUrl: Schema.optional(Schema.String),
  userCode: Schema.optional(Schema.String),
  prompt: Schema.optional(Schema.String),
  diagnostic: Schema.optional(Schema.String),
  expiresAt: Schema.String,
}) {}

export class AgentPriorityItem extends Schema.Class<AgentPriorityItem>(
  'AgentPriorityItem',
)({
  findingId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(200)),
  action: ActionClass,
  reason: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_000)),
  nextMove: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_000)),
}) {}

export class AgentPriorityOutput extends Schema.Class<AgentPriorityOutput>(
  'AgentPriorityOutput',
)({
  summary: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_200)),
  orderedItems: Schema.Array(AgentPriorityItem).check(Schema.isMaxLength(5)),
  notNowFindingIds: Schema.Array(Schema.String).check(Schema.isMaxLength(10)),
  unsupportedClaims: Schema.Array(Schema.String).check(Schema.isMaxLength(10)),
}) {}

export class AgentPriorityReview extends Schema.Class<AgentPriorityReview>(
  'AgentPriorityReview',
)({
  schemaVersion: Schema.Literal('codebase-radar.priority-review/v1'),
  id: Schema.String,
  scanId: Schema.String,
  profileId: Schema.String,
  provider: AgentProvider,
  status: Schema.Literals(['queued', 'running', 'completed', 'failed']),
  output: Schema.optional(AgentPriorityOutput),
  diagnostic: Schema.optional(Schema.String),
  createdAt: Schema.String,
  updatedAt: Schema.String,
}) {}
