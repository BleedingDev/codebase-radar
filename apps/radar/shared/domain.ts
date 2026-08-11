import { Schema } from '@modern-js/plugin-bff/effect-client';
import {
  ActionClass,
  FindingSchema,
  RepositorySnapshot,
  ScanResultFromV1,
} from '@codebase-radar/contracts';

export * from '@codebase-radar/contracts';

export const Audience = Schema.Literals(['technical', 'executive', 'security']);

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
  result: Schema.optional(ScanResultFromV1),
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
  finding: FindingSchema,
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
  candidates: Schema.Array(FindingSchema),
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

const agentLoginUrlMaximumLength = 2_048;
const claudeCodeOAuthClientId = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const claudeCodeOAuthScope = [
  'org:create_api_key',
  'user:profile',
  'user:inference',
  'user:sessions:claude_code',
  'user:mcp_servers',
  'user:file_upload',
].join(' ');

const isCanonicalAgentLoginUrl = (value: string) => {
  if (value.length === 0 || value.length > agentLoginUrlMaximumLength) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.href === value &&
      parsed.protocol === 'https:' &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.port === '' &&
      parsed.hash === ''
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
};

const isClaudeDeviceAuthorizationUrl = (url: URL) => {
  if (
    url.hostname !== 'claude.com' ||
    url.pathname !== '/cai/oauth/authorize' ||
    url.search.length === 0
  ) return false;

  const parameters = url.searchParams;
  const expectedKeys: ReadonlyArray<string> = [
    'code',
    'client_id',
    'response_type',
    'redirect_uri',
    'scope',
    'code_challenge',
    'code_challenge_method',
    'state',
  ];
  if (
    parameters.size !== expectedKeys.length ||
    expectedKeys.some(key => parameters.getAll(key).length !== 1)
  ) return false;

  const clientId = parameters.get('client_id');
  const scope = parameters.get('scope');
  const codeChallenge = parameters.get('code_challenge');
  const state = parameters.get('state');
  return parameters.get('code') === 'true' &&
    parameters.get('response_type') === 'code' &&
    parameters.get('redirect_uri') === 'https://platform.claude.com/oauth/code/callback' &&
    parameters.get('code_challenge_method') === 'S256' &&
    clientId === claudeCodeOAuthClientId &&
    scope === claudeCodeOAuthScope &&
    codeChallenge !== null &&
    /^[A-Za-z0-9_-]{43,128}$/u.test(codeChallenge) &&
    state !== null &&
    /^[A-Za-z0-9_-]{32,256}$/u.test(state);
};

/**
 * A provider prints this URL to an untrusted terminal transcript, so it is not
 * an arbitrary external link. Keep the issuer, path, URL form, and the Claude
 * OAuth redirect target exact before making it available to a browser.
 */
export const isAgentLoginVerificationUrl = (
  provider: 'codex' | 'claude',
  value: string,
) => {
  const url = isCanonicalAgentLoginUrl(value);
  if (url === undefined) return false;
  return provider === 'codex'
    ? url.hostname === 'auth.openai.com' &&
      url.pathname === '/codex/device' &&
      url.search === ''
    : isClaudeDeviceAuthorizationUrl(url);
};

const isKnownAgentLoginVerificationUrl = (value: string) =>
  isAgentLoginVerificationUrl('codex', value) ||
  isAgentLoginVerificationUrl('claude', value);

export const AgentLoginVerificationUrl = Schema.String.pipe(
  Schema.refine(
    (value): value is string => isKnownAgentLoginVerificationUrl(value),
    { expected: 'a canonical, provider-owned HTTPS device-verification URL' },
  ),
);

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
  verificationUrl: Schema.optional(AgentLoginVerificationUrl),
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
  opinionKind: Schema.Literal('unverified-model-opinion'),
  reason: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_000)),
  nextMove: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_000)),
}) {}

export class AgentPriorityOutput extends Schema.Class<AgentPriorityOutput>(
  'AgentPriorityOutput',
)({
  opinionKind: Schema.Literal('unverified-model-opinion'),
  summary: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1_200)),
  orderedItems: Schema.Array(AgentPriorityItem).check(Schema.isMaxLength(1_000)),
  notNowFindingIds: Schema.Array(Schema.String).check(Schema.isMaxLength(10)),
  // At most 40 local windows (1,000 findings / 25) can each carry ten
  // bounded unsupported claims. Keep the public projection lossless.
  unsupportedClaims: Schema.Array(Schema.String).check(Schema.isMaxLength(400)),
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
