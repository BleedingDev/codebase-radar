import {
  Config,
  DateTime,
  Effect,
  Option,
  Redacted,
  Schema,
} from 'effect';
import {
  HttpClient,
  HttpClientRequest,
  HttpClientResponse,
} from 'effect/unstable/http';
import {
  ActionClass,
  AnalyzerRun,
  Evidence,
  ExternalReference,
  Finding,
  FindingScores,
  ScanResult,
  Framework,
  RepositorySnapshot,
  ScanComparison,
  ScanProfile,
  ScanSummary,
} from '../shared/domain';
import { candidateHash, FindingCandidate } from './analyzers';

const RerankResponse = Schema.Struct({
  adjustments: Schema.Array(
    Schema.Struct({
      fingerprint: Schema.String,
      adjustment: Schema.Number,
      rationale: Schema.String,
    }),
  ),
});

const CompletionResponse = Schema.Struct({
  choices: Schema.optional(
    Schema.Array(
      Schema.Struct({
        message: Schema.optional(
          Schema.Struct({ content: Schema.optional(Schema.String) }),
        ),
      }),
    ),
  ),
});

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const actionFor = (
  priority: number,
  confidence: number,
  tags: ReadonlyArray<string>,
): typeof ActionClass.Type => {
  if (tags.includes('generated-or-test') || tags.includes('style-policy')) {
    return 'do not fix';
  }
  if (priority >= 72 && confidence >= 70) return 'fix now';
  if (priority >= 50) return 'investigate';
  if (priority >= 30) return 'monitor';
  return 'do not fix';
};

const llmAdjustments = Effect.fn('llmAdjustments')(function* (
  findings: ReadonlyArray<Finding>,
) {
  const apiKey = yield* Config.option(Config.redacted('LLM_API_KEY'));
  if (Option.isNone(apiKey) || findings.length === 0) {
    return new Map<string, { readonly adjustment: number; readonly rationale: string }>();
  }
  const baseUrl = (
    yield* Config.string('LLM_BASE_URL').pipe(
      Config.withDefault('https://api.openai.com/v1'),
    )
  ).replace(/\/$/u, '');
  const model = yield* Config.string('LLM_MODEL').pipe(Config.withDefault('gpt-5-mini'));
  const client = yield* HttpClient.HttpClient;
  const request = yield* HttpClientRequest.post(`${baseUrl}/chat/completions`).pipe(
    HttpClientRequest.setHeader(
      'authorization',
      `Bearer ${Redacted.value(apiKey.value)}`,
    ),
    HttpClientRequest.bodyJson({
      model,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'Rerank static code-quality findings. Evidence and five input scores are immutable. Return JSON {"adjustments":[{"fingerprint":string,"adjustment":integer -8..8,"rationale":string}]}. Never invent runtime, security, business, or financial facts. Prefer concrete, corroborated, tractable work and penalize style noise.',
        },
        {
          role: 'user',
          content: JSON.stringify(
            findings.map(finding => ({
              fingerprint: finding.fingerprint,
              title: finding.title,
              category: finding.category,
              scores: finding.scores,
              evidenceKinds: finding.evidence.map(evidence => evidence.kind),
              tags: finding.tags,
            })),
          ),
        },
      ],
    }),
  );
  const response = yield* client.execute(request).pipe(
    Effect.flatMap(HttpClientResponse.filterStatusOk),
    Effect.flatMap(HttpClientResponse.schemaBodyJson(CompletionResponse)),
    Effect.timeout('15 seconds'),
  );
  const content = response.choices?.[0]?.message?.content;
  if (!content) return new Map();
  const decoded = yield* Schema.decodeEffect(
    Schema.fromJsonString(RerankResponse),
  )(content);
  const known = new Set(findings.map(finding => finding.fingerprint));
  return new Map(
    decoded.adjustments
      .filter(
        adjustment =>
          known.has(adjustment.fingerprint) &&
          Number.isFinite(adjustment.adjustment) &&
          adjustment.adjustment >= -8 &&
          adjustment.adjustment <= 8,
      )
      .slice(0, 20)
      .map(adjustment => [
        adjustment.fingerprint,
        {
          adjustment: Math.round(adjustment.adjustment),
          rationale: adjustment.rationale.slice(0, 220),
        },
      ]),
  );
});

export const prioritize = Effect.fn('prioritize')(function* (
  candidates: ReadonlyArray<FindingCandidate>,
) {
  const groups = new Map<string, FindingCandidate>();
  for (const candidate of candidates) {
    const fingerprint = yield* candidateHash(candidate.fingerprintSeed.toLowerCase());
    const current = groups.get(fingerprint);
    groups.set(
      fingerprint,
      current === undefined
        ? candidate
        : new FindingCandidate({
            ...current,
            evidence: [...current.evidence, ...candidate.evidence],
            externalReferences: [
              ...(current.externalReferences ?? []),
              ...(candidate.externalReferences ?? []),
            ],
            tags: [...new Set([...current.tags, ...candidate.tags])],
            consequence: Math.max(current.consequence, candidate.consequence),
            blastRadius: Math.max(current.blastRadius, candidate.blastRadius),
            confidence: Math.min(
              98,
              Math.max(current.confidence, candidate.confidence) + 3,
            ),
            effort: Math.max(current.effort, candidate.effort),
            changeExposure: Math.max(
              current.changeExposure,
              candidate.changeExposure,
            ),
          }),
    );
  }
  const baseFindings = [...groups.entries()].map(([fingerprint, candidate]) => {
    const priority = clamp(
      candidate.consequence * 0.3 +
        candidate.blastRadius * 0.2 +
        candidate.confidence * 0.2 +
        candidate.changeExposure * 0.2 +
        (100 - candidate.effort) * 0.1,
    );
    return new Finding({
      id: `finding_${fingerprint}`,
      fingerprint,
      title: candidate.title,
      category: candidate.category,
      action: actionFor(priority, candidate.confidence, candidate.tags),
      summary: candidate.summary,
      technicalSummary: candidate.technicalSummary,
      recommendation: candidate.recommendation,
      scores: new FindingScores({
        consequence: clamp(candidate.consequence),
        blastRadius: clamp(candidate.blastRadius),
        confidence: clamp(candidate.confidence),
        effort: clamp(candidate.effort),
        changeExposure: clamp(candidate.changeExposure),
        priority,
      }),
      evidence: candidate.evidence.map(evidence => new Evidence({ ...evidence })),
      externalReferences: [
        ...new Map(
          (candidate.externalReferences ?? []).map(reference => [
            reference.url,
            new ExternalReference({ ...reference }),
          ]),
        ).values(),
      ],
      tags: candidate.tags,
      statusComparedToPrevious: 'new',
    });
  });
  const adjustments = yield* llmAdjustments(baseFindings).pipe(
    Effect.catch(() => Effect.succeed(new Map())),
  );
  return baseFindings
    .map(finding => {
      const adjustment = adjustments.get(finding.fingerprint);
      if (adjustment === undefined) return finding;
      const priority = clamp(finding.scores.priority + adjustment.adjustment);
      return new Finding({
        ...finding,
        action: actionFor(priority, finding.scores.confidence, finding.tags),
        scores: new FindingScores({ ...finding.scores, priority }),
        evidence: [
          ...finding.evidence,
          new Evidence({
            analyzer: 'bounded-llm-reranker',
            kind: 'inference',
            message: `Priority adjustment ${adjustment.adjustment >= 0 ? '+' : ''}${adjustment.adjustment}: ${adjustment.rationale}`,
          }),
        ],
      });
    })
    .sort(
      (left, right) =>
        right.scores.priority - left.scores.priority ||
        right.scores.confidence - left.scores.confidence ||
        left.fingerprint.localeCompare(right.fingerprint),
    );
});

export const buildScanResult = Effect.fn('buildScanResult')(function* (input: {
  readonly scanId: string;
  readonly owner: string;
  readonly repository: string;
  readonly githubUrl: string;
  readonly commitSha: string;
  readonly defaultBranch: string;
  readonly createdAt: string;
  readonly frameworks: ReadonlyArray<typeof Framework.Type>;
  readonly candidates: ReadonlyArray<FindingCandidate>;
  readonly analyzerRuns: ReadonlyArray<AnalyzerRun>;
  readonly previous?: ScanResult;
}) {
  const ranked = yield* prioritize(input.candidates);
  const previousByFingerprint = new Map(
    (input.previous?.findings ?? []).map(finding => [finding.fingerprint, finding]),
  );
  const findings = ranked.map(finding => {
    const previous = previousByFingerprint.get(finding.fingerprint);
    const statusComparedToPrevious: Finding['statusComparedToPrevious'] =
      previous === undefined
        ? 'new'
        : finding.scores.priority > previous.scores.priority + 4
          ? 'regressed'
          : finding.scores.priority < previous.scores.priority - 4
            ? 'improved'
            : 'persistent';
    return new Finding({ ...finding, statusComparedToPrevious });
  });
  const fingerprints = new Set(findings.map(finding => finding.fingerprint));
  const previousPriority = (input.previous?.findings ?? []).reduce(
    (sum, finding) => sum + finding.scores.priority,
    0,
  );
  const currentPriority = findings.reduce(
    (sum, finding) => sum + finding.scores.priority,
    0,
  );
  const completedAt = (yield* DateTime.nowAsDate).toISOString();
  const frameworkNames =
    input.frameworks.length > 0
      ? input.frameworks.join(', ')
      : 'plain TypeScript/JavaScript';
  const healthScore = clamp(
    100 -
      findings.reduce(
        (sum, finding, index) =>
          sum + finding.scores.priority * (index < 5 ? 0.11 : 0.025),
        0,
      ),
  );
  return new ScanResult({
    schemaVersion: 'codebase-radar.scan-result/v1',
    scanId: input.scanId,
    repository: new RepositorySnapshot({
      owner: input.owner,
      name: input.repository,
      url: input.githubUrl,
      commitSha: input.commitSha,
      defaultBranch: input.defaultBranch,
    }),
    createdAt: input.createdAt,
    completedAt,
    profile: new ScanProfile({
      version: '2026-08-09',
      frameworks: input.frameworks,
      languageCoverage: [
        'TypeScript',
        'JavaScript',
        'TSX/JSX',
        'GitHub Actions',
        'JavaScript lockfiles',
      ],
      limitations: [
        `Detected framework profile: ${frameworkNames}.`,
        'No dependencies, builds, tests, hooks, submodules, or repository executables were run.',
        'Angular, Svelte, and Solid receive universal TS/JS analysis without framework-template semantic linting.',
        'Static structure and advisories do not prove runtime reachability, exploitability, financial loss, or business impact.',
      ],
    }),
    summary: new ScanSummary({
      headline:
        findings.length > 0
          ? `${findings.filter(finding => finding.action === 'fix now').length || 'No'} urgent; ${findings.length} items worth your attention.`
          : 'Nothing was ranked. This does not mean the codebase is risk-free.',
      healthScore,
      fixNow: findings.filter(finding => finding.action === 'fix now').length,
      investigate: findings.filter(finding => finding.action === 'investigate').length,
      monitor: findings.filter(finding => finding.action === 'monitor').length,
      doNotFix: findings.filter(finding => finding.action === 'do not fix').length,
    }),
    findings,
    analyzerRuns: input.analyzerRuns,
    comparison: new ScanComparison({
      ...(input.previous ? { previousScanId: input.previous.scanId } : {}),
      newFindingIds: findings
        .filter(finding => finding.statusComparedToPrevious === 'new')
        .map(finding => finding.id),
      resolvedFingerprints: (input.previous?.findings ?? [])
        .filter(finding => !fingerprints.has(finding.fingerprint))
        .map(finding => finding.fingerprint),
      persistentFindingIds: findings
        .filter(finding => finding.statusComparedToPrevious !== 'new')
        .map(finding => finding.id),
      priorityDelta: input.previous ? currentPriority - previousPriority : 0,
    }),
  });
});
